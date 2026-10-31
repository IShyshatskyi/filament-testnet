//! MEMPOOL-SIGCACHE-1 Phase 1: salted, bounded, success-only Schnorr verify cache.
//!
//! Spec: `docs/plan/Benchmark_Strategy_Plan/keystone_batch_and_mempool_skip_research_2026-10-04.md`
//! Q2 Phase 1 (Oct 25, 2026, owner decisions t27u).
//!
//! A key present in the cache means exactly one thing: "BIP-340 verify returned Ok
//! for this (scheme_tag, sighash, pubkey, sig)". It never means "this tx / spend is
//! legal at this height". Every other rule (structure, TE-1/2/3, UTXO resolve,
//! TX-1/7/8/10/12, TX-2/TX-3, and — when D14 lands — height-gated spend-path
//! selection) runs on every validation, hit or miss. Failures are never cached.
//!
//! Policy:
//! - CV-70 mempool admission (incl. reorg re-admit): lookup; on miss verify and
//!   insert only on Ok ([`SigVerifier::verify_admission`]).
//! - Block validation: lookup only, never insert; record hit keys
//!   ([`SigVerifier::verify_block`]).
//! - Core-style erase: after a block **connects**, erase its hit keys
//!   ([`SigVerifier::erase`]). Nothing is erased if validation/apply fails.
//!
//! The cache lock is held only around lookup / insert / erase, never during verify.

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;


use super::tx_sighash::verify_schnorr_witness;
use crate::common::validation::ValidationError;
use crate::transaction::WitnessEntry;

/// Domain separator; bump whenever sighash or verify rules change.
pub const SIGCACHE_DOMAIN_TAG: &[u8] = b"shisha/sigcache/v1";

/// `scheme_tag` for today's single-key Schnorr output.
///
/// Future spend paths (e.g. D14 native expiring 2-of-2: pre-H 2-of-2 vs post-H
/// sender-only recovery) must get distinct tags (or a sighash v3 path
/// discriminator), and the path must be selected at apply height **before** any
/// lookup. The cache answers one signature at a time, never "is this path satisfied".
pub const SCHEME_TAG_SINGLE_KEY: u8 = 0x00;

/// Per-shard-chain capacity (Phase 1; Phase 2 A/B at 4k/8k/16k may retune).
///
/// ~82 B/entry (32 B key + LRU node/hash-map overhead) → ~0.66 MiB per full
/// cache, ~1% of the 64 MiB PO-10 unsaved-tail cap; ~168 MiB across 255 shards.
/// Sized ~2× the working set (mempool ~1k verifies + 4-block re-admit ~2–4k).
/// See `kameniar_app/docs/MEMORY_BUDGET.md`.
pub const SIGCACHE_MAX_ENTRIES: usize = 8_192;

/// Beacon-chain capacity (Phase 1): ~2.6 MiB full, ~1% of the 256 MiB beacon
/// tail; covers a ~10k-tx beacon mempool. Phase 2 A/B may retune.
pub const SIGCACHE_BEACON_MAX_ENTRIES: usize = 32_768;

/// 32-byte salted cache key.
pub type SigCacheKey = [u8; 32];

/// Signature verification policy passed next to the validation params.
pub trait SigVerifier: Send + Sync {
    /// CV-70 path: lookup; on miss run the real verify, insert on Ok.
    fn verify_admission(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        scheme_tag: u8,
    ) -> Result<(), ValidationError>;

    /// Block path: lookup only (no insert). A hit's key is pushed to `hits`.
    fn verify_block(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        scheme_tag: u8,
        hits: &mut Vec<SigCacheKey>,
    ) -> Result<(), ValidationError>;

    /// Core-style erase-on-connect. Call only after the block connected.
    fn erase(&self, keys: &[SigCacheKey]);

    /// Keep-on-revert (disconnect re-warm): put back keys of signatures in
    /// blocks that were just disconnected, so CV-70 re-admit of their spends
    /// can hit. Keys must come from witnesses that were verified when the
    /// block connected (see `sig_cache_keys_for_tx`).
    fn reinsert(&self, keys: &[SigCacheKey]);
}

/// Always verifies, never stores (tests, cold bench arm, wallet checks).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSigCache;

impl SigVerifier for NoSigCache {
    fn verify_admission(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        _scheme_tag: u8,
    ) -> Result<(), ValidationError> {
        verify_schnorr_witness(witness, pubkey, sighash, input_index)
    }

    fn verify_block(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        _scheme_tag: u8,
        _hits: &mut Vec<SigCacheKey>,
    ) -> Result<(), ValidationError> {
        verify_schnorr_witness(witness, pubkey, sighash, input_index)
    }

    fn erase(&self, _keys: &[SigCacheKey]) {}

    fn reinsert(&self, _keys: &[SigCacheKey]) {}
}

/// Real cache: salted keys in a bounded LRU set behind a short-held mutex.
pub struct SigCache {
    salt: [u8; 32],
    inner: Mutex<LruCache<SigCacheKey, ()>>,
}

impl std::fmt::Debug for SigCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigCache").field("len", &self.len()).finish_non_exhaustive()
    }
}

impl Default for SigCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SigCache {
    /// Cache with [`SIGCACHE_MAX_ENTRIES`] capacity and a fresh OsRng salt.
    pub fn new() -> Self {
        Self::with_capacity(SIGCACHE_MAX_ENTRIES)
    }

    /// Shared handle for a shard chain object ([`SIGCACHE_MAX_ENTRIES`]).
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Shared handle for a beacon chain object ([`SIGCACHE_BEACON_MAX_ENTRIES`]).
    pub fn new_shared_beacon() -> Arc<Self> {
        Arc::new(Self::with_capacity(SIGCACHE_BEACON_MAX_ENTRIES))
    }

    /// Cache with a custom capacity (≥ 1) and a fresh OsRng salt.
    pub fn with_capacity(capacity: usize) -> Self {
        // OS-seeded CSPRNG (rand's ThreadRng, reseeded from the OS RNG); drawn once per instance.
        let salt: [u8; 32] = rand::random();
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self { salt, inner: Mutex::new(LruCache::new(cap)) }
    }

    /// `blake3::keyed_hash(salt, "shisha/sigcache/v1" ‖ scheme_tag ‖ sighash ‖ pubkey ‖ sig)`.
    ///
    /// `sig` is the raw witness bytes (type byte + 64-byte signature).
    pub fn key(&self, scheme_tag: u8, sighash: &[u8; 32], pubkey: &[u8; 32], sig: &[u8]) -> SigCacheKey {
        let mut h = blake3::Hasher::new_keyed(&self.salt);
        h.update(SIGCACHE_DOMAIN_TAG);
        h.update(&[scheme_tag]);
        h.update(sighash);
        h.update(pubkey);
        h.update(sig);
        h.finalize().into()
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Capacity bound.
    pub fn capacity(&self) -> usize {
        self.inner.lock().cap().get()
    }

    /// Presence check (promotes in LRU).
    pub fn contains(&self, key: &SigCacheKey) -> bool {
        self.inner.lock().get(key).is_some()
    }

    fn insert_key(&self, key: SigCacheKey) {
        self.inner.lock().put(key, ());
    }

    /// Keep-on-revert: insert each key (LRU put). See [`SigVerifier::reinsert`].
    pub fn reinsert_keys(&self, keys: &[SigCacheKey]) {
        if keys.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        for k in keys {
            g.put(*k, ());
        }
    }

    /// Test-only warm path that still runs the real verify (TE-1 tests: CV-70
    /// refuses a tx below its locktime, so admission cannot warm it).
    #[doc(hidden)]
    pub fn insert_verified(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        scheme_tag: u8,
    ) -> Result<(), ValidationError> {
        self.verify_admission(witness, pubkey, sighash, input_index, scheme_tag)
    }
}

impl SigVerifier for SigCache {
    fn verify_admission(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        scheme_tag: u8,
    ) -> Result<(), ValidationError> {
        let key = self.key(scheme_tag, sighash, pubkey, &witness.witness_data);
        if self.contains(&key) {
            return Ok(());
        }
        // Lock released: verify runs unlocked.
        verify_schnorr_witness(witness, pubkey, sighash, input_index)?;
        self.insert_key(key);
        Ok(())
    }

    fn verify_block(
        &self,
        witness: &WitnessEntry,
        pubkey: &[u8; 32],
        sighash: &[u8; 32],
        input_index: usize,
        scheme_tag: u8,
        hits: &mut Vec<SigCacheKey>,
    ) -> Result<(), ValidationError> {
        let key = self.key(scheme_tag, sighash, pubkey, &witness.witness_data);
        if self.contains(&key) {
            hits.push(key);
            return Ok(());
        }
        verify_schnorr_witness(witness, pubkey, sighash, input_index)
    }

    fn erase(&self, keys: &[SigCacheKey]) {
        if keys.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        for k in keys {
            g.pop(k);
        }
    }

    fn reinsert(&self, keys: &[SigCacheKey]) {
        self.reinsert_keys(keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::WITNESS_TYPE_SCHNORR;
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    fn signed(sighash: [u8; 32]) -> (WitnessEntry, [u8; 32]) {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x42u8; 32]).unwrap());
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp);
        let mut d = vec![WITNESS_TYPE_SCHNORR];
        d.extend_from_slice(&sig.serialize());
        (WitnessEntry { witness_data: d }, kp.x_only_public_key().0.serialize())
    }

    #[test]
    fn sigcache_salt_differs_between_instances() {
        let (w, pk) = signed([1; 32]);
        let a = SigCache::new();
        let b = SigCache::new();
        let ka = a.key(0, &[1; 32], &pk, &w.witness_data);
        assert_ne!(ka, b.key(0, &[1; 32], &pk, &w.witness_data));
        a.verify_admission(&w, &pk, &[1; 32], 0, 0).unwrap();
        assert!(a.contains(&ka));
        assert!(!b.contains(&ka));
    }

    #[test]
    fn sigcache_scheme_tag_separates_keys() {
        let (w, pk) = signed([1; 32]);
        let c = SigCache::new();
        assert_ne!(c.key(0, &[1; 32], &pk, &w.witness_data), c.key(1, &[1; 32], &pk, &w.witness_data));
        c.verify_admission(&w, &pk, &[1; 32], 0, 0).unwrap();
        let mut hits = vec![];
        // Same sig under another tag is a miss (falls back to verify).
        c.verify_block(&w, &pk, &[1; 32], 0, 1, &mut hits).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn sigcache_never_caches_failures() {
        let (mut w, pk) = signed([1; 32]);
        w.witness_data[10] ^= 1;
        let c = SigCache::new();
        assert!(c.verify_admission(&w, &pk, &[1; 32], 0, 0).is_err());
        assert!(c.verify_admission(&w, &pk, &[1; 32], 0, 0).is_err());
        assert_eq!(c.len(), 0);
        // Valid sig over a different sighash also fails, not cached.
        let (w2, _) = signed([1; 32]);
        assert!(c.verify_admission(&w2, &pk, &[2; 32], 0, 0).is_err());
        assert_eq!(c.len(), 0);
    }

    /// Keep-on-revert: admit → block hit → erase on connect → reinsert on
    /// disconnect → re-admit is a hit (no verify needed; key present).
    #[test]
    fn sigcache_reinsert_after_erase_rewarms() {
        let c = SigCache::new();
        let (w, pk) = signed([7; 32]);
        let k = c.key(SCHEME_TAG_SINGLE_KEY, &[7; 32], &pk, &w.witness_data);
        c.verify_admission(&w, &pk, &[7; 32], 0, SCHEME_TAG_SINGLE_KEY).unwrap();
        let mut hits = vec![];
        c.verify_block(&w, &pk, &[7; 32], 0, SCHEME_TAG_SINGLE_KEY, &mut hits).unwrap();
        assert_eq!(hits, vec![k]);
        c.erase(&hits);
        assert!(!c.contains(&k));
        assert_eq!(c.len(), 0);
        SigVerifier::reinsert(&c, &[k]);
        assert_eq!(c.len(), 1);
        assert!(c.contains(&k));
        let len = c.len();
        c.verify_admission(&w, &pk, &[7; 32], 0, SCHEME_TAG_SINGLE_KEY).unwrap();
        assert_eq!(c.len(), len, "hit: no new insert");
        // NoSigCache is a no-op.
        SigVerifier::reinsert(&NoSigCache, &[k]);
    }

    #[test]
    fn sigcache_bounded_lru() {
        let c = SigCache::with_capacity(8);
        for i in 0..20u8 {
            let (w, pk) = signed([i; 32]);
            c.verify_admission(&w, &pk, &[i; 32], 0, 0).unwrap();
            assert!(c.len() <= 8);
        }
        assert_eq!(c.len(), 8);
        assert_eq!(c.capacity(), 8);
    }

    #[test]
    fn sigcache_block_path_lookup_only_and_erase() {
        let c = SigCache::new();
        let (w1, pk) = signed([1; 32]);
        let (w2, _) = signed([2; 32]);
        c.verify_admission(&w1, &pk, &[1; 32], 0, 0).unwrap();
        let mut hits = vec![];
        c.verify_block(&w1, &pk, &[1; 32], 0, 0, &mut hits).unwrap();
        c.verify_block(&w2, &pk, &[2; 32], 1, 0, &mut hits).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(c.len(), 1, "block path must not insert");
        c.erase(&hits);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn sigcache_concurrent_admit_and_block() {
        let c = Arc::new(SigCache::with_capacity(64));
        let ws: Vec<_> = (0..32u8).map(|i| (signed([i; 32]), [i; 32])).collect();
        let ws = Arc::new(ws);
        let mut hs = vec![];
        for t in 0..4 {
            let c = c.clone();
            let ws = ws.clone();
            hs.push(std::thread::spawn(move || {
                for ((w, pk), sh) in ws.iter() {
                    if t == 0 {
                        let mut hits = vec![];
                        c.verify_block(w, pk, sh, 0, 0, &mut hits).unwrap();
                        c.erase(&hits);
                    } else {
                        c.verify_admission(w, pk, sh, 0, 0).unwrap();
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert!(c.len() <= 64);
    }
}
