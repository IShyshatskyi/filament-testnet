// src/common/blocks/beacon_wire_header.rs
//
// WireBeaconHeader — compact beacon header for light-client peers (T-10 broadcast)
// and the P2P GetHeaders/Headers sync path (NC-9).
//
// 150 bytes (bumped from 118 on 2026-07-25 — see the NC-39-followup note
// below for why).
//
// **Design rationale — why not the full 80-byte mining header?**
//
// The mining header contains `commitment_hash` at bytes [36..68].
// All preimage fields the commitment needs are transmitted separately in
// this struct, so the receiver can recompute `commitment_hash` locally and
// reconstruct the full 80-byte mining header, instead of shipping the
// redundant 32 already-committed bytes directly.
//
// **2026-07-25 fix (NC-39-followup): `commitment_hash()` was computing the
// wrong formula entirely.** This struct originally used
// `calculate_commitment_hash_from_parts_v2` (`Blake3(height || tx_merkle_root
// || merged_mining_root || committed_chain_count)`) — the *legacy* v2
// formula. But every real block mined in this codebase today (pool
// `share_processor.rs`/`share_validator.rs`, `tools/stratum-worker`) is
// validated against **v3**'s `calculate_commitment_hash_from_coinbase`
// (`SHA256d(coinbase_hash || aux_hash)`, using `coinbase_hash` — a
// body-derived value, not `tx_merkle_root`). Since a header-only wire format
// has no access to `coinbase_hash`, the old 118-byte format could not
// reconstruct the real v3 commitment at all — every S5 PoW re-check of a
// real (v3-mined) header batch failed with "hash does not meet difficulty
// target", instantly banning the sending peer. Found live: a Keystone
// restart re-served its own already-applied height-32 header to the
// producer over `GetHeaders`/`Headers`, the producer's S5 check rejected it,
// banned Keystone for 24h, and the soak stalled forever with zero
// reconnection. This bug is 100% reproducible for any real block — it was
// simply never exercised by two live peers exchanging a real headers batch
// before this session's crash-recovery soak. Fixed by adding `coinbase_hash`
// (32 bytes) to the wire format and switching `commitment_hash()` to the
// real v3 formula. See `docs/plan/Correctness_and_Validation_Plan.md` NC-39
// (follow-up section) for the full incident writeup.
//
// Wire layout (150 bytes):
//   [0..4]     version    (u32 LE)
//   [4..36]    prev_mmr_root (32 bytes)
//   [36..40]   delta      (i32 LE, 1/256-second units)
//   [40..44]   bits       (u32 LE, nBits compact difficulty)
//   [44..48]   nonce      (u32 LE, lower 32 bits of 64-bit nonce)
//   [48..52]   height     (u32 LE)
//   [52..84]   merkle_root (32 bytes) — tx-inclusion proofs only; NOT part of
//                          the v3 commitment_hash preimage (kept for #5 below)
//   [84..116]  merged_mining_root (32 bytes)
//   [116..118] committed_chain_count (u16 LE) — v3 commitment-hash preimage
//   [118..150] coinbase_hash (32 bytes) — v3 commitment-hash preimage
//
// The receiver reconstructs the full 80-byte mining header on demand via
// `mining_header()` and can verify PoW without any extra round-trips.

use crate::common::blocks::beacon_block::{BeaconBlock, BeaconBlockCandidateHeader};
use crate::common::crypto::weighted_hash::WeightedHash;
use sha2::{Sha256, Digest};

/// Total wire size of a `WireBeaconHeader` in bytes.
pub const WIRE_BEACON_HEADER_SIZE: usize = 150;

/// Compact beacon header broadcast to light-client peers (T-10 path).
///
/// Contains the minimum set of fields that allow a light client to:
/// 1. **Verify PoW** — reconstruct the 80-byte mining header and check
///    `SHA256d(header) < rbits_to_target(bits, initial_target, asserted_s)`.
/// 2. **Verify commitment** — check `Blake3(height || merkle_root || merged_mining_root)`
///    matches the commitment slot in the reconstructed mining header.
/// 3. **Track block position** — `height`.
/// 4. **Compute `current_mmr_root`** — `WeightedHash::from_leaf_rbits(pow_hash, bits)` → append.
/// 5. **Verify tx inclusion** — Merkle proof against `merkle_root`.
/// 6. **Verify shard coordination** — Merkle proof against `merged_mining_root`.
///
/// `commitment_hash` is NOT transmitted; the receiver derives it from the
/// three preimage fields, saving 32 bytes vs including the full mining header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireBeaconHeader {
    /// Protocol version number.
    pub version: u32,

    /// Previous MMR root — bytes [4..36] of the reconstructed 80-byte mining header.
    pub prev_mmr_root: WeightedHash,

    /// Timestamp deviation (1/256-second units relative to `bitcoin_anchor_timestamp`).
    pub delta: i32,

    /// Compact **rBits** work field — bytes [72..76] of the mining header
    /// (formerly nBits target; firmware treats the slot as opaque).
    pub bits: u32,

    /// Mining nonce (lower 32 bits) — bytes [76..80] of the mining header.
    pub nonce: u32,

    /// Block height (0 = genesis).  Needed to request MMR proofs.
    pub height: u32,

    /// Merkle root of beacon block body (BLAKE3-based txids; FV-BCN).
    /// Part of the `commitment_hash` preimage; needed for tx inclusion proofs.
    pub tx_merkle_root: [u8; 32],

    /// Merged-mining tree root (shard coordination).
    /// Part of the `commitment_hash` preimage; needed for shard proof verification.
    pub merged_mining_root: [u8; 32],

    /// Number of shard chains committed in this block's merged-mining tree.
    /// Part of the `commitment_hash` preimage (CV-62). Transmitted on the
    /// wire at bytes [116..118] — must be, since `commitment_hash()` cannot
    /// re-derive it from anything else the receiver already has.
    pub committed_chain_count: u16,

    /// The coinbase leaf hash (`Stratum_Extranonce_Binding_Plan.md` §3.1) —
    /// the real v3 commitment preimage's other half, alongside
    /// `merged_mining_root`/`committed_chain_count`. Body-derived (not
    /// reconstructable from any other field on this struct), so it must be
    /// transmitted directly. Added 2026-07-25 — see this file's own header
    /// comment for why (`commitment_hash()` was silently using the wrong,
    /// legacy v2 formula before this field existed).
    pub coinbase_hash: [u8; 32],
}

impl WireBeaconHeader {
    /// Build from a `BeaconBlockCandidateHeader` and an already-derived
    /// `coinbase_hash`. Prefer [`Self::from_block`] when a full `BeaconBlock`
    /// (header + body) is available — it derives `coinbase_hash` for you.
    pub fn from_candidate(h: &BeaconBlockCandidateHeader, coinbase_hash: [u8; 32]) -> Self {
        Self {
            version:               h.version,
            prev_mmr_root:         h.prev_mmr_root,
            delta:                 h.delta,
            bits:                  h.bits,
            nonce:                 h.nonce as u32,
            height:                h.height,
            tx_merkle_root:       h.tx_merkle_root,
            merged_mining_root:    h.merged_mining_root,
            committed_chain_count: h.committed_chain_count,
            coinbase_hash,
        }
    }

    /// Build from a full `BeaconBlock` (header + body), deriving
    /// `coinbase_hash` from the stored body via
    /// [`crate::transaction::coinbase_mining_bytes::coinbase_hash_from_stored_body`].
    ///
    /// Falls back to `[0u8; 32]` when the body doesn't have the expected
    /// coinbase shape (genesis, which has no miner-extranonce extension —
    /// genesis is never PoW-checked, so this is safe; it only affects
    /// `commitment_hash()`/`pow_hash()`, both meaningless for genesis).
    pub fn from_block(block: &BeaconBlock) -> Self {
        let coinbase_hash = crate::transaction::coinbase_mining_bytes::coinbase_hash_from_stored_body(&block.body)
            .unwrap_or([0u8; 32]);
        Self::from_candidate(&block.header, coinbase_hash)
    }

    /// Serialize to exactly [`WIRE_BEACON_HEADER_SIZE`] (150) bytes.
    pub fn serialize(&self) -> [u8; WIRE_BEACON_HEADER_SIZE] {
        let mut out = [0u8; WIRE_BEACON_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        out[36..40].copy_from_slice(&self.delta.to_le_bytes());
        out[40..44].copy_from_slice(&self.bits.to_le_bytes());
        out[44..48].copy_from_slice(&self.nonce.to_le_bytes());
        out[48..52].copy_from_slice(&self.height.to_le_bytes());
        out[52..84].copy_from_slice(&self.tx_merkle_root);
        out[84..116].copy_from_slice(&self.merged_mining_root);
        out[116..118].copy_from_slice(&self.committed_chain_count.to_le_bytes());
        out[118..150].copy_from_slice(&self.coinbase_hash);
        out
    }

    /// Deserialize from exactly [`WIRE_BEACON_HEADER_SIZE`] (150) bytes.
    ///
    /// Returns `Err` if `bytes` is not exactly 150 bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != WIRE_BEACON_HEADER_SIZE {
            return Err(format!(
                "WireBeaconHeader: expected {} bytes, got {}",
                WIRE_BEACON_HEADER_SIZE,
                bytes.len(),
            ));
        }
        let version    = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let prev_mmr_root = WeightedHash::from(
            <[u8; 32]>::try_from(&bytes[4..36]).unwrap()
        );
        let delta      = i32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let bits       = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let nonce      = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        let height     = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        let tx_merkle_root: [u8; 32]    = bytes[52..84].try_into().unwrap();
        let merged_mining_root: [u8; 32] = bytes[84..116].try_into().unwrap();
        let committed_chain_count = u16::from_le_bytes(bytes[116..118].try_into().unwrap());
        let coinbase_hash: [u8; 32] = bytes[118..150].try_into().unwrap();
        Ok(Self { version, prev_mmr_root, delta, bits, nonce, height, tx_merkle_root, merged_mining_root,
                committed_chain_count, coinbase_hash })
    }

    /// Compute `commitment_hash = calculate_commitment_hash_from_coinbase(height,
    /// coinbase_hash, merged_mining_root, committed_chain_count)` — the real
    /// v3 formula every live-mined block is actually validated against.
    ///
    /// This is the value that goes at bytes [36..68] of the 80-byte mining header.
    /// **Deliberately does not use `tx_merkle_root`** — matches
    /// `BeaconBlockCandidateHeader::calculate_commitment_hash_v3`, not the
    /// legacy v2 `calculate_commitment_hash_from_parts_v2` this method used
    /// before 2026-07-25 (see this file's header comment for the incident).
    pub fn commitment_hash(&self) -> [u8; 32] {
        crate::common::blocks::beacon_block::calculate_commitment_hash_from_coinbase(
            self.height, self.coinbase_hash, self.merged_mining_root, self.committed_chain_count,
        )
    }

    /// Reconstruct the full 80-byte Bitcoin-compatible mining header.
    ///
    /// Layout:
    /// ```text
    /// [0..4]   version
    /// [4..36]  prev_mmr_root
    /// [36..68] commitment_hash (v3: SHA256d(coinbase_hash || aux_hash), see `commitment_hash()`)
    /// [68..72] delta
    /// [72..76] bits
    /// [76..80] nonce
    /// ```
    pub fn mining_header(&self) -> [u8; 80] {
        let ch = self.commitment_hash();
        let mut hdr = [0u8; 80];
        hdr[0..4].copy_from_slice(&self.version.to_le_bytes());
        hdr[4..36].copy_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        hdr[36..68].copy_from_slice(&ch);
        hdr[68..72].copy_from_slice(&self.delta.to_le_bytes());
        hdr[72..76].copy_from_slice(&self.bits.to_le_bytes());
        hdr[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        hdr
    }

    /// Compute `pow_hash = SHA256d(mining_header())`.
    pub fn pow_hash(&self) -> [u8; 32] {
        let mh = self.mining_header();
        let first = Sha256::digest(mh);
        Sha256::digest(first).into()
    }

    /// Extract `prev_mmr_root` (same as `self.prev_mmr_root` — convenience accessor).
    pub fn prev_mmr_root(&self) -> WeightedHash {
        self.prev_mmr_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_COINBASE_HASH: [u8; 32] = [0xDD; 32];

    fn make_candidate(height: u32) -> BeaconBlockCandidateHeader {
        const BTC_ANCHOR: u64 = 1_704_067_200;
        BeaconBlockCandidateHeader::new(
            1,
            BTC_ANCHOR + 10_000,
            height,
            0x1d00_ffff,
            WeightedHash::from([0xAA; 32]),
            [0xBB; 32],
            [0xCC; 32],
            BTC_ANCHOR,
        )
    }

    fn make_wire(height: u32) -> WireBeaconHeader {
        WireBeaconHeader::from_candidate(&make_candidate(height), TEST_COINBASE_HASH)
    }

    // LBH-1: from_candidate round-trip: serialize → deserialize → fields match
    #[test]
    fn lbh1_from_candidate_round_trip() {
        let lbh = make_wire(42);
        let bytes = lbh.serialize();
        let decoded = WireBeaconHeader::deserialize(&bytes).unwrap();
        assert_eq!(lbh, decoded);
    }

    // LBH-2: serialize produces exactly 150 bytes (bumped from 118 on
    // 2026-07-25 to add coinbase_hash — see this file's header comment)
    #[test]
    fn lbh2_serialize_is_150_bytes() {
        let lbh = make_wire(1);
        assert_eq!(lbh.serialize().len(), WIRE_BEACON_HEADER_SIZE);
        assert_eq!(WIRE_BEACON_HEADER_SIZE, 150);
    }

    // LBH-3: commitment_hash (v3) is non-zero and changes with each real
    // preimage field (height, merged_mining_root, committed_chain_count,
    // coinbase_hash) but NOT with tx_merkle_root — v3 deliberately excludes
    // it (see this file's header comment for why v2 used it and v3 doesn't).
    #[test]
    fn lbh3_commitment_hash_covers_v3_preimage_fields() {
        let lbh = make_wire(10);
        let ch = lbh.commitment_hash();
        assert_ne!(ch, [0u8; 32]);

        let mut modified = lbh.clone();
        modified.height += 1;
        assert_ne!(modified.commitment_hash(), ch, "height must change commitment_hash");

        let mut modified = lbh.clone();
        modified.merged_mining_root[0] ^= 1;
        assert_ne!(modified.commitment_hash(), ch, "merged_mining_root must change commitment_hash");

        let mut modified = lbh.clone();
        modified.committed_chain_count ^= 1;
        assert_ne!(modified.commitment_hash(), ch, "committed_chain_count must change commitment_hash");

        let mut modified = lbh.clone();
        modified.coinbase_hash[0] ^= 1;
        assert_ne!(modified.commitment_hash(), ch, "coinbase_hash must change commitment_hash");

        let mut modified = lbh.clone();
        modified.tx_merkle_root[0] ^= 1;
        assert_eq!(modified.commitment_hash(), ch,
            "tx_merkle_root must NOT affect v3 commitment_hash (only coinbase_hash does)");
    }

    // LBH-4: mining_header() places commitment_hash at [36..68]
    #[test]
    fn lbh4_mining_header_embeds_commitment_hash() {
        let lbh = make_wire(5);
        let mh = lbh.mining_header();
        let ch = lbh.commitment_hash();
        assert_eq!(&mh[36..68], &ch, "commitment_hash must be at bytes [36..68]");
        assert_eq!(&mh[4..36], &<[u8; 32]>::from(lbh.prev_mmr_root), "prev_mmr_root at [4..36]");
        assert_eq!(&mh[0..4], &lbh.version.to_le_bytes(), "version at [0..4]");
    }

    // LBH-5: mining_header() matches BeaconBlockCandidateHeader::serialize_for_mining_v3()
    // — the real live-mining preimage (NOT the legacy v2 serialize_for_mining(),
    // which this test compared against before 2026-07-25; see file header).
    #[test]
    fn lbh5_mining_header_matches_candidate_v3() {
        let cand = make_candidate(77);
        let lbh = WireBeaconHeader::from_candidate(&cand, TEST_COINBASE_HASH);
        let reconstructed = lbh.mining_header();
        let original = cand.serialize_for_mining_v3(TEST_COINBASE_HASH);
        assert_eq!(reconstructed.as_slice(), original.as_slice(),
            "LBH-5: reconstructed mining header must match original v3 preimage");
    }

    // LBH-6: pow_hash() == SHA256d(mining_header())
    #[test]
    fn lbh6_pow_hash_is_sha256d() {
        use sha2::{Sha256, Digest};
        let lbh = make_wire(3);
        let mh = lbh.mining_header();
        let expected: [u8; 32] = Sha256::digest(Sha256::digest(mh)).into();
        assert_eq!(lbh.pow_hash(), expected);
    }

    // LBH-7: pow_hash() matches BeaconBlock::calculate_hash_v3() — the real
    // live-mining hash (NOT the legacy calculate_hash(), which this test
    // compared against before 2026-07-25; see file header for the incident
    // this discrepancy caused).
    #[test]
    fn lbh7_pow_hash_matches_beacon_block_v3() {
        use crate::common::blocks::beacon_block::BeaconBlock;
        let cand = make_candidate(20);
        let lbh = WireBeaconHeader::from_candidate(&cand, TEST_COINBASE_HASH);
        let expected = BeaconBlock::calculate_hash_v3(&cand, TEST_COINBASE_HASH);
        assert_eq!(lbh.pow_hash(), expected,
            "LBH-7: WireBeaconHeader::pow_hash must match BeaconBlock::calculate_hash_v3");
    }

    // LBH-8: bits() == nBits compact value
    #[test]
    fn lbh8_bits_field() {
        let cand = make_candidate(1);
        let lbh = WireBeaconHeader::from_candidate(&cand, TEST_COINBASE_HASH);
        assert_eq!(lbh.bits, cand.bits);
    }

    // LBH-9: prev_mmr_root matches
    #[test]
    fn lbh9_prev_mmr_root() {
        let cand = make_candidate(1);
        let lbh = WireBeaconHeader::from_candidate(&cand, TEST_COINBASE_HASH);
        assert_eq!(lbh.prev_mmr_root(), cand.prev_mmr_root);
    }

    // LBH-10: delta matches
    #[test]
    fn lbh10_delta_field() {
        let cand = make_candidate(1);
        let lbh = WireBeaconHeader::from_candidate(&cand, TEST_COINBASE_HASH);
        assert_eq!(lbh.delta, cand.delta);
    }

    // LBH-11: deserialize rejects wrong-length payloads
    #[test]
    fn lbh11_deserialize_rejects_wrong_length() {
        assert!(WireBeaconHeader::deserialize(&[0u8; 80]).is_err());
        assert!(WireBeaconHeader::deserialize(&[0u8; 118]).is_err()); // old (pre-2026-07-25) size
        assert!(WireBeaconHeader::deserialize(&[0u8; 149]).is_err());
        assert!(WireBeaconHeader::deserialize(&[0u8; 151]).is_err());
        assert!(WireBeaconHeader::deserialize(&[0u8; 148]).is_err());
    }

    // TL-21: commitment_hash is NOT affected by prev_mmr_root or
    // legacy_linear_cumulative_difficulty changes (the removed `difficulty:
    // u64` field this test originally also exercised no longer exists --
    // D1, see DAA_rBits_Native_Redesign.md)
    #[test]
    fn tl21_commitment_unchanged_by_non_preimage_fields() {
        use crate::common::blocks::beacon_block::calculate_commitment_hash_from_parts;
        let cand = make_candidate(50);
        let original_commitment = cand.calculate_commitment_hash();

        let mut modified = cand.clone();
        modified.prev_mmr_root.0[0] ^= 1;
        assert_eq!(
            original_commitment, modified.calculate_commitment_hash(),
            "TL-21: prev_mmr_root must NOT affect commitment_hash",
        );

        let mut modified2 = cand.clone();
        modified2.legacy_linear_cumulative_difficulty += 1;
        assert_eq!(
            original_commitment, modified2.calculate_commitment_hash(),
            "TL-21: legacy_linear_cumulative_difficulty must NOT affect commitment_hash",
        );

        // Confirm via free function too
        let via_parts = calculate_commitment_hash_from_parts(
            cand.height, cand.tx_merkle_root, cand.merged_mining_root,
        );
        assert_eq!(original_commitment, via_parts, "TL-21: method and free fn must agree");
    }

    // TL-22: calculate_commitment_hash_from_parts produces same result as calculate_commitment_hash
    #[test]
    fn tl22_from_parts_matches_method() {
        use crate::common::blocks::beacon_block::calculate_commitment_hash_from_parts;
        let cand = make_candidate(33);
        let via_method = cand.calculate_commitment_hash();
        let via_parts  = calculate_commitment_hash_from_parts(
            cand.height, cand.tx_merkle_root, cand.merged_mining_root,
        );
        assert_eq!(via_method, via_parts);
    }
}
