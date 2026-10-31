// beacon_block.rs - UPDATED with transactions and UTXO support
//
// CHANGES FROM PREVIOUS VERSION (legacy_linear_cumulative_difficulty tracking):
// 1. Added `transactions: Vec<Transaction>` field to BeaconBlock
//      - #[serde(default)] preserves backward-compat with v1/v2 storage
//      - Empty for blocks created with BeaconBlock::new() (header-only path)
// 2. Added BeaconBlock::with_transactions(header, transactions) constructor
// 3. (removed VF-3) BeaconBlock::calculate_merkle_root — use ShardBlockBody::calculate_tx_merkle_root
//      - Uses common::crypto::merkle_hash: leaf=txid identity, internal=SHA256(l||r)
// 4. Added BeaconBlock::verify_transactions(&self, fork_utxo_overlay) -> bool
// 5. Added BeaconBlock::size(&self) -> usize
//      - Returns self.serialize().len(); used by BeaconOrphanPool
// 6. Updated BeaconBlock::serialize() to v3 format
//      - Appends tx_count (u32 LE) + length-prefixed transactions
//      - Fully backward-compatible: v1/v2 blocks round-trip unchanged
// 7. Updated BeaconBlock::deserialize() to handle v3 transactions
//      - Three-format dispatch: v1 (228 B), v2 (244 B), v3 (248+ B)
// 8. Added imports: log::debug, crate::transaction::Transaction,
//      crate::utxo::ForkUtxoOverlay
//
// CHANGES FROM ORIGINAL (legacy_linear_cumulative_difficulty — kept intact):
// 1. Added legacy_linear_cumulative_difficulty field to BeaconBlockCandidateHeader
// 2. Updated constructor to initialize legacy_linear_cumulative_difficulty = 0
// 3. Added accessor method BeaconBlock::legacy_linear_cumulative_difficulty()
// 4. Updated header serialization to include legacy_linear_cumulative_difficulty

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use log::debug;

use crate::transaction::Transaction;
use crate::common::blocks::shard_block::ShardBlockBody;
use crate::common::utxo::ForkUtxoOverlay;
use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::crypto::{merkle_leaf_hash, merkle_hash_pair, MerkleHash, MERKLE_HASH_BYTES};

/// Beacon block candidate header - full template for job generation
/// 
/// TEMPLATE STAGE: Before PoW
/// 
/// This is the complete beacon block template that:
/// - Contains all fields needed for mining
/// - Gets embedded in MiningJob via job cache
/// - Includes merged_mining_root for coordinated mining
/// - Has its own difficulty (beacon chain difficulty)
/// 
/// TWO-LEVEL POW HASH ARCHITECTURE:
///
/// Level 1 (Consensus Commitment):
///   commitment_hash = Blake3(height, merkle_root, merged_mining_root)
///   (prev_mmr_root and difficulty are omitted — already in the mining header;
///    Blake3 is used here for speed; SHA256d is only needed for the outer PoW)
///
/// Level 2 (Bitcoin-Compatible Mining Header):
///   80-byte header = [version, prev_mmr_root, commitment_hash,
///                     timestamp, bits, nonce]
///   pow_hash = SHA256d(80-byte header)
///
/// W3-1: prev_mmr_root is now at bytes 4-35 of the mining header (was
/// prev_block_hash).  prev_block_hash is demoted to bottom-level storage
/// in serialize() and will be removed in Wave 5.
///
/// This ensures:
/// - ALL consensus fields are covered by PoW
/// - Perfect Bitcoin/Stratum compatibility
/// - Easy extensibility for future fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBlockCandidateHeader {
    /// Block version
    pub version: u32,

    /// Block timestamp delta (relative to bitcoin_anchor_timestamp)
    ///
    /// Units: 1/256 second. Computed as:
    ///   delta = ((timestamp - bitcoin_anchor_timestamp) * 256) as i32
    ///
    /// Allows reconstruction of wall-clock time via:
    ///   timestamp = bitcoin_anchor_timestamp + (delta as i64 / 256)
    pub delta: i32,

    /// Block height
    pub height: u32,

    /// Compact **rBits** work field (difficulty encoding) — formerly nBits target.
    ///
    /// Same 4-byte mining-preimage slot at offset 72–76. Semantics (Jul 20, 2026):
    /// compact difficulty for MMR leaf copy + Strategy A PoW expand via
    /// `rbits_to_target(bits, initial_target, asserted_s)`. Firmware treats the
    /// slot as opaque; Stratum share difficulty stays separate nBits/target.
    pub bits: u32,
    
    /// Previous MMR root (state before this block)
    pub prev_mmr_root: WeightedHash,
    
    /// Current MMR root (state after this block)
    /// 
    /// CRITICAL: This field is NOT included in block hash calculation!
    /// It's calculated FROM the block hash, so including it would create
    /// a circular dependency. See serialize_for_hash() for details.
    pub current_mmr_root: WeightedHash,
    
    /// Merkle root of beacon block body transactions (BLAKE3-based; FV-BCN).
    pub tx_merkle_root: [u8; 32],
    
    /// Merged mining root - root of merged mining tree
    /// This is what coordinates mining across all shards
    pub merged_mining_root: [u8; 32],
    
    /// Nonce (will be set by miner during PoW)
    pub nonce: u64,
    
    /// Legacy **linear** cumulative difficulty (Bitcoin-style scalar sum).
    ///
    /// **Not** MMR peak-bagged chain weight (Anti-Pattern CWL-1). Fork choice
    /// uses `WeightedMMR::canonical_chain_weight()` / side-block pool entries
    /// stamped from the MMR append path; **never** this field alone.
    ///
    /// **No longer on the wire** (redirected, Jul 2026): every real append
    /// path (`beacon_chain.rs`, `full_beacon_chain.rs`,
    /// `beacon_reorganization.rs::store_side_block`) already overwrote
    /// whatever value arrived on the wire with the locally-derived canonical
    /// MMR weight before anything read it back, and the field was already
    /// excluded from `serialize_for_hash()` — so the wire bytes were dead
    /// weight. `serialize()`/`deserialize()` no longer read or write this
    /// field; it always starts at 0 on decode and is re-stamped by the
    /// receiver's own append path immediately afterward, exactly as it
    /// already was for every value that arrived on the wire regardless of
    /// what that value happened to be.
    #[serde(default)]
    pub legacy_linear_cumulative_difficulty: u128,

    /// Number of non-null leaves in the merged-mining tree this block commits to.
    ///
    /// Set by the job generator to the count of active shard chains included in
    /// the merged-mining tree.  Included in `calculate_commitment_hash()` so it
    /// is PoW-protected — miners cannot alter it after the nonce search.
    ///
    /// CONSENSUS RULE EX-7:  `committed_chain_count ≤ active_shard_count + step`
    ///                        (no phantom chains)
    /// CONSENSUS RULE EX-8:  if `vote_expand_flag() == 1` then
    ///                        `committed_chain_count ≥ active_shard_count`
    ///                        (vote integrity — voter must mine all live chains)
    /// CONSENSUS RULE EX-7b: checked in `verify_shard_id_and_mmn` — the shard
    ///                        proof's own `active_count` must equal this field.
    ///
    /// `#[serde(default)]` for backward compatibility with stored blocks that
    /// predate this field (treated as 0 → EX-7/EX-8/EX-7b not enforced for old blocks).
    #[serde(default)]
    pub committed_chain_count: u16,

}

/// Compute the Level-1 commitment hash from its three preimage fields.
///
/// `commitment_hash = Blake3(height_le32 || merkle_root || merged_mining_root)`
///
/// **Why Blake3 instead of SHA256d?**  This hash is only a payload value placed
/// in the Bitcoin-compatible mining header's "merkle root" slot (bytes [36..68]).
/// It is NOT the PoW hash — the PoW hash is still `SHA256d(80-byte header)`.
/// SHA256d is only required for the outer PoW to preserve Bitcoin ASIC
/// compatibility.  For the commitment itself, Blake3 is:
/// - ~5× faster than SHA256 on x86-64 (SIMD-accelerated)
/// - Cryptographically sound for a commitment / binding hash
/// - Already used by this codebase for internal MMR nodes
///
/// Only the fields **not** already directly present in the 80-byte mining
/// header are included.  `prev_mmr_root` is at bytes [4..36] of the mining
/// header and is already covered by PoW.  `difficulty` is the decoded form
/// of `bits` at bytes [72..76] — including both would be redundant.
///
/// Used by:
/// - `BeaconBlockCandidateHeader::calculate_commitment_hash`
/// - `shard_block::BeaconHeader::serialize_for_mining` (shard PoW verification)
/// - `WireBeaconHeader::commitment_hash` (receiver-side reconstruction)
pub fn calculate_commitment_hash_from_parts(
    height: u32,
    tx_merkle_root: [u8; 32],
    merged_mining_root: [u8; 32],
) -> [u8; 32] {
    calculate_commitment_hash_from_parts_v2(height, tx_merkle_root, merged_mining_root, 0)
}

/// Extended commitment hash that also commits to `committed_chain_count`.
///
/// Replaces `calculate_commitment_hash_from_parts` for new blocks.  Old blocks
/// set `committed_chain_count = 0` (via `#[serde(default)]`) and therefore hash
/// identically to the original function — backward compatible.
pub fn calculate_commitment_hash_from_parts_v2(
    height: u32,
    tx_merkle_root: [u8; 32],
    merged_mining_root: [u8; 32],
    committed_chain_count: u16,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(&tx_merkle_root);
    hasher.update(&merged_mining_root);
    hasher.update(&committed_chain_count.to_le_bytes());
    hasher.finalize().into()
}

/// The "aux" leaf (`Stratum_Extranonce_Binding_Plan.md` §3.1): everything about
/// a candidate block that isn't the coinbase. Deliberately excludes
/// `tx_merkle_root` — today that field is entirely a function of the coinbase
/// alone (beacon carries exactly one transaction), so folding it in here would
/// double-commit the same content `coinbase_hash` already covers. See the
/// plan's §3.5 for the caveat if beacon ever gains non-coinbase transactions.
pub fn calculate_aux_hash(
    height: u32,
    merged_mining_root: [u8; 32],
    committed_chain_count: u16,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(&merged_mining_root);
    hasher.update(&committed_chain_count.to_le_bytes());
    hasher.finalize().into()
}

/// **New commitment formula (§3.1) — not yet activated, see the plan's
/// critical finding in §7.** A genuine two-leaf SHA256d Merkle tree: leaf 0 is
/// `coinbase_hash` (`SHA256d` over the dedicated Bitcoin-shaped mining bytes,
/// `crate::transaction::coinbase_hash`/`coinbase_hash_from_stored_body` —
/// CB-9), leaf 1 is [`calculate_aux_hash`]'s BLAKE3 bundle, combined the way
/// Bitcoin combines any merkle node: `SHA256d(left ‖ right)`. This makes the
/// coinbase-climb step a real ASIC/Stratum-V1 client would perform genuinely
/// reproducible with only SHA256d — unlike `calculate_commitment_hash_from_parts_v2`
/// (kept unchanged above, still used by the currently-live path and its own
/// characterization tests in `tests/unit/beacon_block_two_level_tests.rs`).
///
/// Once activated (CB-4/CB-5/CB-6/CB-7/CB-9 land together), this is the
/// function `BeaconBlockCandidateHeader::calculate_commitment_hash`,
/// `shard_block::BeaconHeader::serialize_for_mining`, and
/// `WireBeaconHeader::commitment_hash` all need to call instead of
/// `calculate_commitment_hash_from_parts_v2` — not done yet, since that swap
/// must happen in the same change as the wire/worker updates (see the plan's
/// §7 critical finding).
pub fn calculate_commitment_hash_from_coinbase(
    height: u32,
    coinbase_hash: [u8; 32],
    merged_mining_root: [u8; 32],
    committed_chain_count: u16,
) -> [u8; 32] {
    let aux_hash = calculate_aux_hash(height, merged_mining_root, committed_chain_count);
    let mut preimage = [0u8; 64];
    preimage[0..32].copy_from_slice(&coinbase_hash);
    preimage[32..64].copy_from_slice(&aux_hash);
    crate::common::crypto::sha256d(&preimage)
}

#[cfg(test)]
mod commitment_hash_v3_tests {
    use super::*;

    #[test]
    fn different_coinbase_hash_changes_commitment() {
        let c1 = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xAA; 32], 3);
        let c2 = calculate_commitment_hash_from_coinbase(10, [0x02; 32], [0xAA; 32], 3);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_aux_inputs_change_commitment() {
        let base = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xAA; 32], 3);
        let diff_height = calculate_commitment_hash_from_coinbase(11, [0x01; 32], [0xAA; 32], 3);
        let diff_mmr = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xBB; 32], 3);
        let diff_count = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xAA; 32], 4);
        assert_ne!(base, diff_height);
        assert_ne!(base, diff_mmr);
        assert_ne!(base, diff_count);
    }

    #[test]
    fn deterministic() {
        let a = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xAA; 32], 3);
        let b = calculate_commitment_hash_from_coinbase(10, [0x01; 32], [0xAA; 32], 3);
        assert_eq!(a, b);
    }

    #[test]
    fn aux_hash_excludes_coinbase_content() {
        // Same aux inputs, different coinbase_hash — aux_hash itself must be
        // identical (only the final commitment differs), since aux_hash has
        // no coinbase_hash parameter at all.
        let aux = calculate_aux_hash(10, [0xAA; 32], 3);
        let aux_again = calculate_aux_hash(10, [0xAA; 32], 3);
        assert_eq!(aux, aux_again);
    }
}

impl BeaconBlockCandidateHeader {
    /// Create a new beacon block candidate header
    /// 
    /// RULE 1: Incoming block candidate has legacy_linear_cumulative_difficulty = 0
    /// 
    /// This creates a template for mining. The cumulative difficulty will be
    /// calculated and set when the block is appended to the chain, based on
    /// its parent's cumulative difficulty.
    /// 
    /// # Arguments
    /// * `version` - Protocol version number
    /// * `timestamp` - Block creation time (Unix seconds)
    /// * `height` - Block position in chain (genesis = 0)
    /// * `bits` - Compact **rBits** work field (the sole authoritative
    ///   difficulty encoding — D1 retired the parallel `difficulty: u64` lane)
    /// * `prev_mmr_root` - MMR state before this block
    /// * `merkle_root` - Root of transaction merkle tree
    /// * `merged_mining_root` - Root of merged mining tree
    ///
    /// # Returns
    /// New header with legacy_linear_cumulative_difficulty = 0 (to be calculated later).
    ///
    /// Accepts Unix seconds timestamp and bitcoin_anchor_timestamp, computes delta internally.
    ///
    /// `delta` is the block's *deviation* from its expected arrival time
    /// `bitcoin_anchor_timestamp + height * BEACON_INTERVAL_SECS`, in 1/256-second
    /// units — not a raw offset from the anchor. This matches the model the T-1
    /// and T-MTP validation rules are written against (see
    /// `crates/common-types/src/common/validation/beacon.rs`).
    ///
    /// Fixed 2026-07-04: prior to this, `height` was accepted but not used in the
    /// delta formula, so `delta` was actually a pure offset from the anchor
    /// (growing linearly with height) rather than a small deviation around zero.
    /// That mismatch made the T-1/T-MTP rules' `- I_block × 256` slack term
    /// weaker than intended — see `docs/reports/TS-DELTA_Final_Completion_Report.md` §5.
    pub fn new(
        version: u32,
        timestamp: u64,
        height: u32,
        bits: u32,
        prev_mmr_root: WeightedHash,
        tx_merkle_root: [u8; 32],
        merged_mining_root: [u8; 32],
        bitcoin_anchor_timestamp: u64,
    ) -> Self {
        Self::new_with_subsec(
            version, timestamp, 0, height, bits, prev_mmr_root, tx_merkle_root,
            merged_mining_root, bitcoin_anchor_timestamp,
        )
    }

    /// Same as [`Self::new`], but additionally accepts the sub-second
    /// remainder of the real timestamp used to build this template, in
    /// 1/256-second units (`0..256`).
    ///
    /// `delta` is designed with 1/256s (~3.9ms) resolution, but `new()`'s
    /// whole-seconds-only `timestamp` always produces a `delta` that's an
    /// exact multiple of 256, discarding that resolution entirely. Under
    /// real, fast block production (multiple blocks per wall-clock second —
    /// confirmed live via an E3/GHA soak with real 2-thread hashing at a
    /// tiny window), two blocks separated by exactly `adjustment_window_blocks`
    /// heights, built within the same whole second, reconstruct to
    /// numerically *identical* `delta_to_unix` timestamps: the real-elapsed
    /// component is zero (same second) and the height-term's scheduled
    /// advance cancels exactly against `unix_to_delta`'s own height-scaled
    /// subtraction. `adjust_with_chain_weight`'s `InvalidTimespan` check
    /// (`tip_timestamp <= prev_tip_timestamp`) then permanently rejects the
    /// DAA retarget — not from noise or a race, but a deterministic
    /// mathematical tie caused by throwing away real sub-second ordering
    /// information that was available all along. Callers building a
    /// template from a live `SystemTime::now()` read should use this
    /// constructor and pass the real subsecond remainder instead of `new()`.
    pub fn new_with_subsec(
        version: u32,
        timestamp: u64,
        subsec_256ths: u16,
        height: u32,
        bits: u32,
        prev_mmr_root: WeightedHash,
        tx_merkle_root: [u8; 32],
        merged_mining_root: [u8; 32],
        bitcoin_anchor_timestamp: u64,
    ) -> Self {
        // Expected arrival schedule uses the active beacon interval (default 600 s).
        let beacon_secs = crate::common::block_intervals::beacon_interval_secs();
        let beacon_interval_delta_units =
            (beacon_secs as i64).saturating_mul(256);
        let expected_delta_units = (height as i64) * beacon_interval_delta_units;
        let raw_delta_units = (timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256
            + subsec_256ths as i64;
        // Clamp before narrowing: a naive `as i32` truncates on overflow and produces
        // wildly wrong deltas (e.g. future genesis anchor → negative MTP failures).
        let delta_units = raw_delta_units - expected_delta_units;
        let delta = delta_units.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        Self {
            version,
            delta,
            height,
            bits,
            prev_mmr_root,
            current_mmr_root: WeightedHash::zero(),
            tx_merkle_root,
            merged_mining_root,
            nonce: 0,
            legacy_linear_cumulative_difficulty: 0,
            committed_chain_count: 0,
        }
    }

    /// Calculate the beacon template hash for tracking and caching
    /// 
    /// Hash is calculated from:
    /// - version
    /// - timestamp
    /// - prev_mmr_root
    /// - current_mmr_root
    /// - merkle_root
    /// - merged_mining_root
    /// - bits (beacon chain difficulty)
    /// - merged_mining_number (from root subtask)
    /// - orange_tree_encoding (from root subtask)
    /// - k_coefficient (from reward config)
    /// - vote_k_coefficient (same as k_coefficient for now)
    /// 
    /// This hash uniquely identifies a template configuration and is used
    /// for cache lookups to avoid regenerating identical templates.
    /// 
    /// # Arguments
    /// * `merged_mining_number` - Number of active shards in merged mining tree
    /// * `orange_encoding` - Orange tree encoding string
    /// * `k_coefficient` - Reward distribution coefficient
    /// 
    /// # Returns
    /// Hex-encoded SHA256d hash of template configuration
    pub fn calculate_template_hash(
        &self,
        merged_mining_number: u32,
        orange_encoding: &str,
        k_coefficient: f64,
    ) -> String {
        let mut hasher = Sha256::new();
        
        // Add version
        hasher.update(self.version.to_le_bytes());

        // Add timestamp delta
        hasher.update(self.delta.to_le_bytes());
        
        hasher.update(&self.prev_mmr_root);
        hasher.update(&self.current_mmr_root);
        
        // Add merkle_root
        hasher.update(&self.tx_merkle_root);
        
        // Add merged_mining_root
        hasher.update(&self.merged_mining_root);
        
        // Add bits
        hasher.update(self.bits.to_le_bytes());
        
        // Add merged_mining_number
        hasher.update(merged_mining_number.to_le_bytes());
        
        // Add orange_tree_encoding
        hasher.update(orange_encoding.as_bytes());
        
        // Add k_coefficient
        hasher.update(k_coefficient.to_le_bytes());
        
        // Add vote_k_coefficient (same as k_coefficient for now)
        hasher.update(k_coefficient.to_le_bytes());
        
        // Double hash (SHA256d)
        let first_hash = hasher.finalize();
        let final_hash = Sha256::digest(first_hash);
        
        hex::encode(final_hash)
    }
    
    /// Calculate Level 1 commitment hash (Shisha consensus fields).
    ///
    /// TWO-LEVEL POW ARCHITECTURE — LEVEL 1
    ///
    /// The commitment covers the three fields that are NOT already directly
    /// present in the 80-byte mining header:
    ///
    /// | Field              | Rationale |
    /// |--------------------|-----------|
    /// | `height`           | Not in mining header; needed to anchor the block |
    /// | `merkle_root`      | Beacon tx Merkle root; hidden inside commitment |
    /// | `merged_mining_root` | Shard coordination root; hidden inside commitment |
    ///
    /// Fields already in the mining header (committed by PoW — not repeated):
    /// - `prev_mmr_root`  at bytes [4..36]
    /// - `bits` (nBits)   at bytes [72..76]
    /// - `difficulty` is the decoded form of `bits` — including both would be
    ///   redundant and risks a precision inconsistency (nBits is lossy).
    ///
    /// Returns: 32-byte Blake3 of (height LE || merkle_root || merged_mining_root || chain_count).
    pub fn calculate_commitment_hash(&self) -> [u8; 32] {
        calculate_commitment_hash_from_parts_v2(
            self.height,
            self.tx_merkle_root,
            self.merged_mining_root,
            self.committed_chain_count,
        )
    }
    
    /// Serialize to 80-byte Bitcoin block header format for mining
    ///
    /// TWO-LEVEL POW ARCHITECTURE - LEVEL 2
    ///
    /// Standard Bitcoin header format:
    /// - version (4 bytes)
    /// - prev_mmr_root (32 bytes)  ← W3-1: was prev_block_hash; MMR root is now
    ///                                      the canonical chain-linkage field
    /// - commitment_hash (32 bytes) ← Level 1 hash goes here!
    /// - timestamp (4 bytes)
    /// - bits (4 bytes)
    /// - nonce (4 bytes)
    ///
    /// The commitment_hash (Level 1) is placed where Bitcoin's merkle_root
    /// normally goes. This means:
    /// 1. All Shisha consensus fields (in Level 1) are covered by PoW
    /// 2. Miners see a standard 80-byte Bitcoin header
    /// 3. Stratum protocol works unchanged
    /// 4. Perfect Bitcoin compatibility
    ///
    /// prev_block_hash is now a bottom-level field (stored in serialize() but
    /// NOT committed by PoW).  It will be removed entirely in Wave 5.
    ///
    /// Mining Process:
    /// 1. Pool calculates commitment_hash from consensus fields
    /// 2. Pool builds 80-byte header with commitment_hash
    /// 3. Miners hash this header billions of times (standard PoW)
    /// 4. When solution found, block is valid because:
    ///    - PoW covers the 80-byte header
    ///    - Header includes commitment_hash
    ///    - commitment_hash covers all consensus fields
    ///    → All fields are protected by PoW!
    ///
    /// # Returns
    /// 80-byte serialized header suitable for Bitcoin ASICs
    pub fn serialize_for_mining(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(80);

        // Calculate Level 1 commitment hash
        let commitment_hash = self.calculate_commitment_hash();

        // Version (4 bytes, little-endian)
        header.extend_from_slice(&self.version.to_le_bytes());

        // Previous MMR root (32 bytes) — W3-1: replaces prev_block_hash in PoW slot.
        // prev_block_hash is demoted to bottom-level storage (serialize()) and will
        // be removed in Wave 5 once all consumers are migrated.
        header.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));

        // Commitment hash (32 bytes) - Level 1 hash!
        // This replaces Bitcoin's merkle_root position
        // All Shisha consensus fields are committed here
        header.extend_from_slice(&commitment_hash);

        // Timestamp delta (4 bytes, little-endian)
        // Delta is i32 (1/256-second units relative to bitcoin_anchor_timestamp)
        // Serializes directly as 4-byte little-endian signed integer
        header.extend_from_slice(&self.delta.to_le_bytes());

        // Bits (4 bytes, little-endian)
        header.extend_from_slice(&self.bits.to_le_bytes());

        // Nonce (4 bytes, little-endian)
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());

        assert_eq!(header.len(), 80, "Bitcoin header must be exactly 80 bytes");
        header
    }

    /// **Live mining path (`Stratum_Extranonce_Binding_Plan.md` §3.1).**
    /// Two-leaf SHA256d commitment: `SHA256d(coinbase_hash ‖ aux_hash)`,
    /// where `aux_hash = BLAKE3(height ‖ merged_mining_root ‖
    /// committed_chain_count)` (`calculate_aux_hash`). `coinbase_hash` is not
    /// a field on this struct — the header alone doesn't carry the coinbase
    /// body — so it's a parameter here, computed by the caller via CB-9
    /// (`crate::transaction::coinbase_hash`/`coinbase_hash_from_stored_body`).
    ///
    /// Kept as a separate method (not a change to [`Self::calculate_commitment_hash`])
    /// so the old BLAKE3-wrap formula and its direct characterization tests
    /// (`tests/unit/beacon_block_two_level_tests.rs`) stay intact — this is
    /// the one real mining/pool/worker path callers should use going forward.
    pub fn calculate_commitment_hash_v3(&self, coinbase_hash: [u8; 32]) -> [u8; 32] {
        calculate_commitment_hash_from_coinbase(
            self.height,
            coinbase_hash,
            self.merged_mining_root,
            self.committed_chain_count,
        )
    }

    /// **Live mining path.** Same 80-byte layout as [`Self::serialize_for_mining`]
    /// (plan §1.1 — the header format itself never changed), but the
    /// commitment slot is filled via [`Self::calculate_commitment_hash_v3`]
    /// instead of the legacy BLAKE3-wrap. This is what `share_validator.rs`/
    /// `share_processor.rs` (pool) and `tools/stratum-worker` (miner) both
    /// hash for PoW — see the plan's §7 for the activation this method is
    /// part of.
    pub fn serialize_for_mining_v3(&self, coinbase_hash: [u8; 32]) -> Vec<u8> {
        let mut header = Vec::with_capacity(80);
        let commitment_hash = self.calculate_commitment_hash_v3(coinbase_hash);

        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        header.extend_from_slice(&commitment_hash);
        header.extend_from_slice(&self.delta.to_le_bytes());
        header.extend_from_slice(&self.bits.to_le_bytes());
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());

        assert_eq!(header.len(), 80, "Bitcoin header must be exactly 80 bytes");
        header
    }

    /// Serialize complete header for storage and P2P transmission.
    ///
    /// Format (182 bytes — Jul 2026: shrunk from 206; `difficulty`/
    /// `legacy_linear_cumulative_difficulty` dropped, see the redirect note
    /// on `legacy_linear_cumulative_difficulty`'s struct-field doc comment
    /// and the removed `difficulty: u64` field's own history):
    ///
    /// | Offset | Size | Field                  |
    /// |--------|------|------------------------|
    /// | 0      | 80   | mining header (serialize_for_mining) |
    /// | 80     | 32   | current_mmr_root       |
    /// | 112    | 4    | height (u32 LE)        |
    /// | 116    | 32   | merkle_root            |
    /// | 148    | 32   | merged_mining_root     |
    /// | 180    | 2    | committed_chain_count (u16 LE) |
    ///
    /// `prev_mmr_root` is NOT duplicated here — it is already at bytes [4..36]
    /// of the mining header and need not be stored twice.
    ///
    /// `merkle_root` and `merged_mining_root` are appended at the end so that
    /// `build_beacon_header_bytes` can construct a [`WireBeaconHeader`] (148
    /// bytes) from the raw byte slice without deserializing the full struct.
    /// **Any caller reading fixed offsets into this buffer must be updated
    /// alongside this format change** — see `build_beacon_header_bytes`.
    ///
    /// `committed_chain_count` (added after the table above was originally
    /// written) was previously omitted entirely — `WireBeaconHeader::
    /// from_block_payload` silently reconstructed it as 0 regardless of the
    /// real value, corrupting `calculate_commitment_hash()` (and therefore
    /// the PoW hash) for any block that actually set this field (CV-62's
    /// job-generator stamping). See `BeaconBlock::serialize()`'s own doc
    /// comment for the sibling fix in the full block wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(182);

        // [0..80]: 80-byte PoW mining header
        bytes.extend_from_slice(&self.serialize_for_mining());

        // [80..112]: current_mmr_root (state after this block)
        bytes.extend_from_slice(&<[u8; 32]>::from(self.current_mmr_root));

        // [112..116]: height
        bytes.extend_from_slice(&self.height.to_le_bytes());

        // [116..148]: tx_merkle_root (beacon body Merkle root; Level-1 preimage)
        bytes.extend_from_slice(&self.tx_merkle_root);

        // [148..180]: merged_mining_root (shard coordination root; Level-1 preimage)
        bytes.extend_from_slice(&self.merged_mining_root);

        // [180..182]: committed_chain_count (Level-1 preimage; CV-62)
        bytes.extend_from_slice(&self.committed_chain_count.to_le_bytes());

        bytes
    }
    
    /// Serialize header for hash calculation (EXCLUDES current_mmr_root)
    /// 
    /// CRITICAL: This method excludes current_mmr_root from serialization.
    /// 
    /// WHY: current_mmr_root is calculated by appending the block hash to the MMR:
    ///      current_mmr_root = MMR.append(block_hash)
    /// 
    /// If block_hash included current_mmr_root in its calculation, we'd have:
    ///      block_hash = SHA256d(serialize(header including current_mmr_root))
    ///      current_mmr_root = MMR.append(block_hash)
    ///      → CIRCULAR DEPENDENCY!
    /// 
    /// SOLUTION: Exclude current_mmr_root from hash calculation.
    /// 
    /// The block hash represents the block's IDENTITY based on its content.
    /// The current_mmr_root is METADATA about where the block sits in the chain.
    /// These are conceptually separate concerns.
    /// 
    /// WORKFLOW:
    /// 1. Create header with placeholder current_mmr_root
    /// 2. Calculate hash using serialize_for_hash() (excludes current_mmr_root)
    /// 3. Append hash to MMR to get current_mmr_root
    /// 4. Update header.current_mmr_root
    /// 5. Hash remains unchanged (it didn't include current_mmr_root)
    /// 
    /// This is similar to Bitcoin's SegWit pattern where witness data
    /// is excluded from transaction ID calculation.
    /// 
    /// NOTE: legacy_linear_cumulative_difficulty is also excluded for the same reason -
    /// it's metadata derived from chain structure, not block content.
    /// 
    /// # Returns
    /// Serialized header for hash calculation (excludes current_mmr_root and legacy_linear_cumulative_difficulty)
    pub fn serialize_for_hash(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Core mining header (80 bytes)
        bytes.extend_from_slice(&self.serialize_for_mining());
        
        // Add prev_mmr_root (IS part of block identity)
        bytes.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        
        // CRITICAL: Skip current_mmr_root for hash calculation
        // It's derived FROM the hash, so can't be IN the hash
        
        // Add height as u32 (4 bytes)
        bytes.extend_from_slice(&self.height.to_le_bytes());

        // `difficulty: u64` was removed from the header entirely (Jul 2026,
        // D1) -- it used to be added here (8 bytes). `bits` (compact rBits,
        // already covered by `serialize_for_mining()` above) is the sole
        // authoritative work field; this preimage is 8 bytes shorter as a
        // result, changing this function's output for every caller.

        // CRITICAL: Skip legacy_linear_cumulative_difficulty for hash calculation
        // It's derived from chain structure (canonical MMR weight), not block content

        bytes
    }
    
    /// Verify that the commitment hash in the mining header is correct
    /// 
    /// This validates that the Level 1 commitment properly covers all
    /// consensus fields. Used during block validation.
    /// 
    /// Process:
    /// 1. Recalculate expected commitment from consensus fields
    /// 2. Extract actual commitment from bytes 36-67 of mining header
    /// 3. Compare: expected == actual
    /// 
    /// Returns: true if commitment is valid, false otherwise
    pub fn verify_commitment_hash(&self) -> bool {
        // Calculate expected commitment
        let expected_commitment = self.calculate_commitment_hash();

        // Extract commitment from 80-byte mining header
        let serialized = self.serialize_for_mining();
        let actual_commitment = &serialized[36..68]; // Bytes 36-67 (merkle_root position)

        expected_commitment == actual_commitment
    }

    /// [`Self::verify_commitment_hash`]'s v3 twin (plan §3.1) — same
    /// tautological self-consistency check, against `calculate_commitment_hash_v3`
    /// / `serialize_for_mining_v3` instead.
    pub fn verify_commitment_hash_v3(&self, coinbase_hash: [u8; 32]) -> bool {
        let expected_commitment = self.calculate_commitment_hash_v3(coinbase_hash);
        let serialized = self.serialize_for_mining_v3(coinbase_hash);
        let actual_commitment = &serialized[36..68];
        expected_commitment == actual_commitment
    }
}

#[cfg(test)]
mod new_with_subsec_tests {
    use super::*;

    fn header(height: u32, timestamp: u64, subsec_256ths: u16) -> BeaconBlockCandidateHeader {
        BeaconBlockCandidateHeader::new_with_subsec(
            1, timestamp, subsec_256ths, height, 0x03000004,
            WeightedHash::zero(), [0u8; 32], [0u8; 32], /* bitcoin_anchor_timestamp */ 1_000_000,
        )
    }

    /// `new()` (subsec=0) is byte-for-byte equivalent to `new_with_subsec`
    /// with a zero fraction — no behavior change for any existing caller.
    #[test]
    fn new_matches_new_with_subsec_zero() {
        let a = BeaconBlockCandidateHeader::new(
            1, 1_000_100, 5, 0x03000004, WeightedHash::zero(), [0u8; 32], [0u8; 32], 1_000_000,
        );
        let b = header(5, 1_000_100, 0);
        assert_eq!(a.delta, b.delta);
    }

    /// Core precision property the fix depends on: for a FIXED height and
    /// whole-second timestamp (i.e. two templates built within the same
    /// wall-clock second, which is exactly what happens under fast real
    /// block production), a larger `subsec_256ths` must always produce a
    /// strictly larger `delta` — the sub-second remainder must genuinely
    /// reach `delta`, not be silently discarded the way `new()` (subsec
    /// hardcoded to 0) always did.
    #[test]
    fn subsec_fraction_is_reflected_in_delta_at_fixed_height_and_second() {
        let same_second = 1_000_100u64;
        let low = header(4, same_second, 10);
        let high = header(4, same_second, 200);
        assert!(
            high.delta > low.delta,
            "high.delta={} low.delta={}", high.delta, low.delta,
        );
        assert_eq!(high.delta - low.delta, 190);
    }

    /// Reproduces the Aug 12, 2026 E3/GHA InvalidTimespan bug directly at
    /// the arithmetic level `adjust_with_chain_weight` actually exercises
    /// (`unix_to_delta`'s own formula, which `new_with_subsec` mirrors):
    /// with `subsec=0` on both sides (the pre-fix `new()` behavior), two
    /// blocks exactly `window` heights apart, built within the identical
    /// whole wall-clock second and with `window × beacon_interval_secs()`
    /// matching the real elapsed time between them, tie *exactly* — the
    /// height-scaled schedule term in the delta formula and the (zero)
    /// real-elapsed component cancel precisely. A nonzero subsec fraction
    /// on the later block breaks that tie deterministically.
    #[test]
    fn window_crossing_tie_is_broken_by_nonzero_subsec() {
        use crate::common::validation::delta_to_unix;
        let beacon_secs = crate::common::block_intervals::beacon_interval_secs();
        let anchor = 1_000_000u64;
        let same_second = anchor + 2 * beacon_secs; // exactly 2 heights' worth of schedule
        let window = 2u32;

        // subsec=0 on both sides (the pre-fix `new()` behavior) reproduces
        // the tie exactly at the `delta_to_unix`-reconstructed level -- the
        // same comparison `adjust_with_chain_weight`'s InvalidTimespan check
        // makes. The raw `delta` fields themselves are NOT expected to be
        // equal (delta is height-relative by design); it's their
        // reconstructed absolute timestamps that tie.
        let h_outsider = header(0, same_second, 0);
        let h_tip = header(window, same_second, 0);
        let ts_outsider = delta_to_unix(h_outsider.delta, anchor, 0, beacon_secs, 1);
        let ts_tip = delta_to_unix(h_tip.delta, anchor, window as u64, beacon_secs, 1);
        assert_eq!(ts_outsider, ts_tip, "expected the pre-fix tie to reproduce exactly");

        // Any nonzero subsec fraction on the later block breaks it.
        let h_tip_fixed = header(window, same_second, 1);
        let ts_tip_fixed = delta_to_unix(h_tip_fixed.delta, anchor, window as u64, beacon_secs, 1);
        assert!(
            ts_tip_fixed >= ts_outsider,
            "ts_tip_fixed={} ts_outsider={}", ts_tip_fixed, ts_outsider,
        );
        assert!(
            h_tip_fixed.delta > h_tip.delta,
            "h_tip_fixed.delta={} h_tip.delta={}", h_tip_fixed.delta, h_tip.delta,
        );
    }
}

// ============================================================================
// BEACON BLOCK - COMPLETED BLOCK WITH PROOF-OF-WORK
// ============================================================================

/// Completed beacon block (after PoW mining)
///
/// Represents a finalized beacon block that has been mined and validated.
/// Contains the complete header with nonce, previous block linkage, hash,
/// and the ordered list of transactions whose merkle root is committed in
/// the header.
///
/// # Structure
/// - `header`       — All consensus fields including `merkle_root` and
///                    `legacy_linear_cumulative_difficulty`.
/// - `hash`         — SHA256d of the 80-byte mining header; PoW identity.
/// - `transactions` — Ordered transactions whose Merkle tree
///                    root equals `header.merkle_root`.  Empty for the
///                    genesis block and for legacy on-disk blocks.
///
/// # Serialization compatibility
///
/// `BeaconBlock::serialize()` / `deserialize()` supports three on-disk formats:
///
/// | Format | Total bytes    | Description                              |
/// |--------|----------------|------------------------------------------|
/// | v1     | 228            | No `legacy_linear_cumulative_difficulty`, no txs       |
/// | v2     | 244            | Added `legacy_linear_cumulative_difficulty`; no txs    |
/// | v3     | 244 + tx data  | Adds `tx_count (u32)` + length-prefixed  |
/// |        |                | serialized transactions                  |
///
/// Old v1/v2 blocks deserialize with `legacy_linear_cumulative_difficulty = 0` and
/// `transactions = vec![]`.  Call `ensure_legacy_linear_cumulative_difficulty()` and
/// replay transactions through the UTXO set during chain load to restore
/// full state.
///
/// # Cumulative difficulty
/// `header.legacy_linear_cumulative_difficulty` is a linear bookkeeping scalar
/// (parent + difficulty). Fork choice uses MMR peak-bagged chain weight — see
/// `WeightedMMR::canonical_chain_weight()` (Anti-Pattern CWL-1).
/// to this block and is used for fork-choice during reorganisations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBlock {
    /// Block header with all consensus data.
    ///
    /// Contains: version, timestamp, height, difficulty, bits, nonce,
    /// prev_block_hash, prev_mmr_root, current_mmr_root, merkle_root
    /// (Merkle root of `transactions`), merged_mining_root,
    /// and legacy_linear_cumulative_difficulty (linear bookkeeping; not fork choice).
    pub header: BeaconBlockCandidateHeader,

    /// Block hash as WeightedHash (BLAKE3-224 of SHA256d + rBits from nBits).
    ///
    /// Cached value computed via `WeightedHash::from_leaf(&sha256d, header.bits, k)`.
    /// The raw SHA256d (for PoW verification) can be recovered by calling
    /// `BeaconBlock::calculate_hash(&self.header)`.
    ///
    /// Does NOT commit to `current_mmr_root` or `legacy_linear_cumulative_difficulty` —
    /// both are derived from chain structure, not block content.
    pub hash: WeightedHash,

    /// Ordered list of transactions included in this block.
    ///
    /// The Merkle root of these transactions (computed via
    /// `common::crypto::merkle_hash`) equals `header.merkle_root`, which
    /// is covered by the Level-1 commitment hash (and therefore by PoW).
    ///
    /// Empty for blocks created with `BeaconBlock::new()` (header-only
    /// constructor) and for legacy blocks loaded from v1/v2 storage.
    /// Use `BeaconBlock::with_transactions()` when building blocks that
    /// carry transactions.
    ///
    /// Flat five-vector block body (FV-BCN).
    ///
    /// `#[serde(default)]` ensures blocks already in storage deserialize
    /// successfully with an empty body.
    #[serde(default)]
    pub body: ShardBlockBody,
}

impl BeaconBlock {
    /// Wire size in bytes: the length of this block's `BeaconWireBlock` encoding, the quantity
    /// the beacon block size limit counts (witnesses included).
    pub fn wire_size(&self) -> usize {
        BeaconWireBlock::from_block(self).encode().len()
    }

    /// Create a new beacon block from a header with an empty transaction list.
    ///
    /// Used by `BeaconBlockGenerator` and tests that do not yet carry
    /// transactions.  The `header.merkle_root` field is expected to be set
    /// to `[0u8; 32]` (or the merkle root of an empty list) by the caller.
    ///
    /// # Arguments
    /// * `header` — Complete beacon block candidate header with nonce set.
    ///
    /// # Returns
    /// New `BeaconBlock` with `transactions = vec![]` and a freshly
    /// calculated hash.
    pub fn new(header: BeaconBlockCandidateHeader) -> Self {
        let hash = Self::calculate_weighted_hash(&header);
        Self { header, hash, body: ShardBlockBody::empty() }
    }

    /// Create a beacon block carrying a set of transactions.
    ///
    /// The caller is responsible for ensuring that `header.merkle_root`
    /// equals `ShardBlockBody::from_transactions(&transactions, None).calculate_tx_merkle_root()` before
    /// calling this constructor; `append_block` will reject the block
    /// otherwise.
    ///
    /// # Arguments
    /// * `header`       — Complete candidate header with `merkle_root` set
    ///                    to the merkle root of `transactions`.
    /// * `transactions` — Ordered transactions for this block.
    ///
    /// # Returns
    /// New `BeaconBlock` with hash calculated from the header.
    pub fn with_transactions(
        header: BeaconBlockCandidateHeader,
        transactions: Vec<Transaction>,
    ) -> Self {
        let hash = Self::calculate_weighted_hash(&header);
        let body = ShardBlockBody::from_transactions(&transactions, None);
        Self { header, hash, body }
    }
    
    /// Legacy linear cumulative difficulty accessor (bookkeeping only — not fork choice).
    pub fn legacy_linear_cumulative_difficulty(&self) -> u128 {
        self.header.legacy_linear_cumulative_difficulty
    }
    
    /// Set cumulative difficulty
    /// 
    /// Used when:
    /// - Appending block to main chain (cumulative = parent.cumulative + difficulty)
    /// - Storing as side block (calculate from parent chain)
    /// - Processing orphan after parent found (now can calculate)
    /// 
    /// # Arguments
    /// * `cumulative` - New cumulative difficulty value
    pub fn set_legacy_linear_cumulative_difficulty(&mut self, cumulative: u128) {
        self.header.legacy_linear_cumulative_difficulty = cumulative;
    }
    
    // ========================================================================
    // Transaction helpers
    // ========================================================================

    /// Verify that every transaction in the block is valid against `fork_utxo_overlay`.
    ///
    /// **Deprecated:** use `validate_shard_block_body` with `BlockValidationUtxo`.
    #[deprecated(
        since = "0.7.0",
        note = "use validate_shard_block_body with BlockValidationUtxo::PositionalDb"
    )]
    pub fn verify_transactions(&self, fork_utxo_overlay: &ForkUtxoOverlay) -> bool {
        use crate::common::validation::transactions::{
            block_validation_utxo, validate_shard_block_body, BlockBodyValidationParams,
        };
        #[cfg(feature = "full-node")]
        let validation_utxo = block_validation_utxo(None, fork_utxo_overlay);
        #[cfg(not(feature = "full-node"))]
        let validation_utxo = block_validation_utxo(fork_utxo_overlay);
        validate_shard_block_body(
            &self.body,
            validation_utxo,
            BlockBodyValidationParams::for_tests(self.header.height as u32, 0),
        )
        .is_ok()
    }

    /// Total serialized size of this block in bytes.
    ///
    /// Equals the length of `self.serialize()`.  Used by
    /// `BeaconOrphanPool` for memory-pressure accounting.
    pub fn size(&self) -> usize {
        self.serialize().len()
    }
    
    /// Calculate block hash (SHA256d of serialized header)
    /// 
    /// Uses Bitcoin-standard double SHA256:
    /// 1. Serialize header to 80 bytes (serialize_for_mining)
    /// 2. SHA256(serialized) -> first_hash
    /// 3. SHA256(first_hash) -> final_hash
    /// 
    /// This is the standard Bitcoin block hash calculation and provides
    /// strong protection against length extension attacks.
    /// 
    /// The hash does NOT include:
    /// - current_mmr_root (calculated FROM the hash)
    /// - legacy_linear_cumulative_difficulty (derived from chain structure)
    /// 
    /// # Arguments
    /// * `header` - Block header to hash
    /// 
    /// # Returns
    /// 32-byte hash suitable for PoW verification and block identification
    /// Calculate beacon block hash as WeightedHash
    ///
    /// Serializes the header, computes SHA256d, and constructs a WeightedHash
    /// that includes both the hash value and difficulty encoded as rBits.
    ///
    /// # Parameters
    /// - `header`: The beacon block header to hash
    /// - `asserted_s_bits`: Genesis **asserted** s-bits for WeightedHash construction
    ///
    /// Process:
    /// 1. Serialize header for mining (80 bytes)
    /// 2. Double SHA256 (Bitcoin standard)
    /// 3. Construct WeightedHash from result and bits
    pub fn calculate_hash(header: &BeaconBlockCandidateHeader) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        // Serialize header for mining (80 bytes)
        let serialized = header.serialize_for_mining();

        // Double SHA256 (Bitcoin standard)
        let first_hash = Sha256::digest(&serialized);
        let second_hash = Sha256::digest(&first_hash);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second_hash);
        hash
    }

    /// **Live mining path** — same as [`Self::calculate_hash`] but hashes
    /// [`BeaconBlockCandidateHeader::serialize_for_mining_v3`]'s output (the
    /// two-leaf SHA256d commitment, plan §3.1) instead of the legacy
    /// BLAKE3-wrap. `coinbase_hash` comes from CB-9.
    pub fn calculate_hash_v3(header: &BeaconBlockCandidateHeader, coinbase_hash: [u8; 32]) -> [u8; 32] {
        crate::common::crypto::sha256d(&header.serialize_for_mining_v3(coinbase_hash))
    }

    /// Compute the canonical MMR-leaf hash (WeightedHash) for this block.
    ///
    /// Uses the pre-computed [`BeaconBlock::hash`] field (no SHA256d re-run) and
    /// `self.header.bits` (nBits), matching the `mmr.append(block.hash, header.bits)`
    /// calls throughout the beacon chain code.
    ///
    /// Prefer this over [`calculate_weighted_hash`](Self::calculate_weighted_hash)
    /// whenever the `BeaconBlock` struct is available — it avoids the double-SHA256
    /// recomputation and is therefore O(1) instead of O(block_size).
    ///
    /// # Returns
    /// `WeightedHash` combining `self.hash` with rBits difficulty encoding.
    /// Return the pre-computed WeightedHash (identical to `self.hash`).
    ///
    /// After the WeightedHash migration, `BeaconBlock::hash` *is* the WeightedHash,
    /// so this method is now a trivial accessor.  It is kept for call-site
    /// compatibility and to document the equivalence.
    pub fn hash_weighted(&self) -> WeightedHash {
        self.hash
    }

    /// Compute the canonical MMR-leaf hash (WeightedHash) for a beacon block header.
    ///
    /// **Note:** If you have the full [`BeaconBlock`] in scope, prefer
    /// [`hash_weighted`](Self::hash_weighted) — it uses the pre-computed
    /// [`BeaconBlock::hash`] field and avoids the double-SHA256 recomputation.
    ///
    /// Uses [`BLOCK_HASH_W_BITS`] (= 4) and `header.bits` (nBits), matching the
    /// `mmr.append(hash, header.bits)` calls throughout the beacon chain code.
    ///
    /// # Parameters
    /// - `header`: The beacon block candidate header to hash
    ///
    /// # Returns
    /// WeightedHash combining the header's BLAKE3-224 hash with rBits encoding
    pub fn calculate_weighted_hash(header: &BeaconBlockCandidateHeader) -> WeightedHash {
        let plain_hash = Self::calculate_hash(header);
        // Header `bits` is compact rBits — copy into the leaf (no nbits_to_rbits).
        WeightedHash::from_leaf_rbits(&plain_hash, header.bits)
    }

    /// [`Self::calculate_weighted_hash`]'s v3 (two-leaf SHA256d, plan §3.1)
    /// twin — used by validators re-deriving `coinbase_hash` from a received
    /// block's own stored body (`crate::transaction::coinbase_hash_from_stored_body`),
    /// not from live session state the way the mining path does.
    pub fn calculate_weighted_hash_v3(
        header: &BeaconBlockCandidateHeader,
        coinbase_hash: [u8; 32],
    ) -> WeightedHash {
        let plain_hash = Self::calculate_hash_v3(header, coinbase_hash);
        WeightedHash::from_leaf_rbits(&plain_hash, header.bits)
    }

    /// Serialize the complete block to bytes for storage and network transmission.
    ///
    /// # Format (Jul 2026 — `difficulty`/`legacy_linear_cumulative_difficulty`
    /// removed/redirected off the wire, shrinking the header-plus-hash prefix
    /// from 208 to 184 bytes; see `BeaconBlockCandidateHeader::serialize()`'s
    /// doc comment and `deserialize()`'s below)
    ///
    /// ```text
    /// Offset  Size   Field
    /// ------  ----   -----
    ///      0     4   version          (u32 LE)
    ///      4     4   delta            (i32 LE)
    ///      8     4   height           (u32 LE)
    ///     12     4   bits             (u32 LE)
    ///     16    32   prev_mmr_root
    ///     48    32   current_mmr_root
    ///     80    32   merkle_root
    ///    112    32   merged_mining_root
    ///    144     8   nonce            (u64 LE)
    ///    152    32   hash
    ///    184     4   tx_count         (u32 LE)   ← tx shape starts here
    ///    188     4   tx_0_len         (u32 LE)
    ///    192   ...   tx_0 bytes
    ///          ...   (repeated for each transaction)
    /// ```
    ///
    /// A trailing 2-byte `committed_chain_count` (u16 LE) is appended after
    /// the flat body. It was previously omitted from the wire format entirely
    /// — `deserialize()` silently reconstructed every block with
    /// `committed_chain_count = 0`, which corrupts `calculate_commitment_hash()`
    /// (and therefore the PoW hash) for any block that actually set this field
    /// (CV-62's job-generator stamping). See `deserialize()`'s own comment for
    /// the failure this caused.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // ── Header fields (152 bytes) ──────────────────────────────────────
        // `difficulty` removed entirely (D1); `legacy_linear_cumulative_difficulty`
        // redirected off the wire (never written — always 0 on decode, see
        // `deserialize()`).
        bytes.extend_from_slice(&self.header.version.to_le_bytes());
        bytes.extend_from_slice(&self.header.delta.to_le_bytes());
        bytes.extend_from_slice(&self.header.height.to_le_bytes());
        bytes.extend_from_slice(&self.header.bits.to_le_bytes());
        bytes.extend_from_slice(&<[u8; 32]>::from(self.header.prev_mmr_root));
        bytes.extend_from_slice(&<[u8; 32]>::from(self.header.current_mmr_root));
        bytes.extend_from_slice(&self.header.tx_merkle_root);
        bytes.extend_from_slice(&self.header.merged_mining_root);
        bytes.extend_from_slice(&self.header.nonce.to_le_bytes());

        // ── Block hash (32 bytes) ──────────────────────────────────────────
        bytes.extend_from_slice(&*self.hash);

        // ── Body (v5 flat format) ──────────────────────────────────────────
        // Sentinel 0xFFFF_FFFF distinguishes v5 from old v4 tx_count.
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let body_bytes = self.body.serialize();
        bytes.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body_bytes);

        // ── committed_chain_count (2 bytes, v6) ─────────────────────────────
        // Trailing field, appended after the body — mirrors how
        // `legacy_linear_cumulative_difficulty` was added to v2 without breaking v1 readers.
        // Was previously missing entirely: `deserialize()` hardcoded 0
        // regardless of the real value, silently corrupting the Level-1
        // commitment hash (`calculate_commitment_hash`) on every P2P/storage
        // round-trip whenever a block actually set this field (CV-62),
        // causing the receiver to recompute a different PoW hash than the
        // one the miner actually solved against — see
        // `InsufficientProofOfWork` failures at beacon height 1 in the E3
        // crash-recovery dry-run.
        bytes.extend_from_slice(&self.header.committed_chain_count.to_le_bytes());

        bytes
    }
    
    /// Deserialize a beacon block from bytes.
    ///
    /// Handles two on-disk formats transparently:
    ///
    /// | Format | Size          | `legacy_linear_cumulative_difficulty` | `transactions`  |
    /// |--------|---------------|-------------------------|-----------------|
    /// | no-tx  | exactly 184   | always 0 (redirected)   | `vec![]`        |
    /// | tx     | 188+          | always 0 (redirected)   | read from bytes |
    ///
    /// Sizes 185-187 are rejected as invalid (incomplete tx_count field).
    /// (prev_block_hash removed in Wave 5; old v1 blobs are not supported.
    /// Jul 2026: `difficulty`/`legacy_linear_cumulative_difficulty` removed
    /// from the wire — pre-Jul-2026 208/212+-byte payloads are **not**
    /// accepted by this revision; see `BeaconBlockCandidateHeader::
    /// serialize()`'s doc comment. No live network carried the old format.)
    ///
    /// # Errors
    /// Returns `Err` if `data` is not 184 bytes or 188+ bytes, or if any
    /// embedded transaction fails to deserialize.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        // Accepted formats:
        // - no-tx: exactly 184 bytes (header 152 + hash 32, no tx_count)
        // - tx: 188+ bytes (header 152 + hash 32 + tx_count 4 + transactions)
        // - 185-187 bytes: INVALID (incomplete tx_count)
        if data.len() < 184 {
            return Err(format!(
                "Data too short for beacon block: {} bytes (minimum 184)",
                data.len()
            ));
        }

        // Reject sizes 185-187 (incomplete tx_count)
        if data.len() > 184 && data.len() < 188 {
            return Err(format!(
                "Invalid beacon block size: {} bytes (must be 184 or 188+)",
                data.len()
            ));
        }

        let mut offset = 0usize;

        // ── Field readers (closures borrow `data` and advance `offset`) ───
        let read_u32 = |offset: &mut usize| -> u32 {
            let val = u32::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            *offset += 4;
            val
        };

        let read_i32 = |offset: &mut usize| -> i32 {
            let val = i32::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            *offset += 4;
            val
        };

        let read_u64 = |offset: &mut usize| -> u64 {
            let val = u64::from_le_bytes([
                data[*offset],     data[*offset + 1],
                data[*offset + 2], data[*offset + 3],
                data[*offset + 4], data[*offset + 5],
                data[*offset + 6], data[*offset + 7],
            ]);
            *offset += 8;
            val
        };

        let read_hash = |offset: &mut usize| -> [u8; 32] {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[*offset..*offset + 32]);
            *offset += 32;
            hash
        };

        // Wraps read_hash to produce a WeightedHash (raw 32-byte interpretation).
        let read_weighted = |offset: &mut usize| -> WeightedHash {
            WeightedHash::from(read_hash(offset))
        };

        // ── Header fields (136 bytes, present in all formats) ─────────────
        // Jul 2026: `difficulty` (8 bytes) removed entirely (D1 — redundant
        // with `bits`, the sole authoritative rBits work field);
        // `legacy_linear_cumulative_difficulty` (16 bytes) removed from the
        // wire (redirected — every real append path already overwrote
        // whatever value arrived with the locally-derived canonical MMR
        // weight before anything read it back; see the field's own
        // struct-doc comment). Combined, the header-fields-plus-hash prefix
        // shrank from 208 to 184 bytes.
        let version            = read_u32(&mut offset);   // 0–3
        let delta              = read_i32(&mut offset);   // 4–7 (was timestamp u64)
        let height             = read_u32(&mut offset);   // 8–11
        let bits               = read_u32(&mut offset);   // 12–15
        let prev_mmr_root      = read_weighted(&mut offset);  // 16–47
        let current_mmr_root   = read_weighted(&mut offset);  // 48–79
        let body_commitment = read_hash(&mut offset);  // 80–111 (stored as tx_merkle_root)
        let merged_mining_root = read_hash(&mut offset);  // 112–143
        let nonce              = read_u64(&mut offset);   // 144–151
        // offset is now 152.

        // `legacy_linear_cumulative_difficulty` always starts at 0 on decode
        // (redirected off the wire) — every real append path re-stamps it
        // from the canonical MMR weight immediately afterward regardless.
        let legacy_linear_cumulative_difficulty: u128 = 0;

        // ── Block hash (32 bytes, stored as WeightedHash since migration) ──
        // Legacy blocks stored the plain SHA256d here.  Those bytes are read
        // verbatim as a WeightedHash; callers that need the canonical WeightedHash
        // for a legacy block should call `BeaconBlock::calculate_weighted_hash`.
        let hash = read_weighted(&mut offset); // 152–183

        // ── Body dispatch ──────────────────────────────────────────────────
        // - 184 bytes (no-tx shape): no body field → empty ShardBlockBody
        // - 188+ bytes, sentinel == 0xFFFF_FFFF (flat body): flat body bytes follow
        // - 188+ bytes, sentinel != 0xFFFF_FFFF (legacy): sentinel is tx_count;
        //   read length-prefixed Vec<Transaction> and convert via from_transactions
        let body: ShardBlockBody = if data.len() >= 188 {
            let sentinel = read_u32(&mut offset);
            if sentinel == 0xFFFF_FFFFu32 {
                // v5: body_len + flat body bytes
                if offset + 4 > data.len() {
                    return Err("Truncated v5 body_len field".into());
                }
                let body_len = read_u32(&mut offset) as usize;
                if offset + body_len > data.len() {
                    return Err(format!(
                        "Truncated v5 body: need {} bytes, have {}",
                        body_len, data.len() - offset
                    ));
                }
                let body = ShardBlockBody::deserialize(&data[offset..offset + body_len])
                    .map_err(|e| format!("Failed to deserialize v5 body: {}", e))?;
                offset += body_len;
                body
            } else {
                // v4 legacy: sentinel is tx_count
                let tx_count = sentinel as usize;
                // NC-75: bound the allocation before trusting a wire-supplied
                // count — each transaction needs at least a 4-byte length
                // prefix, so `tx_count` can never legitimately exceed the
                // remaining bytes divided by 4. Without this, a garbage or
                // corrupted sentinel (e.g. a payload encoded with the wrong
                // wire format entirely, see `ChainProvider::block_bytes_at`'s
                // own NC-75 fix) causes an unguarded multi-hundred-GB
                // `Vec::with_capacity` allocation abort here.
                let remaining = data.len().saturating_sub(offset);
                if tx_count > remaining / 4 {
                    return Err(format!(
                        "Implausible legacy tx_count {} for {} remaining bytes",
                        tx_count, remaining
                    ));
                }
                let mut txs = Vec::with_capacity(tx_count);
                for i in 0..tx_count {
                    if offset + 4 > data.len() {
                        return Err(format!(
                            "Truncated tx length prefix at transaction {}/{} at offset {}",
                            i, tx_count, offset
                        ));
                    }
                    let tx_len = read_u32(&mut offset) as usize;
                    if offset + tx_len > data.len() {
                        return Err(format!(
                            "Truncated tx body at transaction {}/{} \
                             (need {} bytes, have {})",
                            i, tx_count, tx_len, data.len() - offset
                        ));
                    }
                    let tx = Transaction::deserialize(&data[offset..offset + tx_len])
                        .map_err(|e| format!("Failed to deserialize beacon tx {}/{}: {}", i, tx_count, e))?;
                    offset += tx_len;
                    txs.push(tx);
                }
                ShardBlockBody::from_transactions(&txs, None)
            }
        } else {
            ShardBlockBody::empty()
        };

        // ── committed_chain_count (2 bytes, v6, trailing) ────────────────────
        // Added after the body; older blobs (pre-fix, or v3/v4 with no room
        // left) simply don't have these trailing bytes — default to 0,
        // matching the field's own `#[serde(default)]` migration story.
        let committed_chain_count = if offset + 2 <= data.len() {
            let val = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            val
        } else {
            0
        };
        let _ = offset; // silence unused-assignment lint on the final read

        let header = BeaconBlockCandidateHeader {
            version,
            delta,
            height,
            bits,
            prev_mmr_root,
            current_mmr_root,
            tx_merkle_root: body_commitment,
            merged_mining_root,
            nonce,
            legacy_linear_cumulative_difficulty,
            committed_chain_count,
        };

        Ok(Self { header, hash, body })
    }
}

// ============================================================================
// Beacon wire block — length-prefixed header, for header-only storage reads
// ============================================================================

/// Storage/wire representation of a beacon block with a length-prefixed
/// header section ahead of the body, mirroring `ShardWireBlock`
/// (`common::blocks::shard_block`).
///
/// Beacon's `PositionalUtxoDb` payload used to be a single
/// `bincode::serde::encode_to_vec(&BeaconBlock, standard())` blob — the
/// header and body were not separable without decoding the whole record.
/// `BeaconWireBlock::encode()` instead writes
/// `[header_len: u32 LE][bincode(StoredBeaconHeader)][ShardBlockBody::serialize()]`,
/// letting `PositionalUtxoDb::read_header_bytes` (built for the shard chain,
/// generic over any `ElidedBlockLayout::WireBlock`-configured instance) read
/// just the header section — two small ranged reads — without decoding or
/// transferring the transaction body at all. See
/// `docs/plan/Fast_Node_Start_Design.md` §7.12/§7.13 for the shard-chain
/// precedent and the beacon-chain follow-up this type exists for.
///
/// **Not a straight mirror of `ShardWireBlock`: the header section also
/// carries `coinbase_hash`, a body-derived value.** `WireBeaconHeader`
/// (the actual header-cache/P2P-serving format) needs `coinbase_hash`,
/// computed from the coinbase transaction *inside the body*
/// (`coinbase_hash_from_stored_body`) — found while wiring this up, not
/// assumed: an initial version stored only `BeaconBlockCandidateHeader`
/// (mirroring shard exactly) and would have needed the body decoded anyway
/// to reconstruct a `WireBeaconHeader`, defeating the entire point.
/// `StoredBeaconHeader` computes `coinbase_hash` once at `encode()` time
/// (when the body is naturally already in hand) and persists it alongside
/// the header, so every later header-only read is genuinely body-free.
///
/// `BeaconBlock.hash` (the cached `WeightedHash`) is, like `ShardWireBlock`,
/// deliberately **not** stored — cheaply recomputed on decode via
/// `BeaconBlock::calculate_weighted_hash`.
#[derive(Serialize, Deserialize)]
pub struct StoredBeaconHeader {
    pub header: BeaconBlockCandidateHeader,
    /// Derived from the body at `encode()` time — see this type's own doc
    /// comment. `[0u8; 32]` for genesis (no miner-extranonce extension),
    /// matching `WireBeaconHeader::from_block`'s own fallback.
    pub coinbase_hash: [u8; 32],
}

pub struct BeaconWireBlock {
    pub header: BeaconBlockCandidateHeader,
    pub coinbase_hash: [u8; 32],
    pub body: ShardBlockBody,
}

impl BeaconWireBlock {
    /// Build from a `BeaconBlock`, discarding its cached `hash` (recomputed
    /// on decode) and deriving `coinbase_hash` from the body once, up front.
    pub fn from_block(block: &BeaconBlock) -> Self {
        let coinbase_hash = crate::transaction::coinbase_mining_bytes::coinbase_hash_from_stored_body(&block.body)
            .unwrap_or([0u8; 32]);
        Self {
            header: block.header.clone(),
            coinbase_hash,
            body: block.body.clone(),
        }
    }

    /// Encode to wire/storage bytes.
    ///
    /// Layout: `header_len(4 B LE) + bincode(StoredBeaconHeader) + ShardBlockBody::serialize()`.
    ///
    /// Uses fixed (not variable) integer encoding for the header — see
    /// `ShardWireBlock::encode`'s own doc comment for why: `bincode::config::standard()`'s
    /// default `Varint` encoding makes every scalar field's width depend on
    /// its *value*, which would silently break `read_header_bytes`'s
    /// "read exactly `header_len` bytes starting right after the length
    /// prefix" contract if the length recorded here (from this exact
    /// encoding) ever disagreed with a re-encoding under a different config.
    /// Fixed-int width removes that risk entirely, matching the shard format.
    pub fn encode(&self) -> Vec<u8> {
        let stored = StoredBeaconHeader { header: self.header.clone(), coinbase_hash: self.coinbase_hash };
        let header_bytes = bincode::serde::encode_to_vec(
            &stored, bincode::config::standard().with_fixed_int_encoding(),
        ).expect("StoredBeaconHeader bincode encode");
        let body_bytes = self.body.serialize();
        let hlen = header_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + header_bytes.len() + body_bytes.len());
        out.extend_from_slice(&hlen.to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body_bytes);
        out
    }

    /// Decode from wire/storage bytes produced by `encode`.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("beacon wire block too short for header_len".into());
        }
        let hlen = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + hlen {
            return Err(format!(
                "beacon wire block header truncated: need {} header bytes, have {}",
                hlen, bytes.len() - 4
            ));
        }
        let stored = Self::decode_header_only(&bytes[4..4 + hlen])?;
        let body = ShardBlockBody::deserialize(&bytes[4 + hlen..])
            .map_err(|e| format!("ShardBlockBody decode: {e}"))?;
        Ok(Self { header: stored.header, coinbase_hash: stored.coinbase_hash, body })
    }

    /// Just the header section, decoded without touching the body bytes at
    /// all — what `read_header_bytes`-based callers actually want. Exists
    /// alongside `decode` (which needs the full byte slice anyway, since the
    /// header-section length alone doesn't bound where the body ends) for
    /// callers that already sliced out just `[4..4+header_len]` themselves
    /// (e.g. via `PositionalUtxoDb::read_header_bytes`, which returns
    /// exactly that slice) and want to skip re-deriving the length prefix.
    pub fn decode_header_only(header_bytes: &[u8]) -> Result<StoredBeaconHeader, String> {
        let (stored, _): (StoredBeaconHeader, _) = bincode::serde::decode_from_slice(
            header_bytes, bincode::config::standard().with_fixed_int_encoding(),
        ).map_err(|e| format!("StoredBeaconHeader decode: {e}"))?;
        Ok(stored)
    }

    /// Reconstruct a full `BeaconBlock`, recomputing the cached hash.
    ///
    /// **Must mirror `beacon_replay_leaf_hash`'s v1/v3 fallback exactly**
    /// (found live, Aug 12, 2026, chasing a crash-recovery soak "MMR root
    /// mismatch" that survived the NC-69 fix to the replay/restore paths):
    /// every real mined block is hashed via the coinbase-bound
    /// `calculate_weighted_hash_v3`, never the legacy header-only
    /// `calculate_weighted_hash` this method previously called
    /// unconditionally. `self.coinbase_hash` is already in hand (decoded
    /// alongside the header, or derived from the body in `from_block`), so
    /// there is no reason to silently fall back to v1 for a block that
    /// really has a non-zero coinbase — that fallback exists only for
    /// genesis (no coinbase, `coinbase_hash == [0u8; 32]` by construction)
    /// and header-only/empty-body test fixtures, the same "no derivable
    /// coinbase" case `beacon_replay_leaf_hash`/
    /// `validate_beacon_block_structure_v3` already fall back for.
    /// `P1DbBeaconStorage::get_beacon_block`/`iter_beacon_blocks_ordered`
    /// call this on every restart when the block-body window is
    /// disabled (the default) — silently corrupting every reloaded
    /// non-genesis block's `.hash` with the wrong (v1) value, which then
    /// propagates into `FullBeaconChain::blocks` and any comparison that
    /// trusts it.
    pub fn into_block(self) -> BeaconBlock {
        let hash = if self.coinbase_hash == [0u8; 32] {
            BeaconBlock::calculate_weighted_hash(&self.header)
        } else {
            BeaconBlock::calculate_weighted_hash_v3(&self.header, self.coinbase_hash)
        };
        BeaconBlock { header: self.header, hash, body: self.body }
    }
}

#[cfg(test)]
mod wire_block_into_block_hash_tests {
    use super::*;
    use crate::transaction::{
        build_miner_extranonce_extension, coinbase_hash, producer_stamp_marker, Transaction,
        TxOutput,
    };

    /// Reproduces the Aug 12, 2026 crash-recovery soak "MMR root mismatch"
    /// bug: `into_block()` used to unconditionally recompute `.hash` via
    /// the legacy v1 formula, silently discarding the real v3 hash for any
    /// block with a real (non-zero) coinbase -- exactly what every real
    /// mined block has. This locks in that a real coinbase-bound block's
    /// hash survives an `encode`/`decode`/`into_block` round trip
    /// unchanged.
    #[test]
    fn into_block_preserves_v3_hash_for_real_coinbase_block() {
        let reward_atoms = 100u64;
        let recipient = [7u8; 32];
        let extranonce1 = [1u8, 2, 3, 4];
        let extranonce2 = [0u8; 4];

        let mut tx = Transaction::new(1, 0);
        tx.add_output(TxOutput { value: reward_atoms, recipient });
        let mut body = ShardBlockBody::from_transactions(&[tx], None);
        let ext = build_miner_extranonce_extension(extranonce1, extranonce2);
        body.extensions.push(ext);
        if let Some(desc) = body.descriptors.get_mut(0) {
            desc.extension_len = desc.extension_len.saturating_add(1);
        }
        let tx_merkle_root = body.calculate_tx_merkle_root();

        let header = BeaconBlockCandidateHeader::new(
            1, 1_704_100_005, 1, 0x1e0fffff,
            WeightedHash::zero(), tx_merkle_root, [0u8; 32], 1_704_100_000,
        );

        let cb_hash = coinbase_hash(
            reward_atoms, recipient, producer_stamp_marker(None), extranonce1, extranonce2,
        );
        let expected_hash_bytes = BeaconBlock::calculate_hash_v3(&header, cb_hash);
        let expected = WeightedHash::from_leaf_rbits(&expected_hash_bytes, header.bits);

        let original = BeaconBlock { header, hash: expected, body };
        let wire = BeaconWireBlock::from_block(&original);
        assert_eq!(wire.coinbase_hash, cb_hash, "encode-time coinbase_hash derivation must match");

        let encoded = wire.encode();
        let decoded = BeaconWireBlock::decode(&encoded).unwrap();
        let reconstructed = decoded.into_block();

        assert_eq!(
            reconstructed.hash, expected,
            "into_block() must reproduce the real v3 hash for a block with a real coinbase, \
             not silently fall back to the legacy v1 formula",
        );
    }
}

/*
===============================================================================
CUMULATIVE DIFFICULTY IMPLEMENTATION NOTES (HISTORICAL — Jul 2026)
===============================================================================

SUPERSEDED: `difficulty: u64` no longer exists on the header (D1, removed);
`legacy_linear_cumulative_difficulty` is redirected off the wire (always 0 on
decode, re-stamped from the canonical MMR weight by the receiver's own append
path — see that field's struct-doc comment). The rules/usage patterns below
describe the pre-redirect design and are kept only as historical context for
why the field still exists in memory; do not follow this pseudocode as-is.

RULES (as specified):
1. Incoming block candidate: legacy_linear_cumulative_difficulty = 0
2. Genesis block: Has non-zero difficulty (cumulative = difficulty)
3. Orphan blocks: legacy_linear_cumulative_difficulty remains 0
4. Blocks with parent: legacy_linear_cumulative_difficulty = parent.cumulative + difficulty

USAGE PATTERNS:

1. CREATING TEMPLATE (Mining Pool):
   ```rust
   let header = BeaconBlockCandidateHeader::new(...);
   // header.legacy_linear_cumulative_difficulty = 0 ✓ RULE 1
   ```

2. GENESIS GENERATION:
   ```rust
   let mut genesis = BeaconBlock::new(header);
   genesis.set_legacy_linear_cumulative_difficulty(config.difficulty as u128); ✓ RULE 2
   ```

3. APPENDING TO MAIN CHAIN:
   ```rust
   let parent_cumulative = chain.last().legacy_linear_cumulative_difficulty();
   let cumulative = parent_cumulative + block.header.difficulty as u128;
   block.set_legacy_linear_cumulative_difficulty(cumulative); ✓ RULE 4
   chain.push(block);
   ```

4. STORING SIDE BLOCK:
   ```rust
   let cumulative = calculate_cumulative_from_parent(chain, block)?;
   block.set_legacy_linear_cumulative_difficulty(cumulative); ✓ RULE 4
   side_blocks.insert(hash, block);
   ```

5. ORPHAN (NO PARENT):
   ```rust
   // block.legacy_linear_cumulative_difficulty stays 0 ✓ RULE 3
   orphans.add(block);
   ```

6. ORPHAN BECOMES VALID:
   ```rust
   let parent_cumulative = find_parent(orphan).legacy_linear_cumulative_difficulty();
   let cumulative = parent_cumulative + orphan.header.difficulty as u128;
   orphan.set_legacy_linear_cumulative_difficulty(cumulative); ✓ RULE 4
   process_block(orphan);
   ```

FORK CHOICE:
   ```rust
   if fork_tip.legacy_linear_cumulative_difficulty() > main_tip.legacy_linear_cumulative_difficulty() {
       reorganize_to_fork(fork_tip);
   }
   ```

MIGRATION:
   - Field has #[serde(default)] for backward compatibility
   - Old blocks deserialize with legacy_linear_cumulative_difficulty = 0
   - Call ensure_legacy_linear_cumulative_difficulty() to recalculate
   - Or recalculate during chain load by walking from genesis

WHY NOT IN POW HASH:
   - legacy_linear_cumulative_difficulty is derived from chain structure
   - It's metadata about the chain, not content of this block
   - Difficulty itself IS in the PoW hash (committed field)
   - Parent linkage IS in the PoW hash (prev_block_hash)
   - So cumulative can be calculated: parent.cumulative + difficulty
   - No need to commit it separately

===============================================================================
*/