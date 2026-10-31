use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use bincode;
use crate::transaction::Transaction;
use crate::common::utxo::ForkUtxoOverlay;
use crate::common::crypto::merged_mining_hash::MergedMiningHash;
use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::crypto::{merkle_leaf_hash, merkle_hash_pair, MerkleHash, MERKLE_HASH_BYTES};
use log::debug;

/// Auxiliary Beacon Header — stores the beacon PoW fields that are embedded in shard blocks.
///
/// A shard block was merged-mined alongside a beacon block.  This struct holds
/// the beacon block's fields that are necessary to:
/// - Reconstruct the exact 80-byte beacon PoW header and verify the hash
/// - Verify the shard's Merkle proof against `merged_mining_root`
/// - Validate the beacon difficulty (`bits`)
/// - Verify chain linkage (`prev_mmr_root`)
///
/// # PoW header layout (80 bytes, matches `BeaconBlockCandidateHeader::serialize_for_mining`)
///
/// ```text
/// [0..4]   version
/// [4..36]  prev_mmr_root
/// [36..68] commitment_hash = SHA256d(beacon_height || beacon_merkle_root || merged_mining_root)
/// [68..72] delta
/// [72..76] bits
/// [76..80] nonce (truncated to u32)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconHeader {
    /// Block version number.
    pub version: u32,

    /// Relative timestamp delta (1/256-second units from bitcoin_anchor_timestamp).
    pub delta: i32,

    /// Proof-of-work nonce.
    pub nonce: u64,

    /// Previous MMR root — bytes [4..36] of the 80-byte PoW header.
    pub prev_mmr_root: WeightedHash,

    /// Merged mining tree root — part of the Level-1 commitment preimage.
    /// Also used for shard Merkle proof verification.
    pub merged_mining_root: [u8; 32],

    /// Difficulty bits — compact **rBits** (header-native work field).
    ///
    /// Formerly nBits (compact target). Same wire slot; MMR leaf copies this
    /// value via [`WeightedHash::from_leaf_rbits`]. PoW expand uses
    /// `rbits_to_target` with the network initial beacon target — **not** this
    /// field alone as a Bitcoin-style nBits expand.
    pub bits: u32,

    /// Beacon block height — needed to recompute `commitment_hash` for PoW verification.
    pub beacon_height: u32,

    /// Beacon chain's own transaction Merkle root — needed to recompute `commitment_hash`.
    /// Distinct from the shard's `merkle_root`.
    pub beacon_merkle_root: [u8; 32],

    /// Number of non-null leaves the beacon miner committed to in the merged-mining tree.
    /// PoW-protected (included in the beacon block's `commitment_hash`).
    /// Used by EX-7b validation in `verify_shard_id_and_mmn`.
    /// `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub committed_chain_count: u16,

    /// The real beacon coinbase's `SHA256d` hash — the first leaf of the v3
    /// two-leaf commitment (`Stratum_Extranonce_Binding_Plan.md` §3). Per-share
    /// (depends on that worker's own extranonce), so unlike every other field
    /// here it cannot be copied from a job-level template; the constructor
    /// that builds this from a live share must supply it.
    ///
    /// `#[serde(default)]` (all-zero) for backward compatibility with every
    /// pre-v3 call site (`BeaconHeader::new`, ~60 fixtures) — `hash()` falls
    /// back to the legacy `calculate_commitment_hash_from_parts_v2` formula
    /// when this is all-zero, and to the v3 `calculate_commitment_hash_from_coinbase`
    /// formula otherwise. A genuinely all-zero real coinbase hash is not
    /// possible (SHA256d of a non-empty preimage), so this is an unambiguous
    /// legacy-vs-v3 discriminant, not a collision risk.
    #[serde(default)]
    pub coinbase_hash: [u8; 32],
}

impl BeaconHeader {
    /// Create a new auxiliary beacon header.
    ///
    /// Parameters:
    /// - version: Protocol version
    /// - timestamp: Block creation time (Unix seconds)
    /// - nonce: PoW nonce from miner
    /// - prev_mmr_root: MMR root before this beacon block (bytes 4–35 of 80-byte header)
    /// - merged_mining_root: Root of the merged mining tree
    /// - bits: Beacon difficulty in nBits compact format
    /// - bitcoin_anchor_timestamp: Epoch for delta calculation
    /// - beacon_height: Height of the beacon block
    /// - beacon_merkle_root: Beacon chain's own tx Merkle root (for commitment_hash)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u32,
        timestamp: u64,
        nonce: u64,
        prev_mmr_root: WeightedHash,
        merged_mining_root: [u8; 32],
        bits: u32,
        bitcoin_anchor_timestamp: u64,
        beacon_height: u32,
        beacon_merkle_root: [u8; 32],
    ) -> Self {
        // `delta` is this auxiliary header's deviation from the BEACON chain's
        // own expected arrival time (this is a beacon-schedule header embedded
        // in a shard block for merged mining, so it uses `beacon_height` and the
        // beacon interval, not the shard's). Must match
        // `BeaconBlockCandidateHeader::new` exactly — including the runtime
        // interval from `beacon_interval_secs()` (default 600; digests/devnet
        // use 150). Hardcoding `600 * 256` here rejected every shard PoW after
        // height 0 on digests: worker mined against job delta, shard rebuild
        // recomputed a different delta, commitment hash diverged (CV-84 class).
        let beacon_secs = crate::common::block_intervals::beacon_interval_secs();
        let beacon_interval_delta_units = (beacon_secs as i64).saturating_mul(256);
        let expected_delta_units = (beacon_height as i64) * beacon_interval_delta_units;
        let raw_delta_units = (timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256;
        let delta_units = raw_delta_units - expected_delta_units;
        let delta = delta_units.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        Self {
            version,
            delta,
            nonce,
            prev_mmr_root,
            merged_mining_root,
            bits,
            beacon_height,
            beacon_merkle_root,
            committed_chain_count: 0,
            coinbase_hash: [0u8; 32],
        }
    }

    /// Build the auxiliary header from the mined beacon template + share fields.
    ///
    /// Mirrors `ShareProcessor::candidate_header_from_share`: copy the job's
    /// PoW-committed fields (including `delta`) and apply only the share's
    /// nonce / version / ntime roll. Avoids the Unix-timestamp round-trip that
    /// truncates `delta % 256` via `delta_to_unix` and historically drifted
    /// when `BeaconHeader::new` used a different interval than the job.
    ///
    /// `coinbase_hash` is this share's own real beacon-coinbase hash (the
    /// same value `share_processor.rs` already reconstructs via
    /// `reconstruct_beacon_header_and_body` for the beacon-slot path) — it
    /// cannot come from `template` since coinbase varies per worker/share,
    /// never per job. Passing the real value here is required for `hash()`
    /// to reproduce the same v3 commitment hash the miner actually mined
    /// against; passing `[0u8; 32]` falls back to the legacy v2 formula.
    pub fn from_mined_candidate(
        template: &crate::common::blocks::beacon_block::BeaconBlockCandidateHeader,
        share_version: u32,
        share_nonce: u32,
        share_ntime: u64,
        template_ntime: u64,
        coinbase_hash: [u8; 32],
    ) -> Self {
        let mut delta = template.delta;
        let template_ntime = template_ntime.min(u32::MAX as u64) as u32;
        let share_ntime = share_ntime.min(u32::MAX as u64) as u32;
        if share_ntime != template_ntime {
            let roll = share_ntime.saturating_sub(template_ntime);
            delta = delta.saturating_add((roll as i32).saturating_mul(256));
        }
        Self {
            version: share_version,
            delta,
            nonce: share_nonce as u64,
            prev_mmr_root: template.prev_mmr_root,
            merged_mining_root: template.merged_mining_root,
            bits: template.bits,
            beacon_height: template.height,
            beacon_merkle_root: template.tx_merkle_root,
            committed_chain_count: template.committed_chain_count,
            coinbase_hash,
        }
    }

    /// Serialize to storage bytes.
    ///
    /// Format (120 bytes):
    /// - version (4), delta (4), nonce (8), prev_mmr_root (32),
    ///   merged_mining_root (32), bits (4), beacon_height (4),
    ///   beacon_merkle_root (32)
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(120);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.delta.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        bytes.extend_from_slice(&self.merged_mining_root);
        bytes.extend_from_slice(&self.bits.to_le_bytes());
        bytes.extend_from_slice(&self.beacon_height.to_le_bytes());
        bytes.extend_from_slice(&self.beacon_merkle_root);
        bytes
    }

    /// Serialize to the 80-byte Bitcoin-compatible PoW header.
    ///
    /// Layout (matches `BeaconBlockCandidateHeader::serialize_for_mining` exactly):
    ///
    /// ```text
    /// [0..4]   version
    /// [4..36]  prev_mmr_root
    /// [36..68] commitment_hash = Blake3(beacon_height || beacon_merkle_root || merged_mining_root || committed_chain_count)
    /// [68..72] delta
    /// [72..76] bits
    /// [76..80] nonce (truncated to u32)
    /// ```
    pub fn serialize_for_mining(&self) -> Vec<u8> {
        // Recompute commitment_hash via the single shared formula — calling the
        // same function `BeaconBlockCandidateHeader::calculate_commitment_hash`
        // uses, rather than a separate hand-rolled Blake3 call, so the two can
        // never drift out of sync again. Fixed 2026-07-16: this used to hash
        // only 3 fields (omitting `committed_chain_count` entirely), so this
        // header's reconstructed hash never matched the real beacon block's
        // commitment hash whenever `committed_chain_count != 0` (CV-62) — see
        // the wiki's architecture/shard-count-lifecycle.md page for the full
        // trace of this bug across every "chain count" owner in the codebase.
        //
        // NC-30 (Jul 22, 2026): the real beacon PoW preimage moved to the v3
        // two-leaf coinbase commitment (Stratum_Extranonce_Binding_Plan.md
        // §3) this session, but this method still only ever computed the old
        // v2 (no-coinbase) formula — meaning this aux header's `.hash()`
        // never matched what a real miner actually mined against once v3
        // went live, unconditionally failing every shard block's real PoW
        // re-verification in `verify_shard_id_and_mmn`. `coinbase_hash`
        // (all-zero only for pre-v3 legacy/test construction, per its own
        // doc comment) selects which formula applies.
        let commitment_hash: [u8; 32] = if self.coinbase_hash == [0u8; 32] {
            crate::common::blocks::beacon_block::calculate_commitment_hash_from_parts_v2(
                self.beacon_height,
                self.beacon_merkle_root,
                self.merged_mining_root,
                self.committed_chain_count,
            )
        } else {
            crate::common::blocks::beacon_block::calculate_commitment_hash_from_coinbase(
                self.beacon_height,
                self.coinbase_hash,
                self.merged_mining_root,
                self.committed_chain_count,
            )
        };

        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        header.extend_from_slice(&commitment_hash);
        header.extend_from_slice(&self.delta.to_le_bytes());
        header.extend_from_slice(&self.bits.to_le_bytes());
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());
        debug_assert_eq!(header.len(), 80, "beacon PoW header must be 80 bytes");
        header
    }
    
    /// Calculate PoW hash as WeightedHash
    ///
    /// FIXED: Now possible because we have all required fields!
    ///
    /// This allows verification of the PoW without needing the full beacon template.
    /// The hash calculation uses the 80-byte mining format (Bitcoin-standard).
    ///
    /// Returns a WeightedHash that includes both the hash value and difficulty encoded as rBits.
    ///
    /// # Parameters
    /// - `asserted_s_bits`: Genesis **asserted** s-bits for WeightedHash construction
    ///
    /// Process:
    /// Calculate PoW hash as plain bytes (SHA256d).
    ///
    /// Process:
    /// 1. Serialize to 80-byte format
    /// 2. SHA256(serialized) -> first_hash
    /// 3. SHA256(first_hash) -> final_hash (SHA256d)
    ///
    /// This is the standard Bitcoin block hash calculation.
    pub fn hash(&self) -> [u8; 32] {
        let serialized = self.serialize_for_mining();

        // First SHA256
        let first_hash = Sha256::digest(&serialized);

        // Second SHA256 (SHA256d)
        let second_hash = Sha256::digest(&first_hash);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second_hash);
        hash
    }

    /// Compute the canonical MMR-leaf hash (WeightedHash) for this beacon block.
    ///
    /// Copies header compact **rBits** (`self.bits`) into the leaf.
    pub fn hash_weighted(&self) -> WeightedHash {
        let plain_hash = self.hash();
        WeightedHash::from_leaf_rbits(&plain_hash, self.bits)
    }
}

/// Block header for a shard block
///
/// CANDIDATE STAGE: After PoW
///
/// Contains shard-specific metadata while delegating PoW details to auxiliary BeaconHeader.
///
/// **`chain_weight` field removed entirely (Aug 5, 2026).** It was already
/// `#[serde(skip)]` (never on the wire or in any hash preimage) and was
/// stamped by every real append/replay path from a freshly-computed
/// `mmr.append(...)` return value — but an exhaustive audit of every real
/// (non-comment) reader found it was **only ever read for the current tip**
/// (`self.chain.last()`), which both `ShardChain` and `FullShardChain`
/// already track independently via their own chain-level `chain_weight`
/// scalar. Side-block/fork-candidate weight (genuinely needed per-candidate,
/// since a fork has no chain-level scalar to fall back to) has always come
/// from `LightShardHeader.chain_weight`, computed directly via
/// `compute_peaks_after_append`/`from_block_header_with_local_weight` —
/// untouched by this removal. See `docs/plan/Fast_Node_Start_Design.md`
/// §7.9's write-up for the investigation that found this.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullShardHeader {
    /// Height - the order of this block in the chain
    /// Genesis block has height 0
    pub height: u32,

    /// Previous MMR (Merkle Mountain Range) root
    /// 
    /// This is the MMR state BEFORE this block.
    /// Part of block identity (included in hash calculation).
    /// Enables efficient proofs for historical data.
    pub prev_mmr_root: WeightedHash,

    /// Current MMR root (after including this block)
    ///
    /// CRITICAL: This field is NOT included in block hash calculation!
    /// It's calculated FROM the block hash, so including it would create
    /// a circular dependency. See serialize_for_hash() for details.
    ///
    /// This is the MMR state AFTER this block.
    /// NOT part of block identity (excluded from hash calculation).
    /// Used for chain state tracking and next block's prev_mmr_root.
    pub current_mmr_root: WeightedHash,

    /// Combined commitment over all flat-body vectors (FV-5).
    /// tx_merkle_root = BLAKE3(outputs_commitment ‖ inputs_commitment ‖ …)
    /// Replaces the old `merkle_root`; individual sub-commitments live in
    /// `ShardBlockBody`, not in the header.
    pub tx_merkle_root: [u8; 32],

    /// Compact **rBits** work field (shard DAA output) — formerly nBits target.
    ///
    /// Misnamed historically as "difficulty" / "Bitcoin-style nBits" (CV-30).
    /// After the header-rBits cutover this is the shard's authoritative compact
    /// difficulty for MMR leaf copy + Strategy A PoW (`rbits_to_target`).
    /// Merged-mining PoW uses **this** field, not `beacon_header.bits` (MM-1).
    pub difficulty: u32,

    /// Shard ID this block belongs to
    pub shard_id: u16,

    /// Auxiliary Beacon Header - FIXED to include all PoW fields
    /// 
    /// CRITICAL FIX: Now contains merged_mining_root and other fields
    /// required for PoW verification and merkle proof validation
    /// 
    /// Contains: version, timestamp, nonce, prev_block_hash, 
    ///           merged_mining_root, bits
    pub beacon_header: BeaconHeader,

    /// Pre-computed block hash (NOT in hash calculation)
    ///
    /// OPTIMIZATION: This field stores the SHA256d hash of the header,
    /// computed once during construction. Like current_mmr_root, this is
    /// metadata about the block rather than part of its content.
    ///
    /// CRITICAL: This field is NOT included in block hash calculation!
    /// It's the RESULT of the hash calculation, so including it would
    /// create a circular dependency. See serialize_for_hash() for details.
    ///
    /// Benefits:
    /// - O(1) hash access (field read) instead of O(n) computation
    /// - 50-100x performance improvement (1000ns -> 10ns)
    /// - Eliminates redundant hash computation during block processing
    ///
    /// Serialization:
    /// - Excluded from serialize_for_hash() (hash calculation)
    /// - Included in serialize() (full serialization for storage)
    ///
    /// Integrity:
    /// - Always present in serialized form; deserialization will fail fast
    ///   if the field is absent rather than silently zero-filling it.
    /// - Call ensure_hash() on any block whose hash is suspected to be stale
    ///   (e.g., after manual field mutation in tests).
    ///
    /// WIRE-5 (Jul 16, 2026): deliberately placed here, immediately after
    /// `beacon_header` and before `merged_mining_proof`, rather than trailing
    /// the struct as it originally did. `#[derive(Serialize, Deserialize)]`
    /// (bincode struct-derive order) is this struct's only production
    /// serialization path (`ShardWireBlock::encode()`/`decode()`); this
    /// placement makes the first 274 bytes of every encoded `FullShardHeader`
    /// a fixed-size, decode-free prefix — everything a `LightShardHeader`
    /// projection needs — with `merged_mining_proof` (variable-length) as the
    /// sole trailing section. Breaking change for any already-persisted bytes
    /// under the old field order; no migration needed (no deployed testnet
    /// yet). See `OPTIMIZATION_PLAN.md` §23.
    hash: [u8; 32],

    /// Merkle sibling path proving this shard's inclusion in the merged-mining tree.
    ///
    /// Each element is a `MergedMiningHash` — a 32-byte value whose last 2 bytes
    /// carry embedded `(tree_height, chain_count)` metadata.  The root's
    /// `chain_count()` is the verified active-shard count; no separate
    /// `merged_mining_number` or `orange_encoding` field is needed.
    pub merged_mining_proof: Vec<MergedMiningHash>,
}

impl FullShardHeader {
    /// Create a new block header for a shard
    /// 
    /// CANDIDATE STAGE: During block candidate construction
    /// 
    /// OPTIMIZATION: Hash is computed once during construction using the
    /// builder pattern. This eliminates all redundant hash computation
    /// during block processing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u32,
        prev_mmr_root: WeightedHash,
        current_mmr_root: WeightedHash,
        tx_merkle_root: [u8; 32],
        difficulty: u32,
        merged_mining_proof: Vec<MergedMiningHash>,
        shard_id: u16,
        beacon_header: BeaconHeader,
    ) -> Self {
        // Create temporary header with placeholder hash
        let temp_header = FullShardHeader {
            height,
            prev_mmr_root,
            current_mmr_root,
            tx_merkle_root,
            difficulty,
            merged_mining_proof,
            shard_id,
            beacon_header,
            hash: [0u8; 32],  // Placeholder
        };

        // Compute hash from temp header (excludes hash and current_mmr_root)
        let computed_hash = temp_header.compute_hash();

        // Return header with computed hash
        FullShardHeader {
            hash: computed_hash,
            ..temp_header
        }
    }

    /// Serialize header to fixed-size cache bytes (NOT a P2P wire format).
    ///
    /// Used by legacy header-cache stride bookkeeping and `Block::size()`.
    /// P2P uses `ShardWireBlock::encode()` (bincode header + flat body) or
    /// `LightShardHeader` for header serving (the legacy 94-byte
    /// `encode_wire_header_94` encoder was deleted Jul 31, 2026 — NC-8).
    /// There is no matching `from_cache_bytes()` — do not feed this output to
    /// `ShardWireBlock::decode`.
    pub fn to_cache_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize height
        bytes.extend_from_slice(&self.height.to_le_bytes());
        
        // Serialize prev_mmr_root
        bytes.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));

        // Serialize current_mmr_root (included in full serialization)
        bytes.extend_from_slice(&<[u8; 32]>::from(self.current_mmr_root));

        // tx_merkle_root (FV-5: combined hash of all flat-body sub-commitments)
        bytes.extend_from_slice(&self.tx_merkle_root);

        // Serialize difficulty
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());

        // Serialize shard_id
        bytes.extend_from_slice(&self.shard_id.to_le_bytes());
        
        // Serialize auxiliary beacon header (now with all fields)
        bytes.extend_from_slice(&self.beacon_header.serialize());

        // Merged mining proof (v6 wire format: length u32 + N × 32-byte MergedMiningHash)
        bytes.extend_from_slice(&(self.merged_mining_proof.len() as u32).to_le_bytes());
        for mmh in &self.merged_mining_proof {
            bytes.extend_from_slice(mmh.raw());
        }
        
        // Serialize hash (NEW - included in full serialization)
        bytes.extend_from_slice(&self.hash);
        
        bytes
    }

    /// Serialize header for hash calculation (EXCLUDES current_mmr_root and hash)
    /// 
    /// CRITICAL: This method excludes current_mmr_root and hash from serialization.
    /// 
    /// WHY current_mmr_root is excluded:
    ///      current_mmr_root = MMR.append(block_hash)
    /// 
    /// WHY hash is excluded:
    ///      hash = SHA256d(serialize_for_hash(...))
    /// 
    /// If block_hash included current_mmr_root or hash in its calculation:
    ///      block_hash = SHA256d(serialize(header including current_mmr_root or hash))
    ///      current_mmr_root = MMR.append(block_hash)
    ///      hash = block_hash
    ///      → CIRCULAR DEPENDENCY!
    /// 
    /// SOLUTION: Exclude both current_mmr_root and hash from hash calculation.
    /// 
    /// The block hash represents the block's IDENTITY based on its content.
    /// The current_mmr_root and hash are METADATA about the block.
    /// These are conceptually separate concerns.
    /// 
    /// WORKFLOW:
    /// 1. Create header with placeholder current_mmr_root and hash
    /// 2. Calculate hash using serialize_for_hash() (excludes both fields)
    /// 3. Store computed hash in header.hash
    /// 4. Append hash to MMR to get current_mmr_root
    /// 5. Update header.current_mmr_root
    /// 6. Hash remains unchanged (it didn't include current_mmr_root or itself)
    pub fn serialize_for_hash(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize height
        bytes.extend_from_slice(&self.height.to_le_bytes());
        
        // Serialize prev_mmr_root (IS part of block identity; also occupies the
        // Bitcoin-compatible prevHash slot in the beacon 80-byte mining header
        // since W3-1).
        bytes.extend_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));

        // CRITICAL: Skip current_mmr_root AND hash for hash calculation
        // Both are derived FROM the hash, so can't be IN the hash:
        // - current_mmr_root = MMR.append(hash)
        // - hash = SHA256d(serialize_for_hash(...))

        // tx_merkle_root (FV-5)
        bytes.extend_from_slice(&self.tx_merkle_root);

        // Serialize difficulty
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());

        // PoW hash (commits to all merged mining structure)
        let pow_hash = self.beacon_header.hash();
        bytes.extend_from_slice(&pow_hash);
    
        // Timestamp (for ordering/display)
        bytes.extend_from_slice(&self.beacon_header.delta.to_le_bytes());
        
        bytes
    }

    /// Get the pre-computed block hash (O(1))
    /// 
    /// OPTIMIZATION: Returns the cached hash computed during construction.
    /// 
    /// Performance:
    /// - Before: ~500-1000ns (serialization + double SHA256)
    /// - After:  ~10ns (simple field read)
    /// - Speedup: 50-100x
    /// 
    /// This hash is used as:
    /// - Block identifier
    /// - Previous block reference
    /// - Input to MMR (appended to calculate current_mmr_root)
    /// 
    /// The hash is computed using serialize_for_hash() which EXCLUDES
    /// current_mmr_root and hash fields to avoid circular dependency.
    /// Return block hash as WeightedHash
    ///
    /// This computes the WeightedHash from the stored plain hash plus difficulty bits.
    /// The WeightedHash includes both the 28-byte hash and 4-byte rBits encoding.
    ///
    /// Returns the plain SHA256d hash stored in this header.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Compute this shard's merged-mining tree leaf value ("template hash").
    ///
    /// `BLAKE3(height ‖ prev_mmr_root ‖ tx_merkle_root ‖ difficulty)`
    /// — deliberately excludes `shard_id` (the ID is the leaf's tree *position*,
    /// not its content — see the merged-mining/hash-sorting design docs),
    /// excludes anything nonce/PoW-dependent (`beacon_header`, the block's own
    /// `hash()`/`current_mmr_root`), and excludes `chain_weight` (removed
    /// entirely from every hash preimage — session Jul 25, 2026; see the
    /// field's own doc comment: it's a pure function of `prev_mmr_root`'s own
    /// chain state plus `difficulty`, both already committed here, so it adds
    /// no independent information to this leaf).
    ///
    /// This is the value the merged-mining tree is actually built from at job
    /// generation time, before any nonce search happens — using `self.hash()`
    /// here instead would be circular, since `hash()` transitively commits to
    /// `beacon_header.merged_mining_root` (the tree *root*, which this leaf
    /// helps reconstruct) via `beacon_header.hash()`'s own commitment_hash.
    /// All fields used here are independent of `beacon_header` and of each
    /// other's nonce, so this can be computed identically before mining (to
    /// build the tree) and after mining (to verify a proof against it).
    pub fn merged_mining_leaf_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.height.to_le_bytes());
        h.update(&<[u8; 32]>::from(self.prev_mmr_root));
        h.update(&self.tx_merkle_root);
        h.update(&self.difficulty.to_le_bytes());
        h.finalize().into()
    }

    /// Compute the canonical MMR-leaf hash (WeightedHash) for this block.
    ///
    /// Returns the [`WeightedHash`] that combines this header's pre-computed
    /// `hash` with the nBits difficulty target (rBits).  This is the value
    /// produced when the block is appended to the [`WeightedMMR`] via
    /// `append`.
    ///
    /// **CV-30 / header-rBits:** uses `self.difficulty` — the shard's own compact
    /// **rBits** work field — not `self.beacon_header.bits` (aux mining preimage
    /// slot). Leaf = direct copy via [`WeightedHash::from_leaf_rbits`].
    ///
    /// # Relationship with [`LightShardHeader::hash_weighted`]
    ///
    /// [`LightShardHeader`] has **no** `beacon_header` field.  Its `bits` field
    /// is copied from `full.difficulty` by [`LightShardHeader::from_block_header`].
    ///
    /// ```text
    /// FullShardHeader::hash_weighted()  →  from_leaf_rbits(&self.hash,     self.difficulty)
    /// LightShardHeader::hash_weighted() →  from_leaf_rbits(&self.pow_hash, self.bits)
    ///   where self.bits == full.difficulty
    /// ```
    pub fn hash_weighted(&self) -> WeightedHash {
        WeightedHash::from_leaf_rbits(&self.hash, self.difficulty)
    }

    /// Compute SHA256d hash from header fields (internal use)
    /// 
    /// CANDIDATE STAGE: For block identification
    /// 
    /// This method computes the hash from scratch, used:
    /// - During construction (`FullShardHeader::new`)
    /// - For validation (ensure_hash, validate_hash)
    /// - For backward compatibility (old blocks without hash field)
    /// 
    /// Process:
    /// 1. Serialize header to bytes (WITHOUT current_mmr_root and hash)
    /// 2. SHA256(serialized_header) -> first_hash
    /// 3. SHA256(first_hash) -> final_hash (SHA256d)
    /// 
    /// This double-hashing is standard in Bitcoin.
    ///
    /// CRITICAL: This hash is what gets appended to MMR!
    /// Must match what light clients can calculate from LightShardBlockData.
    fn compute_hash(&self) -> [u8; 32] {
        let serialized = self.serialize_for_hash(); // KEY: excludes current_mmr_root and hash
        
        let first_hash = Sha256::digest(&serialized);
        let result     = Sha256::digest(&first_hash);
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..]);
        hash
    }

    /// Ensure hash is computed (for backward compatibility)
    /// 
    /// Call this after deserializing blocks that may not have the hash field.
    /// If hash is [0u8; 32] (default), computes and stores the hash.
    /// 
    /// Used when loading old blocks from storage that were serialized
    /// before the hash field was added.
    pub fn ensure_hash(&mut self) {
        if self.hash == [0u8; 32] {
            self.hash = self.compute_hash();
        }
    }

    /// Force-recompute the cached identity hash after mutating fields that
    /// participate in [`Self::serialize_for_hash`] (e.g. `beacon_header.nonce`).
    ///
    /// Unlike [`Self::ensure_hash`], this always recomputes — needed when the
    /// stored hash is already non-zero but stale relative to the header fields.
    pub fn recompute_hash(&mut self) {
        self.hash = self.compute_hash();
    }

    /// Validate that stored hash matches computed hash
    /// 
    /// Used to verify integrity of deserialized blocks, especially when
    /// receiving blocks from the network.
    /// 
    /// Returns true if hash is correct, false otherwise.
    #[cfg(debug_assertions)]
    pub fn validate_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

// ============================================================
// LightShardHeader — fixed-size in-memory shard header
// ============================================================

/// Fixed-size shard header for chain-management use (SideBlock pool, ShardHeaderCache).
///
/// Retains all fields needed for consensus decisions and P2P header serving.
/// Drops the variable-length PoW payload (`BeaconHeader`, `merged_mining_proof`)
/// that is only needed during initial PoW verification.
///
/// ## Serialised layout (136 bytes, little-endian, no padding) — WIRE-5
///
/// | Field            | Type          | Offset | Size |
/// |------------------|---------------|--------|------|
/// | height           | u32           |   0    |  4   |
/// | delta            | i32           |   4    |  4   |
/// | prev_mmr_root    | WeightedHash  |   8    | 32   |
/// | current_mmr_root | WeightedHash  |  40    | 32   |
/// | tx_merkle_root   | [u8;32]       |  72    | 32   |
/// | pow_hash         | [u8;32]       | 104    | 32   |
///
/// **WIRE-5 (items 1+2):** `shard_id`, `bits`, and `chain_weight` remain as
/// in-memory fields but are **excluded from the wire/cache serialisation**.
/// Receivers reconstruct `shard_id` from connection/cache context
/// ([`LightShardHeader::deserialize_with_shard_id`]); `bits` is deferred to
/// block-body PoW; `chain_weight` is always recomputed locally from MMR peaks
/// ([`LightShardHeader::from_block_header_with_local_weight`]).
///
/// Size history: 162 (original) → 158 (TS-DELTA: `timestamp u64`→`delta i32`)
/// → 136 (WIRE-5: drop `shard_id`/`bits`/`chain_weight` from the wire).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LightShardHeader {
    /// Block height (0 = genesis).
    pub height: u32,
    /// Relative timestamp delta (1/256-second units from bitcoin_anchor_timestamp).
    pub delta: i32,
    /// Cumulative chain difficulty — **in-memory only**; never trusted from the wire.
    pub chain_weight: u128,
    /// MMR root *before* this block was appended.
    pub prev_mmr_root: WeightedHash,
    /// MMR root *after* this block was appended.
    pub current_mmr_root: WeightedHash,
    /// Combined body commitment (FV-5): BLAKE3(outputs_commitment ‖ inputs_commitment ‖ …).
    /// Individual sub-commitments live in `ShardBlockBody`.
    pub tx_merkle_root: [u8; 32],
    /// Pre-computed SHA256d block hash (= `FullShardHeader::hash()`).
    pub pow_hash: [u8; 32],
    /// Shard this block belongs to — **in-memory only**; derived from cache/connection context on receipt.
    pub shard_id: u16,
    /// Difficulty target (nBits compact) — **in-memory only**; header-phase PoW deferred to block body.
    pub bits: u32,
}

/// Packed serialised size of [`LightShardHeader`] (bytes) after WIRE-5.
pub const LIGHT_SHARD_HEADER_SIZE: usize = 136;

// Compile-time assertion: in-memory size must not exceed 176 bytes.
const _: () = assert!(
    std::mem::size_of::<LightShardHeader>() <= 176,
    "LightShardHeader grew unexpectedly — update serialise/deserialise too",
);

impl LightShardHeader {
    /// Construct from a [`FullShardHeader`] after PoW validation passes.
    ///
    /// Call this immediately after `validate_chain_weight` to demote the header
    /// to its lightweight representation for storage in `SideBlock` and
    /// `ShardHeaderCache`.
    ///
    /// **CV-30:** `bits` is copied from `full.difficulty` (the shard's own
    /// DAA-adjusted nBits), not `full.beacon_header.bits` (the auxiliary
    /// Bitcoin PoW target).  This ensures that `hash_weighted()` on a
    /// `LightShardHeader` produces the same result as on the originating
    /// `FullShardHeader`.
    pub fn from_block_header(full: &FullShardHeader) -> Self {
        LightShardHeader {
            height:           full.height,
            delta:            full.beacon_header.delta,
            // `FullShardHeader` no longer has a `chain_weight` field at all
            // (removed Aug 5, 2026 — see its own struct doc comment); this
            // was already documented as untrustworthy here regardless (see
            // `from_block_header_with_local_weight`'s own doc comment below,
            // which always overwrites it anyway) — `0` until a caller that
            // needs a real value uses that constructor instead.
            chain_weight:     0,
            prev_mmr_root:    full.prev_mmr_root,
            current_mmr_root: full.current_mmr_root,
            tx_merkle_root:  full.tx_merkle_root,
            pow_hash:         full.hash(),
            shard_id:         full.shard_id,
            bits:             full.difficulty, // CV-30: shard-native nBits, not beacon_header.bits
        }
    }

    /// Construct from a [`FullShardHeader`], overriding `chain_weight` with a
    /// locally-computed MMR-derived value.
    ///
    /// # Security
    ///
    /// The `chain_weight` field in the peer's block header **cannot be trusted**.
    /// A peer can send any u128 value in that field; the only authoritative source
    /// is the output of `bag_peaks_weighted_u128` over the post-append MMR peak
    /// set, as returned by `WeightedMMR::compute_peaks_after_append`.
    ///
    /// This constructor embodies the "compute once, trust always" principle:
    /// supply the locally-derived `local_chain_weight` here and never mutate
    /// `chain_weight` afterwards.  The field is kept immutable after construction.
    ///
    /// Use this constructor (not [`Self::from_block_header`]) in all code paths
    /// that process blocks received from peers.
    ///
    /// See `docs/plan/Chain_Weight_MMR_Correctness_Plan.md §4.4`.
    pub fn from_block_header_with_local_weight(
        full: &FullShardHeader,
        local_chain_weight: u128,
    ) -> Self {
        let mut h = Self::from_block_header(full);
        // Override with the locally-computed MMR-derived chain weight.
        // The peer's block.header.chain_weight is NOT used.
        h.chain_weight = local_chain_weight;
        h
    }

    /// Serialise to the canonical 136-byte wire/cache format (WIRE-5).
    ///
    /// Excludes `shard_id`, `bits`, and `chain_weight` — see struct docs.
    /// All multi-byte integers are little-endian.
    pub fn serialize(&self) -> [u8; LIGHT_SHARD_HEADER_SIZE] {
        let mut buf = [0u8; LIGHT_SHARD_HEADER_SIZE];
        let mut off = 0;

        buf[off..off + 4].copy_from_slice(&self.height.to_le_bytes());                off += 4;
        buf[off..off + 4].copy_from_slice(&self.delta.to_le_bytes());                 off += 4;
        // WIRE-5: chain_weight intentionally omitted from the wire.
        buf[off..off + 32].copy_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));    off += 32;
        buf[off..off + 32].copy_from_slice(&<[u8; 32]>::from(self.current_mmr_root)); off += 32;
        buf[off..off + 32].copy_from_slice(&self.tx_merkle_root);                    off += 32;
        buf[off..off + 32].copy_from_slice(&self.pow_hash);
        // WIRE-5: shard_id and bits intentionally omitted from the wire.
        debug_assert_eq!(off + 32, LIGHT_SHARD_HEADER_SIZE);

        buf
    }

    /// Return the plain block hash (SHA256d).
    ///
    /// Returns the PoW hash stored in this header.
    pub fn hash(&self) -> [u8; 32] {
        self.pow_hash
    }

    /// Compute the canonical MMR-leaf hash (WeightedHash) for this block.
    ///
    /// Copies in-memory compact **rBits** (`self.bits`) into the leaf via
    /// [`WeightedHash::from_leaf_rbits`]. A wire-deserialised header with
    /// `bits == 0` must not call this until bits are restored from context.
    pub fn hash_weighted(&self) -> WeightedHash {
        WeightedHash::from_leaf_rbits(&self.pow_hash, self.bits)
    }

    /// Deserialise from exactly [`LIGHT_SHARD_HEADER_SIZE`] bytes.
    ///
    /// Wire-omitted fields are zeroed: `shard_id = 0`, `bits = 0`,
    /// `chain_weight = 0`. Prefer [`Self::deserialize_with_shard_id`] when the
    /// enclosing shard context is known.
    ///
    /// # Panics
    /// Panics if `bytes.len() < LIGHT_SHARD_HEADER_SIZE`.
    pub fn deserialize(bytes: &[u8]) -> Self {
        Self::deserialize_with_shard_id(bytes, 0)
    }

    /// Deserialise and reconstruct `shard_id` from the receiver's context
    /// (which shard's `header_cache` / connection this payload came from).
    ///
    /// `bits` and `chain_weight` remain zero — PoW target is deferred to the
    /// block body; chain weight must be recomputed from MMR peaks before the
    /// header is trusted for fork choice.
    ///
    /// # Panics
    /// Panics if `bytes.len() < LIGHT_SHARD_HEADER_SIZE`.
    pub fn deserialize_with_shard_id(bytes: &[u8], shard_id: u16) -> Self {
        assert!(
            bytes.len() >= LIGHT_SHARD_HEADER_SIZE,
            "LightShardHeader::deserialize: need {} bytes, got {}",
            LIGHT_SHARD_HEADER_SIZE,
            bytes.len(),
        );

        let mut off = 0usize;

        let height = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()); off += 4;
        let delta = i32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()); off += 4;

        let mut prev_arr = [0u8; 32];
        prev_arr.copy_from_slice(&bytes[off..off + 32]);
        let prev_mmr_root = WeightedHash::from(prev_arr); off += 32;

        let mut cur_arr = [0u8; 32];
        cur_arr.copy_from_slice(&bytes[off..off + 32]);
        let current_mmr_root = WeightedHash::from(cur_arr); off += 32;

        let mut tx_merkle_root = [0u8; 32];
        tx_merkle_root.copy_from_slice(&bytes[off..off + 32]); off += 32;

        let mut pow_hash = [0u8; 32];
        pow_hash.copy_from_slice(&bytes[off..off + 32]);

        LightShardHeader {
            height,
            delta,
            chain_weight: 0, // WIRE-5: not on wire; recompute locally
            prev_mmr_root,
            current_mmr_root,
            tx_merkle_root,
            pow_hash,
            shard_id,        // reconstructed from context
            bits: 0,         // WIRE-5: not on wire; deferred to block body
        }
    }
}

/// A complete shard block with header and transactions
///
/// CANDIDATE STAGE: After PoW, awaiting validation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    /// Block header (metadata and PoW)
    pub header: FullShardHeader,

    /// All transactions in this block
    pub transactions: Vec<Transaction>,

    /// NC-103 fix (Aug 28, 2026): transient, never-serialized flag set only
    /// by [`ShardWireBlock::into_block`]/[`ShardWireBlock::into_block_with_transactions`]
    /// when they have *just* independently recomputed the flat body's real
    /// commitment (extensions included) and confirmed it matches
    /// `header.tx_merkle_root`, immediately before that flat body is
    /// consumed into `transactions: Vec<Transaction>` (which structurally
    /// cannot carry `ShardBlockBody.extensions` — e.g. TS-T-11's coinbase
    /// producer stamp). Downstream re-derivation of the commitment from
    /// `transactions` alone (`ShardBlockBody::from_transactions(&txs, None)`)
    /// is *provably* wrong whenever the original body carried any
    /// extension — not a rare edge case, since every real coinbase does —
    /// and was the root cause of shard chains permanently stalling at
    /// height 1 (see `docs/plan/Correctness_and_Validation_Plan.md` NC-103:
    /// `validate_shard_block_structure` recomputing a merkle root that can
    /// never match once extensions are dropped). `Block::new` always
    /// defaults this to `false` — every other construction path (mining,
    /// side-block-pool reconstruction via `block_for_reorg`, test fixtures)
    /// still gets the full, real recompute; only the one path that just
    /// verified the *original* flat bytes is allowed to skip the redundant
    /// (and here, unsound) re-check.
    #[serde(skip, default)]
    pub commitment_verified: bool,
}

impl Block {
    /// Create a new block with header and transactions
    ///
    /// CANDIDATE STAGE: During block candidate construction
    pub fn new(header: FullShardHeader, transactions: Vec<Transaction>) -> Self {
        Block { header, transactions, commitment_verified: false }
    }

    /// Calculate total block size in bytes
    /// Includes header + all transactions
    /// 
    /// TEMPLATE/CANDIDATE STAGE: For size validation
    pub fn size(&self) -> usize {
        self.header.to_cache_bytes().len() + self.transactions.iter().map(|tx| tx.size()).sum::<usize>()
    }

    /// Wire size in bytes: the length of this block's `ShardWireBlock` encoding. This is the
    /// quantity the shard block size limit counts. Needs `transactions` (a flat block received
    /// over P2P has none; its wire size is the payload length).
    pub fn wire_size(&self) -> usize {
        ShardWireBlock::from_block(self).encode().len()
    }

    /// Verify all transactions in this block are valid.
    ///
    /// **Deprecated:** use `validate_shard_block_body` with `BlockValidationUtxo`.
    #[deprecated(
        since = "0.7.0",
        note = "use validate_shard_block_body with BlockValidationUtxo::PositionalDb"
    )]
    pub fn verify_transactions(&self, fork_utxo_overlay: &ForkUtxoOverlay) -> bool {
        let body = ShardBlockBody::from_transactions(&self.transactions, None);
        use crate::common::validation::transactions::{
            block_validation_utxo, validate_shard_block_body, BlockBodyValidationParams,
        };
        #[cfg(feature = "full-node")]
        let validation_utxo = block_validation_utxo(None, fork_utxo_overlay);
        #[cfg(not(feature = "full-node"))]
        let validation_utxo = block_validation_utxo(fork_utxo_overlay);
        validate_shard_block_body(
            &body,
            validation_utxo,
            BlockBodyValidationParams::for_tests(self.header.height, 0),
        )
        .is_ok()
    }
}

// ============================================================================
// FV-12: Flat-vector P2P wire format for shard blocks
// ============================================================================

/// Wire representation of a shard block for P2P transmission (FV-12).
///
/// Replaces `bincode(&Block { header, transactions })` with a compact format:
/// `header_len(4 B LE) + bincode(FullShardHeader) + ShardBlockBody::serialize()`.
///
/// The flat body bytes allow the receiver to verify `tx_merkle_root` from the
/// header without reconstructing `Vec<Transaction>`.  The receiver then calls
/// `append_validated_block` with an empty-transaction `Block` (the full node
/// only needs the header for MMR / header-cache updates).
pub struct ShardWireBlock {
    pub header: FullShardHeader,
    pub body:   ShardBlockBody,
}

impl ShardWireBlock {
    /// Build from a `Block` that still carries `Vec<Transaction>` (mining-pool
    /// path).  Converts transactions to the flat body representation.
    pub fn from_block(block: &Block) -> Self {
        let body = ShardBlockBody::flat_body_for_merkle(
            &block.transactions,
            block.header.tx_merkle_root,
        )
        .unwrap_or_else(|_| ShardBlockBody::from_transactions(&block.transactions, None));
        Self {
            header: block.header.clone(),
            body,
        }
    }

    /// Encode to wire bytes.
    ///
    /// Layout: `header_len(4 B LE) + bincode(FullShardHeader) + ShardBlockBody::serialize()`.
    pub fn encode(&self) -> Vec<u8> {
        // WIRE-5 (Jul 16, 2026): fixed, not variable, integer encoding.
        // `bincode::config::standard()`'s default (`Varint`) makes every
        // scalar field's encoded width depend on its *value*, not just its
        // type — that silently defeats the point of the `hash`-before-
        // `merged_mining_proof` field reorder above, which only produces a
        // genuinely fixed-size, decode-free prefix when every field ahead of
        // `merged_mining_proof` has a value-independent width. See
        // `OPTIMIZATION_PLAN.md` §23 and the `wire5_1_...` regression test.
        let header_bytes = bincode::serde::encode_to_vec(
            &self.header, bincode::config::standard().with_fixed_int_encoding(),
        ).expect("FullShardHeader bincode encode");
        let body_bytes = self.body.serialize();
        let hlen = header_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + header_bytes.len() + body_bytes.len());
        out.extend_from_slice(&hlen.to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body_bytes);
        out
    }

    /// Decode from wire bytes produced by `encode`.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("shard wire block too short for header_len".into());
        }
        let hlen = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + hlen {
            return Err(format!(
                "shard wire block header truncated: need {} body bytes, have {}",
                hlen, bytes.len() - 4
            ));
        }
        let (header, _): (FullShardHeader, _) = bincode::serde::decode_from_slice(
            &bytes[4..4 + hlen], bincode::config::standard().with_fixed_int_encoding(),
        ).map_err(|e| format!("FullShardHeader decode: {e}"))?;
        let body = ShardBlockBody::deserialize(&bytes[4 + hlen..])
            .map_err(|e| format!("ShardBlockBody decode: {e}"))?;
        Ok(Self { header, body })
    }

    /// Returns `true` if `body.calculate_tx_merkle_root() == header.tx_merkle_root`.
    pub fn verify_commitment(&self) -> bool {
        self.body.calculate_tx_merkle_root() == self.header.tx_merkle_root
    }

    /// Reconstruct a `Block` with real transactions via
    /// [`ShardBlockBody::to_transactions`] (CV-81).
    ///
    /// **NC-92 (Aug 25, 2026):** this used to return `Block::new(header, vec![])`
    /// ("header-only — full node only needs the header"). That was true for
    /// MMR/fork-choice, but false once Keystone's `persist_block_to_p1db` /
    /// `build_shard_phase1_delta` derive UTXO *creates* from
    /// `block.transactions` — every P2P-applied shard block wrote an empty
    /// create set, so `GET /shard/{id}/utxo/{h}/{idx}` 404'd forever while
    /// tip height advanced (FS-B / tx-filler / faucet broken; Path-2 watch
    /// still worked because it clones `wire.body().outputs` *before* this
    /// call). Always reconstruct txs now. On descriptor decode failure,
    /// falls back to empty txs and logs — prefer
    /// [`Self::into_block_with_transactions`] when empty creates must fail
    /// closed.
    ///
    /// P10W-5: callers that need the flat body without going through
    /// `Transaction` (e.g. LC-44 watch matching) may still read `self.body()`
    /// before this call; after the call the body is consumed into txs.
    pub fn into_block(self) -> Block {
        // NC-103 fix (Aug 28, 2026): recompute the commitment from the
        // *original* flat body — extensions included — before it is
        // consumed by `to_transactions()` below, and stamp the result onto
        // the returned `Block` so a downstream structural re-check
        // (`validate_shard_block_structure`) doesn't redundantly, and
        // unsoundly, re-derive it from extension-less `Transaction`s. See
        // `Block::commitment_verified`'s own doc comment.
        let commitment_verified = self.body.calculate_tx_merkle_root() == self.header.tx_merkle_root;
        match self.body.to_transactions() {
            Ok(transactions) => {
                let mut block = Block::new(self.header, transactions);
                block.commitment_verified = commitment_verified;
                block
            }
            Err(e) => {
                log::warn!(
                    "ShardWireBlock::into_block: to_transactions failed ({e}); \
                     empty transactions — P1DB creates will be empty (NC-92 class)"
                );
                Block::new(self.header, vec![])
            }
        }
    }

    /// Same as [`Self::into_block`], but returns `Err` instead of falling back
    /// to an empty transaction list when descriptor slices are corrupt.
    /// Prefer this in mining-pool appliers and any path that must not silently
    /// drop UTXO creates.
    pub fn into_block_with_transactions(self) -> Result<Block, String> {
        // NC-103 fix (Aug 28, 2026): see `into_block`'s identical comment
        // and `Block::commitment_verified`'s own doc comment.
        let commitment_verified = self.body.calculate_tx_merkle_root() == self.header.tx_merkle_root;
        let transactions = self.body.to_transactions()?;
        let mut block = Block::new(self.header, transactions);
        block.commitment_verified = commitment_verified;
        Ok(block)
    }

    /// P10W-5: borrow the flat body (outputs/inputs/witnesses/extensions/
    /// descriptors) before it is discarded by `into_block()`.
    pub fn body(&self) -> &ShardBlockBody {
        &self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn make_test_beacon_header() -> BeaconHeader {
        let bitcoin_anchor: u64 = 1_704_067_200;
        let timestamp = bitcoin_anchor + 1_000_000;
        BeaconHeader::new(
            1,                             // version
            timestamp,                     // timestamp
            42,                            // nonce
            WeightedHash::from([1u8; 32]), // prev_mmr_root
            [2u8; 32],                     // merged_mining_root
            0x1d00ffff,                    // bits
            bitcoin_anchor,                // bitcoin_anchor_timestamp
            100,                           // beacon_height
            [3u8; 32],                     // beacon_merkle_root
        )
    }

    #[test]
    fn test_beacon_header_has_all_pow_fields() {
        let bitcoin_anchor: u64 = 1_704_067_200;
        let timestamp = bitcoin_anchor + 1_000_000;
        let beacon_header = make_test_beacon_header();

        assert_eq!(beacon_header.version, 1);
        // Must match `BeaconHeader::new` / `BeaconBlockCandidateHeader::new`
        // (runtime `beacon_interval_secs()`, default 600).
        let beacon_secs = crate::common::block_intervals::beacon_interval_secs() as i64;
        let beacon_height: i64 = 100;
        let expected_delta = ((timestamp as i64 - bitcoin_anchor as i64) * 256
            - beacon_height * beacon_secs * 256) as i32;
        assert_eq!(beacon_header.delta, expected_delta);
        assert_eq!(beacon_header.nonce, 42);
        assert_eq!(<[u8; 32]>::from(beacon_header.prev_mmr_root), [1u8; 32]);
        assert_eq!(beacon_header.merged_mining_root, [2u8; 32]);
        assert_eq!(beacon_header.bits, 0x1d00ffff);
        assert_eq!(beacon_header.beacon_height, 100);
        assert_eq!(beacon_header.beacon_merkle_root, [3u8; 32]);
    }

    #[test]
    fn from_mined_candidate_copies_delta_and_applies_ntime_roll() {
        use crate::common::blocks::beacon_block::BeaconBlockCandidateHeader;

        let mut template = BeaconBlockCandidateHeader::new(
            1,
            1_704_067_200 + 150,
            1,
            0x1d00ffff,
            WeightedHash::from([1u8; 32]),
            [2u8; 32],
            [3u8; 32],
            1_704_067_200,
        );
        template.delta = 205_568; // arbitrary job delta (not necessarily from ::new)
        template.committed_chain_count = 4;

        let header = BeaconHeader::from_mined_candidate(
            &template,
            7,          // share version
            0xdead_beef, // share nonce
            1_000_002,  // share ntime (+2s roll)
            1_000_000,  // template ntime
            [0u8; 32],  // coinbase_hash (legacy v2 path — this test is about delta/ntime-roll, not hash formula)
        );

        assert_eq!(header.version, 7);
        assert_eq!(header.nonce, 0xdead_beef);
        assert_eq!(header.delta, 205_568 + 2 * 256);
        assert_eq!(header.committed_chain_count, 4);
        assert_eq!(header.beacon_height, 1);
        assert_eq!(header.beacon_merkle_root, [2u8; 32]);
        assert_eq!(header.merged_mining_root, [3u8; 32]);
        assert_eq!(<[u8; 32]>::from(header.prev_mmr_root), [1u8; 32]);
    }

    #[test]
    fn test_beacon_header_serialization_for_mining() {
        let beacon_header = make_test_beacon_header();
        let serialized = beacon_header.serialize_for_mining();
        assert_eq!(serialized.len(), 80);
    }

    /// SBH-1: `serialize_for_mining()` puts `commitment_hash` at bytes [36..68],
    /// matching the structure of `BeaconBlockCandidateHeader::serialize_for_mining()`.
    ///
    /// Fixed 2026-07-16: this test used to hand-roll a 3-field Blake3 input
    /// (height || beacon_merkle_root || merged_mining_root, no trailing bytes
    /// at all) as its "expected" value — a formula that, it turns out, never
    /// actually matched the real beacon commitment hash even when
    /// `committed_chain_count == 0`, since `calculate_commitment_hash_from_parts_v2`
    /// always appends the 2-byte count field to its Blake3 input, zero or not.
    /// Now calls the same shared function `serialize_for_mining()` itself
    /// calls, so this test can never silently re-diverge from the source
    /// the way the old hand-rolled copy did.
    #[test]
    fn test_beacon_header_serialize_for_mining_uses_commitment_hash() {
        let beacon_header = make_test_beacon_header();
        let serialized = beacon_header.serialize_for_mining();

        // Bytes [4..36] must be prev_mmr_root
        assert_eq!(&serialized[4..36], &<[u8; 32]>::from(beacon_header.prev_mmr_root));

        // Bytes [36..68] must equal commitment_hash = Blake3(beacon_height ||
        // beacon_merkle_root || merged_mining_root || committed_chain_count).
        // Blake3 is used (not SHA256d) — see calculate_commitment_hash_from_parts for rationale.
        let expected_commitment = crate::common::blocks::beacon_block::calculate_commitment_hash_from_parts_v2(
            beacon_header.beacon_height,
            beacon_header.beacon_merkle_root,
            beacon_header.merged_mining_root,
            beacon_header.committed_chain_count,
        );
        assert_eq!(&serialized[36..68], &expected_commitment,
            "SBH-1: bytes [36..68] must be commitment_hash (Blake3), not raw merged_mining_root");

        // merged_mining_root must NOT appear raw at bytes [36..68]
        assert_ne!(&serialized[36..68], &beacon_header.merged_mining_root,
            "SBH-1: raw merged_mining_root must not appear at bytes [36..68]");
    }

    /// New (2026-07-16): `committed_chain_count` must actually change the
    /// commitment hash — the precise gap the construction-site bug (never
    /// setting this field on the auxiliary header) and the hash-formula bug
    /// (never hashing it) combined to hide. Guards against silent
    /// re-regression of either half.
    #[test]
    fn test_beacon_header_commitment_hash_covers_committed_chain_count() {
        let mut with_zero = make_test_beacon_header();
        with_zero.committed_chain_count = 0;
        let mut with_nonzero = make_test_beacon_header();
        with_nonzero.committed_chain_count = 4;

        let hash_zero = &with_zero.serialize_for_mining()[36..68];
        let hash_nonzero = &with_nonzero.serialize_for_mining()[36..68];
        assert_ne!(hash_zero, hash_nonzero,
            "committed_chain_count must be part of the commitment hash preimage");

        // And it must match the real beacon header's own formula for the same inputs.
        let expected_nonzero = crate::common::blocks::beacon_block::calculate_commitment_hash_from_parts_v2(
            with_nonzero.beacon_height,
            with_nonzero.beacon_merkle_root,
            with_nonzero.merged_mining_root,
            with_nonzero.committed_chain_count,
        );
        assert_eq!(hash_nonzero, &expected_nonzero);
    }

    #[test]
    fn test_beacon_header_pow_hash_calculation() {
        let beacon_header = make_test_beacon_header();
        let hash = beacon_header.hash();
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, beacon_header.hash()); // deterministic
    }

    #[test]
    fn test_beacon_header_full_serialization() {
        let beacon_header = make_test_beacon_header();
        let serialized = beacon_header.serialize();
        // 4 (version) + 4 (delta) + 8 (nonce) + 32 (prev) + 32 (merged) + 4 (bits)
        // + 4 (beacon_height) + 32 (beacon_merkle_root) = 120 bytes
        assert_eq!(serialized.len(), 120);
    }
}

// ============================================================================
// FLAT-VECTOR BLOCK BODY (FV-3 / FV-4)
// ============================================================================

use crate::transaction::{FlatInput, FlatOutput, TxRange};

/// Extract a 32-byte x-only recipient key from a `script_pubkey` (FV-7 transition helper).
///
/// Recognises P2TR output scripts (OP_1 OP_PUSH32 <32 B>). All other script
/// types are hashed with BLAKE3 to produce a deterministic placeholder that will
/// be replaced when FV-11 migrates `TxOutput` to `FlatOutput` natively.
pub fn script_pubkey_to_recipient(script: &[u8]) -> [u8; 32] {
    // P2TR: 0x51 0x20 <32 bytes> (BIP-341)
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        let mut r = [0u8; 32];
        r.copy_from_slice(&script[2..34]);
        return r;
    }
    // Raw 32-byte pubkey (already flat)
    if script.len() == 32 {
        let mut r = [0u8; 32];
        r.copy_from_slice(script);
        return r;
    }
    // Fallback: BLAKE3 hash of script (deterministic placeholder until FV-11)
    *blake3::hash(script).as_bytes()
}

/// Map a genesis/premine address string to a flat `TxOutput.recipient`.
///
/// A `"0x" + 64-hex`-prefixed string decodes directly to the raw 32-byte
/// x-only Schnorr pubkey it names — this is the only way a premine entry
/// can have a real, spendable key behind it. Any other string (a human
/// label like `"teststress1-faucet"`) falls through to
/// [`script_pubkey_to_recipient`]'s BLAKE3-of-bytes placeholder, which has
/// no corresponding private key and is intentionally unspendable — mirrors
/// `pool_wallet_to_recipient` in `src/mining_pool/epoch_params.rs` (kept in
/// sync manually; that copy also handles a legacy 20-byte P2PKH hex form
/// this genesis path has never needed).
pub fn address_string_to_recipient(address: &str) -> [u8; 32] {
    let addr = address.trim();
    if let Some(hex_str) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) {
        if hex_str.len() == 64 {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let mut r = [0u8; 32];
                    r.copy_from_slice(&bytes);
                    return r;
                }
            }
        }
    }
    script_pubkey_to_recipient(addr.as_bytes())
}

/// Flat-vector shard block body.
///
/// Five flat vectors: outputs, inputs, witnesses, extensions, and descriptors.
/// `descriptors` (formerly `TxRange`) maps logical transactions onto slices of
/// those vectors.  No aggregate signature — CISA/MuSig2 removed.
///
/// # Wire format
/// ```text
/// [n_outputs:     u32 LE]   4 bytes
/// [n_inputs:      u32 LE]   4 bytes
/// [n_witnesses:   u32 LE]   4 bytes
/// [n_extensions:  u32 LE]   4 bytes
/// [tx_count:      u32 LE]   4 bytes
/// [outputs:    n_outputs  × 40 B]  FlatOutput records
/// [inputs:     n_inputs   ×  6 B]  FlatInput records
/// [witnesses:  n_witnesses × var]  WitnessEntry: 4-byte len prefix + data
/// [extensions: n_ext       × var]  ExtensionRecord: 2+2+4-byte header + payload
/// [descriptors: tx_count   × 28 B] TransactionDescriptor records
/// ```
///
/// Total prefix = 20 bytes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ShardBlockBody {
    /// Flat vector of outputs, one entry per output across all transactions.
    pub outputs: Vec<FlatOutput>,
    /// Flat vector of inputs (positional only), one entry per input.
    pub inputs: Vec<FlatInput>,
    /// Flat witness vector — one entry per input, in the same order.
    /// Prunable after validation (SegWit-style).
    pub witnesses: Vec<crate::transaction::WitnessEntry>,
    /// Typed extension records (consensus, application, protocol categories).
    pub extensions: Vec<crate::transaction::ExtensionRecord>,
    /// Transaction boundary descriptors — maps logical transactions onto
    /// slices of `outputs`, `inputs`, `witnesses`, and `extensions`.
    pub descriptors: Vec<crate::transaction::TransactionDescriptor>,
}

impl ShardBlockBody {
    /// Body prefix size: 5 × u32 counts.
    pub const PREFIX_BYTES: usize = 20;

    /// Bytes `tx` adds to a serialized body: outputs (40 B each), inputs (6 B), witnesses
    /// (4 B + data each), extensions (8 B + payload each) and its 28 B descriptor. The block size
    /// limits count these **wire** bytes (witnesses included), not `Transaction::size()`, which
    /// leaves the witnesses out. Computed through [`Self::from_transactions`] and
    /// [`Self::serialize`] themselves so it can never drift from the real encoding; a producer
    /// stamp on the coinbase is not included (the template reserve covers it).
    pub fn tx_wire_size(tx: &crate::transaction::Transaction) -> usize {
        Self::from_transactions(std::slice::from_ref(tx), None).serialize().len() - Self::PREFIX_BYTES
    }

    /// Create an empty body (no transactions).
    pub fn empty() -> Self {
        Self {
            outputs:     Vec::new(),
            inputs:      Vec::new(),
            witnesses:   Vec::new(),
            extensions:  Vec::new(),
            descriptors: Vec::new(),
        }
    }

    /// Build a `ShardBlockBody` from a slice of legacy `Transaction` values.
    ///
    /// Witness descriptors are aligned with input counts (one placeholder
    /// [`WitnessEntry`] per input) so flat-body TX-4 parity holds. Real signature
    /// bytes are populated on the wire path; TX-5 verify is still deferred (CV-10).
    ///
    /// When `producer_stamp` is `Some("A"|"B")`, transaction index 0 (coinbase)
    /// receives an application extension that is included in `txid` / merkle root
    /// (TS-T-11).
    pub fn from_transactions(
        txs: &[crate::transaction::Transaction],
        producer_stamp: Option<&str>,
    ) -> Self {
        let total_outputs: usize = txs.iter().map(|t| t.outputs.len()).sum();
        let total_inputs:  usize = txs.iter().map(|t| t.inputs.len()).sum();

        let mut outputs     = Vec::with_capacity(total_outputs);
        let mut inputs      = Vec::with_capacity(total_inputs);
        let mut witnesses   = Vec::new();
        let mut descriptors = Vec::with_capacity(txs.len());

        let mut out_cursor: u32 = 0;
        let mut in_cursor:  u32 = 0;
        let mut wit_cursor: u32 = 0;

        let mut extensions = Vec::new();
        let mut ext_cursor: u32 = 0;

        for (tx_idx, tx) in txs.iter().enumerate() {
            let out_start = out_cursor;
            let in_start  = in_cursor;
            let wit_start = wit_cursor;
            let ext_start = ext_cursor;

            for out in &tx.outputs {
                outputs.push(FlatOutput { value: out.value, recipient: out.recipient });
                out_cursor += 1;
            }

            for (inp_idx, inp) in tx.inputs.iter().enumerate() {
                inputs.push(FlatInput {
                    prev_height:     inp.prev_height,
                    prev_output_idx: inp.prev_output_idx,
                });
                in_cursor += 1;

                let witness_data = tx
                    .witnesses
                    .get(inp_idx)
                    .map(|w| w.witness_data.clone())
                    .unwrap_or_default();
                witnesses.push(crate::transaction::WitnessEntry { witness_data });
                wit_cursor += 1;
            }

            let version_u8 = tx.version;
            let mut ext_len: u16 = 0;
            if crate::transaction::needs_validity_extension(
                version_u8,
                tx.locktime,
                tx.expiration_height,
            ) {
                extensions.push(crate::transaction::build_validity_extension(
                    version_u8,
                    tx.locktime,
                    tx.expiration_height,
                ));
                ext_cursor += 1;
                ext_len += 1;
            }

            // Non-validity records carried by the transaction itself (VF-3):
            // application records, a round-tripped producer stamp or extranonce.
            for ext in &tx.extensions {
                if ext.header.extension_type == crate::transaction::CONSENSUS_EXT_VALIDITY_WINDOW {
                    continue;
                }
                extensions.push(ext.clone());
                ext_cursor += 1;
                ext_len += 1;
            }

            if tx_idx == 0 {
                if let Some(stamp) = producer_stamp {
                    let already_stamped = tx.extensions.iter().any(|e| {
                        e.header.extension_type == crate::transaction::APPLICATION_EXT_PRODUCER_ID
                    });
                    if !already_stamped {
                        if let Some(ext) = crate::transaction::build_producer_stamp_extension(stamp) {
                            extensions.push(ext);
                            ext_cursor += 1;
                            ext_len += 1;
                        }
                    }
                }
            }

            descriptors.push(crate::transaction::TransactionDescriptor {
                out_start,
                out_len: out_cursor - out_start,
                in_start,
                in_len: in_cursor - in_start,
                witness_start: wit_start,
                witness_len: (in_cursor - in_start) as u16,
                extension_start: ext_start,
                extension_len: ext_len,
            });
        }

        Self { outputs, inputs, witnesses, extensions, descriptors }
    }

    /// Reconstruct the flat body whose `tx_merkle_root` matches `expected_root`.
    ///
    /// One canonical reconstruction: `from_transactions(txs, None)`, compared once against
    /// `expected_root`. Since VF-3 Phase 1 every non-validity extension (the TS-T-11 producer
    /// stamp included) lives in `Transaction.extensions` and round-trips through
    /// [`Self::to_transactions`], so there is nothing to guess. OPT-APPLY-ALT-DOUBLE-DECODE-1 P1
    /// (Oct 20, 2026) removed the old `None`/`"A"`/`"B"` loop (up to 3.7x the cost, and a latent
    /// false-reject whenever a new extension type appeared).
    ///
    /// A block whose coinbase was stamped out of band (stamp not in `tx.extensions`) no longer
    /// matches here; local mining now stamps the coinbase transaction itself.
    pub fn flat_body_for_merkle(
        txs: &[crate::transaction::Transaction],
        expected_root: [u8; 32],
    ) -> Result<Self, String> {
        let body = Self::from_transactions(txs, None);
        if body.calculate_tx_merkle_root() == expected_root {
            Ok(body)
        } else {
            Err("tx_merkle_root mismatch".into())
        }
    }

    /// Inverse of `from_transactions` — reconstructs the legacy `Vec<Transaction>`
    /// shape from this flat body (CV-81).
    ///
    /// For each `TransactionDescriptor`, slices `outputs`/`inputs`/`witnesses` by
    /// its recorded ranges (`TxOutput`/`TxInput` are field-identical to
    /// `FlatOutput`/`FlatInput` — see their doc comments) and scans its extension
    /// range for a `CONSENSUS_EXT_VALIDITY_WINDOW` record to recover
    /// `version`/`locktime`/`expiration_height` (defaulting to `FlatTxMeta::default()`
    /// — version 1, locktime 0, expiration 0 — when absent, matching
    /// `needs_validity_extension`'s condition for omitting it on the way in).
    ///
    /// Deliberately does **not** reuse `flat_tx_meta::parse_flat_tx_meta`: that
    /// function assumes a descriptor's extension slot holds *only* the validity
    /// record and errors on anything else, which breaks for a testnet-stress
    /// coinbase — its extension slot also carries a producer-stamp record
    /// (`producer_stamp::build_producer_stamp_extension`, type `0x1001`) in the
    /// same range. This scans for the validity type specifically rather than
    /// assuming a strict 0-or-1 count. Every other record (stamps included) is
    /// kept in `Transaction::extensions`, in slice order, so the txid computed
    /// from the rebuilt transaction equals `txid_at` on this body (VF-3).
    ///
    /// Returns `Err` on any out-of-bounds descriptor range (corrupt/malicious
    /// input) rather than panicking.
    pub fn to_transactions(&self) -> Result<Vec<crate::transaction::Transaction>, String> {
        use crate::transaction::flat_tx_meta::{FlatTxMeta, CONSENSUS_EXT_VALIDITY_WINDOW};
        use crate::transaction::{Transaction, TxInput, TxOutput};

        let mut txs = Vec::with_capacity(self.descriptors.len());

        for (tx_idx, d) in self.descriptors.iter().enumerate() {
            let out_end = (d.out_start as usize)
                .checked_add(d.out_len as usize)
                .filter(|&e| e <= self.outputs.len())
                .ok_or_else(|| format!("to_transactions: tx {tx_idx} output slice out of bounds"))?;
            let in_end = (d.in_start as usize)
                .checked_add(d.in_len as usize)
                .filter(|&e| e <= self.inputs.len())
                .ok_or_else(|| format!("to_transactions: tx {tx_idx} input slice out of bounds"))?;
            let wit_end = (d.witness_start as usize)
                .checked_add(d.witness_len as usize)
                .filter(|&e| e <= self.witnesses.len())
                .ok_or_else(|| format!("to_transactions: tx {tx_idx} witness slice out of bounds"))?;
            let ext_end = (d.extension_start as usize)
                .checked_add(d.extension_len as usize)
                .filter(|&e| e <= self.extensions.len())
                .ok_or_else(|| format!("to_transactions: tx {tx_idx} extension slice out of bounds"))?;

            let outputs: Vec<TxOutput> = self.outputs[d.out_start as usize..out_end]
                .iter()
                .map(|o| TxOutput { value: o.value, recipient: o.recipient })
                .collect();
            let inputs: Vec<TxInput> = self.inputs[d.in_start as usize..in_end]
                .iter()
                .map(|i| TxInput { prev_height: i.prev_height, prev_output_idx: i.prev_output_idx })
                .collect();
            let witnesses = self.witnesses[d.witness_start as usize..wit_end].to_vec();

            let meta = self.tx_meta_at(tx_idx).map_err(|e| format!("to_transactions: {e}"))?;
            let extensions: Vec<crate::transaction::ExtensionRecord> = self.extensions
                [d.extension_start as usize..ext_end]
                .iter()
                .filter(|e| e.header.extension_type != CONSENSUS_EXT_VALIDITY_WINDOW)
                .cloned()
                .collect();

            txs.push(Transaction {
                version: meta.version,
                inputs,
                outputs,
                locktime: meta.locktime,
                expiration_height: meta.expiration_height,
                witnesses,
                extensions,
            });
        }

        Ok(txs)
    }

    /// Total number of outputs across all transactions.
    pub fn n_outputs(&self) -> u32 { self.outputs.len() as u32 }

    /// Total number of inputs across all transactions.
    pub fn n_inputs(&self) -> u32 { self.inputs.len() as u32 }

    /// Number of logical transactions.
    pub fn tx_count(&self) -> u32 { self.descriptors.len() as u32 }

    /// Returns `true` if the first descriptor is a coinbase (in_len == 0).
    pub fn has_coinbase(&self) -> bool {
        self.descriptors.first().map_or(false, |d| d.is_coinbase())
    }

    /// Validity-window meta of descriptor `idx`: scans its extension range for a
    /// `CONSENSUS_EXT_VALIDITY_WINDOW` record, else `FlatTxMeta::default()`.
    fn tx_meta_at(&self, tx_idx: usize) -> Result<crate::transaction::FlatTxMeta, String> {
        use crate::transaction::flat_tx_meta::{
            FlatTxMeta, CONSENSUS_EXT_VALIDITY_WINDOW, VALIDITY_EXTENSION_PAYLOAD_LEN,
        };
        let d = self
            .descriptors
            .get(tx_idx)
            .ok_or_else(|| format!("tx {tx_idx}: no such descriptor"))?;
        let ext_end = (d.extension_start as usize)
            .checked_add(d.extension_len as usize)
            .filter(|&e| e <= self.extensions.len())
            .ok_or_else(|| format!("tx {tx_idx} extension slice out of bounds"))?;
        self.extensions[d.extension_start as usize..ext_end]
            .iter()
            .find(|e| e.header.extension_type == CONSENSUS_EXT_VALIDITY_WINDOW)
            .map(|e| {
                // VF-2: see `flat_tx_meta::parse_validity_extension_record`.
                if e.header.version != crate::transaction::flat_tx_meta::VALIDITY_EXTENSION_HEADER_VERSION {
                    return Err(format!(
                        "tx {tx_idx} validity extension header version {} (expected {})",
                        e.header.version,
                        crate::transaction::flat_tx_meta::VALIDITY_EXTENSION_HEADER_VERSION,
                    ));
                }
                if e.payload.len() != VALIDITY_EXTENSION_PAYLOAD_LEN {
                    return Err(format!(
                        "tx {tx_idx} validity extension payload length {} (expected {})",
                        e.payload.len(),
                        VALIDITY_EXTENSION_PAYLOAD_LEN,
                    ));
                }
                let meta = FlatTxMeta {
                    version: e.payload[0],
                    locktime: u32::from_le_bytes(e.payload[1..5].try_into().unwrap()),
                    expiration_height: u32::from_le_bytes(e.payload[5..9].try_into().unwrap()),
                };
                // Canonical encoding: see `flat_tx_meta::parse_validity_extension_record`.
                if !crate::transaction::flat_tx_meta::needs_validity_extension(
                    meta.version, meta.locktime, meta.expiration_height,
                ) {
                    return Err(format!(
                        "tx {tx_idx} validity extension repeats the defaults: omit the record instead"
                    ));
                }
                Ok(meta)
            })
            .transpose()
            .map(|m| m.unwrap_or_default())
    }

    /// The txid of transaction `idx` on chain `chain_id`, computed from this body's
    /// slices (VF-3 §3.1). Equal to `Transaction::txid(chain_id)` of the same
    /// transaction; `None` for an out-of-range or malformed descriptor.
    pub fn txid_at(&self, idx: usize, chain_id: u16) -> Option<[u8; 32]> {
        let d = self.descriptors.get(idx)?;
        let meta = self.tx_meta_at(idx).ok()?;
        let ins = self.inputs.get(d.in_start as usize..(d.in_start as usize).checked_add(d.in_len as usize)?)?;
        let outs = self.outputs.get(d.out_start as usize..(d.out_start as usize).checked_add(d.out_len as usize)?)?;
        let exts = self.extensions.get(
            d.extension_start as usize..(d.extension_start as usize).checked_add(d.extension_len as usize)?,
        )?;
        Some(crate::transaction::txid_from_parts(
            chain_id,
            meta,
            ins.iter().map(|i| (i.prev_height, i.prev_output_idx)),
            outs.iter().map(|o| (o.value, o.recipient)),
            exts,
        ))
    }

    /// Block commitment leaf for transaction `idx` (what `tx_merkle_root` commits to).
    ///
    /// `tx_leaf_hash = BLAKE3(inputs_slice ‖ outputs_slice ‖ witnesses_slice ‖ extensions_slice ‖ descriptor_bytes)`
    ///
    /// **Not a transaction id.** It binds the transaction's absolute offsets in this
    /// block and its witness bytes, so the same transaction gets a different value in
    /// another block or after re-signing. Never key a pool, index or API by it and
    /// never show it to users; use [`Self::txid_at`] / `Transaction::txid` (VF-3).
    pub fn tx_leaf_hash(&self, idx: usize) -> Option<[u8; 32]> {
        let d = self.descriptors.get(idx)?;
        let ins = self.inputs.get(d.in_start as usize..(d.in_start as usize).checked_add(d.in_len as usize)?);
        let outs = self.outputs.get(d.out_start as usize..(d.out_start as usize).checked_add(d.out_len as usize)?);
        let wits = self.witnesses.get(d.witness_start as usize..(d.witness_start as usize).checked_add(d.witness_len as usize)?);
        let exts = self.extensions.get(d.extension_start as usize..(d.extension_start as usize).checked_add(d.extension_len as usize)?);
        // A slice that falls outside the vectors hashes as if absent, as before.
        Some(Self::tx_leaf_hash_from_parts(
            d,
            ins.unwrap_or(&[]),
            outs.unwrap_or(&[]),
            wits.unwrap_or(&[]),
            exts.unwrap_or(&[]),
        ))
    }

    /// The commitment leaf from a transaction's own slices and descriptor. Same bytes as
    /// [`Self::tx_leaf_hash`]; lets a verifier recompute it from a [`TxInclusionProof`]
    /// without the rest of the block.
    pub fn tx_leaf_hash_from_parts(
        d: &crate::transaction::TransactionDescriptor,
        inputs: &[FlatInput],
        outputs: &[FlatOutput],
        witnesses: &[crate::transaction::WitnessEntry],
        extensions: &[crate::transaction::ExtensionRecord],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for inp in inputs { h.update(&inp.to_bytes()); }
        for out in outputs { h.update(&out.to_bytes()); }
        for w in witnesses {
            h.update(&(w.witness_data.len() as u32).to_le_bytes());
            h.update(&w.witness_data);
        }
        for e in extensions {
            h.update(&e.header.extension_type.to_le_bytes());
            h.update(&e.header.version.to_le_bytes());
            h.update(&(e.payload.len() as u32).to_le_bytes());
            h.update(&e.payload);
        }
        h.update(&d.to_bytes());
        h.finalize().into()
    }

    /// Merkle leaf node for transaction `idx`: `BLAKE3(idx_le32 || tx_leaf_hash)`.
    pub fn tx_merkle_node(idx: u32, tx_leaf_hash: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&idx.to_le_bytes());
        h.update(tx_leaf_hash);
        h.finalize().into()
    }

    /// Sibling hashes from transaction `idx` up to `tx_merkle_root` (an odd level pairs
    /// the last node with itself, as in [`Self::calculate_tx_merkle_root`]).
    pub fn tx_merkle_path(&self, idx: usize) -> Option<Vec<[u8; 32]>> {
        let n = self.descriptors.len();
        if idx >= n {
            return None;
        }
        let mut nodes: Vec<[u8; 32]> = (0..n)
            .map(|i| Self::tx_merkle_node(i as u32, &self.tx_leaf_hash(i).unwrap_or([0u8; 32])))
            .collect();
        let mut pos = idx;
        let mut path = Vec::new();
        while nodes.len() > 1 {
            let sib = if pos ^ 1 < nodes.len() { nodes[pos ^ 1] } else { nodes[pos] };
            path.push(sib);
            let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
            for i in (0..nodes.len()).step_by(2) {
                let left = nodes[i];
                let right = if i + 1 < nodes.len() { nodes[i + 1] } else { left };
                let mut h = blake3::Hasher::new();
                h.update(&left);
                h.update(&right);
                next.push(h.finalize().into());
            }
            nodes = next;
            pos >>= 1;
        }
        Some(path)
    }

    /// Check a path from transaction `idx`'s leaf to `root`.
    pub fn verify_tx_merkle_path(idx: u32, tx_leaf_hash: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
        let mut cur = Self::tx_merkle_node(idx, tx_leaf_hash);
        let mut pos = idx;
        for sib in path {
            let mut h = blake3::Hasher::new();
            if pos & 1 == 0 {
                h.update(&cur);
                h.update(sib);
            } else {
                h.update(sib);
                h.update(&cur);
            }
            cur = h.finalize().into();
            pos >>= 1;
        }
        &cur == root
    }

    /// Proof that the output at global index `output_idx` is committed by this block's
    /// `tx_merkle_root`: the owning transaction's slices and the Merkle path.
    pub fn tx_inclusion_proof(&self, height: u32, output_idx: u32) -> Option<TxInclusionProof> {
        let idx = self.descriptors.iter().position(|d| {
            output_idx >= d.out_start && (output_idx as u64) < d.out_start as u64 + d.out_len as u64
        })?;
        let d = self.descriptors[idx];
        let ins = self.inputs.get(d.in_start as usize..d.in_start as usize + d.in_len as usize)?;
        let outs = self.outputs.get(d.out_start as usize..d.out_start as usize + d.out_len as usize)?;
        let wits = self.witnesses.get(d.witness_start as usize..d.witness_start as usize + d.witness_len as usize)?;
        let exts = self.extensions.get(d.extension_start as usize..d.extension_start as usize + d.extension_len as usize)?;
        Some(TxInclusionProof {
            height,
            output_idx,
            tx_idx: idx as u32,
            descriptor: d,
            inputs: ins.to_vec(),
            outputs: outs.to_vec(),
            witnesses: wits.to_vec(),
            extensions: exts.to_vec(),
            path: self.tx_merkle_path(idx)?,
        })
    }

    /// Compute `tx_merkle_root` = MerkleRoot([txid_0, ..., txid_n]).
    ///
    /// Returns `[0u8; 32]` for an empty body.  This is the sole transaction
    /// commitment placed in the block header (replaces `tx_merkle_root`).
    pub fn calculate_tx_merkle_root(&self) -> [u8; 32] {
        if self.descriptors.is_empty() {
            return [0u8; 32];
        }
        let txids: Vec<Vec<u8>> = (0..self.descriptors.len())
            .map(|i| self.tx_leaf_hash(i).unwrap_or([0u8; 32]).to_vec())
            .collect();
        Self::position_binding_merkle(&txids)
    }

    /// Serialise the body to bytes (wire format).
    ///
    /// Variable-length sections (witnesses, extensions) use 4-byte LE length prefixes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&(self.outputs.len()     as u32).to_le_bytes());
        buf.extend_from_slice(&(self.inputs.len()      as u32).to_le_bytes());
        buf.extend_from_slice(&(self.witnesses.len()   as u32).to_le_bytes());
        buf.extend_from_slice(&(self.extensions.len()  as u32).to_le_bytes());
        buf.extend_from_slice(&(self.descriptors.len() as u32).to_le_bytes());

        for o in &self.outputs    { buf.extend_from_slice(&o.to_bytes()); }
        for i in &self.inputs     { buf.extend_from_slice(&i.to_bytes()); }
        for w in &self.witnesses  {
            buf.extend_from_slice(&(w.witness_data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&w.witness_data);
        }
        for e in &self.extensions {
            buf.extend_from_slice(&e.header.extension_type.to_le_bytes());
            buf.extend_from_slice(&e.header.version.to_le_bytes());
            buf.extend_from_slice(&(e.payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&e.payload);
        }
        for d in &self.descriptors { buf.extend_from_slice(&d.to_bytes()); }

        buf
    }

    /// Deserialise from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::PREFIX_BYTES {
            return Err("body too short for header");
        }
        let n_out  = u32::from_le_bytes(data[0..4].try_into().unwrap())   as usize;
        let n_in   = u32::from_le_bytes(data[4..8].try_into().unwrap())   as usize;
        let n_wit  = u32::from_le_bytes(data[8..12].try_into().unwrap())  as usize;
        let n_ext  = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let n_tx   = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

        let mut pos = Self::PREFIX_BYTES;

        // NC-75: bound each wire-supplied count against the minimum possible
        // per-entry size before trusting it as a `Vec::with_capacity`
        // argument — each entry type has a known minimum wire size (outputs
        // 40B, inputs 6B, witness/extension length prefixes 4B/8B,
        // descriptors 28B), so a count that could never fit in the
        // remaining bytes is provably garbage (a corrupted payload, or one
        // encoded with the wrong wire format entirely — see NC-75's real
        // root cause in `ChainProvider::block_bytes_at`). Without this, a
        // garbage count causes an unguarded multi-hundred-GB allocation
        // abort here, on the hot path every real block decode goes through.
        let remaining = data.len().saturating_sub(pos);
        if n_out > remaining / 40 || n_in > remaining / 6 || n_wit > remaining / 4
            || n_ext > remaining / 8 || n_tx > remaining / 28
        {
            return Err("implausible entry count for remaining body bytes");
        }

        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            if pos + 40 > data.len() { return Err("body too short for outputs"); }
            let arr: &[u8; 40] = data[pos..pos + 40].try_into().unwrap();
            outputs.push(FlatOutput::from_bytes(arr));
            pos += 40;
        }

        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            if pos + 6 > data.len() { return Err("body too short for inputs"); }
            let arr: &[u8; 6] = data[pos..pos + 6].try_into().unwrap();
            inputs.push(FlatInput::from_bytes(arr));
            pos += 6;
        }

        let mut witnesses = Vec::with_capacity(n_wit);
        for _ in 0..n_wit {
            if pos + 4 > data.len() { return Err("body too short for witness len"); }
            let wlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + wlen > data.len() { return Err("body too short for witness data"); }
            witnesses.push(crate::transaction::WitnessEntry { witness_data: data[pos..pos + wlen].to_vec() });
            pos += wlen;
        }

        let mut extensions = Vec::with_capacity(n_ext);
        for _ in 0..n_ext {
            if pos + 8 > data.len() { return Err("body too short for extension header"); }
            let ext_type = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
            let version  = u16::from_le_bytes(data[pos + 2..pos + 4].try_into().unwrap());
            let plen     = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += 8;
            if pos + plen > data.len() { return Err("body too short for extension payload"); }
            extensions.push(crate::transaction::ExtensionRecord {
                header: crate::transaction::ExtensionHeader { extension_type: ext_type, version, payload_length: plen as u32 },
                payload: data[pos..pos + plen].to_vec(),
            });
            pos += plen;
        }

        let mut descriptors = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            if pos + 28 > data.len() { return Err("body too short for descriptors"); }
            let arr: &[u8; 28] = data[pos..pos + 28].try_into().unwrap();
            descriptors.push(crate::transaction::TransactionDescriptor::from_bytes(arr));
            pos += 28;
        }

        Ok(Self { outputs, inputs, witnesses, extensions, descriptors })
    }

    // ---- FV-10: Zero-copy accessors into serialized flat-body bytes ----

    /// Read `output_count` from the flat-body byte prefix without full deserialization.
    ///
    /// Returns `None` if `bytes` is shorter than `PREFIX_BYTES`.
    pub fn extract_output_count(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < Self::PREFIX_BYTES {
            return None;
        }
        Some(u32::from_le_bytes(bytes[0..4].try_into().unwrap()))
    }

    /// Read `input_count` from the flat-body byte prefix.
    pub fn extract_input_count(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < Self::PREFIX_BYTES {
            return None;
        }
        Some(u32::from_le_bytes(bytes[4..8].try_into().unwrap()))
    }

    /// Parse all `FlatOutput` entries from serialized flat-body bytes.
    ///
    /// Returns an error if the byte slice is malformed.  The outputs section
    /// starts at `PREFIX_BYTES` (20) and each entry is `FlatOutput::SIZE` (40) bytes.
    pub fn extract_outputs_slice(bytes: &[u8]) -> Result<Vec<FlatOutput>, &'static str> {
        let n_out = Self::extract_output_count(bytes).ok_or("body too short for prefix")?;
        let end = Self::PREFIX_BYTES + n_out as usize * FlatOutput::SIZE;
        if bytes.len() < end {
            return Err("body too short for declared output_count");
        }
        let mut out = Vec::with_capacity(n_out as usize);
        let mut pos = Self::PREFIX_BYTES;
        for _ in 0..n_out {
            let arr: &[u8; FlatOutput::SIZE] = bytes[pos..pos + FlatOutput::SIZE].try_into().unwrap();
            out.push(FlatOutput::from_bytes(arr));
            pos += FlatOutput::SIZE;
        }
        Ok(out)
    }

    /// Parse all `FlatInput` entries from serialized flat-body bytes.
    pub fn extract_inputs_slice(bytes: &[u8]) -> Result<Vec<FlatInput>, &'static str> {
        let n_out = Self::extract_output_count(bytes).ok_or("body too short for prefix")?;
        let n_in  = Self::extract_input_count(bytes).ok_or("body too short for prefix")?;
        let inputs_start = Self::PREFIX_BYTES + n_out as usize * FlatOutput::SIZE;
        let inputs_end   = inputs_start + n_in as usize * FlatInput::SIZE;
        if bytes.len() < inputs_end {
            return Err("body too short for declared input_count");
        }
        let mut out = Vec::with_capacity(n_in as usize);
        let mut pos = inputs_start;
        for _ in 0..n_in {
            let arr: &[u8; FlatInput::SIZE] = bytes[pos..pos + FlatInput::SIZE].try_into().unwrap();
            out.push(FlatInput::from_bytes(arr));
            pos += FlatInput::SIZE;
        }
        Ok(out)
    }

    /// Build a position-binding Merkle root over a slice of byte elements.
    ///
    /// Each leaf hash = BLAKE3(`i_le32 || element`).
    /// Internal nodes = BLAKE3(`left || right`).
    /// Odd-length levels: last node is paired with itself.
    fn position_binding_merkle(elements: &[Vec<u8>]) -> [u8; 32] {
        if elements.is_empty() {
            return [0u8; 32];
        }

        // Leaf layer: BLAKE3(i_le32 || element)
        let mut nodes: Vec<[u8; 32]> = elements
            .iter()
            .enumerate()
            .map(|(i, elem)| {
                let mut h = blake3::Hasher::new();
                h.update(&(i as u32).to_le_bytes());
                h.update(elem);
                h.finalize().into()
            })
            .collect();

        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut next: Vec<[u8; 32]> = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let left  = nodes[i];
                let right = if i + 1 < nodes.len() { nodes[i + 1] } else { left };
                let mut h = blake3::Hasher::new();
                h.update(&left);
                h.update(&right);
                next.push(h.finalize().into());
            }
            nodes = next;
        }

        nodes[0]
    }
}

// OPT-APPLY-ALT-DOUBLE-DECODE-1 Phase 0 (Oct 20, 2026): golden bytes + round-trip invariants.
#[cfg(test)]
#[path = "shard_block_body_golden_tests.rs"]
mod shard_block_body_golden_tests;

#[cfg(test)]
mod flat_body_tests {
    use super::*;

    fn make_output(value: u64, seed: u8) -> FlatOutput {
        let mut recipient = [0u8; 32];
        recipient[0] = seed;
        FlatOutput { value, recipient }
    }

    fn make_input(height: u32, idx: u16) -> FlatInput {
        FlatInput { prev_height: height, prev_output_idx: idx }
    }

    #[test]
    fn fv_t1_empty_body_round_trip() {
        let body = ShardBlockBody::empty();
        let bytes = body.serialize();
        let decoded = ShardBlockBody::deserialize(&bytes).unwrap();
        assert_eq!(decoded.n_outputs(), 0);
        assert_eq!(decoded.n_inputs(), 0);
        assert_eq!(decoded.tx_count(), 0);
    }

    #[test]
    fn fv_t2_body_round_trip_with_data() {
        use crate::transaction::TransactionDescriptor;
        let mut body = ShardBlockBody::empty();
        body.outputs.push(make_output(1000, 1));
        body.outputs.push(make_output(2000, 2));
        body.inputs.push(make_input(5, 0));
        // coinbase
        body.descriptors.push(TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });
        // regular
        body.descriptors.push(TransactionDescriptor { out_start: 1, out_len: 1, in_start: 0, in_len: 1, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });

        let bytes = body.serialize();
        let decoded = ShardBlockBody::deserialize(&bytes).unwrap();
        assert_eq!(decoded.outputs[0].value, 1000);
        assert_eq!(decoded.outputs[1].value, 2000);
        assert_eq!(decoded.inputs[0].prev_height, 5);
        assert!(decoded.has_coinbase());
        assert_eq!(decoded.descriptors[1].in_len, 1);
    }

    #[test]
    fn cv81_1_to_transactions_round_trips_from_transactions() {
        use crate::transaction::{Transaction, TxInput, TxOutput, WitnessEntry};

        let coinbase = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 5_000_000_000, recipient: [0xAA; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
            extensions: Vec::new(),
        };
        let regular = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 0, prev_output_idx: 0 }],
            outputs: vec![
                TxOutput { value: 1000, recipient: [0xBB; 32] },
                TxOutput { value: 500, recipient: [0xCC; 32] },
            ],
            // Non-default — exercises the validity-extension encode/decode path.
            locktime: 42,
            expiration_height: 1000,
            witnesses: vec![WitnessEntry { witness_data: vec![1, 2, 3, 4] }],
            extensions: Vec::new(),
        };
        let txs = vec![coinbase, regular];

        let body = ShardBlockBody::from_transactions(&txs, None);
        let round_tripped = body.to_transactions().expect("reconstruction must succeed");

        assert_eq!(round_tripped.len(), 2);

        assert!(round_tripped[0].inputs.is_empty());
        assert_eq!(round_tripped[0].outputs.len(), 1);
        assert_eq!(round_tripped[0].outputs[0].value, 5_000_000_000);
        assert_eq!(round_tripped[0].outputs[0].recipient, [0xAA; 32]);
        assert_eq!(round_tripped[0].locktime, 0);
        assert_eq!(round_tripped[0].expiration_height, 0);

        assert_eq!(round_tripped[1].inputs.len(), 1);
        assert_eq!(round_tripped[1].inputs[0].prev_height, 0);
        assert_eq!(round_tripped[1].inputs[0].prev_output_idx, 0);
        assert_eq!(round_tripped[1].outputs.len(), 2);
        assert_eq!(round_tripped[1].outputs[0].value, 1000);
        assert_eq!(round_tripped[1].outputs[1].value, 500);
        assert_eq!(round_tripped[1].locktime, 42);
        assert_eq!(round_tripped[1].expiration_height, 1000);
        assert_eq!(round_tripped[1].witnesses.len(), 1);
        assert_eq!(round_tripped[1].witnesses[0].witness_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn cv81_2_to_transactions_tolerates_producer_stamp_on_coinbase() {
        use crate::transaction::{Transaction, TxOutput};

        // A testnet-stress coinbase carries a producer-stamp extension
        // (type 0x1001) in the same extension slot a validity-window record
        // would occupy — to_transactions must not error on this (unlike
        // flat_tx_meta::parse_flat_tx_meta, which does — see the doc comment
        // on to_transactions).
        let coinbase = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 5_000_000_000, recipient: [0xAA; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
            extensions: Vec::new(),
        };
        let body = ShardBlockBody::from_transactions(&[coinbase], Some("A"));
        assert_eq!(body.extensions.len(), 1, "producer stamp should be the only extension");
        assert_eq!(body.extensions[0].header.extension_type, 0x1001);

        let round_tripped = body.to_transactions().expect("must tolerate the stamp extension");
        assert_eq!(round_tripped.len(), 1);
        assert_eq!(round_tripped[0].locktime, 0);
        assert_eq!(round_tripped[0].expiration_height, 0);
        assert_eq!(round_tripped[0].version, 1);
    }

    #[test]
    fn cv81_3_to_transactions_rejects_out_of_bounds_descriptor() {
        use crate::transaction::TransactionDescriptor;
        let mut body = ShardBlockBody::empty();
        body.outputs.push(make_output(1000, 1));
        // out_len claims 5 outputs but only 1 exists.
        body.descriptors.push(TransactionDescriptor {
            out_start: 0, out_len: 5, in_start: 0, in_len: 0,
            witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0,
        });
        assert!(body.to_transactions().is_err());
    }

    #[test]
    fn fv_t3_tx_merkle_root_position_binding() {
        use crate::transaction::TransactionDescriptor;
        let mut body = ShardBlockBody::empty();
        body.outputs.push(make_output(100, 0xaa));
        body.outputs.push(make_output(200, 0xbb));
        body.descriptors.push(TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });
        body.descriptors.push(TransactionDescriptor { out_start: 1, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });

        let root_ab = body.calculate_tx_merkle_root();

        // Swap outputs — changes txids, must change merkle root
        body.outputs.swap(0, 1);
        let root_ba = body.calculate_tx_merkle_root();

        assert_ne!(root_ab, root_ba, "tx_merkle_root must change when outputs change");
    }

    #[test]
    fn fv_t4_empty_tx_merkle_root_is_zero() {
        let body = ShardBlockBody::empty();
        assert_eq!(body.calculate_tx_merkle_root(), [0u8; 32]);
    }

    #[test]
    fn fv_t5_coinbase_marker() {
        use crate::transaction::TransactionDescriptor;
        let mut body = ShardBlockBody::empty();
        body.descriptors.push(TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });
        assert!(body.has_coinbase());
        assert!(body.descriptors[0].is_coinbase());
    }

    #[test]
    fn fv_t6_flat_input_round_trip() {
        let inp = FlatInput { prev_height: 999, prev_output_idx: 42 };
        let decoded = FlatInput::from_bytes(&inp.to_bytes());
        assert_eq!(decoded, inp);
    }

    #[test]
    fn fv_t7_flat_output_round_trip() {
        let out = make_output(12345678, 0x55);
        let decoded = FlatOutput::from_bytes(&out.to_bytes());
        assert_eq!(decoded, out);
    }

    #[test]
    fn fv_t8_descriptor_round_trip() {
        use crate::transaction::TransactionDescriptor;
        let d = TransactionDescriptor { out_start: 3, out_len: 5, in_start: 2, in_len: 4, witness_start: 1, witness_len: 2, extension_start: 0, extension_len: 0 };
        let decoded = TransactionDescriptor::from_bytes(&d.to_bytes());
        assert_eq!(decoded.out_start, d.out_start);
        assert_eq!(decoded.out_len, d.out_len);
        assert_eq!(decoded.witness_len, d.witness_len);
    }

    // ---- FV-10 accessor tests ----

    #[test]
    fn fv10_extract_output_count_empty() {
        let body = ShardBlockBody::empty();
        let bytes = body.serialize();
        assert_eq!(ShardBlockBody::extract_output_count(&bytes), Some(0));
        assert_eq!(ShardBlockBody::extract_input_count(&bytes), Some(0));
    }

    #[test]
    fn fv10_extract_outputs_roundtrip() {
        let o1 = make_output(100, 1);
        let o2 = make_output(200, 2);
        let i1 = make_input(10, 0);
        let body = ShardBlockBody {
            outputs: vec![o1, o2],
            inputs: vec![i1],
            witnesses: vec![],
            extensions: vec![],
            descriptors: vec![],
        };
        let bytes = body.serialize();

        assert_eq!(ShardBlockBody::extract_output_count(&bytes), Some(2));
        assert_eq!(ShardBlockBody::extract_input_count(&bytes), Some(1));

        let outputs = ShardBlockBody::extract_outputs_slice(&bytes).unwrap();
        assert_eq!(outputs, vec![o1, o2]);

        let inputs = ShardBlockBody::extract_inputs_slice(&bytes).unwrap();
        assert_eq!(inputs, vec![i1]);
    }

    #[test]
    fn fv10_extract_returns_error_on_truncated_bytes() {
        let o1 = make_output(50, 5);
        let body = ShardBlockBody {
            outputs: vec![o1],
            inputs: vec![],
            witnesses: vec![],
            extensions: vec![],
            descriptors: vec![],
        };
        let bytes = body.serialize();
        // Truncate to just the prefix — outputs section is missing.
        let truncated = &bytes[..ShardBlockBody::PREFIX_BYTES];
        assert!(ShardBlockBody::extract_outputs_slice(truncated).is_err());
    }

    #[test]
    fn fv10_extract_too_short_for_prefix() {
        assert_eq!(ShardBlockBody::extract_output_count(&[0u8; 3]), None);
        assert!(ShardBlockBody::extract_outputs_slice(&[0u8; 3]).is_err());
        assert!(ShardBlockBody::extract_inputs_slice(&[0u8; 3]).is_err());
    }

    // -------------------------------------------------------------------------
    // FV-13: commitment round-trip, inclusion proof, reject-swap
    // -------------------------------------------------------------------------

    /// FV-T-9: tx_merkle_root covers txid for each transaction.
    #[test]
    fn fv_t9_tx_merkle_root_covers_all_txids() {
        use crate::transaction::TransactionDescriptor;
        let mut body = ShardBlockBody::empty();
        body.outputs.push(make_output(1000, 0xAA));
        body.outputs.push(make_output(2000, 0xBB));
        body.descriptors.push(TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });
        body.descriptors.push(TransactionDescriptor { out_start: 1, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 });

        let root = body.calculate_tx_merkle_root();
        assert_ne!(root, [0u8; 32]);

        // Changing one output must change the root
        body.outputs[0].value += 1;
        let root2 = body.calculate_tx_merkle_root();
        assert_ne!(root, root2);
    }

    /// FV-T-10: tx_merkle_root differs when descriptor layout changes.
    #[test]
    fn fv_t10_descriptor_tampering_changes_root() {
        use crate::transaction::TransactionDescriptor;
        let out_a = FlatOutput { value: 1_000, recipient: [0xAAu8; 32] };
        let out_b = FlatOutput { value: 2_000, recipient: [0xBBu8; 32] };
        let inp   = FlatInput  { prev_height: 5, prev_output_idx: 0 };

        let mut body1 = ShardBlockBody::empty();
        body1.outputs = vec![out_a, out_b];
        body1.inputs  = vec![inp];
        body1.descriptors = vec![
            TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 },
            TransactionDescriptor { out_start: 1, out_len: 1, in_start: 0, in_len: 1, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 },
        ];

        let mut body2 = ShardBlockBody::empty();
        body2.outputs = vec![out_a, out_b];
        body2.inputs  = vec![inp];
        body2.descriptors = vec![
            TransactionDescriptor { out_start: 0, out_len: 2, in_start: 0, in_len: 1, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 },
        ];

        assert_ne!(body1.calculate_tx_merkle_root(), body2.calculate_tx_merkle_root(),
            "different descriptor layouts must produce different tx_merkle_root");
    }

    /// FV-T-11: tx_merkle_root changes when inputs change.
    #[test]
    fn fv_t11_tx_merkle_root_covers_inputs() {
        use crate::transaction::TransactionDescriptor;
        let output = FlatOutput { value: 5000, recipient: [0xAAu8; 32] };

        let mut body_a = ShardBlockBody::empty();
        body_a.outputs = vec![output];
        body_a.inputs  = vec![FlatInput { prev_height: 1, prev_output_idx: 0 }];
        body_a.descriptors = vec![TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 1, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 }];

        let mut body_b = body_a.clone();
        body_b.inputs[0].prev_height = 2;

        assert_ne!(body_a.calculate_tx_merkle_root(), body_b.calculate_tx_merkle_root(),
            "different inputs must produce different tx_merkle_root");
    }

    // -------------------------------------------------------------------------
    // FV-12: ShardWireBlock encode/decode round-trip
    // -------------------------------------------------------------------------

    /// FV-12-T1: encode → decode round-trip preserves header and body exactly.
    #[test]
    fn fv12_wire_block_round_trip() {
        use crate::transaction::TransactionDescriptor;
        let output = FlatOutput { value: 42_000, recipient: [0x11u8; 32] };
        let input  = FlatInput  { prev_height: 3, prev_output_idx: 7 };
        let descriptor = TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 1, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 };
        let mut body = ShardBlockBody::empty();
        body.outputs = vec![output];
        body.inputs  = vec![input];
        body.descriptors = vec![descriptor];
        let commitment = body.calculate_tx_merkle_root();

        use crate::common::crypto::weighted_hash::WeightedHash;
        let header = FullShardHeader::new(
            1,
            WeightedHash([0u8; 32]),
            WeightedHash([0u8; 32]),
            commitment,
            0x207f_ffff,
            vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
            0,
            BeaconHeader::new(1, 1_000_000, 0, [0u8;32].into(), [0u8;32], 0x207f_ffff, 0, 0, [0u8;32]),
        );

        let wire = ShardWireBlock { header: header.clone(), body: body.clone() };
        let encoded = wire.encode();

        let decoded = ShardWireBlock::decode(&encoded).expect("decode must succeed");
        assert_eq!(decoded.header.height,       header.height);
        assert_eq!(decoded.header.tx_merkle_root, header.tx_merkle_root);
        assert_eq!(decoded.body.outputs,        body.outputs);
        assert_eq!(decoded.body.inputs,         body.inputs);
    }

    /// NC-92: `into_block` must reconstruct transactions so Keystone P1DB
    /// creates (`build_shard_phase1_delta`) are non-empty after a wire apply.
    /// `chain::phase1_delta` exists only with `full-node`, so without this gate
    /// `cargo test -p common-types` (default features) did not compile.
    #[cfg(feature = "full-node")]
    #[test]
    fn nc92_into_block_preserves_coinbase_output_for_p1db_creates() {
        use crate::chain::phase1_delta::build_shard_phase1_delta;
        use crate::transaction::TransactionDescriptor;

        let recipient = [0x26u8; 32];
        let output = FlatOutput {
            value: 100_000_000,
            recipient,
        };
        let descriptor = TransactionDescriptor {
            out_start: 0,
            out_len: 1,
            in_start: 0,
            in_len: 0,
            witness_start: 0,
            witness_len: 0,
            extension_start: 0,
            extension_len: 0,
        };
        let mut body = ShardBlockBody::empty();
        body.outputs = vec![output];
        body.descriptors = vec![descriptor];
        let commitment = body.calculate_tx_merkle_root();

        use crate::common::crypto::weighted_hash::WeightedHash;
        let header = FullShardHeader::new(
            0,
            WeightedHash([0u8; 32]),
            WeightedHash([0u8; 32]),
            commitment,
            0x207f_ffff,
            vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
            0,
            BeaconHeader::new(
                1,
                1_000_000,
                0,
                [0u8; 32].into(),
                [0u8; 32],
                0x207f_ffff,
                0,
                0,
                [0u8; 32],
            ),
        );

        let wire = ShardWireBlock {
            header: header.clone(),
            body: body.clone(),
        };
        let block = wire.into_block();
        assert_eq!(
            block.transactions.len(),
            1,
            "into_block must not discard the coinbase tx (NC-92)"
        );
        assert_eq!(block.transactions[0].outputs.len(), 1);
        assert_eq!(block.transactions[0].outputs[0].value, 100_000_000);
        assert_eq!(block.transactions[0].outputs[0].recipient, recipient);

        let (creates, spends, _) = build_shard_phase1_delta(&block);
        assert!(spends.is_empty());
        assert_eq!(creates.len(), 1, "P1DB creates must include the coinbase output");
        assert_eq!(creates[0].1.value, 100_000_000);
        assert_eq!(creates[0].1.recipient, recipient);
    }

    /// WIRE-5-1: pins the `FullShardHeader` field-reorder invariant
    /// (`OPTIMIZATION_PLAN.md` §23 item 3) — `hash` must bincode-encode
    /// immediately after `beacon_header` and before `merged_mining_proof`,
    /// giving every encoded `FullShardHeader` a fixed 274-byte prefix
    /// containing everything a `LightShardHeader` projection needs, with
    /// `merged_mining_proof` as the sole trailing variable-length section.
    /// Regression guard: if this ever breaks, `rustmmrdb`'s B6
    /// `ElidedBlockLayout::WireBlock` offset math and any future
    /// fixed-offset light-field projection built on this assumption would
    /// silently misdecode instead of failing loudly at this narrow point.
    #[test]
    fn wire5_1_full_shard_header_hash_precedes_merged_mining_proof() {
        use crate::common::crypto::weighted_hash::WeightedHash;

        let header_short_proof = FullShardHeader::new(
            7,
            WeightedHash([0u8; 32]),
            WeightedHash([0u8; 32]),
            [0u8; 32],
            0x207f_ffff,
            vec![MergedMiningHash::from_active_leaf(&[0xAAu8; 32])],
            3,
            BeaconHeader::new(1, 1_000_000, 0, [0u8; 32].into(), [0u8; 32], 0x207f_ffff, 0, 0, [0u8; 32]),
        );
        let header_long_proof = FullShardHeader::new(
            7,
            WeightedHash([0u8; 32]),
            WeightedHash([0u8; 32]),
            [0u8; 32],
            0x207f_ffff,
            vec![
                MergedMiningHash::from_active_leaf(&[0xAAu8; 32]),
                MergedMiningHash::from_active_leaf(&[0xBBu8; 32]),
                MergedMiningHash::from_active_leaf(&[0xCCu8; 32]),
            ],
            3,
            BeaconHeader::new(1, 1_000_000, 0, [0u8; 32].into(), [0u8; 32], 0x207f_ffff, 0, 0, [0u8; 32]),
        );

        let bytes_short = bincode::serde::encode_to_vec(&header_short_proof, bincode::config::standard().with_fixed_int_encoding())
            .expect("bincode encode");
        let bytes_long = bincode::serde::encode_to_vec(&header_long_proof, bincode::config::standard().with_fixed_int_encoding())
            .expect("bincode encode");

        // The fixed prefix (everything up to and including `hash`) must be
        // byte-identical regardless of `merged_mining_proof`'s length --
        // only bytes after the prefix may differ between the two headers.
        const FIXED_PREFIX_LEN: usize = 274;
        assert_eq!(
            bytes_short[..FIXED_PREFIX_LEN], bytes_long[..FIXED_PREFIX_LEN],
            "fixed prefix must be identical across headers differing only in merged_mining_proof length"
        );
        assert_ne!(
            bytes_short.len(), bytes_long.len(),
            "sanity check: the two fixtures must actually have different proof lengths"
        );

        // Round-trip through the real production path (ShardWireBlock) to
        // confirm the reorder didn't just "compile" but decodes correctly
        // too, matching fv12_wire_block_round_trip's own pattern.
        let (decoded, consumed): (FullShardHeader, usize) =
            bincode::serde::decode_from_slice(&bytes_short, bincode::config::standard().with_fixed_int_encoding())
                .expect("decode must succeed");
        assert_eq!(consumed, bytes_short.len());
        assert_eq!(decoded.hash(), header_short_proof.hash());
        assert_eq!(decoded.merged_mining_proof, header_short_proof.merged_mining_proof);
    }

    /// WIRE-5 items 1+2: `LightShardHeader::serialize()` is exactly 136 bytes
    /// and does **not** embed `shard_id`, `bits`, or `chain_weight`. Two headers
    /// that differ only in those three fields must produce identical wire bytes;
    /// a receiver reconstructs `shard_id` from context via
    /// `deserialize_with_shard_id`.
    #[test]
    fn wire5_2_light_shard_header_wire_omits_bits_shard_id_chain_weight() {
        use crate::common::crypto::weighted_hash::WeightedHash;

        let base = LightShardHeader {
            height: 42,
            delta: 1_024,
            chain_weight: 999_999,
            prev_mmr_root: WeightedHash([0x11; 32]),
            current_mmr_root: WeightedHash([0x22; 32]),
            tx_merkle_root: [0x33; 32],
            pow_hash: [0x44; 32],
            shard_id: 7,
            bits: 0x1d00_ffff,
        };
        let mut other = base.clone();
        other.shard_id = 99;
        other.bits = 0x207f_ffff;
        other.chain_weight = 1;

        let a = base.serialize();
        let b = other.serialize();
        assert_eq!(a.len(), LIGHT_SHARD_HEADER_SIZE);
        assert_eq!(LIGHT_SHARD_HEADER_SIZE, 136);
        assert_eq!(
            a, b,
            "wire bytes must be identical when only shard_id/bits/chain_weight differ"
        );

        // Height is at offset 0 — sync layer height extraction depends on this.
        assert_eq!(u32::from_le_bytes(a[0..4].try_into().unwrap()), 42);

        let recovered = LightShardHeader::deserialize_with_shard_id(&a, 7);
        assert_eq!(recovered.height, base.height);
        assert_eq!(recovered.delta, base.delta);
        assert_eq!(recovered.prev_mmr_root, base.prev_mmr_root);
        assert_eq!(recovered.current_mmr_root, base.current_mmr_root);
        assert_eq!(recovered.tx_merkle_root, base.tx_merkle_root);
        assert_eq!(recovered.pow_hash, base.pow_hash);
        assert_eq!(recovered.shard_id, 7, "shard_id must come from context, not the wire");
        assert_eq!(recovered.bits, 0, "bits must not be trusted from the wire");
        assert_eq!(recovered.chain_weight, 0, "chain_weight must not be trusted from the wire");
    }

    /// WIRE-5 item 1 companion: reconstructing `shard_id` from the wrong
    /// context must not silently adopt a wire-embedded value (there is none).
    #[test]
    fn wire5_3_shard_id_reconstruction_is_context_only() {
        use crate::common::crypto::weighted_hash::WeightedHash;

        let lh = LightShardHeader {
            height: 1,
            delta: 0,
            chain_weight: 42,
            prev_mmr_root: WeightedHash([0; 32]),
            current_mmr_root: WeightedHash([0; 32]),
            tx_merkle_root: [0; 32],
            pow_hash: [1; 32],
            shard_id: 3,
            bits: 0x1d00_ffff,
        };
        let bytes = lh.serialize();
        assert_eq!(LightShardHeader::deserialize_with_shard_id(&bytes, 0).shard_id, 0);
        assert_eq!(LightShardHeader::deserialize_with_shard_id(&bytes, 5).shard_id, 5);
        assert_eq!(LightShardHeader::deserialize(&bytes).shard_id, 0);
    }

    /// FV-12-T2: `verify_commitment` returns true for a correctly encoded wire block
    /// and false when the body is tampered.
    #[test]
    fn fv12_verify_commitment() {
        use crate::transaction::TransactionDescriptor;
        use crate::common::crypto::weighted_hash::WeightedHash;

        let output = FlatOutput { value: 7_777, recipient: [0x22u8; 32] };
        let mut body = ShardBlockBody::empty();
        body.outputs = vec![output];
        body.descriptors = vec![TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 }];
        let commitment = body.calculate_tx_merkle_root();
        let header = FullShardHeader::new(
            0,
            WeightedHash([0u8; 32]),
            WeightedHash([0u8; 32]),
            commitment,
            0x207f_ffff,
            vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
            0,
            BeaconHeader::new(1, 1_000_000, 0, [0u8;32].into(), [0u8;32], 0x207f_ffff, 0, 0, [0u8;32]),
        );

        let wire = ShardWireBlock { header: header.clone(), body };
        assert!(wire.verify_commitment(), "fresh wire block must pass commitment check");

        // Tamper: change one output value → commitment mismatch.
        let mut tampered_body = ShardBlockBody::empty();
        tampered_body.outputs = vec![FlatOutput { value: 7_778, recipient: [0x22u8; 32] }];
        tampered_body.descriptors = vec![TransactionDescriptor { out_start: 0, out_len: 1, in_start: 0, in_len: 0, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 }];
        let tampered = ShardWireBlock { header, body: tampered_body };
        assert!(!tampered.verify_commitment(), "tampered body must fail commitment check");
    }
}

/*
===============================================================================
SHARD BLOCK MODULE - BLOCK STRUCTURE FOR INDIVIDUAL SHARDS
===============================================================================

PURPOSE
=======
Defines the block structure for blocks in a single shard chain.
Follows Bitcoin's model with modifications for shard identification and
merged mining integration.


MMR ROOT HANDLING - CRITICAL
=============================

The header contains TWO MMR roots:

1. prev_mmr_root (Previous MMR Root)
   - MMR state BEFORE this block
   - Part of block identity (included in hash)
   - Links to parent block's current_mmr_root
   - Verified during block validation

2. current_mmr_root (Current MMR Root)
   - MMR state AFTER this block
   - NOT part of block identity (excluded from hash)
   - Calculated by: MMR.append(block_hash)
   - Stored with block but doesn't affect hash

WHY EXCLUDE current_mmr_root FROM HASH?

Consider the calculation flow:
  current_mmr_root = MMR.append(block_hash)
  block_hash = SHA256d(serialize(header))

If serialize(header) included current_mmr_root:
  block_hash = SHA256d(serialize(header with current_mmr_root))
  current_mmr_root = MMR.append(block_hash)
  → CIRCULAR DEPENDENCY!

SOLUTION: Exclude current_mmr_root from hash calculation.

This is conceptually correct:
- prev_mmr_root: "What was the chain state?" (input, part of identity)
- current_mmr_root: "What is the chain state?" (output, metadata)

The block hash identifies the block based on its CONTENT.
The current_mmr_root describes WHERE the block is in the CHAIN.


TWO SERIALIZATION METHODS
==========================

1. serialize_for_hash() - Block identity
   Purpose: Calculate block hash
   Contains: All fields EXCEPT current_mmr_root
   Used by: hash() method, block identification

2. serialize() - Complete data
   Purpose: Storage and transmission
   Contains: All fields INCLUDING current_mmr_root
   Used by: Database storage, network transmission


BLOCK CREATION WORKFLOW
========================

Correct sequence for creating shard blocks:

```rust
// Step 1: Create header with placeholder current_mmr_root
let mut header = FullShardHeader::new(
    height,
    prev_mmr_root,
    prev_block_hash,
    [0u8; 32], // Placeholder for current_mmr_root
    merkle_root,
    difficulty,
    // chain_weight removed (Aug 5, 2026) — never read except at the tip,
    // which both chain types already track via their own scalar field.
    shard_id,
    beacon_header,
);

// Step 2: Calculate block hash (excludes current_mmr_root)
let block_hash = header.hash();

// Step 3: Append to MMR to get current_mmr_root
let current_mmr_root = mmr.append(block_hash);

// Step 4: Update header with actual current_mmr_root
header.current_mmr_root = current_mmr_root;

// Step 5: Block hash is still valid (it didn't include current_mmr_root)
let block = Block::new(header, transactions);
```

KEY INSIGHT: Block hash remains stable throughout this process because
it's calculated from serialize_for_hash() which excludes current_mmr_root.


VALIDATION WORKFLOW
===================

When validating blocks in ShardChain::append_block():

```rust
// 1. Verify prev_mmr_root matches current chain state
if block.header.prev_mmr_root != chain.mmr.get_root() {
    return Err("prev_mmr_root mismatch");
}

// 2. Calculate what current_mmr_root should be
let block_hash = block.header.hash(); // Excludes current_mmr_root
let expected_mmr_root = {
    let mut temp_mmr = chain.mmr.clone();
    temp_mmr.append(block_hash)
};

// 3. Verify current_mmr_root is correct
if block.header.current_mmr_root != expected_mmr_root {
    return Err("current_mmr_root mismatch");
}

// 4. Append to actual MMR
let new_mmr_root = chain.mmr.append(block_hash);
assert_eq!(new_mmr_root, expected_mmr_root);
```


BLOCK HEADER FIELDS
===================

height (u32):
- The order of this block in the chain
- Genesis block has height 0
- Increments by 1 with each block
- Used for: block ordering, forking decisions, chain validation

prev_mmr_root ([u8; 32]):
- Previous Merkle Mountain Range root
- MMR state before this block
- Part of block identity (included in hash)
- Enables efficient historical data verification
- Allows light clients to verify past state

current_mmr_root ([u8; 32]):
- Current Merkle Mountain Range root
- MMR state after this block
- NOT part of block identity (excluded from hash)
- Used for chain state tracking
- Next block's prev_mmr_root will equal this

prev_block_hash ([u8; 32]):
- SHA256d hash of previous block header
- Creates chain link
- Ensures tamper detection
- Changing any previous block invalidates all following blocks

merkle_root ([u8; 32]):
- Root of Merkle tree over all transactions
- Enables compact transaction verification
- Calculated fresh for each block
- Verified when block is appended

difficulty (u32):
- Proof-of-work difficulty target
- Bitcoin-style nBits encoding
- Higher difficulty = more leading zeros required
- Per-shard difficulty adjustment

chain_weight: REMOVED (Aug 5, 2026) — was never read except for the
current tip, which `ShardChain`/`FullShardChain` already track via their
own chain-level scalar. Fork selection uses MMR peak-bagged weight
(`LightShardHeader.chain_weight` for side-block candidates), never this
per-block header field.

merged_mining_proof (Vec<MergedMiningHash>):
- Sibling path from shard leaf to merged mining tree root
- Each MergedMiningHash node embeds chain_count and tree_height in bytes 30-31
- Replaces both the old shard_merkle_proof and MergedMiningProof types
- Variable length depending on tree depth; empty = legacy/test block (skipped)

shard_id (u16):
- Which shard this block belongs to
- Immutable - set when block created
- Used to route block to correct shard chain

beacon_header (BeaconHeader):
- Contains shared PoW information
- Stores: version, timestamp, nonce
- Shared across all shards
- Used for cross-shard validation


BEACON HEADER
=============

The BeaconHeader separates proof-of-work concerns from shard-specific logic.

Fields:
- version: Protocol version number
- timestamp: Block creation time (Unix seconds)
- nonce: Proof-of-work counter

Benefits:
- One beacon header per merged mining cycle
- Shared across all active shards
- Reduces redundancy
- Simplifies cross-shard coordination
- Clear separation of concerns


SHARD HEADER vs BEACON HEADER
==============================

ShardHeader contains:
- Shard-specific data (height, prev_block_hash, merkle_root)
- Chain weight and difficulty
- MMR roots for historical verification
- Merkle proof for merged mining
- Reference to beacon header

BeaconHeader contains:
- Proof-of-work parameters (version, timestamp, nonce)
- Shared across all shards
- Common timing information
- Single hash that all shards reference


SERIALIZATION FORMAT
====================

Header serialization (variable size):

- height: 4 bytes (u32, little-endian)
- prev_mmr_root: 32 bytes ([u8; 32])
- current_mmr_root: 32 bytes ([u8; 32]) - only in full serialize()
- prev_block_hash: 32 bytes ([u8; 32])
- merkle_root: 32 bytes ([u8; 32])
- difficulty: 4 bytes (u32, little-endian)
- (chain_weight removed Aug 5, 2026 — never was on the wire, now not a field at all)
- merged_mining_proof_length: 4 bytes (u32, little-endian)
- merged_mining_proof: N * 32 bytes (variable, each entry is a MergedMiningHash)
- shard_id: 2 bytes (u16, little-endian)
- beacon_header: ~20 bytes
  - version: 4 bytes (u32)
  - timestamp: 8 bytes (u64)
  - nonce: 8 bytes (u64)

serialize_for_hash(): ~114+ bytes (excludes current_mmr_root)
serialize(): ~146+ bytes (includes current_mmr_root)

Byte order: Little-endian for all multi-byte fields


CHAIN WEIGHT
============

Purpose: Consensus mechanism
- Prevents low-difficulty chain attacks
- Each block adds its difficulty to chain weight
- Highest chain weight is canonical
- Better than pure block count

Example:
- Chain A: 100 blocks at difficulty 1000 = weight 100,000
- Chain B: 50 blocks at difficulty 2500 = weight 125,000
- Chain B wins despite fewer blocks

Calculation:
chainWeight = previousChainWeight + difficulty


HEIGHT
======

Purpose: Block ordering and validation
- Strictly increasing
- Genesis block: height 0
- Each new block: height = previous + 1

Used for:
- Quick block ordering
- Fork detection (if height matches but hash differs = fork)
- Chain length comparison
- Time-based rules ("must wait N blocks")


MMR ROOT (MERKLE MOUNTAIN RANGE)
================================

Purpose: Efficient historical data proofs
- Better than merkle tree for: "prove this tx is in chain"
- Append-only structure (no tree rebalancing)
- Light clients can verify old transactions without full history

Structure:
- Multiple peaks (merkle trees)
- Efficiently combines when adding new blocks
- Proof size: O(log n) for n blocks

Two roots per block:
- prev_mmr_root: State before this block (part of identity)
- current_mmr_root: State after this block (metadata)


SHARD MERKLE PROOF
==================

Purpose: Prove shard block is part of merged mining tree
- Path from shard header to tree root
- Used by other shards to validate this shard
- Enables light validation without full tree traversal
- Variable length: typically 10-20 hashes for depth 10-20 tree


BLOCK SIZE
==========

Typical: 150+ bytes header + transactions
Maximum: 60KB per constraint

60KB chosen because:
- Fits comfortably in network packets
- Fast to verify
- Balanced propagation vs throughput
- Easy to re-mine if needed


MERKLE TREE
===========

Purpose: Compact proof that transactions are unchanged.

Algorithm: defined in `common::crypto::merkle_hash` (single source of truth).
Current: BLAKE3 at both leaf and internal levels.
Planned upgrade to BLAKE3-224 — see that module for details.

Structure:
- Leaf nodes:     merkle_leaf_hash(txid)
- Internal nodes: merkle_hash_pair(left, right)
- Odd nodes at any level are paired with themselves.
- Root: single hash representing all transactions.
- Empty block: [0u8; 32].

Properties:
- Changing any transaction changes the root.
- O(log n) inclusion proof size for n transactions.
- Hash algorithm can be upgraded by changing merkle_hash.rs only.


DESIGN NOTES
============

This block format is purpose-built for Shisha Protocol sharded chains.
It is NOT required to be compatible with Bitcoin block format or
Bitcoin Merkle tree construction.

Key differences from Bitcoin:
- Added: height, MMR roots, merged_mining_proof, shard_id
- Removed: standalone version/timestamp/nonce (moved to BeaconHeader)
- Transaction Merkle tree: BLAKE3 at leaf and internal levels (see merkle_hash.rs)
- PoW hash (BeaconHeader.hash()) uses SHA256d for miner compatibility


BLOCK VALIDATION
================

A valid block must have:
1. Valid beacon header hash (meets difficulty target)
2. prev_block_hash matches previous block in chain
3. height = previous_height + 1
4. prev_mmr_root matches current chain MMR state
5. current_mmr_root = MMR.append(block_hash)
6. (chain weight is not a header field — tracked chain-level, derived from MMR peaks)
7. merkle_root matches calculated root
8. All transactions valid (inputs exist as UTXOs)
9. Shard merkle proof valid (proves this shard in merged mining)
10. Block size <= 60KB
11. Shard ID matches receiving shard chain


SERIALIZATION
==============

Method: Custom little-endian byte serialization
- No external dependencies
- Deterministic (same input = same bytes)
- Fast to serialize/deserialize
- Used for hash calculation


PERFORMANCE
===========

Operation costs:

calculate_merkle_root(): O(n log n)
- n transactions
- Hash each: O(1)
- Build tree: O(n log n)

verify_transactions(): O(n * m)
- n transactions
- m inputs per transaction
- Each input: O(1) UTXO lookup

size(): O(n)
- Sum all transaction sizes + header serialization

hash(): O(1)
- Fixed-size SHA256d operations


FUTURE EXTENSIONS
==================

Potential enhancements:
- MMR proof extraction (for light clients)
- Merkle proof extraction (for transaction verification)
- Compact block format (for bandwidth optimization)
- Transaction witness data (for scaling)
- Block reward fields


TESTING
=======

Covered:
✓ Block creation
✓ Merkle root calculation
✓ Block size calculation
✓ Transaction verification
✓ MMR integration

TODO:
- Edge cases (empty blocks, large blocks)
- Merkle proof validation
- MMR validation edge cases
- Header serialization round-trip
- Chain weight validation


INTEGRATION WITH CHAIN
======================

ShardChain uses Block for:
1. Storage: maintains Vec<Block>
2. Validation: append_block() validates header + transactions
3. Queries: get_block(height) retrieves block
4. Reorg: drop_last_block() removes block
5. Weight: tracks cumulative difficulty


INTEGRATION WITH MINING
=======================

Miners receive block template (from ShardNode.compose_block()):
1. Partial block with transactions but nonce=0
2. Beacon header provided by coordinator
3. Miner increments nonce trying different values
4. On each iteration: SHA256d(block_header + beacon_header)
5. If hash < difficulty_target: valid proof-of-work
6. Nonce set to winning value and submitted
STORAGE FORMAT
Blocks stored as:

Serialized header (146+ bytes, variable)
Serialized transaction list (variable)
Total size typically < 60KB

MERGED MINING INTEGRATION
This structure enables merged mining:

Multiple shards per beacon header
Shared PoW across shards
Merkle proof connects shard to merged tree
Other shards can verify this shard's contribution
Enables efficient multi-shard mining

COMPARISON TO BITCOIN
Similarities:

Header structure with prev_hash linkage
Merkle tree for transactions
SHA256d hashing
Difficulty-based consensus
UTXO model

Differences:

MMR for efficient light client proofs
Shard ID for multi-chain architecture
Beacon header for cross-shard coordination
Chain weight instead of just height
Merkle proof for merged mining

===============================================================================
*/

/// Proof that one output is committed by a block's `tx_merkle_root` (Filament thin sync, design §6):
/// the owning transaction's slices and descriptor, and the Merkle path to the root.
///
/// The verifier needs the block's `tx_merkle_root` from somewhere it already trusts (a block
/// record bound to its own verified chain). The proof alone proves nothing about which block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInclusionProof {
    pub height: u32,
    /// Global index of the output within the block's flat outputs vector.
    pub output_idx: u32,
    pub tx_idx: u32,
    pub descriptor: crate::transaction::TransactionDescriptor,
    pub inputs: Vec<FlatInput>,
    pub outputs: Vec<FlatOutput>,
    pub witnesses: Vec<crate::transaction::WitnessEntry>,
    pub extensions: Vec<crate::transaction::ExtensionRecord>,
    pub path: Vec<[u8; 32]>,
}

impl TxInclusionProof {
    /// The proved output, once the slices are known to match the descriptor.
    pub fn output(&self) -> Option<&FlatOutput> {
        let d = &self.descriptor;
        if self.output_idx < d.out_start {
            return None;
        }
        self.outputs.get((self.output_idx - d.out_start) as usize)
    }

    /// True when the slices match the descriptor's lengths, the recomputed commitment leaf
    /// sits at `tx_idx` under `tx_merkle_root`, and the claimed output is inside the transaction.
    pub fn verify(&self, tx_merkle_root: &[u8; 32]) -> bool {
        let d = &self.descriptor;
        if self.inputs.len() != d.in_len as usize
            || self.outputs.len() != d.out_len as usize
            || self.witnesses.len() != d.witness_len as usize
            || self.extensions.len() != d.extension_len as usize
            || self.output().is_none()
        {
            return false;
        }
        let leaf = ShardBlockBody::tx_leaf_hash_from_parts(d, &self.inputs, &self.outputs, &self.witnesses, &self.extensions);
        ShardBlockBody::verify_tx_merkle_path(self.tx_idx, &leaf, &self.path, tx_merkle_root)
    }
}

#[cfg(test)]
mod tx_inclusion_proof_tests {
    use super::*;
    use crate::transaction::{TransactionDescriptor, WitnessEntry};

    /// `n` transactions; tx i has i%3 + 1 outputs, one input and one witness, no extensions.
    fn body(n: usize) -> ShardBlockBody {
        let mut b = ShardBlockBody::default();
        for i in 0..n {
            let (out_start, in_start, w_start) = (b.outputs.len() as u32, b.inputs.len() as u32, b.witnesses.len() as u32);
            let outs = i % 3 + 1;
            for j in 0..outs {
                b.outputs.push(FlatOutput { value: 1000 + (i * 10 + j) as u64, recipient: [(i + 1) as u8; 32] });
            }
            b.inputs.push(FlatInput { prev_height: i as u32, prev_output_idx: 0 });
            b.witnesses.push(WitnessEntry { witness_data: vec![i as u8; 64] });
            b.descriptors.push(TransactionDescriptor {
                out_start, out_len: outs as u32, in_start, in_len: 1,
                witness_start: w_start, witness_len: 1, extension_start: 0, extension_len: 0,
            });
        }
        b
    }

    #[test]
    fn every_output_of_every_size_of_block_has_a_valid_proof() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17] {
            let b = body(n);
            let root = b.calculate_tx_merkle_root();
            for o in 0..b.outputs.len() as u32 {
                let p = b.tx_inclusion_proof(7, o).unwrap_or_else(|| panic!("n={n} output {o}"));
                assert!(p.verify(&root), "n={n} output {o}");
                assert_eq!(p.output(), Some(&b.outputs[o as usize]));
                assert_eq!(p.height, 7);
            }
        }
    }

    #[test]
    fn the_leaf_from_parts_equals_the_body_leaf() {
        let b = body(6);
        for i in 0..6 {
            let d = &b.descriptors[i];
            let leaf = ShardBlockBody::tx_leaf_hash_from_parts(
                d,
                &b.inputs[d.in_start as usize..(d.in_start + d.in_len) as usize],
                &b.outputs[d.out_start as usize..(d.out_start + d.out_len) as usize],
                &b.witnesses[d.witness_start as usize..d.witness_start as usize + d.witness_len as usize],
                &[],
            );
            assert_eq!(Some(leaf), b.tx_leaf_hash(i));
        }
    }

    #[test]
    fn a_proof_does_not_verify_after_any_tampering() {
        let b = body(9);
        let root = b.calculate_tx_merkle_root();
        let good = b.tx_inclusion_proof(3, 4).unwrap();
        assert!(good.verify(&root));

        let mut p = good.clone();
        p.outputs[0].value += 1;
        assert!(!p.verify(&root), "changed value");

        let mut p = good.clone();
        p.outputs[0].recipient = [9u8; 32];
        assert!(!p.verify(&root), "changed recipient");

        let mut p = good.clone();
        p.tx_idx ^= 1;
        assert!(!p.verify(&root), "moved to another position");

        let mut p = good.clone();
        p.path[0][0] ^= 1;
        assert!(!p.verify(&root), "changed sibling");

        let mut p = good.clone();
        p.witnesses[0].witness_data[0] ^= 1;
        assert!(!p.verify(&root), "changed witness");

        let mut p = good.clone();
        p.path.pop();
        assert!(!p.verify(&root), "short path");

        let mut p = good.clone();
        p.outputs.pop();
        assert!(!p.verify(&root), "slice shorter than the descriptor");

        assert!(!good.verify(&[0u8; 32]), "another root");
    }

    #[test]
    fn an_output_outside_the_block_has_no_proof() {
        let b = body(4);
        assert!(b.tx_inclusion_proof(1, b.outputs.len() as u32).is_none());
    }
}
