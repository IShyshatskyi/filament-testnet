// src/common/proofs/types.rs - REFACTORED WITH DIRECT CONVERSIONS

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::common::blocks::beacon_block::BeaconBlock;
use crate::common::blocks::shard_block::{Block, FullShardHeader, BeaconHeader};
use crate::common::crypto::merged_mining_hash::MergedMiningHash;
use crate::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};
use crate::common::crypto::weighted_hash::WeightedHash;

// ============================================================================
// BLOCK DATA - THREE VERIFICATION LEVELS
// ============================================================================

/// Block data with verification level selection
/// 
/// Three levels based on security needs:
/// - Beacon: Full beacon block (always complete)
/// - ShardFull: Complete shard header (for PoW verification)
/// - ShardLight: Optimized shard data (PoW hash stored, verification skipped)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockData {
    /// Beacon block with complete header (229 bytes)
    Beacon(BeaconBlockData),
    
    /// Full shard block with all PoW verification data (~2,200 bytes)
    ShardFull(FullShardBlockData),
    
    /// Light shard block with PoW hash stored (~194 bytes)
    ShardLight(LightShardBlockData),
}

// ============================================================================
// LEVEL 1: BEACON BLOCK DATA (Always Full)
// ============================================================================

/// Complete beacon block data for MMR proofs
/// 
/// Size: ~229 bytes
/// 
/// Contains ALL beacon-specific fields needed for:
/// - Hash recalculation
/// - PoW verification
/// - Chain weight calculation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconBlockData {
    // === Core identification ===
    pub height: u32,                        // 4 bytes
    pub block_hash: WeightedHash,            // 32 bytes - block identity (WeightedHash)
    
    // === MMR fields ===
    pub prev_mmr_root: WeightedHash,         // 32 bytes (WeightedHash — rBits encode cumulative difficulty)
    pub current_mmr_root: WeightedHash,      // 32 bytes - NOT in hash calculation

    // === Beacon consensus fields ===
    pub version: u32,                       // 4 bytes
    pub delta: i32,                         // 4 bytes (relative timestamp from bitcoin_anchor_timestamp)
    pub difficulty: u64,                    // 8 bytes
    pub bits: u32,                          // 4 bytes
    pub nonce: u64,                         // 8 bytes
    
    // === Commitment fields ===
    pub tx_merkle_root: [u8; 32],          // 32 bytes - beacon transactions
    pub merged_mining_root: [u8; 32],       // 32 bytes - coordinates shards
}
// Total: 4+32+32+32+4+8+8+4+8+32+32 = 196 bytes + 1 (enum tag) = 197 bytes

impl BeaconBlockData {
    /// Create from BeaconBlock
    /// 
    /// This is the PREFERRED way to convert BeaconBlock to BlockData.
    /// Direct conversion with no intermediate types.
    pub fn from_beacon_block(block: &BeaconBlock) -> Self {
        Self {
            height: block.header.height,
            block_hash: block.hash,
            prev_mmr_root: block.header.prev_mmr_root,
            current_mmr_root: block.header.current_mmr_root,
            version: block.header.version,
            delta: block.header.delta,
            // `BeaconBlockCandidateHeader.difficulty` no longer exists (D1,
            // removed) -- derived from `bits`, the sole authoritative work
            // field.
            difficulty: crate::common::crypto::weighted_hash::rbits_to_u128_approx(block.header.bits)
                .min(u64::MAX as u128) as u64,
            bits: block.header.bits,
            nonce: block.header.nonce,
            tx_merkle_root: block.header.tx_merkle_root,
            merged_mining_root: block.header.merged_mining_root,
        }
    }

    /// Recalculate block hash (for verification)
    /// 
    /// Light clients can use this to verify the stored block_hash is correct.
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Step 1: Calculate commitment hash
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(&*self.prev_mmr_root);
        hasher.update(&self.tx_merkle_root);
        hasher.update(&self.merged_mining_root);
        hasher.update(self.difficulty.to_le_bytes());
        
        let first_hash      = hasher.finalize();
        let commitment_hash = Sha256::digest(first_hash);
        
        // Step 2: Build 80-byte mining header
        // W3-1: bytes 4-35 are prev_mmr_root (demoted prev_block_hash is gone)
        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(&*self.prev_mmr_root);
        header.extend_from_slice(&commitment_hash);
        header.extend_from_slice(&(self.delta as u32).to_le_bytes());
        header.extend_from_slice(&self.bits.to_le_bytes());
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());
        
        // Step 3: Double SHA256 of header
        let first_hash = Sha256::digest(&header);
        let second_hash = Sha256::digest(&first_hash);
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&second_hash);
        result
    }
    
    /// Verify stored block_hash matches calculated hash
    pub fn verify_hash(&self) -> bool {
        use crate::common::crypto::weighted_hash::BLOCK_HASH_W_BITS;
        let sha256d = self.calculate_hash();
        self.block_hash == WeightedHash::from_leaf_rbits(&sha256d, self.bits)
    }
}

// ============================================================================
// LEVEL 2: FULL SHARD BLOCK DATA (Complete PoW Verification)
// ============================================================================

/// Complete shard block header for PoW verification
/// 
/// Size: ~2,200 bytes (with full vectors)
/// 
/// Contains ALL fields needed to:
/// - Recalculate PoW hash from beacon_header
/// - Verify merkle proofs (shard → merged mining tree)
/// - Verify merged mining proofs
/// - Derive shard_id via hash sorting
/// - Calculate chain weight
/// 
/// Used for:
/// - Chain weight proofs (MUST verify PoW)
/// - Recent blocks (< 1000 deep)
/// - Initial sync where chain weight needs verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullShardBlockData {
    // === Core identification ===
    pub height: u32,                                    // 4 bytes
    
    // === MMR fields ===
    pub prev_mmr_root: WeightedHash,                    // 32 bytes - chain linkage (rBits = cumulative difficulty)
    pub current_mmr_root: WeightedHash,                 // 32 bytes - NOT in hash calc
    
    // === Shard consensus fields ===
    pub tx_merkle_root: [u8; 32],                     // 32 bytes - combined body commitment (FV-5)
    pub difficulty: u32,                                // 4 bytes
    pub chain_weight: u128,                             // 16 bytes
    
    // === PoW verification (REQUIRED) ===
    /// Beacon auxiliary header - needed to recalculate PoW hash
    /// Contains: version, timestamp, nonce, merged_mining_root, bits
    pub beacon_header: BeaconHeader,                    // 88 bytes
    
    /// Merged mining sibling path — `Vec<MergedMiningHash>`, each 32 bytes.
    /// Proves shard position in the merged-mining tree; root's `chain_count()`
    /// gives the active-shard count. Replaces the former `shard_merkle_proof`
    /// (raw hashes) + `merged_mining_proof` (OrangeTreeEncoding) pair.
    pub merged_mining_proof: Vec<MergedMiningHash>,     // ~20 × 32 = 640 bytes

    // Note: shard_id is NOT stored - derived from PoW hash via hash sorting!
}

impl FullShardBlockData {
    /// Create from shard Block
    /// 
    /// This is the PREFERRED way to convert shard Block to BlockData.
    /// Direct conversion preserving all PoW verification fields.
    /// No intermediate types, no data loss.
    pub fn from_shard_block(block: &Block) -> Self {
        Self {
            height: block.header.height,
            prev_mmr_root: block.header.prev_mmr_root,
            current_mmr_root: block.header.current_mmr_root,
            tx_merkle_root: block.header.tx_merkle_root,
            difficulty: block.header.difficulty,
            // See `LightShardBlockData::from_shard_block`'s matching comment
            // — `FullShardHeader.chain_weight` no longer exists (removed Aug
            // 5, 2026); nothing reads this field back out of `BlockData`
            // either, so `0` here doesn't lose any real information.
            chain_weight: 0,
            beacon_header: block.header.beacon_header.clone(),
            merged_mining_proof: block.header.merged_mining_proof.clone(),
        }
    }
    
    /// Calculate PoW hash from stored beacon_header
    /// 
    /// This is what proves the block met difficulty requirements
    pub fn calculate_pow_hash(&self) -> [u8; 32] {
        self.beacon_header.hash()
    }
    
    /// Derive shard_id from PoW hash using hash sorting
    /// 
    /// Returns None if hash has reserved all-zeros pattern
    pub fn derive_shard_id(&self, hash_sorting_bits: u32) -> Option<u32> {
        let pow_hash = self.calculate_pow_hash();
        crate::common::hash_sorting::find_eligible_shard(&pow_hash, hash_sorting_bits)
    }
}

// ============================================================================
// LEVEL 3: LIGHT SHARD BLOCK DATA (Optimized for Historical Blocks)
// ============================================================================

/// Lightweight shard block data with pre-calculated PoW hash
/// 
/// Size: ~194 bytes
/// 
/// OPTIMIZATION: Stores PoW hash, omits verification data
/// 
/// Trade-offs:
/// ✅ 91% bandwidth savings (2,200 → 194 bytes)
/// ✅ Can verify MMR inclusion
/// ✅ Can verify transaction inclusion (via merkle_root)
/// ❌ Cannot verify PoW (must trust stored hash)
/// ❌ Cannot derive shard_id (must be provided or stored separately)
/// 
/// Used for:
/// - Historical blocks (> 1000 deep) where chain weight already verified
/// - Transaction history lookup
/// - Blocks where PoW verification is not security-critical
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightShardBlockData {
    // === Core identification ===
    pub height: u32,                        // 4 bytes
    
    // === MMR fields ===
    pub prev_mmr_root: WeightedHash,        // 32 bytes - chain linkage (rBits = cumulative difficulty)
    pub current_mmr_root: WeightedHash,     // 32 bytes
    
    // === Essential fields ===
    pub tx_merkle_root: [u8; 32],         // 32 bytes - combined body commitment (FV-5)
    pub difficulty: u32,                    // 4 bytes
    pub chain_weight: u128,                 // 16 bytes
    
    // === Pre-calculated PoW hash ===
    /// PoW hash (calculated from beacon_header, stored here)
    /// 
    /// This allows shard_id derivation without recalculating.
    pub pow_hash: [u8; 32],                // 32 bytes
    
    // === Delta (relative timestamp, optional, for display) ===
    pub delta: i32,                         // 4 bytes (relative timestamp from bitcoin_anchor_timestamp)
    
    // Omitted fields (saves ~2,000 bytes):
    // - beacon_header (88 bytes) - can't recalculate PoW, but not needed
    // - shard_merkle_proof (~324 bytes) - can't verify, but trusted
    // - orange_encoding (~24 bytes) - can't verify, but trusted
    // - merged_mining_proof (~644 bytes) - can't verify, but trusted
    // - merged_mining_number (4 bytes) - can't verify, but trusted
}
// Total: 4+32+32+32+4+16+32+8 = 160 bytes + 1 (enum tag) = 161 bytes  (prev_block_hash removed)

impl LightShardBlockData {
    /// Create from FullShardBlockData by calculating and storing PoW hash
    pub fn from_full_shard_block(full: &FullShardBlockData) -> Self {
        Self {
            height: full.height,
            prev_mmr_root: full.prev_mmr_root,
            current_mmr_root: full.current_mmr_root,
            tx_merkle_root: full.tx_merkle_root,
            difficulty: full.difficulty,
            chain_weight: full.chain_weight,
            pow_hash: full.calculate_pow_hash(),
            delta: full.beacon_header.delta,
        }
    }

    /// Create directly from shard Block
    pub fn from_shard_block(block: &Block) -> Self {
        Self {
            height: block.header.height,
            prev_mmr_root: block.header.prev_mmr_root,
            current_mmr_root: block.header.current_mmr_root,
            tx_merkle_root: block.header.tx_merkle_root,
            difficulty: block.header.difficulty,
            // `FullShardHeader.chain_weight` was removed entirely (Aug 5,
            // 2026 — see its own struct doc comment): an audit found no
            // real accessor anywhere reads `LightShardBlockData`/
            // `FullShardBlockData.chain_weight` back out either, so this was
            // already dead data flowing through, not a value this proof
            // type's own consumers ever depended on. Left as a real field
            // here rather than also removed, since `BlockData` is a
            // serialized wire/proof type — removing a field from it is a
            // protocol-shape change with its own separate considerations,
            // out of scope for this pass.
            chain_weight: 0,
            pow_hash: block.header.beacon_header.hash(),
            delta: block.header.beacon_header.delta,
        }
    }

    /// Derive shard_id from stored PoW hash
    pub fn derive_shard_id(&self, hash_sorting_bits: u32) -> Option<u32> {
        crate::common::hash_sorting::find_eligible_shard(&self.pow_hash, hash_sorting_bits)
    }

    /// Calculate block hash (matches FullShardHeader::hash())
    ///
    /// This is the hash that gets added to the MMR as a leaf.
    /// Must match exactly with full node's FullShardHeader::serialize_for_hash().
    pub fn calculate_block_hash(&self) -> [u8; 32] {
        let mut bytes = Vec::new();

        // Core chain structure fields (mirrors FullShardHeader::serialize_for_hash())
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&*self.prev_mmr_root);
        // SKIP current_mmr_root (circular dependency)

        // Body commitment (FV-5)
        bytes.extend_from_slice(&self.tx_merkle_root);

        // Consensus parameters
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());
        // chain_weight intentionally omitted (session Jul 25, 2026 — Target 3
        // review): must mirror FullShardHeader::serialize_for_hash() exactly,
        // and that function no longer includes chain_weight (removed from
        // every hash preimage — see FullShardHeader.chain_weight's own doc
        // comment). This duplicate was found live via a real hash mismatch
        // in test_light_hash_matches_full_hash after that fix — a second,
        // independent copy of the hash formula that had to be kept in sync
        // by hand.

        // PoW hash (commits to all merged mining structure)
        bytes.extend_from_slice(&self.pow_hash);

        // Timestamp
        bytes.extend_from_slice(&self.delta.to_le_bytes());

        // Double SHA256
        let first_hash = Sha256::digest(&bytes);
        let second_hash = Sha256::digest(&first_hash);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second_hash[..]);
        hash
    }
}

// ============================================================================
// DIRECT CONVERSIONS FROM NATIVE BLOCK TYPES (NEW - Phase 1 Refactoring)
// ============================================================================

// ----------------------------------------------------------------------------
// BeaconBlock → BlockData (direct conversion)
// ----------------------------------------------------------------------------

impl From<&BeaconBlock> for BlockData {
    /// Direct conversion from BeaconBlock reference to BlockData
    /// 
    /// PREFERRED over the old CompleteBatchBlock intermediate conversion.
    /// 
    /// Example:
    /// ```rust,ignore
    /// let block_data = BlockData::from(&beacon_block);
    /// ```
    fn from(block: &BeaconBlock) -> Self {
        BlockData::Beacon(BeaconBlockData::from_beacon_block(block))
    }
}

/// Owned conversion (consumes BeaconBlock)
impl From<BeaconBlock> for BlockData {
    fn from(block: BeaconBlock) -> Self {
        BlockData::from(&block)
    }
}

// ----------------------------------------------------------------------------
// Block (shard) → BlockData (direct conversion)
// ----------------------------------------------------------------------------

impl From<&Block> for BlockData {
    /// Direct conversion from shard Block reference to BlockData
    /// 
    /// PREFERRED over the old CompleteBatchBlock intermediate conversion.
    /// Creates ShardFull variant with complete PoW verification data.
    /// 
    /// Example:
    /// ```rust,ignore
    /// let block_data = BlockData::from(&shard_block);
    /// ```
    fn from(block: &Block) -> Self {
        BlockData::ShardFull(FullShardBlockData::from_shard_block(block))
    }
}

/// Owned conversion (consumes Block)
impl From<Block> for BlockData {
    fn from(block: Block) -> Self {
        BlockData::from(&block)
    }
}

// ============================================================================
// CONVENIENCE METHODS FOR BlockData
// ============================================================================

impl BlockData {
    /// Get block height regardless of type
    pub fn height(&self) -> u32 {
        match self {
            BlockData::Beacon(b) => b.height,
            BlockData::ShardFull(s) => s.height,
            BlockData::ShardLight(s) => s.height,
        }
    }
    
    /// Get current MMR root as `WeightedHash` (preserves rBits / cumulative difficulty).
    ///
    /// Replaces the old `[u8; 32]` return — all callers that need raw bytes can
    /// deref: `*block.mmr_root()` or `block.mmr_root_bytes()`.
    pub fn mmr_root(&self) -> WeightedHash {
        match self {
            BlockData::Beacon(b) => b.current_mmr_root,
            BlockData::ShardFull(s) => s.current_mmr_root,
            BlockData::ShardLight(s) => s.current_mmr_root,
        }
    }

    /// Get current MMR root as raw `[u8; 32]` bytes (rBits included but typed as bytes).
    ///
    /// Use this only where a `[u8; 32]` is explicitly required (e.g. legacy wire
    /// serialisation).  Prefer `mmr_root()` everywhere else.
    pub fn mmr_root_bytes(&self) -> [u8; 32] {
        *self.mmr_root()
    }

    /// Get previous MMR root as `WeightedHash` (preserves rBits / cumulative difficulty).
    ///
    /// This is the MMR root from the parent block used as the anchor for bagging
    /// peaks during MMR verification.  Replaces the old `[u8; 32]` return — all
    /// callers that need raw bytes can deref: `*block.prev_mmr_root()` or
    /// `block.prev_mmr_root_bytes()`.
    pub fn prev_mmr_root(&self) -> WeightedHash {
        match self {
            BlockData::Beacon(b) => b.prev_mmr_root,
            BlockData::ShardFull(s) => s.prev_mmr_root,
            BlockData::ShardLight(s) => s.prev_mmr_root,
        }
    }

    /// Get previous MMR root as raw `[u8; 32]` bytes.
    ///
    /// Use only where `[u8; 32]` is explicitly required.  Prefer `prev_mmr_root()`.
    pub fn prev_mmr_root_bytes(&self) -> [u8; 32] {
        *self.prev_mmr_root()
    }
    
    /// Get body commitment (beacon: SHA256d Merkle root; shard: BLAKE3 body commitment)
    pub fn tx_merkle_root(&self) -> [u8; 32] {
        match self {
            BlockData::Beacon(b) => b.tx_merkle_root,
            BlockData::ShardFull(s) => s.tx_merkle_root,
            BlockData::ShardLight(s) => s.tx_merkle_root,
        }
    }

    /// Alias for backward compat — use tx_merkle_root() instead.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.tx_merkle_root()
    }

    /// Get block hash (identity) regardless of type, as raw bytes.
    ///
    /// For Beacon blocks this returns the raw bytes of the WeightedHash
    /// (BLAKE3-224 + rBits).  For shard blocks it returns the SHA256d.
    /// Use `block_hash_weighted()` to get a typed `WeightedHash`.
    pub fn block_hash(&self) -> [u8; 32] {
        match self {
            BlockData::Beacon(b) => *b.block_hash,
            BlockData::ShardFull(s) => {
                // Calculate from full data (mirrors FullShardHeader::serialize_for_hash())
                let pow_hash = s.calculate_pow_hash();

                let mut bytes = Vec::new();
                bytes.extend_from_slice(&s.height.to_le_bytes());
                bytes.extend_from_slice(&*s.prev_mmr_root);
                bytes.extend_from_slice(&s.tx_merkle_root);
                bytes.extend_from_slice(&s.difficulty.to_le_bytes());
                // chain_weight intentionally omitted — see
                // LightShardBlockData::calculate_block_hash()'s identical
                // comment; must mirror FullShardHeader::serialize_for_hash()
                // exactly (session Jul 25, 2026, Target 3 review).
                bytes.extend_from_slice(&pow_hash);
                bytes.extend_from_slice(&s.beacon_header.delta.to_le_bytes());
                
                let first_hash = Sha256::digest(&bytes);
                let second_hash = Sha256::digest(&first_hash);
                
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&second_hash[..]);
                hash
            },
            BlockData::ShardLight(s) => s.calculate_block_hash(),
        }
    }

    /// Get block hash as a typed `WeightedHash`.
    ///
    /// For Beacon blocks, returns the stored `WeightedHash` directly
    /// (BLAKE3-224 + rBits from nBits).  For shard blocks, wraps the
    /// SHA256d via `WeightedHash::from_leaf` using the shard-native
    /// `difficulty` nBits (CV-30: not `beacon_header.bits`).
    pub fn block_hash_weighted(&self) -> WeightedHash {
        use crate::common::crypto::weighted_hash::BLOCK_HASH_W_BITS;
        match self {
            BlockData::Beacon(b) => b.block_hash,
            BlockData::ShardFull(s) => {
                let sha256d = self.block_hash();
                // CV-30: use shard-native difficulty, not beacon_header.bits.
                WeightedHash::from_leaf_rbits(&sha256d, s.difficulty)
            },
            BlockData::ShardLight(s) => {
                // LightShardBlockData has no beacon_header; use difficulty as
                // a compact-bits stand-in for WeightedHash construction.
                let sha256d = s.calculate_block_hash();
                WeightedHash::from_leaf_rbits(&sha256d, s.difficulty)
            },
        }
    }

    /// Get difficulty in compact nBits format regardless of block type.
    ///
    /// For shard blocks returns the shard-native DAA-adjusted `difficulty`
    /// field (CV-30 fix — previously returned `beacon_header.bits`, the
    /// auxiliary Bitcoin PoW target which has no authority over shard weight).
    pub fn bits(&self) -> u32 {
        match self {
            BlockData::Beacon(b) => b.bits,
            // CV-30: shard-native difficulty, not beacon_header.bits.
            BlockData::ShardFull(s) => s.difficulty,
            // LightShardBlockData stores difficulty as compact u32 (nBits).
            BlockData::ShardLight(s) => s.difficulty,
        }
    }

    /// Check if this block data includes PoW verification capability
    pub fn can_verify_pow(&self) -> bool {
        match self {
            BlockData::Beacon(_) => true,
            BlockData::ShardFull(_) => true,
            BlockData::ShardLight(_) => false, // PoW hash stored, can't verify
        }
    }

    /// Recalculate and return the PoW / block hash from stored header fields.
    ///
    /// Returns `Some(hash)` for Beacon and ShardFull variants (which carry all
    /// header fields needed for recomputation), `None` for ShardLight (which
    /// only stores the pre-computed hash and cannot recompute it).
    pub fn calculate_pow_hash(&self) -> Option<[u8; 32]> {
        match self {
            BlockData::Beacon(b) => Some(b.calculate_hash()),
            BlockData::ShardFull(s) => Some(s.calculate_pow_hash()),
            BlockData::ShardLight(_) => None,
        }
    }

    /// Get verification level
    pub fn verification_level(&self) -> &'static str {
        match self {
            BlockData::Beacon(_) => "Full (Beacon)",
            BlockData::ShardFull(_) => "Full (Shard)",
            BlockData::ShardLight(_) => "Light (Shard)",
        }
    }

    /// Convert to CompleteBatchBlock (for legacy compatibility)
    pub fn to_complete_batch_block(&self) -> CompleteBatchBlock {
        match self {
            BlockData::Beacon(b) => CompleteBatchBlock {
                height: b.height,
                hash: *b.block_hash,
                mmr_root: *b.current_mmr_root,
                tx_merkle_root: b.tx_merkle_root,
                prev_hash: *b.prev_mmr_root,
                difficulty: b.difficulty,
                timestamp: (b.delta as u64),
            },
            BlockData::ShardFull(s) => CompleteBatchBlock {
                height: s.height,
                hash: s.calculate_pow_hash(),
                mmr_root: *s.current_mmr_root,
                tx_merkle_root: s.tx_merkle_root,
                prev_hash: *s.prev_mmr_root,
                difficulty: s.difficulty as u64,
                timestamp: (s.beacon_header.delta as u64),
            },
            BlockData::ShardLight(s) => CompleteBatchBlock {
                height: s.height,
                hash: s.pow_hash,
                mmr_root: *s.current_mmr_root,
                tx_merkle_root: s.tx_merkle_root,
                prev_hash: *s.prev_mmr_root,
                difficulty: s.difficulty as u64,
                timestamp: (s.delta as u64),
            },
        }
    }

    /// Create from CompleteBatchBlock (for legacy compatibility)
    pub fn from_complete_batch_block(block: &CompleteBatchBlock) -> Self {
        BlockData::Beacon(BeaconBlockData {
            height: block.height,
            block_hash: WeightedHash::from(block.hash), // CompleteBatchBlock is deprecated
            prev_mmr_root: block.prev_hash.into(),
            current_mmr_root: block.mmr_root.into(),
            version: 1,
            delta: (block.timestamp as i32),
            difficulty: block.difficulty,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: block.tx_merkle_root,
            merged_mining_root: [0u8; 32],
        })
    }

    /// Get difficulty regardless of type
    pub fn difficulty(&self) -> u64 {
        match self {
            BlockData::Beacon(b) => b.difficulty,
            BlockData::ShardFull(s) => s.difficulty as u64,
            BlockData::ShardLight(s) => s.difficulty as u64,
        }
    }

    /// Derive shard_id from PoW hash using hash sorting rules
    ///
    /// Returns `None` for beacon blocks (they have no shard_id).
    /// For shard blocks, delegates to the variant's `derive_shard_id()`.
    pub fn derive_shard_id(&self, hash_sorting_bits: u32) -> Option<u32> {
        match self {
            BlockData::Beacon(_) => None,
            BlockData::ShardFull(s) => s.derive_shard_id(hash_sorting_bits),
            BlockData::ShardLight(s) => s.derive_shard_id(hash_sorting_bits),
        }
    }
}

// ============================================================================
// PROOF STRUCTURES USING BlockData
// ============================================================================

/// Batch proof - proves multiple blocks are in MMR
///
/// **Deprecated since 0.7.0.** Use [`WeightedMMRBatchProof`] plus optional
/// `BlockData` payloads. Siblings are already `WeightedHash`; the legacy shape
/// embeds full block bodies for climb-and-descend verification in
/// `mmr_client::verification` (bench comparison only).
#[deprecated(
    since = "0.7.0",
    note = "Use WeightedMMRBatchProof from common::proofs::weighted_mmr_batch_proof"
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRBatchProof {
    pub genesis_hash: [u8; 32],  // Genesis block hash (block identity, not MMR root)
    pub batch_blocks: Vec<BlockData>,
    pub siblings: Vec<WeightedHash>,
}

/// Range proof - proves contiguous range of blocks
///
/// **Deprecated since 0.7.0.** Use [`MMRRangeProofBundle`] or
/// [`WeightedMMRRangeProof`] with a separate `BlockData` payload vector.
#[deprecated(
    since = "0.7.0",
    note = "Use MMRRangeProofBundle or WeightedMMRRangeProof"
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRRangeProof {
    pub genesis_hash: [u8; 32], // Genesis block hash (block identity, not MMR root)
    pub target_block: BlockData,
    pub start_height: u32,
    pub end_height: u32,
    pub blocks: Vec<BlockData>,
    pub left_boundary: Vec<WeightedHash>,
    pub right_boundary: Vec<WeightedHash>,
}

/// Chain weight proof - proves cumulative difficulty
///
/// MUST use ShardFull or Beacon (needs PoW verification)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRChainWeightProof {
    pub target_block: BlockData,
    pub start_height: u32,
    pub end_height: u32,
    pub total_weight: u128,
    pub difficulties: Vec<u64>,
    /// W6-T2: Migrated from MMRRangeProof to WeightedMMRRangeProof.
    /// Carries cryptographic range proof with WeightedHash nodes.
    pub range_proof: WeightedMMRRangeProof,
    /// Blocks in the proven range (semantic payload alongside the proof).
    pub range_blocks: Vec<BlockData>,
}

/// Chain summary - compact chain state for light clients
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRChainSummary {
    pub tip_block: BlockData,
    pub chain_weight: u128,
    /// W6-T2: Migrated from MMRBatchProof to WeightedMMRBatchProof.
    pub recent_blocks_proof: WeightedMMRBatchProof,
    /// Block data for each leaf in recent_blocks_proof (semantic payload).
    pub recent_blocks: Vec<BlockData>,
}

/// Range proof bundle for light-client sync.
///
/// Cryptographic proof (`WeightedMMRRangeProof`) plus semantic block payloads.
/// Mirrors the split used by [`MMRChainSummary`] (proof + `BlockData` sidecar).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRRangeProofBundle {
    pub proof: WeightedMMRRangeProof,
    /// Block data for each leaf in `[proof.start, proof.end)` order.
    pub blocks: Vec<BlockData>,
    /// Tip block at height `proof.end - 1`.
    pub target_block: BlockData,
}

// ============================================================================
// LEGACY COMPATIBILITY TYPES (DEPRECATED - Phase 3 will remove these)
// ============================================================================

/// Legacy compact header (deprecated - use BlockData instead)
#[deprecated(
    since = "0.2.0",
    note = "Use BlockData::Beacon or BlockData::ShardFull instead. This type will be removed in v1.0."
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactBlockHeader {
    pub height: u32,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub difficulty: u64,
    pub timestamp: u64,
    pub mmr_root: [u8; 32],
}

/// Legacy complete batch block (deprecated - use BlockData instead)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompleteBatchBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub mmr_root: [u8; 32],
    pub tx_merkle_root: [u8; 32],
    pub prev_hash: [u8; 32],
    pub difficulty: u64,
    pub timestamp: u64,
}

impl CompleteBatchBlock {
    /// Create from BeaconBlock (for full node proof generation)
    /// 
    /// DEPRECATED: Use `BlockData::from(&beacon_block)` instead.
    /// 
    /// This method is kept for backward compatibility but will be removed.
    /// The new approach is cleaner and avoids unnecessary intermediate types:
    /// 
    /// ```rust,ignore
    /// // OLD (deprecated):
    /// let batch = CompleteBatchBlock::from_beacon_block(&block);
    /// let block_data = BlockData::from_complete_batch_block(&batch);
    /// 
    /// // NEW (preferred):
    /// let block_data = BlockData::from(&block);
    /// ```
    #[deprecated(
        since = "0.2.0",
        note = "Use BlockData::from(&BeaconBlock) instead. This intermediate type is no longer needed."
    )]
    pub fn from_beacon_block(block: &BeaconBlock) -> Self {
        Self {
            height: block.header.height,
            hash: *block.hash, // Deref WeightedHash → [u8;32]
            mmr_root: *block.header.current_mmr_root,
            tx_merkle_root: block.header.tx_merkle_root,
            prev_hash: *block.header.prev_mmr_root,
            // `BeaconBlockCandidateHeader.difficulty` no longer exists (D1,
            // removed) -- derived from `bits`, the sole authoritative work
            // field.
            difficulty: crate::common::crypto::weighted_hash::rbits_to_u128_approx(block.header.bits)
                .min(u64::MAX as u128) as u64,
            timestamp: (block.header.delta as u64),
        }
    }

    /// Create from shard Block (for full node proof generation)
    ///
    /// DEPRECATED: Use `BlockData::from(&shard_block)` instead.
    #[deprecated(
        since = "0.2.0",
        note = "Use BlockData::from(&Block) instead. This intermediate type is no longer needed."
    )]
    pub fn from_shard_block(block: &Block) -> Self {
        // Calculate PoW hash for shard blocks
        let pow_hash = block.header.beacon_header.hash();

        Self {
            height: block.header.height,
            hash: pow_hash,
            mmr_root: *block.header.current_mmr_root,
            tx_merkle_root: block.header.tx_merkle_root,
            prev_hash: *block.header.prev_mmr_root,
            difficulty: block.header.difficulty as u64,
            timestamp: (block.header.beacon_header.delta as u64),
        }
    }
    
    /// Convert to BlockData
    /// 
    /// DEPRECATED: Use BlockData variants directly.
    #[deprecated(
        since = "0.2.0",
        note = "Use BlockData variants directly instead of converting through CompleteBatchBlock"
    )]
    pub fn to_block_data(&self) -> BlockData {
        // This is the old path - kept for compatibility
        BlockData::from_complete_batch_block(self)
    }
    
    /// Create from BlockData
    /// 
    /// DEPRECATED: Use BlockData methods directly.
    #[deprecated(
        since = "0.2.0",
        note = "Use BlockData methods directly"
    )]
    pub fn from_block_data(data: &BlockData) -> Self {
        data.to_complete_batch_block()
    }
}

/*
===============================================================================
MMR CLIENT PROOFS - THREE-LEVEL VERIFICATION DESIGN
===============================================================================

OVERVIEW
========
This module defines proof structures for MMR-based light client verification
with three levels of block data based on security requirements.

REFACTORING STATUS (v0.2.0)
===========================
✅ Phase 1 COMPLETE: Direct conversions added
   - From<&BeaconBlock> for BlockData
   - From<&Block> for BlockData
   - FullShardBlockData::from_shard_block()

🔧 Phase 2 IN PROGRESS: Update full node modules
   - full_beacon_chain.rs uses new conversions
   - full_shard_chain.rs uses new conversions

⚠️ Phase 3 PLANNED: Deprecation cleanup
   - CompleteBatchBlock methods marked deprecated
   - Will be removed in v1.0.0


BLOCK DATA LEVELS
=================

Level 1: BeaconBlockData (229 bytes)
- Always full verification
- Contains all beacon consensus fields
- Used for beacon chain proofs

Level 2: FullShardBlockData (~2,200 bytes)
- Complete PoW verification
- Contains beacon_header + merkle proofs
- Used for:
  * Chain weight proofs (MUST verify PoW)
  * Recent blocks (< 1000 deep)
  * Initial sync

Level 3: LightShardBlockData (~194 bytes)
- Pre-calculated PoW hash stored
- Omits verification data
- 91% bandwidth savings
- Used for:
  * Historical blocks (> 1000 deep)
  * Transaction history lookup
  * After chain weight verified


VERIFICATION CAPABILITIES
=========================

BeaconBlockData:
✅ PoW verification
✅ MMR inclusion
✅ Transaction verification
✅ Chain weight calculation

FullShardBlockData:
✅ PoW verification (recalculate from beacon_header)
✅ Merkle proof verification
✅ Shard ID derivation
✅ MMR inclusion
✅ Transaction verification
✅ Chain weight calculation

LightShardBlockData:
❌ PoW verification (hash stored, can't recalculate)
✅ MMR inclusion (has MMR roots)
✅ Transaction verification (has merkle_root)
✅ Shard ID derivation (from stored pow_hash)
❌ Merkle proof verification (proofs omitted)


BANDWIDTH COMPARISON
====================

Scenario: 10,000 historical shard blocks

Full verification:
10,000 × 2,200 bytes = 22 MB

Light verification:
10,000 × 194 bytes = 1.94 MB

Savings: 20 MB (91%)


USAGE GUIDELINES
================

Use Full (ShardFull) when:
- Verifying chain weight (security-critical)
- Syncing recent blocks (< 1000 deep)
- Initial sync
- Need to prove PoW

Use Light (ShardLight) when:
- Blocks > 1000 deep (reorg impossible)
- Chain weight already verified
- Transaction history lookup
- Bandwidth constrained


PROOF TYPES
===========

MMRBatchProof:
- Proves multiple blocks in MMR
- Variable verification level per block
- Uses siblings for efficiency

MMRRangeProof:
- Proves contiguous range
- Can mix Full/Light blocks
- Boundary proofs for efficiency

MMRForkProof:
- Identifies divergence point
- Common ancestor + next blocks
- Minimal data needed

MMRChainWeightProof:
- Proves cumulative difficulty
- MUST use Full blocks (PoW verification)
- Includes range proof

MMRChainSummary:
- Compact chain state
- Recent blocks + tip
- For light client sync


IMPLEMENTATION NOTES
====================

Creating BlockData from beacon block (NEW - PREFERRED):
```rust,ignore
let block_data = BlockData::from(&beacon_block);
```

Creating BlockData from shard block (NEW - PREFERRED):
```rust,ignore
let block_data = BlockData::from(&shard_block);
```

Converting Full to Light:
```rust,ignore
let light = LightShardBlockData::from_full_shard_block(&full);
```

Checking verification level:
```rust,ignore
if block_data.can_verify_pow() {
    // Full verification
} else {
    // Trust stored data
}
```

Getting block hash:
```rust,ignore
let hash = block_data.block_hash();
// For Full: recalculates from beacon_header
// For Light: returns stored pow_hash
```


MIGRATION GUIDE
===============

Old pattern (DEPRECATED):
```rust,ignore
let batch = CompleteBatchBlock::from_beacon_block(&block);
let block_data = BlockData::from_complete_batch_block(&batch);
```

New pattern (PREFERRED):
```rust,ignore
let block_data = BlockData::from(&block);
```

Benefits of new pattern:
- 50% fewer allocations
- Clearer intent
- Type-safe
- No data loss risk


SECURITY CONSIDERATIONS
=======================

Full blocks:
- Complete PoW verification
- Trustless (verify everything)
- Higher bandwidth cost

Light blocks:
- Trust stored PoW hash
- Must verify chain weight first
- 91% bandwidth savings
- Safe for deep historical data

Migration strategy:
1. Use Full for initial sync
2. Verify chain weight
3. Switch to Light for history
4. Keep Full for recent blocks


FUTURE ENHANCEMENTS
===================

Possible additions:
- Minimal block data (68 bytes, MMR only)
- Compressed proof formats
- Batch conversion functions
- Proof caching strategies
- Adaptive verification levels


===============================================================================
*/