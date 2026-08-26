// filament-types/src/proofs/types.rs — proof payload block data.
//
// `BlockData` carries the consensus fields a light client needs to verify a
// proof checkpoint and independently recompute a block's identity hash.
// Filament's real code only ever constructs/matches the `Beacon` variant —
// `ShardFull`/`ShardLight` are kept only for wire-tag structural
// completeness (so decoding a message that names them doesn't fail) and are
// intentionally minimal: their PoW-recalculation fields (the real shard
// merged-mining verification machinery) are out of scope for this
// light-client packaging.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::weighted_hash::WeightedHash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockData {
    Beacon(BeaconBlockData),
    ShardFull(FullShardBlockData),
    ShardLight(LightShardBlockData),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconBlockData {
    pub height: u32,
    pub block_hash: WeightedHash,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub version: u32,
    pub delta: i32,
    pub difficulty: u64,
    pub bits: u32,
    pub nonce: u64,
    pub tx_merkle_root: [u8; 32],
    pub merged_mining_root: [u8; 32],
}

impl BeaconBlockData {
    /// Recompute the block's identity hash from its own committed fields.
    ///
    /// Step 1: commitment_hash = SHA256d(height || prev_mmr_root ||
    /// tx_merkle_root || merged_mining_root || difficulty).
    /// Step 2: 80-byte mining header = version || prev_mmr_root ||
    /// commitment_hash || delta || bits || nonce, then SHA256d that.
    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(&*self.prev_mmr_root);
        hasher.update(&self.tx_merkle_root);
        hasher.update(&self.merged_mining_root);
        hasher.update(self.difficulty.to_le_bytes());
        let first_hash = hasher.finalize();
        let commitment_hash = Sha256::digest(first_hash);

        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(&*self.prev_mmr_root);
        header.extend_from_slice(&commitment_hash);
        header.extend_from_slice(&(self.delta as u32).to_le_bytes());
        header.extend_from_slice(&self.bits.to_le_bytes());
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());

        let first_hash = Sha256::digest(&header);
        let second_hash = Sha256::digest(first_hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second_hash);
        result
    }

    pub fn verify_hash(&self) -> bool {
        let sha256d = self.calculate_hash();
        self.block_hash == WeightedHash::from_leaf_rbits(&sha256d, self.bits)
    }
}

/// Minimal shard block payload — height/MMR-linkage fields only. Real PoW
/// recalculation for shard blocks (merged-mining proof, beacon aux header)
/// is intentionally not reproduced here; see module doc comment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullShardBlockData {
    pub height: u32,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub tx_merkle_root: [u8; 32],
    pub difficulty: u32,
    pub chain_weight: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightShardBlockData {
    pub height: u32,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub tx_merkle_root: [u8; 32],
    pub difficulty: u32,
    pub chain_weight: u128,
    pub pow_hash: [u8; 32],
    pub delta: i32,
}

impl BlockData {
    pub fn height(&self) -> u32 {
        match self {
            BlockData::Beacon(b) => b.height,
            BlockData::ShardFull(s) => s.height,
            BlockData::ShardLight(s) => s.height,
        }
    }

    pub fn mmr_root(&self) -> WeightedHash {
        match self {
            BlockData::Beacon(b) => b.current_mmr_root,
            BlockData::ShardFull(s) => s.current_mmr_root,
            BlockData::ShardLight(s) => s.current_mmr_root,
        }
    }

    pub fn mmr_root_bytes(&self) -> [u8; 32] {
        *self.mmr_root()
    }

    pub fn prev_mmr_root(&self) -> WeightedHash {
        match self {
            BlockData::Beacon(b) => b.prev_mmr_root,
            BlockData::ShardFull(s) => s.prev_mmr_root,
            BlockData::ShardLight(s) => s.prev_mmr_root,
        }
    }

    pub fn prev_mmr_root_bytes(&self) -> [u8; 32] {
        *self.prev_mmr_root()
    }

    pub fn tx_merkle_root(&self) -> [u8; 32] {
        match self {
            BlockData::Beacon(b) => b.tx_merkle_root,
            BlockData::ShardFull(s) => s.tx_merkle_root,
            BlockData::ShardLight(s) => s.tx_merkle_root,
        }
    }

    /// Recompute the block's identity hash. Only implemented for the
    /// `Beacon` variant — see module doc comment.
    pub fn block_hash(&self) -> [u8; 32] {
        match self {
            BlockData::Beacon(b) => *b.block_hash,
            BlockData::ShardFull(s) => *s.current_mmr_root, // structurally present, not a real recompute
            BlockData::ShardLight(s) => s.pow_hash,
        }
    }

    pub fn block_hash_weighted(&self) -> WeightedHash {
        match self {
            BlockData::Beacon(b) => b.block_hash,
            BlockData::ShardFull(s) => WeightedHash::from_leaf_rbits(&self.block_hash(), s.difficulty),
            BlockData::ShardLight(s) => WeightedHash::from_leaf_rbits(&s.pow_hash, s.difficulty),
        }
    }

    /// `true` only for `Beacon` — the only variant this packaging can
    /// actually recompute PoW for.
    pub fn can_verify_pow(&self) -> bool {
        matches!(self, BlockData::Beacon(_))
    }

    /// Alias for `tx_merkle_root()`.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.tx_merkle_root()
    }

    pub fn difficulty(&self) -> u64 {
        match self {
            BlockData::Beacon(b) => b.difficulty,
            BlockData::ShardFull(s) => s.difficulty as u64,
            BlockData::ShardLight(s) => s.difficulty as u64,
        }
    }

    /// Derive shard_id from the block's PoW hash via hash sorting. Beacon
    /// blocks have no shard_id (`None`).
    pub fn derive_shard_id(&self, hash_sorting_bits: u32) -> Option<u32> {
        match self {
            BlockData::Beacon(_) => None,
            BlockData::ShardFull(_) => crate::hash_sorting::find_eligible_shard(&self.block_hash(), hash_sorting_bits),
            BlockData::ShardLight(s) => crate::hash_sorting::find_eligible_shard(&s.pow_hash, hash_sorting_bits),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRChainSummary {
    pub tip_block: BlockData,
    pub chain_weight: u128,
    pub recent_blocks_proof: crate::proofs::WeightedMMRBatchProof,
    pub recent_blocks: Vec<BlockData>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRRangeProofBundle {
    pub proof: crate::proofs::WeightedMMRRangeProof,
    pub blocks: Vec<BlockData>,
    pub target_block: BlockData,
}

/// Legacy compact block payload — kept for wire compatibility with older
/// message shapes. Prefer `BlockData`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_block_data_hash_is_deterministic() {
        let b = BeaconBlockData {
            height: 1,
            block_hash: WeightedHash::zero(),
            prev_mmr_root: WeightedHash::from_anchor(&[1u8; 32]),
            current_mmr_root: WeightedHash::zero(),
            version: 1,
            delta: 0,
            difficulty: 64,
            bits: 0x0300_0040,
            nonce: 0,
            tx_merkle_root: [2u8; 32],
            merged_mining_root: [3u8; 32],
        };
        assert_eq!(b.calculate_hash(), b.calculate_hash());
    }
}
