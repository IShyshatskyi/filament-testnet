// ============================================================================
// src/mmr_client/chain_handler.rs - Base Chain Handler (UPDATED)
// ============================================================================

//! Generic Chain Handler
//!
//! Provides common functionality for managing any blockchain's state
//! in a light client. Both beacon and shard chains extend this.

use std::collections::HashMap;
use log::{info, debug};
use serde::{Serialize, Deserialize};

pub use common_types::common::types::ChainType;
use common_types::common::crypto::hash_pair;
use common_types::common::crypto::weighted_hash::WeightedHash;
use common_types::common::proofs::{MMRChainSummary, MMRRangeProofBundle, BlockData};
use crate::mmr_client::weighted_mmr_light::WeightedMMRLight;
use crate::mmr_client::storage::{LightClientStorage, ChainId};

/// Chain state for any blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Chain type (Beacon or Shard)
    pub chain_type: ChainType,

    /// Chain identifier
    /// - Beacon: chain_id = 0
    /// - Shard: chain_id = shard_id + 1
    pub chain_id: u32,

    /// Bitcoin anchor hash (prevents pre-mining)
    /// This is the external Bitcoin block hash that anchors the genesis
    pub anchor_hash: [u8; 32],

    /// Genesis block hash (if mined)
    /// None if genesis has not been mined yet (pre-genesis state)
    /// Some(hash) after genesis block is mined and validated
    pub genesis_hash: Option<[u8; 32]>,

    /// Current tip block
    pub tip: BlockData,

    /// Chain weight (cumulative difficulty)
    pub chain_weight: u128,

    /// Maximum blocks to cache
    pub max_cache_size: usize,

    /// Recent blocks cache (for verification)
    pub recent_blocks: HashMap<u32, BlockData>,

    /// Lightweight weighted MMR for verification (preserves rBits chain weight)
    pub mmr_light: WeightedMMRLight,

    /// Expected shard ID for this chain. None for beacon chain.
    /// Used to validate that blocks in proofs belong to the correct shard.
    pub expected_shard_id: Option<u32>,

    /// Number of hash-sorting bits (for shard ID derivation)
    pub hash_sorting_bits: u32,
}

impl ChainState {
    /// Create new chain state from genesis block
    ///
    /// # Arguments
    /// * `chain_type` - Beacon or Shard
    /// * `chain_id` - 0 for beacon, shard_id + 1 for shards
    /// * `anchor_hash` - Bitcoin anchor hash (prevents pre-mining)
    /// * `genesis` - Genesis block (as BlockData)
    /// * `expected_shard_id` - Expected shard ID (None for beacon chain)
    /// * `hash_sorting_bits` - Number of hash-sorting bits for shard ID derivation
    pub fn new(
        chain_type: ChainType,
        chain_id: u32,
        anchor_hash: [u8; 32],
        genesis: BlockData,
        expected_shard_id: Option<u32>,
        hash_sorting_bits: u32,
    ) -> Self {
        let genesis_height = genesis.height();
        let genesis_hash = genesis.block_hash();

        let mut recent_blocks = HashMap::new();
        recent_blocks.insert(genesis_height, genesis.clone());

        Self {
            chain_type,
            chain_id,
            anchor_hash,
            genesis_hash: Some(genesis_hash),
            tip: genesis,
            chain_weight: 0,
            max_cache_size: 100,
            recent_blocks,
            mmr_light: WeightedMMRLight::with_anchor(
                WeightedHash::from_anchor(&anchor_hash),
                100,
            ),
            expected_shard_id,
            hash_sorting_bits,
        }
    }

    /// Create new chain state in pre-genesis state
    ///
    /// Used when genesis block has not been mined yet.
    /// The tip will point to a placeholder block with the anchor hash.
    ///
    /// # Arguments
    /// * `chain_type` - Beacon or Shard
    /// * `chain_id` - 0 for beacon, shard_id + 1 for shards
    /// * `anchor_hash` - Bitcoin anchor hash
    /// * `expected_shard_id` - Expected shard ID (None for beacon chain)
    /// * `hash_sorting_bits` - Number of hash-sorting bits for shard ID derivation
    pub fn new_pre_genesis(
        chain_type: ChainType,
        chain_id: u32,
        anchor_hash: [u8; 32],
        expected_shard_id: Option<u32>,
        hash_sorting_bits: u32,
    ) -> Self {
        use common_types::common::proofs::types::BeaconBlockData;

        // Create placeholder tip pointing to anchor as a Beacon BlockData
        let placeholder_tip = BlockData::Beacon(BeaconBlockData {
            height: 0,
            block_hash: anchor_hash.into(),
            prev_mmr_root: anchor_hash.into(),
            current_mmr_root: anchor_hash.into(),
            version: 1,
            delta: 0,
            difficulty: 0,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        });

        Self {
            chain_type,
            chain_id,
            anchor_hash,
            genesis_hash: None, // Not yet mined
            tip: placeholder_tip,
            chain_weight: 0,
            max_cache_size: 100,
            recent_blocks: HashMap::new(),
            mmr_light: WeightedMMRLight::with_anchor(
                WeightedHash::from_anchor(&anchor_hash),
                100,
            ),
            expected_shard_id,
            hash_sorting_bits,
        }
    }

    /// Set genesis hash after genesis block is mined
    ///
    /// This transitions the chain from pre-genesis to post-genesis state.
    ///
    /// # Arguments
    /// * `genesis` - The mined genesis block (as BlockData)
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(String)` if genesis was already set or validation fails
    pub fn set_genesis(&mut self, genesis: BlockData) -> Result<(), String> {
        // Check if genesis already set
        if self.genesis_hash.is_some() {
            return Err("Genesis already set".to_string());
        }

        // Validate genesis block
        if genesis.height() != 0 {
            return Err(format!("Genesis height must be 0, got {}", genesis.height()));
        }

        if genesis.prev_mmr_root_bytes() != self.anchor_hash {
            return Err(format!(
                "Genesis prev_mmr_root must equal anchor_hash: {} != {}",
                hex::encode(genesis.prev_mmr_root_bytes()),
                hex::encode(self.anchor_hash)
            ));
        }

        let genesis_hash = genesis.block_hash();
        self.genesis_hash = Some(genesis_hash);

        // Update tip
        self.tip = genesis.clone();

        // Add to recent blocks
        self.recent_blocks.insert(0, genesis);

        info!(
            "{}: Genesis set: hash={}",
            self,
            hex::encode(genesis_hash)
        );

        Ok(())
    }
    
    /// Check if genesis has been mined
    pub fn is_genesis_mined(&self) -> bool {
        self.genesis_hash.is_some()
    }
    
    /// Get genesis hash if available
    pub fn genesis_hash(&self) -> Option<[u8; 32]> {
        self.genesis_hash
    }
    
    /// Get anchor hash
    pub fn anchor_hash(&self) -> [u8; 32] {
        self.anchor_hash
    }
    
    /// Validate that a block can be added to this chain
    ///
    /// Checks that the block's prev_mmr_root matches expected values:
    /// - For genesis: prev_mmr_root must equal anchor_hash
    /// - For other blocks: height must follow tip
    pub fn validate_block_for_append(&self, block: &BlockData) -> Result<(), String> {
        if block.height() == 0 {
            // Genesis block validation
            if self.genesis_hash.is_some() {
                return Err("Genesis already exists".to_string());
            }

            if block.prev_mmr_root_bytes() != self.anchor_hash {
                return Err(format!(
                    "Genesis prev_mmr_root must equal anchor: {} != {}",
                    hex::encode(block.prev_mmr_root_bytes()),
                    hex::encode(self.anchor_hash)
                ));
            }
        } else {
            // Regular block validation
            if self.genesis_hash.is_none() {
                return Err("Cannot add block before genesis is set".to_string());
            }

            if block.height() != self.tip.height() + 1 {
                return Err(format!(
                    "Block height {} does not follow tip height {}",
                    block.height(), self.tip.height()
                ));
            }
        }

        Ok(())
    }

    /// Validate shard ID for a block
    ///
    /// If this chain has an expected_shard_id, verify the block belongs
    /// to the correct shard by deriving shard_id from its PoW hash.
    ///
    /// Returns Ok(()) for beacon chains or if shard_id matches.
    /// Returns Err if the block belongs to the wrong shard.
    pub fn validate_shard_id(&self, block: &BlockData) -> Result<(), String> {
        if let Some(expected) = self.expected_shard_id {
            if let Some(derived) = block.derive_shard_id(self.hash_sorting_bits) {
                if derived != expected {
                    return Err(format!(
                        "Shard ID mismatch: block at height {} belongs to shard {} but expected shard {}",
                        block.height(), derived, expected
                    ));
                }
            }
            // If derive_shard_id returns None (e.g. reserved hash pattern),
            // we skip validation — this is acceptable for edge cases.
        }
        Ok(())
    }
    
    /// Get shard ID (for shard chains)
    /// Returns None for beacon chain
    pub fn shard_id(&self) -> Option<u32> {
        match self.chain_type {
            ChainType::Beacon => None,
            ChainType::Shard => {
                if self.chain_id > 0 {
                    Some(self.chain_id - 1)
                } else {
                    None
                }
            }
        }
    }
    
    /// Convert chain_id to ChainId enum for storage operations
    pub fn to_chain_id(&self) -> ChainId {
        match self.chain_type {
            ChainType::Beacon => ChainId::Beacon,
            ChainType::Shard => {
                // chain_id = shard_id + 1, so shard_id = chain_id - 1
                ChainId::Shard(self.chain_id.saturating_sub(1))
            }
        }
    }
    
    /// Get current height
    pub fn height(&self) -> u32 {
        self.tip.height()
    }

    /// Get tip hash
    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip.block_hash()
    }

    /// Get MMR root as `WeightedHash` (preserves rBits / cumulative difficulty).
    pub fn mmr_root(&self) -> WeightedHash {
        self.tip.mmr_root()
    }

    /// Get MMR root as raw `[u8; 32]` bytes.
    pub fn mmr_root_bytes(&self) -> [u8; 32] {
        self.tip.mmr_root_bytes()
    }
}

impl std::fmt::Display for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.chain_type {
            ChainType::Beacon => write!(f, "Beacon"),
            ChainType::Shard => {
                if let Some(shard_id) = self.shard_id() {
                    write!(f, "Shard({})", shard_id)
                } else {
                    write!(f, "Shard(?)")
                }
            }
        }
    }
}

/// Generic chain handler - manages state for any blockchain
pub struct ChainHandler {
    /// Current chain state
    state: ChainState,
    
    /// Persistent storage
    storage: Box<dyn LightClientStorage>,
}

impl ChainHandler {
    /// Create new chain handler with genesis block
    ///
    /// # Arguments
    /// * `chain_type` - Beacon or Shard
    /// * `chain_id` - 0 for beacon, shard_id + 1 for shards
    /// * `anchor_hash` - Bitcoin anchor hash
    /// * `genesis` - Genesis block (as BlockData)
    /// * `storage` - Storage backend
    /// * `expected_shard_id` - Expected shard ID (None for beacon)
    /// * `hash_sorting_bits` - Hash-sorting bits for shard ID derivation
    pub fn new(
        chain_type: ChainType,
        chain_id: u32,
        anchor_hash: [u8; 32],
        genesis: BlockData,
        storage: Box<dyn LightClientStorage>,
        expected_shard_id: Option<u32>,
        hash_sorting_bits: u32,
    ) -> Self {
        let state = ChainState::new(
            chain_type, chain_id, anchor_hash, genesis,
            expected_shard_id, hash_sorting_bits,
        );

        info!("Created chain handler for {}", state);

        Self {
            state,
            storage,
        }
    }

    /// Create new chain handler in pre-genesis state
    ///
    /// Used when genesis block has not been mined yet.
    /// Call `set_genesis()` later when genesis is mined.
    ///
    /// # Arguments
    /// * `chain_type` - Beacon or Shard
    /// * `chain_id` - 0 for beacon, shard_id + 1 for shards
    /// * `anchor_hash` - Bitcoin anchor hash
    /// * `storage` - Storage backend
    /// * `expected_shard_id` - Expected shard ID (None for beacon)
    /// * `hash_sorting_bits` - Hash-sorting bits for shard ID derivation
    pub fn new_pre_genesis(
        chain_type: ChainType,
        chain_id: u32,
        anchor_hash: [u8; 32],
        storage: Box<dyn LightClientStorage>,
        expected_shard_id: Option<u32>,
        hash_sorting_bits: u32,
    ) -> Self {
        let state = ChainState::new_pre_genesis(
            chain_type, chain_id, anchor_hash,
            expected_shard_id, hash_sorting_bits,
        );

        info!("Created chain handler for {} (pre-genesis)", state);

        Self {
            state,
            storage,
        }
    }

    /// Set genesis block after mining
    ///
    /// Transitions from pre-genesis to post-genesis state.
    ///
    /// # Arguments
    /// * `genesis` - Mined genesis block (as BlockData)
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(String)` if validation fails
    pub fn set_genesis(&mut self, genesis: BlockData) -> Result<(), String> {
        self.state.set_genesis(genesis)?;

        // Persist state
        let chain_id = self.state.to_chain_id();
        self.storage.save_state(chain_id, &self.state)?;

        Ok(())
    }
    
    /// Get current chain state
    pub fn state(&self) -> &ChainState {
        &self.state
    }
    
    /// Get chain type
    pub fn chain_type(&self) -> ChainType {
        self.state.chain_type
    }
    
    /// Get chain ID
    pub fn chain_id(&self) -> u32 {
        self.state.chain_id
    }
    
    /// Verify a peer-supplied chain summary's proof and shard-id validity,
    /// WITHOUT mutating local state or comparing weight against the current
    /// tip. Extracted from `apply_chain_summary` (MNT-3,
    /// `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`) so multi-peer
    /// reconciliation can independently verify every candidate response
    /// before picking the max-weight winner — a response can't be trusted
    /// just because it answered first or claims a higher weight than
    /// another; both weight *and* proof have to check out.
    pub fn verify_chain_summary(&self, summary: &MMRChainSummary) -> Result<(), String> {
        // Check if genesis is set (can't sync before genesis)
        if !self.state.is_genesis_mined() {
            return Err("Cannot verify chain summary before genesis is mined".to_string());
        }

        // Get genesis block for verification (already stored as BlockData)
        let genesis_block = self.state.recent_blocks.get(&0)
            .ok_or("Genesis block not found in cache")?;

        // Verify the batch proof using WeightedMMRBatchProof's own verifier
        let anchor = genesis_block.prev_mmr_root_bytes();
        if !summary.recent_blocks_proof.verify_with_anchor(anchor) {
            return Err("Invalid chain summary proof".to_string());
        }

        debug!("{}: Chain summary proof verified", self.state);
        debug!("{}: Calculated {} peaks, leaf_count: {}",
            self.state,
            summary.recent_blocks_proof.peaks.len(),
            summary.recent_blocks_proof.leaf_count);

        // Validate shard IDs for all blocks in the proof
        for block in &summary.recent_blocks {
            self.state.validate_shard_id(block)?;
        }
        // Also validate the tip block
        self.state.validate_shard_id(&summary.tip_block)?;

        Ok(())
    }

    /// Apply chain summary from peer
    pub fn apply_chain_summary(
        &mut self,
        summary: MMRChainSummary,
    ) -> Result<bool, String> {
        info!("{}: Applying chain summary: height {}, weight {}",
            self.state,
            summary.tip_block.height(),
            summary.chain_weight);

        self.verify_chain_summary(&summary)?;

        // Check if this is a heavier chain
        if summary.chain_weight <= self.state.chain_weight {
            info!("{}: Peer chain not heavier, ignoring", self.state);
            return Ok(false);
        }

        info!("{}: Peer chain is heavier: {} > {}",
            self.state,
            summary.chain_weight,
            self.state.chain_weight);

        // Extract peaks and leaf_count from the weighted proof (preserve rBits)
        let new_peaks = summary.recent_blocks_proof.peaks.clone();
        let new_leaf_count = summary.recent_blocks_proof.leaf_count;

        let blocks: Vec<(WeightedHash, u32)> = summary.recent_blocks
            .iter()
            .map(|b| (b.block_hash_weighted(), b.height()))
            .collect();

        self.state.mmr_light.update_from_verified_proof(
            new_peaks,
            new_leaf_count,
            &blocks,
        );

        // Store tip directly as BlockData (no conversion needed)
        self.state.tip = summary.tip_block;
        self.state.chain_weight = summary.chain_weight;

        // Update recent blocks cache from recent_blocks — store BlockData directly
        for block in summary.recent_blocks {
            let height = block.height();
            self.state.recent_blocks.insert(height, block);
        }

        // Trim cache if too large
        self.trim_cache();

        // Persist state
        let chain_id = self.state.to_chain_id();
        self.storage.save_state(chain_id, &self.state)?;

        info!("{}: Chain updated to height {}",
            self.state,
            self.state.height());
        Ok(true)
    }
    
    /// Apply range proof bundle to sync missing blocks.
    pub fn apply_range_proof(
        &mut self,
        bundle: MMRRangeProofBundle,
    ) -> Result<(), String> {
        // Check if genesis is set
        if !self.state.is_genesis_mined() {
            return Err("Cannot apply range proof before genesis is mined".to_string());
        }

        let MMRRangeProofBundle { proof, blocks, target_block } = bundle;

        info!(
            "{}: Applying range proof: blocks {}..{} ({} leaves)",
            self.state,
            proof.start,
            proof.end,
            proof.leaves.len(),
        );

        let genesis_block = self.state.recent_blocks.get(&0)
            .ok_or("Genesis block not found in cache")?
            .clone();

        let anchor = genesis_block.prev_mmr_root_bytes();
        if !proof.verify_with_anchor(anchor) {
            return Err("Invalid range proof".to_string());
        }

        debug!("{}: Range proof verified", self.state);

        let expected_len = (proof.end - proof.start) as usize;
        if blocks.len() != expected_len {
            return Err(format!(
                "Block payload count {} != proof range size {}",
                blocks.len(),
                expected_len,
            ));
        }
        if proof.leaves.len() != expected_len {
            return Err(format!(
                "Proof leaf count {} != range size {}",
                proof.leaves.len(),
                expected_len,
            ));
        }

        let target_height = proof.end.saturating_sub(1);
        if target_block.height() != target_height {
            return Err(format!(
                "Target block height {} != expected {}",
                target_block.height(),
                target_height,
            ));
        }

        for (i, block) in blocks.iter().enumerate() {
            let height = proof.start + i as u32;
            self.state.validate_shard_id(block)?;
            if block.height() != height {
                return Err(format!(
                    "Block at index {} has height {} (expected {})",
                    i,
                    block.height(),
                    height,
                ));
            }
            if block.block_hash_weighted() != proof.leaves[i] {
                return Err(format!(
                    "Block hash at height {} does not match proof leaf",
                    height,
                ));
            }
        }
        self.state.validate_shard_id(&target_block)?;

        for i in 1..blocks.len() {
            if blocks[i].height() != blocks[i - 1].height() + 1 {
                return Err(format!(
                    "Block {} does not follow previous block (heights {} -> {})",
                    blocks[i].height(),
                    blocks[i - 1].height(),
                    blocks[i].height(),
                ));
            }
        }

        let mmr_blocks: Vec<(WeightedHash, u32)> = blocks
            .iter()
            .map(|b| (b.block_hash_weighted(), b.height()))
            .collect();

        if proof.leaf_count > self.state.mmr_light.leaf_count() {
            self.state.mmr_light.update_from_verified_proof(
                proof.peaks.clone(),
                proof.leaf_count,
                &mmr_blocks,
            );
        }

        for block in blocks {
            self.state.recent_blocks.insert(block.height(), block);
        }

        if target_height >= self.state.height() {
            self.state.tip = target_block;
        }

        self.trim_cache();

        let chain_id = self.state.to_chain_id();
        self.storage.save_state(chain_id, &self.state)?;

        info!(
            "{}: Applied {} blocks from range proof",
            self.state,
            expected_len,
        );
        Ok(())
    }
    
    /// Verify transaction is included in a block
    pub fn verify_transaction_in_block(
        &self,
        tx_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        block_height: u32,
    ) -> Result<bool, String> {
        // Get block from cache
        let block = self.state.recent_blocks.get(&block_height)
            .ok_or_else(|| format!("Block {} not in cache", block_height))?;

        // Verify merkle proof against block's merkle_root
        let mut current = tx_hash;
        for sibling in merkle_proof {
            current = hash_pair(&current, sibling);
        }

        let block_merkle_root = block.merkle_root();
        if current == block_merkle_root {
            debug!("{}: Transaction {} verified in block {}",
                   self.state,
                   hex::encode(tx_hash),
                   block_height);
            Ok(true)
        } else {
            debug!("{}: Transaction verification failed", self.state);
            Ok(false)
        }
    }

    /// Get block by height from cache
    pub fn get_block(&self, height: u32) -> Option<&BlockData> {
        self.state.recent_blocks.get(&height)
    }

    /// Check if we have a block at height
    pub fn has_block(&self, height: u32) -> bool {
        self.state.recent_blocks.contains_key(&height)
    }

    /// Get blocks in height range
    pub fn get_blocks_range(&self, start: u32, end: u32) -> Vec<BlockData> {
        (start..=end)
            .filter_map(|h| self.state.recent_blocks.get(&h).cloned())
            .collect()
    }
    
    /// Revert chain to specific height (reorg / rollback scaffolding; not yet wired to callers).
    #[allow(dead_code)]
    fn revert_to_height(&mut self, height: u32) -> Result<(), String> {
        info!("{}: Reverting chain to height {}", self.state, height);

        // Remove all blocks above height
        self.state.recent_blocks.retain(|h, _| *h <= height);

        // Update tip to block at height
        let new_tip = self.state.recent_blocks.get(&height)
            .ok_or_else(|| format!("Block {} not found for revert", height))?
            .clone();

        self.state.tip = new_tip;

        // Recalculate chain weight
        self.state.chain_weight = self.state.recent_blocks.values()
            .map(|b| b.difficulty() as u128)
            .sum();

        // Persist state
        let chain_id = self.state.to_chain_id();
        self.storage.save_state(chain_id, &self.state)?;

        Ok(())
    }
    
    /// Trim cache to max size, keeping most recent blocks
    fn trim_cache(&mut self) {
        if self.state.recent_blocks.len() <= self.state.max_cache_size {
            return;
        }
        
        let tip_height = self.state.height();
        let cutoff = if tip_height > self.state.max_cache_size as u32 {
            tip_height - self.state.max_cache_size as u32
        } else {
            0
        };
        
        self.state.recent_blocks.retain(|h, _| *h >= cutoff);
        
        debug!("{}: Trimmed cache to {} blocks", 
               self.state,
               self.state.recent_blocks.len());
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::proofs::types::BeaconBlockData;
    use crate::mmr_client::storage::InMemoryStorage;

    /// Helper to create a test beacon BlockData
    fn test_beacon_block(height: u32, block_hash: [u8; 32], prev_mmr_root: [u8; 32], difficulty: u64) -> BlockData {
        let bitcoin_anchor_timestamp = 1_704_067_200u64;
        let test_timestamp = 1000000u64;
        let delta = ((test_timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256) as i32;
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash: block_hash.into(),
            prev_mmr_root: prev_mmr_root.into(),
            current_mmr_root: block_hash.into(), // use block_hash as stand-in
            version: 1,
            delta,
            difficulty,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        })
    }

    #[test]
    fn test_chain_state_pre_genesis() {
        let anchor_hash = [1u8; 32];
        let state = ChainState::new_pre_genesis(ChainType::Beacon, 0, anchor_hash, None, 0);

        assert!(!state.is_genesis_mined());
        assert_eq!(state.genesis_hash(), None);
        assert_eq!(state.anchor_hash(), anchor_hash);
        assert_eq!(state.tip.block_hash(), anchor_hash);
    }

    #[test]
    fn test_chain_state_set_genesis() {
        let anchor_hash = [1u8; 32];
        let mut state = ChainState::new_pre_genesis(ChainType::Beacon, 0, anchor_hash, None, 0);

        let genesis = test_beacon_block(0, [2u8; 32], anchor_hash, 1000);

        assert!(state.set_genesis(genesis.clone()).is_ok());
        assert!(state.is_genesis_mined());
        assert_eq!(state.genesis_hash(), Some([2u8; 32]));
        assert_eq!(state.tip.block_hash(), genesis.block_hash());
    }

    #[test]
    fn test_chain_state_genesis_validation() {
        let anchor_hash = [1u8; 32];
        let mut state = ChainState::new_pre_genesis(ChainType::Beacon, 0, anchor_hash, None, 0);

        // Invalid: wrong prev_mmr_root
        let bad_genesis = test_beacon_block(0, [2u8; 32], [99u8; 32], 1000);

        assert!(state.set_genesis(bad_genesis).is_err());
    }

    #[test]
    fn test_chain_state_double_genesis() {
        let anchor_hash = [1u8; 32];
        let mut state = ChainState::new_pre_genesis(ChainType::Beacon, 0, anchor_hash, None, 0);

        let genesis = test_beacon_block(0, [2u8; 32], anchor_hash, 1000);

        assert!(state.set_genesis(genesis.clone()).is_ok());

        // Try to set again - should fail
        assert!(state.set_genesis(genesis).is_err());
    }

    #[test]
    fn test_chain_handler_with_anchor() {
        let anchor_hash = [1u8; 32];
        let genesis = test_beacon_block(0, [2u8; 32], anchor_hash, 1000);

        let storage = Box::new(InMemoryStorage::new());
        let handler = ChainHandler::new(
            ChainType::Beacon,
            0,
            anchor_hash,
            genesis,
            storage,
            None, // beacon: no expected_shard_id
            0,    // hash_sorting_bits irrelevant for beacon
        );

        assert_eq!(handler.state().anchor_hash(), anchor_hash);
        assert_eq!(handler.state().genesis_hash(), Some([2u8; 32]));
        assert_eq!(handler.state().height(), 0);
    }

    #[test]
    fn test_shard_chain_handler() {
        let anchor_hash = [1u8; 32];
        let genesis = test_beacon_block(0, [2u8; 32], anchor_hash, 500);

        let storage = Box::new(InMemoryStorage::new());
        // Shard 5: chain_id = 5 + 1 = 6
        let handler = ChainHandler::new(
            ChainType::Shard,
            6,
            anchor_hash,
            genesis,
            storage,
            Some(5), // expected_shard_id
            8,       // k_bits
        );

        assert_eq!(handler.chain_type(), ChainType::Shard);
        assert_eq!(handler.chain_id(), 6);
        assert_eq!(handler.state().shard_id(), Some(5));
        assert_eq!(handler.state().to_chain_id(), ChainId::Shard(5));
        assert_eq!(format!("{}", handler.state()), "Shard(5)");
        assert_eq!(handler.state().anchor_hash(), anchor_hash);
        assert_eq!(handler.state().expected_shard_id, Some(5));
        assert_eq!(handler.state().hash_sorting_bits, 8);
    }
}