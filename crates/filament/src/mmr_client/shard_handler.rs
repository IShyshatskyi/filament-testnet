// ============================================================================
// src/mmr_client/shard_handler.rs - Shard Chain Handler
// ============================================================================

//! Shard Chain Handler
//!
//! Specialized handler for shard chains with shard-specific features:
//! - Shard ID tracking
//! - Cross-shard transaction verification
//! - Beacon chain coordination

use log::{info, debug};
use std::collections::HashMap;

use common_types::common::proofs::{MMRChainSummary, BlockData};
use crate::mmr_client::chain_handler::{ChainHandler, ChainState, ChainType};
use crate::mmr_client::storage::LightClientStorage;

/// Cross-shard transaction info
#[derive(Debug, Clone)]
pub struct CrossShardTxInfo {
    pub tx_hash: [u8; 32],
    pub source_shard: u32,
    pub dest_shard: u32,
    pub status: CrossShardStatus,
}

/// Cross-shard transaction status
#[derive(Debug, Clone, PartialEq)]
pub enum CrossShardStatus {
    Initiated,
    SourceConfirmed,
    DestinationPending,
    Completed,
    Failed,
}

/// Shard chain specific handler
pub struct ShardChainHandler {
    /// Base chain handler
    handler: ChainHandler,
    
    /// Shard identifier
    shard_id: u32,
    
    /// Current epoch (synced from beacon)
    current_epoch: u32,
    
    /// Blocks per epoch
    blocks_per_epoch: u32,
    
    /// Cross-shard transaction cache
    cross_shard_tx_cache: HashMap<[u8; 32], CrossShardTxInfo>,
}

impl ShardChainHandler {
    /// Create new shard chain handler
    ///
    /// # Arguments
    /// * `shard_id` - Shard identifier (0-based)
    /// * `genesis` - Genesis block (as BlockData)
    /// * `storage` - Storage backend
    /// * `hash_sorting_bits` - Number of hash-sorting bits for shard ID derivation
    pub fn new(
        shard_id: u32,
        genesis: BlockData,
        storage: Box<dyn LightClientStorage>,
        hash_sorting_bits: u32,
    ) -> Self {
        // chain_id = shard_id + 1
        let chain_id = shard_id + 1;
        let anchor_hash = genesis.prev_mmr_root_bytes();
        let handler = ChainHandler::new(
            ChainType::Shard, chain_id, anchor_hash, genesis, storage,
            Some(shard_id), // expected_shard_id
            hash_sorting_bits,
        );

        info!("Created shard chain handler for shard {}", shard_id);

        Self {
            handler,
            shard_id,
            current_epoch: 0,
            blocks_per_epoch: 1008,
            cross_shard_tx_cache: HashMap::new(),
        }
    }
    
    /// Get current chain state
    pub fn state(&self) -> &ChainState {
        self.handler.state()
    }
    
    /// Get shard ID
    pub fn shard_id(&self) -> u32 {
        self.shard_id
    }
    
    /// MNT-3: verify a peer-supplied chain summary's proof and shard-id
    /// validity WITHOUT applying it — passthrough to
    /// `ChainHandler::verify_chain_summary`. Used by multi-peer
    /// reconciliation (`MultiChainClient::reconcile_shard_summaries`) to
    /// independently check each candidate response before picking the
    /// max-weight winner. See `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
    pub fn verify_chain_summary(&self, summary: &MMRChainSummary) -> Result<(), String> {
        self.handler.verify_chain_summary(summary)
    }

    /// Sync from chain summary
    pub fn sync_from_summary(
        &mut self,
        summary: MMRChainSummary,
    ) -> Result<bool, String> {
        let updated = self.handler.apply_chain_summary(summary)?;
        
        if updated {
            self.update_epoch();
        }
        
        Ok(updated)
    }
    
    /// Verify transaction in this shard
    pub fn verify_transaction_in_block(
        &self,
        tx_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        block_height: u32,
    ) -> Result<bool, String> {
        self.handler.verify_transaction_in_block(tx_hash, merkle_proof, block_height)
    }
    
    /// Track a cross-shard transaction
    pub fn track_cross_shard_tx(
        &mut self,
        tx_hash: [u8; 32],
        dest_shard: u32,
    ) {
        let info = CrossShardTxInfo {
            tx_hash,
            source_shard: self.shard_id,
            dest_shard,
            status: CrossShardStatus::Initiated,
        };
        
        self.cross_shard_tx_cache.insert(tx_hash, info);
        
        debug!(
            "Shard {}: Tracking cross-shard tx {} to shard {}",
            self.shard_id,
            hex::encode(tx_hash),
            dest_shard
        );
    }
    
    /// Get cross-shard transaction status
    pub fn get_cross_shard_status(&self, tx_hash: &[u8; 32]) -> Option<CrossShardStatus> {
        self.cross_shard_tx_cache
            .get(tx_hash)
            .map(|info| info.status.clone())
    }
    
    /// Update epoch from beacon chain
    pub fn update_from_beacon(&mut self, beacon_epoch: u32) {
        if beacon_epoch != self.current_epoch {
            info!(
                "Shard {}: Epoch update from beacon: {} -> {}",
                self.shard_id,
                self.current_epoch,
                beacon_epoch
            );
            self.current_epoch = beacon_epoch;
        }
    }
    
    /// Update epoch based on height
    fn update_epoch(&mut self) {
        let height = self.handler.state().height();
        let new_epoch = height / self.blocks_per_epoch;
        
        if new_epoch != self.current_epoch {
            info!(
                "Shard {}: Epoch transition {} -> {}",
                self.shard_id,
                self.current_epoch,
                new_epoch
            );
            self.current_epoch = new_epoch;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::proofs::types::BeaconBlockData;
    use common_types::common::crypto::weighted_hash::WeightedHash;
    use crate::mmr_client::storage::InMemoryStorage;

    #[test]
    fn test_shard_handler_creation() {
        // Use a Beacon BlockData as placeholder genesis for testing
        let bitcoin_anchor_timestamp = 1_704_067_200u64;
        let test_timestamp = 1000000u64;
        let delta = ((test_timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256) as i32;
        let genesis = BlockData::Beacon(BeaconBlockData {
            height: 0,
            block_hash: WeightedHash::from([2u8; 32]),
            prev_mmr_root: [0u8; 32].into(),
            current_mmr_root: [0u8; 32].into(),
            version: 1,
            delta,
            difficulty: 500,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        });

        let storage = Box::new(InMemoryStorage::new());
        let handler = ShardChainHandler::new(42, genesis, storage, 8);

        assert_eq!(handler.shard_id(), 42);
        assert_eq!(handler.state().height(), 0);
        assert_eq!(handler.state().chain_id, 43); // shard_id + 1
        assert_eq!(handler.state().shard_id(), Some(42));
        assert_eq!(handler.state().expected_shard_id, Some(42));
        assert_eq!(handler.state().hash_sorting_bits, 8);
    }
}