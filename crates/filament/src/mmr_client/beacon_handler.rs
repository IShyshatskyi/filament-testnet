// ============================================================================
// src/mmr_client/beacon_handler.rs - Beacon Chain Handler
// ============================================================================

//! Beacon Chain Handler
//!
//! Specialized handler for the beacon chain with beacon-specific features:
//! - Epoch tracking
//! - Consensus parameter updates

use log::info;

//use network_common::common::proofs::types::BlockData;
use network_common::common::proofs::{MMRChainSummary,BlockData};
use crate::mmr_client::chain_handler::{ChainHandler, ChainState, ChainType};
use crate::mmr_client::storage::LightClientStorage;

/// Beacon chain specific handler
pub struct BeaconChainHandler {
    /// Base chain handler
    handler: ChainHandler,
    
    /// Current epoch (for DAA and other periodic updates)
    current_epoch: u64,

    /// Governance epoch length of this network, from its genesis (never a process global).
    epoch_length: u32,
    
}


pub struct ShardParameters {
    pub epoch: u64,
    pub beacon_height: u32,
    pub beacon_weight: u128,
}

impl BeaconChainHandler {
    /// Create new beacon chain handler
    pub fn new(
        genesis: BlockData,
        storage: Box<dyn LightClientStorage>,
    ) -> Self {
        // Beacon chain always has chain_id = 0
        // Genesis prev_mmr_root IS the anchor
        let anchor_hash = genesis.prev_mmr_root_bytes();
        let handler = ChainHandler::new(
            ChainType::Beacon, 0, anchor_hash, genesis, storage,
            None, // beacon: no expected_shard_id
            0,    // hash_sorting_bits irrelevant for beacon
        );

        Self {
            handler,
            current_epoch: 0,
            epoch_length: network_common::common::expand_voting::DEFAULT_EPOCH_LENGTH,
        }
    }

    /// Set the network's governance epoch length (from its genesis `shard_expansion.epoch_length`).
    pub fn set_epoch_length(&mut self, epoch_length: u32) {
        self.epoch_length = epoch_length.max(1);
    }
    
    /// Get current chain state
    pub fn state(&self) -> &ChainState {
        self.handler.state()
    }
    
    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    
    /// MNT-3: verify a peer-supplied chain summary's proof and shard-id
    /// validity WITHOUT applying it — passthrough to
    /// `ChainHandler::verify_chain_summary`. Used by multi-peer
    /// reconciliation (`MultiChainClient::reconcile_beacon_summaries`) to
    /// independently check each candidate response before picking the
    /// max-weight winner. See the multi-node trust design.
    pub fn verify_chain_summary(&self, summary: &MMRChainSummary) -> Result<(), String> {
        self.handler.verify_chain_summary(summary)
    }

    /// Sync from chain summary
    pub async fn sync_from_summary(
        &mut self,
        summary: MMRChainSummary,
    ) -> Result<bool, String> {
        let updated = self.handler.apply_chain_summary(summary)?;
        
        if updated {
            // Update epoch if we crossed a boundary
            self.update_epoch();
        }
        
        Ok(updated)
    }
    
    /// Auto-sync from network (to be implemented with network layer)
    pub async fn auto_sync(&mut self) -> Result<bool, String> {
        // In real implementation, would fetch summary from network
        info!("Beacon: Auto-sync not yet implemented");
        Ok(false)
    }
    
    /// Verify transaction in beacon chain
    pub fn verify_transaction_in_block(
        &self,
        tx_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        block_height: u32,
    ) -> Result<bool, String> {
        self.handler.verify_transaction_in_block(tx_hash, merkle_proof, block_height)
    }
    
    /// Update epoch based on current height
    fn update_epoch(&mut self) {
        let height = self.handler.state().height();
        // The governance epoch length is a genesis parameter of this network,
        // set by the client at init (`set_epoch_length`); not a process global.
        let epoch_len = self.epoch_length.max(1) as u64;
        let new_epoch = (height as u64) / epoch_len;
        
        if new_epoch != self.current_epoch {
            info!("Beacon: Epoch transition {} -> {}", self.current_epoch, new_epoch);
            self.current_epoch = new_epoch;
        }
    }
    
    /// Get shard parameters for current epoch
    pub fn get_shard_parameters(&self) -> ShardParameters {
        ShardParameters {
            epoch: self.current_epoch,
            beacon_height: self.handler.state().height(),
            beacon_weight: self.handler.state().chain_weight,
        }
    }
}

/*
===============================================================================
VERIFICATION VS PROVING SEPARATION
===============================================================================

This module (beacon_handler.rs) is part of mmr_client, which is for 
VERIFICATION only.

What beacon_handler does:
- Accepts proofs from full nodes
- Verifies proofs using mmr_client::verification functions
- Manages verified state

What beacon_handler does NOT do:
- Generate proofs (that's in beacon_chain module)
- Run full MMR operations (that's in beacon_chain)
- Serve as a full node

For proof GENERATION, see:
- beacon_chain.rs: Full node proof generation
- mmr_light_client.rs: Helper functions for proving (deprecated)

This clean separation means:
- Wallets can use mmr_client without full node code
- No circular dependencies
- Clear responsibility boundaries

===============================================================================
*/