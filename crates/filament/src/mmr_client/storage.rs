// ============================================================================
// src/mmr_client/storage.rs - UPDATED WITH CHAINID NAMESPACING
// ============================================================================

//! Storage backends for light client state
//!
//! **CRITICAL UPDATE**: Added ChainId namespacing to prevent collisions
//! between beacon and shard chains.
//!
//! Provides pluggable storage interface with multiple implementations:
//! - InMemoryStorage: For testing
//! - FileStorage: Simple file-based persistence
//! - SqliteStorage: Production database storage (to be implemented)

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

use common_types::common::proofs::types::BlockData;
use crate::mmr_client::chain_handler::ChainState;

// ============================================================================
// CHAIN IDENTIFIER
// ============================================================================

/// Chain identifier for namespacing storage operations
///
/// Prevents collisions when storing multiple chains:
/// - Beacon chain: ChainId::Beacon
/// - Shard chain 5: ChainId::Shard(5)
///
/// Each chain has independent storage namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    /// Beacon chain (always single instance)
    Beacon,
    
    /// Shard chain (identified by shard_id)
    Shard(u32),
}

impl ChainId {
    /// Convert to string for file paths and database keys
    pub fn to_string(&self) -> String {
        match self {
            ChainId::Beacon => "beacon".to_string(),
            ChainId::Shard(id) => format!("shard_{}", id),
        }
    }
    
    /// Parse from string (inverse of to_string)
    pub fn from_string(s: &str) -> Result<Self, String> {
        if s == "beacon" {
            Ok(ChainId::Beacon)
        } else if let Some(id_str) = s.strip_prefix("shard_") {
            let id = id_str.parse::<u32>()
                .map_err(|e| format!("Invalid shard ID: {}", e))?;
            Ok(ChainId::Shard(id))
        } else {
            Err(format!("Invalid chain ID: {}", s))
        }
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// ============================================================================
// STORAGE TRAIT (UPDATED WITH CHAIN NAMESPACING)
// ============================================================================

/// Storage interface for light client
///
/// **IMPORTANT**: All operations now require ChainId parameter to prevent
/// collisions between beacon and shard chains.
pub trait LightClientStorage: Send + Sync {
    /// Save current chain state (scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    /// * `state` - Chain state to save
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) 
        -> Result<(), String>;
    
    /// Load chain state (scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    ///
    /// # Returns
    /// Chain state if found, error otherwise
    fn load_state(&self, chain_id: ChainId) 
        -> Result<ChainState, String>;
    
    /// Save individual block (scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    /// * `block` - Block to save
    fn save_block(&mut self, chain_id: ChainId, block: &BlockData) 
        -> Result<(), String>;
    
    /// Load block by height (scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    /// * `height` - Block height
    ///
    /// # Returns
    /// Block if found, error otherwise
    fn load_block(&self, chain_id: ChainId, height: u32) 
        -> Result<BlockData, String>;
    
    /// Load multiple blocks in range (scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    /// * `start` - Start height (inclusive)
    /// * `end` - End height (inclusive)
    ///
    /// # Returns
    /// Vector of blocks found in range
    fn load_blocks_range(&self, chain_id: ChainId, start: u32, end: u32) 
        -> Result<Vec<BlockData>, String>;
    
    /// Delete blocks above height (for reorg, scoped by chain_id)
    ///
    /// # Arguments
    /// * `chain_id` - Identifies which chain (beacon or shard)
    /// * `height` - Delete all blocks with height > this
    fn delete_blocks_above(&mut self, chain_id: ChainId, height: u32) 
        -> Result<(), String>;
    
    /// Get storage statistics (across all chains)
    fn stats(&self) -> StorageStats;
    
    /// Get statistics for specific chain
    fn chain_stats(&self, chain_id: ChainId) -> ChainStorageStats;
}

/// Storage statistics (across all chains)
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_blocks_stored: usize,
    pub total_storage_bytes: usize,
    pub last_update: u64,
    pub chains_count: usize,
}

/// Storage statistics for a single chain
#[derive(Debug, Clone)]
pub struct ChainStorageStats {
    pub chain_id: ChainId,
    pub blocks_stored: usize,
    pub storage_bytes: usize,
    pub tip_height: u32,
}

// ============================================================================
// IN-MEMORY STORAGE (UPDATED WITH NAMESPACING)
// ============================================================================

pub struct InMemoryStorage {
    /// Chain states: ChainId -> ChainState
    states: HashMap<ChainId, ChainState>,
    
    /// Blocks: (ChainId, height) -> BlockData
    blocks: HashMap<(ChainId, u32), BlockData>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            blocks: HashMap::new(),
        }
    }
}

impl LightClientStorage for InMemoryStorage {
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) 
        -> Result<(), String> 
    {
        self.states.insert(chain_id, state.clone());
        Ok(())
    }
    
    fn load_state(&self, chain_id: ChainId) 
        -> Result<ChainState, String> 
    {
        self.states.get(&chain_id)
            .cloned()
            .ok_or_else(|| format!("No state saved for {}", chain_id))
    }
    
    fn save_block(&mut self, chain_id: ChainId, block: &BlockData) 
        -> Result<(), String> 
    {
        self.blocks.insert((chain_id, block.height()), block.clone());
        Ok(())
    }

    fn load_block(&self, chain_id: ChainId, height: u32)
        -> Result<BlockData, String>
    {
        self.blocks.get(&(chain_id, height))
            .cloned()
            .ok_or_else(|| format!("Block {} not found for {}", height, chain_id))
    }
    
    fn load_blocks_range(&self, chain_id: ChainId, start: u32, end: u32) 
        -> Result<Vec<BlockData>, String> 
    {
        let mut blocks = Vec::new();
        for h in start..=end {
            if let Some(block) = self.blocks.get(&(chain_id, h)) {
                blocks.push(block.clone());
            }
        }
        Ok(blocks)
    }
    
    fn delete_blocks_above(&mut self, chain_id: ChainId, height: u32) 
        -> Result<(), String> 
    {
        self.blocks.retain(|(cid, h), _| {
            *cid != chain_id || *h <= height
        });
        Ok(())
    }
    
    fn stats(&self) -> StorageStats {
        let chains_count = self.states.len();
        let total_blocks = self.blocks.len();
        let total_bytes = total_blocks * 256; // Rough estimate
        
        StorageStats {
            total_blocks_stored: total_blocks,
            total_storage_bytes: total_bytes,
            last_update: 0,
            chains_count,
        }
    }
    
    fn chain_stats(&self, chain_id: ChainId) -> ChainStorageStats {
        let blocks_stored = self.blocks.keys()
            .filter(|(cid, _)| *cid == chain_id)
            .count();
        
        let tip_height = self.states.get(&chain_id)
            .map(|s| s.height())
            .unwrap_or(0);
        
        ChainStorageStats {
            chain_id,
            blocks_stored,
            storage_bytes: blocks_stored * 256,
            tip_height,
        }
    }
}

// ============================================================================
// FILE STORAGE (UPDATED WITH NAMESPACING)
// ============================================================================

pub struct FileStorage {
    base_path: PathBuf,
    blocks: HashMap<(ChainId, u32), BlockData>,
}

impl FileStorage {
    pub fn new(base_path: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&base_path)
            .map_err(|e| format!("Failed to create storage directory: {}", e))?;
        
        Ok(Self {
            base_path,
            blocks: HashMap::new(),
        })
    }
    
    /// Get directory for specific chain
    fn chain_dir(&self, chain_id: ChainId) -> PathBuf {
        self.base_path.join(chain_id.to_string())
    }
    
    /// Get state file path for chain
    fn state_file(&self, chain_id: ChainId) -> PathBuf {
        self.chain_dir(chain_id).join("state.json")
    }
    
    /// Get block file path for chain
    fn block_file(&self, chain_id: ChainId, height: u32) -> PathBuf {
        self.chain_dir(chain_id).join(format!("block_{:08}.json", height))
    }
}

impl LightClientStorage for FileStorage {
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) 
        -> Result<(), String> 
    {
        // Create chain directory
        let chain_dir = self.chain_dir(chain_id);
        std::fs::create_dir_all(&chain_dir)
            .map_err(|e| format!("Failed to create chain directory: {}", e))?;
        
        // Serialize state
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("Serialization failed: {}", e))?;
        
        // Write to file
        std::fs::write(self.state_file(chain_id), json)
            .map_err(|e| format!("Write failed: {}", e))?;
        
        Ok(())
    }
    
    fn load_state(&self, chain_id: ChainId) 
        -> Result<ChainState, String> 
    {
        let json = std::fs::read_to_string(self.state_file(chain_id))
            .map_err(|e| format!("Read failed for {}: {}", chain_id, e))?;
        
        serde_json::from_str(&json)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
    
    fn save_block(&mut self, chain_id: ChainId, block: &BlockData) 
        -> Result<(), String> 
    {
        // Create chain directory
        let chain_dir = self.chain_dir(chain_id);
        std::fs::create_dir_all(&chain_dir)
            .map_err(|e| format!("Failed to create chain directory: {}", e))?;
        
        // Serialize block
        let json = serde_json::to_string_pretty(block)
            .map_err(|e| format!("Serialization failed: {}", e))?;
        
        // Write to file
        std::fs::write(self.block_file(chain_id, block.height()), json)
            .map_err(|e| format!("Write failed: {}", e))?;

        // Cache in memory
        self.blocks.insert((chain_id, block.height()), block.clone());
        Ok(())
    }
    
    fn load_block(&self, chain_id: ChainId, height: u32) 
        -> Result<BlockData, String> 
    {
        // Check cache first
        if let Some(block) = self.blocks.get(&(chain_id, height)) {
            return Ok(block.clone());
        }
        
        // Load from file
        let json = std::fs::read_to_string(self.block_file(chain_id, height))
            .map_err(|e| format!("Read failed for {} block {}: {}", chain_id, height, e))?;
        
        serde_json::from_str(&json)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
    
    fn load_blocks_range(&self, chain_id: ChainId, start: u32, end: u32) 
        -> Result<Vec<BlockData>, String> 
    {
        let mut blocks = Vec::new();
        for h in start..=end {
            match self.load_block(chain_id, h) {
                Ok(block) => blocks.push(block),
                Err(_) => continue,
            }
        }
        Ok(blocks)
    }
    
    fn delete_blocks_above(&mut self, chain_id: ChainId, height: u32) 
        -> Result<(), String> 
    {
        // Find and delete files
        let chain_dir = self.chain_dir(chain_id);
        
        if !chain_dir.exists() {
            return Ok(());
        }
        
        let entries = std::fs::read_dir(&chain_dir)
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();
            
            if filename_str.starts_with("block_") {
                if let Some(h_str) = filename_str.strip_prefix("block_")
                    .and_then(|s| s.strip_suffix(".json")) 
                {
                    if let Ok(h) = h_str.parse::<u32>() {
                        if h > height {
                            std::fs::remove_file(entry.path())
                                .map_err(|e| format!("Failed to delete file: {}", e))?;
                        }
                    }
                }
            }
        }
        
        // Remove from cache
        self.blocks.retain(|(cid, h), _| {
            *cid != chain_id || *h <= height
        });
        
        Ok(())
    }
    
    fn stats(&self) -> StorageStats {
        // Would need to scan all chain directories
        // For now, return rough estimate
        StorageStats {
            total_blocks_stored: self.blocks.len(),
            total_storage_bytes: 0,
            last_update: 0,
            chains_count: 0,
        }
    }
    
    fn chain_stats(&self, chain_id: ChainId) -> ChainStorageStats {
        let blocks_stored = self.blocks.keys()
            .filter(|(cid, _)| *cid == chain_id)
            .count();
        
        ChainStorageStats {
            chain_id,
            blocks_stored,
            storage_bytes: 0,
            tip_height: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::proofs::types::BeaconBlockData;
    use common_types::common::crypto::weighted_hash::WeightedHash;
    use crate::mmr_client::chain_handler::ChainType;
    use crate::mmr_client::weighted_mmr_light::WeightedMMRLight;

    fn create_test_block(height: u32) -> BlockData {
        let bitcoin_anchor_timestamp = 1_704_067_200u64;
        let test_timestamp = 1000000u64;
        let delta = ((test_timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256) as i32;
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash: WeightedHash::from([height as u8; 32]),
            prev_mmr_root: [0u8; 32].into(),
            current_mmr_root: [0u8; 32].into(),
            version: 1,
            delta,
            difficulty: 1000,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        })
    }

    fn create_test_state(chain_id: ChainId, height: u32) -> ChainState {
        let chain_type = match chain_id {
            ChainId::Beacon => ChainType::Beacon,
            ChainId::Shard(_) => ChainType::Shard,
        };

        let id = match chain_id {
            ChainId::Beacon => 0,
            ChainId::Shard(shard_id) => shard_id + 1,
        };

        // Create test block first
        let test_block = create_test_block(height);

        let expected_shard_id = match chain_id {
            ChainId::Beacon => None,
            ChainId::Shard(shard_id) => Some(shard_id),
        };

        ChainState {
            chain_type,
            chain_id: id,
            anchor_hash: test_block.prev_mmr_root_bytes(),
            genesis_hash: if height == 0 { Some(test_block.block_hash()) } else { None },
            tip: test_block,
            chain_weight: 1000 * (height as u128),
            max_cache_size: 100,
            recent_blocks: HashMap::new(),
            mmr_light: WeightedMMRLight::with_anchor(WeightedHash::from_anchor(&[0u8; 32]), 100),
            expected_shard_id,
            hash_sorting_bits: 0,
        }
    }

    #[test]
    fn test_chain_id_to_string() {
        assert_eq!(ChainId::Beacon.to_string(), "beacon");
        assert_eq!(ChainId::Shard(5).to_string(), "shard_5");
    }

    #[test]
    fn test_chain_id_from_string() {
        assert_eq!(ChainId::from_string("beacon").unwrap(), ChainId::Beacon);
        assert_eq!(ChainId::from_string("shard_5").unwrap(), ChainId::Shard(5));
        assert!(ChainId::from_string("invalid").is_err());
    }

    #[test]
    fn test_multi_chain_no_collision() {
        let mut storage = InMemoryStorage::new();

        // Store same height, different chains
        let beacon_block = create_test_block(100);
        let shard_block = create_test_block(100);

        storage.save_block(ChainId::Beacon, &beacon_block).unwrap();
        storage.save_block(ChainId::Shard(5), &shard_block).unwrap();

        // Verify no collision
        let b1 = storage.load_block(ChainId::Beacon, 100).unwrap();
        let b2 = storage.load_block(ChainId::Shard(5), 100).unwrap();

        assert_eq!(b1.block_hash(), [100u8; 32]);
        assert_eq!(b2.block_hash(), [100u8; 32]);

        // Different chains, same height - should coexist
        assert_eq!(storage.blocks.len(), 2);
    }

    #[test]
    fn test_multi_chain_state_isolation() {
        let mut storage = InMemoryStorage::new();

        // Store states for different chains
        storage.save_state(ChainId::Beacon, &create_test_state(ChainId::Beacon, 100)).unwrap();
        storage.save_state(ChainId::Shard(3), &create_test_state(ChainId::Shard(3), 200)).unwrap();

        // Load states
        let beacon_state = storage.load_state(ChainId::Beacon).unwrap();
        let shard_state = storage.load_state(ChainId::Shard(3)).unwrap();

        // Verify isolation
        assert_eq!(beacon_state.tip.height(), 100);
        assert_eq!(shard_state.tip.height(), 200);
    }

    #[test]
    fn test_delete_blocks_above_scoped() {
        let mut storage = InMemoryStorage::new();

        // Add blocks to beacon and shard
        for h in 0..10 {
            storage.save_block(ChainId::Beacon, &create_test_block(h)).unwrap();
            storage.save_block(ChainId::Shard(1), &create_test_block(h)).unwrap();
        }

        assert_eq!(storage.blocks.len(), 20);

        // Delete blocks > 5 from beacon only
        storage.delete_blocks_above(ChainId::Beacon, 5).unwrap();

        // Beacon should have 0-5 (6 blocks)
        // Shard should still have 0-9 (10 blocks)
        assert_eq!(storage.blocks.len(), 16);

        // Verify beacon blocks deleted
        assert!(storage.load_block(ChainId::Beacon, 6).is_err());
        assert!(storage.load_block(ChainId::Beacon, 5).is_ok());

        // Verify shard blocks intact
        assert!(storage.load_block(ChainId::Shard(1), 9).is_ok());
    }
}