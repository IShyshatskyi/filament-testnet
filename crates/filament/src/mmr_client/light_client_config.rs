// src/mmr_client/light_client_config.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Filament bootstrap configuration (genesis anchors, sync, peers).
///
/// Loaded from `light_client_config.toml` — separate from the full-node
/// `[mmr_light_client]` section in `config.toml` (`shisha_core::config::MmrLightClientConfig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilamentBootstrapConfig {
    /// Network configurations
    pub mainnet: NetworkGenesisInfo,
    pub testnet1: NetworkGenesisInfo,
    pub testnet2: NetworkGenesisInfo,
    pub devnet: NetworkGenesisInfo,
    
    /// Sync settings
    pub sync: SyncSettings,
    
    /// Checkpoints for fast sync
    pub checkpoints: CheckpointConfig,
    
    /// Trusted peers
    pub peers: PeerConfig,
}

/// Genesis information for a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGenesisInfo {
    /// Network identifier
    pub network_id: String,

    /// Genesis block hash (hex string)
    pub genesis_hash: String,

    /// Genesis block height (always 0)
    pub genesis_height: u32,

    /// Genesis timestamp
    pub genesis_timestamp: u64,

    /// Genesis difficulty
    pub genesis_difficulty: u64,

    /// Genesis bits
    pub genesis_bits: u32,

    /// Genesis MMR root (hex string)
    pub genesis_mmr_root: String,

    /// Bitcoin anchor hash (hex string)
    pub bitcoin_anchor_hash: String,

    /// Bitcoin anchor height
    pub bitcoin_anchor_height: u32,

    /// Bitcoin anchor timestamp (Unix seconds) - used for delta encoding
    pub bitcoin_anchor_timestamp: u64,
}

impl NetworkGenesisInfo {
    /// Parse genesis hash from hex string to bytes
    pub fn genesis_hash_bytes(&self) -> Result<[u8; 32], String> {
        hex_to_bytes32(&self.genesis_hash)
    }
    
    /// Parse genesis MMR root from hex string to bytes
    pub fn genesis_mmr_root_bytes(&self) -> Result<[u8; 32], String> {
        hex_to_bytes32(&self.genesis_mmr_root)
    }
    
    /// Parse Bitcoin anchor hash from hex string to bytes
    pub fn bitcoin_anchor_hash_bytes(&self) -> Result<[u8; 32], String> {
        hex_to_bytes32(&self.bitcoin_anchor_hash)
    }
    
    /// Create CompleteBatchBlock for genesis
    /// 
    /// CRITICAL: Genesis block uses Bitcoin anchor hash for prev_hash
    /// This prevents pre-mining by anchoring to an external blockchain
    pub fn to_complete_batch_block(&self) -> Result<common_types::common::proofs::CompleteBatchBlock, String> {
        let bitcoin_anchor = self.bitcoin_anchor_hash_bytes()?;
        
        Ok(common_types::common::proofs::CompleteBatchBlock {
            height: self.genesis_height,
            hash: self.genesis_hash_bytes()?,
            mmr_root: self.genesis_mmr_root_bytes()?,
            tx_merkle_root: [0u8; 32], // Genesis has no transactions
            prev_hash: bitcoin_anchor,  // FIXED: Use Bitcoin anchor, not zero!
            difficulty: self.genesis_difficulty,
            timestamp: self.genesis_timestamp,
        })
    }
    
    /// Create BlockData for genesis
    /// 
    /// CRITICAL: Genesis block uses Bitcoin anchor hash for:
    /// - prev_block_hash: Links to Bitcoin blockchain
    /// - prev_mmr_root: Initial MMR state equals anchor
    /// 
    /// This matches the full node genesis generation in genesis.rs
    pub fn to_block_data(&self) -> Result<common_types::common::proofs::BlockData, String> {
        use common_types::common::proofs::{BlockData, BeaconBlockData};

        let bitcoin_anchor = self.bitcoin_anchor_hash_bytes()?;

        // TS-DELTA: Calculate delta as (timestamp - bitcoin_anchor_timestamp) * 256
        let delta = (((self.genesis_timestamp as i64 - self.bitcoin_anchor_timestamp as i64) * 256) as i32);

        Ok(BlockData::Beacon(BeaconBlockData {
            height: self.genesis_height,
            block_hash: self.genesis_hash_bytes()?.into(),
            prev_mmr_root: bitcoin_anchor.into(),      // FIXED: Use Bitcoin anchor!
            current_mmr_root: self.genesis_mmr_root_bytes()?.into(),
            version: 1,
            delta,
            difficulty: self.genesis_difficulty,
            bits: self.genesis_bits,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        }))
    }
}

/// Sync settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSettings {
    pub recent_blocks_cache_size: usize,
    pub poll_interval_secs: u64,
    pub max_concurrent_requests: usize,
    pub range_proof_batch_size: u32,
    pub request_timeout_secs: u64,
    pub paranoid_mode: bool,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            recent_blocks_cache_size: 100,
            poll_interval_secs: 10,
            max_concurrent_requests: 10,
            range_proof_batch_size: 100,
            request_timeout_secs: 30,
            paranoid_mode: false,
        }
    }
}

/// Checkpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointConfig {
    pub mainnet: HashMap<String, String>,
    pub testnet1: HashMap<String, String>,
    pub devnet: HashMap<String, String>,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            mainnet: HashMap::new(),
            testnet1: HashMap::new(),
            devnet: HashMap::new(),
        }
    }
}

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub mainnet: PeerList,
    pub testnet1: PeerList,
    pub devnet: PeerList,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            mainnet: PeerList::default(),
            testnet1: PeerList::default(),
            devnet: PeerList::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerList {
    #[serde(default)]
    pub peers: Vec<String>,
}

/// Deprecated alias — use [`FilamentBootstrapConfig`].
#[deprecated(since = "0.5.0", note = "renamed to FilamentBootstrapConfig (RF-11 naming collision fix)")]
pub type LightClientConfig = FilamentBootstrapConfig;

impl FilamentBootstrapConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))
    }
    
    /// Get network genesis info by network ID
    pub fn get_network(&self, network_id: &str) -> Option<&NetworkGenesisInfo> {
        match network_id {
            "mainnet" => Some(&self.mainnet),
            "testnet1" => Some(&self.testnet1),
            "testnet2" => Some(&self.testnet2),
            "devnet" => Some(&self.devnet),
            _ => None,
        }
    }
    
    /// Validate genesis hash matches expected value
    pub fn validate_genesis(
        &self,
        network_id: &str,
        genesis_hash: &[u8; 32],
    ) -> Result<(), String> {
        let network = self.get_network(network_id)
            .ok_or_else(|| format!("Unknown network: {}", network_id))?;
        
        let expected = network.genesis_hash_bytes()?;
        
        if genesis_hash != &expected {
            return Err(format!(
                "Genesis hash mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(genesis_hash)
            ));
        }
        
        Ok(())
    }
}

/// Helper function to parse hex string to 32-byte array
fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim_start_matches("0x");
    
    if hex.len() != 64 {
        return Err(format!(
            "Invalid hex length: {} (expected 64 characters)",
            hex.len()
        ));
    }
    
    let bytes = hex::decode(hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hex_to_bytes32() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes32(hex).unwrap();
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[30], 0);
    }
    
    #[test]
    fn test_network_genesis_info() {
        let info = NetworkGenesisInfo {
            network_id: "devnet".to_string(),
            genesis_hash: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            genesis_height: 0,
            genesis_timestamp: 1704067200,
            genesis_difficulty: 1,
            genesis_bits: 0x207fffff,
            genesis_mmr_root: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            bitcoin_anchor_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            bitcoin_anchor_height: 0,
            bitcoin_anchor_timestamp: 1704067200,
        };
        
        let hash = info.genesis_hash_bytes().unwrap();
        assert_eq!(hash[31], 1);
        
        let block = info.to_complete_batch_block().unwrap();
        assert_eq!(block.height, 0);
        assert_eq!(block.difficulty, 1);
    }
}
