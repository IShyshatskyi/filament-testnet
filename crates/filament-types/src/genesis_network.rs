//! Minimal network genesis file + generator stubs for public Filament packaging.

use crate::genesis::BeaconGenesisConfig;
use crate::proofs::types::{BeaconBlockData, BlockData};
use crate::weighted_hash::WeightedHash;
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkGenesisConfig {
    pub beacon: BeaconGenesisConfig,
}

impl NetworkGenesisConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    pub fn devnet() -> Self {
        Self {
            beacon: BeaconGenesisConfig::devnet(),
        }
    }
}

/// Public stand-in for the private genesis `BeaconBlock` handle.
#[derive(Clone, Debug)]
pub struct BeaconBlock {
    pub hash: WeightedHash,
    pub data: BeaconBlockData,
}

pub struct GenesisGenerator;

impl GenesisGenerator {
    pub fn generate_beacon_genesis(cfg: &BeaconGenesisConfig) -> Result<BeaconBlock, String> {
        let leaf = WeightedHash::from_leaf_rbits(&cfg.bitcoin_anchor_hash, cfg.bits);
        let data = BeaconBlockData {
            height: 0,
            block_hash: leaf,
            prev_mmr_root: WeightedHash::from_anchor(&cfg.bitcoin_anchor_hash),
            current_mmr_root: leaf,
            version: 1,
            delta: 0,
            difficulty: 1,
            bits: cfg.bits,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        };
        Ok(BeaconBlock { hash: leaf, data })
    }

    pub fn beacon_genesis_hash(cfg: &BeaconGenesisConfig) -> Result<[u8; 32], String> {
        Ok(Self::generate_beacon_genesis(cfg)?.hash.into())
    }
}

impl BeaconBlockData {
    pub fn from_beacon_block(block: &BeaconBlock) -> Self {
        block.data.clone()
    }
}

impl From<&BeaconBlock> for BlockData {
    fn from(block: &BeaconBlock) -> Self {
        BlockData::Beacon(BeaconBlockData::from_beacon_block(block))
    }
}
