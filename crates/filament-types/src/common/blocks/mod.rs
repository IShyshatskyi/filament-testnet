// src/common/blocks/mod.rs

//! Block structures for beacon and shard chains.
//!
//! This module provides the core block types used throughout the system:
//! - `BeaconBlock` - Beacon chain blocks
//! - `BeaconBlockCandidateHeader` - Templates for mining
//! - `Block` - Shard chain blocks
//! - `BlockVersion` - Bitcoin-style version field with embedded s parameter and vote flags

pub mod beacon_block;
pub mod beacon_wire_header;
pub mod shard_block;
pub mod version;

// Re-export commonly used types
pub use beacon_block::{BeaconBlock, BeaconBlockCandidateHeader, calculate_commitment_hash_from_parts};
pub use beacon_wire_header::{WireBeaconHeader, WIRE_BEACON_HEADER_SIZE};
pub use shard_block::{Block, FullShardHeader, BeaconHeader, LightShardHeader, LIGHT_SHARD_HEADER_SIZE,
                      ShardBlockBody, ShardWireBlock};
pub use version::{
    BlockVersion, 
    extract_s_from_version, 
    extract_vote_k_from_version,
    extract_vote_expand_from_version,
    extract_base_version, 
    make_version
};