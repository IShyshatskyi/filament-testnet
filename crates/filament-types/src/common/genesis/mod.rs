//! Genesis configuration and block generation.
//!
//! - `genesis_config` — Network, beacon, and shard genesis configurations
//! - `genesis` — Genesis block generation and validation

pub mod genesis_config;
pub mod genesis;
pub mod premine_outpoints;
pub mod network_identity;

pub use genesis_config::{
    BeaconGenesisConfig, ShardGenesisConfig, NetworkGenesisConfig,
    NetworkId, PremineOutput, bitcoin_anchors,
    SHARD_CALIBRATION_CONSTANT, SHARD_CALIBRATION_SHIFT_BITS,
    shard_calibration_shift_bits,
    beacon_any_chain_floor_u128, beacon_difficulty_floor_u128,
};
pub use genesis::GenesisGenerator;
pub use network_identity::{
    P2pProtocolKind, p2p_network_magic, p2p_network_magic_bytes, UNKNOWN_GENESIS_HASH,
};
pub use premine_outpoints::{
    PremineOutpointEntry, PremineOutpointTable, PremineRole,
    SHARD_FIRST_PREMINE_OUTPUT_IDX, SHARD_POOL_REWARD_OUTPUT_IDX,
    SHARD_PREMINE_BLOCK_HEIGHT,
    beacon_premine_outpoints, shard_premine_outpoints,
};
