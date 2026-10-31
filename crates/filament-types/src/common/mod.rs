//! Shared filament wire/consensus types — ported from private `filament_common`
//! plus the narrow kameniar companions those modules import
//! (`expand_voting`, `k_voting_config`, `orange_tree`, `emission_schedule`,
//! `utxo`, `validation`).

pub mod block_intervals;
pub mod blocks;
pub mod compact_beacon;
pub mod compact_block;
pub mod crypto;
pub mod emission_schedule;
pub mod expand_voting;
pub mod genesis;
pub mod hash_sorting;
pub mod ipp;
pub mod k_voting_config;
pub mod notification_ring;
pub mod orange_tree;
pub mod proofs;
pub mod relay_hash;
pub mod types;
pub mod utxo;
pub mod validation;
pub mod verification;
pub mod weighted_mmr_core;
pub mod windowed_weighted_mmr;

// Re-exports matching private `common::` convenience surface (subset).
pub use blocks::{BeaconBlock, BeaconBlockCandidateHeader, Block, FullShardHeader, BeaconHeader};
pub use crypto::{sha256d, hash_pair, hash_data, hash_meets_target, nbits_to_target, difficulty_to_nbits};
pub use genesis::{
    BeaconGenesisConfig, ShardGenesisConfig, NetworkGenesisConfig,
    PremineOutput, GenesisGenerator,
    SHARD_CALIBRATION_CONSTANT, SHARD_CALIBRATION_SHIFT_BITS,
    shard_calibration_shift_bits,
    beacon_any_chain_floor_u128, beacon_difficulty_floor_u128,
};
pub use relay_hash::relay_id;
pub use types::ChainType;
