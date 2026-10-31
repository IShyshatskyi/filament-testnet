//! Proof type definitions shared between Full Node and MMR Client.
//!
//! Full Node generates these proofs; MMR Client verifies them.
//! Types include batch, range, fork, and chain weight proofs.

pub mod types;
pub use types::*;

// Weighted MMR proof types (WeightedHash nodes; FlyClient-style cumulative difficulty)
pub mod weighted_mmr_batch_proof;
pub mod weighted_mmr_range_proof;
pub mod weighted_fork_proof;

pub mod thin_sync;
pub use thin_sync::{
    decode_shard_blocks, encode_shard_blocks, ThinHeaderProofResponse, ThinHeadersResponse, ThinSessionResponse,
    ThinShardBlocksResponse, ThinShardSessionResponse, ThinTipResponse, MAX_HEADERS_PER_REQUEST,
    MAX_SESSION_HEADERS, MAX_SHARD_BLOCKS_PER_REQUEST,
};
pub use weighted_mmr_batch_proof::WeightedMMRBatchProof;
pub use weighted_mmr_range_proof::WeightedMMRRangeProof;
pub use weighted_fork_proof::WeightedChainWeightProof;

// Fork resolution clue: locate the first divergent MMR node from a peer's batch proof
pub mod fork_clue;
pub mod side_fork_path;

// Climb-and-descent fork proof (canonical fork proof type)
pub mod fork_proof;
pub use fork_proof::{ForkProof, ForkProofError, ForkProofResult};


