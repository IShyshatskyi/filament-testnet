// ============================================================================
// src/mmr_client/protocol.rs - NETWORK PROTOCOL
// ============================================================================

//! Network protocol for light client communication
//!
//! Defines request/response messages for light clients to communicate
//! with full nodes and request proofs.

use serde::{Serialize, Deserialize};
use log::debug;
use crate::mmr_client::proof_selector::{
    ProofSelector,
    ProofStrategy,
    DEFAULT_DENSITY_THRESHOLD,
};
use common_types::common::proofs::{
    MMRChainSummary,
    MMRRangeProofBundle,
    WeightedMMRBatchProof,
    ForkProof,
    WeightedChainWeightProof,
    CompleteBatchBlock,
};

/// Light client protocol messages - Request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightClientRequest {
    /// Request current chain summary with recent blocks
    GetChainSummary {
        /// Number of recent blocks to include
        recent_count: usize,
    },
    
    /// Request range proof for block range
    GetRangeProof {
        /// Start height (inclusive)
        start_height: u32,
        /// End height (inclusive)
        end_height: u32,
        /// Target height to prove against
        target_height: u32,
    },
    
    /// Request batch proof for specific blocks
    GetBatchProof {
        /// Heights of blocks to prove
        batch_heights: Vec<u32>,
        /// Target height to prove against
        target_height: u32,
    },

    /// **Auto-detecting unified proof request.**
    ///
    /// The server selects between `RangeProof` and `BatchProof` based on the
    /// fill density of `heights` relative to `density_threshold`:
    ///
    /// ```text
    /// density = |heights| / (max(heights) - min(heights) + 1)
    ///
    /// density >= density_threshold  →  RangeProof(min, max)
    /// density <  density_threshold  →  BatchProof(heights)
    /// ```
    ///
    /// # Guidance
    ///
    /// - Use `DEFAULT_DENSITY_THRESHOLD` (0.35) unless you have profiling data.
    /// - Set `density_threshold = 1.0` to always force `BatchProof`.
    /// - Set `density_threshold = 0.0` to always force `RangeProof`.
    ///
    /// # Response
    ///
    /// Will be either `LightClientResponse::RangeProof` or
    /// `LightClientResponse::BatchProof`. Callers must handle both variants.
    GetBlockProof {
        /// Heights to prove. May be unsorted or contain duplicates — normalised
        /// server-side. Must not be empty.
        heights: Vec<u32>,
        /// Chain tip height to prove against. Must be `>= max(heights)`.
        target_height: u32,
        /// Fill-density threshold in `[0.0, 1.0]`. Clamped if out of range.
        /// Pass `DEFAULT_DENSITY_THRESHOLD` if unsure.
        #[serde(default = "default_density_threshold")]
        density_threshold: f32,
    },

    /// Request fork detection proof
    GetForkProof {
        /// Our current tip hash
        our_tip_hash: [u8; 32],
        /// Our current height
        our_height: u32,
    },
    
    /// Request chain weight proof
    GetChainWeightProof {
        /// Start height
        start_height: u32,
        /// End height
        end_height: u32,
        /// Target height
        target_height: u32,
    },
    
    /// Request single block header
    GetBlockHeader {
        /// Height of block to retrieve
        height: u32,
    },
    
    /// Request transaction merkle proof
    GetTransactionProof {
        /// Transaction hash
        tx_hash: [u8; 32],
        /// Block height containing transaction
        block_height: u32,
    },
}

/// Light client protocol messages - Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightClientResponse {
    /// Chain summary with recent blocks and proof
    ChainSummary(MMRChainSummary),
    
    /// Range proof with block headers
    RangeProof(MMRRangeProofBundle),
    
    /// Batch proof for multiple blocks
    BatchProof(WeightedMMRBatchProof),
    
    /// Fork detection proof
    ForkProof(ForkProof),
    
    /// Chain weight proof
    ChainWeightProof(WeightedChainWeightProof),
    
    /// Single block header
    BlockHeader {
        block: CompleteBatchBlock,
    },
    
    /// Transaction merkle proof
    TransactionProof {
        /// Merkle proof path
        merkle_proof: Vec<[u8; 32]>,
        /// Block containing transaction
        block: CompleteBatchBlock,
    },
    
    /// Error response
    Error {
        message: String,
    },
}

fn default_density_threshold() -> f32 {
    DEFAULT_DENSITY_THRESHOLD
}

impl LightClientRequest {
    /// Convenience constructor for `GetBlockProof` using the default threshold.
    pub fn get_block_proof(heights: Vec<u32>, target_height: u32) -> Self {
        Self::GetBlockProof {
            heights,
            target_height,
            density_threshold: DEFAULT_DENSITY_THRESHOLD,
        }
    }

    /// Convenience constructor for `GetBlockProof` with a custom threshold.
    pub fn get_block_proof_with_threshold(
        heights:           Vec<u32>,
        target_height:     u32,
        density_threshold: f32,
    ) -> Self {
        Self::GetBlockProof {
            heights,
            target_height,
            density_threshold,
        }
    }

    /// Serialize request to bytes for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| format!("Serialization failed: {}", e))
    }

    /// Deserialize request from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
}

impl LightClientResponse {
    /// Serialize response to bytes for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| format!("Serialization failed: {}", e))
    }

    /// Deserialize response from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
}

// ============================================================================
// PROTOCOL HANDLER (SERVER-SIDE)
// ============================================================================

/// Protocol handler for full node serving light clients
pub struct LightClientProtocolHandler<C> {
    /// Reference to chain (full node)
    chain: C,
}

impl<C> LightClientProtocolHandler<C>
where
    C: ChainInterface,
{
    pub fn new(chain: C) -> Self {
        Self { chain }
    }
    
    /// Handle incoming light client request
    pub fn handle_request(&self, request: LightClientRequest) -> LightClientResponse {
        match request {
            LightClientRequest::GetChainSummary { recent_count } => {
                match self.chain.generate_chain_summary(recent_count) {
                    Ok(summary) => LightClientResponse::ChainSummary(summary),
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }
            
            LightClientRequest::GetRangeProof { start_height, end_height, target_height } => {
                match self.chain.generate_range_proof(start_height, end_height, target_height) {
                    Ok(proof) => LightClientResponse::RangeProof(proof),
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }
            
            LightClientRequest::GetBatchProof { batch_heights, target_height } => {
                match self.chain.generate_batch_proof(&batch_heights, target_height) {
                    Ok(proof) => LightClientResponse::BatchProof(proof),
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }

            // ── Auto-detecting unified variant ────────────────────────────
            LightClientRequest::GetBlockProof { heights, target_height, density_threshold } => {
                self.handle_get_block_proof(heights, target_height, density_threshold)
            }
            
            LightClientRequest::GetForkProof { our_tip_hash, our_height } => {
                match self.chain.generate_fork_proof(our_tip_hash, our_height) {
                    Ok(proof) => LightClientResponse::ForkProof(proof),
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }
            
            LightClientRequest::GetChainWeightProof { start_height, end_height, target_height } => {
                match self.chain.generate_chain_weight_proof(start_height, end_height, target_height) {
                    Ok(proof) => LightClientResponse::ChainWeightProof(proof),
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }
            
            LightClientRequest::GetBlockHeader { height } => {
                match self.chain.get_block(height) {
                    Some(block) => LightClientResponse::BlockHeader { block },
                    None => LightClientResponse::Error {
                        message: format!("Block {} not found", height),
                    },
                }
            }
            
            LightClientRequest::GetTransactionProof { tx_hash, block_height } => {
                match self.chain.generate_transaction_proof(tx_hash, block_height) {
                    Ok((merkle_proof, block)) => LightClientResponse::TransactionProof {
                        merkle_proof,
                        block,
                    },
                    Err(e) => LightClientResponse::Error { message: e },
                }
            }
        }
    }

    /// Dispatch `GetBlockProof` via `ProofSelector` and call the cheapest
    /// `ChainInterface` method.
    fn handle_get_block_proof(
        &self,
        heights:           Vec<u32>,
        target_height:     u32,
        density_threshold: f32,
    ) -> LightClientResponse {
        match ProofSelector::analyze_with_stats(&heights, target_height, density_threshold) {
            Err(e) => LightClientResponse::Error { message: e.to_string() },

            Ok(stats) => {
                debug!(
                    "GetBlockProof: {} heights, span={}, density={:.3}, threshold={:.3} → {}",
                    stats.requested_count,
                    stats.span,
                    stats.density,
                    stats.threshold,
                    if matches!(stats.strategy, ProofStrategy::Range { .. }) { "Range" } else { "Batch" },
                );

                match stats.strategy {
                    ProofStrategy::Range { start, end } => {
                        match self.chain.generate_range_proof(start, end, target_height) {
                            Ok(proof) => LightClientResponse::RangeProof(proof),
                            Err(e)    => LightClientResponse::Error { message: e },
                        }
                    }
                    ProofStrategy::Batch { heights: sorted_heights } => {
                        match self.chain.generate_batch_proof(&sorted_heights, target_height) {
                            Ok(proof) => LightClientResponse::BatchProof(proof),
                            Err(e)    => LightClientResponse::Error { message: e },
                        }
                    }
                }
            }
        }
    }
}

/// Interface that full node chain must implement to serve light clients
pub trait ChainInterface {
    fn generate_chain_summary(&self, recent_count: usize) -> Result<MMRChainSummary, String>;
    fn generate_range_proof(&self, start: u32, end: u32, target: u32) -> Result<MMRRangeProofBundle, String>;
    fn generate_batch_proof(&self, heights: &[u32], target: u32) -> Result<WeightedMMRBatchProof, String>;
    fn generate_fork_proof(&self, their_tip: [u8; 32], their_height: u32) -> Result<ForkProof, String>;
    fn generate_chain_weight_proof(&self, start: u32, end: u32, target: u32) -> Result<WeightedChainWeightProof, String>;
    fn get_block(&self, height: u32) -> Option<CompleteBatchBlock>;
    fn generate_transaction_proof(&self, tx_hash: [u8; 32], block_height: u32) -> Result<(Vec<[u8; 32]>, CompleteBatchBlock), String>;
}

/*
===============================================================================
STORAGE AND PROTOCOL MODULES
===============================================================================

STORAGE MODULE
==============

Purpose:
  Persistent storage for light client state and blocks

Implementations:
  1. InMemoryStorage
     - For testing
     - No persistence
     - Fast

  2. FileStorage
     - Simple file-based persistence
     - JSON format
     - Easy to debug
     - Suitable for desktop applications

  3. SqliteStorage (TODO)
     - Production database
     - Efficient queries
     - ACID guarantees
     - Suitable for production

Interface:
  - save_state() / load_state()
  - save_block() / load_block()
  - load_blocks_range()
  - delete_blocks_above() (for reorg)
  - stats()


PROTOCOL MODULE
===============

Purpose:
  Network protocol for light client ↔ full node communication

Request Types:
  - GetChainSummary: Initial sync
  - GetRangeProof: Sync block range
  - GetBatchProof: Sync specific blocks
  - GetForkProof: Detect forks
  - GetChainWeightProof: Verify chain work
  - GetBlockHeader: Single block
  - GetTransactionProof: Verify transaction

Response Types:
  - ChainSummary: With recent blocks + proof
  - RangeProof: Block range + proof
  - BatchProof: Specific blocks + proof
  - ForkProof: Common ancestor + divergence
  - ChainWeightProof: Cumulative difficulty + proof
  - BlockHeader: Single block data
  - TransactionProof: Merkle proof + block
  - Error: Error message

Serialization:
  - Uses bincode for efficiency
  - ~20% smaller than JSON
  - Fast serialization


PROTOCOL HANDLER
================

Server-side handler for full nodes:

```rust
// Full node serves light clients
let handler = LightClientProtocolHandler::new(beacon_chain);

// Handle request
let response = handler.handle_request(request);
send_to_client(response);
```

Chain Interface:
  Full node chain must implement ChainInterface trait
  Provides all proof generation methods


USAGE EXAMPLE
=============

Light Client:
```rust
// Initialize storage
let storage = Box::new(FileStorage::new("~/.mychain/light")?);
let manager = ChainManager::new(genesis, storage);

// Request chain summary
let request = LightClientRequest::GetChainSummary { recent_count: 100 };
let response = network.send(peer, request).await?;

// Apply summary
if let LightClientResponse::ChainSummary(summary) = response {
    manager.apply_chain_summary(summary)?;
}
```

Full Node:
```rust
// Create protocol handler
let handler = LightClientProtocolHandler::new(beacon_chain);

// Serve light clients
loop {
    let (peer, request) = network.recv().await?;
    let response = handler.handle_request(request);
    network.send(peer, response).await?;
}
```


INTEGRATION
===========

These modules complete the light client infrastructure:

mmr_client/
  ├── mod.rs              # Exports
  ├── mmr.rs              # Core MMR
  ├── proofs.rs           # Proof types
  ├── verification.rs     # Verification
  ├── chain_manager.rs    # High-level management ✓
  ├── storage.rs          # Persistence ✓
  └── protocol.rs         # Network protocol ✓


TESTING
=======

Storage Tests:
```rust
#[test]
fn test_storage_roundtrip() {
    let mut storage = InMemoryStorage::new();
    storage.save_state(&state)?;
    let loaded = storage.load_state()?;
    assert_eq!(state.tip.height, loaded.tip.height);
}
```

Protocol Tests:
```rust
#[test]
fn test_protocol_serialization() {
    let request = LightClientRequest::GetChainSummary { recent_count: 10 };
    let bytes = request.to_bytes()?;
    let decoded = LightClientRequest::from_bytes(&bytes)?;
    // Verify roundtrip
}
```


===============================================================================
*/