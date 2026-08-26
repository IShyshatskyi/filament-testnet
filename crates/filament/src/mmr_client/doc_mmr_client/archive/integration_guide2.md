# MMR Light Client Integration Guide

## Overview
This guide integrates MMR light client proofs into your existing codebase in 6 steps.

## File Structure After Integration
```
src/
├── lib.rs                      (modify - add exports)
├── mmr_core.rs                 (modify - add methods)
├── mmr_light_client.rs         (NEW - proof types)
├── beacon_chain.rs             (modify - add proof generation)
├── beacon_light_client.rs      (NEW - light client impl)
├── light_client_protocol.rs    (NEW - network protocol)
├── app.rs                      (modify - add light client API)
├── config.rs                   (modify - add config)
└── main.rs                     (modify - initialize light client)
```

## Step 1: Create `mmr_light_client.rs`

Create `src/mmr_light_client.rs` with proof type definitions.

**What it contains:**
- `MMRBatchProof` - Multiple blocks at once
- `MMRRangeProof` - Contiguous block range
- `MMRForkProof` - Fork detection
- `MMRChainWeightProof` - Cumulative difficulty
- `MMRChainSummary` - Compact chain state
- `CompactBlockHeader` - Minimal block info
- Verification functions

**Integration point:** Referenced by `mmr_core.rs` and `beacon_chain.rs`

## Step 2: Extend `mmr_core.rs`

Add new methods to the existing `MMR` impl block:

```rust
impl MMR {
    // EXISTING METHODS (keep these)
    // - new()
    // - append()
    // - prove()
    // - verify_proof()
    // - get_root()
    // etc.
    
    // NEW METHODS (add these)
    
    /// Generate batch proof for multiple leaves
    pub fn prove_batch(&self, leaf_indices: &[u32]) -> MMRBatchProof { ... }
    
    /// Generate range proof for contiguous leaves
    pub fn prove_range(&self, start: u32, end: u32) -> Result<MMRRangeProof, String> { ... }
    
    /// Find fork point between two MMRs
    pub fn find_fork_point(&self, other_mmr: &Self) -> Result<MMRForkProof, String> { ... }
    
    /// Generate chain weight proof
    pub fn prove_chain_weight(
        &self,
        start: u32,
        end: u32,
        difficulties: &[u64],
    ) -> Result<MMRChainWeightProof, String> { ... }
}
```

**Key point:** These are additions, not replacements. Your existing MMR code stays unchanged.

## Step 3: Extend `beacon_chain.rs`

Add proof generation methods to `BeaconChain`:

```rust
impl BeaconChain {
    // EXISTING METHODS (keep all these)
    // - new()
    // - append_block()
    // - get_mmr_root()
    // - generate_mmr_proof()
    // etc.
    
    // NEW METHODS FOR LIGHT CLIENTS (add these)
    
    /// Generate chain summary for light clients
    pub fn generate_chain_summary(&self, recent_count: usize) 
        -> Result<MMRChainSummary, String> { ... }
    
    /// Generate range proof for block range
    pub fn generate_range_proof(&self, start: u32, end: u32) 
        -> Result<(MMRRangeProof, Vec<CompactBlockHeader>), String> { ... }
    
    /// Generate chain weight proof
    pub fn generate_chain_weight_proof(&self, start: u32, end: u32) 
        -> Result<MMRChainWeightProof, String> { ... }
    
    /// Find fork point with another chain
    pub fn find_fork_point_with(&self, other_chain: &Self) 
        -> Result<MMRForkProof, String> { ... }
    
    /// Verify chain summary from peer
    pub fn verify_chain_summary(&self, summary: &MMRChainSummary) 
        -> Result<bool, String> { ... }
}
```

**Integration point:** Full nodes call these methods to serve light clients.

## Step 4: Update `lib.rs`

Add new module declarations and exports:

```rust
// EXISTING MODULES (keep all)
pub mod mmr_core;
pub mod beacon_chain;
// ... all your existing modules

// NEW MODULES (add these)
pub mod mmr_light_client;
pub mod beacon_light_client;
pub mod light_client_protocol;

// EXISTING RE-EXPORTS (keep all)
pub use mmr_core::{MMR, MMRProof};
// ... all your existing re-exports

// NEW RE-EXPORTS (add these)
pub use mmr_light_client::{
    MMRBatchProof,
    MMRRangeProof,
    MMRForkProof,
    MMRChainWeightProof,
    MMRChainSummary,
    CompactBlockHeader,
};

pub use beacon_light_client::BeaconLightClient;
pub use light_client_protocol::{
    LightClientRequest,
    LightClientResponse,
    LightClientProtocolHandler,
};
```

## Step 5: Create `light_client_protocol.rs`

Create `src/light_client_protocol.rs` for network protocol:

```rust
/// Network protocol for serving light client requests
/// 
/// Contains:
/// - Request/Response message enums
/// - Protocol handler for full nodes
/// - Message serialization/deserialization

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightClientRequest {
    GetChainSummary { recent_count: usize },
    GetRangeProof { start_height: u32, end_height: u32 },
    GetChainWeightProof { start_height: u32, end_height: u32 },
    // ... etc
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightClientResponse {
    ChainSummary(MMRChainSummary),
    RangeProof { proof: MMRRangeProof, blocks: Vec<CompactBlockHeader> },
    // ... etc
}

pub struct LightClientProtocolHandler {
    beacon_chain: Arc<RwLock<BeaconChain>>,
}

impl LightClientProtocolHandler {
    pub async fn handle_request(&self, req: LightClientRequest) 
        -> LightClientResponse { ... }
}
```

## Step 6: Create `beacon_light_client.rs`

Create `src/beacon_light_client.rs` for light client implementation:

```rust
/// Light client implementation for beacon chain
/// 
/// Maintains minimal state:
/// - Current MMR root
/// - Chain height
/// - Chain weight
/// - Recent blocks (last 100)

pub struct BeaconLightClient {
    mmr_root: [u8; 32],
    height: u32,
    chain_weight: u128,
    recent_blocks: Vec<CompactBlockHeader>,
}

impl BeaconLightClient {
    pub fn new() -> Self { ... }
    
    pub async fn sync(&mut self) -> Result<(), String> { ... }
    
    pub fn verify_summary(&self, summary: &MMRChainSummary) -> bool { ... }
}
```

## Step 7: Update `config.rs`

Add light client configuration:

```rust
/// Add to Config struct
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    // ... existing fields ...
    
    /// Light client configuration (optional)
    #[serde(default)]
    pub light_client: LightClientConfig,
}

/// New configuration section
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LightClientConfig {
    /// Enable light client API server
    #[serde(default = "default_enable_light_client")]
    pub enabled: bool,
    
    /// Port for light client API
    #[serde(default = "default_light_client_port")]
    pub port: u16,
    
    /// Number of recent blocks to include in summaries
    #[serde(default = "default_recent_blocks")]
    pub recent_blocks: usize,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            recent_blocks: 100,
        }
    }
}

fn default_enable_light_client() -> bool { false }
fn default_light_client_port() -> u16 { 8080 }
fn default_recent_blocks() -> usize { 100 }
```

## Step 8: Update `app.rs`

Add light client API to app context:

```rust
pub struct AppContext {
    // ... existing fields ...
    
    /// Light client protocol handler (optional)
    pub light_client_api: Option<Arc<LightClientProtocolHandler>>,
}

impl AppContext {
    pub fn new(
        config: Config,
        genesis_config: Arc<NetworkGenesisConfig>,
        shutdown_token: Arc<AtomicBool>,
        shard_job_submitter: ShardJobSubmitter,
        job_cache: SharedJobCache,
        job_generator: SharedJobGenerator,
        beacon_chain: Arc<RwLock<BeaconChain>>,  // Add this parameter
    ) -> Self {
        // Create light client API if enabled
        let light_client_api = if config.light_client.enabled {
            Some(Arc::new(LightClientProtocolHandler::new(beacon_chain)))
        } else {
            None
        };
        
        Self {
            config,
            genesis_config,
            shutdown_token,
            shard_job_submitter,
            job_cache,
            job_generator,
            light_client_api,
        }
    }
}
```

## Step 9: Update `main.rs`

Initialize and start light client API server:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ... existing initialization ...
    
    // Phase X: Initialize beacon chain (if not already done)
    let beacon_chain = Arc::new(RwLock::new(BeaconChain::new()));
    
    // ... existing code ...
    
    // Phase Y: Start light client API server (if enabled)
    if config.light_client.enabled {
        info!("Starting light client API server on port {}", 
              config.light_client.port);
        
        let light_client_api = Arc::new(
            LightClientProtocolHandler::new(beacon_chain.clone())
        );
        
        // Spawn API server
        tokio::spawn(async move {
            start_light_client_api_server(light_client_api, config.light_client.port)
                .await
                .unwrap_or_else(|e| {
                    error!("Light client API server error: {}", e);
                });
        });
    }
    
    // ... rest of main ...
}

/// Start HTTP server for light client API
async fn start_light_client_api_server(
    handler: Arc<LightClientProtocolHandler>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use axum, actix-web, or warp to create HTTP API
    // Example routes:
    // GET  /chain/summary
    // GET  /chain/range/:start/:end
    // GET  /chain/weight/:start/:end
    // POST /chain/fork (with body containing peer root)
    
    info!("Light client API listening on 0.0.0.0:{}", port);
    
    // Implementation depends on your HTTP framework choice
    Ok(())
}
```

## Step 10: Add to `config.toml`

Add light client section to your config file:

```toml
# ... existing config ...

[light_client]
enabled = true           # Enable light client API
port = 8080             # API server port
recent_blocks = 100     # How many recent blocks to include in summaries
```

## Testing Integration

### Test 1: Proof Generation
```rust
#[tokio::test]
async fn test_light_client_proof_generation() {
    let mut chain = BeaconChain::new();
    
    // Add some blocks
    for i in 0..10 {
        // ... add block ...
    }
    
    // Generate chain summary
    let summary = chain.generate_chain_summary(5).unwrap();
    assert_eq!(summary.height, 10);
    assert_eq!(summary.recent_blocks.len(), 5);
    
    // Verify summary
    assert!(chain.verify_chain_summary(&summary).unwrap());
}
```

### Test 2: Range Proof
```rust
#[tokio::test]
async fn test_range_proof() {
    let mut chain = BeaconChain::new();
    
    // Add 20 blocks
    for i in 0..20 {
        // ... add block ...
    }
    
    // Generate range proof
    let (proof, blocks) = chain.generate_range_proof(5, 10).unwrap();
    
    assert_eq!(blocks.len(), 6); // 5,6,7,8,9,10
    assert!(verify_range_proof(&chain.get_mmr_root(), &proof));
}
```

### Test 3: Fork Detection
```rust
#[tokio::test]
async fn test_fork_detection() {
    let mut chain_a = BeaconChain::new();
    let mut chain_b = BeaconChain::new();
    
    // Common blocks
    for i in 0..5 {
        // ... add same block to both chains ...
    }
    
    // Diverge
    // ... add different blocks ...
    
    // Find fork
    let fork_proof = chain_a.find_fork_point_with(&chain_b).unwrap();
    assert_eq!(fork_proof.fork_point, 4); // Last common block
}
```

## Dependencies to Add

Update `Cargo.toml`:

```toml
[dependencies]
# ... existing dependencies ...

# For light client API server (choose one)
axum = "0.7"              # Recommended: Modern, ergonomic
tokio = { version = "1", features = ["full"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors"] }

# OR
actix-web = "4"           # Alternative: Mature, performant

# For serialization (if not already present)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bincode = "1"             # For efficient binary encoding
```

## Gradual Rollout Strategy

### Phase 1: Backend Only (Week 1)
- Integrate proof types
- Add beacon chain methods
- Write unit tests
- No network exposure yet

### Phase 2: Internal API (Week 2)
- Add protocol handler
- Create test API endpoint
- Internal testing only
- Monitor performance

### Phase 3: Beta Release (Week 3)
- Enable light client API in config
- Document API endpoints
- Beta testers use light clients
- Collect feedback

### Phase 4: Production (Week 4)
- Enable by default
- Add monitoring/metrics
- Optimize proof caching
- Full documentation

## Monitoring & Metrics

Add metrics to track:
```rust
// In protocol handler
let metrics = Metrics::new();
metrics.increment("light_client.requests.chain_summary");
metrics.timing("light_client.proof_generation_ms", duration);
metrics.gauge("light_client.active_clients", count);
```

## Performance Tuning

### Proof Caching
```rust
// Add to LightClientProtocolHandler
use lru::LruCache;

pub struct LightClientProtocolHandler {
    beacon_chain: Arc<RwLock<BeaconChain>>,
    proof_cache: Arc<RwLock<LruCache<String, MMRRangeProof>>>,
}

impl LightClientProtocolHandler {
    async fn handle_get_range_proof(&self, start: u32, end: u32) 
        -> LightClientResponse 
    {
        let cache_key = format!("{}:{}", start, end);
        
        // Check cache first
        {
            let mut cache = self.proof_cache.write().await;
            if let Some(proof) = cache.get(&cache_key) {
                // Return cached proof
                return LightClientResponse::RangeProof { 
                    proof: proof.clone(), 
                    blocks: vec![] 
                };
            }
        }
        
        // Generate and cache
        let chain = self.beacon_chain.read().await;
        let (proof, blocks) = chain.generate_range_proof(start, end).unwrap();
        
        {
            let mut cache = self.proof_cache.write().await;
            cache.put(cache_key, proof.clone());
        }
        
        LightClientResponse::RangeProof { proof, blocks }
    }
}
```

## Security Checklist

- [ ] Rate limit light client requests
- [ ] Validate all input parameters
- [ ] Add request size limits
- [ ] Enable CORS properly
- [ ] Add authentication (optional)
- [ ] Monitor for DoS attempts
- [ ] Add request logging

## Documentation

Create `docs/light_client_api.md`:

```markdown
# Light Client API Documentation

## Endpoints

### GET /chain/summary
Returns compact chain state with recent blocks.

**Query Parameters:**
- `recent_count` (optional): Number of recent blocks (default: 100)

**Response:**
```json
{
  "height": 12345,
  "mmr_root": "0x...",
  "chain_weight": "1234567890",
  "recent_blocks": [...],
  "proof": {...}
}
```

### GET /chain/range/:start/:end
Returns range proof for blocks [start, end].

... etc ...
```

## Support

Questions? Issues?
- Check docs/light_client_api.md
- Run tests: `cargo test light_client`
- Enable debug logging: `RUST_LOG=debug`

## Summary

Integration complete! You now have:
✅ Extended MMR with batch/range/fork proofs
✅ Beacon chain generating proofs
✅ Protocol handler serving light clients
✅ Configuration for enabling/disabling
✅ Tests verifying functionality
✅ Documentation for API users

Next steps:
1. Run tests: `cargo test`
2. Start with `enabled = false` in config
3. Enable for internal testing
4. Roll out to production gradually
