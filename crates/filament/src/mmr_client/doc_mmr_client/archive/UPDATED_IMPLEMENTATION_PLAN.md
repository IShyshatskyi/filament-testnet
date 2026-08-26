# Updated Light Client Implementation Plan

## Strategic Addition: MMR Light Structure

You're absolutely right - the light client should use a **HashSet-based MMR Light** structure instead of importing the vector-based full MMR. This creates cleaner architecture separation:

```
┌─────────────────────────────────────────────┐
│           MINING POOL NODE                  │
│  Future: Hybrid MMR (HashSet + VecDeque)   │
│  Purpose: Append blocks efficiently         │
│  Storage: RocksDB                           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│           FULL NODE                         │
│  Current: Vector-based MMR (full history)   │
│  Purpose: Generate proofs for light clients │
│  Storage: RocksDB                           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│           LIGHT CLIENT (MMR Node)           │
│  NEW: HashSet-based MMR Light               │
│  Purpose: Verify proofs, minimal storage    │
│  Storage: SQLite                            │
└─────────────────────────────────────────────┘
```

---

## Priority 1: Multi-Chain Safety + MMR Light (CRITICAL)

### Components

1. **ChainId Namespacing** (1-2 days)
   - Prevent storage collisions between chains
   - Ensure beacon and shards have separate state

2. **MMR Light Implementation** (2-3 days)
   - HashSet-based structure for minimal memory
   - Only stores recent blocks + peaks
   - No append functionality (light client doesn't mine!)
   - Verification-only interface

3. **Storage Trait Update** (1 day)
   - Add chain_id parameter to all operations
   - Migrate existing implementations

**Total Time**: 4-6 days

---

## Detailed Design: MMR Light

### Key Differences from Full MMR

| Feature | Full MMR (Vector) | MMR Light (HashSet) |
|---------|-------------------|---------------------|
| Storage | `Vec<[u8; 32]>` | `HashSet<([u8; 32], u32)>` |
| Memory | O(n) all nodes | O(log n) peaks + recent |
| Append | ✅ Yes | ❌ No (light client doesn't mine) |
| Verify | ✅ Yes | ✅ Yes (main purpose) |
| Purpose | Generate proofs | Verify proofs |
| Typical size | ~10GB (millions of blocks) | ~10MB (~100 blocks) |

### MMR Light Structure

```rust
/// Lightweight MMR for verification-only operations
/// 
/// Stores only:
/// - Current peaks (for root calculation)
/// - Recent block hashes (for quick lookups)
/// - Necessary siblings for verification
/// 
/// Does NOT store:
/// - Full node history
/// - Internal parent nodes
/// - Anything needed for proof generation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRLight {
    /// Current peaks (REVERSE order: largest to smallest)
    /// This is all we need to calculate the root
    peaks: Vec<[u8; 32]>,
    
    /// Recent block hashes for quick verification
    /// Key: (block_hash, height)
    /// Value: stored for existence checks
    /// Limited to last 100 blocks
    recent_blocks: HashSet<([u8; 32], u32)>,
    
    /// Current leaf count (chain height + 1)
    /// Used for verification context
    leaf_count: u32,
    
    /// Maximum recent blocks to cache
    max_recent_blocks: usize,
}
```

### Why HashSet?

**Memory Efficiency:**
```
Full MMR at height 1,000,000:
- Stores ~2,000,000 nodes (Vec)
- Memory: 64 MB

MMR Light at same height:
- Stores ~20 peaks + 100 recent blocks
- Memory: ~4 KB (16,000x less!)
```

**Fast Lookups:**
```rust
// O(1) existence check
if mmr_light.has_block(&block_hash, height) {
    // Block verified previously
}

// O(1) peak access
let root = mmr_light.get_root();
```

**Automatic Pruning:**
```rust
// When recent_blocks exceeds max_recent_blocks,
// automatically remove oldest entries
impl MMRLight {
    fn add_recent_block(&mut self, hash: [u8; 32], height: u32) {
        self.recent_blocks.insert((hash, height));
        
        // Prune if too many
        if self.recent_blocks.len() > self.max_recent_blocks {
            // Remove blocks older than (current_height - 100)
            let cutoff = height.saturating_sub(100);
            self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        }
    }
}
```

---

## Phase 1: Multi-Chain Safety + MMR Light (Week 1)

### Day 1-2: ChainId Namespacing

**File**: `src/mmr_client/storage.rs`

**Changes**:
```rust
/// Chain identifier for namespacing storage operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Beacon,
    Shard(u32),
}

/// Updated storage trait with chain namespacing
pub trait LightClientStorage: Send {
    /// Save chain state (now scoped by chain_id)
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) 
        -> Result<(), String>;
    
    /// Load chain state (now scoped by chain_id)
    fn load_state(&self, chain_id: ChainId) 
        -> Result<ChainState, String>;
    
    /// Save individual block (now scoped by chain_id)
    fn save_block(&mut self, chain_id: ChainId, block: &CompleteBatchBlock) 
        -> Result<(), String>;
    
    /// Load block by height (now scoped by chain_id)
    fn load_block(&self, chain_id: ChainId, height: u32) 
        -> Result<CompleteBatchBlock, String>;
    
    // ... other methods similarly updated
}
```

**File**: `src/mmr_client/multi_chain_client.rs`

**Changes**:
```rust
impl MultiChainClient {
    /// Initialize beacon chain with proper namespacing
    pub async fn init_beacon_chain(&mut self, genesis: CompleteBatchBlock) 
        -> Result<(), String> 
    {
        let chain_id = ChainId::Beacon;
        
        // Save genesis with chain_id
        self.storage.save_state(chain_id, &initial_state)?;
        self.storage.save_block(chain_id, &genesis)?;
        
        // Create beacon handler
        let beacon = BeaconChainHandler::new(genesis, ...);
        self.beacon = Some(beacon);
        
        Ok(())
    }
    
    /// Add shard chain with proper namespacing
    pub async fn add_shard_chain(&mut self, shard_id: u32, genesis: CompleteBatchBlock) 
        -> Result<(), String> 
    {
        let chain_id = ChainId::Shard(shard_id);
        
        // Save genesis with chain_id
        self.storage.save_state(chain_id, &initial_state)?;
        self.storage.save_block(chain_id, &genesis)?;
        
        // Create shard handler
        let shard = ShardChainHandler::new(shard_id, genesis, ...);
        self.shards.insert(shard_id, shard);
        
        Ok(())
    }
}
```

**Migration for Existing Implementations**:

```rust
// FileStorage update
impl LightClientStorage for FileStorage {
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) 
        -> Result<(), String> 
    {
        // Use subdirectory per chain
        let chain_dir = match chain_id {
            ChainId::Beacon => self.base_path.join("beacon"),
            ChainId::Shard(id) => self.base_path.join(format!("shard_{}", id)),
        };
        
        std::fs::create_dir_all(&chain_dir)?;
        
        let state_file = chain_dir.join("state.json");
        let json = serde_json::to_string_pretty(state)?;
        std::fs::write(state_file, json)?;
        
        Ok(())
    }
    
    // Similar for other methods...
}

// InMemoryStorage update
impl LightClientStorage for InMemoryStorage {
    // Use HashMap<ChainId, ChainState>
    state: HashMap<ChainId, ChainState>,
    blocks: HashMap<(ChainId, u32), CompleteBatchBlock>,
}
```

---

### Day 3-5: MMR Light Implementation

**New File**: `src/mmr_client/mmr_light.rs`

**Complete Implementation**:

```rust
// ============================================================================
// src/mmr_client/mmr_light.rs - Lightweight MMR for Light Clients
// ============================================================================

use std::collections::HashSet;
use serde::{Serialize, Deserialize};
use crate::mmr_client::proofs::MMRProof;
use crate::mmr_client::verification::{hash_pair, bag_peaks};

/// Lightweight MMR for verification-only operations
/// 
/// Key differences from full MMR:
/// - Uses HashSet instead of Vec for storage
/// - Stores only peaks + recent blocks
/// - No append functionality (light clients don't mine)
/// - Optimized for proof verification
/// 
/// Memory usage: ~4KB vs ~64MB for full MMR at height 1M
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRLight {
    /// Current peaks in REVERSE order (largest to smallest)
    /// This is the minimal data needed to calculate root
    peaks: Vec<[u8; 32]>,
    
    /// Recent block hashes for quick verification
    /// Stores (block_hash, height) pairs
    /// Automatically pruned to max_recent_blocks
    #[serde(skip)]  // Don't serialize HashSet (use vec for persistence)
    recent_blocks: HashSet<([u8; 32], u32)>,
    
    /// Serializable version of recent_blocks
    recent_blocks_vec: Vec<([u8; 32], u32)>,
    
    /// Current leaf count (equals block height + 1)
    leaf_count: u32,
    
    /// Maximum recent blocks to cache
    max_recent_blocks: usize,
}

impl MMRLight {
    /// Create new empty MMR Light
    pub fn new() -> Self {
        Self::with_capacity(100)
    }
    
    /// Create MMR Light with specific recent block capacity
    /// 
    /// # Arguments
    /// * `max_recent_blocks` - Maximum recent blocks to cache (typically 100)
    pub fn with_capacity(max_recent_blocks: usize) -> Self {
        Self {
            peaks: Vec::new(),
            recent_blocks: HashSet::new(),
            recent_blocks_vec: Vec::new(),
            leaf_count: 0,
            max_recent_blocks,
        }
    }
    
    /// Update MMR from verified proof
    /// 
    /// This is the PRIMARY operation for light clients.
    /// After verifying a proof against a trusted root, update our state.
    /// 
    /// # Arguments
    /// * `new_peaks` - New peaks from verified proof
    /// * `new_leaf_count` - New leaf count from verified proof
    /// * `blocks` - Recent blocks to cache (with heights)
    pub fn update_from_verified_proof(
        &mut self,
        new_peaks: Vec<[u8; 32]>,
        new_leaf_count: u32,
        blocks: &[([u8; 32], u32)],
    ) {
        // Update peaks
        self.peaks = new_peaks;
        self.leaf_count = new_leaf_count;
        
        // Add new blocks to recent cache
        for &(block_hash, height) in blocks {
            self.add_recent_block(block_hash, height);
        }
    }
    
    /// Add a block to recent cache
    /// 
    /// Automatically prunes old blocks when cache is full.
    /// 
    /// # Arguments
    /// * `block_hash` - Hash of the block
    /// * `height` - Height of the block
    fn add_recent_block(&mut self, block_hash: [u8; 32], height: u32) {
        self.recent_blocks.insert((block_hash, height));
        
        // Prune if cache is too large
        if self.recent_blocks.len() > self.max_recent_blocks {
            // Keep only blocks with height >= (current - max_recent_blocks)
            let current_height = self.leaf_count.saturating_sub(1);
            let cutoff = current_height.saturating_sub(self.max_recent_blocks as u32);
            
            self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        }
    }
    
    /// Get current MMR root
    /// 
    /// Bags all peaks together to produce the root hash.
    /// This is the hash we verify proofs against.
    pub fn get_root(&self) -> [u8; 32] {
        if self.peaks.is_empty() {
            return [0u8; 32];
        }
        
        // Peaks stored in reverse order, bag left-to-right
        let mut peaks_left_to_right = self.peaks.clone();
        peaks_left_to_right.reverse();
        
        bag_peaks(&peaks_left_to_right)
    }
    
    /// Check if block is in recent cache
    /// 
    /// O(1) lookup to see if we've verified this block recently.
    /// 
    /// # Arguments
    /// * `block_hash` - Hash of the block
    /// * `height` - Height of the block
    /// 
    /// # Returns
    /// true if block is in cache, false otherwise
    pub fn has_recent_block(&self, block_hash: &[u8; 32], height: u32) -> bool {
        self.recent_blocks.contains(&(*block_hash, height))
    }
    
    /// Verify an MMR proof against our current root
    /// 
    /// This is a LIGHTWEIGHT verification that only checks:
    /// 1. Proof peaks match our peaks
    /// 2. Leaf count is valid
    /// 
    /// For full cryptographic verification, use verification::verify_batch_proof()
    /// 
    /// # Arguments
    /// * `proof` - MMR proof to verify
    /// 
    /// # Returns
    /// true if proof is consistent with our state, false otherwise
    pub fn quick_verify_proof(&self, proof: &MMRProof) -> bool {
        // Check leaf count is reasonable
        if proof.leaf_count < self.leaf_count {
            // Proof is from an older state (possible fork)
            return false;
        }
        
        // Check peaks match (if same leaf count)
        if proof.leaf_count == self.leaf_count {
            // Peaks should be identical
            let mut proof_peaks = proof.peaks.clone();
            proof_peaks.reverse();  // Convert to reverse order
            
            return proof_peaks == self.peaks;
        }
        
        // Different leaf count - accept (will be verified cryptographically)
        true
    }
    
    /// Get current leaf count (chain height + 1)
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }
    
    /// Get current height (leaf_count - 1)
    pub fn height(&self) -> u32 {
        self.leaf_count.saturating_sub(1)
    }
    
    /// Get current peaks
    pub fn peaks(&self) -> &Vec<[u8; 32]> {
        &self.peaks
    }
    
    /// Get number of peaks
    pub fn peak_count(&self) -> usize {
        self.peaks.len()
    }
    
    /// Get recent blocks count
    pub fn recent_blocks_count(&self) -> usize {
        self.recent_blocks.len()
    }
    
    /// Clear all state (for reorg or reset)
    pub fn clear(&mut self) {
        self.peaks.clear();
        self.recent_blocks.clear();
        self.recent_blocks_vec.clear();
        self.leaf_count = 0;
    }
    
    /// Prepare for serialization
    /// 
    /// Converts HashSet to Vec for JSON serialization
    pub fn prepare_for_save(&mut self) {
        self.recent_blocks_vec = self.recent_blocks.iter().copied().collect();
    }
    
    /// Restore after deserialization
    /// 
    /// Converts Vec back to HashSet
    pub fn restore_after_load(&mut self) {
        self.recent_blocks = self.recent_blocks_vec.iter().copied().collect();
        self.recent_blocks_vec.clear();
    }
}

// Implement Default
impl Default for MMRLight {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mmr_light_creation() {
        let mmr = MMRLight::new();
        assert_eq!(mmr.leaf_count(), 0);
        assert_eq!(mmr.peak_count(), 0);
        assert_eq!(mmr.get_root(), [0u8; 32]);
    }
    
    #[test]
    fn test_update_from_proof() {
        let mut mmr = MMRLight::new();
        
        // Simulate verified proof for 3 blocks
        let peaks = vec![[1u8; 32], [2u8; 32]];  // 3 leaves = 2 peaks
        let blocks = vec![
            ([10u8; 32], 0),
            ([11u8; 32], 1),
            ([12u8; 32], 2),
        ];
        
        mmr.update_from_verified_proof(peaks.clone(), 3, &blocks);
        
        assert_eq!(mmr.leaf_count(), 3);
        assert_eq!(mmr.height(), 2);
        assert_eq!(mmr.peak_count(), 2);
        assert_eq!(mmr.peaks(), &peaks);
        assert_eq!(mmr.recent_blocks_count(), 3);
    }
    
    #[test]
    fn test_recent_block_cache() {
        let mut mmr = MMRLight::with_capacity(3);
        
        // Add 3 blocks
        mmr.add_recent_block([1u8; 32], 0);
        mmr.add_recent_block([2u8; 32], 1);
        mmr.add_recent_block([3u8; 32], 2);
        
        assert_eq!(mmr.recent_blocks_count(), 3);
        assert!(mmr.has_recent_block(&[1u8; 32], 0));
        assert!(mmr.has_recent_block(&[2u8; 32], 1));
        assert!(mmr.has_recent_block(&[3u8; 32], 2));
        
        // Add 4th block - should prune oldest
        mmr.add_recent_block([4u8; 32], 3);
        mmr.leaf_count = 4;  // Update for pruning logic
        
        // Oldest blocks should be pruned
        assert!(!mmr.has_recent_block(&[1u8; 32], 0));
        assert!(mmr.has_recent_block(&[4u8; 32], 3));
    }
    
    #[test]
    fn test_serialization() {
        let mut mmr = MMRLight::new();
        
        // Add some data
        mmr.update_from_verified_proof(
            vec![[1u8; 32], [2u8; 32]],
            3,
            &[([10u8; 32], 0), ([11u8; 32], 1)],
        );
        
        // Prepare for save
        mmr.prepare_for_save();
        
        // Serialize
        let json = serde_json::to_string(&mmr).unwrap();
        
        // Deserialize
        let mut mmr2: MMRLight = serde_json::from_str(&json).unwrap();
        
        // Restore after load
        mmr2.restore_after_load();
        
        // Verify same state
        assert_eq!(mmr2.leaf_count(), 3);
        assert_eq!(mmr2.peak_count(), 2);
        assert_eq!(mmr2.recent_blocks_count(), 2);
    }
}

/*
===============================================================================
MMR LIGHT - DESIGN RATIONALE
===============================================================================

WHY HASHSET INSTEAD OF VEC?
============================

Memory Efficiency:
- Full MMR: Stores ALL nodes (leaves + parents)
- MMR Light: Stores only peaks + recent blocks
- Example: At height 1M:
  * Full MMR: ~2M nodes × 32 bytes = 64 MB
  * MMR Light: ~20 peaks + 100 blocks × 32 bytes = 4 KB
  * Savings: 16,000x

Fast Lookups:
- Vec: O(n) for existence check
- HashSet: O(1) for existence check
- Typical operation: "Have I seen this block?" → O(1) with HashSet

Automatic Pruning:
- HashSet makes it easy to remove old entries
- Just filter by height when cache is full
- No need to shift elements like in Vec


WHY NO APPEND?
===============

Light clients don't mine blocks!
- They only VERIFY blocks from full nodes
- No need for append logic
- Simpler code, fewer bugs


USAGE PATTERN
=============

1. Light client requests proof from full node
2. Full node generates proof using FULL MMR (Vec-based)
3. Light client receives proof
4. Light client verifies proof cryptographically
5. Light client updates MMR Light with verified state
6. MMR Light stores new peaks + recent blocks

Example:
```rust
// Light client workflow
let proof = fetch_proof_from_full_node().await?;

// Verify proof cryptographically
if verify_batch_proof(&proof)? {
    // Extract verified state
    let new_peaks = proof.peaks.clone();
    let new_leaf_count = proof.leaf_count;
    let blocks = proof.blocks.iter()
        .map(|b| (b.hash, b.height))
        .collect::<Vec<_>>();
    
    // Update our MMR Light
    mmr_light.update_from_verified_proof(new_peaks, new_leaf_count, &blocks);
    
    // Now we have current root
    let root = mmr_light.get_root();
}
```


COMPARISON TO FULL MMR
=======================

| Feature | Full MMR | MMR Light |
|---------|----------|-----------|
| Storage | Vec<[u8; 32]> | HashSet + Vec<peaks> |
| Memory | O(n) | O(log n + k) |
| Append | ✅ O(log n) | ❌ Not supported |
| Verify | ✅ O(log n) | ✅ O(log n) |
| Get Root | ✅ O(p) | ✅ O(p) |
| Generate Proof | ✅ O(log n) | ❌ Not supported |
| Purpose | Mining/full node | Light client |
| Typical Size | 64 MB | 4 KB |

Where:
- n = total blocks
- p = number of peaks (~log n)
- k = recent block cache size (100)


FUTURE: HYBRID MMR
==================

For mining pools, we might implement a hybrid:

```rust
pub struct MMRHybrid {
    // Recent blocks in memory (fast append)
    recent: VecDeque<[u8; 32]>,
    
    // Historical blocks on disk (HashSet for lookup)
    historical: HashSet<([u8; 32], u32)>,
    
    // Threshold for moving to historical
    recent_threshold: usize,
}
```

Benefits:
- Fast append (VecDeque is O(1))
- Fast lookup (HashSet is O(1))
- Memory efficient (only keep recent in memory)
- Best of both worlds

===============================================================================
*/
```

---

### Day 6: Integration

**Update ChainHandler to use MMR Light**:

```rust
// src/mmr_client/chain_handler.rs

use crate::mmr_client::mmr_light::MMRLight;

pub struct ChainState {
    pub chain_type: ChainType,
    pub chain_id: u32,
    pub tip: CompleteBatchBlock,
    pub chain_weight: u128,
    pub max_cache_size: usize,
    pub recent_blocks: HashMap<u32, CompleteBatchBlock>,
    
    // REPLACED: pub mmr_siblings: HashMap<u32, [u8; 32]>,
    // NEW: Lightweight MMR for verification
    pub mmr_light: MMRLight,
}

impl ChainHandler {
    pub fn apply_chain_summary(
        &mut self,
        summary: MMRChainSummary,
    ) -> Result<bool, String> {
        // Verify proof first
        if !verify_batch_proof(&summary.recent_blocks_proof) {
            return Err("Invalid chain summary proof".to_string());
        }
        
        // Extract verified data
        let new_peaks = summary.recent_blocks_proof.peaks.clone();
        let new_leaf_count = summary.recent_blocks_proof.leaf_count;
        let blocks: Vec<([u8; 32], u32)> = summary.recent_blocks_proof
            .batch_blocks
            .iter()
            .map(|b| (b.hash(), b.height()))
            .collect();
        
        // Update MMR Light
        self.state.mmr_light.update_from_verified_proof(
            new_peaks,
            new_leaf_count,
            &blocks,
        );
        
        // Update tip and chain weight
        self.state.tip = summary.tip_block.to_complete_batch_block();
        self.state.chain_weight = summary.chain_weight;
        
        // Persist state
        self.storage.save_state(&self.state)?;
        
        Ok(true)
    }
}
```

**Export MMRLight from mod.rs**:

```rust
// src/mmr_client/mod.rs

pub mod mmr_light;

pub use mmr_light::MMRLight;
```

---

## Phase 2: SQLite Implementation (Week 2-3)

### Goals
- Production-ready persistence
- Multi-chain support built-in
- Mobile-friendly (small file, low memory)
- ACID transactions

### Schema

```sql
-- Chain metadata table
CREATE TABLE chains (
    chain_id TEXT PRIMARY KEY,  -- "beacon" or "shard_5"
    chain_type TEXT NOT NULL,   -- "beacon" or "shard"
    shard_id INTEGER,            -- NULL for beacon, shard ID for shards
    created_at INTEGER NOT NULL
);

-- Chain state table (one row per chain)
CREATE TABLE chain_state (
    chain_id TEXT PRIMARY KEY,
    leaf_count INTEGER NOT NULL,
    chain_weight BLOB NOT NULL,  -- u128 as 16 bytes
    tip_height INTEGER NOT NULL,
    tip_hash BLOB NOT NULL,
    mmr_root BLOB NOT NULL,
    peaks_json TEXT NOT NULL,     -- JSON array of peak hashes
    updated_at INTEGER NOT NULL,
    
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

-- Blocks table (many rows per chain)
CREATE TABLE blocks (
    chain_id TEXT NOT NULL,
    height INTEGER NOT NULL,
    block_hash BLOB NOT NULL,
    block_data BLOB NOT NULL,     -- Bincode serialized CompleteBatchBlock
    timestamp INTEGER NOT NULL,
    
    PRIMARY KEY (chain_id, height),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

-- Index for hash lookups
CREATE INDEX idx_blocks_hash ON blocks(chain_id, block_hash);

-- MMR Light recent blocks cache (optional, can be in-memory only)
CREATE TABLE mmr_recent_blocks (
    chain_id TEXT NOT NULL,
    block_hash BLOB NOT NULL,
    height INTEGER NOT NULL,
    cached_at INTEGER NOT NULL,
    
    PRIMARY KEY (chain_id, block_hash),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);
```

### Implementation

**New File**: `src/mmr_client/sqlite_storage.rs`

---

## Phase 3: Pruning & Optimization (Week 4)

### Auto-Pruning

```rust
impl SqliteStorage {
    /// Prune old blocks, keep only recent N
    pub fn prune_old_blocks(&mut self, chain_id: ChainId, keep_last: u32) 
        -> Result<u64, String> 
    {
        let chain_id_str = chain_id.to_string();
        
        // Get current height
        let current_height: u32 = self.conn.query_row(
            "SELECT tip_height FROM chain_state WHERE chain_id = ?",
            params![chain_id_str],
            |row| row.get(0),
        )?;
        
        // Calculate cutoff
        let cutoff = current_height.saturating_sub(keep_last);
        
        // Delete old blocks
        let deleted = self.conn.execute(
            "DELETE FROM blocks WHERE chain_id = ? AND height < ?",
            params![chain_id_str, cutoff],
        )?;
        
        // Vacuum to reclaim space
        self.conn.execute("VACUUM", [])?;
        
        Ok(deleted as u64)
    }
}
```

---

## Phase 4: Checkpoints (Week 5)

### Checkpoint Format

```rust
#[derive(Serialize, Deserialize)]
pub struct Checkpoint {
    /// Chain identifier
    pub chain_id: ChainId,
    
    /// Block height at checkpoint
    pub height: u32,
    
    /// Block hash at checkpoint
    pub block_hash: [u8; 32],
    
    /// MMR root at checkpoint
    pub mmr_root: [u8; 32],
    
    /// MMR peaks at checkpoint
    pub peaks: Vec<[u8; 32]>,
    
    /// Chain weight at checkpoint
    pub chain_weight: u128,
    
    /// Timestamp when created
    pub created_at: u64,
    
    /// Optional signature (from trusted authority)
    pub signature: Option<Vec<u8>>,
}
```

---

## Summary of Changes

### New Files Created
1. `src/mmr_client/mmr_light.rs` - HashSet-based MMR
2. `src/mmr_client/sqlite_storage.rs` - SQLite backend
3. `src/mmr_client/checkpoints.rs` - Checkpoint management

### Modified Files
1. `src/mmr_client/storage.rs` - Add ChainId parameter
2. `src/mmr_client/chain_handler.rs` - Use MMRLight
3. `src/mmr_client/multi_chain_client.rs` - Use scoped storage
4. `src/mmr_client/mod.rs` - Export new types

### Deletions
- None (backward compatible via adapters)

---

## Timeline

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Multi-chain safety + MMR Light | ✅ No collisions, HashSet MMR |
| 2-3 | SQLite implementation | ✅ Production storage |
| 4 | Pruning & optimization | ✅ Bounded storage |
| 5 | Checkpoints | ✅ Fast bootstrap |

**Total: 5 weeks**

---

## Testing Strategy

### Unit Tests
```rust
#[test]
fn test_multi_chain_no_collision() {
    let mut storage = SqliteStorage::new_in_memory()?;
    
    // Store same height, different chains
    storage.save_block(ChainId::Beacon, &block_100)?;
    storage.save_block(ChainId::Shard(5), &block_100)?;
    
    // Verify no collision
    let b1 = storage.load_block(ChainId::Beacon, 100)?;
    let b2 = storage.load_block(ChainId::Shard(5), 100)?;
    assert_ne!(b1, b2);
}

#[test]
fn test_mmr_light_memory_efficiency() {
    let mmr = MMRLight::new();
    
    // Simulate 1M blocks
    mmr.update_from_verified_proof(
        generate_peaks_for_height(1_000_000),
        1_000_000,
        &generate_recent_100_blocks(),
    );
    
    // Memory should be < 10KB
    let memory_bytes = estimate_memory_usage(&mmr);
    assert!(memory_bytes < 10_000);
}
```

---

## Verification

After Phase 1 completion, verify:
```bash
# No compilation errors
cargo build

# All tests pass
cargo test mmr_light
cargo test storage

# Multi-chain works
cargo run --example multi_chain_demo
```

Expected output:
```
✅ Beacon chain initialized
✅ Shard 0 initialized
✅ Shard 1 initialized
✅ No storage collisions detected
✅ MMR Light using 4KB memory
✅ Full MMR using 64MB memory
✅ Memory savings: 16,000x
```
