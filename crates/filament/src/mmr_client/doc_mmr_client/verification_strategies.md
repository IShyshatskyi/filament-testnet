# MMR Proof Design - Verification Strategies

> ⚠️ **Currency note (added Jul 3, 2026):** design-era rationale for the `VerificationStrategy` enum (Paranoid / Full / Light), which remains live code in `verification.rs`. Written before the WeightedHash migration (Mar 2026) and Phase 10 — type names and proof formats mentioned here may predate the `Weighted*` types. For current behaviour, [`docs/reference.md`](../../../../../docs/reference.md) (repo root) and the source win.


## Core Understanding

### What Light Clients Actually Verify

**Chain Weight Verification (Critical for Security):**
```
To prove our chain is heaviest:
1. Verify PoW for each block (hash < target)
2. Sum difficulties → total chain weight
3. Compare to competing chains
4. Choose heaviest chain

For PoW verification, we need:
- Complete header (all fields)
- Beacon aux header (version, timestamp, nonce, prev_hash, merged_mining_root, bits)
- All merkle proofs
→ Need EVERYTHING to recalculate PoW hash
```

**Trust Model Trade-offs:**
```
Recent blocks (< 100 deep):
- MUST verify PoW (security critical)
- MUST verify chain weight
- Need full headers

Deep blocks (> 1000 deep):
- Can SKIP PoW verification (trust chain weight already verified)
- Only verify MMR inclusion
- Can use simplified headers
```

---

## Header Field Analysis

### Current Shard BlockHeader

```rust
pub struct BlockHeader {
    // === MMR linking ===
    pub height: u32,                        // Block position
    pub prev_mmr_root: [u8; 32],           // Links to parent (real previous block link)
    pub current_mmr_root: [u8; 32],        // MMR after this block (NOT hashable)
    
    // === Block identity ===
    pub prev_block_hash: [u8; 32],         // PLACEHOLDER (can store PoW hash)
    pub merkle_root: [u8; 32],             // Transaction commitment
    pub difficulty: u32,                    // PoW target
    pub chain_weight: u128,                 // Cumulative difficulty
    
    // === PoW verification (REQUIRED for chain weight proof) ===
    pub beacon_header: BeaconHeader,        // 88 bytes - needed for PoW hash
    pub shard_merkle_proof: Vec<[u8; 32]>, // ~10 hashes - prove to merged mining tree
    pub orange_encoding: OrangeTreeEncoding, // ~20 bytes - active shard structure
    pub merged_mining_proof: Vec<[u8; 32]>, // ~20 hashes - prove to beacon
    pub merged_mining_number: u32,          // Active shard count
    
    // === Derived (not stored) ===
    // pub shard_id: u16,  // NOT STORED - derived from PoW hash via hash sorting
}
```

**Total: ~1,226 bytes (will grow to ~2,200 bytes)**

### What Each Field Does

**For PoW Verification:**
```
PoW hash = SHA256d(beacon_header.serialize_for_mining())

Where beacon_header contains:
- version, timestamp, nonce (mining parameters)
- prev_block_hash (chain link)
- merged_mining_root (commitment to all shards)
- bits (difficulty target)

To verify PoW:
1. Reconstruct beacon_header from stored data
2. Calculate PoW hash
3. Verify: PoW_hash < difficulty_target
4. Derive shard_id from PoW_hash via hash sorting
5. Verify shard_merkle_proof: shard_id → merged_mining_root
6. Verify merged_mining_proof: full merkle path
```

**Without ANY field, PoW verification fails!**

---

## Optimization Strategy: Verification Levels

### Level 1: Full Verification (Recent Blocks)

**Used for: Chain weight proof, recent sync**

```rust
pub struct FullShardBlockData {
    // Core
    pub height: u32,
    pub prev_mmr_root: [u8; 32],
    pub current_mmr_root: [u8; 32],
    pub merkle_root: [u8; 32],
    pub difficulty: u32,
    pub chain_weight: u128,
    
    // PoW verification (COMPLETE)
    pub beacon_header: BeaconHeader,        // 88 bytes
    pub shard_merkle_proof: Vec<[u8; 32]>,  // ~320 bytes
    pub orange_encoding: OrangeTreeEncoding, // ~20 bytes
    pub merged_mining_proof: Vec<[u8; 32]>, // ~640 bytes
    pub merged_mining_number: u32,
}
// Total: ~1,226 bytes (grows to ~2,200 bytes)
```

**Purpose:**
- Verify PoW hash meets difficulty
- Prove block contributes to chain weight
- Essential for chain weight proofs

---

### Level 2: Light Verification (Deep Historical Blocks)

**Used for: Old blocks where chain weight already trusted**

**Optimization: Store PoW hash, skip beacon_aux**

```rust
pub struct LightShardBlockData {
    // Core (same)
    pub height: u32,
    pub prev_mmr_root: [u8; 32],
    pub current_mmr_root: [u8; 32],
    pub merkle_root: [u8; 32],
    pub difficulty: u32,
    pub chain_weight: u128,
    
    // PoW hash (pre-calculated, stored in prev_block_hash placeholder)
    pub pow_hash: [u8; 32],  // Stored instead of recalculating
    
    // Omitted (saves ~1,000 bytes):
    // - beacon_header (can't recalculate, but not needed)
    // - shard_merkle_proof (can't verify, but trusted)
    // - merged_mining_proof (can't verify, but trusted)
    // - orange_encoding (can't verify, but trusted)
    // - merged_mining_number (can't verify, but trusted)
}
// Total: ~194 bytes
```

**Trade-off:**
- ✅ 85% bandwidth savings (1,226 → 194 bytes)
- ❌ Can't verify PoW (must trust chain weight)
- ✅ Can verify MMR inclusion
- ✅ Can verify transaction inclusion (via merkle_root)

**When to use:**
- Blocks > 1000 deep (where reorg impossible)
- After chain weight already verified
- For transaction history lookup

---

### Level 3: Minimal (Pure MMR Verification)

**Used for: Checkpoints, summaries where only MMR matters**

```rust
pub struct MinimalBlockData {
    pub height: u32,
    pub current_mmr_root: [u8; 32],
    pub pow_hash: [u8; 32],  // For shard_id derivation
}
// Total: 68 bytes
```

**Trade-off:**
- ✅ 94% bandwidth savings (1,226 → 68 bytes)
- ❌ Can't verify anything except MMR inclusion
- ✅ Good for checkpoints every N blocks

---

## Proposed Proof Types

### Chain Weight Proof (MUST use Full)

```rust
pub struct MMRChainWeightProof {
    pub target_block: FullShardBlockData,      // Need PoW verification
    pub start_height: u32,
    pub end_height: u32,
    pub total_weight: u128,
    pub blocks: Vec<FullShardBlockData>,       // ALL blocks need PoW data
    pub range_proof: MMRRangeProof,
}
```

**Size for 100 blocks:**
- 100 × 1,226 = 122.6 KB (current)
- 100 × 2,200 = 220 KB (future)

**No optimization possible - need everything for PoW verification**

---

### Chain Summary (Mixed strategy)

```rust
pub struct MMRChainSummary {
    pub tip_block: FullShardBlockData,         // Recent - need PoW
    pub chain_weight: u128,
    pub recent_blocks_proof: MMRBatchProof {
        pub batch_blocks: Vec<FullShardBlockData>,  // Recent - need PoW
        pub siblings: Vec<[u8; 32]>,
    },
}
```

**Size for 100 recent blocks:**
- Same as chain weight proof: 122.6 KB → 220 KB
- No optimization without losing security

---

### Historical Range Proof (Can use Light)

```rust
pub struct MMRRangeProof {
    pub genesis_hash: [u8; 32],
    pub target_block: FullShardBlockData,      // Target always full
    pub start_height: u32,
    pub end_height: u32,
    pub blocks: Vec<LightShardBlockData>,      // Historical can be light!
    pub left_boundary: Vec<[u8; 32]>,
    pub right_boundary: Vec<[u8; 32]>,
}
```

**Size for 100 historical blocks:**
- Full: 100 × 1,226 = 122.6 KB
- Light: 100 × 194 = 19.4 KB
- **Savings: 103.2 KB (84%)**

**Use case:**
- Syncing blocks 1000-1100 (old, chain weight already proven)
- Client already verified chain weight
- Just needs blocks for transaction history

---

## Implementation Design

### Tagged Enum with Verification Levels

```rust
pub enum BlockData {
    Beacon(BeaconBlockData),           // 229 bytes
    ShardFull(FullShardBlockData),     // 1,226 bytes (→ 2,200 future)
    ShardLight(LightShardBlockData),   // 194 bytes
    ShardMinimal(MinimalBlockData),    // 68 bytes
}

impl BlockData {
    /// Get verification level
    pub fn verification_level(&self) -> VerificationLevel {
        match self {
            BlockData::ShardFull(_) => VerificationLevel::Full,
            BlockData::ShardLight(_) => VerificationLevel::Light,
            BlockData::ShardMinimal(_) => VerificationLevel::Minimal,
            BlockData::Beacon(_) => VerificationLevel::Full,
        }
    }
    
    /// Can verify PoW?
    pub fn can_verify_pow(&self) -> bool {
        matches!(self, BlockData::ShardFull(_) | BlockData::Beacon(_))
    }
}
```

---

## Request Pattern

```rust
pub enum ProofRequest {
    ChainWeight {
        start: u32,
        end: u32,
        // Always returns Full blocks (need PoW)
    },
    
    ChainSummary {
        recent_count: usize,
        // Always returns Full blocks (need PoW)
    },
    
    HistoricalRange {
        start: u32,
        end: u32,
        verification_level: VerificationLevel,  // Client chooses!
    },
}

pub enum VerificationLevel {
    Full,     // Need PoW verification (recent blocks, chain weight)
    Light,    // Trust chain weight (historical blocks)
    Minimal,  // Checkpoints only
}
```

---

## Bandwidth Savings Summary

### Scenario 1: Initial Sync (verify chain weight)
**10,000 blocks with full verification**
- Must use Full: 10,000 × 2,200 = 22 MB
- No savings possible (need PoW verification)

### Scenario 2: Historical Sync (chain weight trusted)
**10,000 old blocks for transaction history**
- Full: 10,000 × 2,200 = 22 MB
- Light: 10,000 × 194 = 1.94 MB
- **Savings: 20 MB (91%)**

### Scenario 3: Multi-shard historical sync
**10 shards × 10,000 old blocks**
- Full: 220 MB
- Light: 19.4 MB
- **Savings: 200 MB (91%)**

---

## Recommendation

**Use verification-level based design:**

1. **Always use Full for:**
   - Chain weight proofs
   - Recent blocks (< 100-1000 deep)
   - Initial sync
   - Any PoW verification

2. **Use Light for:**
   - Historical blocks (> 1000 deep)
   - Transaction history lookup
   - When chain weight already verified

3. **Use Minimal for:**
   - Checkpoint summaries
   - Very old block references

**Implementation:**
```rust
pub enum BlockData {
    Beacon(BeaconBlockData),
    ShardFull(FullShardBlockData),   // Complete PoW verification
    ShardLight(LightShardBlockData), // Skip PoW, store hash
}
```

This gives massive savings (91%) for historical data while maintaining full security for chain weight verification.

Is this the right approach?
