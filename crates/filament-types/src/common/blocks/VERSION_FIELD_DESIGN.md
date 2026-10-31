# Bitcoin-Style Version Field with Hash-Sorting Parameter (s) and Vote Flags

## Overview

The beacon block header's `version` field follows Bitcoin's approach of encoding multiple pieces of information in a single 32-bit integer. This document explains the design, rationale, and usage of this field.

## Version Field Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    32-bit version field                             │
├────────┬────────┬────────┬─────────────────────────────────────────┤
│  0-3   │   4    │   5    │              6-31                       │
│ 4 bits │ 1 bit  │ 1 bit  │            26 bits                      │
├────────┼────────┼────────┼─────────────────────────────────────────┤
│   s    │ vote_k │vote_exp│      Base version number                │
│ (0-15) │ (0/1)  │ (0/1)  │      (0-67,108,863)                     │
└────────┴────────┴────────┴─────────────────────────────────────────┘
```

### Bit Layout

- **Bits 0-3**: Hash-sorting number (s) - 4 bits, values 0-15
- **Bit 4**: Vote K flag - 1 bit, voting on k parameter changes
- **Bit 5**: Vote Expand flag - 1 bit, voting on network expansion
- **Bits 6-31**: Base version number - 26 bits, reserved for protocol versions

### Example Values

| Description | Base | S | VK | VE | Hex Value | Binary (last 8 bits) |
|-------------|------|---|----|----|-----------|---------------------|
| V1, s=0, no votes | 1 | 0 | 0 | 0 | 0x00000040 | 01 00 0000 |
| V1, s=4, no votes | 1 | 4 | 0 | 0 | 0x00000044 | 01 00 0100 |
| V1, s=4, vote_k | 1 | 4 | 1 | 0 | 0x00000054 | 01 01 0100 |
| V1, s=4, vote_exp | 1 | 4 | 0 | 1 | 0x00000064 | 01 10 0100 |
| V1, s=4, both votes | 1 | 4 | 1 | 1 | 0x00000074 | 01 11 0100 |
| V2, s=8, both votes | 2 | 8 | 1 | 1 | 0x000000F8 | 10 11 1000 |

## Hash-Sorting Number (s)

### Purpose

The hash-sorting number `s` determines how many bits of a block's proof-of-work hash are used to assign blocks to shards. This enables:

1. **Random shard assignment** - Miners don't know which shard they're mining for until PoW is found
2. **Merged mining** - A single proof-of-work can be valid for multiple shards
3. **Fair distribution** - Blocks are randomly distributed across shards
4. **Dynamic scaling** - Network can add shards by increasing s

### Why "s" instead of "k"?

The letter "k" is already used for another parameter in the system (the k coefficient in merged mining weight calculations). To avoid confusion, we use "s" for the hash-sorting number:
- **s** = hash-sorting number (determines shards from PoW hash)
- **k** = separate parameter for merged mining weight (already exists)

### Formula

Maximum shards = 2^s - 1

(The value 0 is reserved, so actual shard IDs range from 0 to 2^s - 2)

### Relationship to Hash-Sorting

When a miner finds a valid proof-of-work:

1. Extract the last s bits from the block hash
2. If bits == 0: Reserved (no shard assignment)
3. If bits > 0: Shard ID = (bits - 1)

Example with s=4 (4 bits = 16 values):
- Hash bits 0000: Reserved
- Hash bits 0001: Shard 0
- Hash bits 0010: Shard 1
- ...
- Hash bits 1111: Shard 14

Total: 15 shards (shard IDs 0-14)

### S Values for Different Network Sizes

| S | Max Shards | Use Case | Difficulty Multiplier |
|---|------------|----------|----------------------|
| 0 | 0 | Beacon-only, no sharding | 1x |
| 4 | 15 | Small test networks | 16x |
| 6 | 63 | Small production networks | 64x |
| 8 | 255 | Medium networks | 256x |
| 10 | 1,023 | Large networks | 1,024x |
| 12 | 4,095 | Very large networks | 4,096x |
| 15 | 32,767 | Maximum theoretical | 32,768x |

**Note**: Difficulty multiplier represents how much harder it is to solo mine for a specific shard compared to pool mining (which accepts any shard).

## Vote Flags

### Vote K Flag (Bit 4)

The vote_k_flag is used for BIP 9-style voting on changes to the k parameter (which is separate from s, the hash-sorting number).

**Purpose**: Miners signal their preference for k parameter changes by setting this bit in blocks they mine.

**Values**:
- `0`: No vote or vote against k change proposal
- `1`: Vote for k change proposal

**Example Use Cases**:
- Adjusting merged mining weight calculations
- Modifying k coefficient in reward distribution
- Changing k-related consensus parameters

### Vote Expand Flag (Bit 5)

The vote_expand_flag is used for voting on network expansion proposals.

**Purpose**: Miners signal their preference for network expansion (adding shards, increasing capacity, etc.) by setting this bit.

**Values**:
- `0`: No vote or vote against expansion
- `1`: Vote for expansion

**Example Use Cases**:
- Increasing s value (adding more shards)
- Enabling new shard chains
- Activating cross-shard features
- Approving capacity increases

### Voting Mechanism

Similar to Bitcoin's BIP 9:

1. **Proposal Period**: A change is proposed (e.g., increase s from 4 to 5)
2. **Voting Period**: Miners signal support by setting the appropriate flag
3. **Threshold**: If ≥ 95% of blocks in a 2016-block window have the flag set
4. **Lock-in**: Change is scheduled for activation
5. **Activation**: Change takes effect after grace period

**Example**:
```rust
// Miner supports increasing s and changing k
let version = BlockVersion::new(1, 4, true, true);

// Miner only supports k change, not expansion
let version = BlockVersion::new(1, 4, true, false);

// Miner doesn't support any changes
let version = BlockVersion::new(1, 4, false, false);
```

## Design Rationale

### Why Embed s and Vote Flags in Version?

1. **Consensus Critical**: All three fields affect consensus rules
2. **PoW Protected**: Version is in the 80-byte mining header, covered by proof-of-work
3. **No Extra Fields**: Reuses existing version field, no protocol changes needed
4. **Bitcoin Compatibility**: Follows Bitcoin's BIP 9 pattern
5. **Efficient**: Single u32 field carries multiple pieces of information

### Bit Allocation Rationale

**s (4 bits)**:
- Range: 0-15 sufficient (15 bits → 32,767 shards maximum)
- Most networks won't exceed s=12 (4,095 shards)

**Vote flags (2 bits)**:
- Binary choices (yes/no) require only 1 bit each
- Allows two independent voting mechanisms
- Can be extended to 4-8 flags in bits 4-11 if needed

**Base version (26 bits)**:
- 67,108,863 possible version numbers
- More than sufficient for protocol evolution
- Can accommodate centuries of upgrades

## Implementation

### Basic Usage

```rust
use common::blocks::BlockVersion;

// Create version with base=1, s=4, no votes
let version = BlockVersion::new(1, 4, false, false);

// Extract values
assert_eq!(version.base_version(), 1);
assert_eq!(version.s(), 4);
assert_eq!(version.vote_k_flag(), false);
assert_eq!(version.vote_expand_flag(), false);
assert_eq!(version.max_shards(), 15);

// Convert to/from u32
let raw: u32 = version.as_u32();
let restored = BlockVersion::from_u32(raw);
```

### Creating Versions with Votes

```rust
// Vote for k change only
let version = BlockVersion::new(1, 4, true, false);
assert_eq!(version.vote_k_flag(), true);

// Vote for expansion only
let version = BlockVersion::new(1, 4, false, true);
assert_eq!(version.vote_expand_flag(), true);

// Vote for both
let version = BlockVersion::new(1, 4, true, true);
assert_eq!(version.vote_k_flag(), true);
assert_eq!(version.vote_expand_flag(), true);
```

### In Beacon Headers

```rust
use common::blocks::{BlockVersion, BeaconBlockCandidateHeader};

// Miner supports expansion but not k change
let version = BlockVersion::new(1, 4, false, true);

let header = BeaconBlockCandidateHeader::new(
    version.as_u32(),  // version
    timestamp,
    height,
    // ... other fields
);

// Extract fields from header
let s = BlockVersion::from_u32(header.version).s();
let vote_k = BlockVersion::from_u32(header.version).vote_k_flag();
let vote_expand = BlockVersion::from_u32(header.version).vote_expand_flag();
```

### Validation with Vote Counting

```rust
fn count_votes_in_window(
    blocks: &[BeaconBlock],
    window_size: usize,
) -> (usize, usize) {
    let mut vote_k_count = 0;
    let mut vote_expand_count = 0;
    
    for block in blocks.iter().take(window_size) {
        let version = BlockVersion::from_u32(block.header.version);
        if version.vote_k_flag() {
            vote_k_count += 1;
        }
        if version.vote_expand_flag() {
            vote_expand_count += 1;
        }
    }
    
    (vote_k_count, vote_expand_count)
}

fn check_activation_threshold(
    vote_count: usize,
    window_size: usize,
    threshold_percent: f64,
) -> bool {
    let threshold = (window_size as f64 * threshold_percent / 100.0) as usize;
    vote_count >= threshold
}
```

## Helper Functions

For code that can't use `BlockVersion` directly:

```rust
use common::blocks::{
    extract_s_from_version, 
    extract_vote_k_from_version,
    extract_vote_expand_from_version,
    make_version
};

// Extract s from raw u32
let s = extract_s_from_version(version_u32);

// Extract vote flags
let vote_k = extract_vote_k_from_version(version_u32);
let vote_expand = extract_vote_expand_from_version(version_u32);

// Create version from parts
let version_u32 = make_version(1, 4, true, false);
```

## Consensus Rules

### Rule 1: S Must Match Across Merged Mining Tree

All shard blocks merged-mined with a beacon block must use the same s value:

```rust
// Beacon block has s=4
let beacon_version = BlockVersion::new(1, 4, false, false);

// ALL shard blocks in the tree must also have s=4
for shard_block in merged_tree {
    let shard_s = extract_s_from_version(shard_block.beacon_header.version);
    assert_eq!(shard_s, beacon_version.s());
}
```

### Rule 2: Vote Flags Don't Affect Validation

Vote flags are for signaling only - they don't change block validity:

```rust
// These two blocks are equally valid (same s, different votes)
let block1 = BlockVersion::new(1, 4, true, true);
let block2 = BlockVersion::new(1, 4, false, false);

// Both pass validation as long as s=4 is correct
```

### Rule 3: S Changes Must Be Coordinated

When s changes (network expansion), all participants must upgrade:

```rust
// Before: s=4 (15 shards)
let old_s = 4;

// After: s=5 (31 shards)  
let new_s = 5;

// This must happen at a specific block height where everyone upgrades
```

### Rule 4: Vote Activation Requires Supermajority

Changes require ≥95% support in a 2016-block window:

```rust
const VOTING_WINDOW: usize = 2016;
const ACTIVATION_THRESHOLD: f64 = 95.0;

let (vote_k_count, vote_expand_count) = count_votes_in_window(blocks, VOTING_WINDOW);

let k_activates = check_activation_threshold(vote_k_count, VOTING_WINDOW, ACTIVATION_THRESHOLD);
let expand_activates = check_activation_threshold(vote_expand_count, VOTING_WINDOW, ACTIVATION_THRESHOLD);
```

## Security Considerations

### 1. All Fields are PoW-Protected

All fields (s, vote_k, vote_expand, base_version) are part of the 80-byte mining header:
- Covered by proof-of-work
- Miners cannot change without re-mining
- Full nodes verify all fields

### 2. Vote Manipulation Requires Mining Power

To manipulate voting:
- Attacker needs >5% hash rate to prevent activation
- Attacker needs >50% hash rate to force activation (but then they control the network anyway)
- Economic incentives align miners with network health

### 3. S Value Affects Security Budget

Higher s means:
- More shards
- Lower security per shard (hash rate divided)
- Higher 51% attack risk per shard

Formula: `Security per shard = Total hash rate / 2^s`

### 4. Extraction is Deterministic

Bit extraction is simple and deterministic:
```rust
let s = (version & 0x0F) as u8;              // Bits 0-3
let vote_k = (version & 0x10) != 0;          // Bit 4
let vote_expand = (version & 0x20) != 0;     // Bit 5
let base = (version & 0xFFFFFFC0) >> 6;      // Bits 6-31
```

No floating point, no ambiguity, always the same result.

## Migration Guide

### From Raw u32

If you're currently using `u32` directly:

```rust
// Old code
let version: u32 = 1;

// New code - create with s and vote flags
let version = BlockVersion::new(1, 4, false, false).as_u32();

// Or extract from existing
let s = BlockVersion::from_u32(old_version).s();
let vote_k = BlockVersion::from_u32(old_version).vote_k_flag();
```

### Backward Compatibility

The `BlockVersion` type is fully backward compatible:

```rust
// Old code still works
let header = BeaconBlockCandidateHeader {
    version: 1,  // Raw u32
    // ...
};

// Can extract fields later
let s = extract_s_from_version(header.version);
let vote_k = extract_vote_k_from_version(header.version);
```

## Frequently Asked Questions

### Q: Why "s" instead of "k"?

**A**: The letter "k" is already occupied by another parameter in the merged mining system (k coefficient). Using "s" for "hash-sorting" avoids confusion and makes the code clearer.

### Q: Can miners set vote flags without affecting their blocks?

**A**: Yes! Vote flags are purely for signaling. Blocks with different vote flag values are all equally valid as long as s matches.

### Q: What happens if a vote fails?

**A**: Nothing changes. The network continues with current parameters. The proposal can be re-submitted later or modified.

### Q: Can s and vote flags change independently?

**A**: Yes. S changes require hard coordination (everyone upgrades). Vote flags just signal preference for future changes.

### Q: How are vote tallies tracked?

**A**: Each full node maintains a sliding window of the last 2016 blocks and counts votes in each category. When a threshold is reached, the change locks in.

### Q: What if different miners vote for different values of s?

**A**: S is not voted on through these flags. S changes are coordinated hard forks. The vote flags are for voting on proposals to change other parameters (like k coefficient).

## References

- **Bitcoin BIP 9**: Version bits with timeout and delay
  https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki

- **Bitcoin BIP 34**: Block v2, Height in Coinbase
  https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki

- **JAX Hash-Sorting**: merged_mining/hash_sorting.rs
  Details on how s bits are extracted and used

- **JAX PoW Validation**: validation/pow.rs
  Shows how s affects difficulty and shard assignment

## Version History

- **v0.2.2**: Initial implementation with k parameter
- **v0.2.3**: Changed to s parameter, added vote_k and vote_expand flags
- **v1.0.0**: Stable API, production ready

---

**Last Updated**: 2024-01-15  
**Author**: JAX Network Development Team
