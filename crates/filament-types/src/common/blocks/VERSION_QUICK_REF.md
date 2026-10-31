# Version Field Quick Reference

## Bit Layout

```
32-bit Version Field
┌────────┬────────┬────────┬─────────────────────┐
│  0-3   │   4    │   5    │       6-31          │
│   s    │ vote_k │vote_exp│    base_version     │
│ (0-15) │ (0/1)  │ (0/1)  │    (0-67M)          │
└────────┴────────┴────────┴─────────────────────┘
```

## Quick Examples

```rust
use common::blocks::BlockVersion;

// Basic usage
let v = BlockVersion::new(1, 4, false, false);  // v1, s=4, no votes
let v = BlockVersion::new(1, 4, true, false);   // v1, s=4, vote for k
let v = BlockVersion::new(1, 4, false, true);   // v1, s=4, vote for expand
let v = BlockVersion::new(1, 4, true, true);    // v1, s=4, vote for both

// Extract fields
let s = v.s();                    // Hash-sorting number (0-15)
let vote_k = v.vote_k_flag();     // Vote K flag (bool)
let vote_exp = v.vote_expand_flag();  // Vote Expand flag (bool)
let base = v.base_version();      // Base version number

// Modify fields
v.set_s(8);                       // Change s to 8
v.set_vote_k_flag(true);          // Set vote K
v.set_vote_expand_flag(true);     // Set vote expand
v.set_base_version(2);            // Upgrade to v2

// Convert to/from u32
let raw = v.as_u32();             // To u32
let v2 = BlockVersion::from_u32(raw);  // From u32

// Helper functions (for legacy code)
let s = extract_s_from_version(version_u32);
let vote_k = extract_vote_k_from_version(version_u32);
let vote_exp = extract_vote_expand_from_version(version_u32);
let version_u32 = make_version(1, 4, true, false);
```

## Common Values

| Description | Code | Hex | Max Shards |
|-------------|------|-----|------------|
| V1, s=0, no votes | `BlockVersion::new(1, 0, false, false)` | 0x00000040 | 0 |
| V1, s=4, no votes | `BlockVersion::new(1, 4, false, false)` | 0x00000044 | 15 |
| V1, s=4, vote k | `BlockVersion::new(1, 4, true, false)` | 0x00000054 | 15 |
| V1, s=4, vote exp | `BlockVersion::new(1, 4, false, true)` | 0x00000064 | 15 |
| V1, s=4, both votes | `BlockVersion::new(1, 4, true, true)` | 0x00000074 | 15 |
| V1, s=8, both votes | `BlockVersion::new(1, 8, true, true)` | 0x00000078 | 255 |
| V2, s=4, no votes | `BlockVersion::new(2, 4, false, false)` | 0x00000084 | 15 |

## Field Meanings

### s (Hash-Sorting Number)
- **Purpose**: Determines shard assignment from PoW hash
- **Range**: 0-15
- **Formula**: Max shards = 2^s - 1
- **Example**: s=4 → 15 shards, s=8 → 255 shards

### vote_k Flag
- **Purpose**: Vote on k parameter changes (separate from s)
- **Values**: false (no/against), true (yes/for)
- **Use**: BIP 9-style voting on k coefficient changes

### vote_expand Flag
- **Purpose**: Vote on network expansion
- **Values**: false (no/against), true (yes/for)
- **Use**: Signal support for adding shards, increasing capacity

### base_version
- **Purpose**: Protocol version number
- **Range**: 0 to 67,108,863
- **Use**: Track protocol upgrades, hard forks

## Consensus Rules

✓ All shard blocks in merged tree must have same s
✓ Vote flags don't affect block validity
✓ s changes require coordinated hard fork
✓ Votes activate at 95% threshold in 2016-block window

## Validation Example

```rust
fn validate_beacon_block_version(
    block: &BeaconBlock,
    expected_s: u8,
) -> Result<(), ValidationError> {
    let version = BlockVersion::from_u32(block.header.version);
    
    // Check s matches
    if version.s() != expected_s {
        return Err(ValidationError::InvalidHashSortingNumber {
            expected: expected_s,
            actual: version.s(),
        });
    }
    
    // Vote flags are informational only - don't fail validation
    
    Ok(())
}
```

## Vote Counting Example

```rust
fn count_votes(blocks: &[BeaconBlock]) -> (usize, usize) {
    let mut vote_k_count = 0;
    let mut vote_expand_count = 0;
    
    for block in blocks {
        let v = BlockVersion::from_u32(block.header.version);
        if v.vote_k_flag() { vote_k_count += 1; }
        if v.vote_expand_flag() { vote_expand_count += 1; }
    }
    
    (vote_k_count, vote_expand_count)
}

// Check if threshold reached (95% of 2016 blocks)
fn check_activation(vote_count: usize) -> bool {
    vote_count >= 1915  // 95% of 2016
}
```

## Common Mistakes to Avoid

❌ **Don't** confuse s with k (they're different parameters)
❌ **Don't** validate vote flags (they're signaling only)
❌ **Don't** change s mid-epoch (only at difficulty adjustment)
❌ **Don't** forget to preserve other fields when modifying one

✓ **Do** use s for hash-sorting
✓ **Do** use vote flags for signaling
✓ **Do** validate s matches across merged tree
✓ **Do** use helper functions for backward compatibility

## Performance Notes

- Version creation: ~1 CPU cycle
- Field extraction: ~1 CPU cycle  
- Validation: ~5 CPU cycles
- Storage: 0 extra bytes (reuses existing field)
- Network: 0 extra bandwidth

## References

- Full documentation: VERSION_FIELD_DESIGN.md
- Implementation: version.rs
- Examples: version_examples.rs
- Bitcoin BIP 9: https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
