// merged_mining/hash_sorting.rs
//
// Hash Sorting Module - 2-for-1 PoW Technique for Merged Mining
//
// PURPOSE:
// Implements hash-sorting rules that determine which shard(s) a proof-of-work
// hash is eligible for after mining. Uses SHA256d (Bitcoin's hash function)
// for ASIC compatibility.
//
// KEY CONCEPT:
// After finding a valid PoW hash, extract the last k bits to determine
// shard eligibility. This enables:
// - Random shard assignment (unpredictable which shard gets the block)
// - Merged mining (single PoW can satisfy multiple shards)
// - Fair distribution across shards
//
// HASH SORTING RULE:
// shard_id = (last_k_bits_of_hash - 1)
// Special case: all-zeros is reserved (no shard assignment)
//
// BITCOIN ASIC COMPATIBILITY:
// Uses SHA256d exactly as Bitcoin does, so standard Bitcoin ASICs work
// without modification. Hash-sorting is applied pool-side after PoW.

use log::{debug, info};

/// Convert hash bytes to hex string (Bitcoin format: reversed byte order)
/// 
/// Bitcoin displays hashes in reversed byte order (big-endian display)
/// while internally using little-endian for calculations.
pub fn hash_to_hex_string(hash: &[u8]) -> String {
    // Bitcoin displays hashes in reversed byte order
    let mut reversed = hash.to_vec();
    reversed.reverse();
    hex::encode(reversed)
}

/// Parse hex hash string to bytes (handles Bitcoin's reversed format)
pub fn hex_string_to_hash(hash_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let mut bytes = hex::decode(hash_str.trim_start_matches("0x"))?;
    bytes.reverse(); // Reverse to get internal format
    Ok(bytes)
}

/// Extract the last k bits from a SHA256d hash
///
/// Hash is in Bitcoin internal format (little-endian for this operation)
///
/// USAGE: Determines which shard (if any) this hash is eligible for
/// FORMULA: last_k_bits mod 2^k
///
/// Reads from the **end** of `hash_bytes`, not the start. `hash_bytes[0]`
/// (in this internal, unreversed representation) is exactly the byte PoW
/// difficulty forces toward zero — that's what "hash meets target" means
/// for a big-endian-style numeric comparison. Sorting on it would make
/// `sorting_bits` collapse to 0 (the reserved "no shard" sentinel) for
/// nearly every share instead of the uniform distribution across shards
/// this is supposed to produce; the trailing bytes are the ones PoW leaves
/// effectively random. Found via a devnet_15 soak where zero shard blocks
/// were ever produced despite thousands of valid shares.
pub fn extract_sorting_bits(hash_bytes: &[u8], k: u32) -> u32 {
    if hash_bytes.len() < 32 {
        return 0;
    }

    let mut result = 0u32;
    let bytes_needed = ((k + 7) / 8) as usize;
    let len = hash_bytes.len();

    for i in 0..bytes_needed.min(len) {
        result |= (hash_bytes[len - 1 - i] as u32) << (i * 8);
    }

    // Mask to get only k bits
    let mask = (1u32 << k) - 1;
    result & mask
}

/// Check if hash is eligible for a specific shard using hash sorting
/// 
/// RULE: hash mod 2^k == (shard_id + 1)
/// SPECIAL CASE: hash mod 2^k == 0 is reserved (no shard)
/// 
/// EXAMPLE (k=4):
/// - Hash bits 0000 → reserved (no shard)
/// - Hash bits 0001 → shard 0
/// - Hash bits 0010 → shard 1
/// - Hash bits 1111 → shard 14
pub fn is_hash_eligible_for_shard(hash_bytes: &[u8], shard_id: u32, k: u32) -> bool {
    let sorting_bits = extract_sorting_bits(hash_bytes, k);
    let expected_value = shard_id + 1;
    
    debug!(
        "Hash sorting check: hash_bits={}, expected={} (shard_id={} + 1)",
        sorting_bits, expected_value, shard_id
    );
    
    // All-zeros is reserved
    if sorting_bits == 0 {
        debug!("Hash has all-zero sorting bits (reserved)");
        return false;
    }
    
    // Check if sorting bits match shard
    let eligible = sorting_bits == expected_value;
    
    if eligible {
        info!("Hash is eligible for shard {} (sorting_bits={})", shard_id, sorting_bits);
    } else {
        debug!("Hash not eligible for shard {} (sorting_bits={}, expected={})", 
               shard_id, sorting_bits, expected_value);
    }
    
    eligible
}

/// Find which shard (if any) a hash is eligible for
/// 
/// RETURNS:
/// - Some(shard_id) if hash passes sorting filter for that shard
/// - None if hash has reserved all-zeros pattern
/// 
/// HASH-SORTING ARCHITECTURE:
/// This is where shard assignment is determined AFTER PoW is found.
/// The miner doesn't know which shard they're mining for during the
/// PoW search - it's determined randomly by the hash result.
pub fn find_eligible_shard(hash_bytes: &[u8], k: u32) -> Option<u32> {
    let sorting_bits = extract_sorting_bits(hash_bytes, k);
    
    // All-zeros is reserved
    if sorting_bits == 0 {
        debug!("Hash has reserved all-zero sorting bits");
        return None;
    }
    
    // shard_id = (sorting_bits - 1)
    let shard_id = sorting_bits - 1;

    info!("Hash is eligible for shard {} (sorting_bits={})", shard_id, sorting_bits);

    Some(shard_id)
}

/// Like [`find_eligible_shard`], but additionally treats any `shard_id` at or
/// beyond `active_shard_count` as "no shard" instead of a phantom out-of-range
/// assignment.
///
/// `find_eligible_shard` alone only knows about the `2^k` bit-space carved out
/// by `k`; it has no notion of how many shards actually exist. Per
/// `EpochExpandState`'s own doc comment ("Valid shard IDs for this epoch:
/// `[1, 2^s_bits − 1)`"), `k`'s bit-width is deliberately provisioned with
/// headroom above `active_shard_count` is optional (genesis may freeze a larger
/// `s`); as of Jul 21, 2026 count may also **fill** capacity
/// (`initial_shard_count ≤ 2^s_bits − 1`) so hash-sorting doesn't always need
/// spare codes — but mid-epoch activation still benefits from headroom when
/// operators choose it. Confirmed live via the E3
/// crash-recovery dry-run (`hash_sorting_bits=4`, `initial_shard_count=1`):
/// callers that used the unbounded `find_eligible_shard` treated sorting
/// values for shards 1-14 as real "block candidates," which were then
/// dropped downstream with "submission channel not registered" — shard
/// height never advanced despite hundreds of qualifying shares.
///
/// Callers that dispatch to a real, currently-active shard (pool routing,
/// job generation) should use this variant. `find_eligible_shard` itself is
/// left unbounded — it is also used purely for hash/shard self-consistency
/// checks (e.g. `verify_hash_sorting_assignment`) where the caller already
/// supplies and separately validates `claimed_shard_id`, so no active-count
/// bound is needed there.
pub fn find_eligible_shard_bounded(
    hash_bytes: &[u8],
    k: u32,
    active_shard_count: u32,
) -> Option<u32> {
    let shard_id = find_eligible_shard(hash_bytes, k)?;
    if shard_id >= active_shard_count {
        debug!(
            "Hash sorting bits map to shard {} but only {} shard(s) are active — treating as no shard",
            shard_id, active_shard_count
        );
        return None;
    }
    Some(shard_id)
}

/// Represents a 256-bit unsigned integer for proper difficulty calculation
/// 
/// Stored as four 64-bit limbs in little-endian order.
/// Used for accurate difficulty calculations that exceed u64 range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256([u64; 4]);

impl U256 {
    /// Create U256 from hash bytes (little-endian internal format)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            for j in 0..8 {
                let byte_idx = i * 8 + j;
                if byte_idx < bytes.len() {
                    *limb |= (bytes[byte_idx] as u64) << (j * 8);
                }
            }
        }
        U256(limbs)
    }
    
    /// Check if this value is zero
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
    
    /// Count leading zeros in the 256-bit number
    pub fn leading_zeros(&self) -> u32 {
        for (i, &limb) in self.0.iter().rev().enumerate() {
            if limb != 0 {
                return (i as u32 * 64) + limb.leading_zeros();
            }
        }
        256
    }
}

/// Check if hash meets difficulty target (Bitcoin-style)
/// 
/// RULE: hash < target (as 256-bit numbers)
/// 
/// Direct byte-by-byte comparison in little-endian format.
/// This is the standard Bitcoin PoW verification.
pub fn hash_meets_target(hash_bytes: &[u8], target_bytes: &[u8]) -> bool {
    if hash_bytes.len() != 32 || target_bytes.len() != 32 {
        return false;
    }
    
    let hash = U256::from_bytes(hash_bytes);
    let target = U256::from_bytes(target_bytes);
    
    // Direct 256-bit comparison: hash < target
    hash < target
}

/// Calculate the hash sorting modulus (2^k)
pub fn hash_sorting_modulus(k: u32) -> u64 {
    if k >= 64 {
        u64::MAX
    } else {
        1u64 << k
    }
}

/// Default hash-sorting exponent `s` (matches [`BlockVersion::default`](crate::common::blocks::BlockVersion::default) `.s()`).
pub const DEFAULT_HASH_SORTING_BITS: u32 = 4;

/// Calculate maximum number of shards supported by hash-sorting bits `s`
/// 
/// FORMULA: 2^k - 1 (all-zeros is reserved)
/// 
/// EXAMPLES:
/// - k=4: 15 shards (values 1-15, 0 is reserved)
/// - k=8: 255 shards
/// - k=16: 65535 shards
pub fn max_shards_for_hash_sorting_bits(s: u32) -> u32 {
    if s >= 32 {
        u32::MAX
    } else {
        (1u32 << s) - 1
    }
}

/*
===============================================================================
BITCOIN ASIC MINING WITH SHA256D
===============================================================================

HASH FUNCTION
=============
SHA256d (Double SHA-256):
- First hash: SHA256(block_header)
- Second hash: SHA256(first_hash)
- This is identical to Bitcoin's proof-of-work

Block Header Format (80 bytes):
- Version (4 bytes)
- Previous block hash (32 bytes)
- Merkle root (32 bytes)
- Timestamp (4 bytes)
- nBits difficulty target (4 bytes)
- Nonce (4 bytes)

Bitcoin ASICs:
- Optimized for SHA256d calculation
- Can try billions of nonces per second
- Miners increment nonce and recalculate hash
- When hash < target: valid proof-of-work


HASH SORTING WITH BITCOIN
==========================

The hash sorting technique works perfectly with Bitcoin ASICs:

1. ASIC calculates: hash = SHA256d(block_header)

2. Check hash sorting bits:
   - Extract last k bits from hash
   - If bits match (shard_id + 1): eligible for that shard
   - If bits are all-zero: no shard (but may still reward miner)

3. Check difficulty:
   - hash < target_difficulty
   - Standard Bitcoin difficulty check

4. If both pass: Valid block for shard!


BYTE ORDER CONSIDERATIONS
==========================

Bitcoin uses different byte orders for different purposes:

Internal Format (for calculations):
- Little-endian for most operations
- Hash sorting uses internal format
- Difficulty comparisons use internal format

Display Format (for humans):
- Reversed byte order (big-endian display)
- This is what you see in block explorers
- Example: Internal 0x12345678 displays as 0x78563412

Our Implementation:
- Stores hashes in internal format
- Converts to display format when logging
- Extracts sorting bits from internal format


DIFFICULTY CALCULATION
======================

Bitcoin Difficulty:
- difficulty = max_target / current_target
- max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
- Higher difficulty = smaller target = more leading zeros needed

nBits Format:
- Compact representation of target
- Format: 0xMMNNNNNN
  - MM: Size (number of bytes)
  - NNNNNN: Mantissa
- Example: 0x1d00ffff is Bitcoin's genesis difficulty

Verification:
- Calculate hash = SHA256d(header)
- Check: hash < target
- If true: valid proof-of-work


ASIC COMPATIBILITY
==================

Our pool is fully compatible with Bitcoin ASICs:

✓ Uses SHA256d hash function
✓ 80-byte block header format
✓ Standard nBits difficulty encoding
✓ Compatible with Stratum mining protocol
✓ Supports extranonce for scaling

Additional Feature:
✓ Hash sorting for merged mining
  - Transparent to ASICs
  - No protocol changes needed
  - Pool-side implementation only


PERFORMANCE CHARACTERISTICS
============================

Modern Bitcoin ASICs:
- Antminer S19 Pro: ~110 TH/s (trillion hashes/second)
- At k=4 bits: Each hash has 1/16 chance for any shard
- Expected blocks per shard: ~7 TH/s effectively

Hash Sorting Overhead:
- Zero overhead for miners (ASICs unchanged)
- Minimal overhead for pool (bit extraction)
- O(1) operation per share

===============================================================================
*/