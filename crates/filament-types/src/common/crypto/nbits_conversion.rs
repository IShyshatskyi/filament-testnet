// src/common/crypto/nbits_conversion.rs

// ============================================================================
// CORRECTED: nBits (Compact Difficulty) Conversion Functions
// ============================================================================
//
// This file provides CORRECT Bitcoin-compatible nBits conversion AND
// preserves the correct hash-sorting difficulty formula.
//
// CRITICAL FIXES:
// 1. nbits_to_target() now returns [u8; 32] instead of u64 ✓
// 2. Proper 256-bit expansion following Bitcoin's algorithm ✓
// 3. Correct difficulty_to_nbits() with precise encoding ✓
// 4. KEPT: calculate_difficulty_from_target(target, k) formula ✓
//
// UNDERSTANDING HASH-SORTING DIFFICULTY:
// --------------------------------------
// The formula Difficulty = 2^(256 + k) / target is CORRECT because:
//
// When mining for a SPECIFIC shard, miners must find a hash that:
// 1. Meets PoW target: hash < target
// 2. Has correct k bits: (hash & ((1<<k)-1)) == (shard_id + 1)
//
// Only 1 in 2^k hashes meeting (1) will also meet (2).
// Therefore, effective difficulty is multiplied by 2^k.
//
// TWO MINING SCENARIOS:
// ---------------------
// Pool Mining (any shard):
//   - Difficulty = 2^256 / target
//   - Hash-sorting determines shard AFTER finding PoW
//
// Solo Mining (specific shard):
//   - Difficulty = 2^(256 + k) / target  
//   - Hash-sorting is part of the mining problem
//   - 2^k times harder than pool mining
//
// ============================================================================

use log::{debug, warn};

// ============================================================================
// Core Conversion Functions
// ============================================================================

/// Convert nBits compact format to full 256-bit target
///
/// **FIXED (v0.2.2)**: Now returns full [u8; 32] instead of truncated u64
///
/// This follows Bitcoin's exact algorithm for expanding the compact
/// representation to a full 256-bit difficulty target.
///
/// # Format
/// ```text
/// nBits = 0xMMNNNNNN
/// MM     = size (number of bytes)
/// NNNNNN = mantissa (3-byte value)
/// ```
///
/// # Expansion
/// ```text
/// target = mantissa × 256^(size - 3)
/// ```
///
/// # Examples
/// ```rust
/// use common_types::common::crypto::nbits_conversion::nbits_to_target;
/// // Bitcoin genesis difficulty
/// let target = nbits_to_target(0x1d00ffff);
/// assert_eq!(target[0], 0x00);
/// assert_eq!(target[1], 0x00);
/// assert_eq!(target[2], 0x00);
/// assert_eq!(target[3], 0x00);
/// assert_eq!(target[4], 0xff);
/// assert_eq!(target[5], 0xff);
/// // Rest is zeros
/// ```
///
/// # Arguments
/// * `nbits` - Compact difficulty representation
///
/// # Returns
/// * Full 256-bit target as [u8; 32]
/// * Returns [0u8; 32] for invalid inputs
pub fn nbits_to_target(nbits: u32) -> [u8; 32] {
    if nbits == 0 {
        return [0u8; 32];
    }
    
    // Extract size and mantissa
    let size = ((nbits >> 24) & 0xFF) as usize;
    let mantissa = nbits & 0x00FFFFFF;
    
    // Validate size (must be 1-32)
    if size == 0 || size > 32 {
        warn!("Invalid nBits size: {}", size);
        return [0u8; 32];
    }
    
    // Note: Bitcoin nBits treats bit 23 of the mantissa as a sign bit to
    // indicate negative targets (which are invalid for PoW). However, this
    // codebase also uses nBits to represent rBits difficulty values where the
    // sign bit can legitimately be set. We therefore do NOT reject such values
    // here — the caller is responsible for ensuring the semantics are correct.
    
    let mut target = [0u8; 32];
    
    // Convert mantissa to bytes (big-endian)
    let mantissa_bytes = mantissa.to_be_bytes();
    
    if size <= 3 {
        // Mantissa fits in last 3 bytes
        // Position at bytes [32-size, 32-size+1, 32-size+2]
        let pos = 32 - size;
        target[pos] = mantissa_bytes[1]; // Skip first byte (always 0 for 24-bit)
        if size >= 2 {
            target[pos + 1] = mantissa_bytes[2];
        }
        if size >= 3 {
            target[pos + 2] = mantissa_bytes[3];
        }
    } else {
        // Mantissa goes at position (32 - size) to (32 - size + 2)
        let pos = 32 - size;
        target[pos] = mantissa_bytes[1];     // Skip first byte
        target[pos + 1] = mantissa_bytes[2];
        target[pos + 2] = mantissa_bytes[3];
    }
    
    debug!(
        "nBits 0x{:08x} → target {}",
        nbits,
        hex::encode(target)
    );
    
    target
}

/// Convert 256-bit target to nBits compact format
///
/// **FIXED (v0.2.2)**: Now properly encodes full 256-bit targets
///
/// Finds the first non-zero byte and encodes it with the following
/// 2 bytes as the mantissa, with the position encoded as size.
///
/// # Arguments
/// * `target` - Full 256-bit target
///
/// # Returns
/// * Compact nBits representation
/// * Returns 0 for all-zero target
///
/// # Examples
/// ```rust
/// use common_types::common::crypto::nbits_conversion::target_to_nbits;
/// let target: [u8; 32] = [
///     0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
/// let nbits = target_to_nbits(&target);
/// assert_eq!(nbits, 0x1d00ffff); // Bitcoin genesis
/// ```
pub fn target_to_nbits(target: &[u8; 32]) -> u32 {
    // Find first non-zero byte (size)
    let mut size = 0;
    let mut first_nonzero = 0;
    
    for (i, &byte) in target.iter().enumerate() {
        if byte != 0 {
            first_nonzero = i;
            size = 32 - i;
            break;
        }
    }
    
    if size == 0 {
        // All zeros
        return 0;
    }
    
    // Extract 3-byte mantissa starting at first non-zero byte
    let mut mantissa = (target[first_nonzero] as u32) << 16;
    
    if first_nonzero + 1 < 32 {
        mantissa |= (target[first_nonzero + 1] as u32) << 8;
    }
    if first_nonzero + 2 < 32 {
        mantissa |= target[first_nonzero + 2] as u32;
    }
    
    // Check if high bit is set (would be interpreted as negative)
    // If so, shift right and increase size
    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        size += 1;
    }
    
    // Encode: size in top byte, mantissa in lower 3 bytes
    let nbits = ((size as u32) << 24) | (mantissa & 0x00FFFFFF);
    
    debug!(
        "Target {} → nBits 0x{:08x}",
        hex::encode(target),
        nbits
    );
    
    nbits
}

// ============================================================================
// Difficulty Conversion Functions
// ============================================================================

/// Convert difficulty value to nBits compact format
///
/// **FIXED (v0.2.2)**: Now uses proper 256-bit arithmetic
///
/// Formula: target = max_target / difficulty
///          nbits = compact(target)
///
/// # Arguments
/// * `difficulty` - Difficulty value (1 = Bitcoin genesis)
///
/// # Returns
/// * nBits compact representation
///
/// # Examples
/// ```rust
/// use common_types::common::crypto::nbits_conversion::difficulty_to_nbits;
/// let nbits = difficulty_to_nbits(1);
/// assert_eq!(nbits, 0x1d00ffff); // Bitcoin genesis
///
/// let nbits_hard = difficulty_to_nbits(16307);
/// // Should be close to 0x1b0404cb
/// ```
pub fn difficulty_to_nbits(difficulty: u64) -> u32 {
    if difficulty == 0 {
        warn!("Zero difficulty, returning 0");
        return 0;
    }
    
    // Bitcoin genesis difficulty target (difficulty = 1)
    // 0x00000000ffff0000000000000000000000000000000000000000000000000000
    const MAX_TARGET: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    if difficulty == 1 {
        return target_to_nbits(&MAX_TARGET);
    }
    
    // Calculate target = max_target / difficulty
    let target = divide_u256_by_u64(&MAX_TARGET, difficulty);
    
    // Convert to compact format
    target_to_nbits(&target)
}

/// Convert difficulty to nBits using a network-specific MAX_TARGET
///
/// Each Shisha Network chain defines its own MAX_TARGET:
/// - Devnet:   2^228 (nBits 0x1d100000, ~2^28 hashes for diff=1)
/// - Testnet1: 0xFFFF×256^26 (nBits 0x1d00ffff, ~2^32 hashes, = Bitcoin)
/// - Testnet2: 2^204 (nBits 0x1a100000, ~2^52 hashes)
/// - Mainnet:  2^200 (nBits 0x1a010000, ~2^56 hashes)
///
/// Formula: target = max_target / difficulty
///          nBits  = compact(target)
///
/// # Arguments
/// * `difficulty` - Difficulty value (1 = easiest for this network)
/// * `max_target` - Network-specific maximum target (difficulty=1 target)
///
/// # Returns
/// * nBits compact representation
pub fn difficulty_to_nbits_with_max_target(difficulty: u64, max_target: &[u8; 32]) -> u32 {
    if difficulty == 0 {
        warn!("Zero difficulty, returning 0");
        return 0;
    }

    if difficulty == 1 {
        return target_to_nbits(max_target);
    }

    // Calculate target = max_target / difficulty
    let target = divide_u256_by_u64(max_target, difficulty);

    // Convert to compact format
    target_to_nbits(&target)
}

/// The largest target representable by the compact nBits encoding used
/// throughout this codebase: `size = 32`, `mantissa = 0x7FFFFF` (the largest
/// mantissa whose sign bit, bit 23, is clear — a set sign bit would force
/// `target_to_nbits` to bump `size` to 33, which `nbits_to_target`'s own
/// `size > 32` guard then rejects, so `size = 33` never round-trips).
///
/// `config/genesis_crash_recovery.toml` already uses this exact value
/// (`bits = 0x207fffff`) as its deliberately-trivial devnet target — it is
/// not an arbitrary sentinel, it is the true ceiling of this encoding.
pub const MAX_REPRESENTABLE_NBITS: u32 = 0x207f_ffff;

/// Multiply a 256-bit target by `2^shift_bits`, saturating at
/// [`MAX_REPRESENTABLE_NBITS`]'s target instead of silently wrapping.
///
/// Used to derive a shard genesis target that is a fixed multiple (currently
/// `16` = `2^4`, see `SHARD_CALIBRATION_CONSTANT` in
/// `crates/common-types/src/common/genesis/genesis_config.rs`) easier than
/// the beacon anchor block it derives from. A naive `U256::shl` would drop
/// the overflowed high bits and return a small, wrong value instead of the
/// intended "as easy as representable" ceiling — this matters in practice,
/// since some devnet/crash-recovery configs deliberately set the beacon's
/// own genesis `bits` to the absolute maximum already (`0x207fffff`), and a
/// shard "16x easier than the beacon's already-maximal target" must clamp at
/// that same maximum rather than wrap into a tiny (very hard) target.
pub fn scale_target_by_power_of_two_saturating(target: &[u8; 32], shift_bits: u32) -> [u8; 32] {
    if shift_bits == 0 {
        return *target;
    }

    let ceiling_bytes = nbits_to_target(MAX_REPRESENTABLE_NBITS);
    let t = U256::from_bytes(target);

    // A left shift by `shift_bits` overflows the 256-bit space iff the value
    // occupies more than `256 - shift_bits` bits, i.e. iff its leading-zero
    // count is smaller than `shift_bits`.
    if t.leading_zeros() < shift_bits {
        return ceiling_bytes;
    }

    let scaled = t.shl(shift_bits);
    let ceiling = U256::from_bytes(&ceiling_bytes);
    if scaled > ceiling {
        return ceiling_bytes;
    }

    scaled.to_bytes()
}

/// Calculate base difficulty from target using a network-specific MAX_TARGET
///
/// Formula: difficulty = max_target / target
///
/// For shard-specific difficulty (solo mining), multiply by 2^k:
///   shard_difficulty = base_difficulty × 2^k
///
/// # Arguments
/// * `target_bytes` - Full 256-bit target
/// * `max_target` - Network-specific maximum target
///
/// # Returns
/// * Difficulty value (1 = easiest for this network)
pub fn calculate_difficulty_with_max_target(
    target_bytes: &[u8; 32],
    max_target: &[u8; 32],
) -> u64 {
    let target = U256::from_bytes(target_bytes);
    let max = U256::from_bytes(max_target);

    if target.is_zero() {
        return u64::MAX; // infinite difficulty
    }

    let difficulty = max.div(&target);

    // Convert to u64, saturating at max
    let result = difficulty.to_u128();
    if result > u64::MAX as u128 {
        u64::MAX
    } else if result == 0 {
        1 // minimum difficulty
    } else {
        result as u64
    }
}

/// Calculate difficulty from 256-bit target FOR SPECIFIC SHARD MINING
///
/// **CORRECT FORMULA** (v0.2.2): Kept with k parameter!
///
/// Formula: Difficulty = 2^(256 + k) / target
///
/// This calculates the difficulty of mining a block for a SPECIFIC shard,
/// accounting for the hash-sorting filter.
///
/// # Why the k parameter is necessary and correct
///
/// When mining for a specific shard, the miner must find a hash that:
/// 1. Meets PoW target: hash < target
/// 2. Has correct k bits: (hash & ((1<<k)-1)) == (shard_id + 1)
///
/// Only 1 in 2^k hashes meeting (1) will also meet (2).
/// Therefore, effective difficulty is multiplied by 2^k.
///
/// # Two Mining Scenarios
///
/// ## Pool Mining (any shard)
/// Pool miners find hash < target, then hash-sorting determines shard.
/// Use k=0 to get base difficulty:
/// ```text
/// let base_difficulty = calculate_difficulty_from_target(&target, 0);
/// ```
///
/// ## Solo Mining (specific shard)
/// Solo miners targeting specific shard must find hash with correct k bits.
/// Use actual k value to get effective difficulty:
/// ```text
/// let shard_difficulty = calculate_difficulty_from_target(&target, 4);
/// // This is 16x harder than base_difficulty for k=4
/// ```
///
/// # Arguments
/// * `target_bytes` - Full 256-bit target
/// * `k` - Hash-sorting bits parameter
///   - k=0: Base difficulty (pool mining)
///   - k>0: Shard-specific difficulty (solo mining)
///
/// # Returns
/// * Difficulty value as u128
/// * Returns 0 for invalid/zero targets
///
/// # Examples
/// ```rust
/// use common_types::common::crypto::nbits_conversion::{nbits_to_target, calculate_difficulty_from_target};
/// let target = nbits_to_target(0x1d00ffff);
///
/// // Base difficulty (pool mining)
/// let diff_pool = calculate_difficulty_from_target(&target, 0);
/// assert!(diff_pool >= 1); // ≈ 1.0
///
/// // Shard difficulty with k=4 (solo mining)
/// let diff_solo = calculate_difficulty_from_target(&target, 4);
/// assert!(diff_solo > diff_pool); // 2^4 times harder
/// ```
/// * `asserted_s_bits` - Asserted difficulty-scaling exponent (genesis-frozen `s`
///   used in `calculate_difficulty_from_target`; not live `expand_state.s_bits`)
pub fn calculate_difficulty_from_target(target_bytes: &[u8; 32], asserted_s_bits: u32) -> u128 {
    let target = U256::from_bytes(target_bytes);
    
    if target.is_zero() {
        return 0;
    }
    
    // difficulty = 2^(256 + k) / target
    let leading_zeros = target.leading_zeros();
    
    if leading_zeros >= 192 {
        // Target fits in 64 bits
        let target_u64 = target.0[0];
        if target_u64 == 0 {
            return 0;
        }
        let max_target = 0xFFFFFFFFFFFFFFFFu128;
        let base_difficulty = max_target / (target_u64 as u128);
        
        if asserted_s_bits >= 128 {
            return u128::MAX;
        }
        let multiplier = 1u128 << asserted_s_bits;
        base_difficulty.saturating_mul(multiplier)
    } else if leading_zeros >= 128 {
        // Target fits in 128 bits
        let target_u128 = ((target.0[1] as u128) << 64) | (target.0[0] as u128);
        if target_u128 == 0 {
            return 0;
        }
        let max_target = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
        let base_difficulty = max_target / target_u128;
        
        if asserted_s_bits >= 128 {
            return u128::MAX;
        }
        let multiplier = 1u128 << asserted_s_bits;
        base_difficulty.saturating_mul(multiplier)
    } else {
        // Target is large (>= 2^128), calculate difficulty properly
        // For genesis target (0x00000000ffff000...), we're in this branch
        
        // Find highest non-zero limb to calculate difficulty
        for i in (0..4).rev() {
            if target.0[i] != 0 {
                let limb = target.0[i];
                let limb_leading_zeros = limb.leading_zeros();
                let limb_bits = 64 - limb_leading_zeros;
                
                // Position of this limb in the 256-bit number
                let limb_position = i * 64;
                
                // Effective bit position of the highest bit
                let highest_bit_pos = limb_position + limb_bits as usize;
                
                // difficulty ≈ 2^(256 + k) / 2^highest_bit_pos = 2^(256 + k - highest_bit_pos)
                let exponent = (256 + asserted_s_bits as usize) as i32 - highest_bit_pos as i32;
                
                if exponent < 0 {
                    // Target is huge, difficulty < 1
                    return 1;
                } else if exponent >= 128 {
                    return u128::MAX;
                } else {
                    return 1u128 << exponent;
                }
            }
        }
        
        // All limbs are zero (shouldn't happen due to earlier check)
        0
    }
}

// ============================================================================
// Helper: 256-bit Division
// ============================================================================

/// Divide a 256-bit number by a 64-bit number
///
/// Returns: dividend / divisor as [u8; 32]
fn divide_u256_by_u64(dividend: &[u8; 32], divisor: u64) -> [u8; 32] {
    if divisor == 0 {
        warn!("Division by zero");
        return [0u8; 32];
    }
    
    if divisor == 1 {
        return *dividend;
    }
    
    // Use U256 for the division
    let dividend_u256 = U256::from_bytes(dividend);
    let divisor_u256 = U256::from(divisor);
    
    let result = dividend_u256.div(&divisor_u256);
    result.to_bytes()
}

// ============================================================================
// U256 Helper Type (Minimal Implementation)
// ============================================================================

/// Simple 256-bit unsigned integer
///
/// Stored as four 64-bit limbs in little-endian order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256([u64; 4]);

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare from most-significant limb (index 3) to least-significant (index 0)
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                other_ord => return other_ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl U256 {
    /// Create from bytes (big-endian, standard display format)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        
        // Read in big-endian order
        for i in 0..4 {
            let mut limb = 0u64;
            for j in 0..8 {
                let byte_idx = i * 8 + j;
                limb = (limb << 8) | (bytes[byte_idx] as u64);
            }
            limbs[3 - i] = limb; // Store in little-endian limb order
        }
        
        U256(limbs)
    }
    
    /// Convert to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        for i in 0..4 {
            let limb = self.0[3 - i]; // Read in reverse (big-endian)
            for j in 0..8 {
                bytes[i * 8 + j] = ((limb >> (56 - j * 8)) & 0xFF) as u8;
            }
        }
        
        bytes
    }
    
    /// Create from u64
    pub fn from(value: u64) -> Self {
        U256([value, 0, 0, 0])
    }

    /// Create from u128 (low two limbs).
    pub fn from_u128(value: u128) -> Self {
        U256([value as u64, (value >> 64) as u64, 0, 0])
    }
    
    /// Convert to u128 (saturating)
    pub fn to_u128(&self) -> u128 {
        if self.0[2] != 0 || self.0[3] != 0 {
            return u128::MAX; // Saturate
        }
        
        ((self.0[1] as u128) << 64) | (self.0[0] as u128)
    }
    
    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
    
    /// Count leading zeros
    fn leading_zeros(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return ((3 - i) as u32 * 64) + self.0[i].leading_zeros();
            }
        }
        256
    }
    
    /// Divide by another U256 (binary long division)
    pub fn div(&self, divisor: &U256) -> U256 {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        // Standard binary long division
        let mut quotient = U256([0, 0, 0, 0]);
        let mut remainder = U256([0, 0, 0, 0]);

        for i in (0..256).rev() {
            // Shift remainder left by 1
            remainder = remainder.shl(1);

            // Bring in bit i of the dividend
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            if (self.0[limb_idx] >> bit_idx) & 1 == 1 {
                remainder.0[0] |= 1;
            }

            // If remainder >= divisor, subtract and set quotient bit
            if remainder >= *divisor {
                remainder = remainder.sub(divisor);
                quotient.0[limb_idx] |= 1u64 << bit_idx;
            }
        }

        quotient
    }
    
    /// Subtract
    fn sub(&self, other: &U256) -> U256 {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        
        for i in 0..4 {
            let (diff, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) | (b2 as u64);
        }
        
        U256(result)
    }
    
    /// Shift left
    fn shl(&self, n: u32) -> U256 {
        if n == 0 {
            return *self;
        }
        
        if n >= 256 {
            return U256([0, 0, 0, 0]);
        }
        
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        
        let mut result = [0u64; 4];
        
        for i in 0..4 {
            if i >= limb_shift {
                result[i] = self.0[i - limb_shift] << bit_shift;
                
                if bit_shift > 0 && i > limb_shift {
                    result[i] |= self.0[i - limb_shift - 1] >> (64 - bit_shift);
                }
            }
        }
        
        U256(result)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nbits_to_target_genesis() {
        let target = nbits_to_target(0x1d00ffff);
        
        // Expected: 0x00000000ffff0000...
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x00);
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        assert_eq!(target[6], 0x00);
    }
    
    #[test]
    fn test_nbits_roundtrip() {
        let test_cases = vec![
            0x1d00ffff,
            0x1b0404cb,
            0x1a05db8b,
        ];
        
        for nbits in test_cases {
            let target = nbits_to_target(nbits);
            let nbits2 = target_to_nbits(&target);
            assert_eq!(nbits, nbits2);
        }
    }
    
    #[test]
    fn test_difficulty_with_hash_sorting() {
        let target = nbits_to_target(0x1d00ffff);

        // Base difficulty (k=0, pool mining)
        let diff_base = calculate_difficulty_from_target(&target, 0);

        // With k=4 (solo mining, 15 shards)
        let diff_k4 = calculate_difficulty_from_target(&target, 4);

        // Should be 16x harder (2^4 = 16)
        // Use division to avoid overflow with large u128 values
        let ratio = diff_k4 / diff_base;
        assert!(ratio >= 15, "Expected ratio >= 15, got {}", ratio);
        assert!(ratio <= 17, "Expected ratio <= 17, got {}", ratio);
    }

    // ========================================================================
    // Per-Network MAX_TARGET Tests
    // ========================================================================

    #[test]
    fn test_devnet_max_target_nbits() {
        // Devnet: MAX_TARGET = 2^228, nBits should be 0x1d100000
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nbits = difficulty_to_nbits_with_max_target(1, &max_target);
        assert_eq!(nbits, 0x1d100000, "Devnet diff=1 nBits mismatch: got 0x{:08x}", nbits);

        // Roundtrip: nbits → target → nbits
        let target = nbits_to_target(nbits);
        assert_eq!(target, max_target, "Devnet MAX_TARGET roundtrip failed");
    }

    #[test]
    fn test_testnet1_max_target_nbits() {
        // Testnet1: MAX_TARGET = Bitcoin genesis (0xFFFF × 256^26), nBits = 0x1d00ffff
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nbits = difficulty_to_nbits_with_max_target(1, &max_target);
        assert_eq!(nbits, 0x1d00ffff, "Testnet1 diff=1 nBits mismatch: got 0x{:08x}", nbits);
    }

    #[test]
    fn test_testnet2_max_target_nbits() {
        // Testnet2: MAX_TARGET = 2^204, nBits = 0x1a100000
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nbits = difficulty_to_nbits_with_max_target(1, &max_target);
        assert_eq!(nbits, 0x1a100000, "Testnet2 diff=1 nBits mismatch: got 0x{:08x}", nbits);
    }

    #[test]
    fn test_mainnet_max_target_nbits() {
        // Mainnet: MAX_TARGET = 2^200, nBits = 0x1a010000
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nbits = difficulty_to_nbits_with_max_target(1, &max_target);
        assert_eq!(nbits, 0x1a010000, "Mainnet diff=1 nBits mismatch: got 0x{:08x}", nbits);
    }

    #[test]
    fn test_difficulty_roundtrip_with_max_target() {
        // Test: difficulty_to_nbits → nbits_to_target → calculate_difficulty should roundtrip
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        for diff in [1u64, 2, 10, 100, 1000, 10000] {
            let nbits = difficulty_to_nbits_with_max_target(diff, &max_target);
            let target = nbits_to_target(nbits);
            let recovered = calculate_difficulty_with_max_target(&target, &max_target);
            // Allow small rounding error from nBits compression
            let ratio = if recovered > diff { recovered / diff } else { diff / recovered };
            assert!(ratio <= 2, "Roundtrip failed for diff={}: recovered={}, ratio={}", diff, recovered, ratio);
        }
    }
}