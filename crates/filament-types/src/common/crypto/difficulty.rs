//! Difficulty and target conversion utilities.
//!
//! **FIXED (v0.2.2)**: Now uses proper 256-bit targets instead of truncated u64.
//!
//! This module provides a clean interface to difficulty conversion functions,
//! delegating to the nbits_conversion module for the actual implementation.

use crate::common::crypto::nbits_conversion;

/// Check if a hash meets a difficulty target (hash < target).
///
/// Performs full 256-bit comparison: hash < target
///
/// # Arguments
/// * `hash` - The hash to check (typically from PoW)
/// * `target` - The difficulty target (256-bit)
///
/// # Returns
/// * `true` if hash < target (valid PoW)
/// * `false` otherwise
pub fn hash_meets_target(hash: &[u8], target: &[u8]) -> bool {
    // Byte-by-byte comparison (big-endian)
    for i in 0..hash.len().min(target.len()) {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    // Equal - not valid (must be strictly less than)
    false
}

/// Convert nBits compact difficulty to full 256-bit target.
///
/// **FIXED (v0.2.2)**: Now returns [u8; 32] instead of u64
///
/// This follows Bitcoin's exact algorithm for expanding the compact
/// representation to a full 256-bit difficulty target.
///
/// # Arguments
/// * `nbits` - Compact difficulty (0xMMNNNNNN format)
///
/// # Returns
/// * Full 256-bit target as [u8; 32]
pub fn nbits_to_target(nbits: u32) -> [u8; 32] {
    nbits_conversion::nbits_to_target(nbits)
}

/// Convert difficulty value to nBits compact format.
///
/// # Arguments
/// * `difficulty` - Difficulty value (1 = Bitcoin genesis)
///
/// # Returns
/// * nBits compact representation
pub fn difficulty_to_nbits(difficulty: u64) -> u32 {
    nbits_conversion::difficulty_to_nbits(difficulty)
}

/// Convert 256-bit target to nBits compact format.
///
/// # Arguments
/// * `target` - Full 256-bit target
///
/// # Returns
/// * nBits compact representation
pub fn target_to_nbits(target: &[u8; 32]) -> u32 {
    nbits_conversion::target_to_nbits(target)
}

/// Calculate difficulty from 256-bit target for specific shard mining
///
/// Formula: Difficulty = 2^(256 + k) / target
///
/// This is CORRECT for shard-specific mining where miners must find
/// a hash that both meets the PoW target AND has the correct k bits.
///
/// # Arguments
/// * `target` - Full 256-bit target
/// * `k` - Hash-sorting bits parameter (0 for pool mining)
///
/// # Returns
/// * Difficulty value as u128
pub fn calculate_difficulty_from_target(target: &[u8; 32], k: u32) -> u128 {
    nbits_conversion::calculate_difficulty_from_target(target, k)
}