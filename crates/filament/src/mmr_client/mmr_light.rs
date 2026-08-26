// ============================================================================
// src/mmr_client/mmr_light.rs - Lightweight MMR for Light Clients
// ============================================================================

//! Lightweight MMR for verification-only operations
//!
//! Key differences from full MMR:
//! - Uses HashSet instead of Vec for storage
//! - Stores only peaks + recent blocks (~100)
//! - No append functionality (light clients don't mine)
//! - Optimized for proof verification
//!
//! Memory usage: ~4KB vs ~64MB for full MMR at height 1M
//!
//! ## Why HashSet?
//!
//! **Memory Efficiency:**
//! - Full MMR: Stores ALL nodes (leaves + parents)
//! - MMR Light: Stores only peaks + recent blocks
//! - At height 1M: 64 MB → 4 KB (16,000x savings!)
//!
//! **Fast Lookups:**
//! - Vec: O(n) for existence check
//! - HashSet: O(1) for existence check
//!
//! **Automatic Pruning:**
//! - Easy to remove old entries
//! - Just filter by height
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Light client workflow
//! let mut mmr_light = MMRLight::new();
//!
//! // 1. Fetch proof from full node
//! let proof = fetch_proof_from_full_node().await?;
//!
//! // 2. Verify proof cryptographically
//! if verify_batch_proof(&proof)? {
//!     // 3. Extract verified state
//!     let blocks: Vec<([u8; 32], u32)> = proof.blocks
//!         .iter()
//!         .map(|b| (b.hash(), b.height()))
//!         .collect();
//!
//!     // 4. Update MMR Light with verified data
//!     mmr_light.update_from_verified_proof(
//!         proof.peaks.clone(),
//!         proof.leaf_count,
//!         &blocks,
//!     );
//!
//!     // 5. Now we have current root
//!     let root = mmr_light.get_root();
//! }
//! ```

use std::collections::HashSet;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use log::debug;

use common_types::common::crypto::weighted_hash::{bag_peaks_weighted, WeightedHash};

// ============================================================================
// CUSTOM SERIALIZATION FUNCTIONS
// ============================================================================

/// Serialize HashSet<([u8; 32], u32)> as Vec for JSON compatibility
fn serialize_recent_blocks<S>(
    blocks: &HashSet<([u8; 32], u32)>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert HashSet → Vec for serialization
    // This creates a temporary Vec, but only during serialization
    let vec: Vec<([u8; 32], u32)> = blocks.iter().copied().collect();
    vec.serialize(serializer)
}

/// Deserialize Vec back into HashSet<([u8; 32], u32)>
fn deserialize_recent_blocks<'de, D>(
    deserializer: D,
) -> Result<HashSet<([u8; 32], u32)>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as Vec, then convert → HashSet
    let vec: Vec<([u8; 32], u32)> = Vec::deserialize(deserializer)?;
    Ok(vec.into_iter().collect())
}

// ============================================================================
// MMR LIGHT STRUCTURE
// ============================================================================

/// Lightweight MMR for verification-only operations
///
/// Stores only the minimal data needed for verification:
/// - Current peaks (for root calculation)
/// - Recent block hashes (for quick lookups via HashSet)
///
/// Memory usage: ~4KB + (cache_size × 36 bytes)
/// Example: 1000 block cache = ~40KB
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRLight {
    /// Bitcoin anchor (for validation)
    anchor_hash: [u8; 32],

    /// Current peaks in REVERSE order (largest to smallest)
    peaks: Vec<[u8; 32]>,
    
    /// Recent block hashes for O(1) verification
    /// 
    /// Uses custom serialization:
    /// - In memory: HashSet for O(1) lookups
    /// - On disk: Vec for JSON compatibility
    /// 
    /// The conversion happens transparently during ser/de
    #[serde(
        serialize_with = "serialize_recent_blocks",
        deserialize_with = "deserialize_recent_blocks"
    )]
    recent_blocks: HashSet<([u8; 32], u32)>,
    
    /// Current leaf count (equals block height + 1)
    leaf_count: u32,
    
    /// Maximum recent blocks to cache (user-configurable)
    max_recent_blocks: usize,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl MMRLight {
    /// Create new empty MMR Light with default capacity
    pub fn new() -> Self {
        Self::with_capacity(100)
    }

    /// Create MMR Light with specific capacity
    ///
    /// # Arguments
    /// * `max_recent_blocks` - Maximum blocks to cache
    ///
    /// # Recommended Values
    /// - Desktop wallet: 500-1000 blocks
    /// - Mobile wallet: 100-200 blocks
    /// - Server/Full verification: 2000-5000 blocks
    pub fn with_capacity(max_recent_blocks: usize) -> Self {
        Self {
            anchor_hash: [0u8; 32],
            peaks: Vec::new(),
            recent_blocks: HashSet::new(),
            leaf_count: 0,
            max_recent_blocks,
        }
    }
    
    /// Create with anchor hash
    pub fn with_anchor(anchor_hash: [u8; 32], max_recent_blocks: usize) -> Self {
        Self {
            anchor_hash,
            peaks: Vec::new(),
            recent_blocks: HashSet::new(),
            leaf_count: 0,
            max_recent_blocks,
        }
    }
    
    /// Update maximum cache size (user preference)
    ///
    /// If new size is smaller, prunes old blocks immediately.
    ///
    /// # Arguments
    /// * `new_max` - New maximum cache size
    pub fn set_max_recent_blocks(&mut self, new_max: usize) {
        self.max_recent_blocks = new_max;
        
        // Prune if necessary
        if self.recent_blocks.len() > new_max {
            self.prune_to_size(new_max);
        }
    }
    
    /// Get current maximum cache size
    pub fn max_recent_blocks(&self) -> usize {
        self.max_recent_blocks
    }
    
    /// Update MMR from a cryptographically verified proof of a heavier chain.
    ///
    /// This is the PRIMARY operation for light clients. The caller must have
    /// already verified the proof cryptographically and confirmed the incoming
    /// chain is heavier before calling this function.
    ///
    /// # Reorg safety
    ///
    /// The `HashSet<(hash, height)>` storage means a naive insert of a new
    /// block at height H leaves the old block's `(old_hash, H)` entry in the
    /// set alongside `(new_hash, H)`. This function prevents that in two steps:
    ///
    /// **Step 1 — purge definitely-orphaned entries.** Any cached entry whose
    /// height is ≥ `new_leaf_count` cannot exist on the new canonical chain
    /// (the chain is not that long). One `retain` removes them all, covering
    /// reorgs to shorter chains completely.
    ///
    /// **Step 2 — evict stale entries at proof-covered heights.** The proof
    /// supplies ground truth for a set of specific heights. For each such
    /// height, remove all existing cached entries (old-chain or duplicates)
    /// before inserting the new-chain entry. This guarantees at most one entry
    /// per height for every height the proof covers.
    ///
    /// Heights within `[0, new_leaf_count)` that the proof does not cover are
    /// left as-is. Those entries may be on the shared prefix (correct) or
    /// orphaned (stale) — the light client cannot determine which without proof
    /// coverage. `has_recent_block` answers based on what proofs have certified.
    ///
    /// # Arguments
    /// * `new_peaks`     — MMR peaks of the new canonical chain (stored in
    ///                     reverse order; `get_root` reverses before bagging).
    /// * `new_leaf_count` — Tip height + 1 of the new canonical chain.
    /// * `blocks`        — Sparse set of `(hash, height)` pairs from the new
    ///                     chain. May be empty (e.g. chain-weight proofs).
    ///
    /// # Guarantees after return
    /// - `get_root()` reflects the new canonical chain's MMR root.
    /// - `leaf_count()` equals `new_leaf_count`.
    /// - No cached entry has `height >= new_leaf_count`.
    /// - For every `(hash, height)` in `blocks`: `has_recent_block(hash, height)` is
    ///   `true` and no other hash is cached at that height.
    /// - `recent_blocks_count()` ≤ `max_recent_blocks`.
    pub fn update_from_verified_proof(
        &mut self,
        new_peaks: Vec<[u8; 32]>,
        new_leaf_count: u32,
        blocks: &[([u8; 32], u32)],
    ) {
        debug!("MMRLight: Updating from verified proof (leaf_count: {} -> {})",
               self.leaf_count, new_leaf_count);

        // ── Step 1: Purge definitely-orphaned entries ─────────────────────
        // Any entry at height ≥ new_leaf_count cannot be on the new canonical
        // chain. This single pass handles reorgs to shorter chains in full,
        // and cleans up the top of any reorg regardless of direction.
        self.recent_blocks.retain(|(_, h)| *h < new_leaf_count);

        // ── Step 2: Evict stale entries at proof-covered heights ──────────
        // Build the set of heights the proof provides ground truth for, then
        // remove ALL cached entries at those heights in one O(n) pass before
        // inserting the new-chain entries. This prevents the HashSet from
        // accumulating (old_hash, H) and (new_hash, H) simultaneously.
        if !blocks.is_empty() {
            let proof_heights: HashSet<u32> = blocks.iter().map(|(_, h)| *h).collect();
            self.recent_blocks.retain(|(_, h)| !proof_heights.contains(h));

            for &(block_hash, height) in blocks {
                self.recent_blocks.insert((block_hash, height));
            }
        }

        debug!("MMRLight: Recent blocks cached: {}", self.recent_blocks.len());

        // ── Step 3: Replace peaks and leaf count ──────────────────────────
        self.peaks = new_peaks;
        self.leaf_count = new_leaf_count;

        debug!("MMRLight: New peaks count: {}", self.peaks.len());

        // ── Step 4: Enforce capacity ──────────────────────────────────────
        if self.recent_blocks.len() > self.max_recent_blocks {
            self.prune_to_size(self.max_recent_blocks);
        }
    }
    
    /// Add a block to recent cache
    ///
    /// Automatically prunes old blocks when cache exceeds max_recent_blocks.
    /// Uses height-based pruning to keep most recent blocks.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block
    /// * `height` - Height of the block
    fn add_recent_block(&mut self, block_hash: [u8; 32], height: u32) {
        // O(1) insert
        self.recent_blocks.insert((block_hash, height));
        
        // Prune if cache is too large
        if self.recent_blocks.len() > self.max_recent_blocks {
            self.prune_by_height_from(height);
        }
    }
    
    /// Prune cache by height (keep most recent blocks)
    /// 
    /// NOTE: Uses leaf_count which may be out of sync during add operations.
    /// Deprecated in favor of prune_by_height_from().
    fn prune_by_height(&mut self) {
        let current_height = self.leaf_count.saturating_sub(1);
        let cutoff = current_height.saturating_sub(self.max_recent_blocks as u32 - 1);
        
        debug!("MMRLight: Pruning blocks below height {}", cutoff);
        
        // O(n) but only happens when cache is full
        self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        
        debug!("MMRLight: After pruning: {} blocks", self.recent_blocks.len());
    }
    
    /// Prune cache by height from a specific current height (keep most recent blocks)
    /// 
    /// This is the fixed version that doesn't rely on leaf_count being in sync.
    ///
    /// # Arguments
    /// * `current_height` - The height of the block being added
    fn prune_by_height_from(&mut self, current_height: u32) {
        let cutoff = current_height.saturating_sub(self.max_recent_blocks as u32 - 1);
        
        debug!("MMRLight: Pruning blocks below height {} (current_height: {})", cutoff, current_height);
        
        // O(n) but only happens when cache is full
        self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        
        debug!("MMRLight: After pruning: {} blocks", self.recent_blocks.len());
    }
    
    /// Prune cache to specific size (for user preference changes)
    fn prune_to_size(&mut self, target_size: usize) {
        if self.recent_blocks.len() <= target_size {
            return;
        }
        
        // Collect heights and sort to find cutoff
        let mut heights: Vec<u32> = self.recent_blocks
            .iter()
            .map(|(_, h)| *h)
            .collect();
        heights.sort_unstable();
        
        // Keep the highest 'target_size' blocks
        if let Some(&cutoff) = heights.get(heights.len() - target_size) {
            self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        }
        
        debug!("MMRLight: Pruned to {} blocks", self.recent_blocks.len());
    }
    
    /// Get current MMR root
    ///
    /// Bags all peaks together to produce the root hash.
    ///
    /// # Returns
    /// 32-byte root hash, or anchor if empty
    pub fn get_root(&self) -> [u8; 32] {
        if self.peaks.is_empty() {
            return self.anchor_hash;
        }

        // Peaks stored in reverse order, bag left-to-right.
        // `bag_peaks_weighted` requires WeightedHash; convert from [u8; 32] and back.
        let mut peaks_ltr: Vec<WeightedHash> = self.peaks.iter()
            .map(|&p| WeightedHash::from(p))
            .collect();
        peaks_ltr.reverse();

        *bag_peaks_weighted(&peaks_ltr, WeightedHash::from(self.anchor_hash)).raw()
    }
    
    /// Check if block is in recent cache - O(1) operation
    ///
    /// This is called frequently during proof verification,
    /// so O(1) HashSet lookup is critical for performance.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block
    /// * `height` - Height of the block
    ///
    /// # Returns
    /// true if block is in cache
    pub fn has_recent_block(&self, block_hash: &[u8; 32], height: u32) -> bool {
        self.recent_blocks.contains(&(*block_hash, height))
    }
    
    // NOTE: quick_verify_proof() removed in v0.2.1
    // It was never used in the codebase and relied on deprecated MMRProof type.
    // For quick verification, use MMRLight::has_recent_block() instead.
    
    // ========================================================================
    // GETTERS
    // ========================================================================
    
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
    
    /// Get anchor hash
    pub fn anchor_hash(&self) -> [u8; 32] {
        self.anchor_hash
    }
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /// Clear all state (for reorg or reset)
    pub fn clear(&mut self) {
        debug!("MMRLight: Clearing all state");
        
        self.peaks.clear();
        self.recent_blocks.clear();
        self.leaf_count = 0;
    }
    
    /// Estimate memory usage in bytes
    ///
    /// Useful for monitoring and optimization.
    ///
    /// # Returns
    /// Approximate memory usage in bytes
    pub fn estimate_memory_bytes(&self) -> usize {
        let peaks_bytes = self.peaks.len() * 32;
        let recent_blocks_bytes = self.recent_blocks.len() * (32 + 4 + 8); // hash + height + overhead
        let overhead = 64; // struct overhead
        
        peaks_bytes + recent_blocks_bytes + overhead
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        let memory_bytes = self.estimate_memory_bytes();
        let fill_percent = if self.max_recent_blocks > 0 {
            (self.recent_blocks.len() as f64 / self.max_recent_blocks as f64 * 100.0) as u32
        } else {
            0
        };
        
        CacheStats {
            current_size: self.recent_blocks.len(),
            max_size: self.max_recent_blocks,
            fill_percent,
            memory_bytes,
            peak_count: self.peaks.len(),
            leaf_count: self.leaf_count,
        }
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Cache statistics for monitoring
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub current_size: usize,
    pub max_size: usize,
    pub fill_percent: u32,
    pub memory_bytes: usize,
    pub peak_count: usize,
    pub leaf_count: u32,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache: {}/{} blocks ({}% full), {} peaks, {} leaves, ~{} bytes",
            self.current_size,
            self.max_size,
            self.fill_percent,
            self.peak_count,
            self.leaf_count,
            self.memory_bytes
        )
    }
}

// ============================================================================
// TRAIT IMPLEMENTATIONS
// ============================================================================

impl Default for MMRLight {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

/*
REORG HANDLING IN MMRLight — RESOLVED
======================================
The fix lives in update_from_verified_proof (see implementation above).

Two-step algorithm:
  Step 1: retain entries with height < new_leaf_count   (drops definitely-orphaned)
  Step 2: collect proof_heights, retain entries NOT in proof_heights, insert proof entries
           (evicts stale duplicates at proof-covered heights; O(n + k) total)

Heights inside [0, new_leaf_count) not covered by the proof are left unchanged —
the light client cannot determine whether they are on the shared prefix or orphaned
without proof coverage for those heights. This is the fundamental light-client guarantee.
*/

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Build an MMRLight already populated with blocks 0..n at leaf_count n.
    fn mmr_with_blocks(n: u32) -> MMRLight {
        let mut m = MMRLight::with_capacity(100);
        let blocks: Vec<([u8; 32], u32)> = (0..n).map(|i| ([i as u8 + 1; 32], i)).collect();
        // Initial update: no reorg path, just extension from empty.
        m.update_from_verified_proof(vec![[0xAA; 32]], n, &blocks);
        m
    }

    // =========================================================================
    // Serialisation (unchanged behaviour)
    // =========================================================================

    #[test]
    fn test_custom_serde_serialization() {
        let mut mmr = MMRLight::with_capacity(3);

        mmr.update_from_verified_proof(
            vec![[1u8; 32], [2u8; 32]],
            3,
            &[([10u8; 32], 0), ([11u8; 32], 1), ([12u8; 32], 2)],
        );

        let json = serde_json::to_string(&mmr).unwrap();
        let mmr2: MMRLight = serde_json::from_str(&json).unwrap();

        assert_eq!(mmr2.leaf_count(), 3);
        assert_eq!(mmr2.peak_count(), 2);
        assert_eq!(mmr2.recent_blocks_count(), 3);
        assert!(mmr2.has_recent_block(&[10u8; 32], 0));
        assert!(mmr2.has_recent_block(&[11u8; 32], 1));
        assert!(mmr2.has_recent_block(&[12u8; 32], 2));
        assert!(!mmr2.has_recent_block(&[99u8; 32], 0));
    }

    // =========================================================================
    // Cache sizing (unchanged behaviour)
    // =========================================================================

    #[test]
    fn test_dynamic_cache_resizing() {
        let mut mmr = MMRLight::with_capacity(5);

        for i in 0..10u32 {
            mmr.add_recent_block([i as u8 + 1; 32], i);
            mmr.leaf_count = i + 1;
        }
        assert_eq!(mmr.recent_blocks_count(), 5);

        mmr.set_max_recent_blocks(10);
        assert_eq!(mmr.max_recent_blocks(), 10);

        for i in 10..15u32 {
            mmr.add_recent_block([i as u8 + 1; 32], i);
            mmr.leaf_count = i + 1;
        }
        assert_eq!(mmr.recent_blocks_count(), 10);

        mmr.set_max_recent_blocks(3);
        assert_eq!(mmr.recent_blocks_count(), 3);
        assert!(mmr.has_recent_block(&[13u8; 32], 12));
        assert!(mmr.has_recent_block(&[14u8; 32], 13));
        assert!(mmr.has_recent_block(&[15u8; 32], 14));
    }

    #[test]
    fn test_large_cache_performance() {
        let mut mmr = MMRLight::with_capacity(1000);

        for i in 0u32..2000 {
            mmr.add_recent_block([(i % 255) as u8 + 1; 32], i);
            mmr.leaf_count = i + 1;
        }

        assert_eq!(mmr.recent_blocks_count(), 1000);

        let stats = mmr.cache_stats();
        assert!(stats.memory_bytes < 100_000);
    }

    #[test]
    fn test_cache_stats() {
        let mut mmr = MMRLight::with_capacity(100);

        for i in 0..50u32 {
            mmr.add_recent_block([i as u8 + 1; 32], i);
            mmr.leaf_count = i + 1;
        }

        let stats = mmr.cache_stats();
        assert_eq!(stats.current_size, 50);
        assert_eq!(stats.max_size, 100);
        assert_eq!(stats.fill_percent, 50);
        assert_eq!(stats.leaf_count, 50);
    }

    // =========================================================================
    // Step 1: heights ≥ new_leaf_count are removed unconditionally
    // =========================================================================

    #[test]
    fn reorg_to_shorter_chain_purges_excess_heights() {
        // Cache has heights 0-10, leaf_count=11.
        // New chain is shorter: new_leaf_count=8.
        // Heights 8, 9, 10 must be removed.
        let mut mmr = mmr_with_blocks(11);
        assert_eq!(mmr.recent_blocks_count(), 11);

        mmr.update_from_verified_proof(vec![[0xBB; 32]], 8, &[]);

        assert_eq!(mmr.leaf_count(), 8);
        for h in 8..11u32 {
            // No entry at these heights regardless of hash.
            let any_present = (0u8..=255).any(|b| mmr.has_recent_block(&[b; 32], h));
            assert!(!any_present, "height {} must be absent after shorter-chain update", h);
        }
        // Heights 0-7 are untouched (proof carried no blocks, so Step 2 is a no-op).
        for h in 0..8u32 {
            assert!(mmr.has_recent_block(&[h as u8 + 1; 32], h),
                "height {} must still be cached", h);
        }
    }

    #[test]
    fn reorg_to_zero_leaf_count_clears_all() {
        let mut mmr = mmr_with_blocks(5);
        mmr.update_from_verified_proof(vec![], 0, &[]);
        assert_eq!(mmr.recent_blocks_count(), 0);
        assert_eq!(mmr.leaf_count(), 0);
    }

    #[test]
    fn extension_removes_nothing_by_height() {
        // new_leaf_count > current leaf_count: no heights exceed the new tip.
        let mut mmr = mmr_with_blocks(5);
        let new_block = ([0xF1; 32], 5u32);
        mmr.update_from_verified_proof(vec![[0xCC; 32]], 6, &[new_block]);

        // All original heights still present.
        for h in 0..5u32 {
            assert!(mmr.has_recent_block(&[h as u8 + 1; 32], h));
        }
        // New height inserted.
        assert!(mmr.has_recent_block(&[0xF1; 32], 5));
    }

    // =========================================================================
    // Step 2: proof-covered heights replace stale entries (no duplicates)
    // =========================================================================

    #[test]
    fn reorg_tip_block_old_hash_evicted_new_hash_present() {
        // Classic 1-block tip reorg: height 4 replaced by a different block.
        let mut mmr = mmr_with_blocks(5);    // heights 0-4, leaf_count=5
        let old_hash_at_4: [u8; 32] = [5u8; 32];   // what mmr_with_blocks put at height 4

        assert!(mmr.has_recent_block(&old_hash_at_4, 4), "old hash should be cached before reorg");

        let new_hash_at_4 = [0x44u8; 32];
        mmr.update_from_verified_proof(
            vec![[0xBB; 32]],
            5,
            &[(new_hash_at_4, 4)],
        );

        assert!(!mmr.has_recent_block(&old_hash_at_4, 4),
            "old hash must be gone after reorg update");
        assert!(mmr.has_recent_block(&new_hash_at_4, 4),
            "new hash must be present after reorg update");
    }

    #[test]
    fn reorg_multiple_heights_no_orphaned_duplicates() {
        // Heights 2, 3, 4 all replaced on the new chain.
        let mut mmr = mmr_with_blocks(5);

        let new_blocks = [
            ([0x22u8; 32], 2u32),
            ([0x33u8; 32], 3u32),
            ([0x44u8; 32], 4u32),
        ];
        mmr.update_from_verified_proof(vec![[0xBB; 32]], 5, &new_blocks);

        // Old hashes at heights 2, 3, 4 must be gone.
        for (old, h) in [([3u8; 32], 2u32), ([4u8; 32], 3u32), ([5u8; 32], 4u32)] {
            assert!(!mmr.has_recent_block(&old, h),
                "old hash at height {} must be evicted", h);
        }
        // New hashes must be present.
        for (new, h) in new_blocks {
            assert!(mmr.has_recent_block(&new, h),
                "new hash at height {} must be present", h);
        }
        // Unchanged heights (0, 1) must still be there.
        for h in 0..2u32 {
            assert!(mmr.has_recent_block(&[h as u8 + 1; 32], h),
                "height {} must be untouched", h);
        }
    }

    #[test]
    fn proof_covered_height_has_exactly_one_entry() {
        // Even if the same height appears in the cache twice (e.g. from a prior
        // buggy update), a new proof covering that height evicts all old entries
        // and inserts exactly one.
        let mut mmr = MMRLight::with_capacity(20);

        // Simulate a stale duplicate by direct insert.
        mmr.recent_blocks.insert(([0xAA; 32], 5));
        mmr.recent_blocks.insert(([0xBB; 32], 5));
        mmr.leaf_count = 6;

        // Proof covers height 5 with a definitive new hash.
        mmr.update_from_verified_proof(vec![[0xCC; 32]], 6, &[([0xDD; 32], 5)]);

        // Only the new hash should be at height 5.
        assert!(mmr.has_recent_block(&[0xDD; 32], 5));
        assert!(!mmr.has_recent_block(&[0xAA; 32], 5));
        assert!(!mmr.has_recent_block(&[0xBB; 32], 5));

        // Count entries at height 5: exactly 1.
        let count_at_5 = mmr.recent_blocks.iter().filter(|(_, h)| *h == 5).count();
        assert_eq!(count_at_5, 1, "exactly one entry must exist at height 5");
    }

    #[test]
    fn same_hash_in_proof_is_idempotent() {
        // If the proof supplies the same hash that is already cached (shared prefix),
        // the entry is removed and re-inserted — net effect is no change.
        let mut mmr = mmr_with_blocks(5);
        let existing = ([3u8; 32], 2u32);   // already in cache from mmr_with_blocks

        mmr.update_from_verified_proof(vec![[0xCC; 32]], 5, &[existing]);

        assert!(mmr.has_recent_block(&existing.0, existing.1),
            "re-inserting the same entry must leave it present");
        let count_at_2 = mmr.recent_blocks.iter().filter(|(_, h)| *h == 2).count();
        assert_eq!(count_at_2, 1, "no duplicate created for idempotent insert");
    }

    // =========================================================================
    // Combined Step 1 + Step 2 (reorg that both shortens and diverges)
    // =========================================================================

    #[test]
    fn reorg_to_shorter_chain_with_diverging_blocks() {
        // Cache: heights 0-9, leaf_count=10.
        // New chain: new_leaf_count=7, proof covers heights 5 and 6 with new hashes.
        // Expectation: heights 7-9 purged (Step 1); old hashes at 5,6 evicted (Step 2).
        let mut mmr = mmr_with_blocks(10);

        let new_5 = [0x55u8; 32];
        let new_6 = [0x66u8; 32];
        mmr.update_from_verified_proof(
            vec![[0xBB; 32]],
            7,
            &[(new_5, 5), (new_6, 6)],
        );

        assert_eq!(mmr.leaf_count(), 7);

        // Heights 7-9: purged by Step 1.
        for h in 7..10u32 {
            let any = (0u8..=255).any(|b| mmr.has_recent_block(&[b; 32], h));
            assert!(!any, "height {} must be absent", h);
        }
        // Heights 5, 6: old hashes gone, new hashes present.
        assert!(!mmr.has_recent_block(&[6u8; 32], 5));
        assert!(mmr.has_recent_block(&new_5, 5));
        assert!(!mmr.has_recent_block(&[7u8; 32], 6));
        assert!(mmr.has_recent_block(&new_6, 6));
        // Heights 0-4: untouched.
        for h in 0..5u32 {
            assert!(mmr.has_recent_block(&[h as u8 + 1; 32], h));
        }
    }

    // =========================================================================
    // Capacity enforcement after reorg
    // =========================================================================

    #[test]
    fn reorg_respects_max_recent_blocks() {
        // Capacity 5. Reorg inserts 8 new blocks → must prune to 5.
        let mut mmr = MMRLight::with_capacity(5);
        mmr.update_from_verified_proof(vec![[0xAA; 32]], 3, &[
            ([1u8; 32], 0), ([2u8; 32], 1), ([3u8; 32], 2),
        ]);

        let new_blocks: Vec<([u8; 32], u32)> = (0..8u32)
            .map(|i| ([i as u8 + 0x10; 32], i))
            .collect();
        mmr.update_from_verified_proof(vec![[0xBB; 32]], 8, &new_blocks);

        assert!(
            mmr.recent_blocks_count() <= 5,
            "cache must not exceed capacity after reorg, got {}",
            mmr.recent_blocks_count()
        );
    }

    // =========================================================================
    // Empty-blocks update (chain-weight proof pattern)
    // =========================================================================

    #[test]
    fn empty_blocks_updates_peaks_and_leaf_count_only() {
        let mut mmr = mmr_with_blocks(5);
        let new_peaks = vec![[0xBB; 32], [0xCC; 32]];
        mmr.update_from_verified_proof(new_peaks.clone(), 6, &[]);

        assert_eq!(mmr.leaf_count(), 6);
        assert_eq!(mmr.peak_count(), 2);
        // Blocks 0-4 still present (proof covered no heights, Step 2 no-op).
        assert_eq!(mmr.recent_blocks_count(), 5);
    }

    #[test]
    fn empty_blocks_shorter_chain_still_purges_excess_heights() {
        let mut mmr = mmr_with_blocks(10);
        mmr.update_from_verified_proof(vec![[0xBB; 32]], 6, &[]);

        for h in 6..10u32 {
            let any = (0u8..=255).any(|b| mmr.has_recent_block(&[b; 32], h));
            assert!(!any, "height {} must be absent even with empty proof blocks", h);
        }
        assert_eq!(mmr.recent_blocks_count(), 6);
    }

    // =========================================================================
    // Invariants that must hold after every update
    // =========================================================================

    #[test]
    fn invariant_no_entry_at_or_above_leaf_count() {
        let mut mmr = mmr_with_blocks(10);
        mmr.update_from_verified_proof(vec![[0xBB; 32]], 7, &[([0x77; 32], 6)]);

        for (_, h) in &mmr.recent_blocks {
            assert!(*h < mmr.leaf_count(),
                "entry at height {} violates invariant: must be < leaf_count {}",
                h, mmr.leaf_count());
        }
    }

    #[test]
    fn invariant_proof_covered_heights_have_single_entry() {
        let mut mmr = mmr_with_blocks(5);
        let proof_blocks = [([0x11u8; 32], 1u32), ([0x33u8; 32], 3u32)];
        mmr.update_from_verified_proof(vec![[0xBB; 32]], 6, &proof_blocks);

        for (_, h) in proof_blocks {
            let count = mmr.recent_blocks.iter().filter(|(_, rh)| *rh == h).count();
            assert_eq!(count, 1,
                "height {} must have exactly 1 entry after update, found {}", h, count);
        }
    }

    #[test]
    fn invariant_capacity_never_exceeded() {
        let cap = 5usize;
        let mut mmr = MMRLight::with_capacity(cap);

        // Run several updates of varying sizes.
        for round in 0u32..4 {
            let start = round * 3;
            let blocks: Vec<([u8; 32], u32)> = (start..start + 6)
                .map(|i| ([(i % 200) as u8 + 1; 32], i))
                .collect();
            mmr.update_from_verified_proof(vec![[round as u8; 32]], start + 6, &blocks);
            assert!(mmr.recent_blocks_count() <= cap,
                "round {}: cache size {} exceeds capacity {}", round, mmr.recent_blocks_count(), cap);
        }
    }
}

/*
===============================================================================
MMR LIGHT VS FULL MMR - COMPARISON
===============================================================================

MEMORY USAGE AT HEIGHT 1,000,000:
=================================

Full MMR (Vec-based):
- Nodes: ~2,000,000 × 32 bytes = 64 MB
- Purpose: Generate proofs, full history

MMR Light (HashSet-based):
- Peaks: ~20 × 32 bytes = 640 bytes
- Recent blocks: 100 × (32 + 4) bytes = 3,600 bytes
- Total: ~4 KB

Savings: 16,000x less memory!


OPERATIONS COMPARISON:
=====================

| Operation | Full MMR | MMR Light | Notes |
|-----------|----------|-----------|-------|
| Append | O(log n) | ❌ Not supported | Light clients don't mine |
| Verify | O(log n) | O(log n) | Both can verify proofs |
| Get Root | O(p) | O(p) | p = peak count |
| Generate Proof | O(log n) | ❌ Not supported | Full node only |
| Has Block | O(n) | O(1) | HashSet advantage |
| Memory | O(n) | O(log n + k) | k = recent cache |


WHEN TO USE EACH:
=================

Full MMR:
- Mining pools (need append)
- Full nodes (need to generate proofs)
- Archival nodes (need full history)

MMR Light:
- Light clients (verify only)
- Mobile wallets (memory constrained)
- Embedded devices (minimal resources)
- Web browsers (WASM constraints)


FUTURE: HYBRID MMR
==================

For mining pools, a hybrid approach:

```rust,ignore
pub struct MMRHybrid {
    // Recent blocks: fast append (VecDeque)
    recent: VecDeque<[u8; 32]>,
    
    // Historical: fast lookup (HashSet)
    historical: HashSet<([u8; 32], u32)>,
    
    // Threshold for moving to historical
    recent_threshold: usize,
}
```

Benefits:
- O(1) append (VecDeque)
- O(1) lookup (HashSet)
- Memory efficient (only recent in RAM)
- Best of both worlds

===============================================================================
*/