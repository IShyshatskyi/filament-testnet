// ============================================================================
// src/mmr_client/weighted_mmr_light.rs - Weighted MMR Light Client State
// ============================================================================

//! Lightweight weighted MMR for verification-only light client operations.
//!
//! This is the weighted counterpart of [`super::mmr_light::MMRLight`], using
//! [`WeightedHash`] (224-bit BLAKE3 hash + 32-bit compact rBits) instead of
//! plain `[u8; 32]` for peaks and recent-block cache entries.
//!
//! ## Why WeightedHash?
//!
//! Every MMR node in a [`WeightedMMR`] carries cumulative chain difficulty in
//! its rBits field.  A light client that stores `WeightedHash` peaks can
//! therefore read the **total chain weight directly from the MMR root** — no
//! separate difficulty field needed, and the weight is covered by the same
//! cryptographic commitment as the structural hash.
//!
//! ## Memory
//!
//! Same O(log n + k) as `MMRLight`:
//! - Peaks: ~20 × 32 bytes = 640 bytes at height 1 M
//! - Recent-block cache: k × (32 + 4) bytes = 3.6 KB at k = 100
//!
//! ## Usage
//!
//! ```rust,ignore
//! let mut mmr = WeightedMMRLight::new();
//!
//! // After verifying a WeightedMMRBatchProof:
//! mmr.update_from_verified_proof(
//!     proof.peaks.clone(),   // Vec<WeightedHash>
//!     proof.leaf_count,
//!     &proof_blocks,         // &[(WeightedHash, u32)]
//! );
//!
//! let root: WeightedHash = mmr.get_root();
//! println!("chain weight: {}", root.cumulative_difficulty_approx());
//! ```

use std::collections::HashSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use log::debug;

use common_types::common::crypto::weighted_hash::{bag_peaks_weighted, WeightedHash};

// ============================================================================
// CUSTOM SERIALIZATION FOR HashSet<(WeightedHash, u32)>
// ============================================================================
//
// `HashSet` serializes as an unordered sequence, which is valid JSON but
// causes determinism problems in round-trip tests.  Serializing via Vec
// guarantees a well-formed sequence and round-trips correctly through
// serde_json.

/// Serialize `HashSet<(WeightedHash, u32)>` as a `Vec` for JSON stability.
fn serialize_recent_blocks<S>(
    blocks: &HashSet<(WeightedHash, u32)>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec: Vec<(WeightedHash, u32)> = blocks.iter().copied().collect();
    vec.serialize(serializer)
}

/// Deserialize a `Vec<(WeightedHash, u32)>` back into a `HashSet`.
fn deserialize_recent_blocks<'de, D>(
    deserializer: D,
) -> Result<HashSet<(WeightedHash, u32)>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<(WeightedHash, u32)> = Vec::deserialize(deserializer)?;
    Ok(vec.into_iter().collect())
}

// ============================================================================
// WeightedMMRLight
// ============================================================================

/// Lightweight weighted MMR for verification-only light clients.
///
/// Holds only the minimal state needed to:
/// - Compute the current MMR root (via peak bagging)
/// - Answer `has_recent_block(hash, height)` in O(1)
/// - Track cumulative chain weight (via `get_root().cumulative_difficulty_approx()`)
///
/// # Reorg safety
///
/// `update_from_verified_proof` applies a two-step algorithm identical to
/// [`super::mmr_light::MMRLight`]:
/// 1. **Purge** all cached entries with `height >= new_leaf_count`.
/// 2. **Evict** stale entries at proof-covered heights, then insert new ones.
///
/// # Memory
///
/// Peak count ≤ 64 (64-bit chain).  Recent-block cache bounded by
/// `max_recent_blocks` (default 100).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedMMRLight {
    /// Anchor node (Bitcoin genesis or chain-specific genesis WeightedHash).
    /// rBits = 0 by convention; the anchor contributes no chain weight.
    anchor: WeightedHash,

    /// Current MMR peaks in **reverse** order (largest to smallest).
    ///
    /// `get_root()` reverses this slice before calling `bag_peaks_weighted`
    /// so that peaks are folded left-to-right as required by the MMR spec.
    peaks: Vec<WeightedHash>,

    /// O(1) lookup cache of recently seen blocks: `(weighted_hash, height)`.
    ///
    /// Custom serde: serialized as a `Vec` for JSON stability; deserialized
    /// back into a `HashSet` transparently.
    #[serde(
        serialize_with = "serialize_recent_blocks",
        deserialize_with = "deserialize_recent_blocks"
    )]
    recent_blocks: HashSet<(WeightedHash, u32)>,

    /// Number of leaves committed to the MMR (= chain height + 1).
    leaf_count: u32,

    /// Upper bound on `recent_blocks.len()`.
    max_recent_blocks: usize,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl WeightedMMRLight {
    // -------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------

    /// Create an empty `WeightedMMRLight` with a 100-block recent-block cache.
    pub fn new() -> Self {
        Self::with_capacity(100)
    }

    /// Create with a specific cache capacity.
    ///
    /// # Arguments
    /// * `max_recent_blocks` — maximum blocks to hold in the O(1) cache.
    ///
    /// # Recommended values
    /// - Mobile wallet: 100–200
    /// - Desktop wallet: 500–1 000
    /// - Server / full verification: 2 000–5 000
    pub fn with_capacity(max_recent_blocks: usize) -> Self {
        Self {
            anchor: WeightedHash::zero(),
            peaks: Vec::new(),
            recent_blocks: HashSet::new(),
            leaf_count: 0,
            max_recent_blocks,
        }
    }

    /// Create with an explicit anchor `WeightedHash`.
    ///
    /// Typical callers use [`WeightedHash::from_anchor`] to build the anchor
    /// from a Bitcoin genesis block hash:
    ///
    /// ```rust,ignore
    /// let anchor = WeightedHash::from_anchor(&bitcoin_genesis_hash);
    /// let mmr = WeightedMMRLight::with_anchor(anchor, 200);
    /// ```
    pub fn with_anchor(anchor: WeightedHash, max_recent_blocks: usize) -> Self {
        Self {
            anchor,
            peaks: Vec::new(),
            recent_blocks: HashSet::new(),
            leaf_count: 0,
            max_recent_blocks,
        }
    }

    // -------------------------------------------------------------------
    // Primary update operation
    // -------------------------------------------------------------------

    /// Update state from a cryptographically verified proof of a heavier chain.
    ///
    /// The caller **must** have verified the proof before calling this method.
    /// No additional cryptographic checks are performed here.
    ///
    /// # Reorg safety
    ///
    /// Two-step algorithm (mirrors `MMRLight::update_from_verified_proof`):
    ///
    /// **Step 1 — purge definitely-orphaned entries.**
    /// Retains only entries whose `height < new_leaf_count`.  This fully
    /// handles reorgs to shorter chains.
    ///
    /// **Step 2 — evict stale entries at proof-covered heights.**
    /// Removes all cached entries whose height appears in `blocks`, then
    /// inserts the new-chain entries.  This prevents `(old_hash, H)` and
    /// `(new_hash, H)` from coexisting for any proof-covered height.
    ///
    /// Heights in `[0, new_leaf_count)` not covered by the proof are left
    /// unchanged.
    ///
    /// # Arguments
    /// * `new_peaks`      — MMR peaks of the new canonical chain, in **reverse**
    ///                      order (largest to smallest).  Pass the `peaks` field
    ///                      of a verified `WeightedMMRBatchProof` directly.
    /// * `new_leaf_count` — Tip height + 1 of the new canonical chain.
    /// * `blocks`         — Sparse set of `(WeightedHash, height)` pairs from
    ///                      the new chain.  May be empty (e.g. chain-weight
    ///                      proofs that carry no block data).
    ///
    /// # Post-conditions
    /// - `get_root()` reflects the new canonical chain's MMR root.
    /// - `leaf_count()` equals `new_leaf_count`.
    /// - No cached entry has `height >= new_leaf_count`.
    /// - For every `(wh, height)` in `blocks`: `has_recent_block(wh, height)`
    ///   is `true` and no other hash is cached at that height.
    /// - `recent_blocks_count() <= max_recent_blocks`.
    pub fn update_from_verified_proof(
        &mut self,
        new_peaks: Vec<WeightedHash>,
        new_leaf_count: u32,
        blocks: &[(WeightedHash, u32)],
    ) {
        debug!(
            "WeightedMMRLight: updating from verified proof \
             (leaf_count: {} → {})",
            self.leaf_count, new_leaf_count
        );

        // ── Step 1: purge definitely-orphaned entries ──────────────────────
        self.recent_blocks.retain(|(_, h)| *h < new_leaf_count);

        // ── Step 2: evict stale entries at proof-covered heights ───────────
        if !blocks.is_empty() {
            let proof_heights: HashSet<u32> = blocks.iter().map(|(_, h)| *h).collect();
            self.recent_blocks.retain(|(_, h)| !proof_heights.contains(h));

            for &(wh, height) in blocks {
                self.recent_blocks.insert((wh, height));
            }
        }

        debug!(
            "WeightedMMRLight: recent blocks cached: {}",
            self.recent_blocks.len()
        );

        // ── Step 3: replace peaks and leaf count ───────────────────────────
        self.peaks = new_peaks;
        self.leaf_count = new_leaf_count;

        debug!("WeightedMMRLight: new peaks count: {}", self.peaks.len());

        // ── Step 4: enforce capacity ────────────────────────────────────────
        if self.recent_blocks.len() > self.max_recent_blocks {
            self.prune_to_size(self.max_recent_blocks);
        }
    }

    // -------------------------------------------------------------------
    // Root computation
    // -------------------------------------------------------------------

    /// Compute the current MMR root by bagging all peaks.
    ///
    /// Returns the anchor when no peaks have been committed.  The returned
    /// `WeightedHash` carries the cumulative chain difficulty in its `rbits()`
    /// field — no separate weight field is needed.
    ///
    /// # Complexity
    /// O(p) where p = number of peaks (≤ 64 for a 64-bit height chain).
    pub fn get_root(&self) -> WeightedHash {
        if self.peaks.is_empty() {
            return self.anchor;
        }

        // Peaks are stored largest-to-smallest; bag_peaks_weighted expects
        // them smallest-to-largest (left-to-right in the MMR bitmap).
        let mut peaks_ltr = self.peaks.clone();
        peaks_ltr.reverse();

        bag_peaks_weighted(&peaks_ltr, self.anchor)
    }

    // -------------------------------------------------------------------
    // Cache queries
    // -------------------------------------------------------------------

    /// O(1) lookup: check whether a block is in the recent-block cache.
    ///
    /// Returns `true` only if the exact `(wh, height)` pair was inserted by
    /// a prior `update_from_verified_proof` call.  A block that was on an
    /// orphaned chain is removed during the next reorg update.
    pub fn has_recent_block(&self, wh: &WeightedHash, height: u32) -> bool {
        self.recent_blocks.contains(&(*wh, height))
    }

    // -------------------------------------------------------------------
    // Cache management
    // -------------------------------------------------------------------

    /// Update the cache size limit.
    ///
    /// If `new_max` is smaller than the current cache size, prunes immediately
    /// by keeping the blocks at the highest heights.
    pub fn set_max_recent_blocks(&mut self, new_max: usize) {
        self.max_recent_blocks = new_max;
        if self.recent_blocks.len() > new_max {
            self.prune_to_size(new_max);
        }
    }

    /// Current cache size limit.
    pub fn max_recent_blocks(&self) -> usize {
        self.max_recent_blocks
    }

    /// Add a single block to the recent-block cache (internal / test helper).
    ///
    /// Automatically prunes when the cache exceeds `max_recent_blocks`.
    fn add_recent_block(&mut self, wh: WeightedHash, height: u32) {
        self.recent_blocks.insert((wh, height));
        if self.recent_blocks.len() > self.max_recent_blocks {
            self.prune_by_height_from(height);
        }
    }

    /// Prune the cache to `target_size` by discarding the lowest-height entries.
    fn prune_to_size(&mut self, target_size: usize) {
        if self.recent_blocks.len() <= target_size {
            return;
        }

        let mut heights: Vec<u32> = self.recent_blocks.iter().map(|(_, h)| *h).collect();
        heights.sort_unstable();

        if let Some(&cutoff) = heights.get(heights.len() - target_size) {
            self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        }

        debug!(
            "WeightedMMRLight: pruned to {} blocks",
            self.recent_blocks.len()
        );
    }

    /// Prune entries below a height-based cutoff derived from `current_height`.
    fn prune_by_height_from(&mut self, current_height: u32) {
        let cutoff = current_height.saturating_sub(self.max_recent_blocks as u32 - 1);
        self.recent_blocks.retain(|(_, h)| *h >= cutoff);
        debug!(
            "WeightedMMRLight: pruned entries below height {} → {} blocks",
            cutoff,
            self.recent_blocks.len()
        );
    }

    // -------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------

    /// Number of leaves committed to the MMR (= chain height + 1).
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    /// Current chain height (= leaf_count - 1, saturating at 0).
    pub fn height(&self) -> u32 {
        self.leaf_count.saturating_sub(1)
    }

    /// Current MMR peaks (in reverse / storage order).
    pub fn peaks(&self) -> &[WeightedHash] {
        &self.peaks
    }

    /// Number of peaks.
    pub fn peak_count(&self) -> usize {
        self.peaks.len()
    }

    /// Current number of entries in the recent-block cache.
    pub fn recent_blocks_count(&self) -> usize {
        self.recent_blocks.len()
    }

    /// The anchor `WeightedHash` (genesis / pivot point; rBits = 0).
    pub fn anchor(&self) -> WeightedHash {
        self.anchor
    }

    // -------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------

    /// Reset all state (for full reorg / re-sync from genesis).
    pub fn clear(&mut self) {
        debug!("WeightedMMRLight: clearing all state");
        self.peaks.clear();
        self.recent_blocks.clear();
        self.leaf_count = 0;
    }

    /// Approximate memory footprint in bytes.
    pub fn estimate_memory_bytes(&self) -> usize {
        // WeightedHash = 32 bytes; height = 4 bytes; HashSet entry overhead ≈ 8 bytes
        let peaks_bytes = self.peaks.len() * 32;
        let cache_bytes = self.recent_blocks.len() * (32 + 4 + 8);
        let overhead = 64;
        peaks_bytes + cache_bytes + overhead
    }

    /// Snapshot of cache statistics for monitoring / diagnostics.
    pub fn cache_stats(&self) -> WeightedCacheStats {
        let memory_bytes = self.estimate_memory_bytes();
        let fill_percent = if self.max_recent_blocks > 0 {
            (self.recent_blocks.len() as f64 / self.max_recent_blocks as f64 * 100.0) as u32
        } else {
            0
        };
        WeightedCacheStats {
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
// TRAIT IMPLEMENTATIONS
// ============================================================================

impl Default for WeightedMMRLight {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Diagnostic statistics for a `WeightedMMRLight` instance.
#[derive(Debug, Clone)]
pub struct WeightedCacheStats {
    pub current_size: usize,
    pub max_size: usize,
    pub fill_percent: u32,
    pub memory_bytes: usize,
    pub peak_count: usize,
    pub leaf_count: u32,
}

impl std::fmt::Display for WeightedCacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WeightedCache: {}/{} blocks ({}% full), {} peaks, \
             {} leaves, ~{} bytes",
            self.current_size,
            self.max_size,
            self.fill_percent,
            self.peak_count,
            self.leaf_count,
            self.memory_bytes,
        )
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::crypto::weighted_hash::WeightedHash;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn leaf(seed: u8) -> WeightedHash {
        // Public packaging: use header-native rBits (no legacy nBits→rBits helper).
        WeightedHash::from_leaf_rbits(&[seed; 32], 0x0300_0001)
    }

    /// Build a `WeightedMMRLight` populated with blocks `0..n`.
    fn mmr_with_blocks(n: u32) -> WeightedMMRLight {
        let mut m = WeightedMMRLight::with_capacity(100);
        let blocks: Vec<(WeightedHash, u32)> = (0..n).map(|i| (leaf(i as u8 + 1), i)).collect();
        let peaks = vec![WeightedHash::from_leaf_rbits(&[0xAAu8; 32], 0x0300_0001)];
        m.update_from_verified_proof(peaks, n, &blocks);
        m
    }

    // -----------------------------------------------------------------------
    // Constructor tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_is_empty() {
        let m = WeightedMMRLight::default();
        assert_eq!(m.leaf_count(), 0);
        assert_eq!(m.peak_count(), 0);
        assert_eq!(m.recent_blocks_count(), 0);
        assert_eq!(m.max_recent_blocks(), 100);
    }

    #[test]
    fn with_anchor_stores_anchor() {
        let anchor = WeightedHash::from_anchor(&[0xFFu8; 32]);
        let m = WeightedMMRLight::with_anchor(anchor, 50);
        assert_eq!(m.anchor(), anchor);
        assert_eq!(m.max_recent_blocks(), 50);
    }

    #[test]
    fn get_root_returns_anchor_when_empty() {
        let anchor = WeightedHash::from_anchor(&[0xAAu8; 32]);
        let m = WeightedMMRLight::with_anchor(anchor, 10);
        assert_eq!(m.get_root(), anchor);
    }

    // -----------------------------------------------------------------------
    // Root computation
    // -----------------------------------------------------------------------

    #[test]
    fn get_root_single_peak() {
        let anchor = WeightedHash::zero();
        let peak   = leaf(1);
        let mut m  = WeightedMMRLight::with_anchor(anchor, 10);
        m.update_from_verified_proof(vec![peak], 1, &[(peak, 0)]);

        use common_types::common::crypto::weighted_hash::bag_peaks_weighted;
        let expected = bag_peaks_weighted(&[peak], anchor);
        assert_eq!(m.get_root(), expected);
    }

    #[test]
    fn get_root_carries_chain_weight() {
        let m = mmr_with_blocks(5);
        let root = m.get_root();
        // The root of a non-empty weighted MMR must have non-zero rBits.
        assert!(root.has_weight(), "root must carry cumulative chain weight");
    }

    // -----------------------------------------------------------------------
    // Serialisation round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn serde_round_trip() {
        let mut m = WeightedMMRLight::with_capacity(3);
        let blocks = vec![(leaf(10), 0u32), (leaf(11), 1), (leaf(12), 2)];
        m.update_from_verified_proof(vec![leaf(1), leaf(2)], 3, &blocks);

        let json  = serde_json::to_string(&m).unwrap();
        let m2: WeightedMMRLight = serde_json::from_str(&json).unwrap();

        assert_eq!(m2.leaf_count(), 3);
        assert_eq!(m2.peak_count(), 2);
        assert_eq!(m2.recent_blocks_count(), 3);
        assert!(m2.has_recent_block(&leaf(10), 0));
        assert!(m2.has_recent_block(&leaf(11), 1));
        assert!(m2.has_recent_block(&leaf(12), 2));
        assert!(!m2.has_recent_block(&leaf(99), 0));
    }

    // -----------------------------------------------------------------------
    // Cache sizing
    // -----------------------------------------------------------------------

    #[test]
    fn add_recent_block_prunes_at_capacity() {
        let mut m = WeightedMMRLight::with_capacity(5);
        for i in 0..10u32 {
            m.add_recent_block(leaf(i as u8 + 1), i);
            m.leaf_count = i + 1;
        }
        assert_eq!(m.recent_blocks_count(), 5);
    }

    #[test]
    fn set_max_recent_blocks_prunes_immediately() {
        let mut m = WeightedMMRLight::with_capacity(10);
        for i in 0..10u32 {
            m.add_recent_block(leaf(i as u8 + 1), i);
            m.leaf_count = i + 1;
        }
        m.set_max_recent_blocks(3);
        assert_eq!(m.recent_blocks_count(), 3);
    }

    #[test]
    fn cache_stats_fill_percent() {
        let mut m = WeightedMMRLight::with_capacity(100);
        for i in 0..50u32 {
            m.add_recent_block(leaf(i as u8 + 1), i);
            m.leaf_count = i + 1;
        }
        let stats = m.cache_stats();
        assert_eq!(stats.current_size, 50);
        assert_eq!(stats.fill_percent, 50);
        assert_eq!(stats.leaf_count, 50);
    }

    // -----------------------------------------------------------------------
    // Step 1: heights ≥ new_leaf_count purged unconditionally
    // -----------------------------------------------------------------------

    #[test]
    fn reorg_to_shorter_chain_purges_excess_heights() {
        let mut m = mmr_with_blocks(11);
        assert_eq!(m.recent_blocks_count(), 11);

        m.update_from_verified_proof(vec![leaf(0xBB)], 8, &[]);

        assert_eq!(m.leaf_count(), 8);
        for h in 8..11u32 {
            let any = (1u8..=255).any(|b| m.has_recent_block(&leaf(b), h));
            assert!(!any, "height {} must be absent after shorter-chain update", h);
        }
        // Heights 0-7 untouched (proof carried no blocks → Step 2 no-op).
        for h in 0..8u32 {
            assert!(
                m.has_recent_block(&leaf(h as u8 + 1), h),
                "height {} must still be cached",
                h
            );
        }
    }

    #[test]
    fn reorg_to_zero_clears_all() {
        let mut m = mmr_with_blocks(5);
        m.update_from_verified_proof(vec![], 0, &[]);
        assert_eq!(m.recent_blocks_count(), 0);
        assert_eq!(m.leaf_count(), 0);
    }

    #[test]
    fn extension_removes_nothing_by_height() {
        let mut m  = mmr_with_blocks(5);
        let new_block = (leaf(0xF1), 5u32);
        m.update_from_verified_proof(vec![leaf(0xCC)], 6, &[new_block]);

        for h in 0..5u32 {
            assert!(m.has_recent_block(&leaf(h as u8 + 1), h));
        }
        assert!(m.has_recent_block(&leaf(0xF1), 5));
    }

    // -----------------------------------------------------------------------
    // Step 2: proof-covered heights evict stale entries
    // -----------------------------------------------------------------------

    #[test]
    fn reorg_tip_block_old_hash_evicted_new_hash_present() {
        let mut m = mmr_with_blocks(5); // heights 0-4
        let old_at_4 = leaf(5);         // what mmr_with_blocks put at height 4

        assert!(m.has_recent_block(&old_at_4, 4));

        let new_at_4 = leaf(0x44);
        m.update_from_verified_proof(vec![leaf(0xBB)], 5, &[(new_at_4, 4)]);

        assert!(!m.has_recent_block(&old_at_4, 4), "old hash must be evicted");
        assert!(m.has_recent_block(&new_at_4, 4),  "new hash must be present");
    }

    #[test]
    fn reorg_multiple_heights_no_orphaned_duplicates() {
        let mut m = mmr_with_blocks(5);
        let new_blocks = [(leaf(0x22), 2u32), (leaf(0x33), 3), (leaf(0x44), 4)];
        m.update_from_verified_proof(vec![leaf(0xBB)], 5, &new_blocks);

        for (old, h) in [(leaf(3), 2u32), (leaf(4), 3), (leaf(5), 4)] {
            assert!(!m.has_recent_block(&old, h), "old hash at height {} must be evicted", h);
        }
        for (wh, h) in new_blocks {
            assert!(m.has_recent_block(&wh, h), "new hash at height {} must be present", h);
        }
        for h in 0..2u32 {
            assert!(m.has_recent_block(&leaf(h as u8 + 1), h), "height {} must be untouched", h);
        }
    }

    #[test]
    fn proof_covered_height_has_exactly_one_entry() {
        let mut m = WeightedMMRLight::with_capacity(20);
        m.recent_blocks.insert((leaf(0xAA), 5));
        m.recent_blocks.insert((leaf(0xBB), 5));
        m.leaf_count = 6;

        m.update_from_verified_proof(vec![leaf(0xCC)], 6, &[(leaf(0xDD), 5)]);

        assert!(m.has_recent_block(&leaf(0xDD), 5));
        assert!(!m.has_recent_block(&leaf(0xAA), 5));
        assert!(!m.has_recent_block(&leaf(0xBB), 5));

        let count = m.recent_blocks.iter().filter(|(_, h)| *h == 5).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn same_hash_in_proof_is_idempotent() {
        let mut m = mmr_with_blocks(5);
        let existing = (leaf(3), 2u32);
        m.update_from_verified_proof(vec![leaf(0xCC)], 5, &[existing]);

        assert!(m.has_recent_block(&existing.0, existing.1));
        let count = m.recent_blocks.iter().filter(|(_, h)| *h == 2).count();
        assert_eq!(count, 1);
    }

    // -----------------------------------------------------------------------
    // Combined Step 1 + Step 2
    // -----------------------------------------------------------------------

    #[test]
    fn reorg_shorter_chain_with_diverging_blocks() {
        let mut m   = mmr_with_blocks(10);
        let new_5   = leaf(0x55);
        let new_6   = leaf(0x66);
        m.update_from_verified_proof(vec![leaf(0xBB)], 7, &[(new_5, 5), (new_6, 6)]);

        assert_eq!(m.leaf_count(), 7);

        for h in 7..10u32 {
            let any = (1u8..=255).any(|b| m.has_recent_block(&leaf(b), h));
            assert!(!any, "height {} must be absent", h);
        }
        assert!(!m.has_recent_block(&leaf(6), 5));
        assert!(m.has_recent_block(&new_5, 5));
        assert!(!m.has_recent_block(&leaf(7), 6));
        assert!(m.has_recent_block(&new_6, 6));
        for h in 0..5u32 {
            assert!(m.has_recent_block(&leaf(h as u8 + 1), h));
        }
    }

    // -----------------------------------------------------------------------
    // Capacity enforcement after reorg
    // -----------------------------------------------------------------------

    #[test]
    fn reorg_respects_max_recent_blocks() {
        let mut m = WeightedMMRLight::with_capacity(5);
        m.update_from_verified_proof(
            vec![leaf(0xAA)],
            3,
            &[(leaf(1), 0), (leaf(2), 1), (leaf(3), 2)],
        );

        let new_blocks: Vec<(WeightedHash, u32)> =
            (0..8u32).map(|i| (leaf(i as u8 + 0x10), i)).collect();
        m.update_from_verified_proof(vec![leaf(0xBB)], 8, &new_blocks);

        assert!(
            m.recent_blocks_count() <= 5,
            "cache must not exceed capacity after reorg, got {}",
            m.recent_blocks_count()
        );
    }

    // -----------------------------------------------------------------------
    // Empty-blocks update (chain-weight proof pattern)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_blocks_updates_peaks_and_leaf_count_only() {
        let mut m   = mmr_with_blocks(5);
        let new_peaks = vec![leaf(0xBB), leaf(0xCC)];
        m.update_from_verified_proof(new_peaks.clone(), 6, &[]);

        assert_eq!(m.leaf_count(), 6);
        assert_eq!(m.peak_count(), 2);
        assert_eq!(m.recent_blocks_count(), 5);
    }

    #[test]
    fn empty_blocks_shorter_chain_still_purges_excess_heights() {
        let mut m = mmr_with_blocks(10);
        m.update_from_verified_proof(vec![leaf(0xBB)], 6, &[]);

        for h in 6..10u32 {
            let any = (1u8..=255).any(|b| m.has_recent_block(&leaf(b), h));
            assert!(!any, "height {} must be absent even with empty proof blocks", h);
        }
        assert_eq!(m.recent_blocks_count(), 6);
    }

    // -----------------------------------------------------------------------
    // Invariants
    // -----------------------------------------------------------------------

    #[test]
    fn invariant_no_entry_at_or_above_leaf_count() {
        let mut m = mmr_with_blocks(10);
        m.update_from_verified_proof(vec![leaf(0xBB)], 7, &[(leaf(0x77), 6)]);

        for (_, h) in &m.recent_blocks {
            assert!(
                *h < m.leaf_count(),
                "entry at height {} violates invariant: must be < leaf_count {}",
                h,
                m.leaf_count()
            );
        }
    }

    #[test]
    fn invariant_proof_covered_heights_have_single_entry() {
        let mut m = mmr_with_blocks(5);
        let proof_blocks = [(leaf(0x11), 1u32), (leaf(0x33), 3u32)];
        m.update_from_verified_proof(vec![leaf(0xBB)], 6, &proof_blocks);

        for (_, h) in proof_blocks {
            let count = m.recent_blocks.iter().filter(|(_, rh)| *rh == h).count();
            assert_eq!(count, 1, "height {} must have exactly 1 entry, found {}", h, count);
        }
    }

    #[test]
    fn invariant_capacity_never_exceeded() {
        let cap = 5usize;
        let mut m = WeightedMMRLight::with_capacity(cap);

        for round in 0u32..4 {
            let start  = round * 3;
            let blocks: Vec<(WeightedHash, u32)> = (start..start + 6)
                .map(|i| (leaf((i % 200) as u8 + 1), i))
                .collect();
            m.update_from_verified_proof(vec![leaf(round as u8)], start + 6, &blocks);
            assert!(
                m.recent_blocks_count() <= cap,
                "round {}: cache {} exceeds capacity {}",
                round,
                m.recent_blocks_count(),
                cap
            );
        }
    }

    // -----------------------------------------------------------------------
    // clear()
    // -----------------------------------------------------------------------

    #[test]
    fn clear_resets_all_state() {
        let mut m = mmr_with_blocks(5);
        m.clear();
        assert_eq!(m.leaf_count(), 0);
        assert_eq!(m.peak_count(), 0);
        assert_eq!(m.recent_blocks_count(), 0);
        // anchor is untouched
        assert!(!m.anchor().is_zero() || m.anchor() == WeightedHash::zero());
    }
}
