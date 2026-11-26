// src/mmr_client/proof_selector.rs
//
// Auto-detect range vs batch proof strategy.
//
// # Problem
//
// Callers of the light client API previously had to manually choose between
// `GetRangeProof` (consecutive block range) and `GetBatchProof` (arbitrary
// height set).  This is leaky: the caller should not need to reason about
// internal proof cost models.
//
// # Solution
//
// `ProofSelector::analyze` takes the requested heights and a density threshold
// and returns the cheapest strategy:
//
//   density = |heights| / (max - min + 1)
//
//   density >= threshold  →  RangeProof  (low gap overhead, cheap MMR walk)
//   density <  threshold  →  BatchProof  (sparse set, individual witnesses)
//
// # Default threshold
//
// 0.35 (35 % fill) — calibrated against Linux 2-core bench data (May 2026).
// Range proofs are cheaper than batch for D ≥ ~0.22–0.41 across N=10..200.
// 0.35 is a conservative centre of that band.  Callers may tune this per
// `SyncConfiguration`.  See `DEFAULT_DENSITY_THRESHOLD` for derivation.
//
// # Edge cases handled
//
// - Empty input            → `Err(ProofSelectorError::EmptyHeights)`
// - Single height          → `BatchProof` (range overhead not justified)
// - All heights equal      → `BatchProof`
// - Unsorted input         → sorted internally; sorted order returned
// - target_height < max    → `Err(ProofSelectorError::TargetBelowRange)`
// - threshold out of [0,1] → clamped silently (no panic)

use std::fmt;

// ── Public types ─────────────────────────────────────────────────────────────

/// Outcome of `ProofSelector::analyze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStrategy {
    /// Request a contiguous range proof covering `[start, end]`.
    ///
    /// May include a few un-requested intermediate blocks when density < 1.0,
    /// but total MMR path cost is lower than individual witnesses.
    Range {
        /// Inclusive lower bound (minimum of requested heights).
        start: u32,
        /// Inclusive upper bound (maximum of requested heights).
        end: u32,
    },

    /// Request a batch proof for exactly the listed heights.
    ///
    /// Preferred when the requested set is sparse (many gaps) so the proof
    /// payload stays small.
    ///
    /// `heights` is sorted ascending.
    Batch {
        heights: Vec<u32>,
    },
}

/// Errors returned by `ProofSelector::analyze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofSelectorError {
    /// The input heights slice was empty.
    EmptyHeights,

    /// `target_height` is less than the maximum requested height.
    ///
    /// Both `RangeProof` and `BatchProof` require the target to be at or beyond
    /// the proven range.
    TargetBelowRange {
        target:    u32,
        max_height: u32,
    },
}

impl fmt::Display for ProofSelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHeights => write!(f, "heights slice must not be empty"),
            Self::TargetBelowRange { target, max_height } => write!(
                f,
                "target_height {} is below max requested height {}",
                target, max_height,
            ),
        }
    }
}

/// Proof strategy analysis statistics (useful for logging / metrics).
#[derive(Debug, Clone)]
pub struct SelectorStats {
    /// Number of unique heights requested.
    pub requested_count: usize,
    /// Span of the range: `max - min + 1`.
    pub span: u32,
    /// Fill density in `[0.0, 1.0]`.
    pub density: f32,
    /// Threshold that was applied.
    pub threshold: f32,
    /// Chosen strategy.
    pub strategy: ProofStrategy,
}

// ── ProofSelector ─────────────────────────────────────────────────────────────

/// Stateless helper that selects the cheapest proof strategy for a height set.
pub struct ProofSelector;

impl ProofSelector {
    /// Analyse `heights` and return the cheapest `ProofStrategy`.
    ///
    /// # Arguments
    ///
    /// * `heights`           — The block heights to prove.  May be unsorted or
    ///                         contain duplicates; duplicates are de-duplicated.
    /// * `target_height`     — The chain tip height to prove against.  Must be
    ///                         `>= max(heights)`.
    /// * `density_threshold` — Fill ratio above which `RangeProof` is chosen.
    ///                         Clamped to `[0.0, 1.0]`.  Pass
    ///                         `DEFAULT_DENSITY_THRESHOLD` if unsure.
    ///
    /// # Returns
    ///
    /// `Ok(ProofStrategy)` on success, `Err(ProofSelectorError)` on invalid input.
    pub fn analyze(
        heights:           &[u32],
        target_height:     u32,
        density_threshold: f32,
    ) -> Result<ProofStrategy, ProofSelectorError> {
        if heights.is_empty() {
            return Err(ProofSelectorError::EmptyHeights);
        }

        // De-duplicate and sort — cheap for the sizes we expect (≤ 10k).
        let mut sorted: Vec<u32> = heights.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let min = sorted[0];
        let max = *sorted.last().unwrap(); // safe: sorted is non-empty

        // Validate target_height.
        if target_height < max {
            return Err(ProofSelectorError::TargetBelowRange {
                target:     target_height,
                max_height: max,
            });
        }

        // Single block or all-equal — batch is always cheaper.
        if min == max {
            return Ok(ProofStrategy::Batch { heights: sorted });
        }

        // Compute density.
        let span    = max - min + 1;              // always >= 2 here
        let density = sorted.len() as f32 / span as f32;

        // Clamp threshold to [0, 1] to avoid surprising behaviour.
        let threshold = density_threshold.clamp(0.0, 1.0);

        if density >= threshold {
            Ok(ProofStrategy::Range { start: min, end: max })
        } else {
            Ok(ProofStrategy::Batch { heights: sorted })
        }
    }

    /// Like `analyze` but also returns diagnostic `SelectorStats`.
    ///
    /// Useful for logging the decision at `debug!` level without paying the
    /// cost of a separate `analyze` call.
    pub fn analyze_with_stats(
        heights:           &[u32],
        target_height:     u32,
        density_threshold: f32,
    ) -> Result<SelectorStats, ProofSelectorError> {
        if heights.is_empty() {
            return Err(ProofSelectorError::EmptyHeights);
        }

        let mut sorted: Vec<u32> = heights.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let min = sorted[0];
        let max = *sorted.last().unwrap();

        if target_height < max {
            return Err(ProofSelectorError::TargetBelowRange {
                target:     target_height,
                max_height: max,
            });
        }

        let requested_count = sorted.len();

        if min == max {
            let strategy = ProofStrategy::Batch { heights: sorted };
            return Ok(SelectorStats {
                requested_count,
                span: 1,
                density: 1.0,
                threshold: density_threshold.clamp(0.0, 1.0),
                strategy,
            });
        }

        let span      = max - min + 1;
        let density   = requested_count as f32 / span as f32;
        let threshold = density_threshold.clamp(0.0, 1.0);

        let strategy = if density >= threshold {
            ProofStrategy::Range { start: min, end: max }
        } else {
            ProofStrategy::Batch { heights: sorted }
        };

        Ok(SelectorStats {
            requested_count,
            span,
            density,
            threshold,
            strategy,
        })
    }
}

/// Default density threshold exported for use in `SyncConfiguration`.
///
/// 0.35 means: if ≥ 35 % of the span is requested, use a range proof.
///
/// # Calibration (May 20, 2026 — Linux 2-core bench data)
///
/// The threshold is the density D at which range-proof verification cost equals
/// batch-proof cost for N requested heights over a span S = N/D.
///
/// Using `batch_original` and `range_original` baselines (Linux 2-core):
///
/// | N   | batch cost | range crossover S | crossover D |
/// |-----|------------|-------------------|-------------|
/// |  10 |  17.27 µs  |  ~45 heights      |    ~0.22    |
/// |  50 |  75.37 µs  |  ~145 heights     |    ~0.34    |
/// | 100 | 146.6  µs  |  ~260 heights     |    ~0.38    |
/// | 200 | 283.9  µs  |  ~490 heights     |    ~0.41    |
///
/// Range proofs are cheaper for D ≥ ~0.22–0.41 across practical N values.
/// 0.35 sits at the centre of this band and is conservative (the optimised
/// paths lower the crossover further to ~0.20).
///
/// The prior default 0.75 was theoretical ("≤ 25 % extra blocks") and
/// incorrectly routed density-0.35–0.75 sets to batch even though range is
/// faster there.
pub const DEFAULT_DENSITY_THRESHOLD: f32 = 0.35;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── error cases ──────────────────────────────────────────────────────────

    #[test]
    fn empty_heights_returns_error() {
        let err = ProofSelector::analyze(&[], 100, DEFAULT_DENSITY_THRESHOLD).unwrap_err();
        assert_eq!(err, ProofSelectorError::EmptyHeights);
    }

    #[test]
    fn target_below_max_returns_error() {
        let err = ProofSelector::analyze(&[10, 20, 30], 25, DEFAULT_DENSITY_THRESHOLD).unwrap_err();
        assert_eq!(
            err,
            ProofSelectorError::TargetBelowRange { target: 25, max_height: 30 }
        );
    }

    // ── single / all-equal → always batch ────────────────────────────────────

    #[test]
    fn single_height_is_batch() {
        let s = ProofSelector::analyze(&[42], 100, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![42] });
    }

    #[test]
    fn duplicate_heights_deduped_to_single_is_batch() {
        let s = ProofSelector::analyze(&[7, 7, 7], 100, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![7] });
    }

    // ── dense → range ─────────────────────────────────────────────────────────

    #[test]
    fn fully_dense_consecutive_is_range() {
        // heights 100..=109 — density 1.0 ≥ 0.75
        let heights: Vec<u32> = (100..=109).collect();
        let s = ProofSelector::analyze(&heights, 200, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Range { start: 100, end: 109 });
    }

    #[test]
    fn exactly_at_threshold_is_range() {
        // span = 8, need 6/8 = 0.75 exactly → range
        let heights = vec![0u32, 1, 2, 3, 4, 7]; // 6 of span 8
        let s = ProofSelector::analyze(&heights, 100, 0.75).unwrap();
        assert_eq!(s, ProofStrategy::Range { start: 0, end: 7 });
    }

    // ── sparse → batch ────────────────────────────────────────────────────────

    #[test]
    fn very_sparse_is_batch() {
        // 3 blocks in span of 1000 — density 0.003
        let heights = vec![1u32, 500, 1000];
        let s = ProofSelector::analyze(&heights, 2000, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![1, 500, 1000] });
    }

    #[test]
    fn just_below_threshold_is_batch() {
        // span = 8, need < 6 → use 5 → density 0.625 < 0.75
        let heights = vec![0u32, 2, 4, 6, 7]; // 5 of span 8
        let s = ProofSelector::analyze(&heights, 100, 0.75).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![0, 2, 4, 6, 7] });
    }

    // ── output is always sorted ───────────────────────────────────────────────

    #[test]
    fn unsorted_input_produces_sorted_batch() {
        let heights = vec![30u32, 10, 20];
        let s = ProofSelector::analyze(&heights, 100, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![10, 20, 30] });
    }

    #[test]
    fn unsorted_input_produces_correct_range() {
        let heights = vec![109u32, 100, 105, 102, 107, 101, 103, 104, 106, 108];
        let s = ProofSelector::analyze(&heights, 200, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(s, ProofStrategy::Range { start: 100, end: 109 });
    }

    // ── threshold clamping ────────────────────────────────────────────────────

    #[test]
    fn threshold_above_1_clamped_to_batch_for_sparse() {
        // threshold clamped to 1.0 — only 100 % fill qualifies as range
        let heights = vec![0u32, 1, 2, 3, 4, 7]; // density 0.75, not 1.0
        let s = ProofSelector::analyze(&heights, 100, 2.0).unwrap();
        assert_eq!(s, ProofStrategy::Batch { heights: vec![0, 1, 2, 3, 4, 7] });
    }

    #[test]
    fn threshold_0_always_range() {
        // threshold 0.0 → any non-empty set with span > 1 is range
        let heights = vec![1u32, 1000];
        let s = ProofSelector::analyze(&heights, 2000, 0.0).unwrap();
        assert_eq!(s, ProofStrategy::Range { start: 1, end: 1000 });
    }

    // ── target_height == max is valid ─────────────────────────────────────────

    #[test]
    fn target_equal_to_max_is_ok() {
        let heights = vec![10u32, 20, 30];
        let s = ProofSelector::analyze(&heights, 30, DEFAULT_DENSITY_THRESHOLD).unwrap();
        // sparse → batch
        assert_eq!(s, ProofStrategy::Batch { heights: vec![10, 20, 30] });
    }

    // ── stats variant ─────────────────────────────────────────────────────────

    #[test]
    fn stats_reports_correct_density() {
        let heights: Vec<u32> = (0..=9).collect(); // 10 of span 10
        let stats = ProofSelector::analyze_with_stats(&heights, 100, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(stats.requested_count, 10);
        assert_eq!(stats.span, 10);
        assert!((stats.density - 1.0).abs() < f32::EPSILON);
        assert_eq!(stats.strategy, ProofStrategy::Range { start: 0, end: 9 });
    }

    #[test]
    fn stats_reports_sparse_density() {
        let heights = vec![0u32, 99];
        let stats = ProofSelector::analyze_with_stats(&heights, 200, DEFAULT_DENSITY_THRESHOLD).unwrap();
        assert_eq!(stats.span, 100);
        assert!((stats.density - 0.02).abs() < 0.001);
        assert!(matches!(stats.strategy, ProofStrategy::Batch { .. }));
    }
}