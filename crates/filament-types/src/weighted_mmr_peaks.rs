//! Peak-only shim: `WeightedMMR::compute_peaks_after_append`.
//! Not the private full-node MMR write engine.

use crate::weighted_hash::WeightedHash;

/// Placeholders unit for peak-append math used by the light client.
pub struct WeightedMMR;

impl WeightedMMR {
    /// Peaks and root after appending one leaf (pure; no store).
    pub fn compute_peaks_after_append(
        current_peaks: &[WeightedHash],
        leaf_count_before: u32,
        leaf: WeightedHash,
        anchor: WeightedHash,
    ) -> (Vec<WeightedHash>, WeightedHash, u128) {
        crate::mmr_math::compute_peaks_after_append(current_peaks, leaf_count_before, leaf, anchor)
    }
}
