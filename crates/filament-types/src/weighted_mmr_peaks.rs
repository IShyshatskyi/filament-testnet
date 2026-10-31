//! Peak-only shim: `WeightedMMR::compute_peaks_after_append`.
//! Not the private full-node MMR write engine.

use crate::weighted_hash::{
    bag_peaks_weighted_u128, hash_pair_weighted, WeightedHash,
};

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
        let mut peaks: Vec<WeightedHash> = current_peaks.to_vec();
        let mut new_peak = leaf;
        let merge_count = leaf_count_before.trailing_ones() as usize;
        for _ in 0..merge_count {
            let left = peaks
                .pop()
                .expect("compute_peaks_after_append: peaks exhausted during merge");
            new_peak = hash_pair_weighted(&left, &new_peak);
        }
        peaks.push(new_peak);
        let (new_root, chain_weight) = bag_peaks_weighted_u128(&peaks, anchor);
        (peaks, new_root, chain_weight)
    }
}
