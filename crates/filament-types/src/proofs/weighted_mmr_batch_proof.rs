// filament-types/src/proofs/weighted_mmr_batch_proof.rs
//
// Inclusion proof for one or more (not necessarily contiguous) leaves in a
// weighted MMR.
//
// Verification is positional:
//   1. From `leaf_count` alone, derive every peak's position and height.
//   2. For each leaf, climb exactly its peak's height in sibling steps with
//      hash_pair_weighted and compare to `peaks[i]` for that peak.
//   3. Bag all peaks with the genesis anchor and compare to `root`.
// Never "is the climb result somewhere in the peak list": that accepts a proof
// relabelled onto another peak's leaf.

use serde::{Deserialize, Serialize};

use crate::weighted_hash::{bag_peaks_weighted, hash_pair_weighted, WeightedHash};
use crate::genesis::BeaconGenesisConfig;
use super::mmr_peaks::peak_descriptors;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedMMRBatchProof {
    pub leaf_indices: Vec<u32>,
    pub leaf_hashes: Vec<WeightedHash>,
    pub siblings: Vec<WeightedHash>,
    pub peaks: Vec<WeightedHash>,
    pub leaf_count: u32,
    pub root: WeightedHash,
}

impl Default for WeightedMMRBatchProof {
    fn default() -> Self {
        Self {
            leaf_indices: vec![],
            leaf_hashes: vec![],
            siblings: vec![],
            peaks: vec![],
            leaf_count: 0,
            root: WeightedHash::zero(),
        }
    }
}

impl WeightedMMRBatchProof {
    pub fn verify_with_anchor(&self, genesis_anchor: [u8; 32]) -> bool {
        if self.leaf_indices.len() != self.leaf_hashes.len() {
            return false;
        }
        if self.leaf_indices.is_empty() {
            return false;
        }

        // `leaf_count` fixes every peak's position and height, so each leaf is checked
        // against exactly one peak, after exactly that peak's height in sibling steps.
        let descriptors = peak_descriptors(self.leaf_count);
        if descriptors.len() != self.peaks.len() {
            return false;
        }

        let mut peak_i = 0usize;
        let mut sibling_cursor = 0usize;
        let mut prev: Option<u32> = None;
        for (&leaf_idx, &leaf_hash) in self.leaf_indices.iter().zip(&self.leaf_hashes) {
            // Sorted, de-duplicated indices let the peak cursor only move forward.
            if leaf_idx >= self.leaf_count || prev.is_some_and(|p| leaf_idx <= p) {
                return false;
            }
            prev = Some(leaf_idx);

            // The peak whose leaf range [pos << h, (pos + 1) << h) contains this leaf.
            let peak_height = loop {
                let (pos, height) = descriptors[peak_i];
                if u64::from(leaf_idx) < (u64::from(pos) + 1) << height {
                    break height as usize;
                }
                peak_i += 1;
            };

            let Some(path) = self.siblings.get(sibling_cursor..sibling_cursor + peak_height) else {
                return false;
            };
            sibling_cursor += peak_height;

            let mut current = leaf_hash;
            for (level, sibling) in path.iter().enumerate() {
                current = if (leaf_idx >> level) & 1 == 0 {
                    hash_pair_weighted(&current, sibling)
                } else {
                    hash_pair_weighted(sibling, &current)
                };
            }
            if current != self.peaks[peak_i] {
                return false;
            }
        }

        // No trailing siblings.
        if sibling_cursor != self.siblings.len() {
            return false;
        }

        let anchor = WeightedHash::from_anchor(&genesis_anchor);
        bag_peaks_weighted(&self.peaks, anchor) == self.root
    }

    pub fn verify(&self) -> bool {
        let cfg = BeaconGenesisConfig::devnet();
        self.verify_with_anchor(cfg.bitcoin_anchor_hash)
    }

    pub fn cumulative_difficulty_approx(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }
}

#[cfg(test)]
mod positional_verify_tests {
    use super::super::mmr_peaks::test_tree::tree;

    /// Every honest proof verifies: each single leaf and a multi-leaf batch, for every
    /// peak layout up to 40 leaves.
    #[test]
    fn honest_proofs_verify_for_all_layouts() {
        for n in 1..=40u32 {
            let t = tree(n);
            for leaf in 0..n {
                assert!(t.batch(&[leaf]).verify(), "n={n} leaf={leaf}");
            }
            let some: Vec<u32> = (0..n).step_by(3).collect();
            assert!(t.batch(&some).verify(), "n={n} batch");
        }
    }

    /// Forged inclusion: leaf 6 of 7 is its own height-0 peak, so its proof has no
    /// siblings. Relabelled as "leaf 4 has leaf 6's hash" it used to pass, because the
    /// old verifier only asked whether the climb result appeared anywhere in the peak
    /// list. Leaf 4 sits under the height-1 peak, so it needs one sibling.
    #[test]
    fn leaf_relabelled_into_another_peak_is_rejected() {
        let mut proof = tree(7).batch(&[6]);
        assert!(proof.siblings.is_empty() && proof.verify());
        proof.leaf_indices = vec![4];
        assert!(!proof.verify());
    }

    #[test]
    fn peak_count_trailing_siblings_order_and_bounds_are_checked() {
        let t = tree(7);
        let good = t.batch(&[2]);
        assert!(good.verify());

        let mut extra_peak = good.clone();
        extra_peak.peaks.push(extra_peak.peaks[0]);
        assert!(!extra_peak.verify());

        let mut trailing = good.clone();
        trailing.siblings.push(trailing.siblings[0]);
        assert!(!trailing.verify());

        let mut unsorted = t.batch(&[1, 5]);
        assert!(unsorted.verify());
        unsorted.leaf_indices.swap(0, 1);
        unsorted.leaf_hashes.swap(0, 1);
        assert!(!unsorted.verify());

        let mut duplicate = t.batch(&[1, 5]);
        duplicate.leaf_indices = vec![1, 1];
        duplicate.leaf_hashes = vec![duplicate.leaf_hashes[0]; 2];
        assert!(!duplicate.verify());

        let mut out_of_range = good.clone();
        out_of_range.leaf_indices = vec![7];
        assert!(!out_of_range.verify());

        let mut empty = good;
        empty.leaf_indices.clear();
        empty.leaf_hashes.clear();
        assert!(!empty.verify());
    }
}
