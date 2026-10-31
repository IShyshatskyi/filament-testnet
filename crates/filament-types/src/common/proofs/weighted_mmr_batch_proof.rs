// src/common/proofs/weighted_mmr_batch_proof.rs
//
// ============================================================================
// WEIGHTED MMR BATCH PROOF
// ============================================================================
//
// Inclusion proof for one or more leaves in a WeightedMMR.
// Each proof node (sibling, peak) is a `WeightedHash` — verification uses
// `hash_pair_weighted` so the reconstructed path accumulates rBits identically
// to how the MMR was built.
//
// Verification steps:
//   1. From `leaf_count` alone, derive every peak's position and height
//      (`WeightedMMR::peak_descriptors`) — pure index arithmetic.
//   2. For each leaf, climb exactly its peak's height in sibling steps with
//      hash_pair_weighted and compare to `peaks[i]` for that peak.
//   3. Bag all peaks with the genesis anchor → reconstructed root.
//   4. Compare reconstructed root to `self.root`.
//
// ============================================================================

use serde::{Deserialize, Serialize};
use crate::common::crypto::weighted_hash::{
    WeightedHash, hash_pair_weighted, bag_peaks_weighted,
};
use crate::common::weighted_mmr_core::WeightedMMR;

/// Batch inclusion proof for one or more leaves in a `WeightedMMR`.
///
/// Covers any set of leaf indices (not necessarily contiguous).
/// For a contiguous range use `WeightedMMRRangeProof` which also carries
/// `range_rbits`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedMMRBatchProof {
    /// Sorted, deduplicated leaf indices covered by this proof.
    pub leaf_indices: Vec<u32>,
    /// `WeightedHash` of each leaf in the same order as `leaf_indices`.
    pub leaf_hashes: Vec<WeightedHash>,
    /// Concatenated sibling paths — one path per leaf, in `leaf_indices` order.
    pub siblings: Vec<WeightedHash>,
    /// All current MMR peaks in left-to-right order.
    pub peaks: Vec<WeightedHash>,
    /// Leaf count of the MMR at the time the proof was generated.
    pub leaf_count: u32,
    /// MMR root at proof generation time (hash + cumulative difficulty).
    pub root: WeightedHash,
}

impl Default for WeightedMMRBatchProof {
    fn default() -> Self {
        Self {
            leaf_indices: vec![],
            leaf_hashes:  vec![],
            siblings:     vec![],
            peaks:        vec![],
            leaf_count:   0,
            root:         WeightedHash::zero(),
        }
    }
}

impl WeightedMMRBatchProof {
    /// Verify this proof against a genesis anchor.
    ///
    /// Returns `true` iff every leaf inclusion is valid and the root is
    /// correctly derived from the claimed peaks.
    ///
    /// The `genesis_anchor` is the `bitcoin_anchor_hash` from `BeaconGenesisConfig`.
    pub fn verify_with_anchor(&self, genesis_anchor: [u8; 32]) -> bool {
        if self.leaf_indices.len() != self.leaf_hashes.len() {
            return false;
        }
        if self.leaf_indices.is_empty() {
            return false;
        }

        // Positional verification: `leaf_count` alone fixes every peak's
        // position and height, so each leaf is checked against exactly one
        // peak — `peaks[i]` for the peak whose leaf range contains it — after
        // exactly that peak's height in sibling steps. No search over peaks.
        let descriptors = WeightedMMR::peak_descriptors(self.leaf_count);
        if descriptors.len() != self.peaks.len() {
            return false;
        }

        let mut peak_i = 0usize;
        let mut sibling_cursor = 0usize;
        let mut prev: Option<u32> = None;
        for (&leaf_idx, &leaf_hash) in self.leaf_indices.iter().zip(&self.leaf_hashes) {
            // The prover emits sorted, de-duplicated indices; requiring that
            // lets the peak cursor only move forward.
            if leaf_idx >= self.leaf_count || prev.is_some_and(|p| leaf_idx <= p) {
                return false;
            }
            prev = Some(leaf_idx);

            // Advance to the peak whose leaf range [pos << h, (pos + 1) << h)
            // contains this leaf; one exists because leaf_idx < leaf_count.
            let peak_height = loop {
                let (mmr_pos, height) = descriptors[peak_i];
                if u64::from(leaf_idx) < (u64::from(mmr_pos) + 1) << height {
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

        // Every sibling must be consumed (no trailing data in the proof).
        if sibling_cursor != self.siblings.len() {
            return false;
        }

        // Verify peaks bag to the claimed root.
        let anchor = WeightedHash::from_anchor(&genesis_anchor);
        bag_peaks_weighted(&self.peaks, anchor) == self.root
    }

    /// Verify using devnet genesis anchor (for tests).
    pub fn verify(&self) -> bool {
        use crate::common::genesis::genesis_config::BeaconGenesisConfig;
        let cfg = BeaconGenesisConfig::devnet();
        self.verify_with_anchor(cfg.bitcoin_anchor_hash)
    }

    /// Claimed cumulative chain difficulty at proof time.
    pub fn cumulative_difficulty_approx(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }
}

#[cfg(test)]
mod positional_verify_tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use crate::common::windowed_weighted_mmr::WindowedWeightedMMR;

    fn mmr_with(n: u32) -> WindowedWeightedMMR {
        let mut mmr = WindowedWeightedMMR::new(&BeaconGenesisConfig::devnet());
        for i in 0..n {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&(i + 1).to_le_bytes());
            mmr.append(WeightedHash::from_leaf_rbits(&h, 0x0300_0001)).unwrap();
        }
        mmr
    }

    /// Every proof the real prover emits verifies: each single leaf and one
    /// multi-leaf batch, across leaf counts with every peak layout up to 40.
    #[test]
    fn prover_output_verifies_for_all_layouts() {
        for n in 1..=40u32 {
            let mmr = mmr_with(n);
            for leaf in 0..n {
                let proof = mmr.prove_batch(&[leaf]).unwrap();
                assert!(proof.verify(), "n={n} leaf={leaf}");
            }
            let all: Vec<u32> = (0..n).step_by(3).collect();
            assert!(mmr.prove_batch(&all).unwrap().verify(), "n={n} batch");
        }
    }

    /// Forged inclusion: leaf 6 of 7 is its own height-0 peak, so its proof
    /// has no siblings. Relabelling that proof as "leaf 4 has leaf 6's hash"
    /// used to pass, because the verifier only asked whether the climb result
    /// appeared anywhere in the peak list. Leaf 4 sits under the height-1
    /// peak, so it needs one sibling and must match `peaks[1]`.
    #[test]
    fn leaf_relabelled_into_another_peak_is_rejected() {
        let mmr = mmr_with(7);
        let mut proof = mmr.prove_batch(&[6]).unwrap();
        assert!(proof.siblings.is_empty() && proof.verify());
        proof.leaf_indices = vec![4];
        assert!(!proof.verify(), "leaf 4 cannot be proven with leaf 6's peak");
    }

    /// The peak list must have exactly the peaks `leaf_count` implies, and the
    /// proof must carry no unused siblings.
    #[test]
    fn peak_count_and_trailing_siblings_are_checked() {
        let mmr = mmr_with(7);
        let good = mmr.prove_batch(&[2]).unwrap();

        let mut extra_peak = good.clone();
        extra_peak.peaks.push(extra_peak.peaks[0]);
        assert!(!extra_peak.verify());

        let mut trailing = good.clone();
        trailing.siblings.push(trailing.siblings[0]);
        assert!(!trailing.verify());

        let mut unsorted = mmr.prove_batch(&[1, 5]).unwrap();
        unsorted.leaf_indices.swap(0, 1);
        unsorted.leaf_hashes.swap(0, 1);
        assert!(!unsorted.verify());
    }
}
