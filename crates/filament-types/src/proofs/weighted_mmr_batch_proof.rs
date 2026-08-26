// filament-types/src/proofs/weighted_mmr_batch_proof.rs
//
// Inclusion proof for one or more (not necessarily contiguous) leaves in a
// weighted MMR. Verification climbs each leaf's sibling path with
// hash_pair_weighted, confirms the reconstructed node is a declared peak,
// then bags all peaks and checks against the claimed root.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::weighted_hash::{bag_peaks_weighted, hash_pair_weighted, WeightedHash};
use crate::genesis::BeaconGenesisConfig;

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

        let anchor = WeightedHash::from_anchor(&genesis_anchor);
        let peaks_set: HashSet<WeightedHash> = self.peaks.iter().copied().collect();

        let mut sibling_cursor = 0usize;
        for (i, &leaf_idx) in self.leaf_indices.iter().enumerate() {
            let leaf_hash = self.leaf_hashes[i];
            let (reconstructed_peak, consumed) =
                self.reconstruct_peak(leaf_idx, leaf_hash, &self.siblings[sibling_cursor..]);
            sibling_cursor += consumed;
            if !peaks_set.contains(&reconstructed_peak) {
                return false;
            }
        }

        bag_peaks_weighted(&self.peaks, anchor) == self.root
    }

    pub fn verify(&self) -> bool {
        let cfg = BeaconGenesisConfig::devnet();
        self.verify_with_anchor(cfg.bitcoin_anchor_hash)
    }

    pub fn cumulative_difficulty_approx(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }

    fn reconstruct_peak(
        &self,
        leaf_idx: u32,
        leaf_hash: WeightedHash,
        siblings: &[WeightedHash],
    ) -> (WeightedHash, usize) {
        let mut current = leaf_hash;
        let mut pos = 2 * leaf_idx as usize;
        let mut height = 0u32;
        let max_valid = 2 * self.leaf_count as usize;

        for (consumed, &sibling) in siblings.iter().enumerate() {
            let sibling_pos = Self::sibling_position(pos, height);
            let parent_pos = Self::parent_position(pos, height);
            if sibling_pos >= max_valid || parent_pos >= max_valid {
                return (current, consumed);
            }
            current = if Self::is_left_child(pos, height) {
                hash_pair_weighted(&current, &sibling)
            } else {
                hash_pair_weighted(&sibling, &current)
            };
            pos = parent_pos;
            height += 1;

            if self.peaks.contains(&current) {
                return (current, consumed + 1);
            }
            let next_sibling = Self::sibling_position(pos, height);
            let next_parent = Self::parent_position(pos, height);
            if next_sibling >= max_valid || next_parent >= max_valid {
                return (current, consumed + 1);
            }
        }
        (current, siblings.len())
    }

    fn is_left_child(pos: usize, height: u32) -> bool {
        if height >= 31 { false } else { ((pos >> (height + 1)) & 1) == 0 }
    }
    fn parent_position(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + (1 << height) } else { pos - (1 << height) }
    }
    fn sibling_position(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + 2 * (1 << height) } else { pos - 2 * (1 << height) }
    }
}
