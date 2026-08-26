// filament-types/src/proofs/weighted_mmr_range_proof.rs
//
// Compact inclusion proof for a contiguous leaf range [start, end) in a
// weighted MMR: one sibling path per maximal aligned subtree ("range peak")
// instead of one per leaf.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::weighted_hash::{
    bag_peaks_weighted, hash_pair_weighted, rbits_add, rbits_to_u128_approx, WeightedHash,
};
use crate::genesis::BeaconGenesisConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedMMRRangeProof {
    pub start: u32,
    pub end: u32,
    pub leaves: Vec<WeightedHash>,
    pub siblings: Vec<WeightedHash>,
    pub siblings_per_peak: Vec<u8>,
    pub peaks: Vec<WeightedHash>,
    pub leaf_count: u32,
    pub root: WeightedHash,
    pub range_rbits: u32,
}

impl WeightedMMRRangeProof {
    pub fn verify_with_anchor(&self, genesis_anchor: [u8; 32]) -> bool {
        let r = (self.end - self.start) as usize;
        if r != self.leaves.len() || r == 0 {
            return false;
        }

        let anchor = WeightedHash::from_anchor(&genesis_anchor);
        let peaks_set: HashSet<WeightedHash> = self.peaks.iter().copied().collect();

        let peak_positions = Self::range_peak_positions(self.start, self.end);
        if peak_positions.len() != self.siblings_per_peak.len() {
            return false;
        }

        let range_peak_hashes = Self::compute_range_peak_hashes(&self.leaves, self.start, self.end);
        if range_peak_hashes.len() != peak_positions.len() {
            return false;
        }

        let max_valid = 2 * self.leaf_count as usize;
        let mut sibling_cursor = 0usize;

        for (k, (&(range_h, range_pos), &range_hash)) in
            peak_positions.iter().zip(range_peak_hashes.iter()).enumerate()
        {
            let n = self.siblings_per_peak[k] as usize;
            if sibling_cursor + n > self.siblings.len() {
                return false;
            }
            let sibling_slice = &self.siblings[sibling_cursor..sibling_cursor + n];
            sibling_cursor += n;

            let mut cur_hash = range_hash;
            let mut cur_pos = range_pos;
            let mut height = range_h;

            for &sibling in sibling_slice {
                let sibling_pos = Self::sibling_position(cur_pos, height);
                let parent_pos = Self::parent_position(cur_pos, height);
                if sibling_pos >= max_valid || parent_pos >= max_valid {
                    return false;
                }
                cur_hash = if Self::is_left_child(cur_pos, height) {
                    hash_pair_weighted(&cur_hash, &sibling)
                } else {
                    hash_pair_weighted(&sibling, &cur_hash)
                };
                cur_pos = parent_pos;
                height += 1;
            }

            if !peaks_set.contains(&cur_hash) {
                return false;
            }
        }

        if sibling_cursor != self.siblings.len() {
            return false;
        }

        bag_peaks_weighted(&self.peaks, anchor) == self.root
    }

    pub fn verify(&self) -> bool {
        let cfg = BeaconGenesisConfig::devnet();
        self.verify_with_anchor(cfg.bitcoin_anchor_hash)
    }

    pub fn range_difficulty_approx(&self) -> u128 {
        rbits_to_u128_approx(self.range_rbits)
    }

    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub fn recompute_range_rbits(&self) -> u32 {
        self.leaves.iter().fold(0u32, |acc, leaf| rbits_add(acc, leaf.rbits()))
    }

    pub fn full_chain_difficulty_approx(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }

    pub fn range_peak_positions(start: u32, end: u32) -> Vec<(u32, usize)> {
        let mut peaks = Vec::new();
        let mut i = start;
        while i < end {
            let mut h = 0u32;
            loop {
                let next_block = 1u32 << (h + 1);
                if i % next_block != 0 || i + next_block > end {
                    break;
                }
                h += 1;
            }
            let pos = 2 * i as usize + (1usize << h) - 1;
            peaks.push((h, pos));
            i += 1u32 << h;
        }
        peaks
    }

    pub(crate) fn compute_range_peak_hashes(
        leaves: &[WeightedHash],
        start: u32,
        end: u32,
    ) -> Vec<WeightedHash> {
        let mut hashes = Vec::new();
        let mut offset = 0usize;
        let mut i = start;
        while i < end {
            let mut h = 0u32;
            loop {
                let next_block = 1u32 << (h + 1);
                if i % next_block != 0 || i + next_block > end {
                    break;
                }
                h += 1;
            }
            let block_size = 1usize << h;
            hashes.push(Self::hash_complete_subtree(&leaves[offset..offset + block_size]));
            offset += block_size;
            i += block_size as u32;
        }
        hashes
    }

    fn hash_complete_subtree(leaves: &[WeightedHash]) -> WeightedHash {
        match leaves.len() {
            0 => WeightedHash::zero(),
            1 => leaves[0],
            _ => {
                let mid = leaves.len() / 2;
                let left = Self::hash_complete_subtree(&leaves[..mid]);
                let right = Self::hash_complete_subtree(&leaves[mid..]);
                hash_pair_weighted(&left, &right)
            }
        }
    }

    #[inline]
    pub(crate) fn is_left_child(pos: usize, height: u32) -> bool {
        if height >= 31 { false } else { ((pos >> (height + 1)) & 1) == 0 }
    }
    #[inline]
    pub(crate) fn parent_position(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + (1 << height) } else { pos - (1 << height) }
    }
    #[inline]
    fn sibling_position(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + 2 * (1 << height) } else { pos - 2 * (1 << height) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wh(seed: u8) -> WeightedHash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_mul(37);
        WeightedHash::from_anchor(&bytes)
    }

    #[test]
    fn peak_positions_aligned_power_of_two() {
        assert_eq!(WeightedMMRRangeProof::range_peak_positions(0, 8), vec![(3, 7)]);
    }

    #[test]
    fn peak_positions_non_aligned() {
        assert_eq!(WeightedMMRRangeProof::range_peak_positions(1, 4), vec![(0, 2), (1, 5)]);
    }

    #[test]
    fn peak_positions_two_equal_height() {
        assert_eq!(WeightedMMRRangeProof::range_peak_positions(2, 6), vec![(1, 5), (1, 9)]);
    }

    #[test]
    fn peak_positions_single_leaf() {
        assert_eq!(WeightedMMRRangeProof::range_peak_positions(5, 6), vec![(0, 10)]);
    }

    #[test]
    fn hash_subtree_pair_matches_hash_pair_weighted() {
        let h1 = wh(1);
        let h2 = wh(2);
        let result = WeightedMMRRangeProof::compute_range_peak_hashes(&[h1, h2], 0, 2);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], hash_pair_weighted(&h1, &h2));
    }

    #[test]
    fn non_aligned_range_produces_two_peaks() {
        let leaves: Vec<WeightedHash> = (1u8..=3).map(wh).collect();
        let result = WeightedMMRRangeProof::compute_range_peak_hashes(&leaves, 1, 4);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], leaves[0]);
        assert_eq!(result[1], hash_pair_weighted(&leaves[1], &leaves[2]));
    }
}
