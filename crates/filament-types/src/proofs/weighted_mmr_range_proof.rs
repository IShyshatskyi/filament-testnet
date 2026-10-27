// filament-types/src/proofs/weighted_mmr_range_proof.rs
//
// Compact inclusion proof for a contiguous leaf range [start, end) in a
// weighted MMR: one sibling path per maximal aligned subtree ("range peak")
// instead of one per leaf.
//
// Verification is positional: `leaf_count` alone fixes every MMR peak's position
// and height, each range peak lies inside exactly one of them, must climb exactly
// the height difference, and must equal `peaks[that index]`. It never asks whether
// a climb result appears somewhere in the peak list (that accepts forgeries).

use serde::{Deserialize, Serialize};

use crate::weighted_hash::{
    bag_peaks_weighted, hash_pair_weighted, rbits_add, rbits_to_u128_approx, WeightedHash,
};
use crate::genesis::BeaconGenesisConfig;
use super::mmr_peaks::peak_descriptors;

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
        let Some(len) = self.end.checked_sub(self.start) else {
            return false;
        };
        let r = len as usize;
        if r != self.leaves.len() || r == 0 {
            return false;
        }
        if self.end > self.leaf_count {
            return false;
        }

        // Step 1: the maximal aligned blocks of [start, end), hashed bottom-up.
        let peak_positions = Self::range_peak_positions(self.start, self.end);
        if peak_positions.len() != self.siblings_per_peak.len() {
            return false;
        }
        let range_peak_hashes = Self::compute_range_peak_hashes(&self.leaves, self.start, self.end);
        if range_peak_hashes.len() != peak_positions.len() {
            return false;
        }

        // Step 2: positional. Each block climbs to the MMR peak containing it.
        let descriptors = peak_descriptors(self.leaf_count);
        if descriptors.len() != self.peaks.len() {
            return false;
        }
        let mut mmr_peak_i = 0usize;
        let mut sibling_cursor = 0usize;
        let mut block_start = self.start;

        for (k, (&(range_h, _), &range_hash)) in
            peak_positions.iter().zip(range_peak_hashes.iter()).enumerate()
        {
            // The MMR peak whose leaf range contains this block.
            let peak_h = loop {
                let Some(&(pos, height)) = descriptors.get(mmr_peak_i) else {
                    return false;
                };
                if u64::from(block_start) < (u64::from(pos) + 1) << height {
                    break height;
                }
                mmr_peak_i += 1;
            };
            // An aligned 2^range_h block inside an aligned 2^peak_h peak lies wholly
            // inside it iff range_h <= peak_h.
            if range_h > peak_h {
                return false;
            }
            let n = (peak_h - range_h) as usize;
            if self.siblings_per_peak[k] as usize != n {
                return false;
            }
            let Some(path) = self.siblings.get(sibling_cursor..sibling_cursor + n) else {
                return false;
            };
            sibling_cursor += n;

            let mut cur_hash = range_hash;
            for (step, sibling) in path.iter().enumerate() {
                let level = range_h + step as u32;
                cur_hash = if (block_start >> level) & 1 == 0 {
                    hash_pair_weighted(&cur_hash, sibling)
                } else {
                    hash_pair_weighted(sibling, &cur_hash)
                };
            }
            if cur_hash != self.peaks[mmr_peak_i] {
                return false;
            }
            block_start += 1u32 << range_h;
        }

        // No trailing siblings.
        if sibling_cursor != self.siblings.len() {
            return false;
        }

        // Step 3: the claimed peaks bag to the claimed root.
        let anchor = WeightedHash::from_anchor(&genesis_anchor);
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

#[cfg(test)]
mod positional_verify_tests {
    use super::super::mmr_peaks::test_tree::tree;

    /// Every honest range proof verifies, for every [start, end) of every size up to 24.
    #[test]
    fn honest_range_proofs_verify_for_all_ranges() {
        for n in 1..=24u32 {
            let t = tree(n);
            for start in 0..n {
                for end in start + 1..=n {
                    assert!(t.range(start, end).verify(), "n={n} range={start}..{end}");
                }
            }
        }
    }

    #[test]
    fn tampered_range_proofs_are_rejected() {
        let t = tree(11);
        let good = t.range(2, 9);
        assert!(good.verify());

        let mut wrong_count = good.clone();
        wrong_count.siblings_per_peak[0] += 1;
        assert!(!wrong_count.verify(), "wrong sibling count for a block");

        let mut trailing = good.clone();
        trailing.siblings.push(trailing.siblings[0]);
        assert!(!trailing.verify());

        let mut shifted = good.clone();
        shifted.start += 1;
        shifted.end += 1;
        assert!(!shifted.verify(), "same leaves claimed at another position");

        let mut bad_leaf = good.clone();
        bad_leaf.leaves[3] = bad_leaf.leaves[2];
        assert!(!bad_leaf.verify());

        let mut past_end = good.clone();
        past_end.end = 12;
        past_end.leaves.push(past_end.leaves[0]);
        assert!(!past_end.verify(), "range beyond leaf_count");

        let mut inverted = good.clone();
        std::mem::swap(&mut inverted.start, &mut inverted.end);
        assert!(!inverted.verify(), "end < start must be false, not a panic");
    }

    /// A block proven against the wrong MMR peak must not pass just because its climb
    /// result equals some other peak.
    #[test]
    fn block_relabelled_into_another_peak_is_rejected() {
        let t = tree(7); // peaks: 4 leaves, 2 leaves, 1 leaf
        let mut proof = t.range(6, 7); // leaf 6 is its own height-0 peak: no siblings
        assert!(proof.verify() && proof.siblings.is_empty());
        proof.start = 4;
        proof.end = 5; // leaf 4 sits under the height-1 peak and needs one sibling
        assert!(!proof.verify());
    }
}
