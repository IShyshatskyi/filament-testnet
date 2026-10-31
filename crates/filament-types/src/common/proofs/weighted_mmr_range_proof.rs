// src/common/proofs/weighted_mmr_range_proof.rs
//
// ============================================================================
// WEIGHTED MMR RANGE PROOF  (compact format — March 2026)
// ============================================================================
//
// Inclusion proof for a contiguous range of leaves [start, end) in a
// WeightedMMR, with compact sibling storage and O(R) verification.
//
// PROOF FORMAT
// ------------
// Any range [start, end) decomposes uniquely into at most O(log N) maximal
// aligned complete subtrees (range peaks).  A "range peak" at height h
// starting at leaf i covers leaves [i, i+2^h) and corresponds to the actual
// internal MMR node at position  2*i + (1<<h) - 1.
//
// Instead of storing one full sibling path per leaf (O(R × log N) total),
// this proof stores:
//   - `leaves`: R leaf WeightedHashes
//   - `siblings`: one sibling path per range peak  (flat, concatenated)
//   - `siblings_per_peak`: how many siblings each range peak consumed
//
// Total siblings: sum over range-peaks k of depth(k) ≤ K × log N
// where K = number of range peaks ≤ min(log N, R).
//
// For R=100, N=2048: old format ~100 × 11 = 1100 siblings;
//                    new format ≤   7 × 11 =   77 siblings (~14× reduction).
//
// VERIFICATION ALGORITHM
// ----------------------
// 1. Re-derive range peaks from `leaves` by hashing each aligned subtree
//    bottom-up — O(R) work.
// 2. For each range peak, find the MMR peak containing it from `leaf_count`
//    alone (`WeightedMMR::peak_descriptors`), climb exactly the height
//    difference and compare to `peaks[that index]` — O(K log N) work total.
// 3. Verify that all claimed `peaks` bag to `root` — O(P) work.
//
// Total: O(R + K log N + P)  vs  O(R × log N) for the per-leaf approach.
//
// ============================================================================

use serde::{Deserialize, Serialize};
use crate::common::crypto::weighted_hash::{
    WeightedHash, hash_pair_weighted, bag_peaks_weighted, rbits_add, rbits_to_u128_approx,
};
use crate::common::weighted_mmr_core::WeightedMMR;

/// Inclusion proof for a contiguous leaf range `[start, end)` in a `WeightedMMR`.
///
/// Uses compact sibling storage: one sibling path per aligned subtree peak
/// rather than one per leaf, yielding O(log² N) siblings vs O(R log N).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedMMRRangeProof {
    /// First leaf index (inclusive).
    pub start: u32,
    /// Last leaf index (exclusive).
    pub end: u32,
    /// `WeightedHash` of each leaf in `[start, end)` order.
    pub leaves: Vec<WeightedHash>,
    /// Flat concatenation of sibling paths for each range peak, left → right.
    ///
    /// Range peaks are the maximal aligned complete subtrees covering [start, end).
    /// Their sibling paths lead from each range peak up to a known MMR peak.
    pub siblings: Vec<WeightedHash>,
    /// Number of siblings consumed by each range peak, in left-to-right order.
    ///
    /// `siblings_per_peak.len()` equals the number of range peaks (≤ log₂ N).
    /// `siblings_per_peak[k]` is the climb depth of the k-th range peak.
    pub siblings_per_peak: Vec<u8>,
    /// All MMR peaks in left-to-right order (at proof generation time).
    pub peaks: Vec<WeightedHash>,
    /// Leaf count of the MMR at proof generation time.
    pub leaf_count: u32,
    /// MMR root at proof generation time.
    pub root: WeightedHash,
    /// Compact sum of all leaf rBits in `[start, end)`.
    ///
    /// Allows the verifier to quickly determine the total chain work for this
    /// range without summing individual leaves.
    pub range_rbits: u32,
}

impl WeightedMMRRangeProof {
    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Verify this proof against a genesis anchor.
    ///
    /// Returns `true` iff every leaf is included in the MMR at the claimed
    /// `leaf_count` and the `root` is correctly derived.
    ///
    /// **Complexity:** O(R + K log N + P) where R = range size, K = number of
    /// range peaks (≤ log N), P = number of MMR peaks (≤ log N).
    pub fn verify_with_anchor(&self, genesis_anchor: [u8; 32]) -> bool {
        let r = (self.end - self.start) as usize;
        if r != self.leaves.len() {
            return false;
        }
        if r == 0 {
            return false;
        }

        if self.end > self.leaf_count {
            return false;
        }

        // Step 1 — Decompose [start, end) into aligned range peaks and
        //          compute each peak's hash bottom-up from the leaves.
        let peak_positions = Self::range_peak_positions(self.start, self.end);

        if peak_positions.len() != self.siblings_per_peak.len() {
            return false;
        }

        let range_peak_hashes =
            Self::compute_range_peak_hashes(&self.leaves, self.start, self.end);
        if range_peak_hashes.len() != peak_positions.len() {
            return false;
        }

        // Step 2 — Positional: `leaf_count` alone fixes every MMR peak's
        //          position and height. Each range peak lies inside exactly one
        //          of them, must climb exactly the height difference, and must
        //          equal `peaks[that index]`. No search over peaks.
        let descriptors = WeightedMMR::peak_descriptors(self.leaf_count);
        if descriptors.len() != self.peaks.len() {
            return false;
        }

        let mut mmr_peak_i = 0usize;
        let mut sibling_cursor = 0usize;
        let mut block_start = self.start;

        for (k, (&(range_h, _), &range_hash)) in
            peak_positions.iter().zip(range_peak_hashes.iter()).enumerate()
        {
            // Advance to the MMR peak whose leaf range contains this block.
            let peak_h = loop {
                let (mmr_pos, height) = descriptors[mmr_peak_i];
                if u64::from(block_start) < (u64::from(mmr_pos) + 1) << height {
                    break height;
                }
                mmr_peak_i += 1;
            };
            // An aligned 2^range_h block starting inside an aligned 2^peak_h
            // peak lies wholly inside it iff range_h <= peak_h.
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

        // All siblings must have been consumed (no trailing junk in proof).
        if sibling_cursor != self.siblings.len() {
            return false;
        }

        // Step 3 — Verify peaks bag to the claimed root.
        let anchor = WeightedHash::from_anchor(&genesis_anchor);
        let reconstructed_root = bag_peaks_weighted(&self.peaks, anchor);
        reconstructed_root == self.root
    }

    /// Verify using devnet genesis anchor (for tests).
    pub fn verify(&self) -> bool {
        use crate::common::genesis::genesis_config::BeaconGenesisConfig;
        let cfg = BeaconGenesisConfig::devnet();
        self.verify_with_anchor(cfg.bitcoin_anchor_hash)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Approximate total chain difficulty contributed by the range `[start, end)`.
    pub fn range_difficulty_approx(&self) -> u128 {
        rbits_to_u128_approx(self.range_rbits)
    }

    /// Number of leaves covered by this proof.
    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    /// True iff the range covers zero leaves (invalid proof).
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Recompute `range_rbits` from the leaf hashes in this proof.
    pub fn recompute_range_rbits(&self) -> u32 {
        self.leaves.iter().fold(0u32, |acc, leaf| rbits_add(acc, leaf.rbits()))
    }

    /// Cumulative chain difficulty at proof tip (full chain, not just the range).
    pub fn full_chain_difficulty_approx(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }

    // -----------------------------------------------------------------------
    // Internal helpers (pub(crate) so the prover in full_weighted_mmr_core
    // can reuse the same decomposition logic without duplication)
    // -----------------------------------------------------------------------

    /// Decompose `[start, end)` into maximal aligned complete subtrees.
    ///
    /// Returns `(height, mmr_position)` for each range peak, left → right.
    ///
    /// A subtree at height h starting at leaf i is aligned iff `i % 2^h == 0`.
    /// Its MMR node position is `2*i + (1 << h) - 1`.
    pub fn range_peak_positions(start: u32, end: u32) -> Vec<(u32, usize)> {
        let mut peaks = Vec::new();
        let mut i = start;
        while i < end {
            // Largest h such that i is 2^h-aligned AND i + 2^h ≤ end.
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

    /// Compute each range peak's hash by hashing aligned leaf groups bottom-up.
    ///
    /// Groups correspond to the subtrees from `range_peak_positions`.
    /// Each group of 2^h leaves is hashed as a complete binary tree to reproduce
    /// the exact internal MMR node that the prover climbs from.
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

    /// Hash a complete binary subtree of leaves bottom-up.
    ///
    /// `leaves.len()` must be a power of two (guaranteed by the alignment
    /// decomposition in `range_peak_positions`).
    fn hash_complete_subtree(leaves: &[WeightedHash]) -> WeightedHash {
        match leaves.len() {
            0 => WeightedHash::zero(),
            1 => leaves[0],
            _ => {
                let mid = leaves.len() / 2;
                let left  = Self::hash_complete_subtree(&leaves[..mid]);
                let right = Self::hash_complete_subtree(&leaves[mid..]);
                hash_pair_weighted(&left, &right)
            }
        }
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn wh(seed: u8) -> WeightedHash {
        // Use the batch-proof-verified zero as base; distinguish by first byte
        // via raw pointer write (WeightedHash is Copy/[u8;32+4] internally).
        // For structural tests we just need distinct, valid-ish values.
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_mul(37);
        // Construct via from_anchor which sets rbits=0 — fine for position tests.
        WeightedHash::from_anchor(&bytes)
    }

    #[test]
    fn peak_positions_aligned_power_of_two() {
        // [0,8) = one peak at height 3, pos = 2*0 + 8 - 1 = 7
        let peaks = WeightedMMRRangeProof::range_peak_positions(0, 8);
        assert_eq!(peaks, vec![(3, 7)]);
    }

    #[test]
    fn peak_positions_non_aligned() {
        // [1,4): leaf1 at (h=0,pos=2) then subtree[2,4) at (h=1,pos=5)
        let peaks = WeightedMMRRangeProof::range_peak_positions(1, 4);
        assert_eq!(peaks, vec![(0, 2), (1, 5)]);
    }

    #[test]
    fn peak_positions_two_equal_height() {
        // [2,6): subtree[2,4) at (h=1,pos=5) + subtree[4,6) at (h=1,pos=9)
        let peaks = WeightedMMRRangeProof::range_peak_positions(2, 6);
        assert_eq!(peaks, vec![(1, 5), (1, 9)]);
    }

    #[test]
    fn peak_positions_single_leaf() {
        // [5,6): pos = 2*5 + 1 - 1 = 10
        let peaks = WeightedMMRRangeProof::range_peak_positions(5, 6);
        assert_eq!(peaks, vec![(0, 10)]);
    }

    #[test]
    fn hash_subtree_single() {
        let h1 = wh(1);
        let result = WeightedMMRRangeProof::compute_range_peak_hashes(&[h1], 0, 1);
        assert_eq!(result, vec![h1]);
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
    fn hash_subtree_four_leaves() {
        let leaves: Vec<WeightedHash> = (1u8..=4).map(wh).collect();
        let result = WeightedMMRRangeProof::compute_range_peak_hashes(&leaves, 0, 4);
        assert_eq!(result.len(), 1);
        let expected = hash_pair_weighted(
            &hash_pair_weighted(&leaves[0], &leaves[1]),
            &hash_pair_weighted(&leaves[2], &leaves[3]),
        );
        assert_eq!(result[0], expected);
    }

    #[test]
    fn non_aligned_range_produces_two_peaks() {
        // [1,4): leaf1 alone, then leaves[2,3] as a pair
        let leaves: Vec<WeightedHash> = (1u8..=3).map(wh).collect(); // 3 leaves: idx 1,2,3
        let result = WeightedMMRRangeProof::compute_range_peak_hashes(&leaves, 1, 4);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], leaves[0]); // just leaf 1
        assert_eq!(result[1], hash_pair_weighted(&leaves[1], &leaves[2])); // leaves 2,3
    }
}

#[cfg(test)]
mod positional_verify_tests {
    use crate::common::crypto::weighted_hash::WeightedHash;
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

    /// Every range the real prover emits verifies, for every peak layout up
    /// to 24 leaves.
    #[test]
    fn prover_output_verifies_for_all_ranges() {
        for n in 1..=24u32 {
            let mmr = mmr_with(n);
            for start in 0..n {
                for end in start + 1..=n {
                    let proof = mmr.prove_range(start, end).unwrap();
                    assert!(proof.verify(), "n={n} range=[{start},{end})");
                }
            }
        }
    }

    /// Forged inclusion: leaf 6 of 7 is its own height-0 peak, so the proof of
    /// [6, 7) has no siblings. Relabelled as [4, 5) it used to pass because the
    /// climb result only had to appear somewhere in the peak list. Leaf 4 sits
    /// under the height-1 peak, so it needs one sibling and must equal
    /// `peaks[1]`.
    #[test]
    fn range_relabelled_into_another_peak_is_rejected() {
        let mmr = mmr_with(7);
        let mut proof = mmr.prove_range(6, 7).unwrap();
        assert!(proof.siblings.is_empty() && proof.verify());
        proof.start = 4;
        proof.end = 5;
        assert!(!proof.verify(), "[4,5) cannot be proven with leaf 6's peak");
    }

    /// The peak list must have exactly the peaks `leaf_count` implies, and a
    /// range may not extend past `leaf_count`.
    #[test]
    fn peak_count_and_bounds_are_checked() {
        let mmr = mmr_with(7);
        let good = mmr.prove_range(1, 3).unwrap();

        let mut extra_peak = good.clone();
        extra_peak.peaks.push(extra_peak.peaks[0]);
        assert!(!extra_peak.verify());

        let mut past_end = mmr.prove_range(6, 7).unwrap();
        past_end.leaf_count = 6;
        assert!(!past_end.verify());
    }
}
