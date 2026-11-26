// filament-types/src/proofs/mmr_peaks.rs
//
// Which peaks does a leaf count imply? Pure index arithmetic, used by the proof
// verifiers so that every leaf is checked against exactly ONE peak (the one whose
// leaf range contains it), after exactly that peak's height in sibling steps.
//
// A verifier that only asks "does the climb result appear anywhere in the peak
// list?" accepts forged inclusions: relabel a proof for a leaf of one peak as a
// proof for a leaf under another. The leaf count fixes where the peaks are, so
// nothing needs searching.

/// For `leaf_count` leaves, the peaks from the leftmost (tallest) to the rightmost,
/// each as `(peak_position_at_its_height, height)`: the peak covers leaves
/// `[position << height, (position + 1) << height)`. One peak per set bit of
/// `leaf_count`. Empty for zero leaves.
pub(crate) fn peak_descriptors(leaf_count: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::with_capacity(leaf_count.count_ones() as usize);
    let mut covered = 0u32;
    for bit in (0..32u32).rev() {
        if (leaf_count >> bit) & 1 == 1 {
            out.push((covered >> bit, bit));
            covered += 1u32 << bit;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peaks_follow_the_set_bits() {
        assert_eq!(peak_descriptors(0), vec![]);
        assert_eq!(peak_descriptors(1), vec![(0, 0)]);
        assert_eq!(peak_descriptors(7), vec![(0, 2), (2, 1), (6, 0)]);
        assert_eq!(peak_descriptors(8), vec![(0, 3)]);
        assert_eq!(peak_descriptors(11), vec![(0, 3), (4, 1), (10, 0)]);
    }

    #[test]
    fn peaks_tile_the_leaves_exactly() {
        for n in 0..=300u32 {
            let ds = peak_descriptors(n);
            assert_eq!(ds.len() as u32, n.count_ones());
            let mut next = 0u64;
            for (pos, h) in ds {
                assert_eq!(u64::from(pos) << h, next, "n={n}");
                next = (u64::from(pos) + 1) << h;
            }
            assert_eq!(next, u64::from(n));
        }
        // the largest count must not overflow
        assert_eq!(peak_descriptors(u32::MAX).len(), 32);
    }
}

/// Test-only reference builder: hashes a fixed list of leaves into the perfect subtrees an
/// MMR of that size has, and cuts proofs out of them. It exists so the verifiers can be
/// tested here; it appends nothing, prunes nothing and is not an MMR engine.
#[cfg(test)]
pub(crate) mod test_tree {
    use super::peak_descriptors;
    use crate::genesis::BeaconGenesisConfig;
    use crate::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};
    use crate::weighted_hash::{bag_peaks_weighted, hash_pair_weighted, WeightedHash};

    pub fn leaf(i: u32) -> WeightedHash {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&(i + 1).to_le_bytes());
        WeightedHash::from_leaf_rbits(&h, 0x0300_0001)
    }

    pub struct Tree {
        /// `levels[h][j]` is the hash of the aligned block of 2^h leaves starting at `j << h`
        /// (only complete blocks exist).
        pub levels: Vec<Vec<WeightedHash>>,
        pub n: u32,
    }

    pub fn tree(n: u32) -> Tree {
        let mut levels = vec![(0..n).map(leaf).collect::<Vec<_>>()];
        while levels.last().unwrap().len() >= 2 {
            let prev = levels.last().unwrap();
            let next = prev.chunks_exact(2).map(|p| hash_pair_weighted(&p[0], &p[1])).collect();
            levels.push(next);
        }
        Tree { levels, n }
    }

    impl Tree {
        pub fn peaks(&self) -> Vec<WeightedHash> {
            peak_descriptors(self.n).iter().map(|&(pos, h)| self.levels[h as usize][pos as usize]).collect()
        }

        pub fn root(&self) -> WeightedHash {
            let anchor = WeightedHash::from_anchor(&BeaconGenesisConfig::devnet().bitcoin_anchor_hash);
            bag_peaks_weighted(&self.peaks(), anchor)
        }

        fn peak_height_of(&self, leaf: u32) -> u32 {
            peak_descriptors(self.n)
                .into_iter()
                .find(|&(pos, h)| u64::from(leaf) < (u64::from(pos) + 1) << h)
                .unwrap()
                .1
        }

        pub fn batch(&self, leaves: &[u32]) -> WeightedMMRBatchProof {
            let mut siblings = vec![];
            for &l in leaves {
                for level in 0..self.peak_height_of(l) {
                    siblings.push(self.levels[level as usize][((l >> level) ^ 1) as usize]);
                }
            }
            WeightedMMRBatchProof {
                leaf_indices: leaves.to_vec(),
                leaf_hashes: leaves.iter().map(|&l| leaf(l)).collect(),
                siblings,
                peaks: self.peaks(),
                leaf_count: self.n,
                root: self.root(),
            }
        }

        pub fn range(&self, start: u32, end: u32) -> WeightedMMRRangeProof {
            let mut siblings = vec![];
            let mut per_peak = vec![];
            let mut b = start;
            for (range_h, _) in WeightedMMRRangeProof::range_peak_positions(start, end) {
                let peak_h = self.peak_height_of(b);
                per_peak.push((peak_h - range_h) as u8);
                for level in range_h..peak_h {
                    siblings.push(self.levels[level as usize][((b >> level) ^ 1) as usize]);
                }
                b += 1 << range_h;
            }
            let mut proof = WeightedMMRRangeProof {
                start,
                end,
                leaves: (start..end).map(leaf).collect(),
                siblings,
                siblings_per_peak: per_peak,
                peaks: self.peaks(),
                leaf_count: self.n,
                root: self.root(),
                range_rbits: 0,
            };
            proof.range_rbits = proof.recompute_range_rbits();
            proof
        }
    }
}
