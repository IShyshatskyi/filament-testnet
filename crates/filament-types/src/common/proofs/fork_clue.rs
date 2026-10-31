// Fork resolution, step 5 of `docs/plan/Fork_Resolution_Design.md`: read a peer's "clue" and locate the
// first divergent MMR node.
//
// A clue is a `WeightedMMRBatchProof` of the peer's (K's) block at a probe height H (and K's tip). The proof
// holds K's hashes of aligned subtrees: the sibling nodes along H's path to its peak, plus K's other peaks.
// Together with leaf H they cover every leaf of K's MMR exactly once ("the tiling"). A node's hash depends only
// on the leaves under it, and a node's position is a fixed function of (index, level) (Anti-Patterns #28), so
// we can compare each K tile with OUR OWN node at the same position:
//   * equal   -> every leaf under the tile is identical (common history);
//   * differs -> the tile contains a divergent leaf.
// Going from genesis to tip, the first tile that differs is the "first divergent MMR node" (owner's term:
// "last divergent node" when read from tip to genesis). The first divergent block lies in its leaf range.
//
// NOTHING IS REBUILT HERE (Anti-Patterns #46). Cost: O(log n) tiles, one node lookup each, by position.

use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::proofs::weighted_mmr_batch_proof::WeightedMMRBatchProof;
use crate::common::weighted_mmr_core::WeightedMMR;

/// One aligned subtree of the peer's MMR: level `level`, index `index`, covering leaves
/// `[index << level, (index + 1) << level)`. Same addressing as `get_node_hash(mmr_pos = index, mmr_height = level)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClueTile {
    pub level: u32,
    pub index: u32,
    pub hash: WeightedHash,
}

impl ClueTile {
    /// First leaf covered.
    pub fn first_leaf(&self) -> u64 {
        u64::from(self.index) << self.level
    }
    /// One past the last leaf covered.
    pub fn end_leaf(&self) -> u64 {
        (u64::from(self.index) + 1) << self.level
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClueError {
    /// The proof has no leaves, or its leaf count is zero.
    Empty,
    /// The proof's shape does not match its leaf count (peak count, sibling count, leaf index).
    Malformed(&'static str),
}

/// The tiling of the peer's MMR built from a clue proof, taken around the proof's FIRST leaf `x`
/// (the probe leaf H, or the peer's tip when the clue holds only the tip).
///
/// Result: leaf `x` itself, the sibling of `x` at every level up to its peak, and every other peak of the
/// peer's MMR. The tiles are returned in leaf order and cover `[0, proof.leaf_count)` exactly once.
/// The proof's internal hashes are NOT verified here (use `verify_with_anchor` and compare the root with a
/// root we trust); this only reads its structure.
pub fn clue_tiling(proof: &WeightedMMRBatchProof) -> Result<Vec<ClueTile>, ClueError> {
    if proof.leaf_indices.is_empty() || proof.leaf_count == 0 {
        return Err(ClueError::Empty);
    }
    if proof.leaf_indices.len() != proof.leaf_hashes.len() {
        return Err(ClueError::Malformed("leaf_indices and leaf_hashes differ in length"));
    }
    let descriptors = WeightedMMR::peak_descriptors(proof.leaf_count);
    if descriptors.len() != proof.peaks.len() {
        return Err(ClueError::Malformed("peak count does not match leaf_count"));
    }
    let x = proof.leaf_indices[0];
    if x >= proof.leaf_count {
        return Err(ClueError::Malformed("leaf index beyond leaf_count"));
    }

    let mut tiles = Vec::with_capacity(descriptors.len() + 40);
    for (i, &(peak_index, height)) in descriptors.iter().enumerate() {
        let first = u64::from(peak_index) << height;
        let end = (u64::from(peak_index) + 1) << height;
        if u64::from(x) >= first && u64::from(x) < end {
            // x's own peak: replaced by x and its sibling path. The first leaf's path is the first
            // `height` siblings (the prover emits one path per leaf, in leaf order).
            let h = height as usize;
            let Some(path) = proof.siblings.get(..h) else {
                return Err(ClueError::Malformed("sibling path shorter than the peak height"));
            };
            for (level, sib) in path.iter().enumerate() {
                tiles.push(ClueTile {
                    level: level as u32,
                    index: (x >> level) ^ 1,
                    hash: *sib,
                });
            }
            tiles.push(ClueTile { level: 0, index: x, hash: proof.leaf_hashes[0] });
        } else {
            tiles.push(ClueTile { level: height, index: peak_index, hash: proof.peaks[i] });
        }
    }
    tiles.sort_by_key(|t| t.first_leaf());
    Ok(tiles)
}

/// What comparing a clue with our own chain tells us.
#[derive(Debug, PartialEq, Eq)]
pub enum ClueOutcome {
    /// The first divergent block lies in leaves `first_leaf ..= last_leaf` (an aligned subtree). Every
    /// leaf before `first_leaf` is proven common.
    Diverges { first_leaf: u32, last_leaf: u32 },
    /// No comparable tile differs: our leaves `0 .. compared_leaves` are proven common. If
    /// `compared_leaves == own_leaf_count` we are a prefix of the peer's chain (we are only behind);
    /// otherwise the leaves from `compared_leaves` on are not covered by a comparable tile and the header
    /// link check decides.
    NoDivergence { compared_leaves: u32 },
    /// We could not read one of our own nodes (pruned and not recoverable): no conclusion.
    Unavailable,
}

/// Locate the first divergent MMR node.
///
/// `own_leaf_count` = our tip index + 1. `own_node(index, level)` returns OUR hash of the aligned subtree
/// (same addressing as [`ClueTile`]); only called for tiles that lie entirely inside our leaves.
pub fn locate_divergence(
    tiles: &[ClueTile],
    own_leaf_count: u32,
    own_node: impl Fn(u32, u32) -> Option<WeightedHash>,
) -> ClueOutcome {
    let mut compared = 0u64;
    for tile in tiles {
        if tile.first_leaf() != compared {
            // The tiling must be contiguous from leaf 0; a gap means the input was not a tiling.
            return ClueOutcome::Unavailable;
        }
        if tile.end_leaf() > u64::from(own_leaf_count) {
            // Reaches past our tip: not comparable, and nothing after it is either.
            break;
        }
        match own_node(tile.index, tile.level) {
            None => return ClueOutcome::Unavailable,
            Some(h) if h != tile.hash => {
                return ClueOutcome::Diverges {
                    first_leaf: tile.first_leaf() as u32,
                    last_leaf: (tile.end_leaf() - 1) as u32,
                };
            }
            Some(_) => compared = tile.end_leaf(),
        }
    }
    ClueOutcome::NoDivergence { compared_leaves: compared as u32 }
}

/// Clip a divergent range to the reorg limit: a fork more than `max_depth` blocks below our tip is
/// refused anyway, so only leaves `own_tip_index - max_depth ..= last_leaf` matter. `None` = the whole
/// range is deeper than the limit (refuse).
pub fn clip_to_reorg_limit(first_leaf: u32, last_leaf: u32, own_tip_index: u32, max_depth: u32) -> Option<(u32, u32)> {
    let lowest = own_tip_index.saturating_sub(max_depth);
    let first = first_leaf.max(lowest);
    (first <= last_leaf).then_some((first, last_leaf))
}

/// Number of leaves in an inclusive range.
pub fn range_len(first_leaf: u32, last_leaf: u32) -> u32 {
    last_leaf - first_leaf + 1
}

#[cfg(test)]
mod tests {
    //! The replayed MMRs in this module are TEST ORACLES (Anti-Patterns #46): they are how we know what the
    //! fast production path must return. They never serve production.
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use crate::common::windowed_weighted_mmr::WindowedWeightedMMR;

    fn leaf(seed: u32, i: u32) -> WeightedHash {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&(i + 1).to_le_bytes());
        h[4..8].copy_from_slice(&seed.to_le_bytes());
        WeightedHash::from_leaf_rbits(&h, 0x0300_0001)
    }

    /// A chain: `common` shared leaves, then leaves unique to `seed`, `total` leaves overall.
    fn chain(seed: u32, common: u32, total: u32) -> WindowedWeightedMMR {
        let mut mmr = WindowedWeightedMMR::new(&BeaconGenesisConfig::devnet());
        for i in 0..total {
            let s = if i < common { 0 } else { seed };
            mmr.append(leaf(s, i)).unwrap();
        }
        mmr
    }

    fn own_node_of(a: &WindowedWeightedMMR) -> impl Fn(u32, u32) -> Option<WeightedHash> + '_ {
        move |index, level| a.get_node_hash(index, level)
    }

    /// The tiling covers [0, leaf_count) exactly once, for every leaf count and probe leaf.
    #[test]
    fn tiling_covers_every_leaf_exactly_once() {
        for n in 1..=70u32 {
            let k = chain(1, 0, n);
            for x in 0..n {
                let proof = k.prove_batch(&[x]).unwrap();
                let tiles = clue_tiling(&proof).unwrap();
                let mut next = 0u64;
                for t in &tiles {
                    assert_eq!(t.first_leaf(), next, "n={n} x={x}: gap or overlap");
                    next = t.end_leaf();
                }
                assert_eq!(next, u64::from(n), "n={n} x={x}");
            }
        }
    }

    /// The core property. For every chain pair and probe height: the divergent range contains the first
    /// divergent leaf, and every leaf before it is proven common (it really is common).
    #[test]
    fn divergent_range_contains_the_first_divergent_leaf() {
        for common in 1..=40u32 {
            for a_len in common..=common + 12 {
                for k_len in common..=common + 12 {
                    if a_len == common && k_len == common { continue; } // identical chains
                    let a = chain(1, common, a_len);
                    let k = chain(2, common, k_len);
                    // every probe height that both chains have, with K's tip added as the second leaf
                    for h in 0..a_len.min(k_len) {
                        let mut leaves = vec![h, k_len - 1];
                        leaves.sort_unstable();
                        leaves.dedup();
                        let proof = k.prove_batch(&leaves).unwrap();
                        let tiles = clue_tiling(&proof).unwrap();
                        let f = common; // first divergent leaf = number of shared leaves
                        match locate_divergence(&tiles, a_len, own_node_of(&a)) {
                            ClueOutcome::Diverges { first_leaf, last_leaf } => {
                                assert!(a_len > common && k_len > common);
                                assert!(first_leaf <= f && f <= last_leaf,
                                    "common={common} a={a_len} k={k_len} h={h}: range {first_leaf}..={last_leaf} misses {f}");
                            }
                            ClueOutcome::NoDivergence { compared_leaves } => {
                                // Nothing comparable differed: whatever was compared must really be common.
                                assert!(compared_leaves <= common,
                                    "common={common} a={a_len} k={k_len} h={h}: claimed {compared_leaves} common leaves");
                            }
                            ClueOutcome::Unavailable => panic!("oracle MMR has every node"),
                        }
                    }
                }
            }
        }
    }

    /// K's tip is at or below the probe height: the clue holds only the tip leaf ("empty batch").
    #[test]
    fn tip_only_clue_when_the_peer_is_not_above_the_probe_height() {
        for common in 1..=30u32 {
            for k_extra in 1..=9u32 {
                let a = chain(1, common, common + 15);
                let k = chain(2, common, common + k_extra);
                let tip = common + k_extra - 1;
                let proof = k.prove_batch(&[tip]).unwrap();
                let tiles = clue_tiling(&proof).unwrap();
                match locate_divergence(&tiles, common + 15, own_node_of(&a)) {
                    ClueOutcome::Diverges { first_leaf, last_leaf } =>
                        assert!(first_leaf <= common && common <= last_leaf, "common={common} k_extra={k_extra}"),
                    other => panic!("expected a divergence, got {other:?} (common={common} k_extra={k_extra})"),
                }
            }
        }
    }

    /// The worked example in the design doc: A has leaves 0..11, fork at leaf 9, K's clue for its leaf 11.
    #[test]
    fn design_doc_worked_example() {
        let a = chain(1, 9, 12);
        let k = chain(2, 9, 14);
        let proof = k.prove_batch(&[11]).unwrap();
        let tiles = clue_tiling(&proof).unwrap();
        assert_eq!(locate_divergence(&tiles, 12, own_node_of(&a)),
            ClueOutcome::Diverges { first_leaf: 8, last_leaf: 9 });
    }

    /// Probing the last leaf of the range is dense at the end of the range (design doc section 6).
    #[test]
    fn probing_the_last_leaf_of_a_range_narrows_a_shallow_fork_fast() {
        // A and K share 1017 leaves (fork at leaf 1017). A has 1020 leaves (tip 1019), K 1030.
        let a = chain(1, 1017, 1020);
        let k = chain(2, 1017, 1030);
        let mut probe = 1019u32;
        let mut rounds = 0;
        let (mut s, mut e);
        loop {
            let proof = k.prove_batch(&[probe]).unwrap();
            let tiles = clue_tiling(&proof).unwrap();
            match locate_divergence(&tiles, 1020, own_node_of(&a)) {
                ClueOutcome::Diverges { first_leaf, last_leaf } => { s = first_leaf; e = last_leaf; }
                other => panic!("{other:?}"),
            }
            rounds += 1;
            assert!(s <= 1017 && 1017 <= e);
            if range_len(s, e) <= 16 || rounds >= 8 { break; }
            probe = e;
        }
        assert!(range_len(s, e) <= 16 && rounds <= 3, "rounds={rounds} range={s}..={e}");
    }

    #[test]
    fn identical_prefix_means_no_divergence() {
        let a = chain(1, 20, 20);
        let k = chain(2, 20, 31);
        let proof = k.prove_batch(&[19]).unwrap();
        let tiles = clue_tiling(&proof).unwrap();
        // A is a prefix of K: every comparable tile equals A's.
        match locate_divergence(&tiles, 20, own_node_of(&a)) {
            ClueOutcome::NoDivergence { compared_leaves } => assert!(compared_leaves <= 20),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unreadable_own_node_gives_no_conclusion() {
        let k = chain(2, 5, 12);
        let proof = k.prove_batch(&[11]).unwrap();
        let tiles = clue_tiling(&proof).unwrap();
        assert_eq!(locate_divergence(&tiles, 12, |_, _| None), ClueOutcome::Unavailable);
    }

    #[test]
    fn malformed_proofs_are_rejected_without_panicking() {
        let k = chain(2, 5, 12);
        let good = k.prove_batch(&[11]).unwrap();
        let mut p = good.clone(); p.siblings.clear();
        assert!(matches!(clue_tiling(&p), Err(ClueError::Malformed(_))));
        let mut p = good.clone(); p.peaks.pop();
        assert!(matches!(clue_tiling(&p), Err(ClueError::Malformed(_))));
        let mut p = good.clone(); p.leaf_indices[0] = 99;
        assert!(matches!(clue_tiling(&p), Err(ClueError::Malformed(_))));
        let mut p = good; p.leaf_indices.clear(); p.leaf_hashes.clear();
        assert_eq!(clue_tiling(&p), Err(ClueError::Empty));
    }

    #[test]
    fn clipping_to_the_reorg_limit() {
        assert_eq!(clip_to_reorg_limit(0, 1023, 1020, 100), Some((920, 1023)));
        assert_eq!(clip_to_reorg_limit(1016, 1019, 1020, 100), Some((1016, 1019)));
        assert_eq!(clip_to_reorg_limit(0, 800, 1020, 100), None, "deeper than the limit");
        assert_eq!(clip_to_reorg_limit(0, 5, 10, 100), Some((0, 5)));
    }
}
