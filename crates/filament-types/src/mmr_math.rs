// mmr_math.rs — pure MMR arithmetic shared by every product.
//
// Pure arithmetic: no storage, no engine state. Ported from the node's network-wide crate; the
// shared consensus vectors (`tests/consensus_vectors.rs`) pin every function here to the node's
// output. A light client that has no block bodies needs exactly this
// much of the MMR: the peak decomposition of a leaf count, the peaks (and
// bagged root and chain weight) after one more leaf, and which nodes a fork
// path reads.
//
// MMR access is positional (Anti-Patterns Registry): nothing here searches a
// peak list or rebuilds a tree; every function is arithmetic on indexes.

use crate::weighted_hash::{
    bag_peaks_weighted_u128, hash_pair_weighted, WeightedHash,
};

/// The peaks of an MMR with `leaf_count` leaves, as `(mmr_pos, mmr_height)`,
/// highest peak first: for each set bit `b` of `leaf_count`, one peak of
/// height `b` with `mmr_pos = leaves_processed >> b` (the subtree index at
/// height `b`). Pure bit decomposition; the peak count is `popcount`.
pub fn peak_descriptors(leaf_count: u32) -> Vec<(u32, u32)> {
    if leaf_count == 0 {
        return vec![];
    }
    let highest_bit = 31u32.saturating_sub(leaf_count.leading_zeros());
    let mut out = Vec::new();
    let mut leaves_processed = 0u32;
    for bit_pos in (0..=highest_bit).rev() {
        if (leaf_count >> bit_pos) & 1 == 1 {
            out.push((leaves_processed >> bit_pos, bit_pos));
            leaves_processed += 1u32 << bit_pos;
        }
    }
    out
}

/// Peaks, bagged root and chain weight after appending `leaf` to an MMR whose
/// current peaks are `current_peaks` (`leaf_count_before` leaves).
///
/// **Do not drop the `u128` weight.** It is the only authoritative chain
/// weight for a fork block: an incremental `parent + difficulty` sum uses a
/// different computation than the MMR peak bagger and accumulates rounding
/// error. A light client has no block headers and derives chain weight from
/// the peaks only.
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
    (peaks, new_root, chain_weight) // chain_weight MUST be returned and used by the caller
}

/// Peak lists after each of `leaves` is appended in order, starting from the
/// MMR state `base_peaks` (= peaks after `base_leaf_count` leaves). Entry `i`
/// is the peak list after `base_leaf_count + i + 1` leaves. Reads no stored
/// nodes, so it works however far a node window has been pruned.
pub fn replay_peaks_after_appends(
    base_peaks: &[WeightedHash],
    base_leaf_count: u32,
    leaves: &[WeightedHash],
) -> Vec<Vec<WeightedHash>> {
    let mut peaks: Vec<WeightedHash> = base_peaks.to_vec();
    let mut out = Vec::with_capacity(leaves.len());
    for (i, leaf) in leaves.iter().enumerate() {
        let leaf_count_before = base_leaf_count + i as u32;
        let mut new_peak = *leaf;
        for _ in 0..leaf_count_before.trailing_ones() {
            let left = peaks
                .pop()
                .expect("replay_peaks_after_appends: base_peaks inconsistent with base_leaf_count");
            new_peak = hash_pair_weighted(&left, &new_peak);
        }
        peaks.push(new_peak);
        out.push(peaks.clone());
    }
    out
}

/// MMR root after the single genesis leaf: the value a block's
/// `current_mmr_root` holds at height 0. Equal to appending `genesis_leaf` to
/// an empty MMR anchored at `bitcoin_anchor_hash`.
pub fn genesis_mmr_root(bitcoin_anchor_hash: &[u8; 32], genesis_leaf: WeightedHash) -> WeightedHash {
    let anchor = WeightedHash::from_anchor(bitcoin_anchor_hash);
    compute_peaks_after_append(&[], 0, genesis_leaf, anchor).1
}

/// Whether the subtree rooted at `(index, height)` contains leaf `target`.
#[inline]
fn nav_contains(index: usize, height: usize, target: usize) -> bool {
    let start = index << height;
    let end = (index + 1) << height;
    target >= start && target < end
}

/// The nodes a fork path from leaf `from_height` to leaf `to_height` reads, as
/// `(index, level)` pairs (a node `(i, l)` covers leaves `[i << l, (i + 1) << l)`),
/// in the order the proof lists them. **Pure**: depends only on the two leaf
/// indexes, never on any tree's contents, so the same nodes can be obtained
/// from another source (a fork held as side blocks) without building a tree.
///
/// Climb while the current node is a LEFT child whose right sibling does not
/// contain `to` (record that sibling); stop at the lowest common ancestor;
/// descend, recording the left child whenever `to` lies in the right subtree.
pub fn fork_path_positions(from_height: u32, to_height: u32) -> Vec<(u32, u32)> {
    if from_height == to_height {
        return Vec::new();
    }
    let from = from_height as usize;
    let to = to_height as usize;
    let mut out: Vec<(u32, u32)> = Vec::new();
    let mut cur_index: usize = from;
    let mut cur_height: usize = 0;

    // Climb phase.
    loop {
        // A tree has at most 32 levels; the guard only protects against `from > to` input.
        if cur_height > 32 {
            return out;
        }
        if cur_index % 2 != 0 {
            // Right child: climb without consuming a sibling.
        } else if nav_contains(cur_index + 1, cur_height, to) {
            break; // lowest common ancestor found
        } else {
            out.push(((cur_index + 1) as u32, cur_height as u32));
        }
        cur_index /= 2;
        cur_height += 1;
    }

    // Pivot.
    cur_index += 1;

    // Descent phase.
    while cur_height > 0 {
        cur_height -= 1;
        cur_index *= 2; // left child
        if !nav_contains(cur_index, cur_height, to) {
            // `to` is in the right subtree: record the left child, move right.
            out.push((cur_index as u32, cur_height as u32));
            cur_index += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_descriptors_known_values() {
        assert_eq!(peak_descriptors(0), vec![]);
        assert_eq!(peak_descriptors(1), vec![(0, 0)]);
        assert_eq!(peak_descriptors(8), vec![(0, 3)]);
        // 13 = 0b1101: peaks of height 3, 2, 0 over leaves [0,8), [8,12), [12,13).
        assert_eq!(peak_descriptors(13), vec![(0, 3), (2, 2), (12, 0)]);
    }

    #[test]
    fn fork_path_positions_same_leaf_is_empty() {
        assert!(fork_path_positions(5, 5).is_empty());
    }

    #[test]
    fn fork_path_positions_adjacent_siblings() {
        // Leaves 0 and 1 share a parent: the path from 0 to 1 reads leaf 1's sibling side only.
        assert_eq!(fork_path_positions(0, 1), vec![]);
    }
}
