//! Peer-branch navigation path for a `ForkProof`, WITHOUT building the peer's tree.
//!
//! A `ForkProof` carries three navigation paths: to the common block, to our tip, and to the peer's tip.
//! The first two are read from our own MMR (`WindowedWeightedMMR::collect_fork_path`). The third lives in
//! the peer's branch, which is a different tree: our chain up to the fork point `H1` plus the peer's
//! blocks above it, held here as side blocks. The old Keystone code built that tree (re-hashing every
//! block from genesis) to read the path from it. That is the forbidden rebuild (Anti-Patterns #46).
//!
//! Instead:
//! 1. the asker's tip is located in the side-block pool and the pool is walked back to the fork point
//!    (`ShardSideBlockManager::build_fork_chain`), which yields the fork blocks, hence their leaf hashes;
//! 2. the positions to read are a pure function of the two heights
//!    (`WindowedWeightedMMR::fork_path_positions`);
//! 3. each position is classified by the leaves it covers ([`classify_fork_node`]) and obtained from the
//!    source that holds it.
//!
//! **Step 4 is not implemented here.** A node that covers fork leaves together with other leaves is not
//! stored anywhere: it has to be computed from the side-block fork. [`collect_side_fork_path`] takes that
//! computation as a parameter, so it is the single place to plug in once the owner has decided how.
//! Production code passes a stub that fails; nothing calls this function yet.

use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::windowed_weighted_mmr::WindowedWeightedMMR;

/// Where the hash of a node of the peer's branch comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkNodeKind {
    /// Covers only leaves `0..=common_height`: identical in both branches (shared prefix).
    Prefix,
    /// A single fork leaf: the leaf hash of the side block at this offset in the fork
    /// (`offset 0` = the block right above the fork point).
    ForkLeaf { offset: usize },
    /// Covers at least one fork leaf and more than itself: stored nowhere, to be computed (step 4).
    ForkInternal,
}

/// Classify node `(index, level)` (covering leaves `[index << level, (index + 1) << level)`) against the
/// the last common block `common_height` (the last leaf both branches share; the fork height is
/// `common_height + 1`, the first divergent leaf).
pub fn classify_fork_node(index: u32, level: u32, common_height: u32) -> ForkNodeKind {
    let end = (u64::from(index) + 1) << level; // exclusive
    let first_fork_leaf = u64::from(common_height) + 1;
    if end <= first_fork_leaf {
        ForkNodeKind::Prefix
    } else if level == 0 {
        ForkNodeKind::ForkLeaf { offset: (u64::from(index) - first_fork_leaf) as usize }
    } else {
        ForkNodeKind::ForkInternal
    }
}

/// The navigation path from the common block to the peer's tip, inside the peer's branch.
///
/// * `prefix_node(index, level)` returns a node covering only shared leaves (our own MMR holds them).
/// * `fork_leaves` are the leaf hashes of the side blocks above the fork point, oldest first.
/// * `fork_internal(index, level)` returns a node that mixes fork leaves (**step 4**).
///
/// Returns exactly what `WindowedWeightedMMR::collect_fork_path(common_height, peer_tip_height)` returns
/// on the peer's real tree.
pub fn collect_side_fork_path(
    common_height: u32,
    peer_tip_height: u32,
    prefix_node: impl Fn(u32, u32) -> Option<WeightedHash>,
    fork_leaves: &[WeightedHash],
    fork_internal: impl Fn(u32, u32) -> Result<WeightedHash, String>,
) -> Result<Vec<WeightedHash>, String> {
    let expected = peer_tip_height.saturating_sub(common_height) as usize;
    if fork_leaves.len() != expected {
        return Err(format!(
            "collect_side_fork_path: expected {expected} fork leaves, got {}",
            fork_leaves.len()
        ));
    }
    let mut out = Vec::new();
    for (index, level) in WindowedWeightedMMR::fork_path_positions(common_height, peer_tip_height) {
        let hash = match classify_fork_node(index, level, common_height) {
            ForkNodeKind::Prefix => prefix_node(index, level)
                .ok_or_else(|| format!("collect_side_fork_path: prefix node ({index}, level {level}) missing"))?,
            ForkNodeKind::ForkLeaf { offset } => *fork_leaves
                .get(offset)
                .ok_or_else(|| format!("collect_side_fork_path: fork leaf offset {offset} out of range"))?,
            ForkNodeKind::ForkInternal => fork_internal(index, level)?,
        };
        out.push(hash);
    }
    Ok(out)
}

/// Step 4 placeholder: fails loudly. Replace with the real computation of a mixed node from the
/// side-block fork. Not for production use until then.
pub fn step4_not_implemented(index: u32, level: u32) -> Result<WeightedHash, String> {
    Err(format!(
        "side fork path: node ({index}, level {level}) mixes fork leaves; computing it from the side \
         blocks is not implemented (Gap E step 4)"
    ))
}

#[cfg(test)]
mod tests {
    //! The replayed MMRs here are TEST ORACLES (Anti-Patterns #46): they say what the production path
    //! must return. They never serve production.
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use std::cell::Cell;

    fn leaf(seed: u32, i: u32) -> WeightedHash {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&(i + 1).to_le_bytes());
        h[4..8].copy_from_slice(&seed.to_le_bytes());
        WeightedHash::from_leaf_rbits(&h, 0x0300_0001)
    }

    fn chain(seed: u32, common: u32, total: u32) -> WindowedWeightedMMR {
        let mut m = WindowedWeightedMMR::new(&BeaconGenesisConfig::devnet());
        for i in 0..total {
            m.append(leaf(if i < common { 0 } else { seed }, i)).unwrap();
        }
        m
    }

    /// The pure plan reads exactly the nodes `collect_fork_path` returns, for every pair of leaves.
    #[test]
    fn plan_matches_collect_fork_path_for_every_pair() {
        for n in 2..=70u32 {
            let m = chain(1, 0, n);
            for from in 0..n {
                for to in 0..n {
                    if from >= to { continue; }
                    let planned: Vec<WeightedHash> = WindowedWeightedMMR::fork_path_positions(from, to)
                        .into_iter()
                        .map(|(i, l)| m.get_node_hash(i, l).expect("oracle has every node"))
                        .collect();
                    assert_eq!(planned, m.collect_fork_path(from, to).unwrap(), "n={n} from={from} to={to}");
                }
            }
        }
    }

    /// Prefix and single-leaf nodes come from the shared chain and the fork leaves; mixed nodes go to the
    /// step-4 parameter. With an oracle standing in for step 4 the result equals the peer tree's own path,
    /// for many shapes. Nothing but mixed nodes ever reaches step 4.
    #[test]
    fn side_path_equals_the_peer_trees_own_path() {
        for common in 0..=40u32 {
            for fork_len in 1..=40u32 {
                let ours = chain(1, common + 1, common + 1 + 5); // shares leaves 0..=common with the peer
                let peer = chain(2, common + 1, common + 1 + fork_len);
                let peer_tip = common + fork_len;
                let fork_leaves: Vec<WeightedHash> =
                    (common + 1..=peer_tip).map(|i| leaf(2, i)).collect();

                let step4_calls = Cell::new(0u32);
                let got = collect_side_fork_path(
                    common,
                    peer_tip,
                    |i, l| ours.get_node_hash(i, l),
                    &fork_leaves,
                    |i, l| {
                        step4_calls.set(step4_calls.get() + 1);
                        assert_eq!(classify_fork_node(i, l, common), ForkNodeKind::ForkInternal);
                        peer.get_node_hash(i, l).ok_or_else(|| "oracle".to_string())
                    },
                )
                .unwrap();
                assert_eq!(got, peer.collect_fork_path(common, peer_tip).unwrap(), "common={common} fork={fork_len}");
                // O(log n) positions, so O(log n) mixed nodes at most.
                assert!(step4_calls.get() <= 2 * 33, "common={common} fork={fork_len}: {}", step4_calls.get());
            }
        }
    }

    #[test]
    fn classification_follows_the_leaves_a_node_covers() {
        // fork point 9: leaves 0..=9 are shared, 10.. are fork leaves
        assert_eq!(classify_fork_node(4, 1, 9), ForkNodeKind::Prefix); // leaves 8..10 exclusive end 10
        assert_eq!(classify_fork_node(9, 0, 9), ForkNodeKind::Prefix);
        assert_eq!(classify_fork_node(10, 0, 9), ForkNodeKind::ForkLeaf { offset: 0 });
        assert_eq!(classify_fork_node(13, 0, 9), ForkNodeKind::ForkLeaf { offset: 3 });
        assert_eq!(classify_fork_node(5, 1, 9), ForkNodeKind::ForkInternal); // leaves 10..12
        assert_eq!(classify_fork_node(1, 3, 9), ForkNodeKind::ForkInternal); // leaves 8..16 straddle
    }

    #[test]
    fn a_wrong_number_of_fork_leaves_is_an_error_and_the_stub_fails_loudly() {
        let ours = chain(1, 10, 15);
        let r = collect_side_fork_path(9, 14, |i, l| ours.get_node_hash(i, l), &[leaf(2, 10)], step4_not_implemented);
        assert!(r.is_err());
        let leaves: Vec<WeightedHash> = (10..=14).map(|i| leaf(2, i)).collect();
        let r = collect_side_fork_path(9, 14, |i, l| ours.get_node_hash(i, l), &leaves, step4_not_implemented);
        // 9 -> 14 needs mixed nodes: the stub must refuse, not return a wrong path
        assert!(r.unwrap_err().contains("not implemented"));
    }
}
