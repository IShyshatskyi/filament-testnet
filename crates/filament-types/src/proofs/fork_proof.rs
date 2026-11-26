// filament-types/src/proofs/fork_proof.rs
//
// Bidirectional fork proof: convinces a light client of the common ancestor
// between two chains, and which side has more cumulative work, via three
// climb-and-descent MMR navigation passes (genesis→common, common→our_tip,
// common→peer_tip) — no raw block-by-block download needed.

use serde::{Deserialize, Serialize};

use crate::proofs::types::BlockData;
use crate::verification::HybridMMRState;
use crate::weighted_hash::WeightedHash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkProof {
    pub common_block: BlockData,
    pub our_tip: BlockData,
    pub peer_tip: BlockData,
    pub path_to_common: Vec<WeightedHash>,
    pub path_from_common_to_our_tip: Vec<WeightedHash>,
    pub path_from_common_to_peer_tip: Vec<WeightedHash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkProofError {
    CommonNotBelowOurTip,
    CommonNotBelowPeerTip,
    ToCommonNavigationFailed(String),
    CommonRootMismatch { expected: WeightedHash, got: WeightedHash },
    ToOurTipNavigationFailed(String),
    OurTipRootMismatch { expected: WeightedHash, got: WeightedHash },
    ToPeerTipNavigationFailed(String),
    PeerTipRootMismatch { expected: WeightedHash, got: WeightedHash },
}

impl std::fmt::Display for ForkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommonNotBelowOurTip => write!(f, "common_block is not strictly below our_tip"),
            Self::CommonNotBelowPeerTip => write!(f, "common_block is not strictly below peer_tip"),
            Self::ToCommonNavigationFailed(m) => write!(f, "PASS 1 (genesis → common) navigation failed: {m}"),
            Self::CommonRootMismatch { expected, got } => write!(f, "PASS 1 root mismatch: expected {expected:?}, got {got:?}"),
            Self::ToOurTipNavigationFailed(m) => write!(f, "PASS 2 (common → our_tip) navigation failed: {m}"),
            Self::OurTipRootMismatch { expected, got } => write!(f, "PASS 2 root mismatch: expected {expected:?}, got {got:?}"),
            Self::ToPeerTipNavigationFailed(m) => write!(f, "PASS 3 (common → peer_tip) navigation failed: {m}"),
            Self::PeerTipRootMismatch { expected, got } => write!(f, "PASS 3 root mismatch: expected {expected:?}, got {got:?}"),
        }
    }
}

impl std::error::Error for ForkProofError {}

#[derive(Clone, Debug, PartialEq)]
pub struct ForkProofResult {
    pub our_root: WeightedHash,
    pub peer_root: WeightedHash,
    pub our_weight: u128,
    pub peer_weight: u128,
    pub canonical_chain_wins: bool,
    pub headers_to_fetch: u32,
}

/// Navigate `state` from leaf index `from_idx` to `to_idx`, consuming
/// siblings in order. `state.rightmost_peak` must already hold the hash of
/// the leaf at `from_idx`.
fn navigate_to(
    state: &mut HybridMMRState,
    from_idx: usize,
    to_idx: usize,
    siblings: &mut std::slice::Iter<'_, WeightedHash>,
) -> Result<(), String> {
    use crate::verification::{contains_as_ancestor, is_left_child_at_height};

    if from_idx == to_idx {
        return Ok(());
    }

    let mut cur_index = from_idx;
    let mut cur_height = 0usize;
    let target_idx = to_idx;

    loop {
        if !is_left_child_at_height(cur_index, cur_height) {
            state
                .climb_right_child()
                .map_err(|e| format!("navigate_to({from_idx}→{to_idx}): climb_right_child: {e}"))?;
        } else if !contains_as_ancestor(cur_index + 1, cur_height, target_idx) {
            let sib = siblings.next().ok_or_else(|| {
                format!(
                    "navigate_to({from_idx}→{to_idx}): missing sibling during climb at \
                     (index={cur_index}, height={cur_height})"
                )
            })?;
            state.climb_left_child(*sib);
        } else {
            break;
        }
        cur_index /= 2;
        cur_height += 1;
    }

    cur_index += 1;

    while cur_height > 0 {
        cur_height -= 1;
        cur_index *= 2;

        if !contains_as_ancestor(cur_index, cur_height, target_idx) {
            let sib = siblings.next().ok_or_else(|| {
                format!("navigate_to({from_idx}→{to_idx}): missing sibling during descent at height={cur_height}")
            })?;
            state.descend_into_right_child(*sib);
            cur_index += 1;
        } else {
            state.descend_into_left_child();
        }
    }

    Ok(())
}

impl ForkProof {
    /// Verify the fork proof against a trusted genesis anchor + genesis leaf
    /// hash. Runs three sequential navigation passes; see module doc.
    pub fn verify(
        &self,
        genesis_anchor: [u8; 32],
        genesis_block_hash: WeightedHash,
    ) -> Result<ForkProofResult, ForkProofError> {
        if self.our_tip.height() <= self.common_block.height() {
            return Err(ForkProofError::CommonNotBelowOurTip);
        }
        if self.peer_tip.height() <= self.common_block.height() {
            return Err(ForkProofError::CommonNotBelowPeerTip);
        }

        let anchor_wh = WeightedHash::from_anchor(&genesis_anchor);
        let mut state = HybridMMRState::new(anchor_wh, genesis_block_hash);

        // PASS 1: genesis → common_block.
        if self.common_block.height() == 0 {
            // Genesis is itself the common ancestor: its prev_mmr_root is
            // the bare anchor (no post-genesis bagging to compare against).
            if anchor_wh != self.common_block.prev_mmr_root() {
                return Err(ForkProofError::CommonRootMismatch {
                    expected: self.common_block.prev_mmr_root(),
                    got: anchor_wh,
                });
            }
        } else {
            navigate_to(
                &mut state,
                0,
                self.common_block.height() as usize,
                &mut self.path_to_common.iter(),
            )
            .map_err(ForkProofError::ToCommonNavigationFailed)?;

            state.commit_peak();
            let got = state.get_root();
            if got != self.common_block.prev_mmr_root() {
                return Err(ForkProofError::CommonRootMismatch {
                    expected: self.common_block.prev_mmr_root(),
                    got,
                });
            }
        }

        state.set_rightmost_peak(self.common_block.block_hash_weighted());
        let common_state = state.clone();

        // PASS 2: common_block → our_tip.
        navigate_to(
            &mut state,
            self.common_block.height() as usize,
            self.our_tip.height() as usize,
            &mut self.path_from_common_to_our_tip.iter(),
        )
        .map_err(ForkProofError::ToOurTipNavigationFailed)?;

        state.commit_peak();
        let got = state.get_root();
        if got != self.our_tip.prev_mmr_root() {
            return Err(ForkProofError::OurTipRootMismatch {
                expected: self.our_tip.prev_mmr_root(),
                got,
            });
        }

        state.set_rightmost_peak(self.our_tip.block_hash_weighted());
        state.commit_peak();
        let our_root = state.get_root();

        // PASS 3: common_block → peer_tip (rewind to post-PASS-1 snapshot).
        let mut state = common_state;

        navigate_to(
            &mut state,
            self.common_block.height() as usize,
            self.peer_tip.height() as usize,
            &mut self.path_from_common_to_peer_tip.iter(),
        )
        .map_err(ForkProofError::ToPeerTipNavigationFailed)?;

        state.commit_peak();
        let got = state.get_root();
        if got != self.peer_tip.prev_mmr_root() {
            return Err(ForkProofError::PeerTipRootMismatch {
                expected: self.peer_tip.prev_mmr_root(),
                got,
            });
        }

        state.set_rightmost_peak(self.peer_tip.block_hash_weighted());
        state.commit_peak();
        let peer_root = state.get_root();

        let our_weight = our_root.cumulative_difficulty_approx();
        let peer_weight = peer_root.cumulative_difficulty_approx();

        Ok(ForkProofResult {
            our_root,
            peer_root,
            our_weight,
            peer_weight,
            canonical_chain_wins: our_weight >= peer_weight,
            headers_to_fetch: self.our_tip.height() - self.common_block.height(),
        })
    }
}

/// Thin wrapper matching the calling convention of the batch/range verifiers.
pub fn verify_fork_proof(
    proof: &ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: WeightedHash,
) -> Result<ForkProofResult, ForkProofError> {
    proof.verify(genesis_anchor, genesis_block_hash)
}
