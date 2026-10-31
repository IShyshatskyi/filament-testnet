// src/common/proofs/fork_proof.rs
//
// ============================================================================
// FORK PROOF — bidirectional, climb-and-descent MMR fork proof
// ============================================================================
//
// OVERVIEW
// --------
// `ForkProof` is the target fork-proof type that replaces:
//   - `WeightedAdvancedForkProof` (production, unidirectional, no block data)
//   - `AdvancedForkProof`         (partially implemented, never built)
//   - `MMRForkProof`              (legacy, structural only — kept for find_fork_point)
//
// A fork proof convinces a light client of three things in one round trip:
//   1. The common ancestor block between the two chains.
//   2. The full node's canonical chain tip.
//   3. The peer's fork tip.
//   4. Cryptographic paths linking genesis → common, common → our tip, and
//      common → peer tip, using the same climb-and-descent sibling sequences
//      that `verify_batch_proof_optimized` / `HybridMMRState` already consume.
//
// PATHS
// -----
// Each path is a flat `Vec<WeightedHash>` produced by
// `WindowedWeightedMMR::collect_fork_path(from, to)`, which delegates to
// `prove_batch(&[from, to]).siblings`.  The verifier (`ForkProof::verify`,
// implemented in Step 3) runs `HybridMMRState` climb-and-descent three times,
// consuming each path's siblings in order — the same code path used for batch
// and range proof verification.
//
// VERIFICATION CHECKPOINTS
// ------------------------
// After navigating to each block the verifier compares the reconstructed
// bagged-peak state against the block's `prev_mmr_root` field.  That field
// is part of the pre-image of the block hash, so a matching checkpoint proves
// the path is correct without the verifier having seen any intermediate block
// headers.
//
// MODULE LAYOUT
// -------------
// This file contains only type definitions and serde implementations (Step 2).
// `ForkProof::verify` will be added in Step 3.
// `ForkProof::build` will be added to `FullBeaconChain` in Step 4.
// ============================================================================

use serde::{Deserialize, Serialize};

use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::proofs::BlockData;

// ============================================================================
// PRIMARY TYPE
// ============================================================================

/// Bidirectional fork proof using climb-and-descent MMR sibling paths.
///
/// ## Fields
///
/// ### Block data
///
/// Three `BlockData` values carry the consensus fields needed for verification
/// checkpoints and fork-choice comparison:
///
/// * `common_block` — last block both chains agree on.
/// * `our_tip`      — full node's canonical chain tip.
/// * `peer_tip`     — peer's fork tip.
///
/// ### Sibling paths
///
/// Each path is a flat `Vec<WeightedHash>` in the order the
/// `HybridMMRState` climb-and-descent verifier will consume them — exactly
/// the `siblings` field of `WeightedMMRBatchProof` for that pair of leaves.
///
/// * `path_to_common`               — genesis leaf  → `common_block`.
/// * `path_from_common_to_our_tip`  — `common_block` → `our_tip`.
/// * `path_from_common_to_peer_tip` — `common_block` → `peer_tip`.
///
/// `path_to_common` is empty when `common_block.height() == 0` (fork from
/// genesis); the other two paths are always non-empty unless the tip equals
/// the common block (which the verifier rejects as a structural guard).
///
/// ## Verification
///
/// Call `ForkProof::verify(genesis_anchor, genesis_block_hash)` (Step 3).
/// The verifier runs three sequential `HybridMMRState` navigation passes,
/// cloning the state after PASS 1 so that PASS 3 starts from the same
/// post-common checkpoint as PASS 2.
///
/// ## Generation
///
/// Built by `FullBeaconChain::build_fork_proof(peer_tip_hash)` (Step 4),
/// which calls `WindowedWeightedMMR::collect_fork_path` for our-side paths
/// and reconstructs a temporary MMR over the peer's fork headers from
/// `BeaconSideBlockManager::block_store` for the peer-side path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkProof {
    /// Last block both chains agree on.
    pub common_block: BlockData,

    /// Full node's canonical chain tip.
    pub our_tip: BlockData,

    /// Peer's fork tip.
    pub peer_tip: BlockData,

    // Naming (Oct 23, 2026): `common_block` / `common_height` in this type mean the LAST COMMON block
    // (the proof's anchor). The node-level `fork_height` is the first *divergent* height, i.e.
    // `common_block.height() + 1`. These names are part of a serialized type and stay as they are.

    /// Siblings for the walk from genesis leaf (height 0) to `common_block`.
    ///
    /// Produced by `collect_fork_path(mmr, 0, common_block.height())`.
    /// Empty when `common_block.height() == 0` (fork from genesis — no
    /// PASS 1 navigation needed).
    ///
    /// Length: O(log(common_height)).  Typically 0–20 entries.
    pub path_to_common: Vec<WeightedHash>,

    /// Siblings for the walk from `common_block` to `our_tip`.
    ///
    /// Produced by `collect_fork_path(mmr, common_block.height(),
    /// our_tip.height())`.  The verifier's `HybridMMRState` is already at
    /// the post-common position at the start of PASS 2 (it was left there
    /// by PASS 1), so these siblings resume exactly where PASS 1 stopped.
    ///
    /// Length: O(log(our_tip_height − common_height)).  Typically 0–20 entries.
    pub path_from_common_to_our_tip: Vec<WeightedHash>,

    /// Siblings for the walk from `common_block` to `peer_tip`.
    ///
    /// Same structure as `path_from_common_to_our_tip` but follows the
    /// peer's fork branch.  PASS 3 rewinds the verifier state to the clone
    /// taken after PASS 1 before consuming these siblings.
    ///
    /// Produced by `collect_fork_path(peer_fork_mmr, common_block.height(),
    /// peer_tip.height())` where `peer_fork_mmr` is a temporary MMR
    /// reconstructed from `BeaconSideBlockManager::block_store`.
    ///
    /// Length: O(log(peer_tip_height − common_height)).  Typically 0–20 entries.
    pub path_from_common_to_peer_tip: Vec<WeightedHash>,
}

// ============================================================================
// ERROR TYPE
// ============================================================================

/// Reason a `ForkProof::verify` call failed.
///
/// Each variant corresponds to a specific check in the three-pass verifier.
/// The `*Mismatch` variants carry both the expected and reconstructed roots
/// so callers can log the exact disagreement without re-running verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkProofError {
    // ── structural guards (checked before any hashing) ────────────────────

    /// `our_tip.height() <= common_block.height()`.
    ///
    /// The full node's tip must be strictly above the common ancestor.
    CommonNotBelowOurTip,

    /// `peer_tip.height() <= common_block.height()`.
    ///
    /// The peer's tip must be strictly above the common ancestor.
    CommonNotBelowPeerTip,

    // ── PASS 1: genesis → common_block ────────────────────────────────────

    /// `HybridMMRState` climb-and-descent failed while consuming
    /// `path_to_common`.
    ToCommonNavigationFailed(String),

    /// The bagged-peak state reconstructed after PASS 1 does not match
    /// `common_block.prev_mmr_root()`.
    CommonRootMismatch {
        expected: WeightedHash,
        got: WeightedHash,
    },

    // ── PASS 2: common_block → our_tip ────────────────────────────────────

    /// `HybridMMRState` climb-and-descent failed while consuming
    /// `path_from_common_to_our_tip`.
    ToOurTipNavigationFailed(String),

    /// The bagged-peak state reconstructed after PASS 2 navigation does not
    /// match `our_tip.prev_mmr_root()`.
    OurTipRootMismatch {
        expected: WeightedHash,
        got: WeightedHash,
    },

    // ── PASS 3: common_block → peer_tip ───────────────────────────────────

    /// `HybridMMRState` climb-and-descent failed while consuming
    /// `path_from_common_to_peer_tip`.
    ToPeerTipNavigationFailed(String),

    /// The bagged-peak state reconstructed after PASS 3 navigation does not
    /// match `peer_tip.prev_mmr_root()`.
    PeerTipRootMismatch {
        expected: WeightedHash,
        got: WeightedHash,
    },

    // ── paranoid-mode only ────────────────────────────────────────────────

    /// `VerificationStrategy::Paranoid` was requested but one or more of
    /// `common_block`, `our_tip`, `peer_tip` does not carry verifiable PoW
    /// data (e.g. a `BlockData::ShardLight` block without a nonce).
    PowVerificationUnavailable,
}

impl std::fmt::Display for ForkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommonNotBelowOurTip =>
                write!(f, "common_block is not strictly below our_tip"),
            Self::CommonNotBelowPeerTip =>
                write!(f, "common_block is not strictly below peer_tip"),
            Self::ToCommonNavigationFailed(msg) =>
                write!(f, "PASS 1 (genesis → common) navigation failed: {msg}"),
            Self::CommonRootMismatch { expected, got } =>
                write!(f, "PASS 1 root mismatch: expected {expected:?}, got {got:?}"),
            Self::ToOurTipNavigationFailed(msg) =>
                write!(f, "PASS 2 (common → our_tip) navigation failed: {msg}"),
            Self::OurTipRootMismatch { expected, got } =>
                write!(f, "PASS 2 root mismatch: expected {expected:?}, got {got:?}"),
            Self::ToPeerTipNavigationFailed(msg) =>
                write!(f, "PASS 3 (common → peer_tip) navigation failed: {msg}"),
            Self::PeerTipRootMismatch { expected, got } =>
                write!(f, "PASS 3 root mismatch: expected {expected:?}, got {got:?}"),
            Self::PowVerificationUnavailable =>
                write!(f, "paranoid PoW check requested but block data does not carry PoW fields"),
        }
    }
}

impl std::error::Error for ForkProofError {}

// ============================================================================
// RESULT TYPE
// ============================================================================

/// Outcome of a successful `ForkProof::verify` call.
///
/// All fields are derived from the verified paths — callers can trust them
/// only after `verify` returns `Ok(result)`.
#[derive(Clone, Debug, PartialEq)]
pub struct ForkProofResult {
    /// Reconstructed bagged-peak root at `our_tip` height.
    ///
    /// The `rBits` field encodes our cumulative chain difficulty.
    pub our_root: WeightedHash,

    /// Reconstructed bagged-peak root at `peer_tip` height.
    ///
    /// The `rBits` field encodes the peer's cumulative chain difficulty.
    pub peer_root: WeightedHash,

    /// Approximate cumulative work on our chain (decoded from `our_root.rBits`).
    pub our_weight: u128,

    /// Approximate cumulative work on the peer's chain (decoded from `peer_root.rBits`).
    pub peer_weight: u128,

    /// `true` when our chain has strictly more cumulative work than the peer's.
    ///
    /// Equal-weight chains resolve in favour of our chain (the full node's
    /// canonical chain is preferred when weights are indistinguishable).
    pub canonical_chain_wins: bool,

    /// Number of headers the syncing peer needs to fetch.
    ///
    /// Equal to `our_tip.height() - common_block.height()`.
    pub headers_to_fetch: u32,
}

// ============================================================================
// VERIFICATION
// ============================================================================

/// Navigate the `HybridMMRState` from leaf index `from_idx` to leaf index
/// `to_idx`, consuming siblings from `siblings` in order.
///
/// This is the climb-and-descent loop extracted verbatim from
/// `verify_batch_proof_with_strategy_optimized` in `verification.rs`,
/// parameterised over a leaf-index range and a sibling iterator instead of
/// a block iterator.
///
/// ## Contract
/// - `siblings` must contain exactly the entries that `collect_fork_path(from_idx,
///   to_idx)` produced — that is, `prove_batch(&[from_idx, to_idx]).siblings`.
/// - `state` must be positioned with `rightmost_peak` holding the hash of the
///   leaf at `from_idx` (placed there by the previous `set_rightmost_peak` call).
/// - After return the state is positioned at `to_idx` height 0, ready for a
///   `commit_peak` + checkpoint check.
///
/// ## Returns
/// `Ok(())` on success; `Err(String)` if a sibling is missing or a right-child
/// climb fails (both indicate a malformed proof).
pub(crate) fn navigate_to(
    state: &mut crate::common::verification::HybridMMRState,
    from_idx: usize,
    to_idx: usize,
    siblings: &mut std::slice::Iter<'_, crate::common::crypto::weighted_hash::WeightedHash>,
) -> Result<(), String> {
    use crate::common::verification::{contains_as_ancestor, is_left_child_at_height};

    // No navigation needed when already at the target.
    if from_idx == to_idx {
        return Ok(());
    }

    let mut cur_index  = from_idx;
    let mut cur_height = 0usize;
    let target_idx     = to_idx;

    // ── Climb phase ───────────────────────────────────────────────────────────
    loop {
        if !is_left_child_at_height(cur_index, cur_height) {
            // Right child: merge with the top of the completed-peak stack.
            state.climb_right_child()
                .map_err(|e| format!("navigate_to({from_idx}→{to_idx}): climb_right_child: {e}"))?;
        } else if !contains_as_ancestor(cur_index + 1, cur_height, target_idx) {
            // Left child whose right-sibling subtree does NOT contain the target:
            // consume a sibling and climb to the parent.
            let sib = siblings.next().ok_or_else(|| {
                format!(
                    "navigate_to({from_idx}→{to_idx}): missing sibling during climb \
                     at (index={cur_index}, height={cur_height})"
                )
            })?;
            state.climb_left_child(*sib);
        } else {
            // Left child whose right-sibling subtree DOES contain the target:
            // stop climbing and pivot sideways.
            break;
        }
        cur_index  /= 2;
        cur_height += 1;
    }

    // ── Pivot into the sibling subtree ────────────────────────────────────────
    cur_index += 1;

    // ── Descent phase ─────────────────────────────────────────────────────────
    while cur_height > 0 {
        cur_height -= 1;
        cur_index  *= 2; // move to left child

        if !contains_as_ancestor(cur_index, cur_height, target_idx) {
            // Target is in the right subtree: park the left subtree root,
            // swap in the proof sibling, move right.
            let sib = siblings.next().ok_or_else(|| {
                format!(
                    "navigate_to({from_idx}→{to_idx}): missing sibling during descent \
                     at height={cur_height}"
                )
            })?;
            state.descend_into_right_child(*sib);
            cur_index += 1;
        } else {
            // Target is in the left subtree: keep current peak, continue down.
            state.descend_into_left_child();
        }
    }

    Ok(())
}

impl ForkProof {
    /// Verify the fork proof against a trusted genesis anchor.
    ///
    /// Runs three sequential `HybridMMRState` navigation passes over the
    /// sibling paths:
    ///
    /// * **PASS 1** — genesis → `common_block`: establishes the MMR state at
    ///   the common ancestor.  Checks `common_block.prev_mmr_root()`.
    /// * **PASS 2** — `common_block` → `our_tip`: follows our canonical branch.
    ///   Checks `our_tip.prev_mmr_root()`.  Reads `our_weight` from the final root.
    /// * **PASS 3** — `common_block` → `peer_tip`: rewinds to the post-PASS-1
    ///   clone and follows the peer's fork branch.  Checks
    ///   `peer_tip.prev_mmr_root()`.  Reads `peer_weight` from the final root.
    ///
    /// # Arguments
    ///
    /// * `genesis_anchor`     — `bitcoin_anchor_hash` from `BeaconGenesisConfig`.
    ///   Must match the anchor baked into every MMR root on this network.
    /// * `genesis_block_hash` — Trusted `WeightedHash` of the genesis leaf
    ///   (leaf 0 in the MMR).  Typically read from `BeaconGenesisConfig` or the
    ///   light-client config file.
    ///
    /// # Returns
    ///
    /// `Ok(ForkProofResult)` if all three passes verify correctly.
    /// `Err(ForkProofError)` naming the specific check that failed.
    pub fn verify(
        &self,
        genesis_anchor: [u8; 32],
        genesis_block_hash: WeightedHash,
    ) -> Result<ForkProofResult, ForkProofError> {
        use crate::common::verification::HybridMMRState;

        // ── Structural guards (checked before any hashing) ────────────────────
        if self.our_tip.height() <= self.common_block.height() {
            return Err(ForkProofError::CommonNotBelowOurTip);
        }
        if self.peer_tip.height() <= self.common_block.height() {
            return Err(ForkProofError::CommonNotBelowPeerTip);
        }

        let anchor_wh = WeightedHash::from_anchor(&genesis_anchor);
        let mut state = HybridMMRState::new(anchor_wh, genesis_block_hash);

        // ── PASS 1: genesis → common_block ────────────────────────────────────
        //
        // Navigate from leaf 0 to `common_block.height()`, consuming siblings
        // from `path_to_common`.
        //
        // **Fork-at-genesis special case** (`common_block.height() == 0`):
        // The genesis block is itself the common ancestor.  Its `prev_mmr_root`
        // is the bitcoin anchor hash (the MMR was empty before genesis was
        // appended) — NOT the post-genesis bagged root.  We therefore skip
        // `navigate_to` + `commit_peak` entirely and compare `anchor_wh`
        // directly.  Calling `commit_peak` here would give the *post-genesis*
        // root (`hash_pair_weighted(anchor, genesis_hash)`) which would never
        // equal the anchor.
        if self.common_block.height() == 0 {
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

            // Commit the navigated peak so `get_root()` returns the bagged
            // state BEFORE `common_block` was appended.
            state.commit_peak();

            // Checkpoint: reconstructed root must equal common_block.prev_mmr_root().
            let got = state.get_root();
            if got != self.common_block.prev_mmr_root() {
                return Err(ForkProofError::CommonRootMismatch {
                    expected: self.common_block.prev_mmr_root(),
                    got,
                });
            }
        }

        // Advance past common_block: its hash becomes the new rightmost peak.
        state.set_rightmost_peak(self.common_block.block_hash_weighted());

        // Clone the state at this exact point so PASS 3 can start from the
        // same post-common position without re-running PASS 1.
        let common_state = state.clone();

        // ── PASS 2: common_block → our_tip ────────────────────────────────────
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

        // Advance past our_tip and commit its leaf to get the final root.
        state.set_rightmost_peak(self.our_tip.block_hash_weighted());
        state.commit_peak();
        let our_root = state.get_root();

        // ── PASS 3: common_block → peer_tip ───────────────────────────────────
        // Rewind to the post-common snapshot.
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

        // ── Result ────────────────────────────────────────────────────────────
        let our_weight  = our_root.cumulative_difficulty_approx();
        let peer_weight = peer_root.cumulative_difficulty_approx();

        Ok(ForkProofResult {
            our_root,
            peer_root,
            our_weight,
            peer_weight,
            // Equal-weight chains resolve in favour of our canonical chain.
            canonical_chain_wins: our_weight >= peer_weight,
            headers_to_fetch: self.our_tip.height() - self.common_block.height(),
        })
    }
}

// ============================================================================
// PUBLIC WRAPPER (used by mmr_client::verification, Step 5)
// ============================================================================

/// Verify a fork proof against a trusted genesis anchor.
///
/// Thin wrapper over [`ForkProof::verify`] matching the calling convention of
/// `verify_batch_proof` / `verify_range_proof`.
///
/// # Arguments
/// * `proof`               — fork proof received from the full node.
/// * `genesis_anchor`      — `bitcoin_anchor_hash` from `BeaconGenesisConfig`.
/// * `genesis_block_hash`  — trusted genesis leaf `WeightedHash`.
///
/// # Returns
/// `Ok(ForkProofResult)` on success; `Err(ForkProofError)` on failure.
pub fn verify_fork_proof(
    proof: &ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: WeightedHash,
) -> Result<ForkProofResult, ForkProofError> {
    proof.verify(genesis_anchor, genesis_block_hash)
}

// ============================================================================
// TESTS — types and serde only (Step 2)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::proofs::{BlockData, BeaconBlockData};

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Zero-filled `BlockData::Beacon` at the given height.
    ///
    /// Used by serde and structural tests that need a valid `BlockData` but
    /// do not exercise cryptographic correctness.
    fn dummy_block(height: u32) -> BlockData {
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash:         WeightedHash::zero(),
            prev_mmr_root:      [0u8; 32].into(),
            current_mmr_root:   [0u8; 32].into(),
            version:            1,
            delta:              0,
            difficulty:         1,
            bits:               0x1d00ffff,
            nonce:              0,
            tx_merkle_root:    [0u8; 32],
            merged_mining_root: [0u8; 32],
        })
    }

    /// Minimal `ForkProof` with zero-filled paths.
    ///
    /// Cryptographically invalid — only suitable for serde and structural tests.
    fn dummy_fork_proof() -> ForkProof {
        ForkProof {
            common_block:                 dummy_block(5),
            our_tip:                      dummy_block(20),
            peer_tip:                     dummy_block(10),
            path_to_common:               vec![WeightedHash::zero(); 3],
            path_from_common_to_our_tip:  vec![WeightedHash::zero(); 2],
            path_from_common_to_peer_tip: vec![WeightedHash::zero(); 2],
        }
    }

    // ── serde ─────────────────────────────────────────────────────────────────

    /// Serialise and deserialise a `ForkProof` via bincode; confirm all path
    /// lengths survive.
    #[test]
    fn fork_proof_bincode_round_trip() {
        let proof = dummy_fork_proof();

        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
            .expect("bincode encode must not fail");
        let back: ForkProof =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .map(|(v, _)| v)
                .expect("bincode decode must not fail");

        assert_eq!(
            proof.path_to_common.len(),
            back.path_to_common.len(),
            "path_to_common length must survive round-trip"
        );
        assert_eq!(
            proof.path_from_common_to_our_tip.len(),
            back.path_from_common_to_our_tip.len(),
            "path_from_common_to_our_tip length must survive round-trip"
        );
        assert_eq!(
            proof.path_from_common_to_peer_tip.len(),
            back.path_from_common_to_peer_tip.len(),
            "path_from_common_to_peer_tip length must survive round-trip"
        );
    }

    /// Serialise and deserialise via serde_json; confirm block heights survive.
    #[test]
    fn fork_proof_json_round_trip() {
        let proof = dummy_fork_proof();

        let json = serde_json::to_string(&proof)
            .expect("serde_json::to_string must not fail");
        let back: ForkProof = serde_json::from_str(&json)
            .expect("serde_json::from_str must not fail");

        assert_eq!(
            proof.common_block.height(),
            back.common_block.height(),
            "common_block height must survive JSON round-trip"
        );
        assert_eq!(
            proof.our_tip.height(),
            back.our_tip.height(),
            "our_tip height must survive JSON round-trip"
        );
        assert_eq!(
            proof.peer_tip.height(),
            back.peer_tip.height(),
            "peer_tip height must survive JSON round-trip"
        );
    }

    /// Round-trip a proof with an empty `path_to_common` (fork at genesis).
    #[test]
    fn fork_proof_empty_path_to_common_round_trips() {
        let proof = ForkProof {
            common_block:                 dummy_block(0),
            our_tip:                      dummy_block(10),
            peer_tip:                     dummy_block(5),
            path_to_common:               vec![],   // genesis fork — no PASS 1 siblings
            path_from_common_to_our_tip:  vec![WeightedHash::zero(); 2],
            path_from_common_to_peer_tip: vec![WeightedHash::zero(); 1],
        };

        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let back: ForkProof =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .map(|(v, _)| v)
                .unwrap();

        assert!(
            back.path_to_common.is_empty(),
            "empty path_to_common must survive round-trip"
        );
    }

    // ── ForkProofError ────────────────────────────────────────────────────────

    /// Every `ForkProofError` variant must implement `Display` without panicking.
    #[test]
    fn fork_proof_error_display_does_not_panic() {
        let wh = WeightedHash::zero();
        let variants: Vec<ForkProofError> = vec![
            ForkProofError::CommonNotBelowOurTip,
            ForkProofError::CommonNotBelowPeerTip,
            ForkProofError::ToCommonNavigationFailed("test error".into()),
            ForkProofError::CommonRootMismatch    { expected: wh, got: wh },
            ForkProofError::ToOurTipNavigationFailed("test error".into()),
            ForkProofError::OurTipRootMismatch    { expected: wh, got: wh },
            ForkProofError::ToPeerTipNavigationFailed("test error".into()),
            ForkProofError::PeerTipRootMismatch   { expected: wh, got: wh },
            ForkProofError::PowVerificationUnavailable,
        ];
        for v in &variants {
            // Must not panic.
            let s = format!("{v}");
            assert!(!s.is_empty(), "Display output must not be empty");
        }
    }

    /// `PartialEq` must distinguish structurally identical variants from
    /// structurally different ones.
    #[test]
    fn fork_proof_error_partial_eq() {
        assert_eq!(
            ForkProofError::CommonNotBelowOurTip,
            ForkProofError::CommonNotBelowOurTip,
            "same variant must compare equal"
        );
        assert_ne!(
            ForkProofError::CommonNotBelowOurTip,
            ForkProofError::CommonNotBelowPeerTip,
            "different variants must compare unequal"
        );
        assert_eq!(
            ForkProofError::ToCommonNavigationFailed("a".into()),
            ForkProofError::ToCommonNavigationFailed("a".into()),
        );
        assert_ne!(
            ForkProofError::ToCommonNavigationFailed("a".into()),
            ForkProofError::ToCommonNavigationFailed("b".into()),
        );
    }

    /// `ForkProofError` implements `std::error::Error`.
    #[test]
    fn fork_proof_error_implements_std_error() {
        let err: &dyn std::error::Error = &ForkProofError::CommonNotBelowOurTip;
        let _ = err.to_string(); // must not panic
    }

    // ── ForkProofResult ───────────────────────────────────────────────────────

    /// `ForkProofResult` must be constructible and its fields directly readable.
    #[test]
    fn fork_proof_result_fields_accessible() {
        let r = ForkProofResult {
            our_root:             WeightedHash::zero(),
            peer_root:            WeightedHash::zero(),
            our_weight:           1_000,
            peer_weight:          500,
            canonical_chain_wins: true,
            headers_to_fetch:     15,
        };
        assert!(r.canonical_chain_wins, "canonical_chain_wins must be readable");
        assert_eq!(r.headers_to_fetch, 15, "headers_to_fetch must match construction value");
        assert!(r.our_weight > r.peer_weight, "our_weight must be greater than peer_weight");
    }

    // ── structural invariants ─────────────────────────────────────────────────

    /// `Clone` and `Debug` must be derived and work without panicking.
    #[test]
    fn fork_proof_clone_and_debug() {
        let proof = dummy_fork_proof();
        let cloned = proof.clone();
        let _ = format!("{cloned:?}"); // must not panic
        assert_eq!(
            proof.path_to_common.len(),
            cloned.path_to_common.len(),
            "cloned path length must match original"
        );
    }

    /// Path lengths must match what was supplied at construction time.
    #[test]
    fn fork_proof_path_lengths_match_construction() {
        let proof = ForkProof {
            common_block:                 dummy_block(3),
            our_tip:                      dummy_block(15),
            peer_tip:                     dummy_block(7),
            path_to_common:               vec![WeightedHash::zero(); 5],
            path_from_common_to_our_tip:  vec![WeightedHash::zero(); 4],
            path_from_common_to_peer_tip: vec![WeightedHash::zero(); 3],
        };
        assert_eq!(proof.path_to_common.len(), 5);
        assert_eq!(proof.path_from_common_to_our_tip.len(), 4);
        assert_eq!(proof.path_from_common_to_peer_tip.len(), 3);
    }

    /// Block height accessors must reflect the heights supplied at construction.
    #[test]
    fn fork_proof_block_heights_accessible() {
        let proof = dummy_fork_proof();
        assert_eq!(proof.common_block.height(), 5);
        assert_eq!(proof.our_tip.height(), 20);
        assert_eq!(proof.peer_tip.height(), 10);
    }

    // ── Step 3: cryptographic verification ───────────────────────────────────
    //
    // NC-5 (Jul 9, 2026): this block previously built real WindowedWeightedMMRs
    // in-tree and exercised ForkProof::verify directly, but WindowedWeightedMMR
    // lives in `full_node` (shisha-core / crates/keystone), which was never a
    // dependency of this crate -- `crate::full_node::...` never resolved here.
    // Confirmed via git log this predates the Jul 3, 2026 Gap 9/10 crate-split
    // and has been silently failing to compile (and therefore never running)
    // ever since. Deleted rather than patched: equivalent (and more thorough --
    // it also covers verify_fork_proof_with_strategy and a chain-built
    // end-to-end path) coverage of the exact same climb-and-descent verifier
    // already exists and passes in `tests/mmr_client/fork_proof_verification_tests.rs`,
    // part of shisha-core's own integration test suite, which can reach both
    // `common_types::common::proofs::fork_proof` and `full_node::windowed_weighted_mmr`
    // without the self-referential-crate problem an in-crate dev-dependency here
    // would hit. See NC-5 in docs/plan/Correctness_and_Validation_Plan.md.
}
