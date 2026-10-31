// src/mmr_client/verification.rs — Filament (light client) proof verification
//
// Batch and range inclusion proofs are verified via
// `WeightedMMRBatchProof::verify_with_anchor` and
// `WeightedMMRRangeProof::verify_with_anchor` (see `common::proofs`).
//
// This module retains:
//   - VerificationStrategy (chain-weight / fork policy hooks)
//   - ForkProof verification wrappers
//   - MMRChainWeightProof verification
//   - WeightedChainWeightProof verification
//   - HybridMMRState (used by ForkProof climb-and-descent navigation)

use crate::common::crypto::weighted_hash::{hash_pair_weighted, WeightedHash};
use crate::common::proofs::*;
use log::{debug, warn};

// ============================================================================
// VERIFICATION STRATEGIES BY SECURITY LEVEL
// ============================================================================

/// Verification strategy determines what to verify based on security needs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStrategy {
    /// Full verification - verify everything including PoW
    /// Use for: chain weight proofs, recent blocks, initial sync
    Full,

    /// Light verification - trust PoW, verify MMR inclusion
    /// Use for: historical blocks where chain weight already verified
    Light,

    /// Paranoid verification - verify everything even for Light blocks
    /// Use for: maximum security, audit mode
    Paranoid,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        VerificationStrategy::Full
    }
}

/// Verification result with detailed error information
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

impl VerificationResult {
    pub fn success() -> Self {
        Self {
            valid: true,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            error: Some(error),
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

// ============================================================================
// FORK PROOF VERIFICATION
// ============================================================================

/// Verify a [`ForkProof`] built by [`FullBeaconChain::build_fork_proof`].
///
/// Delegates to [`ForkProof::verify`].  Returns `true` iff the proof is
/// cryptographically valid for the given genesis parameters.
pub fn verify_fork_proof(
    proof: &crate::common::proofs::fork_proof::ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: crate::common::crypto::weighted_hash::WeightedHash,
) -> bool {
    proof
        .verify(genesis_anchor, genesis_block_hash)
        .is_ok()
}

/// Verify a [`ForkProof`] with an explicit [`VerificationStrategy`].
pub fn verify_fork_proof_with_strategy(
    proof: &crate::common::proofs::fork_proof::ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: crate::common::crypto::weighted_hash::WeightedHash,
    _strategy: VerificationStrategy,
) -> bool {
    proof
        .verify(genesis_anchor, genesis_block_hash)
        .is_ok()
}

// ============================================================================
// CHAIN WEIGHT PROOF VERIFICATION
// ============================================================================

/// Verify chain weight proof (Full strategy by default).
pub fn verify_chain_weight_proof(proof: &MMRChainWeightProof, genesis_block: &BlockData) -> bool {
    verify_chain_weight_proof_with_strategy(proof, VerificationStrategy::default(), genesis_block)
}

/// Verify chain weight proof with explicit verification strategy.
///
/// Chain weight proofs require Full blocks (Light blocks are rejected).
pub fn verify_chain_weight_proof_with_strategy(
    proof: &MMRChainWeightProof,
    strategy: VerificationStrategy,
    genesis_block: &BlockData,
) -> bool {
    for block in &proof.range_blocks {
        if !block.can_verify_pow() {
            warn!(
                "Chain weight proof: Light block at height {} rejected (cannot verify PoW)",
                block.height()
            );
            return false;
        }
    }

    if !proof.target_block.can_verify_pow() {
        warn!("Chain weight proof: target block cannot verify PoW");
        return false;
    }

    let calculated_weight: u128 = proof.difficulties.iter().map(|&d| d as u128).sum();

    if calculated_weight != proof.total_weight {
        debug!(
            "Chain weight mismatch: expected {}, calculated {}",
            proof.total_weight, calculated_weight
        );
        return false;
    }

    if proof.difficulties.len() != (proof.end_height - proof.start_height + 1) as usize {
        debug!(
            "Difficulty count mismatch: expected {}, got {}",
            proof.end_height - proof.start_height + 1,
            proof.difficulties.len()
        );
        return false;
    }

    if strategy == VerificationStrategy::Paranoid {
        debug!("Paranoid mode: verifying PoW for each block");
        for (i, block) in proof.range_blocks.iter().enumerate() {
            let pow_hash = block.block_hash();
            let difficulty = proof.difficulties[i];

            if !verify_pow_hash(&pow_hash, difficulty) {
                warn!(
                    "Paranoid mode: PoW verification failed at height {}",
                    block.height()
                );
                return false;
            }
        }
    }

    let anchor = genesis_block.prev_mmr_root_bytes();
    if !proof.range_proof.verify_with_anchor(anchor) {
        debug!("Chain weight proof: range proof verification failed");
        return false;
    }

    debug!(
        "Chain weight proof verified: {} blocks, weight {}",
        proof.difficulties.len(),
        proof.total_weight
    );
    true
}

// ============================================================================
// WEIGHTED CHAIN WEIGHT PROOF VERIFICATION
// ============================================================================

/// Verify a `WeightedChainWeightProof` using the genesis anchor.
pub fn verify_weighted_chain_weight_proof(
    proof: &crate::common::proofs::WeightedChainWeightProof,
    genesis_anchor: [u8; 32],
) -> bool {
    proof.verify(genesis_anchor)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Check if node at (index, height) contains target_leaf as descendant
pub(crate) fn contains_as_ancestor(index: usize, height: usize, target_leaf: usize) -> bool {
    let start = index << height;
    let end = (index + 1) << height;
    target_leaf >= start && target_leaf < end
}

/// Check if node is a left child at given height
pub(crate) fn is_left_child_at_height(index: usize, height: usize) -> bool {
    let _ = height;
    index % 2 == 0
}

/// Verify PoW hash meets difficulty target (for Paranoid mode)
pub fn verify_pow_hash(hash: &[u8; 32], difficulty: u64) -> bool {
    let target = u64::MAX / difficulty;

    let hash_value = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);

    hash_value < target
}

// ============================================================================
// HYBRID MMR STATE (ForkProof navigation)
// ============================================================================

/// Maximum MMR peak depth supported by HybridMMRState.
const MAX_MMR_PEAKS: usize = 32;

/// Hybrid MMR state for verification with progressive bagging.
///
/// Used by [`ForkProof::verify`] for climb-and-descent navigation between
/// fork-path leaf indices.
#[derive(Clone)]
pub(crate) struct HybridMMRState {
    completed_peaks: [WeightedHash; MAX_MMR_PEAKS],
    completed_len: usize,
    bagged_peaks: [WeightedHash; MAX_MMR_PEAKS],
    bagged_len: usize,
    rightmost_peak: WeightedHash,
    anchor_hash: WeightedHash,
}

impl HybridMMRState {
    #[inline]
    pub(crate) fn new(anchor_hash: WeightedHash, genesis_hash: WeightedHash) -> Self {
        let mut bagged = [WeightedHash::zero(); MAX_MMR_PEAKS];
        bagged[0] = anchor_hash;
        Self {
            completed_peaks: [WeightedHash::zero(); MAX_MMR_PEAKS],
            completed_len: 0,
            bagged_peaks: bagged,
            bagged_len: 1,
            rightmost_peak: genesis_hash,
            anchor_hash,
        }
    }

    #[inline]
    pub(crate) fn get_root(&self) -> WeightedHash {
        self.bagged_peaks[self.bagged_len - 1]
    }

    #[inline]
    pub(crate) fn climb_left_child(&mut self, right_sibling: WeightedHash) {
        self.rightmost_peak = hash_pair_weighted(&self.rightmost_peak, &right_sibling);
    }

    #[inline]
    pub(crate) fn climb_right_child(&mut self) -> Result<(), String> {
        if self.completed_len == 0 {
            return Err("Cannot climb from right child: no previous peak".to_string());
        }
        self.completed_len -= 1;
        self.bagged_len -= 1;
        let left_sibling = self.completed_peaks[self.completed_len];
        self.rightmost_peak = hash_pair_weighted(&left_sibling, &self.rightmost_peak);
        Ok(())
    }

    #[inline]
    pub(crate) fn descend_into_right_child(&mut self, right_sibling: WeightedHash) {
        self.commit_peak_internal();
        self.rightmost_peak = right_sibling;
    }

    #[inline]
    pub(crate) fn descend_into_left_child(&self) {}

    #[inline]
    pub(crate) fn commit_peak(&mut self) {
        self.commit_peak_internal();
    }

    #[inline]
    fn commit_peak_internal(&mut self) {
        debug_assert!(
            self.completed_len < MAX_MMR_PEAKS,
            "HybridMMRState: peak stack overflow"
        );
        self.completed_peaks[self.completed_len] = self.rightmost_peak;
        self.completed_len += 1;

        let new_bag = hash_pair_weighted(
            &self.bagged_peaks[self.bagged_len - 1],
            &self.rightmost_peak,
        );
        self.bagged_peaks[self.bagged_len] = new_bag;
        self.bagged_len += 1;
    }

    #[inline]
    pub(crate) fn set_rightmost_peak(&mut self, peak: WeightedHash) {
        self.rightmost_peak = peak;
    }

    #[inline]
    pub(crate) fn get_peaks(&self) -> &[WeightedHash] {
        &self.completed_peaks[..self.completed_len]
    }
}
