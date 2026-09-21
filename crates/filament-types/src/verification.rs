// filament-types/src/verification.rs — verification strategy + chain-weight /
// fork wrappers + the HybridMMRState climb-and-descent navigation primitive
// used by ForkProof::verify.

use crate::weighted_hash::{hash_pair_weighted, WeightedHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStrategy {
    Full,
    Light,
    Paranoid,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        VerificationStrategy::Full
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

impl VerificationResult {
    pub fn success() -> Self {
        Self { valid: true, error: None, warnings: Vec::new() }
    }

    pub fn failure(error: String) -> Self {
        Self { valid: false, error: Some(error), warnings: Vec::new() }
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

pub fn verify_fork_proof(
    proof: &crate::proofs::ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: WeightedHash,
) -> bool {
    proof.verify(genesis_anchor, genesis_block_hash).is_ok()
}

pub fn verify_fork_proof_with_strategy(
    proof: &crate::proofs::ForkProof,
    genesis_anchor: [u8; 32],
    genesis_block_hash: WeightedHash,
    _strategy: VerificationStrategy,
) -> bool {
    proof.verify(genesis_anchor, genesis_block_hash).is_ok()
}

pub fn verify_weighted_chain_weight_proof(
    proof: &crate::proofs::WeightedChainWeightProof,
    genesis_anchor: [u8; 32],
) -> bool {
    proof.verify(genesis_anchor)
}

/// Verify chain weight proof (Full strategy by default).
pub fn verify_chain_weight_proof(
    proof: &crate::proofs::MMRChainWeightProof,
    genesis_block: &crate::proofs::BlockData,
) -> bool {
    verify_chain_weight_proof_with_strategy(proof, VerificationStrategy::default(), genesis_block)
}

/// Verify chain weight proof with an explicit strategy.
///
/// Light blocks are always rejected — chain weight needs PoW-capable blocks.
/// `Paranoid` additionally spot-checks PoW against each difficulty entry.
pub fn verify_chain_weight_proof_with_strategy(
    proof: &crate::proofs::MMRChainWeightProof,
    strategy: VerificationStrategy,
    genesis_block: &crate::proofs::BlockData,
) -> bool {
    for block in &proof.range_blocks {
        if !block.can_verify_pow() {
            return false;
        }
    }

    if !proof.target_block.can_verify_pow() {
        return false;
    }

    let calculated_weight: u128 = proof.difficulties.iter().map(|&d| d as u128).sum();
    if calculated_weight != proof.total_weight {
        return false;
    }

    if proof.difficulties.len() != (proof.end_height - proof.start_height + 1) as usize {
        return false;
    }

    if strategy == VerificationStrategy::Paranoid {
        for (i, block) in proof.range_blocks.iter().enumerate() {
            let pow_hash = block.block_hash();
            let difficulty = proof.difficulties[i];
            if !verify_pow_hash(&pow_hash, difficulty) {
                return false;
            }
        }
    }

    let anchor = genesis_block.prev_mmr_root_bytes();
    proof.range_proof.verify_with_anchor(anchor)
}

/// Check whether `hash` (read as a little-endian u64 prefix) meets a plain
/// difficulty target — `Paranoid`-mode PoW spot-check.
pub fn verify_pow_hash(hash: &[u8; 32], difficulty: u64) -> bool {
    let target = u64::MAX / difficulty;
    let hash_value = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);
    hash_value < target
}

pub(crate) fn contains_as_ancestor(index: usize, height: usize, target_leaf: usize) -> bool {
    let start = index << height;
    let end = (index + 1) << height;
    target_leaf >= start && target_leaf < end
}

pub(crate) fn is_left_child_at_height(index: usize, _height: usize) -> bool {
    index % 2 == 0
}

const MAX_MMR_PEAKS: usize = 32;

/// Climb-and-descent MMR navigation state used by `ForkProof::verify` to
/// walk from one leaf index to another using only a sibling path, without
/// holding the whole MMR.
#[derive(Clone)]
pub struct HybridMMRState {
    completed_peaks: [WeightedHash; MAX_MMR_PEAKS],
    completed_len: usize,
    bagged_peaks: [WeightedHash; MAX_MMR_PEAKS],
    bagged_len: usize,
    rightmost_peak: WeightedHash,
}

impl HybridMMRState {
    #[inline]
    pub fn new(anchor_hash: WeightedHash, genesis_hash: WeightedHash) -> Self {
        let mut bagged = [WeightedHash::zero(); MAX_MMR_PEAKS];
        bagged[0] = anchor_hash;
        Self {
            completed_peaks: [WeightedHash::zero(); MAX_MMR_PEAKS],
            completed_len: 0,
            bagged_peaks: bagged,
            bagged_len: 1,
            rightmost_peak: genesis_hash,
        }
    }

    #[inline]
    pub fn get_root(&self) -> WeightedHash {
        self.bagged_peaks[self.bagged_len - 1]
    }

    #[inline]
    pub fn climb_left_child(&mut self, right_sibling: WeightedHash) {
        self.rightmost_peak = hash_pair_weighted(&self.rightmost_peak, &right_sibling);
    }

    #[inline]
    pub fn climb_right_child(&mut self) -> Result<(), String> {
        if self.completed_len == 0 {
            return Err("cannot climb from right child: no previous peak".to_string());
        }
        self.completed_len -= 1;
        self.bagged_len -= 1;
        let left_sibling = self.completed_peaks[self.completed_len];
        self.rightmost_peak = hash_pair_weighted(&left_sibling, &self.rightmost_peak);
        Ok(())
    }

    #[inline]
    pub fn descend_into_right_child(&mut self, right_sibling: WeightedHash) {
        self.commit_peak_internal();
        self.rightmost_peak = right_sibling;
    }

    #[inline]
    pub fn descend_into_left_child(&self) {}

    #[inline]
    pub fn commit_peak(&mut self) {
        self.commit_peak_internal();
    }

    #[inline]
    fn commit_peak_internal(&mut self) {
        debug_assert!(self.completed_len < MAX_MMR_PEAKS, "HybridMMRState: peak stack overflow");
        self.completed_peaks[self.completed_len] = self.rightmost_peak;
        self.completed_len += 1;
        let new_bag = hash_pair_weighted(&self.bagged_peaks[self.bagged_len - 1], &self.rightmost_peak);
        self.bagged_peaks[self.bagged_len] = new_bag;
        self.bagged_len += 1;
    }

    #[inline]
    pub fn set_rightmost_peak(&mut self, peak: WeightedHash) {
        self.rightmost_peak = peak;
    }

    #[inline]
    pub fn get_peaks(&self) -> &[WeightedHash] {
        &self.completed_peaks[..self.completed_len]
    }
}
