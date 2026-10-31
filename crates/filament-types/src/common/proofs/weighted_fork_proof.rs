// src/common/proofs/weighted_fork_proof.rs
//
// ============================================================================
// WEIGHTED CHAIN WEIGHT PROOF
// ============================================================================
//
// These proof types exploit the FlyClient property of WeightedMMR:
//
//   The MMR root itself is a cumulative-difficulty certificate.
//   root.rbits() == compact encoding of total chain work.
//   No separate proof-of-work hash list is needed.
//
// CHAIN WEIGHT PROOF (simplified vs vanilla)
// ------------------------------------------
// Vanilla:  { root, legacy_linear_cumulative_difficulty, pow_hash_list }
// Weighted: { root, height, inclusion_proof }
//           root.rbits() IS the cumulative difficulty — no extra field.
//
// Fork proofs live in `fork_proof.rs` (`ForkProof`).
//
// ============================================================================

use serde::{Deserialize, Serialize};
use crate::common::crypto::weighted_hash::WeightedHash;
use crate::common::proofs::WeightedMMRBatchProof;

// ============================================================================
// CHAIN WEIGHT PROOF
// ============================================================================

/// Proves that an MMR root encodes at least a given amount of cumulative work.
///
/// With `WeightedMMR`, the proof reduces to:
/// - The root itself (root.rbits() = cumulative difficulty)
/// - A batch inclusion proof that the root is reachable from genesis
///
/// No separate legacy_linear_cumulative_difficulty field or PoW hash list is needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedChainWeightProof {
    /// The MMR root whose rBits encodes total cumulative chain work.
    pub root: WeightedHash,
    /// Chain height at which this root was generated.
    pub height: u32,
    /// Inclusion proof linking this root to genesis (optional; used by light
    /// clients that do not already hold the full peak list).
    pub inclusion_proof: Option<WeightedMMRBatchProof>,
}

impl WeightedChainWeightProof {
    /// Claimed cumulative chain difficulty (decoded from root.rbits()).
    ///
    /// This is the primary payload — no separately-stored difficulty needed.
    pub fn claimed_difficulty(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }

    /// Compact rBits encoding of claimed difficulty.
    pub fn claimed_difficulty_rbits(&self) -> u32 {
        self.root.rbits()
    }

    /// Verify the inclusion proof (if present) against a genesis anchor.
    ///
    /// If no inclusion proof is provided, returns `true` — the caller is
    /// responsible for verifying the root via other means (e.g. they already
    /// hold the tip root from a trusted source).
    pub fn verify(&self, genesis_anchor: [u8; 32]) -> bool {
        match &self.inclusion_proof {
            Some(proof) => proof.verify_with_anchor(genesis_anchor),
            None => true,
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;

    fn anchor() -> [u8; 32] {
        BeaconGenesisConfig::devnet().bitcoin_anchor_hash
    }

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32]; h[0] = seed; h[31] = seed.wrapping_mul(37); h
    }

    fn build_wmmr(n: u8) -> crate::common::weighted_mmr_core::WeightedMMR {
        use crate::common::weighted_mmr_core::WeightedMMR;
        use crate::common::crypto::weighted_hash::WeightedHash;
        let mut m = WeightedMMR::new();
        for i in 1..=n { let _ = m.append(WeightedHash::from_leaf_rbits(&make_hash(i), 0x0300_0001)); }
        m
    }

    #[test]
    fn chain_weight_proof_difficulty_from_root() {
        let mmr = build_wmmr(10);
        let proof = WeightedChainWeightProof {
            root: mmr.get_root(),
            height: 10,
            inclusion_proof: None,
        };
        assert_eq!(proof.claimed_difficulty(), mmr.cumulative_difficulty_approx());
    }

    #[test]
    fn chain_weight_proof_verify_no_inclusion() {
        let mmr = build_wmmr(8);
        let proof = WeightedChainWeightProof {
            root: mmr.get_root(),
            height: 8,
            inclusion_proof: None,
        };
        assert!(proof.verify(anchor())); // no inclusion proof → trivially true
    }
}
