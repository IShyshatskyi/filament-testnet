// filament-types/src/proofs/weighted_fork_proof.rs — chain weight proof.
//
// The MMR root itself is a cumulative-difficulty certificate (root.rbits()
// encodes total chain work), so a "chain weight proof" needs only the root
// plus an optional inclusion proof linking it to genesis.

use serde::{Deserialize, Serialize};

use crate::proofs::WeightedMMRBatchProof;
use crate::weighted_hash::WeightedHash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedChainWeightProof {
    pub root: WeightedHash,
    pub height: u32,
    pub inclusion_proof: Option<WeightedMMRBatchProof>,
}

impl WeightedChainWeightProof {
    pub fn claimed_difficulty(&self) -> u128 {
        self.root.cumulative_difficulty_approx()
    }

    pub fn claimed_difficulty_rbits(&self) -> u32 {
        self.root.rbits()
    }

    /// If no inclusion proof is present, returns `true` — the caller is
    /// responsible for having obtained the root from a trusted source.
    pub fn verify(&self, genesis_anchor: [u8; 32]) -> bool {
        match &self.inclusion_proof {
            Some(proof) => proof.verify_with_anchor(genesis_anchor),
            None => true,
        }
    }
}
