//! Beacon chain summary v2 — clean-room types and offline verification for Filament.
//!
//! Keystone serves `GET /chain/summary/v2` with trusted epoch-boundary headers and
//! NC-200 record proofs in one weighted MMR batch proof. v1 `GET /chain/summary` remains.

use serde::{Deserialize, Serialize};

use crate::beacon_epoch_record::BeaconEpochRecord;
use crate::expand_voting::s_bits_for_chain_count;
use crate::proofs::types::{BlockData, MMRChainSummary};
use crate::proofs::WeightedMMRBatchProof;
use crate::shard_body::BeaconEpochRecordProof;

/// Maximum trusted epoch-boundary slots in a v2 summary (`W` ∈ {1, 2}).
pub const CHAIN_SUMMARY_V2_MAX_EPOCHS: usize = 2;

/// Default `W` when Keystone builds a v2 summary.
pub const CHAIN_SUMMARY_V2_DEFAULT_EPOCHS: usize = 2;

/// Wire path for the beacon summary v2 (v1 remains `GET /chain/summary`).
pub const CHAIN_SUMMARY_V2_PATH: &str = "/chain/summary/v2";

/// One trusted epoch-start carried in a v2 summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochBoundaryInSummary {
    /// Governance epoch index (`>= 1`). Height must be `epoch * epoch_length`.
    pub epoch: u32,
    /// Epoch-start beacon block (`BlockData::Beacon` only).
    pub block: BlockData,
    /// NC-200 record under this block's body root.
    pub record_proof: BeaconEpochRecordProof,
}

/// Beacon `GET /chain/summary/v2` response.
///
/// `recent_blocks_proof` must cover every leaf in `recent_blocks` **and** every
/// epoch-boundary height in `epoch_boundaries` (an epoch start older than the
/// recent window appears only in `epoch_boundaries` but still in the proof).
///
/// `epoch_boundaries` is ascending by `epoch`, length `0..=CHAIN_SUMMARY_V2_MAX_EPOCHS`,
/// and contains **trusted** epochs only (`<= newest_trusted_epoch` for the tip).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MMRChainSummaryV2 {
    pub tip_block: BlockData,
    pub chain_weight: u128,
    pub recent_blocks_proof: WeightedMMRBatchProof,
    pub recent_blocks: Vec<BlockData>,
    pub epoch_boundaries: Vec<EpochBoundaryInSummary>,
}

impl MMRChainSummaryV2 {
    /// Drop the v2 epoch window and return the v1-shaped tip / recent payload.
    pub fn as_v1(&self) -> MMRChainSummary {
        MMRChainSummary {
            tip_block: self.tip_block.clone(),
            chain_weight: self.chain_weight,
            recent_blocks_proof: self.recent_blocks_proof.clone(),
            recent_blocks: self.recent_blocks.clone(),
        }
    }
}

/// Newest epoch Filament may adopt from a tip at `tip_height` (strictly before
/// the tip's current epoch). Same rule as Filament `thin_epoch::newest_trusted_epoch`.
pub fn newest_trusted_epoch(tip_height: u32, epoch_length: u32) -> u32 {
    (tip_height / epoch_length.max(1)).saturating_sub(1)
}

/// Errors from [`verify_chain_summary_v2`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainSummaryV2Error {
    EmptyEpochWindowNotAllowedWhenTrustedExists { newest_trusted: u32 },
    TooManyEpochBoundaries { got: usize },
    EpochNotAscending { index: usize },
    EpochZeroForbidden,
    EpochNotTrusted { epoch: u32, newest_trusted: u32 },
    BlockNotBeacon { epoch: u32 },
    HeightMismatch { epoch: u32, height: u32, expected: u32 },
    RecordProofFailed { epoch: u32 },
    RecordEpochMismatch { epoch: u32, record_epoch: u32 },
    SBitsMismatch { epoch: u32, got: u8, expected: u8 },
    ContinuityCount { earlier: u32, later: u32 },
    ContinuityK { earlier: u32, later: u32 },
    BatchProofInvalid,
    TipNotBeacon,
    TipHeightZero,
}

impl std::fmt::Display for ChainSummaryV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEpochWindowNotAllowedWhenTrustedExists { newest_trusted } => write!(
                f,
                "v2 summary omitted trusted epoch {newest_trusted} (must include 1..W trusted slots when tip has them)"
            ),
            Self::TooManyEpochBoundaries { got } => {
                write!(f, "v2 epoch_boundaries length {got} exceeds W={CHAIN_SUMMARY_V2_MAX_EPOCHS}")
            }
            Self::EpochNotAscending { index } => {
                write!(f, "epoch_boundaries not strictly ascending at index {index}")
            }
            Self::EpochZeroForbidden => write!(f, "epoch 0 has no record; must not appear in v2"),
            Self::EpochNotTrusted { epoch, newest_trusted } => write!(
                f,
                "epoch {epoch} is not trusted at this tip (newest trusted is {newest_trusted}); refusing provisional/current"
            ),
            Self::BlockNotBeacon { epoch } => {
                write!(f, "epoch {epoch} boundary block is not BlockData::Beacon")
            }
            Self::HeightMismatch { epoch, height, expected } => write!(
                f,
                "epoch {epoch} boundary height {height} != expected {expected}"
            ),
            Self::RecordProofFailed { epoch } => {
                write!(f, "epoch {epoch} record does not verify under the header body root")
            }
            Self::RecordEpochMismatch { epoch, record_epoch } => {
                write!(f, "epoch {epoch} record claims epoch_index {record_epoch}")
            }
            Self::SBitsMismatch { epoch, got, expected } => {
                write!(f, "epoch {epoch} s_bits {got} != s_bits_for_chain_count ({expected})")
            }
            Self::ContinuityCount { earlier, later } => write!(
                f,
                "active_shard_count continuity broken between epochs {earlier} and {later}"
            ),
            Self::ContinuityK { earlier, later } => {
                write!(f, "k / k_next hand-over broken between epochs {earlier} and {later}")
            }
            Self::BatchProofInvalid => write!(f, "recent_blocks_proof failed against the genesis anchor"),
            Self::TipNotBeacon => write!(f, "tip_block is not BlockData::Beacon"),
            Self::TipHeightZero => write!(f, "tip height 0 cannot carry a v2 summary"),
        }
    }
}

impl std::error::Error for ChainSummaryV2Error {}

/// Offline checks for a beacon [`MMRChainSummaryV2`].
///
/// Does **not** open shards — callers adopt [`adopted_epoch_record`] only after this
/// returns `Ok` and then apply the §3.1 shard rule themselves.
pub fn verify_chain_summary_v2(
    summary: &MMRChainSummaryV2,
    genesis_anchor: [u8; 32],
    epoch_length: u32,
) -> Result<(), ChainSummaryV2Error> {
    let tip_height = match &summary.tip_block {
        BlockData::Beacon(b) => b.height,
        _ => return Err(ChainSummaryV2Error::TipNotBeacon),
    };
    if tip_height == 0 {
        return Err(ChainSummaryV2Error::TipHeightZero);
    }

    let newest_trusted = newest_trusted_epoch(tip_height, epoch_length);
    let n = summary.epoch_boundaries.len();
    if n > CHAIN_SUMMARY_V2_MAX_EPOCHS {
        return Err(ChainSummaryV2Error::TooManyEpochBoundaries { got: n });
    }
    if newest_trusted >= 1 && n == 0 {
        return Err(ChainSummaryV2Error::EmptyEpochWindowNotAllowedWhenTrustedExists { newest_trusted });
    }

    let el = epoch_length.max(1);
    let mut parsed: Vec<(u32, BeaconEpochRecord)> = Vec::with_capacity(n);

    for (i, eb) in summary.epoch_boundaries.iter().enumerate() {
        if eb.epoch == 0 {
            return Err(ChainSummaryV2Error::EpochZeroForbidden);
        }
        if eb.epoch > newest_trusted {
            return Err(ChainSummaryV2Error::EpochNotTrusted {
                epoch: eb.epoch,
                newest_trusted,
            });
        }
        if i > 0 && eb.epoch <= summary.epoch_boundaries[i - 1].epoch {
            return Err(ChainSummaryV2Error::EpochNotAscending { index: i });
        }

        let BlockData::Beacon(ref hdr) = eb.block else {
            return Err(ChainSummaryV2Error::BlockNotBeacon { epoch: eb.epoch });
        };
        let expected = eb.epoch.saturating_mul(el);
        if hdr.height != expected {
            return Err(ChainSummaryV2Error::HeightMismatch {
                epoch: eb.epoch,
                height: hdr.height,
                expected,
            });
        }

        let record = eb
            .record_proof
            .verify(&hdr.tx_merkle_root)
            .ok_or(ChainSummaryV2Error::RecordProofFailed { epoch: eb.epoch })?;
        if record.epoch_index != eb.epoch {
            return Err(ChainSummaryV2Error::RecordEpochMismatch {
                epoch: eb.epoch,
                record_epoch: record.epoch_index,
            });
        }
        let expected_s = s_bits_for_chain_count(record.active_shard_count);
        if record.s_bits != expected_s {
            return Err(ChainSummaryV2Error::SBitsMismatch {
                epoch: eb.epoch,
                got: record.s_bits,
                expected: expected_s,
            });
        }
        parsed.push((eb.epoch, record));
    }

    if parsed.len() >= 2 {
        for w in parsed.windows(2) {
            let (e0, r0) = &w[0];
            let (e1, r1) = &w[1];
            if r1.prev_active_shard_count != r0.active_shard_count {
                return Err(ChainSummaryV2Error::ContinuityCount {
                    earlier: *e0,
                    later: *e1,
                });
            }
            if r1.k_active_kbits != r0.k_next_kbits {
                return Err(ChainSummaryV2Error::ContinuityK {
                    earlier: *e0,
                    later: *e1,
                });
            }
        }
    }

    if !summary.recent_blocks_proof.verify_with_anchor(genesis_anchor) {
        return Err(ChainSummaryV2Error::BatchProofInvalid);
    }

    Ok(())
}

/// The newest trusted record in a verified summary, if any (adopt for count / `k`).
pub fn adopted_epoch_record(summary: &MMRChainSummaryV2) -> Option<BeaconEpochRecord> {
    let eb = summary.epoch_boundaries.last()?;
    let BlockData::Beacon(ref hdr) = eb.block else {
        return None;
    };
    eb.record_proof.verify(&hdr.tx_merkle_root)
}

/// Rough additive JSON size for `W` epoch-boundary slots (not including the base
/// tip/recent summary).
pub fn estimated_epoch_window_overhead_bytes(w: usize) -> usize {
    let w = w.min(CHAIN_SUMMARY_V2_MAX_EPOCHS);
    w.saturating_mul(1200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_epoch_record::beacon_ext_leaf;
    use crate::proofs::types::BeaconBlockData;
    use crate::shard_body::tx_merkle_node;
    use crate::weighted_hash::WeightedHash;

    fn beacon_at(height: u32, body_root: [u8; 32]) -> BlockData {
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash: WeightedHash::zero(),
            prev_mmr_root: WeightedHash::zero(),
            current_mmr_root: WeightedHash::zero(),
            version: 1,
            delta: 0,
            difficulty: 1,
            bits: 0,
            nonce: 0,
            tx_merkle_root: body_root,
            merged_mining_root: [0u8; 32],
        })
    }

    fn record(epoch: u32, count: u16, prev: u16, k: u32, k_next: u32) -> BeaconEpochRecord {
        BeaconEpochRecord {
            epoch_index: epoch,
            k_active_kbits: k,
            k_next_kbits: k_next,
            active_shard_count: count,
            prev_active_shard_count: prev,
            s_bits: s_bits_for_chain_count(count),
        }
    }

    #[test]
    fn refuses_provisional_current_epoch() {
        let el = 8u32;
        let tip = beacon_at(17, [1u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![EpochBoundaryInSummary {
                epoch: 2,
                block: beacon_at(16, [2u8; 32]),
                record_proof: BeaconEpochRecordProof {
                    payload: record(2, 4, 3, 1, 1).to_bytes().to_vec(),
                    path: vec![],
                },
            }],
        };
        let err = verify_chain_summary_v2(&summary, [0u8; 32], el).unwrap_err();
        assert!(
            matches!(err, ChainSummaryV2Error::EpochNotTrusted { epoch: 2, newest_trusted: 1 }),
            "got {err:?}"
        );
    }

    #[test]
    fn newest_trusted_matches_thin_epoch_formula() {
        assert_eq!(newest_trusted_epoch(39, 8), 3);
        assert_eq!(newest_trusted_epoch(8, 8), 0);
        assert_eq!(newest_trusted_epoch(15, 8), 0);
        assert_eq!(newest_trusted_epoch(16, 8), 1);
    }

    #[test]
    fn rejects_too_many_slots() {
        let tip = beacon_at(100, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: (1..=3)
                .map(|e| EpochBoundaryInSummary {
                    epoch: e,
                    block: beacon_at(e * 8, [0u8; 32]),
                    record_proof: BeaconEpochRecordProof {
                        payload: record(e, 3, 3, 1, 1).to_bytes().to_vec(),
                        path: vec![],
                    },
                })
                .collect(),
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::TooManyEpochBoundaries { got: 3 })
        ));
    }

    #[test]
    fn estimated_overhead_caps_at_w() {
        assert_eq!(estimated_epoch_window_overhead_bytes(2), 2400);
        assert_eq!(estimated_epoch_window_overhead_bytes(9), 2400);
    }

    #[test]
    fn refuses_height_mismatch() {
        let tip = beacon_at(24, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![EpochBoundaryInSummary {
                epoch: 1,
                block: beacon_at(9, [0u8; 32]),
                record_proof: BeaconEpochRecordProof {
                    payload: record(1, 3, 3, 1, 1).to_bytes().to_vec(),
                    path: vec![],
                },
            }],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::HeightMismatch { .. })
        ));
    }

    #[test]
    fn refuses_count_continuity_break() {
        let tip = beacon_at(24, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![
                EpochBoundaryInSummary {
                    epoch: 1,
                    block: beacon_at(8, [1u8; 32]),
                    record_proof: BeaconEpochRecordProof {
                        payload: record(1, 3, 3, 1, 2).to_bytes().to_vec(),
                        path: vec![],
                    },
                },
                EpochBoundaryInSummary {
                    epoch: 2,
                    block: beacon_at(16, [2u8; 32]),
                    record_proof: BeaconEpochRecordProof {
                        payload: record(2, 5, 4, 2, 2).to_bytes().to_vec(),
                        path: vec![],
                    },
                },
            ],
        };
        let err = verify_chain_summary_v2(&summary, [0u8; 32], 8).unwrap_err();
        assert!(
            matches!(
                err,
                ChainSummaryV2Error::RecordProofFailed { .. }
                    | ChainSummaryV2Error::ContinuityCount { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_epoch_zero() {
        let tip = beacon_at(16, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![EpochBoundaryInSummary {
                epoch: 0,
                block: beacon_at(0, [0u8; 32]),
                record_proof: BeaconEpochRecordProof {
                    payload: record(0, 3, 3, 1, 1).to_bytes().to_vec(),
                    path: vec![],
                },
            }],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::EpochZeroForbidden)
        ));
    }

    fn self_proving(rec: BeaconEpochRecord) -> (BeaconEpochRecordProof, [u8; 32]) {
        let payload = rec.to_bytes().to_vec();
        let leaf = beacon_ext_leaf(Some(&payload));
        let body_root = tx_merkle_node(0, &leaf);
        (BeaconEpochRecordProof { payload, path: vec![] }, body_root)
    }

    #[test]
    fn refuses_s_bits_mismatch() {
        let mut rec = record(1, 3, 3, 1, 1);
        rec.s_bits = 0;
        let (proof, body) = self_proving(rec);
        let tip = beacon_at(16, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![EpochBoundaryInSummary {
                epoch: 1,
                block: beacon_at(8, body),
                record_proof: proof,
            }],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::SBitsMismatch { epoch: 1, .. })
        ));
    }

    #[test]
    fn refuses_record_epoch_mismatch() {
        let (proof, body) = self_proving(record(9, 3, 3, 1, 1));
        let tip = beacon_at(16, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![EpochBoundaryInSummary {
                epoch: 1,
                block: beacon_at(8, body),
                record_proof: proof,
            }],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::RecordEpochMismatch {
                epoch: 1,
                record_epoch: 9
            })
        ));
    }

    #[test]
    fn refuses_count_continuity_with_valid_records() {
        let (p1, b1) = self_proving(record(1, 3, 3, 1, 2));
        let (p2, b2) = self_proving(record(2, 5, 4, 2, 2));
        let tip = beacon_at(24, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![
                EpochBoundaryInSummary {
                    epoch: 1,
                    block: beacon_at(8, b1),
                    record_proof: p1,
                },
                EpochBoundaryInSummary {
                    epoch: 2,
                    block: beacon_at(16, b2),
                    record_proof: p2,
                },
            ],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::ContinuityCount {
                earlier: 1,
                later: 2
            })
        ));
    }

    #[test]
    fn refuses_k_continuity_break() {
        let (p1, b1) = self_proving(record(1, 3, 3, 1, 7));
        let (p2, b2) = self_proving(record(2, 3, 3, 2, 2));
        let tip = beacon_at(24, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![
                EpochBoundaryInSummary {
                    epoch: 1,
                    block: beacon_at(8, b1),
                    record_proof: p1,
                },
                EpochBoundaryInSummary {
                    epoch: 2,
                    block: beacon_at(16, b2),
                    record_proof: p2,
                },
            ],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::ContinuityK {
                earlier: 1,
                later: 2
            })
        ));
    }

    #[test]
    fn refuses_empty_window_when_trusted_exists() {
        let tip = beacon_at(16, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::EmptyEpochWindowNotAllowedWhenTrustedExists { newest_trusted: 1 })
        ));
    }

    #[test]
    fn refuses_non_ascending_epochs() {
        let (p2, b2) = self_proving(record(2, 3, 3, 1, 1));
        let tip = beacon_at(24, [0u8; 32]);
        let summary = MMRChainSummaryV2 {
            tip_block: tip,
            chain_weight: 1,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
            epoch_boundaries: vec![
                EpochBoundaryInSummary {
                    epoch: 2,
                    block: beacon_at(16, b2),
                    record_proof: p2,
                },
                EpochBoundaryInSummary {
                    epoch: 1,
                    block: beacon_at(8, [0u8; 32]),
                    record_proof: BeaconEpochRecordProof {
                        payload: record(1, 3, 3, 1, 1).to_bytes().to_vec(),
                        path: vec![],
                    },
                },
            ],
        };
        assert!(matches!(
            verify_chain_summary_v2(&summary, [0u8; 32], 8),
            Err(ChainSummaryV2Error::EpochNotAscending { index: 1 })
        ));
    }
}