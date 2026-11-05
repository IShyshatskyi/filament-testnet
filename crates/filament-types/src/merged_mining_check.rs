//! Check of a shard block's proof of work, hash-sorting route and merged-mining proof (clean-room
//! port; checked against the node by the shared vectors).
//!
//! A shard block has no proof of work of its own: it reuses the PoW of the auxiliary beacon
//! candidate it was merge-mined with. The check ties four things together: the aux hash meets the
//! shard's difficulty, its last bits route it to this shard, the shard's leaf sits in the aux
//! header's `merged_mining_root` by a merkle proof, and the chain count packed in that root is in
//! the range the caller expects for the epoch.

use crate::expand_voting::checked_s_bits_for_chain_count;
use crate::hash_sorting::extract_sorting_bits;
use crate::merged_mining_hash::MergedMiningHash;
use crate::pow_target::{hash_meets_target, rbits_to_target};
use crate::shard_header::FullShardHeader;
use crate::weighted_hash::rbits_to_u128_approx;

/// Why a shard block failed the check. The variants mirror the node's error classes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergedMiningError {
    /// The difficulty field is unusable or below the shard floor.
    InvalidRbits(&'static str),
    /// The packed chain count is above the protocol maximum.
    ChainCountAboveMaximum(u16),
    /// The aux PoW hash does not meet the shard target.
    InsufficientProofOfWork,
    /// The hash routes to the beacon, or to another shard than the one claimed.
    HashSorting(String),
    /// The merged-mining proof does not reconstruct the aux header's root, or the count is out of range.
    ProofInvalid(String),
}

fn validate_rbits_reasonableness(rbits: u32) -> Result<(), MergedMiningError> {
    if rbits == 0 {
        return Err(MergedMiningError::InvalidRbits("rBits is zero"));
    }
    if rbits & 0x00FF_FFFF == 0 {
        return Err(MergedMiningError::InvalidRbits("rBits mantissa is zero"));
    }
    if rbits_to_u128_approx(rbits) == 0 {
        return Err(MergedMiningError::InvalidRbits("rBits decodes to zero difficulty"));
    }
    Ok(())
}

/// Shard difficulty must be at least the any-chain floor `2^asserted_s`.
fn validate_shard_rbits_floor(rbits: u32, asserted_s: u32) -> Result<(), MergedMiningError> {
    let Some(floor) = 1u128.checked_shl(asserted_s) else {
        return Err(MergedMiningError::InvalidRbits("shard difficulty floor overflow"));
    };
    if rbits_to_u128_approx(rbits) < floor {
        return Err(MergedMiningError::InvalidRbits("rBits D below shard floor 2^asserted_s"));
    }
    Ok(())
}

/// Check one shard header.
///
/// * `expected_active_shard_count`: inclusive `(min, max)` range the packed chain count must fall
///   in (`None` skips the check).
/// * `ref_s`: reference width of the header's epoch, used for the difficulty floor at height > 0
///   (falls back to the asserted width).
/// * `genesis_asserted_s_bits`: kept for call-site symmetry with the beacon check; a shard block's
///   count of zero maps through the count-to-width mapping, with no genesis fallback.
///
/// An empty merged-mining proof skips the proof and routing checks (legacy and test blocks).
pub fn verify_shard_id_and_mmn_with_ref_s(
    header: &FullShardHeader,
    _tree_depth: usize,
    expected_active_shard_count: Option<(u16, u16)>,
    ref_s: Option<u32>,
    initial_target: &[u8; 32],
    _genesis_asserted_s_bits: u32,
) -> Result<(), MergedMiningError> {
    let pow_hash = header.beacon_header.hash();
    let count = header.beacon_header.root_chain_count();
    let asserted_s = checked_s_bits_for_chain_count(count)
        .map(u32::from)
        .ok_or(MergedMiningError::ChainCountAboveMaximum(count))?;
    let floor_s = if header.height > 0 { ref_s.unwrap_or(asserted_s) } else { asserted_s };

    validate_rbits_reasonableness(header.difficulty)?;
    validate_shard_rbits_floor(header.difficulty, floor_s)?;
    let target = rbits_to_target(header.difficulty, initial_target, asserted_s);
    if !hash_meets_target(&pow_hash, &target) {
        return Err(MergedMiningError::InsufficientProofOfWork);
    }

    let proof = &header.merged_mining_proof;
    if proof.is_empty() {
        return Ok(());
    }

    let bits = extract_sorting_bits(&pow_hash, asserted_s);
    if bits == 0 {
        return Err(MergedMiningError::HashSorting(
            "hash sorting bits are 0: reserved for the beacon chain".to_string(),
        ));
    }
    let routed = (bits - 1) as u16;
    if routed != header.shard_id {
        return Err(MergedMiningError::HashSorting(format!(
            "hash assigns to shard {routed}, block claims shard {}",
            header.shard_id
        )));
    }

    if proof.len() > 15 || (header.shard_id as u32) >> proof.len() != 0 {
        return Err(MergedMiningError::ProofInvalid(format!(
            "shard id {} does not fit a proof of depth {}",
            header.shard_id,
            proof.len()
        )));
    }

    let mut current = MergedMiningHash::from_active_leaf(&header.merged_mining_leaf_hash());
    let mut pos = header.shard_id as u32;
    for sibling in proof {
        current = if pos & 1 == 0 {
            MergedMiningHash::combine(&current, sibling)
        } else {
            MergedMiningHash::combine(sibling, &current)
        };
        pos >>= 1;
    }
    if current.tree_height() as usize != proof.len() {
        return Err(MergedMiningError::ProofInvalid(format!(
            "root tree height {} does not match proof length {}",
            current.tree_height(),
            proof.len()
        )));
    }
    if *current.raw() != header.beacon_header.merged_mining_root {
        return Err(MergedMiningError::ProofInvalid("root mismatch".to_string()));
    }
    if let Some((min, max)) = expected_active_shard_count {
        let active = current.chain_count() as u32;
        if active < min as u32 || active > max as u32 {
            return Err(MergedMiningError::ProofInvalid(format!(
                "{active} active chains outside the admissible range {min}..={max}"
            )));
        }
    }
    Ok(())
}

/// [`verify_shard_id_and_mmn_with_ref_s`] for a [`Block`] with one exact expected chain count
/// (`None` skips the count check) and no reference width.
pub fn verify_shard_id_and_mmn(
    block: &crate::shard_header::Block,
    tree_depth: usize,
    expected_active_shard_count: Option<u16>,
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), MergedMiningError> {
    verify_shard_id_and_mmn_with_ref_s(
        &block.header,
        tree_depth,
        expected_active_shard_count.map(|c| (c, c)),
        None,
        initial_target,
        genesis_asserted_s_bits,
    )
}

impl std::fmt::Display for MergedMiningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRbits(r) => write!(f, "invalid rBits: {r}"),
            Self::ChainCountAboveMaximum(c) => write!(f, "chain count {c} above the protocol maximum"),
            Self::InsufficientProofOfWork => write!(f, "insufficient proof of work"),
            Self::HashSorting(r) => write!(f, "hash sorting: {r}"),
            Self::ProofInvalid(r) => write!(f, "merged-mining proof invalid: {r}"),
        }
    }
}

impl std::error::Error for MergedMiningError {}
