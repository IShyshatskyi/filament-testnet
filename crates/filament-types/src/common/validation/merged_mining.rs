// src/common/validation/merged_mining.rs

use crate::common::blocks::shard_block::Block;
use crate::common::crypto::difficulty;
use crate::common::crypto::merged_mining_hash::MergedMiningHash;
use super::errors::ValidationError;
use log::{debug, info};

/// Verify shard-id assignment and merged-mining number (MMN) for a shard block.
///
/// Formerly `verify_merged_mining_proof`. Checks, in order:
/// 1. Shard PoW against `FullShardHeader.difficulty` (+ asserted-s soft fold from
///    aux `beacon_header.committed_chain_count`) on the aux mining preimage
///    (`beacon_header.hash()`) — MM-1 / Anti-Pattern entry 7.
/// 2. Hash-sorting assignment of the PoW hash to `header.shard_id` (when a
///    non-empty sibling proof is present).
/// 3. Merkle sibling-path reconstruction of `merged_mining_root` and EX-7b /
///    CV-25 active-count (MMN) cross-check from the reconstructed root's
///    `chain_count()`.
///
/// The proof is a Merkle sibling path in the merged-mining tree stored as
/// `Vec<MergedMiningHash>`.  Each element's embedded `chain_count` and
/// `tree_height` fields are verified during reconstruction.  The root's
/// `chain_count()` replaces the former `merged_mining_number` field.
///
/// # Arguments
/// * `block`                - The shard block to verify.
/// * `tree_depth`           - Depth of the merged mining tree (must reflect current `s_bits`).
/// * `committed_chain_count` - The `committed_chain_count` field from the beacon
///   header that wrapped this shard block.  Set to 0 for legacy blocks (no
///   EX-7b enforcement).
/// * `expected_active_shard_count` - Dynamic active shard count from the beacon
///   epoch parameter vector at the block's beacon height (CV-25 / K-12).  Used
///   when `committed_chain_count == 0` (legacy blocks without PoW commitment).
///
/// # Returns
/// * `Ok(())` if proof is valid.
/// * `Err(ValidationError)` if any check fails.
pub fn verify_shard_id_and_mmn(
    block: &Block,
    tree_depth: usize,
    committed_chain_count: u16,
    expected_active_shard_count: Option<u16>,
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    verify_shard_id_and_mmn_ranged(
        block,
        tree_depth,
        committed_chain_count,
        expected_active_shard_count.map(|c| (c, c)),
        initial_target,
        genesis_asserted_s_bits,
    )
}

/// [`verify_shard_id_and_mmn`] with an admissible count RANGE `(min, max)` (inclusive)
/// instead of one exact value (NC-166, `expand_voting::admissible_count_range`).
pub fn verify_shard_id_and_mmn_ranged(
    block: &Block,
    tree_depth: usize,
    committed_chain_count: u16,
    expected_active_shard_count: Option<(u16, u16)>,
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    info!(
        "Verifying shard_id + MMN for block at height {} (shard {})",
        block.header.height,
        block.header.shard_id
    );

    // Shard "beacon-style" PoW (CV-30 P-1 / MM-1):
    // Preimage = aux beacon_header; target = rbits_to_target(shard difficulty rBits).
    let pow_hash = block.header.beacon_header.hash();
    let asserted_s = super::pow::resolve_shard_asserted_s(
        block.header.beacon_header.committed_chain_count,
        genesis_asserted_s_bits,
    )?;
    // Phase B shard floor: D ≥ 2^asserted_s (no cal× factor).
    super::pow::validate_rbits_reasonableness(block.header.difficulty)?;
    super::pow::validate_shard_rbits_floor(block.header.difficulty, asserted_s)?;
    let shard_target = crate::common::crypto::weighted_hash::rbits_to_target(
        block.header.difficulty,
        initial_target,
        asserted_s,
    );
    if !difficulty::hash_meets_target(&pow_hash, &shard_target) {
        return Err(ValidationError::InsufficientProofOfWork {
            hash: pow_hash,
            target: shard_target,
        });
    }

    let expected_root: [u8; 32] = block.header.beacon_header.merged_mining_root;

    debug!(
        "Target merged_mining_root: {}",
        hex::encode(expected_root)
    );

    // Walk the sibling path bottom-up to reconstruct the root.
    let proof = &block.header.merged_mining_proof;

    // Empty proof means the block was created before MMMT-1 or by a test fixture
    // that does not supply a sibling path.  Skip root-match enforcement in that case.
    // The PoW check above still applies regardless — it does not depend on the
    // proof being present.
    if proof.is_empty() {
        info!("✅ Merged mining proof skipped (empty proof — legacy or test block)");
        return Ok(());
    }

    // Hash-sorting assignment (Header rBits §5.7.6 Q5 / Milestone C):
    // PoW hash must actually route to the claimed shard_id under asserted s.
    // Enforced once a real sibling proof is present (production path). Empty-proof
    // fixtures above return early. Previously only the Merkle leaf *position* was
    // bound to shard_id (Anti-Patterns MM-1/2).
    super::pow::verify_hash_sorting_assignment(
        &pow_hash,
        block.header.shard_id,
        asserted_s,
    )?;

    // Leaf: this shard's template hash — NOT `block.header.hash()`. The full
    // block hash transitively commits to `beacon_header.merged_mining_root`
    // (via `beacon_header.hash()`'s commitment_hash), i.e. the very root this
    // leaf is being used to reconstruct — using it here would be circular.
    // `merged_mining_leaf_hash()` uses only height/prev_mmr_root/tx_merkle_root/
    // difficulty, all independent of `beacon_header` and of each other's
    // nonce, matching what the tree is actually built from at job generation
    // time (before any nonce search) — see its own doc comment. (This
    // comment previously also listed `chain_weight`, which the real
    // implementation never actually read — stale even before that field was
    // removed entirely, Aug 5, 2026.)
    let shard_hash = block.header.merged_mining_leaf_hash();
    let mut current = MergedMiningHash::from_active_leaf(&shard_hash);

    // Position-binding: `MergedMiningHash::combine` is BLAKE3(left ‖ right),
    // which is order-sensitive — combine(a, b) != combine(b, a) in general.
    // A previous version of this loop always did `combine(current, sibling)`
    // regardless of level, which only reconstructs the correct root when
    // `shard_id == 0` (the all-left leaf). The tree extraction side
    // (`LinearMiningTreeSnapshot::extract_shard_merkle_proof`) already derives
    // the correct left/right side from `shard_id`'s binary path (bit 0 at the
    // leaf level, shifting right one level at a time) — replay that same
    // bit-path here so a proof only verifies when the leaf truly sits at the
    // position `shard_id` claims.
    //
    // Note this binds the proof to the *claimed* `shard_id` via the Merkle bit-path.
    // Independently, `verify_hash_sorting_assignment` (called above after PoW)
    // proves the PoW hash's sorting bits select that same shard — both checks
    // are required (Anti-Patterns MM-1/2).
    let mut pos = block.header.shard_id as u32;
    for sibling in proof.iter() {
        current = if pos & 1 == 0 {
            // current is the left child; sibling is the right child.
            MergedMiningHash::combine(&current, sibling)
        } else {
            // current is the right child; sibling is the left child.
            MergedMiningHash::combine(sibling, &current)
        };
        pos >>= 1;
    }

    if proof.len() != tree_depth {
        debug!(
            "Proof length {} does not match expected tree_depth {}",
            proof.len(), tree_depth
        );
        // Not a hard error at validation time — tree depth can change on epoch
        // boundaries.  Continue with whatever root was reconstructed.
    }

    let reconstructed_root: [u8; 32] = *current.raw();
    let active_count = current.chain_count() as u32;

    debug!(
        "Reconstructed root: {}, counted {} active shards",
        hex::encode(reconstructed_root),
        active_count
    );

    // CRITICAL: Verify root matches beacon header.
    if reconstructed_root != expected_root {
        return Err(ValidationError::MergedMiningProofInvalid {
            reason: format!(
                "Root mismatch: expected {}, reconstructed {}",
                hex::encode(expected_root),
                hex::encode(reconstructed_root)
            ),
        });
    }

    verify_merged_mining_active_count_ranged(
        active_count,
        committed_chain_count,
        expected_active_shard_count,
    )?;

    info!(
        "✅ Merged mining proof verified: {} active shards, root matches",
        active_count,
    );

    Ok(())
}

/// NC-166 (Oct 2026): the caller-known "true" count is now an admissible RANGE
/// (`expand_voting::admissible_count_range`, fixed two epochs ahead) via
/// `verify_merged_mining_active_count_ranged`; this exact-value form wraps it as `(c, c)`.
///
/// EX-7b / CV-25 / asserted-vs-true deviation bound: verify reconstructed
/// active chain count against beacon commitment, AND (when the caller has a
/// locally-known true value) bind that commitment to it.
///
/// Two independent checks, both against `active_count` (the count
/// reconstructed by walking the merged-mining sibling proof — a purely
/// structural fact about *this* proof, not asserted by anyone):
///
/// 1. **EX-7b (always, when `committed_chain_count != 0`):** the proof's own
///    reconstructed count must match the PoW-protected `committed_chain_count`
///    the miner asserted in the aux beacon header. This only proves
///    *self-consistency* — that the miner built a proof matching their own
///    claim — never that the claim is *true*.
/// 2. **Deviation bound (Header_rBits_Instead_of_nBits_Design.md §5.7.0
///    decision 3 / Anti-Patterns Registry entry 8, MM-2):** when the caller
///    supplies `expected_active_shard_count`, that value is always this
///    node's own authoritative true count for the exact epoch the block
///    references — every real call site (`ShardChain::validate_block_full`,
///    `FullShardChain::validate_block`) only computes and passes it *after*
///    `ensure_epoch_ready`/the epoch-params lookup has already succeeded, so
///    a node that is still behind on beacon sync never reaches this
///    comparison at all (see `docs/plan/Asserted_vs_True_Chain_Count_Deviation_Bound_Design.md`
///    §3 for why that's a liveness question, not a safety one, and what's
///    still open there). Whenever it *is* `Some`, the miner's asserted
///    `committed_chain_count` must equal it exactly — a PoW-protected claim
///    that merely agrees with itself (check 1) is not enough; per
///    Anti-Patterns entry 8, the embedded aux `BeaconHeader` is a miner's own
///    independently-mined claim, never the real canonical beacon header, and
///    must never be trusted without cross-checking against this node's own
///    chain state.
///
/// Before this fix, check 2 only ever ran in the `committed_chain_count == 0`
/// (legacy, no-PoW-commitment) branch — the common `!= 0` case had no
/// asserted-vs-true cross-check at all, so a miner could assert any
/// self-consistent `committed_chain_count` (deriving a softer asserted-s PoW
/// target / different rBits floor from it) with no binding to the network's
/// real active shard count.
pub(crate) fn verify_merged_mining_active_count(
    active_count: u32,
    committed_chain_count: u16,
    expected_active_shard_count: Option<u16>,
) -> Result<(), ValidationError> {
    verify_merged_mining_active_count_ranged(
        active_count,
        committed_chain_count,
        expected_active_shard_count.map(|c| (c, c)),
    )
}

/// Range form of [`verify_merged_mining_active_count`]: the true count is only known to lie
/// in `[min, max]` (NC-166). EX-7b is unchanged; the deviation bound becomes "the committed
/// count lies in the range", which still stops a miner from asserting a larger count than the
/// protocol could ever have reached (the asserted `s` fold only eases the PoW target).
pub(crate) fn verify_merged_mining_active_count_ranged(
    active_count: u32,
    committed_chain_count: u16,
    expected_active_shard_count: Option<(u16, u16)>,
) -> Result<(), ValidationError> {
    if committed_chain_count != 0 {
        if active_count != committed_chain_count as u32 {
            return Err(ValidationError::MergedMiningProofInvalid {
                reason: format!(
                    "Shard proof shows {} active chains but beacon committed to {} (EX-7b)",
                    active_count, committed_chain_count
                ),
            });
        }
        if let Some((min, max)) = expected_active_shard_count {
            if committed_chain_count < min || committed_chain_count > max {
                return Err(ValidationError::MergedMiningProofInvalid {
                    reason: format!(
                        "Shard block asserts committed_chain_count {} but this node's \
                         admissible active shard count range for the referenced epoch is \
                         {}..={} (asserted-vs-true deviation bound)",
                        committed_chain_count, min, max
                    ),
                });
            }
        }
    } else if let Some((min, max)) = expected_active_shard_count {
        if active_count < min as u32 || active_count > max as u32 {
            return Err(ValidationError::MergedMiningProofInvalid {
                reason: format!(
                    "Shard proof shows {} active chains but epoch cache expects {}..={} (CV-25)",
                    active_count, min, max
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NC-166: a count anywhere in the admissible range passes, outside fails.
    #[test]
    fn nc166_range_accepts_both_ends_and_rejects_outside() {
        for c in [3u16, 4] {
            verify_merged_mining_active_count_ranged(c as u32, c, Some((3, 4))).unwrap();
        }
        for c in [2u16, 5] {
            verify_merged_mining_active_count_ranged(c as u32, c, Some((3, 4)))
                .expect_err("outside the range must fail");
        }
    }

    #[test]
    fn cv25_accepts_matching_epoch_cache_count() {
        verify_merged_mining_active_count(1, 0, Some(1)).unwrap();
    }

    #[test]
    fn cv25_rejects_mismatch_with_epoch_cache_count() {
        let err = verify_merged_mining_active_count(1, 0, Some(4))
            .expect_err("CV-25 mismatch must fail");
        match err {
            ValidationError::MergedMiningProofInvalid { reason } => {
                assert!(reason.contains("CV-25"), "reason: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ex7b_reconstructed_count_must_match_committed_count() {
        // active_count (from the proof) must always agree with the
        // PoW-protected committed_chain_count, regardless of epoch cache.
        verify_merged_mining_active_count(1, 1, None).unwrap();
        let err = verify_merged_mining_active_count(2, 1, None)
            .expect_err("EX-7b mismatch must fail");
        assert!(matches!(err, ValidationError::MergedMiningProofInvalid { .. }));
    }

    /// Deviation bound (Header_rBits_Instead_of_nBits_Design.md §5.7.0
    /// decision 3): once the true count is locally known, a self-consistent
    /// but *false* committed_chain_count must still be rejected — it is no
    /// longer enough for the miner's claim to only agree with itself.
    #[test]
    fn deviation_bound_rejects_self_consistent_but_false_committed_count() {
        // Proof and commitment agree with each other (1 == 1) but disagree
        // with this node's own true epoch count (99) — must reject.
        let err = verify_merged_mining_active_count(1, 1, Some(99))
            .expect_err("asserted committed_chain_count must match the true count");
        assert!(matches!(err, ValidationError::MergedMiningProofInvalid { .. }));
    }

    #[test]
    fn deviation_bound_accepts_when_asserted_equals_true_count() {
        verify_merged_mining_active_count(1, 1, Some(1)).unwrap();
    }

    #[test]
    fn deviation_bound_not_enforced_without_local_epoch_data() {
        // `expected_active_shard_count == None` means the caller has no
        // authoritative true count to compare against yet (e.g. no epoch
        // cache wired at all) — the asserted count is trusted as before,
        // same as pre-fix behavior. This is deliberately NOT the "node is
        // behind on beacon sync" case — every real call site only computes
        // `Some(..)` after its own epoch-readiness check already succeeded,
        // so a behind-node block never reaches this function at all (see
        // `docs/plan/Asserted_vs_True_Chain_Count_Deviation_Bound_Design.md`).
        verify_merged_mining_active_count(1, 1, None).unwrap();
    }

    /// Soft initial target (~2^248) so D=1 / D=256 / asserted-s fold bands
    /// are findable within a few thousand nonce probes. Production genesis
    /// `max_target` values are far harder and make these unit tests impractical.
    fn mm_test_initial_target() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = 0x00;
        t[1] = 0xff;
        t
    }

    /// MM-1 correction: PoW target is shard `header.difficulty` (compact rBits),
    /// not aux `beacon_header.bits`. A hash that meets easy aux work but misses
    /// the harder shard rBits target must be rejected.
    #[test]
    fn mm1_shard_pow_uses_header_difficulty_not_aux_bits() {
        use crate::common::blocks::shard_block::{BeaconHeader, Block, FullShardHeader};
        use crate::common::crypto::difficulty::hash_meets_target;
        use crate::common::crypto::weighted_hash::{
            rbits_to_target, u128_to_rbits, WeightedHash,
        };
        use crate::common::validation::pow::resolve_beacon_asserted_s;

        let initial = mm_test_initial_target();
        const AUX_RBITS: u32 = 0x0300_0001; // D=1
        let shard_rbits = u128_to_rbits(256);

        let mut beacon_header = BeaconHeader::new(
            1,
            1_704_067_200,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            AUX_RBITS,
            1_704_067_200,
            0,
            [0u8; 32],
        );
        let asserted_s =
            resolve_beacon_asserted_s(beacon_header.committed_chain_count, 1).unwrap();
        let aux_target = rbits_to_target(AUX_RBITS, &initial, asserted_s);
        let shard_target = rbits_to_target(shard_rbits, &initial, asserted_s);
        let mut found_aux_only = false;
        for _ in 0..2_000_000 {
            let h = beacon_header.hash();
            if hash_meets_target(&h, &aux_target) && !hash_meets_target(&h, &shard_target) {
                found_aux_only = true;
                break;
            }
            beacon_header.nonce = beacon_header.nonce.wrapping_add(1);
        }
        assert!(
            found_aux_only,
            "test setup: need a nonce that meets aux target but not shard target"
        );

        let block = Block::new(
            FullShardHeader::new(
                1,
                WeightedHash::zero(),
                WeightedHash::zero(),
                [0u8; 32],
                shard_rbits,
                vec![],
                0,
                beacon_header,
            ),
            vec![],
        );

        let err = verify_shard_id_and_mmn(&block, 4, 0, None, &initial, 1)
            .expect_err("must reject: meets aux bits but not shard difficulty");
        assert!(
            matches!(err, ValidationError::InsufficientProofOfWork { .. }),
            "got {err:?}"
        );
    }

    /// Happy path: meeting shard `header.difficulty` rBits is enough even when
    /// aux `beacon_header.bits` encodes harder work (shard-only share class).
    #[test]
    fn mm1_shard_pow_accepts_when_shard_target_met_aux_harder() {
        use crate::common::blocks::shard_block::{BeaconHeader, Block, FullShardHeader};
        use crate::common::crypto::difficulty::hash_meets_target;
        use crate::common::crypto::weighted_hash::{
            rbits_to_target, u128_to_rbits, WeightedHash,
        };
        use crate::common::validation::pow::resolve_beacon_asserted_s;

        let initial = mm_test_initial_target();
        let hard_aux = u128_to_rbits(256);
        // count=0 → asserted_s=1 → any-chain floor D≥2 (Phase B shard floor).
        let easy_shard = u128_to_rbits(2);

        let mut beacon_header = BeaconHeader::new(
            1,
            1_704_067_200,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            hard_aux,
            1_704_067_200,
            0,
            [0u8; 32],
        );
        let asserted_s =
            resolve_beacon_asserted_s(beacon_header.committed_chain_count, 1).unwrap();
        let shard_target = rbits_to_target(easy_shard, &initial, asserted_s);
        let mut found = false;
        for _ in 0..2_000_000 {
            if hash_meets_target(&beacon_header.hash(), &shard_target)
                && !hash_meets_target(
                    &beacon_header.hash(),
                    &rbits_to_target(hard_aux, &initial, asserted_s),
                )
            {
                found = true;
                break;
            }
            beacon_header.nonce = beacon_header.nonce.wrapping_add(1);
        }
        assert!(found, "setup: want shard-only hash (fails hard aux rBits)");

        let block = Block::new(
            FullShardHeader::new(
                1,
                WeightedHash::zero(),
                WeightedHash::zero(),
                [0u8; 32],
                easy_shard,
                vec![],
                0,
                beacon_header,
            ),
            vec![],
        );

        verify_shard_id_and_mmn(&block, 4, 0, None, &initial, 1)
            .expect("must accept: meets shard difficulty even if aux bits unmet");
    }

    /// Asserted-s for shard PoW comes from aux `committed_chain_count`, not from
    /// the MM-tree packed chain_count. A non-zero committed count softens the
    /// target (`T × 2^s`) relative to plain `rbits_to_target(..., s=0)`.
    #[test]
    fn asserted_s_for_shard_pow_from_aux_committed_count_not_mm_root() {
        use crate::common::blocks::shard_block::{BeaconHeader, Block, FullShardHeader};
        use crate::common::crypto::difficulty::hash_meets_target;
        use crate::common::crypto::weighted_hash::{
            rbits_to_target, u128_to_rbits, WeightedHash,
        };
        use crate::common::expand_voting::s_bits_for_chain_count;
        use crate::common::validation::pow::resolve_beacon_asserted_s;

        let initial = mm_test_initial_target();
        let shard_rbits = u128_to_rbits(256);
        const COMMITTED_COUNT: u16 = 4;
        let asserted_s = resolve_beacon_asserted_s(COMMITTED_COUNT, 2).unwrap();
        assert_eq!(asserted_s, s_bits_for_chain_count(COMMITTED_COUNT) as u32);
        assert_eq!(asserted_s, 3);

        let plain = rbits_to_target(shard_rbits, &initial, 0);
        let folded = rbits_to_target(shard_rbits, &initial, asserted_s);
        assert!(folded > plain, "soft left-shift must enlarge target");

        let mut beacon_header = BeaconHeader::new(
            1,
            1_704_067_200,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            0x0300_0001,
            1_704_067_200,
            0,
            [0u8; 32],
        );
        beacon_header.committed_chain_count = COMMITTED_COUNT;

        let mut found = false;
        for _ in 0..5_000_000 {
            let h = beacon_header.hash();
            if hash_meets_target(&h, &folded) && !hash_meets_target(&h, &plain) {
                found = true;
                break;
            }
            beacon_header.nonce = beacon_header.nonce.wrapping_add(1);
        }
        assert!(
            found,
            "setup: need a nonce that meets folded target but not plain rBits"
        );

        let block = Block::new(
            FullShardHeader::new(
                1,
                WeightedHash::zero(),
                WeightedHash::zero(),
                [0u8; 32],
                shard_rbits,
                vec![],
                0,
                beacon_header,
            ),
            vec![],
        );

        verify_shard_id_and_mmn(&block, 4, COMMITTED_COUNT, None, &initial, 2)
            .expect("must accept under asserted-s soft left-shift from aux committed_chain_count");
    }
}
