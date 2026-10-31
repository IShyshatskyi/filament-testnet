// src/common/validation/pow.rs

// ============================================================================
// CORRECTED: PoW Validation with Proper nBits Handling
// ============================================================================
//
// This file shows the CORRECTED proof-of-work verification that properly
// uses 256-bit targets expanded from nBits compact format.
//
// CRITICAL FIXES:
// 1. Uses full [u8; 32] targets instead of truncated u64
// 2. Proper 256-bit comparison for hash < target
// 3. No incorrect 0xFF padding
// 4. Clear separation of PoW verification vs hash-sorting
//
// ============================================================================

use crate::common::blocks::beacon_block::{BeaconBlock, BeaconBlockCandidateHeader};
use crate::common::crypto::difficulty;
use super::errors::ValidationError;
use log::debug;

// ============================================================================
// CV-05: nBits Bounds Check
// ============================================================================

/// Maximum permitted nBits exponent byte.
///
/// The nBits compact format packs the target as:
///   `target = mantissa × 256^(exponent − 3)`
///
/// An exponent of 29 (0x1d) already gives Bitcoin-genesis difficulty.
/// An exponent of 32 (0x20) places the mantissa in the very top bytes,
/// producing an astronomically easy target.  We cap at 0x20 (== 32) to
/// prevent trivially-easy targets while remaining compatible with the
/// Bitcoin encoding used by the `nbits_to_target` implementation.
const NBITS_MAX_EXPONENT: u32 = 0x20;

/// Bit-mask for the nBits negative flag (Bitcoin compact-float sign bit).
///
/// When bit 23 of the mantissa (i.e. bit 23 of the lower 24 bits of
/// `nbits`) is set, `nbits_to_target` would produce a negative number
/// in the signed-integer interpretation.  Such values are unconditionally
/// invalid for proof-of-work difficulty targets.
const NBITS_NEGATIVE_FLAG: u32 = 0x0080_0000;

/// CV-05: Validate that an nBits compact-float encodes a plausible
/// proof-of-work target.
///
/// Rejects the following classes of input:
///
/// | Class | Condition | Why it is invalid |
/// |---|---|---|
/// | Zero nBits | `nbits == 0` | Expands to all-zeros target; no hash can be < 0 |
/// | Zero mantissa | lower 24 bits all zero | Same all-zeros expansion; impossible to mine |
/// | Negative target | bit 23 of mantissa set | Sign bit — target would be negative |
/// | Overflow exponent | exponent byte > 32 | Target wraps / becomes all-zeros in `nbits_to_target` |
/// | Zero expansion | expanded target == [0; 32] | Defense-in-depth; catches edge cases in any of the above |
///
/// This function does **not** enforce a minimum network difficulty —
/// that is a consensus-layer concern.  It only rejects structurally
/// malformed or provably impossible values that no honest miner would
/// ever produce.
///
/// # Arguments
/// * `nbits` — Compact difficulty value from the block header.
///
/// # Errors
/// Returns `ValidationError::InvalidNBits` for any rejected value.
pub fn validate_nbits_reasonableness(nbits: u32) -> Result<(), ValidationError> {
    // ── 1. Zero nBits ────────────────────────────────────────────────────────
    if nbits == 0 {
        return Err(ValidationError::InvalidNBits {
            nbits,
            reason: "nBits is zero; target would be all-zeros (impossible to mine)",
        });
    }

    // ── 2. Zero mantissa ─────────────────────────────────────────────────────
    let mantissa = nbits & 0x00FF_FFFF;
    if mantissa == 0 {
        return Err(ValidationError::InvalidNBits {
            nbits,
            reason: "mantissa is zero; target would be all-zeros (impossible to mine)",
        });
    }

    // ── 3. Negative-target flag ───────────────────────────────────────────────
    if mantissa & NBITS_NEGATIVE_FLAG != 0 {
        return Err(ValidationError::InvalidNBits {
            nbits,
            reason: "negative-target flag set (bit 23 of mantissa); invalid for PoW",
        });
    }

    // ── 4. Overflow exponent ──────────────────────────────────────────────────
    let exponent = nbits >> 24;
    if exponent > NBITS_MAX_EXPONENT {
        return Err(ValidationError::InvalidNBits {
            nbits,
            reason: "exponent byte > 32; target overflows 256 bits",
        });
    }

    // ── 5. Defense-in-depth: expanded target must not be all-zeros ───────────
    let expanded = difficulty::nbits_to_target(nbits);
    if expanded == [0u8; 32] {
        return Err(ValidationError::InvalidNBits {
            nbits,
            reason: "nBits expands to all-zeros target (impossible to mine)",
        });
    }

    Ok(())
}

/// CV-05: Validate that a block's nBits encodes a target no easier than the
/// network-configured maximum (`BeaconGenesisConfig::max_target`).
///
/// A *larger* target value means a *lower* difficulty (more hashes qualify).
/// The network enforces a floor difficulty by bounding the target from above:
/// any block whose target exceeds `max_target` is trivially solvable and must
/// be rejected.
///
/// This check is complementary to [`validate_nbits_reasonableness`]:
/// * `validate_nbits_reasonableness` — structural/malformation checks only;
///   does not require genesis config; called in all three PoW paths.
/// * `validate_nbits_against_max_target` — genesis-config-aware floor check;
///   called from the chain-aware paths (`FullBeaconChain::validate_block`,
///   `verify_shard_block_pow_and_sorting` when a genesis config is available).
///
/// # Arguments
/// * `nbits`      — Compact difficulty from the block header.
/// * `max_target` — 256-bit big-endian network maximum target (from
///                  `BeaconGenesisConfig::max_target`).
///
/// # Returns
/// * `Ok(())` when `nbits_to_target(nbits) <= max_target` (big-endian compare).
/// * `Err(ValidationError::NbitsExceedsMaxTarget)` otherwise.
///
/// # Panics
/// Never — `nbits_to_target` is total; this function does not allocate.
pub fn validate_nbits_against_max_target(
    nbits: u32,
    max_target: &[u8; 32],
) -> Result<(), ValidationError> {
    let expanded = difficulty::nbits_to_target(nbits);
    // Big-endian lexicographic comparison: expanded > max_target means too easy.
    if &expanded > max_target {
        return Err(ValidationError::NbitsExceedsMaxTarget {
            nbits,
            expanded_target: expanded,
            max_target: *max_target,
        });
    }
    Ok(())
}

// ============================================================================
// CV-60: Beacon hash-sorting enforcement
// ============================================================================

/// Verify that a beacon block's PoW hash occupies the beacon-reserved slot.
///
/// The Shisha hash-sorting scheme partitions the `2^k` possible last-k-bit
/// values as follows:
///
/// | Value | Assignment |
/// |-------|------------|
/// | `0`   | **Beacon** (reserved) |
/// | `1`   | Shard 0 |
/// | `2`   | Shard 1 |
/// | …     | … |
/// | `2^k − 1` | Shard `2^k − 2` |
///
/// A valid beacon block **must** have `sorting_bits == 0`.  Any other value
/// means the hash is assigned to a shard — accepting it as a beacon block
/// would allow cross-chain PoW reuse and break the fork-choice separation.
///
/// # Arguments
/// * `pow_hash` — The SHA256d PoW hash of the beacon header.
/// * `k`        — Current hash-sorting bit-width (`BLOCK_HASH_W_BITS`).
///
/// # Errors
/// Returns `ValidationError::BeaconHashSortingViolation` when the last `k`
/// bits of the hash are non-zero (i.e. the hash is shard-eligible, not
/// beacon-eligible).
pub fn verify_beacon_hash_sorting(pow_hash: &[u8; 32], k: u32) -> Result<(), ValidationError> {
    use crate::common::hash_sorting::extract_sorting_bits;
    let sorting_bits = extract_sorting_bits(pow_hash, k);
    if sorting_bits != 0 {
        return Err(ValidationError::BeaconHashSortingViolation {
            sorting_bits,
            k,
        });
    }
    Ok(())
}

/// The **single** merged-mining soft-fold width (`asserted_s`) resolver for the
/// beacon PoW path — Beacon_Difficulty_Unification_Design.md Principle 1.
///
/// Every path that needs `asserted_s` — the retarget floor, the authoritative
/// PoW re-verify, the S5 headers-first pre-filter, the light client — derives
/// it here, so the number the miner mined against and the number every
/// validator checks against can never silently diverge (Flaw B, the NC-104
/// root cause).
///
/// - `committed_chain_count == 0` on a **beacon** header means genesis
///   (height 0). Genesis's nonce is found by `genesis_miner.rs` against
///   `genesis.asserted_s_bits`, so that is the only correct answer for `0` here
///   — **not** `s_bits_for_chain_count(0) = 1`, the 16×-harder value that
///   false-banned the producer (NC-104). (S5 additionally skips genesis
///   outright, Principle 4, so this branch is defence-in-depth on that path.)
/// - Otherwise: the pure count→s mapping
///   ([`crate::common::expand_voting::s_bits_for_chain_count`]). MM-2/8: the
///   committed count is the miner's claim; EX-7/EX-8 bounds it, and the
///   deviation-vs-true-epoch-params question is out of scope here (decision 3).
///
/// `Err(ChainCountAboveMaximum)` for a count above
/// [`crate::common::expand_voting::MAX_COMMITTED_CHAIN_COUNT`] (NC-137: it used
/// to panic inside `compute_required_s_bits`).
#[inline]
pub fn resolve_beacon_asserted_s(
    committed_chain_count: u16,
    genesis_asserted_s_bits: u32,
) -> Result<u32, ValidationError> {
    if committed_chain_count == 0 {
        Ok(genesis_asserted_s_bits)
    } else {
        checked_asserted_s(committed_chain_count)
    }
}

fn checked_asserted_s(committed_chain_count: u16) -> Result<u32, ValidationError> {
    use crate::common::expand_voting::{checked_s_bits_for_chain_count, MAX_COMMITTED_CHAIN_COUNT};
    checked_s_bits_for_chain_count(committed_chain_count)
        .map(u32::from)
        .ok_or(ValidationError::ChainCountAboveMaximum {
            count: committed_chain_count,
            max: MAX_COMMITTED_CHAIN_COUNT,
        })
}

/// Shard-side `asserted_s` resolver.
///
/// **Unlike [`resolve_beacon_asserted_s`], there is no `count == 0` genesis
/// fallback.** A shard block's embedded `beacon_header` is always a real
/// height-≥1 beacon candidate (a shard block is never merge-mined against
/// beacon *genesis*), so the genesis-miner asymmetry that motivates the
/// beacon `0` branch does not exist here — `0` maps straight through
/// `s_bits_for_chain_count`, exactly as the pre-unification
/// `asserted_s_from_committed_chain_count` did. The `genesis_asserted_s_bits`
/// param is kept only for call-site symmetry with the beacon resolver.
/// Same NC-137 bound as [`resolve_beacon_asserted_s`].
#[inline]
pub fn resolve_shard_asserted_s(
    committed_chain_count: u16,
    _genesis_asserted_s_bits: u32,
) -> Result<u32, ValidationError> {
    checked_asserted_s(committed_chain_count)
}

/// Validate that compact **rBits** (header work field) is structurally usable.
///
/// Rejects zero / zero-mantissa / non-decodable values. Unlike the legacy
/// nBits checker, this does **not** expand via `nbits_to_target` (wrong
/// semantics for rBits).
pub fn validate_rbits_reasonableness(rbits: u32) -> Result<(), ValidationError> {
    if rbits == 0 {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "rBits is zero; leaf weight / PoW difficulty would be zero",
        });
    }
    let mantissa = rbits & 0x00FF_FFFF;
    if mantissa == 0 {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "rBits mantissa is zero",
        });
    }
    let d = crate::common::crypto::weighted_hash::rbits_to_u128_approx(rbits);
    if d == 0 {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "rBits decodes to zero difficulty (compact size too small)",
        });
    }
    Ok(())
}

/// Genesis Phase B: reject beacon header rBits whose decoded work `D` is below
/// `shard_calibration × 2^asserted_s`.
///
/// Same floor as [`crate::common::genesis::genesis_config::BeaconGenesisConfig::validate_difficulty_params`].
pub fn validate_beacon_rbits_floor(
    rbits: u32,
    shard_calibration: u32,
    asserted_s: u32,
) -> Result<(), ValidationError> {
    let d = crate::common::crypto::weighted_hash::rbits_to_u128_approx(rbits);
    let Some(floor) =
        crate::common::genesis::genesis_config::beacon_difficulty_floor_u128(shard_calibration, asserted_s)
    else {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "beacon difficulty floor overflow (cal×2^asserted_s)",
        });
    };
    if d < floor {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "rBits D below beacon floor cal×2^asserted_s",
        });
    }
    Ok(())
}

/// Raise `raw` compact rBits to at least the **one** merged beacon retarget
/// floor (`max(minimum_difficulty, cal × 2^asserted_s)`).
///
/// Beacon_Difficulty_Unification_Design.md Principle 3: the last step of the
/// retarget rule, applied nowhere else. `asserted_s` must come from the
/// *deterministic* `active_shard_count_at(next_height)` via
/// [`resolve_beacon_asserted_s`] (Principle 2 — never a live atomic).
///
/// Replaces `clamp_beacon_rbits_to_floor` (which applied only the `cal × 2^s`
/// half) and the DAA's separately-applied `minimum_rbits`.
pub fn apply_beacon_retarget_floor(
    raw_rbits: u32,
    minimum_difficulty: u64,
    shard_calibration: u32,
    asserted_s: u32,
) -> u32 {
    use crate::common::crypto::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};
    let d = rbits_to_u128_approx(raw_rbits);
    let floor = crate::common::genesis::genesis_config::beacon_merged_floor_u128(
        minimum_difficulty,
        shard_calibration,
        asserted_s,
    )
    .unwrap_or(d);
    if d < floor { u128_to_rbits(floor) } else { raw_rbits }
}

/// Genesis Phase B (shard path): reject shard header rBits whose decoded work
/// `D` is below the any-chain floor `2^asserted_s` (no `shard_calibration`
/// factor — that multiplier is what makes shard *easier than beacon*, not
/// something shard's own floor needs again).
///
/// Same inequality genesis already enforces via
/// [`crate::common::genesis::genesis_config::beacon_any_chain_floor_u128`].
pub fn validate_shard_rbits_floor(rbits: u32, asserted_s: u32) -> Result<(), ValidationError> {
    let d = crate::common::crypto::weighted_hash::rbits_to_u128_approx(rbits);
    let Some(floor) =
        crate::common::genesis::genesis_config::beacon_any_chain_floor_u128(asserted_s)
    else {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "shard difficulty floor overflow (2^asserted_s)",
        });
    };
    if d < floor {
        return Err(ValidationError::InvalidNBits {
            nbits: rbits,
            reason: "rBits D below shard floor 2^asserted_s",
        });
    }
    Ok(())
}

/// Raise `raw` compact shard rBits to at least the shard retarget floor
/// (`2^asserted_s` — no `cal` factor, that multiplier is what makes shard
/// easier than beacon). Beacon_Difficulty_Unification_Design.md §6.
///
/// (`shard_minimum_difficulty` has no config field today; if one is added the
/// floor becomes `max(shard_minimum_difficulty, 2^asserted_s)`.)
pub fn apply_shard_retarget_floor(raw_rbits: u32, asserted_s: u32) -> u32 {
    use crate::common::crypto::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};
    let d = rbits_to_u128_approx(raw_rbits);
    let floor =
        crate::common::genesis::genesis_config::beacon_any_chain_floor_u128(asserted_s).unwrap_or(d);
    if d < floor { u128_to_rbits(floor) } else { raw_rbits }
}

/// Verify proof-of-work for a beacon block (header-native rBits — Strategy A).
///
/// Checks that:
/// 1. Header `bits` (compact rBits) is structurally valid
/// 2. Header work meets the Phase B floor `cal × 2^asserted_s`
/// 3. Block hash meets `rbits_to_target(bits, initial_target, asserted_s)`
/// 4. Commitment hash is valid (two-level PoW architecture)
/// 5. Hash-sorting bits are zero — beacon-reserved slot (CV-60), using
///    **asserted** `s = s_bits_for_chain_count(committed_chain_count)`
///
/// # Arguments
/// * `block` — The beacon block to validate
/// * `initial_target` — Network difficulty-1 reference target (genesis `max_target`)
/// * `shard_calibration` — Genesis `shard_calibration` (beacon:shard interval ratio)
/// * `genesis_asserted_s_bits` — Genesis `asserted_s_bits` (the `count == 0`
///   answer for [`resolve_beacon_asserted_s`]; unreachable on this path once
///   Principle 6 lands, but threaded so every path uses the one resolver)
pub fn verify_beacon_proof_of_work(
    block: &BeaconBlock,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    let asserted_s = resolve_beacon_asserted_s(
        block.header.committed_chain_count,
        genesis_asserted_s_bits,
    )?;
    verify_beacon_proof_of_work_with_asserted_s(
        block,
        asserted_s,
        initial_target,
        shard_calibration,
    )
}

/// Verify beacon PoW using an explicit asserted hash-sorting width.
///
/// Prefer [`verify_beacon_proof_of_work`], which derives asserted `s` from
/// `committed_chain_count`.
pub fn verify_beacon_proof_of_work_with_asserted_s(
    block: &BeaconBlock,
    asserted_s_bits: u32,
    initial_target: &[u8; 32],
    shard_calibration: u32,
) -> Result<(), ValidationError> {
    debug!(
        "Verifying PoW for beacon block at height {} (asserted_s={}, cal={})",
        block.header.height, asserted_s_bits, shard_calibration
    );

    validate_rbits_reasonableness(block.header.bits)?;
    // Beacon_Difficulty_Unification_Design.md Q3: the standalone rBits-floor
    // check is gone from the PoW path. A `bits` that passed the continuity
    // check (`bits == beacon_expected_rbits`) is already >= the merged floor by
    // construction; re-checking it here with its own `asserted_s` is exactly
    // the "second floor with its own s" shape that caused NC-104.
    let _ = shard_calibration;

    let pow_hash = BeaconBlock::calculate_hash(&block.header);

    let target = crate::common::crypto::weighted_hash::rbits_to_target(
        block.header.bits,
        initial_target,
        asserted_s_bits,
    );

    debug!(
        "PoW check: hash={}, target={}, rbits=0x{:08x}, asserted_s={}",
        hex::encode(pow_hash),
        hex::encode(target),
        block.header.bits,
        asserted_s_bits
    );

    if !difficulty::hash_meets_target(&pow_hash, &target) {
        return Err(ValidationError::InsufficientProofOfWork {
            hash: pow_hash,
            target,
        });
    }

    debug!("PoW verification passed: hash meets target");

    verify_beacon_hash_sorting(&pow_hash, asserted_s_bits)?;

    debug!("Beacon hash-sorting check passed (sorting_bits == 0)");

    if !block.header.verify_commitment_hash() {
        return Err(ValidationError::InvalidCommitmentHash);
    }

    debug!("Commitment hash verification passed");

    Ok(())
}

/// **v3 (plan §3.1)** — verify beacon PoW via the two-leaf SHA256d commitment
/// (`coinbase_hash` leaf + BLAKE3 aux leaf, SHA256d combine) instead of the
/// legacy BLAKE3-wrap `verify_beacon_proof_of_work` above.
///
/// `coinbase_hash` must be independently re-derived by the caller from the
/// block's own stored body — `crate::transaction::coinbase_hash_from_stored_body(&block.body)`
/// — never trusted as a bare argument from anywhere else, since the whole
/// point of this check is confirming the block's real coinbase content is
/// what PoW was actually solved against.
pub fn verify_beacon_proof_of_work_v3(
    block: &BeaconBlock,
    coinbase_hash: [u8; 32],
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    let asserted_s_bits = resolve_beacon_asserted_s(
        block.header.committed_chain_count,
        genesis_asserted_s_bits,
    )?;

    debug!(
        "Verifying PoW (v3) for beacon block at height {} (asserted_s={}, cal={})",
        block.header.height, asserted_s_bits, shard_calibration
    );

    validate_rbits_reasonableness(block.header.bits)?;
    // Beacon_Difficulty_Unification_Design.md Q3: the standalone rBits-floor
    // check is gone from the PoW path. A `bits` that passed the continuity
    // check (`bits == beacon_expected_rbits`) is already >= the merged floor by
    // construction; re-checking it here with its own `asserted_s` is exactly
    // the "second floor with its own s" shape that caused NC-104.
    let _ = shard_calibration;

    let pow_hash = BeaconBlock::calculate_hash_v3(&block.header, coinbase_hash);

    let target = crate::common::crypto::weighted_hash::rbits_to_target(
        block.header.bits,
        initial_target,
        asserted_s_bits,
    );

    debug!(
        "PoW check (v3): hash={}, target={}, rbits=0x{:08x}, asserted_s={}",
        hex::encode(pow_hash),
        hex::encode(target),
        block.header.bits,
        asserted_s_bits
    );

    if !difficulty::hash_meets_target(&pow_hash, &target) {
        return Err(ValidationError::InsufficientProofOfWork {
            hash: pow_hash,
            target,
        });
    }

    debug!("PoW verification (v3) passed: hash meets target");

    verify_beacon_hash_sorting(&pow_hash, asserted_s_bits)?;

    debug!("Beacon hash-sorting check passed (sorting_bits == 0)");

    if !block.header.verify_commitment_hash_v3(coinbase_hash) {
        return Err(ValidationError::InvalidCommitmentHash);
    }

    debug!("Commitment hash verification (v3) passed");

    Ok(())
}

/// Deprecated name: the `s_bits` argument is **ignored**.
#[deprecated(
    since = "0.8.0",
    note = "s_bits argument ignored; use verify_beacon_proof_of_work (asserted s from committed_chain_count)"
)]
pub fn verify_beacon_proof_of_work_with_hash_sorting(
    block: &BeaconBlock,
    _s_bits: u32,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    verify_beacon_proof_of_work(block, initial_target, shard_calibration, genesis_asserted_s_bits)
}

/// Verify proof-of-work for a beacon header candidate (Strategy A / rBits).
pub fn verify_beacon_header_pow(
    header: &BeaconBlockCandidateHeader,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    validate_rbits_reasonableness(header.bits)?;

    let asserted_s = resolve_beacon_asserted_s(header.committed_chain_count, genesis_asserted_s_bits)?;
    // Q3: no standalone rBits-floor check here — see verify_beacon_proof_of_work_with_asserted_s.
    let _ = shard_calibration;
    let pow_hash = BeaconBlock::calculate_hash(header);
    let target = crate::common::crypto::weighted_hash::rbits_to_target(
        header.bits,
        initial_target,
        asserted_s,
    );

    if !difficulty::hash_meets_target(&pow_hash, &target) {
        return Err(ValidationError::InsufficientProofOfWork {
            hash: pow_hash,
            target,
        });
    }

    verify_beacon_hash_sorting(&pow_hash, asserted_s)?;

    if !header.verify_commitment_hash() {
        return Err(ValidationError::InvalidCommitmentHash);
    }

    Ok(())
}

/// Check if a hash meets a difficulty target
///
/// Generic helper for any PoW verification.
/// Performs full 256-bit comparison: hash < target
///
/// # Arguments
/// * `hash` - The hash to check (SHA256d output)
/// * `target` - The difficulty target (256-bit, from nBits expansion)
///
/// # Returns
/// * `true` if hash < target (valid PoW)
/// * `false` otherwise
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    difficulty::hash_meets_target(hash, target)
}

/// Convert nBits compact difficulty to full 256-bit target
///
/// **FIXED (v0.2.2)**: Now returns [u8; 32] instead of u64
///
/// # Arguments
/// * `nbits` - Compact difficulty (0xMMNNNNNN format)
///
/// # Returns
/// * Full 256-bit target as [u8; 32]
pub fn nbits_to_target(nbits: u32) -> [u8; 32] {
    difficulty::nbits_to_target(nbits)
}

// ============================================================================
// Hash-Sorting Integration (Post-PoW)
// ============================================================================

/// Verify hash-sorting assignment for a shard block
///
/// Hash-sorting is applied AFTER PoW verification to determine which
/// shard(s) a valid proof-of-work is eligible for.
///
/// # Process
/// 1. PoW verified: hash < target (independent of sharding)
/// 2. Extract sorting bits: last k bits of hash
/// 3. Determine shard: shard_id = (sorting_bits - 1)
/// 4. Validate block is assigned to correct shard
///
/// # Arguments
/// * `pow_hash` - The validated proof-of-work hash
/// * `claimed_shard_id` - Shard ID claimed by the block
/// * `k` - Hash-sorting bits parameter
///
/// # Returns
/// * `Ok(actual_shard_id)` if hash-sorting is valid
/// * `Err(ValidationError)` if hash is reserved or wrong shard
pub fn verify_hash_sorting_assignment(
    pow_hash: &[u8; 32],
    claimed_shard_id: u16,
    k: u32,
) -> Result<u16, ValidationError> {
    use crate::common::hash_sorting::extract_sorting_bits;
    
    // Extract last k bits from hash
    let sorting_bits = extract_sorting_bits(pow_hash, k);
    
    debug!(
        "Hash-sorting: hash={}, k={}, sorting_bits={}",
        hex::encode(pow_hash),
        k,
        sorting_bits
    );
    
    // Check for reserved value (all zeros)
    // sorting_bits == 0 is the beacon chain's reserved slot; a shard block
    // carrying this hash would allow cross-chain PoW reuse.
    if sorting_bits == 0 {
        return Err(ValidationError::CustomError(
            "Hash sorting bits are 0 — reserved for the beacon chain, not valid for a shard block".to_string()
        ));
    }
    
    // Determine actual shard from hash
    let actual_shard_id = (sorting_bits - 1) as u16;
    
    // Verify claimed shard matches actual
    if claimed_shard_id != actual_shard_id {
        return Err(ValidationError::CustomError(format!(
            "Hash-sorting mismatch: hash assigns to shard {}, block claims shard {}",
            actual_shard_id,
            claimed_shard_id
        )));
    }
    
    debug!(
        "Hash-sorting verified: shard_id={} (sorting_bits={})",
        actual_shard_id,
        sorting_bits
    );
    
    Ok(actual_shard_id)
}

/// Complete validation for a shard block (PoW + Hash-Sorting)
///
/// This is the complete validation pipeline for shard blocks:
/// 1. Verify PoW meets difficulty target (independent of sharding)
/// 2. Verify hash-sorting assigns to correct shard (post-PoW filtering)
/// 3. Verify beacon header commitment
///
/// # Arguments
/// * `block` - Shard block to validate
/// * `k` - Hash-sorting bits parameter
///
/// # Returns
/// * `Ok(())` if all validations pass
/// * `Err(ValidationError)` with specific error
pub fn verify_shard_block_pow_and_sorting(
    block: &crate::common::blocks::shard_block::Block,
    k: u32,
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    // Step 1: Beacon-style PoW against the **shard** work field (compact rBits).
    // Preimage = embedded aux `beacon_header` mining layout.
    // Target = rbits_to_target(FullShardHeader.difficulty, initial_target, asserted_s).
    let beacon_header = &block.header.beacon_header;

    validate_rbits_reasonableness(block.header.difficulty)?;

    let pow_hash = beacon_header.hash();
    let asserted_s = resolve_shard_asserted_s(
        beacon_header.committed_chain_count,
        genesis_asserted_s_bits,
    )?;
    validate_shard_rbits_floor(block.header.difficulty, asserted_s)?;
    let target = crate::common::crypto::weighted_hash::rbits_to_target(
        block.header.difficulty,
        initial_target,
        asserted_s,
    );

    if !difficulty::hash_meets_target(&pow_hash, &target) {
        return Err(ValidationError::InsufficientProofOfWork {
            hash: pow_hash,
            target,
        });
    }

    debug!(
        "Shard block PoW verified (shard_rbits=0x{:08x}, asserted_s={})",
        block.header.difficulty, asserted_s
    );

    // Step 2: Verify hash-sorting assignment (use asserted s when available)
    let sorting_k = if beacon_header.committed_chain_count != 0 {
        asserted_s
    } else {
        k
    };
    verify_hash_sorting_assignment(&pow_hash, block.header.shard_id, sorting_k)?;

    debug!("Shard block hash-sorting verified");

    // Step 3 (Merkle inclusion) lives in `verify_shard_id_and_mmn`, which
    // also runs this same shard-target PoW check before walking siblings.
    Ok(())
}

// ============================================================================
// Difficulty Reporting Functions
// ============================================================================

/// Get base network difficulty (pool mining, any shard)
///
/// This is the difficulty of finding a hash that meets the PoW target,
/// regardless of which shard it ends up on.
///
/// # Arguments
/// * `target` - Full 256-bit target
///
/// # Returns
/// * Base difficulty (k=0)
pub fn get_base_difficulty(target: &[u8; 32]) -> u128 {
    use crate::common::crypto::nbits_conversion::calculate_difficulty_from_target;
    calculate_difficulty_from_target(target, 0)
}

/// Get shard-specific difficulty (solo mining for specific shard)
///
/// This is the difficulty of finding a hash that:
/// 1. Meets the PoW target
/// 2. Has correct k bits for the target shard
///
/// This is 2^k times harder than base difficulty.
///
/// # Arguments
/// * `target` - Full 256-bit target
/// * `k` - Hash-sorting bits parameter
///
/// # Returns
/// * Shard-specific difficulty (accounting for hash-sorting)
pub fn get_shard_difficulty(target: &[u8; 32], k: u32) -> u128 {
    use crate::common::crypto::nbits_conversion::calculate_difficulty_from_target;
    calculate_difficulty_from_target(target, k)
}

/// Get difficulty multiplier from hash-sorting
///
/// Returns 2^k, the factor by which solo mining for a specific shard
/// is harder than pool mining.
///
/// # Arguments
/// * `k` - Hash-sorting bits parameter
///
/// # Returns
/// * Difficulty multiplier (2^k)
///
/// # Examples
/// ```rust,ignore
/// assert_eq!(get_hash_sorting_multiplier(0), 1);   // No hash-sorting
/// assert_eq!(get_hash_sorting_multiplier(4), 16);  // k=4 (15 shards)
/// assert_eq!(get_hash_sorting_multiplier(8), 256); // k=8 (255 shards)
/// ```
pub fn get_hash_sorting_multiplier(k: u32) -> u128 {
    if k >= 128 {
        return u128::MAX;
    }
    1u128 << k
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::crypto::weighted_hash::WeightedHash;

    /// NC-137: a chain count above the protocol maximum is rejected, not a
    /// panic (it used to trip `compute_required_s_bits`'s `s <= 15` assert).
    #[test]
    fn nc137_chain_count_above_maximum_is_rejected() {
        use crate::common::expand_voting::MAX_COMMITTED_CHAIN_COUNT;
        let over = MAX_COMMITTED_CHAIN_COUNT + 1;
        let expected = ValidationError::ChainCountAboveMaximum { count: over, max: MAX_COMMITTED_CHAIN_COUNT };
        assert_eq!(resolve_beacon_asserted_s(over, 2), Err(expected.clone()));
        assert_eq!(resolve_shard_asserted_s(over, 2), Err(expected.clone()));
        assert_eq!(resolve_beacon_asserted_s(u16::MAX, 2).is_err(), true);
        assert_eq!(resolve_beacon_asserted_s(MAX_COMMITTED_CHAIN_COUNT, 2), Ok(15));

        // A header claiming it: the PoW check returns the error.
        let mut header = BeaconBlockCandidateHeader::new(
            1, 1_704_067_200, 1, 0x0300_0001, WeightedHash::zero(), [0; 32], [0; 32], 1_704_067_200,
        );
        header.committed_chain_count = over;
        assert_eq!(verify_beacon_header_pow(&header, &[0xFF; 32], 1, 2), Err(expected));
    }
    
    #[test]
    fn test_hash_meets_target_basic() {
        // Easy target (large value)
        let easy_target = [
            0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        
        // Hash with leading zeros (should pass)
        let easy_hash = [
            0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        assert!(hash_meets_target(&easy_hash, &easy_target));
        
        // Hard target (small value)
        let hard_target = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        assert!(!hash_meets_target(&easy_hash, &hard_target));
    }
    
    #[test]
    fn test_nbits_expansion() {
        // Bitcoin genesis difficulty
        let target = nbits_to_target(0x1d00ffff);
        
        // Should be: 0x00000000ffff0000...0000
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x00);
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        assert_eq!(target[6], 0x00);
    }
    
    #[test]
    fn test_difficulty_relationship() {
        let target = nbits_to_target(0x1d00ffff);
        
        // Base difficulty (pool mining)
        let diff_base = get_base_difficulty(&target);
        
        // Shard difficulty with k=4
        let diff_shard = get_shard_difficulty(&target, 4);
        
        // Multiplier should be 16 (2^4)
        let multiplier = get_hash_sorting_multiplier(4);
        assert_eq!(multiplier, 16);
        
        // Shard difficulty should be base × multiplier
        // Use division to avoid overflow
        let ratio = diff_shard / diff_base;
        assert!(ratio >= 15, "Expected ratio >= 15, got {}", ratio);  // Allow rounding
        assert!(ratio <= 17, "Expected ratio <= 17, got {}", ratio);
    }
    
    #[test]
    fn test_hash_sorting_reserved() {
        // Hash with FIRST 4 bits = 0000 (reserved)
        // extract_sorting_bits reads from the beginning of the hash
        let hash = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        let result = verify_hash_sorting_assignment(&hash, 0, 4);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_hash_sorting_valid() {
        // Hash with LAST 4 bits = 0001 (shard 0). NC-5 fix: `extract_sorting_bits`
        // (CV-79, Jul 8 2026) reads from the END of the hash, not the start —
        // this fixture predates that fix and was never caught because this
        // crate's test binary didn't compile until NC-5 was fixed (see
        // docs/plan/Correctness_and_Validation_Plan.md).
        let hash = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let result = verify_hash_sorting_assignment(&hash, 0, 4);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        assert_eq!(result.unwrap(), 0);
    }

    /// Assignment accept/reject under asserted s from count (§5.7 Milestone C).
    #[test]
    fn hash_sorting_assignment_accept_reject_with_asserted_s() {
        // sorting_bits = 1 → shard 0; asserted_s for count=4 is 3.
        let hash_ok = hash_with_last_k_bits(3, 1);
        let asserted_s = resolve_beacon_asserted_s(4, 2).unwrap();
        assert_eq!(asserted_s, 3);
        assert_eq!(
            verify_hash_sorting_assignment(&hash_ok, 0, asserted_s).unwrap(),
            0
        );
        // Wrong claimed shard
        assert!(verify_hash_sorting_assignment(&hash_ok, 5, asserted_s).is_err());
        // Beacon-reserved slot (sorting_bits == 0) rejected for shards
        let hash_beacon = hash_with_last_k_bits(3, 0);
        assert!(verify_hash_sorting_assignment(&hash_beacon, 0, asserted_s).is_err());
    }
    
    #[test]
    fn test_hash_sorting_wrong_shard() {
        // Hash with FIRST 4 bits = 0001 (shard 0)
        // extract_sorting_bits reads from the beginning of the hash
        let hash = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Claim shard 5 (wrong!)
        let result = verify_hash_sorting_assignment(&hash, 5, 4);
        assert!(result.is_err());
    }

    // ── CV-05: validate_nbits_reasonableness ─────────────────────────────────

    /// NB-01: nbits == 0 is rejected.
    #[test]
    fn nb_01_zero_nbits_rejected() {
        let err = validate_nbits_reasonableness(0).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidNBits { nbits: 0, .. }),
            "Expected InvalidNBits(0), got {:?}",
            err
        );
    }

    /// NB-02: Zero mantissa (non-zero exponent) is rejected.
    #[test]
    fn nb_02_zero_mantissa_rejected() {
        // exponent = 0x1d, mantissa = 0x000000
        let nbits = 0x1d00_0000u32;
        let err = validate_nbits_reasonableness(nbits).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidNBits { nbits: 0x1d00_0000, .. }),
            "Expected InvalidNBits, got {:?}",
            err
        );
    }

    /// NB-03: Negative-target flag (bit 23 of mantissa set) is rejected.
    #[test]
    fn nb_03_negative_target_flag_rejected() {
        // exponent = 0x1d, mantissa = 0x80ffff → bit 23 set
        let nbits = 0x1d80_ffffu32;
        let err = validate_nbits_reasonableness(nbits).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidNBits { nbits: 0x1d80_ffff, .. }),
            "Expected InvalidNBits, got {:?}",
            err
        );
    }

    /// NB-04: Overflow exponent (exponent byte > 32 == 0x20) is rejected.
    #[test]
    fn nb_04_overflow_exponent_rejected() {
        // exponent = 0x21 (33 > 32), mantissa = 0x00ffff
        let nbits = 0x2100_ffffu32;
        let err = validate_nbits_reasonableness(nbits).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidNBits { nbits: 0x2100_ffff, .. }),
            "Expected InvalidNBits, got {:?}",
            err
        );
    }

    /// NB-05: A valid, well-formed nBits (Bitcoin genesis) passes.
    #[test]
    fn nb_05_valid_nbits_accepted() {
        // 0x1d00ffff — Bitcoin genesis difficulty (exponent=29, mantissa=0x00ffff)
        assert!(
            validate_nbits_reasonableness(0x1d00_ffff).is_ok(),
            "Bitcoin-genesis nBits 0x1d00ffff should be accepted"
        );
    }

    /// NB-06: Maximum valid exponent (0x20 == 32) with positive mantissa is accepted.
    #[test]
    fn nb_06_max_exponent_accepted() {
        // exponent = 0x20, mantissa = 0x007fff (bit 23 clear → positive)
        // Produces the largest representable target without the negative flag.
        let nbits = 0x2000_7fffu32;
        assert!(
            validate_nbits_reasonableness(nbits).is_ok(),
            "nBits 0x2000_7fff with exponent 0x20 and positive mantissa should be accepted"
        );
    }

    /// NB-07: The error Display includes the hex value and reason.
    #[test]
    fn nb_07_error_display_includes_hex_and_reason() {
        let err = validate_nbits_reasonableness(0).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("0x00000000"),
            "Display should include hex nbits: {}", msg
        );
        assert!(
            msg.contains("zero") || msg.contains("impossible"),
            "Display should mention zero/impossible: {}", msg
        );
    }

    // ── CV-60: verify_beacon_hash_sorting ────────────────────────────────────

    fn zero_hash() -> [u8; 32] { [0u8; 32] }

    fn hash_with_last_k_bits(k: u32, value: u32) -> [u8; 32] {
        // Sets the LAST (k+7)/8 bytes so that extract_sorting_bits returns
        // `value`. NC-5 fix: `extract_sorting_bits` (CV-79, Jul 8 2026) reads
        // from `hash_bytes[len-1-i]` (the end of the hash), not the start —
        // this helper wrote to `h[0..bytes_needed]` (matching the pre-CV-79,
        // buggy extraction) and was never caught because this crate's test
        // binary didn't compile until NC-5 was fixed (see
        // docs/plan/Correctness_and_Validation_Plan.md).
        let mut h = [0u8; 32];
        let bytes_needed = ((k + 7) / 8) as usize;
        let masked = value & ((1u32 << k) - 1);
        for i in 0..bytes_needed {
            h[31 - i] = (masked >> (i * 8)) as u8;
        }
        h
    }

    /// BHS-1: sorting_bits == 0 is accepted (beacon reserved slot).
    #[test]
    fn bhs_01_zero_sorting_bits_accepted() {
        let hash = zero_hash(); // all zeros → sorting_bits == 0 for any k
        assert!(
            verify_beacon_hash_sorting(&hash, 4).is_ok(),
            "All-zero hash should be accepted for the beacon slot"
        );
    }

    /// BHS-2: sorting_bits == 1 is rejected (shard 0 slot).
    #[test]
    fn bhs_02_shard_zero_slot_rejected() {
        let hash = hash_with_last_k_bits(4, 1);
        let err = verify_beacon_hash_sorting(&hash, 4).unwrap_err();
        assert!(
            matches!(err, ValidationError::BeaconHashSortingViolation { sorting_bits: 1, k: 4 }),
            "sorting_bits=1 should be rejected: {:?}", err
        );
    }

    /// BHS-3: sorting_bits == 0b1111 (15, the last shard for k=4) is rejected.
    #[test]
    fn bhs_03_last_shard_slot_rejected() {
        let hash = hash_with_last_k_bits(4, 0b1111);
        let err = verify_beacon_hash_sorting(&hash, 4).unwrap_err();
        assert!(
            matches!(err, ValidationError::BeaconHashSortingViolation { sorting_bits: 15, k: 4 }),
            "sorting_bits=15 should be rejected: {:?}", err
        );
    }

    /// BHS-4: Error message mentions the sorting_bits value and k.
    #[test]
    fn bhs_04_error_display_mentions_bits_and_k() {
        let hash = hash_with_last_k_bits(4, 3);
        let err = verify_beacon_hash_sorting(&hash, 4).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("3"), "Display should mention sorting_bits=3: {}", msg);
        assert!(msg.contains("4") || msg.contains("beacon"), "Display should mention k or beacon: {}", msg);
    }

    // ── §5.7: asserted_s from committed_chain_count ─────────────────────────

    #[test]
    fn resolve_beacon_asserted_s_matches_helper_for_nonzero_count() {
        use crate::common::expand_voting::s_bits_for_chain_count;
        // count > 0: pure count→s mapping, genesis_asserted_s_bits irrelevant.
        for count in [1u16, 4, 5, 14, 15] {
            assert_eq!(
                resolve_beacon_asserted_s(count, 2).unwrap(),
                s_bits_for_chain_count(count) as u32,
                "count={count}"
            );
        }
        // count == 0 (genesis only): returns genesis.asserted_s_bits, NOT
        // s_bits_for_chain_count(0) = 1. This is the NC-104 fix.
        assert_eq!(resolve_beacon_asserted_s(0, 5).unwrap(), 5);
        assert_eq!(resolve_beacon_asserted_s(0, 2).unwrap(), 2);
        assert_ne!(resolve_beacon_asserted_s(0, 5).unwrap(), s_bits_for_chain_count(0) as u32);
    }

    /// Beacon slot check uses asserted s from committed count, not a fixed DEFAULT.
    /// A hash with last-4-bits non-zero but last-3-bits zero fails under s=4 and
    /// passes under s=3 (= s_bits_for_chain_count(4)).
    #[test]
    fn beacon_hash_sorting_uses_asserted_s_width() {
        // Last 4 bits = 0b1000 = 8 → fails k=4, passes k=3 (last 3 bits = 0).
        let hash = hash_with_last_k_bits(4, 0b1000);
        assert!(
            verify_beacon_hash_sorting(&hash, 4).is_err(),
            "must fail under asserted_s=4"
        );
        assert!(
            verify_beacon_hash_sorting(&hash, 3).is_ok(),
            "must pass under asserted_s=3 (count=4 → s_bits_for_chain_count)"
        );
        assert_eq!(resolve_beacon_asserted_s(4, 2).unwrap(), 3);
    }

    /// Shard floor: D ≥ 2^asserted_s (no cal×). Under-floor rBits rejected;
    /// clamp raises to exact floor.
    #[test]
    fn shard_rbits_floor_rejects_and_clamps() {
        use crate::common::crypto::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};
        let asserted_s = 2u32;
        let floor = 1u128 << asserted_s; // 4
        let under = u128_to_rbits(floor - 1);
        assert!(
            validate_shard_rbits_floor(under, asserted_s).is_err(),
            "D=3 must fail floor 2^2=4"
        );
        let at = u128_to_rbits(floor);
        assert!(validate_shard_rbits_floor(at, asserted_s).is_ok());
        let clamped = apply_shard_retarget_floor(under, asserted_s);
        assert_eq!(rbits_to_u128_approx(clamped), floor);
        // Already above floor: unchanged.
        let above = u128_to_rbits(floor * 2);
        assert_eq!(apply_shard_retarget_floor(above, asserted_s), above);
    }

    // ── CV-05: validate_nbits_against_max_target ─────────────────────────────

    /// NMT-1: A target strictly below max_target is accepted.
    #[test]
    fn nmt_01_target_within_max_accepted() {
        // max_target: 0x00000000ffff0000...0000 (Bitcoin genesis)
        let max_target = nbits_to_target(0x1d00_ffff);
        // nbits with a much harder target (smaller): exponent 0x18, mantissa 0x00ffff
        let nbits_harder = 0x1800_ffffu32;
        assert!(
            validate_nbits_against_max_target(nbits_harder, &max_target).is_ok(),
            "Target strictly below max_target should be accepted"
        );
    }

    /// NMT-2: A target exactly equal to max_target is accepted.
    #[test]
    fn nmt_02_target_equal_to_max_accepted() {
        let max_target = nbits_to_target(0x1d00_ffff);
        // Same nbits → same target
        assert!(
            validate_nbits_against_max_target(0x1d00_ffff, &max_target).is_ok(),
            "Target exactly equal to max_target should be accepted"
        );
    }

    /// NMT-3: A target strictly above max_target is rejected.
    #[test]
    fn nmt_03_target_exceeding_max_rejected() {
        // max_target: Bitcoin genesis difficulty
        let max_target = nbits_to_target(0x1d00_ffff);
        // An easier target: exponent 0x1e → larger expansion → easier mining
        let nbits_easier = 0x1e00_ffffu32;
        let err = validate_nbits_against_max_target(nbits_easier, &max_target).unwrap_err();
        assert!(
            matches!(err, ValidationError::NbitsExceedsMaxTarget { nbits, .. } if nbits == nbits_easier),
            "Expected NbitsExceedsMaxTarget, got {:?}", err
        );
    }

    /// NMT-4: Error display includes nbits hex and both target hex strings.
    #[test]
    fn nmt_04_error_display_includes_targets() {
        let max_target = nbits_to_target(0x1d00_ffff);
        let nbits_easier = 0x1e00_ffffu32;
        let err = validate_nbits_against_max_target(nbits_easier, &max_target).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("1e00ffff"), "Display should include nbits hex: {}", msg);
    }
}