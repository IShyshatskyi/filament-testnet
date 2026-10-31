// src/common/validation/k_coeff.rs
//
// CV-15/CV-16/CV-19 — k-Coefficient Validation and Reward Rules
//
// # Three-parameter taxonomy
//
// | # | Name              | Wire size | Location                                    | Purpose |
// |---|-------------------|-----------|---------------------------------------------|---------|
// | 1 | Shard chain count | 2 bytes   | merged-mining Merkle header                 | Active shards claimed by a block composer. |
// | 2 | **k-coefficient** | 4 bytes   | `EpochKState` / `ShardParameters.k_active_kbits` (chain state only) | Per-epoch economic multiplier. **Not in block header** — see Path A decision Jun 24, 2026. |
// | 3 | w_bits            | 4 bytes   | `WeightedHash` rBits                        | Chain-weight scaling exponent (constant `BLOCK_HASH_W_BITS = 4`). |
//
// This file implements **parameter #2 only**.
//
// # KBits compact encoding
//
// k is stored exclusively as a 4-byte KBits u32:
//   kBits = (size_byte << 24) | mantissa_24bit
//   k_encoded = round(k × 2^48)      (mainnet: k ∈ (0, 1]; testnets may start higher)
//
// See `src/common/crypto/k_bits.rs` for `encode_kbits_u128`/`decode_kbits_u128`.
//
// # Path A decision (Jun 24, 2026)
//
// k is NOT committed in individual block headers. It is derived from chain
// state (`EpochKState`) at epoch boundaries and propagated to shard chains
// via `ShardParameters`. Rules K-3 (intra-epoch constancy) and K-4
// (epoch-boundary adjustment) are enforced by the chain state machine, not
// per-block header validation functions.
//
// # Rules implemented
//
// | Rule | Description                                     | Status |
// |------|-------------------------------------------------|--------|
// | K-1  | compact k: zero / sentinel rejection            | ✅ `validate_compact_k_sanity` |
// | K-2  | KBits bounds: k ∈ [k_min_kbits, k_initial]     | ✅ `validate_k_kbits_bounds` |
// | K-3  | Intra-epoch constancy                           | ✅ enforced by chain state (`k_active_kbits()`) — no per-block header field (Path A) |
// | K-4  | Epoch-boundary adjustment correctness           | ✅ `finalise_epoch` in `epoch_k_state.rs` |
// | K-5  | Adjustment magnitude cap                        | ✅ `slow_decline_num/den` + `fast_decline_num/den` in `KVotingConfig` (both < 1; k never rises) |
// | K-6  | Shard coinbase reward formula                   | ✅ `calculate_shard_reward` (§7.5 integer formula) |
// | K-8  | Genesis k matches `k_initial_kbits`             | ✅ `validate_genesis_k_kbits` |
// | K-9  | EpochKState structure                           | ✅ `epoch_k_state.rs` |
// | K-10 | k consistency through reorg                     | ✅ `k_history: Vec<EpochKState>` on `BeaconChain` |

use super::errors::ValidationError;
use crate::common::crypto::k_bits::{decode_kbits_u128, ONE_KBITS};

// EPOCH_LENGTH is the canonical 4096-block beacon epoch from expand_voting.
pub use crate::common::expand_voting::EPOCH_LENGTH;

// ── Constants ────────────────────────────────────────────────────────────────

/// Fixed-point shift used in the KBits representation.
///
/// `k_encoded = round(k_float × 2^K_FIXED_SHIFT)` where K_FIXED_SHIFT = 48.
pub const K_FIXED_SHIFT: u32 = 48;

/// `2^K_FIXED_SHIFT` — multiply a floating-point k by this to get `k_encoded`.
pub const K_FIXED_ONE: u64 = 1u64 << K_FIXED_SHIFT; // = 2^48

// ── K-1: Compact k sanity ─────────────────────────────────────────────────

/// CV-15 K-1: Reject obviously malformed KBits values.
///
/// Checks:
/// - `compact_k == 0` — decodes to zero (zero reward multiplier)
/// - `compact_k == u32::MAX` — reserved sentinel
///
/// Full encoding/decoding is provided by `decode_kbits` in `k_bits.rs`.
pub fn validate_compact_k_sanity(compact_k: u32) -> Result<(), ValidationError> {
    if compact_k == 0 {
        return Err(ValidationError::InvalidKCoeff {
            compact_k,
            reason: "compact k is zero — decodes to zero reward multiplier",
        });
    }
    if compact_k == u32::MAX {
        return Err(ValidationError::InvalidKCoeff {
            compact_k,
            reason: "compact k is 0xFFFFFFFF — reserved sentinel value",
        });
    }
    Ok(())
}

// ── K-2: KBits bounds check ──────────────────────────────────────────────

/// CV-16 K-2: Verify that a KBits value decodes within the operational range.
///
/// Both bounds are KBits compact values; comparison is done in decoded form
/// (`k_encoded`, u64) to avoid any encoding artefacts.
///
/// The upper bound is the network's genesis `k_initial_kbits` (k never rises
/// above genesis). The lower bound comes from `KVotingConfig.k_min_kbits` —
/// a structural floor (the KBits format's representable minimum), NOT an
/// economic floor. See K_VOTING_DESIGN_v4.md §0.2.
///
/// # Arguments
///
/// * `compact_k`       — KBits value to validate.
/// * `k_min_kbits`     — Minimum KBits from `KVotingConfig` (structural floor).
/// * `k_max_kbits`     — Ceiling KBits (`KVotingConfig.k_initial_kbits`).
pub fn validate_k_kbits_bounds(
    compact_k: u32,
    k_min_kbits: u32,
    k_max_kbits: u32,
) -> Result<(), ValidationError> {
    let k_enc     = decode_kbits_u128(compact_k);
    let k_min_enc = decode_kbits_u128(k_min_kbits);
    let k_max_enc = decode_kbits_u128(k_max_kbits);

    if k_enc == 0 || k_min_enc == 0 || k_max_enc == 0 || k_enc < k_min_enc || k_enc > k_max_enc {
        return Err(ValidationError::InvalidKCoeff {
            compact_k,
            reason: "k_encoded is outside [k_min_kbits, k_initial_kbits]",
        });
    }
    Ok(())
}

// ── K-6: Shard block reward calculation ─────────────────────────────────

/// CV-19 K-6: Compute the shard block coinbase reward using pure integer
/// arithmetic (§7.5 of K_VOTING_DESIGN_v4.md).
///
/// # Formula
///
/// ```text
/// shard_reward = (k_encoded × shard_difficulty) / (2^48 × merged_mining_number)
/// ```
///
/// where:
/// - `k_encoded = decode_kbits_u128(k_active_kbits)` — fixed-point k (× 2^48)
/// - `shard_difficulty` — expected SHA256d evaluations for this shard's target
/// - `merged_mining_number` — number of shard chains this PoW is eligible for
///
/// All arithmetic is u128 to prevent overflow; the final value is floored.
/// Returns `Err` if `merged_mining_number == 0`.
///
/// For k = 1.0 and merged_mining_number = 1: reward = shard_difficulty.
/// For k = 2^16 (testnet-stress) and mmn = 1: reward = shard_difficulty × 2^16.
pub fn calculate_shard_reward(
    k_active_kbits:       u32,
    shard_difficulty:     u64,
    merged_mining_number: u32,
) -> Result<u64, String> {
    if merged_mining_number == 0 {
        return Err("merged_mining_number must be > 0".into());
    }
    let k_encoded   = decode_kbits_u128(k_active_kbits);
    let numerator   = k_encoded.saturating_mul(shard_difficulty as u128);
    let denominator = (1u128 << K_FIXED_SHIFT).saturating_mul(merged_mining_number as u128);
    Ok((numerator / denominator) as u64)
}

/// K-6: verify a block's coinbase value does not exceed the k-scaled reward
/// cap plus fees (plus, for shard genesis only, a one-time premine
/// allowance).
///
/// Pure function over already-resolved inputs — deliberately has **no**
/// coupling to `ForkUtxoOverlay`, `PositionalUtxoDb`, `ShardEpochCache`, or any other
/// backend-specific type. Every caller (mining-pool `ShardChain`, Keystone
/// `FullShardChain`) resolves `k_active_kbits`/`merged_mining_number`/`fees`
/// from its own epoch-cache/UTXO-backend — which legitimately differ between
/// the two node types — and passes plain values here, so the one thing that
/// must never drift between them (the actual cap arithmetic) lives in
/// exactly one place. Moved here from mining-pool-local
/// `validate_block_k6_coinbase` (Jul 2026), the same session that found and
/// fixed several other "two independent copies of the same formula silently
/// diverged" bugs (see `docs/plan/Correctness_and_Validation_Plan.md` CV-91
/// and the Target-3 `chain_weight` hash-preimage history) — Keystone
/// previously had no K-6 check at all, in part because there was no shared
/// place to put the cap math without dragging along a mining-pool-only type.
pub fn validate_k6_coinbase_cap(
    k_active_kbits: u32,
    shard_difficulty: u64,
    merged_mining_number: u32,
    fees: u64,
    premine_allowance: u64,
    actual_coinbase: u64,
) -> Result<(), String> {
    let base_reward = calculate_shard_reward(k_active_kbits, shard_difficulty, merged_mining_number)?;
    let max_coinbase = base_reward
        .checked_add(fees)
        .and_then(|v| v.checked_add(premine_allowance))
        .ok_or_else(|| "K-6: coinbase cap overflow".to_string())?;
    if actual_coinbase > max_coinbase {
        return Err(format!(
            "K-6: coinbase value {} exceeds max {} (base={}, fees={}, premine={}, k=0x{:08x}, mmn={})",
            actual_coinbase, max_coinbase, base_reward, fees, premine_allowance,
            k_active_kbits, merged_mining_number,
        ));
    }
    Ok(())
}

// ── K-8: Genesis k-coefficient ─────────────────────────────────────────

/// CV-15 K-8: Verify that the genesis chain state k matches `k_initial_kbits`.
///
/// Compares decoded `k_encoded` values to avoid sensitivity to KBits mantissa
/// rounding differences in config serialisation.
///
/// # Arguments
///
/// * `genesis_kbits`  — KBits from the genesis `EpochKState`.
/// * `expected_kbits` — `KVotingConfig.k_initial_kbits`.
pub fn validate_genesis_k_kbits(
    genesis_kbits: u32,
    expected_kbits: u32,
) -> Result<(), ValidationError> {
    if decode_kbits_u128(genesis_kbits) != decode_kbits_u128(expected_kbits) {
        return Err(ValidationError::InvalidKCoeff {
            compact_k: genesis_kbits,
            reason: "genesis k_active_kbits does not match k_initial_kbits in genesis config",
        });
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::k_bits::{float_to_kbits, MIN_KBITS};

    // ── K-1: compact k sanity ─────────────────────────────────────────────

    #[test]
    fn k1_zero_compact_k_rejected() {
        let err = validate_compact_k_sanity(0).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { compact_k: 0, .. }));
    }

    #[test]
    fn k1_sentinel_compact_k_rejected() {
        let err = validate_compact_k_sanity(u32::MAX).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { compact_k: 0xFFFF_FFFF, .. }));
    }

    #[test]
    fn k1_normal_value_accepted() {
        assert!(validate_compact_k_sanity(0x0001_0000).is_ok());
        assert!(validate_compact_k_sanity(ONE_KBITS).is_ok());
        assert!(validate_compact_k_sanity(MIN_KBITS).is_ok());
    }

    // ── K-2: KBits bounds ─────────────────────────────────────────────────

    #[test]
    fn k2_one_passes_with_min_floor() {
        assert!(validate_k_kbits_bounds(ONE_KBITS, MIN_KBITS, ONE_KBITS).is_ok());
    }

    #[test]
    fn k2_min_kbits_passes() {
        assert!(validate_k_kbits_bounds(MIN_KBITS, MIN_KBITS, ONE_KBITS).is_ok());
    }

    #[test]
    fn k2_zero_kbits_rejected() {
        let err = validate_k_kbits_bounds(0, MIN_KBITS, ONE_KBITS).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { .. }));
    }

    #[test]
    fn k2_below_min_rejected() {
        // k_half < ONE_KBITS used as a high min to force rejection
        let k_half = float_to_kbits(0.5);
        let err = validate_k_kbits_bounds(k_half, ONE_KBITS, ONE_KBITS).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { .. }));
    }

    #[test]
    fn k2_above_initial_rejected() {
        use crate::common::crypto::k_bits::K_TIMES_2_POW_16_KBITS;
        let err = validate_k_kbits_bounds(K_TIMES_2_POW_16_KBITS, MIN_KBITS, ONE_KBITS).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { .. }));
    }

    #[test]
    fn k2_times_2_pow_16_ok_when_initial() {
        use crate::common::crypto::k_bits::K_TIMES_2_POW_16_KBITS;
        assert!(validate_k_kbits_bounds(
            K_TIMES_2_POW_16_KBITS,
            MIN_KBITS,
            K_TIMES_2_POW_16_KBITS
        )
        .is_ok());
    }

    #[test]
    fn k6_times_2_pow_16_scales_reward() {
        use crate::common::crypto::k_bits::K_TIMES_2_POW_16_KBITS;
        let reward = calculate_shard_reward(K_TIMES_2_POW_16_KBITS, 16, 15).unwrap();
        // At floor-ish D_shard=16, MMN=15, k=2^16 → (2^64 * 16) / (2^48 * 15) = 2^16 * 16 / 15
        assert_eq!(reward, (65536u64 * 16) / 15);
    }

    // ── K-6: calculate_shard_reward ───────────────────────────────────────

    #[test]
    fn k6_k_one_merged_one_equals_difficulty() {
        let reward = calculate_shard_reward(ONE_KBITS, 1_000_000, 1).unwrap();
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn k6_k_one_merged_two_halves_reward() {
        let reward = calculate_shard_reward(ONE_KBITS, 1_000_000, 2).unwrap();
        assert_eq!(reward, 500_000);
    }

    #[test]
    fn k6_k_half_merged_one() {
        let k_half = float_to_kbits(0.5);
        let reward = calculate_shard_reward(k_half, 1_000_000, 1).unwrap();
        let diff = (reward as i64 - 500_000_i64).abs();
        assert!(diff <= 1, "k=0.5, mm=1 → ~500_000, got {}", reward);
    }

    #[test]
    fn k6_zero_kbits_gives_zero() {
        let reward = calculate_shard_reward(0, 1_000_000, 1).unwrap();
        assert_eq!(reward, 0);
    }

    #[test]
    fn k6_merged_mining_zero_errors() {
        assert!(calculate_shard_reward(ONE_KBITS, 1_000_000, 0).is_err());
    }

    // ── K-8: genesis k ─────────────────────────────────────────────────────

    #[test]
    fn k8_matching_kbits_accepted() {
        assert!(validate_genesis_k_kbits(ONE_KBITS, ONE_KBITS).is_ok());
    }

    #[test]
    fn k8_mismatched_kbits_rejected() {
        let k_half = float_to_kbits(0.5);
        let err = validate_genesis_k_kbits(k_half, ONE_KBITS).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { .. }));
    }

    #[test]
    fn k8_zero_genesis_rejected() {
        let err = validate_genesis_k_kbits(0, ONE_KBITS).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidKCoeff { .. }));
    }

    // ── EPOCH_LENGTH ───────────────────────────────────────────────────────

    #[test]
    fn epoch_length_is_4096() {
        assert_eq!(EPOCH_LENGTH, 4096u32);
    }
}
