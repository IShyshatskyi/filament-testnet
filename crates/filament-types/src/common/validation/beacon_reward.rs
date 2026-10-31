// src/common/validation/beacon_reward.rs
//
// CV-26 / CV-27 — Beacon Chain Reward Validation Rules
//
// Beacon chain block rewards are governed by the canonical emission schedule
// defined in `src/common/emission_schedule.rs`.  This file implements the
// *validation* layer on top of that schedule: structural checks on the coinbase
// transaction, value-cap enforcement, and premine verification.
//
// # Emission schedule (mainnet)
//
//   Premine  : 21 000 000 coins, genesis block only
//   Subsidy  : 1 coin per block at every height ≥ 1 ("tail inflation", no halving)
//   1 coin   = 100 000 000 atomic units
//
// See `crate::common::emission_schedule` for the canonical constants.
//
// # Rules implemented
//
// | Rule  | Description                                             | Status |
// |-------|----------------------------------------------------------|--------|
// | BR-2  | Beacon block reward schedule — `beacon_block_reward()`  | ✅     |
// | BR-3  | Coinbase structural invariants (zero inputs, first pos) | ✅     |
// | BR-5  | No premine disbursement outside the genesis block       | ✅ (via BR-2 cap) |
// | BR-1  | Genesis premine: total equality + output count check    | ✅ partial |
// | BR-4  | Reward separation from k-coefficient                    | ✅ (by construction) |
//
// # Spec gaps / deferred
//
// - **BR-1 per-output pubkey check:** `PremineOutput::address` is still a
//   human-readable string.  Once changed to `[u8; 32]`, extend
//   `validate_beacon_premine` to compare each output's `recipient` against the
//   corresponding pubkey in genesis config.  See CV-27.
//
// - **MIN_TRANSACTION_FEE:** flat per-tx floor, kept at 0 (unused) and
//   superseded by the size-proportional TX-12 / CV-28 check —
//   `check_min_fee` in `validation/transactions.rs`, wired into both
//   `validate_block_body` and `validate_transaction_for_mempool` via
//   `BlockBodyValidationParams`/`MempoolAdmissionParams::with_min_fee_per_4_bytes`
//   (off by default; rate constant pending governance sign-off).

use crate::common::emission_schedule;
use crate::transaction::Transaction;
use super::errors::ValidationError;

// ── Re-exports for callers that imported the old names from here ──────────────

pub use emission_schedule::{
    ATOMIC_UNITS_PER_COIN,
    PREMINE_ATOMS,
    TAIL_EMISSION_ATOMS,
    beacon_block_subsidy,
    max_coinbase_value,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Height of the genesis block.  Only the genesis coinbase may disburse the
/// premine (BR-1 / BR-5).
pub const GENESIS_BLOCK_HEIGHT: u32 = 0;

/// Flat minimum transaction fee per transaction in atomic units. Unused —
/// superseded by the size-proportional TX-12 / CV-28 check (see module
/// doc comment above). Kept at 0 for backward compatibility with any
/// existing callers of this constant.
pub const MIN_TRANSACTION_FEE: u64 = 0;

// ── BR-2: Beacon block reward schedule ───────────────────────────────────────

/// CV-26 BR-2: Compute the block subsidy (excluding fees) for a beacon block
/// at `height`.
///
/// Delegates entirely to [`emission_schedule::beacon_block_subsidy`].
/// Callers that previously used `beacon_block_reward(h, &config)` can migrate
/// to `beacon_block_subsidy(h)` directly — no config needed, the schedule is
/// compile-time constant.
///
/// The genesis block (height 0) returns 0 — it carries only the premine (BR-5).
/// Every block at height ≥ 1 returns exactly `TAIL_EMISSION_ATOMS` (1 coin).
#[inline]
pub fn beacon_block_reward(height: u32) -> u64 {
    emission_schedule::beacon_block_subsidy(height)
}

// ── BR-3: Coinbase structural invariants ─────────────────────────────────────

/// CV-27 BR-3: Validate the structural invariants of a beacon coinbase
/// transaction.
///
/// A beacon coinbase MUST satisfy all of the following, independent of the
/// reward amount:
///
/// 1. **Zero inputs** — creates coins from nothing; must not consume any UTXO.
/// 2. **At least one output** — must pay the reward somewhere.
/// 3. **Version 1** — beacon coinbase transactions use version 1.
/// 4. **No expiration** — `locktime == 0`; a coinbase that can expire is
///    semantically incoherent (coinbase maturity is handled separately).
///
/// The block-ordering invariant (coinbase must be the first transaction at
/// index 0) is enforced by the block-level validator, not here.
///
/// # Arguments
///
/// * `coinbase` — The transaction to validate.
pub fn validate_beacon_coinbase_structure(coinbase: &Transaction) -> Result<(), ValidationError> {
    // CB-1: no inputs
    if !coinbase.inputs.is_empty() {
        return Err(ValidationError::InvalidCoinbaseStructure {
            reason: format!(
                "beacon coinbase must have zero inputs, found {}",
                coinbase.inputs.len()
            ),
        });
    }

    // BR-3 rule 2: at least one output
    if coinbase.outputs.is_empty() {
        return Err(ValidationError::InvalidCoinbaseStructure {
            reason: "beacon coinbase must have at least one output".into(),
        });
    }

    // BR-3 rule 3: version must be 1
    if coinbase.version != 1 {
        return Err(ValidationError::InvalidCoinbaseStructure {
            reason: format!(
                "beacon coinbase version must be 1, got {}",
                coinbase.version
            ),
        });
    }

    // BR-3 rule 4: locktime == 0 (no expiration)
    if coinbase.locktime != 0 {
        return Err(ValidationError::InvalidCoinbaseStructure {
            reason: format!(
                "beacon coinbase locktime must be 0 (no expiration), got {}",
                coinbase.locktime
            ),
        });
    }

    Ok(())
}

// ── BR-2 / BR-5: Coinbase value cap ──────────────────────────────────────────

/// CV-26 BR-2 + BR-5: Verify that the coinbase total does not exceed the
/// scheduled reward plus accumulated transaction fees.
///
/// Enforces both:
///
/// - **BR-2:** `coinbase_total ≤ beacon_block_subsidy(height) + tx_fees`
/// - **BR-5:** No premine disbursement outside the genesis block.  At H > 0
///   the cap is `TAIL_EMISSION_ATOMS` from the emission schedule, never the
///   premine amount.
///
/// The caller is responsible for computing `tx_fees`; this function does not
/// perform UTXO lookups.
pub fn validate_beacon_coinbase_value(
    coinbase: &Transaction,
    height: u32,
    tx_fees: u64,
) -> Result<(), ValidationError> {
    let coinbase_total: u64 = coinbase.outputs.iter().map(|o| o.value).sum();
    let max_allowed = emission_schedule::max_coinbase_value(height, tx_fees);

    if coinbase_total > max_allowed {
        return Err(ValidationError::BeaconCoinbaseExceedsSchedule {
            height,
            coinbase_total,
            max_allowed,
        });
    }

    Ok(())
}

// ── BR-1: Premine validation ──────────────────────────────────────────────────

/// CV-27 BR-1 (partial): Validate the genesis coinbase against the configured
/// premine.
///
/// Performs the checks that do not require raw pubkey comparison:
///
/// 1. **Total equality:** `sum(outputs.value) == premine_amount`.  Hard equality
///    — under-delivery makes coins permanently inaccessible; over-delivery
///    inflates supply.
///
/// 2. **Output count:** `outputs.len() == premine_outputs.len()`.  Ensures no
///    hidden extra outputs or missing recipients.
///
/// **⚠️ Deferred (CV-27):** Per-output recipient pubkey equality cannot be
/// checked until `PremineOutput::address` is changed from `String` to `[u8; 32]`
/// (raw x-only Schnorr pubkey).  Once that field is added, extend this function
/// to compare each `output.recipient` against the corresponding
/// `premine_outputs[i].pubkey`.
///
/// # Arguments
///
/// * `genesis_coinbase` — The coinbase transaction of the genesis block.
/// * `premine_amount` — Total JXN atoms expected in the premine.
/// * `premine_output_count` — Number of premine recipients (from genesis config).
pub fn validate_beacon_premine(
    genesis_coinbase: &Transaction,
    premine_amount: u64,
    premine_output_count: usize,
) -> Result<(), ValidationError> {
    let actual_total: u64 = genesis_coinbase.outputs.iter().map(|o| o.value).sum();

    // Check 1: total must exactly match the configured premine amount.
    if actual_total != premine_amount {
        return Err(ValidationError::BeaconPremineMismatch {
            expected_total: premine_amount,
            actual_total,
        });
    }

    // Check 2: output count must match the expected number of premine recipients.
    if genesis_coinbase.outputs.len() != premine_output_count {
        return Err(ValidationError::InvalidCoinbaseStructure {
            reason: format!(
                "genesis coinbase has {} outputs but premine config specifies {} recipients",
                genesis_coinbase.outputs.len(),
                premine_output_count
            ),
        });
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::emission_schedule::{TAIL_EMISSION_ATOMS, PREMINE_ATOMS};
    use crate::transaction::{Transaction, TxOutput};

    fn make_coinbase(version: u8, locktime: u32, outputs: Vec<u64>) -> Transaction {
        let mut tx = Transaction::new(version, locktime);
        for value in outputs {
            tx.add_output(TxOutput { value, recipient: [0u8; 32] });
        }
        tx
    }

    // ── BR-2: beacon_block_reward ────────────────────────────────────────────

    #[test]
    fn br2_genesis_always_zero() {
        assert_eq!(beacon_block_reward(0), 0);
    }

    #[test]
    fn br2_tail_emission_is_one_coin_at_all_heights() {
        for h in [1u32, 2, 100, 210_000, 1_000_000, u32::MAX] {
            assert_eq!(beacon_block_reward(h), TAIL_EMISSION_ATOMS, "height {h}");
        }
    }

    #[test]
    fn br2_no_halving_subsidy_never_decreases() {
        assert_eq!(beacon_block_reward(1), beacon_block_reward(210_000));
        assert_eq!(beacon_block_reward(1), beacon_block_reward(u32::MAX));
    }

    // ── BR-3: coinbase structure ─────────────────────────────────────────────

    #[test]
    fn br3_valid_coinbase_accepted() {
        let cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS]);
        assert!(validate_beacon_coinbase_structure(&cb).is_ok());
    }

    #[test]
    fn br3_coinbase_with_inputs_rejected() {
        use crate::transaction::TxInput;
        let mut cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS]);
        cb.inputs.push(TxInput { prev_height: 0, prev_output_idx: 0 });
        let err = validate_beacon_coinbase_structure(&cb).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCoinbaseStructure { .. }));
    }

    #[test]
    fn br3_coinbase_no_outputs_rejected() {
        let cb = make_coinbase(1, 0, vec![]);
        let err = validate_beacon_coinbase_structure(&cb).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCoinbaseStructure { .. }));
    }

    #[test]
    fn br3_coinbase_wrong_version_rejected() {
        let cb = make_coinbase(2, 0, vec![TAIL_EMISSION_ATOMS]);
        let err = validate_beacon_coinbase_structure(&cb).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCoinbaseStructure { .. }));
    }

    #[test]
    fn br3_coinbase_nonzero_locktime_rejected() {
        let cb = make_coinbase(1, 100, vec![TAIL_EMISSION_ATOMS]);
        let err = validate_beacon_coinbase_structure(&cb).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCoinbaseStructure { .. }));
    }

    // ── BR-2/BR-5: coinbase value cap ────────────────────────────────────────

    #[test]
    fn br2_exact_tail_emission_accepted() {
        let cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS]);
        assert!(validate_beacon_coinbase_value(&cb, 1, 0).is_ok());
    }

    #[test]
    fn br2_value_with_fees_accepted() {
        let fees = 5_000;
        let cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS + fees]);
        assert!(validate_beacon_coinbase_value(&cb, 1, fees).is_ok());
    }

    #[test]
    fn br2_value_exceeds_cap_rejected() {
        let cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS + 1]);
        let err = validate_beacon_coinbase_value(&cb, 1, 0).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BeaconCoinbaseExceedsSchedule {
                height: 1,
                max_allowed,
                ..
            } if max_allowed == TAIL_EMISSION_ATOMS
        ));
    }

    #[test]
    fn br5_genesis_coinbase_cannot_claim_tail_emission() {
        let cb = make_coinbase(1, 0, vec![1]); // even 1 atom exceeds the 0 cap at genesis
        let err = validate_beacon_coinbase_value(&cb, 0, 0).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BeaconCoinbaseExceedsSchedule { height: 0, .. }
        ));
    }

    #[test]
    fn br2_saturating_add_prevents_overflow() {
        let cb = make_coinbase(1, 0, vec![TAIL_EMISSION_ATOMS]);
        assert!(validate_beacon_coinbase_value(&cb, 1, u64::MAX).is_ok());
    }

    // ── BR-1: premine validation ─────────────────────────────────────────────

    #[test]
    fn br1_canonical_premine_accepted() {
        // Split 21M coins across two outputs (just as an example)
        let half = PREMINE_ATOMS / 2;
        let cb = make_coinbase(1, 0, vec![half, PREMINE_ATOMS - half]);
        assert!(validate_beacon_premine(&cb, PREMINE_ATOMS, 2).is_ok());
    }

    #[test]
    fn br1_wrong_total_rejected() {
        let cb = make_coinbase(1, 0, vec![PREMINE_ATOMS - 1]);
        let err = validate_beacon_premine(&cb, PREMINE_ATOMS, 1).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BeaconPremineMismatch { expected_total, .. }
            if expected_total == PREMINE_ATOMS
        ));
    }

    #[test]
    fn br1_wrong_output_count_rejected() {
        let cb = make_coinbase(1, 0, vec![PREMINE_ATOMS]);
        let err = validate_beacon_premine(&cb, PREMINE_ATOMS, 2).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCoinbaseStructure { .. }));
    }

    #[test]
    fn br1_zero_premine_genesis_accepted() {
        let cb = make_coinbase(1, 0, vec![0]);
        assert!(validate_beacon_premine(&cb, 0, 1).is_ok());
    }
}
