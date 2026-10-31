// src/common/utxo/beacon_subsidy.rs
//
// ⚠️  COMPATIBILITY SHIM — superseded by `crate::common::emission_schedule`
//
// The canonical emission schedule is:
//   Premine  : 21 000 000 coins at genesis (height 0)
//   Subsidy  : 1 coin per block at every height ≥ 1, forever (no halving)
//   1 coin   = 100 000 000 atomic units
//
// New code should import from `crate::common::emission_schedule` directly.
// This file exists only for backward compatibility with `coinbase.rs` callers
// that use `BeaconSubsidyConfig` and `total_block_reward`.
//
// `BeaconSubsidyConfig` is now a thin wrapper: its `schedule` and
// `terminal_subsidy` fields are ignored at runtime — `block_subsidy` always
// delegates to `emission_schedule::beacon_block_subsidy`.  The 60-entry
// epoch/grand-epoch schema (4 096 blocks/epoch, 5 grand-epochs) is deprecated
// and will be removed after all callers migrate.

use serde::{Deserialize, Serialize};
use crate::common::emission_schedule;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (kept for backward compatibility — do not add new callers)
// ─────────────────────────────────────────────────────────────────────────────

#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const EPOCH_LENGTH: u64 = 4_096;
#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const EPOCHS_PER_GRAND_EPOCH: u64 = 12;
#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const GRAND_EPOCH_LENGTH: u64 = 4_096 * 12; // 49 152
#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const NUM_GRAND_EPOCHS: u64 = 5;
#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const TOTAL_SCHEDULE_EPOCHS: usize = 60;
#[deprecated(since = "0.7.0", note = "use emission_schedule constants instead")]
pub const ACTIVE_PERIOD_BLOCKS: u64 = 4_096 * 12 * 5; // 245 760

// ─────────────────────────────────────────────────────────────────────────────
// Configuration type (compatibility shim)
// ─────────────────────────────────────────────────────────────────────────────

/// Beacon-chain subsidy config shim.
///
/// ⚠️  The `schedule` and `terminal_subsidy` fields are **ignored at runtime**.
/// `block_subsidy` always delegates to
/// `crate::common::emission_schedule::beacon_block_subsidy`, which implements
/// the canonical "1 coin per block, no halving" schedule.
///
/// This struct is retained only so that `coinbase.rs` can compile without
/// changes.  Migrate callers to `emission_schedule` and then delete this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconSubsidyConfig {
    #[serde(default)]
    pub schedule: Vec<u64>,
    #[serde(default)]
    pub terminal_subsidy: u64,
}

impl BeaconSubsidyConfig {
    /// Always returns `Ok(())` — validation is no longer meaningful.
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    /// Return a zero-cost devnet / test instance.
    #[cfg(any(test, feature = "devnet"))]
    pub fn devnet() -> Self {
        Self { schedule: vec![], terminal_subsidy: 0 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core functions — delegate to emission_schedule
// ─────────────────────────────────────────────────────────────────────────────

/// Return the block subsidy for `height`.
///
/// Ignores `config` — always delegates to
/// [`emission_schedule::beacon_block_subsidy`]:
/// - height 0 → 0 (premine-only genesis)
/// - height ≥ 1 → `TAIL_EMISSION_ATOMS` (1 coin, no halving)
pub fn block_subsidy(height: u64, _config: &BeaconSubsidyConfig) -> Result<u64, String> {
    Ok(emission_schedule::beacon_block_subsidy(height as u32))
}

/// Return the total block reward = subsidy + transaction fees.
pub fn total_block_reward(
    height: u64,
    _config: &BeaconSubsidyConfig,
    tx_fees: u64,
) -> Result<u64, String> {
    Ok(emission_schedule::max_coinbase_value(height as u32, tx_fees))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::emission_schedule::{TAIL_EMISSION_ATOMS, PREMINE_ATOMS};

    fn cfg() -> BeaconSubsidyConfig { BeaconSubsidyConfig::devnet() }

    #[test]
    fn genesis_subsidy_is_zero() {
        assert_eq!(block_subsidy(0, &cfg()).unwrap(), 0);
    }

    #[test]
    fn non_genesis_subsidy_is_one_coin() {
        for h in [1u64, 100, 1_000_000] {
            assert_eq!(block_subsidy(h, &cfg()).unwrap(), TAIL_EMISSION_ATOMS);
        }
    }

    #[test]
    fn total_reward_adds_fees() {
        let fees = 50_000u64;
        assert_eq!(
            total_block_reward(1, &cfg(), fees).unwrap(),
            TAIL_EMISSION_ATOMS + fees
        );
    }

    #[test]
    fn premine_constant_is_correct() {
        assert_eq!(PREMINE_ATOMS, 2_100_000_000_000_000);
    }
}
