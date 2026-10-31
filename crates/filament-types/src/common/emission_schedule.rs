// src/common/emission_schedule.rs
//
// CV-26 — Canonical Shisha Coin Emission Schedule
//
// This file is the **single authoritative source** for all beacon-chain emission
// parameters.  Everything that needs to know "how many coins does a block
// produce?" must import from here, not from ad-hoc constants scattered across
// the codebase.
//
// # Schedule (mainnet)
//
//   Premine  : 21 000 000 coins (disbursed entirely in the genesis block)
//   Subsidy  : 1 coin per block, permanent, no halving ("tail inflation")
//   Unit     : 1 coin = 100 000 000 atomic units (same scale as BTC/satoshi)
//
// The genesis block (height 0) carries only the premine; its block subsidy is 0.
// Every block at height ≥ 1 is entitled to exactly TAIL_EMISSION_ATOMS subsidy
// plus any transaction fees collected in that block.
//
// # How to replace this schedule
//
// Change the constants below and recompile.  The rest of the codebase
// (`beacon_reward.rs`, `beacon_subsidy.rs`, `coinbase.rs`, `genesis_config.rs`)
// all delegate to `beacon_block_subsidy()` — nothing else needs to change.
//
// For a network fork with different emission: swap this file or add a runtime
// `EmissionSchedule` enum and plumb it through `BeaconGenesisConfig`.

// ── Units ────────────────────────────────────────────────────────────────────

/// Number of atomic units in one coin.
///
/// 1 Shisha Coin = 10^8 atomic units (mirrors Bitcoin's satoshi scale).
pub const ATOMIC_UNITS_PER_COIN: u64 = 100_000_000;

// ── Premine ──────────────────────────────────────────────────────────────────

/// Total premine in whole coins.
pub const PREMINE_COINS: u64 = 21_000_000;

/// Total premine in atomic units.
///
/// This is the exact value that must equal the sum of all genesis coinbase
/// outputs (BR-1 check).
pub const PREMINE_ATOMS: u64 = PREMINE_COINS * ATOMIC_UNITS_PER_COIN;
//  = 2_100_000_000_000_000

// ── Tail inflation ───────────────────────────────────────────────────────────

/// Per-block subsidy in atomic units, paid at every height ≥ 1, forever.
///
/// Set to exactly one coin (ATOMIC_UNITS_PER_COIN).  There is no halving.
pub const TAIL_EMISSION_ATOMS: u64 = ATOMIC_UNITS_PER_COIN;
//  = 100_000_000

// ── Core function ────────────────────────────────────────────────────────────

/// Return the block subsidy (excluding transaction fees) for a given height.
///
/// # Rules
///
/// | Height | Subsidy                      | Reason                        |
/// |--------|------------------------------|-------------------------------|
/// | 0      | 0                            | Genesis block carries premine  |
/// | ≥ 1    | `TAIL_EMISSION_ATOMS`        | Flat tail inflation, no halving|
///
/// Transaction fees are **not** included here; callers must add them separately.
#[inline]
pub const fn beacon_block_subsidy(height: u32) -> u64 {
    if height == 0 {
        0 // genesis carries only the premine, not a scheduled subsidy
    } else {
        TAIL_EMISSION_ATOMS
    }
}

/// Maximum coinbase output value for a block at `height`, given `tx_fees`.
///
/// `coinbase_total ≤ beacon_block_subsidy(height) + tx_fees`
///
/// Uses `saturating_add` so a fee total of `u64::MAX` does not overflow.
#[inline]
pub fn max_coinbase_value(height: u32, tx_fees: u64) -> u64 {
    beacon_block_subsidy(height).saturating_add(tx_fees)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_correct() {
        assert_eq!(ATOMIC_UNITS_PER_COIN, 100_000_000);
        assert_eq!(PREMINE_ATOMS, 2_100_000_000_000_000);
        assert_eq!(TAIL_EMISSION_ATOMS, 100_000_000);
    }

    #[test]
    fn genesis_subsidy_is_zero() {
        assert_eq!(beacon_block_subsidy(0), 0);
    }

    #[test]
    fn subsidy_is_one_coin_at_all_non_genesis_heights() {
        for h in [1u32, 2, 100, 1_000, 1_000_000, u32::MAX] {
            assert_eq!(
                beacon_block_subsidy(h),
                TAIL_EMISSION_ATOMS,
                "height {h}"
            );
        }
    }

    #[test]
    fn no_halving_subsidy_never_decreases() {
        let a = beacon_block_subsidy(1);
        let b = beacon_block_subsidy(210_000); // Bitcoin halving height
        let c = beacon_block_subsidy(u32::MAX);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn max_coinbase_includes_fees() {
        let fees = 5_000;
        assert_eq!(
            max_coinbase_value(1, fees),
            TAIL_EMISSION_ATOMS + fees
        );
    }

    #[test]
    fn max_coinbase_genesis_is_just_fees() {
        // Genesis block subsidy is 0; only fees (if any) are claimable.
        assert_eq!(max_coinbase_value(0, 0), 0);
        assert_eq!(max_coinbase_value(0, 999), 999);
    }

    #[test]
    fn max_coinbase_saturates_on_overflow() {
        assert_eq!(max_coinbase_value(1, u64::MAX), u64::MAX);
    }

    #[test]
    fn premine_equals_21m_coins() {
        assert_eq!(PREMINE_COINS, 21_000_000);
        assert_eq!(PREMINE_ATOMS, PREMINE_COINS * ATOMIC_UNITS_PER_COIN);
    }
}
