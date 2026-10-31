// src/common/validation/mod.rs

//! Validation module — consensus rule enforcement for beacon and shard blocks.
//!
//! Provides context-free structural validation and context-dependent chain
//! validation for both beacon and shard blocks, plus PoW and merged-mining
//! proof verification.
//!
//! ## Sub-modules
//!
//! - `errors` — Shared `ValidationError` enum
//! - `pow` — Proof-of-work verification (hash < target, commitment hash)
//! - `beacon` — Beacon block structure and chain validation
//! - `shard` — Shard block structure and chain validation
//! - `merged_mining` — Merged-mining proof verification
//! - `transactions` — Transaction structural validation (CV-09)
//! - `k_coeff` — k-coefficient validation and reward formula (CV-15/CV-16/CV-19)
//! - `beacon_reward` — Beacon reward schedule + premine validation (CV-26/CV-27)

use std::time::{SystemTime, UNIX_EPOCH};

pub mod errors;
pub mod pow;
pub mod beacon;
pub mod shard;
pub mod merged_mining;
pub mod transactions;
pub mod k_coeff;
pub mod beacon_reward;

// Re-export commonly used items
pub use errors::ValidationError;

pub use pow::{
    resolve_beacon_asserted_s,
    resolve_shard_asserted_s,
    verify_beacon_proof_of_work,
    verify_beacon_proof_of_work_with_asserted_s,
    verify_beacon_proof_of_work_with_hash_sorting,
    verify_beacon_header_pow,
    verify_beacon_hash_sorting,
    hash_meets_target,
    nbits_to_target,
    validate_nbits_reasonableness,
    validate_rbits_reasonableness,
    validate_beacon_rbits_floor,
    apply_beacon_retarget_floor,
    validate_shard_rbits_floor,
    apply_shard_retarget_floor,
    validate_nbits_against_max_target,
};

pub use beacon::{
    validate_beacon_block_structure,
    validate_beacon_block_structure_v3,
    validate_beacon_block_structure_with_hash_sorting,
    validate_beacon_block_against_chain,
    validate_beacon_genesis,
    validate_beacon_expand_rules,
};

pub use shard::{
    validate_shard_block_structure,
    validate_shard_block_against_chain,
    validate_shard_genesis_linkage,
};

pub use merged_mining::{verify_shard_id_and_mmn, verify_shard_id_and_mmn_ranged};

pub use transactions::{
    validate_transaction_structure,
    validate_coinbase_structure,
    validate_no_intra_block_double_spend,
    validate_tx_value_conservation,
    validate_tx_coinbase_maturity,
    validate_block_body,
    validate_shard_block_body,
    validate_shard_block_body_with,
    validate_block_body_with,
    BlockBodyValidationParams,
    BlockValidationUtxo,
    ForkPointUtxoView,
    block_validation_utxo,
    validate_transaction_at_height,
    validate_transaction_at_height_with_window,
    validate_flat_tx_at_height_with_window,
    validate_transaction_for_mempool,
    validate_transaction_for_mempool_with,
    compute_mempool_fee_rate,
    sig_cache_keys_for_tx,
    MempoolAdmissionParams,
    TX_VERSION,
    MAX_INPUTS_PER_TX,
    MAX_OUTPUTS_PER_TX,
    MAX_SHARD_BLOCK_OUTPUTS,
    MAX_BEACON_BLOCK_OUTPUTS,
    DEFAULT_MAX_SHARD_BLOCK_WIRE_BYTES,
    DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES,
    SHARD_BLOCK_WIRE_RESERVE,
    BEACON_BLOCK_WIRE_RESERVE,
    template_wire_budget,
    max_block_outputs,
    COINBASE_MATURITY,
    beacon_coinbase_maturity,
    shard_coinbase_maturity,
    DEFAULT_MIN_FEE_PER_4_BYTES,
    min_fee_atoms_for_size,
};

pub use k_coeff::{
    validate_compact_k_sanity,
    validate_k_kbits_bounds,
    validate_genesis_k_kbits,
    calculate_shard_reward,
    validate_k6_coinbase_cap,
    K_FIXED_SHIFT,
    K_FIXED_ONE,
    EPOCH_LENGTH,
};

pub use beacon_reward::{
    beacon_block_reward,
    validate_beacon_coinbase_structure,
    validate_beacon_coinbase_value,
    validate_beacon_premine,
    GENESIS_BLOCK_HEIGHT,
    MIN_TRANSACTION_FEE,
};

pub use beacon::{
    MAX_FUTURE_SECS,
    MAX_CHAIN_DRIFT_SECS,
    LOCAL_CLOCK_TOLERANCE_SECS,
    LARGE_GAP_MULTIPLIER,
};

pub use shard::{SHARD_INTERVAL_NUM, SHARD_INTERVAL_DEN};

/// Returns the current Unix timestamp in seconds.
///
/// Used by CV-01 (T-2) future-timestamp check in the standalone validators.
/// The inline chain paths use their own `current_timestamp()` already in scope.
///
/// Panics only if the system clock predates the Unix epoch (non-recoverable
/// environment misconfiguration).
#[inline]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs()
}

/// Return a monotonically increasing timestamp in nanoseconds.
///
/// Uses `std::time::Instant` which is guaranteed never to go backwards,
/// making it safe for TTL checks even across NTP steps or VM migrations.
/// The absolute value is arbitrary (epoch undefined); only differences matter.
#[inline]
pub fn monotonic_nanos() -> u64 {
    use std::time::Instant;
    // SAFETY: Instant::now() is always >= any previous Instant on the same
    // thread.  We convert to nanos with saturation to avoid overflow on very
    // long-running processes (u64 wraps after ~584 years).
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    Instant::now().duration_since(*start).as_nanos().min(u64::MAX as u128) as u64
}

// ── Delta/Timestamp Conversion Helpers (CV-01/TS-DELTA) ──────────────────
//
// Fixed 2026-07-04: `delta` is the block's *deviation* (in 1/256-second units)
// from its expected arrival time `bitcoin_anchor_ts + height × interval`, not a
// raw offset from the anchor. Prior to this fix, these two functions (and the
// header constructors in `common::blocks`) computed/reconstructed a pure
// anchor-relative offset with no height term, while the T-1/T-MTP validation
// rules' `- I_block × 256` slack terms were written assuming the
// deviation model. See `docs/reports/TS-DELTA_Final_Completion_Report.md` §5.
//
// `interval_num`/`interval_den` express the block interval as a rational
// number of seconds so the expected-time component can be computed as an
// exact integer in delta-unit space, never introducing fractional-second
// truncation: beacon uses (600, 1); shard uses (75, 2) = 37.5 s. For both,
// `interval_num × 256` is evenly divisible by `interval_den`.

/// Compute a block's expected-arrival delta-unit offset:
/// `height × interval_num × 256 / interval_den`.
#[inline]
fn expected_delta_units(height: u64, interval_num: u64, interval_den: u64) -> i64 {
    let den = interval_den.max(1) as i64;
    (height as i64)
        .saturating_mul(interval_num as i64)
        .saturating_mul(256)
        / den
}

/// Convert a height-aware delta value (in 1/256-second units, deviation from
/// the block's expected arrival time) to a Unix timestamp.
///
/// # Arguments
/// * `delta` - Block delta from the block header
/// * `bitcoin_anchor_ts` - The bitcoin anchor timestamp (Unix seconds) from genesis config
/// * `height` - The block's height on this chain
/// * `interval_num`/`interval_den` - Nominal block interval in seconds, as a rational
///   (beacon: 600/1; shard: 75/2)
///
/// # Returns
/// Unix timestamp in seconds (reconstructed wall-clock time)
///
/// # Note
/// Division by 256 truncates fractional seconds. For validation purposes, this is acceptable
/// as it matches the precision floor of the protocol (3.9 millisecond resolution).
#[inline]
pub fn delta_to_unix(delta: i32, bitcoin_anchor_ts: u64, height: u64, interval_num: u64, interval_den: u64) -> u64 {
    // ts = bitcoin_anchor_ts + (expected_delta_units + delta) / 256 seconds
    let total_units = expected_delta_units(height, interval_num, interval_den)
        .saturating_add(delta as i64);
    let offset_secs = total_units / 256i64;
    if offset_secs >= 0 {
        bitcoin_anchor_ts.saturating_add(offset_secs as u64)
    } else {
        bitcoin_anchor_ts.saturating_sub((-offset_secs) as u64)
    }
}

/// Same as [`delta_to_unix`], but additionally returns the 1/256-second
/// remainder instead of discarding it — pass both into
/// [`crate::difficulty_adjustment::devnet_cumulative::DevnetCumulativeDAA::adjust_with_chain_weight_subsec`]
/// (NC-74). Uses `rem_euclid`/`div_euclid` (floor division, always a
/// `0..256` remainder) rather than `delta_to_unix`'s truncating `/`, since a
/// negative remainder can't be represented as the `u16` this returns; the
/// whole-second component still matches `delta_to_unix`'s own output
/// whenever that output is non-negative-offset from the anchor (true for
/// any real block, which is always at or after genesis).
#[inline]
pub fn delta_to_unix_with_subsec(
    delta: i32, bitcoin_anchor_ts: u64, height: u64, interval_num: u64, interval_den: u64,
) -> (u64, u16) {
    let total_units = expected_delta_units(height, interval_num, interval_den)
        .saturating_add(delta as i64);
    let offset_secs = total_units.div_euclid(256);
    let subsec = total_units.rem_euclid(256) as u16;
    let ts = if offset_secs >= 0 {
        bitcoin_anchor_ts.saturating_add(offset_secs as u64)
    } else {
        bitcoin_anchor_ts.saturating_sub((-offset_secs) as u64)
    };
    (ts, subsec)
}

/// T-3b cumulative-drift helper: how far a block's *converted* wall-clock
/// timestamp (`block_unix_ts`, already reconstructed via [`delta_to_unix`])
/// sits from the genesis-anchored expected schedule for the reference height
/// the block's delta is actually scaled to.
///
/// Both arguments must already be on the same basis: `block_unix_ts` must
/// have been computed with the same `(genesis_ts, ref_height, interval_secs)`
/// triple passed here — mismatching them (e.g. reconstructing `block_unix_ts`
/// against a shard's own height/interval while the delta being converted is
/// actually the embedded beacon header's, on the beacon's height/interval)
/// silently produces a multi-year/decade false-positive drift. This is
/// exactly the bug found via a live 2026-07-25 devnet_15 soak in both
/// `BeaconChain::apply_beacon_block_to_memory` (wrong variable: raw delta
/// instead of the converted timestamp) and `ShardChain::validate_block_full`
/// (wrong basis: shard height/interval instead of the embedded beacon
/// header's height/interval).
///
/// # Returns
/// Signed drift in seconds: positive means the block arrived late relative
/// to schedule, negative means early.
#[inline]
pub fn cumulative_drift_secs(
    block_unix_ts: u64,
    genesis_ts: u64,
    ref_height: u64,
    interval_secs: u64,
) -> i64 {
    let expected_ts = genesis_ts.saturating_add(ref_height.saturating_mul(interval_secs));
    block_unix_ts as i64 - expected_ts as i64
}

/// The wall-clock gap, expressed as a multiple of the block interval, above
/// which T-3a emits a soft warning. A wall-clock gap of `10 × I` between two
/// consecutive blocks produces a `delta` *difference* of `(10 I − I) × 256 =
/// 9 × I × 256` units — the two blocks' schedule terms cancel, so only the
/// lateness *beyond* one nominal interval shows up in the delta difference.
pub const T3A_GAP_INTERVAL_MULTIPLE: i128 = 9;

/// CV-02 / T-3a: soft "consecutive-gap" warning, computed entirely in
/// deviation-delta space (1 unit = 1/256 second) — the same space `delta`
/// and the T-MTP check live in.
///
/// `gap_delta` is the raw difference between two consecutive blocks' `delta`
/// header fields (`this.delta - prev.delta`). The threshold is a wall-clock
/// gap of ~10 block intervals, i.e. `T3A_GAP_INTERVAL_MULTIPLE × I × 256`
/// delta units. The interval is passed as a rational (`interval_num /
/// interval_den`) so the shard's 75/2 works without floats; pass
/// `(beacon_interval_secs(), 1)` for the beacon.
///
/// Returns `Some((gap_secs, threshold_secs))` — both already converted to
/// wall-clock seconds, ready for the log message — when the gap exceeds the
/// threshold, else `None`.
///
/// Callers must **never** log `gap_delta` directly: a raw delta gap of e.g.
/// `58209` is ~227 s, not 58209 s. Logging the raw delta as seconds (and
/// dividing a seconds-scale threshold by 256 down to "0 s") was the
/// mining-pool T-3a bug the 2026-09-05 linear AWS soak surfaced — the two
/// inline copies in `src/mining_pool/{beacon,shard}_chain.rs` had never been
/// aligned with the shared validators after NC-39 fixed the sibling T-3b
/// drift check on the same sites (NC-39b / T3A-MP-1). This helper is now the
/// single source of truth for all four T-3a sites.
#[inline]
pub fn t3a_gap_warning(gap_delta: i32, interval_num: u64, interval_den: u64) -> Option<(i64, i64)> {
    let den = (interval_den.max(1)) as i128;
    let threshold_delta = T3A_GAP_INTERVAL_MULTIPLE * (interval_num as i128) * 256 / den;
    if (gap_delta as i128) > threshold_delta {
        let gap_secs = (gap_delta as i64) / 256;
        let threshold_secs =
            (T3A_GAP_INTERVAL_MULTIPLE as i64 * interval_num as i64) / (interval_den.max(1) as i64);
        Some((gap_secs, threshold_secs))
    } else {
        None
    }
}

/// Convert a Unix timestamp to a height-aware delta value (in 1/256-second
/// units, deviation from the block's expected arrival time).
///
/// # Arguments
/// * `unix_ts` - Unix timestamp in seconds
/// * `bitcoin_anchor_ts` - The bitcoin anchor timestamp (Unix seconds) from genesis config
/// * `height` - The block's height on this chain
/// * `interval_num`/`interval_den` - Nominal block interval in seconds, as a rational
///   (beacon: 600/1; shard: 75/2)
///
/// # Returns
/// * `Ok(delta)` if the conversion succeeds
/// * `Err(ValidationError::DeltaOutOfRange)` if the delta would overflow i32
#[inline]
pub fn unix_to_delta(unix_ts: u64, bitcoin_anchor_ts: u64, height: u64, interval_num: u64, interval_den: u64) -> Result<i32, ValidationError> {
    // delta = (unix_ts - bitcoin_anchor_ts) * 256 - expected_delta_units
    let offset_secs = unix_ts as i64 - bitcoin_anchor_ts as i64;
    let raw_units = offset_secs.saturating_mul(256i64);
    let delta_raw = raw_units.saturating_sub(expected_delta_units(height, interval_num, interval_den));

    if delta_raw < i32::MIN as i64 || delta_raw > i32::MAX as i64 {
        return Err(ValidationError::DeltaOutOfRange {
            delta: if delta_raw < i32::MIN as i64 { i32::MIN } else { i32::MAX },
            reason: "delta computation overflows i32 range",
        });
    }

    Ok(delta_raw as i32)
}

/// Validate that a block delta satisfies the Median Time Past (MTP) rule.
///
/// The MTP rule prevents timestamp spam: a block's delta must be strictly greater than
/// the median of the previous 11 blocks' deltas minus `I_block × 6 × 256`.
///
/// The threshold is derived from the BTC rule `T(h) > median(T(h-1)..T(h-11))`:
/// in deviation-delta space this becomes `delta(h) > delta_median(prev 11) - I × 6 × 256`,
/// where 6 is the approximate position of the median in the 11-block window and
/// `I × 256` converts the block interval from seconds to 1/256-second units.
///
/// Chain-specific `mtp_offset` values:
/// - Beacon: `6 × 600 × 256 = 921_600`
/// - Shard:  `6 × SHARD_INTERVAL_NUM × 256 / SHARD_INTERVAL_DEN = 57_600`
///
/// # Arguments
/// * `delta` - The block's delta value (1/256-second units)
/// * `prev_deltas` - Array of previous block deltas (up to 11, newest-first)
/// * `mtp_offset` - Chain-specific offset: `I_block × 6 × 256` (see above)
///
/// # Returns
/// * `Ok(())` if the block passes the MTP check
/// * `Err(ValidationError::TimestampBelowMtp)` if the block violates the rule
///
/// Chain-specific MTP offset for beacon blocks (`6 × interval × 256`).
#[inline]
pub fn beacon_mtp_offset() -> i32 {
    crate::common::block_intervals::beacon_mtp_offset()
}

/// Chain-specific MTP offset for shard blocks.
#[inline]
pub fn shard_mtp_offset() -> i32 {
    crate::common::block_intervals::shard_mtp_offset()
}

/// Deprecated production default — use [`beacon_mtp_offset`].
pub const BEACON_MTP_OFFSET: i32 = 921_600;

/// Deprecated production default — use [`shard_mtp_offset`].
pub const SHARD_MTP_OFFSET: i32 = 57_600;

/// # Note
/// If `prev_deltas` has fewer than 11 entries, this function uses what's available.
/// The first block (height 0) trivially passes (no previous deltas to compare).
pub fn validate_timestamp_mtp(
    delta: i32,
    prev_deltas: &[i32],
    mtp_offset: i32,
) -> Result<(), ValidationError> {
    if prev_deltas.is_empty() {
        // First block trivially passes
        return Ok(());
    }

    // Take up to 11 previous deltas; sort and find median
    let count = prev_deltas.len().min(11);
    let mut sorted = prev_deltas[..count].to_vec();
    sorted.sort();
    let median = sorted[count / 2]; // Integer division gives lower median for even counts

    // MTP rule: delta > median - I_block × 6 × 256
    let min_allowed = median.saturating_sub(mtp_offset);

    if delta <= min_allowed {
        return Err(ValidationError::TimestampBelowMtp {
            delta,
            median_past_delta: median,
            min_allowed_delta: min_allowed,
        });
    }

    Ok(())
}

/// A shard block's time, in 1/256-second units since the genesis anchor.
///
/// A shard block carries no timestamp of its own: its time is the aux beacon
/// header's `delta`, which is an offset from the **beacon** schedule at that
/// header's **beacon** height (Anti-Patterns #6). Two shard blocks usually
/// reference different beacon heights, so their raw `delta`s are not
/// comparable — rebuild the time first (`beacon_height × beacon_interval × 256
/// + delta`). Same reconstruction as T-2's `delta_to_unix`, kept in 1/256 s.
#[inline]
pub fn shard_time_units(beacon_delta: i32, beacon_height: u64) -> i64 {
    expected_delta_units(
        beacon_height,
        crate::common::block_intervals::beacon_interval_secs(),
        1,
    )
    .saturating_add(beacon_delta as i64)
}

/// Shard Median-Time-Past (NC-133): a shard block's time must be later than
/// the median of the previous (up to 11) shard blocks' times — Bitcoin's rule
/// on times rebuilt by [`shard_time_units`]. A tie is rejected. This is safe
/// because the job generator gives every job a strictly later time (at least
/// 1/256 s after the previous one), so blocks from one pool never share a
/// timestamp. `prev_units` may be in any order.
///
/// Do not use [`validate_timestamp_mtp`] for shards: it compares raw deltas,
/// which is only meaningful when every delta is measured against the same
/// chain's schedule at consecutive heights (the beacon chain).
pub fn validate_shard_timestamp_mtp(
    time_units: i64,
    prev_units: &[i64],
) -> Result<(), ValidationError> {
    if prev_units.is_empty() {
        return Ok(());
    }
    let count = prev_units.len().min(11);
    let mut sorted = prev_units[..count].to_vec();
    sorted.sort_unstable();
    let median = sorted[count / 2];
    if time_units <= median {
        return Err(ValidationError::ShardTimestampBelowMtp {
            time_units,
            median_past_units: median,
        });
    }
    Ok(())
}

#[cfg(test)]
mod shard_mtp_tests {
    use super::{shard_time_units, validate_shard_timestamp_mtp, ValidationError};

    const I: i64 = 600 * 256; // default beacon interval in delta units

    /// The SC-CS-64 shape: the beacon runs ahead of schedule, so each newer
    /// aux header has a higher beacon height and a *lower* delta even though
    /// wall-clock time only moves forward. Raw-delta MTP rejected these.
    #[test]
    fn honest_blocks_with_falling_delta_pass() {
        // 12 shard blocks, 5 s apart, each on a beacon header one height later
        // (the beacon producing every 5 s against a 600 s schedule).
        let times: Vec<i64> = (0..12)
            .map(|i| {
                let beacon_h = 100 + i as u64;
                let wall = 1_000_000 * 256 + i * 5 * 256;
                let delta = (wall - beacon_h as i64 * I) as i32;
                assert_eq!(shard_time_units(delta, beacon_h), wall);
                shard_time_units(delta, beacon_h)
            })
            .collect();
        for i in 1..times.len() {
            let start = i.saturating_sub(11);
            let prev: Vec<i64> = times[start..i].to_vec();
            assert!(validate_shard_timestamp_mtp(times[i], &prev).is_ok(), "block {i}");
        }
        // And the raw deltas really do fall (the old check's false premise).
        let d0 = (times[0] - 100 * I) as i32;
        let d11 = (times[11] - 111 * I) as i32;
        assert!(d11 < d0);
    }

    #[test]
    fn time_at_or_below_median_rejected() {
        let prev = [10, 20, 30, 40, 50];
        assert!(validate_shard_timestamp_mtp(31, &prev).is_ok());
        assert!(matches!(
            validate_shard_timestamp_mtp(30, &prev),
            Err(ValidationError::ShardTimestampBelowMtp { time_units: 30, median_past_units: 30 })
        ), "a tie is rejected");
        assert!(matches!(
            validate_shard_timestamp_mtp(29, &prev),
            Err(ValidationError::ShardTimestampBelowMtp { time_units: 29, median_past_units: 30 })
        ));
        assert!(validate_shard_timestamp_mtp(0, &[]).is_ok());
    }
}

#[cfg(test)]
mod drift_tests {
    use super::{cumulative_drift_secs, delta_to_unix};

    // T-3b-1: on-schedule block (delta=0) at a beacon-scale height/interval
    // — drift must be exactly zero.
    #[test]
    fn t3b_1_beacon_on_schedule_zero_drift() {
        let genesis_ts = 1_784_000_000u64;
        let beacon_interval = 150u64; // devnet_15
        let height = 10u64;
        let block_unix_ts = delta_to_unix(0, genesis_ts, height, beacon_interval, 1);
        let drift = cumulative_drift_secs(block_unix_ts, genesis_ts, height, beacon_interval);
        assert_eq!(drift, 0);
    }

    // T-3b-2: same schedule, but with a real (small) delta — drift must
    // equal the delta, not some multi-year/decade nonsense value.
    #[test]
    fn t3b_2_beacon_small_real_deviation_matches_delta() {
        let genesis_ts = 1_784_000_000u64;
        let beacon_interval = 150u64;
        let height = 10u64;
        let delta_units = 25 * 256; // 25 seconds late, in 1/256s units
        let block_unix_ts = delta_to_unix(delta_units, genesis_ts, height, beacon_interval, 1);
        let drift = cumulative_drift_secs(block_unix_ts, genesis_ts, height, beacon_interval);
        assert_eq!(drift, 25);
    }

    // T-3b-3: shard-side usage — the delta being converted is the embedded
    // *beacon* header's, so `block_unix_ts` and the drift comparison must
    // both use the beacon's height/interval, never the shard's own. This
    // reproduces the exact live-soak-confirmed shard bug: reconstructing
    // `block_unix_ts` on the beacon basis (correct) but computing drift
    // against a shard-height/shard-interval basis (the bug) — verifying the
    // fixed call pattern (both on beacon basis) stays near zero for an
    // on-schedule aux beacon delta, regardless of the shard's own height.
    #[test]
    fn t3b_3_shard_uses_embedded_beacon_basis_not_shard_basis() {
        let genesis_ts = 1_784_000_000u64;
        let beacon_interval = 150u64;
        let beacon_height = 3u64; // the aux beacon header's height
        let shard_height = 47u64; // unrelated, much larger shard height
        let (shard_num, shard_den) = (75u64, 2u64); // 37.5s, devnet_15 shard interval

        let block_unix_ts = delta_to_unix(0, genesis_ts, beacon_height, beacon_interval, 1);

        // Correct: compare on the same (beacon) basis the delta was converted with.
        let correct_drift =
            cumulative_drift_secs(block_unix_ts, genesis_ts, beacon_height, beacon_interval);
        assert_eq!(correct_drift, 0);

        // The old bug's shape: expected_ts derived from shard height/interval
        // instead — reproduces a large spurious drift, confirming the two
        // bases are NOT interchangeable (guards against reintroducing the bug).
        let buggy_shard_interval_secs = shard_num / shard_den.max(1); // integer approx, as the old code did via the "twice" trick
        let buggy_expected_ts =
            genesis_ts.saturating_add(shard_height.saturating_mul(buggy_shard_interval_secs));
        let buggy_drift = block_unix_ts as i64 - buggy_expected_ts as i64;
        assert_ne!(
            buggy_drift, 0,
            "sanity: the old shard-basis computation should NOT agree with the fixed beacon-basis one \
             (if it does, this test's premise no longer demonstrates the bug)"
        );
    }

    // T-3b-4: genuine drift (e.g. a stale/corrupted delta far off schedule)
    // must still be detected — the fix must not silently defeat the check.
    #[test]
    fn t3b_4_genuine_drift_detected() {
        let genesis_ts = 1_784_000_000u64;
        let beacon_interval = 150u64;
        let height = 10u64;
        // Delta corresponds to a timestamp 40 days off schedule.
        let delta_units = (40 * 86_400) * 256;
        let block_unix_ts = delta_to_unix(delta_units, genesis_ts, height, beacon_interval, 1);
        let drift = cumulative_drift_secs(block_unix_ts, genesis_ts, height, beacon_interval);
        assert_eq!(drift, 40 * 86_400);
    }
}

#[cfg(test)]
mod t3a_tests {
    use super::t3a_gap_warning;

    // T-3a-1: an on-schedule consecutive pair (delta difference 0) never warns.
    #[test]
    fn t3a_1_on_schedule_gap_no_warning() {
        assert_eq!(t3a_gap_warning(0, 600, 1), None); // beacon, production
        assert_eq!(t3a_gap_warning(0, 75, 2), None); // shard, production
        assert_eq!(t3a_gap_warning(0, 5, 1), None); // crash-recovery 5 s
    }

    // T-3a-2: a modest overshoot (well under 9 intervals of extra lateness)
    // stays quiet — the threshold is 9 × I × 256 delta units.
    #[test]
    fn t3a_2_small_gap_below_threshold_no_warning() {
        // beacon I=600 → threshold 9·600·256 = 1_382_400 delta units.
        assert_eq!(t3a_gap_warning(1_000_000, 600, 1), None);
        // shard I=5 → threshold 9·5·256 = 11_520.
        assert_eq!(t3a_gap_warning(11_520, 5, 1), None); // exactly at bound: not `>`
        assert_eq!(t3a_gap_warning(11_000, 5, 1), None);
    }

    // T-3a-3: the exact mining-pool units bug the 2026-09-05 linear AWS soak
    // caught. Kameniar beacon logged `anomalous gap: 58209 (delta units,
    // threshold 0 s worth)` on the 5 s crash-recovery interval. The helper
    // must report ~227 s (58209 / 256), NOT 58209, and a 45 s threshold
    // (9 × 5), NOT 0.
    #[test]
    fn t3a_3_soak_beacon_units_bug_regression() {
        let (gap_secs, threshold_secs) =
            t3a_gap_warning(58_209, 5, 1).expect("58209 delta ≫ 11520 threshold — must warn");
        assert_eq!(gap_secs, 227, "must be gap_delta / 256 seconds, never the raw delta");
        assert_eq!(threshold_secs, 45, "9 × 5 s interval, never 0 and never a hardcoded 375");
    }

    // T-3a-4: the shard-side counterpart. Kameniar shard logged
    // `anomalous gap: 49627 s (threshold 375 s)` — raw delta mislabelled `s`,
    // hardcoded production-era `375`. At the 5 s soak interval the helper
    // must report ~193 s and a 45 s threshold; the rational-interval path
    // (75/2) must also work without floats.
    #[test]
    fn t3a_4_soak_shard_units_bug_regression() {
        let (gap_secs, threshold_secs) =
            t3a_gap_warning(49_627, 5, 1).expect("49627 delta ≫ 11520 threshold — must warn");
        assert_eq!(gap_secs, 193);
        assert_eq!(threshold_secs, 45);

        // Production shard interval 75/2 = 37.5 s → threshold 9·75·256/2 = 86_400.
        assert_eq!(t3a_gap_warning(80_000, 75, 2), None);
        let (g, t) = t3a_gap_warning(100_000, 75, 2).expect("100000 > 86400 — must warn");
        assert_eq!(g, 100_000 / 256); // 390 s
        assert_eq!(t, 9 * 75 / 2); // 337 s (integer, matches the pre-existing shared validator)
    }

    // T-3a-5: a negative gap (this block's delta lower than prev's — allowed
    // since T-1 block-to-block ordering was removed 2026-07-04) never warns.
    #[test]
    fn t3a_5_negative_gap_no_warning() {
        assert_eq!(t3a_gap_warning(-500_000, 600, 1), None);
        assert_eq!(t3a_gap_warning(i32::MIN, 5, 1), None);
    }

    // T-3a-6: interval_den = 0 is treated as 1 (no divide-by-zero).
    #[test]
    fn t3a_6_zero_denominator_is_safe() {
        assert_eq!(t3a_gap_warning(0, 600, 0), None);
        assert!(t3a_gap_warning(i32::MAX, 5, 0).is_some());
    }
}

#[cfg(test)]
mod mtp_tests {
    use super::{validate_timestamp_mtp, beacon_mtp_offset, shard_mtp_offset};

    // T-MTP-1: fewer than 11 previous deltas — function uses what's available.
    #[test]
    fn tmtp_1_partial_window_passes() {
        // 5 previous deltas, all at delta=0 (on schedule).
        // median = 0; min_allowed = 0 - 921_600 = very negative; new delta=100 passes.
        let prev = vec![0i32; 5];
        assert!(validate_timestamp_mtp(100, &prev, beacon_mtp_offset()).is_ok());
    }

    // T-MTP-2: empty previous deltas — first block trivially passes.
    #[test]
    fn tmtp_2_empty_prev_passes() {
        assert!(validate_timestamp_mtp(-999_999, &[], beacon_mtp_offset()).is_ok());
    }

    // T-MTP-3: delta well above threshold — passes.
    #[test]
    fn tmtp_3_normal_block_passes() {
        // 11 deltas all at 0; median=0; min_allowed = -921_600; new delta=0 > -921_600.
        let prev = vec![0i32; 11];
        assert!(validate_timestamp_mtp(0, &prev, beacon_mtp_offset()).is_ok());
    }

    // T-MTP-4: delta exactly at the threshold — rejects (rule is strictly greater-than).
    #[test]
    fn tmtp_4_delta_at_threshold_rejects() {
        // 11 deltas all at 921_600; median=921_600; min_allowed=0; new delta=0 is NOT > 0.
        let prev = vec![beacon_mtp_offset(); 11];
        assert!(validate_timestamp_mtp(0, &prev, beacon_mtp_offset()).is_err());
    }

    // T-MTP-5: delta one above the threshold — passes.
    #[test]
    fn tmtp_5_delta_one_above_threshold_passes() {
        let prev = vec![beacon_mtp_offset(); 11];
        // min_allowed = median - offset = 921_600 - 921_600 = 0; delta=1 > 0.
        assert!(validate_timestamp_mtp(1, &prev, beacon_mtp_offset()).is_ok());
    }

    // T-MTP-6: shard offset constant is correct (57_600 = 6 × 37.5 × 256).
    #[test]
    fn tmtp_6_shard_offset_value() {
        assert_eq!(shard_mtp_offset(), 57_600);
    }

    // T-MTP-7: beacon offset constant is correct (921_600 = 6 × 600 × 256).
    #[test]
    fn tmtp_7_beacon_offset_value() {
        assert_eq!(beacon_mtp_offset(), 921_600);
    }

    // T-MTP-8: only the first 11 previous deltas are used even if more are given.
    #[test]
    fn tmtp_8_uses_only_11_prev() {
        // First 11 deltas are high (median = 2_000_000); the 12th is ignored.
        // min_allowed = 2_000_000 - 921_600 = 1_078_400; delta=0 should fail.
        let mut prev = vec![2_000_000i32; 11];
        prev.push(-9_999_999); // 12th entry — should be ignored
        assert!(validate_timestamp_mtp(0, &prev, beacon_mtp_offset()).is_err());
    }

    // T-MTP-9: mixed deltas — median is correctly computed (sorted, lower median for even N).
    #[test]
    fn tmtp_9_median_correctly_sorted() {
        // Unsorted: [5,3,1,4,2] (5 entries, odd count, median = 3).
        // min_allowed = 3 - 921_600 = very negative; delta=0 passes.
        let prev = vec![5i32, 3, 1, 4, 2];
        assert!(validate_timestamp_mtp(0, &prev, beacon_mtp_offset()).is_ok());
    }
}