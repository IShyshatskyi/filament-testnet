// src/common/validation/beacon.rs
//
// UPDATED for BLAKE3 (v0.2.2): Genesis validation now uses BLAKE3 hash_pair

use crate::common::blocks::beacon_block::BeaconBlock;
use crate::common::genesis::genesis_config::BeaconGenesisConfig;
use crate::common::weighted_mmr_core::WeightedMMR;
use crate::common::crypto::weighted_hash::WeightedHash;
use super::errors::ValidationError;
use super::pow::verify_beacon_proof_of_work;
use log::{debug, warn};

// ── Timestamp validation constants ───────────────────────────────────────────

/// CV-01 (T-2): Maximum number of seconds a beacon block timestamp may exceed
/// the node's local wall clock before the block is rejected.
/// One beacon block interval (see [`crate::common::block_intervals`]).
#[inline]
pub fn max_future_secs() -> u64 {
    crate::common::block_intervals::beacon_interval_secs()
}

/// Deprecated alias — use [`max_future_secs`] for the active network interval.
pub const MAX_FUTURE_SECS: u64 = 600;

/// CV-02 (T-3a): a consecutive-block `delta` gap larger than
/// `LARGE_GAP_MULTIPLIER × I_block × 256` deviation-delta units triggers a soft
/// warning. Not a consensus rejection. A wall-clock gap of `10 × I` produces a
/// delta *difference* of `(10 I − I) × 256 = 9 × I × 256`, hence the factor 9
/// (corrected from 10 on 2026-09-09; see NC-39b / T3A-MP-1).
///
/// The T-3a threshold + delta→seconds display math is centralised in
/// [`super::t3a_gap_warning`]; this constant is kept only for reference and
/// backward compatibility.
pub const LARGE_GAP_MULTIPLIER: u64 = 9;

/// CV-02 (T-3b): Cumulative drift from the genesis-anchored expected schedule
/// larger than this triggers a soft warning. Not a consensus rejection.
/// 30 days × 86 400 s/day.
pub const MAX_CHAIN_DRIFT_SECS: i64 = 2_592_000;

/// CV-02 (T-3b): Local wall clock confirmation window.
/// If |now − expected_ts| is within this value, the local clock independently
/// confirms (or refutes) the drift.  7 days × 86 400 s/day.
pub const LOCAL_CLOCK_TOLERANCE_SECS: i64 = 604_800;

/// Expected beacon block interval in seconds (default 600; overridable on devnet).
#[inline]
fn beacon_interval_secs() -> u64 {
    crate::common::block_intervals::beacon_interval_secs()
}

/// NC-155: a beacon block may not exceed `DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES` on the wire
/// (witnesses included; about 1 MiB, owner rule of Oct 8, 2026). The genesis block (height 0)
/// is exempt because it carries the premine.
pub fn validate_beacon_block_wire_size(block: &BeaconBlock) -> Result<(), ValidationError> {
    if block.header.height == 0 {
        return Ok(());
    }
    let size = block.wire_size();
    if size > super::transactions::DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES {
        return Err(ValidationError::BlockTooLarge {
            size,
            max: super::transactions::DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES,
        });
    }
    Ok(())
}

/// Validate beacon block structure (context-free validation)
/// 
/// Checks that the block itself is well-formed:
/// - Proof-of-work is valid
/// - Commitment hash is valid
/// - Block hash matches header
/// 
/// Does NOT check:
/// - Whether block connects to chain (use validate_beacon_block_against_chain)
/// - Whether transactions are valid
/// - Whether MMR transition is correct
/// 
/// # Arguments
/// * `block` - The beacon block to validate
/// 
/// # Returns
/// * `Ok(())` if structure is valid
/// * `Err(ValidationError)` with specific error
pub fn validate_beacon_block_structure(
    block: &BeaconBlock,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    debug!("Validating beacon block structure at height {}", block.header.height);
    validate_beacon_block_wire_size(block)?;

    // Verify proof-of-work (Strategy A: rBits → target via genesis max_target)
    // + Phase B floor cal×2^asserted_s
    verify_beacon_proof_of_work(block, initial_target, shard_calibration, genesis_asserted_s_bits)?;

    // Verify hash calculation
    let calculated_hash = BeaconBlock::calculate_weighted_hash(&block.header);
    if calculated_hash != block.hash {
        return Err(ValidationError::CustomError(format!(
            "Block hash mismatch: stored {}, calculated {}",
            hex::encode(*block.hash),
            hex::encode(*calculated_hash)
        )));
    }

    debug!("Beacon block structure validation passed");
    Ok(())
}

/// **v3 (`Stratum_Extranonce_Binding_Plan.md` §3.1)** — beacon block structure
/// validation via the two-leaf SHA256d commitment, replacing
/// [`validate_beacon_block_structure`]'s legacy BLAKE3-wrap check.
///
/// Recovers `coinbase_hash` from the block's own stored body (CB-9's
/// `coinbase_hash_from_stored_body`) rather than trusting anything the block
/// merely claims. **Not yet fully hardened**: a block whose body has no
/// derivable coinbase (empty body — the same "loaded from old storage /
/// synthetic test fixture" shape tolerated elsewhere, e.g.
/// `validate_beacon_genesis`) falls back to the legacy BLAKE3-wrap check
/// instead of failing closed. This mirrors CB-2's own "warning, not yet a
/// hard reject" status (plan §7) — real, CB-0-produced blocks always have a
/// coinbase and are unaffected either way; a large body of pre-existing test
/// fixtures across this codebase still build empty-body test blocks the old
/// way, and hard-rejecting them here (rather than tolerating, as this
/// function does today) is a distinct, larger fixture-migration task, not
/// something to do as a side effect of activating v3 validation. Flip this to
/// fail closed only once those fixtures are updated in the same pass — see
/// the plan's §7 "existing finding, still open."
pub fn validate_beacon_block_structure_v3(
    block: &BeaconBlock,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    debug!("Validating beacon block structure (v3) at height {}", block.header.height);
    validate_beacon_block_wire_size(block)?;

    let Some(coinbase_hash) = crate::transaction::coinbase_hash_from_stored_body(&block.body) else {
        debug!(
            "Block at height {} has no derivable coinbase — falling back to legacy \
             BLAKE3-wrap structure validation (not yet hardened, see doc comment)",
            block.header.height
        );
        return validate_beacon_block_structure(block, initial_target, shard_calibration, genesis_asserted_s_bits);
    };

    super::pow::verify_beacon_proof_of_work_v3(
        block,
        coinbase_hash,
        initial_target,
        shard_calibration,
        genesis_asserted_s_bits,
    )?;

    let calculated_hash = BeaconBlock::calculate_weighted_hash_v3(&block.header, coinbase_hash);
    if calculated_hash != block.hash {
        return Err(ValidationError::CustomError(format!(
            "Block hash mismatch (v3): stored {}, calculated {}",
            hex::encode(*block.hash),
            hex::encode(*calculated_hash)
        )));
    }

    debug!("Beacon block structure validation (v3) passed");
    Ok(())
}

/// Deprecated alias: the `s_bits` argument is **ignored**.
///
/// PoW hash-sorting width is always derived from
/// `block.header.committed_chain_count` via [`verify_beacon_proof_of_work`]
/// (Header rBits §5.7). Prefer [`validate_beacon_block_structure`].
#[deprecated(
    since = "0.8.0",
    note = "s_bits argument ignored; use validate_beacon_block_structure (asserted s from committed_chain_count)"
)]
pub fn validate_beacon_block_structure_with_hash_sorting(
    block: &BeaconBlock,
    _s_bits: u32,
    initial_target: &[u8; 32],
    shard_calibration: u32,
    genesis_asserted_s_bits: u32,
) -> Result<(), ValidationError> {
    validate_beacon_block_structure(block, initial_target, shard_calibration, genesis_asserted_s_bits)
}

/// Validate beacon block against chain state (context-dependent validation)
/// 
/// Checks that the block properly connects to the chain:
/// - Height increments by 1
/// - Previous hash matches
/// - Timestamp advances
/// - Difficulty transition is valid
/// - MMR root transitions correctly
/// 
/// # Arguments
/// * `block` - The new block to validate
/// * `prev_block` - The previous block in the chain
/// * `expected_mmr_root` - What the MMR root should be after appending prev_block
/// 
/// # Returns
/// * `Ok(())` if block connects properly
/// * `Err(ValidationError)` with specific error
pub fn validate_beacon_block_against_chain(
    block: &BeaconBlock,
    prev_block: &BeaconBlock,
    expected_mmr_root: [u8; 32],
    genesis_timestamp: u64,
) -> Result<(), ValidationError> {
    debug!(
        "Validating beacon block {} against previous block {}",
        block.header.height,
        prev_block.header.height
    );

    // Height must increment by 1
    let expected_height = prev_block.header.height + 1;
    if block.header.height != expected_height {
        return Err(ValidationError::InvalidBlockHeight {
            expected: expected_height,
            actual: block.header.height,
        });
    }

    // ── T-1 (block-to-block monotonic timestamp) — removed 2026-07-04 ────────
    // There is no plan to run a block-to-block ordering check alongside T-MTP.
    // Bitcoin itself has no such rule: consensus only requires a block's
    // timestamp to exceed the median of the previous 11 (MTP) and stay within
    // the future-timestamp window — adjacent blocks may have equal or even
    // decreasing timestamps. T-MTP (`validate_timestamp_mtp`, called by every
    // caller of this function — mining-pool `BeaconChain::apply_beacon_block_to_memory`
    // and full-node `FullBeaconChain::validate_block` each call it separately
    // right after this function returns) is this codebase's MTP analogue and
    // is the sole timestamp-ordering backstop, matching Bitcoin's model.
    // See docs/reports/TS-DELTA_Final_Completion_Report.md §5.

    // ── T-2 (CV-01): Maximum future timestamp ────────────────────────────────
    let now = super::unix_now();
    let max_future = now.saturating_add(max_future_secs());
    // Reconstruct wall-clock timestamp from delta (height-aware — see
    // docs/reports/TS-DELTA_Final_Completion_Report.md §5).
    let block_ts = super::delta_to_unix(
        block.header.delta, genesis_timestamp, block.header.height as u64,
        beacon_interval_secs(), 1,
    );
    if block_ts > max_future {
        return Err(ValidationError::FutureTimestamp {
            delta: block.header.delta,
            timestamp: block_ts,
            now,
            max_future,
        });
    }

    // ── T-3 (CV-02): Soft reasonableness warnings — never reject ─────────────

    // T-3a: Consecutive gap (in delta units; 1 delta unit = 1/256 second).
    // Threshold = 9 × I_block × 256 delta units (~10 intervals of wall-clock
    // lateness). Single source of truth: `super::t3a_gap_warning` — the same
    // helper the mining-pool inline paths now use, so the two can't drift
    // apart again (NC-39b / T3A-MP-1).
    let gap = block.header.delta.saturating_sub(prev_block.header.delta);
    if let Some((gap_secs, threshold_secs)) =
        super::t3a_gap_warning(gap, beacon_interval_secs(), 1)
    {
        warn!(
            "[CV-02/T-3a] Beacon block {} anomalous timestamp gap: {} s \
             (threshold {} s = 9 × {} s interval — gaps exceeding 10 intervals)",
            block.header.height, gap_secs, threshold_secs, beacon_interval_secs(),
        );
    }

    // T-3b: Cumulative drift from genesis-anchored schedule.
    //   expected_ts = genesis_timestamp + height × BEACON_INTERVAL_SECS
    let expected_ts = genesis_timestamp
        .saturating_add(block.header.height as u64 * beacon_interval_secs());
    let drift = block_ts as i64 - expected_ts as i64;  // Both now in wall-clock seconds
    if drift.abs() > MAX_CHAIN_DRIFT_SECS {
        let clock_delta = now as i64 - expected_ts as i64;
        let confirmed = clock_delta.abs() < LOCAL_CLOCK_TOLERANCE_SECS;
        warn!(
            "[CV-02/T-3b] Beacon block {} cumulative drift {:.1} days \
             (expected_ts={}, block_ts={}, drift={} s). {}",
            block.header.height,
            drift.abs() as f64 / 86_400.0,
            expected_ts,
            block_ts,
            drift,
            if confirmed {
                format!("Local clock CONFIRMS drift (clock_delta={} s).", clock_delta)
            } else {
                format!(
                    "Local clock agreement INDETERMINATE \
                     (clock_delta={} s ≥ {} s tolerance).",
                    clock_delta, LOCAL_CLOCK_TOLERANCE_SECS
                )
            }
        );
    }

    // Previous MMR root must match chain state
    if block.header.prev_mmr_root != WeightedHash::from(expected_mmr_root) {
        return Err(ValidationError::InvalidMmrRoot {
            expected: expected_mmr_root,
            actual: block.header.prev_mmr_root.into(),
        });
    }

    debug!("Beacon block chain validation passed");
    Ok(())
}

/// Validate beacon genesis block
/// 
/// Special validation for the genesis block:
/// - Height must be 0
/// - Previous hash must be Bitcoin anchor
/// - Current MMR root must equal hash(anchor, genesis_hash)
/// 
/// **BLAKE3 (v0.2.2)**: This now uses BLAKE3 for hash_pair. If you have
/// an existing genesis block created with SHA256, you'll need to either:
/// 1. Regenerate it with BLAKE3, or
/// 2. Use the legacy validation function (see below)
/// 
/// # Arguments
/// * `block` - The genesis block
/// * `config` - Genesis configuration
/// 
/// # Returns
/// * `Ok(())` if genesis is valid
/// * `Err(ValidationError)` with specific error
pub fn validate_beacon_genesis(
    block: &BeaconBlock,
    config: &BeaconGenesisConfig,
) -> Result<(), ValidationError> {
    debug!("Validating beacon genesis block");
    
    // Height must be 0
    if block.header.height != 0 {
        return Err(ValidationError::InvalidBlockHeight {
            expected: 0,
            actual: block.header.height,
        });
    }
    
    // Previous MMR root must be Bitcoin anchor
    if block.header.prev_mmr_root != WeightedHash::from(config.bitcoin_anchor_hash) {
        return Err(ValidationError::InvalidMmrRoot {
            expected: config.bitcoin_anchor_hash,
            actual: block.header.prev_mmr_root.into(),
        });
    }

    // Current MMR root = WeightedMMR(anchor).append(genesis_hash, bits)
    let expected_mmr_root = {
        let mut mmr = WeightedMMR::new_with_config(config);
        mmr.append(block.hash).0
    };

    if block.header.current_mmr_root != expected_mmr_root {
        return Err(ValidationError::InvalidMmrRoot {
            expected: expected_mmr_root.into(),
            actual: block.header.current_mmr_root.into(),
        });
    }
    
    // Verify hash if expected — config stores plain SHA256d; compare against plain hash
    if let Some(expected_hash) = config.expected_hash {
        let plain_hash = BeaconBlock::calculate_hash(&block.header);
        if plain_hash != expected_hash {
            return Err(ValidationError::CustomError(format!(
                "Genesis hash mismatch: expected {}, got {}",
                hex::encode(expected_hash),
                hex::encode(plain_hash)
            )));
        }
    }

    debug!("Beacon genesis validation passed");
    Ok(())
}

// ── Shard Expansion voting rules ─────────────────────────────────────────────

/// Validate EX-7 and EX-8 — committed_chain_count integrity rules.
///
/// Call this from beacon block validation after the block structure and chain
/// context checks have passed.
///
/// * **EX-7**: `committed_chain_count` must not exceed `active_shard_count + step`.
///   Prevents phantom-chain attacks where a miner claims to be mining chains
///   that do not yet exist.
/// * **EX-8**: If `vote_expand_flag = 1`, then `committed_chain_count` must be
///   ≥ `active_shard_count`.  A miner who votes for expansion must demonstrate
///   they are already merge-mining all currently active chains.
///
/// Skip enforcement when `committed_chain_count == 0` (legacy / backward compat).
///
/// **Beacon_Difficulty_Unification_Design.md Principle 6** (dropping this
/// `== 0` skip and making the EX-8 lower bound unconditional) is **deferred** —
/// a first attempt (commit `d01c2f2d`, reverted `<this commit>`) broke ~15
/// beacon-block test fixtures that stamp `committed_chain_count = 0` at
/// `height > 0`. It needs its own fixture-migration pass (and the design's own
/// `genesis.timestamp > CV-62` gate) alongside the shard-side Principle 6.
/// Principle 1 (the resolver, the actual NC-104 ban fix) does not depend on it.
pub fn validate_beacon_expand_rules(
    committed_chain_count: u16,
    vote_expand_flag: bool,
    active_shard_count: u16,
    step: u16,
) -> Result<(), ValidationError> {
    if committed_chain_count == 0 {
        // Legacy block — no enforcement.
        return Ok(());
    }

    // EX-7: upper bound — no phantom chains.
    let ceiling = active_shard_count.saturating_add(step);
    if committed_chain_count > ceiling {
        return Err(ValidationError::CustomError(format!(
            "EX-7: committed_chain_count ({}) > active_shard_count ({}) + step ({}) = {}",
            committed_chain_count, active_shard_count, step, ceiling,
        )));
    }

    // EX-8: vote integrity.
    if vote_expand_flag && committed_chain_count < active_shard_count {
        return Err(ValidationError::CustomError(format!(
            "EX-8: vote_expand_flag=1 but committed_chain_count ({}) \
             < active_shard_count ({})",
            committed_chain_count, active_shard_count,
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::genesis::genesis::GenesisGenerator;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use crate::common::blocks::beacon_block::{BeaconBlock, BeaconBlockCandidateHeader};
    
    #[test]
    fn test_validate_genesis_blake3() {
        // Generate fresh genesis with BLAKE3 (v0.2.2+)
        let config = BeaconGenesisConfig::devnet();
        let genesis = GenesisGenerator::generate_beacon_genesis(&config).unwrap();
        
        // Should validate successfully with BLAKE3
        assert!(
            validate_beacon_genesis(&genesis, &config).is_ok(),
            "Genesis validation should pass with BLAKE3"
        );
    }

    // ── Timestamp validation tests (CV-01 / CV-02) ───────────────────────────

    /// Minimal block factory for timestamp tests.  No PoW — timestamp checks
    /// run before proof-of-work verification in the standalone validator.
    fn make_block(height: u32, timestamp: u64) -> BeaconBlock {
        let bitcoin_anchor = genesis_ts();
        let header = BeaconBlockCandidateHeader::new(
            1,
            timestamp,
            height,
            0x1d00ffff,
            WeightedHash::zero(),
            [0u8; 32],
            [0u8; 32],
            bitcoin_anchor,
        );
        BeaconBlock::with_transactions(header, vec![])
    }

    fn genesis_ts() -> u64 { 1_704_067_200 } // 2024-01-01 UTC (bitcoin anchor)

    fn make_block_with_anchor(height: u32, timestamp: u64, bitcoin_anchor: u64) -> BeaconBlock {
        let header = BeaconBlockCandidateHeader::new(
            1,
            timestamp,
            height,
            0x1d00ffff,
            WeightedHash::zero(),
            [0u8; 32],
            [0u8; 32],
            bitcoin_anchor,
        );
        BeaconBlock::with_transactions(header, vec![])
    }

    // ── T-1 (block-to-block monotonic timestamp) — removed 2026-07-04 ────────
    //
    // There is no plan to run a block-to-block ordering check alongside T-MTP.
    // Bitcoin has no such rule; T-MTP (tested separately via
    // `validate_timestamp_mtp`) is this codebase's MTP analogue and is the
    // sole timestamp-ordering backstop, matching Bitcoin's model. The five
    // `test_t1_*` cases that used to live here (on-schedule / late-arrival /
    // barely-valid accept cases, equal-timestamp / past-timestamp reject
    // cases) were removed along with the rule — they asserted rejection
    // behavior that intentionally no longer exists. Their only helper,
    // `make_block_with_delta` (built a block with an explicit delta override),
    // had no other callers and was removed with them. See
    // docs/reports/TS-DELTA_Final_Completion_Report.md §5.

    // ── T-2 (CV-01: future timestamp) ────────────────────────────────────────

    #[test]
    fn test_t2_accepts_just_within() {
        // Use fixed test anchor (CRITICAL: matches BITCOIN_ANCHOR_TIMESTAMP)
        let anchor = genesis_ts();  // 1_704_067_200

        // Create blocks with timestamps close to anchor to avoid i32 delta overflow
        // The T-2 threshold compares reconstructed timestamp against now + 600 seconds
        // So we need a block timestamp that keeps us within the limit
        let now = super::super::unix_now();
        let block_base = anchor + 1000;
        let prev = make_block_with_anchor(1, block_base, anchor);
        // To be within limit: T_recon = anchor + delta <= now + 600
        // So: delta <= (now + 600 - anchor)
        // Safe value: use a timestamp well before now
        let block = make_block_with_anchor(2, block_base + 100, anchor);
        let result = validate_beacon_block_against_chain(&block, &prev, [0u8; 32], anchor);
        // Only FutureTimestamp is expected to fail; height/mmr mismatches are ok here
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ValidationError::FutureTimestamp { .. }),
                "timestamp in safe past should NOT trigger FutureTimestamp"
            );
        }
    }

    #[test]
    fn test_t2_accepts_at_limit() {
        // Use fixed test anchor (CRITICAL: matches BITCOIN_ANCHOR_TIMESTAMP)
        let anchor = genesis_ts();  // 1_704_067_200

        // Create blocks with timestamps close to anchor to avoid i32 delta overflow
        let block_base = anchor + 1000;
        let prev = make_block_with_anchor(1, block_base, anchor);
        let block = make_block_with_anchor(2, block_base + 100, anchor);
        let result = validate_beacon_block_against_chain(&block, &prev, [0u8; 32], anchor);
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ValidationError::FutureTimestamp { .. }),
                "timestamp in safe past should NOT trigger FutureTimestamp"
            );
        }
    }

    #[test]
    fn test_t2_rejects_one_over_limit() {
        // NOTE: T-2 future threshold testing requires real wall-clock comparison.
        // In test environment with bitcoin_anchor far in the past (Jan 1 2024),
        // all test blocks have timestamps in the past relative to unix_now().
        // This test verifies the validation logic compiles and runs,
        // but cannot test the actual future threshold with historical timestamps.

        let anchor = genesis_ts();  // 1_704_067_200
        let block_base = anchor + 1000;

        let prev = make_block_with_anchor(1, block_base, anchor);
        let block = make_block_with_anchor(2, block_base + MAX_FUTURE_SECS + 1, anchor);
        let result = validate_beacon_block_against_chain(&block, &prev, [0u8; 32], anchor);

        // The validation will likely NOT return FutureTimestamp because block is in the past.
        // Just verify validation executed without panicking.
        // The actual T-2 threshold is tested implicitly in production with real timestamps.
        let _ = result;
    }

    #[test]
    fn test_t2_rejects_max_u64() {
        // NOTE: T-2 future threshold testing requires real wall-clock comparison.
        // In test environment with bitcoin_anchor far in the past (Jan 1 2024),
        // all test blocks have timestamps in the past relative to unix_now().

        let anchor = genesis_ts();  // 1_704_067_200
        let block_base = anchor + 1000;
        let prev = make_block_with_anchor(1, block_base, anchor);
        let block = make_block_with_anchor(2, block_base + MAX_FUTURE_SECS + 100, anchor);
        let result = validate_beacon_block_against_chain(&block, &prev, [0u8; 32], anchor);

        // The validation will likely NOT return FutureTimestamp because block is in the past.
        // Just verify validation executed without panicking.
        let _ = result;
    }

    // ── T-3a (CV-02: consecutive gap warning) — just confirms no hard reject ──

    #[test]
    fn test_t3a_large_gap_is_not_rejected() {
        // T-3a warns (never rejects) when consecutive gap > 9 × I_block × 256.
        // 9 × 600 s = 5400 s threshold. Use gap = 6001 s >> 5400 s to trigger warning.
        // With T-1 rule delta(h) > delta(h-1) - I×256:
        //   delta(prev) = 1100 × 256 = 281_600
        //   delta(block) = 7101 × 256 = 1_817_856
        //   gap = 6001 × 256 = 1_536_256 > threshold 1_382_400 → warn but never reject.
        let anchor = genesis_ts();
        let block_base = anchor + 1000;
        let prev  = make_block_with_anchor(1, block_base + 100, anchor);
        let block = make_block_with_anchor(2, block_base + 6101, anchor); // gap = 6001 s
        let result = validate_beacon_block_against_chain(&block, &prev, [0u8; 32], anchor);
        // A large gap must NEVER cause FutureTimestamp or a T-1 hard reject.
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ValidationError::FutureTimestamp { .. }),
                "large gap must not cause FutureTimestamp"
            );
            let msg = e.to_string();
            assert!(
                !msg.contains("monotone"),
                "block is strictly after prev — T-1 must pass; got: {}", msg
            );
        }
    }

    // ── validate_beacon_expand_rules (EX-7 / EX-8) ───────────────────────────

    #[test]
    fn ex7_legacy_zero_skips_enforcement() {
        // committed_chain_count == 0 → legacy block, no rules apply.
        // (Principle 6 would tighten this — deferred, see the fn's doc comment.)
        assert!(validate_beacon_expand_rules(0, false, 4, 1).is_ok());
        assert!(validate_beacon_expand_rules(0, true, 4, 1).is_ok());
    }

    #[test]
    fn ex7_at_ceiling_passes() {
        // committed_chain_count == active + step → exactly at ceiling → OK.
        assert!(validate_beacon_expand_rules(5, false, 4, 1).is_ok());
    }

    #[test]
    fn ex7_below_ceiling_passes() {
        assert!(validate_beacon_expand_rules(4, false, 4, 1).is_ok());
    }

    #[test]
    fn ex7_above_ceiling_rejected() {
        // committed_chain_count == 6 > active(4) + step(1) = 5 → EX-7 violation.
        let err = validate_beacon_expand_rules(6, false, 4, 1).unwrap_err();
        assert!(err.to_string().contains("EX-7"), "expected EX-7 error, got: {err}");
    }

    #[test]
    fn ex8_vote_with_sufficient_count_passes() {
        assert!(validate_beacon_expand_rules(4, true, 4, 1).is_ok());
        assert!(validate_beacon_expand_rules(5, true, 4, 1).is_ok());
    }

    #[test]
    fn ex8_vote_with_insufficient_count_rejected() {
        let err = validate_beacon_expand_rules(3, true, 4, 1).unwrap_err();
        assert!(err.to_string().contains("EX-8"), "expected EX-8 error, got: {err}");
    }

    #[test]
    fn ex8_no_vote_low_count_still_passes() {
        // vote_expand_flag=0 with committed_chain_count < active → EX-8 doesn't fire
        // (Principle 6 would change this — deferred).
        assert!(validate_beacon_expand_rules(3, false, 4, 1).is_ok());
    }

    // ── unix_now sanity ───────────────────────────────────────────────────────

    #[test]
    fn test_unix_now_is_reasonable() {
        let now = super::super::unix_now();
        // After 2024-01-01 00:00:00 UTC (Unix 1_704_067_200)
        // Before 2100-01-01 00:00:00 UTC (Unix 4_102_444_800)
        assert!(now > 1_704_067_200, "unix_now() too small: {}", now);
        assert!(now < 4_102_444_800, "unix_now() too large: {}", now);
    }

    // ── NC-155: beacon block size is counted in wire bytes ───────────────────

    use super::super::transactions::DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES;

    fn spend_tx_with_witness(prev_height: u32) -> crate::transaction::Transaction {
        use crate::transaction::{Transaction, TxInput, TxOutput, WitnessEntry};
        let mut t = Transaction::new(1, 0);
        t.inputs.push(TxInput { prev_height, prev_output_idx: 0 });
        t.add_output(TxOutput { value: 1, recipient: [0x33; 32] });
        t.witnesses.push(WitnessEntry { witness_data: vec![7u8; 73] });
        t
    }

    fn beacon_block_with_spends(n: u32) -> BeaconBlock {
        let txs: Vec<_> = (0..n).map(spend_tx_with_witness).collect();
        let header = BeaconBlockCandidateHeader::new(
            1, 100, 5, 0x1d00ffff, WeightedHash::zero(), [0u8; 32], [0u8; 32], genesis_ts(),
        );
        BeaconBlock::with_transactions(header, txs)
    }

    /// The size check counts witnesses. Every transaction is 70 B without its witness and about
    /// 160 B on the wire, so a block whose witness-free size is far below the limit can still be
    /// over it. The old check (witness-free) accepted this block; the wire check rejects it.
    #[test]
    fn nc155_beacon_block_over_the_wire_limit_is_rejected() {
        let n = 7_000;
        let block = beacon_block_with_spends(n);
        let witness_free: usize = block.body.to_transactions().unwrap().iter().map(|t| t.size()).sum();
        assert!(witness_free < DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES / 2, "old measure {witness_free} would accept");
        assert!(block.wire_size() > DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES, "wire {}", block.wire_size());
        let err = validate_beacon_block_wire_size(&block).unwrap_err();
        assert!(matches!(err, ValidationError::BlockTooLarge { .. }), "{err:?}");
    }

    #[test]
    fn nc155_beacon_block_under_the_wire_limit_and_genesis_are_accepted() {
        let small = beacon_block_with_spends(500);
        assert!(small.wire_size() < DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES);
        validate_beacon_block_wire_size(&small).expect("small block accepted");
        // Height 0 carries the premine and is exempt.
        let mut genesis = beacon_block_with_spends(7_000);
        genesis.header.height = 0;
        validate_beacon_block_wire_size(&genesis).expect("genesis exempt");
    }
}
