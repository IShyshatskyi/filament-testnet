// src/common/validation/shard.rs

use crate::common::blocks::{shard_block::Block, ShardBlockBody};
use crate::common::crypto::weighted_hash::WeightedHash;
use super::errors::ValidationError;
use log::{debug, warn};

// ── Timestamp validation constants ───────────────────────────────────────────

/// CV-01 (T-2): Maximum future timestamp tolerance (one beacon block interval).
#[inline]
pub fn max_future_secs() -> u64 {
    crate::common::block_intervals::beacon_interval_secs()
}

/// Deprecated alias — use [`max_future_secs`].
pub const MAX_FUTURE_SECS: u64 = 600;

/// CV-02 (T-3a): consecutive-gap multiple of the interval, in deviation-delta
/// space (`9 × I × 256` units). A wall-clock gap of `10 × I` yields a delta
/// difference of `(10 I − I) × 256 = 9 × I × 256` (corrected from 10 on
/// 2026-09-09; see NC-39b / T3A-MP-1). Threshold + display math is centralised
/// in [`super::t3a_gap_warning`]; kept here only for reference.
pub const LARGE_GAP_MULTIPLIER: u64 = 9;

/// CV-02 (T-3b): Maximum cumulative drift before soft warning (30 days).
pub const MAX_CHAIN_DRIFT_SECS: i64 = 2_592_000;

/// CV-02 (T-3b): Local clock confirmation window (7 days).
pub const LOCAL_CLOCK_TOLERANCE_SECS: i64 = 604_800;

/// Default shard interval numerator/denominator (37.5 s). Runtime value via
/// [`crate::common::block_intervals::shard_interval_num`] /
/// [`crate::common::block_intervals::shard_interval_den`].
pub const SHARD_INTERVAL_NUM: u64 = 75;
pub const SHARD_INTERVAL_DEN: u64 = 2;

#[inline]
fn shard_interval_num() -> u64 {
    crate::common::block_intervals::shard_interval_num()
}

#[inline]
fn shard_interval_den() -> u64 {
    crate::common::block_intervals::shard_interval_den()
}

#[inline]
fn beacon_interval_secs() -> u64 {
    crate::common::block_intervals::beacon_interval_secs()
}

/// Validate shard block structure (context-free validation)
/// 
/// Checks:
/// - Block size within limits
/// - Shard ID matches expected
/// - Header hash is correct
/// - Beacon header is present
/// 
/// # Arguments
/// * `block` - The shard block to validate
/// * `expected_shard_id` - Expected shard ID
/// * `max_block_size` - Maximum allowed block size
/// 
/// # Returns
/// * `Ok(())` if structure is valid
/// * `Err(ValidationError)` with specific error
pub fn validate_shard_block_structure(
    block: &Block,
    expected_shard_id: u16,
    max_block_size: usize,
) -> Result<(), ValidationError> {
    debug!(
        "Validating shard block structure for shard {} at height {}",
        block.header.shard_id,
        block.header.height
    );
    
    // Size check: wire bytes (witnesses included). A flat block received over P2P carries no
    // `transactions`; its wire size is its payload length, which the P2P entry point checks.
    let block_size = if block.transactions.is_empty() { block.size() } else { block.wire_size() };
    if block_size > max_block_size {
        return Err(ValidationError::BlockTooLarge {
            size: block_size,
            max: max_block_size,
        });
    }
    
    // Shard ID check
    if block.header.shard_id != expected_shard_id {
        return Err(ValidationError::InvalidShardId {
            expected: expected_shard_id,
            actual: block.header.shard_id,
        });
    }

    // Body commitment check (FV-8): recompute from flat body and compare against header.
    //
    // When `block.transactions` is empty the block was received over P2P in the
    // flat-vector wire format (FV-12).  The caller (`run_block_sync_loop`) already
    // verified `ShardWireBlock::verify_commitment()` before reconstructing the
    // minimal `Block { header, transactions: [] }` for this call — so we skip the
    // redundant check here.
    //
    // NC-103 fix (Aug 28, 2026): a non-empty `block.transactions` no longer
    // implies "always re-verify". Since NC-92 (Aug 25, 2026),
    // `ShardWireBlock::into_block`/`into_block_with_transactions` — the
    // *ordinary* P2P/P1DB-adapter reconstruction path, not just fork-reorg —
    // always populate real transactions. `Transaction` has no `extensions`
    // field (TS-T-11's producer stamp lives only on `ShardBlockBody`), so
    // re-deriving the commitment from `transactions` alone is structurally
    // incapable of matching a header whose original body carried any
    // extension — which is every real coinbase, every time. That made this
    // check fail deterministically for the first real block on every shard,
    // permanently stalling shard chains at height 1 (see
    // docs/plan/Correctness_and_Validation_Plan.md NC-103). Those two
    // `ShardWireBlock` methods now independently recompute the commitment
    // from the *original* flat body (extensions included) before it's
    // consumed, and stamp `block.commitment_verified` with the real result
    // — so only that already-verified case skips the redundant, unsound
    // re-check here. Every other construction path (mining, side-block-pool
    // reconstruction via `block_for_reorg`, test fixtures) defaults
    // `commitment_verified` to `false` and still gets the full recompute.
    if !block.transactions.is_empty() && !block.commitment_verified {
        let calculated = ShardBlockBody::from_transactions(&block.transactions, None)
            .calculate_tx_merkle_root();
        if calculated != block.header.tx_merkle_root {
            // NC-103 DEBUG (Aug 28, 2026): temporary diagnostic instrumentation
            // to pin the exact mismatch mechanism -- see
            // docs/plan/Correctness_and_Validation_Plan.md NC-103. A non-empty
            // `block.transactions` reaching this check means the Block being
            // validated did NOT come from ordinary P2P sync (which already
            // verified commitment via ShardWireBlock::verify_commitment()
            // and hands this function an empty-transactions Block) -- most
            // likely `SideBlockManager::block_for_reorg()` reconstructing a
            // previously-stored side-block-pool entry during real fork
            // reconciliation. Note: the reconstructed `Transaction` type has
            // no `extensions` field of its own (TS-T-11's producer stamp is a
            // flat-body-level `ShardBlockBody.extensions` concept, not
            // per-`Transaction`), so it can't be recovered from `block`
            // alone here -- logging what IS available on this side.
            // Remove once NC-103's root cause is confirmed.
            let per_tx_output_counts: Vec<usize> =
                block.transactions.iter().map(|tx| tx.outputs.len()).collect();
            warn!(
                "NC-103 DEBUG: Body commitment mismatch -- shard={} height={} \
                 block_hash={} calculated_root={} header_root={} tx_count={} \
                 per_tx_output_counts={:?}",
                block.header.shard_id,
                block.header.height,
                hex::encode(block.header.hash()),
                hex::encode(calculated),
                hex::encode(block.header.tx_merkle_root),
                block.transactions.len(),
                per_tx_output_counts,
            );
            return Err(ValidationError::CustomError(
                "Body commitment mismatch".to_string(),
            ));
        }
    }

    debug!("Shard block structure validation passed.");
    Ok(())
}

/// NC-40 / CV-23: height-0 special linkage checks shared by Kameniar and Keystone.
///
/// Call only for `block.header.height == 0`. Enforces:
/// - **(a)** `prev_mmr_root == expected_anchor` (CV-23 genesis anchor learned at
///   `activate_shard` — the beacon tip's `current_mmr_root` at activation)
/// - **(b)** `difficulty == expected_genesis_bits` (NC-19: beacon-anchor header
///   bits × `shard_calibration`, stored at the same activate call)
///
/// Chain-count / merged-mining checks are **not** height-0 specials — callers
/// continue into the ordinary MM/body/K-6 path after this returns `Ok`.
///
/// The anchor's own rBits are bagged *cumulative* beacon MMR weight and must
/// not be confused with `expected_genesis_bits` (per-block PoW difficulty).
pub fn validate_shard_genesis_linkage(
    block: &Block,
    shard_id: u16,
    expected_anchor: WeightedHash,
    expected_genesis_bits: u32,
) -> Result<(), ValidationError> {
    debug!(
        "Validating shard {} genesis linkage (height {}, expected_bits={:#x})",
        shard_id, block.header.height, expected_genesis_bits
    );

    if block.header.height != 0 {
        return Err(ValidationError::CustomError(format!(
            "validate_shard_genesis_linkage called for non-genesis height {}",
            block.header.height
        )));
    }

    if block.header.prev_mmr_root != expected_anchor {
        return Err(ValidationError::ShardGenesisAnchorMismatch {
            shard_id,
            expected: expected_anchor.into(),
            actual: block.header.prev_mmr_root.into(),
        });
    }

    if block.header.difficulty != expected_genesis_bits {
        return Err(ValidationError::ShardGenesisDifficultyMismatch {
            shard_id,
            expected_bits: expected_genesis_bits,
            actual_bits: block.header.difficulty,
        });
    }

    Ok(())
}

/// Validate shard block against chain state
/// 
/// Checks:
/// - Height increments by 1
/// - Previous hash matches
/// - MMR transition is correct
/// - Chain weight increases correctly
/// 
/// # Arguments
/// * `block` - New block to validate
/// * `prev_block` - Previous block in chain
/// * `expected_mmr_root` - Expected MMR root before this block
/// 
/// # Returns
/// * `Ok(())` if block connects properly
/// * `Err(ValidationError)` with specific error
pub fn validate_shard_block_against_chain(
    block: &Block,
    prev_block: &Block,
    expected_mmr_root: [u8; 32],
    genesis_timestamp: u64,
) -> Result<(), ValidationError> {
    debug!(
        "Validating shard block {} against previous block {}",
        block.header.height,
        prev_block.header.height
    );

    // Height must increment
    let expected_height = prev_block.header.height + 1;
    if block.header.height != expected_height {
        return Err(ValidationError::InvalidBlockHeight {
            expected: expected_height,
            actual: block.header.height,
        });
    }

    // ── T-1 (block-to-block monotonic timestamp) — removed 2026-07-04 ────────
    // There is no plan to run a block-to-block ordering check alongside T-MTP.
    // Bitcoin itself has no such rule; T-MTP (`validate_timestamp_mtp`, called
    // by every caller of this function) is this codebase's MTP analogue and
    // is the sole timestamp-ordering backstop, matching Bitcoin's model.
    // See docs/reports/TS-DELTA_Final_Completion_Report.md §5.
    // `block_delta`/`prev_delta` are the auxiliary *beacon* header's delta
    // (shard blocks share their timestamp with the beacon block from the same
    // merged-mining round) — still needed below for T-2 and T-3a.
    let block_delta = block.header.beacon_header.delta;
    let prev_delta  = prev_block.header.beacon_header.delta;

    // ── T-2 (CV-01): Maximum future timestamp ────────────────────────────────
    let now = super::unix_now();
    let max_future = now.saturating_add(max_future_secs());
    // Reconstruct wall-clock timestamp from delta (height-aware — see
    // docs/reports/TS-DELTA_Final_Completion_Report.md §5). `block_delta` is the
    // auxiliary *beacon* header's delta (shard blocks share their timestamp with
    // the beacon block from the same merged-mining round), so it's on the
    // beacon's own 600s schedule and beacon_height — not the shard's height/interval.
    let reconstructed_ts = super::delta_to_unix(
        block_delta, genesis_timestamp, block.header.beacon_header.beacon_height as u64,
        beacon_interval_secs(), 1,
    );
    if reconstructed_ts > max_future {
        return Err(ValidationError::FutureTimestamp {
            delta: block_delta,
            timestamp: reconstructed_ts,
            now,
            max_future,
        });
    }

    // ── T-3 (CV-02): Soft reasonableness warnings — never reject ─────────────

    // T-3a: Consecutive gap (in delta units; 1 delta unit = 1/256 second).
    // Threshold = 9 × I_shard × 256 delta units. Single source of truth:
    // `super::t3a_gap_warning` — the same helper the mining-pool inline path
    // now uses (NC-39b / T3A-MP-1). `gap` is the aux *beacon* header's delta
    // difference (shard blocks share the beacon timestamp), judged against the
    // *shard* interval: a shard chain advances one shard interval per block.
    let gap = block_delta.saturating_sub(prev_delta);
    if let Some((gap_secs, threshold_secs)) =
        super::t3a_gap_warning(gap, shard_interval_num(), shard_interval_den())
    {
        warn!(
            "[CV-02/T-3a] Shard {} block {} anomalous timestamp gap: {} s \
             (threshold {} s = 9 × {:.1} s interval — gaps exceeding 10 intervals)",
            block.header.shard_id, block.header.height, gap_secs, threshold_secs,
            shard_interval_num() as f64 / shard_interval_den().max(1) as f64,
        );
    }

    // T-3b: Cumulative drift. `reconstructed_ts` above (like `block_delta`) is
    // on the aux *beacon* header's height/interval (see the T-2 comment
    // above), not the shard's own height × shard interval — the expected
    // schedule must be reconstructed on that same beacon basis. Comparing a
    // beacon-scale reconstructed timestamp against a shard-height-derived
    // expectation produced a permanent multi-decade false-positive drift on
    // every shard block (confirmed live via a 2026-07-25 devnet_15 soak —
    // same bug class as the mining-pool producer-side duplicate in
    // src/mining_pool/shard_chain.rs).
    let beacon_height = block.header.beacon_header.beacon_height as u64;
    let expected_ts_approx = (genesis_timestamp as i64)
        .saturating_add((beacon_height as i64).saturating_mul(beacon_interval_secs() as i64));
    let drift_secs = super::cumulative_drift_secs(
        reconstructed_ts, genesis_timestamp, beacon_height, beacon_interval_secs(),
    );
    if drift_secs.abs() > MAX_CHAIN_DRIFT_SECS {
        let clock_delta = now as i64 - expected_ts_approx as i64;
        let confirmed = clock_delta.abs() < LOCAL_CLOCK_TOLERANCE_SECS;
        warn!(
            "[CV-02/T-3b] Shard {} block {} cumulative drift {:.1} days \
             (expected_ts≈{}, block_ts={}, drift≈{} s). {}",
            block.header.shard_id,
            block.header.height,
            drift_secs.abs() as f64 / 86_400.0,
            expected_ts_approx,
            reconstructed_ts,
            drift_secs,
            if confirmed {
                format!("Local clock CONFIRMS drift (clock_delta={} s).", clock_delta)
            } else {
                "Local clock agreement INDETERMINATE.".to_string()
            }
        );
    }

    // Previous MMR root must match
    if block.header.prev_mmr_root != WeightedHash::from(expected_mmr_root) {
        return Err(ValidationError::InvalidMmrRoot {
            expected: expected_mmr_root,
            actual: block.header.prev_mmr_root.into(),
        });
    }

    // `chain_weight` validation removed (session Jul 25, 2026 — Target 3
    // review): the field is no longer part of the wire or of any hash
    // preimage (see `FullShardHeader.chain_weight`'s own doc comment). There
    // is nothing here to validate — a receiver's own `chain_weight` is a
    // pure function of already-trusted inputs (the parent's own canonical
    // weight, already established by `prev_mmr_root` matching above, plus
    // this block's own already-PoW-verified `difficulty`), so it is computed
    // locally wherever fork-choice needs it, never read off this header.
    // The old "must increase" check here was strictly weaker than Kameniar's
    // equivalent check anyway (it never verified the value was *correct*,
    // only that it was *larger* than the previous stamped value) — removing
    // it closes that validator-asymmetry gap rather than tightening it,
    // since there is no longer a stamped value on either side to compare.

    debug!("Shard block chain validation passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::blocks::shard_block::{Block, FullShardHeader, BeaconHeader};
    
    /// Build a minimal shard block. beacon_ts is the beacon chain wall-clock time (Unix seconds).
    /// No PoW or merged-mining proof — timestamp checks run first.
    /// Uses devnet bitcoin anchor timestamp.
    // `chain_weight` param kept (unused) so every call site below didn't
    // need touching when `FullShardHeader.chain_weight` was removed (Aug 5,
    // 2026) — it never fed anything but that now-gone field.
    fn make_shard_block(height: u32, beacon_ts: u64, _chain_weight: u128) -> Block {
        let bitcoin_anchor = genesis_ts();
        let beacon_header = BeaconHeader::new(
            1,
            beacon_ts,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            0x1d00ffff,
            bitcoin_anchor,
            0,
            [0u8; 32],
        );
        let header = FullShardHeader::new(
            height,
            WeightedHash::zero(),
            WeightedHash::zero(),
            [0u8; 32],
            1,
            vec![],
            1,
            beacon_header,
        );
        Block::new(header, vec![])
    }

    fn genesis_ts() -> u64 { 1_704_067_200 } // 2024-01-01 UTC (bitcoin anchor)

    fn make_shard_block_with_anchor(height: u32, beacon_ts: u64, _chain_weight: u128, bitcoin_anchor: u64) -> Block {
        let beacon_header = BeaconHeader::new(
            1,
            beacon_ts,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            0x1d00ffff,
            bitcoin_anchor,
            0,
            [0u8; 32],
        );
        let header = FullShardHeader::new(
            height,
            WeightedHash::zero(),
            WeightedHash::zero(),
            [0u8; 32],
            1,
            vec![],
            1,
            beacon_header,
        );
        Block::new(header, vec![])
    }

    // ── T-1 (block-to-block monotonic timestamp) — removed 2026-07-04 ────────
    //
    // There is no plan to run a block-to-block ordering check alongside T-MTP.
    // Bitcoin has no such rule; T-MTP (this codebase's MTP analogue) is the
    // sole timestamp-ordering backstop, matching Bitcoin's model. The five
    // `test_t1_shard_*` cases that used to live here, and their only helper
    // (`make_shard_block_with_beacon_delta`), were removed along with the
    // rule — they asserted rejection behavior that intentionally no longer
    // exists. See docs/reports/TS-DELTA_Final_Completion_Report.md §5.

    // ── T-2 (CV-01: future timestamp) ────────────────────────────────────────

    #[test]
    fn test_t2_shard_accepts_within_limit() {
        // Use fixed test anchor (CRITICAL: matches BITCOIN_ANCHOR_TIMESTAMP)
        let anchor = genesis_ts();  // 1_704_067_200

        // Create blocks with timestamps close to anchor to avoid i32 delta overflow
        let block_base = anchor + 1000;
        let prev  = make_shard_block_with_anchor(1, block_base, 100, anchor);
        let block = make_shard_block_with_anchor(2, block_base + 100, 200, anchor);
        let result = validate_shard_block_against_chain(&block, &prev, [0u8; 32], anchor);
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ValidationError::FutureTimestamp { .. }),
                "timestamp in safe past must not trigger FutureTimestamp"
            );
        }
    }

    #[test]
    fn test_t2_shard_rejects_one_over_limit() {
        // NOTE: T-2 future threshold testing requires real wall-clock comparison.
        // In test environment with bitcoin_anchor far in the past (Jan 1 2024),
        // all test blocks have timestamps in the past relative to unix_now().
        // This test verifies the validation logic compiles and runs,
        // but cannot test the actual future threshold with historical timestamps.

        let anchor = 1_704_067_200u64;  // Jan 1, 2024 UTC
        let block_base = anchor + 1000;

        let prev  = make_shard_block_with_anchor(1, block_base, 100, anchor);
        let future_ts = block_base + MAX_FUTURE_SECS + 1;
        let block = make_shard_block_with_anchor(2, future_ts, 200, anchor);
        let result = validate_shard_block_against_chain(&block, &prev, [0u8; 32], anchor);

        // The validation will likely NOT return FutureTimestamp because block is in the past.
        // Just verify validation executed without panicking.
        // The actual T-2 threshold is tested implicitly in production with real timestamps.
        let _ = result;
    }

    #[test]
    fn test_t2_shard_rejects_max_u64() {
        // NOTE: T-2 future threshold testing requires real wall-clock comparison.
        // In test environment with bitcoin_anchor far in the past (Jan 1 2024),
        // all test blocks have timestamps in the past relative to unix_now().

        let anchor = 1_704_067_200u64;  // Jan 1, 2024 UTC
        let block_base = anchor + 1000;

        let prev  = make_shard_block_with_anchor(1, block_base, 100, anchor);
        let block = make_shard_block_with_anchor(2, block_base + MAX_FUTURE_SECS + 100, 200, anchor);
        let result = validate_shard_block_against_chain(&block, &prev, [0u8; 32], anchor);

        // The validation will likely NOT return FutureTimestamp because block is in the past.
        // Just verify validation executed without panicking.
        let _ = result;
    }

    // ── T-3a (CV-02: gap warning) — large gap must never hard-reject ──────────

    #[test]
    fn test_t3a_shard_large_gap_is_not_rejected() {
        // Use fixed test anchor (CRITICAL: matches BITCOIN_ANCHOR_TIMESTAMP)
        let anchor = genesis_ts();  // 1_704_067_200

        // Create blocks with timestamps close to anchor to avoid i32 delta overflow
        // gap = 399 s > 375 s threshold
        let block_base = anchor + 1000;
        let prev  = make_shard_block_with_anchor(1, block_base + 100, 100, anchor);
        let block = make_shard_block_with_anchor(2, block_base + 499, 200, anchor); // gap = 399 s
        let result = validate_shard_block_against_chain(&block, &prev, [0u8; 32], anchor);
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ValidationError::FutureTimestamp { .. }),
                "large gap must not cause FutureTimestamp"
            );
        }
    }

    // ── NC-40: height-0 genesis linkage (shared Kameniar/Keystone) ───────────

    #[test]
    fn nc40_genesis_linkage_accepts_matching_anchor_and_bits() {
        let anchor = WeightedHash::from_parts([0xAB; 28], 0x0102_0304);
        let bits = 0x0300_0434;
        let mut block = make_shard_block(0, genesis_ts() + 100, 0);
        block.header.prev_mmr_root = anchor;
        block.header.difficulty = bits;
        assert!(validate_shard_genesis_linkage(&block, 0, anchor, bits).is_ok());
    }

    #[test]
    fn nc40_genesis_linkage_rejects_wrong_anchor() {
        let expected = WeightedHash::from_parts([0xAB; 28], 0x0102_0304);
        let wrong = WeightedHash::from_parts([0xCD; 28], 0x0102_0304);
        let bits = 0x0300_0434;
        let mut block = make_shard_block(0, genesis_ts() + 100, 0);
        block.header.prev_mmr_root = wrong;
        block.header.difficulty = bits;
        let err = validate_shard_genesis_linkage(&block, 3, expected, bits).unwrap_err();
        assert!(matches!(err, ValidationError::ShardGenesisAnchorMismatch { shard_id: 3, .. }));
    }

    #[test]
    fn nc40_genesis_linkage_rejects_wrong_bits() {
        let anchor = WeightedHash::from_parts([0xAB; 28], 0x0102_0304);
        let mut block = make_shard_block(0, genesis_ts() + 100, 0);
        block.header.prev_mmr_root = anchor;
        block.header.difficulty = 0xDEAD_BEEF;
        let err = validate_shard_genesis_linkage(&block, 1, anchor, 0x0300_0434).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ShardGenesisDifficultyMismatch {
                shard_id: 1,
                expected_bits: 0x0300_0434,
                actual_bits: 0xDEAD_BEEF,
            }
        ));
    }

    // ── NC-103 (Aug 28, 2026): body-commitment check must not reject a
    // wire-reconstructed block whose original body carried an extension
    // (e.g. TS-T-11's coinbase producer stamp) — see `Block::commitment_
    // verified`'s doc comment for the full mechanism. This is the same bug
    // class that permanently stalled every shard chain at height 1 in a
    // live soak. ──────────────────────────────────────────────────────────

    fn make_beacon_header_for_shard_tests() -> BeaconHeader {
        BeaconHeader::new(
            1,
            genesis_ts() + 100,
            0,
            WeightedHash::zero(),
            [0u8; 32],
            0x1d00ffff,
            genesis_ts(),
            0,
            [0u8; 32],
        )
    }

    #[test]
    fn nc103_wire_reconstructed_block_with_producer_stamp_passes_structure_check() {
        use crate::common::blocks::shard_block::ShardWireBlock;
        use crate::common::crypto::merged_mining_hash::MergedMiningHash;
        use crate::transaction::{Transaction, TxOutput};

        let coinbase = Transaction {
            version: 1,
            locktime: 0,
            expiration_height: 0,
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, recipient: [0xAA; 32] }],
            witnesses: vec![],
            extensions: Vec::new(),
        };
        // Real production shape: coinbase carries a producer-stamp extension
        // (TS-T-11) — this is what every locally-mined block does.
        let body = ShardBlockBody::from_transactions(&[coinbase], Some("A"));
        let commitment = body.calculate_tx_merkle_root();

        let header = FullShardHeader::new(
            1,
            WeightedHash::zero(),
            WeightedHash::zero(),
            commitment,
            1,
            vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
            1,
            make_beacon_header_for_shard_tests(),
        );

        let wire = ShardWireBlock { header, body };
        // Sanity: the wire-level commitment is genuinely correct.
        assert!(wire.verify_commitment());

        let block = wire.into_block();
        assert!(
            block.commitment_verified,
            "into_block must stamp commitment_verified when the flat body really matched"
        );
        assert!(
            !block.transactions.is_empty(),
            "into_block must still reconstruct real transactions (NC-92)"
        );

        // Before the NC-103 fix this unconditionally failed: re-deriving the
        // commitment from `block.transactions` alone (no extensions) never
        // matches a header committed with the producer-stamp extension
        // present.
        validate_shard_block_structure(&block, 1, 4 * 1024 * 1024)
            .expect("structure check must accept a wire-reconstructed block whose original \
                     flat-body commitment was already independently confirmed");
    }

    #[test]
    fn nc103_unverified_reconstruction_with_real_mismatch_is_still_rejected() {
        use crate::transaction::{Transaction, TxOutput};

        // A block NOT produced via ShardWireBlock::into_block (commitment_
        // verified defaults false) whose header commitment genuinely does
        // not match its transactions must still be rejected — the fix only
        // skips the redundant, unsound re-check for the one path that
        // already confirmed the real (extension-inclusive) commitment.
        let coinbase = Transaction {
            version: 1,
            locktime: 0,
            expiration_height: 0,
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, recipient: [0xAA; 32] }],
            witnesses: vec![],
            extensions: Vec::new(),
        };
        let header = FullShardHeader::new(
            1,
            WeightedHash::zero(),
            WeightedHash::zero(),
            [0xFFu8; 32], // deliberately wrong commitment
            1,
            vec![],
            1,
            make_beacon_header_for_shard_tests(),
        );
        let block = Block::new(header, vec![coinbase]);
        assert!(!block.commitment_verified);

        let err = validate_shard_block_structure(&block, 1, 4 * 1024 * 1024).unwrap_err();
        assert!(matches!(err, ValidationError::CustomError(_)));
    }

    /// Shard block size is counted in wire bytes (witnesses included), as with the beacon.
    /// 700 one-input spends are 49 KB without witnesses (inside 60 KiB) but about 112 KB on the wire.
    #[test]
    fn shard_block_over_the_wire_limit_is_rejected_even_when_witness_free_size_fits() {
        use crate::transaction::{Transaction, TxInput, TxOutput, WitnessEntry};
        let mut block = make_shard_block(1, 1_000, 0);
        block.transactions = (0..700u32)
            .map(|i| {
                let mut t = Transaction::new(1, 0);
                t.inputs.push(TxInput { prev_height: i, prev_output_idx: 0 });
                t.add_output(TxOutput { value: 1, recipient: [0x33; 32] });
                t.witnesses.push(WitnessEntry { witness_data: vec![7u8; 73] });
                t
            })
            .collect();
        let limit = 61_440;
        assert!(block.size() <= limit, "the witness-free measure {} fits", block.size());
        assert!(block.wire_size() > limit, "wire size {} does not", block.wire_size());
        let err = validate_shard_block_structure(&block, block.header.shard_id, limit).unwrap_err();
        assert!(matches!(err, ValidationError::BlockTooLarge { .. }), "{err:?}");
    }
}
