// src/common/validation/errors.rs

use std::fmt;

/// Validation error types for all blockchain components
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    // PoW Errors
    InsufficientProofOfWork {
        hash: [u8; 32],
        target: [u8; 32],
    },
    /// CV-05: nBits compact-float encodes a zero, negative, overflowed,
    /// or trivially-easy target that no honest miner would ever produce.
    InvalidNBits {
        nbits: u32,
        reason: &'static str,
    },
    InvalidCommitmentHash,

    /// CV-05: Block's nBits encodes a target that exceeds the network's maximum
    /// allowed target (`BeaconGenesisConfig::max_target`).
    ///
    /// A target that is greater than `max_target` represents an easier
    /// proof-of-work than the network minimum, so the block would violate the
    /// network-wide floor difficulty.  Blocks with such an nBits value must be
    /// rejected outright; even if the hash meets the block's own target, the
    /// network does not recognise that difficulty level as valid.
    NbitsExceedsMaxTarget {
        /// The compact nBits value that failed the check.
        nbits: u32,
        /// The expanded 256-bit target derived from `nbits`.
        expanded_target: [u8; 32],
        /// The network's maximum allowed target.
        max_target: [u8; 32],
    },

    /// CV-60: Beacon block's PoW hash has non-zero last-k-bits.
    ///
    /// The beacon chain occupies the hash-sorting reserved slot (sorting_bits == 0).
    /// A non-zero value means the hash is shard-eligible and must be rejected.
    BeaconHashSortingViolation {
        /// The actual last-k-bit value extracted from the PoW hash.
        sorting_bits: u32,
        /// The k value used for extraction.
        k: u32,
    },

    // Structure Errors
    InvalidBlockHeight {
        expected: u32,
        actual: u32,
    },
    InvalidPreviousHash {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    BlockTooLarge {
        size: usize,
        max: usize,
    },
    
    // MMR Errors
    InvalidMmrRoot {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    MmrTransitionFailed {
        reason: String,
    },
    
    // Shard-Specific Errors
    InvalidShardId {
        expected: u16,
        actual: u16,
    },
    MergedMiningProofInvalid {
        reason: String,
    },

    // ── CV-23 (S-6/S-7): Dynamic Shard Activation Errors ──────────────────────

    /// S-6: a block claims to activate (or build on) a shard at a beacon
    /// height that isn't the shard's actual epoch-boundary activation height.
    ShardActivationOutsideEpochBoundary {
        shard_id: u16,
        claimed_height: u32,
        expected_height: u32,
    },

    /// S-7: a dynamically-activated shard's genesis (height 0) block's
    /// `prev_mmr_root` does not match the beacon chain's `current_mmr_root`
    /// at the shard's activation height — i.e. the genesis anchor is wrong
    /// or the node hasn't yet learned the correct one (subscribe pending).
    ShardGenesisAnchorMismatch {
        shard_id: u16,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// NC-40: height-0 shard block's `difficulty` does not match the NC-19
    /// genesis bits stored at `activate_shard` (beacon-anchor bits ×
    /// `shard_calibration`). Distinct from the genesis *anchor*'s rBits
    /// (bagged cumulative beacon MMR weight) — those are not interchangeable.
    ShardGenesisDifficultyMismatch {
        shard_id: u16,
        expected_bits: u32,
        actual_bits: u32,
    },

    // Transaction Errors
    InvalidTransaction {
        reason: String,
    },

    // ── CV-15: k-Coefficient Errors ──────────────────────────────────────────

    /// K-1 / K-8: compact k encoding is zero, malformed, or mismatches genesis.
    InvalidKCoeff {
        /// The raw 4-byte compact encoding that failed validation.
        compact_k: u32,
        reason: &'static str,
    },

    // ── CV-26: Beacon Reward Errors ──────────────────────────────────────────

    /// BR-2 / BR-5: coinbase total exceeds `beacon_block_reward(height) + tx_fees`.
    BeaconCoinbaseExceedsSchedule {
        height: u32,
        coinbase_total: u64,
        max_allowed: u64,
    },

    /// BR-1: genesis coinbase does not exactly match the configured premine.
    BeaconPremineMismatch {
        expected_total: u64,
        actual_total: u64,
    },

    /// BR-3: beacon coinbase violates a structural invariant (zero inputs,
    /// first position, output count, no expiration).
    InvalidCoinbaseStructure {
        reason: String,
    },

    // ── CV-01: Timestamp Errors ───────────────────────────────────────────────

    /// CV-01 (T-2): Block timestamp (reconstructed from delta) is more than
    /// MAX_FUTURE_SECS (600 s) ahead of the node's local wall clock at the
    /// time of validation.
    ///
    /// Accepting such a block would poison the fork: no subsequent block can ever
    /// carry a timestamp higher than the maximum representable value, making
    /// the branch unextendable.
    FutureTimestamp {
        /// Delta value carried in the block header (in 1/256-second units).
        delta: i32,
        /// Reconstructed wall-clock Unix time from delta.
        timestamp: u64,
        /// Node's wall-clock Unix time at validation.
        now: u64,
        /// `now + MAX_FUTURE_SECS` — the maximum acceptable timestamp.
        max_future: u64,
    },

    /// CV-01 (T-MTP): Block delta is below the Median Time Past rule.
    /// The delta must be strictly greater than the median of the previous 11 deltas
    /// minus `I_block × 6 × 256` (beacon: 921_600; shard: 57_600).
    ///
    /// NOTE (May 14, 2026): The current implementation uses an incorrect constant of
    /// 76_800 (= 300 × 256). The correct constant is `I_block × 6 × 256` per
    /// `Correctness_and_Validation_Plan.md` §3 T-MTP. Re-implementation pending.
    TimestampBelowMtp {
        /// Block's delta value (1/256-second units from Bitcoin anchor).
        delta: i32,
        /// Median delta of previous 11 blocks.
        median_past_delta: i32,
        /// Minimum acceptable delta (median - I_block × 6 × 256).
        min_allowed_delta: i32,
    },

    /// NC-133 (shard T-MTP): a shard block's time is not later than the
    /// median of the previous 11 shard blocks' times. Times are 1/256-second units
    /// since the genesis anchor, rebuilt from each block's aux beacon header
    /// (`delta` + its beacon height's schedule) — see `shard_time_units`.
    ShardTimestampBelowMtp {
        /// This block's time (1/256 s since the anchor).
        time_units: i64,
        /// Median time of the previous blocks (1/256 s since the anchor).
        median_past_units: i64,
    },

    /// CV-01: Block delta is outside valid range.
    /// This catches malformed delta values that would cause arithmetic overflow.
    DeltaOutOfRange {
        /// The delta value that failed validation.
        delta: i32,
        /// Reason for rejection (e.g., "would cause integer overflow").
        reason: &'static str,
    },

    // ── CV-11: Transaction Expiration / Locktime Errors ──────────────────────

    /// TE-1: A transaction's locktime has not yet been reached.
    ///
    /// The transaction must not be included in a block until
    /// `block_height >= tx.locktime`.
    TransactionNotYetValid {
        locktime: u32,
        block_height: u32,
    },

    /// TE-2: A transaction's expiration height has been reached or passed.
    ///
    /// If `tx.expiration_height > 0`, the transaction must not be included
    /// in a block at height `>= tx.expiration_height`.
    /// Valid window: `[locktime, expiration_height)`.
    TransactionExpired {
        expiration_height: u32,
        block_height: u32,
    },

    /// CV-12 / TE-3: transaction's expiration window exceeds the configured cap.
    ///
    /// `window = expiration_height - max(locktime, submission_height)` exceeded
    /// `max_expiration_window`. Both mempool admission and block validation enforce
    /// this rule when `max_expiration_window > 0`.
    ExpirationWindowExceeded {
        /// Computed window: `expiration_height - effective_start`.
        window: u32,
        /// Configured maximum allowed window.
        max: u32,
    },

    /// TX-7: non-coinbase transaction's output total exceeds its input total.
    ValueOverflow {
        /// Sum of all input UTXO values for this transaction.
        input_total: u64,
        /// Sum of all output values for this transaction.
        output_total: u64,
    },

    /// TX-8: coinbase output spent before reaching maturity height.
    CoinbaseImmature {
        /// Block height at which the coinbase output was created.
        prev_height: u32,
        /// Global output index within that block.
        prev_output_idx: u16,
        /// Height of the block that would include the spending transaction.
        current_height: u32,
        /// Earliest block height at which this coinbase output may be spent
        /// (`prev_height + COINBASE_MATURITY`).
        maturity_height: u32,
    },

    /// TX-9: block output count exceeds the u16 address space (65 535).
    ///
    /// `output_index` is a `u16`, so at most 65 535 outputs may appear in one
    /// block across all transactions.
    OutputCountExceeded {
        /// Actual total number of outputs in the block.
        count: usize,
        /// Maximum permitted outputs per block.
        max: usize,
    },

    /// TX-10: `TxOutput.recipient` is not a valid x-only Schnorr public key.
    ///
    /// The 32-byte recipient field must be the x-coordinate of a point on the
    /// secp256k1 curve.  An output with an invalid pubkey can never be spent.
    InvalidRecipientPubkey {
        /// Zero-based index of the output within the block's flat output vector.
        output_index: usize,
    },

    /// TX-4 / CV-69: per-input Schnorr signature count does not match spending
    /// input count (flat-vector `witnesses[]` / descriptor `witness_len`).
    SignatureCountMismatch {
        /// Expected count (spending inputs or descriptor `in_len`).
        inputs: usize,
        /// Actual count (`witnesses.len()` or descriptor `witness_len`).
        signatures: usize,
    },

    /// CV-10 / TX-5: Schnorr signature verification failed for a spending input.
    InvalidSignature {
        input_index: usize,
        reason: String,
    },

    /// ESC-1..ESC-3: an escrow policy-hash spend (witness `0x02` / `0x03`) broke a
    /// structural rule (length, policy hash, height window). Signature failures use
    /// [`ValidationError::InvalidSignature`]. Spec: `docs/plan/Escrow_Policy_Hash_Consensus_Spec.md`.
    EscrowSpend {
        input_index: usize,
        rule: &'static str,
        reason: String,
    },

    /// TX-12 / CV-28: non-coinbase transaction's implicit fee falls below the
    /// size-proportional floor (`fee >= ceil(size/4) * min_fee_per_4_bytes`).
    /// Enforced identically at mempool admission and block validation.
    TransactionBelowMinFee {
        /// Estimated wire size of the transaction in bytes.
        tx_size_bytes: u64,
        /// Actual fee paid (`sum(inputs) - sum(outputs)`).
        fee: u64,
        /// Minimum fee required for `tx_size_bytes` at the configured rate.
        min_required: u64,
    },

    /// NC-137: a header commits to more chains than the protocol allows
    /// (`> MAX_COMMITTED_CHAIN_COUNT`, i.e. `s > 15`). Invalid, never clamped.
    ChainCountAboveMaximum {
        count: u16,
        max: u16,
    },

    // Generic Errors
    CustomError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ValidationError::ChainCountAboveMaximum { count, max } => {
                write!(f, "committed_chain_count {count} exceeds the protocol maximum {max}")
            }
            ValidationError::InsufficientProofOfWork { hash, target } => {
                write!(
                    f,
                    "Insufficient proof-of-work: hash {} does not meet target {}",
                    hex::encode(hash),
                    hex::encode(target)
                )
            }
            ValidationError::InvalidNBits { nbits, reason } => {
                write!(f, "Invalid nBits 0x{:08x}: {}", nbits, reason)
            }
            ValidationError::InvalidCommitmentHash => {
                write!(f, "Invalid commitment hash - consensus fields tampered")
            }
            ValidationError::NbitsExceedsMaxTarget { nbits, expanded_target, max_target } => {
                write!(
                    f,
                    "nBits 0x{:08x} expands to target {} which exceeds network max_target {}",
                    nbits,
                    hex::encode(expanded_target),
                    hex::encode(max_target),
                )
            }
            ValidationError::BeaconHashSortingViolation { sorting_bits, k } => {
                write!(
                    f,
                    "Beacon hash-sorting violation: last {} bits = {} (must be 0 for beacon)",
                    k, sorting_bits
                )
            }
            ValidationError::InvalidBlockHeight { expected, actual } => {
                write!(f, "Invalid block height: expected {}, got {}", expected, actual)
            }
            ValidationError::InvalidPreviousHash { expected, actual } => {
                write!(
                    f,
                    "Invalid previous hash: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            ValidationError::BlockTooLarge { size, max } => {
                write!(f, "Block too large: {} bytes exceeds limit of {} bytes", size, max)
            }
            ValidationError::InvalidMmrRoot { expected, actual } => {
                write!(
                    f,
                    "Invalid MMR root: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            ValidationError::MmrTransitionFailed { reason } => {
                write!(f, "MMR transition failed: {}", reason)
            }
            ValidationError::InvalidShardId { expected, actual } => {
                write!(f, "Invalid shard ID: expected {}, got {}", expected, actual)
            }
            ValidationError::MergedMiningProofInvalid { reason } => {
                write!(f, "Merged mining proof invalid: {}", reason)
            }
            ValidationError::ShardActivationOutsideEpochBoundary {
                shard_id,
                claimed_height,
                expected_height,
            } => {
                write!(
                    f,
                    "Shard {} activation claimed at height {}, but expected activation height is {}",
                    shard_id, claimed_height, expected_height
                )
            }
            ValidationError::ShardGenesisAnchorMismatch { shard_id, expected, actual } => {
                write!(
                    f,
                    "Shard {} genesis anchor mismatch: expected {}, got {}",
                    shard_id,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            ValidationError::ShardGenesisDifficultyMismatch {
                shard_id,
                expected_bits,
                actual_bits,
            } => {
                write!(
                    f,
                    "Shard {} genesis difficulty mismatch: expected {:#x} (stored genesis bits), got {:#x}",
                    shard_id, expected_bits, actual_bits
                )
            }
            ValidationError::InvalidTransaction { reason } => {
                write!(f, "Invalid transaction: {}", reason)
            }
            ValidationError::InvalidKCoeff { compact_k, reason } => {
                write!(f, "Invalid k-coefficient 0x{:08x}: {}", compact_k, reason)
            }
            ValidationError::BeaconCoinbaseExceedsSchedule { height, coinbase_total, max_allowed } => {
                write!(
                    f,
                    "Beacon coinbase at height {} exceeds schedule: {} > {} (reward + fees)",
                    height, coinbase_total, max_allowed
                )
            }
            ValidationError::BeaconPremineMismatch { expected_total, actual_total } => {
                write!(
                    f,
                    "Genesis premine mismatch: expected {} atoms, got {}",
                    expected_total, actual_total
                )
            }
            ValidationError::InvalidCoinbaseStructure { reason } => {
                write!(f, "Invalid coinbase structure: {}", reason)
            }
            ValidationError::FutureTimestamp { delta, timestamp, now, max_future } => write!(
                f,
                "block timestamp {} (delta {}) is {} s ahead of local clock {} \
                 (max allowed: {}, limit: now + 600 s)",
                timestamp,
                delta,
                timestamp.saturating_sub(*now),
                now,
                max_future,
            ),
            ValidationError::ShardTimestampBelowMtp { time_units, median_past_units } => write!(
                f,
                "shard block time {} is not later than the median of the previous blocks {} \
                 ({:.1} s at or before it; 1/256 s units since the anchor)",
                time_units,
                median_past_units,
                (*median_past_units - *time_units) as f64 / 256.0,
            ),
            ValidationError::TimestampBelowMtp { delta, median_past_delta, min_allowed_delta } => write!(
                f,
                "block delta {} is below median-time-past rule: \
                 must be > median({}) - I×6×256 = {} (actual: {})",
                delta,
                median_past_delta,
                min_allowed_delta,
                delta,
            ),
            ValidationError::DeltaOutOfRange { delta, reason } => write!(
                f,
                "block delta {} is out of range: {}",
                delta, reason
            ),
            ValidationError::TransactionNotYetValid { locktime, block_height } => write!(
                f,
                "transaction locktime {} not yet reached (block height {})",
                locktime, block_height,
            ),
            ValidationError::TransactionExpired { expiration_height, block_height } => write!(
                f,
                "TE-2 transaction expired: expiration_height {} <= block_height {}",
                expiration_height, block_height,
            ),
            ValidationError::ExpirationWindowExceeded { window, max } => write!(
                f,
                "TE-3 expiration window {} exceeds maximum allowed {}",
                window, max,
            ),
            ValidationError::ValueOverflow { input_total, output_total } => write!(
                f,
                "TX-7 value overflow: outputs ({}) exceed inputs ({})",
                output_total, input_total,
            ),
            ValidationError::CoinbaseImmature { prev_height, prev_output_idx, current_height, maturity_height } => write!(
                f,
                "TX-8 coinbase immature: output {}:{} created at height {}, \
                 spendable at {} but spending at {} (need {} more blocks)",
                prev_height, prev_output_idx,
                prev_height,
                maturity_height,
                current_height,
                maturity_height.saturating_sub(*current_height),
            ),
            ValidationError::OutputCountExceeded { count, max } => write!(
                f,
                "TX-9 output count exceeded: block has {} outputs, max is {}",
                count, max,
            ),
            ValidationError::InvalidRecipientPubkey { output_index } => write!(
                f,
                "TX-10 invalid recipient pubkey at output index {}",
                output_index,
            ),
            ValidationError::SignatureCountMismatch { inputs, signatures } => write!(
                f,
                "TX-4 signature count mismatch: {} spending input(s), {} signature(s)",
                inputs, signatures,
            ),
            ValidationError::InvalidSignature { input_index, reason } => write!(
                f,
                "TX-5 invalid signature for input {}: {}",
                input_index, reason
            ),
            ValidationError::EscrowSpend { input_index, rule, reason } => write!(
                f,
                "{} escrow spend invalid for input {}: {}",
                rule, input_index, reason
            ),
            ValidationError::TransactionBelowMinFee { tx_size_bytes, fee, min_required } => write!(
                f,
                "TX-12 fee too low: {} bytes requires min fee {}, transaction pays {}",
                tx_size_bytes, min_required, fee,
            ),
            ValidationError::CustomError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<String> for ValidationError {
    fn from(s: String) -> Self {
        ValidationError::CustomError(s)
    }
}

impl From<&str> for ValidationError {
    fn from(s: &str) -> Self {
        ValidationError::CustomError(s.to_string())
    }
}