// src/common/validation/transactions.rs
//
// CV-09 — Transaction structural validation rules.
//
// Implements the context-free (stateless) and UTXO-set-dependent subsets of
// the TX-* rules defined in `docs/plan/Correctness_and_Validation_Plan.md`.
//
// # Rules implemented
//
// | Rule  | Description                                              | Status |
// |-------|----------------------------------------------------------|--------|
// | TX-1  | UTXO existence: every input must resolve via `BlockValidationUtxo` | ✅ |
// | TX-2  | Intra-transaction duplicate-input prevention             | ✅     |
// | TX-3  | Intra-block duplicate-input prevention                   | ✅     |
// | TX-4  | Per-input signature count parity (`witnesses[]`)         | ✅ CV-69 |
// | TX-5  | Per-input Schnorr signature verify                      | ✅ CV-10 |
// | TX-6  | chain_id domain separation in sighash                   | ✅ CV-10 |
// | TX-7  | Value conservation: non-coinbase sum(inputs) >= sum(out) | ✅     |
// | TX-8  | Coinbase maturity: epoch-derived (64 beacon / 1024 shard) | ✅     |
// | TX-9  | Block total output count ≤ 65 535 (`output_index: u16`)  | ✅     |
// | TX-10 | Valid x-only Schnorr recipient pubkey (non-coinbase)     | ✅     |
// | TX-11 | Transaction version must be 1 or 2                       | ✅     |
// | TX-12 | Minimum fee floor, size-proportional (CV-28)             | ✅ opt-in, `min_fee_per_4_bytes=0` disables |
// | CV-70 | Mempool admission (`validate_transaction_for_mempool`)   | ✅     |
// | CB-1  | Coinbase structure: no inputs, ≥1 output, version 1      | ✅     |
// | ST-1  | Script size limits per input/output                      | ✅     |
// | ST-2  | Non-empty outputs list                                   | ✅     |
// | ST-3  | Max input / output counts (DoS bound)                    | ✅     |
//
// CV-10 (TX-5/TX-6) uses `sighash_v2` (txid + prevouts_hash) + `verify_schnorr_witness` in
// `validate_block_body` when `BlockBodyValidationParams::verify_signatures` is true.

use std::collections::{HashMap, HashSet};

use secp256k1::XOnlyPublicKey;

use crate::transaction::{
    ExtensionRecord, FlatInput, FlatOutput, Transaction, TransactionDescriptor, TxInput,
    WitnessEntry,
};
use crate::transaction::flat_tx_meta::{
    parse_flat_tx_meta, parse_flat_tx_meta_scan, validate_coinbase_extensions, FlatTxMeta,
};
use crate::common::crypto::{prevouts_hash, sighash_v2, spend_checks, SCHNORR_WITNESS_LEN};
use crate::common::crypto::{NoSigCache, SigCache, SigCacheKey, SigVerifier, SCHEME_TAG_SINGLE_KEY};
use crate::common::utxo::ForkUtxoOverlay;
use super::errors::ValidationError;

// ── UTXO lookup for block validation ────────────────────────────────────────

/// UTXO source for **consensus validation reads** in `validate_block_body`.
///
/// Production block acceptance MUST use [`BlockValidationUtxo::PositionalDb`]
/// when `PositionalUtxoDb` is wired.
///
/// [`BlockValidationUtxo::ReorgBuffer`] reads from the in-memory `ForkUtxoOverlay`.
/// Used when P1DB is not attached (unit tests, non-`full-node` builds).
/// The reorg buffer itself is always maintained on chain structs for apply/revert —
/// this enum only selects which store validation queries.
pub enum BlockValidationUtxo<'a> {
    /// In-memory reorg buffer (`ForkUtxoOverlay`) — validation read path when P1DB absent.
    ReorgBuffer(&'a ForkUtxoOverlay),
    /// Authoritative mmap store (rustmmrdb) — production validation read path.
    #[cfg(feature = "full-node")]
    PositionalDb(&'a rustmmrdb::PositionalUtxoDb),
    /// REORG-SPEC-VERIFY-2 P1: a speculative *fork-point* view, used to run
    /// [`validate_shard_block_body`] against a competing fork **before**
    /// `reorganize_to_fork`'s Step 3 real revert. Pure in-memory, storage-
    /// backend-independent (built by the reorg engine from one batched P1DB
    /// read up front). See [`ForkPointUtxoView`].
    ForkPoint(&'a ForkPointUtxoView<'a>),
    /// Test-only: same reads as [`Self::ReorgBuffer`], but counts
    /// [`Self::get_batch`] calls. Used by TX-VALID-EXPIRY-1 regressions to
    /// prove a TE-1/2/3 failure never touches the UTXO batch path.
    #[cfg(test)]
    CountingReorgBuffer {
        set: &'a ForkUtxoOverlay,
        get_batch_calls: &'a std::cell::Cell<usize>,
    },
}

/// REORG-SPEC-VERIFY-2 P1 — a **fork-point** UTXO view for running
/// [`validate_shard_block_body`] (check 9: TX-1/2/3/4/5/7/8/10/12, TE-1/2/3)
/// speculatively against a competing fork *before* `reorganize_to_fork`'s
/// Step 3 does the real revert / `p1db.rollback_to`.
///
/// It answers "does outpoint `(h, i)` resolve, and to what, **as of the fork
/// point**", assembled from three pieces the reorg engine already has without
/// mutating any storage:
///
///  * `resolved` — the durable outputs the fork's inputs reference that were
///    created below `fork_height` (the shared blocks), resolved up front in one batched
///    `PositionalUtxoDb::get_utxos_batch` + one `verify_unspent_batch_as_of`
///    against the *live* tip. Only outputs unspent at the live tip carry data
///    (`(Some(_), _)`); one unspent at the tip is necessarily unspent as of
///    the fork point too (spends only ever move forward), and its value /
///    recipient / coinbase-ness are unaffected by discarding blocks above
///    `last_common_height`, so the live read *is* the fork-point read. A
///    `(None, spent_as_of_fork)` entry means the output does not resolve as of
///    the fork point (spent at/below the fork, above the tip, or never
///    created); `spent_as_of_fork` distinguishes a genuine still-spent input.
///  * `overlay` — the candidate fork's own not-yet-durable outputs from blocks
///    *earlier* than the one being validated, accumulated fork-point-first
///    (`ForkUtxoOverlay::apply_flat_body` per block), exactly as
///    `apply_alternative_chain` builds `self.fork_utxo_overlay` in Step 4.
///  * `consumed` — durable outpoints already spent by an *earlier* fork block,
///    so an intra-fork double-spend of a durable output resolves to "absent"
///    here just as it would after Step 4 marked it spent.
///
/// Outpoints at or above `fork_height` that are not fork-internal are masked absent (with `fork_height == 0` nothing durable exists at all):
/// they belong to blocks the reorg discards, so as of the fork point they do
/// not exist. Every read is deterministic and infallible — no I/O, so
/// `validate_shard_block_body` running against this view can only ever fail
/// for a genuine content reason, never a transient storage error.
///
/// **Invariant (mirrors `reorg_dry_run_verify_spends`):** a fork block that
/// spends an outpoint this view cannot classify with certainty (a durable
/// output that resolves `None` but is *not* recorded spent as of the fork —
/// i.e. it may have been spent by a discarded tip block and is legitimately
/// re-spendable, or may never have existed) must be left for Step 4's
/// authoritative `validate_block_full`, never rejected here. The reorg
/// engine's helper (`dry_run_verify_fork_bodies`) enforces that by *skipping*
/// such a block rather than validating it against this view.
pub struct ForkPointUtxoView<'a> {
    resolved: &'a HashMap<(u32, u16), (Option<FlatOutput>, bool)>,
    overlay: &'a ForkUtxoOverlay,
    consumed: &'a HashSet<(u32, u16)>,
    fork_height: u32,
}

impl<'a> ForkPointUtxoView<'a> {
    pub fn new(
        resolved: &'a HashMap<(u32, u16), (Option<FlatOutput>, bool)>,
        overlay: &'a ForkUtxoOverlay,
        consumed: &'a HashSet<(u32, u16)>,
        fork_height: u32,
    ) -> Self {
        Self { resolved, overlay, consumed, fork_height }
    }

    /// `true` iff the durable input at `(height, idx)` is recorded spent as of
    /// the fork point (a genuine still-spent conflict, as opposed to an output
    /// that resolves `None` only because a discarded tip block spent it or it
    /// never existed). Retained as a small explicit accessor for that
    /// distinction — the reorg helper acts on it via the `resolved` map
    /// directly, and P3's Step-3.5 pass will want it too.
    pub fn spent_as_of_fork(&self, height: u32, idx: u16) -> bool {
        matches!(self.resolved.get(&(height, idx)), Some((_, true)))
    }

    /// PO-4: one output as this view resolves it (`None` = absent or spent).
    pub fn output(&self, height: u32, idx: u16) -> Option<FlatOutput> {
        self.get(height, idx)
    }

    fn get(&self, height: u32, idx: u16) -> Option<FlatOutput> {
        // The overlay answers only above the fork point; at or below it the
        // durable read is authoritative (PO-4: a live tail overlay may still
        // hold a not-yet-purged entry for a height P1DB already has).
        if height >= self.fork_height {
            return self.overlay.get(height, idx).copied();
        }
        if self.consumed.contains(&(height, idx)) {
            return None;
        }
        self.resolved.get(&(height, idx)).and_then(|&(data, _spent)| data)
    }

    fn is_coinbase_output(&self, height: u32, idx: u16) -> bool {
        if height >= self.fork_height {
            return self.overlay.is_coinbase_output(height, idx);
        }
        if height < self.fork_height
            && matches!(self.resolved.get(&(height, idx)), Some((Some(_), _)))
        {
            // Same heuristic as `BlockValidationUtxo::PositionalDb`: a shard /
            // beacon block's single coinbase output is at index 0.
            return idx == 0;
        }
        false
    }
}

impl BlockValidationUtxo<'_> {
    fn get(&self, height: u32, idx: u16) -> Result<Option<FlatOutput>, ValidationError> {
        match self {
            Self::ReorgBuffer(set) => Ok(set.get(height, idx).cloned()),
            Self::ForkPoint(view) => Ok(view.get(height, idx)),
            #[cfg(feature = "full-node")]
            Self::PositionalDb(db) => {
                let op = rustmmrdb::Outpoint::new(height, idx);
                db.get_utxo(&op)
                    .map_err(|e| ValidationError::InvalidTransaction {
                        reason: format!("UTXO lookup failed: {e}"),
                    })
                    .map(|opt| {
                        opt.map(|o| FlatOutput {
                            value: o.value,
                            recipient: o.recipient,
                        })
                    })
            }
            #[cfg(test)]
            Self::CountingReorgBuffer { set, .. } => Ok(set.get(height, idx).cloned()),
        }
    }

    fn is_coinbase_output(&self, height: u32, idx: u16) -> bool {
        match self {
            Self::ReorgBuffer(set) => set.is_coinbase_output(height, idx),
            Self::ForkPoint(view) => view.is_coinbase_output(height, idx),
            #[cfg(feature = "full-node")]
            Self::PositionalDb(_) => {
                // Single coinbase output per block at index 0 (shard + beacon tail).
                idx == 0
            }
            #[cfg(test)]
            Self::CountingReorgBuffer { set, .. } => set.is_coinbase_output(height, idx),
        }
    }

    /// TX-VALID-BATCH-1 (`docs/plan/OPTIMIZATION_PLAN.md` §19.1): resolve
    /// many inputs' outputs in one call instead of one [`Self::get`] call
    /// per input. `validate_block_body` calls this once for a whole block's
    /// `inputs[]` (already a single flat vector spanning every transaction,
    /// per the flat-body design — no per-transaction reassembly needed)
    /// instead of once per transaction's own small slice, so the batch is
    /// the block's full input count, not just one transaction's.
    ///
    /// `ReorgBuffer` has no batching to offer (`ForkUtxoOverlay` is an
    /// in-memory `HashMap`, already O(1) per lookup with no I/O) — this
    /// exists on that variant purely so callers don't need to branch on
    /// which `BlockValidationUtxo` variant they hold. Returns results in
    /// the same order as `inputs`.
    fn get_batch(&self, inputs: &[FlatInput]) -> Result<Vec<Option<FlatOutput>>, ValidationError> {
        match self {
            Self::ReorgBuffer(set) => Ok(inputs
                .iter()
                .map(|i| set.get(i.prev_height, i.prev_output_idx).copied())
                .collect()),
            Self::ForkPoint(view) => Ok(inputs
                .iter()
                .map(|i| view.get(i.prev_height, i.prev_output_idx))
                .collect()),
            #[cfg(feature = "full-node")]
            Self::PositionalDb(db) => {
                let ops: Vec<rustmmrdb::Outpoint> = inputs
                    .iter()
                    .map(|i| rustmmrdb::Outpoint::new(i.prev_height, i.prev_output_idx))
                    .collect();
                let resolved = db.get_utxos_batch(&ops).map_err(|e| {
                    ValidationError::InvalidTransaction {
                        reason: format!("UTXO batch lookup failed: {e}"),
                    }
                })?;
                Ok(resolved
                    .into_iter()
                    .map(|opt| {
                        opt.map(|o| FlatOutput {
                            value: o.value,
                            recipient: o.recipient,
                        })
                    })
                    .collect())
            }
            #[cfg(test)]
            Self::CountingReorgBuffer {
                set,
                get_batch_calls,
            } => {
                get_batch_calls.set(get_batch_calls.get().saturating_add(1));
                Ok(inputs
                    .iter()
                    .map(|i| set.get(i.prev_height, i.prev_output_idx).copied())
                    .collect())
            }
        }
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

/// TX-11: the one transaction version, for coinbases and spends alike. Every spend signs sighash v2
/// (`sighash_v2`); there is no other scheme, so the version no longer marks it. (Owner decision
/// Oct 17, 2026: the earlier version 2 meant nothing of its own; one `u8` representation everywhere.)
pub const TX_VERSION: u8 = 1;

/// Absolute upper bound on inputs per transaction.  Beyond this a node would
/// take O(N²) to scan for duplicates; 100 000 matches Bitcoin Core's safety
/// limit.  (ST-3)
pub const MAX_INPUTS_PER_TX: usize = 100_000;

/// Absolute upper bound on outputs per transaction.  `output_index` is a u16
/// so the absolute ceiling is 65 535; we cap tighter for safety.  (TX-9 / ST-3)
pub const MAX_OUTPUTS_PER_TX: usize = 65_535;

/// Maximum total outputs in a single shard block (coinbase included).
///
/// Must equal rustmmrdb's storage cap (`rustmmrdb::MAX_SHARD_OUTPUTS_PER_BLOCK`):
/// the slot store refuses a block with more outputs at persist time, which
/// halts the chain. The literal is pinned to that constant by a test
/// (CLAUDE.md item 17; TX-9 spec: "must match or be tighter").
pub const MAX_SHARD_BLOCK_OUTPUTS: usize = 1_016;

/// Maximum total outputs in a single beacon block (coinbase included).
/// Equals `rustmmrdb::MAX_BEACON_OUTPUTS_PER_BLOCK`: 16 pages × 1,016 slots,
/// a 32-byte header on every page (CLAUDE.md item 21; was 16,376 until Oct 13, 2026).
pub const MAX_BEACON_BLOCK_OUTPUTS: usize = 16_256;

/// Default maximum **wire** size of a shard block: the length of its `ShardWireBlock` encoding
/// (header with merged-mining proof, plus the flat body with witnesses). Owner rule, Oct 8, 2026:
/// about 64 KiB on the wire; 60 KiB is inside the accepted band. Temporary: short addresses will
/// make the stored and wire sizes differ, and this rule will then be revisited.
pub const DEFAULT_MAX_SHARD_BLOCK_WIRE_BYTES: usize = 61_440;

/// Default maximum **wire** size of a beacon block (`BeaconWireBlock` encoding): about 1 MiB;
/// 960 KiB is inside the accepted band (owner, Oct 8, 2026). Same temporary status.
pub const DEFAULT_MAX_BEACON_BLOCK_WIRE_BYTES: usize = 983_040;

/// Wire bytes a shard template keeps free for what is not a pool transaction: the header with
/// its merged-mining proof (about 300 B at a small tree, growing with depth), the coinbase and
/// the 20 B body prefix. The pool selection budget is the block limit minus this.
pub const SHARD_BLOCK_WIRE_RESERVE: usize = 2_048;

/// The same for a beacon template (a larger header; a coinbase that may carry several outputs).
pub const BEACON_BLOCK_WIRE_RESERVE: usize = 4_096;

/// Wire bytes the pool may select for a template: `max_block_size - reserve`.
pub fn template_wire_budget(max_block_size: usize, reserve: usize) -> usize {
    max_block_size.saturating_sub(reserve)
}

/// TX-9 per-chain block output limit. TX-6 chain domain: beacon is `0`,
/// shard `s` is `s + 1`.
pub fn max_block_outputs(chain_id: u16) -> usize {
    if chain_id == 0 { MAX_BEACON_BLOCK_OUTPUTS } else { MAX_SHARD_BLOCK_OUTPUTS }
}

/// Maximum byte length of a `TxInput.script_sig`.  (ST-1)
pub const MAX_SCRIPT_SIG_BYTES: usize = 10_000;

/// Coinbase maturity in blocks.  A UTXO created by a coinbase cannot be spent
/// until this many blocks have passed.  (TX-8 — enforced during UTXO lookup,
/// not here.)
///
/// Retained for existing test fixtures / call sites that want the plain
/// pre-NC-91 mainnet-class number (**not** the live mainnet value: mainnet is
/// 64 beacon / 1024 shard blocks via the functions below); live genesis-derived deployments should prefer
/// [`beacon_coinbase_maturity`] / [`shard_coinbase_maturity`] below (Aug 27,
/// 2026 revision — see `docs/plan/Correctness_and_Validation_Plan.md` NC-91).
pub const COINBASE_MATURITY: u32 = 100;

/// Coinbase maturity for the **beacon** chain, derived from the network's own
/// governance epoch length rather than a flat per-network-class constant
/// (mainnet=100 / everything-else=0, the scheme this replaces — see NC-91).
/// A short-epoch soak/test network legitimately wants a much shorter wait
/// than mainnet, but "0" (immediate spend) throws away the coinbase-maturity
/// protection entirely rather than just scaling it down.
///
/// `max(1, epoch_length / 256) * 4` — the `/256` scales maturity down
/// proportionally to how short the network's epoch is; the floor-then-`*4`
/// guarantees a real (never-zero, never-below-4) wait on any network,
/// however short its epoch. Mainnet: `4096 / 256 = 16`, `16 * 4 = 64`.
pub fn beacon_coinbase_maturity(epoch_length: u32) -> u32 {
    (epoch_length / 256).max(1) * 4
}

/// Coinbase maturity for a **shard** chain — shard blocks are produced far
/// more often than beacon blocks (that's what `shard_calibration` *is*, the
/// beacon:shard block-interval ratio — see
/// `docs/plan/Epoch_Alignment_Reference.md`), so a shard coinbase needs a
/// proportionally longer wait, in shard blocks, to reach the same real
/// elapsed-time depth as the beacon-side figure above.
pub fn shard_coinbase_maturity(epoch_length: u32, shard_calibration: u32) -> u32 {
    beacon_coinbase_maturity(epoch_length) * shard_calibration
}

/// TX-12 / CV-28: default minimum fee (in atomic units) required per 4 bytes
/// of serialized transaction size. `0` disables the check.
///
/// Production TX-12 floor: **16 shard/beacon atoms per 4 serialized bytes**.
///
/// Owner choice (Oct 30, 2026) for the public CPU testnet: ~4 atoms/byte so a
/// typical ~200 B transfer costs ~800 atoms — sensible next to k=2^16 floor
/// rewards, revisitable once real ASICs show up. `for_tests()` still defaults
/// `min_fee_per_4_bytes` to `0` (disabled); `production()` uses this constant.
pub const DEFAULT_MIN_FEE_PER_4_BYTES: u64 = 16;

/// TX-12 size-proportional minimum fee for `tx_size_bytes`.
#[inline]
pub fn min_fee_atoms_for_size(tx_size_bytes: u64) -> u64 {
    let units = (tx_size_bytes + 3) / 4;
    units.saturating_mul(DEFAULT_MIN_FEE_PER_4_BYTES)
}

/// TX-12 / CV-28: check a non-coinbase transaction's fee against the
/// size-proportional floor `fee >= ceil(tx_size_bytes / 4) * min_fee_per_4_bytes`.
///
/// `min_fee_per_4_bytes == 0` disables the check unconditionally.
fn check_min_fee(
    tx_size_bytes: u64,
    fee: u64,
    min_fee_per_4_bytes: u64,
) -> Result<(), ValidationError> {
    if min_fee_per_4_bytes == 0 {
        return Ok(());
    }
    let units = (tx_size_bytes + 3) / 4;
    let min_required = units.saturating_mul(min_fee_per_4_bytes);
    if fee < min_required {
        return Err(ValidationError::TransactionBelowMinFee {
            tx_size_bytes,
            fee,
            min_required,
        });
    }
    Ok(())
}

/// TX-12 / CV-28: estimated wire size of one flat-vector transaction.
///
/// `descriptor(28) + outputs × 40 + inputs × 6 + witnesses × (4-byte length
/// prefix + 65-byte Schnorr witness)`. Extension records are intentionally
/// excluded — most transactions carry none, and their overhead is small
/// relative to the anti-spam floor this check enforces.
/// TX-12 size of one transaction in the flat body: descriptor + outputs + inputs +
/// the real witness bytes (`4 + len` each). Escrow witnesses (ESC) are 197 / 133 bytes,
/// so witnesses are counted by length, not as a fixed 65 bytes.
fn flat_tx_size_bytes(out_len: u32, in_len: u32, witnesses: &[WitnessEntry]) -> u64 {
    TransactionDescriptor::SIZE as u64
        + out_len as u64 * FlatOutput::SIZE as u64
        + in_len as u64 * FlatInput::SIZE as u64
        + witnesses.iter().map(|w| 4 + w.witness_data.len() as u64).sum::<u64>()
}

// ── Error extensions ─────────────────────────────────────────────────────────
//
// Additional `ValidationError` variants used only by this module.  The enum
// lives in `errors.rs`; we extend it by mapping these domain errors to the
// existing `InvalidTransaction` catch-all until a dedicated enum variant is
// added in a follow-up (CV-09 phase 2).
//
// Convenience constructors so call sites stay readable.

fn err_version(version: u8) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!("TX-11: transaction version must be {} (got {})", TX_VERSION, version),
    }
}

fn err_empty_outputs() -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: "transaction must have at least one output".into(),
    }
}

fn err_too_many_inputs(count: usize) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!("too many inputs: {} exceeds limit {}", count, MAX_INPUTS_PER_TX),
    }
}

fn err_too_many_outputs(count: usize) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!("too many outputs: {} exceeds limit {}", count, MAX_OUTPUTS_PER_TX),
    }
}

fn err_script_sig_too_large(idx: usize, len: usize) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!(
            "input[{}] script_sig too large: {} bytes (max {})",
            idx, len, MAX_SCRIPT_SIG_BYTES
        ),
    }
}

fn err_duplicate_input(prev_height: u32, prev_output_idx: u16) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!(
            "duplicate input {}:{} — intra-transaction double-spend",
            prev_height, prev_output_idx
        ),
    }
}

fn err_coinbase_has_inputs(count: usize) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!(
            "coinbase transaction must have zero inputs, found {}",
            count
        ),
    }
}

fn err_utxo_not_found(prev_height: u32, prev_output_idx: u16) -> ValidationError {
    ValidationError::InvalidTransaction {
        reason: format!(
            "TX-1: input {}:{} not found in UTXO set (unknown or already spent)",
            prev_height, prev_output_idx
        ),
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Validate a single transaction's structure (context-free, no UTXO access).
///
/// Checks all stateless TX rules:
/// - TX-11: version is 1 or 2; a transaction with inputs is version 2
/// - ST-2:  at least one output
/// - ST-3:  input / output counts within bounds
/// - ST-1:  script_sig / script_pubkey sizes within bounds
/// - TX-2:  no duplicate `(prev_height, prev_output_idx)` pairs
///
/// Does **not** check:
/// - TX-4:  per-input signature count — enforced in `validate_block_body` (flat vector)
/// - UTXO existence (TX-1) — requires `PositionalUtxoDb`
/// - Value conservation (TX-7) — requires resolved UTXOs
/// - Coinbase maturity (TX-8) — requires chain height
/// - Schnorr signature verification (TX-5) — requires Shisha-native Outpoint model
/// - Recipient pubkey validity (TX-10) — reserved for Shisha-native model
pub fn validate_transaction_structure(tx: &Transaction) -> Result<(), ValidationError> {
    // TX-11: the one version.
    if tx.version != TX_VERSION {
        return Err(err_version(tx.version));
    }

    // ST-2: must have at least one output
    if tx.outputs.is_empty() {
        return Err(err_empty_outputs());
    }

    // ST-3: input / output count bounds
    if tx.inputs.len() > MAX_INPUTS_PER_TX {
        return Err(err_too_many_inputs(tx.inputs.len()));
    }
    if tx.outputs.len() > MAX_OUTPUTS_PER_TX {
        return Err(err_too_many_outputs(tx.outputs.len()));
    }

    // ST-1: script_sig removed — authorization now in ShardBlockBody::witnesses[].

    // TX-2: intra-transaction duplicate inputs
    {
        let mut seen: HashSet<(u32, u16)> = HashSet::with_capacity(tx.inputs.len());
        for inp in &tx.inputs {
            let key = (inp.prev_height, inp.prev_output_idx);
            if !seen.insert(key) {
                return Err(err_duplicate_input(inp.prev_height, inp.prev_output_idx));
            }
        }
    }

    Ok(())
}

/// Validate the coinbase transaction of a block (CV-09 CB-1).
///
/// A coinbase transaction:
/// - Has **zero** inputs (creates coins from block reward).
/// - Has **at least one** output.
/// - Must be version 1 or 2 (TX-11).
///
/// Value correctness (k-reward cap) is checked separately by
/// `validate_coinbase_value` once the reward schedule is wired (CV-26).
pub fn validate_coinbase_structure(coinbase: &Transaction) -> Result<(), ValidationError> {
    // TX-11: the one version
    if coinbase.version != TX_VERSION {
        return Err(err_version(coinbase.version));
    }

    // CB-1: no inputs
    if !coinbase.inputs.is_empty() {
        return Err(err_coinbase_has_inputs(coinbase.inputs.len()));
    }

    // ST-2: at least one output
    if coinbase.outputs.is_empty() {
        return Err(err_empty_outputs());
    }

    // ST-3: output count bound
    if coinbase.outputs.len() > MAX_OUTPUTS_PER_TX {
        return Err(err_too_many_outputs(coinbase.outputs.len()));
    }

    Ok(())
}

/// Validate all transactions in a block for intra-block duplicate inputs (TX-3).
///
/// Accumulates spent `(prev_height, prev_output_idx)` outpoints across all
/// non-coinbase transactions in block order.  Returns the first duplicate found.
///
/// The coinbase (first transaction, `inputs.is_empty()`) is skipped — it has
/// no inputs to check.
///
/// This check is O(N) in total transaction inputs; it must run before any UTXO
/// state updates.
pub fn validate_no_intra_block_double_spend(
    transactions: &[Transaction],
) -> Result<(), ValidationError> {
    let input_count: usize = transactions.iter().map(|tx| tx.inputs.len()).sum();
    let mut seen: HashSet<(u32, u16)> = HashSet::with_capacity(input_count);

    for tx in transactions {
        // Coinbase transactions have no inputs — skip.
        if tx.is_coinbase() {
            continue;
        }
        for inp in &tx.inputs {
            let key = (inp.prev_height, inp.prev_output_idx);
            if !seen.insert(key) {
                return Err(err_duplicate_input(inp.prev_height, inp.prev_output_idx));
            }
        }
    }

    Ok(())
}

/// Parameters for flat-body block validation (TE + TX-5 + UTXO rules).
#[derive(Clone, Copy, Debug)]
pub struct BlockBodyValidationParams {
    pub block_height: u32,
    pub coinbase_maturity: u32,
    /// TE-3 cap; `0` disables the expiration-window check.
    pub max_expiration_window: u32,
    /// TX-6 chain domain byte in the sighash preimage.
    pub chain_id: u16,
    /// When false, skips Schnorr verify (unit tests without real signatures).
    pub verify_signatures: bool,
    /// TX-12 / CV-28: minimum fee per 4 bytes of serialized tx size.
    /// `0` disables the check. See [`with_min_fee_per_4_bytes`](Self::with_min_fee_per_4_bytes).
    pub min_fee_per_4_bytes: u64,
}

impl BlockBodyValidationParams {
    /// Test / devnet defaults: TE-3 off, signatures not verified, no min fee.
    pub fn for_tests(block_height: u32, coinbase_maturity: u32) -> Self {
        Self {
            block_height,
            coinbase_maturity,
            max_expiration_window: 0,
            chain_id: 0,
            verify_signatures: false,
            min_fee_per_4_bytes: 0,
        }
    }

    /// Production block acceptance: TE-3 enforced, Schnorr verify enabled,
    /// TX-12 min-fee floor enforced at [`DEFAULT_MIN_FEE_PER_4_BYTES`] — a
    /// transaction fee rate is never zero (override with
    /// [`Self::with_min_fee_per_4_bytes`]).
    pub fn production(
        block_height: u32,
        coinbase_maturity: u32,
        max_expiration_window: u32,
        chain_id: u16,
    ) -> Self {
        Self {
            block_height,
            coinbase_maturity,
            max_expiration_window,
            chain_id,
            verify_signatures: true,
            min_fee_per_4_bytes: DEFAULT_MIN_FEE_PER_4_BYTES,
        }
    }

    /// TX-12 / CV-28: enable the minimum-fee floor at the given rate
    /// (atomic units per 4 bytes of serialized tx size).
    pub fn with_min_fee_per_4_bytes(mut self, min_fee_per_4_bytes: u64) -> Self {
        self.min_fee_per_4_bytes = min_fee_per_4_bytes;
        self
    }
}

/// CV-11 / TE-1 + TE-2 + CV-12 / TE-3 on flat validity metadata.
pub fn validate_flat_tx_at_height_with_window(
    meta: &FlatTxMeta,
    block_height: u32,
    max_expiration_window: u32,
) -> Result<(), ValidationError> {
    if meta.locktime > 0 && block_height < meta.locktime {
        return Err(ValidationError::TransactionNotYetValid {
            locktime: meta.locktime,
            block_height,
        });
    }
    if meta.expiration_height > 0 && block_height >= meta.expiration_height {
        return Err(ValidationError::TransactionExpired {
            expiration_height: meta.expiration_height,
            block_height,
        });
    }
    if max_expiration_window > 0 && meta.expiration_height > 0 {
        let effective_start = meta.locktime.max(block_height);
        let window = meta.expiration_height.saturating_sub(effective_start);
        if window > max_expiration_window {
            return Err(ValidationError::ExpirationWindowExceeded {
                window,
                max: max_expiration_window,
            });
        }
    }
    Ok(())
}

/// CV-11 / TE-1 + TE-2: Validate that a transaction is valid at the given block height.
///
/// **TE-1 (locktime):** A transaction with `locktime > 0` MUST NOT be included in a block
/// at height less than `locktime`. Valid window: `[locktime, ∞)`.
///
/// **TE-2 (expiration):** A transaction with `expiration_height > 0` MUST NOT be included
/// in a block at height `>= expiration_height`. Valid window: `[locktime, expiration_height)`.
///
/// Coinbase transactions (no inputs) are exempt from locktime; `expiration_height` must
/// be 0 for coinbase transactions (enforced separately by `validate_coinbase_structure`).
///
/// # Arguments
/// * `tx`           — The transaction to validate.
/// * `block_height` — Height of the block that would contain `tx`.
///
/// # Errors
/// - `TransactionNotYetValid` when `tx.locktime > 0 && block_height < tx.locktime`.
/// - `TransactionExpired` when `tx.expiration_height > 0 && block_height >= tx.expiration_height`.
pub fn validate_transaction_at_height(
    tx: &Transaction,
    block_height: u32,
) -> Result<(), ValidationError> {
    validate_transaction_at_height_with_window(tx, block_height, 0)
}

/// CV-11 / TE-1 + TE-2 + CV-12 / TE-3: validate a transaction at a given height,
/// optionally enforcing the expiration-window cap.
///
/// * `max_expiration_window = 0` disables the TE-3 cap check (legacy / tests).
/// * Otherwise rejects if `expiration_height - max(locktime, block_height) > max_expiration_window`.
pub fn validate_transaction_at_height_with_window(
    tx: &Transaction,
    block_height: u32,
    max_expiration_window: u32,
) -> Result<(), ValidationError> {
    // TE-1: locktime
    if tx.locktime > 0 && block_height < tx.locktime {
        return Err(ValidationError::TransactionNotYetValid {
            locktime: tx.locktime,
            block_height,
        });
    }
    // TE-2: expiration
    if tx.expiration_height > 0 && block_height >= tx.expiration_height {
        return Err(ValidationError::TransactionExpired {
            expiration_height: tx.expiration_height,
            block_height,
        });
    }
    // TE-3: expiration window cap
    if max_expiration_window > 0 && tx.expiration_height > 0 {
        let effective_start = tx.locktime.max(block_height);
        let window = tx.expiration_height.saturating_sub(effective_start);
        if window > max_expiration_window {
            return Err(ValidationError::ExpirationWindowExceeded {
                window,
                max: max_expiration_window,
            });
        }
    }
    Ok(())
}

/// TX-7: Validate that a non-coinbase transaction does not create value.
pub fn validate_tx_value_conservation(
    tx: &Transaction,
    fork_utxo_overlay: &ForkUtxoOverlay,
) -> Result<(), ValidationError> {
    if tx.is_coinbase() {
        return Ok(());
    }

    let mut input_total: u64 = 0;
    for input in &tx.inputs {
        let output = fork_utxo_overlay
            .get(input.prev_height, input.prev_output_idx)
            .ok_or_else(|| ValidationError::InvalidTransaction {
                reason: format!(
                    "TX-7: input {}:{} not found in UTXO set",
                    input.prev_height, input.prev_output_idx
                ),
            })?;
        input_total = input_total.checked_add(output.value).ok_or_else(|| {
            ValidationError::InvalidTransaction {
                reason: "TX-7: input value sum overflows u64".into(),
            }
        })?;
    }

    let output_total: u64 = tx
        .outputs
        .iter()
        .try_fold(0u64, |acc, out| acc.checked_add(out.value))
        .ok_or_else(|| ValidationError::InvalidTransaction {
            reason: "TX-7: output value sum overflows u64".into(),
        })?;

    if output_total > input_total {
        return Err(ValidationError::ValueOverflow { input_total, output_total });
    }

    Ok(())
}

/// TX-8: Validate that all inputs spent by a transaction have satisfied
/// the coinbase maturity requirement.
///
/// For each input referencing a coinbase output (output index less than the
/// coinbase output count at the creation height), the spending block height
/// must satisfy: `current_height - prev_height >= maturity`.
///
/// `maturity = 0` disables the check entirely (devnet / tests).
///
/// If `current_height - prev_height >= maturity`, maturity is guaranteed
/// regardless of whether the output was coinbase — no map lookup.
/// Only outputs within the last `maturity` blocks need the map lookup.
pub fn validate_tx_coinbase_maturity(
    tx: &Transaction,
    fork_utxo_overlay: &ForkUtxoOverlay,
    current_height: u32,
    maturity: u32,
) -> Result<(), ValidationError> {
    if tx.is_coinbase() || maturity == 0 {
        return Ok(());
    }

    for input in &tx.inputs {
        let age = current_height.saturating_sub(input.prev_height);
        if age >= maturity {
            // Output is old enough: maturity guaranteed regardless of type.
            continue;
        }
        // Output is recent — check whether it is a coinbase output.
        if fork_utxo_overlay.is_coinbase_output(input.prev_height, input.prev_output_idx) {
            return Err(ValidationError::CoinbaseImmature {
                prev_height: input.prev_height,
                prev_output_idx: input.prev_output_idx,
                current_height,
                maturity_height: input.prev_height + maturity,
            });
        }
    }

    Ok(())
}

/// CV-70: Parameters for full-node / P2P mempool admission.
#[derive(Clone, Copy, Debug)]
pub struct MempoolAdmissionParams {
    pub tip_height: u32,
    pub coinbase_maturity: u32,
    /// TE-3 cap; `0` disables the expiration-window check.
    pub max_expiration_window: u32,
    /// TX-6 chain domain byte in the sighash preimage.
    pub chain_id: u16,
    /// When true and `tx.witnesses` is populated, run TX-5 Schnorr verify.
    pub verify_signatures: bool,
    /// TX-12 / CV-28: minimum fee per 4 bytes of serialized tx size.
    /// `0` disables the check. See [`with_min_fee_per_4_bytes`](Self::with_min_fee_per_4_bytes).
    pub min_fee_per_4_bytes: u64,
}

impl MempoolAdmissionParams {
    /// Test defaults: TE-3 off, signatures not verified, no min fee.
    pub fn for_tests(tip_height: u32, coinbase_maturity: u32) -> Self {
        Self {
            tip_height,
            coinbase_maturity,
            max_expiration_window: 0,
            chain_id: 0,
            verify_signatures: false,
            min_fee_per_4_bytes: 0,
        }
    }

    /// Production mempool admission: TE-3 enforced; TX-5 when witnesses present;
    /// TX-12 min-fee floor enforced at [`DEFAULT_MIN_FEE_PER_4_BYTES`] — a
    /// transaction fee rate is never zero (override with
    /// [`Self::with_min_fee_per_4_bytes`]).
    pub fn production(
        tip_height: u32,
        coinbase_maturity: u32,
        max_expiration_window: u32,
        chain_id: u16,
    ) -> Self {
        Self {
            tip_height,
            coinbase_maturity,
            max_expiration_window,
            chain_id,
            verify_signatures: true,
            min_fee_per_4_bytes: DEFAULT_MIN_FEE_PER_4_BYTES,
        }
    }

    /// TX-12 / CV-28: enable the minimum-fee floor at the given rate
    /// (atomic units per 4 bytes of serialized tx size).
    pub fn with_min_fee_per_4_bytes(mut self, min_fee_per_4_bytes: u64) -> Self {
        self.min_fee_per_4_bytes = min_fee_per_4_bytes;
        self
    }
}

/// CV-70: Consensus checks before admitting a transaction to a full-node mempool.
///
/// Enforces structure (ST-* / TX-2 / TX-11), time rules (TE-1/2/3), UTXO
/// existence (TX-1), value conservation (TX-7), coinbase maturity (TX-8),
/// recipient validity (TX-10), and the minimum-fee floor (TX-12, when
/// `params.min_fee_per_4_bytes > 0`).  TX-3 (intra-block duplicate inputs) is
/// intentionally omitted — the mempool is not a block.
///
/// TX-4 / TX-5: with `params.verify_signatures` (every production node) a spend
/// must carry exactly one valid Schnorr witness per input; an unsigned spend is
/// refused because it could never be mined (sighash v2, Oct 1, 2026). With the
/// flag off (tests only) witnesses are checked only when present.
pub fn validate_transaction_for_mempool(
    tx: &Transaction,
    utxo: BlockValidationUtxo<'_>,
    params: MempoolAdmissionParams,
) -> Result<(), ValidationError> {
    validate_transaction_for_mempool_with(tx, utxo, params, &NoSigCache)
}

/// CV-70 with a per-chain [`SigVerifier`] (MEMPOOL-SIGCACHE-1 Phase 1).
///
/// Identical rules and order to [`validate_transaction_for_mempool`]; only the
/// TX-5 verify goes through `verifier.verify_admission` (lookup, insert on Ok).
/// Nothing is inserted when `params.verify_signatures` is false.
pub fn validate_transaction_for_mempool_with(
    tx: &Transaction,
    utxo: BlockValidationUtxo<'_>,
    params: MempoolAdmissionParams,
    verifier: &dyn SigVerifier,
) -> Result<(), ValidationError> {
    if tx.is_coinbase() {
        return Err(ValidationError::InvalidTransaction {
            reason: "coinbase transactions cannot be admitted to mempool".into(),
        });
    }

    validate_transaction_structure(tx)?;
    // TX-9: a block holds at most `max_block_outputs` outputs, coinbase
    // included (≥ 1), so a transaction with more can never be mined.
    let max_outputs = max_block_outputs(params.chain_id);
    if tx.outputs.len() >= max_outputs {
        return Err(ValidationError::OutputCountExceeded {
            count: tx.outputs.len(),
            max: max_outputs - 1,
        });
    }
    validate_transaction_at_height_with_window(
        tx,
        params.tip_height,
        params.max_expiration_window,
    )?;

    let flat_inputs: Vec<FlatInput> = tx
        .inputs
        .iter()
        .map(|i| FlatInput {
            prev_height: i.prev_height,
            prev_output_idx: i.prev_output_idx,
        })
        .collect();
    let flat_outputs: Vec<FlatOutput> = tx
        .outputs
        .iter()
        .map(|o| FlatOutput {
            value: o.value,
            recipient: o.recipient,
        })
        .collect();

    for (idx, out) in flat_outputs.iter().enumerate() {
        if XOnlyPublicKey::from_slice(&out.recipient).is_err() {
            return Err(ValidationError::InvalidRecipientPubkey { output_index: idx });
        }
    }

    let mut input_pubkeys: Vec<[u8; 32]> = Vec::with_capacity(flat_inputs.len());
    let mut input_prevouts: Vec<(u64, [u8; 32])> = Vec::with_capacity(flat_inputs.len());
    let mut input_total: u64 = 0;
    for inp in &flat_inputs {
        let utxo_out = utxo
            .get(inp.prev_height, inp.prev_output_idx)?
            .ok_or_else(|| err_utxo_not_found(inp.prev_height, inp.prev_output_idx))?;
        input_pubkeys.push(utxo_out.recipient);
        input_prevouts.push((utxo_out.value, utxo_out.recipient));
        input_total = input_total.checked_add(utxo_out.value).ok_or_else(|| {
            ValidationError::InvalidTransaction {
                reason: "TX-7: input value sum overflows u64".into(),
            }
        })?;
    }
    let output_total: u64 = flat_outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or_else(|| ValidationError::InvalidTransaction {
            reason: "TX-7: output value sum overflows u64".into(),
        })?;
    if output_total > input_total {
        return Err(ValidationError::ValueOverflow {
            input_total,
            output_total,
        });
    }

    // TX-12 / CV-28: minimum fee floor, on the same flat-body size the block rule uses
    // (real witness bytes), so admission never accepts a fee a block would reject.
    let flat_size = flat_tx_size_bytes(flat_outputs.len() as u32, flat_inputs.len() as u32, &tx.witnesses);
    check_min_fee(flat_size, input_total - output_total, params.min_fee_per_4_bytes)?;

    if params.coinbase_maturity > 0 {
        for inp in &flat_inputs {
            let age = params.tip_height.saturating_sub(inp.prev_height);
            if age < params.coinbase_maturity
                && utxo.is_coinbase_output(inp.prev_height, inp.prev_output_idx)
            {
                return Err(ValidationError::CoinbaseImmature {
                    prev_height: inp.prev_height,
                    prev_output_idx: inp.prev_output_idx,
                    current_height: params.tip_height,
                    maturity_height: inp.prev_height + params.coinbase_maturity,
                });
            }
        }
    }

    // TX-4 / TX-5: one witness per input. With signature checks on (every
    // production node) an unsigned spend is refused: it could never be mined.
    if params.verify_signatures || tx.has_witnesses() {
        if tx.witnesses.len() != tx.inputs.len() {
            return Err(ValidationError::SignatureCountMismatch {
                inputs: tx.inputs.len(),
                signatures: tx.witnesses.len(),
            });
        }
    }
    if params.verify_signatures {
        let txid = tx.txid(params.chain_id).0;
        let prev = prevouts_hash(&input_prevouts);
        for (i, witness) in tx.witnesses.iter().enumerate() {
            let sighash = sighash_v2(&txid, &prev, i as u32);
            // ESC-1..ESC-3 (escrow witnesses) run before any cache lookup; the height
            // is the one TE-1/TE-2 use for admission.
            for c in spend_checks(witness, &input_pubkeys[i], &sighash, i, Some(params.tip_height))? {
                verifier.verify_admission(&c.witness, &c.pubkey, &c.message, i, c.scheme_tag)?;
            }
        }
    }

    Ok(())
}

/// Keep-on-revert (disconnect re-warm): the [`SigCache`] keys CV-70 would compute for
/// `tx`'s TX-5 witnesses against `utxo` (the post-rollback state), without verifying.
///
/// Resolves prevouts like the TX-5 loop, builds `sighash_v2` and the salted key with
/// [`SCHEME_TAG_SINGLE_KEY`]. Coinbases, witness/input count mismatches and witnesses
/// of the wrong length yield nothing; an unresolved input stops the walk (prevouts hash
/// needs every input) and returns what was computed (nothing). Inserting these keys is
/// safe only for transactions whose signatures were verified when their block connected.
pub fn sig_cache_keys_for_tx(
    tx: &Transaction,
    utxo: BlockValidationUtxo<'_>,
    chain_id: u16,
    cache: &SigCache,
) -> Vec<SigCacheKey> {
    if tx.is_coinbase() || tx.witnesses.is_empty() || tx.witnesses.len() != tx.inputs.len() {
        return Vec::new();
    }
    let mut pubkeys = Vec::with_capacity(tx.inputs.len());
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        match utxo.get(inp.prev_height, inp.prev_output_idx) {
            Ok(Some(o)) => {
                pubkeys.push(o.recipient);
                prevouts.push((o.value, o.recipient));
            }
            _ => return Vec::new(),
        }
    }
    let txid = tx.txid(chain_id).0;
    let prev = prevouts_hash(&prevouts);
    // Witnesses here already passed validation, so the height window is not re-checked
    // (`None`); escrow witnesses yield one key per signature, as CV-70 inserted them.
    let mut keys = Vec::new();
    for (i, w) in tx.witnesses.iter().enumerate() {
        let sighash = sighash_v2(&txid, &prev, i as u32);
        if let Ok(checks) = spend_checks(w, &pubkeys[i], &sighash, i, None) {
            for c in checks {
                if c.witness.witness_data.len() == SCHNORR_WITNESS_LEN {
                    keys.push(cache.key(c.scheme_tag, &c.message, &c.pubkey, &c.witness.witness_data));
                }
            }
        }
    }
    keys
}

/// Fee rate (sat per 1000 bytes) for mempool prioritisation after CV-70 admission.
pub fn compute_mempool_fee_rate(
    tx: &Transaction,
    utxo: BlockValidationUtxo<'_>,
) -> Option<f64> {
    if tx.is_coinbase() {
        return Some(0.0);
    }
    let mut input_sum: u64 = 0;
    for input in &tx.inputs {
        let out = utxo.get(input.prev_height, input.prev_output_idx).ok()??;
        input_sum = input_sum.checked_add(out.value)?;
    }
    let output_sum: u64 = tx
        .outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))?;
    let fee = input_sum.saturating_sub(output_sum);
    let size = tx.size().max(1) as u64;
    Some((fee.saturating_mul(1000) / size) as f64)
}

/// Select the UTXO store for **validation reads** (TX-1 / TX-7 / TX-8).
///
/// Returns [`BlockValidationUtxo::PositionalDb`] when P1DB is wired (production).
/// Otherwise returns [`BlockValidationUtxo::ReorgBuffer`] — the only case where
/// `ForkUtxoOverlay` holds full history, since it is then the sole source of
/// truth (tests / P1DB-less builds).
///
/// Note: this is a strict either/or, never blended. When P1DB is wired,
/// `ForkUtxoOverlay` still gets populated transiently during apply/revert (to
/// bridge not-yet-committed blocks), but validation reads never consult it —
/// only `PositionalDb`.
#[cfg(feature = "full-node")]
pub fn block_validation_utxo<'a>(
    p1db: Option<&'a rustmmrdb::PositionalUtxoDb>,
    reorg_buffer: &'a ForkUtxoOverlay,
) -> BlockValidationUtxo<'a> {
    match p1db {
        Some(db) => BlockValidationUtxo::PositionalDb(db),
        None => BlockValidationUtxo::ReorgBuffer(reorg_buffer),
    }
}

#[cfg(not(feature = "full-node"))]
pub fn block_validation_utxo<'a>(reorg_buffer: &'a ForkUtxoOverlay) -> BlockValidationUtxo<'a> {
    BlockValidationUtxo::ReorgBuffer(reorg_buffer)
}

/// TILE-1 (NC-190, Oct 20, 2026; consensus rule): the descriptors must partition `outputs`,
/// `inputs`, `witnesses` and `extensions` exactly, in transaction order: each descriptor's
/// `*_start` equals the running end of the previous one, and the final ends equal the vector
/// lengths. This is precisely the layout `ShardBlockBody::from_transactions` produces.
///
/// Why: `tx_leaf_hash` hashes only the slices a descriptor references, so without this a body
/// could carry entries no descriptor references (same `tx_merkle_root`, different wire bytes;
/// `to_transactions` would silently drop them and shift positional output indices), or two
/// descriptors could overlap. With it, `from_transactions(to_transactions(b), None) == b` for
/// every accepted body. O(tx_count), no hashing. Runs for shard and beacon bodies alike.
pub fn check_descriptors_tile(
    n_outputs: usize,
    n_inputs: usize,
    n_witnesses: usize,
    n_extensions: usize,
    ranges: &[TransactionDescriptor],
) -> Result<(), ValidationError> {
    let (mut out, mut inp, mut wit, mut ext) = (0usize, 0usize, 0usize, 0usize);
    for (i, r) in ranges.iter().enumerate() {
        let bad = |what: &str, start: usize, expected: usize| ValidationError::InvalidTransaction {
            reason: format!(
                "TILE-1: descriptor {i} {what}_start {start} != {expected} (descriptors must tile the flat vectors exactly)"
            ),
        };
        if r.out_start as usize != out { return Err(bad("out", r.out_start as usize, out)); }
        if r.in_start as usize != inp { return Err(bad("in", r.in_start as usize, inp)); }
        if r.witness_start as usize != wit { return Err(bad("witness", r.witness_start as usize, wit)); }
        if r.extension_start as usize != ext { return Err(bad("extension", r.extension_start as usize, ext)); }
        // usize is >= 32 bits on every supported target; a u32 sum cannot overflow usize here.
        out += r.out_len as usize;
        inp += r.in_len as usize;
        wit += r.witness_len as usize;
        ext += r.extension_len as usize;
    }
    for (what, got, len) in [
        ("outputs", out, n_outputs),
        ("inputs", inp, n_inputs),
        ("witnesses", wit, n_witnesses),
        ("extensions", ext, n_extensions),
    ] {
        if got != len {
            return Err(ValidationError::InvalidTransaction {
                reason: format!(
                    "TILE-1: descriptors cover {got} {what} but the body has {len} (descriptors must tile the flat vectors exactly)"
                ),
            });
        }
    }
    Ok(())
}

/// FV-11 / CV-09: Validate a `ShardBlockBody` flat-vector representation.
///
/// Enforces the following rules using only the flat `FlatInput`/`FlatOutput`/
/// `TransactionDescriptor` arrays — no `Transaction` reconstruction required:
///
/// | Rule  | Description                                                         |
/// |-------|---------------------------------------------------------------------|
/// | CB-1  | First range must be coinbase (in_len == 0); ≥1 output              |
/// | TX-1  | Every non-coinbase input must resolve via [`BlockValidationUtxo`]     |
/// | TX-2  | No duplicate inputs within a single transaction                     |
/// | TX-3  | No duplicate inputs across transactions in the same block           |
/// | TX-7  | Non-coinbase: Σ inputs ≥ Σ outputs (value conservation)            |
/// | TX-8  | Non-coinbase: coinbase outputs must be mature before spending        |
/// | TX-9  | Total block outputs ≤ `max_block_outputs(chain_id)` (1 016 / 16 256) |
/// | TX-4  | Per-transaction and block-level signature count parity              |
/// | TILE-1| Descriptors tile outputs/inputs/witnesses/extensions exactly (NC-190)|
/// | TX-10 | Non-coinbase outputs: recipient is a valid x-only Schnorr pubkey   |
/// | TX-12 | Non-coinbase: fee ≥ size-proportional floor (`min_fee_per_4_bytes`) |
///
/// | TE-1  | locktime not yet reached at `block_height`                          |
/// | TE-2  | expiration height reached or passed                                 |
/// | TE-3  | expiration window cap (`max_expiration_window`)                     |
/// | TX-5  | Per-input Schnorr verify (when `verify_signatures`)                 |
///
/// Validity metadata (version, locktime, expiration) is read from consensus
/// extension type `0x0001` in `extensions[]`; default when `extension_len == 0`.
///
/// **Ordering (TX-VALID-EXPIRY-1):** TE-1/2/3 and TX-11 run in an I/O-free
/// pre-pass that caches [`FlatTxMeta`] per non-coinbase range *before*
/// [`BlockValidationUtxo::get_batch`]. A TE-failing block pays zero UTXO I/O.
///
/// `signatures` is `ShardBlockBody::witnesses` — one Schnorr signature entry per
/// spending input (coinbase descriptors use `witness_len == 0`).
pub fn validate_block_body(
    outputs: &[FlatOutput],
    inputs:  &[FlatInput],
    ranges:  &[TransactionDescriptor],
    signatures: &[WitnessEntry],
    extensions: &[ExtensionRecord],
    utxo: BlockValidationUtxo<'_>,
    params: BlockBodyValidationParams,
) -> Result<(), ValidationError> {
    let mut hits = Vec::new();
    validate_block_body_with(
        outputs, inputs, ranges, signatures, extensions, utxo, params, &NoSigCache, &mut hits,
    )
}

/// [`validate_block_body`] with a per-chain [`SigVerifier`] (MEMPOOL-SIGCACHE-1 Phase 1).
///
/// Block path is **lookup only**: a hit skips the Schnorr crypto and its key is
/// pushed to `sig_cache_hits`; a miss verifies and never inserts. All other rules
/// (TE-1/2/3, TX-1/2/3/7/8/10/12, ...) run unchanged on every call. The caller
/// erases `sig_cache_hits` via [`SigVerifier::erase`] **only after the block
/// connects**; on any error the hits must be discarded without erasing.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_body_with(
    outputs: &[FlatOutput],
    inputs:  &[FlatInput],
    ranges:  &[TransactionDescriptor],
    signatures: &[WitnessEntry],
    extensions: &[ExtensionRecord],
    utxo: BlockValidationUtxo<'_>,
    params: BlockBodyValidationParams,
    verifier: &dyn SigVerifier,
    sig_cache_hits: &mut Vec<SigCacheKey>,
) -> Result<(), ValidationError> {
    if ranges.is_empty() {
        // TILE-1: no descriptors means the flat vectors must be empty too.
        check_descriptors_tile(outputs.len(), inputs.len(), signatures.len(), extensions.len(), ranges)?;
        return Ok(());
    }

    // TX-9: block-level total output count must fit the storage cap
    // (a block over it passes validation but halts the chain at persist).
    let max_outputs = max_block_outputs(params.chain_id);
    if outputs.len() > max_outputs {
        return Err(ValidationError::OutputCountExceeded {
            count: outputs.len(),
            max: max_outputs,
        });
    }

    // CB-1: first range must be coinbase (in_len == 0) with ≥1 output.
    let first = ranges[0];
    if first.in_len != 0 {
        return Err(ValidationError::InvalidTransaction {
            reason: "CB-1: first transaction range must be coinbase (in_len == 0)".into(),
        });
    }
    if first.out_len == 0 {
        return Err(ValidationError::InvalidTransaction {
            reason: "CB-1: coinbase transaction must have at least one output".into(),
        });
    }
    if first.witness_len != 0 {
        return Err(ValidationError::SignatureCountMismatch {
            inputs: 0,
            signatures: first.witness_len as usize,
        });
    }

    // TX-4: block-level signature count must equal total spending inputs.
    let total_spending_inputs: usize = ranges
        .iter()
        .map(|r| r.in_len as usize)
        .sum();
    if signatures.len() != total_spending_inputs {
        return Err(ValidationError::SignatureCountMismatch {
            inputs: total_spending_inputs,
            signatures: signatures.len(),
        });
    }

    // TILE-1 (NC-190): descriptors must tile the flat vectors exactly. After the cheap, more
    // specific CB-1/TX-4 block-level errors, before any UTXO lookup or signature work.
    check_descriptors_tile(outputs.len(), inputs.len(), signatures.len(), extensions.len(), ranges)?;

    // TX-VALID-EXPIRY-1 (`OPTIMIZATION_PLAN.md` §19.3): TE-1/2/3 (+ TX-11 version)
    // pre-pass *before* the block-wide UTXO batch. A TE-failing block must pay
    // zero UTXO I/O. Cache parsed `FlatTxMeta` for the main loop so the common
    // valid-block path does not double-parse extensions.
    // `None` = coinbase range (stamp / validity-window rules stay in the main loop).
    let mut cached_meta: Vec<Option<FlatTxMeta>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if range.in_len == 0 {
            cached_meta.push(None);
            continue;
        }
        let meta = parse_flat_tx_meta(extensions, range)?;
        if meta.version != TX_VERSION {
            return Err(err_version(meta.version));
        }
        validate_flat_tx_at_height_with_window(
            &meta,
            params.block_height,
            params.max_expiration_window,
        )?;
        cached_meta.push(Some(meta));
    }

    // TX-VALID-BATCH-1: resolve every spending input's output in one call
    // for the whole block, instead of once per input inside the per-transaction
    // loop below. `inputs[]` is already the block's full flat input vector
    // (no per-transaction reassembly needed — see `BlockValidationUtxo::get_batch`'s
    // own doc comment). Runs only after the TE pre-pass above succeeds.
    let resolved_inputs = utxo.get_batch(inputs)?;

    // Inter-block duplicate-input set (TX-3).
    let mut block_seen: HashSet<(u32, u16)> = HashSet::new();

    for (tx_idx, range) in ranges.iter().enumerate() {
        let is_coinbase = range.in_len == 0;

        // TX-4: descriptor signature count must match input count.
        if range.witness_len != range.in_len as u16 {
            return Err(ValidationError::SignatureCountMismatch {
                inputs: range.in_len as usize,
                signatures: range.witness_len as usize,
            });
        }

        // Slice bounds checks.
        let out_end = (range.out_start as usize)
            .checked_add(range.out_len as usize)
            .filter(|&e| e <= outputs.len())
            .ok_or_else(|| ValidationError::InvalidTransaction {
                reason: format!("FV-11: range {} out-of-bounds output slice", tx_idx),
            })?;
        let in_end = (range.in_start as usize)
            .checked_add(range.in_len as usize)
            .filter(|&e| e <= inputs.len())
            .ok_or_else(|| ValidationError::InvalidTransaction {
                reason: format!("FV-11: range {} out-of-bounds input slice", tx_idx),
            })?;
        let _wit_end = (range.witness_start as usize)
            .checked_add(range.witness_len as usize)
            .filter(|&e| e <= signatures.len())
            .ok_or_else(|| ValidationError::InvalidTransaction {
                reason: format!("TX-4: range {} out-of-bounds signature slice", tx_idx),
            })?;

        let tx_outputs = &outputs[range.out_start as usize..out_end];
        let tx_inputs  = &inputs[range.in_start as usize..in_end];

        if tx_outputs.is_empty() {
            return Err(ValidationError::InvalidTransaction {
                reason: format!("FV-11: transaction {} has zero outputs", tx_idx),
            });
        }

        if is_coinbase {
            // CV-87: coinbase may carry TS-T-11 producer stamp (0x1001) in the
            // same extension range — scan/validate instead of strict parse_flat_tx_meta.
            validate_coinbase_extensions(extensions, range)?;
            let meta = parse_flat_tx_meta_scan(extensions, range)?;
            if meta.locktime != 0 || meta.expiration_height != 0 {
                return Err(ValidationError::InvalidTransaction {
                    reason: "coinbase must not carry validity-window metadata".into(),
                });
            }
            continue;
        }

        // TE-1/2/3 + TX-11 already enforced in the pre-pass; reuse cached meta.
        let meta = cached_meta[tx_idx].expect("non-coinbase meta cached by TE pre-pass");

        // TX-10: every non-coinbase output recipient must be a valid x-only
        // Schnorr pubkey on secp256k1.
        for (local_idx, out) in tx_outputs.iter().enumerate() {
            let global_idx = range.out_start as usize + local_idx;
            if XOnlyPublicKey::from_slice(&out.recipient).is_err() {
                return Err(ValidationError::InvalidRecipientPubkey {
                    output_index: global_idx,
                });
            }
        }

        // TX-2: intra-transaction duplicate input check.
        let mut intra_seen: HashSet<(u32, u16)> = HashSet::with_capacity(tx_inputs.len());
        for inp in tx_inputs {
            let key = (inp.prev_height, inp.prev_output_idx);
            if !intra_seen.insert(key) {
                return Err(ValidationError::InvalidTransaction {
                    reason: format!(
                        "TX-2: duplicate input {}:{} within transaction {}",
                        inp.prev_height, inp.prev_output_idx, tx_idx
                    ),
                });
            }
        }

        // TX-3: inter-transaction duplicate input check.
        for inp in tx_inputs {
            let key = (inp.prev_height, inp.prev_output_idx);
            if !block_seen.insert(key) {
                return Err(ValidationError::InvalidTransaction {
                    reason: format!(
                        "TX-3: duplicate input {}:{} across transactions in block",
                        inp.prev_height, inp.prev_output_idx
                    ),
                });
            }
        }

        // TX-1 + TX-7: UTXO existence and value conservation. Resolved via
        // `resolved_inputs` (TX-VALID-BATCH-1's block-wide batch resolve
        // above) sliced at this transaction's own range — same offsets
        // `tx_inputs` itself was sliced at, since both come from the same
        // flat `inputs[]` vector in the same order.
        let tx_resolved = &resolved_inputs[range.in_start as usize..in_end];
        let mut input_pubkeys: Vec<[u8; 32]> = Vec::with_capacity(tx_inputs.len());
        let mut input_prevouts: Vec<(u64, [u8; 32])> = Vec::with_capacity(tx_inputs.len());
        let mut input_total: u64 = 0;
        for (inp, resolved) in tx_inputs.iter().zip(tx_resolved) {
            let utxo_out = resolved
                .ok_or_else(|| err_utxo_not_found(inp.prev_height, inp.prev_output_idx))?;
            input_pubkeys.push(utxo_out.recipient);
            input_prevouts.push((utxo_out.value, utxo_out.recipient));
            input_total = input_total.checked_add(utxo_out.value).ok_or_else(|| {
                ValidationError::InvalidTransaction {
                    reason: "TX-7: input value sum overflows u64".into(),
                }
            })?;
        }
        let output_total: u64 = tx_outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .ok_or_else(|| ValidationError::InvalidTransaction {
                reason: "TX-7: output value sum overflows u64".into(),
            })?;
        if output_total > input_total {
            return Err(ValidationError::ValueOverflow { input_total, output_total });
        }

        // TX-12 / CV-28: minimum fee floor.
        let wit_lo = (range.witness_start as usize).min(signatures.len());
        let wit_hi = (range.witness_start as usize + range.witness_len as usize).min(signatures.len());
        let tx_size_bytes = flat_tx_size_bytes(range.out_len, range.in_len, &signatures[wit_lo..wit_hi]);
        check_min_fee(tx_size_bytes, input_total - output_total, params.min_fee_per_4_bytes)?;

        // TX-8: coinbase maturity.
        if params.coinbase_maturity > 0 {
            for inp in tx_inputs {
                let age = params.block_height.saturating_sub(inp.prev_height);
                if age < params.coinbase_maturity
                    && utxo.is_coinbase_output(inp.prev_height, inp.prev_output_idx)
                {
                    return Err(ValidationError::CoinbaseImmature {
                        prev_height: inp.prev_height,
                        prev_output_idx: inp.prev_output_idx,
                        current_height: params.block_height,
                        maturity_height: inp.prev_height + params.coinbase_maturity,
                    });
                }
            }
        }

        // TX-5 / TX-6: per-input Schnorr authorization.
        if params.verify_signatures {
            let ext_end = (range.extension_start as usize)
                .checked_add(range.extension_len as usize)
                .filter(|&e| e <= extensions.len())
                .ok_or_else(|| ValidationError::InvalidTransaction {
                    reason: format!("TX-5: range {} out-of-bounds extension slice", tx_idx),
                })?;
            let txid = crate::transaction::txid_from_parts(
                params.chain_id,
                meta,
                tx_inputs.iter().map(|i| (i.prev_height, i.prev_output_idx)),
                tx_outputs.iter().map(|o| (o.value, o.recipient)),
                &extensions[range.extension_start as usize..ext_end],
            );
            let prev = prevouts_hash(&input_prevouts);
            let wit_start = range.witness_start as usize;
            for (local_i, inp) in tx_inputs.iter().enumerate() {
                let witness = signatures
                    .get(wit_start + local_i)
                    .ok_or_else(|| ValidationError::InvalidTransaction {
                        reason: format!("TX-5: missing witness for input {}", local_i),
                    })?;
                let sighash = sighash_v2(&txid, &prev, local_i as u32);
                // ESC-1..ESC-3 before any cache lookup (spec ESC-6).
                for c in spend_checks(
                    witness,
                    &input_pubkeys[local_i],
                    &sighash,
                    local_i,
                    Some(params.block_height),
                )? {
                    verifier.verify_block(
                        &c.witness,
                        &c.pubkey,
                        &c.message,
                        local_i,
                        c.scheme_tag,
                        sig_cache_hits,
                    )?;
                }
            }
        }
    }

    Ok(())
}

/// Validate a [`ShardBlockBody`] against flat-vector TX rules (FV-11 / CV-09).
pub fn validate_shard_block_body(
    body: &crate::common::blocks::ShardBlockBody,
    utxo: BlockValidationUtxo<'_>,
    params: BlockBodyValidationParams,
) -> Result<(), ValidationError> {
    validate_block_body(
        &body.outputs,
        &body.inputs,
        &body.descriptors,
        &body.witnesses,
        &body.extensions,
        utxo,
        params,
    )
}

/// [`validate_shard_block_body`] with a [`SigVerifier`]; see [`validate_block_body_with`].
pub fn validate_shard_block_body_with(
    body: &crate::common::blocks::ShardBlockBody,
    utxo: BlockValidationUtxo<'_>,
    params: BlockBodyValidationParams,
    verifier: &dyn SigVerifier,
    sig_cache_hits: &mut Vec<SigCacheKey>,
) -> Result<(), ValidationError> {
    validate_block_body_with(
        &body.outputs,
        &body.inputs,
        &body.descriptors,
        &body.witnesses,
        &body.extensions,
        utxo,
        params,
        verifier,
        sig_cache_hits,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// `docs/plan/Coinbase_Maturity_Design.md` §3: the derived maturity per epoch length / calibration.
    #[test]
    fn derived_coinbase_maturity_table() {
        assert_eq!(beacon_coinbase_maturity(4096), 64); // mainnet-class
        assert_eq!(shard_coinbase_maturity(4096, 16), 1024); // same wall-clock wait in shard blocks
        assert_eq!(beacon_coinbase_maturity(256), 4); // the floor: never below 4 blocks
        assert_eq!(shard_coinbase_maturity(256, 16), 64); // testnet-stress / devnet_15
        assert_eq!(shard_coinbase_maturity(256, 1), 4); // crash_recovery soak
        assert_eq!(beacon_coinbase_maturity(8), 4); // tiny epochs still get a real wait
        assert_eq!(beacon_coinbase_maturity(1), 4);
        // wall-clock invariant: shard maturity in shard blocks == beacon maturity in beacon blocks
        for cal in [1u32, 4, 16] {
            assert_eq!(shard_coinbase_maturity(4096, cal), beacon_coinbase_maturity(4096) * cal);
        }
    }
    use crate::common::blocks::ShardBlockBody;
    use crate::transaction::{Transaction, TxInput, TxOutput, FlatOutput};
    use crate::common::utxo::ForkUtxoOverlay;

    /// Valid secp256k1 x-only pubkey for TX-10 block tests.
    const TEST_XONLY_PUBKEY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
        0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
        0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ];

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn simple_input(prev_height: u32, prev_output_idx: u16) -> TxInput {
        TxInput { prev_height, prev_output_idx }
    }

    fn simple_output(value: u64) -> TxOutput {
        TxOutput {
            value,
            recipient: TEST_XONLY_PUBKEY,
        }
    }

    fn flat_output(value: u64) -> FlatOutput {
        FlatOutput {
            value,
            recipient: TEST_XONLY_PUBKEY,
        }
    }

    /// UTXO entry at `(1, 0)` matching `minimal_regular_tx` spend input.
    fn utxo_funding_height_1() -> ForkUtxoOverlay {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(1, 0, flat_output(5_000_000));
        utxo
    }

    fn minimal_regular_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(1_000)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn minimal_coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![simple_output(5_000_000)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        }
    }

    // ── CV-70: mempool admission ─────────────────────────────────────────────

    #[test]
    fn cv70_valid_spend_accepted() {
        let utxo = utxo_funding_height_1();
        let tx = minimal_regular_tx();
        assert!(validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            MempoolAdmissionParams::for_tests(10, 0),
        )
        .is_ok());
    }

    /// Item 17: a transaction that cannot fit in a block beside the coinbase
    /// is refused at admission (shard cap 1,016; beacon 16,256).
    #[test]
    fn cv70_tx_with_too_many_outputs_rejected() {
        let utxo = utxo_funding_height_1();
        for chain_id in [0u16, 1] {
            let mut tx = minimal_regular_tx();
            tx.outputs = (0..max_block_outputs(chain_id)).map(|_| simple_output(1)).collect();
            let mut params = MempoolAdmissionParams::for_tests(10, 0);
            params.chain_id = chain_id;
            let err = validate_transaction_for_mempool(&tx, BlockValidationUtxo::ReorgBuffer(&utxo), params).unwrap_err();
            assert!(matches!(err, ValidationError::OutputCountExceeded { .. }), "chain {chain_id}: {err:?}");
        }
    }

    #[test]
    fn cv70_missing_utxo_rejected() {
        let utxo = ForkUtxoOverlay::new();
        let tx = minimal_regular_tx();
        assert!(validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            MempoolAdmissionParams::for_tests(10, 0),
        )
        .is_err());
    }

    #[test]
    fn cv70_coinbase_rejected() {
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_transaction_for_mempool(
            &minimal_coinbase(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            MempoolAdmissionParams::for_tests(10, 0),
        )
        .is_err());
    }

    #[test]
    fn cv70_value_overflow_rejected() {
        let utxo = utxo_funding_height_1();
        let mut tx = minimal_regular_tx();
        tx.outputs[0].value = 10_000_000;
        assert!(validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            MempoolAdmissionParams::for_tests(10, 0),
        )
        .is_err());
    }

    #[test]
    fn cv70_compute_fee_rate_positive() {
        let utxo = utxo_funding_height_1();
        let tx = minimal_regular_tx();
        let rate = compute_mempool_fee_rate(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
        )
        .expect("fee rate");
        assert!(rate > 0.0);
    }

    // ── TX-12 / CV-28: minimum fee floor ─────────────────────────────────────

    #[test]
    fn cv28_min_fee_disabled_by_default_accepts_zero_fee() {
        let utxo = utxo_with(1, 0, 1_000);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(1_000)], // zero fee
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            MempoolAdmissionParams::for_tests(10, 0),
        )
        .is_ok());
    }

    #[test]
    fn cv28_mempool_below_floor_rejected() {
        let utxo = utxo_with(1, 0, 1_000);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(1_000)], // zero fee
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let params = MempoolAdmissionParams::for_tests(10, 0).with_min_fee_per_4_bytes(100);
        let err = validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            params,
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::TransactionBelowMinFee { fee: 0, .. }),
            "unexpected error: {:?}", err
        );
    }

    #[test]
    fn cv28_mempool_at_or_above_floor_accepted() {
        let utxo = utxo_funding_height_1(); // funds 5_000_000 at (1, 0)
        let tx = minimal_regular_tx(); // spends to 1_000 → fee 4_999_000
        let params = MempoolAdmissionParams::for_tests(10, 0).with_min_fee_per_4_bytes(100);
        assert!(validate_transaction_for_mempool(
            &tx,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            params,
        )
        .is_ok());
    }

    #[test]
    fn cv28_check_min_fee_boundary_exact_match_accepted() {
        // 66-byte tx → 17 units of 4 bytes → min_required = 1700 at rate 100.
        assert!(check_min_fee(66, 1700, 100).is_ok());
        assert!(check_min_fee(66, 1699, 100).is_err());
    }

    // ── TX-11: version check ──────────────────────────────────────────────────

    #[test]
    fn tx11_version_0_rejected() {
        let mut tx = minimal_regular_tx();
        tx.version = 0;
        assert!(validate_transaction_structure(&tx).is_err());
    }

    #[test]
    fn tx11_version_2_spend_rejected() {
        // Oct 17, 2026: there is exactly one transaction version (1).
        let mut tx = minimal_regular_tx();
        tx.version = 2;
        let err = validate_transaction_structure(&tx).unwrap_err();
        assert!(format!("{err:?}").contains("TX-11"), "{err:?}");
    }

    #[test]
    fn tx11_version_1_coinbase_accepted() {
        let mut cb = minimal_coinbase();
        cb.version = 1;
        assert!(validate_coinbase_structure(&cb).is_ok());
    }

    #[test]
    fn tx11_version_1_spend_accepted() {
        let mut tx = minimal_regular_tx();
        tx.version = 1;
        assert!(validate_transaction_structure(&tx).is_ok());
    }

    #[test]
    fn tx11_version_2_coinbase_rejected() {
        let mut cb = minimal_coinbase();
        cb.version = 2;
        assert!(validate_coinbase_structure(&cb).is_err());
    }

    #[test]
    fn tx11_version_3_rejected() {
        let mut tx = minimal_regular_tx();
        tx.version = 3;
        assert!(validate_transaction_structure(&tx).is_err());
    }

    // ── ST-2: non-empty outputs ───────────────────────────────────────────────

    #[test]
    fn st2_empty_outputs_rejected() {
        let mut tx = minimal_regular_tx();
        tx.outputs.clear();
        let err = validate_transaction_structure(&tx).unwrap_err();
        assert!(err.to_string().contains("at least one output"));
    }

    // ── ST-3: count limits ────────────────────────────────────────────────────

    #[test]
    fn st3_too_many_outputs_rejected() {
        let mut tx = minimal_regular_tx();
        tx.outputs = (0..MAX_OUTPUTS_PER_TX + 1)
            .map(|i| simple_output(i as u64))
            .collect();
        assert!(validate_transaction_structure(&tx).is_err());
    }

    // ── TX-2: intra-transaction duplicate inputs ──────────────────────────────

    #[test]
    fn tx2_duplicate_input_rejected() {
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(7, 0), simple_input(7, 0)],
            outputs: vec![simple_output(500)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let err = validate_transaction_structure(&tx).unwrap_err();
        assert!(err.to_string().contains("double-spend") || err.to_string().contains("duplicate"));
    }

    #[test]
    fn tx2_same_height_different_vout_accepted() {
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(7, 0), simple_input(7, 1)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_transaction_structure(&tx).is_ok());
    }

    #[test]
    fn tx2_same_vout_different_height_accepted() {
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0), simple_input(2, 0)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_transaction_structure(&tx).is_ok());
    }

    // ── TX-3: intra-block duplicate inputs ───────────────────────────────────

    #[test]
    fn tx3_intra_block_double_spend_rejected() {
        let coinbase = minimal_coinbase();
        let tx_a = Transaction {
            version: 1,
            inputs: vec![simple_input(3, 0)],
            outputs: vec![simple_output(500)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let tx_b = Transaction {
            version: 1,
            inputs: vec![simple_input(3, 0)], // same outpoint as tx_a
            outputs: vec![simple_output(400)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let txs = vec![coinbase, tx_a, tx_b];
        let err = validate_no_intra_block_double_spend(&txs).unwrap_err();
        assert!(err.to_string().contains("double-spend") || err.to_string().contains("duplicate"));
    }

    #[test]
    fn tx3_coinbase_skipped_in_double_spend_check() {
        // Two coinbase-like transactions (no inputs) must not trigger TX-3.
        let cb1 = minimal_coinbase();
        let cb2 = minimal_coinbase();
        assert!(validate_no_intra_block_double_spend(&[cb1, cb2]).is_ok());
    }

    #[test]
    fn tx3_distinct_outpoints_accepted() {
        let coinbase = minimal_coinbase();
        let tx_a = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(500)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let tx_b = Transaction {
            version: 1,
            inputs: vec![simple_input(2, 0)],
            outputs: vec![simple_output(400)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_no_intra_block_double_spend(&[coinbase, tx_a, tx_b]).is_ok());
    }

    // ── CB-1: coinbase structure ──────────────────────────────────────────────

    #[test]
    fn cb1_coinbase_with_inputs_rejected() {
        let mut cb = minimal_coinbase();
        cb.inputs.push(simple_input(0, 0));
        let err = validate_coinbase_structure(&cb).unwrap_err();
        assert!(err.to_string().contains("zero inputs") || err.to_string().contains("coinbase"));
    }

    #[test]
    fn cb1_coinbase_no_outputs_rejected() {
        let mut cb = minimal_coinbase();
        cb.outputs.clear();
        assert!(validate_coinbase_structure(&cb).is_err());
    }

    #[test]
    fn cb1_coinbase_valid_accepted() {
        assert!(validate_coinbase_structure(&minimal_coinbase()).is_ok());
    }

    // ── Flat-body block-level structure (replaces validate_block_transactions) ─

    #[test]
    fn block_empty_body_accepted() {
        let utxo = ForkUtxoOverlay::new();
        let body = ShardBlockBody::from_transactions(&[], None);
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_ok());
    }

    #[test]
    fn block_coinbase_only_flat_accepted() {
        let utxo = ForkUtxoOverlay::new();
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase()], None);
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_ok());
    }

    #[test]
    fn block_intra_block_double_spend_flat_caught() {
        let tx_a = Transaction {
            version: 1,
            inputs: vec![simple_input(42, 0)],
            outputs: vec![simple_output(500)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let tx_b = Transaction {
            version: 1,
            inputs: vec![simple_input(42, 0)],
            outputs: vec![simple_output(400)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), tx_a, tx_b], None);
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_err());
    }

    fn te_block_params(block_height: u32, max_window: u32) -> BlockBodyValidationParams {
        BlockBodyValidationParams {
            block_height,
            coinbase_maturity: 0,
            max_expiration_window: max_window,
            chain_id: 0,
            verify_signatures: false,
            min_fee_per_4_bytes: 0,
        }
    }

    // ── CV-11 / TE-1: validate_transaction_at_height ─────────────────────────

    /// TE1-1: tx with locktime=0 is always valid.
    #[test]
    fn te1_1_locktime_zero_always_valid() {
        let tx = minimal_regular_tx(); // locktime=0
        assert!(validate_transaction_at_height(&tx, 0).is_ok());
        assert!(validate_transaction_at_height(&tx, 1000).is_ok());
    }

    /// TE1-2: tx with locktime=5 is valid at height >= 5.
    #[test]
    fn te1_2_locktime_met_at_exact_height() {
        let mut tx = minimal_regular_tx();
        tx.locktime = 5;
        assert!(validate_transaction_at_height(&tx, 5).is_ok());
        assert!(validate_transaction_at_height(&tx, 100).is_ok());
    }

    /// TE1-3: tx with locktime=5 is invalid at height < 5.
    #[test]
    fn te1_3_locktime_not_yet_reached() {
        let mut tx = minimal_regular_tx();
        tx.locktime = 5;
        let err = validate_transaction_at_height(&tx, 4).unwrap_err();
        assert!(
            matches!(err, ValidationError::TransactionNotYetValid { locktime: 5, block_height: 4 }),
            "Expected TransactionNotYetValid, got {:?}", err
        );
    }

    /// TE1-4: flat-body validator rejects a block containing a locked tx.
    #[test]
    fn te1_4_block_with_locked_tx_rejected() {
        let mut locked_tx = minimal_regular_tx();
        locked_tx.locktime = 100;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), locked_tx], None);
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            te_block_params(50, 1024),
        )
        .is_err());
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo_funding_height_1()),
            te_block_params(100, 1024),
        )
        .is_ok());
    }

    // ── CV-11 / TE-2: expiration_height enforcement ──────────────────────────

    /// TE2-1: tx with expiration_height=0 never expires.
    #[test]
    fn te2_1_no_expiration_always_valid() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 0;
        assert!(validate_transaction_at_height(&tx, 0).is_ok());
        assert!(validate_transaction_at_height(&tx, u32::MAX).is_ok());
    }

    /// TE2-2: tx with expiration_height=10 is valid at height 9 (strictly before expiry).
    #[test]
    fn te2_2_valid_before_expiration() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 10;
        assert!(validate_transaction_at_height(&tx, 9).is_ok());
    }

    /// TE2-3: tx with expiration_height=10 is INVALID at height 10 (window is half-open).
    #[test]
    fn te2_3_expired_at_exact_height() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 10;
        let err = validate_transaction_at_height(&tx, 10).unwrap_err();
        assert!(
            matches!(err, ValidationError::TransactionExpired { expiration_height: 10, block_height: 10 }),
            "Expected TransactionExpired, got {:?}", err
        );
    }

    /// TE2-4: tx with expiration_height=10 is INVALID at height > 10.
    #[test]
    fn te2_4_expired_past_height() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 10;
        let err = validate_transaction_at_height(&tx, 999).unwrap_err();
        assert!(
            matches!(err, ValidationError::TransactionExpired { expiration_height: 10, block_height: 999 }),
            "Expected TransactionExpired, got {:?}", err
        );
    }

    /// TE2-5: flat-body validator rejects a block containing an expired tx.
    #[test]
    fn te2_5_block_with_expired_tx_rejected() {
        let mut expired_tx = minimal_regular_tx();
        expired_tx.expiration_height = 5;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), expired_tx], None);
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            te_block_params(5, 1024),
        )
        .is_err());
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo_funding_height_1()),
            te_block_params(4, 1024),
        )
        .is_ok());
    }

    /// TE3-1: no expiration_height → TE-3 never fires regardless of window.
    #[test]
    fn te3_1_no_expiration_window_check_skipped() {
        let tx = minimal_regular_tx(); // expiration_height = 0
        assert!(validate_transaction_at_height_with_window(&tx, 0, 1024).is_ok());
    }

    /// TE3-2: window = 0 disables TE-3 cap entirely.
    #[test]
    fn te3_2_zero_max_window_disables_check() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 10000; // huge window
        assert!(validate_transaction_at_height_with_window(&tx, 0, 0).is_ok());
    }

    /// TE3-3: window within cap → accepted.
    #[test]
    fn te3_3_window_within_cap_accepted() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 100;
        // submission_height = 0, locktime = 0 → effective_start = 0, window = 100 ≤ 1024
        assert!(validate_transaction_at_height_with_window(&tx, 0, 1024).is_ok());
    }

    /// TE3-4: window exactly equals cap → accepted (inclusive boundary).
    #[test]
    fn te3_4_window_exactly_at_cap_accepted() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 1024;
        assert!(validate_transaction_at_height_with_window(&tx, 0, 1024).is_ok());
    }

    /// TE3-5: window exceeds cap by one → rejected.
    #[test]
    fn te3_5_window_exceeds_cap_by_one_rejected() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 1025;
        let err = validate_transaction_at_height_with_window(&tx, 0, 1024).unwrap_err();
        assert!(
            matches!(err, ValidationError::ExpirationWindowExceeded { window: 1025, max: 1024 }),
            "Expected ExpirationWindowExceeded, got {:?}", err
        );
    }

    /// TE3-6: locktime shifts effective_start; window measured from max(locktime, height).
    #[test]
    fn te3_6_locktime_reduces_effective_window() {
        let mut tx = minimal_regular_tx();
        tx.locktime = 500;
        tx.expiration_height = 1600; // window from locktime = 1100 > 1024
        // At height == locktime, TE-1 passes; effective_start = max(500,500) = 500; window = 1100 > 1024
        let err = validate_transaction_at_height_with_window(&tx, 500, 1024).unwrap_err();
        assert!(matches!(err, ValidationError::ExpirationWindowExceeded { window: 1100, max: 1024 }),
            "Expected ExpirationWindowExceeded{{window:1100,max:1024}}, got {:?}", err);
        // But if height > locktime, window shrinks
        // effective_start = max(500, 600) = 600; window = 1600-600 = 1000 ≤ 1024
        assert!(validate_transaction_at_height_with_window(&tx, 600, 1024).is_ok());
    }

    /// TE3-7: flat-body validator enforces TE-3 in bulk.
    #[test]
    fn te3_7_block_with_oversized_window_rejected() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 2000;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), tx], None);
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            te_block_params(0, 1024),
        )
        .is_err());
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo_funding_height_1()),
            te_block_params(0, 0),
        )
        .is_ok());
    }

    // ── TX-VALID-EXPIRY-1: TE pre-pass before block-wide UTXO batch ─────────

    /// EXPIRY-1 reject: TE-2 failure must not call `get_batch`.
    #[test]
    fn tx_valid_expiry_1_expired_tx_skips_utxo_batch() {
        let mut expired_tx = minimal_regular_tx();
        expired_tx.expiration_height = 5;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), expired_tx], None);
        let utxo = utxo_funding_height_1();
        let batch_calls = std::cell::Cell::new(0);
        let err = validate_shard_block_body(
            &body,
            BlockValidationUtxo::CountingReorgBuffer {
                set: &utxo,
                get_batch_calls: &batch_calls,
            },
            te_block_params(5, 1024),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::TransactionExpired {
                    expiration_height: 5,
                    block_height: 5
                }
            ),
            "expected TransactionExpired, got {err:?}"
        );
        assert_eq!(
            batch_calls.get(),
            0,
            "TE-2 reject must not call utxo.get_batch"
        );
    }

    /// EXPIRY-1 reject: TE-1 (locktime) failure must not call `get_batch`.
    #[test]
    fn tx_valid_expiry_1_locktime_skips_utxo_batch() {
        let mut tx = minimal_regular_tx();
        tx.locktime = 100;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), tx], None);
        let utxo = utxo_funding_height_1();
        let batch_calls = std::cell::Cell::new(0);
        let err = validate_shard_block_body(
            &body,
            BlockValidationUtxo::CountingReorgBuffer {
                set: &utxo,
                get_batch_calls: &batch_calls,
            },
            te_block_params(50, 1024),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::TransactionNotYetValid {
                    locktime: 100,
                    block_height: 50
                }
            ),
            "expected TransactionNotYetValid, got {err:?}"
        );
        assert_eq!(batch_calls.get(), 0);
    }

    /// EXPIRY-1 reject: TE-3 window cap failure must not call `get_batch`.
    #[test]
    fn tx_valid_expiry_1_te3_skips_utxo_batch() {
        let mut tx = minimal_regular_tx();
        tx.expiration_height = 2000;
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), tx], None);
        let utxo = utxo_funding_height_1();
        let batch_calls = std::cell::Cell::new(0);
        let err = validate_shard_block_body(
            &body,
            BlockValidationUtxo::CountingReorgBuffer {
                set: &utxo,
                get_batch_calls: &batch_calls,
            },
            te_block_params(0, 1024),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::ExpirationWindowExceeded { .. }),
            "expected ExpirationWindowExceeded, got {err:?}"
        );
        assert_eq!(batch_calls.get(), 0);
    }

    /// EXPIRY-1 valid path: one `get_batch` after TE pre-pass succeeds.
    #[test]
    fn tx_valid_expiry_1_valid_block_calls_utxo_batch_once() {
        let body =
            ShardBlockBody::from_transactions(&[minimal_coinbase(), minimal_regular_tx()], None);
        let utxo = utxo_funding_height_1();
        let batch_calls = std::cell::Cell::new(0);
        validate_shard_block_body(
            &body,
            BlockValidationUtxo::CountingReorgBuffer {
                set: &utxo,
                get_batch_calls: &batch_calls,
            },
            te_block_params(0, 1024),
        )
        .expect("valid block must pass");
        assert_eq!(
            batch_calls.get(),
            1,
            "valid path must call utxo.get_batch exactly once"
        );
    }

    fn utxo_with(height: u32, idx: u16, value: u64) -> ForkUtxoOverlay {
        let mut u = ForkUtxoOverlay::new();
        u.add(height, idx, flat_output(value));
        u
    }

    /// TX7-1: normal spend (input > output) is accepted.
    #[test]
    fn tx7_1_valid_spend_accepted() {
        let utxo = utxo_with(1, 0, 1000);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_tx_value_conservation(&tx, &utxo).is_ok());
    }

    /// TX7-2: spend where input == output is accepted (zero fee).
    #[test]
    fn tx7_2_zero_fee_accepted() {
        let utxo = utxo_with(1, 0, 1000);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(1000)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_tx_value_conservation(&tx, &utxo).is_ok());
    }

    /// TX7-3: outputs exceed inputs → ValueOverflow.
    #[test]
    fn tx7_3_outputs_exceed_inputs_rejected() {
        let utxo = utxo_with(1, 0, 500);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(600)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let err = validate_tx_value_conservation(&tx, &utxo).unwrap_err();
        assert!(
            matches!(err, ValidationError::ValueOverflow { input_total: 500, output_total: 600 }),
            "unexpected error: {:?}", err
        );
    }

    /// TX7-4: coinbase skipped — outputs may exceed (notional) inputs.
    #[test]
    fn tx7_4_coinbase_skipped() {
        let utxo = ForkUtxoOverlay::new(); // empty — coinbase doesn't look up UTXOs
        let cb = minimal_coinbase();
        assert!(validate_tx_value_conservation(&cb, &utxo).is_ok());
    }

    // ── TX-8: coinbase maturity ───────────────────────────────────────────────

    const MATURITY: u32 = 100; // used in all TX-8 tests

    /// TX8-1: spending a non-coinbase output within 100 blocks is allowed.
    #[test]
    fn tx8_1_regular_output_within_maturity_window_accepted() {
        let mut utxo = ForkUtxoOverlay::new();
        // Block 10 had a coinbase creating 1 output (idx 0) + regular at idx 1.
        // Mark only 1 coinbase output at height 10.
        utxo.apply_transactions_batch(
            &[
                minimal_coinbase(),
                // second tx that creates output idx 1
                Transaction {
                    version: 1,
                    inputs: vec![],  // fake coinbase-style for seeding only
                    outputs: vec![simple_output(500)],
                    locktime: 0,
                    expiration_height: 0,
                    witnesses: Vec::new(),
                    extensions: Vec::new(),
                },
            ],
            10,
        );
        // Spend the regular output at (10, 1) at height 50 (< 10+100=110).
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(10, 1)],
            outputs: vec![simple_output(400)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_tx_coinbase_maturity(&tx, &utxo, 50, MATURITY).is_ok());
    }

    /// TX8-2: spending a coinbase output before maturity is rejected.
    #[test]
    fn tx8_2_coinbase_output_before_maturity_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.apply_transactions_batch(&[minimal_coinbase()], 10);
        // idx 0 is coinbase output; current_height=50 < 10+100=110.
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(10, 0)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let err = validate_tx_coinbase_maturity(&tx, &utxo, 50, MATURITY).unwrap_err();
        assert!(
            matches!(err, ValidationError::CoinbaseImmature {
                prev_height: 10,
                prev_output_idx: 0,
                current_height: 50,
                maturity_height: 110,
            }),
            "unexpected error: {:?}", err
        );
    }

    /// TX8-3: spending a coinbase output exactly at maturity height is allowed.
    #[test]
    fn tx8_3_coinbase_output_at_maturity_accepted() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.apply_transactions_batch(&[minimal_coinbase()], 10);
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(10, 0)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        // current_height = 10 + MATURITY = 110 → allowed.
        assert!(validate_tx_coinbase_maturity(&tx, &utxo, 110, MATURITY).is_ok());
    }

    /// TX8-4: spending any output from a block > 100 blocks ago is always allowed.
    #[test]
    fn tx8_4_old_output_always_allowed() {
        // No coinbase tracking needed — age check short-circuits.
        let utxo = ForkUtxoOverlay::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(1, 0)],
            outputs: vec![simple_output(500)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_tx_coinbase_maturity(&tx, &utxo, 101, MATURITY).is_ok());
    }

    /// TX8-6: maturity=0 disables the check entirely (devnet mode).
    #[test]
    fn tx8_6_maturity_zero_disables_check() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.apply_transactions_batch(&[minimal_coinbase()], 10);
        // Spending coinbase output 1 block later would normally fail at maturity=100.
        let tx = Transaction {
            version: 1,
            inputs: vec![simple_input(10, 0)],
            outputs: vec![simple_output(900)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        assert!(validate_tx_coinbase_maturity(&tx, &utxo, 11, 0).is_ok());
    }

    /// TX8-5: flat-body validator integrates TX-7 + TX-8 (see fv11_8).
    #[test]
    fn tx8_5_block_with_immature_coinbase_spend_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.apply_transactions_batch(&[minimal_coinbase()], 5);
        let spend_tx = Transaction {
            version: 1,
            inputs: vec![simple_input(5, 0)],
            outputs: vec![simple_output(100)],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), spend_tx], None);
        assert!(validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(50, MATURITY),
        )
        .is_err());
    }

    // ── FV-11: validate_block_body ────────────────────────────────────────────

    fn flat_input(prev_height: u32, prev_output_idx: u16) -> FlatInput {
        FlatInput { prev_height, prev_output_idx }
    }

    fn make_range(out_start: u32, out_len: u32, in_start: u32, in_len: u32) -> TransactionDescriptor {
        TransactionDescriptor { out_start, out_len, in_start, in_len, witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0 }
    }

    /// A spend range without a validity record (the one transaction version, TX-11).
    fn make_v2_spend_range(
        out_start: u32,
        out_len: u32,
        in_start: u32,
        in_len: u32,
        witness_start: u32,
    ) -> TransactionDescriptor {
        TransactionDescriptor {
            extension_start: 0,
            extension_len: 0,
            ..make_spend_range(out_start, out_len, in_start, in_len, witness_start)
        }
    }

    /// Extensions vector for [`make_v2_spend_range`]: none (a spend of the one version needs no
    /// validity record).
    fn v2_ext() -> Vec<ExtensionRecord> {
        Vec::new()
    }

    fn make_spend_range(
        out_start: u32,
        out_len: u32,
        in_start: u32,
        in_len: u32,
        witness_start: u32,
    ) -> TransactionDescriptor {
        TransactionDescriptor {
            out_start,
            out_len,
            in_start,
            in_len,
            witness_start,
            witness_len: in_len as u16,
            extension_start: 0,
            extension_len: 0,
        }
    }

    fn dummy_signatures(n: usize) -> Vec<WitnessEntry> {
        (0..n)
            .map(|_| WitnessEntry {
                witness_data: vec![0u8; 64],
            })
            .collect()
    }

    /// FV11-1: empty ranges is always valid.
    #[test]
    fn fv11_1_empty_body_valid() {
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_block_body(&[], &[], &[], &[], &[], BlockValidationUtxo::ReorgBuffer(&utxo), BlockBodyValidationParams::for_tests(1, 0)).is_ok());
    }

    /// FV11-2: coinbase-only block is valid.
    #[test]
    fn fv11_2_coinbase_only_valid() {
        let outputs = vec![flat_output(5_000_000)];
        let ranges = vec![make_range(0, 1, 0, 0)];
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_block_body(&outputs, &[], &ranges, &[], &[], BlockValidationUtxo::ReorgBuffer(&utxo), BlockBodyValidationParams::for_tests(1, 0)).is_ok());
    }

    /// CV-87: TS-T-11 producer stamp on coinbase must not fail validate_block_body.
    #[test]
    fn cv87_coinbase_with_producer_stamp_valid() {
        use crate::common::blocks::shard_block::ShardBlockBody;
        use crate::transaction::Transaction;

        let coinbase = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 5_000_000,
                recipient: TEST_XONLY_PUBKEY,
            }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
            extensions: Vec::new(),
        };
        let body = ShardBlockBody::from_transactions(&[coinbase], Some("A"));
        let utxo = ForkUtxoOverlay::new();
        assert!(
            validate_block_body(
                &body.outputs,
                &body.inputs,
                &body.descriptors,
                &body.witnesses,
                &body.extensions,
                BlockValidationUtxo::ReorgBuffer(&utxo),
                BlockBodyValidationParams::for_tests(0, 0),
            )
            .is_ok()
        );
    }

    /// FV11-3: CB-1 — first range must be coinbase.
    #[test]
    fn fv11_3_cb1_first_range_must_be_coinbase() {
        let outputs = vec![flat_output(1_000)];
        let inputs  = vec![flat_input(0, 0)];
        // First range has in_len=1 (not coinbase) — should fail.
        let ranges = vec![make_spend_range(0, 1, 0, 1, 0)];
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_block_body(&outputs, &inputs, &ranges, &dummy_signatures(1), &[], BlockValidationUtxo::ReorgBuffer(&utxo), BlockBodyValidationParams::for_tests(1, 0)).is_err());
    }

    /// FV11-4: CB-1 — coinbase must have ≥1 output.
    #[test]
    fn fv11_4_cb1_coinbase_needs_output() {
        // out_len=0 for the coinbase range.
        let ranges = vec![make_range(0, 0, 0, 0)];
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_block_body(&[], &[], &ranges, &[], &[], BlockValidationUtxo::ReorgBuffer(&utxo), BlockBodyValidationParams::for_tests(1, 0)).is_err());
    }

    /// FV11-5: TX-2 — intra-transaction duplicate input rejected.
    #[test]
    fn fv11_5_tx2_intra_dup_input_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient: [0u8; 32] });

        let outputs = vec![flat_output(5_000_000), flat_output(9_000)];
        let inputs  = vec![flat_input(0, 0), flat_input(0, 0)]; // dup
        let ranges  = vec![
            make_range(0, 1, 0, 0), // coinbase
            make_spend_range(1, 1, 0, 2, 0), // spend with dup
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(2),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_err());
    }

    /// FV11-6: TX-3 — inter-transaction duplicate input rejected.
    #[test]
    fn fv11_6_tx3_inter_dup_input_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient: [0u8; 32] });

        let outputs = vec![flat_output(5_000_000), flat_output(4_000), flat_output(4_000)];
        let inputs  = vec![flat_input(0, 0), flat_input(0, 0)]; // same input used in two txs
        let ranges  = vec![
            make_range(0, 1, 0, 0), // coinbase
            make_spend_range(1, 1, 0, 1, 0), // tx1 spends (0,0)
            make_spend_range(2, 1, 1, 1, 1), // tx2 spends (0,0) again
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(2),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_err());
    }

    /// FV11-7: TX-7 — value overflow rejected.
    #[test]
    fn fv11_7_tx7_value_overflow_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 5_000, recipient: [0u8; 32] });

        let outputs = vec![flat_output(5_000_000), flat_output(6_000)]; // 6k > 5k input
        let inputs  = vec![flat_input(0, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_spend_range(1, 1, 0, 1, 0),
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_err());
    }

    /// FV11-8: TX-8 — coinbase maturity enforced.
    #[test]
    fn fv11_8_tx8_coinbase_maturity_enforced() {
        let mut utxo = ForkUtxoOverlay::new();
        // Simulate a coinbase output created at height 5.
        utxo.apply_transactions_batch(&[minimal_coinbase()], 5);

        let outputs = vec![flat_output(5_000_000), flat_output(100)];
        let inputs  = vec![flat_input(5, 0)]; // spending coinbase from height 5
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_spend_range(1, 1, 0, 1, 0),
        ];
        // Block height 50 < 5 + 100 maturity
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(50, 100),
        )
        .is_err());
    }

    /// FV11-9: valid coinbase + spend of mature non-coinbase UTXO.
    #[test]
    fn fv11_9_valid_coinbase_and_spend() {
        let mut utxo = ForkUtxoOverlay::new();
        // UTXO value is what matters for TX-7; recipient is irrelevant for lookup.
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient: [0u8; 32] });

        // Non-coinbase output must pass TX-10: use a valid x-only Schnorr pubkey.
        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(9_000)];
        let inputs  = vec![flat_input(0, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(10, 100),
        )
        .is_ok());
    }

    /// FV11-10: TX-12 / CV-28 — fee at/above the floor is accepted, below is rejected.
    #[test]
    fn fv11_10_tx12_min_fee_floor() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient: [0u8; 32] });

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(9_000)]; // fee = 1_000
        let inputs  = vec![flat_input(0, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];

        // tx_size_bytes = 28 (descriptor) + 40 (1 output) + 6 (1 input) + 69 (1 witness) = 143.
        // At rate 10: min_required = ceil(143/4) * 10 = 360 <= fee 1_000 → accepted.
        let low_rate = BlockBodyValidationParams::for_tests(10, 0).with_min_fee_per_4_bytes(10);
        assert!(validate_block_body(
            &outputs, &inputs, &ranges, &dummy_signatures(1), &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo), low_rate,
        )
        .is_ok());

        // At rate 50: min_required = 36 * 50 = 1_800 > fee 1_000 → rejected.
        let high_rate = BlockBodyValidationParams::for_tests(10, 0).with_min_fee_per_4_bytes(50);
        let err = validate_block_body(
            &outputs, &inputs, &ranges, &dummy_signatures(1), &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo), high_rate,
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::TransactionBelowMinFee { fee: 1_000, min_required: 1_800, .. }),
            "unexpected error: {:?}", err
        );
    }

    // ── TX-1: UTXO existence ──────────────────────────────────────────────────

    /// TX1-1: spending an outpoint absent from the UTXO set is rejected.
    #[test]
    fn tx1_1_unknown_utxo_rejected() {
        let utxo = ForkUtxoOverlay::new(); // empty

        let outputs = vec![flat_output(5_000_000), flat_output(100)];
        let inputs  = vec![flat_input(99, 0)]; // no such UTXO
        let ranges  = vec![
            make_range(0, 1, 0, 0), // coinbase
            make_spend_range(1, 1, 0, 1, 0), // spends unknown UTXO
        ];
        let err = validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(100, 0),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("TX-1") || msg.contains("not found"), "unexpected: {}", msg);
    }

    /// TX1-2: spending a known UTXO (already in the set) is accepted.
    #[test]
    fn tx1_2_known_utxo_accepted() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(5, 0, valid_pubkey_output(1_000));

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(900)];
        let inputs  = vec![flat_input(5, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(100, 0),
        )
        .is_ok());
    }

    // ── TX-9: block output count limit ───────────────────────────────────────

    /// TX9-1: exactly the per-chain limit is accepted (shard and beacon).
    #[test]
    fn tx9_1_max_outputs_accepted() {
        assert!(item17_validate_n_outputs(max_block_outputs(1), 1).is_ok());
        assert!(item17_validate_n_outputs(max_block_outputs(0), 0).is_ok());
    }

    /// TX9-2: one output over the limit is rejected, with the right `max`.
    #[test]
    fn tx9_2_over_limit_rejected() {
        for chain_id in [0u16, 1] {
            let err = item17_validate_n_outputs(max_block_outputs(chain_id) + 1, chain_id).unwrap_err();
            assert!(
                matches!(err, ValidationError::OutputCountExceeded { max, .. } if max == max_block_outputs(chain_id)),
                "expected OutputCountExceeded, got {:?}", err
            );
        }
    }

    // ── TX-9 vs storage cap (CLAUDE.md item 17, P1DB-OUTPUT-CAP) ─────────────
    //
    // rustmmrdb's slot store refuses more than 1,016 outputs per shard block
    // and 16,256 per beacon block (`rustmmrdb::MAX_SHARD_OUTPUTS_PER_BLOCK` /
    // `MAX_BEACON_OUTPUTS_PER_BLOCK`, `spendstore/mod.rs`), and a refused
    // persist halts the chain. Consensus must reject such a block first. The
    // literals are pinned to the rustmmrdb constants by
    // `tx9_item17_storage_cap_literals_match_rustmmrdb` (full-node builds).

    /// Storage cap per shard block (`rustmmrdb::MAX_SHARD_OUTPUTS_PER_BLOCK`).
    const ITEM17_STORAGE_SHARD_CAP: usize = 1_016;
    /// Storage cap per beacon block (`rustmmrdb::MAX_BEACON_OUTPUTS_PER_BLOCK`).
    const ITEM17_STORAGE_BEACON_CAP: usize = 16_256;

    /// One coinbase range carrying `n` outputs, validated on `chain_id`
    /// (TX-6: beacon is 0, shard `s` is `s + 1`).
    fn item17_validate_n_outputs(n: usize, chain_id: u16) -> Result<(), ValidationError> {
        let outputs: Vec<FlatOutput> = (0..n).map(|_| flat_output(1)).collect();
        let ranges = vec![make_range(0, n as u32, 0, 0)];
        let utxo = ForkUtxoOverlay::new();
        let mut params = BlockBodyValidationParams::for_tests(1, 0);
        params.chain_id = chain_id;
        validate_block_body(&outputs, &[], &ranges, &[], &[], BlockValidationUtxo::ReorgBuffer(&utxo), params)
    }

    /// Passing guard: the literals above are the real rustmmrdb caps.
    #[cfg(feature = "full-node")]
    #[test]
    fn tx9_item17_storage_cap_literals_match_rustmmrdb() {
        assert_eq!(ITEM17_STORAGE_SHARD_CAP, rustmmrdb::MAX_SHARD_OUTPUTS_PER_BLOCK as usize);
        assert_eq!(ITEM17_STORAGE_BEACON_CAP, rustmmrdb::MAX_BEACON_OUTPUTS_PER_BLOCK as usize);
    }

    /// Passing guard: a block at exactly the storage cap stays valid.
    #[test]
    fn tx9_item17_blocks_at_storage_cap_accepted() {
        assert!(item17_validate_n_outputs(ITEM17_STORAGE_SHARD_CAP, 1).is_ok());
        assert!(item17_validate_n_outputs(ITEM17_STORAGE_BEACON_CAP, 0).is_ok());
    }

    /// Item 17: a shard block with 1,017 outputs must be rejected.
    #[test]
    fn tx9_item17_shard_block_over_storage_cap_rejected() {
        let res = item17_validate_n_outputs(ITEM17_STORAGE_SHARD_CAP + 1, 1);
        assert!(
            matches!(res, Err(ValidationError::OutputCountExceeded { .. })),
            "item 17: a shard block with {} outputs passed validation ({:?}) but storage refuses more \
             than {} (OutputLimitExceeded at persist halts the chain)",
            ITEM17_STORAGE_SHARD_CAP + 1, res, ITEM17_STORAGE_SHARD_CAP
        );
    }

    /// Item 17 / item 21: a beacon block with 16,257 outputs must be rejected.
    #[test]
    fn tx9_item17_beacon_block_over_storage_cap_rejected() {
        let res = item17_validate_n_outputs(ITEM17_STORAGE_BEACON_CAP + 1, 0);
        assert!(
            matches!(res, Err(ValidationError::OutputCountExceeded { .. })),
            "item 17: a beacon block with {} outputs passed validation ({:?}) but storage refuses more \
             than {} (OutputLimitExceeded at persist halts the chain)",
            ITEM17_STORAGE_BEACON_CAP + 1, res, ITEM17_STORAGE_BEACON_CAP
        );
    }

    // ── TX-10: valid Schnorr recipient pubkey ─────────────────────────────────

    // A secp256k1 generator point x-coordinate — a known valid x-only pubkey.
    // G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    const VALID_PUBKEY: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    ];

    fn valid_pubkey_flat_output(value: u64) -> FlatOutput {
        FlatOutput { value, recipient: VALID_PUBKEY }
    }

    fn valid_pubkey_output(value: u64) -> FlatOutput {
        FlatOutput { value, recipient: VALID_PUBKEY }
    }

    /// TX10-1: non-coinbase output with a valid Schnorr pubkey is accepted.
    #[test]
    fn tx10_1_valid_pubkey_accepted() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(1, 0, valid_pubkey_output(1_000));

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(900)];
        let inputs  = vec![flat_input(1, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_ok());
    }

    /// TX10-2: non-coinbase output with all-zeros recipient (not a valid curve
    /// point) is rejected.
    #[test]
    fn tx10_2_invalid_pubkey_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(1, 0, FlatOutput { value: 1_000, recipient: [0u8; 32] });

        // Output at index 1 has an all-zero recipient (invalid curve point).
        let outputs = vec![
            flat_output(5_000_000),
            FlatOutput {
                value: 900,
                recipient: [0u8; 32],
            },
        ];
        let inputs  = vec![flat_input(1, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0), // coinbase — exempt from TX-10
            make_v2_spend_range(1, 1, 0, 1, 0), // regular output with bad pubkey
        ];
        let err = validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidRecipientPubkey { output_index: 1 }),
            "expected InvalidRecipientPubkey at index 1, got {:?}", err
        );
    }

    /// TX10-3: coinbase outputs are exempt from TX-10 (OP_RETURN commitment
    /// uses a BLAKE3 hash which is not a valid curve point).
    #[test]
    fn tx10_3_coinbase_output_exempt_from_pubkey_check() {
        // Coinbase output with all-zeros recipient (would fail TX-10 if checked).
        let outputs = vec![flat_output(5_000_000)];
        let ranges  = vec![make_range(0, 1, 0, 0)]; // coinbase range only
        let utxo = ForkUtxoOverlay::new();
        assert!(validate_block_body(&outputs, &[], &ranges, &[], &[], BlockValidationUtxo::ReorgBuffer(&utxo), BlockBodyValidationParams::for_tests(1, 0)).is_ok());
    }

    /// TX10-4: all-0xFF recipient is not a valid x-only pubkey — rejected.
    #[test]
    fn tx10_4_ff_pubkey_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(1, 0, FlatOutput { value: 1_000, recipient: [0xFFu8; 32] });

        let outputs = vec![flat_output(5_000_000), FlatOutput { value: 900, recipient: [0xFFu8; 32] }];
        let inputs  = vec![flat_input(1, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];
        let err = validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidRecipientPubkey { .. }),
            "expected InvalidRecipientPubkey, got {:?}", err
        );
    }

    // ── TX-4: per-input signature count parity (CV-69) ───────────────────────

    /// TX4-1: spend with matching signature count accepted.
    #[test]
    fn tx4_1_matching_signature_count_accepted() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, valid_pubkey_output(10_000));

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(9_000)];
        let inputs  = vec![flat_input(0, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_v2_spend_range(1, 1, 0, 1, 0),
        ];
        assert!(validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &v2_ext(),
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .is_ok());
    }

    /// TX4-2: block-level signature count mismatch rejected.
    #[test]
    fn tx4_2_block_signature_count_mismatch_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, valid_pubkey_output(10_000));

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(9_000)];
        let inputs  = vec![flat_input(0, 0)];
        let ranges  = vec![
            make_range(0, 1, 0, 0),
            make_spend_range(1, 1, 0, 1, 0),
        ];
        let err = validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &[], // missing signature
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::SignatureCountMismatch { inputs: 1, signatures: 0 }),
            "expected SignatureCountMismatch, got {:?}", err
        );
    }

    /// TX4-3: per-descriptor witness_len != in_len rejected.
    #[test]
    fn tx4_3_descriptor_signature_len_mismatch_rejected() {
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, valid_pubkey_output(10_000));

        let outputs = vec![flat_output(5_000_000), valid_pubkey_flat_output(9_000)];
        let inputs  = vec![flat_input(0, 0), flat_input(0, 1)]; // two inputs
        let mut bad_range = make_spend_range(1, 1, 0, 2, 0);
        bad_range.witness_len = 1; // only one signature declared
        let ranges = vec![make_range(0, 1, 0, 0), bad_range];
        let err = validate_block_body(
            &outputs,
            &inputs,
            &ranges,
            &dummy_signatures(1),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::SignatureCountMismatch { inputs: 2, signatures: 1 }),
            "expected SignatureCountMismatch, got {:?}", err
        );
    }

    /// TX4-4: coinbase descriptor must have witness_len == 0.
    #[test]
    fn tx4_4_coinbase_with_signatures_rejected() {
        let mut bad_coinbase = make_range(0, 1, 0, 0);
        bad_coinbase.witness_len = 1;
        let ranges = vec![bad_coinbase];
        let outputs = vec![flat_output(5_000_000)];
        let utxo = ForkUtxoOverlay::new();
        let err = validate_block_body(
            &outputs,
            &[],
            &ranges,
            &dummy_signatures(0),
            &[],
            BlockValidationUtxo::ReorgBuffer(&utxo),
            BlockBodyValidationParams::for_tests(1, 0),
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::SignatureCountMismatch { inputs: 0, signatures: 1 }),
            "expected SignatureCountMismatch, got {:?}", err
        );
    }

    // ── TX-5 / CV-10: Schnorr signature verification ─────────────────────────

    /// Test-only sighash-v2 signer built on this crate's own `secp256k1`
    /// dependency — mirrors `crates/filament/src/wallet/transaction_builder.rs::SchnorrSigner`,
    /// which cannot be used here directly (it depends on `common-types`; see
    /// NC-5 in `docs/plan/Correctness_and_Validation_Plan.md`).
    fn sign_for_test(
        tx: &Transaction,
        key: &secp256k1::SecretKey,
        chain_id: u16,
        prevouts: &[(u64, [u8; 32])],
    ) -> Vec<WitnessEntry> {
        use secp256k1::{Keypair, Message, Secp256k1};
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, key);
        let txid = tx.txid(chain_id).0;
        let prev = crate::common::crypto::prevouts_hash(prevouts);
        (0..tx.inputs.len())
            .map(|i| {
                let msg = Message::from_digest(crate::common::crypto::sighash_v2(&txid, &prev, i as u32));
                let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
                let mut data = Vec::with_capacity(65);
                data.push(0x01u8);
                data.extend_from_slice(sig.as_ref());
                WitnessEntry { witness_data: data }
            })
            .collect()
    }

    /// TX5-1: correctly signed spend passes production validation.
    #[test]
    fn tx5_1_valid_schnorr_signature_accepted() {
        use secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_bytes = [0x11u8; 32];
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
        let (xonly, _) = keypair.x_only_public_key();
        let recipient = xonly.serialize();

        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient });

        let coinbase = minimal_coinbase();
        let spend = Transaction {
            version: 1,
            inputs: vec![simple_input(0, 0)],
            outputs: vec![TxOutput { value: 9_000, recipient }],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let sk = keypair.secret_key();
        let mut signed = spend.clone();
        signed.witnesses = sign_for_test(&signed, &sk, 1, &[(10_000, recipient)]);

        let body = ShardBlockBody::from_transactions(&[coinbase, signed], None);
        let params = BlockBodyValidationParams::production(1, 0, 1024, 1);
        assert!(
            validate_shard_block_body(
                &body,
                BlockValidationUtxo::ReorgBuffer(&utxo),
                params,
            )
            .is_ok()
        );
    }

    /// TX5-2: tampered witness rejected when signature verify is enabled.
    #[test]
    fn tx5_2_invalid_schnorr_signature_rejected() {
        use secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_bytes = [0x22u8; 32];
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
        let (xonly, _) = keypair.x_only_public_key();
        let recipient = xonly.serialize();

        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient });

        let coinbase = minimal_coinbase();
        let spend = Transaction {
            version: 1,
            inputs: vec![simple_input(0, 0)],
            outputs: vec![TxOutput { value: 9_000, recipient }],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let sk = keypair.secret_key();
        let mut signed = spend;
        signed.witnesses = sign_for_test(&signed, &sk, 1, &[(10_000, recipient)]);
        signed.witnesses[0].witness_data[10] ^= 0xFF;

        let body = ShardBlockBody::from_transactions(&[coinbase, signed], None);
        let params = BlockBodyValidationParams::production(1, 0, 1024, 1);
        let err = validate_shard_block_body(
            &body,
            BlockValidationUtxo::ReorgBuffer(&utxo),
            params,
        )
        .unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidSignature { .. }),
            "expected InvalidSignature, got {:?}", err
        );
    }

    // ── VF-3 Phase 2: sighash v2 is the only scheme (design §5 P2.7) ──────────

    /// One funded key, its UTXO at (0,0) worth 10_000, and an unsigned spend.
    fn v2_fixture(version: u8) -> (secp256k1::SecretKey, [u8; 32], ForkUtxoOverlay, Transaction) {
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x33u8; 32]).unwrap());
        let recipient = keypair.x_only_public_key().0.serialize();
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient });
        let spend = Transaction {
            version,
            inputs: vec![simple_input(0, 0)],
            outputs: vec![TxOutput { value: 9_000, recipient }],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        (keypair.secret_key(), recipient, utxo, spend)
    }

    fn block_check(tx: Transaction, utxo: &ForkUtxoOverlay) -> Result<(), ValidationError> {
        let body = ShardBlockBody::from_transactions(&[minimal_coinbase(), tx], None);
        let params = BlockBodyValidationParams::production(1, 0, 1024, 1);
        validate_shard_block_body(&body, BlockValidationUtxo::ReorgBuffer(utxo), params)
    }

    fn mempool_check(tx: &Transaction, utxo: &ForkUtxoOverlay) -> Result<(), ValidationError> {
        let params = MempoolAdmissionParams::production(1, 0, 1024, 1);
        validate_transaction_for_mempool(tx, BlockValidationUtxo::ReorgBuffer(utxo), params)
    }

    /// V2-1: a spend signed with sighash v2 passes both paths.
    #[test]
    fn sighash_v2_1_signed_spend_accepted() {
        let (sk, recipient, utxo, mut tx) = v2_fixture(1);
        tx.witnesses = sign_for_test(&tx, &sk, 1, &[(10_000, recipient)]);
        mempool_check(&tx, &utxo).unwrap();
        block_check(tx, &utxo).unwrap();
    }

    /// V2-2: TX-11 — a spend of any other version is refused, even correctly signed.
    #[test]
    fn sighash_v2_2_other_version_spend_rejected() {
        let (sk, recipient, utxo, mut tx) = v2_fixture(2);
        tx.witnesses = sign_for_test(&tx, &sk, 1, &[(10_000, recipient)]);
        let e = mempool_check(&tx, &utxo).unwrap_err();
        assert!(format!("{e:?}").contains("TX-11"), "{e:?}");
        let e = block_check(tx, &utxo).unwrap_err();
        assert!(format!("{e:?}").contains("TX-11"), "{e:?}");
    }

    /// V2-3: an unsigned spend is refused by production mempool admission
    /// (it could never be mined).
    #[test]
    fn sighash_v2_3_unsigned_spend_rejected_by_mempool() {
        let (_, _, utxo, tx) = v2_fixture(1);
        assert!(matches!(
            mempool_check(&tx, &utxo),
            Err(ValidationError::SignatureCountMismatch { inputs: 1, signatures: 0 })
        ));
    }

    /// V2-4: anything changed after signing invalidates the signature —
    /// an extension, the chain, or the prevout value the signer was told.
    #[test]
    fn sighash_v2_4_tampering_after_signing_rejected() {
        use crate::transaction::{ExtensionHeader, ExtensionRecord};
        let (sk, recipient, utxo, tx) = v2_fixture(1);

        let mut ext = tx.clone();
        ext.witnesses = sign_for_test(&ext, &sk, 1, &[(10_000, recipient)]);
        ext.extensions.push(ExtensionRecord {
            header: ExtensionHeader { extension_type: 0x1234, version: 1, payload_length: 1 },
            payload: vec![1],
        });
        assert!(matches!(mempool_check(&ext, &utxo), Err(ValidationError::InvalidSignature { .. })));

        let mut chain = tx.clone();
        chain.witnesses = sign_for_test(&chain, &sk, 2, &[(10_000, recipient)]);
        assert!(matches!(mempool_check(&chain, &utxo), Err(ValidationError::InvalidSignature { .. })));

        // Signer told the input is worth 9_500 (hiding 500 of fee): rejected.
        let mut lie = tx;
        lie.witnesses = sign_for_test(&lie, &sk, 1, &[(9_500, recipient)]);
        assert!(matches!(mempool_check(&lie, &utxo), Err(ValidationError::InvalidSignature { .. })));
        assert!(matches!(block_check(lie, &utxo), Err(ValidationError::InvalidSignature { .. })));
    }

    // ── MEMPOOL-SIGCACHE-1 Phase 1: Q2 test matrix ───────────────────────────

    mod sigcache {
        use super::*;
        use crate::common::crypto::{
            prevouts_hash, sighash_v2, NoSigCache, SigCache, SigCacheKey, SCHEME_TAG_SINGLE_KEY,
        };

        const CHAIN: u16 = 1;
        const WIN: u32 = 1024;

        fn key() -> (secp256k1::SecretKey, [u8; 32]) {
            use secp256k1::{Keypair, Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x5Au8; 32]).unwrap());
            (kp.secret_key(), kp.x_only_public_key().0.serialize())
        }

        fn funded(recipient: [u8; 32]) -> ForkUtxoOverlay {
            let mut utxo = ForkUtxoOverlay::new();
            utxo.add(0, 0, FlatOutput { value: 10_000, recipient });
            utxo
        }

        fn signed_spend(locktime: u32, expiration_height: u32) -> (Transaction, [u8; 32]) {
            let (sk, r) = key();
            let mut tx = Transaction {
                version: 1,
                inputs: vec![simple_input(0, 0)],
                outputs: vec![TxOutput { value: 9_000, recipient: r }],
                locktime,
                expiration_height,
                witnesses: Vec::new(),
                extensions: Vec::new(),
            };
            tx.witnesses = sign_for_test(&tx, &sk, CHAIN, &[(10_000, r)]);
            (tx, r)
        }

        fn mp(tip: u32) -> MempoolAdmissionParams {
            MempoolAdmissionParams::production(tip, 0, WIN, CHAIN)
        }

        fn bp(h: u32) -> BlockBodyValidationParams {
            BlockBodyValidationParams::production(h, 0, WIN, CHAIN)
        }

        fn admit(tx: &Transaction, utxo: &ForkUtxoOverlay, p: MempoolAdmissionParams, v: &dyn SigVerifier)
            -> Result<(), ValidationError> {
            validate_transaction_for_mempool_with(tx, BlockValidationUtxo::ReorgBuffer(utxo), p, v)
        }

        fn block(txs: &[Transaction], utxo: &ForkUtxoOverlay, p: BlockBodyValidationParams, v: &dyn SigVerifier,
            hits: &mut Vec<SigCacheKey>) -> Result<(), ValidationError> {
            let mut all = vec![minimal_coinbase()];
            all.extend_from_slice(txs);
            let body = ShardBlockBody::from_transactions(&all, None);
            validate_shard_block_body_with(&body, BlockValidationUtxo::ReorgBuffer(utxo), p, v, hits)
        }

        /// Keep-on-revert: admit → block hit → erase on connect → keys recomputed by
        /// `sig_cache_keys_for_tx` equal the erased ones → reinsert → re-admit hits.
        #[test]
        fn keep_on_revert_rewarm_hits_readmit() {
            let (tx, r) = signed_spend(0, 0);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            let mut hits = Vec::new();
            block(&[tx.clone()], &utxo, bp(11), &c, &mut hits).unwrap();
            assert_eq!(hits.len(), 1);
            c.erase(&hits);
            assert_eq!(c.len(), 0);
            let keys = sig_cache_keys_for_tx(&tx, BlockValidationUtxo::ReorgBuffer(&utxo), CHAIN, &c);
            assert_eq!(keys, hits, "recomputed keys match the erased block hits");
            assert!(sig_cache_keys_for_tx(&tx, BlockValidationUtxo::ReorgBuffer(&utxo), CHAIN + 1, &c) != hits);
            assert!(sig_cache_keys_for_tx(&tx, BlockValidationUtxo::ReorgBuffer(&ForkUtxoOverlay::new()), CHAIN, &c).is_empty());
            SigVerifier::reinsert(&c, &keys);
            assert!(c.contains(&keys[0]));
            admit(&tx, &utxo, mp(10), &c).unwrap();
            assert_eq!(c.len(), 1);
            let mut hits2 = Vec::new();
            block(&[tx], &utxo, bp(11), &c, &mut hits2).unwrap();
            assert_eq!(hits2, keys);
        }

        /// TE-2 at H and H+1 fails despite warm cache; H-1 passes on a hit.
        #[test]
        fn te2_expiry_enforced_on_cache_hit() {
            let (tx, r) = signed_spend(0, 20);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            assert_eq!(c.len(), 1);
            let mut hits = Vec::new();
            block(&[tx.clone()], &utxo, bp(19), &c, &mut hits).unwrap();
            assert_eq!(hits.len(), 1, "H-1 must pass via a cache hit");
            for h in [20, 21] {
                let mut hits = Vec::new();
                let e = block(&[tx.clone()], &utxo, bp(h), &c, &mut hits).unwrap_err();
                assert!(matches!(e, ValidationError::TransactionExpired { .. }), "h={h}: {e:?}");
            }
            assert_eq!(c.len(), 1, "block path never inserts or erases by itself");
        }

        /// TE-1 enforced on a hit (warmed via insert_verified; CV-70 refuses pre-locktime).
        #[test]
        fn te1_locktime_enforced_on_cache_hit() {
            let (tx, r) = signed_spend(30, 0);
            let utxo = funded(r);
            let c = SigCache::new();
            let sh = sighash_v2(&tx.txid(CHAIN).0, &prevouts_hash(&[(10_000, r)]), 0);
            c.insert_verified(&tx.witnesses[0], &r, &sh, 0, SCHEME_TAG_SINGLE_KEY).unwrap();
            let mut hits = Vec::new();
            let e = block(&[tx.clone()], &utxo, bp(29), &c, &mut hits).unwrap_err();
            assert!(matches!(e, ValidationError::TransactionNotYetValid { .. }), "{e:?}");
            let mut hits = Vec::new();
            block(&[tx], &utxo, bp(30), &c, &mut hits).unwrap();
            assert_eq!(hits.len(), 1);
        }

        /// TE-3 window enforced on a hit.
        #[test]
        fn te3_window_enforced_on_cache_hit() {
            let (tx, r) = signed_spend(0, 500);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            let mut p = bp(10);
            p.max_expiration_window = 100;
            let mut hits = Vec::new();
            let e = block(&[tx], &utxo, p, &c, &mut hits).unwrap_err();
            assert!(matches!(e, ValidationError::ExpirationWindowExceeded { .. }), "{e:?}");
        }

        /// Same outpoint re-addressed (different value / owner) → sighash/pubkey change → miss + reject.
        #[test]
        fn readdressed_input_misses_and_rejects() {
            let (tx, r) = signed_spend(0, 0);
            let c = SigCache::new();
            admit(&tx, &funded(r), mp(10), &c).unwrap();
            let mut other_value = ForkUtxoOverlay::new();
            other_value.add(0, 0, FlatOutput { value: 9_999, recipient: r });
            let mut other_owner = ForkUtxoOverlay::new();
            other_owner.add(0, 0, FlatOutput { value: 10_000, recipient: [0x77; 32] });
            for u in [&other_value, &other_owner] {
                let mut hits = Vec::new();
                assert!(block(&[tx.clone()], u, bp(11), &c, &mut hits).is_err());
                assert!(hits.is_empty());
            }
        }

        /// TX-8 coinbase maturity enforced on a hit.
        #[test]
        fn tx8_maturity_enforced_on_cache_hit() {
            let (sk, r) = key();
            let mut utxo = ForkUtxoOverlay::new();
            let cb = Transaction { outputs: vec![TxOutput { value: 10_000, recipient: r }], ..minimal_coinbase() };
            utxo.apply_transactions_batch(&[cb], 0);
            let mut tx = Transaction {
                version: 1,
                inputs: vec![simple_input(0, 0)],
                outputs: vec![TxOutput { value: 9_000, recipient: r }],
                locktime: 0, expiration_height: 0, witnesses: Vec::new(), extensions: Vec::new(),
            };
            tx.witnesses = sign_for_test(&tx, &sk, CHAIN, &[(10_000, r)]);
            let c = SigCache::new();
            admit(&tx, &utxo, MempoolAdmissionParams::production(200, 100, WIN, CHAIN), &c).unwrap();
            assert_eq!(c.len(), 1);
            let mut hits = Vec::new();
            let e = block(&[tx], &utxo, BlockBodyValidationParams::production(50, 100, WIN, CHAIN), &c, &mut hits)
                .unwrap_err();
            assert!(matches!(e, ValidationError::CoinbaseImmature { .. }), "{e:?}");
        }

        /// TX-3 duplicate spend in one block rejected even with both sigs hitting.
        #[test]
        fn tx3_double_spend_enforced_on_cache_hit() {
            let (tx, r) = signed_spend(0, 0);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            let mut hits = Vec::new();
            assert!(block(&[tx.clone(), tx], &utxo, bp(11), &c, &mut hits).is_err());
        }

        #[test]
        fn verify_signatures_false_inserts_nothing() {
            let (tx, r) = signed_spend(0, 0);
            let c = SigCache::new();
            let mut p = mp(10);
            p.verify_signatures = false;
            admit(&tx, &funded(r), p, &c).unwrap();
            assert!(c.is_empty());
        }

        #[test]
        fn failed_admission_not_cached() {
            let (mut tx, r) = signed_spend(0, 0);
            tx.witnesses[0].witness_data[10] ^= 0xFF;
            let c = SigCache::new();
            assert!(matches!(admit(&tx, &funded(r), mp(10), &c), Err(ValidationError::InvalidSignature { .. })));
            assert!(c.is_empty());
        }

        #[test]
        fn block_path_never_inserts() {
            let (tx, r) = signed_spend(0, 0);
            let c = SigCache::new();
            let mut hits = Vec::new();
            block(&[tx], &funded(r), bp(11), &c, &mut hits).unwrap();
            assert!(hits.is_empty());
            assert!(c.is_empty());
        }

        #[test]
        fn wrong_chain_id_misses() {
            let (tx, r) = signed_spend(0, 0);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            let mut p = bp(11);
            p.chain_id = 2;
            let mut hits = Vec::new();
            let e = block(&[tx], &utxo, p, &c, &mut hits).unwrap_err();
            assert!(matches!(e, ValidationError::InvalidSignature { .. }), "{e:?}");
            assert!(hits.is_empty());
        }

        /// Hits are erased only by the caller after connect; a failed block erases nothing.
        #[test]
        fn erase_after_connect_only() {
            let (tx, r) = signed_spend(0, 20);
            let utxo = funded(r);
            let c = SigCache::new();
            admit(&tx, &utxo, mp(10), &c).unwrap();
            let mut hits = Vec::new();
            assert!(block(&[tx.clone()], &utxo, bp(25), &c, &mut hits).is_err());
            assert_eq!(c.len(), 1); // failed: caller drops hits, no erase
            let mut hits = Vec::new();
            block(&[tx], &utxo, bp(11), &c, &mut hits).unwrap();
            c.erase(&hits);
            assert!(c.is_empty());
        }

        /// Cold cache, warm cache, and NoSigCache produce identical verdicts.
        #[test]
        fn cold_warm_nocache_equivalent() {
            let (good, r) = signed_spend(0, 20);
            let utxo = funded(r);
            let mut bad = good.clone();
            bad.witnesses[0].witness_data[12] ^= 1;
            let mut readdr = ForkUtxoOverlay::new();
            readdr.add(0, 0, FlatOutput { value: 9_999, recipient: r });
            let cases: Vec<(Vec<Transaction>, &ForkUtxoOverlay, u32)> = vec![
                (vec![good.clone()], &utxo, 11),
                (vec![good.clone()], &utxo, 20),
                (vec![bad.clone()], &utxo, 11),
                (vec![good.clone(), good.clone()], &utxo, 11),
                (vec![good.clone()], &readdr, 11),
            ];
            for (txs, u, h) in cases {
                let mut hits = Vec::new();
                let base = block(&txs, u, bp(h), &NoSigCache, &mut hits);
                let cold = SigCache::new();
                let mut hits = Vec::new();
                let rc = block(&txs, u, bp(h), &cold, &mut hits);
                let warm = SigCache::new();
                admit(&good, &utxo, mp(10), &warm).unwrap();
                let mut hits = Vec::new();
                let rw = block(&txs, u, bp(h), &warm, &mut hits);
                assert_eq!(base, rc);
                assert_eq!(base, rw);
            }
        }

        // ── ESC: escrow policy-hash output (docs/plan/Escrow_Policy_Hash_Consensus_Spec.md) ──

        use crate::common::crypto::escrow::{coop_witness, escrow_sighash, recovery_witness};
        use crate::common::crypto::{EscrowPolicy, WITNESS_TYPE_ESCROW_COOP, WITNESS_TYPE_ESCROW_RECOVERY};

        const H: u32 = 100;

        struct Esc {
            sender: secp256k1::Keypair,
            provider: secp256k1::Keypair,
            policy: EscrowPolicy,
            utxo: ForkUtxoOverlay,
            tx: Transaction,
        }

        /// Escrow output worth 10_000 at (0,0); unsigned spend paying 9_000 to the sender.
        fn esc_fixture() -> Esc {
            use secp256k1::{Keypair, Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let sender = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x31u8; 32]).unwrap());
            let provider = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x32u8; 32]).unwrap());
            let policy = EscrowPolicy {
                sender_pk: sender.x_only_public_key().0.serialize(),
                provider_pk: provider.x_only_public_key().0.serialize(),
                unlock_height: H,
            };
            let mut utxo = ForkUtxoOverlay::new();
            utxo.add(0, 0, FlatOutput { value: 10_000, recipient: policy.hash() });
            let tx = Transaction {
                version: 1,
                inputs: vec![simple_input(0, 0)],
                outputs: vec![TxOutput { value: 9_000, recipient: policy.sender_pk }],
                locktime: 0,
                expiration_height: 0,
                witnesses: Vec::new(),
                extensions: Vec::new(),
            };
            Esc { sender, provider, policy, utxo, tx }
        }

        fn esc_msg(e: &Esc, path: u8) -> [u8; 32] {
            let prev = prevouts_hash(&[(10_000, e.policy.hash())]);
            escrow_sighash(&sighash_v2(&e.tx.txid(CHAIN).0, &prev, 0), path)
        }

        fn sig(k: &secp256k1::Keypair, m: &[u8; 32]) -> [u8; 64] {
            secp256k1::Secp256k1::new()
                .sign_schnorr_no_aux_rand(&secp256k1::Message::from_digest(*m), k)
                .serialize()
        }

        fn esc_coop(mut e: Esc) -> (Transaction, ForkUtxoOverlay, [u8; 64]) {
            let m = esc_msg(&e, WITNESS_TYPE_ESCROW_COOP);
            let s_sender = sig(&e.sender, &m);
            e.tx.witnesses = vec![coop_witness(&e.policy, &s_sender, &sig(&e.provider, &m))];
            (e.tx, e.utxo, s_sender)
        }

        fn esc_recovery(mut e: Esc) -> (Transaction, ForkUtxoOverlay) {
            let m = esc_msg(&e, WITNESS_TYPE_ESCROW_RECOVERY);
            e.tx.witnesses = vec![recovery_witness(&e.policy, &sig(&e.sender, &m))];
            (e.tx, e.utxo)
        }

        fn is_rule(e: &ValidationError, r: &str) -> bool {
            matches!(e, ValidationError::EscrowSpend { rule, .. } if *rule == r)
        }

        /// Spec tests 2 + 11 (block and mempool): cooperative only below H.
        #[test]
        fn esc_coop_spend_valid_only_below_h() {
            let (tx, utxo, _) = esc_coop(esc_fixture());
            let v = NoSigCache;
            admit(&tx, &utxo, mp(H - 1), &v).unwrap();
            block(&[tx.clone()], &utxo, bp(H - 1), &v, &mut Vec::new()).unwrap();
            assert!(is_rule(&admit(&tx, &utxo, mp(H), &v).unwrap_err(), "ESC-3"));
            assert!(is_rule(&block(&[tx], &utxo, bp(H), &v, &mut Vec::new()).unwrap_err(), "ESC-3"));
        }

        /// Spec tests 3 + 11: recovery only from H (refused at admission before H).
        #[test]
        fn esc_recovery_spend_valid_only_from_h() {
            let (tx, utxo) = esc_recovery(esc_fixture());
            let v = NoSigCache;
            assert!(is_rule(&admit(&tx, &utxo, mp(H - 1), &v).unwrap_err(), "ESC-3"));
            assert!(is_rule(&block(&[tx.clone()], &utxo, bp(H - 1), &v, &mut Vec::new()).unwrap_err(), "ESC-3"));
            admit(&tx, &utxo, mp(H), &v).unwrap();
            block(&[tx], &utxo, bp(H), &v, &mut Vec::new()).unwrap();
        }

        /// Spec test 6 through the real validators: the sender's cooperative signature
        /// placed in a recovery witness after H does not authorise the spend.
        #[test]
        fn esc_path_reuse_rejected_end_to_end() {
            let e = esc_fixture();
            let policy = e.policy;
            let (mut tx, utxo, s_sender) = esc_coop(e);
            tx.witnesses = vec![recovery_witness(&policy, &s_sender)];
            let v = NoSigCache;
            assert!(matches!(admit(&tx, &utxo, mp(H), &v).unwrap_err(), ValidationError::InvalidSignature { .. }));
            assert!(matches!(
                block(&[tx], &utxo, bp(H), &v, &mut Vec::new()).unwrap_err(),
                ValidationError::InvalidSignature { .. }
            ));
        }

        /// Spec test 7: a single-key witness cannot spend an escrow output.
        #[test]
        fn esc_single_key_witness_cannot_spend_escrow() {
            let e = esc_fixture();
            let sk = e.sender.secret_key();
            let pol_hash = e.policy.hash();
            let mut tx = e.tx.clone();
            tx.witnesses = sign_for_test(&tx, &sk, CHAIN, &[(10_000, pol_hash)]);
            let v = NoSigCache;
            assert!(admit(&tx, &e.utxo, mp(10), &v).is_err());
            assert!(block(&[tx], &e.utxo, bp(10), &v, &mut Vec::new()).is_err());
        }

        /// Spec test 9 (was `sigcache_2of2_*` placeholders): a cached cooperative
        /// signature never makes a cooperative spend valid at or after H — the path is
        /// selected by height before any cache lookup.
        #[test]
        fn esc_cached_coop_signature_does_not_pass_at_h() {
            let (tx, utxo, _) = esc_coop(esc_fixture());
            let c = SigCache::new();
            admit(&tx, &utxo, mp(H - 1), &c).unwrap();
            assert_eq!(c.len(), 2, "two signatures cached under the two escrow tags");
            let mut hits = Vec::new();
            assert!(is_rule(&block(&[tx.clone()], &utxo, bp(H), &c, &mut hits).unwrap_err(), "ESC-3"));
            assert!(hits.is_empty());
            // Below H the cached pair hits, and keep-on-revert recomputes the same keys.
            block(&[tx.clone()], &utxo, bp(H - 1), &c, &mut hits).unwrap();
            assert_eq!(hits.len(), 2);
            let keys = sig_cache_keys_for_tx(&tx, BlockValidationUtxo::ReorgBuffer(&utxo), CHAIN, &c);
            assert_eq!(keys, hits);
        }

        /// ESC-6: the recovery signature is cached under its own tag, distinct from the
        /// cooperative sender key for the same signer.
        #[test]
        fn esc_scheme_tags_separate_paths() {
            let (coop, utxo, _) = esc_coop(esc_fixture());
            let (rec, _) = esc_recovery(esc_fixture());
            let c = SigCache::new();
            let ck = sig_cache_keys_for_tx(&coop, BlockValidationUtxo::ReorgBuffer(&utxo), CHAIN, &c);
            let rk = sig_cache_keys_for_tx(&rec, BlockValidationUtxo::ReorgBuffer(&utxo), CHAIN, &c);
            assert_eq!((ck.len(), rk.len()), (2, 1));
            assert!(!ck.contains(&rk[0]));
        }

        /// TX-12 counts real witness bytes on both paths: a fee that would cover a
        /// 65-byte witness does not cover the 197-byte cooperative witness.
        #[test]
        fn esc_fee_floor_counts_real_witness_bytes() {
            let mut e = esc_fixture();
            e.tx.outputs[0].value = 10_000 - 500; // fee 500
            let (tx, utxo, _) = esc_coop(e);
            let v = NoSigCache;
            // flat size = 28 + 40 + 6 + (4 + 197) = 275 → floor ceil(275/4) * 10 = 690 > 500.
            let mpp = mp(10).with_min_fee_per_4_bytes(10);
            let bpp = bp(10).with_min_fee_per_4_bytes(10);
            assert!(admit(&tx, &utxo, mpp, &v).is_err());
            assert!(block(&[tx], &utxo, bpp, &v, &mut Vec::new()).is_err());
        }
    }
}
