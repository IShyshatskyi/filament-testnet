// src/common/expand_voting.rs — Shard Expansion Voting
//
// Implements the on-chain voting mechanism that allows miners to open new shard
// chains via a supermajority (5/8) vote recorded in the beacon block version
// field (bit 5: vote_expand_flag).
//
// Two public types:
//  - ExpandVotingConfig  — consensus-critical parameters embedded in genesis
//  - EpochExpandState    — per-epoch tally + expansion decision
//
// Public functions:
//  - record_expand_vote  — called per block
//  - finalise_expand_epoch — called at epoch boundary (pure, deterministic)
//  - compute_required_s_bits — derives s exponent for a shard count

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default blocks-per-epoch (consensus-critical). Used by mainnet, testnet1,
/// testnet2, and devnet. Networks that need a different value (e.g.
/// testnet-stress, TS-2b) set `ExpandVotingConfig.epoch_length` in genesis
/// and call [`init_epoch_length`] once at process startup.
pub const DEFAULT_EPOCH_LENGTH: u32 = 4096;

/// Deprecated alias for [`DEFAULT_EPOCH_LENGTH`]. Always equals the default —
/// NOT necessarily the active process epoch length. New code (and any code
/// that runs after startup, i.e. every production epoch-boundary check)
/// must call [`epoch_length`] instead. Kept only so existing tests that
/// assert against the literal 4096 keep compiling/passing unchanged.
pub const EPOCH_LENGTH: u32 = DEFAULT_EPOCH_LENGTH;

/// Beacon blocks after an epoch boundary before new shard IDs become valid.
pub const SHARD_ACTIVATION_DELAY: u32 = 16;

// ── Per-process epoch length (TS-2b) ─────────────────────────────────────────
//
// `EPOCH_LENGTH` used to be a single compile-time constant shared by every
// network. Since epoch length is genuinely consensus-critical and identical
// for every chain within one running network, but testnet-stress needs a
// much shorter epoch (256 blocks) to ramp shard count inside a 30-day
// window, it is now a per-*process* value: set once at startup from the
// loaded network's `ExpandVotingConfig.epoch_length`, then read by every
// epoch-boundary computation for the lifetime of the process. A process
// only ever runs one network, so this is equivalent to "per-network"
// without threading a config reference through every call site (several of
// which — e.g. `ShardEpochCache` — are deliberately config-free for O(1)
// lookups).
static EPOCH_LENGTH_CELL: OnceLock<u32> = OnceLock::new();

thread_local! {
    /// Test-only, per-thread override of the epoch length (see [`set_epoch_length_for_test`]).
    static EPOCH_LENGTH_TEST_OVERRIDE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// **Tests only.** Set the epoch length for the *current thread* only, so tests that need
/// different epoch lengths (8, 64, 256, ...) can run side by side in one process under plain
/// `cargo test`, instead of fighting over the process-wide `OnceLock` that
/// [`init_epoch_length`] sets (that one panics on a second, different value). The override is
/// read by [`epoch_length`] on this thread only: a test that moves epoch-dependent work onto
/// another thread (a multi-thread runtime, `spawn_blocking`, rayon) would see the default; keep
/// such work on the test thread. Production code must keep using [`init_epoch_length`].
pub fn set_epoch_length_for_test(value: u32) {
    EPOCH_LENGTH_TEST_OVERRIDE.with(|c| c.set(Some(value)));
}

/// Initialise the process-wide epoch length from the active network's
/// genesis `shard_expansion.epoch_length`. Must be called once, at startup,
/// before any beacon/shard chain state is constructed — calling it after
/// chain state exists would desynchronise epoch-boundary math between code
/// that ran before and after the change.
///
/// Idempotent when called again with the same value (harmless — e.g. tests
/// that build multiple chains for the same network); panics if called again
/// with a *different* value, since that would silently corrupt consensus
/// state rather than fail loudly.
///
/// **Test note (fixed Oct 7, 2026):** tests must NOT call this. Different tests need
/// different epoch lengths (8, 64, 256), and this process-wide cell can only be set once,
/// so they collided under plain `cargo test` (one process per test binary). Tests call
/// [`set_epoch_length_for_test`], a per-thread override, instead.
pub fn init_epoch_length(value: u32) {
    if let Err(_) = EPOCH_LENGTH_CELL.set(value) {
        let existing = *EPOCH_LENGTH_CELL.get().expect("just failed to set, so it's occupied");
        assert_eq!(
            existing, value,
            "epoch_length already initialised to {existing}, cannot reinitialise to {value} \
             in the same process"
        );
    }
}

/// The active process-wide epoch length in blocks (consensus-critical).
///
/// Defaults to [`DEFAULT_EPOCH_LENGTH`] (4096) unless overridden at startup
/// via [`init_epoch_length`] — e.g. testnet-stress sets 256 (TS-2b).
#[inline]
pub fn epoch_length() -> u32 {
    if let Some(v) = EPOCH_LENGTH_TEST_OVERRIDE.with(|c| c.get()) {
        return v;
    }
    *EPOCH_LENGTH_CELL.get().unwrap_or(&DEFAULT_EPOCH_LENGTH)
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Shard expansion voting parameters. CONSENSUS CRITICAL.
///
/// Embedded in `BeaconGenesisConfig.shard_expansion`; changing any field is a
/// hard fork.  All nodes must use identical values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandVotingConfig {
    /// Shard chains active at genesis (no voting required for epoch 0).
    /// May be any positive count that fits within `2^initial_s_bits − 1`
    /// (inclusive — may fill every non-zero hash-sorting code).
    /// While `active_shard_count < 4`, each successful expand epoch opens
    /// exactly one new shard (`compute_step`); at ≥ 4 the percentage step
    /// formula applies.
    pub initial_shard_count: u16,

    /// Hash-sorting exponent at genesis.
    /// Must satisfy `initial_shard_count ≤ 2^initial_s_bits − 1`.
    pub initial_s_bits: u8,

    /// Numerator for the threshold check.
    /// Expansion fires when `ones_count × threshold_denominator ≥ total × threshold_numerator`.
    /// Default: 5.
    pub threshold_numerator: u64,

    /// Denominator for the threshold check.  Default: 8.
    pub threshold_denominator: u64,

    /// Step numerator: `step = floor(count × step_numerator / step_denominator)`.
    /// Default: 1.
    pub step_numerator: u16,

    /// Step denominator.  Default: 4.
    pub step_denominator: u16,

    /// Beacon blocks after epoch boundary before new shard chains activate.
    /// Default: 16.
    pub activation_delay: u32,

    /// Blocks per epoch (TS-2b). CONSENSUS CRITICAL — identical for every
    /// chain (beacon + all shards) within one network for the network's
    /// lifetime.
    ///
    /// `#[serde(default)]` so existing genesis TOML files that predate this
    /// field (mainnet/testnet1/testnet2/devnet) keep getting
    /// [`DEFAULT_EPOCH_LENGTH`] (4096) with no config changes required.
    /// Read once at process startup via [`init_epoch_length`]; all
    /// production epoch-boundary math afterward reads it back through
    /// [`epoch_length`].
    #[serde(default = "default_epoch_length")]
    pub epoch_length: u32,
}

fn default_epoch_length() -> u32 {
    DEFAULT_EPOCH_LENGTH
}

impl Default for ExpandVotingConfig {
    fn default() -> Self {
        Self {
            initial_shard_count: 3,
            initial_s_bits: 2,
            threshold_numerator: 5,
            threshold_denominator: 8,
            step_numerator: 1,
            step_denominator: 4,
            activation_delay: SHARD_ACTIVATION_DELAY,
            epoch_length: DEFAULT_EPOCH_LENGTH,
        }
    }
}

impl ExpandVotingConfig {
    /// Returns the genesis config for testnet (3 shards, s=2).
    pub fn testnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.initial_shard_count == 0 {
            return Err("initial_shard_count must be > 0".into());
        }
        let capacity = (1u32 << self.initial_s_bits).saturating_sub(1);
        if self.initial_shard_count as u32 > capacity {
            return Err(format!(
                "initial_shard_count ({}) must be ≤ 2^s_bits − 1 ({})",
                self.initial_shard_count, capacity
            ));
        }
        if self.threshold_numerator == 0 || self.threshold_denominator == 0 {
            return Err("threshold numerator/denominator must be > 0".into());
        }
        if self.threshold_numerator >= self.threshold_denominator {
            return Err("threshold_numerator must be < threshold_denominator".into());
        }
        if self.step_denominator == 0 || self.step_numerator == 0 {
            return Err("step_numerator/denominator must be > 0".into());
        }
        if self.activation_delay == 0 {
            return Err("activation_delay must be > 0".into());
        }
        if self.epoch_length == 0 {
            return Err("epoch_length must be > 0".into());
        }
        if self.activation_delay >= self.epoch_length {
            return Err(format!(
                "activation_delay ({}) must be < epoch_length ({})",
                self.activation_delay, self.epoch_length
            ));
        }
        // Soft: under-filled (s, count) is valid capacity-wise but suboptimal.
        // Standard + stress presets (3 / s=2) sit in-band. See
        // `nonoptimal_s_bits_warning`.
        emit_nonoptimal_s_bits_warning(self.initial_s_bits, self.initial_shard_count);
        Ok(())
    }

    /// Number of new shards to open after a successful expand vote.
    ///
    /// - **`active_shard_count < 4`:** always `1` (fixed one-at-a-time ramp
    ///   until the network reaches the percentage-step regime).
    /// - **`active_shard_count ≥ 4`:** `max(1, floor(count × num / den))`
    ///   (default ~25% of current count per epoch).
    pub fn compute_step(&self, active_shard_count: u16) -> u16 {
        compute_step_with(active_shard_count, self.step_numerator, self.step_denominator)
    }
}

/// [`ExpandVotingConfig::compute_step`] from the two step parameters alone.
pub fn compute_step_with(active_shard_count: u16, step_numerator: u16, step_denominator: u16) -> u16 {
    if active_shard_count < 4 {
        return 1;
    }
    let step = (active_shard_count as u32 * step_numerator as u32) / step_denominator.max(1) as u32;
    step.max(1) as u16
}

/// Admissible `committed_chain_count` range (inclusive) for a shard block in epoch E,
/// fixed two epochs ahead (NC-166, owner Oct 13, 2026): `prev_count` is the active shard
/// count at the START of epoch E-1, decided by epoch E-2's votes. Epoch E-1's own vote
/// can add at most one step, so every count a block of epoch E can legitimately carry
/// (including the `activation_delay` window at its start) lies in
/// `[prev_count, prev_count + step(prev_count)]`. The worst case (no expansion) is the
/// bottom, the best case (expansion fires) the top. A reorg that flips epoch E-1's
/// vote therefore cannot invalidate a block of epoch E; only epoch E-2's can.
pub fn admissible_count_range(prev_count: u16, step_numerator: u16, step_denominator: u16) -> (u16, u16) {
    let step = compute_step_with(prev_count, step_numerator, step_denominator);
    (prev_count, prev_count.saturating_add(step).min(MAX_COMMITTED_CHAIN_COUNT))
}

/// Admissible hash-sorting width range for the count range above.
pub fn admissible_s_bits_range(count_range: (u16, u16)) -> (u8, u8) {
    (s_bits_for_chain_count(count_range.0), s_bits_for_chain_count(count_range.1))
}

// ── Per-epoch state ───────────────────────────────────────────────────────────

/// Running tally for one epoch's shard-expansion votes.
///
/// This struct is fully deterministic from the block sequence — it can always
/// be reconstructed by replaying blocks from the epoch start, so no extra undo
/// log is needed for reorg handling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpochExpandState {
    /// Epoch index (0-based).
    pub epoch_index: u64,

    /// Active shard count at the START of this epoch.
    pub active_shard_count: u16,

    /// Hash-sorting exponent at the start of this epoch.
    /// Valid shard IDs for this epoch: `[1, 2^s_bits − 1)`.
    pub s_bits: u8,

    /// Running count of `vote_expand_flag = 1` blocks tallied so far.
    pub ones_count: u32,

    /// Total blocks tallied so far (≤ EPOCH_LENGTH).
    pub total_count: u32,

    /// Finalised vote ratio (ones / total). `None` while the epoch is in progress.
    pub vote_ratio: Option<f64>,

    /// Number of new shards to open at the start of epoch N+1 (after
    /// `activation_delay`).  `None` while the epoch is in progress.
    pub shards_to_open: Option<u16>,
}

impl EpochExpandState {
    /// Initial state for epoch 0 given a genesis config.
    pub fn genesis(config: &ExpandVotingConfig) -> Self {
        Self {
            epoch_index: 0,
            active_shard_count: config.initial_shard_count,
            s_bits: config.initial_s_bits,
            ones_count: 0,
            total_count: 0,
            vote_ratio: None,
            shards_to_open: None,
        }
    }

    /// Shard count that will be active after the pending expansion fires
    /// (0 when still in progress or no expansion voted).
    pub fn next_shard_count(&self) -> u16 {
        self.active_shard_count + self.shards_to_open.unwrap_or(0)
    }

    /// Whether this epoch's vote has been finalised.
    pub fn is_finalised(&self) -> bool {
        self.shards_to_open.is_some()
    }
}

// ── Algorithms ────────────────────────────────────────────────────────────────

/// Record one block's `vote_expand_flag` into the running tally.
///
/// Call this for every beacon block in order.  If the block is the last block
/// of an epoch (i.e. `(height + 1) % EPOCH_LENGTH == 0`), call
/// [`finalise_expand_epoch`] afterward.
pub fn record_expand_vote(state: &mut EpochExpandState, vote_expand_flag: bool) {
    state.total_count += 1;
    if vote_expand_flag {
        state.ones_count += 1;
    }
}

/// Finalise the current epoch's tally and advance state to epoch N+1.
///
/// This is a **pure deterministic function** — given the same `state`,
/// `history`, and `config` it always produces identical results.  No I/O.
///
/// After this call:
/// - `state` holds the initial state for the **next** epoch.
/// - `history` has the finalised snapshot of the just-completed epoch appended.
pub fn finalise_expand_epoch(
    state: &mut EpochExpandState,
    history: &mut Vec<EpochExpandState>,
    config: &ExpandVotingConfig,
) {
    let total = state.total_count.max(1);
    let ratio = state.ones_count as f64 / total as f64;

    // Integer threshold: fires when ones_count / total >= threshold_num / threshold_den
    // i.e. ones_count × threshold_den >= total × threshold_num   (no floating-point)
    let fires = (state.ones_count as u64) * config.threshold_denominator
        >= (total as u64) * config.threshold_numerator;

    let shards_to_open = if fires {
        config.compute_step(state.active_shard_count)
    } else {
        0
    };

    log::info!(
        "Expand-vote epoch {} end: {}/{} ({:.1}%) → {} \
         shards {} → {} (s_bits {} → {})",
        state.epoch_index,
        state.ones_count,
        total,
        ratio * 100.0,
        if shards_to_open > 0 { "EXPAND" } else { "HOLD" },
        state.active_shard_count,
        state.active_shard_count + shards_to_open,
        state.s_bits,
        compute_required_s_bits(state.active_shard_count + shards_to_open, state.s_bits),
    );

    // Finalise the snapshot
    state.vote_ratio = Some(ratio);
    state.shards_to_open = Some(shards_to_open);
    history.push(state.clone());

    // Compute next-epoch values
    let new_count = state.active_shard_count + shards_to_open;
    let new_s_bits = compute_required_s_bits(new_count, state.s_bits);

    // Advance to epoch N+1
    *state = EpochExpandState {
        epoch_index: state.epoch_index + 1,
        active_shard_count: new_count,
        s_bits: new_s_bits,
        ones_count: 0,
        total_count: 0,
        vote_ratio: None,
        shards_to_open: None,
    };
}

/// Compute the minimum `s_bits` exponent that can accommodate `new_count`
/// active shard chains, never decreasing below `current_s`.
///
/// Capacity is `2^s − 1` (all non-zero hash-sorting codes; slot 0 reserved).
/// Count may **fill** capacity (`new_count ≤ 2^s − 1`). We increment `s` while
/// `new_count > 2^s − 1`. Protocol hard ceiling: `s ≤ 15`.
///
/// This is the monotonic form used at expand-epoch finalisation (never shrinks
/// `s` when the count drops). For the pure count→s mapping (PoW asserted-s
/// derivation, genesis consistency), prefer [`s_bits_for_chain_count`].
pub fn compute_required_s_bits(new_count: u16, current_s: u8) -> u8 {
    let mut s = current_s;
    while (new_count as u32) > (1u32 << s).saturating_sub(1) {
        s += 1;
        assert!(s <= 15, "shard count exceeds protocol maximum (s=15, cap=32767)");
    }
    // s=0 has capacity 0; PoW / genesis never use a zero-width sort.
    if s == 0 {
        s = 1;
    }
    s
}

/// Pure count→s mapping: minimum hash-sorting width that covers `count`
/// active shards (Jul 20, 2026 — Header rBits §5.7; **Jul 21:** capacity is
/// inclusive `≤ 2^s − 1`).
///
/// Equivalent to [`compute_required_s_bits`]`(count, 0)`.
///
/// # Formula
///
/// Shard address space with beacon-reserved slot 0:
///
/// ```text
/// capacity(s) = 2^s − 1
/// s_bits_for_chain_count(count) = min { s ∈ 1..=15 | count ≤ 2^s − 1 }
/// ```
///
/// # Edge cases
///
/// | `count` | result | notes |
/// |---------|--------|-------|
/// | 0 | 1 | empty → minimum usable width |
/// | 1 | 1 | fills capacity at `s=1` |
/// | 3 | 2 | fills capacity at `s=2` (standard + stress preset default) |
/// | 4 | 3 | `4 ≤ 7`; larger frozen `s` is optional headroom (soft warn if under-filled) |
/// | 15 | 4 | fills capacity at `s=4` |
/// | 16 | 5 | bumps past full `2^4 − 1` |
///
/// Genesis may freeze `asserted_s_bits == initial_s_bits` **above** this
/// minimum (headroom). Consistency requires the frozen pair still covers
/// `initial_shard_count` — see `BeaconGenesisConfig::validate_difficulty_params`.
pub fn s_bits_for_chain_count(count: u16) -> u8 {
    compute_required_s_bits(count, 0)
}

/// Protocol maximum hash-sorting width (`s ≤ 15`).
pub const MAX_S_BITS: u8 = 15;

/// Most chains a block may commit to: `2^15 − 1 = 32 767` (NC-137). Owner,
/// Sep 30, 2026: a larger count is invalid, not clamped — well before this,
/// block size grows instead of chain count.
pub const MAX_COMMITTED_CHAIN_COUNT: u16 = (1u16 << MAX_S_BITS) - 1;

/// [`s_bits_for_chain_count`] for an **untrusted** count (a header field):
/// `None` above [`MAX_COMMITTED_CHAIN_COUNT`] instead of panicking.
pub fn checked_s_bits_for_chain_count(count: u16) -> Option<u8> {
    (count <= MAX_COMMITTED_CHAIN_COUNT).then(|| s_bits_for_chain_count(count))
}

/// Optimal soft band for genesis `(s, count)`: **`2^s − 2 < count < 2^s`**.
///
/// For integer `count` this is exactly `count == 2^s − 1` (full non-zero
/// hash-sorting capacity). Hard capacity still allows any `1..=2^s−1`; this
/// band is warn-only (Genesis Phase A soft warn).
///
/// Examples: `(s=2, count=3)` in-band; `(s=4, count=4)` (testnet-stress)
/// out-of-band → soft warn; `(s=4, count=15)` in-band.
pub fn s_bits_count_in_optimal_band(s_bits: u8, count: u16) -> bool {
    if s_bits == 0 || s_bits > 63 {
        return false;
    }
    let two_pow_s = 1u128 << s_bits;
    let lower = two_pow_s.saturating_sub(2);
    let c = count as u128;
    lower < c && c < two_pow_s
}

/// Message for the Phase A soft warn when `(s, count)` is outside the optimal
/// band. `None` when in-band (no warning).
pub fn nonoptimal_s_bits_warning(s_bits: u8, count: u16) -> Option<String> {
    if s_bits_count_in_optimal_band(s_bits, count) {
        return None;
    }
    let two_pow_s = 1u128 << s_bits.min(63);
    let lower = two_pow_s.saturating_sub(2);
    Some(format!(
        "non-optimal choice of s-bits: initial_shard_count={count} outside \
         (2^initial_s_bits − 2, 2^initial_s_bits) = ({lower}, {two_pow_s})"
    ))
}

/// Emit [`nonoptimal_s_bits_warning`] via `log::warn!` when out-of-band.
/// No-op when in-band. Safe to call from any validate path (idempotent text).
pub fn emit_nonoptimal_s_bits_warning(s_bits: u8, count: u16) {
    if let Some(msg) = nonoptimal_s_bits_warning(s_bits, count) {
        log::warn!("{msg}");
    }
}

/// Return the `active_shard_count` in effect at a given beacon height,
/// accounting for the `activation_delay` window at epoch boundaries.
///
/// During the first `activation_delay` blocks of a new epoch the shard count
/// is still the **previous** epoch's value.
pub fn active_shard_count_at(
    beacon_height: u32,
    state: &EpochExpandState,
    history: &[EpochExpandState],
    activation_delay: u32,
) -> u16 {
    let el = epoch_length();
    let epoch_start = (beacon_height / el) * el;
    let activation_height = epoch_start + activation_delay;
    if beacon_height < activation_height {
        // Still in delay window — use previous epoch's count.
        //
        // Looks the entry up by its own `epoch_index` field rather than
        // `history[prev_epoch]` positional indexing — the two give identical
        // results for a dense, from-genesis history (every caller today:
        // Keystone's `FullBeaconChain::expand_history`), but positional
        // indexing silently returns the wrong entry (or falls through to the
        // `else` below) once a caller keeps a smaller, non-dense history —
        // which the mining pool's `ParameterChain::expand_history` now does
        // deliberately, trimmed to at most the one entry this function
        // actually needs (Fast Node Start item 4 — see
        // `docs/plan/Fast_Node_Start_Design.md`'s expand_history section).
        let prev_epoch = state.epoch_index.saturating_sub(1);
        if let Some(prev) = history.iter().rev().find(|e| e.epoch_index == prev_epoch) {
            prev.active_shard_count
        } else {
            state.active_shard_count
        }
    } else {
        state.active_shard_count
    }
}

/// Beacon height at which `shard_id` first became consensus-active, resolved
/// from a **scan** of per-epoch `active_shard_count` values (see
/// [`shard_genesis_anchor_height_from_scan`]'s doc comment for the full
/// rationale) rather than a standing `Vec<EpochExpandState>` kept in memory
/// since genesis.
///
/// `scan` is `[(epoch, active_shard_count_during_that_epoch), ...]` for
/// epochs `1..=current_epoch`, in ascending epoch order (e.g. built by
/// reading each epoch's `EpochCheckpoint.chain_count`, or by a full replay
/// when no checkpoint is available — either way, this function only cares
/// about the resulting sequence, not how it was produced). Returns `None`
/// if `shard_id` never appears as newly covered by any entry in `scan`
/// (not yet activated, as far as `scan`'s range reaches).
///
/// `epoch × epoch_length() + activation_delay` mirrors
/// [`finalise_expand_epoch`]'s epoch-advance semantics: if `scan[i].1` is
/// the first count exceeding `shard_id`, `scan[i].0` is one past the epoch
/// whose vote opened it — i.e. exactly `epoch_index + 1` in the older
/// per-epoch-index convention this replaces, so no further adjustment is
/// needed here.
///
/// **Precondition:** `shard_id` must not be a genesis-preprovisioned shard
/// (`shard_id < initial_shard_count`) — `scan`'s counts are cumulative, so
/// any entry's count exceeds a small `shard_id` regardless of whether it
/// really activated there, with no per-entry floor to rule that out. Callers
/// that don't already know this should use
/// [`shard_genesis_anchor_height_from_scan`] instead, which checks it first.
pub fn shard_activation_height_from_scan(
    shard_id: u16,
    scan: &[(u32, u16)],
    activation_delay: u32,
) -> Option<u32> {
    let el = epoch_length();
    scan.iter()
        .find(|(_, count)| *count > shard_id)
        .map(|(epoch, _)| epoch.saturating_mul(el).saturating_add(activation_delay))
}

/// The beacon height at which `shard_id`'s genesis anchor becomes available —
/// unified across genesis-preprovisioned and dynamically-activated shards.
///
/// **Design note (found while adding Fast Node Start item 4, generalized to
/// this whole lookup per direct design review):** the original version of
/// this function took a full `history: &[EpochExpandState]` — every epoch's
/// tally since genesis, kept in memory for the entire life of the process
/// solely to serve this one lookup. In practice this lookup fires exactly
/// once per shard, exactly when that shard is first launched locally with
/// no prior state (`FullShardChain::is_chain_active()` short-circuits every
/// call after that from either stored blocks or this height, so it's never
/// a hot path) — a rare, one-shot event, not something worth permanently
/// growing a vector for. This version takes a `scan` instead: the caller
/// builds it on demand (a direct per-epoch checkpoint read where available,
/// full replay otherwise — see `FullBeaconChain::scan_epoch_shard_counts`),
/// uses it for however many shards need launching in the same batch, then
/// discards it. A plain `Vec` of `(epoch, count)` pairs, not a map — the
/// scan is inherently small (bounded by how many epochs have occurred, not
/// by shard count) and is only ever read via one linear `.find()`, so a
/// hash index buys nothing a `Vec` doesn't already give for free, and
/// building a `HashMap` would cost strictly more than the `Vec` it would
/// have to be built from anyway.
///
/// **Universal lag (2026-07-31):** a genesis-preprovisioned shard
/// (`shard_id < initial_shard_count`) anchors at `activation_delay` — epoch
/// 0's own `epoch_start (= 0) + activation_delay`, the exact same formula
/// [`shard_activation_height_from_scan`] uses for a dynamically-activated
/// shard — **not** the literal beacon genesis height 0. Before this fix
/// genesis shards anchored at a hardcoded 0 while dynamic shards anchored at
/// `activation_delay`, so every shard's rustmmrdb storage-epoch boundaries
/// (indexed from the shard's own local height 0) drifted from every other
/// shard's by however much sooner it had anchored — genesis shards were
/// *not* lagged the same amount as dynamic ones, defeating the point of a
/// "universal" delay. The beacon chain itself never consumes k-coefficient
/// (only shard chains do — see `docs/plan/Correctness_and_Validation_Plan.md`
/// entry 42 / Anti-Patterns Registry MM-7), so there is no requirement that
/// this height line up with the beacon's *own* true epoch boundary — only
/// that every shard, genesis or dynamic, shares the identical lag relative
/// to its own activation epoch. See `docs/plan/Epoch_Alignment_Reference.md`
/// §6 for the full rationale and the per-network `activation_delay` values
/// this produced (4 beacon blocks on standard nets, 1 on fast/soak nets).
///
/// Both genesis and dynamic shards use the exact same downstream mechanism
/// once this height is known: wait for the beacon chain to reach it, then
/// use that block's `current_mmr_root` as the shard's genesis anchor.
/// Returns `None` only for a shard_id that has neither been present at
/// genesis nor opened by any vote `scan` covers yet.
pub fn shard_genesis_anchor_height_from_scan(
    shard_id: u16,
    initial_shard_count: u16,
    scan: &[(u32, u16)],
    activation_delay: u32,
) -> Option<u32> {
    if shard_id < initial_shard_count {
        Some(activation_delay)
    } else {
        shard_activation_height_from_scan(shard_id, scan, activation_delay)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Algorithm-trace fixture: 4 shards / s=4 (pre–Jul-21 production default).
    /// Production [`ExpandVotingConfig::default`] is now 3 / s=2.
    fn default_cfg() -> ExpandVotingConfig {
        ExpandVotingConfig {
            initial_shard_count: 4,
            initial_s_bits: 4,
            ..ExpandVotingConfig::default()
        }
    }

    #[test]
    fn all_ones_expands() {
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg);
        for _ in 0..EPOCH_LENGTH {
            record_expand_vote(&mut state, true);
        }
        let mut history = vec![];
        finalise_expand_epoch(&mut state, &mut history, &cfg);
        let snap = &history[0];
        assert_eq!(snap.shards_to_open, Some(1)); // step = floor(4/4) = 1
        assert_eq!(state.active_shard_count, 5);
    }

    #[test]
    fn below_threshold_holds() {
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg);
        // 60% votes (< 62.5% threshold)
        let yes = (EPOCH_LENGTH as f64 * 0.60) as u32;
        for i in 0..EPOCH_LENGTH {
            record_expand_vote(&mut state, i < yes);
        }
        let mut history = vec![];
        finalise_expand_epoch(&mut state, &mut history, &cfg);
        let snap = &history[0];
        assert_eq!(snap.shards_to_open, Some(0));
        assert_eq!(state.active_shard_count, 4); // unchanged
    }

    #[test]
    fn at_threshold_expands() {
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg);
        // Exactly 5/8 of EPOCH_LENGTH = 2560 ones
        let yes = (EPOCH_LENGTH as u64 * 5 / 8) as u32;
        for i in 0..EPOCH_LENGTH {
            record_expand_vote(&mut state, i < yes);
        }
        let mut history = vec![];
        finalise_expand_epoch(&mut state, &mut history, &cfg);
        let snap = &history[0];
        assert!(snap.shards_to_open.unwrap() >= 1);
    }

    #[test]
    fn step_formula_floor() {
        let cfg = default_cfg();
        assert_eq!(cfg.compute_step(7), 1);  // floor(7/4) = 1
        assert_eq!(cfg.compute_step(8), 2);  // floor(8/4) = 2
        assert_eq!(cfg.compute_step(11), 2); // floor(11/4) = 2
    }

    #[test]
    fn step_one_while_below_four() {
        let cfg = default_cfg();
        // Below 4: fixed +1 per successful expand, not the percentage formula.
        assert_eq!(cfg.compute_step(1), 1);
        assert_eq!(cfg.compute_step(3), 1);
        // At 4+: percentage formula (default den=4).
        assert_eq!(cfg.compute_step(4), 1); // floor(4/4) = 1
    }

    #[test]
    fn s_bits_auto_increment() {
        // count = 15 fills 2^4 − 1 → s stays 4; 16 needs s = 5
        assert_eq!(compute_required_s_bits(15, 4), 4);
        assert_eq!(compute_required_s_bits(16, 4), 5);
    }

    #[test]
    fn s_bits_no_increment() {
        // count = 10 ≤ 2^4 − 1 = 15 → s stays 4
        assert_eq!(compute_required_s_bits(10, 4), 4);
    }

    #[test]
    fn s_bits_for_chain_count_edge_cases() {
        assert_eq!(s_bits_for_chain_count(0), 1);
        assert_eq!(s_bits_for_chain_count(1), 1); // fills capacity at s=1
        assert_eq!(s_bits_for_chain_count(3), 2); // fills capacity at s=2
        assert_eq!(s_bits_for_chain_count(4), 3); // min covering; genesis often uses 4
        assert_eq!(s_bits_for_chain_count(5), 3);
        assert_eq!(s_bits_for_chain_count(14), 4);
        assert_eq!(s_bits_for_chain_count(15), 4); // fills capacity at s=4
        assert_eq!(s_bits_for_chain_count(16), 5);
        // Pure map agrees with monotonic form when current_s is already below min.
        assert_eq!(s_bits_for_chain_count(15), compute_required_s_bits(15, 0));
        assert_eq!(s_bits_for_chain_count(4), compute_required_s_bits(4, 0));
    }

    #[test]
    fn monotonic_count() {
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg);
        let mut history = vec![];
        // Run 4 epochs, all expanding
        for _ in 0..4 {
            for _ in 0..EPOCH_LENGTH {
                record_expand_vote(&mut state, true);
            }
            let prev = state.active_shard_count;
            finalise_expand_epoch(&mut state, &mut history, &cfg);
            assert!(state.active_shard_count >= prev);
        }
    }

    #[test]
    fn genesis_trace_epoch_0_expands() {
        // Worked trace from §6.5: epoch 0, 2600/4096 = 63.5% > 62.5% → EXPAND, step=1
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg); // active=4, s=4
        assert_eq!(state.active_shard_count, 4);
        assert_eq!(state.s_bits, 4);

        for i in 0..EPOCH_LENGTH {
            record_expand_vote(&mut state, i < 2600);
        }
        let mut history = vec![];
        finalise_expand_epoch(&mut state, &mut history, &cfg);
        assert_eq!(history[0].shards_to_open, Some(1));
        assert_eq!(state.active_shard_count, 5);
        assert_eq!(state.s_bits, 4); // 5 < 2^4-1=15, no increment
    }

    #[test]
    fn reorg_replay_produces_same_state() {
        let cfg = default_cfg();
        let mut state = EpochExpandState::genesis(&cfg);
        let votes: Vec<bool> = (0..EPOCH_LENGTH).map(|i| i % 3 != 0).collect();

        for &v in &votes {
            record_expand_vote(&mut state, v);
        }
        let mut history = vec![];
        finalise_expand_epoch(&mut state, &mut history, &cfg);
        let after_first_pass = state.clone();
        let history_first_pass = history.clone();

        // Replay from scratch
        let mut state2 = EpochExpandState::genesis(&cfg);
        for &v in &votes {
            record_expand_vote(&mut state2, v);
        }
        let mut history2 = vec![];
        finalise_expand_epoch(&mut state2, &mut history2, &cfg);

        assert_eq!(after_first_pass, state2);
        assert_eq!(history_first_pass, history2);
    }

    #[test]
    fn config_validate_ok() {
        assert!(ExpandVotingConfig::default().validate().is_ok());
    }

    #[test]
    fn config_validate_allows_small_initial_count() {
        // Jul 21, 2026: default is 3 / s=2; compute_step uses +1 until count ≥ 4.
        let cfg = ExpandVotingConfig::default();
        assert_eq!(cfg.initial_shard_count, 3);
        assert_eq!(cfg.initial_s_bits, 2);
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.compute_step(1), 1);
        assert_eq!(cfg.compute_step(3), 1);
    }

    #[test]
    fn config_validate_allows_full_capacity() {
        // Jul 21, 2026: count may equal 2^s − 1 (fill every non-zero sorting code).
        let mut cfg = ExpandVotingConfig::default();
        cfg.initial_shard_count = 3;
        cfg.initial_s_bits = 2; // capacity 3
        assert!(cfg.validate().is_ok());
        cfg.initial_shard_count = 15;
        cfg.initial_s_bits = 4; // capacity 15
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_zero_initial_count() {
        let mut cfg = ExpandVotingConfig::default();
        cfg.initial_shard_count = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_shard_count_exceeds_capacity() {
        let mut cfg = ExpandVotingConfig::default();
        cfg.initial_s_bits = 4;
        cfg.initial_shard_count = 16; // capacity = 2^4−1 = 15
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn soft_warn_optimal_band_standard_preset_in_band() {
        // s=2, count=3 → 2 < 3 < 4
        assert!(s_bits_count_in_optimal_band(2, 3));
        assert!(nonoptimal_s_bits_warning(2, 3).is_none());
        assert!(ExpandVotingConfig::default().validate().is_ok());
    }

    #[test]
    fn soft_warn_legacy_4_s4_out_of_band() {
        // Pre–Jul-21 stress tuple (4 / s=4): capacity OK, soft band only 15.
        assert!(!s_bits_count_in_optimal_band(4, 4));
        let msg = nonoptimal_s_bits_warning(4, 4).expect("legacy tuple must soft-warn");
        assert!(msg.contains("non-optimal choice of s-bits"));
        assert!(msg.contains("(14, 16)"), "got: {msg}");
        let mut cfg = ExpandVotingConfig::default();
        cfg.initial_shard_count = 4;
        cfg.initial_s_bits = 4;
        assert!(cfg.validate().is_ok(), "soft warn must not fail validation");
    }

    #[test]
    fn soft_warn_full_capacity_in_band() {
        // Exclusive band admits exactly count == 2^s − 1.
        assert!(s_bits_count_in_optimal_band(4, 15));
        assert!(nonoptimal_s_bits_warning(4, 15).is_none());
    }

    // ── active_shard_count_at ─────────────────────────────────────────────────

    fn make_state(epoch: u64, count: u16, s: u8) -> EpochExpandState {
        EpochExpandState {
            epoch_index: epoch,
            active_shard_count: count,
            s_bits: s,
            ones_count: 0,
            total_count: 0,
            vote_ratio: None,
            shards_to_open: None,
        }
    }

    #[test]
    fn active_count_after_delay_returns_current() {
        let state = make_state(1, 5, 4);
        let delay = SHARD_ACTIVATION_DELAY;
        // height == epoch_start + activation_delay → delay window has passed
        let height = 1 * EPOCH_LENGTH + delay;
        assert_eq!(active_shard_count_at(height, &state, &[], delay), 5);
    }

    #[test]
    fn active_count_within_delay_returns_previous() {
        // epoch 1 state has count=5; history has epoch 0 with count=4
        let state = make_state(1, 5, 4);
        let prev = make_state(0, 4, 4);
        let history = vec![prev];
        let delay = SHARD_ACTIVATION_DELAY;
        // height is in the delay window (epoch 1 start + delay - 1)
        let height = 1 * EPOCH_LENGTH + delay - 1;
        assert_eq!(active_shard_count_at(height, &state, &history, delay), 4);
    }

    #[test]
    fn active_count_within_delay_no_history_returns_current() {
        // No previous epoch in history → fall back to current state value
        let state = make_state(1, 5, 4);
        let delay = SHARD_ACTIVATION_DELAY;
        let height = 1 * EPOCH_LENGTH; // very start of epoch, still in delay
        assert_eq!(active_shard_count_at(height, &state, &[], delay), 5);
    }

    // ── shard_activation_height_from_scan / shard_genesis_anchor_height_from_scan (CV-23 S-6/S-7) ─────
    //
    // `scan` fixtures below use the same two-epoch shape the old
    // `EpochExpandState`-based fixtures did: epoch 0's vote opens shard 4
    // (count 4 -> 5, visible starting epoch 1); epoch 1's vote opens shards
    // 5,6 (count 5 -> 7, visible starting epoch 2). As a scan (built from
    // `[(epoch, active_shard_count_during_that_epoch), ...]` for
    // `1..=current_epoch`): `[(1, 5), (2, 7)]`.

    // Note: unlike the old `EpochExpandState`-based `shard_activation_epoch`,
    // `shard_activation_height_from_scan` alone does *not* independently
    // recognize a genesis-range `shard_id` as exempt — `scan`'s counts are
    // cumulative, so *any* scan entry's count exceeds a small `shard_id`,
    // genesis or not, with no per-entry "floor" to compare against. The
    // genesis exemption is `shard_genesis_anchor_height_from_scan`'s job
    // (checked before ever delegating here) — see the cv23 genesis-anchor
    // test below, which exercises that combined, correct behavior.

    #[test]
    fn cv23_dynamically_opened_shard_resolves_to_its_epoch() {
        let scan = vec![(1, 5), (2, 7)];
        let delay = 16;
        // shard 4: first scan entry exceeding it is (1, 5) -> height = 1*el+delay.
        assert_eq!(
            shard_activation_height_from_scan(4, &scan, delay),
            Some(epoch_length() + delay),
        );
        // shards 5, 6: first scan entry exceeding them is (2, 7) -> height = 2*el+delay.
        assert_eq!(
            shard_activation_height_from_scan(5, &scan, delay),
            Some(2 * epoch_length() + delay),
        );
        assert_eq!(
            shard_activation_height_from_scan(6, &scan, delay),
            Some(2 * epoch_length() + delay),
        );
    }

    #[test]
    fn cv23_not_yet_active_shard_returns_none() {
        let scan = vec![(1, 5)];
        assert_eq!(shard_activation_height_from_scan(10, &scan, 16), None);
    }

    #[test]
    fn cv23_empty_scan_returns_none_for_any_non_genesis_shard() {
        assert_eq!(shard_activation_height_from_scan(0, &[], 16), None);
        assert_eq!(shard_activation_height_from_scan(4, &[], 16), None);
    }

    #[test]
    fn cv23_genesis_anchor_height_unifies_genesis_and_dynamic_shards() {
        let scan = vec![(1, 5)];
        let delay = 16;
        // Universal lag (2026-07-31): genesis shards (0..4) anchor at
        // `activation_delay`, the same lag a dynamic shard gets relative to
        // its own activation epoch's start — not the literal height 0.
        for shard_id in 0..4 {
            assert_eq!(
                shard_genesis_anchor_height_from_scan(shard_id, 4, &scan, delay),
                Some(delay)
            );
        }
        // Dynamically-opened shard 4 anchors at its real activation height —
        // same `epoch_start + delay` shape, just a later epoch_start.
        assert_eq!(
            shard_genesis_anchor_height_from_scan(4, 4, &scan, delay),
            Some(epoch_length() + delay)
        );
        // A shard never opened at all (by genesis or vote, within scan's range) has no anchor height.
        assert_eq!(shard_genesis_anchor_height_from_scan(9, 4, &scan, delay), None);
    }

    /// Universal lag (2026-07-31): every shard, genesis or dynamic, must
    /// share the identical lag from its own activation epoch's start — that
    /// uniformity, not alignment with the beacon's own epoch boundary, is
    /// the actual correctness property (the beacon chain never consumes
    /// k-coefficient, only shard chains do).
    #[test]
    fn genesis_and_dynamic_shards_share_the_same_lag_from_their_own_epoch_start() {
        let scan = vec![(1, 5)];
        let delay = 4;
        let genesis_anchor = shard_genesis_anchor_height_from_scan(0, 4, &scan, delay).unwrap();
        let genesis_epoch_start = 0u32; // epoch 0 starts at height 0
        let dynamic_anchor = shard_genesis_anchor_height_from_scan(4, 4, &scan, delay).unwrap();
        let dynamic_epoch_start = epoch_length(); // shard 4 activates at epoch 1's start
        assert_eq!(genesis_anchor - genesis_epoch_start, delay);
        assert_eq!(dynamic_anchor - dynamic_epoch_start, delay);
        assert_eq!(
            genesis_anchor - genesis_epoch_start,
            dynamic_anchor - dynamic_epoch_start,
            "genesis and dynamic shards must share the identical lag from their own epoch start",
        );
    }
}
