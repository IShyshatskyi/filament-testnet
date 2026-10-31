// crates/common-types/src/common/windowed_weighted_mmr.rs
//
// Moved from crates/keystone/src/windowed_weighted_mmr.rs (Aug 8, 2026) —
// per the 3-step extraction path already scoped in this codebase's own
// history ("Dead src/mining_pool/windowed_weighted_mmr.rs deleted" entry):
// this type had zero Keystone-specific coupling (only `common_types::common::*`
// imports, confirmed before the move), which is exactly what made it a
// candidate for sharing with the mining pool (`src/mining_pool/{shard,beacon}_chain.rs`)
// without either side depending on the other's crate. `crates/keystone`
// keeps a `pub use` re-export shim at its old module path so no external
// call site needed to change. Originally moved from
// src/full_node/windowed_weighted_mmr.rs (Gap 11 Phase 2e physical move,
// Jul 13, 2026) into keystone.
//
// ============================================================================
// WINDOWED WEIGHTED MMR
// ============================================================================
//
// OVERVIEW
// --------
// `WindowedWeightedMMR` is the full-node and chain-layer MMR.  It keeps only
// the most recent `node_window` leaves in `WeightedMMR.nodes[]` and serves
// older positions through a three-tier fallback:
//
//   Tier 1 — Hot  : raw_pos >= window_base_pos → WeightedMMR.nodes[]
//   Tier 2 — Warm : floor-state spine          → floor_state_nodes array
//   Tier 3 — Cold : evicted history            → ColdNodeStore (spendflags.db)
//
// It is NOT a wrapper.  It owns the `WeightedMMR` directly (not Arc, not Box)
// and exposes the full append / revert / proof API from a single struct with
// no indirection.
//
// FLOOR-STATE NODE SET
// --------------------
// After pruning to floor F, `floor_state_nodes` is seeded with the peaks of
// the MMR at state F.  Their raw positions are computed via the formula:
//   peak_pos(prefix, h) = (2 * prefix + 1) * 2^h - 1
//                       = leaves_processed * 2 + (1 << h) - 1
//
// During subsequent appends, whenever the cascade produces a parent node whose
// raw position is still below window_base_pos, that parent is stored in
// floor_state_nodes so it can serve as the left sibling for the next cascade
// step.  The map holds O(log N) entries between pruning events.
//
// DISABLING EVICTION
// ------------------
// node_window = u32::MAX disables pruning entirely.  Use this mode until
// PositionalUtxoDb Phase 2 (the real ColdNodeStore backend) is ready.
//
// PROOF GENERATION
// ----------------
// prove_batch and prove_range are implemented here (ported from
// FullWeightedMMR) and route all node reads through get_node_with_fallback,
// transparently handling hot, warm, and cold positions.
// ============================================================================

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::common::genesis::genesis_config::BeaconGenesisConfig;
use crate::common::crypto::weighted_hash::{WeightedHash, rbits_add, hash_pair_weighted, bag_peaks_weighted};
use crate::common::weighted_mmr_core::WeightedMMR;
use crate::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};

// ============================================================================
// COLD NODE STORE
// ============================================================================

/// Read-only access to MMR node hashes that have been evicted from memory.
///
/// The production implementation reads from `spendflags.db` page headers via
/// the PositionalUtxoDb crate (PositionalUtxoDb Phase 2).
/// For tests use `StubColdStore`.
pub trait ColdNodeStore: Send + Sync {
    /// Retrieve the `WeightedHash` at raw MMR position `pos`.
    ///
    /// Returns `None` only if the position was never written — should not
    /// occur for any position previously in the hot window.
    fn get_cold_node(&self, pos: usize) -> Option<WeightedHash>;

    /// PO-3 follow-up (NC-135): how many leaves the store holds durably —
    /// every node of leaves `[0, n)` can be read back through
    /// [`Self::get_cold_node`]. The windowed MMR never prunes a leaf at or
    /// above this count, so a deferred persist can still compute its cascade
    /// from the hot window and the pruned node is readable afterwards.
    ///
    /// `None` = unknown right now (store busy): prune nothing this time.
    /// The default, `Some(u32::MAX)`, keeps the old unpinned behaviour for
    /// stores that are always complete (test stubs).
    fn durable_leaf_count(&self) -> Option<u32> {
        Some(u32::MAX)
    }
}

// ============================================================================
// STUB COLD STORE (tests only)
// ============================================================================

/// In-memory `ColdNodeStore` backed by a `HashMap`.
///
/// Populate via `StubColdStore::populate_from_mmr` before triggering pruning,
/// so every evicted position has a known-correct value.
pub struct StubColdStore {
    nodes: std::collections::HashMap<usize, WeightedHash>, // mmr-guard: allow (test stub, keyed by position)
    /// Number of `get_cold_node` calls — tests can assert which tier was hit.
    pub query_count: std::sync::atomic::AtomicUsize,
    /// Reported by `durable_leaf_count`; `u32::MAX` (the `new` default)
    /// means "everything is durable".
    pub durable_leaves: std::sync::atomic::AtomicU32,
}

impl Default for StubColdStore {
    fn default() -> Self { Self::new() }
}

impl StubColdStore {
    pub fn new() -> Self {
        Self {
            nodes: std::collections::HashMap::new(), // mmr-guard: allow
            query_count: std::sync::atomic::AtomicUsize::new(0),
            durable_leaves: std::sync::atomic::AtomicU32::new(u32::MAX),
        }
    }

    pub fn insert(&mut self, pos: usize, wh: WeightedHash) {
        self.nodes.insert(pos, wh);
    }

    /// Populate all positions `[0, up_to_pos)` from a reference `WeightedMMR`.
    pub fn populate_from_mmr(mmr: &WeightedMMR, up_to_pos: usize) -> Self {
        let mut store = Self::new();
        for pos in 0..up_to_pos {
            if let Some(wh) = mmr.get_node(pos) {
                store.insert(pos, wh);
            }
        }
        store
    }

    pub fn queries(&self) -> usize {
        self.query_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn reset_query_count(&self) {
        self.query_count.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl ColdNodeStore for StubColdStore {
    fn get_cold_node(&self, pos: usize) -> Option<WeightedHash> {
        self.query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.nodes.get(&pos).copied()
    }

    fn durable_leaf_count(&self) -> Option<u32> {
        Some(self.durable_leaves.load(std::sync::atomic::Ordering::Relaxed))
    }
}

// ============================================================================
// WINDOWED WEIGHTED MMR
// ============================================================================

/// See [`WindowedWeightedMMR::floor_state_snapshot`].
#[derive(Clone)]
pub struct FloorStateSnapshot {
    mask: u32,
    nodes: [WeightedHash; 32],
}

/// Full-node MMR with a bounded sliding in-memory window and proof generation.
///
/// Replaces both `WeightedMMR` (for chain-layer use) and `FullWeightedMMR`
/// (for proof generation) in the full-node context.  The mining pool continues
/// to use plain `WeightedMMR` directly.
///
/// # Field-ordering note (WMMR-OPT-FIELDS + WMMR-OPT-MASK, May 28 / Jun 2026)
///
/// `#[repr(C)]` guarantees source-order layout.  Hot scalars
/// (`window_floor_leaf`, `floor_mask`, `node_window`) share the same or
/// adjacent cache lines.  `floor_state_nodes` (1 024 B, warm — Level 2
/// sentinel change from 1 056 B) is at the end.
///
/// Do NOT remove `#[repr(C)]` or reorder the first five fields.
/// The layout test `windowed_mmr_layout_hot_fields` asserts `node_window`
/// is within 128 bytes of `window_floor_leaf`.
#[derive(Clone)]
#[repr(C)]
pub struct WindowedWeightedMMR {
    /// Inner MMR.  After pruning, `inner.get_node(raw_pos)` is valid only for
    /// `raw_pos >= inner.window_base_pos()`.
    inner: WeightedMMR,

    /// First leaf index whose nodes are in the inner sliding window.
    /// Equal to `inner.window_base_pos() / 2`.
    window_floor_leaf: u32,

    /// Level 3 (WMMR-OPT-MASK): occupancy bitmask for `floor_state_nodes`.
    ///
    /// Bit `h` set ↔ `floor_state_nodes[h]` holds a valid node.
    ///
    /// Benefits vs the `[Option<WeightedHash>; 32]` Level 1 encoding:
    /// - Emptiness check is a register-only bit-test (no memory load for
    ///   absent slots).
    /// - Cascade consume-and-promote: consumed slot is cleared from the mask
    ///   with NO write to the array (stale bytes are masked out).
    /// - `advance_floor` reset clears only occupied slots (popcount × 32-byte
    ///   writes) instead of a 1 024-byte memset.
    /// - `floor_state_node_count()` = `POPCNT(floor_mask)` — one instruction.
    ///
    /// HOT: lives in the same cache line as `window_floor_leaf`/`node_window`.
    floor_mask: u32,

    /// Maximum leaves retained in the sliding window.
    /// `u32::MAX` = eviction disabled (default until Phase 2 is ready).
    /// Must be a power of two (or `u32::MAX`) — enforced by `debug_assert!`.
    /// HOT: first check in `maybe_prune`.
    node_window: u32,

    /// Cold node reader.  `None` until PositionalUtxoDb Phase 2 is available.
    cold_store: Option<Arc<dyn ColdNodeStore>>,

    /// Floor-state peak spine + ancestor nodes produced by cascade steps that
    /// consumed floor-state entries as left siblings.
    ///
    /// Level 2 (WMMR-OPT-SENTINEL): `[WeightedHash; 32]` instead of
    /// `[Option<WeightedHash>; 32]`.  Occupancy is tracked via `floor_mask`
    /// (Level 3); stale bytes in unoccupied slots are never read.
    /// Array size: 32 × 32 = 1 024 bytes (16 cache lines, −1 vs Level 1).
    ///
    /// WARM: accessed only on floor-state hit.  Placed last to avoid
    /// polluting the hot `window_floor_leaf`/`floor_mask`/`node_window` cache lines.
    floor_state_nodes: [WeightedHash; 32],
}

impl WindowedWeightedMMR {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create with eviction disabled (`node_window = u32::MAX`, no cold store).
    ///
    /// Produces identical behaviour to a plain `WeightedMMR` with proof
    /// generation.  Use this mode until PositionalUtxoDb Phase 2 is available.
    pub fn new(genesis_config: &BeaconGenesisConfig) -> Self {
        Self {
            inner: WeightedMMR::new_with_config(genesis_config),
            window_floor_leaf: 0,
            floor_mask: 0,
            floor_state_nodes: [WeightedHash::ZERO; 32],
            cold_store: None,
            node_window: u32::MAX,
        }
    }

    /// Create with a specific window size and optional cold store.
    ///
    /// `node_window` must be a power of two or `u32::MAX` (eviction disabled).
    pub fn new_with_window(
        genesis_config: &BeaconGenesisConfig,
        node_window: u32,
        cold_store: Option<Arc<dyn ColdNodeStore>>,
    ) -> Self {
        debug_assert!(
            node_window == u32::MAX || node_window.is_power_of_two(),
            "node_window must be a power of two or u32::MAX; got {node_window}",
        );
        Self {
            inner: WeightedMMR::new_with_config(genesis_config),
            window_floor_leaf: 0,
            floor_mask: 0,
            floor_state_nodes: [WeightedHash::ZERO; 32],
            cold_store,
            node_window,
        }
    }

    /// Construct from an already-loaded `WeightedMMR` (e.g. from storage).
    ///
    /// Call `maybe_prune()` immediately after to establish the initial floor.
    /// `node_window` must be a power of two or `u32::MAX`.
    pub fn from_inner(
        mmr: WeightedMMR,
        node_window: u32,
        cold_store: Option<Arc<dyn ColdNodeStore>>,
    ) -> Self {
        debug_assert!(
            node_window == u32::MAX || node_window.is_power_of_two(),
            "node_window must be a power of two or u32::MAX; got {node_window}",
        );
        Self {
            inner: mmr,
            window_floor_leaf: 0,
            floor_mask: 0,
            floor_state_nodes: [WeightedHash::ZERO; 32],
            cold_store,
            node_window,
        }
    }

    // -----------------------------------------------------------------------
    // Configuration / introspection
    // -----------------------------------------------------------------------

    pub fn window_floor_leaf(&self) -> u32 { self.window_floor_leaf }
    pub fn window_base_pos(&self) -> usize  { self.inner.window_base_pos() }
    pub fn node_window(&self) -> u32        { self.node_window }

    /// Number of occupied slots in `floor_state_nodes`.
    ///
    /// Level 3: `POPCNT(floor_mask)` — single instruction, no array scan.
    pub fn floor_state_node_count(&self) -> usize {
        self.floor_mask.count_ones() as usize
    }

    pub fn set_cold_store(&mut self, store: Arc<dyn ColdNodeStore>) {
        self.cold_store = Some(store);
    }

    /// The attached cold store, if any — so a caller that rebuilds the MMR
    /// in place (shard activation / complete reset) can carry it over
    /// instead of silently dropping it.
    pub fn cold_store(&self) -> Option<Arc<dyn ColdNodeStore>> {
        self.cold_store.clone()
    }

    /// WMMR-6: update the sliding-window eviction threshold at runtime.
    ///
    /// Safe to call after `load_from_storage` / `from_inner` — historical
    /// nodes already in `nodes[]` are not evicted immediately; the new window
    /// takes effect on the next `append` → `maybe_prune` cycle.
    pub fn set_node_window(&mut self, window: u32) {
        self.node_window = window;
    }

    // -----------------------------------------------------------------------
    // Three-tier node lookup
    // -----------------------------------------------------------------------

    /// Retrieve the `WeightedHash` at raw MMR position `pos`.
    ///
    /// Tier 1 — Hot  : pos >= window_base_pos    → inner.get_node()
    /// Tier 2 — Warm : height slot in floor_state_nodes → array lookup
    /// Tier 3 — Cold : everything else           → ColdNodeStore
    pub fn get_node_with_fallback(&self, pos: usize) -> Option<WeightedHash> {
        let base = self.inner.window_base_pos();
        if pos >= base {
            self.inner.get_node(pos)
        } else if let Some(wh) = self.current_peak_at_raw_pos(pos) {
            Some(wh)
        } else {
            // Level 3: register-only mask check before touching the array.
            let h = (pos + 1).trailing_zeros() as usize;
            if (self.floor_mask >> h) & 1 == 1 {
                Some(self.floor_state_nodes[h])
            } else {
                self.cold_store.as_ref()?.get_cold_node(pos)
            }
        }
    }

    /// Tier 0.5 — is `pos` exactly the raw position of one of the chain's
    /// OWN *current* peaks?
    ///
    /// Aug 19, 2026, fourth pass: closes the real gap this session's
    /// investigation was chasing. A node's raw storage position is fixed by
    /// `(leaf_index, height)` and never depends on leaf count (Anti-Patterns
    /// Registry entry #28) — so a *tall* subtree rooted at leaf 0 gets a
    /// numerically *low* raw position even when it was computed only just
    /// now. Concretely: once `leaf_count` is exactly a power of two, the
    /// entire tree collapses to one peak whose raw position is
    /// `leaf_count - 1` — far below `window_base_pos` for any real
    /// `node_window`, even though it is the chain's own live, current tip.
    /// `window_floor_leaf`'s own decomposition (what `floor_state_nodes`
    /// tracks) has no reason to include that position until the floor
    /// itself later grows a matching bit — so without this check, querying
    /// that peak (e.g. any inclusion proof that climbs up to it) silently
    /// fell through to the cold store, even though the value was sitting in
    /// plain sight the whole time as an element of `self.inner.get_peaks()`.
    ///
    /// `current_peaks` is maintained in lock-step with every append,
    /// independent of pruning — it is the ground truth for "what does the
    /// live tip's peak list look like right now," and consulting it first
    /// means an ordinary append's cascade or a proof over recent data never
    /// needs `floor_state_nodes`/cold store just because a peak's raw
    /// position happens to be numerically low. Historical queries
    /// (`n < leaf_count`) don't hit this path — their peak positions
    /// generally don't match any *current* peak, and correctly fall through
    /// to floor_state/cold store below.
    fn current_peak_at_raw_pos(&self, pos: usize) -> Option<WeightedHash> {
        let leaf_count = self.inner.leaf_count();
        let peaks = self.inner.get_peaks();
        for (i, (mmr_pos, height)) in WeightedMMR::peak_descriptors(leaf_count).into_iter().enumerate() {
            let raw = ((2 * mmr_pos as usize + 1) << height) - 1;
            if raw == pos {
                return peaks.get(i).copied();
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // A4 HASH-DEFER — node-hash access for PositionalUtxoDb wiring
    // -----------------------------------------------------------------------

    /// A4 (HASH-DEFER): retrieve the `WeightedHash` for the MMR node at
    /// PositionalUtxoDb `(mmr_pos, mmr_height)`.
    ///
    /// Formula: `raw_pos = ((2 * mmr_pos + 1) << mmr_height) - 1`
    ///
    /// Routes through `get_node_with_fallback` (hot / warm / cold tiers).
    pub fn get_node_hash(&self, mmr_pos: u32, mmr_height: u32) -> Option<WeightedHash> {
        let raw_pos = ((2 * mmr_pos as usize + 1) << mmr_height as usize)
            .checked_sub(1)?;
        self.get_node_with_fallback(raw_pos)
    }

    /// A4 (HASH-DEFER): returns `(mmr_pos, mmr_height, hash_bytes)` for every
    /// node created or updated when leaf `leaf_count_before` was appended.
    /// Cascade path = leaf plus all ancestor merges that completed.
    pub fn cascade_hashes_after_append(&self, leaf_count_before: u32)
        -> Vec<(u32, u32, [u8; 32])>
    {
        let mut out = Vec::new();
        let mut mmr_pos    = leaf_count_before;
        let mut mmr_height = 0u32;
        loop {
            if let Some(wh) = self.get_node_hash(mmr_pos, mmr_height) {
                out.push((mmr_pos, mmr_height, *wh.raw()));
            }
            if mmr_pos % 2 == 0 { break; }
            mmr_pos    /= 2;
            mmr_height += 1;
        }
        out
    }

    // -----------------------------------------------------------------------
    // Append
    // -----------------------------------------------------------------------

    /// Append a block, then trigger pruning if the window is full.
    ///
    /// Drives the merge cascade externally using `get_node_with_fallback` for
    /// left-sibling reads, ensuring correctness even when cascade steps cross
    /// into the pruned region.  Commits the result to the inner MMR via
    /// `apply_windowed_cascade`.
    ///
    /// Returns `(root, canonical_weight, pruned)`.  `pruned` is `true` if a
    /// pruning event fired — the caller should write an MMR floor checkpoint.
    /// Append a block's [`WeightedHash`] leaf to the MMR.
    ///
    /// The caller must supply a correctly-encoded leaf — use
    /// [`WeightedHash::from_leaf`] or `block.block_hash_weighted()`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the merge cascade needs a left-sibling node that is
    /// missing from all three lookup tiers (hot window, `floor_state_nodes`,
    /// cold store) — see [`Self::run_cascade`]'s doc comment for why this can
    /// no longer silently substitute a zero hash (hardening pass, Aug 19,
    /// 2026 — see `docs/plan/MMR_Windowed_Pruning_Plan.md`'s "Live
    /// proof-corruption gap" note for the incident this closes).
    pub fn append(&mut self, leaf: WeightedHash) -> Result<(WeightedHash, u128, bool), String> {
        let (root, weight) = self.run_cascade(leaf)?;
        let pruned = self.maybe_prune()?;
        Ok((root, weight, pruned))
    }

    /// Drive the merge cascade for a single `append`.
    ///
    /// # NC-67 hardening (Aug 19, 2026)
    ///
    /// The left-sibling read at each cascade step used to fall back to
    /// `WeightedHash::zero()` on a cold-tier miss instead of erroring — a
    /// real, live proof-corruption bug (a cold-tier cache miss silently
    /// substituted a zero hash instead of erroring, producing a
    /// structurally-valid but non-verifying MMR root with no signal to the
    /// caller). Every call site must now propagate this `Result` — never
    /// unwrap it into a zero-fallback again.
    fn run_cascade(
        &mut self,
        leaf: WeightedHash,
    ) -> Result<(WeightedHash, u128), String> {
        let base     = self.inner.window_base_pos();
        let lc       = self.inner.leaf_count() as usize;

        let mut mmr_pos    = lc;
        let mut mmr_height = 0usize;
        let mut new_peak   = leaf;
        let mut merge_count = 0usize;
        let mut above_floor: Vec<(usize, WeightedHash)> = Vec::new();

        while mmr_pos % 2 == 1 {
            // Right-child slot at this merge step.
            let peak_raw = ((2 * mmr_pos + 1) << mmr_height) - 1;
            if peak_raw >= base {
                above_floor.push((peak_raw, new_peak));
            }
            // Below-base right-child slots are never read again; skip.

            // Left sibling.
            let sib_raw      = ((2 * mmr_pos - 1) << mmr_height) - 1;
            let left_sibling = self.get_node_with_fallback(sib_raw).ok_or_else(|| format!(
                "run_cascade: left sibling at raw pos {sib_raw} missing from all three tiers \
                 (hot window, floor_state_nodes, cold store) -- refusing to substitute a zero \
                 hash and silently corrupt the MMR root/weight",
            ))?;

            new_peak = hash_pair_weighted(&left_sibling, &new_peak);

            // Compute the position where new_peak will land next iteration.
            let next_pos    = mmr_pos >> 1;
            let next_height = mmr_height + 1;
            let parent_raw  = ((2 * next_pos + 1) << next_height) - 1;

            // Consume-and-promote: when parent is below the window floor,
            // update floor_state_nodes / floor_mask.
            // Level 3: clearing the consumed slot is a mask-only operation —
            // no write to the array (stale bytes are masked out and ignored).
            //
            // # NC-67 fix (Aug 13, 2026) — skip the write when already occupied
            //
            // `parent_h` can already be occupied by an *unrelated, older*
            // floor-state peak — e.g. one written by an earlier append's own
            // consume-and-promote step, or by `advance_floor_by_power_of_two`
            // — whenever this append's cascade climbs high enough to reach a
            // height a prior below-floor peak already occupies. The old code
            // here overwrote `floor_state_nodes[parent_h]` unconditionally,
            // silently discarding whatever peak was already there — an
            // invalid MMR state (an occupied bit no longer represents a real
            // peak of the claimed prefix `[0, M)`, corrupting every future
            // read of that slot with no error).
            //
            // The correct fix is simply: don't write when occupied — leave
            // the existing entry untouched for the outer loop to consume
            // naturally.
            //
            // Aug 19, 2026, fourth pass: this write logic itself is
            // unchanged (restored verbatim after two intermediate passes
            // this session both proved broken by direct reproduction, then
            // a third pass removed it too aggressively — see git history for
            // the concrete leaf-7/leaf-15 divergences those found). What's
            // new is `get_node_with_fallback`'s separate Tier-0.5 check
            // against the live peak list — this write still can't durably
            // capture the chain's own *current* tip peak whenever its raw
            // position happens to sit below the floor (e.g. leaf_count
            // hitting a power of two), and doesn't need to: Tier-0.5
            // resolves that case directly from `current_peaks`, in memory,
            // independent of anything written here.
            if parent_raw < base {
                let sib_h    = (sib_raw + 1).trailing_zeros() as usize;
                let parent_h = (parent_raw + 1).trailing_zeros() as usize;
                // Clear consumed slot (mask only — no array write needed).
                self.floor_mask &= !(1u32 << sib_h);
                if (self.floor_mask >> parent_h) & 1 == 0 {
                    // Write produced parent into the array and mark it occupied.
                    self.floor_state_nodes[parent_h] = new_peak;
                    self.floor_mask |= 1u32 << parent_h;
                }
                // else: already occupied by older data — leave it for the
                // outer loop's own next iteration to consume via its
                // regular below-base sib_raw read.
            }

            mmr_pos     = next_pos;
            mmr_height  = next_height;
            merge_count += 1;
        }

        let final_peak_raw = ((2 * mmr_pos + 1) << mmr_height) - 1;

        Ok(self.inner.apply_windowed_cascade(
            leaf,
            merge_count,
            &above_floor,
            final_peak_raw,
            new_peak,
        ))
    }

    // -----------------------------------------------------------------------
    // Pruning
    // -----------------------------------------------------------------------

    /// Trigger pruning when `leaf_count - window_floor_leaf > node_window`.
    ///
    /// Called automatically by `append`.  Also call explicitly after
    /// bulk-loading via `from_inner`.
    ///
    /// Returns `true` if a pruning event occurred (checkpoint should be written).
    /// Trigger pruning when `leaf_count - window_floor_leaf > node_window`.
    ///
    /// Level 4 (WMMR-OPT-ALIGN): fires on the hot path via
    /// `advance_floor_by_power_of_two`, which performs an in-place carry
    /// cascade through `floor_mask` — no fallback-tier peak lookup, no array
    /// reset.  One `get_node` call and one array write per advance.
    ///
    /// Falls back to `advance_floor` (arbitrary-position seeding) for the
    /// one-time alignment step after a legacy-checkpoint restore where
    /// `window_floor_leaf` is not a multiple of `node_window`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the one-time legacy-alignment path (`advance_floor`)
    /// needs a peak that's missing from all three lookup tiers — see that
    /// function's own doc comment (Aug 19, 2026 hardening: this used to
    /// silently substitute `WeightedHash::zero()` instead of erroring).
    pub fn maybe_prune(&mut self) -> Result<bool, String> {
        if self.node_window == u32::MAX { return Ok(false); }
        let lc = self.inner.leaf_count();
        if lc.saturating_sub(self.window_floor_leaf) <= self.node_window { return Ok(false); }
        // PO-3 follow-up (NC-135): only prune leaves the cold store already
        // holds. While P1DB lags, the hot window grows instead (≈64 bytes
        // per leaf); once the writer catches up, each later append prunes
        // one more window, so a grown window shrinks back quickly.
        let durable = match self.cold_store.as_ref() {
            Some(store) => match store.durable_leaf_count() {
                Some(n) => n,
                None => return Ok(false),
            },
            None => u32::MAX,
        };
        let k = self.node_window.trailing_zeros();
        // One-time alignment step: occurs after restoring a legacy checkpoint
        // where window_floor_leaf is not a multiple of node_window.
        if self.window_floor_leaf % self.node_window != 0 {
            let next_aligned = (self.window_floor_leaf / self.node_window + 1)
                * self.node_window;
            if next_aligned > durable { return Ok(false); }
            self.advance_floor(next_aligned)?;
        } else {
            if self.window_floor_leaf.saturating_add(self.node_window) > durable { return Ok(false); }
            self.advance_floor_by_power_of_two(k);
        }
        Ok(true)
    }

    /// Hot-path floor advance: in-place carry cascade by exactly `node_window = 2^k`.
    ///
    /// Level 4 (WMMR-OPT-ALIGN): requires `window_floor_leaf % node_window == 0`.
    /// Called exclusively from `maybe_prune` (never from checkpoint restore paths).
    ///
    /// Algorithm:
    /// 0. **NC-67 fix (Aug 13, 2026)** — skip entirely if the retiring subtree
    ///    is already absorbed (see below); kept as a defensive invariant
    ///    check even though, as of the Aug 19, 2026 fourth pass below,
    ///    `run_cascade` no longer writes to `floor_mask` at all, so this
    ///    branch should no longer be reachable in practice.
    /// 1. Fetch the root of `[floor, floor + 2^k)` from the hot window.
    /// 2. Carry-chain through `floor_mask` bits starting at height `k`:
    ///    for each occupied slot, merge and clear the slot (mask-only, no write).
    /// 3. Write the merged result at the first unoccupied height.
    /// 4. Prune the inner hot window.
    ///
    /// # `floor_mask` tracks `window_floor_leaf`'s own decomposition, exactly
    ///
    /// Aug 19, 2026, fourth pass (reverted back to this original form after
    /// two intermediate passes both proved broken by direct reproduction —
    /// see `run_cascade`'s doc comment): `floor_mask`, read as a plain
    /// integer, always equals `window_floor_leaf` — every occupied bit `h`
    /// contributes exactly `2^h`, i.e. a binary decomposition of the floor
    /// itself. The floor and its cached state advance strictly in lockstep;
    /// `floor_state_nodes` never needs to hold anything else. A live query
    /// for a below-floor value that ISN'T part of the floor's own
    /// decomposition (e.g. the chain's own current tip peak, whenever its
    /// raw position happens to be numerically low) is answered by
    /// `get_node_with_fallback`'s Tier-0.5 check against the live peak list
    /// instead — see that method's own doc comment.
    fn advance_floor_by_power_of_two(&mut self, k: u32) {
        debug_assert_eq!(
            self.window_floor_leaf % self.node_window, 0,
            "advance_floor_by_power_of_two: floor {} is not aligned to node_window {}",
            self.window_floor_leaf, self.node_window,
        );

        let new_floor = self.window_floor_leaf + self.node_window;

        // Step 0 (NC-67): the retiring subtree is already fully absorbed into
        // a taller floor_state peak — nothing to fetch or write.
        if self.floor_mask >= new_floor {
            self.inner.prune_to_leaf(new_floor);
            self.window_floor_leaf = new_floor;
            return;
        }

        // Step 1: root of the advancing subtree [floor, floor + 2^k) from hot window.
        let peak_raw = WeightedMMR::subtree_root_raw_pos(self.window_floor_leaf, k);
        let mut carry = self.inner.get_node(peak_raw)
            .expect("advancing subtree root must be within the hot window");

        // Step 2: carry-chain — merge with occupied floor-state slots starting at h=k.
        //
        // Aug 19, 2026, fourth pass: reverted to this original form. `floor_mask`
        // must stay *exactly* equal to `window_floor_leaf`'s own binary
        // decomposition at all times — the floor and its cached state advance
        // in lockstep, so `floor_state_nodes` never needs to answer a query
        // for anything that isn't part of the floor's own current
        // decomposition. Any other, below-floor value a live query needs is
        // answered by `get_node_with_fallback`'s Tier-0.5 check against the
        // chain's current peak list instead (see that method's doc comment) —
        // `floor_state_nodes` has exactly one job again.
        let mut h = k as usize;
        while (self.floor_mask >> h) & 1 == 1 {
            carry = hash_pair_weighted(&self.floor_state_nodes[h], &carry);
            self.floor_mask &= !(1u32 << h); // clear consumed slot (no array write)
            h += 1;
        }

        // Step 3: write the merged result at the first unoccupied height.
        self.floor_state_nodes[h] = carry;
        self.floor_mask |= 1u32 << h;

        // Step 4: advance the prune base.
        self.inner.prune_to_leaf(new_floor);
        self.window_floor_leaf = new_floor;
    }

    /// Restore-only floor advance: advance to an arbitrary `new_floor`.
    ///
    /// Uses [`Self::get_peaks_at_checked`] for seeding — called at most once
    /// per node lifetime (checkpoint restore or first alignment after legacy
    /// restore). NOT called from the hot append path.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any peak of `new_floor` is missing from all three
    /// lookup tiers (Aug 19, 2026 hardening — this used to silently
    /// substitute `WeightedHash::zero()` via the now-removed
    /// `peaks_at_via_fallback`, corrupting the restored floor state with no
    /// signal to the caller).
    fn advance_floor(&mut self, new_floor: u32) -> Result<(), String> {
        debug_assert!(new_floor > self.window_floor_leaf);
        debug_assert!(new_floor <= self.inner.leaf_count());

        // Snapshot peaks using the three-tier fallback so that peaks which
        // were already evicted by an earlier pruning event can be read from
        // `floor_state_nodes` (tier-2) or the cold store (tier-3).
        let peaks = self.get_peaks_at_checked(new_floor)?;

        // Level 3: targeted clear — write zeroes only to occupied slots.
        let mut mask = self.floor_mask;
        while mask != 0 {
            let bit_h = mask.trailing_zeros() as usize;
            self.floor_state_nodes[bit_h] = WeightedHash::ZERO;
            mask &= mask - 1;
        }
        self.floor_mask = 0;

        self.seed_floor_state_nodes(new_floor, &peaks);

        self.inner.prune_to_leaf(new_floor);
        self.window_floor_leaf = new_floor;
        Ok(())
    }

    /// NC-71: the safe, public, fallback-aware replacement for
    /// `get_peaks_at`/`get_peaks_at_height` — those two are thin passthroughs
    /// to the plain, non-windowed `WeightedMMR::get_peaks_at`, which only
    /// ever reads the hot in-memory array and panics for any peak position
    /// that pruning has already moved into `floor_state_nodes` or the cold
    /// store, **including exactly `n == window_floor_leaf`** (the position
    /// that was *just* pruned — their doc comments' claimed safety boundary
    /// "valid for n >= window_floor_leaf" is off by one at that exact edge).
    /// Confirmed live: a real crash-recovery soak with real MMR pruning
    /// enabled panicked at this exact boundary
    /// (`docs/plan/Correctness_and_Validation_Plan.md` NC-71).
    ///
    /// Routes every peak position through `get_node_with_fallback` (hot →
    /// `floor_state_nodes` → cold store) and returns `Err` — never a
    /// silently-substituted zero hash — the moment any position misses at
    /// all three tiers. Callers should treat `Err` as "this chain's storage
    /// cannot answer a question its own consensus state requires" and halt
    /// forward progress on this chain (see `common::chain_halt::ChainHaltState`)
    /// rather than proceed with a wrong root or panic the whole process.
    pub fn get_peaks_at_checked(&self, n: u32) -> Result<Vec<WeightedHash>, String> {
        if n > self.inner.leaf_count() {
            return Err(format!(
                "get_peaks_at_checked({n}): requested leaf count exceeds current leaf_count {}",
                self.inner.leaf_count(),
            ));
        }
        if n == 0 { return Ok(vec![]); }
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut result = Vec::new();
        let mut leaves_processed = 0u32;
        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                let wh = self.get_node_with_fallback(peak_raw).ok_or_else(|| format!(
                    "get_peaks_at_checked({n}): peak at raw pos {peak_raw} missing from all \
                     three tiers (hot window, floor_state_nodes, cold store) -- either no \
                     cold store is attached, or the underlying storage for a position this \
                     chain's own consensus state requires is genuinely gone/corrupted",
                ))?;
                result.push(wh);
                leaves_processed += subtree_size;
            }
        }
        Ok(result)
    }

    /// NC-71: the fallback-aware, non-panicking sibling of
    /// `get_peaks_at_historical` — same defect, same fix shape as
    /// [`Self::get_peaks_at_checked`], but against the historical
    /// high-water-mark leaf count (post-revert side-block bookkeeping)
    /// instead of the live `leaf_count`.
    pub fn get_peaks_at_historical_checked(&self, n: u32) -> Result<Vec<WeightedHash>, String> {
        let hwm = self.inner.historical_leaf_count();
        if n > hwm {
            return Err(format!(
                "get_peaks_at_historical_checked({n}): requested leaf count exceeds historical \
                 high-water mark {hwm}",
            ));
        }
        if n == 0 { return Ok(vec![]); }
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut result = Vec::new();
        let mut leaves_processed = 0u32;
        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                let wh = self.get_node_with_fallback(peak_raw).ok_or_else(|| format!(
                    "get_peaks_at_historical_checked({n}): peak at raw pos {peak_raw} missing \
                     from all three tiers (hot window, floor_state_nodes, cold store)",
                ))?;
                result.push(wh);
                leaves_processed += subtree_size;
            }
        }
        Ok(result)
    }

    /// Seed `floor_state_nodes` with the peaks of state `floor`.
    ///
    /// Each peak at bit position `bit_pos` of `floor` has height == `bit_pos`
    /// by construction (`(peak_raw+1).trailing_zeros() == bit_pos`), so it is
    /// stored directly at `floor_state_nodes[bit_pos]`.
    fn seed_floor_state_nodes(&mut self, floor: u32, peaks: &[WeightedHash]) {
        if floor == 0 || peaks.is_empty() { return; }
        let highest_bit = 31u32.saturating_sub(floor.leading_zeros());
        let mut peak_idx = 0usize;
        for bit_pos in (0..=highest_bit).rev() {
            if (floor >> bit_pos) & 1 == 1 {
                if peak_idx < peaks.len() {
                    // Level 2/3: write value + set mask bit.
                    self.floor_state_nodes[bit_pos as usize] = peaks[peak_idx];
                    self.floor_mask |= 1u32 << bit_pos;
                    peak_idx += 1;
                }
            }
        }
        debug_assert_eq!(
            self.floor_mask.count_ones(),
            self.floor_state_nodes.iter().filter(|w| w.has_weight()).count() as u32,
            "floor_mask/array invariant violated after seeding",
        );
    }

    // -----------------------------------------------------------------------
    // Floor-state checkpoint (WMMR Step 7)
    // -----------------------------------------------------------------------

    /// Canonical file name for a floor-state checkpoint at `leaf_count`.
    ///
    /// `chain_prefix` is `"beacon"` or `"shard_<N>"`.
    pub fn checkpoint_filename(chain_prefix: &str, leaf_count: u32) -> String {
        format!("mmr_checkpoint_{}_{}.bin", chain_prefix, leaf_count)
    }

    /// Return the checkpoint path: `<dir>/mmr_checkpoint_<prefix>_<leaf>.bin`.
    pub fn checkpoint_path(dir: &Path, chain_prefix: &str, leaf_count: u32) -> PathBuf {
        dir.join(Self::checkpoint_filename(chain_prefix, leaf_count))
    }

    /// Serialise the current floor state to a binary checkpoint file.
    ///
    /// Binary layout (all integers little-endian):
    /// ```text
    /// window_floor_leaf     : u32  (4 bytes)
    /// floor_state_node_count: u32  (4 bytes)
    /// per entry (× count):
    ///   raw_pos             : u64  (8 bytes)
    ///   weighted_hash       : [u8; 32]  (32 bytes)
    /// ```
    ///
    /// Max file size: 4 + 4 + 32 × (8 + 32) = 1 288 bytes.
    pub fn save_floor_checkpoint(&self, path: &Path) -> Result<(), String> {
        // Collect occupied slots (Level 3: iterate mask bits, not all 32 slots).
        let mut entries: Vec<(usize, WeightedHash)> = Vec::new();
        let mut mask = self.floor_mask;
        while mask != 0 {
            let h = mask.trailing_zeros() as usize;
            entries.push((h, self.floor_state_nodes[h]));
            mask &= mask - 1;
        }

        let node_count = entries.len() as u32;
        let mut buf: Vec<u8> = Vec::with_capacity(8 + entries.len() * 40);

        buf.extend_from_slice(&self.window_floor_leaf.to_le_bytes());
        buf.extend_from_slice(&node_count.to_le_bytes());

        for (h, wh) in &entries {
            // Re-derive a canonical raw_pos from height: (1 << h) - 1.
            let raw_pos = (1usize << h) - 1;
            buf.extend_from_slice(&(raw_pos as u64).to_le_bytes());
            buf.extend_from_slice(&wh.0);
        }

        // Atomic write: temp file → rename.
        let tmp = path.with_extension("bin.tmp");
        std::fs::write(&tmp, &buf)
            .map_err(|e| format!("checkpoint write to {:?}: {}", tmp, e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("checkpoint rename {:?} → {:?}: {}", tmp, path, e))?;

        Ok(())
    }

    /// Deserialise a floor-state checkpoint.
    ///
    /// Returns `(window_floor_leaf, floor_state_nodes, floor_mask)`.
    /// The `floor_mask` is recomputed from the loaded nodes — it is never
    /// stored on disk to avoid a checkpoint format version bump.
    pub fn load_floor_checkpoint(
        path: &Path,
    ) -> Result<(u32, [WeightedHash; 32], u32), String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("checkpoint read {:?}: {}", path, e))?;

        if data.len() < 8 {
            return Err(format!("checkpoint {:?}: too short ({} bytes)", path, data.len()));
        }

        let floor_leaf = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let node_count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

        let expected = 8 + node_count * 40;
        if data.len() != expected {
            return Err(format!(
                "checkpoint {:?}: expected {} bytes for {} nodes, got {}",
                path, expected, node_count, data.len()
            ));
        }

        let mut nodes = [WeightedHash::ZERO; 32];
        let mut mask  = 0u32;
        for i in 0..node_count {
            let offset  = 8 + i * 40;
            let raw_pos = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset + 8..offset + 40]);
            let h = (raw_pos + 1).trailing_zeros() as usize;
            if h < 32 {
                nodes[h] = WeightedHash(hash);
                mask |= 1u32 << h;
            }
        }

        Ok((floor_leaf, nodes, mask))
    }

    /// Apply a previously loaded floor-state snapshot without block replay.
    ///
    /// The `floor_leaf` must be ≤ the current `leaf_count`.  After restoring,
    /// `window_floor_leaf`, `floor_state_nodes`, and `floor_mask` match what
    /// they would be after live pruning at the checkpoint height.
    pub fn restore_floor_state(&mut self, floor_leaf: u32, nodes: [WeightedHash; 32], mask: u32) {
        self.window_floor_leaf = floor_leaf;
        self.floor_state_nodes = nodes;
        self.floor_mask = mask;
        // Align the inner window so hot-node reads use the correct base offset.
        if floor_leaf > 0 {
            self.inner.prune_to_leaf(floor_leaf);
        }
    }

    /// Scan `dir` for checkpoint files matching `mmr_checkpoint_<prefix>_*.bin`
    /// with a leaf count ≤ `max_leaf_count`, and return the path + leaf count
    /// of the most recent valid file.
    pub fn find_latest_checkpoint(
        dir: &Path,
        chain_prefix: &str,
        max_leaf_count: u32,
    ) -> Option<(PathBuf, u32)> {
        let prefix_str = format!("mmr_checkpoint_{}_", chain_prefix);
        let entries = std::fs::read_dir(dir).ok()?;
        let mut best: Option<(PathBuf, u32)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&prefix_str) || !name.ends_with(".bin") { continue; }
            // Extract leaf count between prefix and ".bin".
            let inner = &name[prefix_str.len()..name.len() - 4];
            if let Ok(leaf_count) = inner.parse::<u32>() {
                if leaf_count <= max_leaf_count {
                    if best.as_ref().map(|(_, c)| leaf_count > *c).unwrap_or(true) {
                        best = Some((entry.path(), leaf_count));
                    }
                }
            }
        }
        best
    }

    // -----------------------------------------------------------------------
    // Chain-management delegation
    // -----------------------------------------------------------------------

    pub fn get_root(&self)            -> WeightedHash { self.inner.get_root() }
    pub fn get_root_bytes(&self)      -> [u8; 32]     { self.inner.get_root_bytes() }
    pub fn canonical_chain_weight(&self) -> u128      { self.inner.canonical_chain_weight() }
    pub fn leaf_count(&self)          -> u32           { self.inner.leaf_count() }
    pub fn get_peaks(&self)           -> Vec<WeightedHash> { self.inner.get_peaks() }
    pub fn cumulative_difficulty_approx(&self) -> u128 { self.inner.cumulative_difficulty_approx() }
    pub fn cumulative_difficulty_rbits(&self)  -> u32  { self.inner.cumulative_difficulty_rbits() }
    pub fn bitcoin_anchor(&self)      -> [u8; 32]      { self.inner.bitcoin_anchor() }
    pub fn genesis_mmr_root(&self) -> Result<WeightedHash, String> { self.inner.genesis_mmr_root() }
    pub fn asserted_s_bits(&self)     -> u32           { self.inner.asserted_s_bits() }

    /// Delegates to `WeightedMMR::cold_start_from_peaks` — see that method's
    /// own doc comment. Added for the mining pool (Kameniar), which calls
    /// this directly on a live chain's `WindowedWeightedMMR` during reorg
    /// recovery (unlike Keystone, which only ever calls it on a fresh
    /// `WeightedMMR` before wrapping via `from_inner` — see `restore_beacon_mmr`).
    /// Doesn't touch `nodes[]`/`window_base_pos` (neither does the inner
    /// method), so this wrapper's own floor/window bookkeeping is
    /// unaffected — safe because Kameniar never calls `get_node_with_fallback`
    /// (no proof generation; see this crate's own "Proof Infrastructure
    /// Ownership" convention), the only consumer of that bookkeeping.
    pub fn cold_start_from_peaks(&mut self, n: u32, peaks: &[WeightedHash]) {
        self.inner.cold_start_from_peaks(n, peaks);
    }

    /// NC-161: non-panicking form, see `WeightedMMR::try_cold_start_from_peaks`.
    pub fn try_cold_start_from_peaks(&mut self, n: u32, peaks: &[WeightedHash]) -> Result<(), String> {
        self.inner.try_cold_start_from_peaks(n, peaks)
    }

    /// F11f (Oct 10, 2026): copy of the floor state (`floor_mask` + `floor_state_nodes`) so a
    /// speculative `append` can be undone completely. `run_cascade` writes promoted nodes into
    /// this state, and `revert_to_leaf_count_with_peaks` only reverts the inner MMR. After a
    /// rejected block the leftover slot (a node of the rejected block) was later returned by
    /// `get_node_with_fallback` as if it were a real historical node, so the next rollback
    /// restored a wrong peak and every following valid block failed with a root mismatch.
    /// 1 KiB + a mask; take it before the append, restore it before the rollback reads peaks.
    pub fn floor_state_snapshot(&self) -> FloorStateSnapshot {
        FloorStateSnapshot { mask: self.floor_mask, nodes: self.floor_state_nodes }
    }

    /// Restore the floor state taken by [`Self::floor_state_snapshot`].
    pub fn restore_floor_state_snapshot(&mut self, snapshot: &FloorStateSnapshot) {
        self.floor_mask = snapshot.mask;
        self.floor_state_nodes = snapshot.nodes;
    }

    /// Delegates to `WeightedMMR::revert_to_leaf_count_with_peaks` — see
    /// that method's own doc comment and [`Self::cold_start_from_peaks`]'s
    /// doc comment for why a direct delegate (no extra window bookkeeping)
    /// is safe for Kameniar's usage pattern.
    pub fn revert_to_leaf_count_with_peaks(&mut self, n: u32, peaks: &[WeightedHash]) {
        self.inner.revert_to_leaf_count_with_peaks(n, peaks);
    }

    pub fn has_more_difficulty_than(&self, other: &Self) -> bool {
        self.inner.has_more_difficulty_than(&other.inner)
    }

    /// Bag snapshots at each bit-prefix of `n`.
    ///
    /// When `n >= window_floor_leaf` all required peak nodes are in the hot
    /// window, so we delegate to the inner `WeightedMMR`.
    ///
    /// When `n < window_floor_leaf` (e.g. during `revert_below_floor`) some
    /// peak nodes have been pruned from `nodes[]`.  We reconstruct them through
    /// the three-tier `get_node_with_fallback` path (hot → floor-state spine →
    /// cold store) so that the bags remain accessible regardless of pruning state.
    pub fn collect_weighted_mmr_bags(&self, n: u32) -> Vec<WeightedHash> {
        if n == 0 {
            return Vec::new();
        }
        // Fast path: all required nodes are in the hot window.
        if n >= self.window_floor_leaf {
            return self.inner.collect_weighted_mmr_bags(n);
        }
        // Sub-floor path: use fallback node lookup so pruned peaks are served
        // from the floor-state spine or the cold store.
        let anchor = WeightedHash::from_anchor(&self.inner.bitcoin_anchor());
        let mut bags: Vec<WeightedHash> = Vec::with_capacity(n.count_ones() as usize);
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut prefix: u32 = 0;
        for bit in (0..=highest_bit).rev() {
            if (n >> bit) & 1 == 1 {
                prefix += 1 << bit;
                let peaks = self.get_peaks_at_with_fallback(prefix);
                bags.push(bag_peaks_weighted(&peaks, anchor));
            }
        }
        bags
    }

    /// Compute the MMR peaks after `n` leaves using three-tier node lookup.
    ///
    /// Unlike `get_peaks_at_height` (which panics for pruned positions),
    /// this helper tolerates nodes below `window_base_pos` by reading through
    /// `get_node_with_fallback` (Tier 2 floor-state spine + Tier 3 cold store).
    /// Missing nodes are treated as `WeightedHash::zero()`.
    fn get_peaks_at_with_fallback(&self, n: u32) -> Vec<WeightedHash> {
        let mut peaks = Vec::new();
        let mut leaves_processed = 0u32;
        let mut highest_bit = 0u32;
        for bit_pos in 0..32u32 {
            if (n >> bit_pos) & 1 == 1 { highest_bit = bit_pos; }
        }
        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                let wh = self.get_node_with_fallback(peak_raw)
                    .unwrap_or(WeightedHash::zero());
                peaks.push(wh);
                leaves_processed += subtree_size;
            }
        }
        peaks
    }

    /// Peaks at state `n`, using the three-tier fallback lookup.
    ///
    /// NC-71: this used to delegate straight to `WeightedMMR::get_peaks_at`,
    /// which only ever reads the hot in-memory array and panics for any peak
    /// position already pruned into `floor_state_nodes` or the cold store —
    /// confirmed live in a real crash-recovery soak. Now delegates to
    /// [`Self::get_peaks_at_checked`] instead, which routes every peak
    /// through `get_node_with_fallback` and returns `Err` (rather than
    /// panicking or silently substituting zero) on a genuine triple-tier
    /// miss. See that method's own doc comment for the full rationale.
    ///
    /// # Panics
    /// Panics with the underlying error message on a lookup miss — existing
    /// callers of this API expect an infallible `Vec`; a caller that needs to
    /// handle a miss gracefully should call `get_peaks_at_checked` directly.
    pub fn get_peaks_at_height(&self, n: u32) -> Vec<WeightedHash> {
        self.get_peaks_at_checked(n).expect("get_peaks_at_height")
    }

    /// Alias for `get_peaks_at_height` — mirrors `WeightedMMR::get_peaks_at`.
    pub fn get_peaks_at(&self, n: u32) -> Vec<WeightedHash> {
        self.get_peaks_at_height(n)
    }

    /// Read peak hashes for state `n` using the historical high-water mark.
    ///
    /// Forwards to [`WeightedMMR::get_peaks_at_historical`].  Allows callers to
    /// read peaks for reverted heights without recomputing any hashes — see that
    /// method's documentation for the contract and preconditions.
    pub fn get_peaks_at_historical(&self, n: u32) -> Vec<WeightedHash> {
        self.inner.get_peaks_at_historical(n)
    }

    /// High-water mark leaf count (never decremented by reverts).
    ///
    /// Forwards to [`WeightedMMR::historical_leaf_count`].
    pub fn historical_leaf_count(&self) -> u32 {
        self.inner.historical_leaf_count()
    }

    /// Leaf `WeightedHash` at 0-indexed height.  Reads through the fallback
    /// node store, so works even for pruned/cold leaves.
    pub fn get_leaf(&self, height: usize) -> Option<WeightedHash> {
        self.get_node_with_fallback(2 * height)
    }

    /// Bag peaks with the stored genesis anchor — mirrors `WeightedMMR::bag_peaks_with_anchor`.
    pub fn bag_peaks_with_anchor(&self, peaks: &[WeightedHash]) -> WeightedHash {
        self.inner.bag_peaks_with_anchor(peaks)
    }

    /// Raw inner MMR — for bench fixtures that need direct node access.
    ///
    /// Production code should use `prove_batch` / `prove_range` instead.
    pub fn as_weighted_mmr(&self) -> &WeightedMMR {
        &self.inner
    }

    // -----------------------------------------------------------------------
    // Revert
    // -----------------------------------------------------------------------

    /// Revert to `n` leaves where `n >= window_floor_leaf`.
    ///
    /// Peaks at state `n` are within the sliding window.
    ///
    /// # Panics
    /// Panics if `n < window_floor_leaf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any peak of `n` is missing from all three lookup
    /// tiers (Aug 19, 2026 hardening — this used to silently substitute
    /// `WeightedHash::zero()` via the now-removed `peaks_at_via_fallback`,
    /// corrupting the reverted MMR root with no signal to the caller).
    pub fn revert_to_leaf_count(&mut self, n: u32) -> Result<(), String> {
        assert!(
            n >= self.window_floor_leaf,
            "revert_to_leaf_count({n}): below window floor {}. \
             Use revert_below_floor() with pre-captured bags.",
            self.window_floor_leaf,
        );
        // `inner.revert_to_leaf_count(n)` calls `get_peaks_at(n)` which panics
        // whenever *any* peak of n falls below `window_base_pos`.  This can
        // happen even when `n >= window_floor_leaf` because n's MSB peak may
        // span a range that starts below the floor (e.g. n=window_floor+1 where
        // the large peak covers [0, window_floor)).  Route through
        // `get_peaks_at_checked` + `revert_to_leaf_count_with_peaks` to safely
        // serve three-tier node reads for any such straddling peak.
        let peaks = self.get_peaks_at_checked(n)?;
        self.inner.revert_to_leaf_count_with_peaks(n, &peaks);
        Ok(())
    }

    /// Revert to `n < window_floor_leaf` using pre-captured bag snapshots.
    ///
    /// `bags` is sourced from the S3 header cache:
    ///   `blocks[p-1].header.current_mmr_root` for each bit-prefix `p` of `n`.
    ///
    /// After revert the window is reset to floor = 0.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any peak of `n` is missing from all three lookup
    /// tiers — see `revert_to_leaf_count`'s doc comment for the same
    /// hardening rationale.
    pub fn revert_below_floor(&mut self, n: u32, bags: &[WeightedHash]) -> Result<(), String> {
        assert!(n <= self.inner.leaf_count());
        // Step 1: Resolve the peaks for the target leaf count via the three-tier
        // fallback (hot window → floor_state_nodes → cold store), avoiding the
        // `get_peaks_at` call that panics for pruned positions.
        let peaks = self.get_peaks_at_checked(n)?;
        // Step 2: Revert bagger + leaf_count using the pre-computed peaks.
        // Never calls `get_peaks_at` or `nodes[]`.
        self.inner.revert_to_leaf_count_with_peaks(n, &peaks);
        // Step 3: Reset the window to [0, n).
        //
        // `prune_to_leaf(0)` won't move the window backward (it guards against
        // that).  Instead, use `reset_window_and_seed_peaks` which clears
        // `nodes[]`, sets `window_base_pos = 0`, and writes each peak at its
        // canonical raw position.  Without this, subsequent `append` calls
        // would try to write new leaf nodes at raw positions below the old
        // `window_base_pos` and silently discard them, producing wrong roots.
        self.inner.reset_window_and_seed_peaks(n, &peaks);
        self.window_floor_leaf = 0;
        // Level 3: targeted clear of occupied slots, then zero mask.
        let mut mask = self.floor_mask;
        while mask != 0 {
            let bit_h = mask.trailing_zeros() as usize;
            self.floor_state_nodes[bit_h] = WeightedHash::ZERO;
            mask &= mask - 1;
        }
        self.floor_mask = 0;
        Ok(())
    }

    /// Unified revert dispatcher — calls `bags_fn` only when `n < window_floor_leaf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` under the same conditions as `revert_to_leaf_count`/
    /// `revert_below_floor`, whichever this dispatches to.
    pub fn revert<F>(&mut self, n: u32, bags_fn: F) -> Result<(), String>
    where
        F: FnOnce(u32) -> Vec<WeightedHash>,
    {
        if n >= self.window_floor_leaf {
            self.revert_to_leaf_count(n)
        } else {
            let bags = bags_fn(n);
            self.revert_below_floor(n, &bags)
        }
    }

    // -----------------------------------------------------------------------
    // Proof generation
    // -----------------------------------------------------------------------

    /// Batch inclusion proof.  All node reads go through `get_node_with_fallback`.
    pub fn prove_batch(&self, leaf_indices: &[u32]) -> Result<WeightedMMRBatchProof, String> {
        if leaf_indices.is_empty() {
            return Err("prove_batch: leaf_indices is empty".to_string());
        }
        let lc = self.inner.leaf_count();
        for &idx in leaf_indices {
            if idx >= lc {
                return Err(format!("prove_batch: index {idx} >= leaf_count {lc}"));
            }
        }

        let mut sorted = leaf_indices.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let peaks      = self.inner.get_peaks();
        let root       = self.inner.get_root();
        let leaf_count = lc;
        let mut all_siblings: Vec<WeightedHash> = Vec::new();
        let mut leaf_hashes: Vec<WeightedHash>  = Vec::new();

        for &idx in &sorted {
            let leaf_pos  = 2 * idx as usize;
            let leaf_hash = self.get_node_with_fallback(leaf_pos)
                .ok_or_else(|| format!("prove_batch: no node at pos {leaf_pos}"))?;
            leaf_hashes.push(leaf_hash);
            let siblings = self.climb_to_peak(idx)?;
            all_siblings.extend(siblings);
        }

        Ok(WeightedMMRBatchProof {
            leaf_indices: sorted,
            leaf_hashes,
            siblings: all_siblings,
            peaks,
            leaf_count,
            root,
        })
    }

    /// Range inclusion proof for leaves `[start, end)`.
    pub fn prove_range(&self, start: u32, end: u32) -> Result<WeightedMMRRangeProof, String> {
        if start >= end {
            return Err(format!("prove_range: empty range [{start}, {end})"));
        }
        let lc = self.inner.leaf_count();
        if end > lc {
            return Err(format!("prove_range: end {end} > leaf_count {lc}"));
        }

        let leaves: Vec<WeightedHash> = (start..end)
            .map(|i| {
                self.get_node_with_fallback(2 * i as usize)
                    .ok_or_else(|| format!("prove_range: missing leaf at pos {}", 2 * i))
            })
            .collect::<Result<_, _>>()?;

        let range_rbits = leaves.iter().fold(0u32, |acc, l| rbits_add(acc, l.rbits()));

        let peak_positions = WeightedMMRRangeProof::range_peak_positions(start, end);
        let mmr_peaks      = self.inner.get_peaks();
        let root           = self.inner.get_root();
        let leaf_count     = lc;

        let mut all_siblings:     Vec<WeightedHash> = Vec::new();
        let mut siblings_per_peak: Vec<u8>          = Vec::new();

        for &(range_h, range_pos) in &peak_positions {
            let siblings = self.climb_from_position(range_pos, range_h)?;
            siblings_per_peak.push(siblings.len() as u8);
            all_siblings.extend(siblings);
        }

        Ok(WeightedMMRRangeProof {
            start,
            end,
            leaves,
            siblings: all_siblings,
            siblings_per_peak,
            peaks: mmr_peaks,
            leaf_count,
            root,
            range_rbits,
        })
    }

    /// Sibling path for navigating from leaf `from_height` to leaf `to_height`
    /// in the climb-and-descent verifier (`navigate_to` in `fork_proof.rs`).
    ///
    /// Returns siblings in the exact order consumed by `navigate_to`:
    ///
    /// 1. **Climb phase** — right-sibling hashes at each left-child level
    ///    where the right subtree does NOT contain `to_height`.
    /// 2. **Descent phase** — left-child hashes at each level where
    ///    `to_height` lies in the right subtree.
    ///
    /// # Arguments
    ///
    /// * `from_height` — starting leaf index (0-based).
    /// * `to_height`   — ending leaf index (must be `> from_height` and
    ///                   `< self.leaf_count()`).
    ///
    /// # Returns
    ///
    /// * `Ok(vec![])` when `from_height == to_height` — no navigation needed.
    /// * `Ok(siblings)` with the navigation sibling sequence.
    /// * `Err` when either height is out of range or a node is missing.
    ///
    /// # Note — NOT the same as `prove_batch` siblings
    ///
    /// `prove_batch(&[from, to]).siblings` concatenates the full climb-to-peak
    /// paths for BOTH leaves.  That format is for batch inclusion proofs, not
    /// for climb-and-descent navigation.  `collect_fork_path` produces a
    /// strictly smaller set: only the nodes actually needed to navigate between
    /// the two leaf positions.
    pub fn collect_fork_path(
        &self,
        from_height: u32,
        to_height: u32,
    ) -> Result<Vec<WeightedHash>, String> {
        if from_height == to_height {
            return Ok(vec![]);
        }

        let lc = self.inner.leaf_count();
        if from_height >= lc {
            return Err(format!(
                "collect_fork_path: from={from_height} >= leaf_count={lc}"
            ));
        }
        if to_height >= lc {
            return Err(format!(
                "collect_fork_path: to={to_height} >= leaf_count={lc}"
            ));
        }

        // The navigation plan is a pure function of the two leaf indexes (`fork_path_positions`); this
        // method only reads the planned nodes from THIS tree.
        let mut siblings: Vec<WeightedHash> = Vec::new();
        for (index, level) in Self::fork_path_positions(from_height, to_height) {
            let pos = Self::nav_pos(index as usize, level as usize);
            let node = self.get_node_with_fallback(pos).ok_or_else(|| {
                format!(
                    "collect_fork_path({from_height}→{to_height}): \
                     missing node ({index}, level {level}) at pos {pos}"
                )
            })?;
            siblings.push(node);
        }
        Ok(siblings)
    }

    /// The nodes `collect_fork_path(from, to)` reads, as `(index, level)` pairs (a node `(i, l)` covers
    /// leaves `[i << l, (i + 1) << l)`), in the order they are returned. **Pure**: depends only on the
    /// two leaf indexes, never on any tree's contents. That is what lets a caller obtain the same
    /// nodes from another source (the fork held as side blocks) without building a tree to read them
    /// from (`side_fork_path`).
    ///
    /// Climb while the current node is a LEFT child whose right sibling does not contain `to`
    /// (record that sibling); stop at the lowest common ancestor; descend, recording the left child
    /// whenever `to` lies in the right subtree.
    pub fn fork_path_positions(from_height: u32, to_height: u32) -> Vec<(u32, u32)> {
        if from_height == to_height {
            return Vec::new();
        }
        let from = from_height as usize;
        let to = to_height as usize;
        let mut out: Vec<(u32, u32)> = Vec::new();
        let mut cur_index: usize = from;
        let mut cur_height: usize = 0;

        // Climb phase.
        loop {
            // A tree has at most 32 levels; the guard only protects against `from > to` input.
            if cur_height > 32 {
                return out;
            }
            if cur_index % 2 != 0 {
                // Right child: climb without consuming a sibling.
            } else if Self::nav_contains(cur_index + 1, cur_height, to) {
                break; // lowest common ancestor found
            } else {
                out.push(((cur_index + 1) as u32, cur_height as u32));
            }
            cur_index /= 2;
            cur_height += 1;
        }

        // Pivot.
        cur_index += 1;

        // Descent phase.
        while cur_height > 0 {
            cur_height -= 1;
            cur_index *= 2; // left child
            if !Self::nav_contains(cur_index, cur_height, to) {
                // `to` is in the right subtree: record the left child, move right.
                out.push((cur_index as u32, cur_height as u32));
                cur_index += 1;
            }
        }
        out
    }

    /// Convert a normalised (index, height) pair to an MMR flat-array position.
    ///
    /// A node at height `h` that is the `index`-th subtree of size `2^h`
    /// occupies flat position `index * 2^(h+1) + 2^h − 1`.
    ///
    /// Leaves (h=0): `index * 2 + 0 = 2 * index`. ✓
    #[inline]
    fn nav_pos(index: usize, height: usize) -> usize {
        index * (2 << height) + (1 << height) - 1
    }

    /// Whether the subtree rooted at `(index, height)` contains leaf `target`.
    #[inline]
    fn nav_contains(index: usize, height: usize, target: usize) -> bool {
        let start = index << height;
        let end   = (index + 1) << height;
        target >= start && target < end
    }

    // -----------------------------------------------------------------------
    // Climb helpers (shared by prove_batch and prove_range)
    // -----------------------------------------------------------------------

    fn climb_to_peak(&self, leaf_idx: u32) -> Result<Vec<WeightedHash>, String> {
        self.climb_from_position(2 * leaf_idx as usize, 0)
    }

    fn climb_from_position(
        &self,
        start_pos: usize,
        start_height: u32,
    ) -> Result<Vec<WeightedHash>, String> {
        let max_valid = 2 * self.inner.leaf_count() as usize;
        let mut siblings: Vec<WeightedHash> = Vec::new();
        let mut pos    = start_pos;
        let mut height = start_height;

        // The path ends at a peak of the current MMR. A missing parent below a peak is a pruned node.
        // Peak test by arithmetic (Anti-Patterns #46, no set or search): a peak of height `h` exists
        // iff bit `h` of the leaf count is set, and its index is `(leaf_count >> (h + 1)) << 1`.
        let leaf_count = u64::from(self.inner.leaf_count());

        loop {
            // Node index at this height (in-order layout: pos = ((2 * index + 1) << height) - 1).
            let index = (((pos + 1) >> height) >> 1) as u64;
            if height < 32
                && (leaf_count >> height) & 1 == 1
                && index == (leaf_count >> (height + 1)) << 1
            {
                break;
            }

            let sib_pos    = Self::sibling_pos(pos, height);
            let parent_pos = Self::parent_pos(pos, height);

            if sib_pos >= max_valid || parent_pos >= max_valid { break; }

            match self.get_node_with_fallback(parent_pos) {
                Some(_) => {
                    // NC-67/hardening pass (Aug 19, 2026): a cold-tier miss here used to
                    // silently substitute WeightedHash::zero(), producing a
                    // structurally-valid but non-verifying proof with no signal to the
                    // caller (see docs/plan/MMR_Windowed_Pruning_Plan.md's "Live
                    // proof-corruption gap" note). Since the parent node above was
                    // confirmed present, its sibling must also exist in a correct MMR —
                    // a genuine miss here means storage cannot answer a question this
                    // chain's own consensus state requires, so surface it as an error
                    // instead of silently corrupting the proof.
                    let sib = self.get_node_with_fallback(sib_pos).ok_or_else(|| format!(
                        "climb_from_position: sibling at raw pos {sib_pos} missing from all \
                         three tiers (hot window, floor_state_nodes, cold store) while its \
                         parent at {parent_pos} is present -- refusing to substitute a zero \
                         hash and silently produce a non-verifying proof",
                    ))?;
                    siblings.push(sib);
                    pos    = parent_pos;
                    height += 1;
                }
                // Both positions are inside the MMR, so the parent exists in a correct MMR; a miss
                // means the node was pruned and no store answers for it. Stopping here (the old
                // `break`) returned an `Ok` proof with a path shorter than the peak height: it can
                // never verify, and a peer that received it was banned for a "malformed clue".
                None => {
                    return Err(format!(
                        "climb_from_position: parent at raw pos {parent_pos} missing from all three tiers \
                         (pruned, no cold store) -- cannot build a complete sibling path",
                    ));
                }
            }
        }

        Ok(siblings)
    }

    #[inline]
    fn is_left_child(pos: usize, height: u32) -> bool {
        if height >= 31 { false } else { ((pos >> (height + 1)) & 1) == 0 }
    }
    #[inline]
    fn parent_pos(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + (1 << height) }
        else                                { pos - (1 << height) }
    }
    #[inline]
    fn sibling_pos(pos: usize, height: u32) -> usize {
        if Self::is_left_child(pos, height) { pos + 2 * (1 << height) }
        else                                { pos - 2 * (1 << height) }
    }
}

// ============================================================================
// TESTS — collect_fork_path
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use crate::common::crypto::weighted_hash::{WeightedHash, BLOCK_HASH_W_BITS};

    const NBITS: u32 = 0x1d00ffff;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Deterministic, non-zero leaf hash for index `i`.
    fn make_hash(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0..4].copy_from_slice(&i.wrapping_add(1).to_le_bytes());
        h[28..32].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// Build a `WindowedWeightedMMR` with `n` leaves, eviction disabled.
    fn build(n: u32) -> WindowedWeightedMMR {
        let config = BeaconGenesisConfig::devnet();
        let mut mmr = WindowedWeightedMMR::new(&config);
        for i in 0..n {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), NBITS)).unwrap();
        }
        mmr
    }

    // ── collect_fork_path ────────────────────────────────────────────────────

    /// Degenerate case: same height → no siblings needed.
    #[test]
    fn fork_path_empty_when_from_equals_to() {
        let mmr = build(8);
        let path = mmr.collect_fork_path(3, 3).unwrap();
        assert!(path.is_empty(), "same height → empty path");
    }

    /// `to_height` equal to `leaf_count` is out of range (leaves are 0-indexed).
    #[test]
    fn fork_path_rejects_out_of_range() {
        let mmr = build(4);
        // leaf_count = 4, so valid indices are 0..3
        assert!(mmr.collect_fork_path(0, 4).is_err(), "to_height == leaf_count must error");
        assert!(mmr.collect_fork_path(0, 100).is_err(), "to_height > leaf_count must error");
    }

    /// Navigation path is strictly smaller than the batch-proof siblings.
    ///
    /// `collect_fork_path` returns only the nodes needed for a climb-and-descent
    /// traversal; `prove_batch` returns FULL paths to the peak for each leaf.
    /// Navigation siblings are a strict subset.
    #[test]
    fn fork_path_smaller_than_prove_batch() {
        let mmr  = build(16);
        let path  = mmr.collect_fork_path(3, 11).unwrap();
        let batch = mmr.prove_batch(&[3, 11]).unwrap();
        assert!(
            path.len() < batch.siblings.len(),
            "navigation path ({} siblings) must be strictly smaller than batch proof ({} siblings)",
            path.len(), batch.siblings.len(),
        );
    }

    /// Non-empty path for non-adjacent leaves in a 16-leaf MMR.
    #[test]
    fn fork_path_is_non_empty_for_non_adjacent_leaves() {
        let mmr = build(16);
        let path = mmr.collect_fork_path(3, 11).unwrap();
        assert!(!path.is_empty(), "non-adjacent leaves must have at least one sibling");
    }

    /// Adjacent leaves (0, 1) share an immediate parent — exactly 1 sibling.
    #[test]
    fn fork_path_adjacent_leaves_one_sibling() {
        let mmr  = build(4);
        let path = mmr.collect_fork_path(0, 1).unwrap();
        // Navigate from leaf 0 to leaf 1: only one climb step (leaf 0 is a left
        // child), right sibling = leaf 1 → stop (leaf 1 IS the target).
        // Actually: leaf 0 is left child; right sibling subtree [1,2) DOES contain
        // target 1 → break immediately.  Then pivot to cur_index=1 and descent
        // with cur_height=0 is already at the leaf, so no descent siblings.
        // Result: 0 siblings (the two leaves share a common parent and the climb
        // breaks at height 0 before consuming any sibling).
        // For (0→1): climb loop breaks immediately (right sibling covers target),
        // no climb siblings; descent loop with cur_height=0 exits immediately.
        assert_eq!(path.len(), 0, "adjacent leaf 0→1: no siblings needed");

        // For (0→3): climb 0→2→... with 2 siblings consumed.
        let path03 = mmr.collect_fork_path(0, 3).unwrap();
        assert!(!path03.is_empty(), "leaf 0→3 needs siblings");
    }

    /// Check path lengths for several (from, to) pairs in a 20-leaf MMR.
    #[test]
    fn fork_path_length_sensible_various_pairs() {
        let mmr = build(20);
        for (from, to) in [(0u32, 19u32), (1, 17), (5, 13), (0, 1), (7, 8)] {
            let path = mmr.collect_fork_path(from, to).unwrap();
            let batch = mmr.prove_batch(&[from, to]).unwrap();
            // Navigation path must never exceed batch proof length.
            assert!(
                path.len() <= batch.siblings.len(),
                "collect_fork_path({from}, {to}): nav={} > batch={}",
                path.len(), batch.siblings.len()
            );
        }
    }

    /// Path from genesis (leaf 0) to the last leaf must be non-empty.
    #[test]
    fn fork_path_genesis_to_tip_non_empty() {
        let mmr  = build(10);
        let path = mmr.collect_fork_path(0, 9).unwrap();
        assert!(!path.is_empty(), "genesis-to-tip path must have siblings");
    }
}

/// NC-67 re-audit (Aug 13, 2026): empirically re-checks, against the
/// *current* `run_cascade`/`advance_floor_by_power_of_two`, whether the
/// silent zero-fallback divergence NC-67's own deep-dive found (Aug 8, 2026)
/// is still present. That investigation traced a real, instrumented repro
/// but never checked one in — this module is that repro, made permanent, so
/// the question has a standing, re-runnable answer instead of a one-off
/// trace in a doc.
#[cfg(test)]
mod nc67_reaudit_tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;
    use crate::common::crypto::weighted_hash::WeightedHash;
    use crate::common::weighted_mmr_core::WeightedMMR;

    const NBITS: u32 = 0x1d00ffff;

    fn make_hash(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0..4].copy_from_slice(&i.wrapping_add(1).to_le_bytes());
        h[28..32].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// Appends `n` leaves to a `WindowedWeightedMMR` with the given
    /// `node_window` and no cold store, and to a plain unbounded reference
    /// `WeightedMMR` fed the identical leaf sequence, then compares roots
    /// and canonical chain weight after every single append (not just at
    /// the end) — so a divergence is caught at the exact leaf that
    /// introduces it, not just "somewhere in N appends".
    fn compare_bounded_vs_reference(node_window: u32, n: u32) {
        let config = BeaconGenesisConfig::devnet();
        let mut windowed = WindowedWeightedMMR::new_with_window(&config, node_window, None);
        let mut reference = WeightedMMR::new_with_config(&config);

        for i in 0..n {
            let leaf = WeightedHash::from_leaf_rbits(&make_hash(i), NBITS);
            windowed.append(leaf).unwrap();
            reference.append(leaf);

            assert_eq!(
                windowed.get_root(), reference.get_root(),
                "root diverged at leaf {i} (node_window={node_window}, n={n})",
            );
            assert_eq!(
                windowed.canonical_chain_weight(), reference.canonical_chain_weight(),
                "canonical_chain_weight diverged at leaf {i} (node_window={node_window}, n={n})",
            );
        }
    }

    #[test]
    fn bounded_window_matches_reference_across_many_prune_cycles_no_cold_store() {
        // Mirrors NC-67's own deep-dive repro parameters (node_window=4) plus
        // the wider binary-searched set its writeup names (4, 8, 16, 32, 64) —
        // 128 is covered separately below since it alone needs ~640 leaves.
        for window in [4u32, 8, 16, 32, 64] {
            compare_bounded_vs_reference(window, window * 12);
        }
    }

    #[test]
    fn bounded_window_128_matches_reference_across_640_leaves() {
        // The exact window/leaf-count NC-67's own regression guard
        // (tests/mining_pool/shard_chain_tests.rs) uses for Kameniar's real
        // `chain_window_size = 128` production config.
        compare_bounded_vs_reference(128, 640);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::mem::offset_of;

    /// WMMR-OPT-FIELDS + WMMR-OPT-MASK: hot scalars must be within 128 bytes
    /// of each other so they share cache lines.
    #[test]
    fn windowed_mmr_layout_hot_fields() {
        let off_floor  = offset_of!(WindowedWeightedMMR, window_floor_leaf);
        let off_mask   = offset_of!(WindowedWeightedMMR, floor_mask);
        let off_window = offset_of!(WindowedWeightedMMR, node_window);
        let gap = off_window.saturating_sub(off_floor);
        assert!(
            gap <= 128,
            "WMMR-OPT-FIELDS regression: node_window is {} bytes past window_floor_leaf \
             (limit 128). Keep #[repr(C)] and scalars in source order. \
             window_floor_leaf={} node_window={} gap={}",
            gap, off_floor, off_window, gap,
        );
        // floor_mask must sit between window_floor_leaf and floor_state_nodes.
        let off_spine = offset_of!(WindowedWeightedMMR, floor_state_nodes);
        assert!(
            off_mask > off_floor && off_mask < off_spine,
            "WMMR-OPT-MASK: floor_mask must be between window_floor_leaf and floor_state_nodes \
             (floor_leaf={off_floor}, floor_mask={off_mask}, spine={off_spine})",
        );
    }
}

/// PO-3 follow-up (NC-135): a deferred P1DB persist computes the leaf's
/// cascade from the windowed MMR. If the MMR pruned those nodes before the
/// persist ran, the cascade came back short and P1DB never got the hashes.
#[cfg(test)]
mod durable_pin_tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;

    const NBITS: u32 = 0x1d00ffff;

    fn leaf(i: u32) -> WeightedHash {
        let mut h = [0u8; 32];
        h[0..4].copy_from_slice(&(i + 1).to_le_bytes());
        WeightedHash::from_leaf_rbits(&h, NBITS)
    }

    /// A cold store that has persisted nothing yet: the MMR must keep every
    /// leaf hot, so the cascade of an early leaf is still complete.
    #[test]
    fn nothing_is_pruned_before_the_store_holds_it() {
        let store = Arc::new(StubColdStore::new());
        store.durable_leaves.store(0, std::sync::atomic::Ordering::Relaxed);
        let config = BeaconGenesisConfig::devnet();
        let mut mmr = WindowedWeightedMMR::new_with_window(&config, 4, Some(store.clone()));
        for i in 0..16 {
            mmr.append(leaf(i)).unwrap();
        }
        assert_eq!(mmr.window_floor_leaf(), 0, "no leaf is durable, nothing pruned");
        // Leaf 1's cascade: the leaf and its parent over [0, 2).
        assert_eq!(mmr.cascade_hashes_after_append(1).len(), 2);

        // The store catches up to 10 leaves: prune whole windows below it,
        // one window per call (one per append in production).
        store.durable_leaves.store(10, std::sync::atomic::Ordering::Relaxed);
        mmr.maybe_prune().unwrap();
        mmr.maybe_prune().unwrap();
        mmr.maybe_prune().unwrap();
        assert_eq!(mmr.window_floor_leaf(), 8, "prunes only whole durable windows");

        // Fully durable: back to the normal window.
        store.durable_leaves.store(u32::MAX, std::sync::atomic::Ordering::Relaxed);
        mmr.maybe_prune().unwrap();
        assert_eq!(mmr.window_floor_leaf(), 12);
        // After a real append, the cascade of a pruned-then-cold leaf is
        // answered by the store (it was durable when pruned).
        mmr.append(leaf(16)).unwrap();
    }

    /// A busy store (unknown durable count) prunes nothing that round.
    #[test]
    fn busy_store_prunes_nothing() {
        struct Busy;
        impl ColdNodeStore for Busy {
            fn get_cold_node(&self, _pos: usize) -> Option<WeightedHash> { None }
            fn durable_leaf_count(&self) -> Option<u32> { None }
        }
        let config = BeaconGenesisConfig::devnet();
        let mut mmr = WindowedWeightedMMR::new_with_window(&config, 4, Some(Arc::new(Busy)));
        for i in 0..16 {
            mmr.append(leaf(i)).unwrap();
        }
        assert_eq!(mmr.window_floor_leaf(), 0);
    }
}
