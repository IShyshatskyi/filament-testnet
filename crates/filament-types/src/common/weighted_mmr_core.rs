// src/mining_pool/weighted_mmr_core.rs
//
// ============================================================================
// WEIGHTED MMR (LIGHTWEIGHT) — Mining Pool Variant
// ============================================================================
//
// OVERVIEW
// --------
// This is the mining-pool–facing WeightedMMR: append-only, chain-reorg–capable,
// no proof generation. It mirrors `mmr_core.rs` in role and API surface, but
// every node is a `WeightedHash` — a 32-byte composite of
//   [224-bit BLAKE3-truncated hash | 32-bit rBits cumulative difficulty]
//
// The root's rBits encodes the TOTAL cumulative chain work, cryptographically
// bound to the structural hash. Light clients can compare roots directly for
// fork choice without any separately-reported difficulty value.
//
// LEAF CREATION
// -------------
// append(WeightedHash::from_leaf_rbits(&block_hash, nbits))
//   Caller constructs the leaf; w_bits comes from BLOCK_HASH_W_BITS (= 4).
//
// TWO-VARIANT DESIGN
// ------------------
// This file is the LIGHTWEIGHT variant (no proof generation):
//   src/mining_pool/weighted_mmr_core.rs   ← this file
//
// The FULL variant adds prove_batch / prove_range / climb-and-descend:
//   src/full_node/full_weighted_mmr_core.rs
//
// WINDOWED PRUNING
// ----------------
// `window_base_pos` tracks the first raw MMR position that is present in
// `nodes[0]` after a call to `prune_to_leaf`.  Before any pruning it is 0.
//
// `get_node(pos)` returns `None` for `pos < window_base_pos`, preserving the
// existing None-on-miss contract while making evicted positions invisible.
//
// `prune_to_leaf(n)` drains `nodes[0 .. 2*n - window_base_pos]`, advancing
// `window_base_pos` to `2*n`.  The bagger, `leaf_count`, and `get_root` are
// completely unaffected — they are independent of `nodes[]`.
// WMMR-PRUNE-OPT-1 ✅: `nodes` is a `VecDeque`, so `drain(..n)` removes from
// the front in O(n_drained) — no memmove of remaining elements.
//
// The full-node windowed wrapper (`WindowedWeightedMMR`) drives the merge
// cascade externally and commits results via `apply_windowed_cascade` so that
// left-sibling reads for below-floor positions are satisfied from
// `floor_state_nodes` or a `ColdNodeStore` rather than from `nodes[]`.
// ============================================================================

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use crate::common::genesis::genesis_config::BeaconGenesisConfig;
use crate::common::crypto::weighted_hash::{
    WeightedHash, WeightedPeakBagger,
    hash_pair_weighted, bag_peaks_weighted, bag_peaks_weighted_u128,
    nbits_to_rbits,
    BLOCK_HASH_W_BITS, HASH_BYTES,
};

// ============================================================================
// CORE DATA STRUCTURE
// ============================================================================

/// Weighted Merkle Mountain Range — mining-pool variant.
///
/// Every node stores a [`WeightedHash`] (28-byte BLAKE3 hash + 4-byte rBits).
/// The root's rBits is the total cumulative chain difficulty, cryptographically
/// bound to the Merkle root. No separate chain-weight field is needed.
///
/// # Memory layout
/// `nodes[2*i - window_base_pos]` holds the WeightedHash for leaf i when
/// `2*i >= window_base_pos` (i.e. leaf i is within the current window).
/// Internal nodes occupy derived odd positions using the same offset.
///
/// Before any pruning `window_base_pos == 0` and the layout is the classic
/// flat array: `nodes[2*i]` = leaf i.
///
/// # Key difference from `mmr_core.rs`
/// - Nodes are `WeightedHash` instead of `[u8; 32]`
/// - Internal merges use `hash_pair_weighted` (accumulates rBits)
/// - Bagging uses `WeightedPeakBagger` (accumulates rBits)
/// - `append` takes 2 args; `asserted_s_bits` is read from the stored genesis config
/// # Field-ordering note (WMMR-OPT-FIELDS cache-line fix, May 28 2026)
///
/// `#[repr(C)]` guarantees source-order layout.  `cached_nbits`/`cached_rbits`
/// (hot, `#[serde(skip)]`) are placed adjacent to `asserted_s_bits` so the nbits→rbits
/// cache check in `append_with_nbits` requires no extra DRAM fetch.
/// `genesis_config` (cold, `#[serde(skip)]`) is moved to the end so it does
/// not displace `current_peaks` or `window_base_pos` to a distant cache line.
///
/// The relative declaration order of all non-`#[serde(skip)]` fields
/// (`nodes`, `bagger`, `leaf_count`, `asserted_s_bits`, `anchor_hash`, `current_peaks`,
/// `window_base_pos`, `historical_leaf_count`) is preserved, so the bincode
/// wire format is unchanged.
///
/// Do NOT remove `#[repr(C)]` or move `genesis_config` above `cached_rbits`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct WeightedMMR {
    /// Flat node storage (offset by `window_base_pos`).
    /// `nodes[raw_pos - window_base_pos]` for any `raw_pos >= window_base_pos`.
    ///
    /// WMMR-PRUNE-OPT-1: `VecDeque` instead of `Vec`.  `drain(..n)` removes
    /// the front `n` entries in O(n_drained) time instead of the O(n_remaining)
    /// memmove that `Vec::drain` would require.  For `node_window = 256`,
    /// pruning drains 512 entries while the remaining window holds 256+;
    /// the saving is proportional to chain length.
    ///
    /// Serde note: both `Vec` and `VecDeque` serialise as a length-prefixed
    /// sequence in bincode, so existing serialised state reads back correctly.
    nodes: VecDeque<WeightedHash>,         // serialized, hot

    /// Progressive weighted peak bagger.
    /// `bagger.current_root()` = current MMR root with embedded cumulative difficulty.
    bagger: WeightedPeakBagger,            // serialized, hot

    /// Number of leaves appended.
    leaf_count: u32,                       // serialized, hot

    /// Hash-sorting exponent **s** used in difficulty scaling (`2^s` multiplier
    /// in `calculate_difficulty_from_target`). This is the **asserted** value
    /// from genesis config, not live `expand_state.s_bits` (true network s).
    ///
    /// Stored separately so `append` does not require an extra argument.
    #[serde(alias = "asserted_s_bits", alias = "k_bits")]
    asserted_s_bits: u32,                // serialized, hot

    /// One-entry nbits→rbits conversion cache.
    ///
    /// Within a single difficulty epoch all blocks share the same `nbits`, so
    /// the expensive `nbits_to_rbits` pipeline (256-bit arithmetic) produces the
    /// same result for 2 016 consecutive blocks.  Caching the last result
    /// eliminates ~2 015/2 016 of those conversions during bulk sync.
    ///
    /// `cached_nbits = 0` is the "cold" sentinel; zero `nbits` is structurally
    /// invalid (CV-05), so no valid block will accidentally match it.
    ///
    /// Both fields are `#[serde(skip)]`: the cache is always rebuilt on the
    /// first `append_with_nbits` after load — no correctness risk.
    ///
    /// Reset to zero on every `revert_to_leaf_count*` call to prevent stale
    /// entries after a cross-epoch reorg.
    ///
    /// HOT: placed adjacent to `asserted_s_bits` (MOVED from end).
    #[serde(skip)]
    cached_nbits: u32,                     // HOT — MOVED adjacent to k_bits
    #[serde(skip)]
    cached_rbits: u32,                     // HOT — MOVED adjacent to k_bits

    /// Bitcoin anchor hash used to seed the bagger.
    #[serde(default)]
    anchor_hash: [u8; 32],                 // serialized, cold (set once at init)

    /// Current peaks in left-to-right order, maintained in lock-step with the
    /// bagger.  Stored separately so `get_peaks()` never reads `nodes[]` and
    /// is therefore correct after `prune_to_leaf` evicts old peak positions.
    current_peaks: Vec<WeightedHash>,      // serialized, hot

    /// First raw MMR position present in `nodes[0]`.
    /// Equal to `2 * window_floor_leaf`.  Always 0 before any `prune_to_leaf` call.
    /// `#[serde(default)]` preserves backward compatibility with pre-windowing
    /// serialized state (deserialized value will be 0, which is correct).
    #[serde(default)]
    window_base_pos: usize,                // serialized, semi-hot

    /// High-water mark: the maximum `leaf_count` ever reached.
    ///
    /// Unlike `leaf_count`, this counter is **never decremented** by any revert
    /// operation.  After a reorg the node data for leaves
    /// `leaf_count .. historical_leaf_count` is still valid in `nodes[]` (it has
    /// only been logically undone by resetting `leaf_count`).
    ///
    /// This enables [`get_peaks_at_historical`] to read peak nodes for reverted
    /// heights without needing to re-derive them via hash computation.
    ///
    /// `#[serde(default)]` ensures deserialization of pre-existing state works:
    /// a missing value deserializes as 0, which is safe — callers should call
    /// [`sync_historical_leaf_count`] after loading from storage if they need
    /// the correct high-water mark.
    #[serde(default)]
    historical_leaf_count: u32,            // serialized, rarely written

    /// Genesis configuration. Not serialized; re-inject after deserialization.
    /// COLD: moved to end (was between k_bits and current_peaks).
    #[serde(skip)]
    genesis_config: Option<BeaconGenesisConfig>,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl WeightedMMR {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create an empty `WeightedMMR` using the devnet genesis configuration.
    pub fn new() -> Self {
        Self::new_with_config(&BeaconGenesisConfig::devnet())
    }

    /// Create a `WeightedMMR` with the given genesis configuration (recommended).
    pub fn new_with_config(genesis_config: &BeaconGenesisConfig) -> Self {
        let anchor = WeightedHash::from_anchor(&genesis_config.bitcoin_anchor_hash);
        Self {
            nodes: VecDeque::from(vec![WeightedHash::zero(); 1024]),
            bagger: WeightedPeakBagger::new(anchor),
            leaf_count: 0,
            asserted_s_bits: genesis_config.asserted_s_bits,
            anchor_hash: genesis_config.bitcoin_anchor_hash,
            genesis_config: Some(genesis_config.clone()),
            current_peaks: Vec::new(),
            window_base_pos: 0,
            historical_leaf_count: 0,
            cached_nbits: 0,
            cached_rbits: 0,
        }
    }

    /// Create a `WeightedMMR` pre-allocated for `expected_leaves` blocks.
    pub fn with_capacity(genesis_config: &BeaconGenesisConfig, expected_leaves: usize) -> Self {
        let anchor = WeightedHash::from_anchor(&genesis_config.bitcoin_anchor_hash);
        let capacity = (2 * expected_leaves).max(1024);
        Self {
            nodes: VecDeque::from(vec![WeightedHash::zero(); capacity]),
            bagger: WeightedPeakBagger::new(anchor),
            leaf_count: 0,
            asserted_s_bits: genesis_config.asserted_s_bits,
            anchor_hash: genesis_config.bitcoin_anchor_hash,
            genesis_config: Some(genesis_config.clone()),
            current_peaks: Vec::new(),
            window_base_pos: 0,
            historical_leaf_count: 0,
            cached_nbits: 0,
            cached_rbits: 0,
        }
    }

    /// Create a `WeightedMMR` from a raw anchor hash.
    ///
    /// `asserted_s_bits` defaults to 4 (legacy callers / mining-pool path).
    /// Prefer [`Self::with_anchor_capacity_s_bits`] when the caller has a
    /// genesis-configured asserted-s value (Keystone shard chains).
    pub fn with_anchor_and_capacity(anchor: [u8; 32], expected_leaves: usize) -> Self {
        Self::with_anchor_capacity_s_bits(anchor, expected_leaves, 4)
    }

    /// Create a `WeightedMMR` from a raw bagging anchor and asserted s-bits.
    ///
    /// For **shard** chains the bagging anchor is the CV-23 shard genesis
    /// anchor (beacon `current_mmr_root` at activation), **not** the network
    /// `bitcoin_anchor_hash`. Only the beacon chain bags against Bitcoin.
    pub fn with_anchor_capacity_s_bits(
        anchor: [u8; 32],
        expected_leaves: usize,
        asserted_s_bits: u32,
    ) -> Self {
        let weighted_anchor = WeightedHash::from_anchor(&anchor);
        let capacity = (2 * expected_leaves).max(1024);
        Self {
            nodes: VecDeque::from(vec![WeightedHash::zero(); capacity]),
            bagger: WeightedPeakBagger::new(weighted_anchor),
            leaf_count: 0,
            asserted_s_bits,
            anchor_hash: anchor,
            genesis_config: None,
            current_peaks: Vec::new(),
            window_base_pos: 0,
            historical_leaf_count: 0,
            cached_nbits: 0,
            cached_rbits: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    pub fn bitcoin_anchor(&self) -> [u8; 32] { self.anchor_hash }
    pub fn asserted_s_bits(&self) -> u32 { self.asserted_s_bits }

    pub fn set_genesis_config(&mut self, config: BeaconGenesisConfig) {
        self.asserted_s_bits = config.asserted_s_bits;
        self.anchor_hash = config.bitcoin_anchor_hash;
        self.genesis_config = Some(config);
    }

    // -----------------------------------------------------------------------
    // Append
    // -----------------------------------------------------------------------

    /// Append a block's [`WeightedHash`] leaf to the MMR.
    ///
    /// The caller must supply a correctly-encoded leaf — use
    /// [`WeightedHash::from_leaf`] or `block.block_hash_weighted()`.
    /// rBits (bytes 28–31) must encode the block's difficulty via `nbits_to_rbits`.
    ///
    /// **Windowing contract:** do **not** call this on a pruned `WeightedMMR`
    /// (one where `window_base_pos > 0`).  Left-sibling reads for positions
    /// below the floor return `WeightedHash::zero()`, producing a wrong merge
    /// result.  When the outer `MiningPoolWindowedMMR` has pruned the inner MMR,
    /// appends are driven via `apply_windowed_cascade` instead.
    pub fn append(&mut self, leaf: WeightedHash) -> (WeightedHash, u128) {
        let mut mmr_pos = self.leaf_count as usize;
        let mut mmr_height = 0usize;

        // Grow node storage if needed (relative to window_base_pos).
        let raw_needed = ((2 * mmr_pos + 1) << 0) - 1 + 2; // worst case single leaf
        let idx_needed = raw_needed.saturating_sub(self.window_base_pos) + 2;
        if self.nodes.len() <= idx_needed {
            let new_size = idx_needed.next_power_of_two().max(1024);
            self.nodes.resize(new_size, WeightedHash::zero());
        }

        self.leaf_count += 1;
        // Track the high-water mark — never decremented by reverts.
        if self.leaf_count > self.historical_leaf_count {
            self.historical_leaf_count = self.leaf_count;
        }

        let mut new_peak = leaf;

        // Merge cascade.
        while mmr_pos % 2 == 1 {
            let peak_raw = ((2 * mmr_pos + 1) << mmr_height) - 1;
            self.write_node_raw(peak_raw, new_peak);
            self.bagger.pop_peak();
            self.current_peaks.pop();

            let sibling_raw = ((2 * mmr_pos - 1) << mmr_height) - 1;
            let left_sibling = self.read_node_raw(sibling_raw);

            new_peak = hash_pair_weighted(&left_sibling, &new_peak);

            mmr_pos >>= 1;
            mmr_height += 1;
        }

        let peak_raw = ((2 * mmr_pos + 1) << mmr_height) - 1;
        self.write_node_raw(peak_raw, new_peak);
        self.bagger.push_peak(new_peak);
        self.current_peaks.push(new_peak);

        (self.bagger.canonical_root(), self.bagger.canonical_chain_weight())
    }

    /// Append a block by raw hash and nBits, building the leaf internally
    /// with a one-entry nbits→rbits conversion cache.
    ///
    /// Within a difficulty epoch all blocks share the same `nbits`, so the
    /// expensive `nbits_to_rbits` pipeline runs once per epoch instead of once
    /// per block.  The cache is invalidated on every `revert_to_leaf_count*`
    /// call so cross-epoch reorgs never produce stale rBits.
    /// Append a leaf from a raw PoW hash and header compact **rBits**.
    ///
    /// # Arguments
    /// * `block_hash` — raw 32-byte block PoW hash
    /// * `rbits`      — block header compact rBits (direct copy into the leaf)
    #[inline]
    pub fn append_with_rbits(&mut self, block_hash: &[u8; 32], rbits: u32) -> (WeightedHash, u128) {
        // Cache last-seen header rBits (field names retain historical `nbits`).
        if rbits != self.cached_nbits {
            self.cached_nbits = rbits;
            self.cached_rbits = rbits;
        }
        let mut hash_224 = [0u8; HASH_BYTES];
        hash_224.copy_from_slice(&block_hash[..HASH_BYTES]);
        let leaf = WeightedHash::from_parts(hash_224, rbits);
        self.append(leaf)
    }

    /// Deprecated alias — header work field is rBits; use [`Self::append_with_rbits`].
    #[deprecated(since = "0.8.0", note = "use append_with_rbits (header stamps rBits)")]
    #[inline]
    pub fn append_with_nbits(&mut self, block_hash: &[u8; 32], nbits: u32) -> (WeightedHash, u128) {
        self.append_with_rbits(block_hash, nbits)
    }

    // -----------------------------------------------------------------------
    // Windowed pruning
    // -----------------------------------------------------------------------

    /// First raw MMR position present in `nodes[0]`.  Zero before any pruning.
    #[inline]
    pub fn window_base_pos(&self) -> usize {
        self.window_base_pos
    }

    /// Evict nodes for leaves `[0, n)` from the in-memory window.
    ///
    /// After this call `get_node(raw_pos)` returns `None` for all
    /// `raw_pos < 2 * n`.  `leaf_count`, `get_root`, `get_peaks`, and the
    /// bagger are completely unaffected.
    ///
    /// # Implementation note — WMMR-PRUNE-OPT-1 ✅ (VecDeque)
    ///
    /// `nodes` is a `VecDeque<WeightedHash>`.  `drain(..n)` removes `n` entries
    /// from the *front* in O(n_drained) time — no memmove of the remaining
    /// elements.  `Vec::drain(..n)` would be O(n_remaining) due to the
    /// left-shift memmove (~16 KB per floor advance, 7× over 2 000 appends).
    ///
    /// **Why drain cannot simply be removed:** `get_node` indexes into the deque
    /// as `nodes[raw_pos - window_base_pos]`.  After advancing `window_base_pos`
    /// without draining, `nodes[0]` still holds the old value for the original
    /// raw_pos=0, but the new indexing expects it to hold the value for
    /// `raw_pos = window_base_pos`.  All positions ≥ `window_base_pos` would
    /// return stale data.
    ///
    /// # Caller contract
    /// The caller (`WindowedWeightedMMR`) must have already snapshotted the
    /// floor-state peaks into `floor_state_nodes` before calling this, so that
    /// future cascade steps driven via `apply_windowed_cascade` can read them.
    ///
    /// # Panics
    /// Panics if `n > leaf_count`.
    pub fn prune_to_leaf(&mut self, n: u32) {
        assert!(
            n <= self.leaf_count,
            "prune_to_leaf({n}): exceeds leaf_count {}",
            self.leaf_count,
        );
        let new_base = 2 * n as usize;
        if new_base <= self.window_base_pos {
            return; // no backward movement
        }
        // WMMR-PRUNE-OPT-1: `VecDeque::drain(..n)` removes `n` elements from
        // the *front* in O(n_drained) time — no memmove of remaining elements.
        // `Vec::drain` would be O(n_remaining) due to the left-shift memmove.
        let drain = (new_base - self.window_base_pos).min(self.nodes.len());
        self.nodes.drain(..drain);
        self.window_base_pos = new_base;
    }

    /// Reset the sliding window to cover `[0, leaf_count)` and re-seed
    /// `nodes[]` with `peaks` at their canonical raw positions.
    ///
    /// Used by `WindowedWeightedMMR::revert_below_floor` to restore a valid
    /// window state after reverting to a leaf count that falls entirely below
    /// the old `window_base_pos`.  After this call:
    /// - `window_base_pos == 0`
    /// - `nodes[]` contains exactly the peak hashes at their canonical raw
    ///   positions; all intermediate nodes are gone.
    /// - `leaf_count` and `bagger` are **unchanged** — the caller must have
    ///   already set them via `revert_to_leaf_count_with_peaks`.
    ///
    /// # Panics
    /// Panics if `peaks.len() != n.count_ones()`.
    pub fn reset_window_and_seed_peaks(&mut self, n: u32, peaks: &[WeightedHash]) {
        assert_eq!(
            peaks.len(),
            n.count_ones() as usize,
            "reset_window_and_seed_peaks({n}): expected {} peaks, got {}",
            n.count_ones(), peaks.len(),
        );
        self.nodes.clear();
        self.window_base_pos = 0;
        if n == 0 { return; }
        // Write each peak at its canonical raw position so that future
        // `run_cascade` calls can read left-sibling peaks from `nodes[]`.
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut leaves_processed = 0u32;
        let mut peak_idx = 0usize;
        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                self.write_node_raw(peak_raw, peaks[peak_idx]);
                peak_idx += 1;
                leaves_processed += subtree_size;
            }
        }
    }

    /// Initialise this MMR from an externally-supplied peak set without block replay.
    ///
    /// Used by `MiningPoolWindowedMMR` for cold-start recovery: after a restart the
    /// peaks are read from `spendflags.db` (slow path) or from an
    /// `MmrFloorCheckpoint` file (fast path), and this method reconstructs the
    /// in-memory bagger and `leaf_count` without touching `nodes[]` at all.
    ///
    /// Unlike `revert_to_leaf_count_with_peaks`, this method has **no precondition
    /// on `self.leaf_count`** — it is correct on a freshly-constructed MMR
    /// (`leaf_count == 0`) as well as on a partially-replayed one.
    ///
    /// After this call:
    /// - `leaf_count == n`
    /// - `get_root()` returns the correct bagged root for those peaks
    /// - `nodes[]` is **empty** — the caller is responsible for seeding
    ///   `nodes[]` and/or `floor_state_nodes` via `reset_window_and_seed_peaks`
    ///   or `MiningPoolWindowedMMR::restore_floor_state` as appropriate.
    ///
    /// # Panics
    /// Panics if `peaks.len() != n.count_ones() as usize`.
    pub fn cold_start_from_peaks(&mut self, n: u32, peaks: &[WeightedHash]) {
        if let Err(e) = self.try_cold_start_from_peaks(n, peaks) {
            panic!("{e}");
        }
    }

    /// NC-161 (F9): the non-panicking form. Any peak list read from storage (an epoch
    /// checkpoint, a carried-forward header) must go through this: a list whose length is
    /// not `popcount(n)` belongs to a different leaf count and must be rejected so the
    /// caller falls back to a bounded or full replay. `self` is untouched on `Err`.
    pub fn try_cold_start_from_peaks(&mut self, n: u32, peaks: &[WeightedHash]) -> Result<(), String> {
        if peaks.len() != n.count_ones() as usize {
            return Err(format!(
                "cold_start_from_peaks({n}): expected {} peaks, got {}",
                n.count_ones(),
                peaks.len(),
            ));
        }
        // Rebuild bagger and current_peaks from the supplied peak hashes.
        // This is identical to what rebuild_bagger_from_peaks does — inlined
        // here so we can also set leaf_count without going through any revert
        // assert.
        let anchor = WeightedHash::from_anchor(&self.bitcoin_anchor());
        self.bagger = WeightedPeakBagger::new(anchor);
        self.current_peaks.clear();
        for &peak in peaks {
            self.bagger.push_peak(peak);
            self.current_peaks.push(peak);
        }
        self.leaf_count = n;
        if n > self.historical_leaf_count {
            self.historical_leaf_count = n;
        }
        Ok(())
    }

    /// Derive `(mmr_pos, mmr_height)` for every peak in a chain of
    /// `leaf_count` leaves, left-to-right — pure arithmetic, no storage
    /// access. Standard formula: the peak at bit position `b` (counting from
    /// MSB) starting at `leaves_processed` leaves has `mmr_height = b`,
    /// `mmr_pos = leaves_processed >> b` (the subtree index at height `b`).
    ///
    /// Shared by both node types' Fast Node Start MMR-peak restore (§7,
    /// `docs/plan/Fast_Node_Start_Design.md`): the mining pool's
    /// `src/mining_pool/mmr_node_store.rs` and Keystone's
    /// `FullBeaconChain`/`FullShardChain` restore paths both call this
    /// directly instead of each keeping their own copy of the bit
    /// decomposition — the two node types differ only in how they turn a
    /// `(mmr_pos, mmr_height)` pair into a stored hash (mining pool:
    /// `MmrNodeStore::get_weighted_hash`, keyed the same way; Keystone:
    /// `ColdNodeStore::get_cold_node`, keyed by raw position, so callers
    /// convert via `((2 * mmr_pos + 1) << mmr_height) - 1` — the same
    /// formula [`Self::get_node_hash`] already uses in the other direction).
    pub fn peak_descriptors(leaf_count: u32) -> Vec<(u32, u32)> {
        if leaf_count == 0 {
            return vec![];
        }
        let highest_bit = 31u32.saturating_sub(leaf_count.leading_zeros());
        let mut out = Vec::new();
        let mut leaves_processed = 0u32;
        for bit_pos in (0..=highest_bit).rev() {
            if (leaf_count >> bit_pos) & 1 == 1 {
                out.push((leaves_processed >> bit_pos, bit_pos));
                leaves_processed += 1u32 << bit_pos;
            }
        }
        out
    }

    /// Reconstruct the peak hash list at `target_leaf_count`, given a trusted
    /// peak set already known at an earlier `floor_leaf_count <= target_leaf_count`,
    /// using at most one lookup per set bit of `target_leaf_count` (≤ 32) — no
    /// block replay (Problem 2, `docs/plan/Windowed_MMR_Floor_Recovery_Problem.md`).
    ///
    /// For each of `target_leaf_count`'s own peaks (from [`Self::peak_descriptors`]):
    /// - If the peak's leaf range is fully contained in `[0, floor_leaf_count)`,
    ///   it is taken directly from `floor_peaks` — no lookup needed.
    /// - Otherwise `lookup(mmr_pos, mmr_height)` is called once for its
    ///   already-completed node hash (e.g. via a durable per-node hash store
    ///   populated by an append-time cascade, such as
    ///   `PositionalUtxoDb::get_spend_flag_node_hash` /
    ///   `WeightedMMR::cascade_hashes_after_append`).
    ///
    /// **Why the first case is always correct, not just usually correct:**
    /// MMR merges are monotonic — once two subtrees combine into a taller
    /// one, further growth never de-merges them. Take any peak `(pos, h)` of
    /// `target_leaf_count`'s decomposition whose range `[pos << h, (pos+1) << h)`
    /// ends at or before `floor_leaf_count`: since it is *unmerged* at the
    /// later leaf count `target_leaf_count`, it cannot have been *more*
    /// merged at the earlier `floor_leaf_count` (merging only ever
    /// increases with growth). And since its range was already fully
    /// populated by `floor_leaf_count`, it cannot have been *less* merged
    /// (incomplete) there either. So it must be exactly height `h`,
    /// unmerged, at `floor_leaf_count` too — meaning it is guaranteed to
    /// appear verbatim in `floor_peaks` (`floor_peaks` is exactly
    /// `peak_descriptors(floor_leaf_count)`'s own hash list, by
    /// construction of whoever wrote the checkpoint this floor came from).
    ///
    /// Returns `None` — never a wrong answer — the moment any needed
    /// `lookup` call misses; callers should fall back to a bounded or full
    /// replay in that case.
    pub fn reconstruct_peaks_at(
        floor_leaf_count: u32,
        floor_peaks: &[[u8; 32]],
        target_leaf_count: u32,
        mut lookup: impl FnMut(u32, u32) -> Option<[u8; 32]>,
    ) -> Option<Vec<[u8; 32]>> {
        // NC-161 (F9): validate the shape in EVERY branch. A new epoch's checkpoint carries the
        // previous epoch's peaks forward until the boundary write replaces them, so for a
        // moment `floor_peaks` can belong to a different leaf count than `floor_leaf_count`.
        if floor_peaks.len() != floor_leaf_count.count_ones() as usize {
            return None;
        }
        if target_leaf_count == floor_leaf_count {
            return Some(floor_peaks.to_vec());
        }
        if target_leaf_count < floor_leaf_count {
            return None;
        }
        let floor_descriptors = Self::peak_descriptors(floor_leaf_count);
        if floor_descriptors.len() != floor_peaks.len() {
            return None; // checkpoint/peaks shape mismatch -- don't trust it
        }
        // Merges are monotonic, so the target peaks that lie wholly below the
        // floor are exactly the floor's own leading peaks, in the same order:
        // take them by index, never by lookup.
        let mut out = Vec::with_capacity(32);
        for (i, (mmr_pos, mmr_height)) in
            Self::peak_descriptors(target_leaf_count).into_iter().enumerate()
        {
            let covered_end = (mmr_pos as u64 + 1) << mmr_height;
            let hash = if covered_end <= floor_leaf_count as u64 {
                if floor_descriptors.get(i) != Some(&(mmr_pos, mmr_height)) {
                    return None; // cannot happen for well-formed inputs
                }
                floor_peaks[i]
            } else {
                lookup(mmr_pos, mmr_height)?
            };
            out.push(hash);
        }
        Some(out)
    }

    /// Apply a pre-computed windowed cascade to the inner MMR state.
    ///
    /// Called exclusively by `WindowedWeightedMMR::append`, which drives the
    /// cascade using the three-tier fallback so that left siblings for pruned
    /// positions are correctly sourced.
    ///
    /// # Arguments
    /// * `block_hash`       — raw block hash (used to create the leaf node).
    /// * `difficulty_nbits` — nBits for the leaf.
    /// * `merge_count`      — number of merge steps that fired.  The bagger
    ///   pops this many peaks from its right end.
    /// * `above_floor_nodes` — `(raw_pos, value)` for every cascade node at
    ///   `raw_pos >= window_base_pos`.  These are written into `nodes[]`.
    /// * `final_peak_raw`   — raw position of the resulting MMR peak.
    /// * `new_peak`         — `WeightedHash` of the resulting MMR peak.
    pub fn apply_windowed_cascade(
        &mut self,
        leaf: WeightedHash,
        merge_count: usize,
        above_floor_nodes: &[(usize, WeightedHash)],
        final_peak_raw: usize,
        new_peak: WeightedHash,
    ) -> (WeightedHash, u128) {
        let leaf_raw = 2 * self.leaf_count as usize;

        // Grow nodes if needed to accommodate the final peak.
        let required_idx = final_peak_raw.saturating_sub(self.window_base_pos) + 1;
        if self.nodes.len() < required_idx {
            let new_size = required_idx.next_power_of_two().max(1024);
            self.nodes.resize(new_size, WeightedHash::zero());
        }

        self.leaf_count += 1;
        // Track the high-water mark — never decremented by reverts.
        // Mirrors the identical update in `append`; must be kept in sync.
        if self.leaf_count > self.historical_leaf_count {
            self.historical_leaf_count = self.leaf_count;
        }

        // Write the leaf (always hot — new leaves are always above floor).
        self.write_node_raw(leaf_raw, leaf);

        // Write above-floor intermediate nodes.
        for &(raw_pos, val) in above_floor_nodes {
            self.write_node_raw(raw_pos, val);
        }

        // Write final peak.
        self.write_node_raw(final_peak_raw, new_peak);

        // Rebuild bagger and current_peaks: pop consumed peaks, push merged peak.
        for _ in 0..merge_count {
            self.bagger.pop_peak();
            self.current_peaks.pop();
        }
        self.bagger.push_peak(new_peak);
        self.current_peaks.push(new_peak);

        (self.bagger.canonical_root(), self.bagger.canonical_chain_weight())
    }

    // -----------------------------------------------------------------------
    // Root / State Accessors
    // -----------------------------------------------------------------------

    pub fn get_root(&self) -> WeightedHash {
        self.bagger.canonical_root()
    }

    pub fn get_root_bytes(&self) -> [u8; 32] {
        self.bagger.canonical_root().0
    }

    pub fn canonical_chain_weight(&self) -> u128 {
        self.bagger.canonical_chain_weight()
    }

    pub fn genesis_mmr_root(&self) -> Result<WeightedHash, String> {
        if self.leaf_count == 0 {
            return Err("No genesis block added yet".to_string());
        }
        self.bagger
            .genesis_root()
            .ok_or_else(|| "Invalid bagger state — genesis root not found".to_string())
    }

    pub fn leaf_count(&self) -> u32 { self.leaf_count }

    pub fn cumulative_difficulty_approx(&self) -> u128 {
        self.bagger.cumulative_difficulty_approx()
    }

    pub fn cumulative_difficulty_rbits(&self) -> u32 {
        self.bagger.current_root().rbits()
    }

    /// Leaf `WeightedHash` at 0-indexed `height`.  Returns `None` if pruned or absent.
    pub fn get_leaf(&self, height: usize) -> Option<WeightedHash> {
        self.get_node(2 * height)
    }

    pub fn get_leaf_rbits(&self, height: usize) -> Option<u32> {
        self.get_leaf(height).map(|n| n.rbits())
    }

    /// Node at raw MMR position `position`.
    ///
    /// Returns `None` if `position < window_base_pos` (pruned), if the
    /// translated index is out of bounds, or if the slot holds
    /// `WeightedHash::zero()` (unwritten).
    pub fn get_node(&self, position: usize) -> Option<WeightedHash> {
        if position < self.window_base_pos {
            return None; // pruned
        }
        let idx = position - self.window_base_pos;
        if idx >= self.nodes.len() {
            return None;
        }
        let node = self.nodes[idx];
        if node.is_zero() { None } else { Some(node) }
    }

    /// A4 (HASH-DEFER): retrieve the `WeightedHash` for the MMR node identified
    /// by the PositionalUtxoDb `(mmr_pos, mmr_height)` pair.
    ///
    /// Converts to the 0-indexed raw MMR position using the formula:
    ///   `raw_pos = ((2 * mmr_pos + 1) << mmr_height) - 1`
    ///
    /// Returns `None` if the node has been pruned out of the hot window or if
    /// the position has not yet been written (leaf count too small).
    pub fn get_node_hash(&self, mmr_pos: u32, mmr_height: u32) -> Option<WeightedHash> {
        let raw_pos = ((2 * mmr_pos as usize + 1) << mmr_height as usize)
            .checked_sub(1)?;
        self.get_node(raw_pos)
    }

    /// A4 (HASH-DEFER): iterate all nodes that were newly created or updated
    /// when leaf `leaf_count_before` was appended (0-indexed = the count *before*
    /// the append, i.e. the leaf index that was just appended).
    ///
    /// Returns `(mmr_pos, mmr_height, WeightedHash)` for each node in the
    /// cascade path from the leaf up to the peak created by the merge.
    /// Cascade path length = number of trailing 1-bits in `(leaf_count_before + 1)`.
    ///
    /// The caller passes these tuples to `PositionalUtxoDb::set_node_hash` so
    /// the spendflags page tree mirrors the live MMR.
    pub fn cascade_hashes_after_append(&self, leaf_count_before: u32)
        -> Vec<(u32, u32, [u8; 32])>
    {
        let mut out = Vec::new();
        let mut mmr_pos    = leaf_count_before;
        let mut mmr_height = 0u32;

        // Walk upward while the parent merge completed (right-child slots).
        // The leaf itself was just appended; its position is `(lc, 0)`.
        loop {
            if let Some(wh) = self.get_node_hash(mmr_pos, mmr_height) {
                out.push((mmr_pos, mmr_height, *wh.raw()));
            }
            // If mmr_pos is even (0-indexed), it is a left child — its parent
            // has not yet been created (the right sibling hasn't arrived).
            // If mmr_pos is odd, it was just merged into its parent.
            if mmr_pos % 2 == 0 { break; }
            mmr_pos    /= 2;
            mmr_height += 1;
        }
        out
    }

    pub fn actual_size_bytes(&self) -> usize {
        if self.leaf_count == 0 { return 0; }
        self.nodes.len() * 32 + self.bagger.len() * 32
    }

    pub fn capacity_bytes(&self) -> usize {
        self.nodes.capacity() * 32
    }

    // -----------------------------------------------------------------------
    // Peak Access
    // -----------------------------------------------------------------------

    /// Current peaks in left-to-right order.
    ///
    /// Returns the cached `current_peaks` vector maintained in lock-step with
    /// the bagger.  Never reads `nodes[]` — correct after `prune_to_leaf`.
    pub fn get_peaks(&self) -> Vec<WeightedHash> {
        self.current_peaks.clone()
    }

    /// Peaks as they were after exactly `n` leaves were appended.
    ///
    /// Reads peak values from `nodes[]` using their raw positions.
    ///
    /// For `n == self.leaf_count` (current state): all peak positions were
    /// written after `window_base_pos` was last advanced, so they are always
    /// within the window.
    ///
    /// For `n < self.leaf_count` (historical state): peak positions must also
    /// be within the window (`raw_pos >= window_base_pos`).  This is
    /// guaranteed when `n >= window_floor_leaf`.  Callers must not request
    /// peaks for `n < window_floor_leaf`; use bag snapshots from the S3
    /// header cache instead.
    ///
    /// # Panics
    /// - If `n > self.leaf_count`.
    /// - If any peak position for state `n` falls below `window_base_pos`.
    pub fn get_peaks_at(&self, n: u32) -> Vec<WeightedHash> {
        assert!(
            n <= self.leaf_count,
            "get_peaks_at({n}) called but WeightedMMR only has {} leaves",
            self.leaf_count,
        );

        let mut peaks = Vec::new();
        let mut leaves_processed = 0u32;

        let mut highest_bit = 0u32;
        for bit_pos in 0..32 {
            if (n >> bit_pos) & 1 == 1 { highest_bit = bit_pos; }
        }

        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                let wh = self.get_node(peak_raw).unwrap_or_else(|| {
                    panic!(
                        "get_peaks_at({n}): peak at raw pos {peak_raw} is below                          window_base_pos {} (pruned). Use bag snapshots from the                          S3 header cache for targets below window_floor_leaf.",
                        self.window_base_pos,
                    )
                });
                peaks.push(wh);
                leaves_processed += subtree_size;
            }
        }

        peaks
    }

    /// Read peak hashes for the MMR state after `n` leaves using the high-water
    /// mark, not the current `leaf_count`.
    ///
    /// After a reorg the `leaf_count` is reset but the node data written to
    /// `nodes[]` for every previously-appended leaf remains valid.  This method
    /// allows callers to read peaks for any `n ≤ historical_leaf_count` — including
    /// heights that were reverted — without recomputing any hashes.
    ///
    /// # Typical use: side-block pool population during reorg
    ///
    /// When we revert M blocks from the canonical chain we want to store each
    /// reverted block as a `SideBlock` together with the MMR peak list that existed
    /// *after* that block was applied.  After `revert_to_leaf_count_with_peaks(T+1)`
    /// the `leaf_count` is `T+1`.  For any reverted block at height `H > T` we have
    /// `H+1 > leaf_count`, so `get_peaks_at` would panic.  With this method we
    /// instead check `H+1 ≤ historical_leaf_count`, which is always true if those
    /// blocks were once canonical.
    ///
    /// # Panics
    /// - If `n > self.historical_leaf_count`.
    /// - If any peak position for state `n` falls below `window_base_pos` (pruned).
    pub fn get_peaks_at_historical(&self, n: u32) -> Vec<WeightedHash> {
        assert!(
            n <= self.historical_leaf_count,
            "get_peaks_at_historical({n}) called but historical high-water mark is {} leaves",
            self.historical_leaf_count,
        );

        let mut peaks = Vec::new();
        let mut leaves_processed = 0u32;

        let mut highest_bit = 0u32;
        for bit_pos in 0..32 {
            if (n >> bit_pos) & 1 == 1 { highest_bit = bit_pos; }
        }

        for bit_pos in (0..=highest_bit).rev() {
            if (n >> bit_pos) & 1 == 1 {
                let subtree_size = 1u32 << bit_pos;
                let peak_raw = (leaves_processed * 2 + subtree_size - 1) as usize;
                let wh = self.get_node(peak_raw).unwrap_or_else(|| {
                    panic!(
                        "get_peaks_at_historical({n}): peak at raw pos {peak_raw} is below \
                         window_base_pos {} (pruned). Use bag snapshots from the \
                         S3 header cache for targets below window_floor_leaf.",
                        self.window_base_pos,
                    )
                });
                peaks.push(wh);
                leaves_processed += subtree_size;
            }
        }

        peaks
    }

    /// Return the high-water `leaf_count` (never decremented by reverts).
    ///
    /// This equals `leaf_count` when no revert has ever been performed; after a
    /// reorg it is greater than `leaf_count` by the reorg depth.
    #[inline]
    pub fn historical_leaf_count(&self) -> u32 {
        self.historical_leaf_count
    }

    /// Align `historical_leaf_count` to `leaf_count`.
    ///
    /// Call this after loading an MMR from serialised state where
    /// `historical_leaf_count` was not stored (it will have deserialized as 0).
    /// Sets `historical_leaf_count = leaf_count`, which is correct for any MMR
    /// that was persisted at a canonical tip (no pending reorg).
    pub fn sync_historical_leaf_count(&mut self) {
        if self.historical_leaf_count < self.leaf_count {
            self.historical_leaf_count = self.leaf_count;
        }
    }

    // -----------------------------------------------------------------------
    // Revert (Chain Reorg Support)
    // -----------------------------------------------------------------------

    /// Revert to the state after exactly `n` leaves.
    ///
    /// Only `leaf_count` and `bagger` are updated; `nodes[]` is untouched.
    /// Peak positions for `n` must be within the window (i.e. `n >= window_floor_leaf`).
    /// For reverts below the window floor use `revert_to_leaf_count_with_bags`.
    pub fn revert_to_leaf_count(&mut self, n: u32) {
        assert!(
            n <= self.leaf_count,
            "revert_to_leaf_count({n}) called but WeightedMMR only has {} leaves",
            self.leaf_count,
        );
        let peaks = self.get_peaks_at(n);
        self.rebuild_bagger_from_peaks(&peaks);
        self.leaf_count = n;
        self.cached_nbits = 0;
        self.cached_rbits = 0;
        self.lower_window_base_for_revert(n);
    }

    /// After a revert to `n` leaves the window must not start above `2n`.
    ///
    /// `window_base_pos` is the first raw position held in `nodes`. A node is stored only if its
    /// raw position is at or above it, so a base left at the old tip's value (restore at 10
    /// leaves => 20) makes every re-append below it silently drop its nodes -- the persist step
    /// then finds nothing to write for those heights. Raw positions `>= 2n` held in `nodes`
    /// belong to the abandoned fork; clearing them and setting the base to `2n` gives the state
    /// a prune at `n` would have. A base already at or below `2n` is left alone: the re-append
    /// overwrites those positions in place.
    fn lower_window_base_for_revert(&mut self, n: u32) {
        let want = 2 * n as usize;
        if self.window_base_pos > want {
            self.nodes.clear();
            self.window_base_pos = want;
        }
    }

    /// Revert using pre-captured bag snapshots from block headers.
    ///
    /// `bags` is the sequence of `block[prefix-1].header.current_mmr_root`
    /// values for each set bit of `n` in MSB-to-LSB order — exactly what
    /// `ShardChain::collect_mmr_bags(n)` produces.
    ///
    /// # ⚠ Performance note: bags are validated but NOT used
    ///
    /// Prefix-bag roots cannot be inverted to individual peak hashes without
    /// reversing the BLAKE3-224 hash, so this function falls back to
    /// `get_peaks_at(n)` (reads `nodes[]`) regardless.  The `bags` argument
    /// is length-checked only and then discarded — this function is therefore
    /// **identical in cost to `revert_to_leaf_count(n)`**.
    ///
    /// If individual peak hashes are available (e.g. from `SideBlock.peaks`),
    /// prefer `revert_to_leaf_count_with_peaks` for a true O(k) path that
    /// never reads `nodes[]`.
    pub fn revert_to_leaf_count_with_bags(&mut self, n: u32, bags: &[WeightedHash]) {
        assert!(
            n <= self.leaf_count,
            "revert_to_leaf_count_with_bags({n}) called but WeightedMMR only has {} leaves",
            self.leaf_count,
        );
        assert_eq!(
            bags.len(),
            n.count_ones() as usize,
            "revert_to_leaf_count_with_bags({n}): expected {} bags, got {}",
            n.count_ones(),
            bags.len(),
        );
        // bags are prefix-bag-roots (each is bag_peaks_weighted over a prefix).
        // They cannot be used to rebuild individual peaks without hash inversion,
        // so we fall back to get_peaks_at for nodes[]-resident targets.
        // For the fast path, callers should prefer revert_to_leaf_count_with_peaks.
        let peaks = self.get_peaks_at(n);
        self.rebuild_bagger_from_peaks(&peaks);
        self.leaf_count = n;
        self.cached_nbits = 0;
        self.cached_rbits = 0;
        self.lower_window_base_for_revert(n);
    }

    /// Fast O(k) revert using pre-captured individual peak hashes.
    ///
    /// `peaks` must be the `Vec<WeightedHash>` of individual peak hashes after
    /// exactly `n` leaves have been appended — i.e. `SideBlock.peaks` at the
    /// block whose height equals the target leaf count minus one.
    ///
    /// Unlike `revert_to_leaf_count` and `revert_to_leaf_count_with_bags`,
    /// this variant **never reads `nodes[]`**.  It calls `rebuild_bagger_from_peaks`
    /// directly, making the revert cost O(k) where k = popcount(n), independent
    /// of chain depth or window size.
    ///
    /// # When to use
    /// Call this from `ShardChain::revert_to_height` and `BeaconChain::revert_to_height`
    /// when the `SideBlock.peaks` (or equivalent per-block peak snapshot) is
    /// available for the target height.  This eliminates the dominant reorg
    /// regression introduced when `get_peaks_at` began scanning `nodes[]` in
    /// the WeightedMMR era.
    ///
    /// # Invariant
    /// `peaks.len() == n.count_ones()`.  Panics if the lengths disagree.
    pub fn revert_to_leaf_count_with_peaks(&mut self, n: u32, peaks: &[WeightedHash]) {
        assert!(
            n <= self.leaf_count,
            "revert_to_leaf_count_with_peaks({n}) called but WeightedMMR only has {} leaves",
            self.leaf_count,
        );
        assert_eq!(
            peaks.len(),
            n.count_ones() as usize,
            "revert_to_leaf_count_with_peaks({n}): expected {} peaks, got {}",
            n.count_ones(),
            peaks.len(),
        );
        // Directly rebuild bagger from the provided peak hashes — no nodes[] read.
        self.rebuild_bagger_from_peaks(peaks);
        self.leaf_count = n;
        self.cached_nbits = 0;
        self.cached_rbits = 0;
        self.lower_window_base_for_revert(n);
    }

    /// Generic revert using a stored-root callback.
    ///
    /// ⚠ The `get_root_at` closure is called to collect bag snapshots, but the
    /// results are discarded — the revert itself reads `nodes[]` via
    /// `get_peaks_at(n)`.  The callback is unused in the current implementation.
    /// Consider removing this method or fixing it to actually use the callback.
    pub fn revert_to_leaf_count_with_root<F>(&mut self, n: u32, get_root_at: F)
    where
        F: Fn(u32) -> WeightedHash,
    {
        assert!(
            n <= self.leaf_count,
            "revert_to_leaf_count_with_root({n}) called but WeightedMMR only has {} leaves",
            self.leaf_count,
        );
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut prefix: u32 = 0;
        let mut bag_snapshots: Vec<WeightedHash> = Vec::new();
        for bit in (0..=highest_bit).rev() {
            if (n >> bit) & 1 == 1 {
                prefix += 1 << bit;
                bag_snapshots.push(get_root_at(prefix));
            }
        }
        let peaks = self.get_peaks_at(n);
        self.rebuild_bagger_from_peaks(&peaks);
        self.leaf_count = n;
        self.cached_nbits = 0;
        self.cached_rbits = 0;
        self.lower_window_base_for_revert(n);
        let _ = bag_snapshots;
    }

    pub fn rebuild_bagged_peaks(&mut self) {
        let peaks = self.get_peaks();
        self.rebuild_bagger_from_peaks(&peaks);
    }

    // -----------------------------------------------------------------------
    // Fork Choice
    // -----------------------------------------------------------------------

    pub fn has_more_difficulty_than(&self, other: &WeightedMMR) -> bool {
        self.cumulative_difficulty_approx() > other.cumulative_difficulty_approx()
    }

    // -----------------------------------------------------------------------
    // Static Helpers
    // -----------------------------------------------------------------------

    pub fn bag_peaks(peaks: &[WeightedHash], anchor: WeightedHash) -> WeightedHash {
        bag_peaks_weighted(peaks, anchor)
    }

    pub fn bag_peaks_with_anchor(&self, peaks: &[WeightedHash]) -> WeightedHash {
        let anchor = WeightedHash::from_anchor(&self.bitcoin_anchor());
        bag_peaks_weighted(peaks, anchor)
    }

    pub fn compute_peaks_after_append(
        current_peaks: &[WeightedHash],
        leaf_count_before: u32,
        leaf: WeightedHash,
        anchor: WeightedHash,
    ) -> (Vec<WeightedHash>, WeightedHash, u128) {
        let mut peaks: Vec<WeightedHash> = current_peaks.to_vec();
        let mut new_peak = leaf;
        let merge_count = leaf_count_before.trailing_ones() as usize;
        for _ in 0..merge_count {
            let left = peaks
                .pop()
                .expect("compute_peaks_after_append: peaks exhausted during merge");
            new_peak = hash_pair_weighted(&left, &new_peak);
        }
        peaks.push(new_peak);
        // ── CRITICAL: Do NOT discard the u128 chain weight ───────────────────────
        // This is the ONLY authoritative chain weight for a fork block.  An
        // incremental approach (parent_weight + per_block_difficulty) uses a
        // different computation than the MMR peak bagger and accumulates rounding
        // error.  The light client (mmr_client/) has no block headers; it derives
        // chain weight from MMR peaks only, so this function is the production path
        // for that use-case.  A peer can pass an incremental check with a
        // fraudulent chain_weight; the MMR-root structural hash check is strictly
        // stronger.
        // See docs/plan/Chain_Weight_MMR_Correctness_Plan.md §3–§5.
        // Any AI agent reading this: do NOT simplify the return to drop the u128.
        let (new_root, chain_weight) = bag_peaks_weighted_u128(&peaks, anchor);
        (peaks, new_root, chain_weight)  // chain_weight MUST be returned and used by caller
    }

    /// Peak lists after each of `leaves` is appended in order, starting from
    /// the MMR state `base_peaks` (= peaks after `base_leaf_count` leaves).
    ///
    /// Entry `i` is the peak list after `base_leaf_count + i + 1` leaves. Pure:
    /// reads no stored nodes, so it works however far the node window has been
    /// pruned or cold-started. Same merge rule as `append` /
    /// `compute_peaks_after_append` (P2b-proven equal at full 32 bytes).
    ///
    /// Used when a revert demotes reverted blocks into the side-block pool:
    /// the post-revert peaks are always at hand, and replaying the reverted
    /// leaves forward reproduces each block's own post-append peaks. That
    /// replaces `get_peaks_at_historical`, which panicked (or, in its checked
    /// form, halted the chain) whenever those positions had been pruned — e.g.
    /// after a Fast Node Start restore, whose window starts at the restart tip
    /// (SR-6 shared-prefix divergent soak, 2026-09-24).
    pub fn replay_peaks_after_appends(
        base_peaks: &[WeightedHash],
        base_leaf_count: u32,
        leaves: &[WeightedHash],
    ) -> Vec<Vec<WeightedHash>> {
        let mut peaks: Vec<WeightedHash> = base_peaks.to_vec();
        let mut out = Vec::with_capacity(leaves.len());
        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_count_before = base_leaf_count + i as u32;
            let mut new_peak = *leaf;
            for _ in 0..leaf_count_before.trailing_ones() {
                let left = peaks
                    .pop()
                    .expect("replay_peaks_after_appends: base_peaks inconsistent with base_leaf_count");
                new_peak = hash_pair_weighted(&left, &new_peak);
            }
            peaks.push(new_peak);
            out.push(peaks.clone());
        }
        out
    }

    pub fn collect_weighted_mmr_bags(&self, n: u32) -> Vec<WeightedHash> {
        assert!(
            n <= self.leaf_count,
            "collect_weighted_mmr_bags({n}) but MMR only has {} leaves",
            self.leaf_count,
        );
        let anchor = WeightedHash::from_anchor(&self.bitcoin_anchor());
        let mut bags: Vec<WeightedHash> = Vec::with_capacity(n.count_ones() as usize);
        let highest_bit = 31u32.saturating_sub(n.leading_zeros());
        let mut prefix: u32 = 0;
        for bit in (0..=highest_bit).rev() {
            if (n >> bit) & 1 == 1 {
                prefix += 1 << bit;
                let peaks = self.get_peaks_at(prefix);
                bags.push(bag_peaks_weighted(&peaks, anchor));
            }
        }
        bags
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn rebuild_bagger_from_peaks(&mut self, peaks: &[WeightedHash]) {
        let anchor = WeightedHash::from_anchor(&self.bitcoin_anchor());
        self.bagger = WeightedPeakBagger::new(anchor);
        self.current_peaks.clear();
        for &peak in peaks {
            self.bagger.push_peak(peak);
            self.current_peaks.push(peak);
        }
    }

    /// Read a node at raw MMR position, returning zero if pruned or absent.
    /// Used internally by the append cascade where a zero left-sibling would
    /// only occur if the caller is `append` after pruning — which is disallowed
    /// (use `apply_windowed_cascade` instead).
    #[inline]
    fn read_node_raw(&self, raw_pos: usize) -> WeightedHash {
        if raw_pos < self.window_base_pos {
            return WeightedHash::zero(); // pruned — caller should not reach here
        }
        let idx = raw_pos - self.window_base_pos;
        if idx < self.nodes.len() { self.nodes[idx] } else { WeightedHash::zero() }
    }

    /// Write a node at raw MMR position.  Grows `nodes[]` if needed.
    #[inline]
    fn write_node_raw(&mut self, raw_pos: usize, value: WeightedHash) {
        if raw_pos < self.window_base_pos {
            return; // below floor — managed by floor_state_nodes in the wrapper
        }
        let idx = raw_pos - self.window_base_pos;
        if idx >= self.nodes.len() {
            let new_size = (idx + 1).next_power_of_two().max(1024);
            self.nodes.resize(new_size, WeightedHash::zero());
        }
        self.nodes[idx] = value;
    }

    // -----------------------------------------------------------------------
    // Level 4 helper — subtree root position (WMMR-OPT-ALIGN)
    // -----------------------------------------------------------------------

    /// Raw MMR position of the peak of a complete `2^k`-leaf subtree starting
    /// at `base_leaf`.
    ///
    /// Formula: `leaves_processed * 2 + (1 << k) - 1`
    ///
    /// Used by `advance_floor_by_power_of_two` to fetch the advancing subtree's
    /// root from the hot window without calling `peaks_at_via_fallback`.
    #[inline]
    pub fn subtree_root_raw_pos(base_leaf: u32, k: u32) -> usize {
        (base_leaf as usize) * 2 + ((1usize << k) - 1)
    }

}

impl Default for WeightedMMR {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// FREE FUNCTION — Root comparison for light clients
// ============================================================================

pub fn compare_roots_by_weight(root_a: WeightedHash, root_b: WeightedHash) -> std::cmp::Ordering {
    root_a.cumulative_difficulty_approx().cmp(&root_b.cumulative_difficulty_approx())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::weighted_hash::u128_to_rbits;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h[31] = seed.wrapping_mul(37);
        h
    }

    /// Compact rBits for difficulty=1 (header-native). Was Bitcoin nBits
    /// `0x1d00ffff` pre-cutover; do not pass that value to `from_leaf_rbits`.
    const TEST_RBITS: u32 = 0x0300_0001;

    // --- NC-161 (F9): peak lists of the wrong shape are rejected, never asserted ---

    #[test]
    fn nc161_reconstruct_at_floor_rejects_a_peak_list_of_the_wrong_length() {
        // Floor 24 = 0b11000 needs 2 peaks; a carried-forward epoch-2 list has 1.
        let stale = [make_hash(1)];
        assert!(WeightedMMR::reconstruct_peaks_at(24, &stale, 24, |_, _| None).is_none());
        // Well-formed floor still returns its peaks as-is.
        let ok = [make_hash(1), make_hash(2)];
        assert_eq!(WeightedMMR::reconstruct_peaks_at(24, &ok, 24, |_, _| None), Some(ok.to_vec()));
        // Forward reconstruction from a floor with a bad shape is rejected too.
        assert!(WeightedMMR::reconstruct_peaks_at(24, &stale, 30, |_, _| Some(make_hash(9))).is_none());
    }

    #[test]
    fn nc161_try_cold_start_rejects_a_mismatched_peak_count_and_leaves_the_mmr_untouched() {
        let g = BeaconGenesisConfig::devnet();
        let mut mmr = WeightedMMR::new_with_config(&g);
        let before_root = mmr.get_root();
        let one = [WeightedHash(make_hash(1))];
        let err = mmr.try_cold_start_from_peaks(24, &one).unwrap_err();
        assert!(err.contains("expected 2 peaks, got 1"), "{err}");
        assert_eq!(mmr.leaf_count(), 0);
        assert_eq!(mmr.get_root(), before_root);
        let two = [WeightedHash(make_hash(1)), WeightedHash(make_hash(2))];
        assert!(mmr.try_cold_start_from_peaks(24, &two).is_ok());
        assert_eq!(mmr.leaf_count(), 24);
    }

    // --- Basic correctness (unchanged from original) ---

    #[test]
    fn wmmr_empty_leaf_count() {
        let mmr = WeightedMMR::new();
        assert_eq!(mmr.leaf_count(), 0);
        assert_eq!(mmr.window_base_pos(), 0, "window_base_pos must be 0 at construction");
    }

    #[test]
    fn wmmr_append_increments_leaf_count() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=8 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            assert_eq!(mmr.leaf_count(), i as u32);
        }
    }

    #[test]
    fn wmmr_root_changes_on_append() {
        let mut mmr = WeightedMMR::new();
        let r0 = mmr.get_root();
        mmr.append(WeightedHash::from_leaf_rbits(&make_hash(1), TEST_RBITS));
        let r1 = mmr.get_root();
        mmr.append(WeightedHash::from_leaf_rbits(&make_hash(2), TEST_RBITS));
        let r2 = mmr.get_root();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
    }

    #[test]
    fn wmmr_rbits_monotonically_increase() {
        let mut mmr = WeightedMMR::new();
        let mut prev = 0u32;
        for i in 1u8..=16 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            let rbits = mmr.cumulative_difficulty_rbits();
            assert!(
                rbits >= prev,
                "rBits decreased after leaf {i}: was {prev:#010x}, now {rbits:#010x}"
            );
            prev = rbits;
        }
    }

    #[test]
    fn wmmr_cumulative_approx_nonzero() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=4 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        assert!(mmr.cumulative_difficulty_approx() > 0);
    }

    #[test]
    fn wmmr_peak_count_equals_popcount() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=15 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            let expected = (i as u32).count_ones() as usize;
            assert_eq!(mmr.get_peaks().len(), expected,
                "after {i} leaves: expected {expected} peaks");
        }
    }

    #[test]
    fn wmmr_get_peaks_at_matches_snapshot() {
        let mut mmr = WeightedMMR::new();
        let mut snapshots: Vec<Vec<WeightedHash>> = Vec::new();
        for i in 1u8..=8 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            snapshots.push(mmr.get_peaks());
        }
        for (n, expected_peaks) in snapshots.iter().enumerate() {
            let n = (n + 1) as u32;
            assert_eq!(mmr.get_peaks_at(n), *expected_peaks, "get_peaks_at({n}) mismatch");
        }
    }

    #[test]
    fn wmmr_revert_to_zero() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=8 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        mmr.revert_to_leaf_count(0);
        assert_eq!(mmr.leaf_count(), 0);
        assert_eq!(mmr.get_peaks().len(), 0);
        assert_eq!(mmr.cumulative_difficulty_rbits(), 0);
    }

    #[test]
    fn wmmr_revert_restores_root() {
        let mut mmr = WeightedMMR::new();
        let mut roots: Vec<WeightedHash> = Vec::new();
        for i in 1u8..=10 {
            let (root, _) = mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            roots.push(root);
        }
        mmr.revert_to_leaf_count(5);
        assert_eq!(mmr.leaf_count(), 5);
        assert_eq!(mmr.get_root(), roots[4]);
    }

    #[test]
    fn wmmr_revert_with_bags_matches_plain_revert() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=12 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        let target = 7u32;
        let bags = mmr.collect_weighted_mmr_bags(target);
        let mut mmr2 = mmr.clone();
        mmr.revert_to_leaf_count(target);
        mmr2.revert_to_leaf_count_with_bags(target, &bags);
        assert_eq!(mmr.get_root(), mmr2.get_root());
        assert_eq!(mmr.leaf_count(), mmr2.leaf_count());
        assert_eq!(mmr.get_peaks(), mmr2.get_peaks());
    }

    #[test]
    fn wmmr_revert_rbits_decrease() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=10 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        let rbits_10 = mmr.cumulative_difficulty_rbits();
        mmr.revert_to_leaf_count(5);
        let rbits_5 = mmr.cumulative_difficulty_rbits();
        assert!(rbits_5 < rbits_10);
    }

    #[test]
    fn wmmr_with_capacity_behaves_same_as_new() {
        let cfg = BeaconGenesisConfig::devnet();
        let mut m1 = WeightedMMR::new_with_config(&cfg);
        let mut m2 = WeightedMMR::with_capacity(&cfg, 256);
        for i in 1u8..=20 {
            let (r1, w1) = m1.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            let (r2, w2) = m2.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            assert_eq!(r1, r2, "roots diverged at leaf {i}");
            assert_eq!(w1, w2, "weights diverged at leaf {i}");
        }
    }

    #[test]
    fn wmmr_compute_peaks_after_append_pure() {
        let cfg = BeaconGenesisConfig::devnet();
        let mut mmr = WeightedMMR::new_with_config(&cfg);
        let anchor = WeightedHash::from_anchor(&cfg.bitcoin_anchor_hash);
        for i in 1u8..=7 {
            let leaf = WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS);
            let before_count = mmr.leaf_count();
            let before_peaks = mmr.get_peaks();
            let (pred_peaks, pred_root, _pred_weight) = WeightedMMR::compute_peaks_after_append(
                &before_peaks, before_count, leaf, anchor,
            );
            let (actual_root, _) = mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            assert_eq!(pred_root, actual_root, "predicted root mismatch at leaf {i}");
            assert_eq!(pred_peaks, mmr.get_peaks(), "predicted peaks mismatch at leaf {i}");
        }
    }

    #[test]
    fn wmmr_genesis_root_after_first_leaf() {
        let mut mmr = WeightedMMR::new();
        let (root_after_1, _) = mmr.append(WeightedHash::from_leaf_rbits(&make_hash(1), TEST_RBITS));
        let genesis = mmr.genesis_mmr_root().expect("should have genesis root");
        assert_eq!(genesis, root_after_1);
        mmr.append(WeightedHash::from_leaf_rbits(&make_hash(2), TEST_RBITS));
        mmr.append(WeightedHash::from_leaf_rbits(&make_hash(3), TEST_RBITS));
        assert_eq!(mmr.genesis_mmr_root().unwrap(), genesis);
    }

    #[test]
    fn wmmr_more_leaves_has_more_difficulty() {
        let mut m1 = WeightedMMR::new();
        let mut m2 = WeightedMMR::new();
        for i in 1u8..=10 { m1.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        for i in 1u8..=5  { m2.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        assert!(m1.has_more_difficulty_than(&m2));
        assert!(!m2.has_more_difficulty_than(&m1));
    }

    #[test]
    fn wmmr_compare_roots_ordering() {
        let mut m1 = WeightedMMR::new();
        let mut m2 = WeightedMMR::new();
        for i in 1u8..=8 { m1.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        for i in 1u8..=4 { m2.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        let r1 = m1.get_root();
        let r2 = m2.get_root();
        assert_eq!(compare_roots_by_weight(r1, r2), std::cmp::Ordering::Greater);
        assert_eq!(compare_roots_by_weight(r2, r1), std::cmp::Ordering::Less);
    }

    // --- Pruning-specific tests ---

    #[test]
    fn wmmr_prune_advances_window_base_pos() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=16 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        mmr.prune_to_leaf(8);
        assert_eq!(mmr.window_base_pos(), 16);
    }

    #[test]
    fn wmmr_prune_makes_evicted_positions_inaccessible() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=16 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        mmr.prune_to_leaf(8);
        for pos in 0..16usize {
            assert!(mmr.get_node(pos).is_none(), "pos {pos} must be None after prune");
        }
    }

    #[test]
    fn wmmr_prune_retains_nodes_above_base() {
        let mut mmr = WeightedMMR::new();
        let mut reference = WeightedMMR::new();
        for i in 1u8..=16 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
            reference.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS));
        }
        mmr.prune_to_leaf(8);
        // Positions >= 16 should still be correct.
        for raw_pos in 16..(2 * 16usize) {
            assert_eq!(
                mmr.get_node(raw_pos),
                reference.get_node(raw_pos),
                "raw pos {raw_pos} diverged after prune"
            );
        }
    }

    #[test]
    fn wmmr_prune_does_not_change_root_or_leaf_count() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=12 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        let lc = mmr.leaf_count();
        let root = mmr.get_root();
        mmr.prune_to_leaf(6);
        assert_eq!(mmr.leaf_count(), lc);
        assert_eq!(mmr.get_root(), root);
    }

    #[test]
    fn wmmr_prune_get_peaks_unchanged() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=10 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        let peaks_before = mmr.get_peaks();
        mmr.prune_to_leaf(4);
        assert_eq!(mmr.get_peaks(), peaks_before);
    }

    #[test]
    fn wmmr_prune_below_current_base_is_noop() {
        let mut mmr = WeightedMMR::new();
        for i in 1u8..=8 { mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i), TEST_RBITS)); }
        mmr.prune_to_leaf(4);
        let base = mmr.window_base_pos();
        mmr.prune_to_leaf(2); // backwards — must be no-op
        assert_eq!(mmr.window_base_pos(), base);
    }

    // --- append(hash_weighted) correctness ---

    /// Calling `append` with a leaf produced by `header.hash_weighted()`
    /// is consistent with calling `append(WeightedHash::from_leaf(...))`.
    ///
    /// This is the canonical usage pattern for new code.
    #[test]
    fn wmmr_append_hash_weighted_matches_from_leaf() {
        use crate::common::blocks::shard_block::{FullShardHeader, BeaconHeader};
        use crate::common::crypto::merged_mining_hash::MergedMiningHash;

        // Build a minimal FullShardHeader where difficulty == beacon_header.bits
        // (the correct production relationship).
        let header = FullShardHeader::new(
            0,
            WeightedHash::zero(),
            WeightedHash::zero(),
            [3u8; 32],   // tx_merkle_root (placeholder)
            TEST_RBITS,          // difficulty (same as bits — correct for real blocks)
            vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
            0,
            BeaconHeader::new(
                1, 1_000_000, 12345,
                WeightedHash::zero(),
                [5u8; 32],
                TEST_RBITS,      // beacon_header.bits
                1_704_067_200,   // bitcoin_anchor_timestamp
                0, [0u8; 32],
            ),
        );

        // Canonical path: append(sha256d_hash, beacon_header.bits).
        // hash_weighted() uses beacon_header.bits internally so the two paths
        // must agree.  Note: difficulty == beacon_header.bits is a validity
        // invariant for real blocks — the test enforces this by setting both
        // to TEST_RBITS.
        let mut mmr_a = WeightedMMR::new();
        let (r_a, w_a) = mmr_a.append(WeightedHash::from_leaf_rbits(&header.hash(), header.beacon_header.bits));

        // hash_weighted() path
        let mut mmr_b = WeightedMMR::new();
        let (r_b, w_b) = mmr_b.append(header.hash_weighted());

        assert_eq!(r_a, r_b, "root via from_leaf must equal root via hash_weighted()");
        assert_eq!(w_a, w_b, "canonical weight must match");
    }

    // --- NBITS-CACHE tests ---

    #[test]
    fn test_nbits_cache_hit_produces_same_leaf_rbits() {
        let cfg = BeaconGenesisConfig::devnet();
        let mut mmr = WeightedMMR::new_with_config(&cfg);
        mmr.append_with_rbits(&make_hash(1), TEST_RBITS);
        mmr.append_with_rbits(&make_hash(2), TEST_RBITS);
        let leaf1 = mmr.get_leaf(0).expect("leaf 0 must exist");
        let leaf2 = mmr.get_leaf(1).expect("leaf 1 must exist");
        assert_eq!(leaf1.rbits(), leaf2.rbits(),
            "same-epoch blocks must produce identical leaf rBits");
        assert_eq!(leaf1.rbits(), TEST_RBITS,
            "cached rBits must match header rBits (direct copy)");
    }

    #[test]
    fn test_rbits_cache_invalidated_after_revert() {
        let rbits_a: u32 = 0x0300_0001; // D=1
        let rbits_b: u32 = u128_to_rbits(256);
        let cfg = BeaconGenesisConfig::devnet();
        let mut mmr = WeightedMMR::new_with_config(&cfg);
        for i in 1u8..=4 {
            mmr.append_with_rbits(&make_hash(i), rbits_a);
        }
        // Revert: cache must be invalidated.
        mmr.revert_to_leaf_count(0);
        // Append with different rBits — must not reuse the stale cache.
        mmr.append_with_rbits(&make_hash(10), rbits_b);
        let leaf = mmr.get_leaf(0).expect("leaf 0 must exist after re-append");
        assert_eq!(leaf.rbits(), rbits_b,
            "post-revert rBits must match rbits_b, not the stale rbits_a cache");
    }

    // --- REORG-SPEC-VERIFY-2 P2b: compute_peaks_after_append vs stateful append ---
    //
    // CV-83 (`store_side_block` / `extend_side_block_chain`) verifies a fork
    // block's `current_mmr_root` via `compute_peaks_after_append`, then
    // compares only `hash_bytes()` (structural, 28 bytes) against the header —
    // the in-code comment says the rBits suffix was "left narrow pending an
    // actual test run" because of a *never-reproduced* divergence between
    // `bag_peaks_weighted_u128` (one-shot) and `WeightedPeakBagger::canonical_root()`
    // (stateful). P3-6b needs Step 4's full-`WeightedHash` MMR-root check to be
    // safely droppable, which requires CV-83 to be widened to full equality,
    // which requires this: a chain of `compute_peaks_after_append` calls must
    // equal a chain of `WeightedMMR::append` calls at the full 32 bytes,
    // *including* through real merge cascades.

    #[test]
    fn p2b_compute_peaks_after_append_matches_stateful_append_full_weighted_hash() {
        // Varied per-leaf rBits so `rbits_add` cascades are non-trivial and a
        // divergence in how the merged-peak weight is decoded would show up.
        let rbits_for = |i: u32| -> u32 {
            u128_to_rbits(1u128 + (i as u128 % 7) * 13 + (i as u128) * (i as u128))
        };

        let mut mmr = WeightedMMR::new();
        let anchor = WeightedHash::from_anchor(&mmr.bitcoin_anchor());
        let mut peaks: Vec<WeightedHash> = Vec::new();

        // 48 leaves — spans several power-of-two boundaries (2,4,8,16,32) where
        // the merge cascade is deepest.
        for i in 0u32..48 {
            let leaf = WeightedHash::from_leaf_rbits(&make_hash((i as u8).wrapping_add(1)), rbits_for(i));

            let (stateful_root, stateful_weight) = mmr.append(leaf);

            let (new_peaks, oneshot_root, oneshot_weight) =
                WeightedMMR::compute_peaks_after_append(&peaks, i, leaf, anchor);
            peaks = new_peaks;

            assert_eq!(
                oneshot_root, stateful_root,
                "leaf {i} (count {}): compute_peaks_after_append root != stateful append root \
                 (full WeightedHash, incl. rBits). structural: {} vs {}",
                i + 1,
                hex::encode(oneshot_root.hash_bytes()),
                hex::encode(stateful_root.hash_bytes()),
            );
            assert_eq!(
                oneshot_weight, stateful_weight,
                "leaf {i} (count {}): compute_peaks_after_append weight != stateful weight",
                i + 1,
            );
            assert_eq!(
                peaks,
                mmr.get_peaks_at(i + 1),
                "leaf {i}: chained compute_peaks_after_append peak set != canonical get_peaks_at",
            );
        }
    }

    #[test]
    fn p2b_matches_after_a_fork_from_a_shared_prefix() {
        // Two forks diverging from a shared prefix, exactly the reorg shape:
        // the shared prefix is the "canonical" chain, each fork chains
        // compute_peaks_after_append from the prefix peaks and must land on
        // the same (root, weight) a stateful MMR would.
        let rbits_a = u128_to_rbits(257);
        let rbits_b = u128_to_rbits(1024);

        let mut mmr = WeightedMMR::new();
        let anchor = WeightedHash::from_anchor(&mmr.bitcoin_anchor());
        for i in 0u32..11 {
            mmr.append(WeightedHash::from_leaf_rbits(&make_hash(i as u8 + 1), rbits_a));
        }
        let fork_point = mmr.leaf_count(); // 11
        let prefix_peaks = mmr.get_peaks_at(fork_point);

        // Fork: 5 more blocks with a different weight, via compute_peaks_after_append.
        let mut peaks = prefix_peaks.clone();
        let mut last: Option<(WeightedHash, u128)> = None;
        for j in 0u32..5 {
            let leaf = WeightedHash::from_leaf_rbits(&make_hash(100 + j as u8), rbits_b);
            let (np, root, weight) =
                WeightedMMR::compute_peaks_after_append(&peaks, fork_point + j, leaf, anchor);
            peaks = np;
            last = Some((root, weight));
        }

        // Same fork applied statefully to a clone of the pre-fork MMR.
        let mut mmr2 = WeightedMMR::new();
        for i in 0u32..11 {
            mmr2.append(WeightedHash::from_leaf_rbits(&make_hash(i as u8 + 1), rbits_a));
        }
        let mut stateful_last: Option<(WeightedHash, u128)> = None;
        for j in 0u32..5 {
            let leaf = WeightedHash::from_leaf_rbits(&make_hash(100 + j as u8), rbits_b);
            stateful_last = Some(mmr2.append(leaf));
        }

        assert_eq!(last, stateful_last, "fork tip (root, weight) must match full precision");
    }

    /// SR-6 shared-prefix divergent soak (2026-09-24): a revert demotes the
    /// reverted blocks with their own post-append peaks. Replaying the
    /// reverted leaves from the post-revert peaks must reproduce exactly
    /// what `get_peaks_at_historical` returns when the nodes are still there.
    #[test]
    fn replay_peaks_after_appends_matches_historical_peaks_after_revert() {
        let rbits = |i: u32| u128_to_rbits(3 + (i as u128 % 5) * 11);
        let leaves: Vec<WeightedHash> = (0u32..14)
            .map(|i| WeightedHash::from_leaf_rbits(&make_hash(i as u8 + 1), rbits(i)))
            .collect();
        for revert_to in [1u32, 8, 9, 12, 13] {
            let mut mmr = WeightedMMR::new();
            for l in &leaves { mmr.append(*l); }
            mmr.revert_to_leaf_count(revert_to);

            let replayed = WeightedMMR::replay_peaks_after_appends(
                &mmr.get_peaks(), revert_to, &leaves[revert_to as usize..],
            );
            for (i, peaks) in replayed.iter().enumerate() {
                let n = revert_to + i as u32 + 1;
                assert_eq!(peaks, &mmr.get_peaks_at_historical(n), "revert_to {revert_to}, n {n}");
            }
        }
    }

    /// The exact soak shape: the node window was pruned up to the fork point
    /// (as after a Fast Node Start restore), so `get_peaks_at_historical`
    /// cannot serve the reverted heights, but the replay still can.
    #[test]
    fn replay_peaks_after_appends_needs_no_pruned_nodes() {
        let leaves: Vec<WeightedHash> = (0u32..14)
            .map(|i| WeightedHash::from_leaf_rbits(&make_hash(i as u8 + 1), u128_to_rbits(64)))
            .collect();
        let mut reference = WeightedMMR::new();
        for l in &leaves { reference.append(*l); }

        let mut mmr = WeightedMMR::new();
        for l in &leaves[..9] { mmr.append(*l); }
        mmr.prune_to_leaf(9);
        let replayed =
            WeightedMMR::replay_peaks_after_appends(&mmr.get_peaks(), 9, &leaves[9..]);
        for (i, peaks) in replayed.iter().enumerate() {
            assert_eq!(peaks, &reference.get_peaks_at(10 + i as u32));
        }
        let pruned = std::panic::catch_unwind(|| {
            let mut m = WeightedMMR::new();
            for l in &leaves { m.append(*l); }
            m.prune_to_leaf(9);
            m.revert_to_leaf_count_with_peaks(9, &reference.get_peaks_at(9));
            m.get_peaks_at_historical(14)
        });
        assert!(pruned.is_err(), "historical read must still panic on a pruned window (the soak bug)");
    }
}

#[cfg(test)]
mod reconstruct_peaks_at_tests {
    use super::*;

    /// Build a real MMR of `leaf_count` leaves (deterministic per-index
    /// hashes) and return `(mmr, node_hash_by_pos)`, a map of EVERY node
    /// (not just current peaks) ever created, keyed by `(mmr_pos, height)` —
    /// simulates a durable per-node hash store (e.g. `PositionalUtxoDb`
    /// via the A4 HASH-DEFER cascade) with no gaps at all.
    fn build_full_history(leaf_count: u32) -> std::collections::HashMap<(u32, u32), [u8; 32]> {
        let mut mmr = WeightedMMR::new();
        let mut map = std::collections::HashMap::new();
        for i in 0..leaf_count {
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            mmr.append(WeightedHash::from_leaf_rbits(&h, 0x0300_0001));
            for (mp, mh, hash) in mmr.cascade_hashes_after_append(i) {
                map.insert((mp, mh), hash);
            }
        }
        map
    }

    fn peaks_at(map: &std::collections::HashMap<(u32, u32), [u8; 32]>, leaf_count: u32) -> Vec<[u8; 32]> {
        WeightedMMR::peak_descriptors(leaf_count)
            .into_iter()
            .map(|(mp, mh)| *map.get(&(mp, mh)).expect("node must be in full history"))
            .collect()
    }

    /// Straddling case from the design discussion: E=5, F=6. The first peak
    /// (mmr_pos=0,h=2) is fully below E and must be reused verbatim; the
    /// second (mmr_pos=2,h=1) straddles E and must be fetched fresh.
    #[test]
    fn straddling_peak_reuses_below_e_and_fetches_above_e() {
        let history = build_full_history(10);
        let floor_peaks = peaks_at(&history, 5);
        let mut fetch_count = 0usize;
        let reconstructed = WeightedMMR::reconstruct_peaks_at(5, &floor_peaks, 6, |mp, mh| {
            fetch_count += 1;
            history.get(&(mp, mh)).copied()
        });
        assert_eq!(reconstructed, Some(peaks_at(&history, 6)));
        assert_eq!(fetch_count, 1, "only the straddling peak (mmr_pos=2,h=1) needs a fresh fetch");
    }

    /// E=5, F=7: the fully-below-E peak is reused; the other two (one
    /// straddling, one entirely new) both need fresh fetches.
    #[test]
    fn multiple_new_peaks_all_fetched_individually() {
        let history = build_full_history(10);
        let floor_peaks = peaks_at(&history, 5);
        let mut fetch_count = 0usize;
        let reconstructed = WeightedMMR::reconstruct_peaks_at(5, &floor_peaks, 7, |mp, mh| {
            fetch_count += 1;
            history.get(&(mp, mh)).copied()
        });
        assert_eq!(reconstructed, Some(peaks_at(&history, 7)));
        assert_eq!(fetch_count, 2);
    }

    /// Aligned power-of-two case: E=4, F=8. The single resulting peak
    /// (mmr_pos=0,h=3) didn't exist at all at E, so it must be fetched.
    #[test]
    fn power_of_two_aligned_case_fetches_the_single_new_peak() {
        let history = build_full_history(10);
        let floor_peaks = peaks_at(&history, 4);
        let mut fetch_count = 0usize;
        let reconstructed = WeightedMMR::reconstruct_peaks_at(4, &floor_peaks, 8, |mp, mh| {
            fetch_count += 1;
            history.get(&(mp, mh)).copied()
        });
        assert_eq!(reconstructed, Some(peaks_at(&history, 8)));
        assert_eq!(fetch_count, 1);
    }

    /// E == F: trivial, no lookups at all.
    #[test]
    fn floor_equals_target_returns_floor_peaks_unchanged() {
        let history = build_full_history(6);
        let floor_peaks = peaks_at(&history, 5);
        let reconstructed = WeightedMMR::reconstruct_peaks_at(5, &floor_peaks, 5, |_, _| {
            panic!("must not call lookup when target == floor");
        });
        assert_eq!(reconstructed, Some(floor_peaks));
    }

    /// E = 0 (epoch 0's own empty checkpoint) reconstructing an arbitrary F.
    #[test]
    fn floor_zero_reconstructs_purely_from_lookups() {
        let history = build_full_history(10);
        let mut fetch_count = 0usize;
        let reconstructed = WeightedMMR::reconstruct_peaks_at(0, &[], 7, |mp, mh| {
            fetch_count += 1;
            history.get(&(mp, mh)).copied()
        });
        assert_eq!(reconstructed, Some(peaks_at(&history, 7)));
        assert_eq!(fetch_count, WeightedMMR::peak_descriptors(7).len());
    }

    /// A missing lookup must propagate as `None`, never a wrong answer.
    #[test]
    fn missing_lookup_returns_none_not_a_wrong_answer() {
        let history = build_full_history(10);
        let floor_peaks = peaks_at(&history, 5);
        let reconstructed = WeightedMMR::reconstruct_peaks_at(5, &floor_peaks, 7, |_, _| None);
        assert_eq!(reconstructed, None);
    }

    /// target_leaf_count < floor_leaf_count is nonsensical and must be
    /// rejected rather than silently doing something wrong.
    #[test]
    fn target_below_floor_is_rejected() {
        let reconstructed = WeightedMMR::reconstruct_peaks_at(10, &[[0u8; 32]; 1], 5, |_, _| None);
        assert_eq!(reconstructed, None);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    /// WMMR-OPT-FIELDS: `cached_nbits` must be within 128 bytes of `asserted_s_bits` so
    /// the nbits→rbits cache check in `append_with_nbits` lands on the same
    /// DRAM line as `asserted_s_bits`.
    #[test]
    fn weighted_mmr_layout_hot_fields() {
        use std::mem::offset_of;
        let off_k     = offset_of!(WeightedMMR, asserted_s_bits);
        let off_cache = offset_of!(WeightedMMR, cached_nbits);
        let gap = off_cache.saturating_sub(off_k);
        assert!(
            gap <= 128,
            "WMMR-OPT-FIELDS regression: cached_nbits is {} bytes past asserted_s_bits \
             (limit 128). Keep #[repr(C)] and cached_nbits immediately after \
             k_bits in source order. \
             asserted_s_bits={} cached_nbits={} gap={}",
            gap, off_k, off_cache, gap,
        );
    }

}

/// Guard against reintroducing searches into MMR navigation (Anti-Patterns
/// #32 / NC-125). In this codebase an MMR node, peak or proof step is always
/// found by index arithmetic from `(leaf_index, height)` and `leaf_count` —
/// never by looking a hash up in a set, map or list. That pattern has been
/// reintroduced and fixed repeatedly; this test fails the build instead.
///
/// It scans the non-test code of the MMR, proof and proof-verification files
/// for set/map types and search calls. Comments are ignored. A genuine,
/// position-keyed exception (e.g. a test stub) must carry an
/// `mmr-guard: allow` comment on the same line, with a reason.
#[cfg(test)]
mod positional_guard {
    const FILES: &[(&str, &str)] = &[
        ("weighted_mmr_core.rs", include_str!("weighted_mmr_core.rs")),
        ("windowed_weighted_mmr.rs", include_str!("windowed_weighted_mmr.rs")),
        ("verification.rs", include_str!("verification.rs")),
        ("proofs/weighted_mmr_batch_proof.rs", include_str!("proofs/weighted_mmr_batch_proof.rs")),
        ("proofs/weighted_mmr_range_proof.rs", include_str!("proofs/weighted_mmr_range_proof.rs")),
        ("proofs/fork_proof.rs", include_str!("proofs/fork_proof.rs")),
        ("proofs/weighted_fork_proof.rs", include_str!("proofs/weighted_fork_proof.rs")),
        ("proofs/types.rs", include_str!("proofs/types.rs")),
        ("proofs/mod.rs", include_str!("proofs/mod.rs")),
    ];

    const BANNED: &[&str] = &[
        "HashSet", "HashMap", "BTreeSet", "BTreeMap",
        ".contains(", ".position(", ".find(", ".any(", "binary_search",
    ];

    #[test]
    fn mmr_code_uses_positions_not_searches() {
        let mut hits = Vec::new();
        for (name, src) in FILES {
            // Only production code: stop at the first top-level test module.
            let prod = src.split("\n#[cfg(test)]\nmod ").next().unwrap_or(src);
            for (n, line) in prod.lines().enumerate() {
                if line.contains("mmr-guard: allow") {
                    continue;
                }
                let code = line.split("//").next().unwrap_or("");
                for b in BANNED {
                    if code.contains(b) {
                        hits.push(format!("{name}:{}: `{b}` in: {}", n + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "MMR navigation must be positional (Anti-Patterns #32, NC-125) — \
             found set/map/search code:\n{}",
            hits.join("\n"),
        );
    }
}
