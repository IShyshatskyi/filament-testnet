//! PO-4 / NC-128 (`rustmmrdb/docs/state_transition_ordering_design.md` §5.3,
//! read rule "R-C"): the UTXO changes of blocks that are in the chain but not
//! yet in P1DB.
//!
//! A block is applied in memory under the chain lock and written to P1DB
//! later (NC-44 deferred persist, B11 batch persist). Between the two, P1DB
//! is behind the chain: it lacks the outputs those blocks created and still
//! shows the outputs they spent as unspent. Validating against P1DB alone
//! therefore rejects a valid spend of a new output (TX-1) and accepts a
//! second spend of an output already spent (double spend).
//!
//! The difference has two parts: the outputs the not-yet-durable blocks (the
//! "tail") created, held in a [`ForkUtxoOverlay`], and the outpoints they
//! spent, held in [`TailSpends`]. Together with P1DB they give the chain's
//! real current state through the existing [`ForkPointUtxoView`] (fork point
//! = P1DB's commit cursor, fork blocks = the tail). Both are scoped exactly
//! as `ForkUtxoOverlay` is: state of blocks not yet durable, purged once P1DB
//! has them. In steady state (every block persisted) validation reads P1DB
//! directly and neither is consulted.
//!
//! Keystone keeps both in one [`TailUtxoCache`]. Kameniar already keeps the
//! overlay (`fork_utxo_overlay`) and adds only a [`TailSpends`] beside it.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::ForkUtxoOverlay;
use crate::common::blocks::ShardBlockBody;
use crate::common::validation::transactions::ForkPointUtxoView;
use crate::transaction::FlatOutput;

/// Every outpoint spent by the chain's not-yet-durable blocks, whatever the
/// spent output's height. A spend of an output the tail itself created also
/// removes it from the overlay, but once the creating block is durable (and
/// purged) only this record says that a newer, unsaved block spent it.
#[derive(Clone, Debug, Default)]
pub struct TailSpends {
    consumed: HashSet<(u32, u16)>,
    /// `consumed` grouped by the spending block's height.
    spent_by: BTreeMap<u32, Vec<(u32, u16)>>,
}

impl TailSpends {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }

    /// Number of spent outpoints held (memory accounting, NC-173).
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn consumed(&self) -> &HashSet<(u32, u16)> {
        &self.consumed
    }

    /// Record the spends of the block at `height`. Anything recorded for
    /// `height` or above is dropped first: those blocks were reverted.
    pub fn apply(&mut self, body: &ShardBlockBody, height: u32) {
        self.drop_from(height);
        if body.inputs.is_empty() {
            return;
        }
        let spent: Vec<(u32, u16)> =
            body.inputs.iter().map(|i| (i.prev_height, i.prev_output_idx)).collect();
        self.consumed.extend(spent.iter().copied());
        self.spent_by.insert(height, spent);
    }

    /// Forget the spends of blocks at `height` and above (reverted).
    pub fn drop_from(&mut self, height: u32) {
        let removed = self.spent_by.split_off(&height);
        self.forget(removed);
    }

    /// Forget the spends of the block at `height` (P1DB has it now).
    pub fn purge_height(&mut self, height: u32) {
        if let Some(spent) = self.spent_by.remove(&height) {
            for op in spent {
                self.consumed.remove(&op);
            }
        }
    }

    /// Forget the spends of every block at or below `durable`.
    pub fn purge_through(&mut self, durable: u32) {
        let keep = self.spent_by.split_off(&durable.saturating_add(1));
        let removed = std::mem::replace(&mut self.spent_by, keep);
        self.forget(removed);
    }

    // Two folded-in blocks never spend the same outpoint (validation rejects
    // the second), so removing by value cannot drop another block's record.
    fn forget(&mut self, removed: BTreeMap<u32, Vec<(u32, u16)>>) {
        for spent in removed.into_values() {
            for op in spent {
                self.consumed.remove(&op);
            }
        }
    }
}

/// Outputs created and outpoints spent by the chain's not-yet-durable blocks.
#[derive(Clone, Debug, Default)]
pub struct TailUtxoCache {
    /// Unspent outputs created by folded-in blocks.
    overlay: ForkUtxoOverlay,
    spends: TailSpends,
    /// Height of the last block folded in (`None` until the first).
    tip: Option<u32>,
}

impl TailUtxoCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Height of the last block folded in.
    pub fn tip(&self) -> Option<u32> {
        self.tip
    }

    /// `true` when no un-purged block state is held.
    pub fn is_empty(&self) -> bool {
        self.overlay.is_empty() && self.spends.is_empty()
    }

    /// Forget everything, including the tip.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Fold in the block at `height` (must be the next height after
    /// [`Self::tip`], or the first block after a [`Self::reset_at`]).
    pub fn apply(&mut self, body: &ShardBlockBody, height: u32) {
        self.overlay.apply_flat_body(body, height);
        self.spends.apply(body, height);
        self.tip = Some(height);
    }

    /// Start over at `durable` (P1DB's commit cursor): empty, with the tip
    /// set so the next [`Self::apply`] is for `durable + 1`.
    pub fn reset_at(&mut self, durable: Option<u32>) {
        self.clear();
        self.tip = durable;
    }

    /// The cache for the blocks in `(durable, upto]`, built from their bodies
    /// (`body_at(h)`), or `None` when one of them is not available. Empty
    /// (tip `upto`) when `durable >= upto`. Used by the live view
    /// (`upto` = chain tip) and by the reorg pre-checks (`upto` = fork point,
    /// FR-W-07).
    pub fn build_range(
        durable: Option<u32>,
        upto: u32,
        mut body_at: impl FnMut(u32) -> Option<ShardBlockBody>,
    ) -> Option<Self> {
        let mut cache = Self::new();
        let from = durable.map_or(0, |d| d.saturating_add(1));
        if from > upto {
            cache.reset_at(Some(upto));
            return Some(cache);
        }
        cache.reset_at(durable);
        for h in from..=upto {
            cache.apply(&body_at(h)?, h);
        }
        Some(cache)
    }

    /// Drop the state of every block at or below `durable`: P1DB has
    /// committed them, so it now holds their outputs and spends.
    pub fn purge_durable(&mut self, durable: u32) {
        self.overlay.purge_through(durable);
        self.spends.purge_through(durable);
    }

    /// The live view: this cache on top of P1DB as of `durable`. `resolved`
    /// must come from [`resolve_durable`] for the inputs to validate.
    pub fn view<'a>(
        &'a self,
        resolved: &'a HashMap<(u32, u16), (Option<FlatOutput>, bool)>,
        durable: Option<u32>,
    ) -> ForkPointUtxoView<'a> {
        tail_view(resolved, &self.overlay, self.spends.consumed(), durable)
    }

    pub fn overlay(&self) -> &ForkUtxoOverlay {
        &self.overlay
    }

    pub fn spends(&self) -> &TailSpends {
        &self.spends
    }

    /// The two parts, for a [`LiveUtxo`] that owns them.
    pub fn into_parts(self) -> (ForkUtxoOverlay, TailSpends) {
        (self.overlay, self.spends)
    }
}

/// P1DB as of `durable`, plus the tail's outputs (`overlay`) and spends
/// (`consumed`).
pub fn tail_view<'a>(
    resolved: &'a HashMap<(u32, u16), (Option<FlatOutput>, bool)>,
    overlay: &'a ForkUtxoOverlay,
    consumed: &'a HashSet<(u32, u16)>,
    durable: Option<u32>,
) -> ForkPointUtxoView<'a> {
    // Nothing durable yet: fork height 0 with an empty `resolved` map makes
    // every non-overlay outpoint absent, which is right.
    ForkPointUtxoView::new(resolved, overlay, consumed, durable.unwrap_or(0))
}

/// Read from P1DB the inputs a tail view needs to answer: those at or below
/// `durable` that the tail did not spend. (The view never reads the overlay
/// at or below `durable` — P1DB is authoritative there.)
#[cfg(feature = "full-node")]
pub fn resolve_durable(
    p1db: &rustmmrdb::PositionalUtxoDb,
    consumed: &HashSet<(u32, u16)>,
    durable: Option<u32>,
    inputs: impl IntoIterator<Item = (u32, u16)>,
) -> Result<HashMap<(u32, u16), (Option<FlatOutput>, bool)>, String> {
    let mut resolved = HashMap::new();
    let Some(d) = durable else { return Ok(resolved) };
    let wanted: Vec<(u32, u16)> = inputs
        .into_iter()
        .filter(|&(h, i)| h <= d && !consumed.contains(&(h, i)))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if wanted.is_empty() {
        return Ok(resolved);
    }
    let ops: Vec<rustmmrdb::Outpoint> =
        wanted.iter().map(|&(h, i)| rustmmrdb::Outpoint::new(h, i)).collect();
    let outs = p1db
        .get_utxos_batch(&ops)
        .map_err(|e| format!("UTXO batch lookup failed: {e}"))?;
    for (op, out) in wanted.into_iter().zip(outs) {
        let flat = out.map(|o| FlatOutput { value: o.value, recipient: o.recipient });
        resolved.insert(op, (flat, false));
    }
    Ok(resolved)
}

/// One output as [`LiveUtxo::output_state`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputState {
    Unspent(FlatOutput),
    /// Created and since spent (in P1DB or by a not-yet-saved block).
    Spent,
    /// No output at that position on this chain.
    Missing,
}

/// The UTXO state one validation call reads (block body, K-6 fees, mempool
/// admission): P1DB alone when nothing is waiting to be saved, else P1DB
/// plus the tail.
#[cfg(feature = "full-node")]
pub enum LiveUtxo<'a> {
    /// Every applied block is in P1DB — read it directly.
    Durable(&'a rustmmrdb::PositionalUtxoDb),
    /// Some applied blocks are not in P1DB yet.
    Tail {
        overlay: Cow<'a, ForkUtxoOverlay>,
        spends: Cow<'a, TailSpends>,
        resolved: HashMap<(u32, u16), (Option<FlatOutput>, bool)>,
        durable: Option<u32>,
    },
}

#[cfg(feature = "full-node")]
impl<'a> LiveUtxo<'a> {
    /// `cache` must hold every block in `(durable, chain_tip]`; pass `None`
    /// when the chain could not build one (a tail block is no longer in
    /// memory) — then this falls back to P1DB alone, the pre-PO-4 behavior.
    pub fn build(
        p1db: &'a rustmmrdb::PositionalUtxoDb,
        durable: Option<u32>,
        chain_tip: u32,
        cache: Option<Cow<'a, TailUtxoCache>>,
        inputs: impl IntoIterator<Item = (u32, u16)>,
    ) -> Result<Self, String> {
        let parts = cache.map(|c| match c {
            Cow::Borrowed(c) => (Cow::Borrowed(c.overlay()), Cow::Borrowed(c.spends())),
            Cow::Owned(c) => {
                let (o, s) = c.into_parts();
                (Cow::Owned(o), Cow::Owned(s))
            }
        });
        Self::build_from_parts(p1db, durable, chain_tip, parts, inputs)
    }

    /// As [`Self::build`], from an overlay and a spend record kept separately
    /// (Kameniar's `fork_utxo_overlay` + `tail_spends`).
    pub fn build_from_parts(
        p1db: &'a rustmmrdb::PositionalUtxoDb,
        durable: Option<u32>,
        chain_tip: u32,
        parts: Option<(Cow<'a, ForkUtxoOverlay>, Cow<'a, TailSpends>)>,
        inputs: impl IntoIterator<Item = (u32, u16)>,
    ) -> Result<Self, String> {
        if durable.is_some_and(|d| d >= chain_tip) {
            return Ok(Self::Durable(p1db));
        }
        let Some((overlay, spends)) = parts else { return Ok(Self::Durable(p1db)) };
        let resolved = resolve_durable(p1db, spends.consumed(), durable, inputs)?;
        Ok(Self::Tail { overlay, spends, resolved, durable })
    }

    /// The view to pass as `BlockValidationUtxo::ForkPoint`, or `None` to
    /// use `BlockValidationUtxo::PositionalDb`.
    pub fn view(&self) -> Option<ForkPointUtxoView<'_>> {
        match self {
            Self::Durable(_) => None,
            Self::Tail { overlay, spends, resolved, durable } => {
                Some(tail_view(resolved, overlay, spends.consumed(), *durable))
            }
        }
    }

    /// One output, as validation would see it (`None` = absent or spent).
    pub fn output(&self, height: u32, idx: u16) -> Option<FlatOutput> {
        match self {
            Self::Durable(db) => db
                .get_utxo(&rustmmrdb::Outpoint::new(height, idx))
                .ok()
                .flatten()
                .map(|o| FlatOutput { value: o.value, recipient: o.recipient }),
            Self::Tail { .. } => self.view().and_then(|v| v.output(height, idx)),
        }
    }

    /// One output's state as the chain sees it now — for RPC reads, which
    /// must agree with validation (`p1db` must be the one this view was
    /// built from).
    pub fn output_state(
        &self,
        p1db: &rustmmrdb::PositionalUtxoDb,
        height: u32,
        idx: u16,
    ) -> OutputState {
        if let Some(out) = self.output(height, idx) {
            return OutputState::Unspent(out);
        }
        if self.spent_in_tail(height, idx) || p1db.is_spent(&rustmmrdb::Outpoint::new(height, idx)) {
            OutputState::Spent
        } else {
            OutputState::Missing
        }
    }

    /// `true` when a not-yet-saved block already spent `(height, idx)`.
    pub fn spent_in_tail(&self, height: u32, idx: u16) -> bool {
        match self {
            Self::Durable(_) => false,
            Self::Tail { spends, .. } => spends.consumed().contains(&(height, idx)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::FlatInput;

    fn body(inputs: &[(u32, u16)], outputs: usize) -> ShardBlockBody {
        let mut b = ShardBlockBody::default();
        b.inputs = inputs.iter().map(|&(h, i)| FlatInput { prev_height: h, prev_output_idx: i }).collect();
        b.outputs = (0..outputs).map(|v| FlatOutput { value: v as u64 + 1, recipient: [7; 32] }).collect();
        b
    }

    #[test]
    fn tail_outputs_resolve_and_tail_spends_mask_durable_outputs() {
        let mut c = TailUtxoCache::new();
        c.reset_at(Some(5));
        c.apply(&body(&[(3, 0)], 2), 6); // spends durable (3,0), creates (6,0),(6,1)
        c.apply(&body(&[(6, 1)], 1), 7); // spends tail (6,1)
        let mut resolved = HashMap::new();
        resolved.insert((2, 0), (Some(FlatOutput { value: 9, recipient: [1; 32] }), false));
        let v = c.view(&resolved, Some(5));
        assert_eq!(v.output(6, 0).map(|o| o.value), Some(1));
        assert!(v.output(6, 1).is_none(), "spent by 7");
        assert!(v.output(3, 0).is_none(), "spent by 6");
        assert_eq!(v.output(2, 0).map(|o| o.value), Some(9), "durable, untouched");
        assert!(v.output(8, 0).is_none(), "above the tail");
    }

    #[test]
    fn purge_keeps_spends_of_newer_blocks() {
        let mut c = TailUtxoCache::new();
        c.reset_at(Some(5));
        c.apply(&body(&[], 2), 6);
        c.apply(&body(&[(6, 1)], 1), 7);
        c.purge_durable(6); // 6 saved, 7 not
        let resolved = HashMap::new();
        let v = c.view(&resolved, Some(6));
        // (6,1) is unspent in P1DB, but block 7 spent it.
        assert!(v.output(6, 1).is_none());
        c.purge_durable(7);
        assert!(c.is_empty());
        assert_eq!(c.tip(), Some(7));
    }

    #[test]
    fn view_ignores_overlay_at_or_below_the_durable_height() {
        // An overlay entry at a durable height is stale by definition: P1DB
        // is authoritative there.
        let mut overlay = ForkUtxoOverlay::new();
        overlay.add(4, 0, FlatOutput { value: 5, recipient: [2; 32] });
        let consumed = HashSet::new();
        let resolved = HashMap::new(); // P1DB: (4,0) absent/spent
        let v = tail_view(&resolved, &overlay, &consumed, Some(5));
        assert!(v.output(4, 0).is_none());
    }

    #[test]
    fn spends_apply_drops_reverted_heights_and_purge_is_per_height() {
        let mut s = TailSpends::new();
        s.apply(&body(&[(1, 0)], 0), 6);
        s.apply(&body(&[(2, 0)], 0), 7);
        // Block 7 reverted and a different block 7 applied.
        s.apply(&body(&[(3, 0)], 0), 7);
        assert!(s.consumed().contains(&(1, 0)));
        assert!(!s.consumed().contains(&(2, 0)));
        assert!(s.consumed().contains(&(3, 0)));
        s.purge_height(6);
        assert!(!s.consumed().contains(&(1, 0)));
        s.drop_from(7);
        assert!(s.is_empty());
    }
}
