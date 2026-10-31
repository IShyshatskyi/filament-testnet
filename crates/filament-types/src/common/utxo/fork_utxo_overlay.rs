use std::collections::HashMap;
use crate::transaction::{TxOutput, Transaction, FlatOutput};
use log::debug;

/// A transient staging overlay for **not-yet-durably-committed** outputs —
/// the UTXO set of a fork, or of the blocks applied but not yet in P1DB
/// (the unsaved tail — PO-4),
/// never the UTXO set of the main chain.
///
/// This is **not** a cache, windowed or otherwise, of "the UTXO set." The
/// only durable, standing UTXO set in this codebase is `PositionalUtxoDb`
/// (rustmmrdb), which already provides its own fast recent-block access (the
/// slot store's hot window, mmap page cache) — nothing here should ever try
/// to reproduce that.
///
/// The overlay exists to answer exactly one question: while a sequence of
/// blocks is being resolved before any of them are durable anywhere — either
/// a reorg's candidate fork blocks, or the blocks between "applied in-memory"
/// and "P1DB commit landed" (several at once under B11 batch persist and
/// NC-44 deferred persist) — can block K+1 see an output block K
/// just created, without mutating real storage to check? Entries are keyed
/// positionally like `rustmmrdb::Outpoint`, populated on apply, restored on
/// revert (paired with `BlockInputWitness`/`BeaconBlockInputWitness`), and
/// **must be purged via [`Self::purge_height`] the instant the corresponding
/// P1DB commit is confirmed** — never on a chain-length or window-size
/// trigger. In steady state, with no reorg or persist in flight, this
/// structure is empty. See CLAUDE.md's standing rule against reintroducing a
/// general-purpose in-memory UTXO set under any name before changing this
/// invariant.
///
/// Also tracks `coinbase_output_counts` for TX-8 maturity when validation
/// reads from this overlay (tests / builds without P1DB wired — the one case
/// where it legitimately holds full history, since it is then the sole
/// source of truth).
#[derive(Clone, Debug)]
pub struct ForkUtxoOverlay {
    utxos: HashMap<(u32, u16), FlatOutput>,
    /// Maps block height → number of coinbase outputs created at that height.
    /// Only populated for heights where the coinbase transaction has been applied.
    coinbase_output_counts: HashMap<u32, u16>,
}

impl Default for ForkUtxoOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkUtxoOverlay {
    pub fn new() -> Self {
        debug!("Creating new fork UTXO overlay");
        ForkUtxoOverlay { utxos: HashMap::new(), coinbase_output_counts: HashMap::new() }
    }

    /// Returns true if the output at `(block_height, output_idx)` was created by
    /// the coinbase transaction of `block_height`.
    ///
    /// Coinbase outputs always occupy the lowest global indices in a block
    /// (indices 0..coinbase_output_count).  Returns `false` for blocks not in
    /// the in-memory buffer (safe: maturity is guaranteed after 100 blocks).
    pub fn is_coinbase_output(&self, block_height: u32, output_idx: u16) -> bool {
        self.coinbase_output_counts
            .get(&block_height)
            .map(|&count| output_idx < count)
            .unwrap_or(false)
    }

    /// Insert a flat output.
    pub fn add(&mut self, block_height: u32, output_idx: u16, output: FlatOutput) {
        debug!("Adding UTXO: {}:{}  (value: {})", block_height, output_idx, output.value);
        self.utxos.insert((block_height, output_idx), output);
    }

    /// Insert a `TxOutput` (FV-3: `TxOutput` and `FlatOutput` have the same layout).
    pub fn add_tx_output(&mut self, block_height: u32, output_idx: u16, output: &TxOutput) {
        self.add(block_height, output_idx, FlatOutput { value: output.value, recipient: output.recipient });
    }

    pub fn remove(&mut self, block_height: u32, output_idx: u16) -> Option<FlatOutput> {
        debug!("Removing UTXO: {}:{}", block_height, output_idx);
        self.utxos.remove(&(block_height, output_idx))
    }

    pub fn contains(&self, block_height: u32, output_idx: u16) -> bool {
        self.utxos.contains_key(&(block_height, output_idx))
    }

    /// Drop all remaining state for `block_height` — both any still-unspent
    /// outputs and the coinbase-count marker.
    ///
    /// Callers must only invoke this once `block_height`'s P1DB commit is
    /// **confirmed durable** — never on a chain-length, reorg-window, or
    /// other size-based trigger. This overlay exists solely to bridge the
    /// gap before a block is durable anywhere; once P1DB has it, nothing
    /// here is needed for that height. See the module-level doc comment for
    /// the full rationale.
    pub fn purge_height(&mut self, block_height: u32) {
        self.utxos.retain(|&(h, _), _| h != block_height);
        self.coinbase_output_counts.remove(&block_height);
    }

    /// [`Self::purge_height`] for every height `<= max_height` — the P1DB
    /// commit cursor has reached `max_height`, so all of them are durable.
    pub fn purge_through(&mut self, max_height: u32) {
        self.utxos.retain(|&(h, _), _| h > max_height);
        self.coinbase_output_counts.retain(|&h, _| h > max_height);
    }

    pub fn get(&self, block_height: u32, output_idx: u16) -> Option<&FlatOutput> {
        self.utxos.get(&(block_height, output_idx))
    }

    // -------------------------------------------------------------------------
    // Single-transaction apply/revert (for reorg paths)
    // -------------------------------------------------------------------------

    /// Apply a single transaction.
    ///
    /// `block_height` — the block this transaction is included in.
    /// `first_output_idx` — the global output index (across all transactions in
    /// the block) at which this transaction's outputs start.
    pub fn apply_transaction(
        &mut self,
        tx: &Transaction,
        block_height: u32,
        first_output_idx: u16,
    ) {
        debug!(
            "Applying transaction ({} inputs, {} outputs) at height {} offset {}",
            tx.inputs.len(), tx.outputs.len(), block_height, first_output_idx
        );
        if tx.is_coinbase() {
            self.coinbase_output_counts.insert(block_height, tx.outputs.len() as u16);
        }
        for input in &tx.inputs {
            self.remove(input.prev_height, input.prev_output_idx);
        }
        for (i, output) in tx.outputs.iter().enumerate() {
            self.add_tx_output(block_height, first_output_idx + i as u16, output);
        }
        debug!("Transaction applied. UTXO set now has {} entries", self.utxos.len());
    }

    /// Revert a single transaction (undo `apply_transaction`).
    ///
    /// `previous_outputs` — the outputs that were consumed by `tx.inputs`,
    /// in the same order as `tx.inputs`.  `None` for an input whose output
    /// need not be restored (e.g. already absent from the buffer).
    pub fn revert_transaction(
        &mut self,
        tx: &Transaction,
        block_height: u32,
        first_output_idx: u16,
        previous_outputs: Vec<Option<FlatOutput>>,
    ) {
        debug!(
            "Reverting transaction ({} inputs, {} outputs)",
            tx.inputs.len(), tx.outputs.len()
        );
        if tx.is_coinbase() {
            self.coinbase_output_counts.remove(&block_height);
        }
        // Remove outputs created by this transaction
        for i in 0..tx.outputs.len() {
            self.remove(block_height, first_output_idx + i as u16);
        }
        // Restore spent outputs
        for (input_idx, input) in tx.inputs.iter().enumerate() {
            if let Some(Some(flat)) = previous_outputs.get(input_idx) {
                self.add(input.prev_height, input.prev_output_idx, *flat);
            }
        }
        debug!("Transaction reverted. UTXO set now has {} entries", self.utxos.len());
    }

    // -------------------------------------------------------------------------
    // Block-level batch apply/revert (fast paths)
    // -------------------------------------------------------------------------

    /// Apply all transactions in a block atomically.
    ///
    /// Assigns global output indices starting from 0, incrementing across all
    /// transactions in order.
    pub fn apply_transactions_batch(&mut self, transactions: &[Transaction], block_height: u32) {
        if transactions.is_empty() {
            return;
        }
        debug!("Applying {} transactions in batch at height {}", transactions.len(), block_height);

        let mut global_out: u16 = 0;
        let mut to_remove: Vec<(u32, u16)> = Vec::new();
        let mut to_add: Vec<(u32, u16, FlatOutput)> = Vec::new();

        for (tx_idx, tx) in transactions.iter().enumerate() {
            if tx_idx == 0 && tx.is_coinbase() {
                self.coinbase_output_counts.insert(block_height, tx.outputs.len() as u16);
            }
            for input in &tx.inputs {
                to_remove.push((input.prev_height, input.prev_output_idx));
            }
            for output in &tx.outputs {
                to_add.push((block_height, global_out, FlatOutput { value: output.value, recipient: output.recipient }));
                global_out += 1;
            }
        }

        for (h, idx) in to_remove {
            self.utxos.remove(&(h, idx));
        }
        for (h, idx, flat) in to_add {
            self.utxos.insert((h, idx), flat);
        }

        debug!("Batch apply complete. UTXO set now has {} entries", self.utxos.len());
    }

    /// Revert all transactions in a block atomically.
    pub fn revert_transactions_batch(
        &mut self,
        transactions: &[Transaction],
        block_height: u32,
        previous_outputs: &[Vec<Option<FlatOutput>>],
    ) {
        if transactions.is_empty() {
            return;
        }
        debug!("Reverting {} transactions in batch", transactions.len());
        assert_eq!(transactions.len(), previous_outputs.len(),
            "Mismatch between transactions and previous outputs");
        // Remove coinbase count for this block height.
        self.coinbase_output_counts.remove(&block_height);

        // Compute per-tx first_output_idx
        let mut offsets: Vec<u16> = Vec::with_capacity(transactions.len());
        let mut running: u16 = 0;
        for tx in transactions.iter() {
            offsets.push(running);
            running += tx.outputs.len() as u16;
        }

        let mut to_remove: Vec<(u32, u16)> = Vec::new();
        let mut to_restore: Vec<(u32, u16, FlatOutput)> = Vec::new();

        for (idx, (tx, prev_outs)) in transactions.iter().zip(previous_outputs.iter()).enumerate() {
            let first = offsets[idx];
            for i in 0..tx.outputs.len() {
                to_remove.push((block_height, first + i as u16));
            }
            for (input_idx, input) in tx.inputs.iter().enumerate() {
                if let Some(Some(flat)) = prev_outs.get(input_idx) {
                    to_restore.push((input.prev_height, input.prev_output_idx, *flat));
                }
            }
        }

        for (h, idx) in to_remove {
            self.utxos.remove(&(h, idx));
        }
        for (h, idx, flat) in to_restore {
            self.utxos.insert((h, idx), flat);
        }

        debug!("Batch revert complete. UTXO set now has {} entries", self.utxos.len());
    }

    // -------------------------------------------------------------------------
    // Batch lookup helpers
    // -------------------------------------------------------------------------

    pub fn contains_batch(&self, outpoints: &[(u32, u16)]) -> Vec<bool> {
        outpoints.iter().map(|k| self.utxos.contains_key(k)).collect()
    }

    pub fn validate_all_exist(&self, outpoints: &[(u32, u16)]) -> Result<(), String> {
        for k in outpoints {
            if !self.utxos.contains_key(k) {
                return Err(format!("UTXO not found: {}:{}", k.0, k.1));
            }
        }
        Ok(())
    }

    pub fn get_batch(&self, outpoints: &[(u32, u16)]) -> Vec<Option<FlatOutput>> {
        outpoints.iter().map(|k| self.utxos.get(k).cloned()).collect()
    }

    pub fn get_all_or_fail(&self, outpoints: &[(u32, u16)]) -> Result<Vec<FlatOutput>, String> {
        outpoints.iter()
            .map(|k| self.utxos.get(k).cloned()
                .ok_or_else(|| format!("UTXO not found: {}:{}", k.0, k.1)))
            .collect()
    }

    pub fn calculate_batch_input_values(
        &self,
        transactions: &[Transaction],
    ) -> Result<Vec<u64>, String> {
        transactions.iter().map(|tx| {
            let mut total = 0u64;
            for input in &tx.inputs {
                let utxo = self.utxos
                    .get(&(input.prev_height, input.prev_output_idx))
                    .ok_or_else(|| format!("UTXO not found: {}:{}", input.prev_height, input.prev_output_idx))?;
                total = total.checked_add(utxo.value)
                    .ok_or_else(|| "Input value overflow".to_string())?;
            }
            Ok(total)
        }).collect()
    }

    /// Apply a `ShardBlockBody` flat representation (FV-11).
    ///
    /// Faster than `apply_transactions_batch` for the shard chain hot path:
    /// `FlatOutput` is already stored directly without `script_pubkey_to_recipient`
    /// conversion, and the flat vectors are pre-allocated.
    pub fn apply_flat_body(
        &mut self,
        body: &crate::common::blocks::ShardBlockBody,
        block_height: u32,
    ) {
        // Coinbase detection: first range has `in_len == 0`.
        if let Some(first) = body.descriptors.first() {
            if first.in_len == 0 {
                self.coinbase_output_counts.insert(block_height, first.out_len as u16);
            }
        }
        // Remove spent outputs.
        for inp in &body.inputs {
            self.utxos.remove(&(inp.prev_height, inp.prev_output_idx));
        }
        // Add created outputs.
        for (i, out) in body.outputs.iter().enumerate() {
            self.utxos.insert((block_height, i as u16), *out);
        }
        debug!("apply_flat_body at height {}. UTXO set now has {} entries", block_height, self.utxos.len());
    }

    /// Revert a `ShardBlockBody` previously applied via `apply_flat_body`.
    ///
    /// `flat_witness` is a `Vec<Option<FlatOutput>>` indexed by global input
    /// position — `flat_witness[i]` is the UTXO that `body.inputs[i]` spent.
    pub fn revert_flat_body(
        &mut self,
        body: &crate::common::blocks::ShardBlockBody,
        block_height: u32,
        flat_witness: &[Option<FlatOutput>],
    ) {
        // Remove created outputs.
        for i in 0..body.outputs.len() {
            self.utxos.remove(&(block_height, i as u16));
        }
        // Restore spent outputs from witness.
        for (i, inp) in body.inputs.iter().enumerate() {
            if let Some(Some(flat)) = flat_witness.get(i) {
                self.utxos.insert((inp.prev_height, inp.prev_output_idx), *flat);
            }
        }
        // Remove coinbase count for this height.
        self.coinbase_output_counts.remove(&block_height);
        debug!("revert_flat_body at height {}. UTXO set now has {} entries", block_height, self.utxos.len());
    }

    pub fn len(&self) -> usize { self.utxos.len() }
    pub fn is_empty(&self) -> bool { self.utxos.is_empty() }
    pub fn total_value(&self) -> u64 { self.utxos.values().map(|o| o.value).sum() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TxInput, TxOutput};

    fn create_flat_output(value: u64) -> FlatOutput {
        FlatOutput { value, recipient: [0u8; 32] }
    }

    fn create_test_output(value: u64) -> TxOutput {
        TxOutput { value, recipient: [0u8; 32] }
    }

    // Build a tx that spends the listed (height, idx) outpoints and creates `outputs` values.
    // `first_output_idx` indicates where in the block this tx's outputs start — used only by
    // the ForkUtxoOverlay, not stored in the Transaction.
    fn create_test_transaction(
        inputs: Vec<(u32, u16)>,
        outputs: Vec<u64>,
    ) -> Transaction {
        let mut tx = Transaction::new(1, 0);
        for (prev_height, prev_output_idx) in inputs {
            tx.add_input(TxInput { prev_height, prev_output_idx });
        }
        for value in outputs {
            tx.add_output(create_test_output(value));
        }
        tx
    }

    #[test]
    fn test_utxo_add_remove() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        fork_utxo_overlay.add(10, 0, create_flat_output(1000));
        assert!(fork_utxo_overlay.contains(10, 0));
        assert_eq!(fork_utxo_overlay.len(), 1);
        let removed = fork_utxo_overlay.remove(10, 0);
        assert!(removed.is_some());
        assert!(!fork_utxo_overlay.contains(10, 0));
        assert_eq!(fork_utxo_overlay.len(), 0);
    }

    #[test]
    fn test_apply_transaction() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        fork_utxo_overlay.add(5, 0, create_flat_output(1000));

        let tx = create_test_transaction(vec![(5, 0)], vec![600, 400]);
        fork_utxo_overlay.apply_transaction(&tx, 10, 0);

        assert!(!fork_utxo_overlay.contains(5, 0));
        assert!(fork_utxo_overlay.contains(10, 0));
        assert!(fork_utxo_overlay.contains(10, 1));
        assert_eq!(fork_utxo_overlay.len(), 2);
    }

    #[test]
    fn test_revert_transaction() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        let prev_flat = create_flat_output(1000);
        fork_utxo_overlay.add(5, 0, prev_flat);

        let tx = create_test_transaction(vec![(5, 0)], vec![600, 400]);
        fork_utxo_overlay.apply_transaction(&tx, 10, 0);
        fork_utxo_overlay.revert_transaction(&tx, 10, 0, vec![Some(prev_flat)]);

        assert!(!fork_utxo_overlay.contains(10, 0));
        assert!(!fork_utxo_overlay.contains(10, 1));
        assert!(fork_utxo_overlay.contains(5, 0));
        assert_eq!(fork_utxo_overlay.len(), 1);
    }

    #[test]
    fn test_apply_transactions_batch() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        for i in 0u16..10 {
            fork_utxo_overlay.add(1, i, create_flat_output(1000));
        }

        let transactions: Vec<Transaction> = (0u16..10)
            .map(|i| create_test_transaction(vec![(1, i)], vec![600, 400]))
            .collect();

        fork_utxo_overlay.apply_transactions_batch(&transactions, 2);

        for i in 0u16..10 {
            assert!(!fork_utxo_overlay.contains(1, i), "Old UTXO should be spent");
        }
        for i in 0u16..20 {
            assert!(fork_utxo_overlay.contains(2, i), "New UTXO {} should exist", i);
        }
        assert_eq!(fork_utxo_overlay.len(), 20);
    }

    #[test]
    fn test_apply_transactions_batch_empty() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        fork_utxo_overlay.apply_transactions_batch(&[], 1);
        assert_eq!(fork_utxo_overlay.len(), 0);
    }

    #[test]
    fn test_revert_transactions_batch() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        let mut prev_outputs_for_revert = Vec::new();
        for i in 0u16..10 {
            let flat = create_flat_output(1000);
            fork_utxo_overlay.add(1, i, flat);
            prev_outputs_for_revert.push(vec![Some(flat)]);
        }

        let transactions: Vec<Transaction> = (0u16..10)
            .map(|i| create_test_transaction(vec![(1, i)], vec![600, 400]))
            .collect();

        fork_utxo_overlay.apply_transactions_batch(&transactions, 2);
        fork_utxo_overlay.revert_transactions_batch(&transactions, 2, &prev_outputs_for_revert);

        for i in 0u16..10 {
            assert!(fork_utxo_overlay.contains(1, i), "Old UTXO should be restored");
        }
        for i in 0u16..20 {
            assert!(!fork_utxo_overlay.contains(2, i), "New UTXO {} should be gone", i);
        }
        assert_eq!(fork_utxo_overlay.len(), 10);
    }

    #[test]
    fn test_revert_transactions_batch_empty() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        fork_utxo_overlay.revert_transactions_batch(&[], 1, &[]);
        assert_eq!(fork_utxo_overlay.len(), 0);
    }

    #[test]
    #[should_panic(expected = "Mismatch between transactions and previous outputs")]
    fn test_revert_transactions_batch_mismatch() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        let transactions = vec![create_test_transaction(vec![], vec![1000])];
        fork_utxo_overlay.revert_transactions_batch(&transactions, 1, &[]);
    }

    #[test]
    fn test_contains_batch() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        for i in 0u16..5 {
            fork_utxo_overlay.add(1, i, create_flat_output(1000));
        }
        let outpoints = vec![(1u32, 0u16), (1, 1), (1, 2), (1, 9), (1, 3)];
        let results = fork_utxo_overlay.contains_batch(&outpoints);
        assert_eq!(results, vec![true, true, true, false, true]);
    }

    #[test]
    fn test_total_value() {
        let mut fork_utxo_overlay = ForkUtxoOverlay::new();
        fork_utxo_overlay.add(1, 0, create_flat_output(1000));
        fork_utxo_overlay.add(1, 1, create_flat_output(2000));
        fork_utxo_overlay.add(2, 0, create_flat_output(3000));
        assert_eq!(fork_utxo_overlay.total_value(), 6000);
    }

    #[test]
    fn fv11_apply_flat_body_basic() {
        use crate::common::blocks::ShardBlockBody;
        use crate::transaction::FlatInput;
        let mut utxo = ForkUtxoOverlay::new();
        // Pre-load a UTXO to be spent.
        utxo.add(0, 0, FlatOutput { value: 500, recipient: [1u8; 32] });

        let body = ShardBlockBody {
            outputs: vec![
                FlatOutput { value: 300, recipient: [2u8; 32] },
                FlatOutput { value: 200, recipient: [3u8; 32] },
            ],
            inputs: vec![FlatInput { prev_height: 0, prev_output_idx: 0 }],
            witnesses: vec![],
            extensions: vec![],
            descriptors: vec![],
        };
        utxo.apply_flat_body(&body, 1);

        // Spent input removed.
        assert!(!utxo.contains(0, 0));
        // New outputs present with correct values.
        assert_eq!(utxo.get(1, 0).unwrap().value, 300);
        assert_eq!(utxo.get(1, 1).unwrap().value, 200);
        assert_eq!(utxo.len(), 2);
    }

    /// NC-50: `purge_height` drops only the targeted height's remaining
    /// unspent outputs and coinbase marker, leaving other heights intact.
    #[test]
    fn nc50_purge_height_drops_only_target_height() {
        let mut utxo = ForkUtxoOverlay::new();
        let coinbase = create_test_transaction(vec![], vec![100, 200]);
        utxo.apply_transaction(&coinbase, 5, 0);
        utxo.add(6, 0, create_flat_output(300));

        assert!(utxo.is_coinbase_output(5, 0));

        utxo.purge_height(5);

        assert!(!utxo.contains(5, 0));
        assert!(!utxo.contains(5, 1));
        assert!(utxo.contains(6, 0), "unrelated height must survive purge");
        assert!(!utxo.is_coinbase_output(5, 0), "coinbase marker for purged height must be gone");
    }
}
