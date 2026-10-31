use std::collections::{BTreeMap, HashMap, VecDeque};
use crate::transaction::{Transaction, Txid};
use log::{debug, info};

/// Represents a transaction entry in the pool
/// Associates transaction with fee rate and timestamp
#[derive(Clone, Debug)]
pub struct TransactionEntry {
    /// The actual transaction
    pub tx: Transaction,

    /// Fee rate in satoshis per byte
    /// Used for prioritization when composing blocks
    pub fee_rate: f64,

    /// Timestamp when transaction was added to pool
    pub timestamp: u64,

    /// Bytes this transaction adds to a block on the wire (witnesses, descriptor and
    /// extensions included). Block size limits and the pool's byte limit count these, not
    /// `Transaction::size()`.
    pub wire_size: usize,
}

impl TransactionEntry {
    /// Create a new transaction pool entry
    pub fn new(tx: Transaction, fee_rate: f64, timestamp: u64) -> Self {
        let wire_size = crate::common::blocks::ShardBlockBody::tx_wire_size(&tx);
        TransactionEntry {
            tx,
            fee_rate,
            timestamp,
            wire_size,
        }
    }
}

/// See [`TxPool::position_of`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoolPosition {
    pub fee_rate: f64,
    pub wire_size: usize,
    pub added_unix: u64,
    /// Pooled transactions paying a strictly higher fee rate.
    pub better_count: usize,
    /// Wire bytes of those transactions.
    pub better_bytes: usize,
}

/// Fee rate (atoms per byte, `f64`) in the P2P announcement unit: atoms per 1000 bytes.
pub fn fee_rate_milli(fee_rate: f64) -> u32 {
    (fee_rate * 1000.0).clamp(0.0, u32::MAX as f64) as u32
}

/// Transaction pool (mempool) for pending transactions
/// 
/// Maintains unconfirmed transactions waiting to be included in blocks.
/// Supports:
/// - Adding/removing transactions
/// - Fee-based prioritization
/// - Configurable size limits
/// - Fast lookup by txid
#[derive(Clone, Debug)]
pub struct TxPool {
    /// Queue of transactions (order doesn't matter for storage)
    pool: VecDeque<TransactionEntry>,

    /// Index: txid -> position in pool for O(1) lookup
    txid_set: HashMap<Txid, usize>,

    /// CV-13 / TE-5: expiry index — maps `expiration_height` to txids that expire
    /// at that height. Used by `evict_expired(height)` to find and remove stale
    /// transactions in O(expired) time rather than scanning the whole pool.
    expiry_index: BTreeMap<u32, Vec<Txid>>,

    /// Transactions evicted to make room for a higher-paying one (since this pool was created).
    evicted_for_fee: u64,

    /// NC-154: spent-output index. Maps `(prev_height, prev_output_idx)` to the pool transaction
    /// that spends it, so the pool can never hold two transactions spending the same output.
    spent_index: HashMap<(u32, u16), Txid>,

    /// Total bytes of all transactions in pool
    total_size: usize,

    /// Maximum number of transactions allowed in pool
    max_tx_count: usize,

    /// Maximum total bytes allowed in pool (before rejecting new transactions)
    max_pool_bytes: usize,

    /// Chain this pool serves (beacon 0, shard N → N+1). Every key is
    /// `Transaction::txid(chain_id)` (VF-3 Phase 1).
    chain_id: u16,
}

impl TxPool {
    /// Create a new empty transaction pool with configured limits
    /// 
    /// Parameters:
    /// - max_tx_count: Maximum number of transactions (from config.max_tx_pool_size)
    /// - max_block_size: Maximum block size in bytes (from config.max_block_size)
    /// 
    /// The pool size limit is set to 2x block size to allow buffering between blocks.
    /// `chain_id` is the chain whose txids key this pool (beacon 0, shard N → N+1).
    pub fn new(chain_id: u16, max_tx_count: usize, max_block_size: usize) -> Self {
        let max_pool_bytes = max_block_size * 2;
        
        debug!(
            "Creating transaction pool: max {} txs, max_block_size {} bytes, pool limit {} bytes",
            max_tx_count, max_block_size, max_pool_bytes
        );
        
        TxPool {
            pool: VecDeque::new(),
            txid_set: HashMap::new(),
            expiry_index: BTreeMap::new(),
            spent_index: HashMap::new(),
            evicted_for_fee: 0,
            total_size: 0,
            max_tx_count,
            max_pool_bytes,
            chain_id,
        }
    }

    /// The chain whose txids key this pool.
    pub fn chain_id(&self) -> u16 {
        self.chain_id
    }

    /// The id this pool keys `tx` by.
    pub fn txid_of(&self, tx: &Transaction) -> Txid {
        tx.txid(self.chain_id)
    }

    /// Add a transaction to the pool
    /// 
    /// Validates:
    /// - Transaction doesn't already exist in pool
    /// - Pool not at max transaction count
    /// - Adding transaction wouldn't exceed size limit
    /// 
    /// Parameters:
    /// - tx: Transaction to add
    /// - fee_rate: Satoshis per byte (for priority)
    /// - timestamp: Unix timestamp when added
    /// - current_tip_height: Current chain tip height for TE-4 already-expired check
    ///   (pass 0 to skip the expiration check, e.g. when replaying during reorg)
    ///
    /// Returns: Ok(()) on success, Err(String) with reason on failure
    pub fn add_transaction(
        &mut self,
        tx: Transaction,
        fee_rate: f64,
        timestamp: u64,
        current_tip_height: u32,
    ) -> Result<(), String> {
        // CV-57: reject NaN/infinite fee rates before they pollute the sort order.
        if !fee_rate.is_finite() {
            return Err(format!("invalid fee_rate: {fee_rate}"));
        }
        // TE-4: reject already-expired transactions at mempool admission.
        // current_tip_height=0 disables this check (used during reorg replay).
        if current_tip_height > 0 && tx.expiration_height > 0
            && tx.expiration_height <= current_tip_height
        {
            return Err(format!(
                "TE-4 transaction already expired: expiration_height {} <= current_height {}",
                tx.expiration_height, current_tip_height
            ));
        }
        let txid = tx.txid(self.chain_id);
        let tx_size = crate::common::blocks::ShardBlockBody::tx_wire_size(&tx);

        debug!(
            "Adding transaction {} to pool (size: {} bytes, fee_rate: {})",
            txid, tx_size, fee_rate
        );

        // Check if transaction already exists
        if self.txid_set.contains_key(&txid) {
            return Err("Transaction already in pool".to_string());
        }

        // NC-154: refuse a transaction that spends an output another pool transaction already
        // spends. (Replace-by-fee is not implemented: the first spend wins.)
        for input in &tx.inputs {
            if let Some(existing) = self.spent_index.get(&(input.prev_height, input.prev_output_idx)) {
                return Err(format!(
                    "conflicts with pool transaction {existing} (both spend output {}:{})",
                    input.prev_height, input.prev_output_idx
                ));
            }
        }

        // Pool limits. When the pool is full, a transaction that pays a higher fee rate than the
        // lowest-paying ones takes their place; otherwise it is refused. Pooled transactions spend
        // confirmed outputs only (admission requires it), so removing one never strands another.
        let over_count = self.pool.len() >= self.max_tx_count;
        let over_bytes = self.total_size + tx_size > self.max_pool_bytes;
        if over_count || over_bytes {
            let full_err = if over_count {
                format!("Transaction pool full ({} transactions)", self.max_tx_count)
            } else {
                format!("Transaction pool size limit exceeded ({} bytes)", self.max_pool_bytes)
            };
            if tx_size > self.max_pool_bytes {
                return Err(full_err);
            }
            // Cheapest first; among equal fee rates the newest goes first (older stays).
            let mut order: Vec<usize> = (0..self.pool.len()).collect();
            order.sort_by(|&x, &y| {
                self.pool[x]
                    .fee_rate
                    .partial_cmp(&self.pool[y].fee_rate)
                    .unwrap_or(std::cmp::Ordering::Less)
                    .then(y.cmp(&x))
            });
            let mut count = self.pool.len();
            let mut bytes = self.total_size;
            let mut victims: Vec<Txid> = Vec::new();
            for idx in order {
                if count < self.max_tx_count && bytes + tx_size <= self.max_pool_bytes {
                    break;
                }
                let e = &self.pool[idx];
                // NaN sorts lowest, so a NaN-fee entry is evicted first; anything else must pay strictly less.
                if e.fee_rate.is_finite() && e.fee_rate >= fee_rate {
                    return Err(full_err);
                }
                victims.push(e.tx.txid(self.chain_id));
                count -= 1;
                bytes -= e.wire_size;
            }
            if count >= self.max_tx_count || bytes + tx_size > self.max_pool_bytes {
                return Err(full_err);
            }
            for v in victims {
                self.remove_transaction(v);
                self.evicted_for_fee += 1;
            }
        }

        // Add to pool
        // ESC-7: a cooperative escrow spend (witness 0x02) can only be mined below its H,
        // so it shares the TE-5 expiry index under `H - 1` (evicted once block H - 1 is
        // applied). The smaller of that and TE-2's expiration height wins.
        let exp_height = match (
            tx.expiration_height,
            crate::common::crypto::coop_last_valid_height(&tx.witnesses),
        ) {
            (0, None) => 0,
            (0, Some(c)) => c.max(1),
            (e, None) => e,
            (e, Some(c)) => e.min(c.max(1)),
        };
        let entry = TransactionEntry::new(tx, fee_rate, timestamp);
        let position = self.pool.len();
        self.pool.push_back(entry);
        self.txid_set.insert(txid, position);
        self.total_size += tx_size;
        for input in &self.pool[position].tx.inputs {
            self.spent_index.insert((input.prev_height, input.prev_output_idx), txid);
        }
        // CV-13 / TE-5: register in expiry index for efficient eviction.
        if exp_height > 0 {
            self.expiry_index.entry(exp_height).or_default().push(txid);
        }

        debug!(
            "Transaction added. Pool size: {} tx, {} bytes",
            self.pool.len(),
            self.total_size
        );

        Ok(())
    }

    /// REVERT-READMIT-1: true when adding `tx_size` bytes needs no eviction
    /// (under both the count and byte limits).
    pub fn has_room_for(&self, tx_size: usize) -> bool {
        self.pool.len() < self.max_tx_count && self.total_size + tx_size <= self.max_pool_bytes
    }

    /// REVERT-READMIT-1: would [`add_transaction`](Self::add_transaction) find room for a
    /// transaction of `tx_size` wire bytes paying `fee_rate`? Mirrors its limit / fee-eviction
    /// predicate exactly (cheapest first, among equal fee rates newest first; a victim with a
    /// finite fee rate `>=` the candidate's refuses) without mutating. Duplicate / conflict /
    /// expiry checks are not part of this answer.
    pub fn would_accept(&self, tx_size: usize, fee_rate: f64) -> bool {
        if !fee_rate.is_finite() || tx_size > self.max_pool_bytes {
            return false;
        }
        if self.has_room_for(tx_size) {
            return true;
        }
        let mut order: Vec<usize> = (0..self.pool.len()).collect();
        order.sort_by(|&x, &y| {
            self.pool[x]
                .fee_rate
                .partial_cmp(&self.pool[y].fee_rate)
                .unwrap_or(std::cmp::Ordering::Less)
                .then(y.cmp(&x))
        });
        let mut count = self.pool.len();
        let mut bytes = self.total_size;
        for idx in order {
            if count < self.max_tx_count && bytes + tx_size <= self.max_pool_bytes {
                break;
            }
            let e = &self.pool[idx];
            if e.fee_rate.is_finite() && e.fee_rate >= fee_rate {
                return false;
            }
            count -= 1;
            bytes -= e.wire_size;
        }
        count < self.max_tx_count && bytes + tx_size <= self.max_pool_bytes
    }

    /// REVERT-READMIT-1 admission precheck, run **before** CV-70 (TX-5 Schnorr).
    ///
    /// When the pool has room this is a no-op (`fee_rate` is not called). When it is full,
    /// `fee_rate` (UTXO-only, no signature work) is asked for the candidate's rate: `None`
    /// falls through (`Ok`, full validation reports the real error); `Some(r)` that
    /// [`would_accept`](Self::would_accept) refuses returns the same full-pool error
    /// `add_transaction` would, so the caller skips the signature verify.
    pub fn admission_precheck(
        &self,
        tx_size: usize,
        fee_rate: impl FnOnce() -> Option<f64>,
    ) -> Result<(), String> {
        if self.has_room_for(tx_size) {
            return Ok(());
        }
        match fee_rate() {
            Some(r) if !self.would_accept(tx_size, r) => Err(if self.pool.len() >= self.max_tx_count {
                format!("Transaction pool full ({} transactions)", self.max_tx_count)
            } else {
                format!("Transaction pool size limit exceeded ({} bytes)", self.max_pool_bytes)
            }),
            _ => Ok(()),
        }
    }

    /// Remove a transaction from the pool
    /// 
    /// Returns the transaction if found, None otherwise.
    /// Rebuilds txid index after removal to maintain correctness.
    pub fn remove_transaction(&mut self, txid: Txid) -> Option<Transaction> {
        debug!("Removing transaction {} from pool", txid);

        if let Some(pos) = self.txid_set.remove(&txid) {
            if let Some(entry) = self.pool.remove(pos) {
                self.total_size -= entry.wire_size;
                for input in &entry.tx.inputs {
                    self.spent_index.remove(&(input.prev_height, input.prev_output_idx));
                }

                // Fix up indices shifted by the removal — O(n), no txid() recomputation.
                // Entries at positions > pos had their VecDeque index decremented by 1.
                for idx in self.txid_set.values_mut() {
                    if *idx > pos {
                        *idx -= 1;
                    }
                }

                debug!(
                    "Transaction removed. Pool size: {} tx, {} bytes",
                    self.pool.len(),
                    self.total_size
                );

                return Some(entry.tx);
            }
        }

        debug!("Transaction not found in pool");
        None
    }

    /// Keep only transactions for which `keep` returns `true`; returns how many
    /// were removed. One pass over the pool plus one index rebuild — use this,
    /// not repeated `remove_transaction` (O(n) index fix-up per call), when
    /// pruning many entries at once.
    ///
    /// VF-3 Phase 0: Keystone's periodic sweep uses it to drop transactions
    /// whose inputs a mined block already spent (`ShardMempoolRegistry::
    /// prune_spent`). `expiry_index` may keep ids of removed entries; that is
    /// already tolerated — `evict_expired` skips ids no longer in the pool.
    pub fn retain(&mut self, mut keep: impl FnMut(&Transaction) -> bool) -> usize {
        let before = self.pool.len();
        self.pool.retain(|e| keep(&e.tx));
        let removed = before - self.pool.len();
        if removed > 0 {
            self.txid_set = self
                .pool
                .iter()
                .enumerate()
                .map(|(i, e)| (e.tx.txid(self.chain_id), i))
                .collect();
            self.total_size = self.pool.iter().map(|e| e.wire_size).sum();
            self.spent_index = self
                .pool
                .iter()
                .flat_map(|e| {
                    let id = e.tx.txid(self.chain_id);
                    e.tx.inputs.iter().map(move |i| ((i.prev_height, i.prev_output_idx), id))
                })
                .collect();
        }
        removed
    }

    /// Retrieve a transaction from pool without removing it
    /// 
    /// Returns reference to transaction if it exists
    pub fn get_transaction(&self, txid: Txid) -> Option<&Transaction> {
        if let Some(pos) = self.txid_set.get(&txid) {
            return self.pool.get(*pos).map(|entry| &entry.tx);
        }
        None
    }

    /// Compact-block lookup: find serialized tx bytes by short id + salt (TS-T-12b).
    /// Bytes are `serialize_with_witnesses` (the wire format, VF-3); the short id
    /// is derived from this pool's own txid.
    pub fn serialized_by_short_id(&self, short_id: u64, salt: &[u8; 8]) -> Option<Vec<u8>> {
        use crate::common::compact_block::compute_short_id;
        for entry in &self.pool {
            let txid = entry.tx.txid(self.chain_id).0;
            if compute_short_id(&txid, salt) == short_id {
                return Some(entry.tx.serialize_with_witnesses());
            }
        }
        None
    }

    /// Get high-fee transactions for block composition
    /// 
    /// Selects transactions with highest fee rates until reaching
    /// the specified size limit. Returns transactions sorted by
    /// descending fee rate.
    /// 
    /// Used by ShardChain.compose_block() to build blocks.
    /// 
    /// Parameters:
    /// - max_block_size: Maximum **wire** bytes the selected transactions may add to a block
    ///   (witnesses included). Callers pass the configured block limit minus the block overhead
    ///   (header, merged-mining proof, coinbase): see `SHARD_BLOCK_WIRE_RESERVE`.
    /// 
    /// Returns: Vec of transactions sorted by fee rate (highest first)
    pub fn get_high_fee_transactions(&self, max_block_size: usize) -> Vec<Transaction> {
        self.get_high_fee_transactions_capped(max_block_size, usize::MAX)
    }

    /// Like [`get_high_fee_transactions`](Self::get_high_fee_transactions), and
    /// also stops once the selected transactions hold `max_outputs` outputs.
    /// Callers pass the chain's per-block output limit minus the coinbase's
    /// outputs (CLAUDE.md item 17: a block over the storage cap halts the chain).
    pub fn get_high_fee_transactions_capped(
        &self,
        max_block_size: usize,
        max_outputs: usize,
    ) -> Vec<Transaction> {
        debug!(
            "Selecting high-fee transactions (pool: {} tx, limit: {} bytes)",
            self.pool.len(),
            max_block_size
        );

        // Sort all entries by fee rate (highest first)
        let mut sorted_entries: Vec<_> = self.pool.iter().collect();
        sorted_entries.sort_by(|a, b| {
            // Sort descending by fee rate
            // CV-57: treat NaN as lowest priority (Less) so they sort to the end
        // rather than being placed arbitrarily by unwrap_or(Equal).
        b.fee_rate
                .partial_cmp(&a.fee_rate)
                .unwrap_or(std::cmp::Ordering::Less)
        });

        // Select transactions until size limit reached
        let mut transactions = Vec::new();
        let mut total_size = 0;
        let mut total_outputs = 0usize;
        // NC-154: the pool is conflict-free by construction; this guard keeps a template valid even
        // if a conflicting pair ever got in (for example a pool loaded by older code).
        let mut used_inputs: std::collections::HashSet<(u32, u16)> = std::collections::HashSet::new();

        for entry in sorted_entries {
            let tx_size = entry.wire_size;
            let tx_outputs = entry.tx.outputs.len();
            if entry.tx.inputs.iter().any(|i| used_inputs.contains(&(i.prev_height, i.prev_output_idx))) {
                continue;
            }

            if total_size + tx_size <= max_block_size && total_outputs + tx_outputs <= max_outputs {
                for i in &entry.tx.inputs {
                    used_inputs.insert((i.prev_height, i.prev_output_idx));
                }
                transactions.push(entry.tx.clone());
                total_size += tx_size;
                total_outputs += tx_outputs;
            } else {
                // Would exceed limit, skip this and remaining
                break;
            }
        }

        debug!(
            "Selected {} transactions ({} bytes total) for block",
            transactions.len(),
            total_size
        );

        transactions
    }

    // ── P2P mempool sync (Phase 8 Track B): read-only views for the chain provider ──

    /// Pool entries by descending fee rate (NaN last), at most `max`, as
    /// `(txid, fee_rate, wire_size)`. Used to answer a peer's `GetMempoolFilter` with a `TxBatch`.
    pub fn top_entries(&self, max: usize) -> Vec<([u8; 32], f64, usize)> {
        let mut sorted: Vec<&TransactionEntry> = self.pool.iter().collect();
        sorted.sort_by(|a, b| b.fee_rate.partial_cmp(&a.fee_rate).unwrap_or(std::cmp::Ordering::Less));
        sorted
            .into_iter()
            .take(max)
            .map(|e| (e.tx.txid(self.chain_id).0, e.fee_rate, e.wire_size))
            .collect()
    }

    /// Fee rates (atoms per byte) at the given percentiles (0..=100) of the pool, lowest first;
    /// `None` for an empty pool. `p` = 50 is the median; 90 means 90 % of pooled transactions pay
    /// no more than this.
    pub fn fee_rate_percentiles(&self, percentiles: &[u32]) -> Option<Vec<f64>> {
        if self.pool.is_empty() {
            return None;
        }
        let mut rates: Vec<f64> = self.pool.iter().map(|e| e.fee_rate).filter(|r| r.is_finite()).collect();
        if rates.is_empty() {
            return None;
        }
        rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let last = rates.len() - 1;
        Some(percentiles.iter().map(|&p| rates[last * (p.min(100) as usize) / 100]).collect())
    }

    /// Every txid in the pool (for the Bloom filter exchanged on connect).
    pub fn txids(&self) -> Vec<[u8; 32]> {
        self.pool.iter().map(|e| e.tx.txid(self.chain_id).0).collect()
    }

    /// Up to `max_count` transactions (`serialize_with_witnesses`) by descending fee rate, stopping
    /// before `max_bytes` total. Used to answer `GetMissingTxs` with a `TxBatchFull`.
    pub fn top_serialized(&self, max_count: usize, max_bytes: usize) -> Vec<Vec<u8>> {
        let mut sorted: Vec<&TransactionEntry> = self.pool.iter().collect();
        sorted.sort_by(|a, b| b.fee_rate.partial_cmp(&a.fee_rate).unwrap_or(std::cmp::Ordering::Less));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for e in sorted {
            if out.len() >= max_count {
                break;
            }
            let ser = e.tx.serialize_with_witnesses();
            if bytes + ser.len() > max_bytes {
                break;
            }
            bytes += ser.len();
            out.push(ser);
        }
        out
    }

    /// Where a pooled transaction stands, for "is it at risk of being dropped" questions:
    /// its own fee rate, size and admission time, plus how many pooled transactions pay a
    /// **strictly higher** fee rate and how many wire bytes those take. A pool that evicts the
    /// lowest payer first (see `evicted_for_fee`) keeps a transaction only while this count and
    /// byte total fit inside its limits. O(pool size); read-only.
    pub fn position_of(&self, txid: &[u8; 32]) -> Option<PoolPosition> {
        let pos = *self.txid_set.get(&Txid(*txid))?;
        let me = self.pool.get(pos)?;
        let (mut better_count, mut better_bytes) = (0usize, 0usize);
        for e in self.pool.iter() {
            if e.fee_rate > me.fee_rate {
                better_count += 1;
                better_bytes += e.wire_size;
            }
        }
        Some(PoolPosition {
            fee_rate: me.fee_rate,
            wire_size: me.wire_size,
            added_unix: me.timestamp,
            better_count,
            better_bytes,
        })
    }

    /// `(fee_rate, wire_size)` of the pooled transaction with this txid.
    pub fn entry_info(&self, txid: &[u8; 32]) -> Option<(f64, usize)> {
        let pos = *self.txid_set.get(&Txid(*txid))?;
        self.pool.get(pos).map(|e| (e.fee_rate, e.wire_size))
    }

    /// Transactions evicted so far to make room for a higher-paying one.
    pub fn evicted_for_fee(&self) -> u64 {
        self.evicted_for_fee
    }

    /// Get number of transactions in pool
    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Get total bytes of all transactions in pool
    pub fn total_bytes(&self) -> usize {
        self.total_size
    }

    /// Get configured maximum transaction count
    pub fn max_tx_count(&self) -> usize {
        self.max_tx_count
    }

    /// Get configured maximum pool size in bytes
    pub fn max_pool_bytes(&self) -> usize {
        self.max_pool_bytes
    }

    /// NC-154: remove every pool transaction that spends an output `tx` spends (except `tx`
    /// itself). Call it for each transaction a block includes: the pool must not keep a
    /// transaction whose input the chain has just spent, or a template could later include it.
    /// Returns the removed transactions.
    pub fn remove_conflicting(&mut self, tx: &Transaction) -> Vec<Transaction> {
        let own = tx.txid(self.chain_id);
        let mut victims: Vec<Txid> = Vec::new();
        for input in &tx.inputs {
            if let Some(&other) = self.spent_index.get(&(input.prev_height, input.prev_output_idx)) {
                if other != own && !victims.contains(&other) {
                    victims.push(other);
                }
            }
        }
        victims
            .into_iter()
            .filter_map(|id| self.remove_transaction(id))
            .collect()
    }

    /// Clear all transactions from pool
    pub fn clear(&mut self) {
        info!("Clearing transaction pool");
        self.pool.clear();
        self.txid_set.clear();
        self.expiry_index.clear();
        self.spent_index.clear();
        self.total_size = 0;
    }

    /// CV-13 / TE-5: Evict all transactions whose `expiration_height <= block_height`.
    ///
    /// Called by `ShardChain::append_block` after each block is applied, and during
    /// reorg re-entry (`apply_alternative_chain`) after reverting the main chain.
    ///
    /// Returns the list of evicted transactions (may be used for diagnostics or
    /// dropped silently).
    pub fn evict_expired(&mut self, block_height: u32) -> Vec<Transaction> {
        // Collect all txids that expire at or before block_height.
        // BTreeMap::range lets us drain the front of the sorted key space.
        let expired_heights: Vec<u32> = self
            .expiry_index
            .range(..=block_height)
            .map(|(h, _)| *h)
            .collect();

        let mut evicted = Vec::new();
        for h in expired_heights {
            if let Some(txids) = self.expiry_index.remove(&h) {
                for txid in txids {
                    if let Some(tx) = self.remove_transaction(txid) {
                        evicted.push(tx);
                    }
                }
            }
        }

        if !evicted.is_empty() {
            debug!("Evicted {} expired transactions at height {}", evicted.len(), block_height);
        }
        evicted
    }

    /// Look up a transaction by its compact-block short ID.
    ///
    /// `salt` is the 8-byte block-specific nonce derived from the compact block
    /// announcement. The short ID is `BLAKE3(salt || txid)[0..8]` interpreted as
    /// a little-endian u64. Because the salt changes per block, no persistent index
    /// is maintained; instead we scan the pool (O(n), < 1 ms for n ≤ 10 000).
    pub fn find_by_shortid(&self, short_id: u64, salt: &[u8; 8]) -> Option<&Transaction> {
        for entry in &self.pool {
            let txid_bytes: [u8; 32] = entry.tx.txid(self.chain_id).0;
            let computed = compute_compact_short_id(&txid_bytes, salt);
            if computed == short_id {
                return Some(&entry.tx);
            }
        }
        None
    }

    // ── CV-46: mempool snapshot persistence ─────────────────────────────────────

    /// Magic + version header for `mempool_<shard_id>.snapshot` snapshots.
    const WAL_MAGIC: [u8; 4] = *b"MPWL";
    /// v2 (VF-3 Phase 1): entries use `serialize_with_witnesses` (witnesses +
    /// extensions kept) and the pool keys them by the new txid. A v1 WAL is
    /// dropped on load.
    /// v3 (Oct 17, 2026): the serialized transaction carries a one-byte version (it was four bytes).
    /// Older snapshots are dropped on load, like v1.
    const WAL_VERSION: u32 = 3;

    /// Atomically write all pool entries to `path` (`.wal.tmp` then rename).
    pub fn save_wal(&self, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create mempool snapshot parent {:?}: {e}", parent))?;
        }

        let tmp = path.with_extension("wal.tmp");
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| format!("create mempool snapshot {:?}: {e}", tmp))?;

        file.write_all(&Self::WAL_MAGIC)
            .map_err(|e| format!("write mempool snapshot header: {e}"))?;
        file.write_all(&Self::WAL_VERSION.to_le_bytes())
            .map_err(|e| format!("write mempool snapshot version: {e}"))?;
        let count = self.pool.len() as u32;
        file.write_all(&count.to_le_bytes())
            .map_err(|e| format!("write mempool snapshot count: {e}"))?;

        for entry in &self.pool {
            file.write_all(&entry.fee_rate.to_le_bytes())
                .map_err(|e| format!("write mempool snapshot fee_rate: {e}"))?;
            file.write_all(&entry.timestamp.to_le_bytes())
                .map_err(|e| format!("write mempool snapshot timestamp: {e}"))?;
            let tx_bytes = entry.tx.serialize_with_witnesses();
            let tx_len = tx_bytes.len() as u32;
            file.write_all(&tx_len.to_le_bytes())
                .map_err(|e| format!("write mempool snapshot tx_len: {e}"))?;
            file.write_all(&tx_bytes)
                .map_err(|e| format!("write mempool snapshot tx body: {e}"))?;
        }

        file.sync_all()
            .map_err(|e| format!("fsync mempool snapshot {:?}: {e}", tmp))?;
        drop(file);

        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename mempool snapshot {:?} -> {:?}: {e}", tmp, path))?;
        Ok(())
    }

    /// Restore entries from a WAL written by [`save_wal`].
    ///
    /// Skips transactions that fail admission (`add_transaction` errors are
    /// logged and ignored). Returns the number of successfully restored txs.
    pub fn load_wal(
        &mut self,
        path: &std::path::Path,
        current_tip_height: u32,
    ) -> Result<usize, String> {
        use std::io::Read;

        if !path.exists() {
            return Ok(0);
        }

        let mut data = Vec::new();
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut data))
            .map_err(|e| format!("read mempool snapshot {:?}: {e}", path))?;

        if data.len() < 12 {
            return Err(format!("mempool snapshot {:?} truncated ({} bytes)", path, data.len()));
        }
        if data[0..4] != Self::WAL_MAGIC {
            return Err(format!("mempool snapshot {:?} bad magic", path));
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version < Self::WAL_VERSION {
            // Older snapshot: keyed by the retired SHA256d txid and written without witnesses (v1),
            // or with the four-byte transaction version (v2). Drop it rather than misread it.
            info!(
                "Dropping mempool snapshot {:?}: version {version} predates v{} (VF-3)",
                path,
                Self::WAL_VERSION
            );
            return Ok(0);
        }
        if version != Self::WAL_VERSION {
            return Err(format!(
                "mempool snapshot {:?} unsupported version {version} (want {})",
                path,
                Self::WAL_VERSION
            ));
        }
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let mut pos = 12usize;
        let mut restored = 0usize;

        for i in 0..count {
            if pos + 8 + 8 + 4 > data.len() {
                return Err(format!(
                    "mempool snapshot {:?} entry {i} header truncated at offset {pos}",
                    path
                ));
            }
            let fee_rate = f64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let timestamp = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let tx_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + tx_len > data.len() {
                return Err(format!(
                    "mempool snapshot {:?} entry {i} body truncated (need {tx_len} bytes at {pos})",
                    path
                ));
            }
            let tx = Transaction::deserialize_with_witnesses(&data[pos..pos + tx_len])
                .map_err(|e| format!("mempool snapshot {:?} entry {i} decode: {e}", path))?;
            pos += tx_len;

            match self.add_transaction(tx, fee_rate, timestamp, current_tip_height) {
                Ok(()) => restored += 1,
                Err(e) => {
                    debug!("mempool snapshot {:?} entry {i} skipped on restore: {e}", path);
                }
            }
        }

        if restored > 0 {
            info!(
                "Restored {restored}/{count} mempool transaction(s) from {:?}",
                path
            );
        }
        Ok(restored)
    }
}

/// Compute the compact-block short ID for a txid given a per-block salt.
///
/// Formula: BLAKE3(salt || txid)[0..8] as little-endian u64, masked to 48 bits
/// (matching BIP 152 adapted for BLAKE3).
pub fn compute_compact_short_id(txid: &[u8; 32], salt: &[u8; 8]) -> u64 {
    let mut input = [0u8; 40];
    input[..8].copy_from_slice(salt);
    input[8..].copy_from_slice(txid);
    let hash = blake3::hash(&input);
    let raw = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
    raw & 0x0000_FFFF_FFFF_FFFF // 48-bit short ID
}

/*
===============================================================================
TRANSACTION POOL (MEMPOOL) MODULE - UPDATED WITH CONFIGURABLE LIMITS
===============================================================================

PURPOSE
=======
Maintains pending transactions waiting to be included in blocks.
Acts as the "staging area" between transaction submission and block inclusion.

Now uses configuration from ShardNodeConfig instead of hardcoded constants.


DESIGN OVERVIEW
===============

The transaction pool serves two key functions:

1. HOLDING AREA:
   - Transactions arrive from various sources
   - Stored temporarily until included in block
   - Removed when block is confirmed
   - Re-added if block is reverted

2. PRIORITIZATION:
   - Fee rate determines selection order
   - Higher fee = included sooner
   - Miners have incentive to include high-fee transactions
   - Implemented via get_high_fee_transactions()


CONFIGURABLE LIMITS
===================

Transaction Count Limit (from config.shard_node.max_tx_pool_size):
- Prevents unbounded growth
- Default: 10,000 transactions
- Per shard: Each shard has own pool with same limit

Pool Size Limit (calculated from block size):
- 2x block size (from config.shard_node.max_block_size)
- Default: 2 * 61,440 = 122,880 bytes
- Allows buffer between blocks

Block Size Limit (from config.shard_node.max_block_size):
- Used when selecting transactions for block
- Default: 61,440 bytes (60 KB)
- Bitcoin compatibility


POOL CREATION
=============

Create with both explicit limits:
```rust
// In ShardChain::new()
let pool = TxPool::new(
    shard_config.max_tx_pool_size,
    shard_config.max_block_size
);
```

The pool will be created with:
- max_tx_count = config.max_tx_pool_size (e.g., 10,000 transactions)
- max_pool_bytes = 2 * config.max_block_size (e.g., 2 * 61,440 = 122,880 bytes)

This ensures the pool limit is always 2x the block size, providing proper buffering.


DATA STRUCTURES
===============

Primary:
- VecDeque<TransactionEntry>: Stores transactions in insertion order
  Efficient for add/remove operations
  
Secondary Index:
- HashMap<Txid, usize>: Maps txid -> position in deque
  Enables O(1) lookup by transaction ID
  Must be rebuilt when deque changes

Invariant:
- Every transaction in deque has entry in index
- Every index entry points to valid deque position
- Index rebuilt after any removal


OPERATIONS
==========

add_transaction(): O(1)
- Create entry
- Append to deque
- Add to index
- Update size counter

remove_transaction(): O(n)
- Find in index
- Remove from deque
- Rebuild index (necessary because VecDeque removal shifts positions)
- Update size counter

get_transaction(): O(1)
- Look up in index
- Return from deque

get_high_fee_transactions(): O(n log n)
- Sort all transactions by fee rate: O(n log n)
- Select greedily until size limit: O(n)
- Return selected transactions


TRANSACTION ENTRY
=================

Stores:
- tx: The transaction itself
- fee_rate: Satoshis per byte
  Calculated by: total_fee / transaction_size
  Higher fee_rate = higher priority
  
- timestamp: When transaction was added
  Used for diagnostics
  Could be used for time-based eviction


FEE-BASED SELECTION
===================

Block Composition Strategy:
1. Sort all pending transactions by fee rate (highest first)
2. Greedily add transactions until block size limit reached
3. Miners prefer high-fee transactions
4. Incentivizes fee competition

Example:
Pool contains 5 transactions:
- TX1: 1000 bytes, 2.0 sat/byte = 2000 total fee
- TX2: 500 bytes, 1.0 sat/byte = 500 total fee
- TX3: 2000 bytes, 3.0 sat/byte = 6000 total fee
- TX4: 1500 bytes, 0.5 sat/byte = 750 total fee
- TX5: 1000 bytes, 2.5 sat/byte = 2500 total fee

Block composition (max 60KB):
1. Sort by fee_rate:
   TX3 (3.0), TX5 (2.5), TX1 (2.0), TX2 (1.0), TX4 (0.5)

2. Select greedily:
   - Add TX3: 2000 bytes total
   - Add TX5: 3000 bytes total
   - Add TX1: 4000 bytes total
   - Add TX2: 4500 bytes total
   - Try TX4: 6000 bytes - exceeds 60KB, skip
   - Stop (all high-fee ones selected)

Result: TX3, TX5, TX1, TX2 = 4500 bytes


INTEGRATION WITH CHAIN
======================

ShardChain creates and uses TxPool:

Creation (in ShardChain::new()):
```rust
pub fn new(shard_id: u16, shard_config: SharedShardNodeConfig) -> Self {
    let pool = TxPool::new(
        shard_config.max_tx_pool_size,
        shard_config.max_block_size
    );
    
    ShardChain {
        shard_id,
        chain: Vec::new(),
        fork_utxo_overlay: ForkUtxoOverlay::new(),
        tx_pool: pool,
        // ...
    }
}
```

compose_block_template():
- Calls pool.get_high_fee_transactions(shard_config.max_block_size)
- Gets sorted high-fee transactions
- Creates block with selected transactions
- Transactions remain in pool until block appended

append_block():
- For each transaction in block:
  - Calls pool.remove_transaction(txid)
  - Transaction leaves pool permanently (until reorg)

drop_last_block():
- For each transaction in removed block:
  - Calls pool.add_transaction() with fee_rate=0.0
  - Transactions return to pool


BLOCKCHAIN PERSPECTIVE
======================

From blockchain view:
- Transactions flow: Source -> Pool -> Block -> Chain -> History
- Each stage is a queue/buffer
- Next block pulls from pool
- Confirmed in block
- Added to chain

Pool transitions:
- add: When transaction received
- remove: When included in block
- add back: If block reverted


BITCOIN COMPATIBILITY
=====================

Our pool design matches Bitcoin's mempool:
âœ" Priority based on fee rate
âœ" Size limits (transaction and bytes)
âœ" Fast lookup by txid
âœ" Support for removal (eviction)
âœ" FIFO + priority ordering


EVICTION POLICY
===============

Currently: FIFO with size limit
When pool full: newest transaction rejected

Alternative approaches (TODO):
- LRU eviction: Remove oldest low-fee transactions
- Min-fee policy: Evict if fee below threshold
- Dynamic limits: Adjust based on network conditions


DIAGNOSTICS
===========

Available metrics:
- size(): Current transaction count
- total_bytes(): Current pool size in bytes
- max_tx_count(): Configured transaction limit
- max_pool_bytes(): Configured byte limit
- Pool composition by fee rate
- Transaction age statistics


PERFORMANCE
===========

Typical shard pool (default config):
- 1,000-5,000 transactions
- 50-100 KB used (of 120KB limit)
- Memory usage: O(n)
- Lookup: O(1)
- Selection: O(n log n) per block

Acceptable for:
- 1-minute block times
- Hundreds of transactions/sec
- Thousands of pending transactions


FUTURE ENHANCEMENTS
===================

TODO: Implement
- LRU eviction policy
- Minimum fee threshold
- Transaction prioritization by lock time
- Double-spend detection
- Mempool statistics/metrics
- Persistent mempool (survive restart)
- Dynamic fee estimation


MIGRATION FROM HARDCODED CONSTANTS
===================================

Before: Hardcoded limits in TxPool
```rust
// In old code
const MAX_TX_POOL_SIZE: usize = 10000;
const MAX_BLOCK_SIZE: usize = 61440;

pub fn add_transaction(&mut self, tx: Transaction, ...) -> Result<(), String> {
    if self.pool.len() >= MAX_TX_POOL_SIZE { // Hardcoded
        return Err(...);
    }
    if self.total_size + tx_size > MAX_BLOCK_SIZE * 2 { // Hardcoded
        return Err(...);
    }
    // ...
}
```

After: Configurable limits
```rust
pub struct TxPool {
    // ...
    max_tx_count: usize,      // From config
    max_pool_bytes: usize,    // From config
}

pub fn new(max_tx_count: usize) -> Self {
    // Calculate max_pool_bytes from tx_count estimate
    let max_pool_bytes = max_tx_count * 200;
    Self {
        // ...
        max_tx_count,
        max_pool_bytes,
    }
}

pub fn add_transaction(&mut self, tx: Transaction, ...) -> Result<(), String> {
    if self.pool.len() >= self.max_tx_count { // From config
        return Err(...);
    }
    if self.total_size + tx_size > self.max_pool_bytes { // From config
        return Err(...);
    }
    // ...
}
```

Benefits:
- Runtime configurability
- No recompiling to change limits
- Different pools can have different limits
- Clear origin of values in error messages


TESTING
=======

Pool behavior with different limits:

```rust
// Create pool with small limits for testing
let max_block_size = 10000;
let pool = TxPool::new(100, max_block_size); // 100 tx limit, 20KB pool limit

// Add transactions up to limit
for i in 0..100 {
    pool.add_transaction(tx, 1.0, now)?; // Should succeed for first ~100 txs
}

// Next transaction should fail (pool full)
pool.add_transaction(tx, 1.0, now)?; // Should error: "Transaction pool full"

// Also test byte limit:
// If transactions are large, will hit max_pool_bytes limit before tx count limit
let max_block_size = 1000;
let pool = TxPool::new(10000, max_block_size); // max 2KB pool limit
// Adding 5KB transaction would fail with "size limit exceeded"
```


===============================================================================
*/

#[cfg(test)]
mod would_accept_tests {
    use super::*;
    use crate::common::blocks::ShardBlockBody;
    use crate::transaction::{TxInput, TxOutput};

    fn tx(prev_height: u32) -> Transaction {
        let mut t = Transaction::new(1, 0);
        t.inputs.push(TxInput { prev_height, prev_output_idx: 0 });
        t.add_output(TxOutput { value: 10, recipient: [0x33; 32] });
        t
    }

    #[test]
    fn empty_pool_accepts() {
        let pool = TxPool::new(1, 2, 1_000_000);
        let sz = ShardBlockBody::tx_wire_size(&tx(1));
        assert!(pool.would_accept(sz, 1.0));
        assert!(pool.admission_precheck(sz, || panic!("no fee lookup when room")).is_ok());
    }

    #[test]
    fn full_same_fee_refuses_higher_accepts() {
        let mut pool = TxPool::new(1, 2, 1_000_000);
        pool.add_transaction(tx(1), 5.0, 0, 0).unwrap();
        pool.add_transaction(tx(2), 5.0, 0, 0).unwrap();
        let c = tx(3);
        let sz = ShardBlockBody::tx_wire_size(&c);
        assert!(!pool.would_accept(sz, 5.0));
        assert!(!pool.would_accept(sz, 4.0));
        assert!(pool.admission_precheck(sz, || Some(5.0)).unwrap_err().contains("pool full"));
        assert!(pool.admission_precheck(sz, || None).is_ok(), "unresolved falls through");
        // Parity with add_transaction.
        assert!(pool.clone().add_transaction(c.clone(), 5.0, 0, 0).is_err());
        assert!(pool.would_accept(sz, 6.0));
        assert!(pool.admission_precheck(sz, || Some(6.0)).is_ok());
        assert!(pool.add_transaction(c, 6.0, 0, 0).is_ok());
        assert!(!pool.would_accept(sz, f64::NAN));
    }

    #[test]
    fn byte_limit_parity() {
        let sz = ShardBlockBody::tx_wire_size(&tx(1));
        // Room for exactly two by bytes.
        let mut pool = TxPool::new(1, 100, sz); // max_pool_bytes = 2*sz
        pool.add_transaction(tx(1), 1.0, 0, 0).unwrap();
        pool.add_transaction(tx(2), 3.0, 0, 0).unwrap();
        assert!(!pool.would_accept(sz, 1.0));
        assert!(pool.would_accept(sz, 2.0), "evicts the 1.0 entry");
        assert!(pool.admission_precheck(sz, || Some(1.0)).unwrap_err().contains("size limit"));
    }

    #[test]
    fn oversize_refused() {
        let pool = TxPool::new(1, 100, 10);
        assert!(!pool.would_accept(21, 1e9));
        assert!(pool.would_accept(20, 1.0));
    }

    /// ESC-7 (spec test 10): a cooperative escrow spend leaves the pool once block H-1
    /// is applied; a recovery spend is not put on the expiry index.
    #[test]
    fn esc7_coop_spend_evicted_after_block_h_minus_1() {
        use crate::common::crypto::escrow::{coop_witness, recovery_witness};
        use crate::common::crypto::EscrowPolicy;
        let policy = EscrowPolicy { sender_pk: [1; 32], provider_pk: [2; 32], unlock_height: 50 };
        let mut coop = tx(1);
        coop.witnesses = vec![coop_witness(&policy, &[0; 64], &[0; 64])];
        let mut rec = tx(2);
        rec.witnesses = vec![recovery_witness(&policy, &[0; 64])];
        let mut pool = TxPool::new(1, 10, 1_000_000);
        pool.add_transaction(coop, 1.0, 0, 0).unwrap();
        pool.add_transaction(rec, 1.0, 0, 0).unwrap();
        assert!(pool.evict_expired(48).is_empty());
        assert_eq!(pool.evict_expired(49).len(), 1, "evicted after block H-1");
        assert_eq!(pool.evict_expired(1_000).len(), 0, "recovery spend is never expiry-indexed");
    }

    /// ESC-7: TE-2's expiration height still wins when it is earlier than H-1.
    #[test]
    fn esc7_earlier_expiration_height_wins() {
        use crate::common::crypto::escrow::coop_witness;
        use crate::common::crypto::EscrowPolicy;
        let policy = EscrowPolicy { sender_pk: [1; 32], provider_pk: [2; 32], unlock_height: 50 };
        let mut coop = tx(1);
        coop.expiration_height = 20;
        coop.witnesses = vec![coop_witness(&policy, &[0; 64], &[0; 64])];
        let mut pool = TxPool::new(1, 10, 1_000_000);
        pool.add_transaction(coop, 1.0, 0, 0).unwrap();
        assert_eq!(pool.evict_expired(20).len(), 1);
    }
}

#[cfg(test)]
mod retain_tests {
    use super::*;
    use crate::transaction::{TxInput, TxOutput};

    fn tx(prev_height: u32, value: u64) -> Transaction {
        let mut t = Transaction::new(1, 0);
        t.inputs.push(TxInput { prev_height, prev_output_idx: 0 });
        t.add_output(TxOutput { value, recipient: [0x33; 32] });
        t
    }

    /// VF-3 Phase 0: `retain` removes in one pass and leaves every index
    /// consistent — lookups, sizes and later removals still work.
    #[test]
    fn retain_removes_and_rebuilds_indexes() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        let (a, b, c) = (tx(1, 10), tx(2, 20), tx(3, 30));
        for t in [&a, &b, &c] {
            pool.add_transaction(t.clone(), 1.0, 0, 0).unwrap();
        }
        let removed = pool.retain(|t| t.inputs[0].prev_height != 2);
        assert_eq!(removed, 1);
        assert_eq!(pool.size(), 2);
        assert!(pool.get_transaction(b.txid(1)).is_none());
        assert!(pool.get_transaction(a.txid(1)).is_some());
        assert!(pool.get_transaction(c.txid(1)).is_some());
        use crate::common::blocks::ShardBlockBody;
        assert_eq!(pool.total_bytes(), ShardBlockBody::tx_wire_size(&a) + ShardBlockBody::tx_wire_size(&c));
        // Index positions are still right after the rebuild.
        assert!(pool.remove_transaction(c.txid(1)).is_some());
        assert!(pool.get_transaction(a.txid(1)).is_some());
        assert_eq!(pool.retain(|_| true), 0);
    }

    /// P2P mempool sync views: fee-ordered entries, the txid list, serialised payloads under a
    /// byte budget, and per-txid info all agree with what was added.
    #[test]
    fn sync_views_match_the_pool() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        let txs: Vec<Transaction> = (1..=4u32).map(|i| tx(i, 10)).collect();
        for (i, t) in txs.iter().enumerate() {
            pool.add_transaction(t.clone(), (i + 1) as f64, 0, 0).unwrap(); // fee rises with index
        }
        let top = pool.top_entries(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, txs[3].txid(1).0, "highest fee rate first");
        assert_eq!(top[0].1, 4.0);
        assert_eq!(pool.txids().len(), 4);
        assert!(pool.txids().contains(&txs[0].txid(1).0));
        let all = pool.top_serialized(10, usize::MAX);
        assert_eq!(all.len(), 4);
        assert_eq!(Transaction::deserialize_with_witnesses(&all[0]).unwrap().txid(1), txs[3].txid(1));
        let one = all[0].len();
        assert_eq!(pool.top_serialized(10, one).len(), 1, "stops before the byte budget");
        assert_eq!(pool.top_serialized(2, usize::MAX).len(), 2, "stops at the count");
        let (fee, size) = pool.entry_info(&txs[1].txid(1).0).unwrap();
        assert_eq!(fee, 2.0);
        assert_eq!(size, crate::common::blocks::ShardBlockBody::tx_wire_size(&txs[1]));
        assert!(pool.entry_info(&[9u8; 32]).is_none());
    }

    /// `position_of` counts only strictly better payers (ties do not outrank) and reports the
    /// admission time; `None` for an unknown txid.
    #[test]
    fn position_of_counts_strictly_better_payers() {
        let mut pool = TxPool::new(1, 10, 1_000_000);
        let txs: Vec<Transaction> = (1..=4u32).map(|i| tx(i, 10)).collect();
        for (i, (fee, ts)) in [(1.0, 100u64), (2.0, 200), (2.0, 300), (3.0, 400)].into_iter().enumerate() {
            pool.add_transaction(txs[i].clone(), fee, ts, 0).unwrap();
        }
        let low = pool.position_of(&txs[0].txid(1).0).unwrap();
        assert_eq!((low.better_count, low.added_unix), (3, 100));
        assert_eq!(low.better_bytes, pool.entry_info(&txs[3].txid(1).0).unwrap().1 + 2 * low.wire_size);
        let tie = pool.position_of(&txs[1].txid(1).0).unwrap();
        assert_eq!(tie.better_count, 1, "an equal payer does not outrank");
        assert_eq!(pool.position_of(&txs[3].txid(1).0).unwrap().better_count, 0);
        assert!(pool.position_of(&[9u8; 32]).is_none());
    }

    /// Full pool: a transaction paying a higher fee rate evicts the lowest-paying one; one paying
    /// no more than the cheapest pooled transaction is refused. Indexes stay consistent.
    #[test]
    fn full_pool_evicts_the_lowest_fee_for_a_higher_paying_tx() {
        let mut pool = TxPool::new(1, 3, 1_000_000); // three transactions
        let txs: Vec<Transaction> = (1..=5u32).map(|i| tx(i, 10)).collect();
        for (i, fee) in [(0, 2.0), (1, 1.0), (2, 3.0)] {
            pool.add_transaction(txs[i].clone(), fee, 0, 0).unwrap();
        }
        // Cheaper than everything, and equal to the cheapest: refused, pool unchanged.
        assert!(pool.add_transaction(txs[3].clone(), 0.5, 0, 0).is_err());
        assert!(pool.add_transaction(txs[3].clone(), 1.0, 0, 0).is_err(), "equal fee does not evict");
        assert_eq!(pool.size(), 3);
        assert_eq!(pool.evicted_for_fee(), 0);
        // Higher than the cheapest: the fee-1.0 transaction (txs[1]) leaves.
        pool.add_transaction(txs[3].clone(), 5.0, 0, 0).expect("evicts the cheapest");
        assert_eq!(pool.size(), 3);
        assert_eq!(pool.evicted_for_fee(), 1);
        assert!(pool.get_transaction(txs[1].txid(1)).is_none());
        for i in [0usize, 2, 3] {
            assert!(pool.get_transaction(txs[i].txid(1)).is_some(), "tx {i} kept");
        }
        // The evicted transaction's input is free again (no stale conflict entry).
        pool.add_transaction(txs[4].clone(), 9.0, 0, 0).expect("evicts the next cheapest");
        pool.add_transaction(txs[1].clone(), 20.0, 0, 0).expect("its input was released");
        assert_eq!(pool.size(), 3);
        assert_eq!(pool.evicted_for_fee(), 3);
        // Removal still works on the rebuilt index.
        assert!(pool.remove_transaction(txs[1].txid(1)).is_some());
    }

    /// Byte limit: a big high-fee transaction evicts as many low-fee ones as it needs, but never a
    /// transaction that pays as much as it does.
    #[test]
    fn full_pool_by_bytes_evicts_enough_low_fee_transactions() {
        use crate::common::blocks::ShardBlockBody;
        let one = ShardBlockBody::tx_wire_size(&tx(1, 10));
        let mut pool = TxPool::new(1, 100, 1); // placeholder; set the byte limit below
        pool.max_pool_bytes = one * 3; // room for exactly three small transactions
        for (i, fee) in [(1u32, 1.0), (2, 2.0), (3, 3.0)] {
            pool.add_transaction(tx(i, 10), fee, 0, 0).unwrap();
        }
        // A transaction twice as big (two outputs) needs two evictions.
        let mut big = tx(9, 10);
        big.add_output(crate::transaction::TxOutput { value: 5, recipient: [0x34; 32] });
        let big_size = ShardBlockBody::tx_wire_size(&big);
        assert!(big_size > one && big_size <= 2 * one + one, "fixture: needs 1-2 evictions, got {big_size} vs {one}");
        // Pays like the middle one: it would have to evict fee 2.0 as well, so refused.
        assert!(pool.add_transaction(big.clone(), 2.0, 0, 0).is_err());
        assert_eq!(pool.size(), 3);
        pool.add_transaction(big, 10.0, 0, 0).expect("evicts the cheapest until it fits");
        assert!(pool.total_bytes() <= one * 3);
        assert!(pool.evicted_for_fee() >= 1);
        // Larger than the whole pool: refused outright, nothing evicted.
        let before = pool.evicted_for_fee();
        let mut huge = tx(10, 10);
        for _ in 0..100 {
            huge.add_output(crate::transaction::TxOutput { value: 1, recipient: [0x35; 32] });
        }
        assert!(pool.add_transaction(huge, 1000.0, 0, 0).is_err());
        assert_eq!(pool.evicted_for_fee(), before);
    }

    /// Item 17: template selection stops at the output cap even when the
    /// byte limit has room, and keeps highest-fee transactions first.
    #[test]
    fn capped_selection_stops_at_output_limit() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        for i in 1..=5u32 {
            pool.add_transaction(tx(i, 10), 10.0 - i as f64, 0, 0).unwrap(); // 1 output each
        }
        let picked = pool.get_high_fee_transactions_capped(1_000_000, 3);
        assert_eq!(picked.len(), 3);
        assert_eq!(picked[0].inputs[0].prev_height, 1, "highest fee first");
        assert_eq!(pool.get_high_fee_transactions(1_000_000).len(), 5);
    }

    /// Block size limits count wire bytes (witnesses included): selection never exceeds the
    /// wire budget, and the pool's own byte accounting is in wire bytes.
    #[test]
    fn selection_stays_inside_the_wire_budget() {
        use crate::common::blocks::ShardBlockBody;
        use crate::transaction::WitnessEntry;
        let mut pool = TxPool::new(1, 10_000, 61_440);
        let signed = |h: u32| {
            let mut t = tx(h, 10);
            t.witnesses.push(WitnessEntry { witness_data: vec![7u8; 73] });
            t
        };
        for h in 1..=600u32 {
            pool.add_transaction(signed(h), 1.0 + h as f64, 0, 0).unwrap_or(()); // the pool limit may refuse the tail
        }
        let budget = 61_440 - 2_048;
        let picked = pool.get_high_fee_transactions_capped(budget, usize::MAX);
        let wire: usize = picked.iter().map(ShardBlockBody::tx_wire_size).sum();
        let witness_free: usize = picked.iter().map(|t| t.size()).sum();
        assert!(wire <= budget, "selected {wire} wire bytes for a budget of {budget}");
        assert!(wire > budget - 200, "the budget is used ({wire})");
        assert!(witness_free < wire * 2 / 3, "the witnesses are counted ({witness_free} vs {wire})");
        assert!(pool.total_bytes() <= pool.max_pool_bytes());
    }

    /// NC-154: two transactions spending the same output cannot both sit in the pool, so a block
    /// template built from the pool can never contain a double spend.
    #[test]
    fn nc154_conflicting_spend_is_refused_at_admission() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        let first = tx(7, 10);
        let rival = tx(7, 20); // same input (7, 0), different output value
        pool.add_transaction(first.clone(), 5.0, 0, 0).unwrap();
        let err = pool.add_transaction(rival.clone(), 9.0, 0, 0).expect_err("conflict must be refused");
        assert!(err.contains("conflict"), "{err}");
        assert_eq!(pool.size(), 1);
        assert!(pool.get_transaction(first.txid(1)).is_some());
        let picked = pool.get_high_fee_transactions_capped(1_000_000, usize::MAX);
        assert_eq!(picked.len(), 1, "template selection sees no double spend");
    }

    /// NC-154: after the first spender leaves the pool (mined, expired, pruned) its input is free again.
    #[test]
    fn nc154_input_is_free_after_the_spender_leaves() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        let (first, rival) = (tx(7, 10), tx(7, 20));
        pool.add_transaction(first.clone(), 5.0, 0, 0).unwrap();
        assert!(pool.remove_transaction(first.txid(1)).is_some());
        pool.add_transaction(rival.clone(), 5.0, 0, 0).expect("input is free again");
        pool.retain(|_| false);
        pool.add_transaction(first, 5.0, 0, 0).expect("free after retain");
    }

    /// NC-154: a mined block's spends evict pool transactions that spend the same outputs.
    #[test]
    fn nc154_block_spends_evict_conflicting_pool_transactions() {
        let mut pool = TxPool::new(1, 100, 1_000_000);
        let (in_pool, other) = (tx(7, 10), tx(8, 10));
        pool.add_transaction(in_pool.clone(), 5.0, 0, 0).unwrap();
        pool.add_transaction(other.clone(), 5.0, 0, 0).unwrap();
        let mined = tx(7, 99); // a block spent (7, 0) with a different transaction
        let evicted = pool.remove_conflicting(&mined);
        assert_eq!(evicted.len(), 1);
        assert!(pool.get_transaction(in_pool.txid(1)).is_none());
        assert!(pool.get_transaction(other.txid(1)).is_some());
        // The mined transaction itself, if it was in the pool, is not "a conflict with itself".
        let mut pool = TxPool::new(1, 100, 1_000_000);
        pool.add_transaction(mined.clone(), 5.0, 0, 0).unwrap();
        assert!(pool.remove_conflicting(&mined).is_empty());
    }

    /// VF-3 Phase 1: the pool is keyed by `txid(chain_id)` of its own chain.
    #[test]
    fn pool_keys_by_its_chain_txid() {
        let mut pool = TxPool::new(3, 100, 1_000_000);
        let a = tx(1, 10);
        pool.add_transaction(a.clone(), 1.0, 0, 0).unwrap();
        assert!(pool.get_transaction(a.txid(3)).is_some());
        assert!(pool.get_transaction(a.txid(0)).is_none());
        assert_eq!(pool.txid_of(&a), a.txid(3));
    }

    /// WAL v2 keeps witnesses and extensions (v1 wrote the witness-less
    /// legacy bytes, so restored transactions lost their signatures).
    #[test]
    fn wal_v2_round_trips_witnesses_and_extensions() {
        use crate::transaction::{ExtensionHeader, ExtensionRecord, WitnessEntry};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool_0.snapshot");
        let mut a = tx(1, 10);
        a.witnesses.push(WitnessEntry { witness_data: vec![0x01; 65] });
        a.extensions.push(ExtensionRecord {
            header: ExtensionHeader { extension_type: 0x1234, version: 1, payload_length: 1 },
            payload: vec![7],
        });
        let mut pool = TxPool::new(1, 100, 1_000_000);
        pool.add_transaction(a.clone(), 2.0, 5, 0).unwrap();
        pool.save_wal(&path).unwrap();

        let mut restored = TxPool::new(1, 100, 1_000_000);
        assert_eq!(restored.load_wal(&path, 0).unwrap(), 1);
        let got = restored.get_transaction(a.txid(1)).expect("restored under the same txid");
        assert_eq!(got.witnesses, a.witnesses);
        assert_eq!(got.extensions, a.extensions);
    }

    /// A pre-VF-3 (v1) WAL is dropped, not restored and not an error.
    #[test]
    fn wal_v1_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool_0.snapshot");
        let mut bytes = b"MPWL".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let mut pool = TxPool::new(1, 100, 1_000_000);
        assert_eq!(pool.load_wal(&path, 0).unwrap(), 0);
    }

}
