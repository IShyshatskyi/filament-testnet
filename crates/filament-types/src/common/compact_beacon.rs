//! KBM-8 — compact-block (Tier 2) support for **beacon** blocks.
//!
//! A beacon block can carry up to ~1 MiB of transactions that peers usually already hold in their
//! beacon mempool (KBM-2..6). Instead of pushing the whole block, the sender announces
//! `CompactBlockAnn { block_hash, height, shard_id: None, short_ids, header_bytes }` where
//!
//! * `short_ids[i]` = `compute_short_id(txid_i, salt)` for every **non-coinbase** transaction, in block
//!   order (`txid_i` is the chain-id-0 txid; `salt` = first 8 bytes of `block_hash`),
//! * `header_bytes` = the **skeleton**: a [`BeaconWireBlock`] encoding of the same header with a body
//!   that holds only the coinbase (the coinbase is not in any mempool, so it travels in full).
//!
//! The receiver looks every short id up in its beacon pool, rebuilds the body with the coinbase
//! first, and **checks the rebuilt body against the header's `tx_merkle_root`**. Anything that does
//! not match (a missing transaction, a short-id collision, a body that does not rebuild byte for
//! byte) returns `None`, and the caller falls back to Tier 3 (fetch the whole block). A wrong guess
//! therefore costs one round trip, never a bad block.
//!
//! Both `FullNodeChainProvider` (Keystone) and `MiningPoolChainProvider` (Kameniar) call
//! [`reconstruct_beacon_block`] with a lookup over their own pool; the manager calls
//! [`split_beacon_for_compact`] when announcing.

use crate::common::blocks::beacon_block::BeaconWireBlock;
use crate::common::blocks::ShardBlockBody;
use crate::common::compact_block::compute_short_id;
use crate::transaction::{Transaction, BEACON_CHAIN_ID};

/// The wire field holding the skeleton is length-prefixed with a `u16`.
const MAX_SKELETON_BYTES: usize = 60_000;
/// The short-id count is a `u16` on the wire.
const MAX_SHORT_IDS: usize = u16::MAX as usize;

/// The salt every short id of a block uses.
pub fn compact_salt(block_hash: &[u8; 32]) -> [u8; 8] {
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&block_hash[0..8]);
    salt
}

/// Sender side. `wire` is the block's `BeaconWireBlock::encode()` bytes. Returns
/// `(skeleton, short_ids)`, or `None` when there is nothing to save (coinbase-only block), the block
/// does not decode, or it would not fit the announcement.
pub fn split_beacon_for_compact(wire: &[u8], block_hash: &[u8; 32]) -> Option<(Vec<u8>, Vec<u64>)> {
    let block = BeaconWireBlock::decode(wire).ok()?;
    let txs = block.body.to_transactions().ok()?;
    if txs.len() < 2 || txs.len() - 1 > MAX_SHORT_IDS {
        return None;
    }
    let salt = compact_salt(block_hash);
    let short_ids: Vec<u64> =
        txs[1..].iter().map(|t| compute_short_id(&t.txid(BEACON_CHAIN_ID).0, &salt)).collect();
    let skeleton = BeaconWireBlock {
        header: block.header,
        coinbase_hash: block.coinbase_hash,
        body: ShardBlockBody::from_transactions(&txs[..1], None),
    }
    .encode();
    if skeleton.len() > MAX_SKELETON_BYTES {
        return None;
    }
    Some((skeleton, short_ids))
}

/// Receiver side. `lookup(short_id, salt)` returns the pooled transaction's
/// `serialize_with_witnesses()` bytes. Returns the full block's `BeaconWireBlock` bytes, or `None`
/// (Tier 3) if anything is missing or the rebuilt body does not match the header.
pub fn reconstruct_beacon_block(
    skeleton: &[u8],
    short_ids: &[u64],
    block_hash: &[u8; 32],
    lookup: impl Fn(u64, &[u8; 8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let sk = BeaconWireBlock::decode(skeleton).ok()?;
    let mut txs: Vec<Transaction> = sk.body.to_transactions().ok()?;
    if txs.len() != 1 {
        return None; // the skeleton carries exactly the coinbase
    }
    let salt = compact_salt(block_hash);
    for &id in short_ids {
        let bytes = lookup(id, &salt)?;
        txs.push(Transaction::deserialize_with_witnesses(&bytes).ok()?);
    }
    let body = ShardBlockBody::from_transactions(&txs, None);
    if body.calculate_tx_merkle_root() != sk.header.tx_merkle_root {
        return None;
    }
    Some(BeaconWireBlock { header: sk.header, coinbase_hash: sk.coinbase_hash, body }.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::blocks::beacon_block::BeaconBlockCandidateHeader;
    use crate::common::crypto::weighted_hash::WeightedHash;
    use crate::transaction::{TxInput, TxOutput, WitnessEntry};
    use crate::common::utxo::TxPool;

    fn coinbase() -> Transaction {
        let mut t = Transaction::new(1, 0);
        t.add_output(TxOutput { value: 100, recipient: [7u8; 32] });
        t
    }

    fn spend(prev_height: u32, ext: bool) -> Transaction {
        let mut t = Transaction::new(1, 0);
        t.inputs.push(TxInput { prev_height, prev_output_idx: 0 });
        t.add_output(TxOutput { value: 10, recipient: [0x33; 32] });
        t.add_output(TxOutput { value: 5, recipient: [0x34; 32] });
        t.witnesses.push(WitnessEntry { witness_data: vec![prev_height as u8; 73] });
        if ext {
            t.expiration_height = 5_000; // a validity-window record in the flat body
        }
        t
    }

    fn block_with(txs: &[Transaction]) -> (Vec<u8>, [u8; 32]) {
        let body = ShardBlockBody::from_transactions(txs, None);
        let header = BeaconBlockCandidateHeader::new(
            1, 1_700_000_000, 9, 0x0300_0040, WeightedHash::zero(), body.calculate_tx_merkle_root(),
            [5u8; 32], 1_704_067_200,
        );
        let wire = BeaconWireBlock { header, coinbase_hash: [9u8; 32], body }.encode();
        (wire, [0xAB; 32])
    }

    fn pool_lookup(pool: &TxPool) -> impl Fn(u64, &[u8; 8]) -> Option<Vec<u8>> + '_ {
        move |id, salt| pool.serialized_by_short_id(id, salt)
    }

    /// The full path: split, then rebuild from a pool that holds the transactions, byte for byte.
    #[test]
    fn rebuilds_the_exact_block_from_the_pool() {
        let txs = vec![coinbase(), spend(1, false), spend(2, true), spend(3, false)];
        let (wire, hash) = block_with(&txs);
        let (skeleton, ids) = split_beacon_for_compact(&wire, &hash).expect("has transactions");
        assert_eq!(ids.len(), 3);
        assert!(skeleton.len() < wire.len() / 2, "skeleton {} vs block {}", skeleton.len(), wire.len());

        let mut pool = TxPool::new(BEACON_CHAIN_ID, 100, 1_000_000);
        for t in &txs[1..] {
            pool.add_transaction(t.clone(), 1.0, 0, 0).unwrap();
        }
        let rebuilt = reconstruct_beacon_block(&skeleton, &ids, &hash, pool_lookup(&pool)).expect("all present");
        assert_eq!(rebuilt, wire, "byte-identical to the original block");
    }

    /// A missing transaction, a corrupted skeleton, a swapped order, or a pool holding a different
    /// transaction under the same id all end in `None` (Tier 3), never a wrong block.
    #[test]
    fn anything_that_does_not_match_falls_back() {
        let txs = vec![coinbase(), spend(1, false), spend(2, false)];
        let (wire, hash) = block_with(&txs);
        let (skeleton, ids) = split_beacon_for_compact(&wire, &hash).unwrap();

        let mut partial = TxPool::new(BEACON_CHAIN_ID, 100, 1_000_000);
        partial.add_transaction(txs[1].clone(), 1.0, 0, 0).unwrap();
        assert!(reconstruct_beacon_block(&skeleton, &ids, &hash, pool_lookup(&partial)).is_none(), "missing tx");

        let mut full = TxPool::new(BEACON_CHAIN_ID, 100, 1_000_000);
        for t in &txs[1..] {
            full.add_transaction(t.clone(), 1.0, 0, 0).unwrap();
        }
        assert!(reconstruct_beacon_block(&skeleton[..skeleton.len() - 3], &ids, &hash, pool_lookup(&full)).is_none());
        let swapped = vec![ids[1], ids[0]];
        assert!(reconstruct_beacon_block(&skeleton, &swapped, &hash, pool_lookup(&full)).is_none(), "wrong order breaks the merkle root");
        // A lookup that returns a different transaction for the id: merkle check catches it.
        let imposter = spend(99, false).serialize_with_witnesses();
        assert!(reconstruct_beacon_block(&skeleton, &ids, &hash, |_, _| Some(imposter.clone())).is_none());
        // A different salt means different short ids: nothing matches.
        assert!(reconstruct_beacon_block(&skeleton, &ids, &[0xCD; 32], pool_lookup(&full)).is_none());
    }

    /// A really mined beacon coinbase carries the miner-extranonce extension on its descriptor
    /// (and the producer stamp may be set); the rebuilt block must still be byte-identical.
    #[test]
    fn real_mined_coinbase_with_extranonce_extension_rebuilds_exactly() {
        use crate::transaction::build_miner_extranonce_extension;
        let spends = [spend(1, false), spend(2, false)];
        let mut all = vec![coinbase()];
        all.extend(spends.iter().cloned());
        let mut body = ShardBlockBody::from_transactions(&all, None);
        // Attach the extension to transaction 0 exactly as the beacon job builder does: it is
        // pushed to the *front* of descriptor 0's range, so insert it at extension index 0.
        let ext = build_miner_extranonce_extension([1, 2, 3, 4], [0, 0, 0, 0]);
        body.extensions.insert(0, ext);
        body.descriptors[0].extension_len += 1;
        for d in body.descriptors.iter_mut().skip(1) {
            d.extension_start += 1;
        }
        let header = BeaconBlockCandidateHeader::new(
            1, 1_700_000_000, 9, 0x0300_0040, WeightedHash::zero(), body.calculate_tx_merkle_root(),
            [5u8; 32], 1_704_067_200,
        );
        let wire = BeaconWireBlock { header, coinbase_hash: [9u8; 32], body }.encode();
        let hash = [0x42; 32];
        let (skeleton, ids) = split_beacon_for_compact(&wire, &hash).expect("split");
        let mut pool = TxPool::new(BEACON_CHAIN_ID, 100, 1_000_000);
        for t in &spends {
            pool.add_transaction(t.clone(), 1.0, 0, 0).unwrap();
        }
        let rebuilt = reconstruct_beacon_block(&skeleton, &ids, &hash, pool_lookup(&pool))
            .expect("the extranonce extension survives the rebuild");
        assert_eq!(rebuilt, wire);
    }

    /// Nothing to save for a coinbase-only block (the manager then pushes the full body as before).
    #[test]
    fn coinbase_only_block_is_not_split() {
        let (wire, hash) = block_with(&[coinbase()]);
        assert!(split_beacon_for_compact(&wire, &hash).is_none());
        assert!(split_beacon_for_compact(b"garbage", &hash).is_none());
    }
}
