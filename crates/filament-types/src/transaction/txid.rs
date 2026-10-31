//! VF-3 Phase 1 — the one transaction identity (`docs/plan/Txid_Unification_Design.md` §3.1).
//!
//! ```text
//! txid = BLAKE3( "shisha/txid/v1"
//!              ‖ chain_id          : u16 LE  // beacon 0, shard N → N+1 (same as sighash, #22)
//!              ‖ version           : u8      // semantic value; implicit 1 with no validity record
//!              ‖ locktime          : u32 LE
//!              ‖ expiration_height : u32 LE
//!              ‖ n_inputs  : u32 LE ‖ [prev_height u32 LE ‖ prev_output_idx u16 LE] × n
//!              ‖ n_outputs : u32 LE ‖ [value u64 LE ‖ recipient [u8;32]] × m
//!              ‖ n_ext     : u32 LE ‖ [ext_type u16 LE ‖ ext_version u16 LE ‖ len u32 LE ‖ payload] × k )
//! ```
//!
//! The txid is independent of block position and of witnesses, and it hashes
//! semantic values rather than extension encodings: the validity-window record is
//! never hashed as a record (its meaning is the `version`/`locktime`/`expiration`
//! fields), so an explicit default record and no record give the same txid.
//!
//! It is **not** the block commitment leaf: that is
//! [`ShardBlockBody::tx_leaf_hash`](crate::common::blocks::shard_block::ShardBlockBody::tx_leaf_hash),
//! which is position- and witness-bound and must never be shown as an id.
//!
//! Both the standalone path ([`Transaction::txid`]) and the block-slice path
//! (`ShardBlockBody::txid_at`) go through [`txid_from_parts`], so they cannot
//! drift. `tools/tx-spammer` mirrors this encoder; the golden vectors in the
//! tests below are pinned on both sides.

use super::flat_tx_meta::{FlatTxMeta, CONSENSUS_EXT_VALIDITY_WINDOW};
use super::types::{ExtensionRecord, Transaction, Txid};

/// Domain tag prefixed to every txid preimage.
pub const TXID_DOMAIN_TAG: &[u8] = b"shisha/txid/v1";

/// `chain_id` of the beacon chain.
pub const BEACON_CHAIN_ID: u16 = 0;

/// `chain_id` of shard `shard_id` (shard N → N+1), the same convention every
/// signature preimage uses (Anti-Patterns #22).
pub fn shard_chain_id(shard_id: u16) -> u16 {
    shard_id.wrapping_add(1)
}

/// Mempool address of the **beacon chain** in the P2P mempool messages.
///
/// Every mempool message (`TxBatch`, `TxBatchFull`, `GetMempoolFilter`, `MempoolFilter`,
/// `GetMissingTxs`, `FeeFilter`, `Tx`, and the `MultiChainTxBatch` entries) names its chain with
/// a `u16`: the shard id for a shard, and this reserved value for the beacon chain. Shard ids are
/// below [`MAX_SHARD_MEMPOOL_ID`], so the two never collide. Keystone beacon mempool plan KBM-1;
/// negotiated with `ProtocolFeature::BeaconMempool` (ShishaNet v13).
pub const BEACON_MEMPOOL_ID: u16 = u16::MAX;

/// Shard ids are below this value (the subscription mask has 1 024 bits; the admin APIs refuse
/// larger ids). Everything from here up, except [`BEACON_MEMPOOL_ID`], is not a valid mempool address.
pub const MAX_SHARD_MEMPOOL_ID: u16 = 1024;

/// True when `mempool_id` names the beacon chain.
pub fn is_beacon_mempool_id(mempool_id: u16) -> bool {
    mempool_id == BEACON_MEMPOOL_ID
}

/// True when `mempool_id` is a valid address: a shard id below [`MAX_SHARD_MEMPOOL_ID`] or the beacon.
pub fn is_valid_mempool_id(mempool_id: u16) -> bool {
    mempool_id < MAX_SHARD_MEMPOOL_ID || is_beacon_mempool_id(mempool_id)
}

/// `chain_id` (txid / signature domain) of the chain a mempool message addresses:
/// beacon [`BEACON_CHAIN_ID`] for [`BEACON_MEMPOOL_ID`], otherwise [`shard_chain_id`].
pub fn mempool_chain_id(mempool_id: u16) -> u16 {
    if is_beacon_mempool_id(mempool_id) { BEACON_CHAIN_ID } else { shard_chain_id(mempool_id) }
}

/// Hash the canonical txid preimage. Extensions of type
/// [`CONSENSUS_EXT_VALIDITY_WINDOW`] are skipped (their meaning is `meta`).
pub fn txid_from_parts<I, O>(
    chain_id: u16,
    meta: FlatTxMeta,
    inputs: I,
    outputs: O,
    extensions: &[ExtensionRecord],
) -> [u8; 32]
where
    I: ExactSizeIterator<Item = (u32, u16)>,
    O: ExactSizeIterator<Item = (u64, [u8; 32])>,
{
    let mut h = blake3::Hasher::new();
    h.update(TXID_DOMAIN_TAG);
    h.update(&chain_id.to_le_bytes());
    h.update(&[meta.version]);
    h.update(&meta.locktime.to_le_bytes());
    h.update(&meta.expiration_height.to_le_bytes());

    h.update(&(inputs.len() as u32).to_le_bytes());
    for (prev_height, prev_output_idx) in inputs {
        h.update(&prev_height.to_le_bytes());
        h.update(&prev_output_idx.to_le_bytes());
    }

    h.update(&(outputs.len() as u32).to_le_bytes());
    for (value, recipient) in outputs {
        h.update(&value.to_le_bytes());
        h.update(&recipient);
    }

    let is_identity_ext = |e: &&ExtensionRecord| e.header.extension_type != CONSENSUS_EXT_VALIDITY_WINDOW;
    let n_ext = extensions.iter().filter(is_identity_ext).count() as u32;
    h.update(&n_ext.to_le_bytes());
    for e in extensions.iter().filter(is_identity_ext) {
        h.update(&e.header.extension_type.to_le_bytes());
        h.update(&e.header.version.to_le_bytes());
        h.update(&(e.payload.len() as u32).to_le_bytes());
        h.update(&e.payload);
    }

    h.finalize().into()
}

impl Transaction {
    /// The validity-window meta this transaction carries (the version is already a u8,
    /// exactly as `ShardBlockBody::from_transactions` encodes it).
    pub fn flat_meta(&self) -> FlatTxMeta {
        FlatTxMeta {
            version: self.version,
            locktime: self.locktime,
            expiration_height: self.expiration_height,
        }
    }

    /// The transaction id on chain `chain_id` (beacon [`BEACON_CHAIN_ID`], shard N
    /// [`shard_chain_id`]`(N)`). Independent of witnesses and block position.
    pub fn txid(&self, chain_id: u16) -> Txid {
        Txid(txid_from_parts(
            chain_id,
            self.flat_meta(),
            self.inputs.iter().map(|i| (i.prev_height, i.prev_output_idx)),
            self.outputs.iter().map(|o| (o.value, o.recipient)),
            &self.extensions,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::blocks::shard_block::ShardBlockBody;
    use crate::transaction::{
        build_producer_stamp_extension, ExtensionHeader, TxInput, TxOutput, WitnessEntry,
    };

    fn golden_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 1, prev_output_idx: 0 }],
            outputs: vec![TxOutput { value: 100, recipient: [7u8; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
            extensions: vec![],
        }
    }

    fn coinbase(value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value, recipient: [1u8; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
            extensions: vec![],
        }
    }

    fn app_ext(byte: u8) -> ExtensionRecord {
        ExtensionRecord {
            header: ExtensionHeader { extension_type: 0x1234, version: 1, payload_length: 1 },
            payload: vec![byte],
        }
    }

    /// Golden vectors. `tools/tx-spammer/src/txid.rs` pins the same two values;
    /// if either changes, update both in the same change.
    #[test]
    fn golden_vectors_beacon_and_shard0() {
        let tx = golden_tx();
        assert_eq!(
            tx.txid(BEACON_CHAIN_ID).to_string(),
            "1596d3459ed17dc2710eb58695fe617493ff0bd7c47e13f2d18fa9ef7673a4d4",
            "txid preimage changed -- update tools/tx-spammer's pinned vector too"
        );
        assert_eq!(
            tx.txid(shard_chain_id(0)).to_string(),
            "929cf0aa7ef34e3f9b5f5262b169d003c037933f1c24aec7aabf0f75d57c1247",
            "txid preimage changed -- update tools/tx-spammer's pinned vector too"
        );
    }

    /// NC-157: `chain_id` is a `u16`. With a `u8`, shard 255 collided with the beacon
    /// (chain id 0) and shard 256 with shard 0, so a transaction signed for one chain was
    /// valid on another. Every shard the network can hold (ids below `MAX_SHARD_MEMPOOL_ID`)
    /// must get its own txid domain.
    #[test]
    fn nc157_every_shard_has_its_own_chain_id_and_txid() {
        let tx = golden_tx();
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(tx.txid(BEACON_CHAIN_ID)));
        for shard in 0..MAX_SHARD_MEMPOOL_ID {
            assert_eq!(shard_chain_id(shard), shard + 1);
            assert!(seen.insert(tx.txid(shard_chain_id(shard))), "shard {shard} collides");
        }
        assert_ne!(tx.txid(shard_chain_id(255)), tx.txid(BEACON_CHAIN_ID));
        assert_ne!(tx.txid(shard_chain_id(256)), tx.txid(shard_chain_id(0)));
    }

    /// VF-3 Phase 1 is not a consensus change: `tx_leaf_hash` / `tx_merkle_root`
    /// must stay byte-identical. The expected root was computed on `main` at
    /// `e67c6422` (before this change) for the same body.
    #[test]
    fn tx_merkle_root_unchanged_from_pre_vf3() {
        let cb = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![TxOutput { value: 50, recipient: [1u8; 32] }],
            locktime: 0,
            expiration_height: 11,
            witnesses: vec![],
            extensions: vec![],
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 1, prev_output_idx: 0 }],
            outputs: vec![TxOutput { value: 100, recipient: [7u8; 32] }],
            locktime: 3,
            expiration_height: 0,
            witnesses: vec![WitnessEntry { witness_data: vec![1u8; 65] }],
            extensions: vec![],
        };
        let body = ShardBlockBody::from_transactions(&[cb, tx], Some("A"));
        assert_eq!(
            hex::encode(body.calculate_tx_merkle_root()),
            "dce7a7ec164d0ba3d58f413d80a3ee39292328345d02b4ae62a57a30c20f4a15"
        );
        // A round trip through to_transactions (stamp now in tx.extensions) keeps it.
        let again = ShardBlockBody::from_transactions(&body.to_transactions().unwrap(), Some("A"));
        assert_eq!(again.calculate_tx_merkle_root(), body.calculate_tx_merkle_root());
    }

    /// VF-3 Phase 2 vectors (design §5 P2.4), built on `golden_tx()`.
    /// Pinned on every side: here, `tools/tx-spammer/src/sign.rs`, the Ledger
    /// app's host test and the `mmr-light-client` copy. Change them together.
    mod sighash_v2_vectors {
        use super::*;
        use crate::common::crypto::{prevouts_hash, sighash_v2};

        const PREVOUT: (u64, [u8; 32]) = (1000, [9u8; 32]);

        fn v2(tx: &Transaction, chain_id: u16, prevouts: &[(u64, [u8; 32])], i: u32) -> String {
            hex::encode(sighash_v2(&tx.txid(chain_id).0, &prevouts_hash(prevouts), i))
        }

        pub(super) fn pinned() -> [String; 6] {
            let tx = golden_tx();
            let mut tx_v2 = golden_tx();
            tx_v2.version = 2;
            let mut with_ext = golden_tx();
            with_ext.extensions.push(app_ext(1));
            let mut two_in = golden_tx();
            two_in.inputs.push(TxInput { prev_height: 2, prev_output_idx: 3 });
            let two_prev = [PREVOUT, (500, [8u8; 32])];
            [
                hex::encode(prevouts_hash(&[PREVOUT])),                  // V1
                v2(&tx, BEACON_CHAIN_ID, &[PREVOUT], 0),                 // V2
                v2(&tx, shard_chain_id(0), &[PREVOUT], 0),               // V3
                v2(&with_ext, shard_chain_id(0), &[PREVOUT], 0),         // V4
                v2(&two_in, shard_chain_id(0), &two_prev, 1),            // V6 input 1
                v2(&tx_v2, shard_chain_id(0), &[PREVOUT], 0),            // V8 = V3 at version 2
            ]
        }

        #[test]
        fn pinned_vectors() {
            assert_eq!(pinned(), [
                "09d0937f5d233942e5bb94d6dadde0d92d43bfff3c7bc178ae2c64c3f792728b".to_string(), // V1
                "d8a8766d6ac64a127729917dc052e354206add9245effc131fef5dee74ce0752".to_string(), // V2
                "40c2e9fe25b385064a95c81b61f7baa129d617bcc0d5514b05953f55b6328f96".to_string(), // V3
                "3e0ff2935ada6ea04f0be68b996790a218af91cf88e1809288b7cf10aebedf74".to_string(), // V4
                "2a8762df4154b5a830a909efba5633556054f854ff8f72aa2491b8c8d1dc5463".to_string(), // V6 i1
                "6b295c3692527389e268448d59c29be251bcb7e70c7f8afd814908d02a5f208d".to_string(), // V8 = V3 at version 2
            ], "sighash v2 preimage changed -- update every mirror (tx-spammer, Ledger, light client)");
        }

        #[test]
        fn relations() {
            let tx = golden_tx();
            let s0 = shard_chain_id(0);
            // V2 vs V3: chain-separated.
            assert_ne!(v2(&tx, BEACON_CHAIN_ID, &[PREVOUT], 0), v2(&tx, s0, &[PREVOUT], 0));
            // V5: an explicit default validity record does not change the sighash.
            let mut explicit = golden_tx();
            explicit.extensions.push(crate::transaction::build_validity_extension(1, 0, 0));
            assert_eq!(v2(&explicit, s0, &[PREVOUT], 0), v2(&tx, s0, &[PREVOUT], 0));
            // V6: each input signs a different hash.
            let mut two_in = golden_tx();
            two_in.inputs.push(TxInput { prev_height: 2, prev_output_idx: 3 });
            let two_prev = [PREVOUT, (500, [8u8; 32])];
            assert_ne!(v2(&two_in, s0, &two_prev, 0), v2(&two_in, s0, &two_prev, 1));
            // V7: a prevout value off by one changes the sighash (Q-P2-1).
            assert_ne!(v2(&tx, s0, &[(1001, [9u8; 32])], 0), v2(&tx, s0, &[PREVOUT], 0));
            // ...and so does a prevout recipient.
            assert_ne!(v2(&tx, s0, &[(1000, [7u8; 32])], 0), v2(&tx, s0, &[PREVOUT], 0));
            // Witnesses are not signed (re-signing keeps the hash).
            let mut signed = golden_tx();
            signed.witnesses = vec![WitnessEntry { witness_data: vec![1u8; 65] }];
            assert_eq!(v2(&signed, s0, &[PREVOUT], 0), v2(&tx, s0, &[PREVOUT], 0));
        }
    }

    #[test]
    fn chain_separation() {
        let tx = golden_tx();
        assert_ne!(tx.txid(BEACON_CHAIN_ID), tx.txid(shard_chain_id(0)));
        assert_ne!(tx.txid(shard_chain_id(0)), tx.txid(shard_chain_id(1)));
    }

    #[test]
    fn resigning_does_not_change_txid() {
        let a = golden_tx();
        let mut b = golden_tx();
        b.witnesses = vec![WitnessEntry { witness_data: vec![0x01; 65] }];
        assert_eq!(a.txid(1), b.txid(1));
    }

    #[test]
    fn explicit_default_validity_record_does_not_change_txid_and_is_refused_in_a_body() {
        // The identifier ignores the validity record, so adding an explicit all-default one cannot
        // change it ...
        let a = golden_tx();
        let mut b = golden_tx();
        b.extensions.push(crate::transaction::build_validity_extension(1, 0, 0));
        assert_eq!(a.txid(1), b.txid(1));

        // ... which is exactly why a block body that carries one is refused (Oct 17, 2026): the same
        // transaction would have two encodings with the same txid and block hash.
        let mut body = ShardBlockBody::from_transactions(&[coinbase(50), golden_tx()], None);
        let before = body.txid_at(1, 1).unwrap();
        assert_eq!(before, golden_tx().txid(1).0);
        let d = body.descriptors[1];
        body.extensions.insert(d.extension_start as usize, crate::transaction::build_validity_extension(1, 0, 0));
        body.descriptors[1].extension_len += 1;
        assert_eq!(body.txid_at(1, 1), None, "the non-canonical record is not parsed");
    }

    #[test]
    fn validity_fields_and_extensions_are_part_of_identity() {
        let base = golden_tx();
        let mut t = golden_tx();
        t.expiration_height = 9;
        assert_ne!(base.txid(1), t.txid(1));
        let mut t = golden_tx();
        t.extensions.push(app_ext(1));
        assert_ne!(base.txid(1), t.txid(1));
        let mut t2 = golden_tx();
        t2.extensions.push(app_ext(2));
        assert_ne!(t.txid(1), t2.txid(1));
    }

    #[test]
    fn same_tx_at_two_positions_same_txid_different_leaf() {
        let tx = golden_tx();
        let b1 = ShardBlockBody::from_transactions(&[coinbase(50), tx.clone()], None);
        let b2 = ShardBlockBody::from_transactions(&[coinbase(60), coinbase(70), tx.clone()], None);
        assert_eq!(b1.txid_at(1, 1), b2.txid_at(2, 1));
        assert_eq!(b1.txid_at(1, 1).unwrap(), tx.txid(1).0);
        assert_ne!(b1.tx_leaf_hash(1), b2.tx_leaf_hash(2));
    }

    #[test]
    fn stamped_coinbase_round_trips_and_matches_slices() {
        let mut stamped = coinbase(50);
        stamped.version = 2;
        stamped.expiration_height = 11;
        let body = ShardBlockBody::from_transactions(&[stamped, golden_tx()], Some("A"));
        let txs = body.to_transactions().unwrap();
        assert_eq!(txs[0].extensions, vec![build_producer_stamp_extension("A").unwrap()]);
        for (i, tx) in txs.iter().enumerate() {
            assert_eq!(body.txid_at(i, 1).unwrap(), tx.txid(1).0, "tx {i}");
        }
        // Rebuilding from the round-tripped txs (stamp now in tx.extensions)
        // reproduces the same leaves and root, with or without the stamp arg.
        let rebuilt = ShardBlockBody::from_transactions(&txs, None);
        assert_eq!(rebuilt.calculate_tx_merkle_root(), body.calculate_tx_merkle_root());
        let rebuilt = ShardBlockBody::from_transactions(&txs, Some("A"));
        assert_eq!(rebuilt.calculate_tx_merkle_root(), body.calculate_tx_merkle_root());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn arb_tx() -> impl Strategy<Value = Transaction> {
            (
                0u8..4,
                0u32..3,
                0u32..3,
                prop::collection::vec((0u32..100, 0u16..8), 0..4),
                prop::collection::vec((0u64..1000, any::<[u8; 32]>()), 1..4),
                prop::collection::vec(any::<u8>(), 0..3),
            )
                .prop_map(|(version, locktime, expiration_height, ins, outs, exts)| Transaction {
                    version,
                    inputs: ins
                        .into_iter()
                        .map(|(h, i)| TxInput { prev_height: h, prev_output_idx: i })
                        .collect(),
                    outputs: outs
                        .into_iter()
                        .map(|(v, r)| TxOutput { value: v, recipient: r })
                        .collect(),
                    locktime,
                    expiration_height,
                    witnesses: vec![],
                    extensions: exts.into_iter().map(app_ext).collect(),
                })
        }

        proptest! {
            /// Standalone txid == txid recomputed from block slices, for every
            /// transaction of a randomized block (design §6 "Equivalence").
            #[test]
            fn standalone_equals_slices(
                txs in prop::collection::vec(arb_tx(), 1..6),
                chain_id in any::<u16>(),
                stamp in prop::option::of(prop::sample::select(vec!["A", "B"])),
            ) {
                let body = ShardBlockBody::from_transactions(&txs, stamp);
                let round = body.to_transactions().unwrap();
                for (i, tx) in round.iter().enumerate() {
                    prop_assert_eq!(body.txid_at(i, chain_id).unwrap(), tx.txid(chain_id).0);
                }
                // Non-coinbase txs keep their identity through the block.
                for (i, tx) in txs.iter().enumerate().skip(1) {
                    prop_assert_eq!(body.txid_at(i, chain_id).unwrap(), tx.txid(chain_id).0);
                }
            }
        }
    }
}
