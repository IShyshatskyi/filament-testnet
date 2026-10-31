//! OPT-APPLY-ALT-DOUBLE-DECODE-1 Phase 0 (Oct 20, 2026): golden bytes + round-trip invariants
//! for the flat shard block body.
//!
//! Records today's exact `tx_merkle_root`, `ShardBlockBody::serialize()` and
//! `ShardWireBlock::encode()` for a spread of bodies (no stamp, stamp A/B, validity record,
//! application extension, multi-input spends with witnesses). Any later step of the plan
//! (stamp-in-coinbase, threading `&ShardBlockBody`, a tiling check) must keep these identical
//! unless the owner approves a wire change.
//!
//! Re-record (only on an owner-approved format change):
//! `cargo test -p common-types --lib print_golden -- --ignored --nocapture`.

use super::*;
use crate::common::crypto::weighted_hash::WeightedHash;
use crate::transaction::{
    build_producer_stamp_extension, ExtensionHeader, ExtensionRecord, Transaction, TxInput,
    TxOutput, WitnessEntry,
};

fn coinbase(stamp: Option<&str>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput { value: 1_000_000, recipient: [0xC0; 32] }],
        locktime: 0,
        expiration_height: 0,
        witnesses: vec![],
        extensions: stamp.map(|s| vec![build_producer_stamp_extension(s).unwrap()]).unwrap_or_default(),
    }
}

fn app_ext(kind: u16, payload: &[u8]) -> ExtensionRecord {
    ExtensionRecord {
        header: ExtensionHeader {
            extension_type: kind,
            version: 1,
            payload_length: payload.len() as u32,
        },
        payload: payload.to_vec(),
    }
}

fn spend(seed: u8, n_in: u32, locktime: u32, expiration_height: u32, ext: Option<ExtensionRecord>) -> Transaction {
    Transaction {
        version: 1,
        inputs: (0..n_in)
            .map(|i| TxInput { prev_height: seed as u32 + i, prev_output_idx: (seed as u16) * 3 + i as u16 })
            .collect(),
        outputs: vec![
            TxOutput { value: 100 + seed as u64, recipient: [seed; 32] },
            TxOutput { value: 900 + seed as u64, recipient: [seed.wrapping_add(1); 32] },
        ],
        locktime,
        expiration_height,
        witnesses: (0..n_in)
            .map(|i| WitnessEntry { witness_data: vec![seed.wrapping_add(i as u8); 64 + i as usize] })
            .collect(),
        extensions: ext.into_iter().collect(),
    }
}

/// `(name, transactions)` — all deterministic, no RNG.
fn cases() -> Vec<(&'static str, Vec<Transaction>)> {
    vec![
        ("cb_plain", vec![coinbase(None)]),
        ("cb_stamp_a", vec![coinbase(Some("A"))]),
        ("cb_stamp_b", vec![coinbase(Some("B"))]),
        (
            "validity_record",
            vec![coinbase(None), spend(1, 1, 5, 1_000, None)],
        ),
        (
            "app_extension",
            vec![coinbase(Some("A")), spend(2, 1, 0, 0, Some(app_ext(0x1234, &[1, 2, 3])))],
        ),
        (
            "multi_input_witnesses",
            vec![
                coinbase(None),
                spend(3, 3, 0, 0, None),
                spend(4, 2, 7, 0, None),
                spend(5, 1, 0, 0, Some(app_ext(0x1FFF, &[9; 5]))),
            ],
        ),
    ]
}

fn header_for(root: [u8; 32]) -> FullShardHeader {
    FullShardHeader::new(
        1,
        WeightedHash([0u8; 32]),
        WeightedHash([0u8; 32]),
        root,
        0x207f_ffff,
        vec![MergedMiningHash::from_active_leaf(&[0u8; 32])],
        0,
        BeaconHeader::new(1, 1_000_000, 0, [0u8; 32].into(), [0u8; 32], 0x207f_ffff, 0, 0, [0u8; 32]),
    )
}

struct Recorded {
    root: String,
    body_hash: String,
    wire_hash: String,
}

fn record(txs: &[Transaction]) -> Recorded {
    let body = ShardBlockBody::from_transactions(txs, None);
    let root = body.calculate_tx_merkle_root();
    let block = Block::new(header_for(root), txs.to_vec());
    let wire = ShardWireBlock::from_block(&block);
    Recorded {
        root: hex::encode(root),
        body_hash: hex::encode(blake3::hash(&body.serialize()).as_bytes()),
        wire_hash: hex::encode(blake3::hash(&wire.encode()).as_bytes()),
    }
}

/// `(name, tx_merkle_root, blake3(body.serialize()), blake3(ShardWireBlock::encode()))`.
const GOLDEN: &[(&str, &str, &str, &str)] = &[
    ("cb_plain",
        "b6c23c8279745093c0744947ef10193bbae7189ad993a26dbcb6dc2754831b91",
        "693d18948212aad03198da0110a8991c777f6bca57da65ceb0bed12c4734c2f0",
        "a0775ce65bf7a7aee5f05ef6fc93169cd90e7f951a892b23d5452d35c7e51400"),
    ("cb_stamp_a",
        "1d34689df4e7bf24de3b3d60b00c4afedb0f70852f9b1e0ccc0d6e62d3bb3bf1",
        "7c01d7596d253cd42c41ebc50e18a3ab80ce7f85423aa3a766d3a41bd9175f78",
        "1f244418953f421526cd044dba2dd3ea4f72458bf33ff8ef5f685bf3a5162a54"),
    ("cb_stamp_b",
        "4daae005339f037a3d1934441001ce24caad2209a7bfa89cfa662a61f6e8a62b",
        "fa2d247035a79a103072e005427abb849aade17b0feaf8887eae6b8838f1546b",
        "45c4d4c6aa26423855fbdec6ca8854cb1757bb97e8106cec03afd51dec94c984"),
    ("validity_record",
        "d8c134907715e30b91058fa19e19545f29d169e62dbd1b020042f7dcc151e6a3",
        "355fa593e317f35f106b8dade9f6c72670e21898c6ce086be5aa6b80e192b869",
        "7cd966e9574b6b6a6856397e9d360f9d4849dd426e148a3c10755b5a1bf82367"),
    ("app_extension",
        "e4eba9adc336fe41021f8f68556e28712417563ab4bf82016a3bef1dfa7ddc4c",
        "5352529ac90335e912db0c2d1f478501c19f94bff7a64678bad3f715e43caa42",
        "ef659704f799954a0a8961eb672f8407c7e76d0873bd60b5eb6de9d38a054af5"),
    ("multi_input_witnesses",
        "a5f3944b406b0ac473b0692bae73c47c0c62c249c7b51fe58f895854d0c3ed92",
        "0d30a90ba4dae3d1c2c32cf90113bb263753257c35d301203911a48829225218",
        "a535be1fcea391a87319185d3ff9c8644ca518d6e9860882a26766305b7c9b44"),
];

#[test]
#[ignore = "prints the golden table; run manually to (re-)record"]
fn print_golden() {
    for (name, txs) in cases() {
        let r = record(&txs);
        println!("    (\"{name}\", \"{}\", \"{}\", \"{}\"),", r.root, r.body_hash, r.wire_hash);
    }
}

#[test]
fn golden_bytes_are_stable() {
    let cases = cases();
    assert_eq!(cases.len(), GOLDEN.len());
    for ((name, txs), (gname, groot, gbody, gwire)) in cases.iter().zip(GOLDEN) {
        assert_eq!(name, gname);
        let r = record(txs);
        assert_eq!(&r.root, groot, "{name}: tx_merkle_root changed");
        assert_eq!(&r.body_hash, gbody, "{name}: ShardBlockBody::serialize() changed");
        assert_eq!(&r.wire_hash, gwire, "{name}: ShardWireBlock::encode() changed");
    }
}

/// The one-rebuild contract (P1): for every case, the single canonical rebuild, the wire body and
/// `flat_body_for_merkle` are byte-identical, and nothing is lost through `Transaction`.
#[test]
fn single_canonical_rebuild_matches_wire_body_and_round_trips() {
    for (name, txs) in cases() {
        let canonical = ShardBlockBody::from_transactions(&txs, None);
        let root = canonical.calculate_tx_merkle_root();
        let canonical_bytes = canonical.serialize();

        // flat_body_for_merkle == the canonical rebuild (no guessing).
        let found = ShardBlockBody::flat_body_for_merkle(&txs, root)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(found.serialize(), canonical_bytes, "{name}: flat_body_for_merkle");

        // from_block's body == the canonical rebuild.
        let block = Block::new(header_for(root), txs.clone());
        let wire = ShardWireBlock::from_block(&block);
        assert_eq!(wire.body.serialize(), canonical_bytes, "{name}: from_block body");

        // encode -> decode -> into_block_with_transactions keeps every byte.
        let decoded = ShardWireBlock::decode(&wire.encode()).unwrap();
        assert_eq!(decoded.body.serialize(), canonical_bytes, "{name}: decode");
        let rebuilt_block = decoded.into_block_with_transactions().unwrap();
        assert!(rebuilt_block.commitment_verified, "{name}");
        assert_eq!(
            ShardBlockBody::from_transactions(&rebuilt_block.transactions, None).serialize(),
            canonical_bytes,
            "{name}: Block.transactions loses nothing"
        );

        // body -> txs -> body is the identity.
        let again = ShardBlockBody::from_transactions(&canonical.to_transactions().unwrap(), None);
        assert_eq!(again.serialize(), canonical_bytes, "{name}: to/from_transactions identity");
    }
}

/// Stamp in `Transaction.extensions` is byte-identical to the old out-of-band `Some(stamp)`.
#[test]
fn stamp_in_coinbase_extensions_equals_out_of_band_stamp() {
    for id in ["A", "B"] {
        let in_tx = ShardBlockBody::from_transactions(&[coinbase(Some(id))], None);
        let out_of_band = ShardBlockBody::from_transactions(&[coinbase(None)], Some(id));
        assert_eq!(in_tx.serialize(), out_of_band.serialize(), "stamp {id}");
    }
}

/// Run `validate_shard_block_body` on `body` with a coinbase-only-friendly empty overlay.
fn validate(body: &ShardBlockBody) -> Result<(), crate::common::validation::ValidationError> {
    use crate::common::utxo::ForkUtxoOverlay;
    use crate::common::validation::transactions::{
        block_validation_utxo, validate_shard_block_body, BlockBodyValidationParams,
    };
    let overlay = ForkUtxoOverlay::new();
    #[cfg(feature = "full-node")]
    let utxo = block_validation_utxo(None, &overlay);
    #[cfg(not(feature = "full-node"))]
    let utxo = block_validation_utxo(&overlay);
    validate_shard_block_body(body, utxo, BlockBodyValidationParams::for_tests(5, 0))
}

fn tile1_reason(r: Result<(), crate::common::validation::ValidationError>) -> String {
    format!("{:?}", r.expect_err("must be rejected"))
}

/// NC-190 / TILE-1: a body with an output no descriptor references has the SAME `tx_merkle_root`
/// as the honest body but different wire bytes, and `to_transactions` would silently drop it.
/// The tiling rule must reject it.
#[test]
fn nc190_unreferenced_output_is_rejected_by_tile_1() {
    use crate::transaction::FlatOutput;

    let honest = ShardBlockBody::from_transactions(&[coinbase(None)], None);
    assert!(validate(&honest).is_ok());

    let mut padded = honest.clone();
    padded.outputs.push(FlatOutput { value: 999_999_999, recipient: [0xEE; 32] });
    // The malleability the rule exists for: the commitment does not see the extra entry.
    assert_eq!(honest.calculate_tx_merkle_root(), padded.calculate_tx_merkle_root());
    assert_ne!(honest.serialize(), padded.serialize());
    assert!(tile1_reason(validate(&padded)).contains("TILE-1"));
}

#[test]
fn tile_1_rejects_gaps_overlaps_reordering_and_leftovers() {
    use crate::transaction::{FlatInput, FlatOutput};
    let txs = vec![coinbase(None), spend(1, 2, 0, 0, None), spend(2, 1, 0, 0, None)];
    let honest = ShardBlockBody::from_transactions(&txs, None);
    // `validate` would fail later on UTXO resolution for spends, so test the rule directly.
    let tile = |b: &ShardBlockBody| {
        crate::common::validation::transactions::check_descriptors_tile(
            b.outputs.len(), b.inputs.len(), b.witnesses.len(), b.extensions.len(), &b.descriptors,
        )
    };
    assert!(tile(&honest).is_ok());

    // gap in the middle of outputs (descriptor 1 starts one entry late)
    let mut b = honest.clone();
    b.outputs.insert(1, FlatOutput { value: 1, recipient: [1; 32] });
    for d in b.descriptors.iter_mut().skip(1) { d.out_start += 1; }
    assert!(format!("{:?}", tile(&b).unwrap_err()).contains("out_start"));

    // overlap: descriptor 2 re-references descriptor 1's inputs
    let mut b = honest.clone();
    b.descriptors[2].in_start = b.descriptors[1].in_start;
    assert!(format!("{:?}", tile(&b).unwrap_err()).contains("in_start"));

    // reordered descriptors
    let mut b = honest.clone();
    b.descriptors.swap(1, 2);
    assert!(tile(&b).is_err());

    // trailing leftovers in each vector
    let mut b = honest.clone();
    b.inputs.push(FlatInput { prev_height: 9, prev_output_idx: 9 });
    assert!(format!("{:?}", tile(&b).unwrap_err()).contains("inputs"));
    let mut b = honest.clone();
    b.witnesses.push(crate::transaction::WitnessEntry { witness_data: vec![1] });
    assert!(format!("{:?}", tile(&b).unwrap_err()).contains("witnesses"));
    let mut b = honest.clone();
    b.extensions.push(app_ext(0x1000, &[1]));
    assert!(format!("{:?}", tile(&b).unwrap_err()).contains("extensions"));

    // no descriptors but non-empty vectors
    let mut b = ShardBlockBody::empty();
    b.outputs.push(FlatOutput { value: 1, recipient: [1; 32] });
    assert!(tile(&b).is_err());
    assert!(tile(&ShardBlockBody::empty()).is_ok());
}

/// Every case in the golden table is a canonical body: it tiles, and validates structurally.
#[test]
fn golden_bodies_satisfy_tile_1() {
    for (name, txs) in cases() {
        let b = ShardBlockBody::from_transactions(&txs, None);
        crate::common::validation::transactions::check_descriptors_tile(
            b.outputs.len(), b.inputs.len(), b.witnesses.len(), b.extensions.len(), &b.descriptors,
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

mod props {
    use super::*;
    use proptest::prelude::*;

    fn arb_tx() -> impl Strategy<Value = Transaction> {
        (
            0u32..3,
            0u32..3,
            prop::collection::vec((0u32..100, 0u16..8), 0..4),
            prop::collection::vec((0u64..1000, any::<[u8; 32]>()), 1..4),
            prop::collection::vec(0x1000u16..0x1010, 0..3),
        )
            .prop_map(|(locktime, exp, ins, outs, exts)| Transaction {
                version: 1,
                witnesses: ins
                    .iter()
                    .map(|(h, _)| WitnessEntry { witness_data: vec![*h as u8; 3] })
                    .collect(),
                inputs: ins
                    .into_iter()
                    .map(|(h, i)| TxInput { prev_height: h, prev_output_idx: i })
                    .collect(),
                outputs: outs
                    .into_iter()
                    .map(|(v, r)| TxOutput { value: v, recipient: r })
                    .collect(),
                locktime,
                expiration_height: exp,
                extensions: exts.into_iter().map(|k| app_ext(k, &[k as u8])).collect(),
            })
    }

    proptest! {
        /// Every body `from_transactions` can produce round-trips exactly through
        /// `Vec<Transaction>`, with or without the stamp argument already folded in.
        #[test]
        fn body_round_trip_is_identity(
            txs in prop::collection::vec(arb_tx(), 1..6),
            stamp in prop::option::of(prop::sample::select(vec!["A", "B"])),
        ) {
            let body = ShardBlockBody::from_transactions(&txs, stamp);
            let back = body.to_transactions().unwrap();
            let again = ShardBlockBody::from_transactions(&back, None);
            prop_assert_eq!(again.serialize(), body.serialize());
            prop_assert_eq!(again.calculate_tx_merkle_root(), body.calculate_tx_merkle_root());
        }
    }
}
