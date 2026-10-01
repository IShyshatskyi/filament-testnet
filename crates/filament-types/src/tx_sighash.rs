// filament-types/src/tx_sighash.rs — per-input signature hash (sighash v2).
//
// Domain-separated by `chain_id` (the sole cross-shard replay protection
// under the single-key address model) and binds the full flat input/output
// set plus the specific input being signed.


// ── VF-3 Phase 2: sighash v2 ───────────────────────────────────────────────
// Mirrors the monorepo's common-types `prevouts_hash` / `sighash_v2`; the
// vectors below are pinned there too. The only sighash: every spend is
// version 2 and signs this (the old v1 preimage was removed before any
// network ran it).

/// `BLAKE3("shisha/prevouts/v1" ‖ n:u32 ‖ [value u64 ‖ recipient [u8;32]] × n)`:
/// the outputs being spent, in input order.
pub fn prevouts_hash(prevouts: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"shisha/prevouts/v1");
    h.update(&(prevouts.len() as u32).to_le_bytes());
    for (value, recipient) in prevouts {
        h.update(&value.to_le_bytes());
        h.update(recipient);
    }
    h.finalize().into()
}

/// `BLAKE3("shisha/sighash/v2" ‖ txid ‖ prevouts_hash ‖ input_index:u32)`.
pub fn sighash_v2(txid: &[u8; 32], prevouts_hash: &[u8; 32], input_index: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"shisha/sighash/v2");
    h.update(txid);
    h.update(prevouts_hash);
    h.update(&input_index.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VF-3 Phase 2 vectors, same values as the monorepo's common-types
    /// `txid.rs::sighash_v2_vectors`. Change them together.
    #[test]
    fn sighash_v2_matches_node_vectors() {
        use crate::transaction_impl::{Transaction, TxInput, TxOutput};
        use crate::txid::{shard_chain_id, txid_from_parts};
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 1, prev_output_idx: 0 }],
            outputs: vec![TxOutput { value: 100, recipient: [7u8; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
        };
        let prevout = (1000u64, [9u8; 32]);
        let v2 = |tx: &Transaction, chain: u8, prev: &[(u64, [u8; 32])], i: u32| {
            hex::encode(sighash_v2(&tx.txid(chain).0, &prevouts_hash(prev), i))
        };
        assert_eq!(hex::encode(prevouts_hash(&[prevout])),
            "09d0937f5d233942e5bb94d6dadde0d92d43bfff3c7bc178ae2c64c3f792728b"); // V1
        assert_eq!(v2(&tx, 0, &[prevout], 0),
            "29040a0c4b83d7efa694c55b80819d6510c4d7de52468eb15d893dab489575e0"); // V2
        assert_eq!(v2(&tx, shard_chain_id(0), &[prevout], 0),
            "86d63eed241a2f51da83dbd88338af85da3f6273eeab9c4ef72f3b1c11490c07"); // V3
        // V4: + application extension 0x1234 v1 payload [1].
        let txid_ext = txid_from_parts(1, 1, 0, 0, &[(1, 0)], &[(100, [7u8; 32])], &[(0x1234, 1, &[1u8][..])]);
        assert_eq!(hex::encode(sighash_v2(&txid_ext, &prevouts_hash(&[prevout]), 0)),
            "e7ceed183d08c7159d605e41e748125e1d5d266b76551dc417e0578ce5a12725"); // V4
        let mut tx2 = tx.clone();
        tx2.version = 2;
        assert_eq!(v2(&tx2, shard_chain_id(0), &[prevout], 0),
            "2af357d9c002f6689aff8fb954f4478e1671b0e52afe3f87b0ee253b749fdd91"); // V8
        tx.inputs.push(TxInput { prev_height: 2, prev_output_idx: 3 });
        assert_eq!(v2(&tx, shard_chain_id(0), &[prevout, (500, [8u8; 32])], 1),
            "debff03beb83f3ec41f88b3a199062fdf6428451ce3417bc3e7124e08b8e6b78"); // V6 input 1
    }
}
