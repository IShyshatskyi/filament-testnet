//! VF-3 Phase 1 — the one transaction id. Mirrors the private monorepo's
//! `common-types/src/transaction/txid.rs` byte for byte.
//!
//! ```text
//! txid = BLAKE3( "shisha/txid/v1"
//!              ‖ chain_id : u8      // beacon 0, shard N → N+1
//!              ‖ version  : u8      // clamped to u8
//!              ‖ locktime : u32 LE ‖ expiration_height : u32 LE
//!              ‖ n_inputs  : u32 LE ‖ [prev_height u32 LE ‖ prev_output_idx u16 LE] × n
//!              ‖ n_outputs : u32 LE ‖ [value u64 LE ‖ recipient [u8;32]] × m
//!              ‖ n_ext     : u32 LE ‖ [type u16 LE ‖ version u16 LE ‖ len u32 LE ‖ payload] × k )
//! ```
//!
//! Independent of witnesses and block position. Validity-window records are
//! never hashed as records. This crate's `Transaction` carries no extensions,
//! so `Transaction::txid` hashes `n_ext = 0`; `txid_from_parts` takes
//! extensions for callers that have them.

use crate::transaction_impl::{Transaction, Txid};

/// Domain tag prefixed to every txid preimage.
pub const TXID_DOMAIN_TAG: &[u8] = b"shisha/txid/v1";

/// Extension type of the consensus validity-window record (not hashed).
pub const CONSENSUS_EXT_VALIDITY_WINDOW: u16 = 0x0001;

/// `chain_id` of the beacon chain.
pub const BEACON_CHAIN_ID: u8 = 0;

/// `chain_id` of shard `shard_id` (shard N → N+1), the same convention every
/// signature preimage uses.
pub fn shard_chain_id(shard_id: u16) -> u8 {
    shard_id.wrapping_add(1) as u8
}

/// One extension record as hashed into the txid: `(type, version, payload)`.
pub type ExtensionParts<'a> = (u16, u16, &'a [u8]);

/// Hash the canonical txid preimage.
pub fn txid_from_parts(
    chain_id: u8,
    version: u8,
    locktime: u32,
    expiration_height: u32,
    inputs: &[(u32, u16)],
    outputs: &[(u64, [u8; 32])],
    extensions: &[ExtensionParts<'_>],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TXID_DOMAIN_TAG);
    h.update(&[chain_id, version]);
    h.update(&locktime.to_le_bytes());
    h.update(&expiration_height.to_le_bytes());

    h.update(&(inputs.len() as u32).to_le_bytes());
    for (prev_height, prev_output_idx) in inputs {
        h.update(&prev_height.to_le_bytes());
        h.update(&prev_output_idx.to_le_bytes());
    }

    h.update(&(outputs.len() as u32).to_le_bytes());
    for (value, recipient) in outputs {
        h.update(&value.to_le_bytes());
        h.update(recipient);
    }

    let hashed: Vec<_> = extensions
        .iter()
        .filter(|(t, _, _)| *t != CONSENSUS_EXT_VALIDITY_WINDOW)
        .collect();
    h.update(&(hashed.len() as u32).to_le_bytes());
    for (t, v, payload) in hashed {
        h.update(&t.to_le_bytes());
        h.update(&v.to_le_bytes());
        h.update(&(payload.len() as u32).to_le_bytes());
        h.update(payload);
    }

    h.finalize().into()
}

impl Transaction {
    /// The transaction id on chain `chain_id` (beacon [`BEACON_CHAIN_ID`],
    /// shard N [`shard_chain_id`]`(N)`).
    pub fn txid(&self, chain_id: u8) -> Txid {
        let inputs: Vec<_> = self.inputs.iter().map(|i| (i.prev_height, i.prev_output_idx)).collect();
        let outputs: Vec<_> = self.outputs.iter().map(|o| (o.value, o.recipient)).collect();
        Txid(txid_from_parts(
            chain_id,
            self.version.min(u32::from(u8::MAX)) as u8,
            self.locktime,
            self.expiration_height,
            &inputs,
            &outputs,
            &[],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_impl::{TxInput, TxOutput, WitnessEntry};

    fn golden_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 1, prev_output_idx: 0 }],
            outputs: vec![TxOutput { value: 100, recipient: [7u8; 32] }],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![],
        }
    }

    /// Same values the monorepo's common-types and tools/tx-spammer pin.
    #[test]
    fn golden_vectors_beacon_and_shard0() {
        let tx = golden_tx();
        assert_eq!(
            hex::encode(tx.txid(BEACON_CHAIN_ID).0),
            "33acdb7a33c59a15862014ba4eb895e77655470fb7d17127ce7b9ac5a60c2d25"
        );
        assert_eq!(
            hex::encode(tx.txid(shard_chain_id(0)).0),
            "84a4d093da52d86c4b02b347127ea27dfa80366702b570664595d82a1de0b202"
        );
    }

    #[test]
    fn witnesses_do_not_change_txid() {
        let mut b = golden_tx();
        b.witnesses = vec![WitnessEntry { witness_data: vec![1u8; 65] }];
        assert_eq!(golden_tx().txid(1), b.txid(1));
    }

    #[test]
    fn validity_record_is_not_hashed_but_others_are() {
        let tx = golden_tx();
        let base = tx.txid(1).0;
        let ins = [(1u32, 0u16)];
        let outs = [(100u64, [7u8; 32])];
        let validity = [(CONSENSUS_EXT_VALIDITY_WINDOW, 1u16, &[0u8; 9][..])];
        assert_eq!(txid_from_parts(1, 1, 0, 0, &ins, &outs, &validity), base);
        let app = [(0x1234u16, 1u16, &[1u8][..])];
        assert_ne!(txid_from_parts(1, 1, 0, 0, &ins, &outs, &app), base);
    }
}
