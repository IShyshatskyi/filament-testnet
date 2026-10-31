//! Testnet-stress producer identity stamped into coinbase extensions (TS-T-11).
//!
//! Application extension `0x1001` on transaction index 0 carries a single-byte
//! payload (`b'A'` or `b'B'`) so fair-share can be verified from chain data.

use crate::common::blocks::shard_block::ShardBlockBody;
use crate::transaction::{ExtensionHeader, ExtensionRecord};

/// Application extension type for block-producer identity.
pub const APPLICATION_EXT_PRODUCER_ID: u16 = 0x1001;

pub const PRODUCER_STAMP_VERSION: u16 = 1;

/// Returns true for testnet-stress producer labels `"A"` and `"B"`.
pub fn is_valid_producer_id(id: &str) -> bool {
    matches!(id, "A" | "B")
}

/// Build a producer-stamp extension record, or `None` when `id` is invalid.
pub fn build_producer_stamp_extension(producer_id: &str) -> Option<ExtensionRecord> {
    if !is_valid_producer_id(producer_id) {
        return None;
    }
    let byte = producer_id.as_bytes()[0];
    Some(ExtensionRecord {
        header: ExtensionHeader {
            extension_type: APPLICATION_EXT_PRODUCER_ID,
            version: PRODUCER_STAMP_VERSION,
            payload_length: 1,
        },
        payload: vec![byte],
    })
}

/// Parse producer id from a flat body coinbase (descriptor index 0).
pub fn parse_producer_stamp(body: &ShardBlockBody) -> Option<String> {
    parse_producer_stamp_for_tx(body, 0)
}

/// Parse producer id from a specific transaction descriptor index.
pub fn parse_producer_stamp_for_tx(body: &ShardBlockBody, tx_idx: usize) -> Option<String> {
    let desc = body.descriptors.get(tx_idx)?;
    let start = desc.extension_start as usize;
    let end = start + desc.extension_len as usize;
    for ext in body.extensions.get(start..end)? {
        if ext.header.extension_type != APPLICATION_EXT_PRODUCER_ID {
            continue;
        }
        if ext.payload.len() == 1 {
            let c = ext.payload[0] as char;
            if c == 'A' || c == 'B' {
                return Some(c.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::blocks::shard_block::ShardBlockBody;
    use crate::transaction::{TxOutput, Transaction};

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            locktime: 0,
            expiration_height: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 100,
                recipient: [0xAA; 32],
            }],
            witnesses: vec![],
            extensions: Vec::new(),
        }
    }

    #[test]
    fn producer_stamp_changes_merkle_root() {
        let tx = coinbase_tx();
        let root_plain = ShardBlockBody::from_transactions(&[tx.clone()], None)
            .calculate_tx_merkle_root();
        let root_a = ShardBlockBody::from_transactions(&[tx], Some("A"))
            .calculate_tx_merkle_root();
        assert_ne!(root_plain, root_a);
    }

    #[test]
    fn flat_body_for_merkle_finds_stamp_carried_in_tx_extensions() {
        let mut tx = coinbase_tx();
        tx.extensions.push(build_producer_stamp_extension("B").unwrap());
        let expected = ShardBlockBody::from_transactions(&[tx.clone()], None)
            .calculate_tx_merkle_root();
        let body = ShardBlockBody::flat_body_for_merkle(&[tx], expected).unwrap();
        assert_eq!(parse_producer_stamp(&body).as_deref(), Some("B"));
    }

    /// OPT-APPLY-ALT-DOUBLE-DECODE-1 P1: the stamp is no longer guessed. A stamp applied only
    /// out of band (not in `tx.extensions`) does not match; local mining puts it in the coinbase.
    #[test]
    fn flat_body_for_merkle_does_not_guess_out_of_band_stamp() {
        let tx = coinbase_tx();
        let expected = ShardBlockBody::from_transactions(&[tx.clone()], Some("B"))
            .calculate_tx_merkle_root();
        assert!(ShardBlockBody::flat_body_for_merkle(&[tx], expected).is_err());
    }

    /// Out-of-band `Some(stamp)` and stamp-in-`tx.extensions` produce byte-identical bodies:
    /// moving the stamp into the coinbase transaction changes no consensus bytes.
    #[test]
    fn stamp_in_tx_extensions_is_byte_identical_to_out_of_band_stamp() {
        for id in ["A", "B"] {
            let out_of_band = ShardBlockBody::from_transactions(&[coinbase_tx()], Some(id));
            let mut tx = coinbase_tx();
            tx.extensions.push(build_producer_stamp_extension(id).unwrap());
            let in_tx = ShardBlockBody::from_transactions(&[tx], None);
            assert_eq!(out_of_band.serialize(), in_tx.serialize());
            assert_eq!(out_of_band.calculate_tx_merkle_root(), in_tx.calculate_tx_merkle_root());
        }
    }

    #[test]
    fn parse_producer_stamp_roundtrip() {
        let tx = coinbase_tx();
        let body = ShardBlockBody::from_transactions(&[tx], Some("A"));
        assert_eq!(parse_producer_stamp(&body).as_deref(), Some("A"));
    }
}
