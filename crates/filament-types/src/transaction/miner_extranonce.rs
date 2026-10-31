//! Miner extranonce carried in the beacon coinbase (CB-1, Stratum
//! `Stratum_Extranonce_Binding_Plan.md`).
//!
//! Consensus extension `0x0002` on transaction index 0 (the coinbase) carries
//! an 8-byte payload: 4-byte pool-assigned `extranonce1` (fixed for the
//! lifetime of a Stratum session) followed by 4-byte miner-rolled
//! `extranonce2`. Changing either half changes the coinbase txid, which
//! changes `tx_merkle_root`, which changes `commitment_hash`, which changes
//! the PoW hash — the same mechanism Bitcoin uses to bind extranonce via its
//! coinbase, without this codebase adopting a scriptSig-style arbitrary byte
//! field it deliberately doesn't otherwise have.
//!
//! Consensus (not Application, unlike the TS-T-11 producer stamp): every real
//! beacon block will carry exactly one of these once wired in, so its
//! presence/shape is a structural rule any node can check independently (see
//! `validate_coinbase_extensions` in `flat_tx_meta.rs` for the "allowed on any
//! coinbase" shape check, and `full_beacon_chain.rs`'s beacon-only Tier 3 for
//! the "beacon requires exactly one" rule — this module intentionally does not
//! enforce "required," since shard coinbases pass through the same shared
//! extension validator and must not be forced to carry this).

use crate::common::validation::ValidationError;
use crate::transaction::{ExtensionHeader, ExtensionRecord};

/// Consensus extension type: miner extranonce (`extranonce1 ‖ extranonce2`).
pub const CONSENSUS_EXT_MINER_EXTRANONCE: u16 = 0x0002;

pub const MINER_EXTRANONCE_VERSION: u16 = 1;

/// Payload length: 4-byte extranonce1 + 4-byte extranonce2.
pub const MINER_EXTRANONCE_PAYLOAD_LEN: usize = 8;

/// Build the miner-extranonce extension record for a coinbase transaction.
pub fn build_miner_extranonce_extension(
    extranonce1: [u8; 4],
    extranonce2: [u8; 4],
) -> ExtensionRecord {
    let mut payload = Vec::with_capacity(MINER_EXTRANONCE_PAYLOAD_LEN);
    payload.extend_from_slice(&extranonce1);
    payload.extend_from_slice(&extranonce2);
    ExtensionRecord {
        header: ExtensionHeader {
            extension_type: CONSENSUS_EXT_MINER_EXTRANONCE,
            version: MINER_EXTRANONCE_VERSION,
            payload_length: MINER_EXTRANONCE_PAYLOAD_LEN as u32,
        },
        payload,
    }
}

/// Parse `(extranonce1, extranonce2)` from a single extension record.
///
/// Returns `Err` if the record is not a well-formed miner-extranonce record
/// (wrong type, wrong version, or wrong payload length) — callers that have
/// already filtered by `extension_type == CONSENSUS_EXT_MINER_EXTRANONCE`
/// still need this to reject a malformed payload, not just a wrong type.
pub fn parse_miner_extranonce_record(
    ext: &ExtensionRecord,
) -> Result<([u8; 4], [u8; 4]), ValidationError> {
    if ext.header.extension_type != CONSENSUS_EXT_MINER_EXTRANONCE {
        return Err(ValidationError::InvalidTransaction {
            reason: format!(
                "parse_miner_extranonce_record: wrong extension type 0x{:04x}",
                ext.header.extension_type
            ),
        });
    }
    if ext.header.version != MINER_EXTRANONCE_VERSION {
        return Err(ValidationError::InvalidTransaction {
            reason: format!(
                "miner extranonce version {} (expected {})",
                ext.header.version, MINER_EXTRANONCE_VERSION
            ),
        });
    }
    if ext.payload.len() != MINER_EXTRANONCE_PAYLOAD_LEN {
        return Err(ValidationError::InvalidTransaction {
            reason: format!(
                "miner extranonce payload length {} (expected {})",
                ext.payload.len(),
                MINER_EXTRANONCE_PAYLOAD_LEN
            ),
        });
    }
    let mut extranonce1 = [0u8; 4];
    let mut extranonce2 = [0u8; 4];
    extranonce1.copy_from_slice(&ext.payload[0..4]);
    extranonce2.copy_from_slice(&ext.payload[4..8]);
    Ok((extranonce1, extranonce2))
}

/// Scan a coinbase's extension range for the miner-extranonce record.
///
/// Mirrors `producer_stamp::parse_producer_stamp_for_tx`'s scan pattern.
/// Returns `None` if absent (e.g. a shard coinbase, or a beacon block mined
/// before this extension existed) rather than an error — presence is
/// enforced separately as a beacon-only structural rule, not by this parser.
pub fn find_miner_extranonce_for_tx(
    body: &crate::common::blocks::ShardBlockBody,
    tx_idx: usize,
) -> Option<([u8; 4], [u8; 4])> {
    let desc = body.descriptors.get(tx_idx)?;
    let start = desc.extension_start as usize;
    let end = start + desc.extension_len as usize;
    body.extensions
        .get(start..end)?
        .iter()
        .find(|ext| ext.header.extension_type == CONSENSUS_EXT_MINER_EXTRANONCE)
        .and_then(|ext| parse_miner_extranonce_record(ext).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::blocks::ShardBlockBody;
    use crate::transaction::{Transaction, TxOutput};

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
    fn build_and_parse_round_trip() {
        let ext = build_miner_extranonce_extension([1, 2, 3, 4], [5, 6, 7, 8]);
        let (e1, e2) = parse_miner_extranonce_record(&ext).unwrap();
        assert_eq!(e1, [1, 2, 3, 4]);
        assert_eq!(e2, [5, 6, 7, 8]);
    }

    #[test]
    fn parse_rejects_wrong_type() {
        let mut ext = build_miner_extranonce_extension([0; 4], [0; 4]);
        ext.header.extension_type = 0x0001;
        assert!(parse_miner_extranonce_record(&ext).is_err());
    }

    #[test]
    fn parse_rejects_wrong_payload_len() {
        let mut ext = build_miner_extranonce_extension([0; 4], [0; 4]);
        ext.payload.push(0xFF);
        ext.header.payload_length = ext.payload.len() as u32;
        assert!(parse_miner_extranonce_record(&ext).is_err());
    }

    #[test]
    fn extranonce_changes_merkle_root() {
        let tx = coinbase_tx();
        let mut body_a = ShardBlockBody::from_transactions(&[tx.clone()], None);
        let ext_a = build_miner_extranonce_extension([1, 0, 0, 0], [0, 0, 0, 0]);
        body_a.extensions.push(ext_a);
        body_a.descriptors[0].extension_len += 1;

        let mut body_b = ShardBlockBody::from_transactions(&[tx], None);
        let ext_b = build_miner_extranonce_extension([2, 0, 0, 0], [0, 0, 0, 0]);
        body_b.extensions.push(ext_b);
        body_b.descriptors[0].extension_len += 1;

        assert_ne!(body_a.calculate_tx_merkle_root(), body_b.calculate_tx_merkle_root());
    }

    #[test]
    fn find_miner_extranonce_for_tx_roundtrips() {
        let tx = coinbase_tx();
        let mut body = ShardBlockBody::from_transactions(&[tx], None);
        let ext = build_miner_extranonce_extension([9, 9, 9, 9], [1, 1, 1, 1]);
        body.extensions.push(ext);
        body.descriptors[0].extension_len += 1;

        let (e1, e2) = find_miner_extranonce_for_tx(&body, 0).unwrap();
        assert_eq!(e1, [9, 9, 9, 9]);
        assert_eq!(e2, [1, 1, 1, 1]);
    }

    #[test]
    fn find_miner_extranonce_absent_returns_none() {
        let tx = coinbase_tx();
        let body = ShardBlockBody::from_transactions(&[tx], None);
        assert!(find_miner_extranonce_for_tx(&body, 0).is_none());
    }
}
