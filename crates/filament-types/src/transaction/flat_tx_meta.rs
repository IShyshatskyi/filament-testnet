//! Consensus extension encoding for flat-body transaction validity (TE-1/2/3).

use crate::common::validation::ValidationError;
use crate::transaction::producer_stamp::{
    APPLICATION_EXT_PRODUCER_ID, PRODUCER_STAMP_VERSION,
};
use crate::transaction::{ExtensionHeader, ExtensionRecord, TransactionDescriptor};

/// Consensus extension type: per-transaction validity window metadata.
pub const CONSENSUS_EXT_VALIDITY_WINDOW: u16 = 0x0001;

/// Payload: version(u8) || locktime(u32 LE) || expiration_height(u32 LE).
pub const VALIDITY_EXTENSION_PAYLOAD_LEN: usize = 9;

/// Per-transaction metadata carried in `ShardBlockBody::extensions[]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatTxMeta {
    pub version: u8,
    pub locktime: u32,
    pub expiration_height: u32,
}

impl Default for FlatTxMeta {
    fn default() -> Self {
        Self {
            version: 1,
            locktime: 0,
            expiration_height: 0,
        }
    }
}

/// Returns true when a validity extension record is required on the wire.
pub fn needs_validity_extension(version: u8, locktime: u32, expiration_height: u32) -> bool {
    version != 1 || locktime != 0 || expiration_height != 0
}

/// The only `ExtensionHeader.version` a validity-window record may carry (VF-2).
pub const VALIDITY_EXTENSION_HEADER_VERSION: u16 = 1;

/// Build a consensus validity-window extension record.
pub fn build_validity_extension(
    version: u8,
    locktime: u32,
    expiration_height: u32,
) -> ExtensionRecord {
    let mut payload = Vec::with_capacity(VALIDITY_EXTENSION_PAYLOAD_LEN);
    payload.push(version);
    payload.extend_from_slice(&locktime.to_le_bytes());
    payload.extend_from_slice(&expiration_height.to_le_bytes());
    ExtensionRecord {
        header: ExtensionHeader {
            extension_type: CONSENSUS_EXT_VALIDITY_WINDOW,
            version: VALIDITY_EXTENSION_HEADER_VERSION,
            payload_length: VALIDITY_EXTENSION_PAYLOAD_LEN as u32,
        },
        payload,
    }
}

fn extension_slice<'a>(
    extensions: &'a [ExtensionRecord],
    range: &TransactionDescriptor,
) -> Result<&'a [ExtensionRecord], ValidationError> {
    if range.extension_len == 0 {
        return Ok(&[]);
    }
    let start = range.extension_start as usize;
    let end = start
        .checked_add(range.extension_len as usize)
        .filter(|&e| e <= extensions.len())
        .ok_or_else(|| ValidationError::InvalidTransaction {
            reason: "validity extension index out of bounds".into(),
        })?;
    Ok(&extensions[start..end])
}

fn parse_validity_extension_record(ext: &ExtensionRecord) -> Result<FlatTxMeta, ValidationError> {
    // VF-2: the record's header version must be 1. Since the txid unification the txid hashes the
    // PARSED validity meta (version, lock time, expiry) and skips this record altogether, so its header
    // version is in neither the txid nor the sighash: a relayer could set any value and the transaction
    // would stay valid with the same txid, giving the same block (same tx_merkle_root, same block
    // hash) different body bytes. Pinning the value closes that byte-level malleation.
    if ext.header.version != VALIDITY_EXTENSION_HEADER_VERSION {
        return Err(ValidationError::InvalidTransaction {
            reason: format!(
                "validity extension header version {} (expected {})",
                ext.header.version, VALIDITY_EXTENSION_HEADER_VERSION
            ),
        });
    }
    if ext.payload.len() != VALIDITY_EXTENSION_PAYLOAD_LEN {
        return Err(ValidationError::InvalidTransaction {
            reason: format!(
                "validity extension payload length {} (expected {})",
                ext.payload.len(),
                VALIDITY_EXTENSION_PAYLOAD_LEN
            ),
        });
    }

    let meta = FlatTxMeta {
        version: ext.payload[0],
        locktime: u32::from_le_bytes(ext.payload[1..5].try_into().unwrap()),
        expiration_height: u32::from_le_bytes(ext.payload[5..9].try_into().unwrap()),
    };
    // Canonical encoding (Oct 17, 2026): a record that only repeats the defaults means exactly what
    // omitting it means and gives the same txid, so allowing both would let a relayer add or remove
    // it and change the block's body bytes without touching its hash.
    if !needs_validity_extension(meta.version, meta.locktime, meta.expiration_height) {
        return Err(ValidationError::InvalidTransaction {
            reason: "validity extension repeats the defaults (version 1, no lock time, no expiry): \
                     omit the record instead"
                .into(),
        });
    }
    Ok(meta)
}

/// First extension type of the application range. Types below it are consensus types: every node must
/// understand them, so an unknown one is refused. Types from here up are committed to the chain (they
/// are in the txid, so they are signed) but not interpreted by consensus: unknown ones pass through.
pub const APPLICATION_EXT_RANGE_START: u16 = 0x1000;

/// Parse validity metadata for one non-coinbase descriptor from the block extension slice.
///
/// Extension policy (owner-approved Oct 17, 2026; `BV_PROTO_1_Block_Versioning_Research.md` VF-2):
/// - the validity-window record (type 0x0001) is optional, at most once, must be the FIRST record
///   of the descriptor (its position is not in the txid, so a free position would be another
///   body-byte malleation), must have header version 1 and must not merely repeat the defaults;
/// - any other CONSENSUS type (below [`APPLICATION_EXT_RANGE_START`]) is refused: a node cannot
///   validate what it does not understand;
/// - APPLICATION types pass through unvalidated, whatever their version: they are in the txid and
///   therefore signed, but consensus does not interpret them (short-address hints, invoice
///   references, ...). A known application type may still be checked by whoever reads it.
pub fn parse_flat_tx_meta(
    extensions: &[ExtensionRecord],
    range: &TransactionDescriptor,
) -> Result<FlatTxMeta, ValidationError> {
    let slice = extension_slice(extensions, range)?;
    let mut meta = FlatTxMeta::default();
    for (i, ext) in slice.iter().enumerate() {
        match ext.header.extension_type {
            CONSENSUS_EXT_VALIDITY_WINDOW => {
                if i != 0 {
                    return Err(ValidationError::InvalidTransaction {
                        reason: "validity extension must be the first record of the transaction (and appear once)".into(),
                    });
                }
                meta = parse_validity_extension_record(ext)?;
            }
            t if t < APPLICATION_EXT_RANGE_START => {
                return Err(ValidationError::InvalidTransaction {
                    reason: format!("unknown consensus extension type 0x{t:04x} on a transaction"),
                });
            }
            _ => {} // application range: pass through
        }
    }
    Ok(meta)
}

/// Like [`parse_flat_tx_meta`], but scans the descriptor's extension range for
/// a validity-window record instead of requiring it to be the sole entry.
/// Other extensions (e.g. TS-T-11 producer stamp `0x1001` on coinbase) are
/// ignored here — validate them separately via [`validate_coinbase_extensions`].
pub fn parse_flat_tx_meta_scan(
    extensions: &[ExtensionRecord],
    range: &TransactionDescriptor,
) -> Result<FlatTxMeta, ValidationError> {
    let slice = extension_slice(extensions, range)?;
    slice
        .iter()
        .find(|e| e.header.extension_type == CONSENSUS_EXT_VALIDITY_WINDOW)
        .map(parse_validity_extension_record)
        .transpose()
        .map(|meta| meta.unwrap_or_default())
}

/// Validate extensions on a coinbase transaction (descriptor index 0).
///
/// Allows an optional TS-T-11 producer stamp (`0x1001`), an optional CB-1
/// miner-extranonce record (`0x0002`), alongside an optional default
/// validity-window record. Rejects non-default locktime/expiration on
/// coinbase and any other extension types.
///
/// This function is shared by shard *and* beacon coinbase validation
/// (`validate_block_body`'s `is_coinbase` branch runs for both chain types).
/// It therefore only checks the *shape* of a miner-extranonce record when one
/// is present — it does not require one. "Beacon blocks must carry exactly
/// one" is a beacon-only structural rule (CB-2), enforced separately in
/// `FullBeaconChain::validate_block`'s Tier 3, not here — a shard coinbase
/// must never be forced to carry this extension.
pub fn validate_coinbase_extensions(
    extensions: &[ExtensionRecord],
    range: &TransactionDescriptor,
) -> Result<(), ValidationError> {
    let slice = extension_slice(extensions, range)?;
    let mut stamp_count = 0u8;
    let mut extranonce_count = 0u8;

    for ext in slice {
        match ext.header.extension_type {
            CONSENSUS_EXT_VALIDITY_WINDOW => {
                let meta = parse_validity_extension_record(ext)?;
                if meta.locktime != 0 || meta.expiration_height != 0 {
                    return Err(ValidationError::InvalidTransaction {
                        reason: "coinbase must not carry validity-window metadata".into(),
                    });
                }
            }
            APPLICATION_EXT_PRODUCER_ID => {
                stamp_count += 1;
                if stamp_count > 1 {
                    return Err(ValidationError::InvalidTransaction {
                        reason: "coinbase: at most one producer-stamp extension".into(),
                    });
                }
                if ext.header.version != PRODUCER_STAMP_VERSION {
                    return Err(ValidationError::InvalidTransaction {
                        reason: format!(
                            "producer stamp version {} (expected {})",
                            ext.header.version, PRODUCER_STAMP_VERSION
                        ),
                    });
                }
                if ext.payload.len() != 1 || (ext.payload[0] != b'A' && ext.payload[0] != b'B') {
                    return Err(ValidationError::InvalidTransaction {
                        reason: "producer stamp payload must be b'A' or b'B'".into(),
                    });
                }
            }
            CONSENSUS_EXT_MINER_EXTRANONCE => {
                extranonce_count += 1;
                if extranonce_count > 1 {
                    return Err(ValidationError::InvalidTransaction {
                        reason: "coinbase: at most one miner-extranonce extension".into(),
                    });
                }
                crate::transaction::miner_extranonce::parse_miner_extranonce_record(ext)?;
            }
            other => {
                return Err(ValidationError::InvalidTransaction {
                    reason: format!("unexpected extension type 0x{:04x} on coinbase", other),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod vf2_tests {
    use super::*;

    fn descriptor(ext_len: u16) -> TransactionDescriptor {
        TransactionDescriptor {
            out_start: 0,
            out_len: 0,
            in_start: 0,
            in_len: 0,
            witness_start: 0,
            witness_len: 0,
            extension_start: 0,
            extension_len: ext_len,
        }
    }

    /// VF-2: the validity record's header version is covered by neither the txid nor the sighash, so a
    /// validity record with any version but 1 must be refused, or a relayer could change the byte
    /// without invalidating the transaction (same txid, same block hash, different body bytes).
    #[test]
    fn vf2_validity_window_requires_header_version_1() {
        let good = build_validity_extension(2, 10, 100);
        assert!(parse_flat_tx_meta(&[good.clone()], &descriptor(1)).is_ok());
        assert!(parse_flat_tx_meta_scan(&[good.clone()], &descriptor(1)).is_ok());

        for v in [0u16, 2, 7, u16::MAX] {
            let mut bad = good.clone();
            bad.header.version = v;
            assert!(
                parse_flat_tx_meta(&[bad.clone()], &descriptor(1)).is_err(),
                "strict parse must refuse header version {v}"
            );
            assert!(
                parse_flat_tx_meta_scan(&[bad], &descriptor(1)).is_err(),
                "scan parse must refuse header version {v}"
            );
        }
    }

    // ── extension policy (owner-approved Oct 17, 2026) ──────────────────────────────────────

    fn app_record(ty: u16, version: u16, payload: &[u8]) -> ExtensionRecord {
        ExtensionRecord {
            header: ExtensionHeader { extension_type: ty, version, payload_length: payload.len() as u32 },
            payload: payload.to_vec(),
        }
    }

    /// An explicit all-default validity record means the same as no record and gives the same txid, so
    /// it is refused on every path (non-coinbase, scan, coinbase).
    #[test]
    fn explicit_default_validity_record_is_refused_everywhere() {
        let default_record = build_validity_extension(1, 0, 0);
        assert!(parse_flat_tx_meta(&[default_record.clone()], &descriptor(1)).is_err());
        assert!(parse_flat_tx_meta_scan(&[default_record.clone()], &descriptor(1)).is_err());
        assert!(validate_coinbase_extensions(&[default_record], &descriptor(1)).is_err());
        // a record that says something is fine
        for rec in [build_validity_extension(1, 5, 0), build_validity_extension(1, 0, 9)] {
            assert!(parse_flat_tx_meta(&[rec], &descriptor(1)).is_ok());
        }
    }

    /// Unknown CONSENSUS types are refused, APPLICATION types pass through (any version), and the
    /// validity record must be the first record and appear once.
    #[test]
    fn extension_policy_unknown_consensus_rejects_application_passes_validity_first() {
        let validity = build_validity_extension(2, 5, 0);
        // unknown consensus type
        assert!(parse_flat_tx_meta(&[app_record(0x0003, 1, b"x")], &descriptor(1)).is_err());
        // the coinbase-only extranonce type (0x0002) is a consensus type too: not allowed on a spend
        assert!(parse_flat_tx_meta(&[app_record(0x0002, 1, &[0; 8])], &descriptor(1)).is_err());
        // application types pass through, with any version and payload
        assert_eq!(parse_flat_tx_meta(&[app_record(0x2000, 7, b"hint")], &descriptor(1)).unwrap(), FlatTxMeta::default());
        assert_eq!(parse_flat_tx_meta(&[app_record(0x1FFF, 0, b"")], &descriptor(1)).unwrap(), FlatTxMeta::default());
        // validity first, then application records: fine
        let m = parse_flat_tx_meta(&[validity.clone(), app_record(0x2000, 1, b"a")], &descriptor(2)).unwrap();
        assert_eq!((m.version, m.locktime), (2, 5));
        // validity after an application record: refused (position is not in the txid)
        assert!(parse_flat_tx_meta(&[app_record(0x2000, 1, b"a"), validity.clone()], &descriptor(2)).is_err());
        // twice: refused
        assert!(parse_flat_tx_meta(&[validity.clone(), validity], &descriptor(2)).is_err());
    }
}
