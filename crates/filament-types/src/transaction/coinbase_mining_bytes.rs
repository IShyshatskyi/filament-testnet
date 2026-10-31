//! CB-9 (`Stratum_Extranonce_Binding_Plan.md` §3.3) — dedicated, Bitcoin-shaped
//! raw byte serialization of the beacon coinbase, used *only* for computing
//! the mining-facing `coinbase_hash` (leaf 0 of the two-leaf SHA256d Merkle
//! tree, §3.1). This is **not** the on-chain consensus/storage encoding of the
//! coinbase transaction — that remains the flat-vector `ShardBlockBody` model
//! (`outputs`/`descriptors`/`ExtensionRecord`, BLAKE3 txid) used everywhere
//! else in this codebase.
//!
//! The two representations encode the same logical coinbase and must stay
//! deterministically linked: the pool builds these bytes once per job
//! template (with a placeholder extranonce), a miner splices in its own
//! `extranonce1`/`extranonce2` and rehashes, and a validating node must be
//! able to rebuild byte-identical output from the *stored* flat-vector
//! coinbase (reading `reward_atoms` back from its one output, `recipient`
//! from that same output, `producer_stamp_marker` and the extranonce halves
//! from its extension records) — see [`split`] and [`from_stored_fields`].
//!
//! Format (fixed-width, no varints — every field here has a fixed shape by
//! construction: 0 inputs, exactly 1 output, exactly one miner-extranonce
//! extension, at most one producer-stamp extension):
//!
//! ```text
//! coinb1 (41 bytes): reward_atoms(8 LE) ‖ recipient(32) ‖ producer_stamp_marker(1)
//! extranonce (8 bytes): extranonce1(4) ‖ extranonce2(4)
//! coinb2 (0 bytes): empty today — reserved for future fields
//! ```
//!
//! `producer_stamp_marker`: `0x00` = no TS-T-11 stamp, `b'A'`/`b'B'` = the
//! stamp value — mirrors `producer_stamp.rs`'s own one-byte payload exactly,
//! so this marker byte round-trips through the same values the extension
//! record itself already carries.

/// Width of the fixed `coinb1` prefix (see module docs).
pub const COINB1_LEN: usize = 8 + 32 + 1;

/// Width of the spliced extranonce region.
pub const EXTRANONCE_LEN: usize = 8;

/// Marker byte for "no producer stamp" (distinct from `b'A'`/`b'B'`).
pub const NO_PRODUCER_STAMP: u8 = 0x00;

/// Build `coinb1` — the fixed bytes before the extranonce splice point.
pub fn coinb1(reward_atoms: u64, recipient: [u8; 32], producer_stamp_marker: u8) -> [u8; COINB1_LEN] {
    let mut out = [0u8; COINB1_LEN];
    out[0..8].copy_from_slice(&reward_atoms.to_le_bytes());
    out[8..40].copy_from_slice(&recipient);
    out[40] = producer_stamp_marker;
    out
}

/// Build `coinb2` — the fixed bytes after the extranonce splice point.
/// Empty today; kept as an explicit function (not a bare `&[]`) so a future
/// field addition has one call site to change, not every caller.
pub fn coinb2() -> [u8; 0] {
    []
}

/// Build the full mining-facing coinbase byte sequence:
/// `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2`.
pub fn coinbase_mining_bytes(
    reward_atoms: u64,
    recipient: [u8; 32],
    producer_stamp_marker: u8,
    extranonce1: [u8; 4],
    extranonce2: [u8; 4],
) -> Vec<u8> {
    let c1 = coinb1(reward_atoms, recipient, producer_stamp_marker);
    let c2 = coinb2();
    let mut out = Vec::with_capacity(c1.len() + EXTRANONCE_LEN + c2.len());
    out.extend_from_slice(&c1);
    out.extend_from_slice(&extranonce1);
    out.extend_from_slice(&extranonce2);
    out.extend_from_slice(&c2);
    out
}

/// The `coinbase_hash` leaf (§3.1): `SHA256d(coinbase_mining_bytes(...))`.
pub fn coinbase_hash(
    reward_atoms: u64,
    recipient: [u8; 32],
    producer_stamp_marker: u8,
    extranonce1: [u8; 4],
    extranonce2: [u8; 4],
) -> [u8; 32] {
    let bytes = coinbase_mining_bytes(
        reward_atoms,
        recipient,
        producer_stamp_marker,
        extranonce1,
        extranonce2,
    );
    crate::common::crypto::sha256d(&bytes)
}

/// Producer-stamp marker byte for a parsed stamp string (`"A"`/`"B"`/absent).
///
/// Mirrors `producer_stamp::build_producer_stamp_extension`'s own payload
/// byte exactly, so this marker and the real extension's payload always
/// agree.
pub fn producer_stamp_marker(producer_stamp: Option<&str>) -> u8 {
    match producer_stamp {
        Some("A") => b'A',
        Some("B") => b'B',
        _ => NO_PRODUCER_STAMP,
    }
}

/// Recover the mining-view fields from a *stored* flat-vector beacon
/// coinbase (descriptor 0), then rebuild `coinbase_hash` — the verification
/// side of the CB-9 invariant. Returns `None` if the body doesn't have the
/// expected coinbase shape (no output, or no miner-extranonce extension).
pub fn coinbase_hash_from_stored_body(
    body: &crate::common::blocks::ShardBlockBody,
) -> Option<[u8; 32]> {
    let output = body.outputs.first()?;
    let (extranonce1, extranonce2) = super::miner_extranonce::find_miner_extranonce_for_tx(body, 0)?;
    let marker = body
        .descriptors
        .first()
        .and_then(|desc| {
            let start = desc.extension_start as usize;
            let end = start + desc.extension_len as usize;
            body.extensions.get(start..end)
        })
        .and_then(|exts| {
            exts.iter()
                .find(|e| e.header.extension_type == super::producer_stamp::APPLICATION_EXT_PRODUCER_ID)
                .and_then(|e| e.payload.first().copied())
        })
        .unwrap_or(NO_PRODUCER_STAMP);

    Some(coinbase_hash(
        output.value,
        output.recipient,
        marker,
        extranonce1,
        extranonce2,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinb1_len_matches_const() {
        let c1 = coinb1(100, [0xAA; 32], NO_PRODUCER_STAMP);
        assert_eq!(c1.len(), COINB1_LEN);
    }

    #[test]
    fn different_extranonce_changes_hash() {
        let h1 = coinbase_hash(100, [0xAA; 32], NO_PRODUCER_STAMP, [1, 0, 0, 0], [0; 4]);
        let h2 = coinbase_hash(100, [0xAA; 32], NO_PRODUCER_STAMP, [2, 0, 0, 0], [0; 4]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_extranonce2_changes_hash() {
        let h1 = coinbase_hash(100, [0xAA; 32], NO_PRODUCER_STAMP, [1, 0, 0, 0], [0, 0, 0, 0]);
        let h2 = coinbase_hash(100, [0xAA; 32], NO_PRODUCER_STAMP, [1, 0, 0, 0], [0, 0, 0, 1]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn producer_stamp_marker_matches_extension_payload() {
        assert_eq!(producer_stamp_marker(Some("A")), b'A');
        assert_eq!(producer_stamp_marker(Some("B")), b'B');
        assert_eq!(producer_stamp_marker(None), NO_PRODUCER_STAMP);
    }

    #[test]
    fn from_stored_body_round_trips() {
        use crate::common::blocks::ShardBlockBody;
        use crate::transaction::{build_miner_extranonce_extension, Transaction, TxOutput};

        let mut tx = Transaction::new(1, 0);
        tx.add_output(TxOutput {
            value: 12345,
            recipient: [0x77; 32],
        });
        let mut body = ShardBlockBody::from_transactions(&[tx], None);
        let ext = build_miner_extranonce_extension([1, 2, 3, 4], [5, 6, 7, 8]);
        body.extensions.push(ext);
        body.descriptors[0].extension_len += 1;

        let expected = coinbase_hash(12345, [0x77; 32], NO_PRODUCER_STAMP, [1, 2, 3, 4], [5, 6, 7, 8]);
        let actual = coinbase_hash_from_stored_body(&body).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_stored_body_round_trips_with_producer_stamp() {
        use crate::common::blocks::ShardBlockBody;
        use crate::transaction::{build_miner_extranonce_extension, Transaction, TxOutput};

        let mut tx = Transaction::new(1, 0);
        tx.add_output(TxOutput {
            value: 999,
            recipient: [0x11; 32],
        });
        let mut body = ShardBlockBody::from_transactions(&[tx], Some("B"));
        let ext = build_miner_extranonce_extension([9, 9, 9, 9], [0; 4]);
        body.extensions.push(ext);
        body.descriptors[0].extension_len += 1;

        let expected = coinbase_hash(999, [0x11; 32], b'B', [9, 9, 9, 9], [0; 4]);
        let actual = coinbase_hash_from_stored_body(&body).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_stored_body_none_without_extranonce() {
        use crate::common::blocks::ShardBlockBody;
        use crate::transaction::{Transaction, TxOutput};

        let mut tx = Transaction::new(1, 0);
        tx.add_output(TxOutput {
            value: 1,
            recipient: [0; 32],
        });
        let body = ShardBlockBody::from_transactions(&[tx], None);
        assert!(coinbase_hash_from_stored_body(&body).is_none());
    }
}
