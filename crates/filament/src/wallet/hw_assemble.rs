// src/wallet/hw_assemble.rs
//
// FIL-HW-VER-1, assemble-and-verify: the Ledger signs one input at a time and returns a bare
// 64-byte BIP-340 signature per input (`ledger::sign_with_ins`). To broadcast, the host turns
// the signing request (the same fields it sent the device) plus those signatures into a wire
// transaction. Nothing is offered for broadcast unless every signature verifies against the
// exact transaction the host built and the output each input spends, so a device that signed
// something else (or a host that built something else) is caught here, not by the network.
//
// Per input `i` the witness is `0x01 ‖ sig` (WITNESS_TYPE_SCHNORR) and must verify with the
// prevout's recipient as the key over `sighash_v2(txid, prevouts_hash, i)`.

use network_common::crypto::tx_sighash::{prevouts_hash, sighash_v2, verify_schnorr_witness, WITNESS_TYPE_SCHNORR};
use network_common::transaction::{ExtensionRecord, Transaction, TxInput, TxOutput, WitnessEntry};

/// TX-11: the one transaction version (`common_types::...::validation::TX_VERSION`; this crate
/// does not depend on common-types). Same value as the Ledger app and `wallet::...` signers.
pub const TX_VERSION: u8 = 1;

/// What the host sent the device (`ledger::ShishaTxParams`, minus the input index).
#[derive(Debug, Clone)]
pub struct HwTx {
    pub chain_id: u16,
    pub version: u8,
    pub locktime: u32,
    pub expiration_height: u32,
    pub inputs: Vec<HwInput>,
    pub outputs: Vec<HwOutput>,
    /// Whole `ExtensionRecord`s (`ExtensionRecord::to_bytes`), as sent to the device.
    pub ext_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct HwOutput {
    pub value: u64,
    pub recipient: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct HwInput {
    pub prev_height: u32,
    pub prev_output_idx: u16,
    /// Value and recipient of the output being spent (committed by sighash v2).
    pub prevout_value: u64,
    pub prevout_recipient: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Assembled {
    pub tx: Transaction,
    pub txid: [u8; 32],
    /// `Transaction::serialize_with_witnesses`, hex: what Keystone `POST /mempool/submit` takes.
    pub tx_hex: String,
    pub fee_atoms: u64,
}

fn parse_extensions(mut bytes: &[u8]) -> Result<Vec<ExtensionRecord>, String> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (rec, used) = ExtensionRecord::from_bytes(bytes).map_err(|e| format!("ext_bytes: {e}"))?;
        out.push(rec);
        bytes = &bytes[used..];
    }
    Ok(out)
}

/// Build the transaction from `t`, attach one `0x01` witness per input from `signatures`
/// (input order), and verify every one. `Err` means: do not broadcast.
pub fn assemble_signed_transaction(t: &HwTx, signatures: &[[u8; 64]]) -> Result<Assembled, String> {
    if t.version != TX_VERSION {
        return Err(format!("every transaction is version {TX_VERSION} (TX-11); got {}", t.version));
    }
    if t.inputs.is_empty() || t.outputs.is_empty() {
        return Err("a spend needs at least one input and one output".into());
    }
    if signatures.len() != t.inputs.len() {
        return Err(format!("{} signature(s) for {} input(s): every input needs the device's signature", signatures.len(), t.inputs.len()));
    }
    let total_in = t.inputs.iter().try_fold(0u64, |a, i| a.checked_add(i.prevout_value)).ok_or("input sum overflows")?;
    let total_out = t.outputs.iter().try_fold(0u64, |a, o| a.checked_add(o.value)).ok_or("output sum overflows")?;
    let fee_atoms = total_in.checked_sub(total_out).ok_or_else(|| format!("outputs ({total_out}) exceed the inputs ({total_in})"))?;

    let mut tx = Transaction {
        version: t.version,
        inputs: t.inputs.iter().map(|i| TxInput { prev_height: i.prev_height, prev_output_idx: i.prev_output_idx }).collect(),
        outputs: t.outputs.iter().map(|o| TxOutput { value: o.value, recipient: o.recipient }).collect(),
        locktime: t.locktime,
        expiration_height: t.expiration_height,
        witnesses: Vec::new(),
        extensions: parse_extensions(&t.ext_bytes)?,
    };
    let txid = tx.txid(t.chain_id).0;
    let prevouts: Vec<(u64, [u8; 32])> = t.inputs.iter().map(|i| (i.prevout_value, i.prevout_recipient)).collect();
    let ph = prevouts_hash(&prevouts);

    let mut witnesses = Vec::with_capacity(signatures.len());
    for (i, sig) in signatures.iter().enumerate() {
        let mut data = Vec::with_capacity(65);
        data.push(WITNESS_TYPE_SCHNORR);
        data.extend_from_slice(sig);
        let w = WitnessEntry { witness_data: data };
        let base = sighash_v2(&txid, &ph, i as u32);
        verify_schnorr_witness(&w, &t.inputs[i].prevout_recipient, &base, i)
            .map_err(|_| format!("input {i}: the signature does not verify for this transaction and the output it spends (wrong key, wrong prevout, or the device signed something else)"))?;
        witnesses.push(w);
    }
    tx.witnesses = witnesses;
    let tx_hex = hex::encode(tx.serialize_with_witnesses());
    Ok(Assembled { tx, txid, tx_hex, fee_atoms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::escrow::own_xonly;
    use crate::wallet::SchnorrSigner;
    use secp256k1::SecretKey;

    const CHAIN: u16 = 3;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    /// Two inputs held by two different keys, so a signature in the wrong slot is caught.
    fn request() -> (HwTx, Vec<SecretKey>) {
        let keys = vec![key(1), key(2)];
        let t = HwTx {
            chain_id: CHAIN,
            version: TX_VERSION,
            locktime: 10,
            expiration_height: 500,
            inputs: vec![
                HwInput { prev_height: 5, prev_output_idx: 0, prevout_value: 700, prevout_recipient: own_xonly(&keys[0]) },
                HwInput { prev_height: 6, prev_output_idx: 2, prevout_value: 400, prevout_recipient: own_xonly(&keys[1]) },
            ],
            outputs: vec![HwOutput { value: 1000, recipient: [7u8; 32] }],
            ext_bytes: vec![],
        };
        (t, keys)
    }

    /// Signatures as the device returns them: bare 64 bytes per input. The host signer stands in
    /// for the Ledger (same sighash v2).
    fn device_sigs(t: &HwTx, keys: &[SecretKey]) -> Vec<[u8; 64]> {
        let tx = Transaction {
            version: t.version,
            inputs: t.inputs.iter().map(|i| TxInput { prev_height: i.prev_height, prev_output_idx: i.prev_output_idx }).collect(),
            outputs: t.outputs.iter().map(|o| TxOutput { value: o.value, recipient: o.recipient }).collect(),
            locktime: t.locktime,
            expiration_height: t.expiration_height,
            witnesses: Vec::new(),
            extensions: parse_extensions(&t.ext_bytes).unwrap(),
        };
        let prevouts: Vec<(u64, [u8; 32])> = t.inputs.iter().map(|i| (i.prevout_value, i.prevout_recipient)).collect();
        SchnorrSigner::sign_transaction(&tx, keys, t.chain_id, &prevouts)
            .unwrap()
            .iter()
            .map(|w| w.witness_data[1..65].try_into().unwrap())
            .collect()
    }

    #[test]
    fn valid_signatures_assemble_into_a_wire_transaction() {
        let (t, keys) = request();
        let sigs = device_sigs(&t, &keys);
        let a = assemble_signed_transaction(&t, &sigs).unwrap();
        assert_eq!(a.fee_atoms, 100);
        assert_eq!(a.tx.witnesses.len(), 2);
        assert_eq!(a.txid, a.tx.txid(CHAIN).0);
        // The hex is what a node parses: same transaction, same witnesses.
        let parsed = Transaction::deserialize_with_witnesses(&hex::decode(&a.tx_hex).unwrap()).unwrap();
        assert_eq!(parsed.witnesses, a.tx.witnesses);
        assert_eq!(parsed.txid(CHAIN).0, a.txid);
        assert_eq!(parsed.expiration_height, 500);
    }

    #[test]
    fn extensions_are_part_of_what_is_signed() {
        let (mut t, keys) = request();
        let ext = ExtensionRecord {
            header: network_common::transaction::ExtensionHeader { extension_type: 0x1234, version: 1, payload_length: 1 },
            payload: vec![1],
        };
        t.ext_bytes = ext.to_bytes();
        let sigs = device_sigs(&t, &keys);
        let a = assemble_signed_transaction(&t, &sigs).unwrap();
        assert_eq!(a.tx.extensions, vec![ext]);
        // Signatures made without the extension do not verify with it.
        let (plain, keys) = request();
        let plain_sigs = device_sigs(&plain, &keys);
        assert!(assemble_signed_transaction(&t, &plain_sigs).is_err());
    }

    #[test]
    fn refuses_anything_the_device_did_not_sign() {
        let (t, keys) = request();
        let sigs = device_sigs(&t, &keys);

        // A damaged signature.
        let mut bad = sigs.clone();
        bad[1][5] ^= 1;
        assert!(assemble_signed_transaction(&t, &bad).unwrap_err().contains("input 1"));

        // Signatures in the wrong order (each input has its own key).
        let swapped = vec![sigs[1], sigs[0]];
        assert!(assemble_signed_transaction(&t, &swapped).unwrap_err().contains("input 0"));

        // The host builds a different transaction than the one signed: other output amount,
        // other destination, other prevout value, other expiry, other chain.
        let mut other = t.clone();
        other.outputs[0].value = 999;
        assert!(assemble_signed_transaction(&other, &sigs).is_err());
        let mut other = t.clone();
        other.outputs[0].recipient = [8u8; 32];
        assert!(assemble_signed_transaction(&other, &sigs).is_err());
        let mut other = t.clone();
        other.inputs[0].prevout_value = 701;
        assert!(assemble_signed_transaction(&other, &sigs).is_err());
        let mut other = t.clone();
        other.expiration_height = 501;
        assert!(assemble_signed_transaction(&other, &sigs).is_err());
        let mut other = t.clone();
        other.chain_id = CHAIN + 1;
        assert!(assemble_signed_transaction(&other, &sigs).is_err());
    }

    #[test]
    fn refuses_malformed_requests() {
        let (t, keys) = request();
        let sigs = device_sigs(&t, &keys);
        assert!(assemble_signed_transaction(&t, &sigs[..1]).unwrap_err().contains("signature(s)"));
        let mut v2 = t.clone();
        v2.version = 2;
        assert!(assemble_signed_transaction(&v2, &sigs).unwrap_err().contains("TX-11"));
        let mut over = t.clone();
        over.outputs[0].value = 1101;
        assert!(assemble_signed_transaction(&over, &sigs).unwrap_err().contains("exceed"));
        let mut junk = t.clone();
        junk.ext_bytes = vec![1, 2, 3];
        assert!(assemble_signed_transaction(&junk, &sigs).unwrap_err().contains("ext_bytes"));
        let mut empty = t.clone();
        empty.inputs.clear();
        assert!(assemble_signed_transaction(&empty, &[]).is_err());
    }
}
