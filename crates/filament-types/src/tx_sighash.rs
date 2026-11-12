// filament-types/src/tx_sighash.rs — per-input signature hash (sighash v2).
//
// Domain-separated by `chain_id` (the sole cross-shard replay protection
// under the single-key address model) and binds the full flat input/output
// set plus the specific input being signed.


// ── VF-3 Phase 2: sighash v2 ───────────────────────────────────────────────
// Must match the node's `prevouts_hash` / `sighash_v2` byte for byte; the vectors
// in the test below are pinned on the node side too. The only sighash: every spend
// signs this (the old v1 preimage was removed before any network ran it).

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

/// Witness wire prefix: Schnorr signature (BIP-340).
pub const WITNESS_TYPE_SCHNORR: u8 = 0x01;

/// Expected `WitnessEntry::witness_data` length for Schnorr (`0x01` + 64-byte signature).
pub const SCHNORR_WITNESS_LEN: usize = 65;

/// Why a witness did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessError {
    pub input_index: usize,
    pub reason: String,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "input {}: {}", self.input_index, self.reason)
    }
}

impl std::error::Error for WitnessError {}

fn verify_ctx() -> &'static secp256k1::Secp256k1<secp256k1::VerifyOnly> {
    static CTX: std::sync::OnceLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> = std::sync::OnceLock::new();
    CTX.get_or_init(secp256k1::Secp256k1::verification_only)
}

/// Verify one witness (`0x01 ‖ 64-byte BIP-340 signature`) against an x-only public key and a sighash.
pub fn verify_schnorr_witness(
    witness: &crate::transaction_impl::WitnessEntry,
    expected_pubkey: &[u8; 32],
    sighash: &[u8; 32],
    input_index: usize,
) -> Result<(), WitnessError> {
    let err = |reason: String| WitnessError { input_index, reason };
    let data = &witness.witness_data;
    if data.len() != SCHNORR_WITNESS_LEN {
        return Err(err(format!("malformed witness length {} (expected {})", data.len(), SCHNORR_WITNESS_LEN)));
    }
    if data[0] != WITNESS_TYPE_SCHNORR {
        return Err(err(format!("unsupported witness type 0x{:02x}", data[0])));
    }
    let sig = secp256k1::schnorr::Signature::from_slice(&data[1..])
        .map_err(|e| err(format!("invalid Schnorr signature: {e}")))?;
    let pk = secp256k1::XOnlyPublicKey::from_slice(expected_pubkey)
        .map_err(|e| err(format!("invalid x-only pubkey: {e}")))?;
    let msg = secp256k1::Message::from_digest(*sighash);
    verify_ctx().verify_schnorr(&sig, &msg, &pk).map_err(|e| err(format!("signature does not verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sighash v2 vectors, the same values the node pins. Change them together.
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
            extensions: vec![],
        };
        let prevout = (1000u64, [9u8; 32]);
        let v2 = |tx: &Transaction, chain: u16, prev: &[(u64, [u8; 32])], i: u32| {
            hex::encode(sighash_v2(&tx.txid(chain).0, &prevouts_hash(prev), i))
        };
        assert_eq!(hex::encode(prevouts_hash(&[prevout])),
            "09d0937f5d233942e5bb94d6dadde0d92d43bfff3c7bc178ae2c64c3f792728b"); // V1
        assert_eq!(v2(&tx, 0, &[prevout], 0),
            "d8a8766d6ac64a127729917dc052e354206add9245effc131fef5dee74ce0752"); // V2
        assert_eq!(v2(&tx, shard_chain_id(0), &[prevout], 0),
            "40c2e9fe25b385064a95c81b61f7baa129d617bcc0d5514b05953f55b6328f96"); // V3
        // V4: + application extension 0x1234 v1 payload [1].
        let txid_ext = txid_from_parts(1, 1, 0, 0, &[(1, 0)], &[(100, [7u8; 32])], &[(0x1234, 1, &[1u8][..])]);
        assert_eq!(hex::encode(sighash_v2(&txid_ext, &prevouts_hash(&[prevout]), 0)),
            "3e0ff2935ada6ea04f0be68b996790a218af91cf88e1809288b7cf10aebedf74"); // V4
        let mut tx2 = tx.clone();
        tx2.version = 2;
        assert_eq!(v2(&tx2, shard_chain_id(0), &[prevout], 0),
            "6b295c3692527389e268448d59c29be251bcb7e70c7f8afd814908d02a5f208d"); // V8
        tx.inputs.push(TxInput { prev_height: 2, prev_output_idx: 3 });
        assert_eq!(v2(&tx, shard_chain_id(0), &[prevout, (500, [8u8; 32])], 1),
            "2a8762df4154b5a830a909efba5633556054f854ff8f72aa2491b8c8d1dc5463"); // V6 input 1
    }
}
