//! Transaction sighash v2 (TX-5 / TX-6, VF-3 Phase 2) and Schnorr witness verification.

use std::sync::OnceLock;

use secp256k1::{schnorr::Signature, Message, Secp256k1, VerifyOnly, XOnlyPublicKey};

use crate::common::validation::ValidationError;
use crate::transaction::WitnessEntry;

/// Process-wide verify-only secp256k1 context (TX-VALID-SECP-CTX-1).
///
/// libsecp256k1 contexts are expensive to build and safe for concurrent immutable
/// use; never create one per witness. Signing paths keep their own contexts.
fn verify_ctx() -> &'static Secp256k1<VerifyOnly> {
    static CTX: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

/// Witness wire prefix: Schnorr signature (BIP-340).
pub const WITNESS_TYPE_SCHNORR: u8 = 0x01;

/// Expected `WitnessEntry::witness_data` length for Schnorr (`0x01` + 64-byte sig).
pub const SCHNORR_WITNESS_LEN: usize = 65;

// ── VF-3 Phase 2: sighash v2 (Txid_Unification_Design.md §5 P2.1) ──────────
//
// The only sighash: every spending transaction is version 2 and signs this
// (TX-5/TX-11). The old field-by-field v1 preimage (`flat_tx_sighash`) was
// removed before any network ran it.

/// Domain tag of the v2 sighash preimage.
pub const SIGHASH_V2_DOMAIN_TAG: &[u8] = b"shisha/sighash/v2";

/// Domain tag of the prevouts commitment.
pub const PREVOUTS_DOMAIN_TAG: &[u8] = b"shisha/prevouts/v1";

/// Commit to the outputs being spent, in input order (Q-P2-1).
///
/// `BLAKE3("shisha/prevouts/v1" ‖ n:u32 LE ‖ [value u64 LE ‖ recipient [u8;32]] × n)`.
/// A host that lies about an input value (e.g. to hide the fee on a hardware
/// wallet's screen) makes the signature invalid.
pub fn prevouts_hash(prevouts: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PREVOUTS_DOMAIN_TAG);
    h.update(&(prevouts.len() as u32).to_le_bytes());
    for (value, recipient) in prevouts {
        h.update(&value.to_le_bytes());
        h.update(recipient);
    }
    h.finalize().into()
}

/// v2 sighash for one input: `BLAKE3("shisha/sighash/v2" ‖ txid ‖ prevouts_hash ‖ input_index:u32 LE)`.
///
/// `txid` is [`crate::transaction::txid_from_parts`] on the spending chain, so
/// it already covers `chain_id`, version, validity window, inputs, outputs and
/// every non-validity extension. One encoder; no second field-by-field preimage.
pub fn sighash_v2(txid: &[u8; 32], prevouts_hash: &[u8; 32], input_index: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SIGHASH_V2_DOMAIN_TAG);
    h.update(txid);
    h.update(prevouts_hash);
    h.update(&input_index.to_le_bytes());
    h.finalize().into()
}

/// Verify a single `WitnessEntry` against the referenced UTXO pubkey and sighash.
pub fn verify_schnorr_witness(
    witness: &WitnessEntry,
    expected_pubkey: &[u8; 32],
    sighash: &[u8; 32],
    input_index: usize,
) -> Result<(), ValidationError> {
    let data = &witness.witness_data;
    if data.len() != SCHNORR_WITNESS_LEN {
        return Err(ValidationError::InvalidSignature {
            input_index,
            reason: format!(
                "malformed witness length {} (expected {})",
                data.len(),
                SCHNORR_WITNESS_LEN
            ),
        });
    }
    if data[0] != WITNESS_TYPE_SCHNORR {
        return Err(ValidationError::InvalidSignature {
            input_index,
            reason: format!("unsupported witness type 0x{:02x}", data[0]),
        });
    }

    let secp = verify_ctx();
    let sig = Signature::from_slice(&data[1..]).map_err(|e| ValidationError::InvalidSignature {
        input_index,
        reason: format!("invalid Schnorr signature: {e}"),
    })?;
    let pk = XOnlyPublicKey::from_slice(expected_pubkey).map_err(|e| {
        ValidationError::InvalidSignature {
            input_index,
            reason: format!("invalid x-only pubkey: {e}"),
        }
    })?;
    let msg = Message::from_digest(*sighash);
    secp.verify_schnorr(&sig, &msg, &pk)
        .map_err(|e| ValidationError::InvalidSignature {
            input_index,
            reason: format!("Schnorr verify failed: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::sync::Arc;
    use std::thread;

    fn signed_witness() -> (WitnessEntry, [u8; 32], [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("test secret");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (pk, _) = keypair.x_only_public_key();
        let sighash = [0x11u8; 32];
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        let mut data = vec![WITNESS_TYPE_SCHNORR];
        data.extend_from_slice(&sig.serialize());
        (
            WitnessEntry {
                witness_data: data,
            },
            pk.serialize(),
            sighash,
        )
    }

    /// TX-VALID-SECP-CTX-1: same witness verifies twice (shared OnceLock context).
    #[test]
    fn verify_schnorr_witness_reuses_process_context() {
        let (witness, pk, sighash) = signed_witness();
        verify_schnorr_witness(&witness, &pk, &sighash, 0).expect("first verify");
        verify_schnorr_witness(&witness, &pk, &sighash, 1).expect("second verify");
    }

    /// Concurrent verifies share the same VerifyOnly context (`Send + Sync`).
    #[test]
    fn verify_schnorr_witness_concurrent_reuse() {
        let (witness, pk, sighash) = signed_witness();
        let witness = Arc::new(witness);
        let mut handles = Vec::new();
        for i in 0..4 {
            let w = Arc::clone(&witness);
            handles.push(thread::spawn(move || {
                verify_schnorr_witness(&w, &pk, &sighash, i).expect("concurrent verify");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}

