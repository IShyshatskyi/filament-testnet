//! Escrow policy-hash output (D14): ESC-1..ESC-4, ESC-6.
//!
//! Spec: `docs/plan/Escrow_Policy_Hash_Consensus_Spec.md`. An escrow output is an
//! ordinary 40-byte `TxOutput` whose `recipient` is the policy hash
//! `P = BLAKE3("shisha/escrow2of2/v1" ‖ sender_pk ‖ provider_pk ‖ H_le)`. It is spent
//! with witness `0x02` (cooperative, block height `< H`, both signatures) or `0x03`
//! (recovery, block height `≥ H`, sender only). Both sign the path-bound message
//! `BLAKE3("shisha/escrow-sighash/v1" ‖ sighash_v2 ‖ path_byte)`.
//!
//! [`spend_checks`] turns any witness into the single signatures to verify. ESC-1..ESC-3
//! run here, before any signature-cache lookup (the cache answers single signatures,
//! never "is this path valid at this height"). Each escrow signature is handed to the
//! cache as a synthetic `0x01 ‖ sig` witness under its own scheme tag.

use crate::common::validation::ValidationError;
use crate::transaction::WitnessEntry;

use super::sig_cache::SCHEME_TAG_SINGLE_KEY;
use super::tx_sighash::{SCHNORR_WITNESS_LEN, WITNESS_TYPE_SCHNORR};

/// Witness type: cooperative escrow spend (before H).
pub const WITNESS_TYPE_ESCROW_COOP: u8 = 0x02;
/// Witness type: recovery escrow spend (from H).
pub const WITNESS_TYPE_ESCROW_RECOVERY: u8 = 0x03;

/// `sender_pk(32) ‖ provider_pk(32) ‖ H(u32 LE)`.
pub const ESCROW_POLICY_LEN: usize = 68;
/// `0x02 ‖ policy ‖ sig_sender ‖ sig_provider`.
pub const ESCROW_COOP_WITNESS_LEN: usize = 1 + ESCROW_POLICY_LEN + 64 + 64;
/// `0x03 ‖ policy ‖ sig_sender`.
pub const ESCROW_RECOVERY_WITNESS_LEN: usize = 1 + ESCROW_POLICY_LEN + 64;

/// Domain tag of the policy hash.
pub const ESCROW_POLICY_TAG: &[u8] = b"shisha/escrow2of2/v1";
/// Domain tag of the path-bound signature message.
pub const ESCROW_SIGHASH_TAG: &[u8] = b"shisha/escrow-sighash/v1";

/// ESC-6 signature-cache scheme tags (single-key spends use `SCHEME_TAG_SINGLE_KEY = 0x00`).
pub const SCHEME_TAG_ESCROW_COOP_SENDER: u8 = 0x01;
pub const SCHEME_TAG_ESCROW_COOP_PROVIDER: u8 = 0x02;
pub const SCHEME_TAG_ESCROW_RECOVERY: u8 = 0x03;

/// The spending conditions committed to by an escrow output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowPolicy {
    pub sender_pk: [u8; 32],
    pub provider_pk: [u8; 32],
    /// Absolute unlock height on the escrow's own chain.
    pub unlock_height: u32,
}

impl EscrowPolicy {
    /// The 68-byte policy encoding.
    pub fn to_bytes(&self) -> [u8; ESCROW_POLICY_LEN] {
        let mut b = [0u8; ESCROW_POLICY_LEN];
        b[..32].copy_from_slice(&self.sender_pk);
        b[32..64].copy_from_slice(&self.provider_pk);
        b[64..].copy_from_slice(&self.unlock_height.to_le_bytes());
        b
    }

    /// Parse the 68-byte policy encoding.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != ESCROW_POLICY_LEN {
            return None;
        }
        let mut sender_pk = [0u8; 32];
        let mut provider_pk = [0u8; 32];
        sender_pk.copy_from_slice(&b[..32]);
        provider_pk.copy_from_slice(&b[32..64]);
        let unlock_height = u32::from_le_bytes(b[64..68].try_into().ok()?);
        Some(Self { sender_pk, provider_pk, unlock_height })
    }

    /// The output recipient `P` for this policy.
    pub fn hash(&self) -> [u8; 32] {
        escrow_policy_hash(&self.to_bytes())
    }
}

/// `BLAKE3("shisha/escrow2of2/v1" ‖ policy)`.
pub fn escrow_policy_hash(policy: &[u8; ESCROW_POLICY_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ESCROW_POLICY_TAG);
    h.update(policy);
    h.finalize().into()
}

/// Path-bound message: `BLAKE3("shisha/escrow-sighash/v1" ‖ sighash_v2 ‖ path_byte)`.
pub fn escrow_sighash(sighash_v2: &[u8; 32], path_byte: u8) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ESCROW_SIGHASH_TAG);
    h.update(sighash_v2);
    h.update(&[path_byte]);
    h.finalize().into()
}

/// One single-key signature to verify (through the signature cache).
#[derive(Debug, Clone)]
pub struct SigCheck {
    pub pubkey: [u8; 32],
    pub message: [u8; 32],
    /// `0x01 ‖ sig(64)` — the shape `verify_schnorr_witness` and the cache take.
    pub witness: WitnessEntry,
    pub scheme_tag: u8,
}

fn single(pubkey: [u8; 32], message: [u8; 32], sig: &[u8], scheme_tag: u8) -> SigCheck {
    let mut data = Vec::with_capacity(SCHNORR_WITNESS_LEN);
    data.push(WITNESS_TYPE_SCHNORR);
    data.extend_from_slice(sig);
    SigCheck { pubkey, message, witness: WitnessEntry { witness_data: data }, scheme_tag }
}

fn esc(input_index: usize, rule: &'static str, reason: String) -> ValidationError {
    ValidationError::EscrowSpend { input_index, rule, reason }
}

/// The signatures that authorise spending `recipient` with `witness`.
///
/// * `0x01` (and any other non-escrow type): one check of the witness as is against
///   `recipient` and `sighash_v2` — unknown types are rejected by the verifier, as today.
/// * `0x02` / `0x03`: ESC-1 (length), ESC-2 (policy hash == recipient) and, when
///   `block_height` is `Some`, ESC-3 (height window); then two / one checks over
///   [`escrow_sighash`].
///
/// `block_height = None` skips ESC-3 — only for deriving cache keys of witnesses that
/// already passed validation (keep-on-revert), never for accepting a spend.
pub fn spend_checks(
    witness: &WitnessEntry,
    recipient: &[u8; 32],
    sighash_v2: &[u8; 32],
    input_index: usize,
    block_height: Option<u32>,
) -> Result<Vec<SigCheck>, ValidationError> {
    let data = &witness.witness_data;
    let ty = data.first().copied();
    let (expected_len, path) = match ty {
        Some(WITNESS_TYPE_ESCROW_COOP) => (ESCROW_COOP_WITNESS_LEN, WITNESS_TYPE_ESCROW_COOP),
        Some(WITNESS_TYPE_ESCROW_RECOVERY) => (ESCROW_RECOVERY_WITNESS_LEN, WITNESS_TYPE_ESCROW_RECOVERY),
        _ => {
            return Ok(vec![SigCheck {
                pubkey: *recipient,
                message: *sighash_v2,
                witness: witness.clone(),
                scheme_tag: SCHEME_TAG_SINGLE_KEY,
            }]);
        }
    };

    // ESC-1: exact length.
    if data.len() != expected_len {
        return Err(esc(
            input_index,
            "ESC-1",
            format!("witness type 0x{path:02x} length {} (expected {expected_len})", data.len()),
        ));
    }

    // ESC-2: the revealed policy hashes to the spent output's recipient.
    let policy_bytes: [u8; ESCROW_POLICY_LEN] =
        data[1..1 + ESCROW_POLICY_LEN].try_into().expect("length checked");
    if escrow_policy_hash(&policy_bytes) != *recipient {
        return Err(esc(input_index, "ESC-2", "policy hash does not match the spent output".into()));
    }
    let policy = EscrowPolicy::from_bytes(&policy_bytes).expect("length checked");

    // ESC-3: height window. `0x02` only below H, `0x03` only from H.
    if let Some(h) = block_height {
        let ok = if path == WITNESS_TYPE_ESCROW_COOP { h < policy.unlock_height } else { h >= policy.unlock_height };
        if !ok {
            let want = if path == WITNESS_TYPE_ESCROW_COOP { "< H" } else { ">= H" };
            return Err(esc(
                input_index,
                "ESC-3",
                format!(
                    "witness 0x{path:02x} needs block height {want} (height {h}, H {})",
                    policy.unlock_height
                ),
            ));
        }
    }

    // ESC-4 inputs: path-bound message, one check per signature.
    let message = escrow_sighash(sighash_v2, path);
    let sigs = &data[1 + ESCROW_POLICY_LEN..];
    Ok(if path == WITNESS_TYPE_ESCROW_COOP {
        vec![
            single(policy.sender_pk, message, &sigs[..64], SCHEME_TAG_ESCROW_COOP_SENDER),
            single(policy.provider_pk, message, &sigs[64..128], SCHEME_TAG_ESCROW_COOP_PROVIDER),
        ]
    } else {
        vec![single(policy.sender_pk, message, &sigs[..64], SCHEME_TAG_ESCROW_RECOVERY)]
    })
}

/// ESC-7: the last block height at which a cooperative spend in `witnesses` can still be
/// mined (`min H − 1` over its `0x02` witnesses), or `None` when it has none. Witnesses
/// that do not parse are ignored here; admission rejects them anyway.
pub fn coop_last_valid_height(witnesses: &[WitnessEntry]) -> Option<u32> {
    witnesses
        .iter()
        .filter(|w| {
            w.witness_data.first() == Some(&WITNESS_TYPE_ESCROW_COOP)
                && w.witness_data.len() == ESCROW_COOP_WITNESS_LEN
        })
        .filter_map(|w| EscrowPolicy::from_bytes(&w.witness_data[1..1 + ESCROW_POLICY_LEN]))
        .map(|p| p.unlock_height.saturating_sub(1))
        .min()
}

/// ESC-8: signature checks a witness costs (`0x02` = 2, everything else = 1).
pub fn signature_check_cost(witness: &WitnessEntry) -> u32 {
    if witness.witness_data.first() == Some(&WITNESS_TYPE_ESCROW_COOP) { 2 } else { 1 }
}

/// Build a cooperative witness (wallet / tests).
pub fn coop_witness(policy: &EscrowPolicy, sig_sender: &[u8; 64], sig_provider: &[u8; 64]) -> WitnessEntry {
    let mut d = Vec::with_capacity(ESCROW_COOP_WITNESS_LEN);
    d.push(WITNESS_TYPE_ESCROW_COOP);
    d.extend_from_slice(&policy.to_bytes());
    d.extend_from_slice(sig_sender);
    d.extend_from_slice(sig_provider);
    WitnessEntry { witness_data: d }
}

/// Build a recovery witness (wallet / tests).
pub fn recovery_witness(policy: &EscrowPolicy, sig_sender: &[u8; 64]) -> WitnessEntry {
    let mut d = Vec::with_capacity(ESCROW_RECOVERY_WITNESS_LEN);
    d.push(WITNESS_TYPE_ESCROW_RECOVERY);
    d.extend_from_slice(&policy.to_bytes());
    d.extend_from_slice(sig_sender);
    WitnessEntry { witness_data: d }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::verify_schnorr_witness;
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    fn key(secret: u8) -> Keypair {
        let mut s = [0u8; 32];
        s[31] = secret;
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&s).unwrap())
    }
    fn xonly(k: &Keypair) -> [u8; 32] {
        k.x_only_public_key().0.serialize()
    }
    fn sign(k: &Keypair, msg: &[u8; 32]) -> [u8; 64] {
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(*msg), k).serialize()
    }
    fn policy(h: u32) -> (Keypair, Keypair, EscrowPolicy) {
        let (s, p) = (key(3), key(4));
        let pol = EscrowPolicy { sender_pk: xonly(&s), provider_pk: xonly(&p), unlock_height: h };
        (s, p, pol)
    }
    fn verify_all(checks: &[SigCheck]) -> Result<(), ValidationError> {
        for (i, c) in checks.iter().enumerate() {
            verify_schnorr_witness(&c.witness, &c.pubkey, &c.message, i)?;
        }
        Ok(())
    }
    const SH: [u8; 32] = [0x5a; 32];

    /// Test 1: fixed vector (BIP-340 test keys for secrets 3 and 4, H = 1000).
    #[test]
    fn esc_policy_hash_vector() {
        let (_, _, pol) = policy(1000);
        assert_eq!(
            hex::encode(pol.sender_pk),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        let mut pre = ESCROW_POLICY_TAG.to_vec();
        pre.extend_from_slice(&pol.to_bytes());
        assert_eq!(pol.hash(), *blake3::hash(&pre).as_bytes());
        assert_eq!(hex::encode(pol.hash()), ESC_POLICY_HASH_VECTOR);
    }
    /// Pinned P for test 1 (cross-checked against the Python `blake3` package, Oct 28, 2026).
    const ESC_POLICY_HASH_VECTOR: &str = "16420d58377bc077c27e3a60671d9c48820d6a46f5b5816e4bcb5d45a31887d7";

    /// Tests 2 + 3: height window on both paths.
    #[test]
    fn esc3_height_window() {
        let (s, p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let w2 = coop_witness(&pol, &sign(&s, &m2), &sign(&p, &m2));
        verify_all(&spend_checks(&w2, &pol.hash(), &SH, 0, Some(999)).unwrap()).unwrap();
        let e = spend_checks(&w2, &pol.hash(), &SH, 0, Some(1000)).unwrap_err();
        assert!(matches!(e, ValidationError::EscrowSpend { rule: "ESC-3", .. }), "{e}");

        let m3 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_RECOVERY);
        let w3 = recovery_witness(&pol, &sign(&s, &m3));
        verify_all(&spend_checks(&w3, &pol.hash(), &SH, 0, Some(1000)).unwrap()).unwrap();
        let e = spend_checks(&w3, &pol.hash(), &SH, 0, Some(999)).unwrap_err();
        assert!(matches!(e, ValidationError::EscrowSpend { rule: "ESC-3", .. }), "{e}");
    }

    /// Test 4: a changed policy byte fails ESC-2.
    #[test]
    fn esc2_wrong_policy() {
        let (s, p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let mut w = coop_witness(&pol, &sign(&s, &m2), &sign(&p, &m2));
        w.witness_data[1 + 64] ^= 1; // first byte of H
        let e = spend_checks(&w, &pol.hash(), &SH, 0, Some(10)).unwrap_err();
        assert!(matches!(e, ValidationError::EscrowSpend { rule: "ESC-2", .. }), "{e}");
    }

    /// Test 5: a garbage provider signature fails ESC-4.
    #[test]
    fn esc4_provider_signature_required() {
        let (s, _p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let w = coop_witness(&pol, &sign(&s, &m2), &sign(&key(9), &m2));
        let checks = spend_checks(&w, &pol.hash(), &SH, 0, Some(10)).unwrap();
        assert!(verify_all(&checks).is_err());
    }

    /// Test 6: the sender's cooperative signature cannot be reused in a recovery witness.
    #[test]
    fn esc4_path_reuse_rejected() {
        let (s, p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let sig_s = sign(&s, &m2);
        let _coop = coop_witness(&pol, &sig_s, &sign(&p, &m2));
        let stolen = recovery_witness(&pol, &sig_s);
        let checks = spend_checks(&stolen, &pol.hash(), &SH, 0, Some(1000)).unwrap();
        assert!(verify_all(&checks).is_err(), "cooperative signature must not authorise recovery");
    }

    /// Test 8: lengths off by one and an unknown type.
    #[test]
    fn esc1_lengths_and_types() {
        let (s, p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let good = coop_witness(&pol, &sign(&s, &m2), &sign(&p, &m2));
        for len in [ESCROW_COOP_WITNESS_LEN - 1, ESCROW_COOP_WITNESS_LEN + 1] {
            let mut w = good.clone();
            w.witness_data.resize(len, 0);
            let e = spend_checks(&w, &pol.hash(), &SH, 0, Some(10)).unwrap_err();
            assert!(matches!(e, ValidationError::EscrowSpend { rule: "ESC-1", .. }));
        }
        let m3 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_RECOVERY);
        let rec = recovery_witness(&pol, &sign(&s, &m3));
        for len in [ESCROW_RECOVERY_WITNESS_LEN - 1, ESCROW_RECOVERY_WITNESS_LEN + 1] {
            let mut w = rec.clone();
            w.witness_data.resize(len, 0);
            let e = spend_checks(&w, &pol.hash(), &SH, 0, Some(1000)).unwrap_err();
            assert!(matches!(e, ValidationError::EscrowSpend { rule: "ESC-1", .. }));
        }
        // Type 0x04 falls through to the single-key verifier, which rejects it.
        let mut w = good.clone();
        w.witness_data[0] = 0x04;
        let checks = spend_checks(&w, &pol.hash(), &SH, 0, Some(10)).unwrap();
        assert!(verify_all(&checks).is_err());
    }

    /// Test 7: a single-key witness cannot spend an escrow output.
    #[test]
    fn esc5_single_key_witness_cannot_spend_escrow() {
        let (s, _p, pol) = policy(1000);
        let mut d = vec![WITNESS_TYPE_SCHNORR];
        d.extend_from_slice(&sign(&s, &SH));
        let w = WitnessEntry { witness_data: d };
        let checks = spend_checks(&w, &pol.hash(), &SH, 0, Some(10)).unwrap();
        assert!(verify_all(&checks).is_err());
    }

    #[test]
    fn esc7_coop_deadline_and_esc8_cost() {
        let (s, p, pol) = policy(1000);
        let m2 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_COOP);
        let w = coop_witness(&pol, &sign(&s, &m2), &sign(&p, &m2));
        assert_eq!(coop_last_valid_height(std::slice::from_ref(&w)), Some(999));
        assert_eq!(signature_check_cost(&w), 2);
        let m3 = escrow_sighash(&SH, WITNESS_TYPE_ESCROW_RECOVERY);
        let r = recovery_witness(&pol, &sign(&s, &m3));
        assert_eq!(coop_last_valid_height(std::slice::from_ref(&r)), None);
        assert_eq!(signature_check_cost(&r), 1);
    }
}
