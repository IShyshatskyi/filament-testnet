// src/common/filament_common/ipp.rs
//
// Instant payment provider (IPP) endpoint messages — the wire types of
// `filament_app/docs/IPP_PROTOCOL_AND_MUSIG2.md` §2 (escrow model, D14). Not consensus:
// providers are an off-chain service; nothing here is validated by nodes.
//
// * JSON over HTTPS. Outpoints are positional `(height, output_idx)` (Anti-Patterns #13);
//   keys and hashes are lowercase hex; amounts are atoms.
// * `SignedMessage` wraps a message for transport: the signature covers
//   `BLAKE3("shisha/ipp/<type>/v1" ‖ body)` where `body` is the exact JSON text sent, so
//   no JSON canonicalisation is needed; the receiver verifies before it parses.
// * Who signs: provider — `OpenBalanceAck`, `Commitment`, `BroadcastNotif`, `FiatPaid`;
//   payer — `OpenBalanceRequest`, `FundingNotif`, `PayHalfSign`, `TopUpRequest`,
//   `DisputeOpen`; merchant — `DeliveryConfirm`. The receiver checks the signer key against
//   what it already knows (provider registry record, the escrow policy, the merchant's
//   payment request); a message never introduces its own trusted key.
// * A provider's word is never the confirmation of an on-chain fact: escrow outputs and
//   payments are checked through the receiver's own nodes (§1 D12).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Message format version carried by every body.
pub const IPP_VERSION: u32 = 1;

// ─── Shared pieces ────────────────────────────────────────────────────────────

/// A positional output reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outpoint {
    pub height: u32,
    pub output_idx: u16,
}

/// `(value, recipient)` of a spent output — the sighash v2 prevout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prevout {
    pub value_atoms: u64,
    pub recipient_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settlement {
    Crypto,
    Fiat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePayer {
    Payer,
    Merchant,
}

/// Fiat-mode terms locked when the commitment is issued (§3.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FiatTerms {
    /// Amount the merchant receives, in minor units (cents).
    pub amount_minor: u64,
    /// ISO 4217 code.
    pub currency: String,
    /// Atoms per fiat minor unit, as a decimal string (no float rounding on the wire).
    pub rate: String,
    pub rate_source: String,
    pub rate_time_unix: u64,
}

// ─── Messages (§2 table) ──────────────────────────────────────────────────────

/// A typed IPP message; `TYPE` is its tag in `SignedMessage` and in the signed digest.
pub trait IppMessage: Serialize + DeserializeOwned {
    const TYPE: &'static str;
}

macro_rules! ipp_message {
    ($t:ty, $tag:literal) => {
        impl IppMessage for $t {
            const TYPE: &'static str = $tag;
        }
    };
}

/// Payer → provider: open a balance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenBalanceRequest {
    pub version: u32,
    /// TX-6 chain domain (beacon 0, shard n → n + 1).
    pub chain_id: u16,
    pub amount_atoms: u64,
    pub slots: u32,
    /// Requested lock length N; the provider answers with the absolute H.
    pub lock_blocks: u32,
    pub payer_pk_hex: String,
}
ipp_message!(OpenBalanceRequest, "open-balance-request");

/// Provider → payer: the provider escrow key (must equal its registry record), H and a session.
/// Both sides compute the policy and `P` themselves; `policy_hash_hex` is a cross-check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenBalanceAck {
    pub version: u32,
    pub session_id: String,
    pub provider_pk_hex: String,
    pub unlock_height: u32,
    pub policy_hash_hex: String,
}
ipp_message!(OpenBalanceAck, "open-balance-ack");

/// Payer → provider: the funding is in a block (the provider checks it via its own nodes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FundingNotif {
    pub version: u32,
    pub session_id: String,
    pub funding_txid_hex: String,
    pub outpoints: Vec<Outpoint>,
}
ipp_message!(FundingNotif, "funding-notif");

/// Payer → provider: the unsigned payment and the payer's `0x02` signature per input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayHalfSign {
    pub version: u32,
    pub session_id: String,
    pub payment_request_id: String,
    pub chain_id: u16,
    /// `Transaction::serialize_with_witnesses` with no witnesses.
    pub tx_hex: String,
    pub prevouts: Vec<Prevout>,
    pub payer_sigs_hex: Vec<String>,
}
ipp_message!(PayHalfSign, "pay-half-sign");

/// Provider → merchant and payer: payment X is reserved and will be completed (§3.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment {
    pub version: u32,
    /// Provider's registry slot (beacon chain).
    pub provider_id: u32,
    pub merchant_id: String,
    pub payment_request_id: String,
    pub chain_id: u16,
    pub escrow_outpoints: Vec<Outpoint>,
    pub amount_atoms: u64,
    pub settlement: Settlement,
    /// Present exactly when `settlement == Fiat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fiat: Option<FiatTerms>,
    pub fee_atoms: u64,
    pub fee_payer: FeePayer,
    pub category: String,
    /// End of the delivery / return window: beacon height and wall-clock date.
    pub window_end_height: u32,
    pub window_end_unix: u64,
    /// Latest escrow-chain height by which the provider completes the payment.
    pub settle_by_height: u32,
    pub agreement_hash_hex: String,
    pub kyc_level: String,
    pub compliance_profile: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}
ipp_message!(Commitment, "commitment");

/// Merchant → provider: delivered (or the window passed under the agreement's policy).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryConfirm {
    pub version: u32,
    pub payment_request_id: String,
    pub delivered_at_unix: u64,
}
ipp_message!(DeliveryConfirm, "delivery-confirm");

/// Provider → payer and merchant: completed and broadcast. Both confirm via their nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BroadcastNotif {
    pub version: u32,
    pub payment_request_id: String,
    pub txid_hex: String,
}
ipp_message!(BroadcastNotif, "broadcast-notif");

/// Payer → provider: dispute within the window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisputeOpen {
    pub version: u32,
    pub payment_request_id: String,
    pub case_ref: String,
    pub reason: String,
}
ipp_message!(DisputeOpen, "dispute-open");

/// Provider → merchant (fiat mode): the fiat payment reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FiatPaid {
    pub version: u32,
    pub payment_request_id: String,
    /// Escrow → provider payment.
    pub txid_hex: String,
    pub fiat_reference: String,
    pub paid_at_unix: u64,
}
ipp_message!(FiatPaid, "fiat-paid");

/// Payer → provider: more slots for the same policy (same H, same `P`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopUpRequest {
    pub version: u32,
    pub session_id: String,
    pub policy_hash_hex: String,
    pub amount_atoms: u64,
    pub slots: u32,
}
ipp_message!(TopUpRequest, "top-up-request");

// ─── Checks the receiver runs before relying on a commitment ──────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IppError {
    Json(String),
    /// Envelope type differs from the expected message type.
    WrongType { expected: &'static str, got: String },
    BadKey,
    BadSignature,
    /// Signed by a key other than the one the receiver expects.
    UnexpectedSigner,
    UnsupportedVersion(u32),
    Invalid(String),
}

impl std::fmt::Display for IppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::WrongType { expected, got } => write!(f, "expected a {expected} message, got {got}"),
            Self::BadKey => write!(f, "signer key is not a valid x-only public key"),
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::UnexpectedSigner => write!(f, "signed by an unexpected key"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported message version {v}"),
            Self::Invalid(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for IppError {}

impl Commitment {
    /// Field checks that need no chain state. `unlock_height` is the escrow's H and
    /// `safety_margin` the provider's margin (blocks); `now_unix` the receiver's clock.
    pub fn check(&self, unlock_height: u32, safety_margin: u32, now_unix: u64) -> Result<(), IppError> {
        let bad = |s: &str| Err(IppError::Invalid(s.to_string()));
        if self.version != IPP_VERSION {
            return Err(IppError::UnsupportedVersion(self.version));
        }
        if self.escrow_outpoints.is_empty() || self.amount_atoms == 0 {
            return bad("commitment reserves no escrow output or no amount");
        }
        if (self.settlement == Settlement::Fiat) != self.fiat.is_some() {
            return bad("fiat terms must be present exactly in fiat mode");
        }
        if self.settle_by_height.saturating_add(safety_margin) >= unlock_height {
            return bad("settle-by height leaves no safety margin before the escrow unlock height");
        }
        if self.expires_at_unix <= self.issued_at_unix || now_unix >= self.expires_at_unix {
            return bad("commitment is expired");
        }
        Ok(())
    }
}

// ─── Signed envelope ──────────────────────────────────────────────────────────

/// A message as sent: its type tag, the exact JSON body, the signer and the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// The message JSON, verbatim; the signature covers these bytes.
    pub body: String,
    pub signer_pk_hex: String,
    pub sig_hex: String,
}

/// `BLAKE3("shisha/ipp/<type>/v1" ‖ body)`.
pub fn ipp_digest(msg_type: &str, body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"shisha/ipp/");
    h.update(msg_type.as_bytes());
    h.update(b"/v1");
    h.update(body);
    h.finalize().into()
}

impl SignedMessage {
    /// Serialise and sign `msg` with `key` (BIP-340 Schnorr over [`ipp_digest`]).
    pub fn sign<M: IppMessage>(msg: &M, key: &secp256k1::SecretKey) -> Result<Self, IppError> {
        let body = serde_json::to_string(msg).map_err(|e| IppError::Json(e.to_string()))?;
        let secp = secp256k1::Secp256k1::new();
        let kp = secp256k1::Keypair::from_secret_key(&secp, key);
        let digest = ipp_digest(M::TYPE, body.as_bytes());
        let sig = secp.sign_schnorr_no_aux_rand(&secp256k1::Message::from_digest(digest), &kp);
        Ok(Self {
            msg_type: M::TYPE.to_string(),
            body,
            signer_pk_hex: hex::encode(kp.x_only_public_key().0.serialize()),
            sig_hex: hex::encode(sig.as_ref()),
        })
    }

    /// Verify the signature (and, when given, that `expected_signer` signed it), then parse.
    pub fn open<M: IppMessage>(&self, expected_signer: Option<&[u8; 32]>) -> Result<M, IppError> {
        if self.msg_type != M::TYPE {
            return Err(IppError::WrongType { expected: M::TYPE, got: self.msg_type.clone() });
        }
        let pk: [u8; 32] = hex::decode(&self.signer_pk_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(IppError::BadKey)?;
        if expected_signer.is_some_and(|e| e != &pk) {
            return Err(IppError::UnexpectedSigner);
        }
        let xonly = secp256k1::XOnlyPublicKey::from_slice(&pk).map_err(|_| IppError::BadKey)?;
        let sig_bytes = hex::decode(&self.sig_hex).map_err(|_| IppError::BadSignature)?;
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).map_err(|_| IppError::BadSignature)?;
        let digest = ipp_digest(&self.msg_type, self.body.as_bytes());
        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&sig, &secp256k1::Message::from_digest(digest), &xonly)
            .map_err(|_| IppError::BadSignature)?;
        serde_json::from_str(&self.body).map_err(|e| IppError::Json(e.to_string()))
    }

    /// The signer key, once `open` has succeeded for it.
    pub fn signer(&self) -> Option<[u8; 32]> {
        hex::decode(&self.signer_pk_hex).ok().and_then(|v| v.try_into().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn xonly(k: &secp256k1::SecretKey) -> [u8; 32] {
        secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), k).x_only_public_key().0.serialize()
    }

    fn commitment() -> Commitment {
        Commitment {
            version: IPP_VERSION,
            provider_id: 212,
            merchant_id: "m-42".into(),
            payment_request_id: "pr-7".into(),
            chain_id: 2,
            escrow_outpoints: vec![Outpoint { height: 100, output_idx: 1 }],
            amount_atoms: 1_250_000,
            settlement: Settlement::Crypto,
            fiat: None,
            fee_atoms: 5_625,
            fee_payer: FeePayer::Merchant,
            category: "digital-goods".into(),
            window_end_height: 1_300,
            window_end_unix: 1_800_000_000,
            settle_by_height: 1_400,
            agreement_hash_hex: "ab".repeat(32),
            kyc_level: "none".into(),
            compliance_profile: "eu-psd2-v3".into(),
            issued_at_unix: 1_790_000_000,
            expires_at_unix: 1_790_003_600,
        }
    }

    #[test]
    fn digest_is_domain_separated_by_type() {
        assert_ne!(ipp_digest("commitment", b"{}"), ipp_digest("fiat-paid", b"{}"));
        let mut h = blake3::Hasher::new();
        h.update(b"shisha/ipp/commitment/v1{}");
        assert_eq!(ipp_digest("commitment", b"{}"), <[u8; 32]>::from(h.finalize()));
    }

    #[test]
    fn sign_open_round_trip_and_tamper_checks() {
        let provider = key(0x21);
        let c = commitment();
        let signed = SignedMessage::sign(&c, &provider).unwrap();
        assert_eq!(signed.msg_type, "commitment");
        let pk = xonly(&provider);
        assert_eq!(signed.open::<Commitment>(Some(&pk)).unwrap(), c);

        // Another expected signer, another type, a changed body, a changed signature.
        assert_eq!(signed.open::<Commitment>(Some(&xonly(&key(0x22)))), Err(IppError::UnexpectedSigner));
        assert!(matches!(signed.open::<FiatPaid>(None), Err(IppError::WrongType { .. })));
        let mut tampered = signed.clone();
        tampered.body = tampered.body.replace("1250000", "9250000");
        assert_eq!(tampered.open::<Commitment>(Some(&pk)), Err(IppError::BadSignature));
        let mut swapped = signed.clone();
        swapped.signer_pk_hex = hex::encode(xonly(&key(0x22)));
        assert_eq!(swapped.open::<Commitment>(None), Err(IppError::BadSignature));

        // The envelope itself round-trips through JSON with a "type" field.
        let wire = serde_json::to_string(&signed).unwrap();
        assert!(wire.contains("\"type\":\"commitment\""));
        assert_eq!(serde_json::from_str::<SignedMessage>(&wire).unwrap(), signed);
    }

    #[test]
    fn commitment_checks() {
        let c = commitment();
        assert!(c.check(2_000, 300, 1_790_000_100).is_ok());
        assert!(c.check(1_600, 300, 1_790_000_100).is_err(), "settle-by too close to H");
        assert!(c.check(2_000, 300, 1_790_003_600).is_err(), "expired");
        let mut fiat = c.clone();
        fiat.settlement = Settlement::Fiat;
        assert!(fiat.check(2_000, 300, 1_790_000_100).is_err(), "fiat without terms");
        fiat.fiat = Some(FiatTerms {
            amount_minor: 1_250,
            currency: "EUR".into(),
            rate: "1000".into(),
            rate_source: "ecb".into(),
            rate_time_unix: 1_790_000_000,
        });
        assert!(fiat.check(2_000, 300, 1_790_000_100).is_ok());
        let json = serde_json::to_value(&fiat).unwrap();
        assert_eq!(json["settlement"], "fiat");
        assert_eq!(json["fee_payer"], "merchant");
        assert!(serde_json::to_value(&c).unwrap().get("fiat").is_none(), "crypto mode omits fiat");
    }

    #[test]
    fn every_message_type_tag_is_distinct() {
        let tags = [
            OpenBalanceRequest::TYPE, OpenBalanceAck::TYPE, FundingNotif::TYPE, PayHalfSign::TYPE,
            Commitment::TYPE, DeliveryConfirm::TYPE, BroadcastNotif::TYPE, DisputeOpen::TYPE,
            FiatPaid::TYPE, TopUpRequest::TYPE,
        ];
        let set: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(set.len(), tags.len());
    }
}
