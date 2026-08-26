// src/mmr_client/f2f.rs
//
// Track C — Filament-to-Filament (F2F) message codec.
// Track H — Protocol hardening: typed RejectReason, msg_id replay policy.
//
// F2F messages are wallet-to-wallet layer messages relayed by the full node.
// They are encrypted at Track D (relay) using X25519+ChaCha20-Poly1305 once
// the Filament Key Management Design is finalised (LC-59..LC-64, §13).
// In this implementation we send them in plaintext as `payload` bytes inside
// `RelayMessage` wire messages.
//
// **msg_id semantics (§4.1 in P2P_Phase10_Plan.md):**
//   Each F2F transmission carries a fresh 8-byte random `msg_id`.  The relay
//   node deduplicates by `relay_id = BLAKE3(payload)[0..8]` (Track H) — the
//   sender generates a new `msg_id` on every retransmit, so a changed `msg_id`
//   does not affect relay dedup (which is over the full payload including the
//   previous `msg_id`).  Wallet-layer dedup is by `(invoice_id, msg_id)` pair.
//
// Wire format (all LE):
//   magic(2) + msg_type(1) + msg_id(8) + payload_len(2) + payload(...)
//   Total overhead: 13 bytes per F2F message wrapper.

use crate::mmr_client::invoice::Invoice;

/// F2F message magic bytes.
pub const F2F_MAGIC: u16 = 0xF2F0; // "F2F"

// ─── Message type tags ────────────────────────────────────────────────────────

pub const F2F_TYPE_INVOICE_REQUEST: u8 = 0x01;
pub const F2F_TYPE_PAYMENT_PROOF:   u8 = 0x02;
pub const F2F_TYPE_PAYMENT_ACK:     u8 = 0x03;
pub const F2F_TYPE_INVOICE_CANCEL:  u8 = 0x04;
pub const F2F_TYPE_REJECT:          u8 = 0xFF;

// ─── Typed reject reason (Track H) ───────────────────────────────────────────

/// Typed reason for rejecting an F2F message.
///
/// Carried in an `F2fReject` response so the sender can distinguish between
/// temporary errors (retry) and permanent errors (do not retry).
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    /// Malformed wire format (bad magic, truncation, unsupported version).
    MalformedMessage     = 0x01,
    /// `invoice_id` is not known to the recipient.
    UnknownInvoice       = 0x02,
    /// Invoice is in a state that does not accept this message type.
    WrongState           = 0x03,
    /// Amount in `PaymentProof` does not match the invoice amount.
    AmountMismatch       = 0x04,
    /// `msg_id` was already processed (replay detected at wallet layer).
    DuplicateMsgId       = 0x05,
    /// MMR proof in `PaymentProof` failed verification.
    ProofInvalid         = 0x06,
    /// Invoice has expired (past `expiry_height`).
    InvoiceExpired       = 0x07,
    /// Generic / unspecified rejection.
    Other                = 0xFF,
}

impl RejectReason {
    pub fn tag(&self) -> u8 {
        match self {
            Self::MalformedMessage => 0x01,
            Self::UnknownInvoice   => 0x02,
            Self::WrongState       => 0x03,
            Self::AmountMismatch   => 0x04,
            Self::DuplicateMsgId   => 0x05,
            Self::ProofInvalid     => 0x06,
            Self::InvoiceExpired   => 0x07,
            Self::Other            => 0xFF,
        }
    }

    pub fn from_tag(t: u8) -> Self {
        match t {
            0x01 => Self::MalformedMessage,
            0x02 => Self::UnknownInvoice,
            0x03 => Self::WrongState,
            0x04 => Self::AmountMismatch,
            0x05 => Self::DuplicateMsgId,
            0x06 => Self::ProofInvalid,
            0x07 => Self::InvoiceExpired,
            _    => Self::Other,
        }
    }

    /// True if the error is transient and the sender may retry.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::WrongState | Self::Other)
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MalformedMessage => "malformed message",
            Self::UnknownInvoice   => "unknown invoice_id",
            Self::WrongState       => "invoice in wrong state",
            Self::AmountMismatch   => "payment amount mismatch",
            Self::DuplicateMsgId   => "duplicate msg_id (replay)",
            Self::ProofInvalid     => "MMR proof invalid",
            Self::InvoiceExpired   => "invoice expired",
            Self::Other            => "unspecified rejection",
        };
        write!(f, "{s}")
    }
}

// ─── F2F messages ─────────────────────────────────────────────────────────────

/// Sender → Receiver: "here is the invoice I want you to fulfil".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceRequest {
    /// Per-transmission random to prevent relay replay at wallet layer.
    pub msg_id: [u8; 8],
    /// Full invoice encoded with `Invoice::encode()`.
    pub invoice_bytes: Vec<u8>,
}

/// Sender → Receiver: "I submitted this transaction; here are the positional hints".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentProof {
    /// Per-transmission random.
    pub msg_id: [u8; 8],
    /// Invoice ID this proof refers to.
    pub invoice_id: [u8; 16],
    /// Transaction id of the fulfilling transaction.
    pub txid: [u8; 32],
    /// Predicted block height of the output.
    pub height_hint: u32,
    /// Predicted output index.
    pub idx_hint: u16,
    /// Optional serialised `WeightedMMRBatchProof` bytes.
    /// Empty = proof not yet available; receiver should watch for `TxInclusionNotif`.
    pub mmr_proof_bytes: Vec<u8>,
}

/// Receiver → Sender: "I accepted and recorded the payment proof".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAck {
    /// Echoes the `msg_id` from the `PaymentProof` being acknowledged.
    pub msg_id: [u8; 8],
    /// Invoice ID this ack refers to.
    pub invoice_id: [u8; 16],
}

/// Either party → other party: "cancel this invoice".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceCancel {
    pub msg_id: [u8; 8],
    pub invoice_id: [u8; 16],
    /// Optional human-readable reason (≤ 64 bytes).
    pub reason: String,
}

/// Full node → either party: "this F2F message was rejected".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2fReject {
    /// The `msg_id` from the rejected message, or `[0u8; 8]` if not parseable.
    pub rejected_msg_id: [u8; 8],
    pub reason: RejectReason,
    /// Optional ASCII description (≤ 64 bytes).
    pub description: String,
}

// ─── Top-level enum ───────────────────────────────────────────────────────────

/// All F2F message variants, parsed from wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum F2fMessage {
    InvoiceRequest(InvoiceRequest),
    PaymentProof(PaymentProof),
    PaymentAck(PaymentAck),
    InvoiceCancel(InvoiceCancel),
    Reject(F2fReject),
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum F2fError {
    Truncated,
    WrongMagic(u16),
    UnknownType(u8),
    InvalidUtf8,
    InvoiceDecodeError(crate::mmr_client::invoice::InvoiceError),
}

impl std::fmt::Display for F2fError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated          => write!(f, "F2F message truncated"),
            Self::WrongMagic(m)     => write!(f, "wrong F2F magic 0x{m:04X}"),
            Self::UnknownType(t)    => write!(f, "unknown F2F message type 0x{t:02X}"),
            Self::InvalidUtf8       => write!(f, "F2F string field is not valid UTF-8"),
            Self::InvoiceDecodeError(e) => write!(f, "F2F invoice decode: {e}"),
        }
    }
}

impl std::error::Error for F2fError {}

// ─── Wire encode / decode ─────────────────────────────────────────────────────

/// Encode an F2F message to bytes.
pub fn f2f_encode(msg: &F2fMessage) -> Vec<u8> {
    let (msg_type, payload) = match msg {
        F2fMessage::InvoiceRequest(m) => {
            let mut p = Vec::new();
            p.extend_from_slice(&m.msg_id);
            p.extend_from_slice(&(m.invoice_bytes.len() as u16).to_le_bytes());
            p.extend_from_slice(&m.invoice_bytes);
            (F2F_TYPE_INVOICE_REQUEST, p)
        }
        F2fMessage::PaymentProof(m) => {
            let mut p = Vec::new();
            p.extend_from_slice(&m.msg_id);
            p.extend_from_slice(&m.invoice_id);
            p.extend_from_slice(&m.txid);
            p.extend_from_slice(&m.height_hint.to_le_bytes());
            p.extend_from_slice(&m.idx_hint.to_le_bytes());
            p.extend_from_slice(&(m.mmr_proof_bytes.len() as u16).to_le_bytes());
            p.extend_from_slice(&m.mmr_proof_bytes);
            (F2F_TYPE_PAYMENT_PROOF, p)
        }
        F2fMessage::PaymentAck(m) => {
            let mut p = Vec::new();
            p.extend_from_slice(&m.msg_id);
            p.extend_from_slice(&m.invoice_id);
            (F2F_TYPE_PAYMENT_ACK, p)
        }
        F2fMessage::InvoiceCancel(m) => {
            let reason_b = m.reason.as_bytes();
            let reason_b = &reason_b[..reason_b.len().min(64)];
            let mut p = Vec::new();
            p.extend_from_slice(&m.msg_id);
            p.extend_from_slice(&m.invoice_id);
            p.push(reason_b.len() as u8);
            p.extend_from_slice(reason_b);
            (F2F_TYPE_INVOICE_CANCEL, p)
        }
        F2fMessage::Reject(m) => {
            let desc_b = m.description.as_bytes();
            let desc_b = &desc_b[..desc_b.len().min(64)];
            let mut p = Vec::new();
            p.extend_from_slice(&m.rejected_msg_id);
            p.push(m.reason.tag());
            p.push(desc_b.len() as u8);
            p.extend_from_slice(desc_b);
            (F2F_TYPE_REJECT, p)
        }
    };

    // Outer wrapper: magic(2) + type(1) + payload_len(2) + payload
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.extend_from_slice(&F2F_MAGIC.to_le_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Decode an F2F message from bytes.
pub fn f2f_decode(data: &[u8]) -> Result<F2fMessage, F2fError> {
    if data.len() < 5 {
        return Err(F2fError::Truncated);
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != F2F_MAGIC {
        return Err(F2fError::WrongMagic(magic));
    }
    let msg_type    = data[2];
    let payload_len = u16::from_le_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + payload_len {
        return Err(F2fError::Truncated);
    }
    let payload = &data[5..5 + payload_len];

    match msg_type {
        F2F_TYPE_INVOICE_REQUEST => {
            if payload.len() < 10 { return Err(F2fError::Truncated); }
            let msg_id: [u8; 8] = payload[0..8].try_into().unwrap();
            let inv_len = u16::from_le_bytes([payload[8], payload[9]]) as usize;
            if payload.len() < 10 + inv_len { return Err(F2fError::Truncated); }
            let invoice_bytes = payload[10..10 + inv_len].to_vec();
            Ok(F2fMessage::InvoiceRequest(InvoiceRequest { msg_id, invoice_bytes }))
        }
        F2F_TYPE_PAYMENT_PROOF => {
            // msg_id(8) + invoice_id(16) + txid(32) + height_hint(4) + idx_hint(2) + proof_len(2) + proof(...)
            if payload.len() < 64 { return Err(F2fError::Truncated); }
            let msg_id:     [u8; 8]  = payload[0..8].try_into().unwrap();
            let invoice_id: [u8; 16] = payload[8..24].try_into().unwrap();
            let txid:       [u8; 32] = payload[24..56].try_into().unwrap();
            let height_hint = u32::from_le_bytes(payload[56..60].try_into().unwrap());
            let idx_hint    = u16::from_le_bytes(payload[60..62].try_into().unwrap());
            let proof_len   = u16::from_le_bytes(payload[62..64].try_into().unwrap()) as usize;
            if payload.len() < 64 + proof_len { return Err(F2fError::Truncated); }
            let mmr_proof_bytes = payload[64..64 + proof_len].to_vec();
            Ok(F2fMessage::PaymentProof(PaymentProof {
                msg_id, invoice_id, txid, height_hint, idx_hint, mmr_proof_bytes,
            }))
        }
        F2F_TYPE_PAYMENT_ACK => {
            if payload.len() < 24 { return Err(F2fError::Truncated); }
            let msg_id:     [u8; 8]  = payload[0..8].try_into().unwrap();
            let invoice_id: [u8; 16] = payload[8..24].try_into().unwrap();
            Ok(F2fMessage::PaymentAck(PaymentAck { msg_id, invoice_id }))
        }
        F2F_TYPE_INVOICE_CANCEL => {
            if payload.len() < 25 { return Err(F2fError::Truncated); }
            let msg_id:     [u8; 8]  = payload[0..8].try_into().unwrap();
            let invoice_id: [u8; 16] = payload[8..24].try_into().unwrap();
            let reason_len = payload[24] as usize;
            if payload.len() < 25 + reason_len { return Err(F2fError::Truncated); }
            let reason = std::str::from_utf8(&payload[25..25 + reason_len])
                .map_err(|_| F2fError::InvalidUtf8)?
                .to_string();
            Ok(F2fMessage::InvoiceCancel(InvoiceCancel { msg_id, invoice_id, reason }))
        }
        F2F_TYPE_REJECT => {
            if payload.len() < 10 { return Err(F2fError::Truncated); }
            let rejected_msg_id: [u8; 8] = payload[0..8].try_into().unwrap();
            let reason       = RejectReason::from_tag(payload[8]);
            let desc_len     = payload[9] as usize;
            if payload.len() < 10 + desc_len { return Err(F2fError::Truncated); }
            let description = std::str::from_utf8(&payload[10..10 + desc_len])
                .map_err(|_| F2fError::InvalidUtf8)?
                .to_string();
            Ok(F2fMessage::Reject(F2fReject { rejected_msg_id, reason, description }))
        }
        t => Err(F2fError::UnknownType(t)),
    }
}

/// Generate a fresh random `msg_id` (8-byte).
pub fn new_msg_id() -> [u8; 8] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let addr = &t as *const _ as u64;
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    addr.hash(&mut h);
    h.finish().to_le_bytes()
}

/// Compute the relay dedup id: `BLAKE3(payload)[0..8]` (Track H).
///
/// Gap 10 Phase 2 (Jul 3, 2026): the implementation moved to
/// `crates/common-types/src/common/relay_hash.rs` — p2p-proto's
/// relay_store.rs needed it and can't depend back on mmr_client (would
/// recreate the cycle Gap 10 broke). Re-exported here so every existing
/// `crate::mmr_client::f2f::relay_id` call site keeps resolving unchanged.
pub use common_types::common::relay_hash::relay_id;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr_client::invoice::{Invoice, InvoiceState};

    fn sample_invoice_bytes() -> Vec<u8> {
        let inv = Invoice {
            invoice_id:     [1u8; 16],
            recipient:      [2u8; 32],
            amount_atoms:   500,
            shard_id:       0,
            memo:           "pay me".into(),
            expiry_height:  100,
            created_at_ms:  0,
            state:          InvoiceState::Created,
            height_hint:    None,
            idx_hint:       None,
            txid:           None,
            relay_node:     None,
            mmr_proof_bytes: None,
        };
        inv.encode().unwrap()
    }

    // LC-18
    #[test]
    fn f2f_invoice_request_roundtrip() {
        let msg = F2fMessage::InvoiceRequest(InvoiceRequest {
            msg_id: [0xAAu8; 8],
            invoice_bytes: sample_invoice_bytes(),
        });
        let bytes = f2f_encode(&msg);
        let decoded = f2f_decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    // LC-19
    #[test]
    fn f2f_payment_proof_roundtrip() {
        let msg = F2fMessage::PaymentProof(PaymentProof {
            msg_id:          [0x01u8; 8],
            invoice_id:      [0x02u8; 16],
            txid:            [0x03u8; 32],
            height_hint:     42_000,
            idx_hint:        7,
            mmr_proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
        let bytes = f2f_encode(&msg);
        let decoded = f2f_decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    // LC-20
    #[test]
    fn f2f_payment_ack_roundtrip() {
        let msg = F2fMessage::PaymentAck(PaymentAck {
            msg_id:     [0x11u8; 8],
            invoice_id: [0x22u8; 16],
        });
        assert_eq!(f2f_decode(&f2f_encode(&msg)).unwrap(), msg);
    }

    // LC-21
    #[test]
    fn f2f_invoice_cancel_roundtrip() {
        let msg = F2fMessage::InvoiceCancel(InvoiceCancel {
            msg_id:     [0x33u8; 8],
            invoice_id: [0x44u8; 16],
            reason:     "changed my mind".to_string(),
        });
        assert_eq!(f2f_decode(&f2f_encode(&msg)).unwrap(), msg);
    }

    // LC-22
    #[test]
    fn f2f_reject_roundtrip_all_reasons() {
        let reasons = [
            RejectReason::MalformedMessage,
            RejectReason::UnknownInvoice,
            RejectReason::WrongState,
            RejectReason::AmountMismatch,
            RejectReason::DuplicateMsgId,
            RejectReason::ProofInvalid,
            RejectReason::InvoiceExpired,
            RejectReason::Other,
        ];
        for reason in reasons {
            let msg = F2fMessage::Reject(F2fReject {
                rejected_msg_id: [0xFFu8; 8],
                reason:          reason.clone(),
                description:     "test".to_string(),
            });
            let decoded = f2f_decode(&f2f_encode(&msg)).unwrap();
            if let F2fMessage::Reject(r) = decoded {
                assert_eq!(r.reason, reason);
                assert_eq!(r.description, "test");
            } else {
                panic!("wrong variant");
            }
        }
    }

    // LC-23
    #[test]
    fn f2f_wrong_magic_rejected() {
        let mut bytes = f2f_encode(&F2fMessage::PaymentAck(PaymentAck {
            msg_id:     [0u8; 8],
            invoice_id: [0u8; 16],
        }));
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        assert!(matches!(f2f_decode(&bytes), Err(F2fError::WrongMagic(_))));
    }

    // LC-24
    #[test]
    fn f2f_truncated_rejected() {
        let bytes = f2f_encode(&F2fMessage::PaymentAck(PaymentAck {
            msg_id:     [0u8; 8],
            invoice_id: [0u8; 16],
        }));
        assert!(matches!(f2f_decode(&bytes[..3]), Err(F2fError::Truncated)));
    }

    // LC-25 (Track H): relay_id is stable for same payload
    #[test]
    fn relay_id_is_deterministic() {
        let payload = b"hello relay";
        let id1 = relay_id(payload);
        let id2 = relay_id(payload);
        assert_eq!(id1, id2);
    }

    // LC-54 (Track H): changing msg_id changes the payload and thus the relay_id
    #[test]
    fn relay_id_changes_when_msg_id_changes() {
        let msg1 = F2fMessage::PaymentAck(PaymentAck {
            msg_id: [0u8; 8],
            invoice_id: [1u8; 16],
        });
        let msg2 = F2fMessage::PaymentAck(PaymentAck {
            msg_id: [1u8; 8],
            invoice_id: [1u8; 16],
        });
        let bytes1 = f2f_encode(&msg1);
        let bytes2 = f2f_encode(&msg2);
        assert_ne!(relay_id(&bytes1), relay_id(&bytes2));
    }

    // LC-55 (Track H): same payload → same relay_id (relay dedup works)
    #[test]
    fn relay_id_same_for_identical_payload() {
        let msg = F2fMessage::PaymentAck(PaymentAck {
            msg_id: [0xABu8; 8],
            invoice_id: [0xCDu8; 16],
        });
        let bytes = f2f_encode(&msg);
        assert_eq!(relay_id(&bytes), relay_id(&bytes));
    }

    // LC-56 (Track H): RejectReason tag roundtrip
    #[test]
    fn reject_reason_tag_roundtrip() {
        for tag in 0x01..=0x07u8 {
            assert_eq!(RejectReason::from_tag(tag).tag(), tag);
        }
        assert_eq!(RejectReason::from_tag(0xFF).tag(), 0xFF);
    }

    // LC-57 (Track H): retryable reasons are correct
    #[test]
    fn reject_reason_retryable_flags() {
        assert!(!RejectReason::MalformedMessage.is_retryable());
        assert!(!RejectReason::UnknownInvoice.is_retryable());
        assert!(RejectReason::WrongState.is_retryable());
        assert!(!RejectReason::AmountMismatch.is_retryable());
        assert!(!RejectReason::DuplicateMsgId.is_retryable());
        assert!(!RejectReason::ProofInvalid.is_retryable());
        assert!(!RejectReason::InvoiceExpired.is_retryable());
        assert!(RejectReason::Other.is_retryable());
    }

    // LC-58 (Track H): unknown type rejected
    #[test]
    fn f2f_unknown_type_rejected() {
        let mut bytes = f2f_encode(&F2fMessage::PaymentAck(PaymentAck {
            msg_id: [0u8; 8],
            invoice_id: [0u8; 16],
        }));
        bytes[2] = 0x42; // overwrite type byte
        assert!(matches!(f2f_decode(&bytes), Err(F2fError::UnknownType(0x42))));
    }
}
