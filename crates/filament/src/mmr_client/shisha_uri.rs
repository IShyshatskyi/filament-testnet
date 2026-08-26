// src/mmr_client/shisha_uri.rs
//
// Track B — `shisha:` URI v2 parser and encoder.
//
// Scheme:  shisha:<recipient_hex>?<params>
//
// Required params: (none — all optional; a bare address is valid)
// Optional params:
//   amount=<u64>         atoms; omit for "any amount / donation"
//   shard=<u16>          target shard (default: 0)
//   memo=<pct-encoded>   human-readable purpose (≤128 bytes UTF-8)
//   expiry=<u32>         beacon block height after which invoice is void
//   height_hint=<u32>    predicted inclusion height (sender fills in)
//   idx_hint=<u16>       predicted output index (sender fills in)
//   txid=<hex64>         txid (sender fills in after broadcast)
//   relay=<pct-encoded>  preferred relay node e.g. "127.0.0.1:8334"
//   invoice_id=<b64url22> stable 16-byte invoice id (base64url, no padding)
//
// Design reference: `docs/plan/P2P_Phase10_Plan.md` §3

use crate::mmr_client::invoice::{
    base64url_decode16, base64url_encode16, decode_hex32, encode_hex32, Invoice, InvoiceError,
    InvoiceState,
};

/// Parsed representation of a `shisha:` URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShishaUri {
    /// 32-byte recipient address.
    pub recipient: [u8; 32],
    /// Requested amount in atoms (0 = any).
    pub amount_atoms: u64,
    /// Target shard (default 0).
    pub shard_id: u16,
    /// Human-readable description.
    pub memo: String,
    /// Invoice expiry as beacon block height (0 = no expiry).
    pub expiry_height: u32,
    // ── Sender-filled fields (present only after tx construction) ───────────
    pub height_hint: Option<u32>,
    pub idx_hint: Option<u16>,
    pub txid: Option<[u8; 32]>,
    /// Preferred relay node address string.
    pub relay_node: Option<String>,
    /// Stable invoice id (base64url, 22 chars without padding).
    pub invoice_id: Option<[u8; 16]>,
}

impl ShishaUri {
    /// Parse a `shisha:` URI string.
    pub fn parse(s: &str) -> Result<Self, ShishaUriError> {
        let s = s.trim();
        let body = s
            .strip_prefix("shisha:")
            .ok_or(ShishaUriError::MissingScheme)?;

        // Split on '?' to separate recipient hex from query params.
        let (recipient_hex, query) = match body.find('?') {
            Some(pos) => (&body[..pos], &body[pos + 1..]),
            None      => (body, ""),
        };

        if recipient_hex.is_empty() {
            return Err(ShishaUriError::MissingRecipient);
        }
        let recipient = decode_hex32(recipient_hex)
            .map_err(|_| ShishaUriError::InvalidRecipient)?;

        let mut amount_atoms:  u64  = 0;
        let mut shard_id:      u16  = 0;
        let mut memo:          String = String::new();
        let mut expiry_height: u32  = 0;
        let mut height_hint:   Option<u32> = None;
        let mut idx_hint:      Option<u16> = None;
        let mut txid:          Option<[u8; 32]> = None;
        let mut relay_node:    Option<String> = None;
        let mut invoice_id:    Option<[u8; 16]> = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let eq = pair.find('=').ok_or(ShishaUriError::MalformedParam)?;
            let key = &pair[..eq];
            let val = pct_decode(&pair[eq + 1..]);
            match key {
                "amount"       => {
                    amount_atoms = val.parse().map_err(|_| ShishaUriError::InvalidParam("amount"))?;
                }
                "shard"        => {
                    shard_id = val.parse().map_err(|_| ShishaUriError::InvalidParam("shard"))?;
                }
                "memo"         => {
                    if val.len() > 128 {
                        return Err(ShishaUriError::MemoTooLong);
                    }
                    memo = val;
                }
                "expiry"       => {
                    expiry_height = val.parse().map_err(|_| ShishaUriError::InvalidParam("expiry"))?;
                }
                "height_hint"  => {
                    height_hint = Some(val.parse().map_err(|_| ShishaUriError::InvalidParam("height_hint"))?);
                }
                "idx_hint"     => {
                    idx_hint = Some(val.parse().map_err(|_| ShishaUriError::InvalidParam("idx_hint"))?);
                }
                "txid"         => {
                    txid = Some(decode_hex32(&val).map_err(|_| ShishaUriError::InvalidParam("txid"))?);
                }
                "relay"        => {
                    relay_node = Some(val);
                }
                "invoice_id"   => {
                    invoice_id = Some(
                        base64url_decode16(&val)
                            .map_err(|_| ShishaUriError::InvalidParam("invoice_id"))?,
                    );
                }
                _ => {} // ignore unknown params for forward compat
            }
        }

        Ok(Self {
            recipient,
            amount_atoms,
            shard_id,
            memo,
            expiry_height,
            height_hint,
            idx_hint,
            txid,
            relay_node,
            invoice_id,
        })
    }

    /// Encode to a `shisha:` URI string.
    pub fn encode(&self) -> String {
        let mut s = format!("shisha:{}", encode_hex32(&self.recipient));
        let mut sep = '?';

        macro_rules! param {
            ($key:literal, $val:expr) => {{
                s.push(sep);
                sep = '&';
                s.push_str($key);
                s.push('=');
                s.push_str(&pct_encode(&$val.to_string()));
            }};
        }

        if self.amount_atoms > 0     { param!("amount",  self.amount_atoms); }
        if self.shard_id > 0         { param!("shard",   self.shard_id); }
        if !self.memo.is_empty()     { param!("memo",    self.memo); }
        if self.expiry_height > 0    { param!("expiry",  self.expiry_height); }
        if let Some(h) = self.height_hint { param!("height_hint", h); }
        if let Some(i) = self.idx_hint    { param!("idx_hint",    i); }
        if let Some(t) = &self.txid {
            s.push(sep);
            sep = '&';
            s.push_str("txid=");
            s.push_str(&encode_hex32(t));
        }
        if let Some(r) = &self.relay_node { param!("relay", r); }
        if let Some(id) = &self.invoice_id {
            s.push(sep);
            s.push_str("invoice_id=");
            s.push_str(&base64url_encode16(id));
        }

        s
    }

    /// Convert this URI into an `Invoice` struct for local storage.
    pub fn to_invoice(&self, created_at_ms: u64) -> Invoice {
        Invoice {
            invoice_id:      self.invoice_id.unwrap_or_else(crate::mmr_client::invoice::new_invoice_id),
            recipient:       self.recipient,
            amount_atoms:    self.amount_atoms,
            shard_id:        self.shard_id,
            memo:            self.memo.clone(),
            expiry_height:   self.expiry_height,
            created_at_ms,
            state:           InvoiceState::Created,
            height_hint:     self.height_hint,
            idx_hint:        self.idx_hint,
            txid:            self.txid,
            relay_node:      self.relay_node.clone(),
            mmr_proof_bytes: None,
        }
    }

    /// Build a URI from an `Invoice` (for sharing with the sender).
    pub fn from_invoice(inv: &Invoice) -> Self {
        Self {
            recipient:    inv.recipient,
            amount_atoms: inv.amount_atoms,
            shard_id:     inv.shard_id,
            memo:         inv.memo.clone(),
            expiry_height: inv.expiry_height,
            height_hint:  inv.height_hint,
            idx_hint:     inv.idx_hint,
            txid:         inv.txid,
            relay_node:   inv.relay_node.clone(),
            invoice_id:   Some(inv.invoice_id),
        }
    }
}

// ─── AB-6: Contact address-card URI ──────────────────────────────────────────

/// A contact-card URI — `shisha:?addr=<64hex>[&shard=<u16>][&name=<pct-encoded>]`.
///
/// Distinguished from a payment `ShishaUri` by the empty path component and the
/// presence of an `addr` query parameter.  Used to share a contact's address as
/// a QR code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressCard {
    /// 32-byte address of the contact.
    pub address:  [u8; 32],
    /// Preferred shard (0 = auto).
    pub shard_id: u16,
    /// Display name (empty string if not provided).
    pub name:     String,
}

impl AddressCard {
    /// Parse a `shisha:?addr=…` contact-card URI.
    pub fn parse(s: &str) -> Result<Self, ShishaUriError> {
        let s = s.trim();
        let body = s.strip_prefix("shisha:").ok_or(ShishaUriError::MissingScheme)?;

        // Address-card form: empty path, query starts with '?'.
        let query = body.strip_prefix('?').ok_or(ShishaUriError::MissingRecipient)?;

        let mut address: Option<[u8; 32]> = None;
        let mut shard_id: u16 = 0;
        let mut name = String::new();

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let eq = pair.find('=').ok_or(ShishaUriError::MalformedParam)?;
            let key = &pair[..eq];
            let val = pct_decode(&pair[eq + 1..]);
            match key {
                "addr"  => {
                    address = Some(
                        decode_hex32(&val).map_err(|_| ShishaUriError::InvalidRecipient)?,
                    );
                }
                "shard" => {
                    shard_id = val.parse().map_err(|_| ShishaUriError::InvalidParam("shard"))?;
                }
                "name"  => name = val,
                _       => {}
            }
        }

        Ok(Self {
            address:  address.ok_or(ShishaUriError::MissingRecipient)?,
            shard_id,
            name,
        })
    }

    /// Encode as a `shisha:?addr=…` URI string.
    pub fn encode(&self) -> String {
        let mut s = format!("shisha:?addr={}", encode_hex32(&self.address));
        if self.shard_id > 0 {
            s.push_str(&format!("&shard={}", self.shard_id));
        }
        if !self.name.is_empty() {
            s.push_str(&format!("&name={}", pct_encode(&self.name)));
        }
        s
    }
}

// ─── PD-6: Node address URI ──────────────────────────────────────────────────

/// A full-node address URI — `shishanet://host:port[?pk=<64hex>]`.
///
/// Used to share a node's address as a QR code for out-of-band peer exchange.
/// The optional `pk` field carries the node's 32-byte Noise static public key;
/// light clients can use it to verify identity before connecting (future).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddr {
    pub host: String,
    pub port: u16,
    /// 32-byte Noise static public key of the node (optional, future use).
    pub pubkey: Option<[u8; 32]>,
}

impl NodeAddr {
    /// Parse a `shishanet://host:port[?pk=<64hex>]` URI.
    pub fn parse(s: &str) -> Result<Self, ShishaUriError> {
        let s = s.trim();
        let rest = s.strip_prefix("shishanet://").ok_or(ShishaUriError::MissingScheme)?;

        // Split at '?' to separate authority from query.
        let (authority, query_opt) = match rest.find('?') {
            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
            None      => (rest, None),
        };

        // authority = host:port
        let colon = authority.rfind(':').ok_or(ShishaUriError::MissingRecipient)?;
        let host = authority[..colon].to_string();
        let port: u16 = authority[colon + 1..]
            .parse()
            .map_err(|_| ShishaUriError::InvalidParam("port"))?;

        if host.is_empty() {
            return Err(ShishaUriError::MissingRecipient);
        }

        let mut pubkey: Option<[u8; 32]> = None;
        if let Some(query) = query_opt {
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let eq = pair.find('=').ok_or(ShishaUriError::MalformedParam)?;
                let key = &pair[..eq];
                let val = pct_decode(&pair[eq + 1..]);
                if key == "pk" {
                    pubkey = Some(decode_hex32(&val).map_err(|_| ShishaUriError::InvalidParam("pk"))?);
                }
            }
        }

        Ok(Self { host, port, pubkey })
    }

    /// Encode as `shishanet://host:port[?pk=<64hex>]`.
    pub fn encode(&self) -> String {
        let mut s = format!("shishanet://{}:{}", self.host, self.port);
        if let Some(pk) = &self.pubkey {
            s.push_str(&format!("?pk={}", encode_hex32(pk)));
        }
        s
    }
}

// ─── URI error ────────────────────────────────────────────────────────────────

/// Errors from `ShishaUri::parse`.
#[derive(Debug, PartialEq, Eq)]
pub enum ShishaUriError {
    /// Input does not start with `shisha:`.
    MissingScheme,
    /// No recipient hex follows the scheme.
    MissingRecipient,
    /// Recipient is not a valid 64-char hex address.
    InvalidRecipient,
    /// Memo exceeds 128 bytes.
    MemoTooLong,
    /// A query parameter is not `key=value`.
    MalformedParam,
    /// A numeric or hex parameter could not be parsed.
    InvalidParam(&'static str),
}

impl std::fmt::Display for ShishaUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingScheme     => write!(f, "URI must start with \"shisha:\""),
            Self::MissingRecipient  => write!(f, "no recipient address in URI"),
            Self::InvalidRecipient  => write!(f, "recipient is not a valid 64-char hex address"),
            Self::MemoTooLong       => write!(f, "memo exceeds 128 bytes"),
            Self::MalformedParam    => write!(f, "query param is not key=value"),
            Self::InvalidParam(k)   => write!(f, "invalid value for param '{k}'"),
        }
    }
}

impl std::error::Error for ShishaUriError {}

// ─── Percent-encoding helpers ─────────────────────────────────────────────────

/// Percent-decode a URI component (replaces `%XX` with the decoded byte).
fn pct_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                out.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

/// Percent-encode a string (RFC 3986 unreserved chars pass through unchanged).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xF) as usize] as char);
            }
        }
    }
    out
}

const HEX: &[u8] = b"0123456789ABCDEF";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_hex() -> String {
        "abcdef01234567890123456789012345abcdef01234567890123456789012345".to_string()
    }

    fn addr() -> [u8; 32] {
        decode_hex32(&addr_hex()).unwrap()
    }

    // LC-11
    #[test]
    fn uri_roundtrip_minimal() {
        let uri = ShishaUri {
            recipient:    addr(),
            amount_atoms: 0,
            shard_id:     0,
            memo:         String::new(),
            expiry_height: 0,
            height_hint:  None,
            idx_hint:     None,
            txid:         None,
            relay_node:   None,
            invoice_id:   None,
        };
        let encoded = uri.encode();
        assert_eq!(encoded, format!("shisha:{}", addr_hex()));
        let parsed = ShishaUri::parse(&encoded).unwrap();
        assert_eq!(parsed.recipient, addr());
        assert_eq!(parsed.amount_atoms, 0);
        assert_eq!(parsed.shard_id, 0);
    }

    // LC-12
    #[test]
    fn uri_roundtrip_all_fields() {
        let uri = ShishaUri {
            recipient:     addr(),
            amount_atoms:  1_000_000_000,
            shard_id:      3,
            memo:          "coffee & cake".to_string(),
            expiry_height: 999_999,
            height_hint:   Some(50_000),
            idx_hint:      Some(7),
            txid:          Some([0xBBu8; 32]),
            relay_node:    Some("127.0.0.1:8334".to_string()),
            invoice_id:    Some([0x42u8; 16]),
        };
        let encoded = uri.encode();
        let parsed = ShishaUri::parse(&encoded).unwrap();
        assert_eq!(parsed.recipient,     addr());
        assert_eq!(parsed.amount_atoms,  1_000_000_000);
        assert_eq!(parsed.shard_id,      3);
        assert_eq!(parsed.memo,          "coffee & cake");
        assert_eq!(parsed.expiry_height, 999_999);
        assert_eq!(parsed.height_hint,   Some(50_000));
        assert_eq!(parsed.idx_hint,      Some(7));
        assert_eq!(parsed.txid,          Some([0xBBu8; 32]));
        assert_eq!(parsed.relay_node,    Some("127.0.0.1:8334".to_string()));
        assert_eq!(parsed.invoice_id,    Some([0x42u8; 16]));
    }

    // LC-13
    #[test]
    fn uri_wrong_scheme_rejected() {
        assert!(matches!(
            ShishaUri::parse("bitcoin:1A2B3C"),
            Err(ShishaUriError::MissingScheme)
        ));
    }

    // LC-14
    #[test]
    fn uri_invalid_recipient_rejected() {
        assert!(matches!(
            ShishaUri::parse("shisha:ZZZZ?amount=100"),
            Err(ShishaUriError::InvalidRecipient)
        ));
    }

    // LC-15
    #[test]
    fn uri_memo_too_long_rejected() {
        let long_memo = "A".repeat(129);
        let uri = format!("shisha:{}?memo={}", addr_hex(), long_memo);
        assert!(matches!(ShishaUri::parse(&uri), Err(ShishaUriError::MemoTooLong)));
    }

    // LC-16
    #[test]
    fn uri_unknown_params_ignored() {
        let uri = format!("shisha:{}?amount=42&future_param=xyz", addr_hex());
        let parsed = ShishaUri::parse(&uri).unwrap();
        assert_eq!(parsed.amount_atoms, 42);
    }

    // LC-17
    #[test]
    fn uri_to_invoice_roundtrip() {
        let uri = ShishaUri {
            recipient:     addr(),
            amount_atoms:  500,
            shard_id:      1,
            memo:          "test".to_string(),
            expiry_height: 10_000,
            height_hint:   None,
            idx_hint:      None,
            txid:          None,
            relay_node:    None,
            invoice_id:    Some([0x01u8; 16]),
        };
        let inv = uri.to_invoice(1_700_000_000_000);
        assert_eq!(inv.recipient,    addr());
        assert_eq!(inv.amount_atoms, 500);
        assert_eq!(inv.shard_id,     1);
        assert_eq!(inv.memo,         "test");
        let back = ShishaUri::from_invoice(&inv);
        assert_eq!(back.recipient,    addr());
        assert_eq!(back.amount_atoms, 500);
    }

    #[test]
    fn pct_encoding_roundtrip() {
        let s = "hello world & more / stuff";
        assert_eq!(pct_decode(&pct_encode(s)), s);
    }

    // AB-6 — AddressCard tests
    #[test]
    fn address_card_parse_minimal() {
        let addr = "a".repeat(64);
        let uri = format!("shisha:?addr={}", addr);
        let card = AddressCard::parse(&uri).unwrap();
        assert_eq!(hex::encode(card.address), addr);
        assert_eq!(card.shard_id, 0);
        assert!(card.name.is_empty());
    }

    #[test]
    fn address_card_parse_with_name_and_shard() {
        let addr = "0b".repeat(32);
        let uri = format!("shisha:?addr={}&shard=3&name=Alice%20Smith", addr);
        let card = AddressCard::parse(&uri).unwrap();
        assert_eq!(card.name, "Alice Smith");
        assert_eq!(card.shard_id, 3);
    }

    #[test]
    fn address_card_encode_roundtrip() {
        let address = [0xCCu8; 32];
        let card = AddressCard { address, shard_id: 5, name: "Bob & Carol".into() };
        let uri = card.encode();
        let parsed = AddressCard::parse(&uri).unwrap();
        assert_eq!(parsed.address, address);
        assert_eq!(parsed.shard_id, 5);
        assert_eq!(parsed.name, "Bob & Carol");
    }

    #[test]
    fn address_card_wrong_scheme_fails() {
        let err = AddressCard::parse("bitcoin:?addr=aabbccdd").unwrap_err();
        assert_eq!(err, ShishaUriError::MissingScheme);
    }

    #[test]
    fn address_card_missing_addr_param_fails() {
        let err = AddressCard::parse("shisha:?shard=1&name=Alice").unwrap_err();
        assert_eq!(err, ShishaUriError::MissingRecipient);
    }

    // ── PD-T-6: get_invoice_qr encodes shisha URI ───────────────────────────

    /// Simulates the `get_invoice_qr` Tauri command: Invoice → URI → parse →
    /// same invoice_id.  Verifies the full encode/decode round-trip used by the
    /// QR display path in the Filament app.
    #[test]
    fn get_invoice_qr_encodes_shisha_uri() {
        let uri = ShishaUri {
            recipient:     addr(),
            amount_atoms:  1_234_567,
            shard_id:      2,
            memo:          "invoice qr test".to_string(),
            expiry_height: 50_000,
            height_hint:   None,
            idx_hint:      None,
            txid:          None,
            relay_node:    None,
            invoice_id:    Some([0xABu8; 16]),
        };
        // Simulate InvoiceStore::create: convert URI → Invoice
        let inv = uri.to_invoice(1_750_000_000_000);
        // Simulate get_invoice_qr: Invoice → URI string (as returned to the frontend)
        let qr_uri = ShishaUri::from_invoice(&inv).encode();
        // Simulate QR scan / share: parse the URI string back
        let parsed = ShishaUri::parse(&qr_uri).unwrap();
        assert_eq!(parsed.recipient,    addr());
        assert_eq!(parsed.amount_atoms, 1_234_567);
        assert_eq!(parsed.shard_id,     2);
        assert_eq!(parsed.memo,         "invoice qr test");
        assert_eq!(parsed.invoice_id,   Some([0xABu8; 16]),
            "invoice_id must survive URI encode → decode round-trip");
    }

    // ── PD-T-5: NodeAddr roundtrip ───────────────────────────────────────────

    #[test]
    fn node_addr_parse_minimal() {
        let na = NodeAddr::parse("shishanet://seed.example.com:8333").unwrap();
        assert_eq!(na.host, "seed.example.com");
        assert_eq!(na.port, 8333);
        assert!(na.pubkey.is_none());
    }

    #[test]
    fn node_addr_parse_with_pk() {
        let pk_hex = "a".repeat(64);
        let uri = format!("shishanet://192.0.2.1:8334?pk={}", pk_hex);
        let na = NodeAddr::parse(&uri).unwrap();
        assert_eq!(na.host, "192.0.2.1");
        assert_eq!(na.port, 8334);
        assert!(na.pubkey.is_some());
    }

    #[test]
    fn node_addr_encode_roundtrip() {
        let original = NodeAddr { host: "node.shishanet.io".into(), port: 8333, pubkey: None };
        let encoded  = original.encode();
        let parsed   = NodeAddr::parse(&encoded).unwrap();
        assert_eq!(parsed.host, original.host);
        assert_eq!(parsed.port, original.port);
    }

    #[test]
    fn node_addr_wrong_scheme_fails() {
        let err = NodeAddr::parse("shisha:seed.example.com:8333").unwrap_err();
        assert_eq!(err, ShishaUriError::MissingScheme);
    }

    #[test]
    fn node_addr_missing_port_fails() {
        let err = NodeAddr::parse("shishanet://seed.example.com").unwrap_err();
        assert_eq!(err, ShishaUriError::MissingRecipient);
    }
}
