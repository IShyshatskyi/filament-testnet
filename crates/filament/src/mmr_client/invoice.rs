// src/mmr_client/invoice.rs
//
// Track A — Invoice data structures, binary codec, and local file-based store.
//
// The `Invoice` is the receiver-initiated payment request used by the Filament
// wallet.  An invoice travels from receiver → sender (via shisha: URI / QR /
// F2F direct channel), gets annotated by the sender with positional hints
// `(height_hint, idx_hint, txid)` after they construct the transaction, and
// then flows back to the receiver as a `PaymentProof` F2F message.
//
// **State machine:**
//
//   Created → Shared → PaymentSent → Pending(depth) → Confirmed → Archived
//                 ↘                ↗                    ↘
//               Expired                              ReorgReverted
//
// Design reference: `docs/plan/P2P_Phase10_Plan.md` §2

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

/// Lock file serialising `InvoiceStore::create`'s list-then-write (Path-2 item 12).
///
/// Filament HTTP handlers open a fresh `InvoiceStore` per request, so an
/// in-process `Mutex` alone would not close the TOCTOU across concurrent
/// `POST /invoice/create` calls — this blocking `flock` covers any opener
/// of the same store directory (same pattern as rustmmrdb `DataDirLock`).
const CREATE_LOCK_FILE: &str = ".invoice_create.lock";

/// RAII exclusive lock held for the duration of one `create` call.
struct InvoiceCreateLock {
    _file: File,
}

impl InvoiceCreateLock {
    fn acquire(base_dir: &Path) -> Result<Self, InvoiceError> {
        let lock_path = base_dir.join(CREATE_LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| InvoiceError::Io(format!("opening {CREATE_LOCK_FILE}: {e}")))?;
        Self::lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }

    #[cfg(unix)]
    fn lock_exclusive(file: &File) -> Result<(), InvoiceError> {
        use std::os::unix::io::AsRawFd;
        // Blocking LOCK_EX — concurrent creates must serialise, not fail.
        // SAFETY: `file` owns a valid open fd for the duration of this call.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret == 0 {
            return Ok(());
        }
        Err(InvoiceError::Io(format!(
            "flock {CREATE_LOCK_FILE}: {}",
            std::io::Error::last_os_error()
        )))
    }

    #[cfg(not(unix))]
    fn lock_exclusive(_file: &File) -> Result<(), InvoiceError> {
        Ok(())
    }
}

// ─── Invoice state ────────────────────────────────────────────────────────────

/// State of an invoice in the Filament wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceState {
    /// Created locally; not yet shared with the sender.
    Created,
    /// Shared with the sender (encoded as URI / QR / F2F message).
    Shared,
    /// Sender filled in `(height_hint, idx_hint, txid)` and broadcast the tx.
    /// Inclusion not yet verified.
    PaymentSent,
    /// Inclusion verified via MMR proof; `depth` blocks of confirmations so far.
    Pending(u8),
    /// `MIN_CONFIRMATION_DEPTH` blocks confirmed. A matching `TxRevertNotif`
    /// still reverts this to `ReorgReverted` (P0-2) — depth does not freeze
    /// the invoice against an outpoint orphan.
    Confirmed,
    /// `expiry_height` passed without reaching `PaymentSent`.
    Expired,
    /// Previously `Pending` or `Confirmed`; the containing block was orphaned
    /// (reorg). Hints are cleared so a later inclusion can rematch.
    ReorgReverted,
    /// User-dismissed confirmed or expired invoice.
    Archived,
}

impl InvoiceState {
    /// Numeric discriminant for compact serialisation in the binary codec.
    #[allow(dead_code)] // reserved — wire encode does not yet embed state
    fn tag(&self) -> u8 {
        match self {
            Self::Created        => 0,
            Self::Shared         => 1,
            Self::PaymentSent    => 2,
            Self::Pending(_)     => 3,
            Self::Confirmed      => 4,
            Self::Expired        => 5,
            Self::ReorgReverted  => 6,
            Self::Archived       => 7,
        }
    }

    #[allow(dead_code)] // reserved — wire encode does not yet embed state
    fn pending_depth(&self) -> u8 {
        if let Self::Pending(d) = self { *d } else { 0 }
    }
}

// ─── Invoice ──────────────────────────────────────────────────────────────────

/// A receiver-initiated payment request.
///
/// See `docs/plan/P2P_Phase10_Plan.md` §2.1 for the full field descriptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// 16-byte UUID v4 (random), unique per payment.
    pub invoice_id: [u8; 16],
    /// Recipient hex address (32 bytes).
    pub recipient: [u8; 32],
    /// Requested amount in atoms (0 = any amount / donation mode).
    pub amount_atoms: u64,
    /// Target shard chain.
    pub shard_id: u16,
    /// Human-readable description (≤ 128 bytes UTF-8).
    pub memo: String,
    /// Beacon block height after which this invoice is void (0 = no expiry).
    pub expiry_height: u32,
    /// Unix timestamp ms — informational.
    pub created_at_ms: u64,
    /// Current state in the payment lifecycle.
    pub state: InvoiceState,
    // ── Filled in by sender after tx construction ──────────────────────────
    /// Predicted block height at which the tx output will appear.
    pub height_hint: Option<u32>,
    /// Predicted output index in `ShardBlockBody::outputs`.
    pub idx_hint: Option<u16>,
    /// Transaction id of the fulfilling transaction.
    pub txid: Option<[u8; 32]>,
    // ── Relay hint ──────────────────────────────────────────────────────────
    /// Preferred relay full node, e.g. `"127.0.0.1:8334"`.
    pub relay_node: Option<String>,
    /// Serialised `WeightedMMRBatchProof` bytes (set when `Confirmed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mmr_proof_bytes: Option<Vec<u8>>,
}

impl Invoice {
    /// Magic bytes for the binary wire format.
    pub const MAGIC: u16 = 0x5348; // "SH"
    /// Current wire-format version.
    pub const VERSION: u8 = 0x01;
    /// Maximum UTF-8 memo length in bytes.
    pub const MAX_MEMO_BYTES: usize = 128;
    /// Fixed header size before the variable-length memo.
    ///
    /// Layout: magic(2) + version(1) + flags(1) + invoice_id(16) + recipient(32)
    ///         + amount_atoms(8) + shard_id(2) + expiry_height(4) + created_at_ms(8)
    ///         + memo_len(2)
    ///       = 76 bytes
    pub const FIXED_HEADER_BYTES: usize = 76;

    // ── Codec ────────────────────────────────────────────────────────────────

    /// Encode to the binary wire format defined in §2.2.
    ///
    /// Returns `Err` if `memo` exceeds `MAX_MEMO_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>, InvoiceError> {
        let memo_bytes = self.memo.as_bytes();
        if memo_bytes.len() > Self::MAX_MEMO_BYTES {
            return Err(InvoiceError::MemoTooLong(memo_bytes.len()));
        }

        let hints_present = self.height_hint.is_some() && self.idx_hint.is_some();
        let txid_present  = self.txid.is_some();
        let flags: u8 = (hints_present as u8) | ((txid_present as u8) << 1);

        let mut buf = Vec::with_capacity(
            Self::FIXED_HEADER_BYTES
                + memo_bytes.len()
                + if hints_present { 6 } else { 0 }
                + if txid_present  { 32 } else { 0 },
        );

        // Fixed header
        buf.extend_from_slice(&Self::MAGIC.to_le_bytes());
        buf.push(Self::VERSION);
        buf.push(flags);
        buf.extend_from_slice(&self.invoice_id);
        buf.extend_from_slice(&self.recipient);
        buf.extend_from_slice(&self.amount_atoms.to_le_bytes());
        buf.extend_from_slice(&self.shard_id.to_le_bytes());
        buf.extend_from_slice(&self.expiry_height.to_le_bytes());
        buf.extend_from_slice(&self.created_at_ms.to_le_bytes());
        buf.extend_from_slice(&(memo_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(memo_bytes);

        // Optional trailer: positional hints
        if hints_present {
            buf.extend_from_slice(&self.height_hint.unwrap().to_le_bytes());
            buf.extend_from_slice(&self.idx_hint.unwrap().to_le_bytes());
        }
        // Optional trailer: txid
        if txid_present {
            buf.extend_from_slice(&self.txid.unwrap());
        }

        Ok(buf)
    }

    /// Decode from the binary wire format.
    pub fn decode(data: &[u8]) -> Result<Self, InvoiceError> {
        if data.len() < Self::FIXED_HEADER_BYTES {
            return Err(InvoiceError::Truncated);
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != Self::MAGIC {
            return Err(InvoiceError::WrongMagic(magic));
        }
        // version byte at [2] — accept v1
        let flags   = data[3];
        let hints_present = flags & 0x01 != 0;
        let txid_present  = flags & 0x02 != 0;

        let invoice_id: [u8; 16] = data[4..20].try_into().unwrap();
        let recipient:  [u8; 32] = data[20..52].try_into().unwrap();
        let amount_atoms   = u64::from_le_bytes(data[52..60].try_into().unwrap());
        let shard_id       = u16::from_le_bytes(data[60..62].try_into().unwrap());
        let expiry_height  = u32::from_le_bytes(data[62..66].try_into().unwrap());
        let created_at_ms  = u64::from_le_bytes(data[66..74].try_into().unwrap());
        let memo_len       = u16::from_le_bytes(data[74..76].try_into().unwrap()) as usize;

        let mut pos = 76;
        if pos + memo_len > data.len() {
            return Err(InvoiceError::Truncated);
        }
        let memo = std::str::from_utf8(&data[pos..pos + memo_len])
            .map_err(|_| InvoiceError::InvalidUtf8)?
            .to_string();
        pos += memo_len;

        let height_hint;
        let idx_hint;
        if hints_present {
            if pos + 6 > data.len() {
                return Err(InvoiceError::Truncated);
            }
            height_hint = Some(u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()));
            idx_hint    = Some(u16::from_le_bytes(data[pos + 4..pos + 6].try_into().unwrap()));
            pos += 6;
        } else {
            height_hint = None;
            idx_hint    = None;
        }

        let txid;
        if txid_present {
            if pos + 32 > data.len() {
                return Err(InvoiceError::Truncated);
            }
            txid = Some(data[pos..pos + 32].try_into().unwrap());
        } else {
            txid = None;
        }

        Ok(Self {
            invoice_id,
            recipient,
            amount_atoms,
            shard_id,
            expiry_height,
            created_at_ms,
            memo,
            state: InvoiceState::Created,
            height_hint,
            idx_hint,
            txid,
            relay_node: None,
            mmr_proof_bytes: None,
        })
    }

    /// Still awaiting a matching inclusion (or rematch after reorg).
    fn is_in_flight(&self) -> bool {
        matches!(
            self.state,
            InvoiceState::Created
                | InvoiceState::Shared
                | InvoiceState::PaymentSent
                | InvoiceState::Pending(_)
                | InvoiceState::ReorgReverted
        )
    }

    /// Sender or a prior inclusion recorded a specific outpoint.
    fn has_outpoint_hints(&self) -> bool {
        self.height_hint.is_some() && self.idx_hint.is_some()
    }

    /// May claim a new `TxInclusionNotif`. `Pending` is excluded so a later
    /// same-address payment cannot clobber an already-claimed invoice (NC-86).
    fn rematch_eligible(&self) -> bool {
        matches!(
            self.state,
            InvoiceState::Created
                | InvoiceState::Shared
                | InvoiceState::PaymentSent
                | InvoiceState::ReorgReverted
        )
    }
}

// ─── InvoiceError ────────────────────────────────────────────────────────────

/// Errors from the invoice codec and store.
#[derive(Debug, PartialEq, Eq)]
pub enum InvoiceError {
    /// Binary data too short.
    Truncated,
    /// Magic bytes mismatch (expected 0x5348 "SH").
    WrongMagic(u16),
    /// Memo exceeds MAX_MEMO_BYTES.
    MemoTooLong(usize),
    /// Memo bytes are not valid UTF-8.
    InvalidUtf8,
    /// Hex string has wrong length (not 64 chars).
    BadHexLength(usize),
    /// Hex string contains non-hex characters.
    BadHexChar,
    /// I/O error from the file store.
    Io(String),
    /// JSON (de)serialisation error.
    Json(String),
    /// Invoice not found in the store.
    NotFound([u8; 16]),
    /// Another unhinted in-flight invoice already exists for this
    /// `(shard_id, recipient)` — Path-2 matching cannot disambiguate two
    /// such invoices (P0-1 hybrid: one unhinted in-flight, or hinted by outpoint).
    DuplicateUnhintedInFlight { shard_id: u16, recipient: [u8; 32] },
}

impl std::fmt::Display for InvoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated          => write!(f, "invoice data truncated"),
            Self::WrongMagic(m)     => write!(f, "wrong magic 0x{m:04X} (expected 0x5348)"),
            Self::MemoTooLong(n)    => write!(f, "memo {n} bytes > MAX_MEMO_BYTES 128"),
            Self::InvalidUtf8       => write!(f, "memo is not valid UTF-8"),
            Self::BadHexLength(n)   => write!(f, "hex recipient is {n} chars, expected 64"),
            Self::BadHexChar        => write!(f, "hex recipient contains non-hex character"),
            Self::Io(s)             => write!(f, "invoice store I/O: {s}"),
            Self::Json(s)           => write!(f, "invoice store JSON: {s}"),
            Self::NotFound(id)      => write!(f, "invoice {:?} not found", id),
            Self::DuplicateUnhintedInFlight { shard_id, recipient } => write!(
                f,
                "unhinted in-flight invoice already exists for shard {shard_id} recipient {}",
                encode_hex32(&recipient)
            ),
        }
    }
}

impl std::error::Error for InvoiceError {}

// ─── InvoiceStore ─────────────────────────────────────────────────────────────

/// File-based invoice store — one JSON file per invoice under `base_dir/`.
///
/// Operations are synchronous.  The file name is `<hex invoice_id>.json`.
pub struct InvoiceStore {
    base_dir: PathBuf,
}

impl InvoiceStore {
    /// Open (or create) the store rooted at `base_dir`.
    pub fn open(base_dir: impl AsRef<Path>) -> Result<Self, InvoiceError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)
            .map_err(|e| InvoiceError::Io(e.to_string()))?;
        Ok(Self { base_dir })
    }

    fn file_path(&self, invoice_id: &[u8; 16]) -> PathBuf {
        let hex: String = invoice_id.iter().map(|b| format!("{b:02x}")).collect();
        self.base_dir.join(format!("{hex}.json"))
    }

    fn write(&self, invoice: &Invoice) -> Result<(), InvoiceError> {
        let path = self.file_path(&invoice.invoice_id);
        let json = serde_json::to_string_pretty(invoice)
            .map_err(|e| InvoiceError::Json(e.to_string()))?;
        // Atomic write: write to tmp then rename.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json.as_bytes())
            .map_err(|e| InvoiceError::Io(e.to_string()))?;
        fs::rename(&tmp, &path)
            .map_err(|e| InvoiceError::Io(e.to_string()))?;
        Ok(())
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Create a new invoice in `Created` state and persist it.
    ///
    /// The duplicate unhinted-in-flight check and the subsequent write run
    /// under a directory-scoped exclusive flock so two concurrent `create`
    /// calls (including from separate `InvoiceStore::open` of the same dir)
    /// cannot both pass the check (Path-2 follow-up item 12).
    pub fn create(
        &self,
        recipient:     [u8; 32],
        amount_atoms:  u64,
        shard_id:      u16,
        memo:          impl Into<String>,
        expiry_height: u32,
        created_at_ms: u64,
    ) -> Result<[u8; 16], InvoiceError> {
        let _create_lock = InvoiceCreateLock::acquire(&self.base_dir)?;
        for existing in self.list(None)? {
            if existing.shard_id == shard_id
                && existing.recipient == recipient
                && existing.is_in_flight()
                && !existing.has_outpoint_hints()
            {
                return Err(InvoiceError::DuplicateUnhintedInFlight {
                    shard_id,
                    recipient,
                });
            }
        }
        let invoice_id = new_invoice_id();
        let inv = Invoice {
            invoice_id,
            recipient,
            amount_atoms,
            shard_id,
            memo: memo.into(),
            expiry_height,
            created_at_ms,
            state: InvoiceState::Created,
            height_hint: None,
            idx_hint: None,
            txid: None,
            relay_node: None,
            mmr_proof_bytes: None,
        };
        self.write(&inv)?;
        Ok(invoice_id)
    }

    /// Load an invoice by `invoice_id`.
    pub fn load(&self, invoice_id: &[u8; 16]) -> Result<Invoice, InvoiceError> {
        let path = self.file_path(invoice_id);
        let data = fs::read(&path)
            .map_err(|_| InvoiceError::NotFound(*invoice_id))?;
        serde_json::from_slice(&data)
            .map_err(|e| InvoiceError::Json(e.to_string()))
    }

    /// Overwrite the state of an existing invoice (atomic file write).
    pub fn update_state(
        &self,
        invoice_id: &[u8; 16],
        new_state:  InvoiceState,
    ) -> Result<(), InvoiceError> {
        let mut inv = self.load(invoice_id)?;
        inv.state = new_state;
        self.write(&inv)
    }

    /// Set positional hints + txid on an existing invoice, transitioning to `PaymentSent`.
    pub fn apply_hints(
        &self,
        invoice_id:  &[u8; 16],
        height_hint: u32,
        idx_hint:    u16,
        txid:        [u8; 32],
    ) -> Result<(), InvoiceError> {
        let mut inv = self.load(invoice_id)?;
        inv.height_hint = Some(height_hint);
        inv.idx_hint    = Some(idx_hint);
        inv.txid        = Some(txid);
        inv.state       = InvoiceState::PaymentSent;
        self.write(&inv)
    }

    /// Mark invoice as `Confirmed` and store the serialised MMR proof.
    pub fn mark_confirmed(
        &self,
        invoice_id:      &[u8; 16],
        mmr_proof_bytes: Vec<u8>,
    ) -> Result<(), InvoiceError> {
        let mut inv = self.load(invoice_id)?;
        inv.state           = InvoiceState::Confirmed;
        inv.mmr_proof_bytes = Some(mmr_proof_bytes);
        self.write(&inv)
    }

    /// Return all invoices matching `filter`, sorted by `created_at_ms` descending.
    pub fn list(&self, filter: Option<&InvoiceState>) -> Result<Vec<Invoice>, InvoiceError> {
        let mut result = Vec::new();
        let rd = fs::read_dir(&self.base_dir)
            .map_err(|e| InvoiceError::Io(e.to_string()))?;
        for entry in rd {
            let entry = entry.map_err(|e| InvoiceError::Io(e.to_string()))?;
            let p = entry.path();
            if p.extension().map_or(false, |e| e == "json") {
                if let Ok(data) = fs::read(&p) {
                    if let Ok(inv) = serde_json::from_slice::<Invoice>(&data) {
                        let matches = filter.map_or(true, |f| {
                            std::mem::discriminant(&inv.state) == std::mem::discriminant(f)
                        });
                        if matches {
                            result.push(inv);
                        }
                    }
                }
            }
        }
        result.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        Ok(result)
    }

    /// FUD-5: addresses that should stay registered with Keystone (`WatchAddress`).
    pub fn watch_registration_targets(&self) -> Result<Vec<([u8; 32], u16)>, InvoiceError> {
        let mut out = Vec::new();
        for inv in self.list(None)? {
            if matches!(
                inv.state,
                InvoiceState::Created
                    | InvoiceState::Shared
                    | InvoiceState::PaymentSent
                    | InvoiceState::Pending(_)
                    | InvoiceState::ReorgReverted
            ) {
                out.push((inv.recipient, inv.shard_id));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out.dedup();
        Ok(out)
    }

    /// FUD-5 / P0-1: on verified inclusion, match an invoice and enter `Pending(0)`.
    ///
    /// Hybrid matching: a hinted rematch-eligible invoice claims only its
    /// own outpoint; otherwise the newest unhinted rematch-eligible invoice
    /// for `(shard_id, address)` claims the inclusion. `Pending` is never
    /// rematched (NC-86 coinbase-reuse clobber).
    pub fn on_watch_inclusion(
        &self,
        shard_id: u16,
        height: u32,
        output_idx: u16,
        address: [u8; 32],
        mmr_proof_bytes: Vec<u8>,
    ) -> Result<Option<[u8; 16]>, InvoiceError> {
        let invoices = self.list(None)?;
        if let Some(inv) = invoices.iter().find(|inv| {
            inv.shard_id == shard_id
                && inv.recipient == address
                && inv.rematch_eligible()
                && inv.has_outpoint_hints()
                && inv.height_hint == Some(height)
                && inv.idx_hint == Some(output_idx)
        }) {
            return self.claim_inclusion(inv, height, output_idx, mmr_proof_bytes);
        }
        if let Some(inv) = invoices.iter().find(|inv| {
            inv.shard_id == shard_id
                && inv.recipient == address
                && inv.rematch_eligible()
                && !inv.has_outpoint_hints()
        }) {
            return self.claim_inclusion(inv, height, output_idx, mmr_proof_bytes);
        }
        Ok(None)
    }

    fn claim_inclusion(
        &self,
        inv: &Invoice,
        height: u32,
        output_idx: u16,
        mmr_proof_bytes: Vec<u8>,
    ) -> Result<Option<[u8; 16]>, InvoiceError> {
        let mut updated = inv.clone();
        updated.height_hint = Some(height);
        updated.idx_hint = Some(output_idx);
        updated.mmr_proof_bytes = Some(mmr_proof_bytes);
        updated.state = InvoiceState::Pending(0);
        let id = updated.invoice_id;
        self.write(&updated)?;
        Ok(Some(id))
    }

    /// LC-47b / P0-2: revert a `Pending` or `Confirmed` payment at
    /// `(shard_id, height, output_idx)`. Hints are cleared so rematch can
    /// take a new height after the reorg.
    pub fn on_watch_revert(
        &self,
        shard_id: u16,
        height: u32,
        output_idx: u16,
    ) -> Result<Vec<[u8; 16]>, InvoiceError> {
        let mut reverted = Vec::new();
        for inv in self.list(None)? {
            if inv.shard_id != shard_id {
                continue;
            }
            if inv.height_hint != Some(height) || inv.idx_hint != Some(output_idx) {
                continue;
            }
            match inv.state {
                InvoiceState::Pending(_) | InvoiceState::Confirmed => {
                    let mut updated = inv;
                    let id = updated.invoice_id;
                    updated.state = InvoiceState::ReorgReverted;
                    updated.height_hint = None;
                    updated.idx_hint = None;
                    updated.txid = None;
                    updated.mmr_proof_bytes = None;
                    self.write(&updated)?;
                    reverted.push(id);
                }
                _ => {}
            }
        }
        Ok(reverted)
    }

    /// Advance `Pending` invoices toward `Confirmed` as the shard tip grows.
    pub fn advance_pending_confirmations(
        &self,
        shard_id: u16,
        tip_height: u32,
        min_depth: u32,
    ) -> Result<Vec<[u8; 16]>, InvoiceError> {
        let mut confirmed = Vec::new();
        for inv in self.list(None)? {
            if inv.shard_id != shard_id {
                continue;
            }
            let InvoiceState::Pending(_) = inv.state else {
                continue;
            };
            let Some(payment_height) = inv.height_hint else {
                continue;
            };
            let confirmations = tip_height.saturating_sub(payment_height);
            if confirmations >= min_depth {
                let id = inv.invoice_id;
                let proof = inv.mmr_proof_bytes.clone().unwrap_or_default();
                self.mark_confirmed(&id, proof)?;
                confirmed.push(id);
            } else {
                let id = inv.invoice_id;
                self.update_state(&id, InvoiceState::Pending(confirmations as u8))?;
            }
        }
        Ok(confirmed)
    }

    /// Transition all `Created` or `Shared` invoices past `current_height` to `Expired`.
    pub fn prune_expired(&self, current_height: u32) -> Result<usize, InvoiceError> {
        let rd = fs::read_dir(&self.base_dir)
            .map_err(|e| InvoiceError::Io(e.to_string()))?;
        let mut count = 0;
        for entry in rd {
            let entry = entry.map_err(|e| InvoiceError::Io(e.to_string()))?;
            let p = entry.path();
            if p.extension().map_or(false, |e| e == "json") {
                if let Ok(data) = fs::read(&p) {
                    if let Ok(mut inv) = serde_json::from_slice::<Invoice>(&data) {
                        let is_pending_state = matches!(
                            inv.state,
                            InvoiceState::Created | InvoiceState::Shared
                        );
                        if is_pending_state
                            && inv.expiry_height > 0
                            && current_height > inv.expiry_height
                        {
                            inv.state = InvoiceState::Expired;
                            self.write(&inv)?;
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a random 16-byte invoice ID (UUID v4-style).
pub fn new_invoice_id() -> [u8; 16] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple deterministic-enough ID using time + address-of-stack frame.
    // In production this would use `rand::random::<[u8;16]>()`.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stack_addr = &t as *const _ as u64;

    let mut h1 = DefaultHasher::new();
    t.hash(&mut h1);
    stack_addr.hash(&mut h1);
    let p1 = h1.finish();

    let mut h2 = DefaultHasher::new();
    (t ^ 0xDEADBEEF_CAFEBABE).hash(&mut h2);
    (stack_addr.wrapping_add(12345)).hash(&mut h2);
    let p2 = h2.finish();

    let mut id = [0u8; 16];
    id[0..8].copy_from_slice(&p1.to_le_bytes());
    id[8..16].copy_from_slice(&p2.to_le_bytes());
    // Mark as UUID v4 variant bits
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    id
}

/// Decode a 64-character lowercase hex string to a 32-byte array.
pub fn decode_hex32(s: &str) -> Result<[u8; 32], InvoiceError> {
    if s.len() != 64 {
        return Err(InvoiceError::BadHexLength(s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, InvoiceError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(InvoiceError::BadHexChar),
    }
}

/// Encode a 32-byte array as 64 lowercase hex characters.
pub fn encode_hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Encode 16 bytes as 22-character base64url (URL-safe, no padding).
pub fn base64url_encode16(id: &[u8; 16]) -> String {
    // Hand-rolled to avoid adding a dependency.
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(22);
    let mut i = 0;
    while i + 2 < id.len() {
        let v = ((id[i] as u32) << 16) | ((id[i + 1] as u32) << 8) | id[i + 2] as u32;
        out.push(CHARS[(v >> 18) as usize & 0x3F] as char);
        out.push(CHARS[(v >> 12) as usize & 0x3F] as char);
        out.push(CHARS[(v >>  6) as usize & 0x3F] as char);
        out.push(CHARS[ v        as usize & 0x3F] as char);
        i += 3;
    }
    // 16 bytes: last byte is id[15], leftover 1 byte → 2 chars
    if i < id.len() {
        let v = (id[i] as u32) << 16;
        out.push(CHARS[(v >> 18) as usize & 0x3F] as char);
        out.push(CHARS[(v >> 12) as usize & 0x3F] as char);
    }
    out
}

/// Decode a base64url-encoded 16-byte value (22 chars, no padding).
pub fn base64url_decode16(s: &str) -> Result<[u8; 16], InvoiceError> {
    if s.len() < 22 {
        return Err(InvoiceError::Truncated);
    }
    let bytes: Vec<u8> = s.chars().take(22).map(|c| {
        match c {
            'A'..='Z' => Ok(c as u8 - b'A'),
            'a'..='z' => Ok(c as u8 - b'a' + 26),
            '0'..='9' => Ok(c as u8 - b'0' + 52),
            '-'       => Ok(62),
            '_'       => Ok(63),
            _         => Err(InvoiceError::BadHexChar),
        }
    }).collect::<Result<_, _>>()?;

    let mut out = [0u8; 16];
    let mut i = 0;
    let mut bi = 0;
    while i + 3 < bytes.len() && bi + 2 < out.len() {
        let v = ((bytes[i] as u32) << 18)
              | ((bytes[i+1] as u32) << 12)
              | ((bytes[i+2] as u32) <<  6)
              |  (bytes[i+3] as u32);
        out[bi]     = (v >> 16) as u8;
        out[bi + 1] = (v >>  8) as u8;
        out[bi + 2] =  v        as u8;
        i  += 4;
        bi += 3;
    }
    // last 2 chars → 1 byte
    if i + 1 < bytes.len() && bi < out.len() {
        let v = ((bytes[i] as u32) << 18) | ((bytes[i+1] as u32) << 12);
        out[bi] = (v >> 16) as u8;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_invoice() -> Invoice {
        Invoice {
            invoice_id:     [1u8; 16],
            recipient:      [2u8; 32],
            amount_atoms:   1_000_000_000,
            shard_id:       0,
            memo:           "test payment".into(),
            expiry_height:  1000,
            created_at_ms:  1_700_000_000_000,
            state:          InvoiceState::Created,
            height_hint:    None,
            idx_hint:       None,
            txid:           None,
            relay_node:     None,
            mmr_proof_bytes: None,
        }
    }

    // LC-1
    #[test]
    fn invoice_codec_roundtrip_no_hints() {
        let inv = sample_invoice();
        let encoded = inv.encode().unwrap();
        // Fixed header (76) + memo bytes (12)
        assert_eq!(encoded.len(), Invoice::FIXED_HEADER_BYTES + "test payment".len());
        let decoded = Invoice::decode(&encoded).unwrap();
        assert_eq!(decoded.invoice_id,    inv.invoice_id);
        assert_eq!(decoded.recipient,     inv.recipient);
        assert_eq!(decoded.amount_atoms,  inv.amount_atoms);
        assert_eq!(decoded.shard_id,      inv.shard_id);
        assert_eq!(decoded.memo,          inv.memo);
        assert_eq!(decoded.expiry_height, inv.expiry_height);
        assert_eq!(decoded.created_at_ms, inv.created_at_ms);
        assert_eq!(decoded.height_hint,   None);
        assert_eq!(decoded.idx_hint,      None);
        assert_eq!(decoded.txid,          None);
    }

    // LC-2
    #[test]
    fn invoice_codec_roundtrip_with_hints() {
        let mut inv = sample_invoice();
        inv.height_hint = Some(42_000);
        inv.idx_hint    = Some(7);
        let encoded = Invoice::decode(&inv.encode().unwrap()).unwrap();
        assert_eq!(encoded.height_hint, Some(42_000));
        assert_eq!(encoded.idx_hint,    Some(7));
    }

    // LC-3
    #[test]
    fn invoice_codec_roundtrip_with_txid() {
        let mut inv = sample_invoice();
        inv.txid = Some([0xABu8; 32]);
        let decoded = Invoice::decode(&inv.encode().unwrap()).unwrap();
        assert_eq!(decoded.txid, Some([0xABu8; 32]));
    }

    // LC-4
    #[test]
    fn invoice_codec_truncated_rejected() {
        let inv = sample_invoice();
        let mut enc = inv.encode().unwrap();
        // Declare a memo longer than actual data
        let memo_len_pos = 74;
        enc[memo_len_pos]     = 0xFF;
        enc[memo_len_pos + 1] = 0xFF;
        assert!(matches!(Invoice::decode(&enc), Err(InvoiceError::Truncated)));
    }

    // LC-5
    #[test]
    fn invoice_codec_wrong_magic_rejected() {
        let inv = sample_invoice();
        let mut enc = inv.encode().unwrap();
        enc[0] = 0xDE;
        enc[1] = 0xAD;
        assert!(matches!(Invoice::decode(&enc), Err(InvoiceError::WrongMagic(_))));
    }

    fn temp_store() -> (TempDir, InvoiceStore) {
        let dir = TempDir::new().unwrap();
        let store = InvoiceStore::open(dir.path()).unwrap();
        (dir, store)
    }

    // LC-6
    #[test]
    fn invoice_store_create_load_roundtrip() {
        let (_d, store) = temp_store();
        let id = store.create([3u8; 32], 500, 0, "hello", 999, 12345).unwrap();
        let loaded = store.load(&id).unwrap();
        assert_eq!(loaded.invoice_id,   id);
        assert_eq!(loaded.recipient,    [3u8; 32]);
        assert_eq!(loaded.amount_atoms, 500);
        assert_eq!(loaded.memo,         "hello");
        assert_eq!(loaded.state,        InvoiceState::Created);
    }

    // LC-7
    #[test]
    fn invoice_store_apply_hints_transitions_to_payment_sent() {
        let (_d, store) = temp_store();
        let id = store.create([0u8; 32], 0, 0, "", 0, 0).unwrap();
        store.apply_hints(&id, 100, 3, [0xFFu8; 32]).unwrap();
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state,        InvoiceState::PaymentSent);
        assert_eq!(inv.height_hint,  Some(100));
        assert_eq!(inv.idx_hint,     Some(3));
        assert_eq!(inv.txid,         Some([0xFFu8; 32]));
    }

    // LC-8
    #[test]
    fn invoice_store_mark_confirmed() {
        let (_d, store) = temp_store();
        let id = store.create([0u8; 32], 0, 0, "", 0, 0).unwrap();
        store.mark_confirmed(&id, vec![1, 2, 3]).unwrap();
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::Confirmed);
        assert_eq!(inv.mmr_proof_bytes, Some(vec![1, 2, 3]));
    }

    // LC-9
    #[test]
    fn invoice_store_prune_expired() {
        let (_d, store) = temp_store();
        let id = store.create([0u8; 32], 0, 0, "", 5, 0).unwrap();
        store.update_state(&id, InvoiceState::Shared).unwrap();
        let pruned = store.prune_expired(6).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(store.load(&id).unwrap().state, InvoiceState::Expired);
    }

    // LC-10
    #[test]
    fn invoice_store_list_filter_by_state() {
        let (_d, store) = temp_store();
        let id1 = store.create([1u8; 32], 0, 0, "", 0, 1).unwrap();
        let id2 = store.create([2u8; 32], 0, 0, "", 0, 2).unwrap();
        let id3 = store.create([3u8; 32], 0, 0, "", 5, 3).unwrap();
        store.mark_confirmed(&id1, vec![]).unwrap();
        store.mark_confirmed(&id2, vec![]).unwrap();
        store.update_state(&id3, InvoiceState::Shared).unwrap();
        store.prune_expired(6).unwrap();
        let confirmed = store.list(Some(&InvoiceState::Confirmed)).unwrap();
        assert_eq!(confirmed.len(), 2);
    }

    #[test]
    fn hex_helpers_roundtrip() {
        let b = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27u8];
        assert_eq!(decode_hex32(&encode_hex32(&b)).unwrap(), b);
    }

    #[test]
    fn base64url_roundtrip() {
        let id = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1Fu8];
        let encoded = base64url_encode16(&id);
        assert_eq!(encoded.len(), 22);
        let decoded = base64url_decode16(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn p01_rejects_second_unhinted_in_flight_same_shard_address() {
        let (_d, store) = temp_store();
        let addr = [0x11u8; 32];
        store.create(addr, 1, 0, "", 0, 1).unwrap();
        let err = store.create(addr, 2, 0, "", 0, 2).unwrap_err();
        assert!(matches!(
            err,
            InvoiceError::DuplicateUnhintedInFlight { shard_id: 0, .. }
        ));
    }

    /// Path-2 item 12: concurrent creates against separately-opened stores on
    /// the same directory must still produce exactly one unhinted in-flight.
    #[test]
    #[cfg(unix)]
    fn p012_concurrent_create_on_separate_store_opens_rejects_duplicate() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let addr = [0xCCu8; 32];
        let barrier = Arc::new(Barrier::new(2));

        let spawn = |path: PathBuf, barrier: Arc<Barrier>| {
            thread::spawn(move || {
                let store = InvoiceStore::open(&path).unwrap();
                barrier.wait();
                store.create(addr, 1, 0, "", 0, 1)
            })
        };

        let h1 = spawn(path.clone(), Arc::clone(&barrier));
        let h2 = spawn(path.clone(), barrier);
        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        let dups = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, Err(InvoiceError::DuplicateUnhintedInFlight { .. })))
            .count();
        assert_eq!(oks, 1, "exactly one create should succeed: {r1:?} {r2:?}");
        assert_eq!(dups, 1, "other create should be DuplicateUnhintedInFlight");

        let store = InvoiceStore::open(&path).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 1);
    }

    #[test]
    fn p01_allows_second_unhinted_after_first_is_hinted() {
        let (_d, store) = temp_store();
        let addr = [0x12u8; 32];
        let id1 = store.create(addr, 1, 0, "", 0, 1).unwrap();
        store.apply_hints(&id1, 50, 1, [0xAAu8; 32]).unwrap();
        let id2 = store.create(addr, 2, 0, "", 0, 2).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn p01_allows_same_address_on_different_shard() {
        let (_d, store) = temp_store();
        let addr = [0x13u8; 32];
        store.create(addr, 1, 0, "", 0, 1).unwrap();
        store.create(addr, 1, 1, "", 0, 2).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 2);
    }

    #[test]
    fn p01_hinted_invoice_claims_matching_outpoint_not_unrelated() {
        let (_d, store) = temp_store();
        let addr = [0x14u8; 32];
        let id1 = store.create(addr, 1, 0, "", 0, 1).unwrap();
        store.apply_hints(&id1, 50, 1, [0xBBu8; 32]).unwrap();
        let id2 = store.create(addr, 2, 0, "", 0, 2).unwrap();

        let claimed_unrelated = store
            .on_watch_inclusion(0, 99, 0, addr, vec![9])
            .unwrap();
        assert_eq!(claimed_unrelated, Some(id2));
        assert_eq!(store.load(&id1).unwrap().state, InvoiceState::PaymentSent);
        assert_eq!(store.load(&id2).unwrap().state, InvoiceState::Pending(0));

        let claimed_hinted = store
            .on_watch_inclusion(0, 50, 1, addr, vec![8])
            .unwrap();
        assert_eq!(claimed_hinted, Some(id1));
        assert_eq!(store.load(&id1).unwrap().state, InvoiceState::Pending(0));
        assert_eq!(store.load(&id1).unwrap().height_hint, Some(50));
    }

    #[test]
    fn p01_unhinted_claims_when_no_hint_match() {
        let (_d, store) = temp_store();
        let addr = [0x15u8; 32];
        let id = store.create(addr, 1, 0, "", 0, 1).unwrap();
        let claimed = store
            .on_watch_inclusion(0, 7, 3, addr, vec![1])
            .unwrap();
        assert_eq!(claimed, Some(id));
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::Pending(0));
        assert_eq!(inv.height_hint, Some(7));
        assert_eq!(inv.idx_hint, Some(3));
    }

    #[test]
    fn p02_confirmed_invoice_is_reverted_and_hints_cleared() {
        let (_d, store) = temp_store();
        let addr = [0x16u8; 32];
        let id = store.create(addr, 1, 0, "", 0, 1).unwrap();
        store.on_watch_inclusion(0, 100, 0, addr, vec![1]).unwrap();
        store.mark_confirmed(&id, vec![1, 2, 3]).unwrap();
        let reverted = store.on_watch_revert(0, 100, 0).unwrap();
        assert_eq!(reverted, vec![id]);
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::ReorgReverted);
        assert_eq!(inv.height_hint, None);
        assert_eq!(inv.idx_hint, None);
        assert_eq!(inv.txid, None);
        assert_eq!(inv.mmr_proof_bytes, None);
    }

    #[test]
    fn p02_rematch_after_revert_claims_new_height() {
        let (_d, store) = temp_store();
        let addr = [0x17u8; 32];
        let id = store.create(addr, 1, 0, "", 0, 1).unwrap();
        store.on_watch_inclusion(0, 100, 0, addr, vec![1]).unwrap();
        store.on_watch_revert(0, 100, 0).unwrap();
        let rematched = store
            .on_watch_inclusion(0, 200, 1, addr, vec![2])
            .unwrap();
        assert_eq!(rematched, Some(id));
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::Pending(0));
        assert_eq!(inv.height_hint, Some(200));
        assert_eq!(inv.idx_hint, Some(1));
    }
}
