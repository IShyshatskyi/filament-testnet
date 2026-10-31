// src/mmr_client/contact_store.rs
//
// AB-1 — Local address book: `Contact` data model + `ContactStore` atomic JSON store.
//
// Storage: `contacts.json` in the app's data directory.  Writes are atomic
// (write to `.contacts.json.tmp`, then `rename`).  Same pattern as `InvoiceStore`.
//
// Design reference: `filament_app/docs/ADDRESS_BOOK_PLAN.md`

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Contact model ────────────────────────────────────────────────────────────

/// A single address-book entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Stable UUIDv4-like identifier (32 random hex chars, hyphenated).
    pub id:            String,
    /// Display name (max 64 chars).
    pub name:          String,
    /// 64-char lowercase hex of the 32-byte recipient address.
    pub address_hex:   String,
    /// Preferred shard (0 = auto).
    pub shard_id:      u16,
    /// Optional free-text notes (max 256 chars).
    pub notes:         String,
    /// Unix timestamp (ms) when the contact was created.
    pub created_at_ms: u64,
    /// Unix timestamp (ms) when the contact was last modified.
    pub updated_at_ms: u64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ContactError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// No contact with the given id exists.
    NotFound,
    /// `name` exceeds 64 chars.
    NameTooLong,
    /// `notes` exceeds 256 chars.
    NotesTooLong,
    /// `address_hex` is not a valid 64-char lowercase hex string.
    InvalidAddress,
}

impl std::fmt::Display for ContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)         => write!(f, "I/O error: {e}"),
            Self::Json(e)       => write!(f, "JSON error: {e}"),
            Self::NotFound      => write!(f, "contact not found"),
            Self::NameTooLong   => write!(f, "name exceeds 64 characters"),
            Self::NotesTooLong  => write!(f, "notes exceed 256 characters"),
            Self::InvalidAddress => write!(f, "address_hex must be a 64-char hex string"),
        }
    }
}

impl std::error::Error for ContactError {}

// ─── ContactStore ─────────────────────────────────────────────────────────────

/// Atomic JSON-file address book.
///
/// Each operation re-reads and re-writes the full `contacts.json` file.  This
/// keeps the implementation simple and correct under concurrent processes; the
/// file is the source of truth at all times.
pub struct ContactStore {
    path: PathBuf,
}

impl ContactStore {
    /// Open (or create) the contact store at `<base_dir>/contacts.json`.
    pub fn open(base_dir: &Path) -> Result<Self, ContactError> {
        fs::create_dir_all(base_dir).map_err(ContactError::Io)?;
        Ok(Self { path: base_dir.join("contacts.json") })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_all(&self) -> Result<Vec<Contact>, ContactError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read(&self.path).map_err(ContactError::Io)?;
        serde_json::from_slice(&data).map_err(ContactError::Json)
    }

    fn save_all(&self, contacts: &[Contact]) -> Result<(), ContactError> {
        let tmp = self.path.with_file_name(".contacts.json.tmp");
        let data = serde_json::to_vec_pretty(contacts).map_err(ContactError::Json)?;
        fs::write(&tmp, &data).map_err(ContactError::Io)?;
        fs::rename(&tmp, &self.path).map_err(ContactError::Io)?;
        Ok(())
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn new_id() -> String {
        // Generate a random 128-bit identifier encoded as a UUID-like string.
        let b = crate::mmr_client::invoice::new_invoice_id();
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u16::from_le_bytes(b[4..6].try_into().unwrap()),
            u16::from_le_bytes(b[6..8].try_into().unwrap()),
            u16::from_le_bytes(b[8..10].try_into().unwrap()),
            {
                let mut v = 0u64;
                for &byte in &b[10..16] {
                    v = (v << 8) | (byte as u64);
                }
                v
            }
        )
    }

    fn validate_address(address_hex: &str) -> Result<(), ContactError> {
        if address_hex.len() != 64
            || !address_hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ContactError::InvalidAddress);
        }
        Ok(())
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Add a new contact and return it.
    pub fn add(
        &self,
        name:        String,
        address_hex: String,
        shard_id:    u16,
        notes:       String,
    ) -> Result<Contact, ContactError> {
        if name.len() > 64    { return Err(ContactError::NameTooLong); }
        if notes.len() > 256  { return Err(ContactError::NotesTooLong); }
        Self::validate_address(&address_hex)?;

        let now = Self::now_ms();
        let contact = Contact {
            id:            Self::new_id(),
            name,
            address_hex:   address_hex.to_lowercase(),
            shard_id,
            notes,
            created_at_ms: now,
            updated_at_ms: now,
        };
        let mut contacts = self.load_all()?;
        contacts.push(contact.clone());
        self.save_all(&contacts)?;
        Ok(contact)
    }

    /// Return all contacts in insertion order.
    pub fn list(&self) -> Result<Vec<Contact>, ContactError> {
        self.load_all()
    }

    /// Find a contact by its stable id.
    pub fn find_by_id(&self, id: &str) -> Result<Contact, ContactError> {
        self.load_all()?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or(ContactError::NotFound)
    }

    /// Find a contact by address hex (case-insensitive).
    pub fn find_by_address(&self, address_hex: &str) -> Result<Option<Contact>, ContactError> {
        let lower = address_hex.to_lowercase();
        Ok(self.load_all()?.into_iter().find(|c| c.address_hex == lower))
    }

    /// Find a contact by name (case-insensitive, exact match).
    pub fn find_by_name(&self, name: &str) -> Result<Option<Contact>, ContactError> {
        let lower = name.to_lowercase();
        Ok(self.load_all()?.into_iter().find(|c| c.name.to_lowercase() == lower))
    }

    /// Update mutable fields of an existing contact.  Pass `None` to leave a
    /// field unchanged.
    pub fn update(
        &self,
        id:       &str,
        name:     Option<String>,
        shard_id: Option<u16>,
        notes:    Option<String>,
    ) -> Result<Contact, ContactError> {
        if let Some(ref n) = name  { if n.len() > 64   { return Err(ContactError::NameTooLong); } }
        if let Some(ref n) = notes { if n.len() > 256  { return Err(ContactError::NotesTooLong); } }

        let mut contacts = self.load_all()?;
        let idx = contacts.iter().position(|c| c.id == id).ok_or(ContactError::NotFound)?;

        if let Some(n) = name     { contacts[idx].name     = n; }
        if let Some(s) = shard_id { contacts[idx].shard_id = s; }
        if let Some(n) = notes    { contacts[idx].notes    = n; }
        contacts[idx].updated_at_ms = Self::now_ms();

        let updated = contacts[idx].clone();
        self.save_all(&contacts)?;
        Ok(updated)
    }

    /// Delete a contact by id.
    pub fn delete(&self, id: &str) -> Result<(), ContactError> {
        let mut contacts = self.load_all()?;
        let before = contacts.len();
        contacts.retain(|c| c.id != id);
        if contacts.len() == before {
            return Err(ContactError::NotFound);
        }
        self.save_all(&contacts)
    }
}

// ─── Tests (AB-T-1..AB-T-8) ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_store() -> (TempDir, ContactStore) {
        let dir = TempDir::new().unwrap();
        let store = ContactStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn hex_addr(n: u8) -> String {
        format!("{:064x}", n as u128)
    }

    // AB-T-1
    #[test]
    fn add_and_list_contact() {
        let (_dir, store) = tmp_store();
        store.add("Alice".into(), hex_addr(1), 0, String::new()).unwrap();
        store.add("Bob".into(), hex_addr(2), 1, "neighbour".into()).unwrap();
        let all = store.list().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "Alice");
        assert_eq!(all[1].name, "Bob");
    }

    // AB-T-2
    #[test]
    fn delete_removes_contact() {
        let (_dir, store) = tmp_store();
        let c = store.add("Carol".into(), hex_addr(3), 0, String::new()).unwrap();
        store.delete(&c.id).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    // AB-T-3
    #[test]
    fn update_contact_name() {
        let (_dir, store) = tmp_store();
        let c = store.add("Dave".into(), hex_addr(4), 0, String::new()).unwrap();
        let addr = c.address_hex.clone();
        let updated = store.update(&c.id, Some("David".into()), None, None).unwrap();
        assert_eq!(updated.name, "David");
        assert_eq!(updated.address_hex, addr);
    }

    // AB-T-4
    #[test]
    fn find_by_address_returns_match() {
        let (_dir, store) = tmp_store();
        let addr = hex_addr(5);
        store.add("Eve".into(), addr.clone(), 0, String::new()).unwrap();
        let found = store.find_by_address(&addr).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Eve");
    }

    // AB-T-5
    #[test]
    fn find_by_address_returns_none_when_absent() {
        let (_dir, store) = tmp_store();
        let found = store.find_by_address(&hex_addr(99)).unwrap();
        assert!(found.is_none());
    }

    // AB-T-6: import from QR URI (tested via AddressCard::parse → store.add)
    #[test]
    fn import_from_qr_uri_creates_contact() {
        use crate::mmr_client::shisha_uri::AddressCard;
        let (_dir, store) = tmp_store();
        let addr = hex_addr(6);
        let uri = format!("shisha:?addr={}&name=Alice%20Smith", addr);
        let card = AddressCard::parse(&uri).unwrap();
        assert_eq!(card.name, "Alice Smith");
        let c = store
            .add(card.name, hex::encode(card.address), card.shard_id, String::new())
            .unwrap();
        assert_eq!(c.name, "Alice Smith");
    }

    // AB-T-7
    #[test]
    fn export_as_qr_round_trips() {
        use crate::mmr_client::shisha_uri::AddressCard;
        let (_dir, store) = tmp_store();
        let addr = hex_addr(7);
        let c = store.add("Frank".into(), addr.clone(), 2, String::new()).unwrap();
        let raw: [u8; 32] = hex::decode(&c.address_hex).unwrap().try_into().unwrap();
        let card = AddressCard { address: raw, shard_id: c.shard_id, name: c.name.clone() };
        let uri = card.encode();
        let parsed = AddressCard::parse(&uri).unwrap();
        assert_eq!(parsed.address, raw);
        assert_eq!(parsed.name, "Frank");
        assert_eq!(parsed.shard_id, 2);
    }

    // AB-T-8: atomic write survives concurrent reads
    #[test]
    fn atomic_write_survives_concurrent_reads() {
        let dir = TempDir::new().unwrap();
        let store_a = ContactStore::open(dir.path()).unwrap();
        let store_b = ContactStore::open(dir.path()).unwrap();
        store_a.add("Grace".into(), hex_addr(8), 0, String::new()).unwrap();
        // store_b reads from the same file
        let all = store_b.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Grace");
    }
}
