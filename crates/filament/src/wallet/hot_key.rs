// src/wallet/hot_key.rs
//
// Desktop hot key (IPP D10: hot key first, Ledger later): the wallet's spending key kept in
// `<data_dir>/hot_key.json`, encrypted under a password. The Tauri vault (Stronghold) is
// mobile-only, so the desktop app had no key store at all.
//
//   key   = Argon2id(password, salt)  — m = 19 456 KiB, t = 2, p = 1 (the mobile vault's
//           parameters, RFC 9106 §4), 32-byte output
//   file  = ChaCha20-Poly1305(key, nonce, secret, aad = "shisha/filament/hot-key/v1" ‖ pubkey)
//
// The x-only public key is stored in clear (it is the wallet address) and bound as AAD, so
// a file whose public key was swapped does not decrypt. `unlock` also re-derives the public
// key from the decrypted secret. The store never overwrites an existing key (it may hold
// funds) and never deletes one.
//
// IPP-HOTKEY-2: `export_backup` hands out the encrypted file (the backup IS the file: it only
// opens with the password, so keep the password with the backup owner, not in the same place),
// `restore_backup` puts one back on a device with no key, and `change_password` re-encrypts the
// same key under a new password. Every write goes through a temp file that is decrypted again
// before it replaces anything.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngExt as _;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

pub const HOT_KEY_FILE: &str = "hot_key.json";
pub const HOT_KEY_VERSION: u32 = 1;
pub const MIN_PASSWORD_LEN: usize = 8;
const AAD_TAG: &[u8] = b"shisha/filament/hot-key/v1";
const M_KIB: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

#[derive(Debug)]
pub enum HotKeyError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound,
    AlreadyExists,
    WeakPassword,
    /// Wrong password or a damaged / altered file.
    Decrypt,
    BadFile(String),
}

impl std::fmt::Display for HotKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::NotFound => write!(f, "no hot key on this device"),
            Self::AlreadyExists => write!(f, "a hot key already exists on this device; it is never overwritten"),
            Self::WeakPassword => write!(f, "password must be at least {MIN_PASSWORD_LEN} characters"),
            Self::Decrypt => write!(f, "wrong password (or the key file is damaged)"),
            Self::BadFile(s) => write!(f, "hot key file: {s}"),
        }
    }
}

impl std::error::Error for HotKeyError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HotKeyFile {
    version: u32,
    kdf: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
    pubkey_hex: String,
    created_at_ms: u64,
}

/// What can be shown without the password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HotKeyInfo {
    pub pubkey_hex: String,
    pub created_at_ms: u64,
}

fn xonly(key: &SecretKey) -> [u8; 32] {
    Keypair::from_secret_key(&Secp256k1::new(), key).x_only_public_key().0.serialize()
}

fn derive(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], HotKeyError> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| HotKeyError::BadFile(e.to_string()))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| HotKeyError::BadFile(e.to_string()))?;
    Ok(out)
}

fn aad(pubkey: &[u8; 32]) -> Vec<u8> {
    [AAD_TAG, pubkey.as_slice()].concat()
}

fn unhex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], HotKeyError> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| HotKeyError::BadFile(format!("bad {what}")))
}

pub struct HotKeyStore {
    path: PathBuf,
}

impl HotKeyStore {
    pub fn open(dir: &Path) -> Result<Self, HotKeyError> {
        fs::create_dir_all(dir).map_err(HotKeyError::Io)?;
        Ok(Self { path: dir.join(HOT_KEY_FILE) })
    }

    fn load(&self) -> Result<HotKeyFile, HotKeyError> {
        if !self.path.exists() {
            return Err(HotKeyError::NotFound);
        }
        let f: HotKeyFile = serde_json::from_slice(&fs::read(&self.path).map_err(HotKeyError::Io)?).map_err(HotKeyError::Json)?;
        if f.version != HOT_KEY_VERSION || f.kdf != "argon2id" {
            return Err(HotKeyError::BadFile(format!("unknown version {} / kdf {}", f.version, f.kdf)));
        }
        Ok(f)
    }

    /// The stored public key, or `None` when no hot key exists.
    pub fn info(&self) -> Result<Option<HotKeyInfo>, HotKeyError> {
        match self.load() {
            Ok(f) => Ok(Some(HotKeyInfo { pubkey_hex: f.pubkey_hex, created_at_ms: f.created_at_ms })),
            Err(HotKeyError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Encrypt and store `secret`. Refused when a hot key already exists.
    pub fn create(&self, secret: &SecretKey, password: &str) -> Result<HotKeyInfo, HotKeyError> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(HotKeyError::WeakPassword);
        }
        if self.path.exists() {
            return Err(HotKeyError::AlreadyExists);
        }
        let created_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let file = encrypt_file(secret, password, created_at_ms)?;
        self.write_verified(&file, password)?;
        Ok(HotKeyInfo { pubkey_hex: file.pubkey_hex, created_at_ms })
    }

    /// Write `file` to a temp file, check that `password` decrypts what was written, then move it
    /// over the key file. A write that cannot be read back never replaces anything.
    fn write_verified(&self, file: &HotKeyFile, password: &str) -> Result<(), HotKeyError> {
        let tmp = self.path.with_file_name(".hot_key.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(file).map_err(HotKeyError::Json)?).map_err(HotKeyError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(HotKeyError::Io)?;
        }
        let written: HotKeyFile = serde_json::from_slice(&fs::read(&tmp).map_err(HotKeyError::Io)?).map_err(HotKeyError::Json)?;
        if let Err(e) = decrypt_file(&written, password) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        fs::rename(&tmp, &self.path).map_err(HotKeyError::Io)
    }

    /// The encrypted key file as JSON text, for the user to save somewhere safe. Needs the
    /// password: it proves the caller can open the key, and a backup nobody can open is worth
    /// nothing. The text reveals the public key and the KDF parameters, not the secret.
    pub fn export_backup(&self, password: &str) -> Result<String, HotKeyError> {
        let f = self.load()?;
        decrypt_file(&f, password)?;
        serde_json::to_string_pretty(&f).map_err(HotKeyError::Json)
    }

    /// Put a backup made by [`Self::export_backup`] back on a device that has no hot key. Refused
    /// when one exists (it may hold funds); a backup that `password` does not open is refused too.
    pub fn restore_backup(&self, backup_json: &str, password: &str) -> Result<HotKeyInfo, HotKeyError> {
        if self.path.exists() {
            return Err(HotKeyError::AlreadyExists);
        }
        let f: HotKeyFile = serde_json::from_str(backup_json).map_err(|e| HotKeyError::BadFile(format!("not a hot key backup: {e}")))?;
        if f.version != HOT_KEY_VERSION || f.kdf != "argon2id" {
            return Err(HotKeyError::BadFile(format!("unknown version {} / kdf {}", f.version, f.kdf)));
        }
        decrypt_file(&f, password)?;
        self.write_verified(&f, password)?;
        Ok(HotKeyInfo { pubkey_hex: f.pubkey_hex, created_at_ms: f.created_at_ms })
    }

    /// Re-encrypt the same key under `new_password` (fresh salt and nonce; same public key and
    /// creation time). Nothing changes unless `old_password` opens the key and the new file
    /// opens with `new_password`.
    pub fn change_password(&self, old_password: &str, new_password: &str) -> Result<HotKeyInfo, HotKeyError> {
        if new_password.chars().count() < MIN_PASSWORD_LEN {
            return Err(HotKeyError::WeakPassword);
        }
        let current = self.load()?;
        let secret = decrypt_file(&current, old_password)?;
        let file = encrypt_file(&secret, new_password, current.created_at_ms)?;
        self.write_verified(&file, new_password)?;
        Ok(HotKeyInfo { pubkey_hex: file.pubkey_hex, created_at_ms: file.created_at_ms })
    }

    /// Generate a fresh key and store it.
    pub fn generate(&self, password: &str) -> Result<HotKeyInfo, HotKeyError> {
        let key = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
        self.create(&key, password)
    }

    /// Import a key given as 64 hex characters and store it.
    pub fn import_hex(&self, private_key_hex: &str, password: &str) -> Result<HotKeyInfo, HotKeyError> {
        let raw = hex::decode(private_key_hex.trim()).map_err(|_| HotKeyError::BadFile("private key must be 64 hex characters".into()))?;
        let key = SecretKey::from_slice(&raw).map_err(|_| HotKeyError::BadFile("not a valid private key".into()))?;
        self.create(&key, password)
    }

    /// Decrypt the key with `password`.
    pub fn unlock(&self, password: &str) -> Result<SecretKey, HotKeyError> {
        decrypt_file(&self.load()?, password)
    }
}

/// Encrypt `secret` under `password` with a fresh salt and nonce.
fn encrypt_file(secret: &SecretKey, password: &str, created_at_ms: u64) -> Result<HotKeyFile, HotKeyError> {
    let mut rng = rand::rng();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill(&mut salt);
    rng.fill(&mut nonce);
    let pubkey = xonly(secret);
    let key = derive(password, &salt, M_KIB, T_COST, P_COST)?;
    let ct = ChaCha20Poly1305::new_from_slice(&key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &secret.secret_bytes(), aad: &aad(&pubkey) })
        .map_err(|_| HotKeyError::Decrypt)?;
    Ok(HotKeyFile {
        version: HOT_KEY_VERSION,
        kdf: "argon2id".into(),
        m_kib: M_KIB,
        t: T_COST,
        p: P_COST,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ct),
        pubkey_hex: hex::encode(pubkey),
        created_at_ms,
    })
}

/// Decrypt a key file, checking that the secret belongs to the public key it carries.
fn decrypt_file(f: &HotKeyFile, password: &str) -> Result<SecretKey, HotKeyError> {
    let salt = hex::decode(&f.salt_hex).map_err(|_| HotKeyError::BadFile("bad salt".into()))?;
    let nonce: [u8; 12] = unhex(&f.nonce_hex, "nonce")?;
    let pubkey: [u8; 32] = unhex(&f.pubkey_hex, "public key")?;
    let ct = hex::decode(&f.ciphertext_hex).map_err(|_| HotKeyError::BadFile("bad ciphertext".into()))?;
    let key = derive(password, &salt, f.m_kib, f.t, f.p)?;
    let plain = ChaCha20Poly1305::new_from_slice(&key)
        .expect("32-byte key")
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad(&pubkey) })
        .map_err(|_| HotKeyError::Decrypt)?;
    let secret = SecretKey::from_slice(&plain).map_err(|_| HotKeyError::Decrypt)?;
    if xonly(&secret) != pubkey {
        return Err(HotKeyError::Decrypt);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = HotKeyStore::open(dir.path()).unwrap();
        assert!(store.info().unwrap().is_none());
        assert!(matches!(store.unlock("whatever-pass"), Err(HotKeyError::NotFound)));

        let secret = SecretKey::from_slice(&[0x5a; 32]).unwrap();
        assert!(matches!(store.create(&secret, "short"), Err(HotKeyError::WeakPassword)));
        let info = store.create(&secret, "correct horse").unwrap();
        assert_eq!(info.pubkey_hex, hex::encode(xonly(&secret)));
        assert_eq!(store.info().unwrap().unwrap(), info);
        assert_eq!(store.unlock("correct horse").unwrap(), secret);
        assert!(matches!(store.unlock("wrong horse!"), Err(HotKeyError::Decrypt)));

        // Never overwritten.
        assert!(matches!(store.generate("another pass"), Err(HotKeyError::AlreadyExists)));
        assert_eq!(store.unlock("correct horse").unwrap(), secret);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(HOT_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn altered_file_does_not_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let store = HotKeyStore::open(dir.path()).unwrap();
        store.generate("correct horse").unwrap();
        let path = dir.path().join(HOT_KEY_FILE);
        let original = fs::read_to_string(&path).unwrap();

        // Swapped public key (the AAD) → no decrypt.
        let mut f: HotKeyFile = serde_json::from_str(&original).unwrap();
        f.pubkey_hex = hex::encode(xonly(&SecretKey::from_slice(&[0x11; 32]).unwrap()));
        fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();
        assert!(matches!(store.unlock("correct horse"), Err(HotKeyError::Decrypt)));

        // Flipped ciphertext byte → no decrypt.
        let mut f: HotKeyFile = serde_json::from_str(&original).unwrap();
        let mut ct = hex::decode(&f.ciphertext_hex).unwrap();
        ct[0] ^= 1;
        f.ciphertext_hex = hex::encode(ct);
        fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();
        assert!(matches!(store.unlock("correct horse"), Err(HotKeyError::Decrypt)));
    }

    /// IPP-HOTKEY-2: change-password keeps the key, and only the new password opens it.
    #[test]
    fn change_password_keeps_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = HotKeyStore::open(dir.path()).unwrap();
        let secret = SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let before = store.create(&secret, "correct horse").unwrap();
        let file_before = fs::read_to_string(dir.path().join(HOT_KEY_FILE)).unwrap();

        assert!(matches!(store.change_password("wrong horse!", "battery staple"), Err(HotKeyError::Decrypt)));
        assert!(matches!(store.change_password("correct horse", "short"), Err(HotKeyError::WeakPassword)));
        assert_eq!(fs::read_to_string(dir.path().join(HOT_KEY_FILE)).unwrap(), file_before, "failed changes touch nothing");

        let after = store.change_password("correct horse", "battery staple").unwrap();
        assert_eq!(after, before, "same public key and creation time");
        assert_eq!(store.unlock("battery staple").unwrap(), secret);
        assert!(matches!(store.unlock("correct horse"), Err(HotKeyError::Decrypt)));
        assert_ne!(fs::read_to_string(dir.path().join(HOT_KEY_FILE)).unwrap(), file_before, "fresh salt and nonce");
        assert!(!dir.path().join(".hot_key.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(dir.path().join(HOT_KEY_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// IPP-HOTKEY-2: a backup restores the same key on a fresh device, never over an existing one,
    /// and never when the password does not open it.
    #[test]
    fn backup_round_trip_and_refusals() {
        let a = tempfile::tempdir().unwrap();
        let store_a = HotKeyStore::open(a.path()).unwrap();
        let secret = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let info = store_a.create(&secret, "correct horse").unwrap();

        assert!(matches!(store_a.export_backup("wrong horse!"), Err(HotKeyError::Decrypt)));
        let backup = store_a.export_backup("correct horse").unwrap();
        assert!(!backup.contains(&hex::encode(secret.secret_bytes())), "the backup does not contain the secret");

        let b = tempfile::tempdir().unwrap();
        let store_b = HotKeyStore::open(b.path()).unwrap();
        assert!(matches!(store_b.restore_backup(&backup, "wrong horse!"), Err(HotKeyError::Decrypt)));
        assert!(matches!(store_b.restore_backup("{ not json", "correct horse"), Err(HotKeyError::BadFile(_))));
        assert!(store_b.info().unwrap().is_none(), "refused restores leave no key behind");
        assert_eq!(store_b.restore_backup(&backup, "correct horse").unwrap(), info);
        assert_eq!(store_b.unlock("correct horse").unwrap(), secret);

        // Never over an existing key, on either device.
        assert!(matches!(store_b.restore_backup(&backup, "correct horse"), Err(HotKeyError::AlreadyExists)));
        assert!(matches!(store_a.restore_backup(&backup, "correct horse"), Err(HotKeyError::AlreadyExists)));

        // A backup of an altered file (swapped public key) is refused.
        let mut f: HotKeyFile = serde_json::from_str(&backup).unwrap();
        f.pubkey_hex = hex::encode(xonly(&SecretKey::from_slice(&[0x11; 32]).unwrap()));
        let c = tempfile::tempdir().unwrap();
        assert!(matches!(
            HotKeyStore::open(c.path()).unwrap().restore_backup(&serde_json::to_string(&f).unwrap(), "correct horse"),
            Err(HotKeyError::Decrypt)
        ));
    }
}
