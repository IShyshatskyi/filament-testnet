// src/wallet/accounts.rs — several accounts inside one Filament (FIL-ACCOUNTS-1).
//
// An account is an address with its own wallet state (outputs, history, balance) and, when it can spend, its own
// password-encrypted key (`HotKeyStore`, one folder per account). The account the process was started with
// (`--address` / `--signing-key-file`, or the desktop app's hot key) is the account `main`; it is never stored
// here and cannot be removed. All accounts share the chain view, the Keystone list and the indexer list of the
// process: only the wallet differs.
//
// On disk (`<data_dir>/accounts/`):  index.json  (labels and addresses, no secrets)
//                                    <id>/hot_key.json  (Argon2id + ChaCha20-Poly1305, as the desktop hot key)
// Keys are decrypted into memory only by `unlock` (or right after `create` / `import`) and dropped by `lock`.
// No route and no function here returns a secret key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::mmr_client::filament_wallet::FilamentWallet;
use crate::wallet::hot_key::{HotKeyError, HotKeyStore};

/// Id of the account the process started with.
pub const MAIN_ACCOUNT: &str = "main";
const MAX_LABEL_CHARS: usize = 40;
const MAX_ACCOUNTS: usize = 64;
const INDEX_FILE: &str = "index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountMeta {
    id: String,
    label: String,
    /// x-only public key, 64 lowercase hex characters.
    address: String,
    /// No key on this device: the account only watches.
    watch_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    accounts: Vec<AccountMeta>,
}

/// What a client may see about an account.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub id: String,
    pub label: String,
    pub address: String,
    pub watch_only: bool,
    /// The spending key is in memory right now.
    pub unlocked: bool,
}

/// Endpoints every account's wallet queries (the process-wide lists).
#[derive(Debug, Clone, Default)]
pub struct AccountTemplate {
    pub keystone_endpoints: Vec<String>,
    pub indexer_endpoints: Vec<String>,
}

pub struct AccountBook {
    dir: PathBuf,
    metas: Vec<AccountMeta>,
    wallets: HashMap<String, Arc<RwLock<FilamentWallet>>>,
    main: Arc<RwLock<FilamentWallet>>,
    template: AccountTemplate,
}

fn clean_address(a: &str) -> Result<String, String> {
    let a = a.trim().trim_start_matches("0x").to_ascii_lowercase();
    if a.len() == 64 && a.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(a)
    } else {
        Err("an address is 64 hex characters (an x-only public key)".into())
    }
}

fn key_err(e: HotKeyError) -> String {
    match e {
        HotKeyError::WeakPassword => e.to_string(),
        HotKeyError::Decrypt => "wrong password".into(),
        other => other.to_string(),
    }
}

impl AccountBook {
    /// Load `<dir>/index.json` (if any) and build one locked wallet per stored account. `main` is the
    /// process's own wallet.
    pub fn open(dir: &Path, main: Arc<RwLock<FilamentWallet>>, template: AccountTemplate) -> Result<Self, String> {
        let mut book = Self { dir: dir.to_path_buf(), metas: Vec::new(), wallets: HashMap::new(), main, template };
        book.load_index()?;
        Ok(book)
    }

    /// Point the book at its folder and load the stored accounts (the desktop app learns its data folder after
    /// the state exists). Accounts already loaded are replaced.
    pub fn attach_dir(&mut self, dir: &Path) -> Result<(), String> {
        self.dir = dir.to_path_buf();
        self.metas.clear();
        self.wallets.clear();
        self.load_index()
    }

    fn load_index(&mut self) -> Result<(), String> {
        let dir = self.dir.clone();
        let index = dir.join(INDEX_FILE);
        if index.exists() {
            let raw = std::fs::read(&index).map_err(|e| format!("reading {}: {e}", index.display()))?;
            let f: IndexFile = serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", index.display()))?;
            if f.version != 1 {
                return Err(format!("{}: unknown version {}", index.display(), f.version));
            }
            for m in f.accounts {
                let w = self.new_wallet(&m.address);
                self.wallets.insert(m.id.clone(), w);
                self.metas.push(m);
            }
        }
        Ok(())
    }

    fn new_wallet(&self, address: &str) -> Arc<RwLock<FilamentWallet>> {
        let mut w = FilamentWallet::new(address.to_string(), None);
        w.set_keystone_endpoints(self.template.keystone_endpoints.clone());
        w.set_indexer_endpoints(self.template.indexer_endpoints.clone());
        Arc::new(RwLock::new(w))
    }

    fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("creating {}: {e}", self.dir.display()))?;
        let f = IndexFile { version: 1, accounts: self.metas.clone() };
        let tmp = self.dir.join(".index.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.dir.join(INDEX_FILE)).map_err(|e| e.to_string())
    }

    fn key_store(&self, id: &str) -> Result<HotKeyStore, String> {
        HotKeyStore::open(&self.dir.join(id)).map_err(key_err)
    }

    fn new_id(&self) -> String {
        loop {
            let id = format!("acct-{}", hex::encode(rand::random::<[u8; 4]>()));
            if !self.wallets.contains_key(&id) {
                return id;
            }
        }
    }

    fn check_new(&self, label: &str, address: &str, main_address: &str) -> Result<String, String> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
            return Err(format!("a label is 1 to {MAX_LABEL_CHARS} characters"));
        }
        if self.metas.len() >= MAX_ACCOUNTS {
            return Err(format!("at most {MAX_ACCOUNTS} extra accounts"));
        }
        if self.metas.iter().any(|m| m.label.eq_ignore_ascii_case(label)) || label.eq_ignore_ascii_case(MAIN_ACCOUNT) {
            return Err(format!("the label '{label}' is already used"));
        }
        if self.metas.iter().any(|m| m.address == address) || main_address.eq_ignore_ascii_case(address) {
            return Err("this address is already an account here".into());
        }
        Ok(label.to_string())
    }

    /// The wallet of an account; `None` or `"main"` is the process's own wallet.
    pub fn wallet(&self, id: Option<&str>) -> Result<Arc<RwLock<FilamentWallet>>, String> {
        match id {
            None | Some(MAIN_ACCOUNT) | Some("") => Ok(Arc::clone(&self.main)),
            Some(id) => self.wallets.get(id).cloned().ok_or_else(|| format!("no account '{id}'")),
        }
    }

    /// Every account, `main` first.
    pub async fn list(&self) -> Vec<AccountInfo> {
        let main = self.main.read().await;
        let mut out = vec![AccountInfo {
            id: MAIN_ACCOUNT.into(),
            label: "Main".into(),
            address: main.address().to_string(),
            watch_only: !main.has_signing_key(),
            unlocked: main.has_signing_key(),
        }];
        drop(main);
        for m in &self.metas {
            let unlocked = match self.wallets.get(&m.id) {
                Some(w) => w.read().await.has_signing_key(),
                None => false,
            };
            out.push(AccountInfo { id: m.id.clone(), label: m.label.clone(), address: m.address.clone(), watch_only: m.watch_only, unlocked });
        }
        out
    }

    /// New endpoint lists for every account (the process's config changed).
    pub async fn set_template(&mut self, template: AccountTemplate) {
        for w in self.wallets.values() {
            let mut w = w.write().await;
            w.set_keystone_endpoints(template.keystone_endpoints.clone());
            w.set_indexer_endpoints(template.indexer_endpoints.clone());
        }
        self.template = template;
    }

    /// Wallets of the extra accounts (for the background refresh).
    pub fn extra_wallets(&self) -> Vec<Arc<RwLock<FilamentWallet>>> {
        self.wallets.values().cloned().collect()
    }

    async fn main_address(&self) -> String {
        self.main.read().await.address().to_string()
    }

    async fn add_with_key(&mut self, label: &str, info_pubkey: String, store: &HotKeyStore, password: &str, id: String) -> Result<AccountInfo, String> {
        let key = store.unlock(password).map_err(key_err)?;
        let w = self.new_wallet(&info_pubkey);
        w.write().await.attach_hot_key(key)?;
        self.wallets.insert(id.clone(), w);
        self.metas.push(AccountMeta { id: id.clone(), label: label.to_string(), address: info_pubkey.clone(), watch_only: false });
        if let Err(e) = self.save() {
            self.wallets.remove(&id);
            self.metas.pop();
            let _ = std::fs::remove_dir_all(self.dir.join(&id));
            return Err(e);
        }
        Ok(AccountInfo { id, label: label.to_string(), address: info_pubkey, watch_only: false, unlocked: true })
    }

    /// A new account with a freshly generated key, encrypted under `password` (at least 8 characters).
    /// The account is unlocked afterwards. The key is never returned: back it up with [`Self::backup`].
    pub async fn create(&mut self, label: &str, password: &str) -> Result<AccountInfo, String> {
        let main_addr = self.main_address().await;
        let label = self.check_new(label, &"0".repeat(64), &main_addr)?;
        let id = self.new_id();
        let store = self.key_store(&id)?;
        let info = store.generate(password).map_err(key_err)?;
        self.add_with_key(&label, info.pubkey_hex, &store, password, id).await
    }

    /// An account for an existing private key (64 hex characters), stored encrypted under `password`.
    pub async fn import(&mut self, label: &str, private_key_hex: &str, password: &str) -> Result<AccountInfo, String> {
        let main_addr = self.main_address().await;
        let id = self.new_id();
        let store = self.key_store(&id)?;
        let info = store.import_hex(private_key_hex, password).map_err(|e| {
            let _ = std::fs::remove_dir_all(self.dir.join(&id));
            key_err(e)
        })?;
        let label = match self.check_new(label, &info.pubkey_hex, &main_addr) {
            Ok(l) => l,
            Err(e) => {
                let _ = std::fs::remove_dir_all(self.dir.join(&id));
                return Err(e);
            }
        };
        self.add_with_key(&label, info.pubkey_hex, &store, password, id).await
    }

    /// A watch-only account (no key on this device).
    pub async fn add_watch(&mut self, label: &str, address: &str) -> Result<AccountInfo, String> {
        let address = clean_address(address)?;
        let main_addr = self.main_address().await;
        let label = self.check_new(label, &address, &main_addr)?;
        let id = self.new_id();
        let w = self.new_wallet(&address);
        self.wallets.insert(id.clone(), w);
        self.metas.push(AccountMeta { id: id.clone(), label: label.clone(), address: address.clone(), watch_only: true });
        if let Err(e) = self.save() {
            self.wallets.remove(&id);
            self.metas.pop();
            return Err(e);
        }
        Ok(AccountInfo { id, label, address, watch_only: true, unlocked: false })
    }

    /// Decrypt the account's key into memory.
    pub async fn unlock(&self, id: &str, password: &str) -> Result<(), String> {
        let meta = self.metas.iter().find(|m| m.id == id).ok_or_else(|| format!("no account '{id}' (the main account is unlocked where it was started)"))?;
        if meta.watch_only {
            return Err("this account is watch-only: it has no key here".into());
        }
        let key = self.key_store(id)?.unlock(password).map_err(key_err)?;
        let w = self.wallets.get(id).ok_or_else(|| format!("no account '{id}'"))?;
        w.write().await.attach_hot_key(key)
    }

    /// Drop the key from memory; the account keeps watching.
    pub async fn lock(&self, id: &str) -> Result<(), String> {
        let w = self.wallets.get(id).ok_or_else(|| format!("no account '{id}'"))?;
        w.write().await.detach_signing_key();
        Ok(())
    }

    pub fn rename(&mut self, id: &str, label: &str) -> Result<(), String> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
            return Err(format!("a label is 1 to {MAX_LABEL_CHARS} characters"));
        }
        if self.metas.iter().any(|m| m.id != id && m.label.eq_ignore_ascii_case(label)) || label.eq_ignore_ascii_case(MAIN_ACCOUNT) {
            return Err(format!("the label '{label}' is already used"));
        }
        let m = self.metas.iter_mut().find(|m| m.id == id).ok_or_else(|| format!("no account '{id}'"))?;
        m.label = label.to_string();
        self.save()
    }

    /// The encrypted key file as JSON text for the owner to keep (needs the password; reveals no secret).
    pub fn backup(&self, id: &str, password: &str) -> Result<String, String> {
        let meta = self.metas.iter().find(|m| m.id == id).ok_or_else(|| format!("no account '{id}'"))?;
        if meta.watch_only {
            return Err("this account is watch-only: there is no key to back up".into());
        }
        self.key_store(id)?.export_backup(password).map_err(key_err)
    }

    /// Forget an account and delete its key file. Funds on the address are not touched; without a backup of the key
    /// they can no longer be spent from here. The caller must confirm; `main` cannot be removed.
    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        if id == MAIN_ACCOUNT {
            return Err("the main account cannot be removed".into());
        }
        let pos = self.metas.iter().position(|m| m.id == id).ok_or_else(|| format!("no account '{id}'"))?;
        let meta = self.metas.remove(pos);
        self.wallets.remove(id);
        if let Err(e) = self.save() {
            self.metas.insert(pos, meta.clone());
            self.wallets.insert(meta.id.clone(), self.new_wallet(&meta.address));
            return Err(e);
        }
        let _ = std::fs::remove_dir_all(self.dir.join(id));
        Ok(())
    }
}

#[cfg(all(test, feature = "full-node"))]
mod tests {
    use super::*;

    fn main_wallet() -> Arc<RwLock<FilamentWallet>> {
        let mut w = FilamentWallet::new(String::new(), None);
        w.attach_hot_key(bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap()).unwrap();
        Arc::new(RwLock::new(w))
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("filament-accounts-{}", hex::encode(rand::random::<[u8; 6]>())));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn accounts_are_created_locked_unlocked_and_survive_a_restart() {
        let dir = tmp();
        let tpl = AccountTemplate { keystone_endpoints: vec!["http://k1".into()], indexer_endpoints: vec!["http://e1".into()] };
        let mut book = AccountBook::open(&dir, main_wallet(), tpl.clone()).unwrap();
        assert_eq!(book.list().await.len(), 1, "only main");

        let a = book.create("Savings", "correct horse").await.unwrap();
        assert!(a.unlocked && !a.watch_only && a.address.len() == 64);
        assert!(book.create("savings", "another pass").await.unwrap_err().contains("already used"));
        assert!(book.create("X", "short").await.unwrap_err().contains("at least 8"));

        // Import a known key; the address is its public key and the same key cannot be added twice.
        let sk_hex = "11".repeat(32);
        let b = book.import("Imported", &sk_hex, "hunter22hunter").await.unwrap();
        let expect = {
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
            hex::encode(bitcoin::secp256k1::Keypair::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &sk).x_only_public_key().0.serialize())
        };
        assert_eq!(b.address, expect);
        assert!(book.import("Again", &sk_hex, "hunter22hunter").await.unwrap_err().contains("already an account"));
        assert!(!dir.join("index.json").to_string_lossy().is_empty());

        // The index holds no secret.
        let index = std::fs::read_to_string(dir.join("index.json")).unwrap();
        assert!(!index.contains(&sk_hex) && !index.contains("secret"));

        // Wallets are separate objects and lock/unlock work per account.
        let wa = book.wallet(Some(&a.id)).unwrap();
        let wb = book.wallet(Some(&b.id)).unwrap();
        assert_ne!(wa.read().await.address(), wb.read().await.address());
        book.lock(&a.id).await.unwrap();
        assert!(!wa.read().await.has_signing_key() && wb.read().await.has_signing_key());
        assert_eq!(book.unlock(&a.id, "wrong password").await.unwrap_err(), "wrong password");
        book.unlock(&a.id, "correct horse").await.unwrap();
        assert!(wa.read().await.has_signing_key());
        assert_eq!(wa.read().await.keystone_endpoints(), ["http://k1".to_string()]);

        // Restart: accounts come back locked, with their endpoints.
        drop(book);
        let book2 = AccountBook::open(&dir, main_wallet(), tpl).unwrap();
        let list = book2.list().await;
        assert_eq!(list.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(), vec!["Main", "Savings", "Imported"]);
        assert!(list[0].unlocked && !list[1].unlocked && !list[2].unlocked);
        book2.unlock(&b.id, "hunter22hunter").await.unwrap();
        let w = book2.wallet(Some(&b.id)).unwrap();
        assert!(w.read().await.has_signing_key());
        assert_eq!(w.read().await.keystone_endpoints(), ["http://k1".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn watch_accounts_main_protection_rename_backup_and_remove() {
        let dir = tmp();
        let mut book = AccountBook::open(&dir, main_wallet(), AccountTemplate::default()).unwrap();
        let w = book.add_watch("Cold", &format!("0x{}", "AB".repeat(32))).await.unwrap();
        assert!(w.watch_only && !w.unlocked && w.address == "ab".repeat(32));
        assert!(book.add_watch("Bad", "xyz").await.unwrap_err().contains("64 hex"));
        assert!(book.unlock(&w.id, "whatever12").await.unwrap_err().contains("watch-only"));
        assert!(book.backup(&w.id, "whatever12").unwrap_err().contains("watch-only"));
        assert!(book.remove(MAIN_ACCOUNT).unwrap_err().contains("cannot be removed"));
        assert!(book.add_watch("Main", &"cd".repeat(32)).await.unwrap_err().contains("already used"));
        // The main account's own address cannot be added again.
        let main_addr = book.list().await[0].address.clone();
        assert!(book.add_watch("Dup", &main_addr).await.unwrap_err().contains("already an account"));

        let k = book.create("Spend", "passphrase1").await.unwrap();
        book.rename(&k.id, "Spending").unwrap();
        assert_eq!(book.list().await[2].label, "Spending");
        let backup = book.backup(&k.id, "passphrase1").unwrap();
        assert!(backup.contains(&k.address) && !backup.contains("secret_key"));
        assert!(book.backup(&k.id, "nope nope nope").unwrap_err().contains("wrong password"));

        book.remove(&k.id).unwrap();
        assert!(!dir.join(&k.id).exists(), "the key file is gone");
        assert!(book.wallet(Some(&k.id)).is_err());
        assert!(book.wallet(Some("main")).is_ok() && book.wallet(None).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
