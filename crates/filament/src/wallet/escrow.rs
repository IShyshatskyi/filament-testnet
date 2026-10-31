// src/wallet/escrow.rs
//
// Wallet side of the escrow policy-hash output (D14, consensus ESC-1..ESC-9).
// Spec: docs/plan/Escrow_Policy_Hash_Consensus_Spec.md §5 (wallet obligations);
// protocol: filament_app/docs/IPP_PROTOCOL_AND_MUSIG2.md §3.
//
// * `EscrowStore` keeps every escrow policy (68 bytes, not secret) in
//   `<base_dir>/escrows.json` (atomic write, same pattern as `ContactStore`),
//   with its funding outpoints, and exports / imports a versioned backup.
//   Without the policy the wallet cannot build either witness.
// * `new_policy` runs the checks consensus cannot do: both keys valid x-only points,
//   the provider key is not ours, H far enough ahead.
// * `sign_payer_half` signs the cooperative (`0x02`) message for one escrow input;
//   the provider adds its signature and assembles the witness (`coop_witness`).
// * `build_recovery` builds and signs a recovery spend (`0x03`) once H is reached.
//
// Signing uses plain BIP-340 Schnorr over the shared `escrow_sighash` (no MuSig2).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use common_types::common::crypto::escrow::{
    escrow_sighash, recovery_witness, EscrowPolicy, WITNESS_TYPE_ESCROW_COOP, WITNESS_TYPE_ESCROW_RECOVERY,
};
use common_types::common::crypto::{prevouts_hash, sighash_v2};
use common_types::transaction::types::{Transaction, TxInput, TxOutput};
use serde::{Deserialize, Serialize};

/// Backup file format version.
pub const ESCROW_BACKUP_VERSION: u32 = 1;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EscrowError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound,
    /// A key is not a valid x-only public key.
    InvalidKey(&'static str),
    /// The provider key equals the wallet's own key.
    SameKeys,
    /// H does not leave the required room above the tip.
    UnlockTooSoon { unlock_height: u32, min_unlock_height: u32 },
    /// Recovery attempted before H.
    NotYetUnlocked { unlock_height: u32, tip_height: u32 },
    /// The signing key is not the policy's sender key.
    WrongKey,
    /// The transaction input does not spend this escrow (prevout recipient != P).
    NotThisEscrow(usize),
    /// Amount / fee / input problems.
    Build(String),
    /// Backup file has an unknown version or a policy that does not hash to its P.
    BadBackup(String),
}

impl std::fmt::Display for EscrowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::NotFound => write!(f, "escrow not found"),
            Self::InvalidKey(which) => write!(f, "{which} is not a valid x-only public key"),
            Self::SameKeys => write!(f, "provider key must differ from the wallet's own key"),
            Self::UnlockTooSoon { unlock_height, min_unlock_height } => write!(
                f,
                "unlock height {unlock_height} is too soon (needs at least {min_unlock_height})"
            ),
            Self::NotYetUnlocked { unlock_height, tip_height } => write!(
                f,
                "recovery opens at height {unlock_height}; tip is {tip_height}"
            ),
            Self::WrongKey => write!(f, "signing key is not the escrow's sender key"),
            Self::NotThisEscrow(i) => write!(f, "input {i} does not spend this escrow"),
            Self::Build(s) => write!(f, "{s}"),
            Self::BadBackup(s) => write!(f, "bad escrow backup: {s}"),
        }
    }
}

impl std::error::Error for EscrowError {}

// ─── Records ──────────────────────────────────────────────────────────────────

/// One funding output of an escrow (a payment slot), positional (Anti-Patterns #13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowOutpoint {
    pub height: u32,
    pub output_idx: u16,
    pub value_atoms: u64,
}

/// A stored escrow: the policy plus wallet bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowRecord {
    pub id: String,
    /// Display label (provider name).
    pub provider_label: String,
    /// `None` = beacon chain; `Some(n)` = shard n (0-indexed).
    pub shard_id: Option<u16>,
    pub sender_pk_hex: String,
    pub provider_pk_hex: String,
    pub unlock_height: u32,
    /// Hex of the policy hash `P` (the funding outputs' recipient).
    pub policy_hash_hex: String,
    /// Unspent funding outputs known to the wallet.
    pub outpoints: Vec<EscrowOutpoint>,
    pub created_at_ms: u64,
    /// Set when the policy was included in an exported backup.
    pub backed_up_at_ms: Option<u64>,
}

impl EscrowRecord {
    /// The consensus policy this record describes.
    pub fn policy(&self) -> Result<EscrowPolicy, EscrowError> {
        Ok(EscrowPolicy {
            sender_pk: hex32(&self.sender_pk_hex, "sender key")?,
            provider_pk: hex32(&self.provider_pk_hex, "provider key")?,
            unlock_height: self.unlock_height,
        })
    }

    /// TX-6 chain domain for this escrow's chain (beacon = 0, shard n = n + 1).
    pub fn chain_id(&self) -> u16 {
        match self.shard_id {
            None => 0,
            Some(s) => common_types::transaction::shard_chain_id(s),
        }
    }
}

/// Versioned backup of every escrow policy (not secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowBackup {
    pub version: u32,
    pub escrows: Vec<EscrowRecord>,
}

fn hex32(s: &str, what: &'static str) -> Result<[u8; 32], EscrowError> {
    let v = hex::decode(s).map_err(|_| EscrowError::InvalidKey(what))?;
    v.try_into().map_err(|_| EscrowError::InvalidKey(what))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn own_xonly(key: &SecretKey) -> [u8; 32] {
    Keypair::from_secret_key(&Secp256k1::new(), key).x_only_public_key().0.serialize()
}

// ─── Policy checks (spec §5.1) ────────────────────────────────────────────────

/// Build a policy for a new escrow, running the checks consensus cannot do.
///
/// `min_lead_blocks` = return window W + provider safety margin: H must be at least
/// `tip_height + min_lead_blocks + 1`.
pub fn new_policy(
    own_key: &SecretKey,
    provider_pk: [u8; 32],
    unlock_height: u32,
    tip_height: u32,
    min_lead_blocks: u32,
) -> Result<EscrowPolicy, EscrowError> {
    XOnlyPublicKey::from_slice(&provider_pk).map_err(|_| EscrowError::InvalidKey("provider key"))?;
    let sender_pk = own_xonly(own_key);
    if sender_pk == provider_pk {
        return Err(EscrowError::SameKeys);
    }
    let min_unlock_height = tip_height.saturating_add(min_lead_blocks).saturating_add(1);
    if unlock_height < min_unlock_height {
        return Err(EscrowError::UnlockTooSoon { unlock_height, min_unlock_height });
    }
    Ok(EscrowPolicy { sender_pk, provider_pk, unlock_height })
}

/// The funding output paying `value_atoms` into the escrow.
pub fn funding_output(policy: &EscrowPolicy, value_atoms: u64) -> TxOutput {
    TxOutput { value: value_atoms, recipient: policy.hash() }
}

// ─── Signing ──────────────────────────────────────────────────────────────────

fn sign(key: &SecretKey, msg: &[u8; 32]) -> [u8; 64] {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, key);
    *secp
        .sign_schnorr_with_rng(&Message::from_digest(*msg), &kp, &mut OsRng)
        .as_ref()
}

fn escrow_message(
    tx: &Transaction,
    input_index: usize,
    chain_id: u16,
    prevouts: &[(u64, [u8; 32])],
    path: u8,
) -> Result<[u8; 32], EscrowError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(EscrowError::Build(format!(
            "prevout count {} != input count {}",
            prevouts.len(),
            tx.inputs.len()
        )));
    }
    if input_index >= tx.inputs.len() {
        return Err(EscrowError::Build(format!("input {input_index} out of range")));
    }
    let base = sighash_v2(&tx.txid(chain_id).0, &prevouts_hash(prevouts), input_index as u32);
    Ok(escrow_sighash(&base, path))
}

/// The payer's half of a cooperative escrow spend (witness `0x02`) for input
/// `input_index`. The provider verifies it, adds its own signature and assembles the
/// witness with `coop_witness(policy, payer_sig, provider_sig)`.
pub fn sign_payer_half(
    tx: &Transaction,
    input_index: usize,
    chain_id: u16,
    prevouts: &[(u64, [u8; 32])],
    policy: &EscrowPolicy,
    payer_key: &SecretKey,
) -> Result<[u8; 64], EscrowError> {
    if own_xonly(payer_key) != policy.sender_pk {
        return Err(EscrowError::WrongKey);
    }
    if prevouts.get(input_index).map(|p| p.1) != Some(policy.hash()) {
        return Err(EscrowError::NotThisEscrow(input_index));
    }
    let msg = escrow_message(tx, input_index, chain_id, prevouts, WITNESS_TYPE_ESCROW_COOP)?;
    Ok(sign(payer_key, &msg))
}

/// The provider's half (reference implementation for the provider stub and tests).
pub fn sign_provider_half(
    tx: &Transaction,
    input_index: usize,
    chain_id: u16,
    prevouts: &[(u64, [u8; 32])],
    policy: &EscrowPolicy,
    provider_key: &SecretKey,
) -> Result<[u8; 64], EscrowError> {
    if own_xonly(provider_key) != policy.provider_pk {
        return Err(EscrowError::WrongKey);
    }
    if prevouts.get(input_index).map(|p| p.1) != Some(policy.hash()) {
        return Err(EscrowError::NotThisEscrow(input_index));
    }
    let msg = escrow_message(tx, input_index, chain_id, prevouts, WITNESS_TYPE_ESCROW_COOP)?;
    Ok(sign(provider_key, &msg))
}

/// An instant payment built by the payer: the transaction (no witnesses yet), its
/// prevouts and the payer's half-signature for every input (`PayHalfSign`).
#[derive(Clone, Debug)]
pub struct EscrowPayment {
    pub tx: Transaction,
    pub prevouts: Vec<(u64, [u8; 32])>,
    pub payer_sigs: Vec<[u8; 64]>,
}

/// Build a cooperative payment of `amount_atoms` to `to` from the listed escrow
/// outpoints, change back into the same escrow (`P`), and sign the payer's half of
/// every input. Refused unless at least `min_blocks_left` blocks remain before H
/// (spec §5.1: do not start a payment that cannot settle before H).
pub fn build_payment(
    record: &EscrowRecord,
    outpoints: &[EscrowOutpoint],
    payer_key: &SecretKey,
    to: [u8; 32],
    amount_atoms: u64,
    fee_atoms: u64,
    tip_height: u32,
    min_blocks_left: u32,
) -> Result<EscrowPayment, EscrowError> {
    let policy = record.policy()?;
    if own_xonly(payer_key) != policy.sender_pk {
        return Err(EscrowError::WrongKey);
    }
    if tip_height.saturating_add(min_blocks_left) >= policy.unlock_height {
        return Err(EscrowError::Build(format!(
            "escrow unlocks at {}; a payment needs {min_blocks_left} blocks before it (tip {tip_height})",
            policy.unlock_height
        )));
    }
    if outpoints.is_empty() || amount_atoms == 0 {
        return Err(EscrowError::Build("need escrow outpoints and a non-zero amount".into()));
    }
    let total: u64 = outpoints.iter().try_fold(0u64, |a, o| a.checked_add(o.value_atoms))
        .ok_or_else(|| EscrowError::Build("input sum overflows".into()))?;
    let change = amount_atoms
        .checked_add(fee_atoms)
        .and_then(|spend| total.checked_sub(spend))
        .ok_or_else(|| EscrowError::Build(format!("amount + fee exceed escrow value {total}")))?;

    let p = policy.hash();
    let mut outputs = vec![TxOutput { value: amount_atoms, recipient: to }];
    if change > 0 {
        outputs.push(TxOutput { value: change, recipient: p });
    }
    let tx = Transaction {
        version: 1,
        inputs: outpoints
            .iter()
            .map(|o| TxInput { prev_height: o.height, prev_output_idx: o.output_idx })
            .collect(),
        outputs,
        locktime: 0,
        expiration_height: 0,
        witnesses: Vec::new(),
        extensions: Vec::new(),
    };
    let prevouts: Vec<(u64, [u8; 32])> = outpoints.iter().map(|o| (o.value_atoms, p)).collect();
    let chain_id = record.chain_id();
    let payer_sigs = (0..outpoints.len())
        .map(|i| sign_payer_half(&tx, i, chain_id, &prevouts, &policy, payer_key))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EscrowPayment { tx, prevouts, payer_sigs })
}

/// Build and sign a recovery spend of every listed escrow outpoint to `to`, paying
/// `fee_atoms`. Refused before H (wallet mirror of ESC-3: admission uses the tip
/// height, so the tip must be at least H).
pub fn build_recovery(
    record: &EscrowRecord,
    outpoints: &[EscrowOutpoint],
    payer_key: &SecretKey,
    to: [u8; 32],
    fee_atoms: u64,
    tip_height: u32,
) -> Result<Transaction, EscrowError> {
    let policy = record.policy()?;
    if own_xonly(payer_key) != policy.sender_pk {
        return Err(EscrowError::WrongKey);
    }
    if tip_height < policy.unlock_height {
        return Err(EscrowError::NotYetUnlocked { unlock_height: policy.unlock_height, tip_height });
    }
    if outpoints.is_empty() {
        return Err(EscrowError::Build("no escrow outpoints to recover".into()));
    }
    let total: u64 = outpoints.iter().try_fold(0u64, |a, o| a.checked_add(o.value_atoms))
        .ok_or_else(|| EscrowError::Build("input sum overflows".into()))?;
    let value = total
        .checked_sub(fee_atoms)
        .filter(|v| *v > 0)
        .ok_or_else(|| EscrowError::Build(format!("fee {fee_atoms} >= escrow value {total}")))?;

    let mut tx = Transaction {
        version: 1,
        inputs: outpoints
            .iter()
            .map(|o| TxInput { prev_height: o.height, prev_output_idx: o.output_idx })
            .collect(),
        outputs: vec![TxOutput { value, recipient: to }],
        locktime: 0,
        expiration_height: 0,
        witnesses: Vec::new(),
        extensions: Vec::new(),
    };
    let p = policy.hash();
    let prevouts: Vec<(u64, [u8; 32])> = outpoints.iter().map(|o| (o.value_atoms, p)).collect();
    let chain_id = record.chain_id();
    let mut witnesses = Vec::with_capacity(outpoints.len());
    for i in 0..outpoints.len() {
        let msg = escrow_message(&tx, i, chain_id, &prevouts, WITNESS_TYPE_ESCROW_RECOVERY)?;
        witnesses.push(recovery_witness(&policy, &sign(payer_key, &msg)));
    }
    tx.witnesses = witnesses;
    Ok(tx)
}

// ─── Store ────────────────────────────────────────────────────────────────────

/// Atomic JSON-file store of escrow policies (`<base_dir>/escrows.json`).
pub struct EscrowStore {
    path: PathBuf,
}

impl EscrowStore {
    pub fn open(base_dir: &Path) -> Result<Self, EscrowError> {
        fs::create_dir_all(base_dir).map_err(EscrowError::Io)?;
        Ok(Self { path: base_dir.join("escrows.json") })
    }

    fn load_all(&self) -> Result<Vec<EscrowRecord>, EscrowError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read(&self.path).map_err(EscrowError::Io)?;
        serde_json::from_slice(&data).map_err(EscrowError::Json)
    }

    fn save_all(&self, all: &[EscrowRecord]) -> Result<(), EscrowError> {
        let tmp = self.path.with_file_name(".escrows.json.tmp");
        let data = serde_json::to_vec_pretty(all).map_err(EscrowError::Json)?;
        fs::write(&tmp, &data).map_err(EscrowError::Io)?;
        fs::rename(&tmp, &self.path).map_err(EscrowError::Io)?;
        Ok(())
    }

    /// Store a new escrow policy (call before funding: spec §5.2).
    pub fn add(
        &self,
        policy: &EscrowPolicy,
        shard_id: Option<u16>,
        provider_label: &str,
    ) -> Result<EscrowRecord, EscrowError> {
        let mut all = self.load_all()?;
        let p = hex::encode(policy.hash());
        if let Some(existing) = all.iter().find(|r| r.policy_hash_hex == p && r.shard_id == shard_id) {
            return Ok(existing.clone());
        }
        let rec = EscrowRecord {
            id: p[..16].to_string(),
            provider_label: provider_label.to_string(),
            shard_id,
            sender_pk_hex: hex::encode(policy.sender_pk),
            provider_pk_hex: hex::encode(policy.provider_pk),
            unlock_height: policy.unlock_height,
            policy_hash_hex: p,
            outpoints: Vec::new(),
            created_at_ms: now_ms(),
            backed_up_at_ms: None,
        };
        all.push(rec.clone());
        self.save_all(&all)?;
        Ok(rec)
    }

    pub fn list(&self) -> Result<Vec<EscrowRecord>, EscrowError> {
        self.load_all()
    }

    pub fn get(&self, id: &str) -> Result<EscrowRecord, EscrowError> {
        self.load_all()?.into_iter().find(|r| r.id == id).ok_or(EscrowError::NotFound)
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut EscrowRecord)) -> Result<EscrowRecord, EscrowError> {
        let mut all = self.load_all()?;
        let rec = all.iter_mut().find(|r| r.id == id).ok_or(EscrowError::NotFound)?;
        f(rec);
        let out = rec.clone();
        self.save_all(&all)?;
        Ok(out)
    }

    /// Record a funding output once it is in a block (a new payment slot).
    pub fn add_outpoint(&self, id: &str, o: EscrowOutpoint) -> Result<EscrowRecord, EscrowError> {
        self.update(id, |r| {
            if !r.outpoints.iter().any(|x| x.height == o.height && x.output_idx == o.output_idx) {
                r.outpoints.push(o);
            }
        })
    }

    /// Forget an outpoint once it was spent (payment or recovery in a block).
    pub fn remove_outpoint(&self, id: &str, height: u32, output_idx: u16) -> Result<EscrowRecord, EscrowError> {
        self.update(id, |r| r.outpoints.retain(|x| !(x.height == height && x.output_idx == output_idx)))
    }

    /// Escrows whose policy is not in any exported backup yet.
    pub fn not_backed_up(&self) -> Result<Vec<EscrowRecord>, EscrowError> {
        Ok(self.load_all()?.into_iter().filter(|r| r.backed_up_at_ms.is_none()).collect())
    }

    /// Export every policy as a versioned JSON backup and mark all as backed up.
    pub fn export_backup(&self) -> Result<String, EscrowError> {
        let mut all = self.load_all()?;
        let now = now_ms();
        for r in &mut all {
            r.backed_up_at_ms = Some(now);
        }
        let json = serde_json::to_string_pretty(&EscrowBackup { version: ESCROW_BACKUP_VERSION, escrows: all.clone() })
            .map_err(EscrowError::Json)?;
        self.save_all(&all)?;
        Ok(json)
    }

    /// Import a backup (e.g. after a restore). Each policy must hash to its stored P;
    /// already-known escrows keep their local outpoints. Returns how many were added.
    pub fn import_backup(&self, json: &str) -> Result<usize, EscrowError> {
        let backup: EscrowBackup = serde_json::from_str(json).map_err(EscrowError::Json)?;
        if backup.version != ESCROW_BACKUP_VERSION {
            return Err(EscrowError::BadBackup(format!("unknown version {}", backup.version)));
        }
        for r in &backup.escrows {
            let p = hex::encode(r.policy()?.hash());
            if p != r.policy_hash_hex {
                return Err(EscrowError::BadBackup(format!("escrow {} policy does not hash to its P", r.id)));
            }
        }
        let mut all = self.load_all()?;
        let mut added = 0;
        for r in backup.escrows {
            if !all.iter().any(|x| x.policy_hash_hex == r.policy_hash_hex && x.shard_id == r.shard_id) {
                all.push(r);
                added += 1;
            }
        }
        self.save_all(&all)?;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::crypto::escrow::coop_witness;
    use common_types::common::utxo::ForkUtxoOverlay;
    use common_types::common::validation::transactions::{
        validate_transaction_for_mempool, MempoolAdmissionParams,
    };
    use common_types::common::validation::BlockValidationUtxo;
    use common_types::transaction::{shard_chain_id, FlatOutput};

    const H: u32 = 500;

    fn keys() -> (SecretKey, SecretKey) {
        (SecretKey::from_slice(&[0x51; 32]).unwrap(), SecretKey::from_slice(&[0x52; 32]).unwrap())
    }

    fn setup(dir: &Path) -> (EscrowStore, EscrowRecord, EscrowPolicy, SecretKey, SecretKey) {
        let (payer, provider) = keys();
        let policy = new_policy(&payer, own_xonly(&provider), H, 100, 50).unwrap();
        let store = EscrowStore::open(dir).unwrap();
        let rec = store.add(&policy, Some(0), "Northwind Pay").unwrap();
        let rec = store.add_outpoint(&rec.id, EscrowOutpoint { height: 7, output_idx: 0, value_atoms: 10_000 }).unwrap();
        (store, rec, policy, payer, provider)
    }

    fn utxo_for(policy: &EscrowPolicy) -> ForkUtxoOverlay {
        let mut u = ForkUtxoOverlay::new();
        u.add(7, 0, FlatOutput { value: 10_000, recipient: policy.hash() });
        u
    }

    fn admit(tx: &Transaction, policy: &EscrowPolicy, tip: u32) -> Result<(), String> {
        let u = utxo_for(policy);
        validate_transaction_for_mempool(
            tx,
            BlockValidationUtxo::ReorgBuffer(&u),
            MempoolAdmissionParams::production(tip, 0, 1024, shard_chain_id(0)),
        )
        .map_err(|e| e.to_string())
    }

    #[test]
    fn policy_checks() {
        let (payer, provider) = keys();
        assert!(matches!(new_policy(&payer, own_xonly(&payer), H, 100, 50), Err(EscrowError::SameKeys)));
        assert!(matches!(new_policy(&payer, [0u8; 32], H, 100, 50), Err(EscrowError::InvalidKey(_))));
        assert!(matches!(
            new_policy(&payer, own_xonly(&provider), 150, 100, 50),
            Err(EscrowError::UnlockTooSoon { min_unlock_height: 151, .. })
        ));
        assert!(new_policy(&payer, own_xonly(&provider), 151, 100, 50).is_ok());
    }

    /// Payer half + provider half → a cooperative spend the node admits below H.
    #[test]
    fn payer_half_plus_provider_half_is_accepted_by_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let (_s, rec, policy, payer, provider) = setup(dir.path());
        let merchant = [0x77u8; 32];
        let merchant = own_xonly(&SecretKey::from_slice(&merchant).unwrap());
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 7, prev_output_idx: 0 }],
            outputs: vec![
                TxOutput { value: 4_000, recipient: merchant },
                funding_output(&policy, 5_000), // change back into the escrow
            ],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let prevouts = [(10_000, policy.hash())];
        let chain = rec.chain_id();
        let payer_sig = sign_payer_half(&tx, 0, chain, &prevouts, &policy, &payer).unwrap();
        let provider_sig = sign_provider_half(&tx, 0, chain, &prevouts, &policy, &provider).unwrap();
        tx.witnesses = vec![coop_witness(&policy, &payer_sig, &provider_sig)];
        admit(&tx, &policy, H - 1).expect("cooperative spend below H");
        assert!(admit(&tx, &policy, H).is_err(), "cooperative spend refused from H");
        // Payer half alone (provider slot holds the payer's signature twice) is refused.
        tx.witnesses = vec![coop_witness(&policy, &payer_sig, &payer_sig)];
        assert!(admit(&tx, &policy, H - 1).is_err());
    }

    /// `build_payment`: change returns to P, the provider completes it, the node admits it.
    #[test]
    fn build_payment_completed_by_provider_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (_s, rec, policy, payer, provider) = setup(dir.path());
        let merchant = own_xonly(&SecretKey::from_slice(&[0x77u8; 32]).unwrap());
        let pay = build_payment(&rec, &rec.outpoints, &payer, merchant, 4_000, 300, H - 20, 10).unwrap();
        assert_eq!(pay.tx.outputs.len(), 2);
        assert_eq!(pay.tx.outputs[1], funding_output(&policy, 5_700));
        let mut tx = pay.tx.clone();
        let provider_sig = sign_provider_half(&tx, 0, rec.chain_id(), &pay.prevouts, &policy, &provider).unwrap();
        tx.witnesses = vec![coop_witness(&policy, &pay.payer_sigs[0], &provider_sig)];
        admit(&tx, &policy, H - 1).expect("completed payment below H");

        // Exact spend: no change output.
        let exact = build_payment(&rec, &rec.outpoints, &payer, merchant, 9_700, 300, H - 20, 10).unwrap();
        assert_eq!(exact.tx.outputs.len(), 1);
        // Too close to H, over-spend, wrong key.
        assert!(build_payment(&rec, &rec.outpoints, &payer, merchant, 4_000, 300, H - 10, 10).is_err());
        assert!(build_payment(&rec, &rec.outpoints, &payer, merchant, 9_800, 300, H - 20, 10).is_err());
        assert!(matches!(
            build_payment(&rec, &rec.outpoints, &provider, merchant, 4_000, 300, H - 20, 10),
            Err(EscrowError::WrongKey)
        ));
    }

    #[test]
    fn payer_half_refuses_wrong_key_and_foreign_input() {
        let dir = tempfile::tempdir().unwrap();
        let (_s, rec, policy, _payer, provider) = setup(dir.path());
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_height: 7, prev_output_idx: 0 }],
            outputs: vec![TxOutput { value: 9_000, recipient: policy.sender_pk }],
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };
        let c = rec.chain_id();
        assert!(matches!(
            sign_payer_half(&tx, 0, c, &[(10_000, policy.hash())], &policy, &provider),
            Err(EscrowError::WrongKey)
        ));
        let (payer, _) = keys();
        assert!(matches!(
            sign_payer_half(&tx, 0, c, &[(10_000, [9u8; 32])], &policy, &payer),
            Err(EscrowError::NotThisEscrow(0))
        ));
    }

    /// Recovery: refused by the wallet before H, accepted by the node from H.
    #[test]
    fn recovery_spend_from_h() {
        let dir = tempfile::tempdir().unwrap();
        let (_s, rec, policy, payer, _p) = setup(dir.path());
        let to = policy.sender_pk;
        assert!(matches!(
            build_recovery(&rec, &rec.outpoints, &payer, to, 500, H - 1),
            Err(EscrowError::NotYetUnlocked { .. })
        ));
        let tx = build_recovery(&rec, &rec.outpoints, &payer, to, 500, H).unwrap();
        assert_eq!(tx.outputs[0].value, 9_500);
        admit(&tx, &policy, H).expect("recovery spend from H");
        assert!(admit(&tx, &policy, H - 1).is_err(), "node refuses recovery below H");
        assert!(matches!(build_recovery(&rec, &rec.outpoints, &payer, to, 10_000, H), Err(EscrowError::Build(_))));
    }

    #[test]
    fn store_backup_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (store, rec, policy, _payer, _p) = setup(dir.path());
        assert_eq!(store.not_backed_up().unwrap().len(), 1);
        let json = store.export_backup().unwrap();
        assert!(store.not_backed_up().unwrap().is_empty());
        // Adding the same policy again returns the existing record.
        assert_eq!(store.add(&policy, Some(0), "x").unwrap().id, rec.id);

        let other = tempfile::tempdir().unwrap();
        let restored = EscrowStore::open(other.path()).unwrap();
        assert_eq!(restored.import_backup(&json).unwrap(), 1);
        assert_eq!(restored.import_backup(&json).unwrap(), 0, "import is idempotent");
        let r = restored.get(&rec.id).unwrap();
        assert_eq!(r.policy().unwrap(), policy);
        assert_eq!(r.outpoints, rec.outpoints);

        let after = store.remove_outpoint(&rec.id, 7, 0).unwrap();
        assert!(after.outpoints.is_empty());

        // A tampered backup (H changed, P kept) is refused.
        let bad = json.replace(&format!("\"unlock_height\": {H}"), "\"unlock_height\": 501");
        assert!(matches!(restored.import_backup(&bad), Err(EscrowError::BadBackup(_))));
    }
}
