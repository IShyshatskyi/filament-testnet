// src/mmr_client/escrow_api.rs
//
// Escrow commands (IPP D14) shared by the local HTTP API (`filament_server.rs`,
// `/escrow/*`) and the Tauri commands (`filament_app/src-tauri/src/commands.rs`).
// Library: `crate::wallet::escrow`. Protocol: `filament_app/docs/IPP_PROTOCOL_AND_MUSIG2.md`.
//
// * Heights come from the light client's own verified chain state (`local_tip`), never
//   from the request: H checks (open, pay, recover) must not trust the UI.
// * Signing uses the wallet's hot key (`FilamentWallet::with_signing_key`, D10); the key
//   never leaves the wallet.
// * Recovery is broadcast as raw bytes to Keystone `POST /mempool/submit`
//   (`/mempool/submit/beacon` for the beacon chain), the route Keystone actually serves.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mmr_client::filament_wallet::FilamentWallet;
use crate::mmr_client::multi_chain_client::MultiChainClient;
use crate::wallet::escrow::{
    build_payment, build_recovery, new_policy, EscrowError, EscrowOutpoint, EscrowRecord, EscrowStore,
};

/// Default room between the tip and H when opening (return window W + provider margin).
pub const DEFAULT_MIN_LEAD_BLOCKS: u32 = 144;
/// Default blocks that must remain before H for a new payment to settle in time.
pub const DEFAULT_MIN_BLOCKS_LEFT: u32 = 6;

#[derive(Debug)]
pub enum EscrowApiError {
    NotFound(String),
    BadRequest(String),
    /// Chain state or Keystone not available.
    Unavailable(String),
    Internal(String),
}

impl std::fmt::Display for EscrowApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) | Self::BadRequest(s) | Self::Unavailable(s) | Self::Internal(s) => f.write_str(s),
        }
    }
}

impl From<EscrowError> for EscrowApiError {
    fn from(e: EscrowError) -> Self {
        match e {
            EscrowError::NotFound => Self::NotFound(e.to_string()),
            EscrowError::Io(_) | EscrowError::Json(_) => Self::Internal(e.to_string()),
            _ => Self::BadRequest(e.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, EscrowApiError>;

pub fn open_store(data_dir: &str) -> Result<EscrowStore> {
    Ok(EscrowStore::open(std::path::Path::new(data_dir))?)
}

/// Verified tip height of the escrow's chain (`None` = beacon), from the light client.
pub async fn local_tip(client: &MultiChainClient, shard_id: Option<u16>) -> Option<u32> {
    let state = match shard_id {
        None => client.get_beacon_state().await,
        Some(s) => client.get_shard_state(s as u32).await,
    };
    state.ok().map(|st| st.tip.height())
}

async fn require_tip(client: &MultiChainClient, shard_id: Option<u16>) -> Result<u32> {
    local_tip(client, shard_id).await.ok_or_else(|| {
        EscrowApiError::Unavailable(match shard_id {
            None => "beacon chain not synced yet — escrow heights need a verified tip".into(),
            Some(s) => format!("shard {} not synced yet — escrow heights need a verified tip", s + 1),
        })
    })
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim().trim_start_matches("0x"))
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| EscrowApiError::BadRequest(format!("{what} must be 64 hex chars")))
}

// ─── List ─────────────────────────────────────────────────────────────────────

/// One escrow as the Providers screen shows it.
#[derive(Debug, Clone, Serialize)]
pub struct EscrowView {
    #[serde(flatten)]
    pub record: EscrowRecord,
    pub value_atoms: u64,
    /// Verified tip of the escrow's chain, when synced.
    pub tip_height: Option<u32>,
    /// `"empty"` (no funding output yet), `"open"` (cooperative payments possible),
    /// `"closing"` (fewer than [`DEFAULT_MIN_BLOCKS_LEFT`] blocks before H),
    /// `"recoverable"` (tip ≥ H: payer-only recovery), `"unknown"` (no tip).
    pub state: &'static str,
    pub backed_up: bool,
}

fn view(record: EscrowRecord, tip: Option<u32>) -> EscrowView {
    let value_atoms = record.outpoints.iter().map(|o| o.value_atoms).sum();
    let state = match tip {
        _ if record.outpoints.is_empty() => "empty",
        None => "unknown",
        Some(t) if t >= record.unlock_height => "recoverable",
        Some(t) if t.saturating_add(DEFAULT_MIN_BLOCKS_LEFT) >= record.unlock_height => "closing",
        Some(_) => "open",
    };
    EscrowView { backed_up: record.backed_up_at_ms.is_some(), record, value_atoms, tip_height: tip, state }
}

// ─── Funding-output watch (indexer) ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IndexerUtxoPage {
    utxos: Vec<IndexerUtxo>,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    next_cursor: Option<String>,
    #[serde(default)]
    as_of: Vec<IndexerAsOf>,
}

#[derive(Debug, Deserialize)]
struct IndexerUtxo {
    chain: String,
    shard_id: Option<u16>,
    height: u32,
    output_idx: u16,
    value: u64,
}

#[derive(Debug, Deserialize)]
struct IndexerAsOf {
    chain: String,
    shard_id: Option<u16>,
    indexed_height: Option<u32>,
}

fn on_chain(chain: &str, shard: Option<u16>, want: Option<u16>) -> bool {
    match want {
        None => chain == "beacon",
        Some(s) => chain == "shard" && shard == Some(s),
    }
}

/// Unspent outputs paying `p_hex` on the escrow's chain, from the first indexer that
/// answers, plus that indexer's indexed height for the chain.
async fn indexer_outputs(
    http: &reqwest::Client,
    endpoints: &[String],
    p_hex: &str,
    shard_id: Option<u16>,
) -> std::result::Result<(Vec<EscrowOutpoint>, Option<u32>), String> {
    let mut last = String::from("no indexer endpoint configured");
    'endpoints: for ep in endpoints {
        let base = ep.trim_end_matches('/');
        let (mut out, mut indexed, mut cursor) = (Vec::new(), None, None::<String>);
        for _page in 0..64 {
            let mut url = format!("{base}/explorer/utxos?address={p_hex}");
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let page: IndexerUtxoPage = match http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
                Ok(r) if r.status().is_success() => match r.json().await {
                    Ok(p) => p,
                    Err(e) => {
                        last = format!("{base}: {e}");
                        continue 'endpoints;
                    }
                },
                Ok(r) => {
                    last = format!("{base}: HTTP {}", r.status());
                    continue 'endpoints;
                }
                Err(e) => {
                    last = format!("{base}: {e}");
                    continue 'endpoints;
                }
            };
            if indexed.is_none() {
                indexed = page.as_of.iter().find(|a| on_chain(&a.chain, a.shard_id, shard_id)).and_then(|a| a.indexed_height);
            }
            out.extend(
                page.utxos
                    .iter()
                    .filter(|u| on_chain(&u.chain, u.shard_id, shard_id))
                    .map(|u| EscrowOutpoint { height: u.height, output_idx: u.output_idx, value_atoms: u.value }),
            );
            match (page.truncated, page.next_cursor) {
                (true, Some(c)) => cursor = Some(c),
                _ => return Ok((out, indexed)),
            }
        }
        return Ok((out, indexed));
    }
    Err(last)
}

/// Bring every escrow's funding outputs in line with the indexer: add outputs paying `P`;
/// forget a stored output once the indexer has indexed its height and no longer lists it
/// (spent). Outputs above the indexer's height are kept (it may lag). Returns warnings.
pub async fn sync_outpoints(store: &EscrowStore, http: &reqwest::Client, endpoints: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    if endpoints.is_empty() {
        return warnings;
    }
    let records = match store.list() {
        Ok(r) => r,
        Err(e) => return vec![e.to_string()],
    };
    for rec in records {
        let (found, indexed) = match indexer_outputs(http, endpoints, &rec.policy_hash_hex, rec.shard_id).await {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!("escrow {}: {e}", rec.id));
                continue;
            }
        };
        for o in &found {
            if !rec.outpoints.iter().any(|x| x.height == o.height && x.output_idx == o.output_idx) {
                if let Err(e) = store.add_outpoint(&rec.id, *o) {
                    warnings.push(e.to_string());
                }
            }
        }
        for o in &rec.outpoints {
            let covered = indexed.is_some_and(|h| o.height <= h);
            let listed = found.iter().any(|x| x.height == o.height && x.output_idx == o.output_idx);
            if covered && !listed {
                if let Err(e) = store.remove_outpoint(&rec.id, o.height, o.output_idx) {
                    warnings.push(e.to_string());
                }
            }
        }
    }
    warnings
}

pub async fn list(store: &EscrowStore, client: &MultiChainClient) -> Result<Vec<EscrowView>> {
    let mut out = Vec::new();
    for r in store.list()? {
        let tip = local_tip(client, r.shard_id).await;
        out.push(view(r, tip));
    }
    Ok(out)
}

// ─── Open ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct OpenEscrowRequest {
    pub provider_pk_hex: String,
    pub unlock_height: u32,
    /// `None` = beacon chain; `Some(n)` = shard n (0-indexed).
    #[serde(default)]
    pub shard_id: Option<u16>,
    #[serde(default)]
    pub provider_label: String,
    #[serde(default)]
    pub min_lead_blocks: Option<u32>,
}

/// Store a new policy (back it up before funding: spec §5.2). The funding transaction
/// itself is an ordinary send to `policy_hash_hex`; record its outputs with
/// [`add_outpoint`] once they are in a block.
pub async fn open(
    store: &EscrowStore,
    wallet: &FilamentWallet,
    client: &MultiChainClient,
    req: &OpenEscrowRequest,
) -> Result<EscrowView> {
    let provider_pk = hex32(&req.provider_pk_hex, "provider_pk_hex")?;
    let tip = require_tip(client, req.shard_id).await?;
    let lead = req.min_lead_blocks.unwrap_or(DEFAULT_MIN_LEAD_BLOCKS);
    let policy = wallet
        .with_signing_key(|k| new_policy(k, provider_pk, req.unlock_height, tip, lead))
        .map_err(EscrowApiError::BadRequest)??;
    let rec = store.add(&policy, req.shard_id, &req.provider_label)?;
    Ok(view(rec, Some(tip)))
}

pub fn add_outpoint(store: &EscrowStore, id: &str, o: EscrowOutpoint) -> Result<EscrowRecord> {
    Ok(store.add_outpoint(id, o)?)
}

pub fn remove_outpoint(store: &EscrowStore, id: &str, height: u32, output_idx: u16) -> Result<EscrowRecord> {
    Ok(store.remove_outpoint(id, height, output_idx)?)
}

// ─── Backup ───────────────────────────────────────────────────────────────────

/// Export every policy (marks them backed up). Returned as JSON, ready to save.
pub fn export_backup(store: &EscrowStore) -> Result<Value> {
    let json = store.export_backup()?;
    serde_json::from_str(&json).map_err(|e| EscrowApiError::Internal(e.to_string()))
}

/// Import a backup; returns how many escrows were added.
pub fn import_backup(store: &EscrowStore, backup: &Value) -> Result<usize> {
    Ok(store.import_backup(&backup.to_string())?)
}

// ─── Pay (payer half) ─────────────────────────────────────────────────────────

/// A positional reference to one of the escrow's funding outputs.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct OutpointRef {
    pub height: u32,
    pub output_idx: u16,
}

fn pick(record: &EscrowRecord, refs: &Option<Vec<OutpointRef>>) -> Result<Vec<EscrowOutpoint>> {
    match refs {
        None => Ok(record.outpoints.clone()),
        Some(refs) => refs
            .iter()
            .map(|r| {
                record
                    .outpoints
                    .iter()
                    .find(|o| o.height == r.height && o.output_idx == r.output_idx)
                    .copied()
                    .ok_or_else(|| {
                        EscrowApiError::BadRequest(format!(
                            "{}:{} is not a funding output of escrow {}",
                            r.height, r.output_idx, record.id
                        ))
                    })
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayRequest {
    /// Merchant address (64 hex).
    pub to_hex: String,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    /// Escrow outputs to spend; default all.
    #[serde(default)]
    pub outpoints: Option<Vec<OutpointRef>>,
    #[serde(default)]
    pub min_blocks_left: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrevoutView {
    pub value_atoms: u64,
    pub recipient_hex: String,
}

/// `PayHalfSign` body for the provider: the unsigned payment, its prevouts and the
/// payer's signature per input.
#[derive(Debug, Clone, Serialize)]
pub struct PayResponse {
    pub escrow_id: String,
    pub shard_id: Option<u16>,
    /// `Transaction::serialize_with_witnesses` with no witnesses yet.
    pub tx_hex: String,
    pub txid: String,
    pub prevouts: Vec<PrevoutView>,
    pub payer_sigs_hex: Vec<String>,
    pub change_atoms: u64,
}

impl PayResponse {
    /// The `PayHalfSign` message for the provider endpoint (`common::ipp`).
    pub fn to_message(&self, session_id: &str, payment_request_id: &str, chain_id: u16) -> common_types::common::ipp::PayHalfSign {
        common_types::common::ipp::PayHalfSign {
            version: common_types::common::ipp::IPP_VERSION,
            session_id: session_id.to_string(),
            payment_request_id: payment_request_id.to_string(),
            chain_id,
            tx_hex: self.tx_hex.clone(),
            prevouts: self
                .prevouts
                .iter()
                .map(|p| common_types::common::ipp::Prevout { value_atoms: p.value_atoms, recipient_hex: p.recipient_hex.clone() })
                .collect(),
            payer_sigs_hex: self.payer_sigs_hex.clone(),
        }
    }
}

pub async fn pay(
    store: &EscrowStore,
    wallet: &FilamentWallet,
    client: &MultiChainClient,
    id: &str,
    req: &PayRequest,
) -> Result<PayResponse> {
    let record = store.get(id)?;
    let to = hex32(&req.to_hex, "to_hex")?;
    let outpoints = pick(&record, &req.outpoints)?;
    let tip = require_tip(client, record.shard_id).await?;
    let left = req.min_blocks_left.unwrap_or(DEFAULT_MIN_BLOCKS_LEFT);
    let pay = wallet
        .with_signing_key(|k| build_payment(&record, &outpoints, k, to, req.amount_atoms, req.fee_atoms, tip, left))
        .map_err(EscrowApiError::BadRequest)??;
    let change_atoms = pay.tx.outputs.get(1).map(|o| o.value).unwrap_or(0);
    Ok(PayResponse {
        escrow_id: record.id.clone(),
        shard_id: record.shard_id,
        tx_hex: hex::encode(pay.tx.serialize_with_witnesses()),
        txid: hex::encode(pay.tx.txid(record.chain_id()).0),
        prevouts: pay
            .prevouts
            .iter()
            .map(|(v, r)| PrevoutView { value_atoms: *v, recipient_hex: hex::encode(r) })
            .collect(),
        payer_sigs_hex: pay.payer_sigs.iter().map(hex::encode).collect(),
        change_atoms,
    })
}

// ─── Recover ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RecoverRequest {
    /// Destination (64 hex); default the wallet's own address.
    #[serde(default)]
    pub to_hex: Option<String>,
    pub fee_atoms: u64,
    #[serde(default)]
    pub outpoints: Option<Vec<OutpointRef>>,
    /// Submit to Keystone after signing.
    #[serde(default)]
    pub broadcast: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverResponse {
    pub escrow_id: String,
    pub shard_id: Option<u16>,
    /// `Transaction::serialize_with_witnesses` (signed `0x03` witnesses).
    pub tx_hex: String,
    pub txid: String,
    pub value_atoms: u64,
    /// Keystone's answer when `broadcast` was requested.
    pub broadcast: Option<Value>,
}

/// Build and sign the payer-only recovery (from H). Does not broadcast; see
/// [`submit_raw_tx`].
pub async fn recover(
    store: &EscrowStore,
    wallet: &FilamentWallet,
    client: &MultiChainClient,
    id: &str,
    req: &RecoverRequest,
) -> Result<(RecoverResponse, Vec<u8>)> {
    let record = store.get(id)?;
    let to = match &req.to_hex {
        Some(h) => hex32(h, "to_hex")?,
        None => hex32(wallet.address(), "wallet address")?,
    };
    let outpoints = pick(&record, &req.outpoints)?;
    let tip = require_tip(client, record.shard_id).await?;
    let tx = wallet
        .with_signing_key(|k| build_recovery(&record, &outpoints, k, to, req.fee_atoms, tip))
        .map_err(EscrowApiError::BadRequest)??;
    let bytes = tx.serialize_with_witnesses();
    Ok((
        RecoverResponse {
            escrow_id: record.id.clone(),
            shard_id: record.shard_id,
            tx_hex: hex::encode(&bytes),
            txid: hex::encode(tx.txid(record.chain_id()).0),
            value_atoms: tx.outputs[0].value,
            broadcast: None,
        },
        bytes,
    ))
}

/// Submit raw transaction bytes to Keystone (`keystone_submit::submit_raw_tx`).
pub async fn submit_raw_tx(
    http: &reqwest::Client,
    endpoints: &[String],
    shard_id: Option<u16>,
    bytes: Vec<u8>,
) -> Result<Value> {
    crate::mmr_client::keystone_submit::submit_raw_tx(http, endpoints, shard_id, bytes)
        .await
        .map_err(EscrowApiError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(outpoints: Vec<EscrowOutpoint>) -> EscrowRecord {
        EscrowRecord {
            id: "abcd".into(),
            provider_label: String::new(),
            shard_id: Some(0),
            sender_pk_hex: String::new(),
            provider_pk_hex: String::new(),
            unlock_height: 100,
            policy_hash_hex: String::new(),
            outpoints,
            created_at_ms: 0,
            backed_up_at_ms: None,
        }
    }

    #[test]
    fn view_state_follows_tip_and_h() {
        let o = vec![EscrowOutpoint { height: 5, output_idx: 0, value_atoms: 700 }];
        assert_eq!(view(rec(vec![]), Some(10)).state, "empty");
        assert_eq!(view(rec(o.clone()), None).state, "unknown");
        assert_eq!(view(rec(o.clone()), Some(50)).state, "open");
        assert_eq!(view(rec(o.clone()), Some(94)).state, "closing");
        assert_eq!(view(rec(o.clone()), Some(100)).state, "recoverable");
        assert_eq!(view(rec(o), Some(50)).value_atoms, 700);
    }

    /// Funding watch against a fake indexer: new outputs are added, an indexed-and-missing
    /// one is forgotten, one above the indexer's height is kept, other chains are ignored.
    #[tokio::test]
    async fn sync_outpoints_follows_the_indexer() {
        use axum::{routing::get, Json, Router};
        let dir = tempfile::tempdir().unwrap();
        let store = EscrowStore::open(dir.path()).unwrap();
        let policy = common_types::common::crypto::escrow::EscrowPolicy {
            sender_pk: [1; 32],
            provider_pk: [2; 32],
            unlock_height: 500,
        };
        let rec = store.add(&policy, Some(0), "P").unwrap();
        store.add_outpoint(&rec.id, EscrowOutpoint { height: 10, output_idx: 0, value_atoms: 5 }).unwrap(); // spent
        store.add_outpoint(&rec.id, EscrowOutpoint { height: 99, output_idx: 0, value_atoms: 6 }).unwrap(); // above indexer

        let p_hex = rec.policy_hash_hex.clone();
        let app = Router::new().route(
            "/explorer/utxos",
            get(move |q: axum::extract::Query<std::collections::HashMap<String, String>>| {
                let p = p_hex.clone();
                async move {
                    assert_eq!(q.get("address"), Some(&p));
                    let (utxos, truncated, cursor) = if q.get("cursor").is_none() {
                        (serde_json::json!([
                            { "chain": "shard", "shard_id": 0, "height": 20, "output_idx": 1, "value": 700 },
                            { "chain": "shard", "shard_id": 3, "height": 21, "output_idx": 0, "value": 9 }
                        ]), true, Some("c1"))
                    } else {
                        (serde_json::json!([{ "chain": "shard", "shard_id": 0, "height": 22, "output_idx": 2, "value": 800 }]), false, None)
                    };
                    Json(serde_json::json!({
                        "address": p, "utxos": utxos, "truncated": truncated, "next_cursor": cursor,
                        "as_of": [{ "chain": "shard", "shard_id": 0, "indexed_height": 50, "durable_height": 50 }]
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let warnings = sync_outpoints(&store, &reqwest::Client::new(), &[format!("http://{addr}")]).await;
        assert!(warnings.is_empty(), "{warnings:?}");
        let mut got: Vec<(u32, u16, u64)> =
            store.get(&rec.id).unwrap().outpoints.iter().map(|o| (o.height, o.output_idx, o.value_atoms)).collect();
        got.sort();
        assert_eq!(got, vec![(20, 1, 700), (22, 2, 800), (99, 0, 6)]);

        // Unreachable indexer: a warning, nothing changed.
        let w = sync_outpoints(&store, &reqwest::Client::new(), &["http://127.0.0.1:1".into()]).await;
        assert_eq!(w.len(), 1);
        assert_eq!(store.get(&rec.id).unwrap().outpoints.len(), 3);
    }

    #[test]
    fn pick_refuses_unknown_outpoint() {
        let r = rec(vec![EscrowOutpoint { height: 5, output_idx: 1, value_atoms: 700 }]);
        assert_eq!(pick(&r, &None).unwrap().len(), 1);
        assert_eq!(pick(&r, &Some(vec![OutpointRef { height: 5, output_idx: 1 }])).unwrap().len(), 1);
        assert!(pick(&r, &Some(vec![OutpointRef { height: 5, output_idx: 0 }])).is_err());
    }
}
