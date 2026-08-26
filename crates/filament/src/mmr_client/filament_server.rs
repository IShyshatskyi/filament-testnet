// src/mmr_client/filament_server.rs — Filament HTTP API server (port 7380)
//
// All 14+ endpoints described in docs/plan/Filament_App_Plan.md.
// Only compiled when the `full-node` feature is active (axum, tower-http).

#![cfg(feature = "full-node")]

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::{delete, get, post, put},
    Router,
};
use futures_util::stream;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;

use crate::mmr_client::chain_handler::{ChainState, ChainType};
use crate::mmr_client::filament_wallet::{FilamentWallet, SendRequest};
use crate::mmr_client::multi_chain_client::{ChainSyncStatus, ClientEvent, MultiChainClient};

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilamentNodeConfig {
    pub network: String,
    pub port: u16,
    pub node_endpoint: Option<String>,
    pub keystone_endpoint: Option<String>,
    /// MNT-1: additional Keystone REST endpoints to fan wallet-ops queries
    /// out to, alongside `keystone_endpoint`/`node_endpoint` (kept for
    /// backward compatibility with existing config files — see
    /// `all_keystone_endpoints()` for the merged, de-duplicated list
    /// actually used by the wallet). See
    /// `filament_app/docs/MULTI_NODE_TRUST_PLAN.md` Track B.
    #[serde(default)]
    pub keystone_rest_endpoints: Vec<String>,
    pub data_dir: String,
    /// User-added ShishaNet dial targets: `(host, p2p_port)` — not REST ports.
    /// Prefer `keystone_endpoint` + `keystone_p2p_port` for Keystones that
    /// share a host with wallet REST; use this for explicit `shishanet://`
    /// / QR / `--manual-peer` peers.
    #[serde(default)]
    pub manual_peers: Vec<(String, u16)>,
    /// DNS seed hostnames for Layer 3 peer discovery.
    #[serde(default = "default_dns_seeds")]
    pub dns_seeds: Vec<String>,
    /// Live sync loop (MNT-2/3/4 wired to real peers): port each configured
    /// Keystone's light-client `GET /chain/summary` API listens on —
    /// same host as each `keystone_rest_endpoints`/`keystone_endpoint` entry,
    /// different port (Keystone's `mmr_light_client.port`, default 8080 on
    /// the Keystone side; matches `default_light_client_summary_port` here).
    /// See `light_client_summary_url` and
    /// `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
    #[serde(default = "default_light_client_summary_port")]
    pub light_client_summary_port: u16,
    /// Keystone wallet REST port used when converting discovery `(host, port)`
    /// tuples into `http://host:port` endpoint URLs (PD-INT-1). Discovery
    /// seeds advertise ShishaNet P2P ports; wallet ops use this port instead.
    #[serde(default = "default_keystone_rest_port")]
    pub keystone_rest_port: u16,
    /// ShishaNet listen port on each Keystone host derived from
    /// `all_keystone_endpoints()` (same host, this port). Default matches
    /// Keystone's common ShishaNet listen (`18334`). Override when the node
    /// uses a non-default P2P port (e.g. local smoke / testnet-stress).
    #[serde(default = "default_keystone_p2p_port")]
    pub keystone_p2p_port: u16,
    /// When true (default), start a ShishaNet PeerManager, dial
    /// `manual_peers` + peer-cache + REST-derived Keystone hosts, and receive
    /// Path-2 notifs over P2P in addition to the HTTP `/light/notifications`
    /// poll. Live `POST /peers` / Tauri `add_peer` also dial when P2P is up.
    #[serde(default = "default_enable_p2p")]
    pub enable_p2p: bool,
    /// Bind address for Filament's light-client listener (`127.0.0.1:0` =
    /// ephemeral outbound-oriented bind).
    #[serde(default = "default_p2p_listen")]
    pub p2p_listen: String,
    /// Blocks after inclusion before an invoice becomes `Confirmed`
    /// (default 6). Lower only for local/smoke soaks.
    #[serde(default = "default_confirmation_depth")]
    pub confirmation_depth: u32,
    /// Optional 64-hex `bitcoin_anchor_hash` used to verify Path-2 inclusion
    /// MMR proofs when the local beacon chain is not yet initialized (common
    /// for HTTP-only / early-boot Filament). Must match the Keystone genesis
    /// the proofs were built against.
    #[serde(default)]
    pub bitcoin_anchor_hex: Option<String>,
}

fn default_dns_seeds() -> Vec<String> {
    vec!["seeds.shishanet.io".into(), "testnet-seeds.shishanet.io".into()]
}

fn default_light_client_summary_port() -> u16 { 8080 }

fn default_keystone_rest_port() -> u16 { 7379 }

fn default_keystone_p2p_port() -> u16 { 18334 }

fn default_enable_p2p() -> bool { true }

fn default_p2p_listen() -> String { "127.0.0.1:0".into() }

fn default_confirmation_depth() -> u32 { 6 }

impl Default for FilamentNodeConfig {
    fn default() -> Self {
        Self {
            network: "testnet1".into(),
            port: 7380,
            node_endpoint: None,
            keystone_endpoint: None,
            keystone_rest_endpoints: Vec::new(),
            data_dir: "./filament-data".into(),
            manual_peers: Vec::new(),
            dns_seeds: default_dns_seeds(),
            light_client_summary_port: default_light_client_summary_port(),
            keystone_rest_port: default_keystone_rest_port(),
            keystone_p2p_port: default_keystone_p2p_port(),
            enable_p2p: default_enable_p2p(),
            p2p_listen: default_p2p_listen(),
            confirmation_depth: default_confirmation_depth(),
            bitcoin_anchor_hex: None,
        }
    }
}

impl FilamentNodeConfig {
    /// Anchor used for Path-2 MMR proof verification: configured hex override,
    /// else zeros (caller should prefer live beacon state when available).
    pub fn configured_bitcoin_anchor(&self) -> Option<[u8; 32]> {
        let hex = self.bitcoin_anchor_hex.as_ref()?;
        let hex = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() != 64 {
            return None;
        }
        let Ok(bytes) = hex::decode(hex) else {
            return None;
        };
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }
}

impl FilamentNodeConfig {
    /// MNT-1: the full, de-duplicated list of Keystone REST endpoints this
    /// wallet should query — `keystone_rest_endpoints` plus the legacy
    /// single-URL `keystone_endpoint`/`node_endpoint` fields, so existing
    /// config files keep working unedited. `keystone_rest_endpoints` comes
    /// first (explicit multi-endpoint config takes priority ordering).
    pub fn all_keystone_endpoints(&self) -> Vec<String> {
        let mut eps = self.keystone_rest_endpoints.clone();
        for legacy in [&self.keystone_endpoint, &self.node_endpoint].into_iter().flatten() {
            if !eps.contains(legacy) {
                eps.push(legacy.clone());
            }
        }
        eps
    }

    /// PD-INT-1: configured Keystone REST endpoints plus any peers returned
    /// by `PeerDiscovery::resolve()` (cache → manual → hardcoded seeds).
    pub fn effective_keystone_endpoints(
        &self,
        cache: Option<&crate::peer_cache::PeerCache>,
    ) -> Vec<String> {
        let configured = self.all_keystone_endpoints();
        if let Some(cache) = cache {
            return crate::peer_discovery::merge_discovery_keystone_endpoints(
                &configured,
                cache,
                &self.manual_peers,
                &self.dns_seeds,
                &self.network,
                self.keystone_rest_port,
            );
        }
        if let Ok(cache) = crate::peer_cache::PeerCache::open(std::path::Path::new(&self.data_dir)) {
            return crate::peer_discovery::merge_discovery_keystone_endpoints(
                &configured,
                &cache,
                &self.manual_peers,
                &self.dns_seeds,
                &self.network,
                self.keystone_rest_port,
            );
        }
        configured
    }

    /// Live sync loop: every configured Keystone's light-client
    /// chain-summary API URL, derived from `all_keystone_endpoints()` by
    /// swapping the port to `light_client_summary_port` (same host — see the
    /// field doc). Assumes each endpoint is a plain `scheme://host:port`
    /// URL, matching how these entries are used everywhere else in this
    /// file; an endpoint with no parseable `:port` suffix is skipped rather
    /// than guessed at.
    pub fn light_client_summary_urls(&self) -> Vec<String> {
        self.all_keystone_endpoints()
            .into_iter()
            .filter_map(|ep| light_client_summary_url(&ep, self.light_client_summary_port))
            .collect()
    }

    /// PD-INT-1: light-client summary URLs derived from discovery-aware endpoints.
    pub fn effective_light_client_summary_urls(
        &self,
        cache: Option<&crate::peer_cache::PeerCache>,
    ) -> Vec<String> {
        self.effective_keystone_endpoints(cache)
            .into_iter()
            .filter_map(|ep| light_client_summary_url(&ep, self.light_client_summary_port))
            .collect()
    }

    /// PD-UI-4: record a user-added peer in `manual_peers` (idempotent).
    pub fn upsert_manual_peer(&mut self, host: impl Into<String>, port: u16) -> bool {
        let host = host.into();
        if self.manual_peers.iter().any(|(h, p)| h == &host && *p == port) {
            return false;
        }
        self.manual_peers.push((host, port));
        true
    }

    /// PD-UI-4: drop a user-added peer from `manual_peers`.
    pub fn drop_manual_peer(&mut self, host: &str, port: u16) -> bool {
        let before = self.manual_peers.len();
        self.manual_peers.retain(|(h, p)| !(h == host && *p == port));
        self.manual_peers.len() < before
    }
}

/// Parse `host:port` using the last `:` as the port separator.
pub fn parse_host_port(addr: &str) -> Result<(String, u16), String> {
    let addr = addr.trim();
    let Some((host, port_str)) = addr.rsplit_once(':') else {
        return Err(format!("invalid host:port address: {addr}"));
    };
    if host.is_empty() {
        return Err(format!("invalid host:port address: {addr}"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port in address: {addr}"))?;
    Ok((host.to_string(), port))
}

/// See `FilamentNodeConfig::light_client_summary_urls`.
fn light_client_summary_url(endpoint: &str, light_client_summary_port: u16) -> Option<String> {
    let (scheme_and_host, old_port) = endpoint.rsplit_once(':')?;
    // Confirm the split actually landed on a `:port` suffix and not, say,
    // the `http:` scheme separator in a port-less URL (`rsplit_once` finds
    // the *last* `:` regardless of which one that is) — a non-numeric tail
    // means there was no real port to swap out.
    old_port.parse::<u16>().ok()?;
    Some(format!("{}:{}", scheme_and_host, light_client_summary_port))
}

/// PD-INT-1: run peer discovery at startup — merge resolved peers into the
/// wallet's Keystone REST endpoint list and seed `MultiChainClient` for trust
/// reconciliation before the first sync tick.
pub async fn apply_startup_peer_discovery(
    config: &FilamentNodeConfig,
    wallet: &mut FilamentWallet,
    client: &mut MultiChainClient,
) {
    use crate::mmr_client::multi_chain_client::{PeerCapabilities, PeerConnection};
    use crate::peer_discovery::resolve_discovery_peers;

    let data_dir = std::path::Path::new(&config.data_dir);
    let cache = match crate::peer_cache::PeerCache::open(data_dir) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("PeerCache::open failed ({}); skipping startup discovery", e);
            return;
        }
    };

    // PD-INT-2: resolve DNS seeds into the cache before synchronous resolve().
    let dns_written = crate::dns_seeds::refresh_dns_seeds_into_cache(
        &cache,
        &config.dns_seeds,
        crate::dns_seeds::DEFAULT_DNS_SEED_PORT,
    )
    .await;
    if dns_written > 0 {
        info!("PD-INT-2: cached {dns_written} DNS seed peer(s) at startup");
    }

    let peers = resolve_discovery_peers(
        &cache,
        &config.manual_peers,
        &config.dns_seeds,
        &config.network,
    );
    let endpoints = config.effective_keystone_endpoints(Some(&cache));
    wallet.set_keystone_endpoints(endpoints);

    if peers.is_empty() {
        return;
    }

    let now_s = now_ms() / 1000;
    let known: std::collections::HashSet<String> = client
        .get_peers()
        .await
        .into_iter()
        .map(|p| p.address)
        .collect();

    let mut added = 0usize;
    for (host, port) in peers {
        let addr = format!("{host}:{port}");
        if known.contains(&addr) {
            continue;
        }
        let peer = PeerConnection {
            peer_id: format!("discovery-{addr}"),
            address: addr,
            capabilities: PeerCapabilities {
                beacon_proofs: true,
                shard_proofs: true,
                tracked_shards: Vec::new(),
                fast_sync: true,
                archive_node: false,
            },
            connected_at: now_s,
            last_seen: now_s,
        };
        if client.add_peer(peer).await.is_ok() {
            added += 1;
        }
    }
    if added > 0 {
        info!("PD-INT-1: registered {added} discovery peer(s) from startup resolve");
    }
}

// ── Notification ring ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: u64,
    pub ts_ms: u64,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub body: String,
    pub view_hint: Option<String>,
}

pub struct NotifRing {
    items: VecDeque<Notification>,
    next_id: u64,
}

impl NotifRing {
    pub fn new() -> Self {
        Self { items: VecDeque::new(), next_id: 1 }
    }

    pub fn push(&mut self, severity: &str, category: &str, title: &str, body: &str, view_hint: Option<&str>) {
        let id = self.next_id;
        self.next_id += 1;
        self.items.push_front(Notification {
            id,
            ts_ms: now_ms(),
            severity: severity.into(),
            category: category.into(),
            title: title.into(),
            body: body.into(),
            view_hint: view_hint.map(String::from),
        });
        if self.items.len() > 200 {
            self.items.pop_back();
        }
    }

    pub fn since(&self, since_id: u64, n: usize, severity_filter: Option<&str>) -> Vec<Notification> {
        self.items.iter()
            .filter(|item| item.id > since_id)
            .filter(|item| severity_filter.map_or(true, |s| item.severity == s))
            .take(n)
            .cloned()
            .collect()
    }

    pub fn critical_count(&self) -> usize {
        self.items.iter().filter(|n| n.severity == "CRITICAL").count()
    }
}

// ── Log ring ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts: u64,
    pub level: String,
    pub msg: String,
    pub src: String,
}

pub struct LogRing {
    items: VecDeque<LogEntry>,
    next_id: u64,
}

impl LogRing {
    pub fn new() -> Self {
        Self { items: VecDeque::new(), next_id: 1 }
    }

    pub fn push(&mut self, level: &str, msg: &str, src: &str) {
        let id = self.next_id;
        self.next_id += 1;
        self.items.push_front(LogEntry {
            id, ts: now_ms(), level: level.into(), msg: msg.into(), src: src.into(),
        });
        if self.items.len() > 500 {
            self.items.pop_back();
        }
    }

    pub fn recent(&self, n: usize) -> Vec<LogEntry> {
        self.items.iter().take(n).cloned().collect()
    }
}

// ── FlyClient sync stats ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSyncEntry {
    pub chain_id: u32,
    pub label: String,
    pub phase: String,
    pub height: u32,
    pub tip: u32,
    pub progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    pub phase: String,
    pub progress: f64,
    pub tip_height: u32,
    pub synced_height: u32,
    pub sample_count: u32,
    pub sample_target: u32,
    pub peaks_count: u32,
    pub proof_bytes_rx: u64,
    pub spv_bytes_saved: u64,
    pub bandwidth_ratio: f64,
    pub confidence: f64,
    pub last_proof_ms: Option<f64>,
    pub chains: Vec<ChainSyncEntry>,
}

impl SyncStats {
    fn new() -> Self {
        Self {
            phase: "bootstrapping".into(),
            progress: 0.0,
            tip_height: 0,
            synced_height: 0,
            sample_count: 0,
            sample_target: 320,
            peaks_count: 18,
            proof_bytes_rx: 0,
            spv_bytes_saved: 0,
            bandwidth_ratio: 0.014,
            confidence: 0.0,
            last_proof_ms: None,
            chains: Vec::new(),
        }
    }

    fn update(&mut self, status: &ChainSyncStatus, tip: u32) {
        self.tip_height = tip;
        match status {
            ChainSyncStatus::Synced => {
                self.phase = "synced".into();
                self.progress = 1.0;
                self.synced_height = tip;
                self.sample_count = self.sample_target;
                self.confidence = 0.9999;
                self.proof_bytes_rx = 173_000;
                self.spv_bytes_saved = 12_000_000;
            }
            ChainSyncStatus::Syncing { current_height, target_height, progress_percent } => {
                self.phase = "syncing".into();
                self.progress = *progress_percent as f64 / 100.0;
                self.synced_height = *current_height;
                self.tip_height = *target_height;
                self.sample_count = (self.sample_target as f64 * self.progress) as u32;
                self.confidence = self.progress * 0.9999;
                self.proof_bytes_rx = (173_000.0 * self.progress) as u64;
                self.spv_bytes_saved = (12_000_000.0 * self.progress) as u64;
            }
            ChainSyncStatus::NotStarted => {
                self.phase = "bootstrapping".into();
                self.progress = 0.0;
            }
            ChainSyncStatus::Paused => {
                self.phase = "paused".into();
            }
            ChainSyncStatus::Error { .. } => {
                self.phase = "error".into();
            }
            // MNT-6: chain state may be current, but not enough independent
            // peers are connected to trust it — surfaced distinctly rather
            // than folded into "synced".
            ChainSyncStatus::InsufficientPeers { .. } => {
                self.phase = "insufficient_peers".into();
                self.confidence = 0.0;
            }
        }
    }
}

// ── Config persistence ────────────────────────────────────────────────────────

fn config_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("config.toml")
}

async fn save_config_to_disk(cfg: &FilamentNodeConfig) {
    let path = config_path(&cfg.data_dir);
    let toml_str = match toml::to_string_pretty(cfg) {
        Ok(s) => s,
        Err(e) => { log::warn!("config serialize: {}", e); return; }
    };
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Err(e) = tokio::fs::write(&path, toml_str).await {
        log::warn!("config write {:?}: {}", path, e);
    }
}

/// PD-UI-4: atomically persist `FilamentNodeConfig` to `<data_dir>/config.toml`.
pub async fn save_filament_config(cfg: &FilamentNodeConfig) {
    save_config_to_disk(cfg).await;
}

pub async fn load_config_from_disk(data_dir: &str) -> Option<FilamentNodeConfig> {
    let path = config_path(data_dir);
    let bytes = tokio::fs::read_to_string(&path).await.ok()?;
    toml::from_str(&bytes).ok()
}

// ── Pending TX watch (FI-5) ───────────────────────────────────────────────────

#[derive(Clone, Serialize)]
struct PendingTxMeta {
    txid:         String,
    shard_id:     u16,
    amount_atoms: u64,
    submitted_ms: u64,
    /// True once we see it in wallet history with confirmations == 0.
    seen_in_mempool: bool,
}

// ── F2F inbox ─────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct F2fInboxItem {
    pub from_address: String,
    pub msg_type:     String,
    pub received_ms:  u64,
    pub raw:          Value,
}

/// Subscribe to `ClientEvent::F2fReceived`, decrypt, decode, and append to `f2f_inbox`.
///
/// Shared by the HTTP server (`FilamentAppState`) and the Tauri desktop app.
/// Optional `notifs` / `sse_tx` hooks are used by the HTTP server only.
///
/// Path-2 item 11: inbound `PaymentProof` also calls `InvoiceStore::apply_hints`
/// so hybrid outpoint matching is live (not inbox-only).
pub async fn wire_f2f_inbox_subscription(
    client:    Arc<RwLock<MultiChainClient>>,
    wallet:    Arc<RwLock<FilamentWallet>>,
    f2f_inbox: Arc<Mutex<VecDeque<F2fInboxItem>>>,
    data_dir:  std::path::PathBuf,
    notifs:    Option<Arc<Mutex<NotifRing>>>,
    sse_tx:    Option<broadcast::Sender<String>>,
) {
    let f2f_seckey = wallet.read().await.f2f_seckey().to_owned();
    client.write().await.subscribe(Arc::new(move |event| {
        let ClientEvent::F2fReceived { recipient, payload } = event else { return; };
        use crate::mmr_client::f2f_crypto::f2f_decrypt;
        use crate::mmr_client::f2f::{f2f_decode, F2fMessage};
        let plain = match f2f_decrypt(&f2f_seckey, &payload) {
            Ok(p)  => p,
            Err(e) => {
                log::debug!("F2F decrypt failed for relay to {}: {}", hex::encode(recipient), e);
                return;
            }
        };
        let msg = match f2f_decode(&plain) {
            Ok(m)  => m,
            Err(e) => {
                log::warn!("F2F decode failed: {}", e);
                return;
            }
        };
        let (msg_type, raw) = match &msg {
            F2fMessage::InvoiceRequest(m) => (
                "invoice_request",
                json!({ "msg_id": hex::encode(m.msg_id) }),
            ),
            F2fMessage::PaymentProof(m) => {
                // Receiver side of hybrid matching: stamp outpoint hints before
                // the WatchAddress inclusion notif arrives.
                match crate::mmr_client::invoice::InvoiceStore::open(&data_dir) {
                    Ok(store) => {
                        if let Err(e) = store.apply_hints(
                            &m.invoice_id,
                            m.height_hint,
                            m.idx_hint,
                            m.txid,
                        ) {
                            log::warn!(
                                "F2F PaymentProof apply_hints for {}: {}",
                                hex::encode(m.invoice_id),
                                e
                            );
                        }
                    }
                    Err(e) => log::warn!("F2F PaymentProof: open InvoiceStore: {e}"),
                }
                (
                    "payment_proof",
                    json!({
                        "msg_id":     hex::encode(m.msg_id),
                        "invoice_id": hex::encode(m.invoice_id),
                        "txid":       hex::encode(m.txid),
                        "height_hint": m.height_hint,
                        "idx_hint":    m.idx_hint,
                    }),
                )
            }
            F2fMessage::PaymentAck(m) => (
                "payment_ack",
                json!({ "msg_id": hex::encode(m.msg_id), "invoice_id": hex::encode(m.invoice_id) }),
            ),
            F2fMessage::InvoiceCancel(m) => (
                "invoice_cancel",
                json!({ "msg_id": hex::encode(m.msg_id), "invoice_id": hex::encode(m.invoice_id), "reason": m.reason }),
            ),
            F2fMessage::Reject(m) => (
                "reject",
                json!({ "rejected_msg_id": hex::encode(m.rejected_msg_id), "reason": m.reason.to_string() }),
            ),
        };
        let item = F2fInboxItem {
            from_address: hex::encode(recipient),
            msg_type: msg_type.to_string(),
            received_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            raw,
        };
        if let Ok(mut inbox) = f2f_inbox.lock() {
            if inbox.len() >= 64 { inbox.pop_front(); }
            inbox.push_back(item);
        }
        if let Some(ref n) = notifs {
            if let Ok(mut ring) = n.lock() {
                ring.push("INFO", "f2f", "F2F message received",
                    &format!("Type: {}", msg_type), Some("messages"));
            }
        }
        if let Some(ref tx) = sse_tx {
            let _ = tx.send(json!({ "type": "f2f", "msg_type": msg_type }).to_string());
        }
    })).await;
}

// ── FUD-5: Watch notifications (LC-45..LC-47c) ─────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static HTTP_WATCH_SINCE: AtomicU64 = AtomicU64::new(0);

/// Stable token identifying this Filament instance to Keystone HTTP watch APIs.
pub fn watch_client_token(data_dir: &str, wallet_address: &str) -> Vec<u8> {
    format!("filament-watch:{data_dir}:{wallet_address}").into_bytes()
}

/// POST `/light/watch` to every configured Keystone when `watch_address` is called,
/// and also send ShishaNet `WatchAddress` over P2P when a PeerManager is live.
pub fn wire_watch_sender(
    client: &mut MultiChainClient,
    wallet: &FilamentWallet,
    config: &FilamentNodeConfig,
    p2p: Option<Arc<crate::mmr_client::filament_p2p::FilamentP2p>>,
) {
    let token = watch_client_token(&config.data_dir, wallet.address());
    let token_str = String::from_utf8_lossy(&token).into_owned();
    let endpoints = config.all_keystone_endpoints();
    client.set_watch_address_fn(Arc::new(move |address, shard_id| {
        let body = json!({
            "address_hex": hex::encode(address),
            "shard_id": shard_id,
            "client_token": token_str,
        });
        for ep in &endpoints {
            let url = format!("{ep}/light/watch");
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let url = url.clone();
                let body = body.clone();
                handle.spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&body)
                        .send()
                        .await;
                });
            }
        }
        if let Some(ref p2p) = p2p {
            p2p.send_watch_address(address, shard_id);
        }
    }));
}

/// HTTP-only watch registration (no P2P PeerManager).
pub fn wire_http_watch_sender(
    client: &mut MultiChainClient,
    wallet: &FilamentWallet,
    config: &FilamentNodeConfig,
) {
    wire_watch_sender(client, wallet, config, None);
}

/// Start Filament P2P if enabled and dial targets exist (or always bind when
/// `enable_p2p` so inbound notifs work once peers connect later).
pub async fn maybe_start_filament_p2p(
    config: &FilamentNodeConfig,
    client: Arc<RwLock<MultiChainClient>>,
    peer_cache: Option<&crate::peer_cache::PeerCache>,
) -> Option<Arc<crate::mmr_client::filament_p2p::FilamentP2p>> {
    if !config.enable_p2p {
        return None;
    }
    let listen: std::net::SocketAddr = match config.p2p_listen.parse() {
        Ok(a) => a,
        Err(e) => {
            log::warn!("Filament P2P: bad p2p_listen {:?}: {e}", config.p2p_listen);
            return None;
        }
    };
    let dial = crate::mmr_client::filament_p2p::collect_p2p_dial_addrs(
        &config.manual_peers,
        peer_cache,
        &config.all_keystone_endpoints(),
        config.keystone_p2p_port,
    );
    match crate::mmr_client::filament_p2p::start_filament_p2p(
        &config.network,
        listen,
        dial,
        client,
    )
    .await
    {
        Ok(p2p) => {
            log::info!(
                "Filament P2P: listening on {} (manual+cache+REST-host dial; keystone_p2p_port={})",
                config.p2p_listen,
                config.keystone_p2p_port
            );
            Some(Arc::new(p2p))
        }
        Err(e) => {
            log::warn!("Filament P2P: failed to start: {e}");
            None
        }
    }
}

/// Re-register open invoices with Keystone after restart.
pub async fn restore_invoice_watch_registrations(
    client: &mut MultiChainClient,
    data_dir: &std::path::Path,
) {
    if let Ok(store) = crate::mmr_client::invoice::InvoiceStore::open(data_dir) {
        if let Ok(targets) = store.watch_registration_targets() {
            for (addr, shard_id) in targets {
                client.watch_address(addr, shard_id);
            }
        }
    }
}

async fn advance_watch_invoice_confirmations(
    client: &Arc<RwLock<MultiChainClient>>,
    data_dir: &std::path::Path,
    keystone_endpoints: &[String],
    sse_tx: Option<&broadcast::Sender<String>>,
    confirmation_depth: u32,
) {
    let Ok(store) = crate::mmr_client::invoice::InvoiceStore::open(data_dir) else {
        return;
    };
    let min_depth = if confirmation_depth == 0 {
        crate::mmr_client::watch_notify::MIN_CONFIRMATION_DEPTH
    } else {
        confirmation_depth
    };
    // Prefer open-invoice shards so we advance even when Filament has no local
    // MultiChainClient shard state yet (common for HTTP-only light clients).
    let mut shard_ids: Vec<u16> = store
        .list(None)
        .unwrap_or_default()
        .into_iter()
        .filter(|inv| matches!(inv.state, crate::mmr_client::invoice::InvoiceState::Pending(_)))
        .map(|inv| inv.shard_id)
        .collect();
    shard_ids.sort_unstable();
    shard_ids.dedup();
    if shard_ids.is_empty() {
        let c = client.read().await;
        shard_ids = c.shard_ids().into_iter().map(|id| id as u16).collect();
    }
    let mut tips: Vec<(u16, u32)> = Vec::new();
    {
        let c = client.read().await;
        for &shard_id in &shard_ids {
            if let Ok(st) = c.get_shard_state(shard_id as u32).await {
                tips.push((shard_id, st.tip.height()));
            }
        }
    }
    // Always refresh from Keystone when available — prefer max(local, http)
    // so a stale local tip (e.g. tip 0 after partial sync) cannot stall Confirmed.
    if !keystone_endpoints.is_empty() {
        let http = reqwest::Client::new();
        for &shard_id in &shard_ids {
            let mut http_tip: Option<u32> = None;
            for ep in keystone_endpoints {
                let url = format!("{ep}/shard/{shard_id}/tip");
                let Ok(resp) = http.get(&url).send().await else { continue };
                let Ok(body) = resp.json::<serde_json::Value>().await else { continue };
                if let Some(h) = body.get("height").and_then(|v| v.as_u64()) {
                    http_tip = Some(h as u32);
                    break;
                }
            }
            let Some(http_h) = http_tip else { continue };
            if let Some(slot) = tips.iter_mut().find(|(s, _)| *s == shard_id) {
                if http_h > slot.1 {
                    slot.1 = http_h;
                }
            } else {
                tips.push((shard_id, http_h));
            }
        }
    }
    if tips.is_empty() {
        return;
    }
    for (shard_id, tip) in tips {
        if let Ok(confirmed) = store.advance_pending_confirmations(
            shard_id,
            tip,
            min_depth,
        ) {
            for id in confirmed {
                log::info!("FUD-5: invoice confirmed on shard {shard_id} at tip {tip}");
                if let Some(tx) = sse_tx {
                    let _ = tx.send(json!({
                        "type": "tx_inclusion",
                        "state": "confirmed",
                        "shard_id": shard_id,
                        "invoice_id": crate::mmr_client::invoice::base64url_encode16(&id),
                        "tip_height": tip,
                    }).to_string());
                }
            }
        }
    }
}

/// Poll Keystone `/light/notifications` and dispatch into `MultiChainClient` events.
pub async fn poll_keystone_watch_notifications(
    client: &Arc<RwLock<MultiChainClient>>,
    wallet: &FilamentWallet,
    config: &FilamentNodeConfig,
) {
    let token = watch_client_token(&config.data_dir, wallet.address());
    let token_str = String::from_utf8_lossy(&token);
    let since = HTTP_WATCH_SINCE.load(Ordering::Relaxed);
    let http = reqwest::Client::new();
    let mut max_id = since;

    for ep in config.all_keystone_endpoints() {
        let url = format!("{ep}/light/notifications?since={since}&client_token={token_str}");
        let Ok(resp) = http.get(&url).send().await else { continue };
        let Ok(body) = resp.json::<serde_json::Value>().await else { continue };
        let Some(items) = body.get("notifications").and_then(|v| v.as_array()) else {
            continue;
        };
        if let Some(last) = body.get("last_id").and_then(|v| v.as_u64()) {
            max_id = max_id.max(last);
        }
        for item in items {
            let Some(kind) = item.get("type").and_then(|v| v.as_str()) else { continue };
            match kind {
                "inclusion" => {
                    let shard_id = item.get("shard_id").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let height = item.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let output_idx = item.get("output_idx").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let value_atoms = item.get("value_atoms").and_then(|v| v.as_u64()).unwrap_or(0);
                    let address_hex = item.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let proof_b64 = item.get("mmr_proof_base64").and_then(|v| v.as_str()).unwrap_or("");
                    let Ok(addr_bytes) = hex::decode(address_hex.trim_start_matches("0x")) else { continue };
                    if addr_bytes.len() != 32 { continue }
                    let mut address = [0u8; 32];
                    address.copy_from_slice(&addr_bytes);
                    use base64::Engine as _;
                    let mmr_proof_bytes = base64::engine::general_purpose::STANDARD
                        .decode(proof_b64)
                        .unwrap_or_default();
                    client.read().await.handle_tx_inclusion_notif(
                        shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes,
                    ).await;
                }
                "spent" => {
                    let shard_id = item.get("shard_id").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let spend_height = item.get("spend_height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let output_height = item.get("output_height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let output_idx = item.get("output_idx").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    client.read().await.handle_tx_spent_notif(
                        shard_id, spend_height, output_height, output_idx,
                    ).await;
                }
                "revert" => {
                    let shard_id = item.get("shard_id").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let height = item.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let output_idx = item.get("output_idx").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    client.read().await.handle_tx_revert_notif(shard_id, height, output_idx).await;
                }
                _ => {}
            }
        }
    }
    HTTP_WATCH_SINCE.store(max_id, Ordering::Relaxed);
}

/// Subscribe to watch notification events; verify proofs, update invoice FSM + UTXO map.
///
/// `confirmation_depth` overrides the default [`MIN_CONFIRMATION_DEPTH`] when > 0.
/// `configured_anchor` is used when the local beacon chain is not yet initialized
/// (zeros from [`MultiChainClient::genesis_anchor_hash`]).
pub async fn wire_watch_notify_subscription(
    client:    Arc<RwLock<MultiChainClient>>,
    data_dir:  std::path::PathBuf,
    notifs:    Option<Arc<Mutex<NotifRing>>>,
    sse_tx:    Option<broadcast::Sender<String>>,
    confirmation_depth: u32,
    configured_anchor: Option<[u8; 32]>,
    // Base URLs for Keystone's always-on main REST API (same list used for
    // wallet ops — `FilamentNodeConfig::all_keystone_endpoints()`), used to
    // fetch a shard's own genesis anchor on demand (`fetch_shard_genesis_anchor`).
    // Deliberately *not* `light_client_summary_urls()` — that targets the
    // separate opt-in `mmr_light_client.summary_port` server most real
    // deployments never enable, and `/shard/{id}/genesis-anchor` lives on
    // the main API instead (see that route's own doc comment on the
    // Keystone side).
    keystone_rest_endpoints: Vec<String>,
) {
    let client_for_sub = Arc::clone(&client);
    let min_depth = if confirmation_depth == 0 {
        crate::mmr_client::watch_notify::MIN_CONFIRMATION_DEPTH
    } else {
        confirmation_depth
    };
    // FUD-5: per-shard anchor cache (shard_id -> genesis anchor). A shard's
    // own anchor is dynamic (CV-23) and unrelated to the beacon's — see
    // `fetch_shard_genesis_anchor`'s own doc comment. No production path
    // ever calls `MultiChainClient::add_shard_chain` (it exists only as a
    // doc example / test helper — confirmed by grep), so `get_shard_state`
    // never succeeds for a light client that only tracks the beacon chain;
    // this lightweight cache is what actually makes `TxInclusionNotif`
    // verification work without a full per-shard header sync.
    let shard_anchor_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<u16, [u8; 32]>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let keystone_rest_endpoints = Arc::new(keystone_rest_endpoints);
    client.write().await.subscribe(Arc::new(move |event| {
        let client = Arc::clone(&client_for_sub);
        let data_dir = data_dir.clone();
        let notifs = notifs.clone();
        let sse_tx = sse_tx.clone();
        let configured_anchor = configured_anchor;
        let min_depth = min_depth;
        let shard_anchor_cache = Arc::clone(&shard_anchor_cache);
        let keystone_rest_endpoints = Arc::clone(&keystone_rest_endpoints);

        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => return,
        };

        match event {
            ClientEvent::TxInclusionReceived {
                shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes,
            } => {
                handle.spawn(async move {
                    use crate::mmr_client::watch_notify::{
                        process_inclusion_notif, InclusionApplyResult,
                    };

                    // FUD-5 fix: a shard's own MMR is constructed with its own
                    // dynamic per-shard genesis anchor (CV-23: the beacon chain's
                    // `current_mmr_root` at the shard's activation height), not
                    // the beacon chain's own — structurally unrelated — genesis
                    // anchor. `TxInclusionNotif` is exclusively a shard-watch
                    // message (see P10W-7 / `build_shard_watch_notify`), so the
                    // anchor to verify against must always come from that same
                    // shard's own `ChainState` (its own genesis block's
                    // `prev_mmr_root`, populated in `shard_handler.rs`) —
                    // never `genesis_anchor_hash()`, which is unconditionally
                    // the beacon's. Verifying a shard proof against the beacon's
                    // anchor fails `verify_with_anchor` for every single shard
                    // block, unconditionally, which is exactly what was observed
                    // (100% "invalid MMR proof" rejection rate on shard chains).
                    let local_anchor = client.read().await.get_shard_state(shard_id as u32).await
                        .map(|s| s.anchor_hash()).ok();
                    let anchor = match local_anchor {
                        Some(a) => a,
                        None => {
                            // No full per-shard header sync (`add_shard_chain`
                            // has no production caller) — fall back to a
                            // lightweight, cached fetch of just the anchor via
                            // the light-client HTTP API (`GET
                            // /shard/{id}/genesis-anchor`), rather than
                            // silently reusing the beacon's own — structurally
                            // unrelated — anchor.
                            match fetch_shard_genesis_anchor(
                                &shard_anchor_cache,
                                &keystone_rest_endpoints,
                                shard_id,
                            ).await {
                                Some(a) => a,
                                None => {
                                    log::warn!(
                                        "FUD-5: could not resolve shard {shard_id}'s genesis \
                                         anchor (no local ChainState, no light-client API \
                                         endpoint reachable) — dropping inclusion notif"
                                    );
                                    return;
                                }
                            }
                        }
                    };
                    let _ = configured_anchor; // beacon-only fallback; not applicable to shard proofs
                    let Ok(store) = crate::mmr_client::invoice::InvoiceStore::open(&data_dir) else {
                        return;
                    };
                    // Scope the std MutexGuard so it cannot cross an await (Send).
                    let result = {
                        let c = client.read().await;
                        let mut watch = c.watch_state().lock().unwrap();
                        process_inclusion_notif(
                            &mut watch,
                            &store,
                            shard_id,
                            height,
                            output_idx,
                            value_atoms,
                            address,
                            mmr_proof_bytes,
                            anchor,
                        )
                    };
                    match result {
                        Ok((InclusionApplyResult::Accepted, invoice_id)) => {
                            let msg = format!(
                                "{value_atoms} atoms pending on shard {shard_id} at height {height}"
                            );
                            if let Some(ref n) = notifs {
                                if let Ok(mut ring) = n.lock() {
                                    ring.push("INFO", "wallet", "Payment pending", &msg, Some("wallet"));
                                }
                            }
                            if let Some(ref tx) = sse_tx {
                                let mut payload = json!({
                                    "type": "tx_inclusion",
                                    "state": "pending",
                                    "shard_id": shard_id,
                                    "height": height,
                                    "output_idx": output_idx,
                                    "value_atoms": value_atoms,
                                    "address": hex::encode(address),
                                });
                                if let Some(id) = invoice_id {
                                    payload["invoice_id"] = json!(
                                        crate::mmr_client::invoice::base64url_encode16(&id)
                                    );
                                }
                                let _ = tx.send(payload.to_string());
                            }
                            if let Ok(st) = client.read().await.get_shard_state(shard_id as u32).await {
                                let confirmed = store.advance_pending_confirmations(
                                    shard_id,
                                    st.tip.height(),
                                    min_depth,
                                );
                                if let (Ok(ids), Some(ref tx)) = (confirmed, &sse_tx) {
                                    for id in ids {
                                        let _ = tx.send(json!({
                                            "type": "tx_inclusion",
                                            "state": "confirmed",
                                            "shard_id": shard_id,
                                            "invoice_id": crate::mmr_client::invoice::base64url_encode16(&id),
                                            "tip_height": st.tip.height(),
                                        }).to_string());
                                    }
                                }
                            }
                        }
                        Ok((InclusionApplyResult::InvalidProof, _)) => {
                            log::warn!(
                                "FUD-5: rejected inclusion notif — invalid MMR proof \
                                 (invalidating shard {shard_id} genesis-anchor cache)"
                            );
                            shard_anchor_cache.lock().await.remove(&shard_id);
                        }
                        Err(e) => log::warn!("FUD-5: inclusion processing error: {e}"),
                    }
                });
            }
            ClientEvent::TxSpentReceived {
                shard_id, output_height, output_idx, ..
            } => {
                handle.spawn(async move {
                    if client.read().await.watch_state().lock().unwrap()
                        .apply_spent(shard_id, output_height, output_idx)
                    {
                        log::debug!("FUD-5: UTXO spent ({shard_id}, {output_height}, {output_idx})");
                    }
                });
            }
            ClientEvent::TxRevertReceived { shard_id, height, output_idx } => {
                handle.spawn(async move {
                    if client.read().await.watch_state().lock().unwrap()
                        .apply_revert(shard_id, height, output_idx)
                    {
                        log::debug!("FUD-5: UTXO reverted ({shard_id}, {height}, {output_idx})");
                    }
                    let Ok(store) = crate::mmr_client::invoice::InvoiceStore::open(&data_dir) else {
                        return;
                    };
                    if let Ok(reverted) = store.on_watch_revert(shard_id, height, output_idx) {
                        if !reverted.is_empty() {
                            if let Some(ref n) = notifs {
                                if let Ok(mut ring) = n.lock() {
                                    ring.push(
                                        "WARN", "wallet", "Payment reverted",
                                        "Chain reorg reverted a payment",
                                        Some("wallet"),
                                    );
                                }
                            }
                            if let Some(ref tx) = sse_tx {
                                for id in &reverted {
                                    let _ = tx.send(json!({
                                        "type": "tx_revert",
                                        "shard_id": shard_id,
                                        "height": height,
                                        "output_idx": output_idx,
                                        "invoice_id": crate::mmr_client::invoice::base64url_encode16(id),
                                    }).to_string());
                                }
                            }
                        }
                    }
                });
            }
            _ => {}
        }
    })).await;
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct FilamentAppState {
    pub client:     Arc<RwLock<MultiChainClient>>,
    pub wallet:     Arc<RwLock<FilamentWallet>>,
    pub config:     Arc<RwLock<FilamentNodeConfig>>,
    pub notifs:     Arc<Mutex<NotifRing>>,
    pub logs:       Arc<Mutex<LogRing>>,
    pub sse_tx:     broadcast::Sender<String>,
    pub sync_stats: Arc<RwLock<SyncStats>>,
    pub start_time: Instant,
    /// Inbound decrypted F2F messages (newest last, capped at 64 entries).
    pub f2f_inbox:  Arc<Mutex<VecDeque<F2fInboxItem>>>,
    /// Pending tx watch set (FI-5): maps txid hex → metadata.
    pub pending_txids: Arc<Mutex<HashMap<String, PendingTxMeta>>>,
    /// Optional ShishaNet PeerManager for Path-2 P2P inbound notifs.
    pub p2p: Arc<RwLock<Option<Arc<crate::mmr_client::filament_p2p::FilamentP2p>>>>,
}

impl FilamentAppState {
    pub fn new(client: MultiChainClient, wallet: FilamentWallet, config: FilamentNodeConfig) -> Self {
        let (sse_tx, _) = broadcast::channel(256);
        let mut notifs = NotifRing::new();
        let mut logs = LogRing::new();

        notifs.push("INFO", "system", "Filament started",
            &format!("Light client online — network: {}", config.network), Some("settings"));
        logs.push("INFO", &format!("Filament light client started; network={}", config.network), "filament");
        if let Some(ep) = &config.keystone_endpoint {
            logs.push("INFO", &format!("Keystone delegate: {}", ep), "filament");
        }

        Self {
            client:     Arc::new(RwLock::new(client)),
            wallet:     Arc::new(RwLock::new(wallet)),
            config:     Arc::new(RwLock::new(config)),
            notifs:     Arc::new(Mutex::new(notifs)),
            logs:       Arc::new(Mutex::new(logs)),
            sse_tx,
            sync_stats: Arc::new(RwLock::new(SyncStats::new())),
            start_time: Instant::now(),
            f2f_inbox:  Arc::new(Mutex::new(VecDeque::with_capacity(64))),
            pending_txids: Arc::new(Mutex::new(HashMap::new())),
            p2p: Arc::new(RwLock::new(None)),
        }
    }

    pub fn log(&self, level: &str, msg: &str, src: &str) {
        if let Ok(mut r) = self.logs.lock() { r.push(level, msg, src); }
    }

    pub fn notify(&self, severity: &str, category: &str, title: &str, body: &str, hint: Option<&str>) {
        if let Ok(mut r) = self.notifs.lock() { r.push(severity, category, title, body, hint); }
    }

    /// FI-5: register a txid for mempool/confirmation tracking and emit `tx_pending` SSE.
    pub fn watch_tx(&self, txid: String, shard_id: u16, amount_atoms: u64) {
        if let Ok(mut map) = self.pending_txids.lock() {
            map.insert(txid.clone(), PendingTxMeta {
                txid: txid.clone(),
                shard_id,
                amount_atoms,
                submitted_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                seen_in_mempool: false,
            });
        }
        let _ = self.sse_tx.send(json!({
            "type":         "tx_pending",
            "txid":         txid,
            "shard_id":     shard_id,
            "amount_atoms": amount_atoms,
        }).to_string());
    }

    fn runtime(&self) -> FilamentRuntime {
        FilamentRuntime {
            client: Arc::clone(&self.client),
            wallet: Arc::clone(&self.wallet),
            config: Arc::clone(&self.config),
        }
    }
}

/// Shared client/wallet/config handles for HTTP server and Tauri desktop.
#[derive(Clone)]
pub struct FilamentRuntime {
    pub client: Arc<RwLock<MultiChainClient>>,
    pub wallet: Arc<RwLock<FilamentWallet>>,
    pub config: Arc<RwLock<FilamentNodeConfig>>,
}

impl FilamentRuntime {
    /// 5 s maintenance loop: wallet refresh + chain-summary sync (30 s),
    /// invoice prune (5 min), DNS/cache upkeep (10 min).
    pub async fn run_background_loop(
        self,
        peer_cache: Arc<RwLock<Option<crate::peer_cache::PeerCache>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut wallet_tick: u32 = 0;
        let mut sync_peer_tick: u32 = 0;
        loop {
            interval.tick().await;

            wallet_tick += 1;
            if wallet_tick >= 6 {
                wallet_tick = 0;
                self.refresh_wallet_from_keystone().await.ok();
                let cfg = self.config.read().await.clone();
                let data_dir = std::path::PathBuf::from(&cfg.data_dir);
                let wallet = self.wallet.read().await;
                poll_keystone_watch_notifications(
                    &self.client,
                    &wallet,
                    &cfg,
                ).await;
                drop(wallet);
                advance_watch_invoice_confirmations(
                    &self.client,
                    &data_dir,
                    &cfg.all_keystone_endpoints(),
                    None,
                    cfg.confirmation_depth,
                ).await;
            }

            sync_peer_tick += 1;
            if sync_peer_tick >= 6 {
                sync_peer_tick = 0;
                let cache = peer_cache.read().await;
                let results = self
                    .sync_peer_chain_summaries(cache.as_ref())
                    .await;
                drop(cache);
                for (label, result) in results {
                    log_reconciliation_tracing(&label, result);
                }
            }

            {
                static INVOICE_TICK: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                let t = INVOICE_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if t % 60 == 0 {
                    self.prune_expired_invoices().await;
                }
            }

            {
                static PEER_TICK: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                let t = PEER_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if t % 120 == 0 {
                    let cache_guard = peer_cache.read().await;
                    if let Some(cache) = cache_guard.as_ref() {
                        self.maintain_peer_cache(cache).await;
                    }
                }
            }
        }
    }

    /// MNT-7: refresh wallet state from all configured Keystone REST endpoints.
    pub async fn refresh_wallet_from_keystone(
        &self,
    ) -> Result<crate::mmr_client::filament_wallet::RefreshOutcome, String> {
        self.wallet.write().await.refresh_from_keystone().await
    }

    /// G-4: prune expired invoices using the current beacon tip.
    pub async fn prune_expired_invoices(&self) {
        let tip = {
            let client = self.client.read().await;
            client.get_beacon_state().await.map(|st| st.tip.height()).unwrap_or(0)
        };
        if tip == 0 {
            return;
        }
        let data_dir = std::path::PathBuf::from(&self.config.read().await.data_dir);
        if let Ok(store) = crate::mmr_client::invoice::InvoiceStore::open(&data_dir) {
            match store.prune_expired(tip) {
                Ok(n) if n > 0 => log::info!("Pruned {n} expired invoice(s) at height {tip}"),
                Err(e) => log::warn!("Invoice prune error: {e}"),
                _ => {}
            }
        }
    }

    /// PD-3/PD-4: evict stale cache entries, refresh DNS seeds, preserve manual peers.
    /// Returns the number of new DNS seed peers written to the cache.
    pub async fn maintain_peer_cache(&self, cache: &crate::peer_cache::PeerCache) -> usize {
        let (seeds, manual_peers) = {
            let cfg = self.config.read().await;
            (cfg.dns_seeds.clone(), cfg.manual_peers.clone())
        };
        cache.evict_stale();
        for (host, port) in &manual_peers {
            cache.mark_seen(host, *port);
        }
        let dns_written = crate::dns_seeds::refresh_dns_seeds_into_cache(
            cache,
            &seeds,
            crate::dns_seeds::DEFAULT_DNS_SEED_PORT,
        )
        .await;
        if dns_written > 0 {
            log::info!("DNS seeds: cached {dns_written} peer(s)");
        }
        dns_written
    }

    /// MNT-2/3/4: fetch light-client chain summaries and reconcile trust state.
    /// Returns `(label, result)` pairs for optional HTTP notification wiring.
    pub async fn sync_peer_chain_summaries(
        &self,
        peer_cache: Option<&crate::peer_cache::PeerCache>,
    ) -> Vec<(String, Result<crate::mmr_client::multi_chain_client::ReconciliationOutcome, String>)> {
        use crate::mmr_client::multi_chain_client::{
            PeerCapabilities, PeerChainSummaryResponse, PeerConnection,
        };

        let mut outcomes: Vec<(String, Result<crate::mmr_client::multi_chain_client::ReconciliationOutcome, String>)> =
            Vec::new();

        let urls = self
            .config
            .read()
            .await
            .effective_light_client_summary_urls(peer_cache);
        if urls.is_empty() {
            return outcomes;
        }

        let http = reqwest::Client::new();

        let mut beacon_responses: Vec<PeerChainSummaryResponse> = Vec::new();
        for url in &urls {
            match fetch_chain_summary(&http, &format!("{url}/chain/summary")).await {
                Ok(summary) => {
                    beacon_responses.push(PeerChainSummaryResponse {
                        peer_id: url.clone(),
                        summary,
                    });
                }
                Err(e) => log::warn!("Beacon chain summary from {url}: {e}"),
            }
        }

        if !beacon_responses.is_empty() {
            let mut client = self.client.write().await;
            let known: std::collections::HashSet<String> = client
                .get_peers()
                .await
                .into_iter()
                .map(|p| p.peer_id)
                .collect();
            for resp in &beacon_responses {
                if known.contains(&resp.peer_id) {
                    continue;
                }
                let now_s = now_ms() / 1000;
                let _ = client
                    .add_peer(PeerConnection {
                        peer_id: resp.peer_id.clone(),
                        address: resp.peer_id.clone(),
                        capabilities: PeerCapabilities {
                            beacon_proofs: true,
                            shard_proofs: false,
                            tracked_shards: Vec::new(),
                            fast_sync: false,
                            archive_node: false,
                        },
                        connected_at: now_s,
                        last_seen: now_s,
                    })
                    .await;
            }
            let reconcile_result = client.reconcile_beacon_summaries(beacon_responses).await;
            drop(client);
            outcomes.push(("beacon".into(), reconcile_result));
        }

        let shard_ids = self.client.read().await.shard_ids();
        for shard_id in shard_ids {
            let mut shard_responses: Vec<PeerChainSummaryResponse> = Vec::new();
            for url in &urls {
                let summary_url = format!("{url}/shard/{shard_id}/chain/summary");
                match fetch_chain_summary(&http, &summary_url).await {
                    Ok(summary) => {
                        shard_responses.push(PeerChainSummaryResponse {
                            peer_id: url.clone(),
                            summary,
                        });
                    }
                    Err(e) => {
                        log::warn!("Shard {shard_id} chain summary from {url}: {e}");
                    }
                }
            }
            if shard_responses.is_empty() {
                continue;
            }
            let mut client = self.client.write().await;
            for resp in &shard_responses {
                client.mark_peer_shard_capable(&resp.peer_id, shard_id).await;
            }
            let reconcile_result = client
                .reconcile_shard_summaries(shard_id, shard_responses)
                .await;
            drop(client);
            outcomes.push((format!("shard {shard_id}"), reconcile_result));
        }

        outcomes
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

// ── Chain serialization ───────────────────────────────────────────────────────

fn chain_to_json(state: &ChainState, sync: ChainSyncStatus) -> Value {
    let height = state.tip.height();
    let is_beacon = state.chain_id == 0;
    let shard_idx = state.chain_id.saturating_sub(1);
    let status_str = match &sync {
        ChainSyncStatus::Synced => "synced",
        ChainSyncStatus::Syncing { .. } => "syncing",
        ChainSyncStatus::NotStarted => "bootstrapping",
        ChainSyncStatus::Paused => "paused",
        ChainSyncStatus::Error { .. } => "error",
        ChainSyncStatus::InsufficientPeers { .. } => "insufficient_peers",
    };
    let lag: u32 = if let ChainSyncStatus::Syncing { current_height, target_height, .. } = &sync {
        target_height.saturating_sub(*current_height)
    } else { 0 };
    json!({
        "chain_id": state.chain_id,
        "label": if is_beacon { "Beacon".to_string() } else { format!("Shard {}", shard_idx) },
        "color": if is_beacon { "var(--c-beacon)" } else { "var(--c-shard)" },
        "is_beacon": is_beacon,
        "height": height,
        "tip_hash": hex::encode(state.tip.block_hash()),
        "mmr_root": hex::encode(state.tip.mmr_root_bytes()),
        "chain_weight": state.chain_weight.to_string(),
        "status": status_str,
        "lag_blocks": lag,
        "proof_status": if matches!(sync, ChainSyncStatus::Synced) { "verified" } else { "pending" },
        "last_proof_at": height,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health(State(s): State<FilamentAppState>) -> impl IntoResponse {
    Json(json!({ "status": "healthy", "uptime_secs": s.start_time.elapsed().as_secs() }))
}

async fn wallet_address(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let w = s.wallet.read().await;
    Json(json!({ "address": w.address() }))
}

async fn wallet_balance(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let w = s.wallet.read().await;
    Json(w.balance())
}

async fn wallet_utxos(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let w = s.wallet.read().await;
    Json(w.utxos().to_vec())
}

async fn wallet_history(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let w = s.wallet.read().await;
    Json(w.history().to_vec())
}

#[derive(Deserialize)]
struct FeeEstimateQuery { size_bytes: Option<u64> }

async fn wallet_fee_estimate(
    State(s): State<FilamentAppState>,
    Query(q): Query<FeeEstimateQuery>,
) -> impl IntoResponse {
    let tx_size = q.size_bytes.unwrap_or(250); // typical P2PKH-style tx
    let w = s.wallet.read().await;
    let est = w.estimate_fee(tx_size).await;
    drop(w);
    Json(est)
}

async fn wallet_send(
    State(s): State<FilamentAppState>,
    Json(req): Json<SendRequest>,
) -> axum::response::Response {
    let (shard_id, amount_atoms) = (req.shard_id, req.amount_atoms);
    let wallet = s.wallet.read().await;
    match wallet.submit_transaction(&req).await {
        Ok(resp) => {
            let preview = &req.to[..8.min(req.to.len())];
            s.notify("INFO", "wallet", "Transaction submitted",
                &format!("Sent {} atoms to {}…", amount_atoms, preview), Some("wallet"));
            // FI-5: start watching this txid.
            s.watch_tx(resp.txid.clone(), shard_id, amount_atoms);
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

/// FA-13: Build and sign a transaction with a caller-supplied Schnorr key.
/// Body: { to, amount_atoms, fee_atoms, shard_id, secret_key_hex, current_height }
/// Returns: { txid, witness_hex: ["<hex>", ...], status }
/// The witnesses are the serialised WitnessEntry items for ShardBlockBody::witnesses[].
/// NOTE: This endpoint is intentionally local-only (no auth) — the server
/// must never be exposed to the internet; it is for desktop/CLI use only.
#[derive(Deserialize)]
struct SignRequest {
    to: String,
    amount_atoms: u64,
    fee_atoms: u64,
    #[serde(default)]
    shard_id: u16,
    secret_key_hex: String,
    #[serde(default)]
    current_height: u32,
}

async fn wallet_sign(
    State(s): State<FilamentAppState>,
    Json(req): Json<SignRequest>,
) -> axum::response::Response {
    let send_req = SendRequest {
        to: req.to.clone(),
        amount_atoms: req.amount_atoms,
        fee_atoms: req.fee_atoms,
        shard_id: req.shard_id,
    };

    // Select UTXOs from the wallet's cached UTXO set
    let wallet = s.wallet.read().await;
    let selected = match wallet.select_utxos_for_amount(req.amount_atoms, req.fee_atoms, Some(req.shard_id)) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    };

    match wallet.build_signed_transaction(&send_req, &selected, &req.secret_key_hex, req.current_height) {
        Ok((tx, witnesses)) => {
            // Compute txid as BLAKE3 of serialised inputs+outputs
            let txid = {
                let mut preimage = Vec::new();
                preimage.extend_from_slice(&tx.version.to_le_bytes());
                for inp in &tx.inputs {
                    preimage.extend_from_slice(&inp.prev_height.to_le_bytes());
                    preimage.extend_from_slice(&inp.prev_output_idx.to_le_bytes());
                }
                for out in &tx.outputs {
                    preimage.extend_from_slice(&out.value.to_le_bytes());
                    preimage.extend_from_slice(&out.recipient);
                }
                hex::encode(blake3::hash(&preimage).as_bytes())
            };
            let witness_hex: Vec<String> = witnesses.iter()
                .map(|w| hex::encode(&w.witness_data))
                .collect();
            let preview = &req.to[..8.min(req.to.len())];
            s.notify("INFO", "wallet",
                "Transaction signed",
                &format!("Schnorr-signed tx {} → {}…", &txid[..8], preview),
                Some("wallet"));
            (StatusCode::OK, Json(json!({
                "txid": txid,
                "witness_hex": witness_hex,
                "status": "signed"
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

async fn chain_all(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let client = s.client.read().await;
    let mut chains: Vec<Value> = Vec::new();

    match client.get_beacon_state().await {
        Ok(state) => {
            // MNT-6: trust-aware — a beacon that's otherwise "synced" but
            // backed by too few independent peers shows insufficient_peers.
            let sync = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
            chains.push(chain_to_json(state, sync));
        }
        Err(_) => {
            chains.push(json!({
                "chain_id": 0, "label": "Beacon", "is_beacon": true,
                "height": 0,
                "tip_hash": "0".repeat(64),
                "mmr_root": "0".repeat(64),
                "chain_weight": "0",
                "status": "bootstrapping",
                "lag_blocks": 0, "proof_status": "pending", "last_proof_at": 0,
            }));
        }
    }

    for shard_id in client.shard_ids() {
        if let Ok(state) = client.get_shard_state(shard_id).await {
            // MNT-6 (shard precision fix): per-shard trust, not the
            // blanket-capability beacon check.
            let sync = client.get_trusted_sync_status_for_shard(shard_id).await;
            chains.push(chain_to_json(state, sync));
        }
    }

    Json(chains)
}

async fn chain_beacon(State(s): State<FilamentAppState>) -> axum::response::Response {
    let client = s.client.read().await;
    match client.get_beacon_state().await {
        Ok(state) => {
            let sync = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
            (StatusCode::OK, Json(chain_to_json(state, sync))).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))).into_response(),
    }
}

async fn chain_shard(
    State(s): State<FilamentAppState>,
    Path(shard_id): Path<u32>,
) -> axum::response::Response {
    let client = s.client.read().await;
    match client.get_shard_state(shard_id).await {
        Ok(state) => {
            let sync = client.get_trusted_sync_status_for_shard(shard_id).await;
            (StatusCode::OK, Json(chain_to_json(state, sync))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e }))).into_response(),
    }
}

async fn sync_status(State(s): State<FilamentAppState>) -> impl IntoResponse {
    Json(s.sync_stats.read().await.clone())
}

/// `GET /sync/trust` — MNT-5: surfaces the multi-node trust state
/// `MultiChainClient` tracks (MNT-2/6) for the beacon chain — how many
/// reputable, capability-matching peers are connected, whether that meets
/// the configured minimum, and each qualifying peer's own reputation.
/// See `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
async fn sync_trust(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let snapshot = beacon_peer_trust_snapshot(&*s.client.read().await).await;
    Json(json!({
        "connected": snapshot.connected,
        "required": snapshot.required,
        "trusted": snapshot.trusted,
        "peers": snapshot.peers,
    }))
}

/// `GET /sync/proof-latency` — TS-F-3: recent `verify_with_anchor` samples
/// from Path-2 inclusion processing (microseconds, oldest first, cap 64).
async fn sync_proof_latency(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let samples = {
        let c = s.client.read().await;
        let samples = c.watch_state().lock().unwrap().proof_verify_samples_us();
        samples
    };
    let n = samples.len();
    let last_us = samples.last().copied();
    let avg_us = if n == 0 {
        None
    } else {
        Some(samples.iter().sum::<u64>() / n as u64)
    };
    Json(json!({
        "samples_us": samples,
        "count": n,
        "last_us": last_us,
        "avg_us": avg_us,
    }))
}

/// MNT-5 / PD-INT verification: beacon trust floor snapshot shared by HTTP
/// `GET /sync/trust`, Tauri `get_peer_trust`, and integration tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconPeerTrustSnapshot {
    pub connected: usize,
    pub required: usize,
    pub trusted: bool,
    pub peers: Vec<Value>,
}

pub async fn beacon_peer_trust_snapshot(client: &MultiChainClient) -> BeaconPeerTrustSnapshot {
    let required = client.min_peers_for_trust();
    let top = client.get_top_peers(ChainType::Beacon, usize::MAX).await;
    let all_peers = client.get_peers().await;
    let peers: Vec<Value> = all_peers
        .into_iter()
        .filter(|p| top.contains(&p.peer_id))
        .map(|p| {
            let score = client.peer_score(&p.peer_id);
            let since = now_ms().saturating_sub(p.connected_at.saturating_mul(1000)) / 1000;
            json!({
                "peer_id": p.peer_id,
                "addr": p.address,
                "score": score,
                "beacon_proofs": p.capabilities.beacon_proofs,
                "shard_proofs": p.capabilities.shard_proofs,
                "connected_since_secs": since,
            })
        })
        .collect();
    let connected = peers.len();
    BeaconPeerTrustSnapshot {
        connected,
        required,
        trusted: connected >= required,
        peers,
    }
}

async fn peers_list(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let client = s.client.read().await;
    let raw = client.get_peers().await;
    drop(client);
    let peers: Vec<Value> = raw.into_iter().map(|p| {
        let since = now_ms().saturating_sub(p.connected_at.saturating_mul(1000)) / 1000;
        json!({
            "peer_id": p.peer_id,
            "addr": p.address,
            "latency_ms": 0,
            "version": "Keystone/0.6.0",
            "height": 0,
            "connected_since_secs": since,
            "protocol": "ShishaNet/v7",
            "capabilities": {
                "beacon_proofs": p.capabilities.beacon_proofs,
                "shard_proofs": p.capabilities.shard_proofs,
                "archive": p.capabilities.archive_node,
            },
        })
    }).collect();
    Json(peers)
}

#[derive(Deserialize)]
struct AddPeerRequest { addr: String }

async fn peers_add(
    State(s): State<FilamentAppState>,
    Json(req): Json<AddPeerRequest>,
) -> axum::response::Response {
    use crate::mmr_client::multi_chain_client::{PeerCapabilities, PeerConnection};

    let (host, port) = match parse_host_port(&req.addr) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response();
        }
    };

    if let Ok(cache) = crate::peer_cache::PeerCache::open(std::path::Path::new(
        &s.config.read().await.data_dir,
    )) {
        cache.mark_seen(&host, port);
    }

    {
        let mut cfg = s.config.write().await;
        cfg.upsert_manual_peer(&host, port);
        save_config_to_disk(&cfg).await;
    }

    let now_s = now_ms() / 1000;
    let peer = PeerConnection {
        peer_id: format!("manual-{}", req.addr),
        address: req.addr.clone(),
        capabilities: PeerCapabilities {
            beacon_proofs: true,
            shard_proofs: true,
            tracked_shards: Vec::new(),
            fast_sync: true,
            archive_node: false,
        },
        connected_at: now_s,
        last_seen: now_s,
    };
    let mut client = s.client.write().await;
    match client.add_peer(peer).await {
        Ok(()) => {
            s.log("INFO", &format!("Peer added: {}", req.addr), "peers");
            drop(client);
            // Live dial when Path-2 P2P is already running (startup-only dial
            // would miss peers added after boot).
            if let Some(p2p) = s.p2p.read().await.as_ref() {
                let p2p = Arc::clone(p2p);
                let host = host.clone();
                tokio::spawn(async move {
                    p2p.dial_peer(&host, port).await;
                });
            }
            (StatusCode::OK, Json(json!({ "status": "added", "addr": req.addr }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

async fn forget_manual_peer(s: &FilamentAppState, host: &str, port: u16) {
    if let Ok(cache) = crate::peer_cache::PeerCache::open(std::path::Path::new(
        &s.config.read().await.data_dir,
    )) {
        cache.remove(host, port);
    }
    let mut cfg = s.config.write().await;
    cfg.drop_manual_peer(host, port);
    save_config_to_disk(&cfg).await;
}

async fn peers_remove(
    State(s): State<FilamentAppState>,
    Path(peer_id): Path<String>,
) -> axum::response::Response {
    let address = s
        .client
        .read()
        .await
        .get_peers()
        .await
        .into_iter()
        .find(|p| p.peer_id == peer_id)
        .map(|p| p.address);

    let mut client = s.client.write().await;
    match client.remove_peer(&peer_id).await {
        Ok(()) => {
            drop(client);
            if let Some(addr) = address {
                if let Ok((host, port)) = parse_host_port(&addr) {
                    forget_manual_peer(&s, &host, port).await;
                }
            }
            (StatusCode::OK, Json(json!({ "status": "removed" }))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    txid: String,
    shard_id: u16,
}

async fn proofs_verify(
    State(s): State<FilamentAppState>,
    Json(req): Json<VerifyRequest>,
) -> axum::response::Response {
    let txid_bytes_res: Result<Vec<u8>, _> = hex::decode(&req.txid);
    let txid_arr = match txid_bytes_res {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "txid must be 64 hex chars" }))).into_response(),
    };

    let client = s.client.read().await;
    let t0 = Instant::now();
    let valid = client.verify_transaction_in_shard(req.shard_id as u32, txid_arr, &[], 0)
        .await
        .unwrap_or(false);
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    drop(client);

    let prefix = &req.txid[..8.min(req.txid.len())];
    s.notify(
        if valid { "INFO" } else { "WARN" },
        "proof",
        if valid { "Proof verified" } else { "Proof failed" },
        &format!("TX {}… shard {}", prefix, req.shard_id),
        Some("proofs"),
    );

    (StatusCode::OK, Json(json!({
        "valid": valid,
        "proof_type": "batch",
        "proof_bytes": 173_000,
        "ms": elapsed_ms,
        "txid": req.txid,
        "shard_id": req.shard_id,
    }))).into_response()
}

#[derive(Deserialize)]
struct NotifsQuery {
    since: Option<u64>,
    n: Option<usize>,
    severity: Option<String>,
}

async fn notifications(
    State(s): State<FilamentAppState>,
    Query(q): Query<NotifsQuery>,
) -> impl IntoResponse {
    let ring = s.notifs.lock().unwrap();
    let items = ring.since(q.since.unwrap_or(0), q.n.unwrap_or(50), q.severity.as_deref());
    let critical_unread = ring.critical_count();
    let last_id = ring.next_id.saturating_sub(1);
    drop(ring);
    Json(json!({ "items": items, "critical_unread": critical_unread, "last_id": last_id }))
}

#[derive(Deserialize)]
struct LogsQuery { n: Option<usize> }

async fn logs(State(s): State<FilamentAppState>, Query(q): Query<LogsQuery>) -> impl IntoResponse {
    let ring = s.logs.lock().unwrap();
    let items = ring.recent(q.n.unwrap_or(200));
    drop(ring);
    Json(items)
}

async fn config_get(State(s): State<FilamentAppState>) -> impl IntoResponse {
    Json(s.config.read().await.clone())
}

async fn config_set(
    State(s): State<FilamentAppState>,
    Json(new_cfg): Json<FilamentNodeConfig>,
) -> impl IntoResponse {
    let eps = new_cfg.effective_keystone_endpoints(None);
    save_config_to_disk(&new_cfg).await;
    *s.config.write().await = new_cfg;
    s.wallet.write().await.set_keystone_endpoints(eps);
    s.log("INFO", "Config updated and persisted to disk", "config");
    Json(json!({ "ok": true }))
}

// ── /wallet/broadcast ───────────��─────────────────────────────────────────────

#[derive(Deserialize)]
struct BroadcastRequest {
    tx_hex:   String,
    #[serde(default)]
    shard_id: u16,
}

/// MNT-7: broadcasts to every configured Keystone endpoint for propagation
/// redundancy — a reliability improvement, not a trust check. The first
/// endpoint to accept wins; the rest aren't waited on.
async fn wallet_broadcast(
    State(s): State<FilamentAppState>,
    Json(req): Json<BroadcastRequest>,
) -> axum::response::Response {
    let endpoints = {
        let cfg = s.config.read().await;
        let eps = cfg.effective_keystone_endpoints(None);
        if eps.is_empty() { vec!["http://127.0.0.1:7379".to_string()] } else { eps }
    };

    let body = json!({ "tx_hex": req.tx_hex, "shard_id": req.shard_id });
    let client = reqwest::Client::new();

    let mut last_error: Option<Value> = None;
    for ep in &endpoints {
        let url = format!("{}/wallet/broadcast", ep);
        match client.post(&url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status();
                let json: Value = resp.json().await
                    .unwrap_or_else(|_| json!({ "status": status.as_u16() }));
                if status.is_success() {
                    s.notify("INFO", "wallet", "Transaction broadcast",
                        &format!("tx {}… sent to Keystone ({})", &req.tx_hex[..8.min(req.tx_hex.len())], ep),
                        Some("wallet"));
                    // FI-5: register txid from broadcast response if Keystone returns one.
                    if let Some(txid) = json.get("txid").and_then(|v| v.as_str()) {
                        s.watch_tx(txid.to_string(), req.shard_id, 0);
                    }
                    return (StatusCode::OK, Json(json)).into_response();
                }
                last_error = Some(json);
            }
            Err(e) => {
                last_error = Some(json!({ "endpoint": ep, "error": e.to_string() }));
            }
        }
    }

    (StatusCode::BAD_GATEWAY, Json(json!({ "error": last_error.unwrap_or(json!("all configured endpoints failed")) }))).into_response()
}

// ── Invoice routes ───────────��────────────────────────────────────────────────

use crate::mmr_client::invoice::{
    InvoiceStore, InvoiceState, InvoiceError, decode_hex32, encode_hex32,
    base64url_encode16, base64url_decode16,
};
use crate::mmr_client::shisha_uri::ShishaUri;

/// Shared invoice store — lazily created from `config.data_dir`.
fn invoice_store_path(cfg: &FilamentNodeConfig) -> std::path::PathBuf {
    std::path::PathBuf::from(&cfg.data_dir)
}

#[derive(Deserialize)]
struct CreateInvoiceBody {
    recipient_hex:  String,
    amount_atoms:   u64,
    #[serde(default)]
    shard_id:       u16,
    #[serde(default)]
    memo:           String,
    #[serde(default)]
    expiry_height:  u32,
}

async fn invoice_create(
    State(s): State<FilamentAppState>,
    Json(body): Json<CreateInvoiceBody>,
) -> axum::response::Response {
    let data_dir = invoice_store_path(&*s.config.read().await);
    let store = match InvoiceStore::open(&data_dir) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let recipient = match decode_hex32(&body.recipient_hex) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    match store.create(recipient, body.amount_atoms, body.shard_id, body.memo, body.expiry_height, now_ms()) {
        Ok(id) => {
            // FUD-5: register WatchAddress so Keystone can push inclusion notifs.
            s.client.write().await.watch_address(recipient, body.shard_id);
            (StatusCode::OK, Json(json!({ "invoice_id": base64url_encode16(&id) }))).into_response()
        }
        Err(e) => {
            let code = if matches!(e, InvoiceError::DuplicateUnhintedInFlight { .. }) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (code, Json(json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn invoice_list(State(s): State<FilamentAppState>) -> axum::response::Response {
    let data_dir = invoice_store_path(&*s.config.read().await);
    match InvoiceStore::open(&data_dir) {
        Ok(store) => match store.list(None) {
            Ok(invs) => {
                let uris: Vec<String> = invs.iter().map(|i| ShishaUri::from_invoice(i).encode()).collect();
                (StatusCode::OK, Json(json!(uris))).into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn invoice_get(
    State(s): State<FilamentAppState>,
    Path(b64_id): Path<String>,
) -> axum::response::Response {
    let data_dir = invoice_store_path(&*s.config.read().await);
    let store = match InvoiceStore::open(&data_dir) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let id = match base64url_decode16(&b64_id) {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    match store.load(&id) {
        Ok(inv) => {
            let uri = ShishaUri::from_invoice(&inv).encode();
            (StatusCode::OK, Json(json!({
                "invoice_id": b64_id,
                "uri": uri,
                "state": format!("{:?}", inv.state),
                "amount_atoms": inv.amount_atoms,
                "shard_id": inv.shard_id,
                "memo": inv.memo,
                "height_hint": inv.height_hint,
                "idx_hint": inv.idx_hint,
            }))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn invoice_cancel(
    State(s): State<FilamentAppState>,
    Path(b64_id): Path<String>,
) -> axum::response::Response {
    let data_dir = invoice_store_path(&*s.config.read().await);
    let store = match InvoiceStore::open(&data_dir) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let id = match base64url_decode16(&b64_id) {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    match store.update_state(&id, InvoiceState::Archived) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize)]
struct ApplyHintsBody {
    height_hint: u32,
    idx_hint:    u16,
    txid_hex:    String,
}

/// `POST /invoice/{id}/hints` — stamp outpoint hints (Path-2 hybrid match).
/// Used by F2F PaymentProof receivers via the inbox path, and by API/manual senders.
async fn invoice_apply_hints(
    State(s): State<FilamentAppState>,
    Path(b64_id): Path<String>,
    Json(body): Json<ApplyHintsBody>,
) -> axum::response::Response {
    let data_dir = invoice_store_path(&*s.config.read().await);
    let store = match InvoiceStore::open(&data_dir) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let id = match base64url_decode16(&b64_id) {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let txid = match decode_hex32(&body.txid_hex) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    match store.apply_hints(&id, body.height_hint, body.idx_hint, txid) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize)]
struct ParseUriQuery { uri: String }

async fn invoice_parse(_state: State<FilamentAppState>, Query(q): Query<ParseUriQuery>) -> axum::response::Response {
    match ShishaUri::parse(&q.uri) {
        Ok(p) => (StatusCode::OK, Json(json!({
            "recipient_hex":  encode_hex32(&p.recipient),
            "amount_atoms":   p.amount_atoms,
            "shard_id":       p.shard_id,
            "memo":           p.memo,
            "expiry_height":  p.expiry_height,
            "invoice_id":     p.invoice_id.map(|id| base64url_encode16(&id)),
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

// ── Contact / address-book routes ─────────────────────────────────────────────

use crate::mmr_client::contact_store::{Contact, ContactStore, ContactError};

fn contact_store_open(cfg: &FilamentNodeConfig) -> Result<ContactStore, ContactError> {
    let path = std::path::PathBuf::from(&cfg.data_dir);
    let _ = std::fs::create_dir_all(&path);
    ContactStore::open(&path)
}

#[derive(Deserialize)]
struct AddContactBody {
    name:        String,
    address_hex: String,
    #[serde(default)]
    shard_id:    u16,
    #[serde(default)]
    notes:       String,
}

async fn contacts_list(State(s): State<FilamentAppState>) -> axum::response::Response {
    match contact_store_open(&*s.config.read().await) {
        Ok(store) => match store.list() {
            Ok(cs) => (StatusCode::OK, Json(json!(cs))).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn contacts_add(
    State(s): State<FilamentAppState>,
    Json(b): Json<AddContactBody>,
) -> axum::response::Response {
    match contact_store_open(&*s.config.read().await) {
        Ok(store) => match store.add(b.name, b.address_hex, b.shard_id, b.notes) {
            Ok(c)  => (StatusCode::OK, Json(json!(c))).into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn contacts_get(
    State(s): State<FilamentAppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match contact_store_open(&*s.config.read().await) {
        Ok(store) => match store.find_by_id(&id) {
            Ok(c)  => (StatusCode::OK, Json(json!(c))).into_response(),
            Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn contacts_delete(
    State(s): State<FilamentAppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match contact_store_open(&*s.config.read().await) {
        Ok(store) => match store.delete(&id) {
            Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
            Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateContactBody {
    name:     Option<String>,
    shard_id: Option<u16>,
    notes:    Option<String>,
}

async fn contacts_update(
    State(s): State<FilamentAppState>,
    Path(id): Path<String>,
    Json(b): Json<UpdateContactBody>,
) -> axum::response::Response {
    match contact_store_open(&*s.config.read().await) {
        Ok(store) => match store.update(&id, b.name, b.shard_id, b.notes) {
            Ok(c)  => (StatusCode::OK, Json(json!(c))).into_response(),
            Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn sse_events(
    State(s): State<FilamentAppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let rx = s.sse_tx.subscribe();
    let stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(msg) => Some((Ok(Event::default().data(msg)), rx)),
            Err(broadcast::error::RecvError::Lagged(_)) => {
                Some((Ok(Event::default().comment("lagged")), rx))
            }
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── F2F HTTP handlers (F2F-2 transport) ──────────────────────────────────────

/// GET /f2f/pubkey — returns this wallet's F2F public key (compressed, hex).
async fn f2f_pubkey(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let wallet = s.wallet.read().await;
    Json(json!({ "pubkey": hex::encode(wallet.f2f_pubkey()) }))
}

/// GET /f2f/messages — returns decrypted inbound F2F messages (newest last).
async fn f2f_messages(State(s): State<FilamentAppState>) -> impl IntoResponse {
    let inbox = s.f2f_inbox.lock()
        .map(|g| g.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    Json(json!({ "messages": inbox }))
}

#[derive(Deserialize)]
struct F2fSendBody {
    /// Recipient wallet address (32-byte hex).
    to: String,
    /// Recipient's F2F public key (33-byte compressed secp256k1, hex).
    recipient_pubkey: String,
    /// Raw plaintext F2F message bytes (hex) — pre-encoded by the frontend
    /// using the F2F wire format.
    payload_hex: String,
}

/// POST /f2f/send — encrypt and relay an F2F message to a recipient.
async fn f2f_send(
    State(s): State<FilamentAppState>,
    Json(body): Json<F2fSendBody>,
) -> axum::response::Response {
    let to_bytes = match hex::decode(&body.to).ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid to address" }))).into_response(),
    };
    let recip_pk: [u8; 33] = match hex::decode(&body.recipient_pubkey).ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid recipient_pubkey" }))).into_response(),
    };
    let plaintext = match hex::decode(&body.payload_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid payload_hex" }))).into_response(),
    };

    let encrypted = match crate::mmr_client::f2f_crypto::f2f_encrypt(&recip_pk, &plaintext) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };

    s.client.read().await.send_relay_message(to_bytes, encrypted);
    Json(json!({ "ok": true })).into_response()
}

// ── Background task ───────────────────────────────────────────────────────────

fn sync_status_parts(status: &ChainSyncStatus, tip: u32) -> (String, u32, f64) {
    match status {
        ChainSyncStatus::Synced =>
            ("synced".into(), tip, 1.0),
        ChainSyncStatus::Syncing { current_height, target_height, progress_percent } =>
            ("syncing".into(), *current_height, *progress_percent as f64 / 100.0),
        ChainSyncStatus::NotStarted =>
            ("bootstrapping".into(), 0, 0.0),
        ChainSyncStatus::Paused =>
            ("paused".into(), tip, 0.0),
        ChainSyncStatus::Error { .. } =>
            ("error".into(), tip, 0.0),
        ChainSyncStatus::InsufficientPeers { .. } =>
            ("insufficient_peers".into(), tip, 0.0),
    }
}

/// Live multi-node sync (MNT-2/3/4, wired to a real transport): fetch chain
/// summaries from every configured Keystone's light-client API
/// (`FilamentNodeConfig::light_client_summary_urls`, same host as the
/// wallet-ops endpoints, different port — see that method's doc) and
/// reconcile the responses via `MultiChainClient::reconcile_beacon_summaries`/
/// `reconcile_shard_summaries` — every response is verified independently,
/// only the max independently-verified weight is adopted, and disagreement
/// is surfaced rather than silently resolved. Covers the beacon chain and
/// every shard chain Filament already tracks locally (`client.shard_ids()`)
/// — Keystone's light-client API now serves both
/// (`GET /chain/summary` and `GET /shard/{id}/chain/summary`). See
/// `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
///
/// Each endpoint that answers the beacon fetch is registered as a peer
/// (MNT-2's `get_top_peers` candidate pool) if not already known, using the
/// endpoint URL as `peer_id` — this is what makes `has_min_trusted_peers`/
/// `get_trusted_sync_status` (MNT-6) see real peers instead of staying
/// permanently at zero. Shard fetches reuse the same peer set; they don't
/// register peers on their own (a peer that can't serve shards but can serve
/// beacon is still a real, useful peer).
async fn sync_peer_chain_summaries(s: &FilamentAppState) {
    let cache = crate::peer_cache::PeerCache::open(std::path::Path::new(
        &s.config.read().await.data_dir,
    ))
    .ok();
    let results = s
        .runtime()
        .sync_peer_chain_summaries(cache.as_ref())
        .await;
    for (label, result) in results {
        log_reconciliation_result(s, "sync", &label, result);
    }
}

/// Agree on a shard genesis anchor from one or more Keystone answers.
///
/// All-zero answers are skipped (inactive-shard defense in depth — Keystone
/// already 503s those). Returns `None` when nothing usable remains or when
/// any two non-zero answers disagree — caller must not cache a split vote.
pub(crate) fn consensus_shard_anchor(found: &[[u8; 32]]) -> Option<[u8; 32]> {
    let nonzero: Vec<[u8; 32]> = found
        .iter()
        .copied()
        .filter(|a| *a != [0u8; 32])
        .collect();
    let first = nonzero.first().copied()?;
    if nonzero.iter().any(|a| *a != first) {
        return None;
    }
    Some(first)
}

/// Fetch a shard's genesis MMR anchor from Keystone's main REST API
/// (`GET /shard/{id}/genesis-anchor`). A shard's own genesis anchor is its
/// `current_mmr_root` at the shard's activation height — dynamic and
/// unrelated to the beacon's own genesis anchor.
///
/// Queries every configured Keystone REST endpoint and caches only when
/// every usable (non-zero) answer agrees. A single success is enough to
/// cache. Disagreement is logged and **not** cached, so a later retry can
/// still converge. An `InvalidProof` on a subsequent inclusion invalidates
/// that `shard_id` so a shard reactivation with a new anchor can refetch
/// (P0-3 / P1-6). `keystone_rest_endpoints` is Keystone's always-on main
/// API list (`FilamentNodeConfig::all_keystone_endpoints()`), not the
/// separate opt-in light-client summary API.
async fn fetch_shard_genesis_anchor(
    cache: &tokio::sync::Mutex<std::collections::HashMap<u16, [u8; 32]>>,
    keystone_rest_endpoints: &[String],
    shard_id: u16,
) -> Option<[u8; 32]> {
    if let Some(a) = cache.lock().await.get(&shard_id) {
        return Some(*a);
    }
    let http = reqwest::Client::new();
    let mut found = Vec::new();
    for base in keystone_rest_endpoints {
        let url = format!("{base}/shard/{shard_id}/genesis-anchor");
        let Ok(resp) = http.get(&url).send().await else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<serde_json::Value>().await else { continue };
        let Some(hex_str) = body.get("anchor_hash").and_then(|v| v.as_str()) else { continue };
        let Ok(bytes) = hex::decode(hex_str) else { continue };
        let Ok(anchor): Result<[u8; 32], _> = bytes.try_into() else { continue };
        found.push(anchor);
    }
    match consensus_shard_anchor(&found) {
        Some(a) => {
            cache.lock().await.insert(shard_id, a);
            Some(a)
        }
        None => {
            let nonzero = found.iter().filter(|a| **a != [0u8; 32]).count();
            if nonzero > 1 {
                warn!(
                    "FUD-5: shard {shard_id} genesis-anchor disagreement among \
                     {nonzero} Keystone answers — not caching"
                );
            }
            None
        }
    }
}

/// Fetch and JSON-decode a `MMRChainSummary` from a light-client API URL
/// (beacon or shard). Shared by both fetch loops in `sync_peer_chain_summaries`.
async fn fetch_chain_summary(
    http: &reqwest::Client,
    url: &str,
) -> Result<common_types::common::proofs::MMRChainSummary, String> {
    let resp = http.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json::<common_types::common::proofs::MMRChainSummary>().await
        .map_err(|e| format!("bad response body: {}", e))
}

/// Log a reconciliation outcome via `log` (HTTP server ring + stderr).
fn log_reconciliation_tracing(
    label: &str,
    result: Result<crate::mmr_client::multi_chain_client::ReconciliationOutcome, String>,
) {
    match result {
        Ok(outcome) if outcome.disagreement => {
            log::warn!(
                "{label} chain summary reconciliation: disagreement among {} verified peer(s)",
                outcome.verified_peers.len()
            );
        }
        Ok(outcome) if !outcome.rejected_peers.is_empty() => {
            log::warn!(
                "{label} chain summary reconciliation: rejected invalid response(s) from {:?}",
                outcome.rejected_peers
            );
        }
        Ok(_) => {}
        Err(e) if e != "Beacon chain not initialized" && !e.ends_with("not found") => {
            log::warn!("{label} chain summary reconciliation failed: {e}");
        }
        Err(_) => {}
    }
}

/// HTTP-only: also push to notification ring + log buffer.
fn log_reconciliation_result(
    s: &FilamentAppState,
    category: &str,
    label: &str,
    result: Result<crate::mmr_client::multi_chain_client::ReconciliationOutcome, String>,
) {
    match &result {
        Ok(outcome) if outcome.disagreement => {
            s.notify(
                "WARN",
                category,
                "Keystone peers disagree on chain state",
                &format!(
                    "Configured Keystone light-client endpoints reported different {label} chain weight or tip height — one may be stale, lagging, or withholding a heavier chain."
                ),
                Some(category),
            );
            s.log(
                "WARN",
                &format!(
                    "{label} chain summary reconciliation: disagreement among {} verified peer(s)",
                    outcome.verified_peers.len()
                ),
                category,
            );
        }
        Ok(outcome) if !outcome.rejected_peers.is_empty() => {
            s.log(
                "WARN",
                &format!(
                    "{label} chain summary reconciliation: rejected invalid response(s) from {:?}",
                    outcome.rejected_peers
                ),
                category,
            );
        }
        Ok(_) => {}
        Err(e) if *e != "Beacon chain not initialized" && !e.ends_with("not found") => {
            s.log(
                "WARN",
                &format!("{label} chain summary reconciliation failed: {e}"),
                category,
            );
        }
        Err(_) => {}
    }
}

async fn background_task(s: FilamentAppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut wallet_tick: u32 = 0;
    let mut sync_peer_tick: u32 = 0;
    loop {
        interval.tick().await;

        // Refresh sync stats (FA-11: real per-chain breakdown)
        {
            let client = s.client.read().await;
            // MNT-6: trust-aware status for the beacon headline — "synced"
            // only counts if enough independent peers back it up.
            let beacon_status = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
            let beacon_tip = client.get_beacon_state().await.map(|st| st.tip.height()).unwrap_or(0);

            // Build per-chain entries for the UI chain table
            let mut chain_entries: Vec<ChainSyncEntry> = Vec::new();
            let (b_phase, b_height, b_progress) = sync_status_parts(&beacon_status, beacon_tip);
            chain_entries.push(ChainSyncEntry {
                chain_id: 0,
                label: "Beacon".into(),
                phase: b_phase,
                height: b_height,
                tip: beacon_tip,
                progress: b_progress,
            });
            for shard_id in client.shard_ids() {
                // MNT-6 (shard precision fix): per-shard trust — a shard is
                // only "synced" here if peers proven capable of *this*
                // shard specifically meet the trust floor, which is exactly
                // what F2F shard-transaction confirmation needs to rely on.
                let shard_status = client.get_trusted_sync_status_for_shard(shard_id).await;
                let shard_tip = client.get_shard_state(shard_id).await
                    .map(|st| st.tip.height()).unwrap_or(0);
                let (s_phase, s_height, s_progress) = sync_status_parts(&shard_status, shard_tip);
                chain_entries.push(ChainSyncEntry {
                    chain_id: shard_id + 1,
                    label: format!("Shard {}", shard_id),
                    phase: s_phase,
                    height: s_height,
                    tip: shard_tip,
                    progress: s_progress,
                });
            }
            drop(client);

            let mut stats = s.sync_stats.write().await;
            stats.update(&beacon_status, beacon_tip);
            stats.chains = chain_entries;
        }

        let stats = s.sync_stats.read().await.clone();
        let _ = s.sse_tx.send(json!({ "type": "sync_progress", "data": stats }).to_string());

        // Beacon chain_update
        {
            let client = s.client.read().await;
            if let Ok(state) = client.get_beacon_state().await {
                let sync = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
                let chain = chain_to_json(state, sync);
                drop(client);
                let _ = s.sse_tx.send(json!({ "type": "chain_update", "data": chain }).to_string());
            }
        }

        // Wallet refresh every 30 s
        wallet_tick += 1;
        if wallet_tick >= 6 {
            wallet_tick = 0;
            match s.runtime().refresh_wallet_from_keystone().await {
                Ok(outcome) if outcome.disagreement => {
                    s.notify("WARN", "wallet", "Keystone endpoints disagree",
                        "Configured Keystone endpoints returned different wallet data for this address — one may be stale, lagging, or censoring. Cross-check before trusting a large balance change.",
                        Some("wallet"));
                    s.log("WARN", &format!(
                        "Wallet refresh: {} endpoint(s) responded, disagreement detected",
                        outcome.responded.len()), "wallet");
                }
                Ok(outcome) if !outcome.failed.is_empty() => {
                    s.log("WARN", &format!(
                        "Wallet refresh: {} endpoint(s) failed: {:?}",
                        outcome.failed.len(), outcome.failed), "wallet");
                }
                Ok(_) => {}
                Err(e) => {
                    s.log("WARN", &format!("Wallet refresh: {e}"), "wallet");
                }
            }
            let cfg = s.config.read().await.clone();
            let data_dir = std::path::PathBuf::from(&cfg.data_dir);
            {
                let wallet = s.wallet.read().await;
                poll_keystone_watch_notifications(
                    &s.client,
                    &wallet,
                    &cfg,
                ).await;
            }
            advance_watch_invoice_confirmations(
                &s.client,
                &data_dir,
                &cfg.all_keystone_endpoints(),
                Some(&s.sse_tx),
                cfg.confirmation_depth,
            ).await;
        }

        // Live multi-node chain-summary sync every 30 s (MNT-2/3/4)
        sync_peer_tick += 1;
        if sync_peer_tick >= 6 {
            sync_peer_tick = 0;
            sync_peer_chain_summaries(&s).await;
        }

        // FI-5: mempool watch — compare pending txids against wallet history every tick.
        {
            let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_millis() as u64;
            let stale_ms = 86_400_000u64; // 24 h

            let pending_snap: Vec<PendingTxMeta> = {
                let map = s.pending_txids.lock();
                map.map(|g| g.values().cloned().collect()).unwrap_or_default()
            };

            if !pending_snap.is_empty() {
                let history = s.wallet.read().await.history().to_vec();
                let mut confirmed_ids: Vec<String> = Vec::new();
                let mut mempool_ids:   Vec<String> = Vec::new();
                let mut stale_ids:     Vec<String> = Vec::new();

                for meta in &pending_snap {
                    if now_ms.saturating_sub(meta.submitted_ms) > stale_ms {
                        stale_ids.push(meta.txid.clone());
                        continue;
                    }
                    if let Some(entry) = history.iter().find(|h| h.txid == meta.txid) {
                        if entry.confirmations >= 1 {
                            confirmed_ids.push(meta.txid.clone());
                            s.notify("INFO", "wallet", "Transaction confirmed",
                                &format!("txid {}… confirmed ({} confs)",
                                    &meta.txid[..8.min(meta.txid.len())], entry.confirmations),
                                Some("wallet"));
                            let _ = s.sse_tx.send(json!({
                                "type":          "tx_confirmed",
                                "txid":          meta.txid,
                                "shard_id":      meta.shard_id,
                                "confirmations": entry.confirmations,
                                "height":        entry.height,
                            }).to_string());
                        } else if !meta.seen_in_mempool {
                            mempool_ids.push(meta.txid.clone());
                            let _ = s.sse_tx.send(json!({
                                "type":     "tx_mempool",
                                "txid":     meta.txid,
                                "shard_id": meta.shard_id,
                            }).to_string());
                        }
                    }
                }

                if let Ok(mut map) = s.pending_txids.lock() {
                    for id in &confirmed_ids { map.remove(id); }
                    for id in &stale_ids    { map.remove(id); }
                    for id in &mempool_ids  {
                        if let Some(m) = map.get_mut(id) { m.seen_in_mempool = true; }
                    }
                }
            }
        }

        // G-4: invoice expiry pruning every 5 min (60 ticks × 5 s)
        {
            static INVOICE_TICK: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let t = INVOICE_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if t % 60 == 0 {
                s.runtime().prune_expired_invoices().await;
            }
        }

        // PD-3: DNS seed resolution + PD-4: peer-cache eviction every 10 min
        {
            static PEER_TICK: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let t = PEER_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if t % 120 == 0 {
                let data_dir = s.config.read().await.data_dir.clone();
                if let Ok(cache) =
                    crate::peer_cache::PeerCache::open(std::path::Path::new(&data_dir))
                {
                    let dns_written = s.runtime().maintain_peer_cache(&cache).await;
                    if dns_written > 0 {
                        s.log(
                            "INFO",
                            &format!("DNS seeds: cached {dns_written} peer(s)"),
                            "peers",
                        );
                    }
                }
            }
        }
    }
}

// ── Server startup ─────────────────────────────────────────────────────────────

pub async fn start_server(
    client: MultiChainClient,
    wallet: FilamentWallet,
    config: FilamentNodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = config.port;
    let data_dir = std::path::PathBuf::from(&config.data_dir);

    let mut client = client;
    let mut wallet = wallet;
    apply_startup_peer_discovery(&config, &mut wallet, &mut client).await;

    let state = FilamentAppState::new(client, wallet, config);
    let cfg = state.config.read().await.clone();
    let cache = crate::peer_cache::PeerCache::open(std::path::Path::new(&cfg.data_dir)).ok();
    let p2p = maybe_start_filament_p2p(
        &cfg,
        Arc::clone(&state.client),
        cache.as_ref(),
    )
    .await;
    {
        let mut c = state.client.write().await;
        let wallet = state.wallet.read().await;
        wire_watch_sender(&mut c, &wallet, &cfg, p2p.clone());
        restore_invoice_watch_registrations(&mut c, &data_dir).await;
    }
    *state.p2p.write().await = p2p;

    // FUD-5: watch notifications → invoice FSM (LC-45..LC-47c).
    wire_watch_notify_subscription(
        Arc::clone(&state.client),
        data_dir.clone(),
        Some(Arc::clone(&state.notifs)),
        Some(state.sse_tx.clone()),
        cfg.confirmation_depth,
        cfg.configured_bitcoin_anchor(),
        cfg.all_keystone_endpoints(),
    ).await;

    // F2F-2/3: subscribe to F2fReceived — decrypt + dispatch to inbox
    // (+ Path-2 item 11: PaymentProof → apply_hints).
    wire_f2f_inbox_subscription(
        Arc::clone(&state.client),
        Arc::clone(&state.wallet),
        Arc::clone(&state.f2f_inbox),
        data_dir.clone(),
        Some(Arc::clone(&state.notifs)),
        Some(state.sse_tx.clone()),
    ).await;

    // MNT-4: surface peer disagreement to the UI via SSE.
    {
        let sse_tx = state.sse_tx.clone();
        state.client.write().await.subscribe(Arc::new(move |event| {
            let ClientEvent::PeerDisagreement { chain_type, verified_peers } = event else {
                return;
            };
            let verified: Vec<Value> = verified_peers
                .iter()
                .map(|(id, weight, height)| {
                    json!({
                        "peer_id": id,
                        "weight": weight.to_string(),
                        "height": height,
                    })
                })
                .collect();
            let _ = sse_tx.send(json!({
                "type": "peer_disagreement",
                "chain_type": chain_type,
                "verified_peers": verified,
            }).to_string());
        })).await;
    }

    tokio::spawn(background_task(state.clone()));

    let app = Router::new()
        .route("/health",           get(health))
        .route("/wallet/address",   get(wallet_address))
        .route("/wallet/balance",   get(wallet_balance))
        .route("/wallet/utxos",     get(wallet_utxos))
        .route("/wallet/history",   get(wallet_history))
        .route("/wallet/send",      post(wallet_send))
        .route("/wallet/fee",       get(wallet_fee_estimate))
        .route("/wallet/sign",      post(wallet_sign))
        .route("/chain/all",        get(chain_all))
        .route("/chain/beacon",     get(chain_beacon))
        .route("/chain/shard/{id}", get(chain_shard))
        .route("/sync/status",      get(sync_status))
        .route("/sync/trust",       get(sync_trust))
        .route("/sync/proof-latency", get(sync_proof_latency))
        .route("/peers",            get(peers_list).post(peers_add))
        .route("/peers/{id}",       delete(peers_remove))
        .route("/proofs/verify",    post(proofs_verify))
        .route("/notifications",    get(notifications))
        .route("/logs",             get(logs))
        .route("/config",                  get(config_get).post(config_set))
        .route("/events",                  get(sse_events))
        .route("/wallet/broadcast",        post(wallet_broadcast))
        .route("/invoice/create",          post(invoice_create))
        .route("/invoice/list",            get(invoice_list))
        .route("/invoice/parse",           get(invoice_parse))
        .route("/invoice/{id}",            get(invoice_get))
        .route("/invoice/{id}/cancel",     post(invoice_cancel))
        .route("/invoice/{id}/hints",      post(invoice_apply_hints))
        .route("/contacts",                get(contacts_list).post(contacts_add))
        .route("/contacts/{id}",           get(contacts_get).put(contacts_update).delete(contacts_delete))
        .route("/f2f/pubkey",              get(f2f_pubkey))
        .route("/f2f/messages",            get(f2f_messages))
        .route("/f2f/send",                post(f2f_send))
        .with_state(state)
        .layer(CorsLayer::permissive());

    let addr = format!("127.0.0.1:{}", port);
    info!("Filament HTTP server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod pd_ui_4_tests {
    use super::*;

    #[test]
    fn pd_ui_4_parse_host_port() {
        assert_eq!(
            parse_host_port("peer.example.com:8334").unwrap(),
            ("peer.example.com".into(), 8334)
        );
        assert_eq!(
            parse_host_port(" 127.0.0.1:7379 ").unwrap(),
            ("127.0.0.1".into(), 7379)
        );
        assert!(parse_host_port("no-port").is_err());
        assert!(parse_host_port(":8334").is_err());
    }

    #[test]
    fn pd_ui_4_manual_peer_upsert_drop() {
        let mut cfg = FilamentNodeConfig::default();
        assert!(cfg.upsert_manual_peer("node.test", 8334));
        assert!(!cfg.upsert_manual_peer("node.test", 8334));
        assert_eq!(cfg.manual_peers.len(), 1);
        assert!(cfg.drop_manual_peer("node.test", 8334));
        assert!(cfg.manual_peers.is_empty());
        assert!(!cfg.drop_manual_peer("node.test", 8334));
    }

    #[test]
    fn pd_ui_4_manual_peers_toml_roundtrip() {
        let mut cfg = FilamentNodeConfig::default();
        cfg.upsert_manual_peer("keystone-a.test", 7379);
        cfg.upsert_manual_peer("keystone-b.test", 8334);
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let loaded: FilamentNodeConfig = toml::from_str(&toml_str).unwrap();
        assert!(loaded
            .manual_peers
            .contains(&("keystone-a.test".into(), 7379)));
        assert!(loaded
            .manual_peers
            .contains(&("keystone-b.test".into(), 8334)));
    }

    #[test]
    fn consensus_shard_anchor_empty_is_none() {
        assert_eq!(consensus_shard_anchor(&[]), None);
    }

    #[test]
    fn consensus_shard_anchor_all_zeros_is_none() {
        assert_eq!(consensus_shard_anchor(&[[0u8; 32], [0u8; 32]]), None);
    }

    #[test]
    fn consensus_shard_anchor_one_valid() {
        let a = [0xAAu8; 32];
        assert_eq!(consensus_shard_anchor(&[a]), Some(a));
    }

    #[test]
    fn consensus_shard_anchor_two_same() {
        let a = [0xBBu8; 32];
        assert_eq!(consensus_shard_anchor(&[a, a]), Some(a));
    }

    #[test]
    fn consensus_shard_anchor_two_different_is_none() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_eq!(consensus_shard_anchor(&[a, b]), None);
    }

    #[test]
    fn consensus_shard_anchor_valid_plus_zero_keeps_valid() {
        let a = [0xCCu8; 32];
        assert_eq!(consensus_shard_anchor(&[[0u8; 32], a]), Some(a));
    }
}

/// PD-INT cold-start: two configured Keystones → trust floor 2/2 after one
/// chain-summary sync tick (`FilamentRuntime::sync_peer_chain_summaries`).
///
/// Builds a valid weighted chain summary with `WindowedWeightedMMR` from
/// `common-types` (no monolith / Keystone dependency).
#[cfg(test)]
mod pd_int_cold_start_tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use common_types::common::crypto::weighted_hash::{
        rbits_to_u128_approx, WeightedHash,
    };
    use common_types::common::genesis::genesis_config::BeaconGenesisConfig;
    use common_types::common::proofs::types::{BeaconBlockData, BlockData};
    use common_types::common::proofs::MMRChainSummary;
    use common_types::common::windowed_weighted_mmr::WindowedWeightedMMR;

    const SUMMARY_PORT: u16 = 28_180;

    fn make_beacon_block(
        height: u32,
        leaf: WeightedHash,
        prev_root: WeightedHash,
        current_root: WeightedHash,
        bits: u32,
    ) -> BlockData {
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash: leaf,
            prev_mmr_root: prev_root,
            current_mmr_root: current_root,
            version: 1,
            delta: height as i32,
            difficulty: rbits_to_u128_approx(bits).min(u64::MAX as u128) as u64,
            bits,
            nonce: height as u64,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        })
    }

    /// Build genesis + a heavier tip summary (50 leaves) without Keystone.
    fn build_beacon_summary(block_count: u32) -> (BlockData, MMRChainSummary) {
        assert!(
            block_count > 1,
            "need at least genesis + one block for a heavier summary"
        );

        let genesis_cfg = BeaconGenesisConfig::devnet();
        let anchor = genesis_cfg.bitcoin_anchor_hash;
        let bits = genesis_cfg.bits;
        let mut wmmr = WindowedWeightedMMR::new(&genesis_cfg);

        let mut blocks: Vec<BlockData> = Vec::with_capacity(block_count as usize);
        let mut prev_root = WeightedHash::from_anchor(&anchor);

        for height in 0..block_count {
            let raw = [(height as u8).wrapping_add(1); 32];
            let leaf = WeightedHash::from_leaf_rbits(&raw, bits);
            let (new_root, _weight, _evicted) = wmmr
                .append(leaf)
                .expect("append must succeed");
            blocks.push(make_beacon_block(height, leaf, prev_root, new_root, bits));
            prev_root = new_root;
        }

        let recent_count = 10u32.min(block_count.saturating_sub(1));
        let start = block_count - recent_count;
        // Match Keystone: exclude genesis (height 0) from the batch proof.
        let heights: Vec<u32> = (start.max(1)..block_count).collect();
        let recent_blocks_proof = wmmr
            .prove_batch(&heights)
            .expect("prove_batch must succeed");
        let recent_blocks: Vec<BlockData> = heights
            .iter()
            .map(|&h| blocks[h as usize].clone())
            .collect();

        let tip_block = blocks.last().expect("non-empty").clone();
        let summary = MMRChainSummary {
            tip_block,
            chain_weight: wmmr.canonical_chain_weight(),
            recent_blocks_proof,
            recent_blocks,
        };
        (blocks[0].clone(), summary)
    }

    async fn spawn_summary_server(summary: MMRChainSummary) -> tokio::task::JoinHandle<()> {
        let app = Router::new().route(
            "/chain/summary",
            get(move || {
                let summary = summary.clone();
                async move { Json(summary) }
            }),
        );
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{SUMMARY_PORT}"))
            .await
            .unwrap_or_else(|e| panic!("bind 127.0.0.1:{SUMMARY_PORT}: {e}"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
    }

    #[tokio::test]
    async fn pd_int_cold_start_two_keystones_trust_floor_after_sync_tick() {
        let (genesis, summary) = build_beacon_summary(50);

        let server = spawn_summary_server(summary).await;

        let config = FilamentNodeConfig {
            keystone_rest_endpoints: vec![
                "http://127.0.0.1:7379".into(),
                "http://localhost:7379".into(),
            ],
            light_client_summary_port: SUMMARY_PORT,
            dns_seeds: Vec::new(),
            ..FilamentNodeConfig::default()
        };
        assert_eq!(
            config.light_client_summary_urls(),
            vec![
                format!("http://127.0.0.1:{SUMMARY_PORT}"),
                format!("http://localhost:{SUMMARY_PORT}"),
            ]
        );

        let storage = Box::new(crate::mmr_client::storage::InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);
        client.init_beacon_chain(genesis).await.unwrap();
        assert!(client.get_peers().await.is_empty());

        let runtime = FilamentRuntime {
            client: Arc::new(RwLock::new(client)),
            wallet: Arc::new(RwLock::new(FilamentWallet::new(
                "shisha:test".into(),
                None,
            ))),
            config: Arc::new(RwLock::new(config)),
        };

        let outcomes = runtime.sync_peer_chain_summaries(None).await;
        assert!(
            outcomes.iter().any(|(label, r)| label == "beacon" && r.is_ok()),
            "expected successful beacon reconciliation: {outcomes:?}"
        );

        let trust = beacon_peer_trust_snapshot(&*runtime.client.read().await).await;
        assert_eq!(trust.required, 2, "default min_peers_for_trust");
        assert_eq!(
            trust.connected, 2,
            "expected 2 beacon-capable peers after sync tick; peers={:?}",
            trust.peers
        );
        assert!(trust.trusted, "trust floor should read 2 / 2");

        let status = runtime
            .client
            .read()
            .await
            .get_trusted_sync_status(ChainType::Beacon, 0)
            .await;
        assert!(
            matches!(status, ChainSyncStatus::Synced),
            "trusted sync status should be Synced, got {status:?}"
        );

        server.abort();
    }
}
