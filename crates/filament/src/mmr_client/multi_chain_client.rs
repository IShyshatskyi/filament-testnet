// ============================================================================
// src/mmr_client/multi_chain_client.rs - ENHANCED VERSION
// ============================================================================

//! Multi-Chain Light Client with Enhanced Features
//!
//! Additional fields for production use:
//! - Network peer management
//! - Sync configuration and policies
//! - Performance metrics
//! - Event subscriptions
//! - Cross-chain coordination state

use std::path::Path;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, debug, warn};

use common_types::common::proofs::types::BlockData;
use common_types::common::proofs::MMRChainSummary;
use crate::mmr_client::chain_handler::{ChainState, ChainType};
use crate::mmr_client::beacon_handler::BeaconChainHandler;
use crate::mmr_client::shard_handler::ShardChainHandler;
// use crate::mmr_client::proofs::*;
use crate::mmr_client::storage::LightClientStorage;
use crate::mmr_client::storage::InMemoryStorage;
use crate::mmr_client::light_client_config::FilamentBootstrapConfig;
use crate::mmr_client::proof_selector::DEFAULT_DENSITY_THRESHOLD;
use crate::mmr_client::protocol::LightClientRequest;

/// Multi-chain light client coordinator
pub struct MultiChainClient {
    // ========================================================================
    // CORE CHAIN MANAGEMENT
    // ========================================================================
    
    /// Beacon chain handler (required, single)
    beacon: Option<BeaconChainHandler>,
    
    /// Shard chain handlers (map: shard_id -> handler)
    shards: HashMap<u32, ShardChainHandler>,
    
    /// Storage backend (shared across all chains)
    storage: Box<dyn LightClientStorage>,
    
    // ========================================================================
    // NETWORK AND PEER MANAGEMENT
    // ========================================================================
    
    /// Connected peers (for fetching proofs)
    /// Maps peer_id to peer connection info
    peers: Arc<RwLock<HashMap<String, PeerConnection>>>,
    
    /// Active network requests (for tracking in-flight requests)
    active_requests: Arc<RwLock<HashMap<RequestId, PendingRequest>>>,
    
    /// Peer reputation scores (for selecting best peers)
    peer_reputation: HashMap<String, PeerReputation>,
    
    // ========================================================================
    // SYNC CONFIGURATION AND STATE
    // ========================================================================
    
    /// Sync configuration (how aggressive to sync)
    sync_config: SyncConfiguration,
    
    /// Current sync status per chain (keyed by chain_id)
    /// Beacon: chain_id = 0
    /// Shard: chain_id = shard_id + 1
    sync_status: HashMap<u32, ChainSyncStatus>,
    
    /// Last successful sync timestamp per chain (keyed by chain_id)
    last_sync_times: HashMap<u32, u64>,
    
    /// Sync mode (full, fast, archive)
    sync_mode: SyncMode,
    
    // ========================================================================
    // PERFORMANCE METRICS
    // ========================================================================
    
    /// Performance metrics (for monitoring)
    metrics: Arc<RwLock<ClientMetrics>>,
    
    /// Proof cache (avoid re-verifying same proofs)
    proof_cache: Arc<RwLock<ProofCache>>,
    
    // ========================================================================
    // EVENT SUBSCRIPTIONS AND CALLBACKS
    // ========================================================================
    
    /// Event subscribers (for real-time updates)
    /// Apps/wallets subscribe to new blocks, transactions, etc.
    event_subscribers: Arc<RwLock<Vec<EventSubscriber>>>,
    
    /// Notification channels (tokio mpsc for async notifications)
    notification_tx: Option<tokio::sync::mpsc::UnboundedSender<ClientEvent>>,
    
    // ========================================================================
    // CROSS-CHAIN COORDINATION
    // ========================================================================
    
    /// Cross-chain transaction tracker
    /// Tracks transactions that span multiple shards
    cross_chain_tracker: CrossChainTracker,
    
    /// Pending cross-chain operations
    /// For atomic swaps, transfers, etc.
    pending_cross_chain_ops: HashMap<[u8; 32], CrossChainOperation>,
    
    // ========================================================================
    // CONFIGURATION AND LIMITS
    // ========================================================================
    
    /// Maximum number of shards to track simultaneously
    max_shards: usize,
    
    /// Whether to automatically track new shards discovered on network
    auto_discover_shards: bool,
    
    /// Network ID (mainnet, testnet, devnet)
    network_id: NetworkId,
    
    /// Client version (for protocol compatibility)
    client_version: String,

    /// Loaded configuration (NEW)
    config: Option<FilamentBootstrapConfig>,

    /// Active network name (NEW)
    active_network: Option<String>,

    // ========================================================================
    // ADDRESS WATCH (G-3)
    // ========================================================================

    /// Addresses registered for inclusion-notification watch.
    /// Each entry is (address_bytes, shard_id).
    watch_addresses: Vec<([u8; 32], u16)>,

    /// Optional callback that physically sends a WatchAddress registration
    /// to connected peers.  The app wires this up when it has a live
    /// ShishaNet / P2P connection; leaving it `None` is valid (addresses are
    /// still stored locally and will be re-sent if the callback is set later).
    send_watch_fn: Option<Arc<dyn Fn([u8; 32], u16) + Send + Sync>>,

    // ── F2F relay transport (F2F-2) ──────────────────────────────────────────

    /// Optional callback that physically sends a `RelayMessage` to a full-node
    /// peer over ShishaNet.  Receives `(recipient_address, encrypted_payload)`.
    /// Left `None` until the P2P layer is wired; `send_relay_message` returns
    /// silently when unset.
    relay_send_fn: Option<Arc<dyn Fn([u8; 32], Vec<u8>) + Send + Sync>>,

    /// FUD-5: UTXOs learned from verified watch notifications.
    watch_state: std::sync::Mutex<super::watch_notify::WatchNotifyState>,
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Peer identifier (pubkey or address)
    pub peer_id: String,
    
    /// Network address (IP:port or URL)
    pub address: String,
    
    /// Whether this peer supports extended features
    pub capabilities: PeerCapabilities,
    
    /// Connection timestamp
    pub connected_at: u64,
    
    /// Last activity timestamp
    pub last_seen: u64,
}

/// Peer capabilities
#[derive(Debug, Clone)]
pub struct PeerCapabilities {
    /// Supports beacon chain proofs
    pub beacon_proofs: bool,
    
    /// Supports shard chain proofs
    pub shard_proofs: bool,
    
    /// Which shards this peer tracks
    pub tracked_shards: Vec<u32>,
    
    /// Supports fast sync
    pub fast_sync: bool,
    
    /// Supports archive queries (historical data)
    pub archive_node: bool,
}

/// Request tracking
type RequestId = u64;

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request_id: RequestId,
    pub chain_type: ChainType,
    pub request_type: RequestType,
    pub sent_at: u64,
    pub peer_id: String,
}

#[derive(Debug, Clone)]
pub enum RequestType {
    ChainSummary,
    RangeProof { start: u32, end: u32 },
    BlockHeader { height: u32 },
    Transaction { tx_hash: [u8; 32] },
}

/// Peer reputation scoring
#[derive(Debug, Clone)]
pub struct PeerReputation {
    /// Total requests sent to this peer
    pub requests_sent: u64,
    
    /// Successful responses
    pub successful_responses: u64,
    
    /// Failed requests (timeout, invalid data)
    pub failed_requests: u64,
    
    /// Average response time (milliseconds)
    pub avg_response_time_ms: u64,
    
    /// Reputation score (0-100, higher is better)
    pub score: u8,
}

impl PeerReputation {
    /// Calculate reputation score
    pub fn calculate_score(&mut self) {
        if self.requests_sent == 0 {
            self.score = 50; // Neutral for new peers
            return;
        }
        
        let success_rate = (self.successful_responses as f64) / (self.requests_sent as f64);
        let speed_score = if self.avg_response_time_ms < 100 {
            1.0
        } else if self.avg_response_time_ms < 500 {
            0.8
        } else {
            0.5
        };
        
        self.score = ((success_rate * speed_score * 100.0) as u8).min(100);
    }
}

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfiguration {
    /// How often to poll for updates (seconds)
    pub poll_interval_secs: u64,
    
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    
    /// Batch size for range proofs
    pub range_proof_batch_size: u32,
    
    /// Number of recent blocks to cache
    pub recent_blocks_cache_size: usize,
    
    /// Timeout for requests (seconds)
    pub request_timeout_secs: u64,
    
    /// Whether to verify all proofs (vs trust on first success)
    pub paranoid_mode: bool,

    /// Fill-density threshold for auto-selecting range vs batch proofs.
    ///
    /// Heights with `density >= proof_density_threshold` use `RangeProof`;
    /// sparser sets use `BatchProof`. Used by `request_block_proof()`.
    ///
    /// Default: 0.75 (75 % fill). Tune down toward 0.0 during IBD (dense
    /// sequential sync favours range); tune up toward 1.0 for wallet
    /// spot-checks (sparse sets favour batch).
    ///
    /// Valid range: [0.0, 1.0]; values outside are clamped by `ProofSelector`.
    pub proof_density_threshold: f32,

    /// MNT-6: minimum number of connected, capability-matching, reputable
    /// peers required before a chain-summary reconciliation result (see
    /// `reconcile_beacon_summaries`/`reconcile_shard_summaries`) is trusted
    /// enough to report as "synced". Below this floor,
    /// `get_trusted_sync_status` reports `ChainSyncStatus::InsufficientPeers`
    /// instead of silently falling back to single-peer trust. See
    /// `filament_app/docs/MULTI_NODE_TRUST_PLAN.md` MNT-6.
    pub min_peers_for_trust: usize,

    /// MNT-4: height spread (in blocks) tolerated between independently-
    /// verified peer chain-summary responses before they're flagged as
    /// disagreeing. A small tolerance absorbs ordinary network propagation
    /// lag between honest peers; anything wider than this is a possible
    /// fork, censorship, or eclipse signal worth surfacing rather than
    /// silently resolving by picking the heaviest response and moving on.
    pub disagreement_height_tolerance: u32,
}

impl Default for SyncConfiguration {
    fn default() -> Self {
        Self {
            poll_interval_secs: 10,
            max_concurrent_requests: 10,
            range_proof_batch_size: 100,
            recent_blocks_cache_size: 100,
            request_timeout_secs: 30,
            paranoid_mode: false,
            proof_density_threshold: DEFAULT_DENSITY_THRESHOLD,
            min_peers_for_trust: 2,
            disagreement_height_tolerance: 1,
        }
    }
}

/// Chain sync status
#[derive(Debug, Clone, PartialEq)]
pub enum ChainSyncStatus {
    /// Not yet started
    NotStarted,
    
    /// Currently syncing
    Syncing { 
        current_height: u32, 
        target_height: u32,
        progress_percent: u8,
    },
    
    /// Fully synced
    Synced,
    
    /// Error occurred
    Error { message: String },
    
    /// Syncing paused
    Paused,

    /// MNT-6: the underlying chain state may be current, but fewer than
    /// `SyncConfiguration::min_peers_for_trust` reputable peers are
    /// connected — not enough independent sources to trust a chain-summary
    /// result the way `reconcile_beacon_summaries`/`reconcile_shard_summaries`
    /// are meant to. Distinct from `Synced` so callers don't silently treat
    /// a single-peer connection as fully trusted.
    InsufficientPeers { connected: usize, required: usize },
}

/// Sync mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncMode {
    /// Verify all blocks (slowest, most secure)
    Full,
    
    /// Trust checkpoints, verify recent blocks (fast)
    Fast,
    
    /// Download everything including historical state (slowest)
    Archive,
}

/// Performance metrics
#[derive(Debug, Clone, Default)]
pub struct ClientMetrics {
    /// Total proofs verified
    pub proofs_verified: u64,
    
    /// Total proofs failed
    pub proofs_failed: u64,
    
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
    
    /// Total bytes uploaded
    pub bytes_uploaded: u64,
    
    /// Average proof verification time (microseconds)
    pub avg_proof_verification_us: u64,
    
    /// Number of active subscriptions
    pub active_subscriptions: usize,
    
    /// Uptime (seconds)
    pub uptime_secs: u64,
}

/// Proof cache (avoid re-verification)
#[derive(Debug, Clone)]
pub struct ProofCache {
    /// Cached proofs (hash -> verification result)
    cache: HashMap<[u8; 32], bool>,
    
    /// Maximum cache size
    max_size: usize,
}

impl ProofCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_size,
        }
    }
    
    pub fn check(&self, proof_hash: &[u8; 32]) -> Option<bool> {
        self.cache.get(proof_hash).copied()
    }
    
    pub fn insert(&mut self, proof_hash: [u8; 32], valid: bool) {
        if self.cache.len() >= self.max_size {
            // Remove oldest entry (simplified - could use LRU)
            if let Some(key) = self.cache.keys().next().copied() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(proof_hash, valid);
    }
}

/// Event subscriber
pub type EventSubscriber = Arc<dyn Fn(ClientEvent) + Send + Sync>;

/// Client events
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// New block arrived
    NewBlock {
        chain_type: ChainType,
        height: u32,
        hash: [u8; 32],
    },
    
    /// New transaction detected
    NewTransaction {
        chain_type: ChainType,
        tx_hash: [u8; 32],
        block_height: u32,
    },
    
    /// Sync progress update
    SyncProgress {
        chain_type: ChainType,
        current: u32,
        target: u32,
    },
    
    /// Chain reorganization detected
    Reorg {
        chain_type: ChainType,
        old_tip: u32,
        new_tip: u32,
        fork_point: u32,
    },
    
    /// Error occurred
    Error {
        chain_type: ChainType,
        message: String,
    },

    /// Inbound F2F relay message arrived (F2F-2).
    /// `payload` is the raw (still encrypted) relay payload; the server
    /// layer decrypts it and dispatches based on the F2F message type.
    F2fReceived {
        recipient: [u8; 32],
        payload:   Vec<u8>,
    },

    /// Transaction inclusion notification from the full node (G-3 / FUD-5).
    /// Emitted when a `ShishaMessage::TxInclusionNotif` arrives from a peer.
    TxInclusionReceived {
        shard_id:       u16,
        height:         u32,
        output_idx:     u16,
        value_atoms:    u64,
        address:        [u8; 32],
        mmr_proof_bytes: Vec<u8>,
    },

    /// FUD-5: watched UTXO spent in a later block.
    TxSpentReceived {
        shard_id:       u16,
        spend_height:   u32,
        output_height:  u32,
        output_idx:     u16,
    },

    /// FUD-5: prior inclusion reverted by chain reorg.
    TxRevertReceived {
        shard_id:   u16,
        height:     u32,
        output_idx: u16,
    },

    /// MNT-4: two or more independently-verified peers disagree on chain
    /// state by more than `SyncConfiguration::disagreement_height_tolerance`
    /// during a multi-peer reconciliation round (see
    /// `reconcile_beacon_summaries`/`reconcile_shard_summaries`). A possible
    /// fork, censorship, or eclipse condition — surfaced rather than
    /// silently resolved by adopting the heaviest response and moving on.
    /// `verified_peers` lists every peer whose response passed independent
    /// proof verification, as `(peer_id, chain_weight, tip_height)`; peers
    /// whose response failed verification are never included here (see
    /// `ReconciliationOutcome::rejected_peers`).
    PeerDisagreement {
        chain_type:     ChainType,
        verified_peers: Vec<(String, u128, u32)>,
    },
}

/// Cross-chain transaction tracker
#[derive(Debug, Clone)]
pub struct CrossChainTracker {
    /// Active cross-chain transactions
    active_txs: HashMap<[u8; 32], CrossChainTxInfo>,
}

#[derive(Debug, Clone)]
pub struct CrossChainTxInfo {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    
    /// Source shard
    pub source_shard: u32,
    
    /// Destination shard
    pub dest_shard: u32,
    
    /// Status
    pub status: CrossChainStatus,
    
    /// Timestamps
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrossChainStatus {
    /// Initiated on source chain
    Initiated,
    
    /// Confirmed on source chain
    SourceConfirmed,
    
    /// Pending on destination chain
    DestinationPending,
    
    /// Completed on both chains
    Completed,
    
    /// Failed
    Failed { reason: String },
}

/// Cross-chain operation (atomic swap, transfer, etc.)
#[derive(Debug, Clone)]
pub struct CrossChainOperation {
    pub operation_id: [u8; 32],
    pub operation_type: CrossChainOperationType,
    pub status: CrossChainStatus,
}

#[derive(Debug, Clone)]
pub enum CrossChainOperationType {
    Transfer {
        from_shard: u32,
        to_shard: u32,
        amount: u64,
    },
    AtomicSwap {
        shard_a: u32,
        shard_b: u32,
        amount_a: u64,
        amount_b: u64,
    },
}

/// Network identifier
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl MultiChainClient {
    /// Create new multi-chain client with full configuration
    pub fn new_with_config(
        storage: Box<dyn LightClientStorage>,
        sync_config: SyncConfiguration,
        network_id: NetworkId,
        max_shards: usize,
    ) -> Self {
        info!("Creating multi-chain light client");
        info!("  Network: {:?}", network_id);
        info!("  Max shards: {}", max_shards);
        info!("  Sync mode: Fast");
        
        let (notification_tx, _notification_rx) = tokio::sync::mpsc::unbounded_channel();
        
        Self {
            beacon: None,
            shards: HashMap::new(),
            storage,
            peers: Arc::new(RwLock::new(HashMap::new())),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            peer_reputation: HashMap::new(),
            sync_config,
            sync_status: HashMap::new(),
            last_sync_times: HashMap::new(),
            sync_mode: SyncMode::Fast,
            metrics: Arc::new(RwLock::new(ClientMetrics::default())),
            proof_cache: Arc::new(RwLock::new(ProofCache::new(1000))),
            event_subscribers: Arc::new(RwLock::new(Vec::new())),
            notification_tx: Some(notification_tx),
            cross_chain_tracker: CrossChainTracker {
                active_txs: HashMap::new(),
            },
            pending_cross_chain_ops: HashMap::new(),
            max_shards,
            auto_discover_shards: false,
            network_id,
            client_version: "0.1.0".to_string(),
            config: None,
            active_network: None,
            watch_addresses: Vec::new(),
            send_watch_fn: None,
            relay_send_fn: None,
            watch_state: std::sync::Mutex::new(super::watch_notify::WatchNotifyState::default()),
        }
    }
    
    /// Create simple client (basic configuration)
    pub fn new(storage: Box<dyn LightClientStorage>) -> Self {
        Self::new_with_config(
            storage,
            SyncConfiguration::default(),
            NetworkId::Mainnet,
            100, // max 100 shards
        )
    }

    /// Load client from configuration file
    pub fn from_config_file<P: AsRef<Path>>(
        config_path: P,
        storage: Box<dyn LightClientStorage>,
    ) -> Result<Self, String> {
        use crate::mmr_client::light_client_config::FilamentBootstrapConfig;

        info!("Loading light client config from {:?}", config_path.as_ref());

        let config = FilamentBootstrapConfig::from_file(config_path)?;
        Self::from_config(config, storage)
    }

    /// Build a client from an already-loaded [`FilamentBootstrapConfig`] (no file I/O).
    ///
    /// Shared by `from_config_file` and the standalone `filament` binary, which embeds
    /// `light_client_config.toml` at compile time via `FilamentBootstrapConfig::from_embedded()`
    /// rather than reading a runtime path.
    pub fn from_config(
        config: crate::mmr_client::light_client_config::FilamentBootstrapConfig,
        storage: Box<dyn LightClientStorage>,
    ) -> Result<Self, String> {
        // Determine which network is configured
        let network_id = Self::detect_network_id(&config)?;

        info!("Detected network: {:?}", network_id);

        // Convert SyncSettings to SyncConfiguration
        let sync_config = SyncConfiguration {
            poll_interval_secs: config.sync.poll_interval_secs,
            max_concurrent_requests: config.sync.max_concurrent_requests,
            range_proof_batch_size: config.sync.range_proof_batch_size,
            recent_blocks_cache_size: config.sync.recent_blocks_cache_size,
            request_timeout_secs: config.sync.request_timeout_secs,
            paranoid_mode: config.sync.paranoid_mode,
            // SyncSettings has no proof_density_threshold; use the tuned default.
            ..SyncConfiguration::default()
        };

        // Create client
        let mut client = Self::new_with_config(
            storage,
            sync_config,  // ← Now correct type
            network_id,
            100, // max_shards
        );

        // Store config
        client.config = Some(config);

        Ok(client)
    }
    
    /// Initialize from selected network
    pub async fn init_from_network(
        &mut self,
        network: &str,
    ) -> Result<(), String> {
        let config = self.config.as_ref()
            .ok_or("Config not loaded")?;
        
        info!("Initializing {} network", network);
        
        // Get network genesis info
        let network_info = config.get_network(network)
            .ok_or(format!("Unknown network: {}", network))?;
        
        // Create genesis block directly as BlockData (no intermediate conversion)
        let genesis = network_info.to_block_data()?;
        let genesis_height = genesis.height();

        // Initialize beacon chain
        self.init_beacon_chain(genesis).await?;

        // Store active network
        self.active_network = Some(network.to_string());

        info!("Initialized {} network at height {}", network, genesis_height);
        
        Ok(())
    }
    
    fn detect_network_id(config: &FilamentBootstrapConfig) -> Result<NetworkId, String> {
        let zero = "0000000000000000000000000000000000000000000000000000000000000000";
        
        if config.mainnet.genesis_hash != zero {
            Ok(NetworkId::Mainnet)
        } else if config.testnet1.genesis_hash != zero {
            Ok(NetworkId::Testnet)
        } else if config.testnet_stress.genesis_hash != zero {
            // No dedicated NetworkId variant for testnet-stress; this field is
            // cosmetic (logged once, never read elsewhere — see multi_chain_client.rs
            // module notes), so Testnet is the closest real match.
            Ok(NetworkId::Testnet)
        } else if config.devnet.genesis_hash != zero {
            Ok(NetworkId::Devnet)
        } else {
            Err("No valid genesis in config".to_string())
        }
    }
    
    // ========================================================================
    // PEER MANAGEMENT
    // ========================================================================
    
    /// Add a peer connection
    pub async fn add_peer(&mut self, peer: PeerConnection) -> Result<(), String> {
        info!("Adding peer: {} ({})", peer.peer_id, peer.address);
        
        if !peer.capabilities.beacon_proofs && !peer.capabilities.shard_proofs {
            return Err("Peer has no useful capabilities".to_string());
        }
        
        let peer_id = peer.peer_id.clone();
        self.peers.write().await.insert(peer_id.clone(), peer);
        
        // Initialize reputation
        self.peer_reputation.insert(peer_id, PeerReputation {
            requests_sent: 0,
            successful_responses: 0,
            failed_requests: 0,
            avg_response_time_ms: 0,
            score: 50, // Neutral starting score
        });
        
        Ok(())
    }
    
    /// Remove a peer
    pub async fn get_peers(&self) -> Vec<PeerConnection> {
        self.peers.read().await.values().cloned().collect()
    }

    pub fn shard_ids(&self) -> Vec<u32> {
        self.shards.keys().copied().collect()
    }

    // ── G-3: address watch ────────────────────────────────────────────────────

    /// Install the callback that physically sends `WatchAddress` over the
    /// ShishaNet / P2P transport.  Call this once the P2P layer is live.
    /// Already-registered addresses are replayed immediately.
    pub fn set_watch_address_fn(&mut self, f: Arc<dyn Fn([u8; 32], u16) + Send + Sync>) {
        for &(addr, shard_id) in &self.watch_addresses {
            f(addr, shard_id);
        }
        self.send_watch_fn = Some(f);
    }

    /// Register `address` for inclusion-notification watch on `shard_id`.
    /// Stores the entry locally and, if a send callback is wired, dispatches
    /// `WatchAddress` to all connected peers immediately.
    pub fn watch_address(&mut self, address: [u8; 32], shard_id: u16) {
        if self.watch_addresses.iter().any(|&(a, s)| a == address && s == shard_id) {
            return; // already registered
        }
        self.watch_addresses.push((address, shard_id));
        if let Some(ref f) = self.send_watch_fn {
            f(address, shard_id);
        }
        debug!("G-3: watching address {} on shard {}", hex::encode(address), shard_id);
    }

    /// Snapshot of locally registered watches (for P2P reconnect replay).
    pub fn watch_addresses(&self) -> Vec<([u8; 32], u16)> {
        self.watch_addresses.clone()
    }

    /// Re-dispatch every registered watch through the send callback (if wired).
    ///
    /// Keystone clears `WatchAddress` on disconnect (`watch_unregister_all`);
    /// call this after a peer (re)connects so subscriptions are restored.
    pub fn resend_watch_addresses(&self) {
        let Some(ref f) = self.send_watch_fn else {
            return;
        };
        for &(addr, shard_id) in &self.watch_addresses {
            f(addr, shard_id);
        }
    }

    /// Called by the inbound ShishaNet message handler when a
    /// `TxInclusionNotif` message arrives from a full-node peer.
    /// Emits `ClientEvent::TxInclusionReceived` to all subscribers.
    pub async fn handle_tx_inclusion_notif(
        &self,
        shard_id:        u16,
        height:          u32,
        output_idx:      u16,
        value_atoms:     u64,
        address:         [u8; 32],
        mmr_proof_bytes: Vec<u8>,
    ) {
        self.emit_event(ClientEvent::TxInclusionReceived {
            shard_id,
            height,
            output_idx,
            value_atoms,
            address,
            mmr_proof_bytes,
        }).await;
    }

    /// FUD-5: `TxSpentNotif` from a full-node peer or HTTP poll.
    pub async fn handle_tx_spent_notif(
        &self,
        shard_id:       u16,
        spend_height:   u32,
        output_height:  u32,
        output_idx:     u16,
    ) {
        self.emit_event(ClientEvent::TxSpentReceived {
            shard_id,
            spend_height,
            output_height,
            output_idx,
        }).await;
    }

    /// FUD-5: `TxRevertNotif` from a full-node peer or HTTP poll.
    pub async fn handle_tx_revert_notif(
        &self,
        shard_id:   u16,
        height:     u32,
        output_idx: u16,
    ) {
        self.emit_event(ClientEvent::TxRevertReceived {
            shard_id,
            height,
            output_idx,
        }).await;
    }

    /// Bitcoin anchor hash used to verify inclusion proofs (beacon genesis).
    pub async fn genesis_anchor_hash(&self) -> [u8; 32] {
        self.get_beacon_state()
            .await
            .map(|s| s.anchor_hash())
            .unwrap_or([0u8; 32])
    }

    pub fn watch_state(&self) -> &std::sync::Mutex<super::watch_notify::WatchNotifyState> {
        &self.watch_state
    }

    // ── F2F relay transport (F2F-2) ────────────────────────────────────────────

    /// Install the callback that physically sends a `RelayMessage` over
    /// ShishaNet.  Call once the P2P layer is live.
    pub fn set_relay_send_fn(&mut self, f: Arc<dyn Fn([u8; 32], Vec<u8>) + Send + Sync>) {
        self.relay_send_fn = Some(f);
    }

    /// Send an encrypted F2F payload to `recipient` via the relay.
    /// No-op (with a debug log) when the relay send callback is not wired.
    pub fn send_relay_message(&self, recipient: [u8; 32], encrypted_payload: Vec<u8>) {
        match &self.relay_send_fn {
            Some(f) => {
                debug!("F2F: relaying {} bytes to {}", encrypted_payload.len(), hex::encode(recipient));
                f(recipient, encrypted_payload);
            }
            None => {
                debug!("F2F: relay_send_fn not wired — dropping outbound relay message");
            }
        }
    }

    /// Called by the inbound ShishaNet message handler when a
    /// `RelayMessageBundle` entry arrives for our address.
    /// Emits `ClientEvent::F2fReceived`; the server layer decrypts + dispatches.
    pub async fn handle_relay_message(&self, recipient: [u8; 32], payload: Vec<u8>) {
        self.emit_event(ClientEvent::F2fReceived { recipient, payload }).await;
    }

    pub async fn remove_peer(&mut self, peer_id: &str) -> Result<(), String> {
        info!("Removing peer: {}", peer_id);
        
        if self.peers.write().await.remove(peer_id).is_none() {
            return Err(format!("Peer {} not found", peer_id));
        }
        
        self.peer_reputation.remove(peer_id);
        Ok(())
    }
    
    /// Get best peer for a request
    pub async fn get_best_peer(&self, chain_type: ChainType) -> Option<String> {
        let peers = self.peers.read().await;
        
        // Filter peers that can serve this chain type
        let mut candidates: Vec<(&String, &PeerConnection)> = peers
            .iter()
            .filter(|(_, peer)| {
                match chain_type {
                    ChainType::Beacon => peer.capabilities.beacon_proofs,
                    ChainType::Shard => {
                        // For shard queries, peer must support shard proofs
                        // Specific shard filtering will be done elsewhere
                        peer.capabilities.shard_proofs
                    }
                }
            })
            .collect();
        
        if candidates.is_empty() {
            return None;
        }
        
        // Sort by reputation score
        candidates.sort_by_key(|(peer_id, _)| {
            self.peer_reputation
                .get(*peer_id)
                .map(|r| r.score)
                .unwrap_or(50)
        });
        
        // Return best peer
        candidates.last().map(|(peer_id, _)| (*peer_id).clone())
    }

    /// MNT-2: select up to `k` connected, capability-matching peers for a
    /// chain-summary fan-out request, sorted by reputation (highest first).
    /// This is the multi-peer replacement for `get_best_peer`'s single-peer
    /// pick — callers fetch a `MMRChainSummary` from every returned peer
    /// (the actual network I/O is the caller's responsibility, same as
    /// `send_watch_fn`/`relay_send_fn` elsewhere in this type) and pass the
    /// responses to `reconcile_beacon_summaries`/`reconcile_shard_summaries`.
    /// See `filament_app/docs/MULTI_NODE_TRUST_PLAN.md` MNT-2.
    pub async fn get_top_peers(&self, chain_type: ChainType, k: usize) -> Vec<String> {
        let peers = self.peers.read().await;

        let mut candidates: Vec<(&String, &PeerConnection)> = peers
            .iter()
            .filter(|(_, peer)| match chain_type {
                ChainType::Beacon => peer.capabilities.beacon_proofs,
                ChainType::Shard => peer.capabilities.shard_proofs,
            })
            .collect();

        // Highest reputation first.
        candidates.sort_by_key(|(peer_id, _)| {
            std::cmp::Reverse(
                self.peer_reputation
                    .get(*peer_id)
                    .map(|r| r.score)
                    .unwrap_or(50),
            )
        });

        candidates
            .into_iter()
            .take(k)
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// MNT-6 (shard precision fix, Jul 14, 2026): like `get_top_peers`, but
    /// for `ChainType::Shard` additionally requires the peer's own
    /// `capabilities.tracked_shards` to include `shard_id`. `get_top_peers`
    /// only checks the blanket `shard_proofs` flag, so a peer that has only
    /// ever proven capable of shard 0 would incorrectly count toward shard
    /// 1's trust floor too — this is the fix. `chain_type` is accepted (not
    /// just assumed `Shard`) so callers can reuse this for `Beacon` with the
    /// same result `get_top_peers` would give (shard_id is ignored there).
    pub async fn get_top_peers_for_shard(&self, chain_type: ChainType, shard_id: u32, k: usize) -> Vec<String> {
        let peers = self.peers.read().await;

        let mut candidates: Vec<(&String, &PeerConnection)> = peers
            .iter()
            .filter(|(_, peer)| match chain_type {
                ChainType::Beacon => peer.capabilities.beacon_proofs,
                ChainType::Shard => peer.capabilities.shard_proofs
                    && peer.capabilities.tracked_shards.contains(&shard_id),
            })
            .collect();

        candidates.sort_by_key(|(peer_id, _)| {
            std::cmp::Reverse(
                self.peer_reputation
                    .get(*peer_id)
                    .map(|r| r.score)
                    .unwrap_or(50),
            )
        });

        candidates
            .into_iter()
            .take(k)
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// MNT-6 (shard precision fix): mark an already-registered peer as
    /// having proven capable of serving `shard_id` — call this only after a
    /// real, successful chain-summary fetch for that specific shard, not as
    /// a blanket assumption. Upgrades `capabilities.shard_proofs`/
    /// `tracked_shards` in place; deliberately does **not** touch
    /// `peer_reputation` (unlike re-`add_peer`-ing the same `peer_id`, which
    /// would reset its score to neutral — this method exists specifically to
    /// avoid that). No-op if `peer_id` isn't already registered.
    pub async fn mark_peer_shard_capable(&self, peer_id: &str, shard_id: u32) {
        if let Some(peer) = self.peers.write().await.get_mut(peer_id) {
            peer.capabilities.shard_proofs = true;
            if !peer.capabilities.tracked_shards.contains(&shard_id) {
                peer.capabilities.tracked_shards.push(shard_id);
            }
        }
    }

    /// MNT-6: whether enough connected, capability-matching, reputable peers
    /// exist to trust a chain-summary reconciliation result for `chain_type`
    /// — i.e. at least `SyncConfiguration::min_peers_for_trust`. Callers
    /// should treat a "false" result as "insufficient peers for trust", not
    /// silently fall back to whatever single peer happens to be connected.
    /// See `get_trusted_sync_status` for the `ChainSyncStatus`-level view of
    /// this same check.
    pub async fn has_min_trusted_peers(&self, chain_type: ChainType) -> bool {
        self.get_top_peers(chain_type, usize::MAX).await.len()
            >= self.sync_config.min_peers_for_trust
    }

    /// MNT-5: the configured minimum peer count from
    /// `SyncConfiguration::min_peers_for_trust`, for UI surfacing (e.g. "2 of
    /// 2 required peers connected").
    pub fn min_peers_for_trust(&self) -> usize {
        self.sync_config.min_peers_for_trust
    }

    /// MNT-5: a connected peer's reputation score (0-100), or the neutral
    /// default (50) if unknown. For UI surfacing alongside `get_top_peers`.
    pub fn peer_score(&self, peer_id: &str) -> u8 {
        self.peer_reputation.get(peer_id).map(|r| r.score).unwrap_or(50)
    }

    /// MNT-6: sync status for `chain_id`, downgraded to
    /// `ChainSyncStatus::InsufficientPeers` when fewer than
    /// `SyncConfiguration::min_peers_for_trust` reputable peers are
    /// connected for `chain_type` — even if the underlying chain state
    /// itself is otherwise `Synced`. Prefer this over the plain
    /// `get_sync_status`/`get_beacon_sync_status`/`get_shard_sync_status`
    /// accessors wherever a caller is about to *trust* the result (as
    /// opposed to just displaying raw chain height for its own sake).
    ///
    /// **For `chain_type == ChainType::Shard`, this counts peers with the
    /// blanket `shard_proofs` capability, not peers proven capable of this
    /// *specific* shard.** Beacon-appropriate (there's only one beacon), but
    /// imprecise for shards — a peer that's only ever served shard 0 would
    /// count toward shard 1's trust floor too. Use
    /// `get_trusted_sync_status_for_shard` for shard callers instead; kept
    /// here unchanged (rather than made shard-aware) so existing beacon call
    /// sites and the MNT-9 tests referencing this exact signature don't need
    /// to change.
    pub async fn get_trusted_sync_status(
        &self,
        chain_type: ChainType,
        chain_id: u32,
    ) -> ChainSyncStatus {
        let status = self.get_sync_status(chain_id);
        if matches!(status, ChainSyncStatus::Synced) {
            let connected = self.get_top_peers(chain_type, usize::MAX).await.len();
            let required = self.sync_config.min_peers_for_trust;
            if connected < required {
                return ChainSyncStatus::InsufficientPeers { connected, required };
            }
        }
        status
    }

    /// MNT-6 (shard precision fix, Jul 14, 2026): shard-aware counterpart to
    /// `get_trusted_sync_status` — counts only peers proven capable of
    /// *this* `shard_id` specifically (via `get_top_peers_for_shard`,
    /// checking `tracked_shards`), not any peer with the blanket
    /// `shard_proofs` flag set. This is what makes a shard's
    /// `ChainSyncStatus::InsufficientPeers` (or lack of it) actually mean
    /// "N independent peers have confirmed *this* shard's chain state" —
    /// the property F2F shard-transaction confirmation depends on.
    pub async fn get_trusted_sync_status_for_shard(&self, shard_id: u32) -> ChainSyncStatus {
        let chain_id = shard_id + 1;
        let status = self.get_sync_status(chain_id);
        if matches!(status, ChainSyncStatus::Synced) {
            let connected = self.get_top_peers_for_shard(ChainType::Shard, shard_id, usize::MAX).await.len();
            let required = self.sync_config.min_peers_for_trust;
            if connected < required {
                return ChainSyncStatus::InsufficientPeers { connected, required };
            }
        }
        status
    }

    // ========================================================================
    // METRICS AND MONITORING
    // ========================================================================
    
    /// Get current metrics
    pub async fn get_metrics(&self) -> ClientMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Subscribe to events
    pub async fn subscribe(&self, subscriber: EventSubscriber) {
        self.event_subscribers.write().await.push(subscriber);
        
        let mut metrics = self.metrics.write().await;
        metrics.active_subscriptions += 1;
    }
    
    /// Emit event to all subscribers
    async fn emit_event(&self, event: ClientEvent) {
        let subscribers = self.event_subscribers.read().await;
        
        for subscriber in subscribers.iter() {
            subscriber(event.clone());
        }
        
        // Also send to notification channel
        if let Some(ref tx) = self.notification_tx {
            let _ = tx.send(event);
        }
    }
    
    // ========================================================================
    // SYNC STATUS
    // ========================================================================
    
    /// Get sync status for a chain
    pub fn get_sync_status(&self, chain_id: u32) -> ChainSyncStatus {
        self.sync_status
            .get(&chain_id)
            .cloned()
            .unwrap_or(ChainSyncStatus::NotStarted)
    }
    
    /// Update sync status
    fn update_sync_status(&mut self, chain_id: u32, status: ChainSyncStatus) {
        self.sync_status.insert(chain_id, status);
    }
    
    // ========================================================================
    // CROSS-CHAIN OPERATIONS
    // ========================================================================
    
    /// Track a cross-chain transaction
    pub fn track_cross_chain_tx(
        &mut self,
        tx_hash: [u8; 32],
        source_shard: u32,
        dest_shard: u32,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let info = CrossChainTxInfo {
            tx_hash,
            source_shard,
            dest_shard,
            status: CrossChainStatus::Initiated,
            created_at: now,
            updated_at: now,
        };
        
        self.cross_chain_tracker.active_txs.insert(tx_hash, info);
        
        debug!(
            "Tracking cross-chain tx {} from shard {} to shard {}",
            hex::encode(tx_hash),
            source_shard,
            dest_shard
        );
    }
    
    /// Get cross-chain transaction status
    pub fn get_cross_chain_status(&self, tx_hash: &[u8; 32]) -> Option<CrossChainStatus> {
        self.cross_chain_tracker
            .active_txs
            .get(tx_hash)
            .map(|info| info.status.clone())
    }

    /// Initialize beacon chain with genesis block
    pub async fn init_beacon_chain(
        &mut self,
        genesis: BlockData,
    ) -> Result<(), String> {
        if self.beacon.is_some() {
            return Err("Beacon chain already initialized".to_string());
        }

        // Create storage for beacon chain
        let beacon_storage = Box::new(InMemoryStorage::new());

        // Create beacon handler
        let handler = BeaconChainHandler::new(genesis, beacon_storage);

        self.beacon = Some(handler);
        self.sync_status.insert(0, ChainSyncStatus::Synced);

        info!("Beacon chain initialized");
        Ok(())
    }

    /// Add a new shard chain
    ///
    /// # Arguments
    /// * `shard_id` - Shard identifier (0-based)
    /// * `genesis` - Genesis block (as BlockData)
    /// * `hash_sorting_bits` - Number of hash-sorting bits for shard ID derivation
    pub async fn add_shard_chain(
        &mut self,
        shard_id: u32,
        genesis: BlockData,
        hash_sorting_bits: u32,
    ) -> Result<(), String> {
        if self.shards.contains_key(&shard_id) {
            return Err(format!("Shard {} already exists", shard_id));
        }

        if self.shards.len() >= self.max_shards {
            return Err(format!(
                "Maximum shard limit reached ({})",
                self.max_shards
            ));
        }

        // Create storage for shard chain
        let shard_storage = Box::new(InMemoryStorage::new());

        // Create shard handler with shard ID validation
        let handler = ShardChainHandler::new(shard_id, genesis, shard_storage, hash_sorting_bits);

        self.shards.insert(shard_id, handler);
        // Use chain_id as key instead of ChainType
        let chain_id = shard_id + 1;
        self.sync_status.insert(
            chain_id,
            ChainSyncStatus::Synced
        );

        info!("Shard {} added", shard_id);
        Ok(())
    }

    // ── Proof request helpers (v0.2.3) ───────────────────────────────────────

    /// Build a `GetBlockProof` request using this client's configured
    /// `proof_density_threshold`.
    ///
    /// The server will automatically select `RangeProof` or `BatchProof`
    /// depending on how dense the height set is.  The response will be either
    /// `LightClientResponse::RangeProof` or `LightClientResponse::BatchProof`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let req = client.request_block_proof(vec![100, 101, 102, 150], 500);
    /// let resp = network.send(best_peer, req).await?;
    /// match resp {
    ///     LightClientResponse::RangeProof(proof) => { /* verify */ }
    ///     LightClientResponse::BatchProof(proof) => { /* verify */ }
    ///     LightClientResponse::Error { message } => { /* handle */ }
    ///     _ => {}
    /// }
    /// ```
    pub fn request_block_proof(
        &self,
        heights:       Vec<u32>,
        target_height: u32,
    ) -> LightClientRequest {
        LightClientRequest::GetBlockProof {
            heights,
            target_height,
            density_threshold: self.sync_config.proof_density_threshold,
        }
    }

    /// Get beacon sync status
    pub fn get_beacon_sync_status(&self) -> ChainSyncStatus {
        self.get_sync_status(0)
    }
    
    /// Get shard sync status
    pub fn get_shard_sync_status(&self, shard_id: u32) -> ChainSyncStatus {
        self.get_sync_status(shard_id + 1)
    }
    
    /// Update beacon sync status
    fn update_beacon_sync_status(&mut self, status: ChainSyncStatus) {
        self.update_sync_status(0, status);
    }
    
    /// Update shard sync status
    fn update_shard_sync_status(&mut self, shard_id: u32, status: ChainSyncStatus) {
        self.update_sync_status(shard_id + 1, status);
    }
    
    /// Get beacon chain state
    pub async fn get_beacon_state(&self) -> Result<&ChainState, String> {
        self.beacon
            .as_ref()
            .map(|h| h.state())
            .ok_or_else(|| "Beacon chain not initialized".to_string())
    }
    
    /// Get shard chain state
    pub async fn get_shard_state(&self, shard_id: u32) -> Result<&ChainState, String> {
        self.shards
            .get(&shard_id)
            .map(|h| h.state())
            .ok_or_else(|| format!("Shard {} not found", shard_id))
    }
    
    /// Verify transaction in a specific shard
    pub async fn verify_transaction_in_shard(
        &self,
        shard_id: u32,
        tx_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        block_height: u32,
    ) -> Result<bool, String> {
        let handler = self.shards
            .get(&shard_id)
            .ok_or_else(|| format!("Shard {} not found", shard_id))?;
        
        handler.verify_transaction_in_block(tx_hash, merkle_proof, block_height)
    }

    // ========================================================================
    // MULTI-PEER RECONCILIATION (MNT-2/3/4, MULTI_NODE_TRUST_PLAN.md)
    // ========================================================================

    /// MNT-2/3/4: reconcile chain-summary responses fetched from multiple
    /// peers (see `get_top_peers`) for the beacon chain. Every response is
    /// verified independently — a response can't be trusted just because it
    /// answered first or claims a higher weight than another — and only the
    /// max independently-verified weight is adopted. Disagreement among
    /// verified peers is reported via `ClientEvent::PeerDisagreement` rather
    /// than silently resolved.
    ///
    /// The actual network fetch (issuing `GetChainWeightProof`/chain-summary
    /// requests to each peer from `get_top_peers` and collecting the
    /// responses) is the caller's responsibility — this type has no network
    /// I/O of its own, the same division of labour as `send_watch_fn`/
    /// `relay_send_fn` elsewhere in this struct.
    pub async fn reconcile_beacon_summaries(
        &mut self,
        responses: Vec<PeerChainSummaryResponse>,
    ) -> Result<ReconciliationOutcome, String> {
        let disagreement_height_tolerance = self.sync_config.disagreement_height_tolerance;
        let handler = self
            .beacon
            .as_mut()
            .ok_or_else(|| "Beacon chain not initialized".to_string())?;

        let mut rejected_peers: Vec<String> = Vec::new();
        let mut candidates: Vec<(String, u128, u32, MMRChainSummary)> = Vec::new();
        for resp in responses {
            match handler.verify_chain_summary(&resp.summary) {
                Ok(()) => {
                    let weight = resp.summary.chain_weight;
                    let height = resp.summary.tip_block.height();
                    candidates.push((resp.peer_id, weight, height, resp.summary));
                }
                Err(e) => {
                    warn!("Rejecting beacon chain summary from peer {}: {}", resp.peer_id, e);
                    rejected_peers.push(resp.peer_id);
                }
            }
        }

        let verified_peers: Vec<(String, u128, u32)> = candidates
            .iter()
            .map(|(id, w, h, _)| (id.clone(), *w, *h))
            .collect();
        let (winner_idx, disagreement) =
            pick_reconciliation_winner(&verified_peers, disagreement_height_tolerance);

        let (winning_peer, applied) = match winner_idx {
            Some(i) => {
                let (peer_id, _, _, summary) = candidates
                    .into_iter()
                    .nth(i)
                    .expect("winner_idx is a valid index into this same Vec");
                let applied = handler.sync_from_summary(summary).await?;
                (Some(peer_id), applied)
            }
            None => (None, false),
        };

        let outcome = ReconciliationOutcome {
            winning_peer,
            applied,
            rejected_peers,
            disagreement,
            verified_peers,
        };

        if outcome.disagreement {
            self.emit_event(ClientEvent::PeerDisagreement {
                chain_type: ChainType::Beacon,
                verified_peers: outcome.verified_peers.clone(),
            })
            .await;
        }

        Ok(outcome)
    }

    /// MNT-2/3/4: same as `reconcile_beacon_summaries`, for a specific shard
    /// chain. `ShardChainHandler::sync_from_summary` is synchronous (unlike
    /// the beacon handler's), so this doesn't `.await` the apply step.
    pub async fn reconcile_shard_summaries(
        &mut self,
        shard_id: u32,
        responses: Vec<PeerChainSummaryResponse>,
    ) -> Result<ReconciliationOutcome, String> {
        let disagreement_height_tolerance = self.sync_config.disagreement_height_tolerance;
        let handler = self
            .shards
            .get_mut(&shard_id)
            .ok_or_else(|| format!("Shard {} not found", shard_id))?;

        let mut rejected_peers: Vec<String> = Vec::new();
        let mut candidates: Vec<(String, u128, u32, MMRChainSummary)> = Vec::new();
        for resp in responses {
            match handler.verify_chain_summary(&resp.summary) {
                Ok(()) => {
                    let weight = resp.summary.chain_weight;
                    let height = resp.summary.tip_block.height();
                    candidates.push((resp.peer_id, weight, height, resp.summary));
                }
                Err(e) => {
                    warn!("Rejecting shard {} chain summary from peer {}: {}", shard_id, resp.peer_id, e);
                    rejected_peers.push(resp.peer_id);
                }
            }
        }

        let verified_peers: Vec<(String, u128, u32)> = candidates
            .iter()
            .map(|(id, w, h, _)| (id.clone(), *w, *h))
            .collect();
        let (winner_idx, disagreement) =
            pick_reconciliation_winner(&verified_peers, disagreement_height_tolerance);

        let (winning_peer, applied) = match winner_idx {
            Some(i) => {
                let (peer_id, _, _, summary) = candidates
                    .into_iter()
                    .nth(i)
                    .expect("winner_idx is a valid index into this same Vec");
                let applied = handler.sync_from_summary(summary)?;
                (Some(peer_id), applied)
            }
            None => (None, false),
        };

        let outcome = ReconciliationOutcome {
            winning_peer,
            applied,
            rejected_peers,
            disagreement,
            verified_peers,
        };

        if outcome.disagreement {
            self.emit_event(ClientEvent::PeerDisagreement {
                chain_type: ChainType::Shard,
                verified_peers: outcome.verified_peers.clone(),
            })
            .await;
        }

        Ok(outcome)
    }
}

/// MNT-3/4: shared reconciliation math over already independently-verified
/// candidates — picks the max-weight winner (by index into the input slice)
/// and flags disagreement when verified peers' tip heights spread wider than
/// `disagreement_height_tolerance`. Kept as a free function (not a method on
/// `BeaconChainHandler`/`ShardChainHandler`, which don't share a common
/// verify+apply trait since one's `sync_from_summary` is `async` and the
/// other isn't) so the actual weight/disagreement logic has exactly one
/// implementation shared by both `reconcile_beacon_summaries` and
/// `reconcile_shard_summaries`.
fn pick_reconciliation_winner(
    verified_peers: &[(String, u128, u32)],
    disagreement_height_tolerance: u32,
) -> (Option<usize>, bool) {
    let disagreement = match (
        verified_peers.iter().map(|(_, _, h)| *h).min(),
        verified_peers.iter().map(|(_, _, h)| *h).max(),
    ) {
        (Some(min_h), Some(max_h)) => max_h.saturating_sub(min_h) > disagreement_height_tolerance,
        _ => false,
    };

    let winner_idx = verified_peers
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, weight, _))| *weight)
        .map(|(i, _)| i);

    (winner_idx, disagreement)
}

/// One peer's chain-summary response, paired with the peer that sent it
/// (MNT-2/3). Callers build these from `get_top_peers` + their own network
/// fetch, then pass them to `reconcile_beacon_summaries`/
/// `reconcile_shard_summaries`.
#[derive(Debug, Clone)]
pub struct PeerChainSummaryResponse {
    pub peer_id: String,
    pub summary: MMRChainSummary,
}

/// Outcome of reconciling chain-summary responses from multiple peers
/// (MNT-3/4). See `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationOutcome {
    /// Peer whose independently-verified summary had the max chain weight
    /// and was adopted, if any response verified.
    pub winning_peer: Option<String>,
    /// Whether the local chain tip actually advanced as a result (mirrors
    /// `ChainHandler::apply_chain_summary`'s return value — `false` when the
    /// winning summary wasn't actually heavier than the existing local tip).
    pub applied: bool,
    /// Peer ids whose response failed independent proof verification — never
    /// counted toward quorum or trusted, regardless of claimed weight.
    pub rejected_peers: Vec<String>,
    /// True when independently-verified peers' reported tip heights spread
    /// wider than `SyncConfiguration::disagreement_height_tolerance` — a
    /// possible fork, censorship, or eclipse signal. See
    /// `ClientEvent::PeerDisagreement`, emitted whenever this is true.
    pub disagreement: bool,
    /// Every peer whose response passed independent proof verification, as
    /// `(peer_id, chain_weight, tip_height)` — includes the winner and any
    /// non-winning-but-still-valid responses, excludes `rejected_peers`.
    pub verified_peers: Vec<(String, u128, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::proofs::types::BeaconBlockData;
    use common_types::common::proofs::{MMRChainSummary, WeightedMMRBatchProof};

    /// Helper to create a test beacon BlockData
    fn test_beacon_block(height: u32, block_hash: [u8; 32], prev_mmr_root: [u8; 32], difficulty: u64) -> BlockData {
        let bitcoin_anchor_timestamp = 1_704_067_200u64;
        let test_timestamp = 1000000u64;
        let delta = ((test_timestamp as i64 - bitcoin_anchor_timestamp as i64) * 256) as i32;
        BlockData::Beacon(BeaconBlockData {
            height,
            block_hash: block_hash.into(),
            prev_mmr_root: prev_mmr_root.into(),
            current_mmr_root: block_hash.into(),
            version: 1,
            delta,
            difficulty,
            bits: 0x1d00ffff,
            nonce: 0,
            tx_merkle_root: [0u8; 32],
            merged_mining_root: [0u8; 32],
        })
    }

    #[test]
    fn test_shard_handler_creation() {
        let genesis = test_beacon_block(0, [2u8; 32], [0u8; 32], 500);

        let storage = Box::new(InMemoryStorage::new());
        let handler = ShardChainHandler::new(42, genesis, storage, 8);

        assert_eq!(handler.shard_id(), 42);
        assert_eq!(handler.state().height(), 0);
    }

    #[test]
    fn test_beacon_handler_creation() {
        let genesis = test_beacon_block(0, [1u8; 32], [0u8; 32], 1000);

        let storage = Box::new(InMemoryStorage::new());
        let handler = BeaconChainHandler::new(genesis, storage);

        assert_eq!(handler.current_epoch(), 0);
        assert_eq!(handler.state().height(), 0);
    }

    // ── MNT-9: multi-node trust reconciliation tests ──────────────────────
    // See filament_app/docs/MULTI_NODE_TRUST_PLAN.md.

    fn test_peer(id: &str) -> PeerConnection {
        PeerConnection {
            peer_id: id.to_string(),
            address: format!("{id}.example:7380"),
            capabilities: PeerCapabilities {
                beacon_proofs: true,
                shard_proofs: true,
                tracked_shards: vec![],
                fast_sync: false,
                archive_node: false,
            },
            connected_at: 0,
            last_seen: 0,
        }
    }

    #[test]
    fn mnt9_pick_reconciliation_winner_picks_max_weight() {
        let peers = vec![
            ("peer-a".to_string(), 100u128, 10u32),
            ("peer-b".to_string(), 300u128, 10u32),
            ("peer-c".to_string(), 200u128, 10u32),
        ];
        let (winner_idx, disagreement) = pick_reconciliation_winner(&peers, 1);
        assert_eq!(winner_idx, Some(1)); // peer-b has the max weight
        assert!(!disagreement); // all report the same height
    }

    #[test]
    fn mnt9_pick_reconciliation_winner_flags_disagreement_beyond_tolerance() {
        let peers = vec![
            ("peer-a".to_string(), 100u128, 10u32),
            ("peer-b".to_string(), 300u128, 25u32), // far ahead — possible eclipse/censorship signal
        ];
        let (winner_idx, disagreement) = pick_reconciliation_winner(&peers, 1);
        assert_eq!(winner_idx, Some(1));
        assert!(disagreement);
    }

    #[test]
    fn mnt9_pick_reconciliation_winner_tolerates_small_propagation_lag() {
        let peers = vec![
            ("peer-a".to_string(), 100u128, 10u32),
            ("peer-b".to_string(), 300u128, 11u32), // one block ahead, within default tolerance
        ];
        let (winner_idx, disagreement) = pick_reconciliation_winner(&peers, 1);
        assert_eq!(winner_idx, Some(1));
        assert!(!disagreement);
    }

    #[test]
    fn mnt9_pick_reconciliation_winner_empty_input() {
        let peers: Vec<(String, u128, u32)> = vec![];
        let (winner_idx, disagreement) = pick_reconciliation_winner(&peers, 1);
        assert_eq!(winner_idx, None);
        assert!(!disagreement);
    }

    #[tokio::test]
    async fn mnt9_get_top_peers_sorts_by_reputation_and_respects_k() {
        let storage = Box::new(InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);

        for (id, score) in [("low", 10u8), ("high", 90u8), ("mid", 50u8)] {
            client.add_peer(test_peer(id)).await.unwrap();
            client.peer_reputation.get_mut(id).unwrap().score = score;
        }

        let top2 = client.get_top_peers(ChainType::Beacon, 2).await;
        assert_eq!(top2, vec!["high".to_string(), "mid".to_string()]);
    }

    #[tokio::test]
    async fn mnt9_has_min_trusted_peers_respects_configured_floor() {
        let storage = Box::new(InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);
        assert_eq!(client.sync_config.min_peers_for_trust, 2); // default

        assert!(!client.has_min_trusted_peers(ChainType::Beacon).await);

        client.add_peer(test_peer("only-one")).await.unwrap();
        assert!(!client.has_min_trusted_peers(ChainType::Beacon).await);

        client.add_peer(test_peer("second")).await.unwrap();
        assert!(client.has_min_trusted_peers(ChainType::Beacon).await);
    }

    #[tokio::test]
    async fn mnt9_get_trusted_sync_status_downgrades_below_floor() {
        let genesis = test_beacon_block(0, [3u8; 32], [0u8; 32], 100);
        let storage = Box::new(InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);
        client.init_beacon_chain(genesis).await.unwrap();

        // Chain state is "Synced", but zero peers connected — must not be
        // reported as trustworthy synced (this is the exact gap MNT-6
        // closes: a lone connected peer, or none at all, was previously
        // indistinguishable from a properly cross-checked sync).
        let status = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
        assert!(matches!(
            status,
            ChainSyncStatus::InsufficientPeers { connected: 0, required: 2 }
        ));

        client.add_peer(test_peer("a")).await.unwrap();
        client.add_peer(test_peer("b")).await.unwrap();
        let status = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
        assert!(matches!(status, ChainSyncStatus::Synced));
    }

    #[tokio::test]
    async fn mnt9_reconcile_beacon_summaries_rejects_invalid_proof() {
        let genesis = test_beacon_block(0, [9u8; 32], [0u8; 32], 100);
        let storage = Box::new(InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);
        client.init_beacon_chain(genesis).await.unwrap();

        // A peer claiming a huge weight with an empty/default proof — proof
        // verification must reject this regardless of the claimed weight;
        // a response can't be trusted just because it claims to be heavier.
        let bad_summary = MMRChainSummary {
            tip_block: test_beacon_block(1, [1u8; 32], [0u8; 32], 200),
            chain_weight: 999_999,
            recent_blocks_proof: WeightedMMRBatchProof::default(),
            recent_blocks: vec![],
        };

        let responses = vec![PeerChainSummaryResponse {
            peer_id: "lying-peer".to_string(),
            summary: bad_summary,
        }];

        let outcome = client.reconcile_beacon_summaries(responses).await.unwrap();
        assert!(outcome.winning_peer.is_none());
        assert!(!outcome.applied);
        assert_eq!(outcome.rejected_peers, vec!["lying-peer".to_string()]);
        assert!(outcome.verified_peers.is_empty());
        assert!(!outcome.disagreement);
    }

    #[tokio::test]
    async fn mnt9_reconcile_beacon_summaries_empty_responses_is_a_noop() {
        let genesis = test_beacon_block(0, [4u8; 32], [0u8; 32], 100);
        let storage = Box::new(InMemoryStorage::new());
        let mut client = MultiChainClient::new(storage);
        client.init_beacon_chain(genesis).await.unwrap();

        let outcome = client.reconcile_beacon_summaries(vec![]).await.unwrap();
        assert!(outcome.winning_peer.is_none());
        assert!(!outcome.applied);
        assert!(outcome.rejected_peers.is_empty());
        assert!(outcome.verified_peers.is_empty());
        assert!(!outcome.disagreement);
    }
}

// ============================================================================
// SUMMARY OF ADDITIONAL FIELDS
// ============================================================================

/*
ADDED FIELDS BY CATEGORY:

1. Network Management (5 fields):
   - peers: Connected peers
   - active_requests: Request tracking
   - peer_reputation: Peer quality scoring
   - [Enables choosing best peers, handling failures]

2. Sync Configuration (4 fields):
   - sync_config: How to sync
   - sync_status: Current sync state per chain
   - last_sync_times: When last synced
   - sync_mode: Full/Fast/Archive
   - [Enables efficient, configurable sync]

3. Performance (2 fields):
   - metrics: Performance tracking
   - proof_cache: Avoid re-verification
   - [Enables monitoring and optimization]

4. Events (2 fields):
   - event_subscribers: App/wallet callbacks
   - notification_tx: Async event channel
   - [Enables real-time updates to wallets]

5. Cross-Chain (2 fields):
   - cross_chain_tracker: Track multi-shard txs
   - pending_cross_chain_ops: Atomic operations
   - [Enables cross-shard transactions]

6. Configuration (4 fields):
   - max_shards: Limit resource usage
   - auto_discover_shards: Dynamic shard discovery
   - network_id: Mainnet/Testnet/Devnet
   - client_version: Protocol compatibility
   - [Enables flexible deployment]

TOTAL: 19 additional fields
PURPOSE: Production-ready multi-chain light client

These fields enable:
✓ Smart peer selection
✓ Efficient syncing
✓ Real-time wallet updates
✓ Cross-shard operations
✓ Performance monitoring
✓ Resource limits
*/