//! Filament — Shisha Network MMR light-client library: wallet, address
//! derivation, invoice/F2F protocol, peer discovery, and multi-chain sync.
//!
//! ## Scope
//!
//! This crate holds the light-client modules (`mmr_client/`, `wallet/`). Its
//! only workspace dependencies are the public `filament-types` crate (aliased
//! as `common_types`) and, behind the `full-node` feature, `filament-p2p`.
//!
//! Proof *verification* uses `filament-types` (weighted hash + batch/range/fork
//! checkers). Proof *generation* (MMR construction) is not part of this
//! package; unit tests build fixtures with the public `WeightedHash` helpers.
//!
//! ## Feature flags
//!
//! | Feature    | What it enables |
//! |------------|-----------------|
//! | `full-node` | axum HTTP server (`filament_server`) + Schnorr signing (`filament_wallet`) |
//! | `server`   | alias for `full-node` |
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! filament = { path = "../../crates/filament", features = ["full-node"] }
//! ```

// ── Peer discovery — native modules in this crate ───────────────

pub mod seeds;
pub mod peer_cache;
pub mod peer_discovery;
pub mod dns_seeds;

pub use peer_cache::{PeerCache, PeerEntry};
pub use peer_discovery::{
    merge_discovery_keystone_endpoints,
    resolve_discovery_peers,
    PeerDiscovery,
};
pub use dns_seeds::{DEFAULT_DNS_SEED_PORT, parse_port_from_txt, port_from_txt_strings};
#[cfg(feature = "full-node")]
pub use dns_seeds::{refresh_dns_seeds_into_cache, resolve_dns_seed};

// ── Module trees ─────────────────────────────────────────────────────────────

pub mod mmr_client;
pub mod wallet;

// ── NodeAddr (shishanet:// URI) ────────────────────────────────────────

pub use mmr_client::shisha_uri::NodeAddr;

// ── Wallet types ──────────────────────────────────────────────────────────────

pub use mmr_client::filament_wallet::{
    BalanceResponse,
    FeeEstimate,
    FilamentWallet,
    SendRequest,
    SendResponse,
    TxHistoryEntry,
    UtxoEntry,
    ATOMS_PER_COIN,
    DEFAULT_FEE_ATOMS,
};

// ── Server / config (filament_server.rs itself is fully full-node-gated) ─────

#[cfg(feature = "full-node")]
pub use mmr_client::filament_server::{
    apply_startup_peer_discovery,
    load_config_from_disk,
    parse_host_port,
    save_filament_config,
    F2fInboxItem,
    FilamentNodeConfig,
    FilamentRuntime,
    wire_f2f_inbox_subscription,
    wire_watch_notify_subscription,
    wire_http_watch_sender,
    wire_watch_sender,
    maybe_start_filament_p2p,
    restore_invoice_watch_registrations,
    watch_client_token,
};

// ── Client types ──────────────────────────────────────────────────────────────

pub use mmr_client::{
    ChainHandler,
    ChainState,
    ChainSyncStatus,
    ChainType,
    FilamentBootstrapConfig,
    LightClientStorage,
    MultiChainClient,
    SyncConfiguration,
    SyncMode,
};

pub use mmr_client::multi_chain_client::{
    PeerCapabilities,
    PeerConnection,
};

// ── Storage implementations ───────────────────────────────────────────────────

pub use mmr_client::{
    InMemoryStorage,
    FileStorage,
};

// ── Phase 10: Invoice, URI, F2F (Tracks A–H) ─────────────────────────────────

pub use mmr_client::invoice::{
    Invoice,
    InvoiceState,
    InvoiceStore,
    InvoiceError,
    new_invoice_id,
    decode_hex32,
    encode_hex32,
    base64url_encode16,
    base64url_decode16,
};

pub use mmr_client::shisha_uri::{
    ShishaUri,
    ShishaUriError,
    AddressCard,
};

// ── Address Book ─────────────────────────────────────────────────

pub use mmr_client::contact_store::{
    Contact,
    ContactStore,
    ContactError,
};

pub use mmr_client::watch_notify::{
    WatchNotifyState,
    WatchUtxo,
    MIN_CONFIRMATION_DEPTH,
    InclusionApplyResult,
    process_inclusion_notif,
    verify_inclusion_proof_bytes,
    http_watch_peer_id,
};

pub use mmr_client::f2f::{
    F2fMessage,
    F2fError,
    InvoiceRequest,
    PaymentProof,
    PaymentAck,
    InvoiceCancel,
    F2fReject,
    RejectReason,
    f2f_encode,
    f2f_decode,
    new_msg_id,
    relay_id,
};
