//! Filament — Shisha Network MMR light-client library: wallet, address
//! derivation, invoice/F2F protocol, peer discovery, and multi-chain sync.
//!
//! # Gap 8 Phase 2 (this crate) — physical extraction complete
//!
//! `src/mmr_client/`, `src/wallet/`, and `src/address/` have been physically
//! moved here from the monolith. This crate has **zero non-dev dependency on
//! `shisha-core`** — the dependency direction is now correct: the monolith
//! depends on this crate, not the reverse.
//!
//! `wallet/` and `address/` moved alongside `mmr_client/` (not just the
//! originally-planned `mmr_client/`) because both turned out to be used by
//! *nothing else* in the entire codebase: `crate::wallet::` had exactly one
//! external consumer (`mmr_client::filament_wallet`), and `crate::address::`
//! had exactly one (`wallet::`). Verified via `grep` before moving, same
//! rule used for Gap 9/10's construction-engine modules / `k_voting_config` / etc.
//!
//! The monolith keeps `crate::mmr_client::*` and `crate::wallet::*` resolving
//! unchanged via one-line re-export shims at their old locations — no call
//! site outside this crate needed touching.
//!
//! ## `address/` deleted, `wallet/` trimmed (2026-07-04, RF-20 follow-up)
//!
//! The "exactly one consumer" verification above (2026-07-03) checked *within*
//! this Bech32/BIP-44/two-coin subsystem, not *outside* it — `wallet::`'s one
//! consumer was itself dead. Tracing actual runtime reachability (not just
//! grep-for-any-reference) while fixing RF-20's SLIP-44 values found this
//! whole subsystem (`address/`, and all of `wallet/` except
//! `transaction_builder::SchnorrSigner`) had **zero** live callers anywhere,
//! including the Tauri app — it's an early (2026-01-08, "week 1") wallet
//! design superseded by the raw 32-byte-recipient scheme the FV-3 migration
//! (2026-06-13) made canonical, and never updated or removed afterward.
//! `address/` was deleted outright; `wallet/` was trimmed to just
//! `SchnorrSigner`, the one real, load-bearing piece (used directly by
//! `mmr_client::filament_wallet`). Full history:
//! `docs/reports/RF-19_RF-20_Completion_Report.md` §3.
//!
//! ## Public packaging note (MMR write engine)
//!
//! Proof *verification* uses `filament-types` (weighted hash + batch/range/fork
//! checkers). The private MMR *write/construction* engines
//! (`weighted_mmr_core` / `windowed_weighted_mmr`) are intentionally out of
//! scope for this public packaging. Unit tests build fixtures with public
//! `WeightedHash` helpers only.
//!
//! See `docs/plan/Crate_Split_Plan.md` §Gap 8 for the full extraction
//! analysis.
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

// ── Peer discovery (PD-1..PD-4) — native modules in this crate ───────────────

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

// ── Gap 8 Phase 2 — physically extracted module trees ────────────────────────

pub mod mmr_client;
pub mod wallet;

// ── PD-6: NodeAddr (shishanet:// URI) ────────────────────────────────────────

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

// ── Address Book (AB-1..AB-8) ─────────────────────────────────────────────────

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
