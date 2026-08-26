// crates/filament/src/bin/filament.rs — Filament light-client standalone HTTP binary
//
// Starts the Filament HTTP server (port 7380) backed by MultiChainClient
// MMR proof verifier and a watch-only wallet delegate.
//
// Moved here from `shisha-core` `src/bin/filament.rs` once Gap 9 made a
// sole `filament` + `common-types` dependency feasible (no monolith).
// The Tauri desktop binary uses this crate via `filament_app/`.
//
// Usage:
//   filament [--network <testnet1|testnet2|mainnet|devnet|testnet-stress>]
//             [--port <port>] [--keystone <http://host:port>]
//             [--keystone-extra <http://host:port>]...
//             [--manual-peer <host:port>]... [--keystone-p2p-port <port>]
//             [--keystone-summary-port <port>]
//             [--data-dir <path>] [--p2p-listen <host:port>] [--disable-p2p]
//
// --keystone-summary-port overrides light_client_summary_port (default 8080)
// — the port sync_peer_chain_summaries() swaps onto each configured Keystone
// host to reach its GET /chain/summary API. Real deployments typically run
// that on a separate port from the main wallet-ops REST API; a single-port
// Keystone build (e.g. a local soak) needs this set to match.
//
// MNT-1: --keystone-extra may be passed multiple times to configure
// additional Keystone endpoints alongside --keystone; wallet ops fan out to
// all of them rather than trusting a single node. See
// filament_app/docs/MULTI_NODE_TRUST_PLAN.md.
//
// Path-2 P2P dial sources:
//   • --keystone / REST endpoints → host + --keystone-p2p-port (default 18334)
//   • --manual-peer / manual_peers → explicit ShishaNet host:port
//   • peer cache; live POST /peers also dials after startup

use std::env;
use log::info;

use filament::mmr_client::filament_server::{FilamentNodeConfig, load_config_from_disk, start_server};
use filament::mmr_client::filament_wallet::FilamentWallet;
use filament::mmr_client::light_client_config::FilamentBootstrapConfig;
use filament::mmr_client::multi_chain_client::MultiChainClient;
use filament::mmr_client::storage::InMemoryStorage;

fn parse_manual_peer(spec: &str) -> Option<(String, u16)> {
    let (host, port_s) = spec.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn parse_args() -> (FilamentNodeConfig, String) {
    let args: Vec<String> = env::args().collect();
    let mut cfg = FilamentNodeConfig::default();
    let mut address = env::var("FILAMENT_ADDRESS").unwrap_or_else(|_| "0".repeat(64));
    let mut disable_p2p = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                i += 1;
                if i < args.len() { cfg.network = args[i].clone(); }
            }
            "--port" => {
                i += 1;
                if i < args.len() {
                    if let Ok(p) = args[i].parse::<u16>() { cfg.port = p; }
                }
            }
            "--keystone" => {
                i += 1;
                if i < args.len() { cfg.keystone_endpoint = Some(args[i].clone()); }
            }
            "--keystone-extra" => {
                i += 1;
                if i < args.len() { cfg.keystone_rest_endpoints.push(args[i].clone()); }
            }
            "--manual-peer" => {
                i += 1;
                if i < args.len() {
                    if let Some((host, port)) = parse_manual_peer(&args[i]) {
                        cfg.upsert_manual_peer(host, port);
                    } else {
                        eprintln!("filament: bad --manual-peer {:?} (want host:port)", args[i]);
                    }
                }
            }
            "--keystone-p2p-port" => {
                i += 1;
                if i < args.len() {
                    if let Ok(p) = args[i].parse::<u16>() {
                        cfg.keystone_p2p_port = p;
                    }
                }
            }
            "--keystone-summary-port" => {
                i += 1;
                if i < args.len() {
                    if let Ok(p) = args[i].parse::<u16>() {
                        cfg.light_client_summary_port = p;
                    }
                }
            }
            "--p2p-listen" => {
                i += 1;
                if i < args.len() { cfg.p2p_listen = args[i].clone(); }
            }
            "--disable-p2p" => {
                disable_p2p = true;
            }
            "--address" => {
                i += 1;
                if i < args.len() { address = args[i].clone(); }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() { cfg.data_dir = args[i].clone(); }
            }
            "--confirmation-depth" => {
                i += 1;
                if i < args.len() {
                    if let Ok(d) = args[i].parse::<u32>() {
                        cfg.confirmation_depth = d;
                    }
                }
            }
            "--bitcoin-anchor-hex" => {
                i += 1;
                if i < args.len() {
                    cfg.bitcoin_anchor_hex = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    if disable_p2p {
        cfg.enable_p2p = false;
    }
    (cfg, address)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_module("filament", log::LevelFilter::Info)
        .init();

    let (cli_config, address) = parse_args();

    // Merge: CLI flags take precedence over persisted config
    let config = if let Some(mut persisted) = load_config_from_disk(&cli_config.data_dir).await {
        // CLI overrides only for fields the user explicitly set (non-default values)
        if cli_config.network != FilamentNodeConfig::default().network {
            persisted.network = cli_config.network;
        }
        if cli_config.port != FilamentNodeConfig::default().port {
            persisted.port = cli_config.port;
        }
        if cli_config.keystone_endpoint.is_some() {
            persisted.keystone_endpoint = cli_config.keystone_endpoint;
        }
        if !cli_config.keystone_rest_endpoints.is_empty() {
            persisted.keystone_rest_endpoints = cli_config.keystone_rest_endpoints;
        }
        for (host, port) in cli_config.manual_peers {
            persisted.upsert_manual_peer(host, port);
        }
        if cli_config.keystone_p2p_port != FilamentNodeConfig::default().keystone_p2p_port {
            persisted.keystone_p2p_port = cli_config.keystone_p2p_port;
        }
        if cli_config.p2p_listen != FilamentNodeConfig::default().p2p_listen {
            persisted.p2p_listen = cli_config.p2p_listen;
        }
        if !cli_config.enable_p2p {
            persisted.enable_p2p = false;
        }
        if cli_config.confirmation_depth != FilamentNodeConfig::default().confirmation_depth {
            persisted.confirmation_depth = cli_config.confirmation_depth;
        }
        if cli_config.bitcoin_anchor_hex.is_some() {
            persisted.bitcoin_anchor_hex = cli_config.bitcoin_anchor_hex;
        }
        persisted.data_dir = cli_config.data_dir;
        persisted
    } else {
        cli_config
    };

    info!("Filament starting — network: {}, port: {}", config.network, config.port);

    // MNT-1/7 + PD-INT-1: wallet endpoints include discovery merge at startup;
    // `start_server` runs `apply_startup_peer_discovery` before serving.
    let mut wallet = FilamentWallet::new(address, config.keystone_endpoint.clone());
    wallet.set_keystone_endpoints(config.all_keystone_endpoints());
    let storage = Box::new(InMemoryStorage::new());

    // Bootstrap the beacon chain's genesis so sync/proof verification actually has
    // something to verify against. Previously this binary never called
    // init_from_network/init_beacon_chain at all — every sync attempt failed
    // silently with "Beacon chain not initialized," regardless of --network.
    let bootstrap = FilamentBootstrapConfig::from_embedded();
    let mut client = match MultiChainClient::from_config(bootstrap, storage) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("filament: warning: bootstrap config error: {e} — starting without local genesis config");
            MultiChainClient::new(Box::new(InMemoryStorage::new()))
        }
    };
    if let Err(e) = client.init_from_network(&config.network).await {
        eprintln!(
            "filament: warning: could not initialize network '{}': {e} — this network has no genesis \
             configured in light_client_config.toml, so sync against a Keystone will fail until fixed",
            config.network
        );
    }

    start_server(client, wallet, config).await
}
