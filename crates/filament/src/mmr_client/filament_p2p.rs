//! Filament outbound ShishaNet client — dials Keystones, receives Path-2 notifs.
//!
//! Full nodes push `TxInclusionNotif` / `TxSpentNotif` / `TxRevertNotif` over
//! P2P to light-client peers. Until this module, Filament had no PeerManager,
//! so those messages never arrived (HTTP `/light/notifications` poll was the
//! only Path-2 path). This dials configured P2P peers, installs a notif
//! handler that forwards into [`MultiChainClient`], and sends `WatchAddress`
//! over the same connections.
//!
//! Dial sources (deduped):
//! 1. Explicit `manual_peers` / `shishanet://` / `--manual-peer` (ShishaNet ports)
//! 2. Hosts from Keystone REST URLs + `keystone_p2p_port`
//! 3. Live peer-cache entries

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use p2p_proto::p2p::common::manager::PeerManager;
use p2p_proto::p2p::common::traits::{
    Capabilities, LightClientInboundNotif, NODE_LIGHT,
};
use p2p_proto::p2p::shishanet::ShishaProtocol;
use tokio::sync::{watch, RwLock};

use super::multi_chain_client::MultiChainClient;

/// First wait before a dial target that is not connected is dialed again, and the longest wait between dials.
const REDIAL_FIRST_DELAY: Duration = Duration::from_secs(6);
const REDIAL_MAX_DELAY: Duration = Duration::from_secs(60);

/// Running Filament-side PeerManager + shutdown handle.
pub struct FilamentP2p {
    pub mgr: Arc<PeerManager>,
    shutdown_tx: watch::Sender<()>,
    /// Dial targets kept connected: a target that drops is dialed again with backoff.
    targets: Arc<Mutex<Vec<SocketAddr>>>,
}

impl FilamentP2p {
    /// Signal the PeerManager event loop to exit (best-effort).
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Send `WatchAddress` to every connected Keystone.
    pub fn send_watch_address(&self, address: [u8; 32], shard_id: u16) {
        let msg = self.mgr.protocol().build_watch_address(address, shard_id);
        log::info!(
            "Filament P2P: sending WatchAddress shard_id={shard_id} address={}",
            hex::encode(address)
        );
        self.mgr.send_to_all_peers(msg);
    }

    /// Resolve `host:port` and dial (used for live peer-add after startup).
    pub async fn dial_peer(&self, host: &str, port: u16) {
        match resolve_dial_addr(host, port) {
            Some(addr) => {
                log::info!("Filament P2P: dialing {addr}");
                {
                    let mut t = self.targets.lock().expect("targets poisoned");
                    if !t.contains(&addr) {
                        t.push(addr); // re-dialed after a drop, like the startup targets
                    }
                }
                self.mgr.connect(addr).await;
            }
            None => {
                log::warn!("Filament P2P: could not resolve {host}:{port}");
            }
        }
    }
}

/// Build the light-client protocol for `network`, attaching the embedded
/// genesis hash derived from the network's preset.
pub fn protocol_for_network(network: &str) -> ShishaProtocol {
    let mut protocol = ShishaProtocol::new(network.to_string());
    if let Some(hash) = genesis_hash_for_network(network) {
        protocol = protocol.with_genesis_hash(hash);
    }
    protocol
}

/// The beacon genesis hash of a known network, derived from its preset (never from a stored
/// copy of the hash: the copy this replaced had drifted from the real testnet-stress hash and
/// would have refused every real peer). `None` for a network without a preset, and for `devnet`:
/// many unrelated local chains run as `devnet`, so its name does not identify one genesis.
fn genesis_hash_for_network(network: &str) -> Option<[u8; 32]> {
    use network_common::common::genesis::genesis::GenesisGenerator;
    use network_common::common::genesis::genesis_config::BeaconGenesisConfig;
    let cfg = match network {
        "mainnet" => BeaconGenesisConfig::mainnet(),
        "testnet1" => BeaconGenesisConfig::testnet1(),
        "testnet2" => BeaconGenesisConfig::testnet2(),
        "testnet3" => BeaconGenesisConfig::testnet3(),
        "testnet-stress" => BeaconGenesisConfig::testnet_stress(),
        _ => return None,
    };
    GenesisGenerator::beacon_genesis_hash(&cfg).ok()
}

/// Resolve a single host:port to a [`SocketAddr`] (first result wins).
pub fn resolve_dial_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Some(addr);
    }
    (host, port).to_socket_addrs().ok()?.next()
}

/// Extract hostname from a Keystone REST URL (`http://host:port/...`).
///
/// Port and path are stripped; IPv6 bracketed hosts are left as-is when present.
pub fn host_from_rest_endpoint(endpoint: &str) -> Option<String> {
    let without_scheme = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    let authority = without_scheme.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6: `[::1]:7379` or `[::1]`
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return Some(format!("[{host}]"));
    }
    // host:port — only strip if the tail parses as u16 (avoids `http:` false split).
    if let Some((h, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() && !h.is_empty() {
            return Some(h.to_string());
        }
    }
    Some(authority.to_string())
}

/// Collect dial targets from manual peers, peer cache, and REST endpoint hosts.
pub fn collect_p2p_dial_addrs(
    manual_peers: &[(String, u16)],
    cache: Option<&crate::peer_cache::PeerCache>,
    rest_endpoints: &[String],
    keystone_p2p_port: u16,
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut push = |host: &str, port: u16| {
        if let Some(addr) = resolve_dial_addr(host, port) {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    };
    for (host, port) in manual_peers {
        push(host, *port);
    }
    if let Some(cache) = cache {
        for (host, port) in cache.live_peers() {
            push(&host, port);
        }
    }
    for ep in rest_endpoints {
        if let Some(host) = host_from_rest_endpoint(ep) {
            push(&host, keystone_p2p_port);
        }
    }
    out
}

/// Start a light-client PeerManager, wire inbound notifs → `MultiChainClient`,
/// dial `peers`, and spawn the event loop.
pub async fn start_filament_p2p(
    network: &str,
    listen_addr: SocketAddr,
    dial_peers: Vec<SocketAddr>,
    client: Arc<RwLock<MultiChainClient>>,
) -> Result<FilamentP2p, String> {
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let caps = Capabilities {
        services: NODE_LIGHT, // no NODE_NETWORK → classified as light client
        user_agent: "/Filament:0.1.0/".into(),
        beacon_height: 0,
        shard_heights: vec![],
        nonce: rand::random(),
        listen_addr,
    };

    // Pin chain identity when the bootstrap config knows a non-zero genesis
    // hash for this network (testnet-stress today; others stay "unknown" until
    // mined). Unknown (= all-zero) is never compared by either side.
    let protocol = protocol_for_network(network);
    let mgr = PeerManager::new(protocol, caps, listen_addr, 32, shutdown_rx);

    let client_for_handler = Arc::clone(&client);
    mgr.set_light_client_notif_handler(Arc::new(move |notif| {
        let client = Arc::clone(&client_for_handler);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let c = client.read().await;
                match notif {
                    LightClientInboundNotif::Inclusion {
                        shard_id,
                        height,
                        output_idx,
                        value_atoms,
                        address,
                        mmr_proof_bytes,
                    } => {
                        c.handle_tx_inclusion_notif(
                            shard_id,
                            height,
                            output_idx,
                            value_atoms,
                            address,
                            mmr_proof_bytes,
                        )
                        .await;
                    }
                    LightClientInboundNotif::Spent {
                        shard_id,
                        spend_height,
                        output_height,
                        output_idx,
                    } => {
                        c.handle_tx_spent_notif(shard_id, spend_height, output_height, output_idx)
                            .await;
                    }
                    LightClientInboundNotif::Revert {
                        shard_id,
                        height,
                        output_idx,
                    } => {
                        c.handle_tx_revert_notif(shard_id, height, output_idx).await;
                    }
                }
            });
        }
    }));

    let mgr_run = Arc::clone(&mgr);
    tokio::spawn(async move {
        mgr_run.run().await;
    });

    // Wait briefly for the listener to bind (port 0 → ephemeral).
    let _ = tokio::time::timeout(Duration::from_secs(2), mgr.listen_addr()).await;

    for addr in &dial_peers {
        mgr.connect(*addr).await;
    }
    let targets = Arc::new(Mutex::new(dial_peers));

    // A dial target is dialed once above and never again unless this task does it: a Keystone that
    // restarted was otherwise never reached again and the Path-2 notification path stayed dead (soak
    // finding, Nov 12, 2026). A target that is not connected is dialed with a doubling delay (first
    // 6 s, so a handshake still in flight is not duplicated, up to 60 s); the delay resets once it is
    // connected.
    let mgr_redial = Arc::clone(&mgr);
    let targets_redial = Arc::clone(&targets);
    let mut shutdown_redial = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut state: HashMap<SocketAddr, (Instant, Duration)> = HashMap::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown_redial.changed() => break,
                _ = ticker.tick() => {
                    let connected = mgr_redial.connected_addrs().await;
                    let wanted: Vec<SocketAddr> = targets_redial.lock().expect("targets poisoned").clone();
                    let now = Instant::now();
                    for addr in wanted {
                        if connected.contains(&addr) {
                            state.remove(&addr);
                            continue;
                        }
                        let (next, delay) = *state
                            .entry(addr)
                            .or_insert((now + REDIAL_FIRST_DELAY, REDIAL_FIRST_DELAY));
                        if now < next {
                            continue;
                        }
                        log::info!("Filament P2P: {addr} is not connected; dialing again");
                        mgr_redial.connect(addr).await;
                        let delay = (delay * 2).min(REDIAL_MAX_DELAY);
                        state.insert(addr, (Instant::now() + delay, delay));
                    }
                }
            }
        }
    });

    // Keystone drops WatchAddress on disconnect. Re-send whenever a connection we have not seen
    // appears (`connections_total` changes with every new one, so a restart faster than one tick
    // still counts) and stop when Filament shuts down.
    let mgr_watch = Arc::clone(&mgr);
    let client_watch = Arc::clone(&client);
    let mut shutdown_watch = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut last_total = mgr_watch.connections_total();
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown_watch.changed() => break,
                _ = ticker.tick() => {
                    let n = mgr_watch.peers().len();
                    let total = mgr_watch.connections_total();
                    if n > 0 && total != last_total {
                        log::info!(
                            "Filament P2P: {n} peer(s), new connection(s) since the last look; replaying WatchAddress registrations"
                        );
                        client_watch.read().await.resend_watch_addresses();
                        last_total = total;
                    }
                }
            }
        }
    });

    Ok(FilamentP2p { mgr, shutdown_tx, targets })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::storage::InMemoryStorage;
    use p2p_proto::p2p::shishanet::ShishaMessage;
    use tokio::sync::mpsc;

    #[test]
    fn host_from_rest_strips_scheme_port_and_path() {
        assert_eq!(
            host_from_rest_endpoint("http://127.0.0.1:18092/wallet"),
            Some("127.0.0.1".into())
        );
        assert_eq!(
            host_from_rest_endpoint("https://keystone.example:7379"),
            Some("keystone.example".into())
        );
        assert_eq!(
            host_from_rest_endpoint("http://localhost"),
            Some("localhost".into())
        );
    }

    #[test]
    fn collect_rest_derived_dials_keystone_p2p_port() {
        let addrs = collect_p2p_dial_addrs(
            &[],
            None,
            &["http://127.0.0.1:18092".into()],
            28336,
        );
        assert_eq!(addrs, vec!["127.0.0.1:28336".parse().unwrap()]);
    }

    #[test]
    fn collect_dedupes_manual_and_rest_same_socket() {
        let addrs = collect_p2p_dial_addrs(
            &[("127.0.0.1".into(), 18334)],
            None,
            &["http://127.0.0.1:7379".into()],
            18334,
        );
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "127.0.0.1:18334".parse().unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filament_p2p_inbound_inclusion_reaches_client() {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let mut client = MultiChainClient::new(Box::new(InMemoryStorage::new()));
        client
            .subscribe(Arc::new(move |ev| {
                let _ = event_tx.send(ev);
            }))
            .await;

        let client = Arc::new(RwLock::new(client));
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let p2p = start_filament_p2p("testnet1", listen, vec![], Arc::clone(&client))
            .await
            .expect("start p2p");

        let msg = ShishaMessage::TxInclusionNotif {
            shard_id: 0,
            height: 42,
            output_idx: 1,
            value_atoms: 1000,
            address: [0xABu8; 32],
            mmr_proof_bytes: vec![1, 2, 3],
        };
        p2p.mgr.inject_message_for_test(msg).await;

        let got = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("timeout waiting for ClientEvent")
            .expect("channel closed");

        match got {
            crate::mmr_client::multi_chain_client::ClientEvent::TxInclusionReceived {
                height,
                output_idx,
                value_atoms,
                address,
                ..
            } => {
                assert_eq!(height, 42);
                assert_eq!(output_idx, 1);
                assert_eq!(value_atoms, 1000);
                assert_eq!(address, [0xABu8; 32]);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        p2p.shutdown();
    }
    /// The hash the full node documents for testnet-stress. If this drifts, every
    /// real client is refused at the handshake, so it is pinned here on purpose.
    const TESTNET_STRESS_GENESIS: &str = "000003209cb9d6d5f025b849177c322c66bf0e814cdf3558132fbd0203000080";

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn testnet_stress_is_pinned_to_the_documented_genesis_hash() {
        let p = protocol_for_network("testnet-stress");
        assert_eq!(p.genesis_hash(), hex32(TESTNET_STRESS_GENESIS));
        assert_eq!(p.magic(), u32::from_le_bytes(*b"SHTS"));
    }

    #[test]
    fn named_networks_are_pinned_to_their_preset_genesis_except_devnet() {
        use network_common::common::genesis::genesis::GenesisGenerator;
        use network_common::common::genesis::genesis_config::BeaconGenesisConfig;
        // devnet's name does not identify a chain (every local soak genesis runs as devnet).
        assert_eq!(protocol_for_network("devnet").genesis_hash(), [0u8; 32], "devnet should be unpinned");
        for (net, cfg) in [
            ("mainnet", BeaconGenesisConfig::mainnet()),
            ("testnet1", BeaconGenesisConfig::testnet1()),
            ("testnet2", BeaconGenesisConfig::testnet2()),
            ("testnet3", BeaconGenesisConfig::testnet3()),
        ] {
            let want = GenesisGenerator::beacon_genesis_hash(&cfg).unwrap();
            assert_ne!(want, [0u8; 32]);
            assert_eq!(protocol_for_network(net).genesis_hash(), want, "{net}");
        }
    }

    #[test]
    fn an_unconfigured_network_is_unpinned_but_still_has_its_own_magic() {
        let p = protocol_for_network("my-private-net");
        assert_eq!(p.genesis_hash(), [0u8; 32]);
        assert_eq!(p.magic(), p2p_proto::magic_for_network("my-private-net"));
    }

    #[test]
    fn a_node_on_another_testnet_stress_chain_is_refused_by_the_overlay_protocol() {
        use p2p_proto::{NetAddr, VersionMessage, WIRE_VERSION};
        let p = protocol_for_network("testnet-stress");
        let mut theirs = VersionMessage::new(
            WIRE_VERSION,
            1,
            7,
            NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), 1),
        );
        theirs.genesis_hash = [0xAB; 32];
        assert!(p.check_peer_version(&theirs).unwrap_err().contains("genesis mismatch"));
        theirs.genesis_hash = hex32(TESTNET_STRESS_GENESIS);
        assert!(p.check_peer_version(&theirs).is_ok());
    }

    /// Soak finding (Nov 12, 2026): a dial target was connected once and never again after the connection
    /// closed. When the Keystone behind the target restarts on the same address, Filament must be connected again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filament_redials_a_keystone_that_restarted() {
        use p2p_proto::p2p::common::traits::NODE_NETWORK;

        // A free loopback port the stand-in Keystone can bind, close, and bind again.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let keystone_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let start_keystone = || {
            let (stop_tx, stop_rx) = watch::channel(());
            let caps = Capabilities {
                services: NODE_NETWORK,
                user_agent: "/stub-keystone:0.1.0/".into(),
                beacon_height: 0,
                shard_heights: vec![],
                nonce: rand::random(),
                listen_addr: keystone_addr,
            };
            let mgr = PeerManager::new(ShishaProtocol::new("testnet1".into()), caps, keystone_addr, 8, stop_rx);
            let run = Arc::clone(&mgr);
            tokio::spawn(async move { run.run().await });
            (mgr, stop_tx)
        };
        let (keystone, stop_keystone) = start_keystone();
        tokio::time::timeout(Duration::from_secs(2), keystone.listen_addr()).await.expect("keystone bound");

        let client = Arc::new(RwLock::new(MultiChainClient::new(Box::new(InMemoryStorage::new()))));
        let p2p = start_filament_p2p("testnet1", "127.0.0.1:0".parse().unwrap(), vec![keystone_addr], Arc::clone(&client))
            .await
            .expect("start p2p");

        async fn wait_connected(what: &str, secs: u64, mgr: &Arc<PeerManager>, want: usize) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
            while mgr.connected_addrs().await.len() != want {
                assert!(tokio::time::Instant::now() < deadline, "timed out waiting for: {what}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        wait_connected("first connection", 10, &p2p.mgr, 1).await;
        let first_total = p2p.mgr.connections_total();

        // The Keystone goes away (its process is killed) ...
        let _ = stop_keystone.send(());
        wait_connected("the connection to drop", 10, &p2p.mgr, 0).await;
        // ... and comes back on the same address.
        let (_keystone2, _stop2) = start_keystone();
        wait_connected("a new connection after the restart", 40, &p2p.mgr, 1).await;
        assert!(p2p.mgr.connections_total() > first_total, "a new connection means a new peer id");

        p2p.shutdown();
    }
}
