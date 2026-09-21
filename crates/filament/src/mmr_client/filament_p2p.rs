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

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use p2p_proto::p2p::common::manager::PeerManager;
use p2p_proto::p2p::common::traits::{
    Capabilities, LightClientInboundNotif, NODE_LIGHT,
};
use p2p_proto::p2p::shishanet::ShishaProtocol;
use tokio::sync::{watch, RwLock};

use super::multi_chain_client::MultiChainClient;

/// Running Filament-side PeerManager + shutdown handle.
pub struct FilamentP2p {
    pub mgr: Arc<PeerManager>,
    shutdown_tx: watch::Sender<()>,
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
                self.mgr.connect(addr).await;
            }
            None => {
                log::warn!("Filament P2P: could not resolve {host}:{port}");
            }
        }
    }
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

    let protocol = ShishaProtocol::new(network.to_string());
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

    for addr in dial_peers {
        mgr.connect(addr).await;
    }

    // Keystone drops WatchAddress on disconnect. Re-send whenever the peer
    // set grows (handshake complete) and stop when Filament shuts down.
    let mgr_watch = Arc::clone(&mgr);
    let client_watch = Arc::clone(&client);
    let mut shutdown_watch = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut last_peers = 0usize;
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown_watch.changed() => break,
                _ = ticker.tick() => {
                    let n = mgr_watch.peers().len();
                    if n == 0 {
                        last_peers = 0;
                        continue;
                    }
                    if n > last_peers {
                        log::info!(
                            "Filament P2P: peer count {last_peers}→{n}; replaying WatchAddress registrations"
                        );
                        client_watch.read().await.resend_watch_addresses();
                    }
                    last_peers = n;
                }
            }
        }
    });

    Ok(FilamentP2p { mgr, shutdown_tx })
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
}
