use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use filament_p2p::{Capabilities, LightClientInboundNotif, PeerManager, ShishaProtocol, NODE_LIGHT, NODE_NETWORK};
use tokio::sync::watch;

fn caps(services: u64, port: u16) -> Capabilities {
    Capabilities {
        services,
        user_agent: "/test/".into(),
        beacon_height: 0,
        shard_heights: vec![],
        nonce: rand::random(),
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_handshake_and_exchange_notif() {
    let (a_shutdown_tx, a_shutdown_rx) = watch::channel(());
    let (b_shutdown_tx, b_shutdown_rx) = watch::channel(());

    // "Full node" side (B): accepts, sends a TxInclusionNotif once connected.
    let b_mgr = PeerManager::new(
        ShishaProtocol::new("test".into()),
        caps(NODE_NETWORK, 0),
        "127.0.0.1:0".parse().unwrap(),
        8,
        b_shutdown_rx,
    );
    let b_run = Arc::clone(&b_mgr);
    tokio::spawn(async move { b_run.run().await; });
    let b_addr: SocketAddr = tokio::time::timeout(Duration::from_secs(2), b_mgr.listen_addr())
        .await
        .expect("B listener bind timed out");

    // "Light client" side (A): dials B.
    let a_mgr = PeerManager::new(
        ShishaProtocol::new("test".into()),
        caps(NODE_LIGHT, 0),
        "127.0.0.1:0".parse().unwrap(),
        8,
        a_shutdown_rx,
    );
    let received = Arc::new(AtomicBool::new(false));
    let received_clone = Arc::clone(&received);
    a_mgr.set_light_client_notif_handler(Arc::new(move |notif| {
        if let LightClientInboundNotif::Inclusion { height, .. } = notif {
            assert_eq!(height, 42);
            received_clone.store(true, Ordering::SeqCst);
        }
    }));
    let a_run = Arc::clone(&a_mgr);
    tokio::spawn(async move { a_run.run().await; });

    a_mgr.connect(b_addr).await;

    // Give the handshake time to complete, then have B broadcast a notif.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a_mgr.peers().len(), 1, "A should have exactly one connected peer");
    assert_eq!(b_mgr.peers().len(), 1, "B should have exactly one connected peer");

    b_mgr.send_to_all_peers(filament_p2p::ShishaMessage::TxInclusionNotif {
        shard_id: 0,
        height: 42,
        output_idx: 0,
        value_atoms: 100,
        address: [1u8; 32],
        mmr_proof_bytes: vec![],
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(received.load(Ordering::SeqCst), "light client never received the notif");

    let _ = a_shutdown_tx.send(());
    let _ = b_shutdown_tx.send(());
}

// ── Wire v15: network magic, version floor, chain identity ──────────────────

use filament_p2p::framing::{frame, magic_for_network, try_decode};
use filament_p2p::{ShishaMessage, VersionMessage, GENESIS_HASH_LEN, WIRE_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn client(network: &str, genesis: Option<[u8; GENESIS_HASH_LEN]>) -> (Arc<PeerManager>, watch::Sender<()>) {
    let (tx, rx) = watch::channel(());
    let mut protocol = ShishaProtocol::new(network.into());
    if let Some(g) = genesis {
        protocol = protocol.with_genesis_hash(g);
    }
    let mgr = PeerManager::new(protocol, caps(NODE_LIGHT, 0), "127.0.0.1:0".parse().unwrap(), 8, rx);
    let run = Arc::clone(&mgr);
    tokio::spawn(async move { run.run().await });
    (mgr, tx)
}

/// A scripted peer: accepts one connection, reads the client's `version`, and
/// answers with a `version` built by `reply` plus a `verack`. Returns the
/// address and a handle yielding the client's decoded `version` and the raw
/// bytes of the first frame.
async fn scripted_node(
    network: &str,
    reply: impl FnOnce(&VersionMessage) -> VersionMessage + Send + 'static,
) -> (SocketAddr, tokio::task::JoinHandle<(VersionMessage, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let magic = magic_for_network(network);
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (msg, consumed) = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before sending version");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(found) = try_decode(magic, &buf).expect("client framed with the wrong magic") {
                break found;
            }
        };
        let first_frame = buf[..consumed].to_vec();
        let theirs = match ShishaMessage::decode(&msg.command, &msg.payload).unwrap() {
            ShishaMessage::Version(v) => v,
            other => panic!("first message was {}", other.command()),
        };
        let ours = reply(&theirs);
        stream.write_all(&frame(magic, "version", &ours.encode())).await.unwrap();
        stream.write_all(&frame(magic, "verack", &[])).await.unwrap();
        // Keep the socket open long enough for the client to decide.
        tokio::time::sleep(Duration::from_millis(500)).await;
        (theirs, first_frame)
    });
    (addr, handle)
}

fn node_version(version: u32, genesis: [u8; GENESIS_HASH_LEN]) -> impl FnOnce(&VersionMessage) -> VersionMessage {
    move |_| {
        let mut v = VersionMessage::new(
            version,
            NODE_NETWORK,
            0x1234_5678,
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), NODE_NETWORK),
        );
        v.genesis_hash = genesis;
        v
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_speaks_v15_with_the_network_magic_and_trailers() {
    let (addr, node) = scripted_node("devnet", node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", None);
    mgr.connect(addr).await;
    let (version, first_frame) = tokio::time::timeout(Duration::from_secs(3), node).await.unwrap().unwrap();

    assert_eq!(&first_frame[0..4], b"SHDV", "frame starts with the devnet magic");
    assert_eq!(&first_frame[4..11], b"version");
    assert_eq!(version.version, 15);
    assert_eq!(version.genesis_hash, [0u8; GENESIS_HASH_LEN], "a client that does not know the chain says so");
    assert_eq!(version.subscription_mask, [0u8; 128]);
    // The payload must carry every trailer: mask (128) and genesis hash (32) at the end.
    let payload_len = u32::from_le_bytes(first_frame[16..20].try_into().unwrap()) as usize;
    assert_eq!(first_frame.len(), 24 + payload_len);
    let decoded_len = version.encode().len();
    assert_eq!(payload_len, decoded_len, "no unparsed bytes left in the client's own message");
    assert!(payload_len >= 4 + 8 + 8 + 52 + 8 + 1 + 4 + 2 + 6 + 6 + 128 + 32);
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn completes_the_handshake_with_a_current_node() {
    let (addr, node) = scripted_node("devnet", node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", None);
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 1);
    let _ = node.await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_peer_older_than_the_minimum_version() {
    let (addr, node) = scripted_node("devnet", node_version(14, [0u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", None);
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 0, "a v14 node is refused");
    let _ = node.await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_peer_on_a_different_chain() {
    let (addr, node) = scripted_node("devnet", node_version(WIRE_VERSION, [2u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", Some([1u8; GENESIS_HASH_LEN]));
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 0);
    let _ = node.await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn accepts_the_same_chain_and_an_unknown_one() {
    // Same hash on both sides.
    let (addr, node) = scripted_node("devnet", node_version(WIRE_VERSION, [7u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", Some([7u8; GENESIS_HASH_LEN]));
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 1);
    let _ = node.await;
    let _ = shutdown.send(());

    // The node does not say (all-zero): never compared.
    let (addr, node) = scripted_node("devnet", node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])).await;
    let (mgr, shutdown) = client("devnet", Some([7u8; GENESIS_HASH_LEN]));
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 1);
    let _ = node.await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn completes_handshake_with_a_v17_keystone_style_peer() {
    // Current Keystones advertise registry current (17) with tip trailers after
    // the genesis hash (v16+). We speak 15; negotiation is min(ours, theirs).
    let tip_trailer = [0x11u8; 40]; // opaque later-version bytes
    let (addr, node) = scripted_node("devnet", move |_| {
        let mut v = VersionMessage::new(
            17,
            NODE_NETWORK,
            0xABCD_EF01,
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), NODE_NETWORK),
        );
        v.genesis_hash = [0u8; GENESIS_HASH_LEN];
        let mut payload = v.encode();
        payload.extend_from_slice(&tip_trailer);
        // Re-decode through our parser to confirm trailers are ignored, then
        // reply with a clean v17 message (scripted peer still sends via encode).
        let parsed = VersionMessage::decode(&payload).expect("v17+ tip trailer ignored");
        assert_eq!(parsed.version, 17);
        assert_eq!(parsed.genesis_hash, [0u8; GENESIS_HASH_LEN]);
        parsed
    })
    .await;
    let (mgr, shutdown) = client("devnet", None);
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mgr.peers().len(), 1, "v17 Keystone-style peer must complete handshake");
    let _ = node.await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_on_another_network_never_gets_through_the_framing() {
    // The node frames with the mainnet magic; the client expects devnet.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut chunk = [0u8; 4096];
        let _ = stream.read(&mut chunk).await; // the client's version (devnet magic)
        let theirs = node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])(&VersionMessage::new(
            0, 0, 0,
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
        ));
        let mainnet = magic_for_network("mainnet");
        let _ = stream.write_all(&frame(mainnet, "version", &theirs.encode())).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    });
    let (mgr, shutdown) = client("devnet", None);
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mgr.peers().len(), 0);
    let _ = node.await;
    let _ = shutdown.send(());
}

/// A node that writes `version`, `verack` and a notification in ONE segment.
/// Real nodes push right after the handshake, so the client's first read can
/// contain more than the handshake.
async fn node_that_pushes_behind_verack(network: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let magic = magic_for_network(network);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before sending version");
            buf.extend_from_slice(&chunk[..n]);
            if try_decode(magic, &buf).expect("bad framing from client").is_some() {
                break;
            }
        }
        let ours = node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])(&VersionMessage::new(
            WIRE_VERSION,
            0,
            0,
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
        ));
        let notif = ShishaMessage::TxInclusionNotif {
            shard_id: 3,
            height: 77,
            output_idx: 1,
            value_atoms: 5,
            address: [9u8; 32],
            mmr_proof_bytes: vec![],
        };
        let mut one_write = frame(magic, "version", &ours.encode());
        one_write.extend(frame(magic, "verack", &[]));
        one_write.extend(frame(magic, notif.command(), &notif.encode()));
        stream.write_all(&one_write).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_sent_right_behind_verack_is_delivered() {
    let addr = node_that_pushes_behind_verack("devnet").await;
    let (mgr, _shutdown) = client("devnet", None);
    let seen = Arc::new(AtomicBool::new(false));
    let seen2 = Arc::clone(&seen);
    mgr.set_light_client_notif_handler(Arc::new(move |n| {
        if let LightClientInboundNotif::Inclusion { shard_id: 3, height: 77, .. } = n {
            seen2.store(true, Ordering::SeqCst);
        }
    }));
    mgr.connect(addr).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(mgr.peers().len(), 1);
    assert!(seen.load(Ordering::SeqCst), "notification sent in the same segment as verack was dropped");
}

/// Accepts one connection, optionally answers with a bare `version`, then
/// waits for the client to close the socket. Returns how long that took.
async fn stalling_node(network: &str, send_version: bool) -> (SocketAddr, tokio::task::JoinHandle<Option<Duration>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let magic = magic_for_network(network);
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let started = std::time::Instant::now();
        if send_version {
            let v = node_version(WIRE_VERSION, [0u8; GENESIS_HASH_LEN])(&VersionMessage::new(
                WIRE_VERSION,
                0,
                0,
                filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
                filament_p2p::NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            ));
            stream.write_all(&frame(magic, "version", &v.encode())).await.unwrap();
        }
        // Drain whatever the client sends until it hangs up.
        let mut chunk = [0u8; 4096];
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        closed.ok().map(|_| started.elapsed())
    });
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_peer_is_dropped_after_the_handshake_timeout() {
    let (addr, node) = stalling_node("devnet", false).await;
    let (mgr, _shutdown) = client("devnet", None);
    mgr.set_handshake_timeout(Duration::from_millis(400));
    mgr.connect(addr).await;
    let waited = node.await.unwrap().expect("client never closed the connection to a silent peer");
    assert!(waited >= Duration::from_millis(300), "closed too early: {waited:?}");
    assert!(waited < Duration::from_secs(3), "closed too late: {waited:?}");
    assert_eq!(mgr.peers().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_sends_verack_is_dropped_too() {
    let (addr, node) = stalling_node("devnet", true).await;
    let (mgr, _shutdown) = client("devnet", None);
    mgr.set_handshake_timeout(Duration::from_millis(400));
    mgr.connect(addr).await;
    let waited = node.await.unwrap().expect("client never closed the half-open handshake");
    assert!(waited < Duration::from_secs(3), "closed too late: {waited:?}");
    assert_eq!(mgr.peers().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_handshake_timeout_is_five_seconds() {
    assert_eq!(filament_p2p::peer_manager::HANDSHAKE_TIMEOUT, Duration::from_secs(5));
}
