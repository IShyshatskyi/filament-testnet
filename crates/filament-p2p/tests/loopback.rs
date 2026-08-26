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
