//! Dial a ShishaNet peer and report whether the light-client handshake completes.
//!
//! ```bash
//! cargo run -p filament-p2p --example handshake_probe -- 127.0.0.1:18334 devnet
//! ```

use std::sync::Arc;
use std::time::Duration;

use filament_p2p::{Capabilities, PeerManager, ShishaProtocol, NODE_LIGHT};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(target) = args.next() else {
        eprintln!("usage: handshake_probe <host:port> [network]");
        std::process::exit(2);
    };
    let network = args.next().unwrap_or_else(|| "devnet".into());
    let addr: std::net::SocketAddr = match target.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bad host:port {target}: {e}");
            std::process::exit(2);
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let caps = Capabilities {
        services: NODE_LIGHT,
        user_agent: "/Filament-handshake-probe:0.1/".into(),
        beacon_height: 0,
        shard_heights: vec![],
        nonce: rand::random(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
    };
    let protocol = ShishaProtocol::new(network.clone());
    let mgr = PeerManager::new(
        protocol,
        caps,
        "127.0.0.1:0".parse().unwrap(),
        4,
        shutdown_rx,
    );
    let run = Arc::clone(&mgr);
    tokio::spawn(async move {
        run.run().await;
    });
    let _ = tokio::time::timeout(Duration::from_secs(2), mgr.listen_addr()).await;

    eprintln!("dialing {addr} on network={network} (magic={:#010x}) …", mgr.protocol().magic());
    mgr.connect(addr).await;

    for _ in 0..50 {
        if mgr.peers().len() >= 1 {
            eprintln!("handshake OK");
            let _ = shutdown_tx.send(());
            std::process::exit(0);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("handshake FAILED — refused, wrong magic/network, or port closed");
    let _ = shutdown_tx.send(());
    std::process::exit(1);
}
