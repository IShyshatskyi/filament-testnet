// filament-p2p/src/peer_manager.rs — minimal ShishaNet client connection
// manager: dial, handshake, send, and dispatch the handful of inbound
// message types Filament (a light client) actually needs. This is NOT the
// real PeerManager — no inbound listener sync engine, no mempool/DoS/addr
// book machinery, no reorg/orphan handling. It exists to let Filament dial
// out to Keystones, register WatchAddress, and receive
// TxInclusionNotif/TxSpentNotif/TxRevertNotif.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex, Notify, RwLock};

use crate::framing::{frame, magic_for_network, try_decode};
use crate::messages::{
    NetAddr, ShishaMessage, VersionMessage, GENESIS_HASH_LEN, MIN_ACCEPTED_VERSION, UNKNOWN_GENESIS_HASH,
    WIRE_VERSION,
};

/// A peer must finish the version/verack exchange within this long, or the
/// connection is dropped (the full node uses the same 5 s).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Dialing gives up after this long.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub const NODE_NETWORK: u64 = 1 << 0;
pub const NODE_LIGHT: u64 = 1 << 1;

#[derive(Clone, Debug)]
pub struct Capabilities {
    pub services: u64,
    pub user_agent: String,
    pub beacon_height: u32,
    pub shard_heights: Vec<(u16, u64)>,
    pub nonce: u64,
    pub listen_addr: SocketAddr,
}

/// Inbound full-node → light-client notification decoded from the wire.
#[derive(Debug, Clone)]
pub enum LightClientInboundNotif {
    Inclusion {
        shard_id: u16,
        height: u32,
        output_idx: u16,
        value_atoms: u64,
        address: [u8; 32],
        mmr_proof_bytes: Vec<u8>,
    },
    Spent { shard_id: u16, spend_height: u32, output_height: u32, output_idx: u16 },
    Revert { shard_id: u16, height: u32, output_idx: u16 },
}

type PeerId = u64;

struct PeerHandle {
    tx: mpsc::UnboundedSender<ShishaMessage>,
}

/// Handshake and framing for one network: the network name fixes the frame
/// magic, and an optional genesis hash fixes the chain.
///
/// Every outbound connection advertises the current wire version; a peer on
/// an older one is refused (see `check_peer_version`).
#[derive(Clone)]
pub struct ShishaProtocol {
    pub network: String,
    magic: u32,
    genesis_hash: [u8; GENESIS_HASH_LEN],
}

impl ShishaProtocol {
    pub fn new(network: String) -> Self {
        let magic = magic_for_network(&network);
        Self { network, magic, genesis_hash: UNKNOWN_GENESIS_HASH }
    }

    /// Pin the chain this client belongs to. A peer that advertises a
    /// different, non-zero genesis hash is refused at the handshake. Without
    /// this the client advertises "unknown" and accepts any chain on its
    /// network.
    pub fn with_genesis_hash(mut self, genesis_hash: [u8; GENESIS_HASH_LEN]) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    pub fn magic(&self) -> u32 {
        self.magic
    }

    pub fn genesis_hash(&self) -> [u8; GENESIS_HASH_LEN] {
        self.genesis_hash
    }

    /// Build the `WatchAddress` message a light client sends to register
    /// interest in an address.
    pub fn build_watch_address(&self, address: [u8; 32], shard_id: u16) -> ShishaMessage {
        ShishaMessage::WatchAddress { address, shard_id }
    }

    /// Decide whether to keep talking to a peer from its `version` message.
    /// Returns the wire version both sides will use (`min(ours, theirs)`).
    ///
    /// Refused: a peer older than `MIN_ACCEPTED_VERSION`, and a peer whose
    /// non-zero genesis hash differs from ours. All-zero on either side means
    /// "unknown" and is never compared.
    pub fn check_peer_version(&self, theirs: &VersionMessage) -> Result<u32, String> {
        if theirs.version < MIN_ACCEPTED_VERSION {
            return Err(format!(
                "peer wire version {} is older than the minimum {}",
                theirs.version, MIN_ACCEPTED_VERSION
            ));
        }
        let ours = self.genesis_hash;
        let other = theirs.genesis_hash;
        if ours != UNKNOWN_GENESIS_HASH && other != UNKNOWN_GENESIS_HASH && ours != other {
            return Err(format!(
                "genesis mismatch: peer is on a different chain (ours {}, theirs {})",
                hex8(&ours),
                hex8(&other)
            ));
        }
        Ok(theirs.version.min(WIRE_VERSION))
    }
}

fn hex8(bytes: &[u8; GENESIS_HASH_LEN]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

pub struct PeerManager {
    protocol: ShishaProtocol,
    caps: Capabilities,
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    peer_count: AtomicU64,
    next_peer_id: AtomicU64,
    notif_handler: StdRwLock<Option<Arc<dyn Fn(LightClientInboundNotif) + Send + Sync>>>,
    shutdown_rx: watch::Receiver<()>,
    listen_addr: Mutex<Option<SocketAddr>>,
    listen_addr_notify: Notify,
    backlog: usize,
    handshake_timeout_ms: AtomicU64,
}

/// Read-only view of the connected-peer count and bookkeeping — mirrors the
/// `mgr.peers.len()` access pattern used by the real `PeerManager`.
pub struct PeerCountView<'a>(&'a PeerManager);

impl<'a> PeerCountView<'a> {
    pub fn len(&self) -> usize {
        self.0.peer_count.load(Ordering::Relaxed) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PeerManager {
    pub fn new(
        protocol: ShishaProtocol,
        caps: Capabilities,
        _listen_addr_hint: SocketAddr,
        backlog: usize,
        shutdown_rx: watch::Receiver<()>,
    ) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            caps,
            peers: RwLock::new(HashMap::new()),
            peer_count: AtomicU64::new(0),
            next_peer_id: AtomicU64::new(1),
            notif_handler: StdRwLock::new(None),
            shutdown_rx,
            listen_addr: Mutex::new(None),
            listen_addr_notify: Notify::new(),
            backlog,
            handshake_timeout_ms: AtomicU64::new(HANDSHAKE_TIMEOUT.as_millis() as u64),
        })
    }

    /// Override [`HANDSHAKE_TIMEOUT`] (tests, slow links).
    pub fn set_handshake_timeout(&self, timeout: Duration) {
        self.handshake_timeout_ms.store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn protocol(&self) -> &ShishaProtocol {
        &self.protocol
    }

    pub fn peers(&self) -> PeerCountView<'_> {
        PeerCountView(self)
    }

    pub fn set_light_client_notif_handler(
        &self,
        handler: Arc<dyn Fn(LightClientInboundNotif) + Send + Sync>,
    ) {
        *self.notif_handler.write().unwrap() = Some(handler);
    }

    /// Test helper: feed a decoded message through the inbound notif path
    /// without a live TCP peer (synthetic peer id).
    pub async fn inject_message_for_test(self: &Arc<Self>, msg: ShishaMessage) {
        self.dispatch_inbound(u64::MAX, msg).await;
    }

    /// Resolves once the listener has bound (immediately if `run()` hasn't
    /// started a real listener — a light client mostly dials out, so a bind
    /// failure here is non-fatal to outbound connectivity).
    pub async fn listen_addr(&self) -> SocketAddr {
        loop {
            if let Some(addr) = *self.listen_addr.lock().await {
                return addr;
            }
            self.listen_addr_notify.notified().await;
        }
    }

    /// Bind the listener (best-effort — a light client's real traffic is
    /// outbound) and run until the shutdown signal fires.
    pub async fn run(self: Arc<Self>) {
        let hint = self.caps.listen_addr;
        match tokio::net::TcpListener::bind(hint).await {
            Ok(listener) => {
                let bound = listener.local_addr().unwrap_or(hint);
                *self.listen_addr.lock().await = Some(bound);
                self.listen_addr_notify.notify_waiters();

                let mut shutdown = self.shutdown_rx.clone();
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        accepted = listener.accept() => {
                            if let Ok((stream, addr)) = accepted {
                                if self.peers().len() >= self.backlog {
                                    continue;
                                }
                                let this = Arc::clone(&self);
                                tokio::spawn(async move {
                                    if let Err(e) = this.handle_connection(stream, addr, true).await {
                                        log::warn!("filament-p2p: connection from {addr} closed: {e}");
                                    }
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("filament-p2p: listener bind failed ({e}) — outbound-only mode");
                *self.listen_addr.lock().await = Some(hint);
                self.listen_addr_notify.notify_waiters();
                let mut shutdown = self.shutdown_rx.clone();
                let _ = shutdown.changed().await;
            }
        }
    }

    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) {
        let dialed = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")),
        };
        match dialed {
            Ok(stream) => {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    if let Err(e) = this.handle_connection(stream, addr, false).await {
                        log::warn!("filament-p2p: connection to {addr} closed: {e}");
                    }
                });
            }
            Err(e) => log::warn!("filament-p2p: connect to {addr} failed: {e}"),
        }
    }

    pub fn send_to_all_peers(self: &Arc<Self>, msg: ShishaMessage) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let peers = this.peers.read().await;
            for handle in peers.values() {
                let _ = handle.tx.send(msg.clone());
            }
        });
    }

    async fn handle_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
        inbound: bool,
    ) -> Result<(), String> {
        let magic = self.protocol.magic();

        let limit = Duration::from_millis(self.handshake_timeout_ms.load(Ordering::Relaxed));
        let buf = match tokio::time::timeout(limit, self.handshake(&mut stream, addr, inbound, magic)).await {
            Ok(r) => r?,
            Err(_) => return Err(format!("handshake timed out after {limit:?}")),
        };

        // Handshake complete — register the peer and run the steady-state loop.
        let peer_id = self.next_peer_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::unbounded_channel::<ShishaMessage>();
        self.peers.write().await.insert(peer_id, PeerHandle { tx });
        self.peer_count.fetch_add(1, Ordering::Relaxed);
        log::info!("filament-p2p: handshake complete with {addr} (peer_id={peer_id})");

        let (mut read_half, mut write_half) = stream.into_split();
        let mut shutdown = self.shutdown_rx.clone();

        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let bytes = frame(magic, msg.command(), &msg.encode());
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });

        let this = Arc::clone(self);
        let mut leftover = buf;
        let read_result: Result<(), String> = async {
            let mut rb = [0u8; 8192];
            loop {
                // Frames already buffered (read together with the handshake)
                // are delivered before blocking on the socket again.
                while let Some((raw, consumed)) = try_decode(magic, &leftover)? {
                    let msg = ShishaMessage::decode(&raw.command, &raw.payload)?;
                    leftover.drain(..consumed);
                    this.dispatch_inbound(peer_id, msg).await;
                }
                let n = read_half.read(&mut rb).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(());
                }
                leftover.extend_from_slice(&rb[..n]);
            }
        }
        .await;

        tokio::select! {
            _ = shutdown.changed() => {}
            _ = async { read_result } => {}
        }

        self.peers.write().await.remove(&peer_id);
        self.peer_count.fetch_sub(1, Ordering::Relaxed);
        write_task.abort();
        Ok(())
    }

    async fn dispatch_inbound(&self, peer_id: PeerId, msg: ShishaMessage) {
        let notif = match msg {
            ShishaMessage::Ping { nonce } => {
                if let Some(handle) = self.peers.read().await.get(&peer_id) {
                    let _ = handle.tx.send(ShishaMessage::Pong { nonce });
                }
                return;
            }
            ShishaMessage::TxInclusionNotif { shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes } => {
                LightClientInboundNotif::Inclusion { shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes }
            }
            ShishaMessage::TxSpentNotif { shard_id, spend_height, output_height, output_idx } => {
                LightClientInboundNotif::Spent { shard_id, spend_height, output_height, output_idx }
            }
            ShishaMessage::TxRevertNotif { shard_id, height, output_idx } => {
                LightClientInboundNotif::Revert { shard_id, height, output_idx }
            }
            _ => return,
        };

        let handler = self.notif_handler.read().unwrap().clone();
        if let Some(handler) = handler {
            handler(notif);
        }
    }

    /// Version/verack exchange. Returns the bytes read past the handshake:
    /// they may already hold complete frames (a node pushes right behind its
    /// `verack`), so nothing after the handshake is consumed here.
    async fn handshake(
        &self,
        stream: &mut TcpStream,
        addr: SocketAddr,
        inbound: bool,
        magic: u32,
    ) -> Result<Vec<u8>, String> {
        let our_nonce = self.caps.nonce;

        // Outbound: send Version first. Inbound: wait for theirs first.
        if !inbound {
            let v = self.build_version_msg(addr);
            self.write_frame(stream, &v).await?;
        }

        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut read_buf = [0u8; 4096];
        let mut got_version = false;
        let mut got_verack = false;
        let mut sent_verack = false;

        while !(got_version && got_verack) {
            let n = stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("handshake read: {e}"))?;
            if n == 0 {
                return Err("connection closed during handshake".into());
            }
            buf.extend_from_slice(&read_buf[..n]);

            // Stop as soon as both halves are in: anything behind the verack is
            // regular traffic and stays in `buf` for the caller.
            while !(got_version && got_verack) {
                let Some((raw, consumed)) = try_decode(magic, &buf).map_err(|e| format!("handshake decode: {e}"))? else {
                    break;
                };
                let msg = ShishaMessage::decode(&raw.command, &raw.payload).map_err(|e| format!("handshake parse: {e}"))?;
                buf.drain(..consumed);

                match msg {
                    ShishaMessage::Version(v) => {
                        if v.nonce == our_nonce {
                            return Err("self-connection".into());
                        }
                        self.protocol.check_peer_version(&v)?;
                        got_version = true;
                        if inbound {
                            let ours = self.build_version_msg(addr);
                            self.write_frame(stream, &ours).await?;
                        }
                        if !sent_verack {
                            self.write_frame(stream, &ShishaMessage::VerAck).await?;
                            sent_verack = true;
                        }
                    }
                    ShishaMessage::VerAck => {
                        got_verack = true;
                    }
                    _ => {
                        // Anything else this early is out of scope — ignore.
                    }
                }
            }
        }

        Ok(buf)
    }

    fn build_version_msg(&self, their_addr: SocketAddr) -> ShishaMessage {
        let mut v = VersionMessage::new(
            WIRE_VERSION,
            self.caps.services,
            self.caps.nonce,
            NetAddr::from_socket_addr(their_addr, 0),
            NetAddr::from_socket_addr(self.caps.listen_addr, self.caps.services),
        );
        v.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        v.user_agent = self.caps.user_agent.clone();
        v.beacon_height = self.caps.beacon_height;
        v.shard_heights = self.caps.shard_heights.clone();
        v.genesis_hash = self.protocol.genesis_hash();
        ShishaMessage::Version(v)
    }

    async fn write_frame(&self, stream: &mut TcpStream, msg: &ShishaMessage) -> Result<(), String> {
        let bytes = frame(self.protocol.magic(), msg.command(), &msg.encode());
        stream.write_all(&bytes).await.map_err(|e| e.to_string())
    }
}

