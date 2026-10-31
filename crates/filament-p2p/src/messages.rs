// filament-p2p/src/messages.rs — the ShishaNet message subset Filament
// actually uses: handshake (Version/VerAck/Ping/Pong) + the Path-2
// light-client notification messages (WatchAddress out; TxInclusionNotif/
// TxSpentNotif/TxRevertNotif in). Every other real ShishaNet message type
// (sync, mempool, relay, compact blocks, ...) is intentionally not modelled
// — see `PeerManager::run`'s doc comment for how unknown commands are
// handled on receipt (skipped, not an error).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const NET_ADDR_SIZE: usize = 26;
const MAX_SHARDS: usize = 1024;

/// Wire version this client advertises. Both sides then speak
/// `min(ours, theirs)`.
pub const WIRE_VERSION: u32 = 17;

/// Oldest peer wire version this client talks to. Nodes refuse anything older
/// than this themselves, so a lower number here would only delay the failure.
pub const MIN_ACCEPTED_VERSION: u32 = 15;

/// Size of the genesis-hash trailer (wire version 11 and later).
pub const GENESIS_HASH_LEN: usize = 32;

/// Size of the shard-subscription bitmask (wire version 8 and later).
pub const SUBSCRIPTION_MASK_LEN: usize = 128;

/// "Unknown / not checked" chain identity. A light client that does not know
/// its network's genesis hash sends this; it is never compared against.
pub const UNKNOWN_GENESIS_HASH: [u8; GENESIS_HASH_LEN] = [0u8; GENESIS_HASH_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetAddr {
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
}

impl NetAddr {
    pub fn from_socket_addr(addr: SocketAddr, services: u64) -> Self {
        let mut ip = [0u8; 16];
        match addr.ip() {
            IpAddr::V4(v4) => {
                ip[10] = 0xff;
                ip[11] = 0xff;
                ip[12..16].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => ip = v6.octets(),
        }
        Self { services, ip, port: addr.port() }
    }

    #[allow(dead_code)]
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        let port = self.port;
        if self.ip[..10].iter().all(|&b| b == 0) && self.ip[10] == 0xff && self.ip[11] == 0xff {
            let octets: [u8; 4] = self.ip[12..16].try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        } else {
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(self.ip)), port))
        }
    }

    pub fn to_bytes(&self) -> [u8; NET_ADDR_SIZE] {
        let mut buf = [0u8; NET_ADDR_SIZE];
        buf[0..8].copy_from_slice(&self.services.to_le_bytes());
        buf[8..24].copy_from_slice(&self.ip);
        buf[24..26].copy_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn from_bytes(src: &[u8; NET_ADDR_SIZE]) -> Self {
        Self {
            services: u64::from_le_bytes(src[0..8].try_into().unwrap()),
            ip: src[8..24].try_into().unwrap(),
            port: u16::from_be_bytes(src[24..26].try_into().unwrap()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub addr_recv: NetAddr,
    pub addr_from: NetAddr,
    pub nonce: u64,
    pub user_agent: String,
    pub beacon_height: u32,
    pub shard_heights: Vec<(u16, u64)>,
    /// v4+: highest beacon header the sender has cached (0 = none).
    pub beacon_cache_height: u32,
    /// v4+: per-shard header cache heights.
    pub shard_cache_heights: Vec<(u16, u32)>,
    /// v4+: lowest beacon height the sender serves from warm storage (0 = all).
    pub beacon_serve_from: u32,
    /// v4+: per-shard warm-storage floors.
    pub shard_serve_from: Vec<(u16, u32)>,
    /// v8+: bitset of shard ids the sender tracks. All-zero = "accepts all".
    pub subscription_mask: [u8; SUBSCRIPTION_MASK_LEN],
    /// v11+: the sender's beacon genesis block hash, or all-zero when unknown.
    pub genesis_hash: [u8; GENESIS_HASH_LEN],
    /// v16+: optional beacon tip identity (light clients usually leave None).
    pub beacon_tip: Option<crate::tip_identity::ChainTipIdentity>,
    /// v16+: per-shard tip identities.
    pub shard_tips: Vec<(u16, crate::tip_identity::ChainTipIdentity)>,
    /// v17+: optional packed WireBeaconHeader (150 B); light clients leave None.
    pub beacon_tip_header: Option<Vec<u8>>,
    /// v17+: per-shard packed LightShardHeader (136 B each).
    pub shard_tip_headers: Vec<(u16, Vec<u8>)>,
}

impl VersionMessage {
    /// A message with every optional field empty. Tests and callers fill in
    /// what they know.
    pub fn new(version: u32, services: u64, nonce: u64, addr_recv: NetAddr, addr_from: NetAddr) -> Self {
        Self {
            version,
            services,
            timestamp: 0,
            addr_recv,
            addr_from,
            nonce,
            user_agent: String::new(),
            beacon_height: 0,
            shard_heights: Vec::new(),
            beacon_cache_height: 0,
            shard_cache_heights: Vec::new(),
            beacon_serve_from: 0,
            shard_serve_from: Vec::new(),
            subscription_mask: [0u8; SUBSCRIPTION_MASK_LEN],
            genesis_hash: UNKNOWN_GENESIS_HASH,
            beacon_tip: None,
            shard_tips: Vec::new(),
            beacon_tip_header: None,
            shard_tip_headers: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let ua = self.user_agent.as_bytes();
        let v4 = self.version >= 4;
        let mut buf = Vec::with_capacity(
            4 + 8 + 8 + NET_ADDR_SIZE * 2 + 8 + varint_len(ua.len() as u64) + ua.len() + 4 + 2
                + self.shard_heights.len() * 10
                + if v4 { 12 + (self.shard_cache_heights.len() + self.shard_serve_from.len()) * 6 } else { 0 }
                + if self.version >= 8 { SUBSCRIPTION_MASK_LEN } else { 0 }
                + if self.version >= 11 { GENESIS_HASH_LEN } else { 0 },
        );
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.addr_recv.to_bytes());
        buf.extend_from_slice(&self.addr_from.to_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        write_varint(&mut buf, ua.len() as u64);
        buf.extend_from_slice(ua);
        buf.extend_from_slice(&self.beacon_height.to_le_bytes());
        buf.extend_from_slice(&(self.shard_heights.len() as u16).to_le_bytes());
        for &(id, h) in &self.shard_heights {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&h.to_le_bytes());
        }
        if v4 {
            buf.extend_from_slice(&self.beacon_cache_height.to_le_bytes());
            buf.extend_from_slice(&(self.shard_cache_heights.len() as u16).to_le_bytes());
            for &(id, h) in &self.shard_cache_heights {
                buf.extend_from_slice(&id.to_le_bytes());
                buf.extend_from_slice(&h.to_le_bytes());
            }
            buf.extend_from_slice(&self.beacon_serve_from.to_le_bytes());
            buf.extend_from_slice(&(self.shard_serve_from.len() as u16).to_le_bytes());
            for &(id, h) in &self.shard_serve_from {
                buf.extend_from_slice(&id.to_le_bytes());
                buf.extend_from_slice(&h.to_le_bytes());
            }
        }
        if self.version >= 8 {
            buf.extend_from_slice(&self.subscription_mask);
        }
        if self.version >= 11 {
            buf.extend_from_slice(&self.genesis_hash);
        }
        if self.version >= 16 {
            use crate::tip_identity::ChainTipIdentity;
            let mut flags = 0u8;
            if self.beacon_tip.is_some() {
                flags |= 1;
            }
            buf.push(flags);
            if let Some(tip) = &self.beacon_tip {
                buf.extend_from_slice(&tip.encode());
            }
            buf.extend_from_slice(&(self.shard_tips.len() as u16).to_le_bytes());
            for &(id, tip) in &self.shard_tips {
                buf.extend_from_slice(&id.to_le_bytes());
                buf.extend_from_slice(&tip.encode());
                let _ = ChainTipIdentity::WIRE_LEN;
            }
        }
        if self.version >= 17 {
            const BEACON_HDR: usize = 150;
            const SHARD_HDR: usize = 136;
            let mut flags = 0u8;
            if self.beacon_tip_header.as_ref().map(|h| h.len() == BEACON_HDR) == Some(true) {
                flags |= 1;
            }
            buf.push(flags);
            if flags & 1 != 0 {
                buf.extend_from_slice(self.beacon_tip_header.as_ref().unwrap());
            }
            buf.extend_from_slice(&(self.shard_tip_headers.len() as u16).to_le_bytes());
            for &(id, ref hdr) in &self.shard_tip_headers {
                buf.extend_from_slice(&id.to_le_bytes());
                let mut padded = vec![0u8; SHARD_HDR];
                let n = hdr.len().min(SHARD_HDR);
                padded[..n].copy_from_slice(&hdr[..n]);
                buf.extend_from_slice(&padded);
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut pos = 0usize;
        let version = read_u32(data, &mut pos)?;
        let services = read_u64(data, &mut pos)?;
        let timestamp = read_u64(data, &mut pos)?;
        let addr_recv = read_net_addr(data, &mut pos)?;
        let addr_from = read_net_addr(data, &mut pos)?;
        let nonce = read_u64(data, &mut pos)?;
        let user_agent = read_var_str(data, &mut pos)?;
        let beacon_height = read_u32(data, &mut pos)?;
        let shard_count = read_u16(data, &mut pos)? as usize;
        if shard_count > MAX_SHARDS {
            return Err(format!("shard_count {shard_count} exceeds MAX_SHARDS"));
        }
        let required = shard_count * 10;
        if data.len() < pos + required {
            return Err("truncated shard list".to_string());
        }
        let mut shard_heights = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shard_heights.push((read_u16(data, &mut pos)?, read_u64(data, &mut pos)?));
        }

        // Each trailer is optional: an older sender simply stops early, and a
        // receiver treats the missing part as empty / zero.
        let (beacon_cache_height, shard_cache_heights) = if version >= 4 && pos < data.len() {
            let height = read_u32(data, &mut pos)?;
            (height, read_height_list(data, &mut pos, "shard_cache_heights")?)
        } else {
            (0, Vec::new())
        };
        let (beacon_serve_from, shard_serve_from) = if version >= 4 && pos < data.len() {
            let floor = read_u32(data, &mut pos)?;
            (floor, read_height_list(data, &mut pos, "shard_serve_from")?)
        } else {
            (0, Vec::new())
        };
        let subscription_mask = if version >= 8 && pos + SUBSCRIPTION_MASK_LEN <= data.len() {
            let mut arr = [0u8; SUBSCRIPTION_MASK_LEN];
            arr.copy_from_slice(&data[pos..pos + SUBSCRIPTION_MASK_LEN]);
            pos += SUBSCRIPTION_MASK_LEN;
            arr
        } else {
            [0u8; SUBSCRIPTION_MASK_LEN]
        };
        let genesis_hash = if version >= 11 && pos + GENESIS_HASH_LEN <= data.len() {
            let mut arr = [0u8; GENESIS_HASH_LEN];
            arr.copy_from_slice(&data[pos..pos + GENESIS_HASH_LEN]);
            pos += GENESIS_HASH_LEN;
            arr
        } else {
            UNKNOWN_GENESIS_HASH
        };

        let (beacon_tip, shard_tips) = if version >= 16 && pos < data.len() {
            use crate::tip_identity::ChainTipIdentity;
            let flags = data[pos];
            pos += 1;
            let beacon_tip = if flags & 1 != 0 {
                if pos + ChainTipIdentity::WIRE_LEN > data.len() {
                    return Err("truncated beacon tip identity".into());
                }
                let tip = ChainTipIdentity::decode(&data[pos..pos + ChainTipIdentity::WIRE_LEN])?;
                pos += ChainTipIdentity::WIRE_LEN;
                Some(tip)
            } else {
                None
            };
            let n = read_u16(data, &mut pos)? as usize;
            if n > MAX_SHARDS {
                return Err("shard tip count too large".into());
            }
            let mut shard_tips = Vec::with_capacity(n);
            for _ in 0..n {
                let id = read_u16(data, &mut pos)?;
                if pos + ChainTipIdentity::WIRE_LEN > data.len() {
                    return Err("truncated shard tip identity".into());
                }
                let tip = ChainTipIdentity::decode(&data[pos..pos + ChainTipIdentity::WIRE_LEN])?;
                pos += ChainTipIdentity::WIRE_LEN;
                shard_tips.push((id, tip));
            }
            (beacon_tip, shard_tips)
        } else {
            (None, Vec::new())
        };

        let (beacon_tip_header, shard_tip_headers) = if version >= 17 && pos < data.len() {
            const BEACON_HDR: usize = 150;
            const SHARD_HDR: usize = 136;
            let flags = data[pos];
            pos += 1;
            let beacon_tip_header = if flags & 1 != 0 {
                if pos + BEACON_HDR > data.len() {
                    return Err("truncated beacon tip header".into());
                }
                let hdr = data[pos..pos + BEACON_HDR].to_vec();
                pos += BEACON_HDR;
                Some(hdr)
            } else {
                None
            };
            let n = read_u16(data, &mut pos)? as usize;
            if n > MAX_SHARDS {
                return Err("shard tip header count too large".into());
            }
            let mut shard_tip_headers = Vec::with_capacity(n);
            for _ in 0..n {
                let id = read_u16(data, &mut pos)?;
                if pos + SHARD_HDR > data.len() {
                    return Err("truncated shard tip header".into());
                }
                let hdr = data[pos..pos + SHARD_HDR].to_vec();
                pos += SHARD_HDR;
                shard_tip_headers.push((id, hdr));
            }
            (beacon_tip_header, shard_tip_headers)
        } else {
            (None, Vec::new())
        };
        let _ = pos;

        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            beacon_height,
            shard_heights,
            beacon_cache_height,
            shard_cache_heights,
            beacon_serve_from,
            shard_serve_from,
            subscription_mask,
            genesis_hash,
            beacon_tip,
            shard_tips,
            beacon_tip_header,
            shard_tip_headers,
        })
    }
}

/// `count(u16 LE)` then `count` entries of `(id: u16 LE, height: u32 LE)`.
fn read_height_list(data: &[u8], pos: &mut usize, what: &str) -> Result<Vec<(u16, u32)>, String> {
    let count = read_u16(data, pos)? as usize;
    if count > MAX_SHARDS {
        return Err(format!("{what} count {count} exceeds MAX_SHARDS"));
    }
    if data.len() < *pos + count * 6 {
        return Err(format!("truncated {what}"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push((read_u16(data, pos)?, read_u32(data, pos)?));
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub enum ShishaMessage {
    Version(VersionMessage),
    VerAck,
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    WatchAddress { address: [u8; 32], shard_id: u16 },
    TxInclusionNotif {
        shard_id: u16,
        height: u32,
        output_idx: u16,
        value_atoms: u64,
        address: [u8; 32],
        mmr_proof_bytes: Vec<u8>,
    },
    TxSpentNotif { shard_id: u16, spend_height: u32, output_height: u32, output_idx: u16 },
    TxRevertNotif { shard_id: u16, height: u32, output_idx: u16 },
    /// Any message type this client doesn't model — carried through so the
    /// read loop can log/ignore it instead of erroring the connection.
    Unknown { command: String },
}

impl ShishaMessage {
    pub fn command(&self) -> &str {
        match self {
            Self::Version(_) => "version",
            Self::VerAck => "verack",
            Self::Ping { .. } => "ping",
            Self::Pong { .. } => "pong",
            Self::WatchAddress { .. } => "watchaddress",
            Self::TxInclusionNotif { .. } => "txinclnotif",
            Self::TxSpentNotif { .. } => "txspentnotif",
            Self::TxRevertNotif { .. } => "txrevertntf",
            Self::Unknown { command } => command,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Version(v) => v.encode(),
            Self::VerAck => vec![],
            Self::Ping { nonce } | Self::Pong { nonce } => nonce.to_le_bytes().to_vec(),
            Self::WatchAddress { address, shard_id } => {
                let mut buf = Vec::with_capacity(34);
                buf.extend_from_slice(address);
                buf.extend_from_slice(&shard_id.to_le_bytes());
                buf
            }
            Self::TxInclusionNotif { shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes } => {
                let mut buf = Vec::with_capacity(52 + mmr_proof_bytes.len());
                buf.extend_from_slice(&shard_id.to_le_bytes());
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&output_idx.to_le_bytes());
                buf.extend_from_slice(&value_atoms.to_le_bytes());
                buf.extend_from_slice(address);
                buf.extend_from_slice(&(mmr_proof_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(mmr_proof_bytes);
                buf
            }
            Self::TxSpentNotif { shard_id, spend_height, output_height, output_idx } => {
                let mut buf = Vec::with_capacity(12);
                buf.extend_from_slice(&shard_id.to_le_bytes());
                buf.extend_from_slice(&spend_height.to_le_bytes());
                buf.extend_from_slice(&output_height.to_le_bytes());
                buf.extend_from_slice(&output_idx.to_le_bytes());
                buf
            }
            Self::TxRevertNotif { shard_id, height, output_idx } => {
                let mut buf = Vec::with_capacity(8);
                buf.extend_from_slice(&shard_id.to_le_bytes());
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&output_idx.to_le_bytes());
                buf
            }
            Self::Unknown { .. } => vec![],
        }
    }

    pub fn decode(command: &str, payload: &[u8]) -> Result<Self, String> {
        match command {
            "version" => Ok(Self::Version(VersionMessage::decode(payload)?)),
            "verack" => Ok(Self::VerAck),
            "ping" => Ok(Self::Ping { nonce: read_u64(payload, &mut 0)? }),
            "pong" => Ok(Self::Pong { nonce: read_u64(payload, &mut 0)? }),
            "watchaddress" => {
                if payload.len() < 34 {
                    return Err("watchaddress too short".to_string());
                }
                let address: [u8; 32] = payload[0..32].try_into().unwrap();
                let shard_id = u16::from_le_bytes(payload[32..34].try_into().unwrap());
                Ok(Self::WatchAddress { address, shard_id })
            }
            "txinclnotif" => {
                if payload.len() < 52 {
                    return Err("txinclnotif too short".to_string());
                }
                let shard_id = u16::from_le_bytes(payload[0..2].try_into().unwrap());
                let height = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                let output_idx = u16::from_le_bytes(payload[6..8].try_into().unwrap());
                let value_atoms = u64::from_le_bytes(payload[8..16].try_into().unwrap());
                let address: [u8; 32] = payload[16..48].try_into().unwrap();
                let proof_len = u32::from_le_bytes(payload[48..52].try_into().unwrap()) as usize;
                if payload.len() < 52 + proof_len {
                    return Err("txinclnotif proof truncated".to_string());
                }
                let mmr_proof_bytes = payload[52..52 + proof_len].to_vec();
                Ok(Self::TxInclusionNotif { shard_id, height, output_idx, value_atoms, address, mmr_proof_bytes })
            }
            "txspentnotif" => {
                if payload.len() < 12 {
                    return Err("txspentnotif too short".to_string());
                }
                let shard_id = u16::from_le_bytes(payload[0..2].try_into().unwrap());
                let spend_height = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                let output_height = u32::from_le_bytes(payload[6..10].try_into().unwrap());
                let output_idx = u16::from_le_bytes(payload[10..12].try_into().unwrap());
                Ok(Self::TxSpentNotif { shard_id, spend_height, output_height, output_idx })
            }
            "txrevertntf" => {
                if payload.len() < 8 {
                    return Err("txrevertntf too short".to_string());
                }
                let shard_id = u16::from_le_bytes(payload[0..2].try_into().unwrap());
                let height = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                let output_idx = u16::from_le_bytes(payload[6..8].try_into().unwrap());
                Ok(Self::TxRevertNotif { shard_id, height, output_idx })
            }
            other => Ok(Self::Unknown { command: other.to_string() }),
        }
    }
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, String> {
    let end = pos.checked_add(2).ok_or("overflow")?;
    if end > data.len() {
        return Err("truncated u16".into());
    }
    let v = u16::from_le_bytes(data[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    let end = pos.checked_add(4).ok_or("overflow")?;
    if end > data.len() {
        return Err("truncated u32".into());
    }
    let v = u32::from_le_bytes(data[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let end = pos.checked_add(8).ok_or("overflow")?;
    if end > data.len() {
        return Err("truncated u64".into());
    }
    let v = u64::from_le_bytes(data[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_net_addr(data: &[u8], pos: &mut usize) -> Result<NetAddr, String> {
    let end = pos.checked_add(NET_ADDR_SIZE).ok_or("overflow")?;
    if end > data.len() {
        return Err("truncated NetAddr".into());
    }
    let chunk: &[u8; NET_ADDR_SIZE] = data[*pos..end].try_into().unwrap();
    *pos = end;
    Ok(NetAddr::from_bytes(chunk))
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, String> {
    if *pos >= data.len() {
        return Err("truncated u8".into());
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    match read_u8(data, pos)? {
        0xff => read_u64(data, pos),
        0xfe => read_u32(data, pos).map(|v| v as u64),
        0xfd => read_u16(data, pos).map(|v| v as u64),
        v => Ok(v as u64),
    }
}

fn read_var_str(data: &[u8], pos: &mut usize) -> Result<String, String> {
    let len = read_varint(data, pos)? as usize;
    let end = pos.checked_add(len).ok_or("overflow")?;
    if end > data.len() {
        return Err("truncated VarStr".into());
    }
    let s = String::from_utf8(data[*pos..end].to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))?;
    *pos = end;
    Ok(s)
}

fn write_varint(buf: &mut Vec<u8>, v: u64) {
    match v {
        0..=0xfc => buf.push(v as u8),
        0xfd..=0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x10000..=0xffffffff => {
            buf.push(0xfe);
            buf.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            buf.push(0xff);
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
}

fn varint_len(v: u64) -> usize {
    match v {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffffffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: u32) -> VersionMessage {
        let mut v = VersionMessage::new(
            version,
            2,
            999,
            NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), 2),
        );
        v.timestamp = 123;
        v.user_agent = "/Filament:0.1.0/".into();
        v.beacon_height = 5;
        v.shard_heights = vec![(0, 10), (1, 20)];
        v.beacon_cache_height = 7;
        v.shard_cache_heights = vec![(0, 3), (1, 4)];
        v.beacon_serve_from = 2;
        v.shard_serve_from = vec![(1, 9)];
        v.subscription_mask[0] = 0b0000_0011;
        v.subscription_mask[127] = 0x80;
        v.genesis_hash = [0xAB; GENESIS_HASH_LEN];
        v
    }

    #[test]
    fn current_version_roundtrips_with_every_trailer() {
        let v = sample(WIRE_VERSION);
        assert_eq!(VersionMessage::decode(&v.encode()).unwrap(), v);
    }

    #[test]
    fn older_versions_omit_the_trailers_they_do_not_have() {
        // v3: nothing after the shard list. v7: no mask or genesis hash.
        // v10: no genesis hash.
        let full = sample(WIRE_VERSION).encode();
        let v3 = sample(3).encode();
        let v7 = sample(7).encode();
        let v10 = sample(10).encode();
        let shard_list_end = 4 + 8 + 8 + 2 * NET_ADDR_SIZE + 8 + 1 + 16 + 4 + 2 + 2 * 10;
        assert_eq!(v3.len(), shard_list_end);
        assert_eq!(v7.len(), shard_list_end + (4 + 2 + 2 * 6) + (4 + 2 + 6));
        assert_eq!(v10.len(), v7.len() + SUBSCRIPTION_MASK_LEN);
        // v11 genesis + empty v16 tip trailer (1+2) + empty v17 header trailer (1+2)
        assert_eq!(full.len(), v10.len() + GENESIS_HASH_LEN + 3 + 3);

        let d3 = VersionMessage::decode(&v3).unwrap();
        assert!(d3.shard_cache_heights.is_empty() && d3.genesis_hash == UNKNOWN_GENESIS_HASH);
        let d10 = VersionMessage::decode(&v10).unwrap();
        assert_eq!(d10.subscription_mask[127], 0x80);
        assert_eq!(d10.genesis_hash, UNKNOWN_GENESIS_HASH, "no genesis hash before v11");
    }

    #[test]
    fn trailing_bytes_of_a_later_version_are_ignored() {
        let v = sample(WIRE_VERSION);
        let mut bytes = v.encode();
        bytes.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(VersionMessage::decode(&bytes).unwrap(), v);
    }

    #[test]
    fn truncated_trailers_are_errors_not_panics() {
        let bytes = sample(WIRE_VERSION).encode();
        // Cut inside the cache list: a count that promises more than remains.
        let cut = 4 + 8 + 8 + 2 * NET_ADDR_SIZE + 8 + 1 + 16 + 4 + 2 + 2 * 10 + 4 + 2 + 3;
        assert!(VersionMessage::decode(&bytes[..cut]).is_err());
    }

    #[test]
    fn watch_address_roundtrips() {
        let msg = ShishaMessage::WatchAddress { address: [0xDDu8; 32], shard_id: 3 };
        let bytes = msg.encode();
        match ShishaMessage::decode("watchaddress", &bytes).unwrap() {
            ShishaMessage::WatchAddress { address, shard_id } => {
                assert_eq!(address, [0xDDu8; 32]);
                assert_eq!(shard_id, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tx_inclusion_notif_roundtrips() {
        let msg = ShishaMessage::TxInclusionNotif {
            shard_id: 1,
            height: 42,
            output_idx: 0,
            value_atoms: 100_000_000,
            address: [7u8; 32],
            mmr_proof_bytes: vec![1, 2, 3, 4, 5],
        };
        let bytes = msg.encode();
        match ShishaMessage::decode("txinclnotif", &bytes).unwrap() {
            ShishaMessage::TxInclusionNotif { height, value_atoms, mmr_proof_bytes, .. } => {
                assert_eq!(height, 42);
                assert_eq!(value_atoms, 100_000_000);
                assert_eq!(mmr_proof_bytes, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_command_does_not_error() {
        let m = ShishaMessage::decode("someothertype", &[1, 2, 3]).unwrap();
        assert_eq!(m.command(), "someothertype");
    }
}
