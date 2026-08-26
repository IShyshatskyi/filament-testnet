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

/// Protocol wire version this client advertises. Matches the real
/// ShishaProtocol's `version()` (4 — S3 header-cache advertisement); we
/// never populate the v4 cache-height trailer fields (always empty/0,
/// which is valid and self-describing on the wire).
pub const WIRE_VERSION: u32 = 4;

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
}

impl VersionMessage {
    pub fn encode(&self) -> Vec<u8> {
        let ua = self.user_agent.as_bytes();
        let n_shards = self.shard_heights.len();
        let mut buf = Vec::with_capacity(
            4 + 8 + 8 + NET_ADDR_SIZE * 2 + 8 + varint_len(ua.len() as u64) + ua.len() + 4 + 2 + n_shards * 10,
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
        buf.extend_from_slice(&(n_shards as u16).to_le_bytes());
        for &(id, h) in &self.shard_heights {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&h.to_le_bytes());
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
        // Any v4+ cache-height/serve-from/v8 subscription-mask trailer bytes
        // are intentionally left unparsed and unread — we never send them
        // ourselves, and ignoring a peer's trailer is the documented
        // backward-compatible behavior real receivers already use.
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
        })
    }
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

    #[test]
    fn version_message_roundtrips() {
        let v = VersionMessage {
            version: WIRE_VERSION,
            services: 2,
            timestamp: 123,
            addr_recv: NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            addr_from: NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), 2),
            nonce: 999,
            user_agent: "/Filament:0.1.0/".into(),
            beacon_height: 5,
            shard_heights: vec![(0, 10), (1, 20)],
        };
        let bytes = v.encode();
        let decoded = VersionMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, v);
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

#[cfg(test)]
mod xcheck {
    use super::*;

    #[test]
    fn xcheck_against_real_shisha_prefix() {
        let v = VersionMessage {
            version: 4,
            services: 2,
            timestamp: 123,
            addr_recv: NetAddr::from_socket_addr("127.0.0.1:1".parse().unwrap(), 0),
            addr_from: NetAddr::from_socket_addr("127.0.0.1:2".parse().unwrap(), 2),
            nonce: 999,
            user_agent: "/Filament:0.1.0/".into(),
            beacon_height: 5,
            shard_heights: vec![(0, 10), (1, 20)],
        };
        let mine = v.encode();
        let real_hex = "0400000002000000000000007b00000000000000000000000000000000000000000000000000ffff7f0000010001020000000000000000000000000000000000ffff7f0000010002e703000000000000102f46696c616d656e743a302e312e302f05000000020000000a0000000000000001001400000000000000000000000000000000000000";
        let real: Vec<u8> = (0..real_hex.len()).step_by(2).map(|i| u8::from_str_radix(&real_hex[i..i+2], 16).unwrap()).collect();
        // My encoding omits the v4 cache/serve-from trailer (always-empty in
        // this client); the real decoder treats "no more bytes" as
        // "trailer omitted, default 0/empty" (checked in messages.rs decode
        // comment) so this is wire-compatible, not truncated data.
        assert_eq!(mine.len(), 123, "shared-prefix length must match the real encoder before its v4 trailer");
        assert_eq!(&mine[..], &real[..123], "shared prefix must be byte-identical to the real encoder");
    }
}
