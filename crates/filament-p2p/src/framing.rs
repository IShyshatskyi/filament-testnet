// filament-p2p/src/framing.rs — ShishaNet wire framing.
//
// 24-byte header: magic(4) | command(12, NUL-padded) | length(4 LE) |
// checksum(4, BLAKE3(payload)[0..4]) | payload.
//
// The magic identifies the network, not the protocol: every network has its
// own four bytes, and a receiver drops a connection on the first frame whose
// magic differs from its own. See `magic_for_network`.

pub const HEADER_SIZE: usize = 24;
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

/// The four magic bytes for `network`, in the order they appear on the wire.
///
/// Named networks use `SH` plus a two-letter tag:
/// `mainnet` `SHMN`, `testnet1` `SHT1`, `testnet2` `SHT2`, `devnet` `SHDV`,
/// `testnet-stress` `SHTS`. Any other name gets `SX` plus the first two bytes
/// of `BLAKE3("shisha-p2p-magic:shishanet:" || name)`, so a private network
/// has a stable magic of its own and can never collide with a named one.
pub fn magic_bytes_for_network(network: &str) -> [u8; 4] {
    let tag: Option<&[u8; 2]> = match network {
        "mainnet" => Some(b"MN"),
        "testnet1" => Some(b"T1"),
        "testnet2" => Some(b"T2"),
        "devnet" => Some(b"DV"),
        "testnet-stress" => Some(b"TS"),
        _ => None,
    };
    match tag {
        Some(t) => [b'S', b'H', t[0], t[1]],
        None => {
            let mut h = blake3::Hasher::new();
            h.update(b"shisha-p2p-magic:");
            h.update(b"shishanet");
            h.update(b":");
            h.update(network.as_bytes());
            let d = h.finalize();
            let d = d.as_bytes();
            [b'S', b'X', d[0], d[1]]
        }
    }
}

/// The magic as the `u32` the codec compares (the wire bytes read little-endian).
pub fn magic_for_network(network: &str) -> u32 {
    u32::from_le_bytes(magic_bytes_for_network(network))
}

pub struct RawMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = blake3::hash(payload);
    let b = hash.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

pub fn frame(magic: u32, command: &str, payload: &[u8]) -> Vec<u8> {
    let cksum = checksum(payload);
    let mut cmd = [0u8; 12];
    let b = command.as_bytes();
    cmd[..b.len().min(12)].copy_from_slice(&b[..b.len().min(12)]);

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&magic.to_le_bytes());
    buf.extend_from_slice(&cmd);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&cksum);
    buf.extend_from_slice(payload);
    buf
}

/// Try to decode one framed message from the front of `buf`. Returns
/// `Some((message, bytes_consumed))` on success, `None` if more bytes are
/// needed. Errors on a magic other than `magic_expected`, oversized payload, or checksum mismatch.
pub fn try_decode(magic_expected: u32, buf: &[u8]) -> Result<Option<(RawMessage, usize)>, String> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != magic_expected {
        return Err(format!("wrong network magic: {magic:#010x}"));
    }

    let length = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    if length > MAX_PAYLOAD {
        return Err(format!("payload too large: {length}"));
    }
    if buf.len() < HEADER_SIZE + length {
        return Ok(None);
    }

    let cksum: [u8; 4] = buf[20..24].try_into().unwrap();
    let cmd_raw = &buf[4..16];
    let end = cmd_raw.iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&cmd_raw[..end]).into_owned();

    let payload = buf[HEADER_SIZE..HEADER_SIZE + length].to_vec();
    if checksum(&payload) != cksum {
        return Err("checksum mismatch".to_string());
    }

    Ok(Some((RawMessage { command, payload }, HEADER_SIZE + length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: u32 = u32::from_le_bytes(*b"SHDV");

    #[test]
    fn frame_roundtrips() {
        let bytes = frame(M, "verack", &[]);
        let (msg, consumed) = try_decode(M, &bytes).unwrap().unwrap();
        assert_eq!(msg.command, "verack");
        assert!(msg.payload.is_empty());
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn incomplete_frame_returns_none() {
        let bytes = frame(M, "watchaddress", &[1, 2, 3, 4]);
        assert!(try_decode(M, &bytes[..HEADER_SIZE]).unwrap().is_none());
    }

    #[test]
    fn wrong_magic_errors() {
        let bytes = frame(M, "verack", &[]);
        assert!(try_decode(magic_for_network("mainnet"), &bytes).is_err());
    }

    #[test]
    fn corrupted_payload_fails_the_checksum() {
        let mut bytes = frame(M, "ping", &[1, 2, 3, 4, 5, 6, 7, 8]);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(try_decode(M, &bytes).is_err());
    }

    #[test]
    fn named_networks_have_the_documented_magic() {
        assert_eq!(&magic_bytes_for_network("mainnet"), b"SHMN");
        assert_eq!(&magic_bytes_for_network("testnet1"), b"SHT1");
        assert_eq!(&magic_bytes_for_network("testnet2"), b"SHT2");
        assert_eq!(&magic_bytes_for_network("devnet"), b"SHDV");
        assert_eq!(&magic_bytes_for_network("testnet-stress"), b"SHTS");
        assert_eq!(magic_for_network("devnet"), M);
    }

    #[test]
    fn other_names_get_a_stable_prefixed_magic() {
        let a = magic_bytes_for_network("my-private-net");
        assert_eq!(a, magic_bytes_for_network("my-private-net"));
        assert_eq!(&a[..2], b"SX");
        assert_ne!(a, magic_bytes_for_network("my-other-net"));
    }
}
