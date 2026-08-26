// filament-p2p/src/framing.rs — ShishaNet wire framing.
//
// 24-byte header: magic(4 LE) | command(12, NUL-padded) | length(4 LE) |
// checksum(4, BLAKE3(payload)[0..4]) | payload.

pub const HEADER_SIZE: usize = 24;
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

/// ShishaNetwork magic (`0x53484254`, "SHBT" — BLAKE3-checksum framing).
pub const MAGIC: u32 = 0x5348_4254;

pub struct RawMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = blake3::hash(payload);
    let b = hash.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

pub fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let cksum = checksum(payload);
    let mut cmd = [0u8; 12];
    let b = command.as_bytes();
    cmd[..b.len().min(12)].copy_from_slice(&b[..b.len().min(12)]);

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&cmd);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&cksum);
    buf.extend_from_slice(payload);
    buf
}

/// Try to decode one framed message from the front of `buf`. Returns
/// `Some((message, bytes_consumed))` on success, `None` if more bytes are
/// needed. Errors on bad magic, oversized payload, or checksum mismatch.
pub fn try_decode(buf: &[u8]) -> Result<Option<(RawMessage, usize)>, String> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != MAGIC {
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

    #[test]
    fn frame_roundtrips() {
        let bytes = frame("verack", &[]);
        let (msg, consumed) = try_decode(&bytes).unwrap().unwrap();
        assert_eq!(msg.command, "verack");
        assert!(msg.payload.is_empty());
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn incomplete_frame_returns_none() {
        let bytes = frame("watchaddress", &[1, 2, 3, 4]);
        assert!(try_decode(&bytes[..HEADER_SIZE]).unwrap().is_none());
    }

    #[test]
    fn wrong_magic_errors() {
        let mut bytes = frame("verack", &[]);
        bytes[0] = 0xFF;
        assert!(try_decode(&bytes).is_err());
    }
}
