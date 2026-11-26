//! Light-client PoW check for WireBeaconHeader batches.

use filament_types::beacon_wire_header::{WireBeaconHeader, WIRE_BEACON_HEADER_SIZE};

fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] { return true; }
        if hash[i] > target[i] { return false; }
    }
    true
}

fn validate_one_wire_beacon_chunk(
    chunk: &[u8],
    initial_target: &[u8; 32],
    _genesis_asserted_s_bits: u32,
) -> Result<(), &'static str> {
    let h = WireBeaconHeader::deserialize(chunk).map_err(|_| "bad wire header")?;
    let pow = h.pow_hash();
    if !hash_meets_target(&pow, initial_target) {
        return Err("pow does not meet target");
    }
    Ok(())
}

pub fn validate_wire_beacon_headers_pow(
    raw_bytes: &[u8],
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), (usize, &'static str)> {
    if raw_bytes.len() % WIRE_BEACON_HEADER_SIZE != 0 {
        return Err((0, "misaligned wire beacon header bytes"));
    }
    for (i, chunk) in raw_bytes.chunks_exact(WIRE_BEACON_HEADER_SIZE).enumerate() {
        validate_one_wire_beacon_chunk(chunk, initial_target, genesis_asserted_s_bits)
            .map_err(|e| (i, e))?;
    }
    Ok(())
}
