//! Proof-of-work check of packed wire beacon headers (clean-room port; checked against the node by
//! the shared vectors). The light client uses it to reject a header batch before trusting it.

use crate::beacon_wire_header::{WireBeaconHeader, WIRE_BEACON_HEADER_SIZE};
use crate::expand_voting::checked_s_bits_for_chain_count;
use crate::pow_target::{hash_meets_target, rbits_to_target};

/// Check one packed header. Height 0 is trusted from the genesis the client already holds and is
/// never checked. The hash-sorting width comes from the header's own packed chain count; a count of
/// zero means the genesis width.
pub fn validate_one_wire_beacon_chunk(
    chunk: &[u8],
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), &'static str> {
    let header = WireBeaconHeader::deserialize(chunk).map_err(|_| "malformed WireBeaconHeader chunk")?;
    if header.height == 0 {
        return Ok(());
    }
    if header.bits == 0 {
        return Err("zero bits — not a valid difficulty target");
    }
    let count = header.root_chain_count();
    let asserted_s = if count == 0 {
        genesis_asserted_s_bits
    } else {
        checked_s_bits_for_chain_count(count)
            .map(u32::from)
            .ok_or("committed_chain_count above the protocol maximum (NC-137)")?
    };
    let target = rbits_to_target(header.bits, initial_target, asserted_s);
    if hash_meets_target(&header.pow_hash(), &target) {
        Ok(())
    } else {
        Err("hash does not meet difficulty target")
    }
}

/// Sequential check over a flat buffer of packed headers; `Err((index, reason))` for the first bad one.
pub fn validate_wire_beacon_headers_pow_seq(
    raw_bytes: &[u8],
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), (usize, &'static str)> {
    for (i, chunk) in raw_bytes.chunks_exact(WIRE_BEACON_HEADER_SIZE).enumerate() {
        validate_one_wire_beacon_chunk(chunk, initial_target, genesis_asserted_s_bits).map_err(|e| (i, e))?;
    }
    Ok(())
}
