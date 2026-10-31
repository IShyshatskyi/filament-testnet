//! Sequential PoW validation for packed `WireBeaconHeader` batches.
//!
//! Slim port of private `p2p-proto::p2p::common::pow_validator` for the
//! Filament light-client path: sequential only (no rayon / ComputePool).
//! Callers that need bulk parallel validation belong on the full node.

use common_types::common::blocks::beacon_wire_header::{WireBeaconHeader, WIRE_BEACON_HEADER_SIZE};
use common_types::common::crypto::difficulty;
use common_types::common::crypto::weighted_hash::rbits_to_target;
use common_types::common::validation::pow::resolve_beacon_asserted_s;

fn validate_one_wire_beacon_chunk(
    chunk: &[u8],
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), &'static str> {
    debug_assert_eq!(chunk.len(), WIRE_BEACON_HEADER_SIZE);

    let header = WireBeaconHeader::deserialize(chunk)
        .map_err(|_| "malformed WireBeaconHeader chunk")?;

    // Genesis is trusted from config — never PoW-checked here.
    if header.height == 0 {
        return Ok(());
    }

    if header.bits == 0 {
        return Err("zero bits — not a valid difficulty target");
    }

    let asserted_s = resolve_beacon_asserted_s(
        header.committed_chain_count,
        genesis_asserted_s_bits,
    )
    .map_err(|_| "committed_chain_count above the protocol maximum (NC-137)")?;
    let target = rbits_to_target(header.bits, initial_target, asserted_s);
    let hash = header.pow_hash();

    if difficulty::hash_meets_target(&hash, &target) {
        Ok(())
    } else {
        Err("hash does not meet difficulty target")
    }
}

/// Validate proof-of-work for a flat buffer of packed `WireBeaconHeader` chunks.
pub fn validate_wire_beacon_headers_pow(
    raw_bytes: &[u8],
    initial_target: &[u8; 32],
    genesis_asserted_s_bits: u32,
) -> Result<(), (usize, &'static str)> {
    for (i, chunk) in raw_bytes.chunks_exact(WIRE_BEACON_HEADER_SIZE).enumerate() {
        validate_one_wire_beacon_chunk(chunk, initial_target, genesis_asserted_s_bits)
            .map_err(|e| (i, e))?;
    }
    Ok(())
}
