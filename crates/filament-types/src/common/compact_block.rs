// src/p2p/common/compact_block.rs
//
// Phase 8 Track B — B14: Compact block Tier 2 reconstruction helpers.
//
// Implements BIP 152-style short IDs adapted for BLAKE3, used to match
// announced compact-block transactions against the local mempool.

/// Compute the 6-byte short ID for a transaction in a compact block.
///
/// Matches the BIP 152 construction adapted for BLAKE3:
///   short_id = BLAKE3(salt || txid)[0..8] as u64 LE, masked to 48 bits.
///
/// `salt` is the first 8 bytes of BLAKE3(block_header_bytes), derived from
/// the compact block announcement header.  Must match what the sender used.
pub fn compute_short_id(txid: &[u8; 32], salt: &[u8; 8]) -> u64 {
    let mut input = Vec::with_capacity(8 + 32);
    input.extend_from_slice(salt);
    input.extend_from_slice(txid);
    let hash = blake3::hash(&input);
    let bytes: &[u8; 32] = hash.as_bytes();
    let raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    // Mask to 48 bits (6 bytes) to match BIP 152 compact short-ID size.
    raw & 0x0000_FFFF_FFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_deterministic() {
        let txid  = [0xABu8; 32];
        let salt  = [0x01u8; 8];
        let id1   = compute_short_id(&txid, &salt);
        let id2   = compute_short_id(&txid, &salt);
        assert_eq!(id1, id2, "short ID must be deterministic");
    }

    #[test]
    fn short_id_masked_to_48_bits() {
        let txid = [0xFFu8; 32];
        let salt = [0xFFu8; 8];
        let id   = compute_short_id(&txid, &salt);
        assert_eq!(id & 0xFFFF_0000_0000_0000, 0, "top 16 bits must be zero");
    }

    #[test]
    fn different_salts_produce_different_ids() {
        let txid  = [0x11u8; 32];
        let salt1 = [0x01u8; 8];
        let salt2 = [0x02u8; 8];
        let id1   = compute_short_id(&txid, &salt1);
        let id2   = compute_short_id(&txid, &salt2);
        assert_ne!(id1, id2, "different salts should produce different IDs");
    }
}
