//! Compact beacon header for light-client thin sync (148-byte wire record).
//! Clean-room port of the public wire layout — no BeaconBlock dependency.

use crate::hash::sha256d;
use crate::weighted_hash::WeightedHash;
use sha2::{Digest, Sha256};

/// Total wire size of a `WireBeaconHeader` in bytes.
pub const WIRE_BEACON_HEADER_SIZE: usize = 148;

/// Compact beacon header broadcast to light-client peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireBeaconHeader {
    pub version: u32,
    pub prev_mmr_root: WeightedHash,
    pub delta: i32,
    pub bits: u32,
    pub nonce: u32,
    pub height: u32,
    pub tx_merkle_root: [u8; 32],
    /// Merged-mining tree root; its last two bytes pack the tree height (4 bits) and the chain
    /// count (12 bits), so the count is covered by the PoW commitment. There is no separate count
    /// field (removed Nov 2026).
    pub merged_mining_root: [u8; 32],
    pub coinbase_hash: [u8; 32],
}

/// Leaf 1 of the commitment: `BLAKE3(height ‖ merged_mining_root)`.
fn calculate_aux_hash(height: u32, merged_mining_root: [u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&height.to_le_bytes());
    h.update(&merged_mining_root);
    h.finalize().into()
}

/// `SHA256d(coinbase_hash ‖ aux_hash)`: the value in the commitment slot of the 80-byte header.
pub(crate) fn calculate_commitment_hash_from_coinbase(
    height: u32,
    coinbase_hash: [u8; 32],
    merged_mining_root: [u8; 32],
) -> [u8; 32] {
    let aux_hash = calculate_aux_hash(height, merged_mining_root);
    let mut preimage = [0u8; 64];
    preimage[0..32].copy_from_slice(&coinbase_hash);
    preimage[32..64].copy_from_slice(&aux_hash);
    sha256d(&preimage)
}

impl WireBeaconHeader {
    pub fn serialize(&self) -> [u8; WIRE_BEACON_HEADER_SIZE] {
        let mut out = [0u8; WIRE_BEACON_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        out[36..40].copy_from_slice(&self.delta.to_le_bytes());
        out[40..44].copy_from_slice(&self.bits.to_le_bytes());
        out[44..48].copy_from_slice(&self.nonce.to_le_bytes());
        out[48..52].copy_from_slice(&self.height.to_le_bytes());
        out[52..84].copy_from_slice(&self.tx_merkle_root);
        out[84..116].copy_from_slice(&self.merged_mining_root);
        out[116..148].copy_from_slice(&self.coinbase_hash);
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != WIRE_BEACON_HEADER_SIZE {
            return Err(format!(
                "WireBeaconHeader: expected {} bytes, got {}",
                WIRE_BEACON_HEADER_SIZE,
                bytes.len(),
            ));
        }
        Ok(Self {
            version: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            prev_mmr_root: WeightedHash::from(<[u8; 32]>::try_from(&bytes[4..36]).unwrap()),
            delta: i32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            bits: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            nonce: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
            height: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            tx_merkle_root: bytes[52..84].try_into().unwrap(),
            merged_mining_root: bytes[84..116].try_into().unwrap(),
            coinbase_hash: bytes[116..148].try_into().unwrap(),
        })
    }

    pub fn commitment_hash(&self) -> [u8; 32] {
        calculate_commitment_hash_from_coinbase(
            self.height,
            self.coinbase_hash,
            self.merged_mining_root,
        )
    }

    pub fn mining_header(&self) -> [u8; 80] {
        let ch = self.commitment_hash();
        let mut hdr = [0u8; 80];
        hdr[0..4].copy_from_slice(&self.version.to_le_bytes());
        hdr[4..36].copy_from_slice(&<[u8; 32]>::from(self.prev_mmr_root));
        hdr[36..68].copy_from_slice(&ch);
        hdr[68..72].copy_from_slice(&self.delta.to_le_bytes());
        hdr[72..76].copy_from_slice(&self.bits.to_le_bytes());
        hdr[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        hdr
    }

    pub fn pow_hash(&self) -> [u8; 32] {
        let mh = self.mining_header();
        let first = Sha256::digest(mh);
        Sha256::digest(first).into()
    }

    pub fn prev_mmr_root(&self) -> WeightedHash {
        self.prev_mmr_root
    }

    /// Number of active chains packed in `merged_mining_root` (12 bits, cap 4095).
    pub fn root_chain_count(&self) -> u16 {
        u16::from_be_bytes([self.merged_mining_root[30], self.merged_mining_root[31]]) & 0x0FFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned vector shared with the private implementation (`network-common`'s
    /// `pinned_vector_is_stable`): both must produce these exact bytes.
    fn pinned_vector_header() -> WireBeaconHeader {
        WireBeaconHeader {
            version: 1,
            prev_mmr_root: WeightedHash::from([0x11u8; 32]),
            delta: -5,
            bits: 0x0300_0080,
            nonce: 0x0102_0304,
            height: 42,
            tx_merkle_root: [0x22; 32],
            merged_mining_root: [0x33; 32],
            coinbase_hash: [0x44; 32],
        }
    }

    #[test]
    fn pinned_vector_matches_the_node_implementation() {
        let h = pinned_vector_header();
        assert_eq!(
            hex::encode(h.serialize()),
            "010000001111111111111111111111111111111111111111111111111111111111111111fbffffff80000003040302012a000000222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444"
        );
        assert_eq!(hex::encode(h.commitment_hash()), "7fa5d19f563d643a786e2206092b230e223e7c731022cea91ee4eee7336f4a89");
        assert_eq!(hex::encode(h.pow_hash()), "2ebd5f8af33412460078fc3ab413b8c374e184587b35d5416746fa2d7596f5fe");
    }

    #[test]
    fn wire_size_is_148_and_round_trips() {
        let h = pinned_vector_header();
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 148);
        assert_eq!(WireBeaconHeader::deserialize(&bytes).unwrap(), h);
        assert!(WireBeaconHeader::deserialize(&bytes[..147]).is_err());
    }

    #[test]
    fn the_chain_count_is_read_from_the_root_and_covered_by_the_commitment() {
        let mut h = pinned_vector_header();
        h.merged_mining_root[30] = 0x30; // tree height 3
        h.merged_mining_root[31] = 0x07; // 7 chains
        assert_eq!(h.root_chain_count(), 7);
        let before = h.commitment_hash();
        h.merged_mining_root[31] = 0x08;
        assert_ne!(h.commitment_hash(), before);
    }
}
