//! Compact beacon header for light-client thin sync (150-byte wire record).
//! Clean-room port of the public wire layout — no BeaconBlock dependency.

use crate::hash::sha256d;
use crate::weighted_hash::WeightedHash;
use sha2::{Digest, Sha256};

/// Total wire size of a `WireBeaconHeader` in bytes.
pub const WIRE_BEACON_HEADER_SIZE: usize = 150;

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
    pub merged_mining_root: [u8; 32],
    pub committed_chain_count: u16,
    pub coinbase_hash: [u8; 32],
}

fn calculate_aux_hash(
    height: u32,
    merged_mining_root: [u8; 32],
    committed_chain_count: u16,
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(4 + 32 + 2);
    pre.extend_from_slice(&height.to_le_bytes());
    pre.extend_from_slice(&merged_mining_root);
    pre.extend_from_slice(&committed_chain_count.to_le_bytes());
    sha256d(&pre)
}

fn calculate_commitment_hash_from_coinbase(
    height: u32,
    coinbase_hash: [u8; 32],
    merged_mining_root: [u8; 32],
    committed_chain_count: u16,
) -> [u8; 32] {
    let aux_hash = calculate_aux_hash(height, merged_mining_root, committed_chain_count);
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
        out[116..118].copy_from_slice(&self.committed_chain_count.to_le_bytes());
        out[118..150].copy_from_slice(&self.coinbase_hash);
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
            committed_chain_count: u16::from_le_bytes(bytes[116..118].try_into().unwrap()),
            coinbase_hash: bytes[118..150].try_into().unwrap(),
        })
    }

    pub fn commitment_hash(&self) -> [u8; 32] {
        calculate_commitment_hash_from_coinbase(
            self.height,
            self.coinbase_hash,
            self.merged_mining_root,
            self.committed_chain_count,
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
}
