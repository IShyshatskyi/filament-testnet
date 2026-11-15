//! Beacon epoch-parameters record (consensus extension `0x0004`) and the leaf that binds it into the
//! beacon body root. Clean-room port, pinned against the node by the vector in `shard_body`'s tests.
//!
//! The record rides in the beacon coinbase of the first block of every governance epoch and is
//! covered by the proof-of-work through the beacon body root (the header's `tx_merkle_root` from
//! height 1). A light client that checked a header's work and its place in its own beacon chain reads
//! the exact active shard count of that epoch from it.

/// Consensus extension type: the epoch-parameters record. Beacon coinbase only.
pub const CONSENSUS_EXT_BEACON_EPOCH_RECORD: u16 = 0x0004;
pub const BEACON_EPOCH_RECORD_VERSION: u16 = 1;
/// `epoch_index` u32, `k_active_kbits` u32, `k_next_kbits` u32, `active_shard_count` u16,
/// `prev_active_shard_count` u16, `s_bits` u8, all little endian.
pub const BEACON_EPOCH_RECORD_LEN: usize = 4 + 4 + 4 + 2 + 2 + 1;
/// Domain tag of the beacon body root's leaf 0.
pub const BEACON_EXT_LEAF_TAG: &[u8] = b"shisha/beacon-ext-leaf/v1";

/// The values a beacon block commits at an epoch start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconEpochRecord {
    pub epoch_index: u32,
    pub k_active_kbits: u32,
    pub k_next_kbits: u32,
    /// Active shard count of this epoch (visible from `epoch_start + activation_delay`).
    pub active_shard_count: u16,
    pub prev_active_shard_count: u16,
    pub s_bits: u8,
}

impl BeaconEpochRecord {
    pub fn to_bytes(&self) -> [u8; BEACON_EPOCH_RECORD_LEN] {
        let mut b = [0u8; BEACON_EPOCH_RECORD_LEN];
        b[0..4].copy_from_slice(&self.epoch_index.to_le_bytes());
        b[4..8].copy_from_slice(&self.k_active_kbits.to_le_bytes());
        b[8..12].copy_from_slice(&self.k_next_kbits.to_le_bytes());
        b[12..14].copy_from_slice(&self.active_shard_count.to_le_bytes());
        b[14..16].copy_from_slice(&self.prev_active_shard_count.to_le_bytes());
        b[16] = self.s_bits;
        b
    }

    /// Strict parse: exactly [`BEACON_EPOCH_RECORD_LEN`] bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != BEACON_EPOCH_RECORD_LEN {
            return None;
        }
        Some(Self {
            epoch_index: u32::from_le_bytes(b[0..4].try_into().ok()?),
            k_active_kbits: u32::from_le_bytes(b[4..8].try_into().ok()?),
            k_next_kbits: u32::from_le_bytes(b[8..12].try_into().ok()?),
            active_shard_count: u16::from_le_bytes(b[12..14].try_into().ok()?),
            prev_active_shard_count: u16::from_le_bytes(b[14..16].try_into().ok()?),
            s_bits: b[16],
        })
    }
}

/// Leaf 0 of the beacon body root: `BLAKE3(tag || 0x00)` without a record, `BLAKE3(tag || 0x01 || payload)` with one.
pub fn beacon_ext_leaf(record_payload: Option<&[u8]>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(BEACON_EXT_LEAF_TAG);
    match record_payload {
        None => {
            h.update(&[0x00]);
        }
        Some(p) => {
            h.update(&[0x01]);
            h.update(p);
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strict_length() {
        let r = BeaconEpochRecord { epoch_index: 7, k_active_kbits: 0x0901_0000, k_next_kbits: 0x0900_ffff, active_shard_count: 6, prev_active_shard_count: 4, s_bits: 3 };
        assert_eq!(hex::encode(r.to_bytes()), "0700000000000109ffff00090600040003");
        assert_eq!(BeaconEpochRecord::from_bytes(&r.to_bytes()), Some(r));
        assert_eq!(BeaconEpochRecord::from_bytes(&r.to_bytes()[..16]), None);
    }

    #[test]
    fn the_ext_leaf_matches_the_node() {
        // Pinned from the node implementation (network-common `beacon_ext_leaf`).
        assert_eq!(hex::encode(beacon_ext_leaf(None)), "0d91aa65fe6cc06cadffbe7d8c0ce246a634eda49ced1a5edd92a80b89f0f841");
        let payload = hex::decode("0700000000000109ffff00090600040003").unwrap();
        assert_eq!(hex::encode(beacon_ext_leaf(Some(&payload))), "90467c747b9aef09c2e89333ac83cefc18f90a9db93a98e2ebe5a8806dfe0ff5");
    }
}
