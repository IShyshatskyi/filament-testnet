//! Shard block header and the auxiliary beacon header it carries (clean-room port; checked against
//! the node by the shared vectors).
//!
//! A shard block is merge-mined: its proof of work is the PoW of an auxiliary beacon candidate
//! whose `merged_mining_root` commits to the shard's leaf. The shard header's identity hash covers
//! its own fields, that auxiliary PoW hash and the beacon coinbase record when one is present.

use crate::beacon_wire_header::calculate_commitment_hash_from_coinbase;
use crate::hash::sha256d;
use crate::merged_mining_hash::MergedMiningHash;
use crate::weighted_hash::WeightedHash;

/// Commitment of a candidate without a coinbase hash: `BLAKE3(height ‖ tx_merkle_root ‖ merged_mining_root)`.
fn commitment_hash_from_parts(height: u32, tx_merkle_root: [u8; 32], merged_mining_root: [u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&height.to_le_bytes());
    h.update(&tx_merkle_root);
    h.update(&merged_mining_root);
    h.finalize().into()
}

/// The beacon candidate a shard block was mined against.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BeaconHeader {
    pub version: u32,
    pub delta: i32,
    pub nonce: u64,
    pub prev_mmr_root: WeightedHash,
    pub merged_mining_root: [u8; 32],
    pub bits: u32,
    pub beacon_height: u32,
    pub beacon_merkle_root: [u8; 32],
    /// All zero for the legacy commitment; the real beacon coinbase hash otherwise.
    #[serde(default)]
    pub coinbase_hash: [u8; 32],
}

impl BeaconHeader {
    /// Number of active chains packed in `merged_mining_root`.
    pub fn root_chain_count(&self) -> u16 {
        MergedMiningHash::chain_count_of_root(&self.merged_mining_root)
    }

    /// The 80-byte header the miner hashed.
    pub fn serialize_for_mining(&self) -> Vec<u8> {
        let commitment: [u8; 32] = if self.coinbase_hash == [0u8; 32] {
            commitment_hash_from_parts(self.beacon_height, self.beacon_merkle_root, self.merged_mining_root)
        } else {
            calculate_commitment_hash_from_coinbase(self.beacon_height, self.coinbase_hash, self.merged_mining_root)
        };
        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(self.prev_mmr_root.raw());
        header.extend_from_slice(&commitment);
        header.extend_from_slice(&self.delta.to_le_bytes());
        header.extend_from_slice(&self.bits.to_le_bytes());
        header.extend_from_slice(&(self.nonce as u32).to_le_bytes());
        header
    }

    /// PoW hash: `SHA256d` of the 80-byte header.
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize_for_mining())
    }

    /// MMR leaf form of the PoW hash, carrying the header's rBits.
    pub fn hash_weighted(&self) -> WeightedHash {
        WeightedHash::from_leaf_rbits(&self.hash(), self.bits)
    }
}

/// A shard block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullShardHeader {
    pub height: u32,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub tx_merkle_root: [u8; 32],
    /// Compact rBits of the shard difficulty.
    pub difficulty: u32,
    pub shard_id: u16,
    pub beacon_header: BeaconHeader,
    hash: [u8; 32],
    /// Merkle siblings from the shard's leaf up to the beacon header's `merged_mining_root`.
    pub merged_mining_proof: Vec<MergedMiningHash>,
    /// The beacon coinbase record (empty when the block carries none).
    pub beacon_coinbase: Vec<u8>,
}

impl FullShardHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u32,
        prev_mmr_root: WeightedHash,
        current_mmr_root: WeightedHash,
        tx_merkle_root: [u8; 32],
        difficulty: u32,
        merged_mining_proof: Vec<MergedMiningHash>,
        shard_id: u16,
        beacon_header: BeaconHeader,
    ) -> Self {
        let mut header = Self {
            height,
            prev_mmr_root,
            current_mmr_root,
            tx_merkle_root,
            difficulty,
            shard_id,
            beacon_header,
            hash: [0u8; 32],
            merged_mining_proof,
            beacon_coinbase: Vec::new(),
        };
        header.hash = header.compute_hash();
        header
    }

    /// Attach the beacon coinbase record; the identity hash covers it.
    pub fn with_beacon_coinbase(mut self, record: Vec<u8>) -> Self {
        self.beacon_coinbase = record;
        self.hash = self.compute_hash();
        self
    }

    /// Bytes hashed for the identity hash (never `current_mmr_root`: it is derived from the hash).
    pub fn serialize_for_hash(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(self.prev_mmr_root.raw());
        bytes.extend_from_slice(&self.tx_merkle_root);
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());
        bytes.extend_from_slice(&self.beacon_header.hash());
        bytes.extend_from_slice(&self.beacon_header.delta.to_le_bytes());
        if !self.beacon_coinbase.is_empty() {
            bytes.push(self.beacon_coinbase.len() as u8);
            bytes.extend_from_slice(&self.beacon_coinbase);
        }
        bytes
    }

    fn compute_hash(&self) -> [u8; 32] {
        sha256d(&self.serialize_for_hash())
    }

    /// Identity hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The leaf this shard contributes to the merged-mining tree (cut before any PoW exists).
    pub fn merged_mining_leaf_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.height.to_le_bytes());
        h.update(self.prev_mmr_root.raw());
        h.update(&self.tx_merkle_root);
        h.update(&self.difficulty.to_le_bytes());
        h.finalize().into()
    }

    /// MMR leaf form of the identity hash, carrying the shard difficulty.
    pub fn hash_weighted(&self) -> WeightedHash {
        WeightedHash::from_leaf_rbits(&self.hash, self.difficulty)
    }
}

/// A shard block as the light client holds it: the header and (usually no) transactions.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: FullShardHeader,
    pub transactions: Vec<crate::transaction_impl::Transaction>,
}

impl Block {
    pub fn new(header: FullShardHeader, transactions: Vec<crate::transaction_impl::Transaction>) -> Self {
        Self { header, transactions }
    }
}
