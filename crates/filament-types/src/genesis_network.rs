//! Minimal network genesis file + generator stubs for public Filament packaging.

use crate::genesis::BeaconGenesisConfig;
use crate::proofs::types::{BeaconBlockData, BlockData};
use crate::beacon_wire_header::WireBeaconHeader;
use crate::hash::sha256d;
use crate::mmr_math::genesis_mmr_root;
use crate::shard_body::{ShardBlockBody, TransactionDescriptor};
use crate::transaction_impl::{ExtensionHeader, ExtensionRecord, FlatOutput};
use crate::weighted_hash::{rbits_to_u128_approx, WeightedHash};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkGenesisConfig {
    pub beacon: BeaconGenesisConfig,
}

impl NetworkGenesisConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    pub fn devnet() -> Self {
        Self {
            beacon: BeaconGenesisConfig::devnet(),
        }
    }
}

/// Public stand-in for the private genesis `BeaconBlock` handle.
#[derive(Clone, Debug)]
pub struct BeaconBlock {
    pub hash: WeightedHash,
    pub data: BeaconBlockData,
}

pub struct GenesisGenerator;

/// Largest total premine: 21 000 000 coins of 10^8 atoms.
const PREMINE_ATOMS: u64 = 2_100_000_000_000_000;
/// Type of the miner-extranonce consensus extension attached to every coinbase.
const CONSENSUS_EXT_MINER_EXTRANONCE: u16 = 0x0002;

/// Recipient key of a premine address: `0x` + 64 hex is a raw 32-byte key; anything else is a
/// label hashed with BLAKE3 (unspendable). A 34-byte `0x51 0x20 <key>` script or a raw 32-byte
/// string maps to the key as well, as in the node.
fn address_string_to_recipient(address: &str) -> [u8; 32] {
    let addr = address.trim();
    if let Some(hex_str) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) {
        if hex_str.len() == 64 {
            if let Ok(bytes) = hex::decode(hex_str) {
                if let Ok(r) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    return r;
                }
            }
        }
    }
    let script = addr.as_bytes();
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return script[2..34].try_into().unwrap();
    }
    if script.len() == 32 {
        return script.try_into().unwrap();
    }
    *blake3::hash(script).as_bytes()
}

impl GenesisGenerator {
    fn validate_premine(cfg: &BeaconGenesisConfig) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for p in &cfg.premine {
            if !seen.insert(&p.address) {
                return Err(format!("Duplicate premine address: {}", p.address));
            }
        }
        let total: u64 = cfg.premine.iter().map(|p| p.amount).sum();
        if total > PREMINE_ATOMS {
            return Err(format!("Total premine {total} atoms exceeds canonical maximum {PREMINE_ATOMS} atoms"));
        }
        Ok(())
    }

    /// The beacon genesis block. Its hash is the SHA256d of the 80-byte header whose commitment
    /// slot holds `SHA256d(coinbase_hash ‖ aux_hash)`; the coinbase is the OP_RETURN-style output
    /// committing the Bitcoin anchor and the message, followed by the premine, and carries the
    /// all-zero miner-extranonce extension. Checked against the node for every network by the
    /// shared vectors: a different genesis hash would make every proof fail to link.
    pub fn generate_beacon_genesis(cfg: &BeaconGenesisConfig) -> Result<BeaconBlock, String> {
        Self::validate_premine(cfg)?;

        let mut commitment = Vec::with_capacity(37 + cfg.genesis_message.len());
        commitment.extend_from_slice(&cfg.bitcoin_anchor_height.to_le_bytes());
        commitment.extend_from_slice(&cfg.bitcoin_anchor_hash);
        commitment.push(cfg.genesis_message.len() as u8);
        commitment.extend_from_slice(cfg.genesis_message.as_bytes());
        let op_return_recipient: [u8; 32] = blake3::hash(&commitment).into();

        let mut outputs = vec![FlatOutput { value: 0, recipient: op_return_recipient }];
        for entry in &cfg.premine {
            outputs.push(FlatOutput { value: entry.amount, recipient: address_string_to_recipient(&entry.address) });
        }

        let extranonce = ExtensionRecord {
            header: ExtensionHeader { extension_type: CONSENSUS_EXT_MINER_EXTRANONCE, version: 1, payload_length: 8 },
            payload: vec![0u8; 8],
        };
        let body = ShardBlockBody {
            descriptors: vec![TransactionDescriptor {
                out_start: 0,
                out_len: outputs.len() as u32,
                in_start: 0,
                in_len: 0,
                witness_start: 0,
                witness_len: 0,
                extension_start: 0,
                extension_len: 1,
            }],
            outputs,
            inputs: Vec::new(),
            witnesses: Vec::new(),
            extensions: vec![extranonce],
        };
        let tx_merkle_root = body.calculate_tx_merkle_root();

        // Coinbase hash: SHA256d over reward (0), recipient, producer stamp (none), extranonces (zero).
        let mut coinbase = Vec::with_capacity(49);
        coinbase.extend_from_slice(&0u64.to_le_bytes());
        coinbase.extend_from_slice(&op_return_recipient);
        coinbase.push(0x00);
        coinbase.extend_from_slice(&[0u8; 8]);
        let coinbase_hash = sha256d(&coinbase);

        let delta = (((cfg.timestamp as i64) - (cfg.bitcoin_anchor_timestamp as i64)) * 256)
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        let nonce = cfg.nonce.unwrap_or(0);
        let prev_mmr_root = WeightedHash::from_raw(cfg.bitcoin_anchor_hash);
        let header = WireBeaconHeader {
            version: cfg.version,
            prev_mmr_root,
            delta,
            bits: cfg.bits,
            nonce: nonce as u32,
            height: 0,
            tx_merkle_root,
            merged_mining_root: [0u8; 32],
            coinbase_hash,
        };
        let hash = WeightedHash::from_leaf_rbits(&header.pow_hash(), cfg.bits);

        if let Some(expected) = cfg.expected_hash {
            if *hash.raw() != expected {
                return Err(format!(
                    "Generated genesis hash {} doesn't match expected {}",
                    hex::encode(hash.raw()),
                    hex::encode(expected)
                ));
            }
        }

        let data = BeaconBlockData {
            height: 0,
            block_hash: hash,
            prev_mmr_root,
            current_mmr_root: genesis_mmr_root(&cfg.bitcoin_anchor_hash, hash),
            version: cfg.version,
            delta,
            difficulty: rbits_to_u128_approx(cfg.bits).min(u64::MAX as u128) as u64,
            bits: cfg.bits,
            nonce,
            tx_merkle_root,
            merged_mining_root: [0u8; 32],
        };
        Ok(BeaconBlock { hash, data })
    }

    /// Genesis hash without the config's pin (what a client compares against its trusted value).
    pub fn beacon_genesis_hash(cfg: &BeaconGenesisConfig) -> Result<[u8; 32], String> {
        let mut unpinned = cfg.clone();
        unpinned.expected_hash = None;
        Ok(*Self::generate_beacon_genesis(&unpinned)?.hash.raw())
    }
}

impl BeaconBlockData {
    pub fn from_beacon_block(block: &BeaconBlock) -> Self {
        block.data.clone()
    }
}

impl From<&BeaconBlock> for BlockData {
    fn from(block: &BeaconBlock) -> Self {
        BlockData::Beacon(BeaconBlockData::from_beacon_block(block))
    }
}
