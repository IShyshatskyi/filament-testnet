//! Light-client thin-sync JSON response shapes.

use serde::{Deserialize, Serialize};

use super::types::FullShardBlockData;
use super::weighted_mmr_range_proof::WeightedMMRRangeProof;

pub const MAX_SESSION_HEADERS: usize = 16;
pub const MAX_HEADERS_PER_REQUEST: usize = 64;
pub const MAX_SHARD_BLOCKS_PER_REQUEST: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinTipResponse {
    pub height: Option<u32>,
    pub leaf_count: u32,
    pub root_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinHeadersResponse {
    pub from: u32,
    pub leaf_count: u32,
    pub headers_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinSessionResponse {
    pub leaf_count: u32,
    pub root_hex: String,
    pub headers_hex: String,
    pub range_proof: Option<WeightedMMRRangeProof>,
}

pub fn encode_shard_blocks(blocks: &[FullShardBlockData]) -> Result<String, String> {
    if blocks.is_empty() {
        return Ok(String::new());
    }
    let bytes = bincode::serde::encode_to_vec(blocks, bincode::config::standard())
        .map_err(|e| format!("cannot encode shard blocks: {e}"))?;
    Ok(hex::encode(bytes))
}

pub fn decode_shard_blocks(blocks_hex: &str) -> Result<Vec<FullShardBlockData>, String> {
    if blocks_hex.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = hex::decode(blocks_hex).map_err(|_| "shard blocks are not valid hex".to_string())?;
    let (blocks, used): (Vec<FullShardBlockData>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .map_err(|e| format!("cannot decode shard blocks: {e}"))?;
    if used != bytes.len() {
        return Err("trailing bytes after the shard blocks".to_string());
    }
    Ok(blocks)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinShardBlocksResponse {
    pub from: u32,
    pub leaf_count: u32,
    pub blocks_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinShardSessionResponse {
    pub leaf_count: u32,
    pub root_hex: String,
    pub blocks_hex: String,
    pub range_proof: Option<WeightedMMRRangeProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinHeaderProofResponse {
    pub from: u32,
    pub leaf_count: u32,
    pub root_hex: String,
    pub headers_hex: String,
    pub range_proof: WeightedMMRRangeProof,
}
