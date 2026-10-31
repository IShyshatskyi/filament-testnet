//! Light-client "thin sync" responses (`docs/plan/Filament_Thin_Sync_Design.md`).
//!
//! Replaces polling the full `MMRChainSummary` (100 blocks + batch proof) with
//! a tiny tip poll and, once per session, a 16-header summary with a range proof.
//! Byte fields are hex strings so JSON does not inflate them to number arrays.

use serde::{Deserialize, Serialize};

use super::weighted_mmr_range_proof::WeightedMMRRangeProof;

/// Most full headers a session response carries (owner decision, Oct 29, 2026).
pub const MAX_SESSION_HEADERS: usize = 16;

/// `GET /chain/tip`: enough to see whether anything changed. ~100 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinTipResponse {
    /// Height of the tip block; `None` when the chain is empty.
    pub height: Option<u32>,
    /// Number of leaves in the MMR (= tip height + 1).
    pub leaf_count: u32,
    /// MMR root (32 bytes, hex).
    pub root_hex: String,
}

/// Most headers one `GET /chain/headers/{from}` call returns.
pub const MAX_HEADERS_PER_REQUEST: usize = 64;

/// `GET /chain/headers/{from}?max=N`: consecutive full headers starting at
/// height `from`, for incremental updates after a session summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinHeadersResponse {
    pub from: u32,
    pub leaf_count: u32,
    /// Concatenated `WireBeaconHeader` records (hex); empty when `from` is past the tip.
    pub headers_hex: String,
}

/// `GET /chain/session?headers=N`: sent once per session, on request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinSessionResponse {
    pub leaf_count: u32,
    /// MMR root (32 bytes, hex); equals `range_proof.root` when a proof is present.
    pub root_hex: String,
    /// The newest `n <= MAX_SESSION_HEADERS` full headers, oldest first, as
    /// concatenated `WireBeaconHeader` records (hex).
    pub headers_hex: String,
    /// Range proof over the headers' leaves (genesis excluded, as for every
    /// range proof). `None` only when the response holds just the genesis header.
    pub range_proof: Option<WeightedMMRRangeProof>,
}

// ── Shards ────────────────────────────────────────────────────────────────────
//
// A shard block's proof of work lives in its auxiliary beacon header and its
// merged-mining sibling path, so the light client cannot use the 136-byte
// `LightShardHeader` (no `difficulty`, no proof): it needs the whole
// [`FullShardBlockData`] record (~2.2 KB) per block and checks the work itself.

use super::types::FullShardBlockData;

/// Most shard block records one `GET /shard/{id}/chain/headers/{from}` call returns.
pub const MAX_SHARD_BLOCKS_PER_REQUEST: usize = 32;

/// Encode shard block records as one hex string (bincode, so JSON does not
/// inflate byte arrays to number lists).
pub fn encode_shard_blocks(blocks: &[FullShardBlockData]) -> Result<String, String> {
    if blocks.is_empty() {
        return Ok(String::new());
    }
    let bytes = bincode::serde::encode_to_vec(blocks, bincode::config::standard())
        .map_err(|e| format!("cannot encode shard blocks: {e}"))?;
    Ok(hex::encode(bytes))
}

/// Inverse of [`encode_shard_blocks`].
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

/// `GET /shard/{id}/chain/headers/{from}?max=N`: consecutive shard block records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinShardBlocksResponse {
    pub from: u32,
    pub leaf_count: u32,
    /// [`encode_shard_blocks`] output; empty when `from` is past the tip.
    pub blocks_hex: String,
}

/// `GET /shard/{id}/chain/session?headers=N`: the newest `n <= MAX_SESSION_HEADERS`
/// shard block records. When they start at height 0 there is no proof (the
/// client replays the whole chain from its anchor); otherwise one range proof
/// over their leaves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinShardSessionResponse {
    pub leaf_count: u32,
    pub root_hex: String,
    pub blocks_hex: String,
    pub range_proof: Option<WeightedMMRRangeProof>,
}

/// `GET /chain/header-proof/{from}?count=N&at=LEAF_COUNT`: `count` (1 or 2)
/// consecutive beacon headers from `from` (>= 1) with a range proof against the
/// current beacon MMR root. `at` is the leaf count the client verified; the
/// Keystone answers only when its chain has exactly that length (range proofs
/// are built against the current structure), so a proof is never for a root the
/// client has not seen. The client uses it to learn a shard's genesis anchor
/// from beacon data it verified itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThinHeaderProofResponse {
    pub from: u32,
    pub leaf_count: u32,
    pub root_hex: String,
    pub headers_hex: String,
    pub range_proof: WeightedMMRRangeProof,
}
