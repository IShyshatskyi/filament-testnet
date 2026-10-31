//! Type primitives for the Shisha Network.
//!
//! Provides strong types wrapping raw byte arrays and integers to prevent
//! accidental misuse of different hash categories and identifiers.
//!
//! ## Hash Types
//!
//! The project uses three semantically different 32-byte hashes:
//!
//! | Type | Algorithm | Purpose | Example Usage |
//! |------|-----------|---------|---------------|
//! | `PowHash` | SHA256d | Mining / block identification | BeaconBlock::calculate_hash() |
//! | `MmrHash` | SHA256(left‖right) | MMR tree node hashing | mmr_core::hash_pair() |
//! | `LinkingHash` | SHA256(left‖right) | Merkle trees, block linking | merged_mining proof roots |
//!
//! Currently MmrHash and LinkingHash use the same algorithm (SHA256) but are
//! semantically distinct. **PoW hash will remain SHA256d (Bitcoin-standard).**
//! Linking hash and MMR hash may change to different algorithms in the future.
//! Separate types allow these algorithm changes without affecting each other.
//!
//! ## Consensus Types
//!
//! Strong types for chain identification and network selection.

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// HASH TYPES
// ============================================================================

/// Proof-of-Work hash — result of SHA256d(block_header).
///
/// Used for:
/// - Block hash computation (BeaconBlock::calculate_hash, shard Block::hash)
/// - PoW difficulty comparison (hash < target)
/// - Transaction IDs (txid, wtxid)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PowHash(pub [u8; 32]);

/// MMR tree hash — result of SHA256(left || right).
///
/// Used for:
/// - MMR internal node hashing
/// - MMR peak bagging
/// - MMR root computation
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MmrHash(pub [u8; 32]);

/// Linking hash — result of SHA256(left || right).
///
/// Used for:
/// - Merged mining merkle tree nodes
/// - Block prev_hash linkage
/// - Commitment hashes
/// - Any other SHA256-based linking
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkingHash(pub [u8; 32]);

// --- From/Into for backward compatibility with [u8; 32] ---

impl From<[u8; 32]> for PowHash {
    fn from(bytes: [u8; 32]) -> Self { Self(bytes) }
}
impl From<PowHash> for [u8; 32] {
    fn from(h: PowHash) -> Self { h.0 }
}

impl From<[u8; 32]> for MmrHash {
    fn from(bytes: [u8; 32]) -> Self { Self(bytes) }
}
impl From<MmrHash> for [u8; 32] {
    fn from(h: MmrHash) -> Self { h.0 }
}

impl From<[u8; 32]> for LinkingHash {
    fn from(bytes: [u8; 32]) -> Self { Self(bytes) }
}
impl From<LinkingHash> for [u8; 32] {
    fn from(h: LinkingHash) -> Self { h.0 }
}

// --- AsRef ---

impl AsRef<[u8; 32]> for PowHash {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}
impl AsRef<[u8; 32]> for MmrHash {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}
impl AsRef<[u8; 32]> for LinkingHash {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

// --- Debug/Display (hex representation) ---

impl fmt::Debug for PowHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PowHash({})", hex::encode(self.0))
    }
}
impl fmt::Display for PowHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for MmrHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MmrHash({})", hex::encode(self.0))
    }
}
impl fmt::Display for MmrHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for LinkingHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkingHash({})", hex::encode(self.0))
    }
}
impl fmt::Display for LinkingHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ============================================================================
// CONSENSUS TYPES
// ============================================================================

/// Chain identifier — beacon or specific shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Beacon,
    Shard(u32), // u32 to match shard_id usage across the codebase
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainId::Beacon => write!(f, "beacon"),
            ChainId::Shard(id) => write!(f, "shard-{}", id),
        }
    }
}

/// Chain type — beacon or shard.
///
/// Used by chain weight proving, MMR client, and other components that need
/// to distinguish between beacon and shard chain behavior without encoding
/// a specific shard ID.
///
/// Note: `difficulty_adjustment::ChainType` is a separate type that includes
/// `Shard(u16)` — that variant carries a shard ID for DAA purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainType {
    Beacon,
    Shard,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainType::Beacon => write!(f, "Beacon"),
            ChainType::Shard => write!(f, "Shard"),
        }
    }
}

/// Network identifier — re-exported from `common::genesis::genesis_config::NetworkId`.
///
/// The canonical definition with all methods (`bitcoin_anchor_hash()`, `as_str()`, etc.)
/// now lives in `common::genesis::genesis_config`. This re-export preserves backward
/// compatibility for any code that imported `NetworkId` from `common::types`.
pub use super::genesis::genesis_config::NetworkId;
