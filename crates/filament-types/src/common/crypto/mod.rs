//! Cryptographic utilities shared across all solutions.
//!
//! Sub-modules:
//! - `hash`          — General hash functions (SHA256d for PoW, BLAKE3 utilities)
//! - `merkle_hash`   — Merkle tree node type and hash primitives
//! - `difficulty`    — Difficulty/target conversions (nBits, target bytes)
//! - `weighted_hash` — FlyClient-style BLAKE3-224 + rBits MMR node hash

pub mod difficulty;
pub mod hash;
pub mod k_bits;
pub mod merged_mining_hash;
pub mod merkle_hash;
pub mod nbits_conversion;
pub mod weighted_hash;
pub mod tx_sighash;
pub mod sig_cache;
pub mod escrow;

// General hash utilities
pub use tx_sighash::{
    prevouts_hash, sighash_v2, verify_schnorr_witness, PREVOUTS_DOMAIN_TAG, SCHNORR_WITNESS_LEN,
    SIGHASH_V2_DOMAIN_TAG, WITNESS_TYPE_SCHNORR,
};
pub use sig_cache::{
    NoSigCache, SigCache, SigCacheKey, SigVerifier, SCHEME_TAG_SINGLE_KEY, SIGCACHE_DOMAIN_TAG,
    SIGCACHE_BEACON_MAX_ENTRIES, SIGCACHE_MAX_ENTRIES,
};
pub use escrow::{
    coop_last_valid_height, escrow_policy_hash, escrow_sighash, signature_check_cost, spend_checks,
    EscrowPolicy, SigCheck, ESCROW_COOP_WITNESS_LEN, ESCROW_RECOVERY_WITNESS_LEN,
    WITNESS_TYPE_ESCROW_COOP, WITNESS_TYPE_ESCROW_RECOVERY,
};
pub use hash::{hash_data, hash_pair, sha256d};
pub use difficulty::{difficulty_to_nbits, hash_meets_target, nbits_to_target};

// Merkle tree — import these wherever a Merkle tree is built or verified.
pub use merkle_hash::{
    MerkleHash,
    MERKLE_HASH_BYTES,
    merkle_hash_pair,
    merkle_leaf_hash,
};
