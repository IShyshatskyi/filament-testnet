//! filament-types — minimal wire types and proof-verification primitives
//! for the Filament light client.
//!
//! Clean-room reimplementation covering only what a read-only, proof-
//! verifying light client needs: block/proof data shapes, transaction wire
//! format, and the pure verification math (hash pairing, MMR peak bagging,
//! batch/range/fork/chain-weight proof checking). It deliberately does not
//! include the real chain-construction/write engine (MMR append/pruning,
//! reorg/orphan-pool logic) — see each module's own doc comment for what
//! was excluded and why.
//!
//! The public module tree below (`common::`, `transaction::`) mirrors the
//! private monorepo's `common-types` crate path-for-path, purely so
//! `filament`'s own source (which was written against that crate) compiles
//! unchanged against this one. The real implementation lives in the
//! top-level modules; `common`/`transaction` are thin `pub use` shims.

pub mod weighted_hash;
pub mod hash;
pub mod hash_sorting;
pub mod transaction_impl;
pub mod tx_sighash;
pub mod txid;
pub mod relay_hash;
pub mod types;
pub mod genesis;
pub mod verification;
pub mod proofs;

pub mod common {
    pub mod crypto {
        pub use crate::hash;
        pub use crate::hash::hash_pair;
        pub use crate::tx_sighash;
        pub use crate::tx_sighash::{flat_tx_sighash, prevouts_hash, sighash_v2};
        pub use crate::weighted_hash;
        pub use crate::weighted_hash::{
            bag_peaks_weighted, hash_pair_weighted, rbits_add, rbits_to_u128_approx, WeightedHash,
        };
    }

    pub mod genesis {
        pub mod genesis_config {
            pub use crate::genesis::BeaconGenesisConfig;
        }
        pub use genesis_config::BeaconGenesisConfig;
    }

    pub use crate::proofs;
    pub use crate::relay_hash;
    pub use crate::relay_hash::relay_id;
    pub use crate::types;
    pub use crate::types::ChainType;
    pub use crate::verification;
}

pub mod transaction {
    pub use crate::transaction_impl::*;
    pub use crate::txid::{shard_chain_id, txid_from_parts, BEACON_CHAIN_ID, TXID_DOMAIN_TAG};

    pub mod types {
        pub use crate::transaction_impl::*;
    }
}

pub use hash::hash_pair;
pub use relay_hash::relay_id;
pub use tx_sighash::flat_tx_sighash;
pub use types::ChainType;
pub use weighted_hash::{bag_peaks_weighted, rbits_to_u128_approx, WeightedHash};
