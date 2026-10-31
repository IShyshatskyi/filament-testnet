//! filament-types — minimal wire types and proof-verification primitives
//! for the Filament light client (clean-room; no private MMR engines).

pub mod expand_voting;
pub mod weighted_hash;
pub mod hash;
pub mod hash_sorting;
pub mod transaction_impl;
pub mod tx_sighash;
pub mod txid;
pub mod relay_hash;
pub mod types;
pub mod genesis;
pub mod genesis_network;
pub mod verification;
pub mod proofs;
pub mod beacon_wire_header;
pub mod weighted_mmr_peaks;
pub mod crypto_escrow;
pub mod ipp;

pub mod common {
    pub mod crypto {
        pub use crate::hash;
        pub use crate::hash::{hash_pair, sha256d};
        pub use crate::tx_sighash;
        pub use crate::tx_sighash::{prevouts_hash, sighash_v2};
        pub use crate::weighted_hash;
        pub use crate::weighted_hash::{
            bag_peaks_weighted, bag_peaks_weighted_u128, hash_pair_weighted, rbits_add,
            rbits_to_u128_approx, u128_to_rbits, WeightedHash,
        };
        pub mod escrow {
            pub use crate::crypto_escrow::*;
        }
    }

    pub mod blocks {
        pub mod beacon_wire_header {
            pub use crate::beacon_wire_header::*;
        }
        pub use crate::genesis_network::BeaconBlock;
    }

    pub mod genesis {
        pub mod genesis_config {
            pub use crate::genesis::{BeaconGenesisConfig, SHARD_CALIBRATION_CONSTANT};
            pub use crate::genesis_network::NetworkGenesisConfig;
        }
        pub mod genesis {
            pub use crate::genesis_network::GenesisGenerator;
        }
        pub use crate::genesis_network::GenesisGenerator;
        pub use genesis_config::BeaconGenesisConfig;
    }

    pub mod weighted_mmr_core {
        pub use crate::weighted_mmr_peaks::WeightedMMR;
    }

    pub use crate::expand_voting;
    pub use crate::ipp;
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
pub use tx_sighash::{prevouts_hash, sighash_v2};
pub use types::ChainType;
pub use weighted_hash::{bag_peaks_weighted, rbits_to_u128_approx, WeightedHash};
