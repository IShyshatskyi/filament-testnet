//! filament-types — wire types and proof/MMR primitives for the Filament
//! light client.
//!
//! Grown from the private `common-types` `filament_common` tree (plus the
//! kameniar companions those modules import). Layout mirrors
//! `common_types::{common, transaction}` so Lane A `filament` sources keep
//! compiling against `common_types::common::*` / `::transaction::*` via the
//! `common-types` crate rename shim in the public workspace.

pub mod common;
pub mod transaction;

pub use common::crypto::hash_pair;
pub use common::relay_hash::relay_id;
pub use common::crypto::tx_sighash::{prevouts_hash, sighash_v2};
pub use common::types::ChainType;
pub use common::crypto::weighted_hash::{bag_peaks_weighted, rbits_to_u128_approx, WeightedHash};
