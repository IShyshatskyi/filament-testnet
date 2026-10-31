// src/wallet/mod.rs
//
// Trimmed: the earlier Bech32/BIP-44 wallet subsystem (`mnemonic`,
// `derivation`, `multi_shard_wallet`, `utxo`, `balance`, `wallet_manager`) had
// no live callers and predated the flat-vector transaction format that made
// raw 32-byte recipients canonical, so it was removed. Only `SchnorrSigner`
// remains.

pub mod transaction_builder;
pub mod escrow;
pub mod hot_key;

pub use transaction_builder::SchnorrSigner;
