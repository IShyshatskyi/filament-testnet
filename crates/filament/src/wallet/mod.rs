// src/wallet/mod.rs
//
// Trimmed 2026-07-04 (RF-20 follow-up): `mnemonic`, `derivation`,
// `multi_shard_wallet`, `utxo`, `balance`, and `wallet_manager` were deleted
// — the Bech32/BIP-44 wallet subsystem they implemented had zero live
// callers and predates the FV-3 flat-vector migration that made raw 32-byte
// recipients (and the unrelated `mmr_client::shisha_uri`/`filament_wallet`
// address scheme) canonical. See
// the extraction notes

pub mod transaction_builder;
pub mod escrow;
pub mod hot_key;
pub mod hw_assemble;

pub use transaction_builder::SchnorrSigner;
pub use escrow::{EscrowOutpoint, EscrowPayment, EscrowRecord, EscrowStore};
pub use hot_key::{HotKeyError, HotKeyInfo, HotKeyStore};
