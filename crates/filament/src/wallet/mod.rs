// src/wallet/mod.rs
//
// Trimmed 2026-07-04 (RF-20 follow-up): `mnemonic`, `derivation`,
// `multi_shard_wallet`, `utxo`, `balance`, and `wallet_manager` were deleted
// — the Bech32/BIP-44 wallet subsystem they implemented had zero live
// callers and predates the FV-3 flat-vector migration that made raw 32-byte
// recipients (and the unrelated `mmr_client::shisha_uri`/`filament_wallet`
// address scheme) canonical. See
// docs/reports/RF-19_RF-20_Completion_Report.md §3.

pub mod transaction_builder;

pub use transaction_builder::SchnorrSigner;
