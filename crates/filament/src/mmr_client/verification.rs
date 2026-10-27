// src/mmr_client/verification.rs
//
// Compatibility shim: the verification code (including `HybridMMRState`, which
// `ForkProof::verify` needs) lives in `filament-types`. Re-exported so every
// `crate::mmr_client::verification::X` path keeps resolving.

pub use common_types::common::verification::*;
