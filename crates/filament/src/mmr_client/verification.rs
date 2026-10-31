// src/mmr_client/verification.rs
//
// Gap 9 Phase 2 (Jul 3, 2026): this file was physically moved to
// crates/common-types/src/common/verification.rs. It turned out to be a
// genuine production dependency of common::proofs::fork_proof (ForkProof::verify
// calls navigate_to, which needs HybridMMRState) — not test-only as initially
// assumed — which is why it had to move alongside common/transaction rather
// than wait for a later mmr_client extraction. This is a compatibility shim
// so every existing `crate::mmr_client::verification::X` call site keeps
// resolving unchanged. See docs/plan/Crate_Split_Plan.md §Gap 9.

pub use common_types::common::verification::*;
