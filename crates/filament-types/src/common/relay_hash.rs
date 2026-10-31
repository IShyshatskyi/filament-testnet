// crates/common-types/src/common/relay_hash.rs
//
// Gap 10 Phase 2 (Jul 3, 2026): extracted from src/mmr_client/f2f.rs, which
// otherwise depends on src/mmr_client/invoice.rs (a real Filament application
// feature — atomic JSON invoice store — not a "common type"). Only this one
// pure hash function was needed by p2p-proto's relay_store.rs, so only this
// function moved; the rest of f2f.rs stays in the monolith. See
// docs/plan/Crate_Split_Plan.md §Gap 10.

/// Compute the relay dedup id: `BLAKE3(payload)[0..8]` (Track H).
pub fn relay_id(payload: &[u8]) -> [u8; 8] {
    let hash = blake3::hash(payload);
    hash.as_bytes()[0..8].try_into().unwrap()
}
