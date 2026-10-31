// src/mmr_client/parallel_verifier.rs
//
// M: Parallel proof verification for the MMR light client.
//
// # Overview
//
// During initial sync or when processing multiple shard chains simultaneously,
// the light client receives independent proofs (one per chain/shard).
// Verifying them sequentially leaves cores idle; this module verifies them
// concurrently via a dedicated rayon thread pool.
//
// # Design mirrors S5 (parallel PoW validation in P2P)
//
// The S5 module (`src/p2p/common/pow_validator.rs`) established the pattern:
//   - A single `OnceLock<rayon::ThreadPool>` shared across all callers.
//   - An adaptive threshold: below it, fall back to sequential verification
//     on the caller's thread to avoid rayon scheduling overhead.
//   - Thread count = min(cores / 2, MAX_THREADS) — leaves the other half
//     for Tokio tasks.
//
// # Adaptive threshold
//
// Proof verification is heavier than PoW header validation (~100–500 µs vs
// ~900 ns), so the threshold is lower: 4 proofs are already worth parallelising
// because each proof takes hundreds of microseconds.  Single-chain light clients
// (one beacon + one shard) gain nothing here; multi-shard clients syncing N
// shards in parallel are the primary target.
//
// # Async usage
//
// Call from `tokio::task::spawn_blocking` to avoid blocking a Tokio worker:
//
// ```rust,ignore
// let items: Vec<(WeightedMMRBatchProof, [u8; 32])> = /* ... */;
// let results = tokio::task::spawn_blocking(move || {
//     let refs: Vec<_> = items.iter().map(|(p, a)| (p, *a)).collect();
//     verify_batch_proofs_parallel(&refs)
// }).await?;
// ```
//
// # Returned order
//
// Both `verify_batch_proofs_parallel` and `verify_range_proofs_parallel`
// return a `Vec<bool>` whose element `i` corresponds to `items[i]`.
// The parallel path uses an atomic index assignment so the mapping is
// deterministic regardless of thread scheduling.

use std::sync::OnceLock;
use rayon::prelude::*;

use common_types::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of `WeightedMMRBatchProof`s below which sequential verification is used.
///
/// Linux 4-core benchmark (Jun 2, 2026 — PARV-THRESH-1 final):
///   `parallel_batch/32` non-monotonic (0.894× — measurement noise at crossover boundary).
///   `parallel_batch/64` = 1.190× (clear win); N=16: parallel slower.
///   N=32 sits at the crossover and must not be the threshold — it regresses on
///   some runs.  64 is the safe minimum that never regresses on 4-core Linux.
///   On 2-core (GHA): parallel is always slower at all tested N (Rayon limited to
///   2 workers; scheduling overhead > gain).  2-core nodes should never reach 64
///   proofs in a single batch under normal operation.
pub const PROOF_PARALLEL_THRESHOLD_BATCH: usize = 64;

/// Number of `WeightedMMRRangeProof`s below which sequential verification is used.
///
/// Linux 4-core benchmark (May 4, 2026 — PARV-THRESH-1):
///   `parallel_range/16` = 51.2 µs  vs  sequential 69.4 µs  → parallel wins at N=16.
///   Crossover observed at N ≈ 8–16; 16 is the conservative safe threshold.
pub const PROOF_PARALLEL_THRESHOLD_RANGE: usize = 16;

/// Maximum threads in the shared proof-verification pool.
///
/// Sized identically to `POW_MAX_THREADS` (S5): half of available cores,
/// capped here.  MMR verification is memory-bandwidth-bound above 4 threads
/// (proof peak arrays thrash L2 cache at high concurrency).
pub const PROOF_MAX_THREADS: usize = 4;

/// Stack size for each proof-verification thread: 512 KiB.
///
/// Proof verification (climb-and-descend, peak bagging) uses more stack
/// than PoW validation (which is a simple SHA256d loop).  512 KiB gives
/// comfortable headroom for the recursive-style reconstruction.
pub const PROOF_THREAD_STACK_SIZE: usize = 512 * 1024;

// ── Global thread pool ────────────────────────────────────────────────────────

static PROOF_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// Return a reference to the shared proof-verification thread pool.
///
/// The pool is initialised exactly once on the first call (thread-safe via
/// `OnceLock`):
///   - Thread count: `min(available_parallelism / 2, PROOF_MAX_THREADS)`.
///   - Thread names: `proof-verifier-0`, `proof-verifier-1`, …
///   - Stack size: `PROOF_THREAD_STACK_SIZE` (512 KiB).
///
/// # Panics
///
/// Panics only on `rayon::ThreadPoolBuilder` failure, which requires extreme
/// OS resource exhaustion and is not expected in practice.
pub fn proof_thread_pool() -> &'static rayon::ThreadPool {
    PROOF_POOL.get_or_init(|| {
        let hw = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        let num_threads = (hw / 2).max(1).min(PROOF_MAX_THREADS);

        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("proof-verifier-{i}"))
            .stack_size(PROOF_THREAD_STACK_SIZE)
            .build()
            .expect("proof-verifier thread pool build failed")
    })
}

/// Return the number of threads in the shared proof-verification pool.
///
/// Useful in tests and for diagnostic logging.
pub fn proof_pool_thread_count() -> usize {
    proof_thread_pool().current_num_threads()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify multiple `WeightedMMRBatchProof`s, optionally in parallel.
///
/// Each element of `items` is `(proof, genesis_anchor)` where `genesis_anchor`
/// is the `bitcoin_anchor_hash` from `BeaconGenesisConfig` for the relevant
/// network.  The returned `Vec<bool>` preserves input order: `result[i]`
/// corresponds to `items[i]`.
///
/// | Batch size                                         | Strategy                        |
/// |----------------------------------------------------|---------------------------------|
/// | < `PROOF_PARALLEL_THRESHOLD_BATCH` (64)            | Sequential — no rayon overhead  |
/// | ≥ `PROOF_PARALLEL_THRESHOLD_BATCH`                 | Parallel via shared `PROOF_POOL`|
pub fn verify_batch_proofs_parallel(
    items: &[(&WeightedMMRBatchProof, [u8; 32])],
) -> Vec<bool> {
    if items.is_empty() {
        return Vec::new();
    }

    if items.len() < PROOF_PARALLEL_THRESHOLD_BATCH {
        // Sequential path — avoids rayon scheduling overhead for small batches.
        return items
            .iter()
            .map(|(proof, anchor)| proof.verify_with_anchor(*anchor))
            .collect();
    }

    // Parallel path via shared thread pool.
    let mut results = vec![false; items.len()];
    proof_thread_pool().install(|| {
        items
            .par_iter()
            .map(|(proof, anchor)| proof.verify_with_anchor(*anchor))
            .collect_into_vec(&mut results);
    });
    results
}

/// Verify multiple `WeightedMMRRangeProof`s, optionally in parallel.
///
/// Same contract as [`verify_batch_proofs_parallel`] but for range proofs.
/// Range proofs are heavier per proof; the crossover is at N ≈ 8–16 on a
/// 4-core Linux runner, so a threshold of 16 is used (`PROOF_PARALLEL_THRESHOLD_RANGE`).
pub fn verify_range_proofs_parallel(
    items: &[(&WeightedMMRRangeProof, [u8; 32])],
) -> Vec<bool> {
    if items.is_empty() {
        return Vec::new();
    }

    if items.len() < PROOF_PARALLEL_THRESHOLD_RANGE {
        return items
            .iter()
            .map(|(proof, anchor)| proof.verify_with_anchor(*anchor))
            .collect();
    }

    let mut results = vec![false; items.len()];
    proof_thread_pool().install(|| {
        items
            .par_iter()
            .map(|(proof, anchor)| proof.verify_with_anchor(*anchor))
            .collect_into_vec(&mut results);
    });
    results
}

// ── Unit tests ────────────────────────────────────────────────────────────────

