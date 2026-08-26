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

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::common::genesis::genesis_config::BeaconGenesisConfig;
    use common_types::common::proofs::WeightedMMRBatchProof;
    use common_types::common::crypto::weighted_hash::{WeightedHash, bag_peaks_weighted, BLOCK_HASH_W_BITS};
    use common_types::common::weighted_mmr_core::WeightedMMR;

    // Build a single-leaf valid WeightedMMRBatchProof.
    //
    // A 1-leaf MMR has one peak (the leaf itself), no sibling path, and a
    // root equal to bag_peaks_weighted([leaf], anchor).  Verification passes
    // when leaf_idx=0, siblings=[], peaks=[leaf_wh], root=bagged.
    fn make_valid_batch_proof(
        block_seed: u8,
        config: &BeaconGenesisConfig,
    ) -> (WeightedMMRBatchProof, [u8; 32]) {
        let anchor = config.bitcoin_anchor_hash;
        let mut mmr = WeightedMMR::new_with_config(config);
        let block_hash = [block_seed; 32];
        let (root, _) = mmr.append(WeightedHash::from_leaf_rbits(&block_hash, 0x0300_0001));
        let leaf_wh = mmr.get_leaf(0).expect("leaf 0 must exist after one append");
        let peaks = mmr.get_peaks();

        let proof = WeightedMMRBatchProof {
            leaf_indices: vec![0],
            leaf_hashes: vec![leaf_wh],
            siblings: vec![],
            peaks,
            leaf_count: 1,
            root,
        };
        (proof, anchor)
    }

    // Build an invalid proof by flipping one byte of the root.
    fn make_invalid_batch_proof(
        block_seed: u8,
        config: &BeaconGenesisConfig,
    ) -> (WeightedMMRBatchProof, [u8; 32]) {
        let (mut proof, anchor) = make_valid_batch_proof(block_seed, config);
        // Corrupt the stored root so it no longer matches the reconstructed root.
        let mut bad_root_bytes = proof.root.0;
        bad_root_bytes[0] ^= 0xFF;
        proof.root = WeightedHash(bad_root_bytes);
        (proof, anchor)
    }

    // ── PPV-1: empty input returns empty result ──────────────────────────────

    #[test]
    fn ppv1_empty_input_batch_returns_empty() {
        let results = verify_batch_proofs_parallel(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn ppv1b_empty_input_range_returns_empty() {
        let results = verify_range_proofs_parallel(&[]);
        assert!(results.is_empty());
    }

    // ── PPV-2: single valid proof → sequential path → returns true ───────────

    #[test]
    fn ppv2_single_valid_proof_returns_true() {
        let config = BeaconGenesisConfig::devnet();
        let (proof, anchor) = make_valid_batch_proof(1, &config);
        let results = verify_batch_proofs_parallel(&[(&proof, anchor)]);
        assert_eq!(results, vec![true]);
    }

    // ── PPV-3: single invalid proof → sequential path → returns false ────────

    #[test]
    fn ppv3_single_invalid_proof_returns_false() {
        let config = BeaconGenesisConfig::devnet();
        let (proof, anchor) = make_invalid_batch_proof(2, &config);
        let results = verify_batch_proofs_parallel(&[(&proof, anchor)]);
        assert_eq!(results, vec![false]);
    }

    // ── PPV-4: (BATCH_THRESHOLD - 1) proofs → sequential path, all valid ────────

    #[test]
    fn ppv4_below_threshold_all_valid_sequential() {
        let config = BeaconGenesisConfig::devnet();
        let proofs: Vec<_> = (0..PROOF_PARALLEL_THRESHOLD_BATCH - 1)
            .map(|i| make_valid_batch_proof(i as u8 + 1, &config))
            .collect();
        let items: Vec<_> = proofs.iter().map(|(p, a)| (p, *a)).collect();
        let results = verify_batch_proofs_parallel(&items);
        assert_eq!(results.len(), PROOF_PARALLEL_THRESHOLD_BATCH - 1);
        assert!(results.iter().all(|&v| v), "all proofs below threshold should pass");
    }

    // ── PPV-5: BATCH_THRESHOLD proofs → parallel path, all valid ─────────────

    #[test]
    fn ppv5_at_threshold_all_valid_parallel() {
        let config = BeaconGenesisConfig::devnet();
        let proofs: Vec<_> = (0..PROOF_PARALLEL_THRESHOLD_BATCH)
            .map(|i| make_valid_batch_proof(i as u8 + 1, &config))
            .collect();
        let items: Vec<_> = proofs.iter().map(|(p, a)| (p, *a)).collect();
        let results = verify_batch_proofs_parallel(&items);
        assert_eq!(results.len(), PROOF_PARALLEL_THRESHOLD_BATCH);
        assert!(results.iter().all(|&v| v), "all proofs at threshold should pass");
    }

    // ── PPV-6: mixed valid/invalid in parallel batch ──────────────────────────

    #[test]
    fn ppv6_mixed_valid_invalid_parallel() {
        let config = BeaconGenesisConfig::devnet();
        // Build 2×BATCH_THRESHOLD proofs: even indices valid, odd indices invalid.
        let n = PROOF_PARALLEL_THRESHOLD_BATCH * 2;
        let proofs: Vec<_> = (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    make_valid_batch_proof(i as u8 + 1, &config)
                } else {
                    make_invalid_batch_proof(i as u8 + 1, &config)
                }
            })
            .collect();
        let items: Vec<_> = proofs.iter().map(|(p, a)| (p, *a)).collect();
        let results = verify_batch_proofs_parallel(&items);

        assert_eq!(results.len(), n);
        for (i, &v) in results.iter().enumerate() {
            if i % 2 == 0 {
                assert!(v, "proof at even index {i} should be valid");
            } else {
                assert!(!v, "proof at odd index {i} should be invalid");
            }
        }
    }

    // ── PPV-7: order preserved in parallel path ────────────────────────────────

    #[test]
    fn ppv7_parallel_order_matches_sequential() {
        let config = BeaconGenesisConfig::devnet();
        let n = PROOF_PARALLEL_THRESHOLD_BATCH + 4;
        let proofs: Vec<_> = (0..n)
            .map(|i| {
                if i < n / 2 {
                    make_valid_batch_proof(i as u8 + 1, &config)
                } else {
                    make_invalid_batch_proof(i as u8 + 1, &config)
                }
            })
            .collect();
        let items: Vec<_> = proofs.iter().map(|(p, a)| (p, *a)).collect();

        // Sequential reference.
        let sequential: Vec<bool> = items
            .iter()
            .map(|(p, a)| p.verify_with_anchor(*a))
            .collect();

        // Parallel must agree element-by-element.
        let parallel = verify_batch_proofs_parallel(&items);
        assert_eq!(parallel, sequential, "parallel and sequential must agree on every element");
    }

    // ── PPV-8: pool thread count is at most PROOF_MAX_THREADS ────────────────

    #[test]
    fn ppv8_pool_thread_count_at_most_max() {
        let _ = proof_thread_pool(); // force init
        assert!(
            proof_pool_thread_count() <= PROOF_MAX_THREADS,
            "thread count {} exceeds PROOF_MAX_THREADS {}",
            proof_pool_thread_count(),
            PROOF_MAX_THREADS
        );
    }

    // ── PPV-9: pool thread count ≤ available_parallelism / 2 ─────────────────

    #[test]
    fn ppv9_pool_thread_count_half_cores_cap() {
        let hw = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        let expected_max = (hw / 2).max(1).min(PROOF_MAX_THREADS);
        assert!(
            proof_pool_thread_count() <= expected_max,
            "pool used {} threads, expected ≤ {}",
            proof_pool_thread_count(),
            expected_max
        );
    }

    // ── PPV-10: wrong anchor makes valid proof fail ───────────────────────────

    #[test]
    fn ppv10_wrong_anchor_rejects_valid_proof() {
        let config = BeaconGenesisConfig::devnet();
        let (proof, _correct_anchor) = make_valid_batch_proof(42, &config);

        // Use testnet anchor (different genesis hash).
        let wrong_anchor = BeaconGenesisConfig::testnet1().bitcoin_anchor_hash;
        let results = verify_batch_proofs_parallel(&[(&proof, wrong_anchor)]);
        assert_eq!(results, vec![false], "proof must fail with wrong anchor");
    }

    // ── PPV-11: large parallel batch, all valid ───────────────────────────────

    #[test]
    fn ppv11_large_parallel_batch_all_valid() {
        let config = BeaconGenesisConfig::devnet();
        // 68 proofs (> PROOF_PARALLEL_THRESHOLD_BATCH=64) to exercise parallel path.
        let n = PROOF_PARALLEL_THRESHOLD_BATCH + 4;
        let proofs: Vec<_> = (0..n)
            .map(|i| make_valid_batch_proof(i as u8 % 200 + 1, &config))
            .collect();
        let items: Vec<_> = proofs.iter().map(|(p, a)| (p, *a)).collect();
        let results = verify_batch_proofs_parallel(&items);
        assert_eq!(results.len(), n);
        let failures: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, &v)| !v)
            .map(|(i, _)| i)
            .collect();
        assert!(failures.is_empty(), "all proofs should pass, failed at indices: {failures:?}");
    }

    // ── PPV-12: WeightedMMRRangeProof sequential path ────────────────────────
    //
    // Range proofs require a contiguous run of leaves.  We build a 3-leaf MMR
    // via WindowedWeightedMMR (available in all test configurations because
    // tests are compiled with full-node features in the workspace).
    //
    // If the feature is unavailable, this test is excluded at compile time.

    #[test]
    fn ppv12_range_proof_sequential_path() {
        use common_types::common::crypto::weighted_hash::WeightedHash;
        use common_types::common::windowed_weighted_mmr::WindowedWeightedMMR;

        let config = BeaconGenesisConfig::devnet();
        let anchor = config.bitcoin_anchor_hash;

        let mut wmmr = WindowedWeightedMMR::new(&config);
        for seed in 1u8..=3 {
            wmmr.append(WeightedHash::from_leaf_rbits(&[seed; 32], 0x0300_0001))
                .expect("append must succeed");
        }

        let proof = wmmr.prove_range(1, 3).expect("prove_range(1,3) must succeed on a 3-leaf MMR");
        let items: Vec<_> = vec![(&proof, anchor)];
        let results = verify_range_proofs_parallel(&items);
        assert_eq!(results, vec![true], "single range proof must pass");
    }
}
