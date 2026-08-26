# MMR Light Client — Shisha Network

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

> **Moved and refreshed Aug 26, 2026.** Originally `crates/filament/src/mmr_client/README.md`
> (written Jul 26, 2026, predates this repo's `filament-types`/`filament-p2p` crate split).
> Crate paths, full-node branding, and the "API Correctness" punch-list were updated against
> the current codebase; sections not specifically called out were carried forward unverified —
> see the currency notes inline where they apply. See [`../README.md`](../README.md) for the
> product-level overview; this is the deep technical reference.

A high-performance Rust library for implementing **Merkle Mountain Range (MMR) light clients** for the Shisha Network blockchain. The library enables lightweight verification of blockchain state with minimal resource requirements — only MMR peaks (O(log N) hashes) and a bounded recent-block cache, versus gigabytes for a full node.

## 🎯 Why MMR Light Clients?

### The Problem with Traditional SPV

A traditional SPV (Simplified Payment Verification) client proves a transaction is in the heaviest chain by downloading every block header and verifying its proof-of-work — O(n) work that grows with the chain. On Bitcoin's compact 80-byte headers that's manageable. On the Shisha Network it isn't: shard headers are ~2.2 KB each (they embed the merged-mining proof), and block intervals are short (mainnet/testnet: 600s beacon, 37.5s shard; devnet: 150s beacon, 9.375s shard). A wallet verifying a transaction on one shard after a year of mainnet operation would need ~1.85 GB of shard headers alone — multiplied by N active shards, and by every full node that has to serve it to every light client.

### How FlyClient / MMR Changes the Question

The insight from the FlyClient paper (Bünz et al.) is that a light client doesn't need to see every block to be convinced of the chain's total proof-of-work. A full node can instead provide a **statistically sampled proof**: a small, randomly selected subset of blocks whose cumulative difficulty, if honestly sampled, is overwhelmingly likely to represent the real chain weight.

This implementation's chain weight proof (`MMRChainWeightProofV2`) works as follows:

1. The full node builds a **weight space** — a normalised mapping of the chain's difficulty distribution from genesis to tip.
2. It draws 256–512 sample blocks using a **sequential exponential sampler** seeded by the tip block's hash. Because the seed comes from the tip's PoW hash, the prover cannot choose which blocks get sampled.
3. For each sample, it records the cumulative chain weight at that height.
4. It generates a `WeightedMMRBatchProof` with siblings for all sampled blocks, so the verifier can cryptographically confirm each sample exists in the MMR.
5. It includes mandatory **epoch boundary blocks** so the verifier can check difficulty adjustment transitions.

The verifier reconstructs the sampling algorithm deterministically from the seed and checks the reconstructed steps land on the heights the prover claimed. It never needs to see all blocks — just the sample set and its MMR inclusion proof.

### A Concrete Example

A beacon chain running for one year on devnet (~38,400 blocks at 150s/block) or three months on mainnet (600s/block) produces a chain weight proof of roughly:

```
Sampled heights, difficulties, chain weights (~320 samples):  ~9 KB
MMR inclusion siblings (320 × ~16 peaks × 32 bytes):         ~164 KB
Metadata, target block, epoch boundaries:                     ~0.6 KB
─────────────────────────────────────────────────────────────────
Total:                                                        ~173 KB
```

versus ~8.8 MB (devnet) or ~12 MB (mainnet) of full SPV headers for the same chain — roughly **70× smaller on mainnet**, and the ratio improves as the chain grows because the sample count is bounded (256–512) while SPV cost grows linearly.

`MMRChainWeightProofV2::bandwidth_efficiency()` computes this ratio at runtime:

```rust
pub fn bandwidth_efficiency(&self) -> f64 {
    let proof_size      = self.estimate_size_bytes() as f64;
    let full_chain_size = (self.range_length as f64) * 229.0;
    proof_size / full_chain_size  // e.g. 0.014 for a 1-year mainnet beacon chain
}
```

> **Epoch terminology:** `EPOCH_LENGTH = 4096` (blocks) is the canonical parameter adjustment epoch (~28 days at 600 s/block), confirmed in `k_coeff.rs` and asserted by `epoch_length_is_4096`. The DAA uses a separate 2048-block window (~14.2 days). `MMRChainWeightProofV2` includes mandatory boundary blocks from both schedules. Note: `BeaconChainHandler` and `ShardChainHandler` currently hardcode `blocks_per_epoch: 1008` — this is a stale placeholder that has not yet been updated to `EPOCH_LENGTH`.

After verification, the light client keeps only the genesis block (~230 bytes), the O(log N) MMR peaks (~640 bytes for a 1-million-block chain), and a bounded recent-block cache (default 100 blocks) — this is its local storage footprint, distinct from the proof transmitted over the wire.

The savings scale with header size, which is why they matter most for shard chains: the prover only needs `block.difficulty()` and an MMR sibling per sample, not the full 2.2 KB merged-mining header. A client tracking the beacon chain plus one shard receives two independent ~173 KB proofs, not 2× the full header download — proof size depends on sample count, not block count.

| Chain | SPV cost (1 year, mainnet) | MMR proof cost | Ratio |
|---|---|---|---|
| Bitcoin (80-byte headers, 10 min) | ~4.2 MB | ~45 KB | ~1% |
| Shisha beacon (229-byte headers, 10 min) | ~12 MB | ~173 KB | ~1.4% |
| Shisha shard (2,200-byte headers, 37.5 s) | ~1.85 GB | ~173 KB | ~0.009% |

### What This Does and Doesn't Prove

A chain weight proof is **trustless** (the sampling seed comes from the tip's PoW hash, which the prover cannot manipulate without redoing the work) and **statistically sound** (with 256–384 samples, the probability a 50%-hashpower adversary inflates claimed chain weight by 10% undetected is below 10⁻¹⁵, per `confidence_level` in `VerificationStatistics`). But it only convinces you the chain has a certain amount of cumulative work. It does not prove a specific transaction is in a specific block (use `verify_transaction_in_block` for that), replace the need for full nodes as the source of truth, or guarantee UTXO validity (the light client has no UTXO set). The chain weight proof bootstraps trust in the chain's length and difficulty history; subsequent batch or range proofs then prove specific block or transaction inclusion against the MMR root you've verified.

---

## 🚀 Quick Start

### Installation

This library is the `filament` crate (`crates/filament/` in this repo), built on
`filament-types` (wire types + verification math) and, for the P2P/HTTP surfaces,
`filament-p2p`:

```toml
[dependencies]
filament = { path = "../../crates/filament", features = ["full-node"] }
```

`full-node` (alias `server`) enables the HTTP API (`filament_server`), Schnorr wallet
signing, and the Path-2 P2P dialer (`filament_p2p`). Omit it for a verification-only
build with no networking.

### Basic Example

```rust
use filament::{MultiChainClient, InMemoryStorage};
// Use FilamentBootstrapConfig — LightClientConfig is a deprecated alias (renamed RF-11)
use filament::mmr_client::light_client_config::FilamentBootstrapConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load network configuration
    let config = FilamentBootstrapConfig::from_file("light_client_config.toml")?;

    // 2. Initialise light client
    // MultiChainClient::new takes only storage; genesis is registered separately
    // via init_beacon_chain after calling init_from_network (or apply_beacon_summary).
    let storage = Box::new(InMemoryStorage::new());
    let mut client = MultiChainClient::new(storage);

    // 2b. Optionally bootstrap from config (sets network, loads genesis via init_from_network)
    // let mut client = MultiChainClient::from_config_file("light_client_config.toml", storage)?;
    // client.init_from_network("devnet").await?;

    // 3. Sync from network (you supply the transport)
    let summary = fetch_chain_summary_from_network()?;
    client.apply_beacon_summary(summary)?;

    // 4. Verify transaction
    let tx_hash: [u8; 32] = /* your transaction hash */ [0u8; 32];
    let is_confirmed = client.verify_transaction(tx_hash, &merkle_proof, block_height)?;

    println!("Transaction confirmed: {}", is_confirmed);
    Ok(())
}
```

> **Note:** The library does not include a built-in network layer. `fetch_chain_summary_from_network` above is a placeholder for your own transport code — see [Network Protocol](#network-protocol) for the request/response types to serialise over HTTP, WebSocket, or any other transport.

---

## 📚 Key Features

### 1. Three-Level Block Data

The library implements an intelligent block data system that balances security with wire efficiency:

| Variant | Size | PoW Verifiable | Shard ID Derivable | Typical Use |
|---------|------|---------------|-------------------|-------------|
| `BeaconBlockData` | ~229 bytes | ✅ Full | ✗ (beacon has no shard) | Beacon chain proofs |
| `FullShardBlockData` | ~1,200–2,200 bytes | ✅ Full | ✅ | Recent blocks, chain weight proofs |
| `LightShardBlockData` | ~161 bytes ⚠️ | ✗ (stored `pow_hash`) | ✅ | Historical blocks, transaction history |

> ⚠️ **`LightShardBlockData` size discrepancy:** the README Key Features table (above) gives ~161 bytes; `mod.rs` gives ~194 bytes. The authoritative figure should be derived from the serialised `LightShardHeader` struct fields. The "91% bandwidth savings" claim is directionally correct at both sizes vs ~2,200 bytes, but the exact figure needs reconciling with the struct definition.

**Full Shard Blocks** carry everything needed for independent PoW verification:
```rust
pub struct FullShardBlockData {
    // Core fields (~100 bytes)
    pub height: u32,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub merkle_root: [u8; 32],
    pub difficulty: u64,         // shard-native; use .bits() for nBits format (CV-30 fix)

    // PoW verification data (~2,100 bytes)
    pub beacon_header: BeaconHeader,         // 88 bytes — needed for PoW hash
    pub shard_merkle_proof: Vec<[u8; 32]>,  // ~320 bytes — prove to merged mining tree
    pub orange_encoding: OrangeTreeEncoding, // ~20 bytes — active shard structure
    pub merged_mining_proof: Vec<[u8; 32]>, // ~640 bytes — prove to beacon
    pub merged_mining_number: u32,
}
```

**Light Shard Blocks** drop the ~2,000 bytes of PoW material, keeping only the pre-calculated hash:
```rust
pub struct LightShardBlockData {
    pub height: u32,
    pub prev_mmr_root: WeightedHash,
    pub current_mmr_root: WeightedHash,
    pub merkle_root: [u8; 32],
    pub difficulty: u64,

    // Pre-calculated PoW hash (stored by the prover, not re-derived by verifier)
    pub pow_hash: [u8; 32],
    // ~2,000 bytes of PoW verification data omitted
}
```

**Bandwidth saving:** 91% reduction for historical blocks (161 bytes vs ~2,200 bytes).

**When to use each:**
- **Full blocks:** Recent sync, chain weight proofs, initial sync
- **Light blocks:** Historical transaction lookups, deep history (PoW already proven by chain weight)

All three variants are carried in the `BlockData` enum. Key methods:

```rust
block.height()                // u32
block.block_hash()            // [u8; 32]
block.block_hash_weighted()   // WeightedHash (SHA256d[0..28] + rBits for leaves)
block.prev_mmr_root()         // WeightedHash
block.mmr_root()              // WeightedHash (current_mmr_root)
block.difficulty()            // u64
block.bits()                  // u32 — nBits encoding (use this for target calculation)
block.can_verify_pow()        // bool — false for LightShardBlockData
block.derive_shard_id(k_bits) // Option<u32> — None for beacon blocks
```

### 2. Reading Network Governance Parameters from Headers

The beacon chain has two consensus-level voting mechanisms — **k-coefficient voting** (shard reward scaling) and **shard expansion voting** (active shard count) — each governed by a vote bit in `BlockVersion` and a self-describing, PoW-committed field in `BeaconBlockCandidateHeader`. Filament cannot verify the consensus rules behind either mechanism (that requires full epoch vote-tally history, which only a full node maintains), but it **can** read the current committed value directly out of any verified beacon header, with no extra trust assumption beyond the MMR proof you already verified.

```rust
// committed_chain_count is part of the 80-byte mining header and is covered by
// the block's PoW hash — a verified header's value cannot be forged independently
// of redoing the proof-of-work.
//
// NOTE: k_committed_kbits is NOT in individual block headers (Path A decision,
// Jun 24 2026). k is derived from chain state (EpochKState) at epoch boundaries
// and propagated via ShardParameters. Do NOT read it from BeaconBlockCandidateHeader.
let committed_chain_count: u16  = beacon_header.committed_chain_count;

// Decode k from chain state — use EpochKState / ShardParameters, not the header.
// `k_bits`/`kbits_to_float` (display/logging-only conversion, never consensus
// arithmetic) is NOT part of this packaging's `filament-types` surface —
// filament's own code never reads k-coefficient directly, so it wasn't
// ported. If you need it, add the real `k_bits` module from the private
// monorepo's `common-types` crate to your own build.

println!("active shard count (network-wide): {}", committed_chain_count);
```

**What this is good for:** a UI dashboard or wallet status panel that wants to show "shard reward coefficient: 0.0234" or "active shards: 12" using only data the user's own Filament instance has already cryptographically verified — no separate trusted API call to a full node's `/config` or `/chains` endpoint required.

**What this is NOT:** a verification of the voting mechanism itself. Filament does not (and architecturally cannot, without becoming a full node) replay epoch vote tallies, confirm that `k_active_kbits` (derived in `EpochKState::finalise_epoch`) matches what the actual vote history would have produced, or confirm that `committed_chain_count` is within the consensus bound (`≤ active_shard_count + step`). Those checks (rules K-1, EX-7, EX-7b, EX-8) are full-node-only validation rules. A malicious miner who briefly seizes majority hashrate could, in principle, commit an incorrect value to a header that still passes Filament's MMR and PoW checks — Filament has no way to detect this on its own. Display these values as "the network's current self-reported parameter," not as "verified consensus state."

| Field | Type | Location | What it represents | Filament can verify? |
|---|---|---|---|---|
| `k_active_kbits` | `u32` | `EpochKState` / `ShardParameters` (chain state only — **not** in block header, Path A Jun 24 2026) | Compact-encoded shard reward coefficient `k`, active for the epoch | ✗ — full-node epoch state; Filament reads via `ShardParameters` |
| `committed_chain_count` | `u16` | `BeaconBlockCandidateHeader` (2 bytes, PoW-committed) | Network-wide active shard count as of this block | ✗ — opaque, PoW-committed only |

Both fields use `#[serde(default)]` for backward compatibility — headers from before each feature was deployed deserialise with the field set to `0`. Treat `0` as "value not present in this header," not as a literal k of zero or zero active shards.

> **Three-parameter taxonomy — do not conflate:**
> - **`hash_sorting_bits` / `s`** — PoW hash low bits → shard assignment (`derive_shard_id`, genesis config, block version bits 0–3).
> - **`KBits` / `k_active_kbits`** — k-coefficient economic multiplier (epoch voting, shard rewards).
> - **`BLOCK_HASH_W_BITS` / `w_bits`** — compact chain-weight exponent in `WeightedHash` rBits (fork choice; permanent constant 4).

### 3. Flexible Verification Strategies

`VerificationStrategy` applies to **chain-weight** verification (`verify_chain_weight_proof_with_strategy`). Batch and range inclusion use `WeightedMMR*Proof::verify_with_anchor` directly.

```rust
use filament::mmr_client::verification::{
    verify_chain_weight_proof_with_strategy,
    VerificationStrategy,
};

let ok = verify_chain_weight_proof_with_strategy(
    &weight_proof, VerificationStrategy::Paranoid, &genesis_block,
);
```

| Strategy | PoW Verify | Accepts Light Blocks | Use for |
|----------|------------|---------------------|---------|
| Paranoid | ✅ All blocks | ❌ Never | Initial sync, chain weight |
| Full | ❌ Skip | ✅ (Light blocks accepted; chain-weight proofs require Full blocks) | Default |
| Light | ❌ Skip | ✅ | Historical queries, after chain weight verified |

### 4. Multi-Chain Support

```rust
// Beacon chain (coordination layer)
client.apply_beacon_summary(beacon_summary)?;

// Shard chains (execution layers)
client.register_shard(0, shard0_genesis)?;
client.register_shard(1, shard1_genesis)?;
```

Storage is namespaced by `ChainId` (`ChainId::Beacon` or `ChainId::Shard(u32)`) so beacon and shard state never collide.

### 5. Weighted Proof Verification (production path)

Proofs are generated by `WindowedWeightedMMR::prove_batch` / `prove_range` and verified via
`WeightedMMRBatchProof::verify_with_anchor` / `WeightedMMRRangeProof::verify_with_anchor`.
Benchmark groups: `batch_verify` and `range_verify` in the proof optimization benches (RF-17 Batch D, Jun 2026).

### 6. Parallel Verification

For batches of independent proofs (e.g. during initial sync across multiple shards), use the parallel API:

```rust
use filament::mmr_client::{verify_batch_proofs_parallel, verify_range_proofs_parallel};

let pairs: Vec<(&WeightedMMRBatchProof, [u8; 32])> =
    proofs.iter().map(|p| (p, anchor)).collect();

let results = verify_batch_proofs_parallel(&pairs);
```

The thread pool is initialised once via `OnceLock`. Parallelism kicks in above these thresholds (PARV-THRESH-1, closed June 2, 2026 — Linux 4-core production recommendation):

| Threshold constant | Value | Description |
|--------------------|-------|-------------|
| `PROOF_PARALLEL_THRESHOLD_BATCH` | 64 | Min batch proofs before rayon is used |
| `PROOF_PARALLEL_THRESHOLD_RANGE` | 16 | Min range proofs before rayon is used |
| `PROOF_MAX_THREADS` | 4 | Hard cap (half of available cores) |

The batch threshold is 64, not 32. Profiling showed non-monotonic behaviour at N=32 on 4-core (parallel sometimes slower than sequential due to scheduling jitter at that boundary); N=64 is reliably faster. Range crossover is cleaner and confirmed at N≈8–16; threshold set conservatively to 16. `pool_init` (warm `OnceLock` fast-path) = 2.0 ns.

---

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────┐
│                  MultiChainClient                       │
│  (High-level coordinator for beacon + N shards)         │
└────────────────┬────────────────────────────────────────┘
                 │
      ┌──────────┴──────────┐
      │                     │
┌─────▼──────┐      ┌───────▼────────────┐
│  Beacon    │      │  Shard Handlers    │
│  Handler   │      │  (0, 1, 2, ... N)  │
└─────┬──────┘      └───────┬────────────┘
      │                     │
      └──────────┬──────────┘
                 │
        ┌────────▼─────────┐
        │   ChainHandler   │
        │  (Base handler)  │
        └────────┬─────────┘
                 │
        ┌────────▼─────────┐     ┌────────────────────┐
        │   ChainState     │────▶│ WeightedMMRLight   │
        │   - tip height   │     │ (WeightedHash      │
        │   - chain weight │     │  peaks + rBits)    │
        │   - recent cache │     └────────────────────┘
        └────────┬─────────┘     └────────────────────┘
                 │
        ┌────────▼─────────┐
        │     Storage      │
        │  (ChainId-scoped)│
        └──────────────────┘
```

### Module Map

```
mmr_client/
├── verification.rs              — Core proof verification (batch, range, fork, chain weight)
├── parallel_verifier.rs         — Rayon-based parallel verification
├── proof_selector.rs            — Auto-selects range vs batch strategy by density
├── protocol.rs                  — Wire protocol: LightClientRequest / LightClientResponse
├── chain_handler.rs             — Generic per-chain verified state machine (ChainState → WeightedMMRLight)
├── beacon_handler.rs            — Beacon-specific handler (epoch tracking)
├── shard_handler.rs             — Shard-specific handler (epoch sync from beacon)
├── multi_chain_client.rs        — Unified client across beacon + all shards
├── mmr_light.rs                 — Legacy MMRLight ([u8;32] peaks — retained for unit tests only)
├── weighted_mmr_light.rs        — WeightedMMRLight (WeightedHash peaks — wired to ChainState)
├── storage.rs                   — LightClientStorage trait + InMemoryStorage + FileStorage
├── light_client_config.rs       — Config structs (loaded from light_client_config.toml)
├── filament_wallet.rs           — Watch-only wallet: UTXO discovery, fee estimation, UTXO selection,
│                                  Schnorr-signed tx building. Delegates UTXO data to Keystone full node.
│                                  Core signing/submission gated behind `full-node` feature flag.
├── filament_server.rs           — (not yet documented — outside mmr_client/ or undocumented server layer)
└── mod.rs                       — Module exports
```

---

## 📖 Core Concepts

### Merkle Mountain Range (MMR)

An MMR is an append-only binary forest that efficiently proves inclusion of any leaf.

**CRITICAL: MMR-Style Indexing**

This library uses **position-based MMR indexing** where each node's index is determined by its position in the tree, not by sequential insertion order:

```
MMR Index Formula: position = 2 × leaf_height_in_chain

Height 0:  pos 0     pos 2     pos 4     pos 6      pos 8     pos 10    pos 12    pos 14
           (blk 0)  (blk 1)   (blk 2)   (blk 3)   (blk 4)   (blk 5)   (blk 6)   (blk 7)
              └────┬────┘         └────┬────┘           └────┬────┘         └────┬────┘
Height 1:       pos 1              pos 5                 pos 9              pos 13
                   └──────────┬──────────┘                   └──────────┬──────────┘
Height 2:                  pos 3                                     pos 11
                               └─────────────────────┬─────────────────────┘
Height 3:                                          pos 7
                                                   (root)

Parent position = (left_child_pos + right_child_pos) / 2
```

**Why this matters:**
- Block at height 5 always has position 10, regardless of total chain size
- Parents are the arithmetic mean of their children
- No reindexing on append — existing positions never change
- Lock-free concurrent reads (positions are stable)

| Feature | Traditional MMR | This Implementation |
|---------|----------------|---------------------|
| Indexing | Sequential (1, 2, 3 …) | Position-based (2h) |
| On append | Renumber all nodes | No reindexing ever |
| Concurrency | Requires locks | Lock-free reads |
| Proof generation | Complex navigation | Simple arithmetic |

### WeightedHash

Every MMR node carries a `WeightedHash` — a 32-byte value packing a 224-bit hash with a 32-bit compact rBits field encoding cumulative proof-of-work difficulty. The hash portion differs by node type: **leaf nodes** take the first 28 bytes of the block's SHA256d PoW hash (no re-hashing); **internal nodes** use BLAKE3 truncated to 224 bits of the concatenated child hashes. Chain weight is **read directly from the MMR root** without a separate field:

```rust
let root: WeightedHash = mmr.get_root();
let approx_weight: u128 = root.cumulative_difficulty_approx();
```

### Proof Types

Production paths use the `Weighted*` family on `WeightedHash` nodes. Plain `MMRBatchProof` / `MMRRangeProof` remain in `common::proofs` as deprecated wire-compat types (since 0.7.0); do not call the removed `verify_batch_proof` / `verify_range_proof` helpers.

| Proof | Type | Verified by |
|---|---|---|
| Batch inclusion (weighted) | `WeightedMMRBatchProof` | `.verify_with_anchor(anchor)` |
| Range inclusion (weighted, compact) | `WeightedMMRRangeProof` | `.verify_with_anchor(anchor)` |
| Fork (current) | `ForkProof` | `verify_fork_proof` or `ForkProof::verify` |
| Chain weight (weighted) | `WeightedChainWeightProof` | `verify_weighted_chain_weight_proof` |
| Chain weight (legacy v1) | `MMRChainWeightProof` | `verify_chain_weight_proof` |
| Delta-encoded batch (P2P) | `DeltaBatchProof` | `verify_delta_batch_proof` |
| Batch inclusion (legacy) | `MMRBatchProof` | *(deprecated — use WeightedMMRBatchProof)* |
| Range inclusion (legacy) | `MMRRangeProof` | *(deprecated — use WeightedMMRRangeProof)* |

All proof types are defined in `common::proofs`.

**Fork proofs:** Use `ForkProof` (from `common::proofs::fork_proof`) for all new code. It carries full sibling paths for cryptographic climb-and-descent verification. `MMRForkProof` and the older `WeightedAdvancedForkProof` are deprecated since 0.6.0.

---

## 🔧 Verification

### Core Functions

```rust
use filament::mmr_client::verification::{
    verify_fork_proof,
    verify_chain_weight_proof,
    verify_weighted_chain_weight_proof,
    VerificationStrategy,
};
use common_types::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof, BlockData};

// Batch / range — verify on the proof type directly
let ok = batch_proof.verify_with_anchor(anchor);
let ok = range_proof.verify_with_anchor(anchor);

// Fork proof (ForkProof type) — returns Result<ForkProofResult, ForkProofError>
// genesis_block_hash is WeightedHash (the weighted leaf hash of genesis), not [u8;32]
use common_types::common::crypto::weighted_hash::WeightedHash;
use common_types::common::proofs::fork_proof::{ForkProofResult, ForkProofError};
let genesis_block_hash: WeightedHash = genesis_block.block_hash_weighted();
match fork_proof.verify(bitcoin_anchor, genesis_block_hash) {
    Ok(ForkProofResult { our_chain_heavier, .. }) => {
        println!("fork resolved — our chain heavier: {}", our_chain_heavier);
    }
    Err(ForkProofError::InvalidPath(msg)) => eprintln!("invalid fork proof: {}", msg),
    Err(e) => eprintln!("fork proof error: {:?}", e),
}

// Chain weight proof (weighted path preferred)
// Note: second arg is genesis_anchor [u8; 32] (bitcoin_anchor_hash), not a BlockData
let anchor: [u8; 32] = genesis_config.bitcoin_anchor_hash;
let ok = verify_weighted_chain_weight_proof(&weight_proof, anchor);
```

Batch and range proofs take an anchor hash (`[u8; 32]` from `BeaconGenesisConfig::bitcoin_anchor_hash`). Chain-weight verification checks genesis consistency and optionally verifies PoW per `VerificationStrategy`.

### Weighted Proof Verification

The `Weighted*` types verify directly on the `WeightedHash` MMR. Use `BeaconGenesisConfig` to obtain the anchor:

```rust
use common_types::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};
use common_types::common::genesis::genesis_config::BeaconGenesisConfig;

let config = BeaconGenesisConfig::devnet();
let anchor = config.bitcoin_anchor_hash;  // [u8; 32]

let ok = batch_proof.verify_with_anchor(anchor);
let ok = range_proof.verify_with_anchor(anchor);
```

`WeightedMMRRangeProof` uses a **compact sibling format**: one sibling path per aligned subtree peak rather than one per leaf, yielding O(R + K log N + P) complexity vs O(R × log N) for the per-leaf approach. The proof also carries `range_rbits` — the total chain work for the range without summing individual leaves.

### Delta-Encoded Batch Proofs

`DeltaBatchProof` (Phase 7 Track D) transmits only the changed peaks between consecutive blocks, cutting peak-section wire size by ~80%:

```
WeightedMMRBatchProof, N=500, 17 peaks: 500×17×32 = 272 KB (peaks) + 272 KB (siblings) ≈ 544 KB
DeltaBatchProof,       N=500, 17 peaks: 17×32 (base) + 500×1.2×33 (deltas) ≈ 20 KB peaks
                                         + 272 KB (siblings unchanged) ≈ 292 KB  → −46%
```

Gated behind `ProtocolFeature::DeltaProofs` (introduced Shish v6, confirmed in `version_registry.rs`; carried forward into v7 alongside `MultiChainTxBatch`); peers that don't support it receive the full `WeightedMMRBatchProof` unchanged. Use `DeltaBatchProof::from_batch_proof` on the prover side and `verify_delta_batch_proof` on the verifier side. The two functions are semantically equivalent for the same leaf set (CV-32 invariant).

### Proof Selector

When you have a set of block heights to prove, `ProofSelector` picks the cheaper strategy automatically:

```rust
use filament::mmr_client::proof_selector::{ProofSelector, ProofStrategy, DEFAULT_DENSITY_THRESHOLD};

match ProofSelector::analyze(&heights, target_height, DEFAULT_DENSITY_THRESHOLD)? {
    ProofStrategy::Range { start, end } => {
        // request GetRangeProof { start, end, target_height }
    }
    ProofStrategy::Batch { heights } => {
        // request GetBatchProof { heights, target_height }
    }
}
```

`DEFAULT_DENSITY_THRESHOLD` is `0.35`: if ≥ 35% of the span is requested, a range proof is cheaper (calibrated from Linux 2-core bench data, May 2026). `ProofSelector::analyze` deduplicates and sorts its input; pass raw unsorted heights safely. Use `analyze_with_stats` to log the density decision alongside the result.

---

## 🏦 Storage

```rust
use filament::mmr_client::storage::{LightClientStorage, InMemoryStorage, FileStorage};

// In-memory (testing, ephemeral clients)
let storage = Box::new(InMemoryStorage::new());

// File-backed (persistent light client — JSON via serde)
let storage = Box::new(FileStorage::new(PathBuf::from("~/.shisha/light_client"))?);
```

All storage operations are namespaced by `ChainId` to prevent collisions between chains:

```rust
pub trait LightClientStorage: Send + Sync {
    fn save_state(&mut self, chain_id: ChainId, state: &ChainState) -> Result<(), String>;
    fn load_state(&self, chain_id: ChainId) -> Result<ChainState, String>;
    fn save_block(&mut self, chain_id: ChainId, block: &BlockData) -> Result<(), String>;
    fn load_block(&self, chain_id: ChainId, height: u32) -> Result<Option<BlockData>, String>;
    fn delete_blocks_above(&mut self, chain_id: ChainId, height: u32) -> Result<(), String>;
    fn stats(&self) -> StorageStats;
}
```

Implement `LightClientStorage` for custom backends (RocksDB, SQLite, etc.). SQLite is documented as planned but not yet implemented — see [Open Work](#open-work) below.

---

## 📡 Connecting to a Full Node (Keystone)

Filament communicates with a **Keystone** full node over HTTP REST. The full node runs an Axum HTTP server on the port configured in `[light_client] port` (default 8080).

### HTTP endpoints (Keystone full node)

| Endpoint | Returns | Notes |
|---|---|---|
| `GET /health` | `{"status":"healthy","node_type":"full_node"}` | Always 200 |
| `GET /chain/height` | `{"height": N}` | Current beacon tip |
| `GET /chain/summary` | Recent blocks + batch proof | Last `recent_blocks` blocks (default 100) |
| `GET /chain/summary/{count}` | Same, parameterised | |
| `GET /chain/range/{start}/{end}` | `WeightedMMRRangeProof` (JSON) | Inclusive range; genesis (height 0) cannot be `start` |
| `GET /chain/weight/{start}/{end}` | `WeightedChainWeightProof` (JSON) | Beacon only |
| `GET /chain/proof?heights=…&target=…` | Range or batch proof | Server auto-selects cheaper type |
| `GET /chain/fork/{a}/{b}` | `ForkProof` (JSON) | `build_fork_proof_for_peer` |
| `GET /events` | SSE stream at 1 Hz | Live chain + peer metrics |
| `GET /metrics` | Prometheus text | `net_in_bps`, `net_out_bps`, `api_proofs_total` |

**Quick test:**

```bash
curl http://localhost:8080/health
curl http://localhost:8080/chain/height
curl http://localhost:8080/chain/summary/10    # last 10 blocks
curl http://localhost:8080/chain/range/100/200 # range proof blocks 100–200
curl -N http://localhost:8080/events           # SSE stream
```

### Proof sizes (bincode-serialised, 1,000-block chain)

| Type | Range | Approx. size |
|---|---|---|
| `WeightedMMRRangeProof` | 100 blocks | ~12 KB |
| `WeightedMMRRangeProof` | 10 blocks | ~2 KB |
| Chain summary | 100 recent blocks | ~15 KB |
| `WeightedChainWeightProof` | Any tip | ~46 bytes |
| `ForkProof` | Depth 10 | ~500 bytes |

### Critical operational constraints

**1. The full node cannot yet independently sync from peers.**

`FullNodeManager` loads chain state from its own `rustmmrdb` storage, which the mining pool process writes. There is currently no background loop to pull new blocks from P2P peers — the full node is a proof-serving layer over the mining pool's data, not a fully autonomous node. Consequence: Filament clients should treat the full node's tip height as an artifact of the co-located mining pool's activity. For a standalone proof server, the chain sync loop (full node open item #3) must be implemented first.

**2. The full node has no revert path for deep reorganisations.**

`FullBeaconChain::revert_to_height` is not yet implemented (`FullShardChain` has it; `FullBeaconChain` does not). If the full node's chain diverges from the network canonical chain by more than `MAX_REORG_DEPTH = 100` blocks, it cannot recover automatically. Filament clients connecting to a full node affected by a deep reorg will receive stale proofs. Mitigation: connect to multiple independent full nodes and compare tip heights and MMR roots before accepting a proof.

**3. `light_client_protocol.rs` serves `MMRChainWeightProof` (vanilla), not `WeightedChainWeightProof`.**

The `/chain/weight/{start}/{end}` endpoint currently generates proofs via the vanilla `MMRChainWeightProof` path, not the `WeightedChainWeightProof` path. This is a known deferred item (v0.5.0 cleanup schedule). Use `verify_chain_weight_proof` (not `.verify()` on `WeightedChainWeightProof`) when handling proofs from this endpoint.

### `LightClientRequest` / `LightClientResponse` (internal protocol layer)

`LightClientRequest` and `LightClientResponse` are serde-serialisable enums used by `LightClientProtocolHandler` internally. They are not the HTTP wire format — the HTTP API uses plain JSON. These types are relevant if you are implementing a custom transport (e.g. WebSocket or direct TCP) using `LightClientProtocolHandler<C>` on the full node side:

```rust
use filament::mmr_client::protocol::LightClientRequest;
use filament::mmr_client::proof_selector::DEFAULT_DENSITY_THRESHOLD;

// Auto-detecting request — server resolves to RangeProof or BatchProof
let req = LightClientRequest::GetBlockProof {
    heights: vec![100, 150, 200],
    target_height: 500,
    density_threshold: DEFAULT_DENSITY_THRESHOLD,
};

let bytes = req.to_bytes()?;
// ... send bytes over your transport ...
let req = LightClientRequest::from_bytes(&bytes)?;
```

Available request variants:

| Variant | When to use |
|---|---|
| `GetChainSummary` | Bootstrap / tip check |
| `GetRangeProof` | Known contiguous range |
| `GetBatchProof` | Known sparse height set |
| `GetBlockProof` | Prefer this — server picks cheaper strategy |
| `GetForkProof` | Detect divergence from a peer |
| `GetChainWeightProof` | Prove heaviest chain |
| `GetTransaction` | SPV transaction lookup |

### P2P push transport: Tiered Broadcast (TB)

> **Scope note (this packaging):** `filament-p2p` in this repo implements the
> Path-2 mechanism below (`WatchAddress` out, `TxInclusionNotif`/`TxSpentNotif`/
> `TxRevertNotif` in) — a minimal, independently-written client. It does
> **not** implement Tiered Broadcast (the header-push mechanism described in
> this section). The description is kept here as accurate documentation of
> what a full node's P2P layer offers, not a claim that this crate's client
> consumes it. If you need live header push rather than Path-2 polling
> semantics, you'd need to extend `filament-p2p` to classify into the
> light-client tier and handle the pushed header messages described below.

Beyond the request/response HTTP and `LightClientProtocolHandler` paths above, the P2P layer (`src/p2p/common/manager/core.rs`) supports a third transport: a **push** path where a connected full node proactively sends new beacon/shard headers to light-client peers over a live TCP connection, without the client polling.

**How peer classification works:** on handshake completion, the full node inspects the peer's declared services bit. A peer that does not advertise `NODE_NETWORK` is classified into the **light-client tier** (`light_client_write_halves`) rather than the **full-node tier** (`full_node_write_halves`). These are separate write-half maps — a full node tracks two independent broadcast fan-out lists and sends different payloads to each:

| Tier | Receives | Trigger |
|---|---|---|
| Full-node tier | Full block bodies, `Inv`, `GetData`, compact block announcements | `caps.is_full_node()` (advertises `NODE_NETWORK`) |
| Light-client tier | Compact headers only (`BroadcastJob::LightClientHeader`) | Default — any peer that doesn't advertise `NODE_NETWORK` |

**What gets pushed:** `broadcast_header_to_light_clients(chain_type, shard_id, header_bytes)` sends an 80-byte beacon mining header (`chain_type = 0x00`) or `LightShardHeader` bytes (`chain_type = 0x01`, with `shard_id` set) to every connected peer in the light-client tier, every time a new tip is confirmed. This is a header push, not a proof push — Filament still needs a follow-up `GetRangeProof`/`GetBatchProof` (HTTP or `LightClientProtocolHandler`) to get an MMR inclusion proof for the new header before treating it as verified.

**Operational note for mining pool nodes:** `NodeRole::MiningPool` causes `getheaders` requests from light-client-tier peers to be silently dropped (no response, no ban). This is intentional — mining pool processes do not serve historical sync to light clients. Only full nodes (`NodeRole::FullNode`) serve `getheaders`. If you are implementing a raw P2P transport for Filament (rather than using the HTTP API), connect to a Keystone full node, not a Kameniar mining pool peer.

**Why this matters for a custom transport implementation:** if you build a P2P-based sync path for Filament instead of HTTP polling, you do not need to advertise `NODE_NETWORK` in your version message — doing so would place you in the full-node tier and subject you to full block body broadcasts you don't need. Omit the flag to be classified into the lighter-weight tier automatically.

---

## ⚙️ Configuration

Bootstrap from `light_client_config.toml`. Each network section provides genesis and Bitcoin anchor information.

```toml
[devnet]
network_id               = "devnet"
genesis_hash             = "000...000"   # set after genesis mining
genesis_height           = 0
genesis_timestamp        = 1704067200
genesis_difficulty       = 1
genesis_bits             = 0x1d100000    # MAX_TARGET ≈ 2^228
genesis_mmr_root         = "4ae199..."   # equals bitcoin_anchor_hash until genesis mined
bitcoin_anchor_hash      = "4ae199..."   # Bitcoin block 935093 (internal byte order)
bitcoin_anchor_height    = 935093
bitcoin_anchor_timestamp = 1704067200

[sync]
recent_blocks_cache_size = 100
poll_interval_secs       = 10
max_concurrent_requests  = 10
range_proof_batch_size   = 100
request_timeout_secs     = 30
paranoid_mode            = false

[peers.devnet]
peers = ["localhost:8332"]
```

> **Byte order:** `bitcoin_anchor_hash` and `genesis_mmr_root` must be in **internal (little-endian) byte order** — the reverse of what block explorers display.

Bitcoin anchor hashes by network (confirmed from `genesis_config.rs::bitcoin_anchors`):

| Network | Bitcoin block | Internal hash (first 8 bytes) | nBits | Network magic |
|---|---|---|---|---|
| Devnet | 935,093 | `4ae19982df01cb02…` | `0x1d100000` | `[0xFF,0xFF,0xFF,0xFF]` |
| Testnet1 | 935,092 | `46229c66dceb87cf…` | `0x1d00ffff` | `[0x0B,0x11,0x09,0x07]` |
| Testnet2 | 935,091 | `29d5d423d7cb7ea3…` | `0x1a100000` | `[0x0C,0x12,0x0A,0x08]` |
| Mainnet | TBD | all zeros (placeholder) | `0x1a010000` ⚠️ | `[0xF9,0xBE,0xB4,0xD9]` |

⚠️ **Mainnet nBits discrepancy:** `genesis_config.rs::mainnet()` sets `bits = 0x1a010000` (MAX_TARGET = 2^200) but `genesis_mainnet.toml` currently sets `bits = 0x1d00ffff` (Bitcoin genesis target). These must be reconciled before mainnet launch. The code value (`0x1a010000`) is the authoritative intended value per the `BeaconGenesisConfig::mainnet()` doc comment.

> **`bitcoin_anchor_timestamp`** is set to `1704067200` (2024-01-01 UTC) for all networks as a placeholder. For devnet this is intentional. For mainnet and testnet networks, the actual Unix timestamp of the chosen Bitcoin anchor block should be used — it serves as the epoch for TS-DELTA relative timestamp encoding in block headers.

Load in code:

```rust
// FilamentBootstrapConfig is the current name; LightClientConfig is a deprecated alias (RF-11)
use filament::mmr_client::light_client_config::FilamentBootstrapConfig;

let config  = FilamentBootstrapConfig::from_file("light_client_config.toml")?;
let network = config.get_network("devnet").unwrap();
let genesis = network.to_block_data()?;  // BlockData::Beacon(BeaconBlockData { … })
```

Alternatively, use `BeaconGenesisConfig` from `common::genesis::genesis_config` for hardcoded constants in tests:

```rust
use common_types::common::genesis::genesis_config::BeaconGenesisConfig;

let cfg    = BeaconGenesisConfig::devnet();
let anchor = cfg.bitcoin_anchor_hash;  // [u8; 32]
let k_bits = cfg.hash_sorting_bits;               // 4 for all Shisha networks
```

> **Config naming (RF-11, Jun 2026):** Two distinct config types exist:
> - **`config::MmrLightClientConfig`** — full-node / pool HTTP light-client API (`[mmr_light_client]` or legacy `[light_client]` in `config.toml`).
> - **`mmr_client::FilamentBootstrapConfig`** — Filament bootstrap from `light_client_config.toml` (genesis hashes, peers, sync). Deprecated alias: `LightClientConfig`.

> **`mmr_node_window` affects proof availability.** If the full node you are connecting to has set `mmr_node_window` in its `[full_node]` config to a finite value (e.g. 4096), it can only serve proofs for leaves within the active window. Proofs for older blocks require `SpendFlagsColdStore` (WMMR Step 8). Until Step 8 is confirmed active on your peer, connect to a node running with `mmr_node_window = 4294967295` (the default — eviction disabled) if you need historical proofs.

### Anchoring (two levels)

**Only the beacon chain genesis** uses a Bitcoin block as its external anchor:

```
Beacon genesis prev_mmr_root = bitcoin_anchor_hash

→ Cannot mine beacon genesis before that Bitcoin block exists
→ Cryptographically links the Shisha Network root of trust to Bitcoin
```

**Every shard genesis** anchors to a **beacon** block's `current_mmr_root` (CV-23 /
`validate_shard_genesis_linkage`) — never to Bitcoin. See
`docs/plan/network-genesis-and-anchoring.md`.

Beacon-side checks live in light-client `ChainState::set_genesis()` and
full-node genesis validation; shard height-0 uses the shared common-types helper.

---

## 🔒 Security Model

### Why This Library Will Never Use Zero-Knowledge Proofs

ZK-based light clients have become fashionable. This library will not adopt them. The reason is not philosophical preference or complexity aversion — it is a mathematical objection.

**ZK "proofs" are not proofs in the mathematical sense.** A proof in mathematics is absolute: a valid derivation from axioms. A ZK "proof" is a probabilistic argument — a transcript that makes a false statement *astronomically unlikely* to pass verification. The terminology is borrowed from mathematics but the concept is different. This distinction matters enormously in adversarial settings where the cost of being wrong is permanent and irreversible.

**The security rests on unproven assumptions.** ZK proof systems (SNARKs, STARKs, and their variants) are secure under assumptions — typically that certain mathematical problems are hard, or that certain algebraic structures behave in ways that have not been formally proved. These are conjectures, not theorems. Cryptographers work with them because they appear to hold in practice. But "appears to hold" is not the same as "is proved," and the history of cryptography includes many assumptions that held until they didn't.

**Trusted setup is a structural problem, not an implementation detail.** Many ZK systems require a trusted setup ceremony: a group of people generates shared secret parameters, then must destroy them. If any participant retains the secrets, they can forge proofs undetectably. The security of every proof ever generated under that setup is retroactively dependent on the honesty of every ceremony participant. This is not a problem that better engineering solves — it is inherent to the construction.

**Fork selection cannot be verified from multiple independent sources.** In a PoW chain, fork selection is objective: the chain with the most cumulative work wins. Any node can verify this independently by checking the same arithmetic. In ZK-based light clients, you must accept the word of a prover about which chain is canonical. There is no way to aggregate and cross-check fork choice proofs from multiple independent peers the way you can cross-check chain weight. The decentralisation of verification is lost.

**What we use instead, and why:**

| Primitive | Basis | In use since |
|---|---|---|
| SHA-256d (PoW hashes) | 25+ years of cryptanalysis; Bitcoin-compatible | 2009 |
| BLAKE3 (MMR nodes) | Modern, formally analysed, no novel assumptions | 2020 |
| Merkle trees | Pure combinatorics; no cryptographic assumptions beyond the hash | 1979 |
| Proof-of-work | Computational hardness grounded in thermodynamics | 2009 |
| Multi-peer weight verification | No trusted party; any node can independently verify the same arithmetic | — |

The chain weight proof in this library uses `WeightedChainWeightProof` (deterministic MMR
inclusion when populated) or legacy `MMRChainWeightProof` (v1 bool API). Statistical v2
proofs (`MMRChainWeightProofV2`) are produced and verified by the full node in
`src/full_node/chain_weight_proving.rs`, not in `mmr_client` (removed with RF-17 Batch A).

**Our standard:** if a security argument requires assuming that a mathematical problem is hard without a proof that it is hard, it is not suitable for a system where being wrong means losing money irreversibly.

---

### Core Security Features

**Multi-Peer Chain Weight Verification**

The library's key security feature is the ability to connect to multiple independent full nodes, verify each chain using cryptographic proofs, and automatically follow the heaviest (most-work) chain — without downloading all headers and without trusting any single data source:

```rust
use filament::mmr_client::verification::{
    verify_chain_weight_proof, verify_weighted_chain_weight_proof,
};
use common_types::common::proofs::WeightedChainWeightProof;

// v1 API (MMRChainWeightProof) — returns bool
let peers = ["peer1.shisha.network:8333", "peer2.shisha.network:8333"];
let mut best_weight = 0u128;
let mut best_peer = "";

for peer in &peers {
    let proof = fetch_chain_weight_proof(peer)?;
    if verify_chain_weight_proof(&proof, &genesis) {
        if proof.chain_weight > best_weight {
            best_weight = proof.chain_weight;
            best_peer = peer;
        }
    }
}

// WeightedChainWeightProof (canonical light-client path) — inclusion proof optional
let weighted_proof: WeightedChainWeightProof = fetch_weighted_chain_weight_proof(best_peer)?;
let anchor: [u8; 32] = genesis_config.bitcoin_anchor_hash;  // [u8; 32], not a BlockData
if verify_weighted_chain_weight_proof(&weighted_proof, anchor) {
    // chain_weight and optional MMR inclusion proof verified
}

// v2 statistical proofs (full-node prover only) live in src/full_node/chain_weight_proving.rs
// (MMRChainWeightProofV2 + verify_chain_weight_proof_v2) — not part of mmr_client after RF-17
```

**Attack Resistance:**
- **Eclipse attack:** Mitigated by multi-peer connections
- **Sybil attack:** Mitigated by heaviest-chain rule (attackers cannot fake proof-of-work)
- **Long-range attack:** Prevented by cumulative PoW verification anchored to Bitcoin
- **Invalid block attack:** Rejected by MMR proof verification

### Chain Reorganisation Handling

`WeightedMMRLight::update_from_verified_proof` handles reorgs automatically:

1. **Orphan entries beyond the new tip** — any cached `(hash, height)` with `height >= new_leaf_count` is dropped.
2. **Replace stale entries at proof-covered heights** — removes old-chain entries and inserts proof entries at the same heights (prevents the duplicate-hash bug where two entries coexist at the same height after a reorg).
3. **Replace peaks and leaf_count** unconditionally.
4. **Prune to capacity** — retains the highest-height entries up to `max_recent_blocks`.

```rust
// Traditional SPV — 100,000-block reorg: download ~100,000 headers (~23 MB for Shisha beacon)
// MMR Light Client — shallow fork: download ForkProof (KB range)
let fork_proof = fetch_fork_proof(peer)?;   // ForkProof built by FullBeaconChain::build_fork_proof_for_peer
let genesis_block_hash = genesis_block.block_hash_weighted();
match fork_proof.verify(bitcoin_anchor, genesis_block_hash) {
    Ok(result) => { /* WeightedMMRLight reorg handling then follows in update_from_verified_proof */ }
    Err(e) => eprintln!("fork proof rejected: {:?}", e),
}
```

### Trust Model

**Light clients trust:**
1. Genesis block (hardcoded in config — public knowledge)
2. Bitcoin anchor (independently verifiable via the Bitcoin blockchain)
3. Cryptographic primitives (SHA-256, BLAKE3, Merkle proofs — battle-tested since 2008/2022)

**Light clients verify:**
- All MMR proofs cryptographically
- Block PoW (when using Full or Paranoid strategy)
- Chain weight accumulation (sum of verified difficulties)
- Transaction inclusion (Merkle proofs)
- Shard ID of each block in a proof (via `derive_shard_id(k_bits)`)

**Light clients do NOT trust:**
- Full nodes (beyond availability)
- Peer claims (always verify proofs)
- Stored `pow_hash` fields in Light blocks (when using Paranoid mode)
- Network majority (verify heaviest chain independently)

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test mmr::tests
cargo test verification::tests
cargo test storage::tests

# Run with logging
RUST_LOG=debug cargo test

# Run benchmarks
cargo bench
cargo bench --bench range_optimization_bench
cargo bench --bench batch_optimization_bench
```

### Test Coverage

| Component | Coverage | Notes |
|---|---|---|
| `proof_selector.rs` | ~95% | 15 inline tests; all density/threshold paths covered |
| `verification.rs` | Good | Fork + chain-weight paths; batch/range climb-and-descend removed (RF-17 Batch D) |
| `WeightedMMRLight.update_from_verified_proof` | Good | 18 inline tests covering all reorg cases |
| `WeightedMMRBatchProof::verify_with_anchor` | Good | Unit tests in `weighted_mmr_batch_proof.rs` |
| `WeightedMMRRangeProof::verify_with_anchor` | Good | 9 unit tests covering position decomposition and hash reconstruction |
| `storage.rs` — `InMemoryStorage` | ~35% | `FileStorage` entirely untested |
| `ForkProof::verify` | Good | Unit tests in `fork_proof.rs`; integration in `tests/mmr_client/fork_proof_verification_tests.rs` |
| `MultiChainClient` coordination | ~0% | No test covers beacon+shard init or `ProofCache` deduplication |
| `DeltaBatchProof` | Partial | 3 unit tests for delta encoding; `verify_delta_batch_proof` not yet covered end-to-end |
| `batch_optimization_validation.rs` / `range_optimization_validation.rs` | Good | Exercises `verify_with_anchor` on real fixtures (RF-17 Batch D) |

**Priority gaps before first network launch:** `FileStorage` parity tests with `tempdir()`, `MultiChainClient` coordination tests, `verify_delta_batch_proof` end-to-end test.

### Test Infrastructure (Updated Feb 10, 2026)

After migrating the codebase, 9 of 10 original helper files were non-portable (they imported `ShardBlockTemplate`, `Transaction`, mining pipeline types, etc.). A new set of 4 purpose-built helper modules was created under `tests/common/`:

| Helper File | Purpose |
|---|---|
| `genesis_helpers.rs` | Creates test genesis blocks |
| `hash_helpers.rs` | `test_hash()`, `compute_test_block_hash()` |
| `chain_builder.rs` | `build_test_chain()`, `create_test_batch_proof()`, `create_test_range_proof()` |
| `proof_builder.rs` | `create_range_proof()`, `create_mock_chain_weight_proof()` |

Result: 0 compilation errors, 3,824 tests passing (10 skipped — intentional: stress tests, legacy comparison, CI-time integration test), net −1,967 lines vs the old helper set.

### Known Test Infrastructure Issues

1. **4 pre-existing doc test failures:** `src/mmr.rs` (ASCII diagram parsed as Rust), `src/lib.rs` (Quick Start example used wrong `MultiChainClient::new(genesis, storage)` signature — correct is `new(storage)` only; genesis is registered separately via `init_beacon_chain`/`init_from_network`), `src/verification.rs` ×2 (stale crate name references). The Quick Start in this README has been corrected.

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Verification fails | Check genesis hash matches network; verify `bitcoin_anchor_hash` byte order is internal (little-endian) |
| Storage errors | Verify write permissions and disk space |
| Network timeouts | Increase `request_timeout_secs` in config |
| Fork detection false positives | Use `GetForkProof` to find the common ancestor |
| Shard ID mismatch error | Check `hash_sorting_bits` matches the network (4 for all Shisha networks) |

```bash
RUST_LOG=mmr_light_client=trace cargo test
RUST_LOG=debug cargo run
```

---

## 📊 Benchmarks

Verification speedups are covered in [Weighted Proof Verification](#5-weighted-proof-verification-production-path) above. Additional confirmed figures, all from Linux 4-core (the authoritative gate-check platform; macOS is typically 20–40% slower):

```
Fork proofs (ForkProof, June 3, 2026):
  fork_proof_build/chain_100/depth_1:   1.087 µs   (−67% vs WeightedAdvancedForkProof baseline)
  fork_proof_verify/chain_100/depth_1:  ~1.0 µs

Parallel gates (PARV-THRESH-1, June 2, 2026):
  parallel_batch/64:   faster than sequential_batch/64    ✅
  parallel_range/16:   21% faster than sequential_range/16  ✅
  pool_init (warm OnceLock):   2.0 ns
```

**Storage (`FileStorage` / `InMemoryStorage`) has no confirmed baselines yet** — `FileStorage` is untested; figures will be added once the test coverage gap is closed (see Open Work).

**Optimisation tip — batch your requests:**

```rust
// Instead of many single-block requests:
for height in 0..10_000 {
    client.verify_and_apply(fetch_single_proof(height)?)?;
}

// Fetch a range proof — far fewer round trips:
let proof = fetch_range_proof(0, 10_000)?;
proof.verify_with_anchor(anchor)?;
```

---

## 🗺️ Roadmap

### v0.2.x — Current (Optimisation Focus)
- ✅ Weighted batch/range verification via `verify_with_anchor` (RF-17 Batch D, Jun 2026)
- ✅ `WeightedMMRRangeProof` compact sibling format
- ✅ `DeltaBatchProof` wire compression (Phase 7 Track D)
- ✅ Test infrastructure consolidation (3,824 tests passing, June 4, 2026)
- ✅ Weighted MMR migration complete (W1–W7, commit `219d224`, March 22, 2026)
- ✅ `WeightedMMRLight` state type complete and exported
- ✅ `fork_proof_bench.rs` rewritten to use canonical `ForkProof` type (May 17, 2026; prior `WeightedAdvancedForkProof` baselines superseded)
- ✅ Parallel proof thresholds calibrated: `PROOF_PARALLEL_THRESHOLD_BATCH=64`, `PROOF_PARALLEL_THRESHOLD_RANGE=16` (PARV-THRESH-1 closed June 2, 2026 — non-monotonic at N=32 ruled out 32 as safe batch threshold)
- ✅ Windowed MMR gate closed: `windowed_append/2000` = 1.009× unlimited (WMMR-WINDOW-1, June 3, 2026; was 2.263× before `floor_state_nodes` HashMap → `[Option<WeightedHash>; 32]` optimisation)
- ✅ Wire `ChainState` to `WeightedMMRLight` — Jun 23, 2026 (RF-17 Batch B; `ChainState.mmr_light: WeightedMMRLight`)
- ✅ RF-17 Batch D — legacy batch/range verifiers removed; benches retargeted to `verify_with_anchor`
- ⏳ `verify_delta_batch_proof` end-to-end test
- ⏳ `FileStorage` test coverage
- ⏳ `MultiChainClient` coordination tests

### v0.3.0 — Internal Cleanup
- ⏳ Migrate `HybridMMRState` internal siblings from `[u8;32]` to `WeightedHash`
- ✅ Delete `verification_optimized.rs` (orphaned dead file) — removed Jun 23, 2026
- ✅ RF-17 Batch D — legacy `verify_batch_proof` / `verify_range_proof` removed from `verification.rs`
- ⏳ Delete `mmr_client/proofs.rs` re-export shim
- ⏳ Remove deprecated `CompleteBatchBlock`, `CompactBlockHeader` (Group E — v1.0 original target, may pull forward)
- ⏳ Remove deprecated `hash_pair_sha256`, `validate_beacon_genesis_legacy_sha256` (Group C — unblocked; no deployed network; first launch uses BLAKE3 genesis)
- ⏳ Add doc warning to `WeightedChainWeightProof::verify` about unconditional-true when `inclusion_proof` is `None`
- ⏳ Document `ChainState` fields (`anchor_hash`, `expected_shard_id`, `hash_sorting_bits`) for storage implementors

### v0.4.0 — Network Layer + Storage
- ⏳ SQLite storage backend (replaces JSON `FileStorage` for production)
- ⏳ Basic HTTP/WebSocket peer transport
- ⏳ Peer discovery and connection management
- ⏳ Auto-sync background worker (`BeaconChainHandler::auto_sync` is currently a stub returning `Ok(false)`)
- ⏳ Expose `MMRChainWeightProofV2` in the public API
- ⏳ **Full-node blockers** (not Filament-side, but required for end-to-end use): chain sync loop — `FullNodeManager` currently only serves proofs from data the co-located mining pool writes to disk, with no independent peer-import loop (2–3 weeks); `FullBeaconChain::revert_to_height` — missing deep-reorg recovery (`FullShardChain` has it, `FullBeaconChain` doesn't; ~2–3 days); register `examples/full_node_main.rs` as a `[[bin]]` target (currently `cargo run --example full_node_main --features full-node`)

### v0.5.0 — Deprecation Removals
- ✅ Vanilla `MMR` / `FullMMR` deleted (VAN-5, Apr 24, 2026)
- ✅ `FullWeightedMMR` deleted (RF-10, Jun 11, 2026)
- ⏳ Remove `type alias BlockHeader = FullShardHeader` (RF-9 — migrate remaining callers first)
- ⏳ Checkpoint system for fast sync from a trusted height
- ⏳ Proof caching across sessions
- ⏳ Compression for `FileStorage` (current JSON is verbose; MessagePack or CBOR would roughly halve size)

### v1.0.0 — Production
- ⏳ Metrics and monitoring hooks
- ⏳ BHC-1: `BlockHeader::hash()` returning `WeightedHash` (blocked on v0.3.0 cleanup)
- ⏳ CLI tool for manual inspection, sync status, and proof debugging
- ⏳ `kbits_to_float` / `decode_kbits` re-exported from `mmr_client` directly (currently only reachable via `common::crypto::k_bits`)

---

## 🔧 API Correctness — Before Any Public Release

> **Currency note:** this table predates the Aug 2026 crate-split/repackaging
> that produced this repo (`filament-types`/`filament-p2p` replacing direct
> access to the private monorepo's `common-types`/`p2p-proto`). It has not
> been re-audited item-by-item against the current codebase — treat it as a
> historical snapshot of known issues as of Jul 26, 2026, not a live status
> board. One update made during that repackaging, confirmed directly: the
> vanilla (non-weighted) `verify_chain_weight_proof`/`MMRChainWeightProof`
> path this table references below is **no longer part of this packaging's
> public API** — it had zero real callers anywhere in `filament`'s own code,
> so its re-export was dropped rather than carried forward, making the
> `chain_weight_verification.rs` test-fixture item moot *for this repo*
> specifically (it may still describe a real issue in the private monorepo).

Doc/footgun fixes, not roadmapped features — small but worth fixing before wider release:

| Item | Notes |
|---|---|
| **`WeightedChainWeightProof::verify` unconditional-true behaviour** | `verify(genesis_anchor)` checks the optional `inclusion_proof` field only; if `inclusion_proof` is `None` it returns `true` unconditionally. Footgun for callers who construct the proof without populating it. Confirmed still true in this packaging's `filament-types` — ported faithfully, not yet fixed. |
| **`verify_advanced_fork_proof` vs `verify_fork_proof`** | `verify_advanced_fork_proof` takes `(proof: &AdvancedForkProof, bitcoin_anchor: [u8; 32])` and returns `AdvancedForkProofResult`. `verify_fork_proof` (or `ForkProof::verify`) takes `ForkProof` and returns `Result<ForkProofResult, ForkProofError>`. Both exist in `verification.rs`; ensure call sites use the right one for the right type. Not re-verified against current code. |
| **`ChainState` field documentation missing** | `anchor_hash`, `expected_shard_id`, and `hash_sorting_bits` are used to validate shard IDs on every applied proof, but are undocumented — a custom storage implementor won't know what to persist. Not re-verified against current code. |
| ~~**`chain_weight_verification.rs` test fixtures**~~ | Moot for this packaging — see currency note above. |
| **Vacuous optimisation validation tests** | `batch_optimization_validation.rs` / `range_optimization_validation.rs` were retargeted by RF-17 Batch D but should be verified against real fixtures to confirm the `assert_eq!(false, false)` pattern no longer applies. Not re-verified against current code. |
| **`FilamentWallet` undocumented** | `filament_wallet.rs` implements watch-only UTXO discovery, fee estimation (`estimate_fee` via Keystone `/chain/fee_filter`), cross-shard UTXO selection, and Schnorr-signed transaction building — none of this is covered in the README. Key constants: `ATOMS_PER_COIN = 100_000_000`, `DEFAULT_FEE_ATOMS = 10_000`. Core methods (`build_signed_transaction`, `submit_transaction`, `refresh_from_keystone`) are gated behind `#[cfg(feature = "full-node")]`. Still undocumented. |
| **`BeaconChainHandler::auto_sync` stub** | Returns `Ok(false)` unconditionally. Documented in Roadmap (v0.4.0) but not called out in the Architecture section where it could mislead readers into expecting live sync. Not re-verified against current code. |
| **`blocks_per_epoch` stale in handlers** | `BeaconChainHandler` and `ShardChainHandler` hardcode `blocks_per_epoch: 1008`. The canonical value is `EPOCH_LENGTH = 4096` from `k_coeff.rs`. Handlers need updating. Not re-verified against current code. |
| ~~**`MultiChainClient::new` signature**~~ | ✅ Resolved — `new(storage: Box<dyn LightClientStorage>)` only; genesis is registered via `init_beacon_chain` / `init_from_network`. Quick Start and Known Issues updated. |
| **`LightClientConfig` deprecated alias** | The Quick Start previously used `LightClientConfig` (deprecated since 0.5.0, RF-11). Correct import is `FilamentBootstrapConfig` from `mmr_client::light_client_config`. Quick Start updated; any other doc or example using the old name should be migrated. |
| **`LightShardBlockData` size** | Key Features table says ~161 bytes; `mod.rs` says ~194 bytes. Needs reconciliation against the actual serialised `LightShardHeader` struct field widths. The "91% savings" claim is directionally correct at both values. Not re-verified against current code. |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **FlyClient** (Bünz et al.) for the core MMR-based light client concept
- Bitcoin's SPV design and proof-of-work security model
- The Rust blockchain community

**Implementation note:** This library uses position-based MMR indexing (`position = 2 × height`), an advancement over both traditional sequential MMR implementations and the FlyClient reference design. Immutable positions enable lock-free concurrent access and eliminate all reindexing overhead.

---

**Built with ❤️ in Rust for the Shisha Network**
