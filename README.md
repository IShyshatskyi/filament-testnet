# Filament-Test — MMR Light Client (public test packaging)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

This repository is **Filament-Test**: the public **test-network** packaging of the
Filament MMR light client for the **Heaviest Chain Rule Test Network**.

It is **not** the production Filament product line. Use it to verify beacon and shard
chain weight with Merkle Mountain Range (MMR) proofs on testnet — without a full UTXO
set or every historical header.

GitHub repo name: `mmr-light-client`. Cargo package / binary name: **`filament`**
(synced from upstream; CLI unchanged).

> Protocol source of truth remains a private monorepo; re-sync with
> [`scripts/sync_from_shisha.sh`](scripts/sync_from_shisha.sh). Pin in [`VERSION`](VERSION).

---

## Why MMR light clients?

### The scalability problem

**Network traffic efficiency and low latency are critical for blockchain scalability.**

Traditional SPV (Simplified Payment Verification) clients have fundamental limitations
that MMR light clients solve.

### Traditional SPV (problems)

| Operation | Traditional SPV | Network load |
|-----------|-----------------|--------------|
| Initial sync (1M blocks) | 80 MB headers | 80 MB download |
| Verify 1M PoW hashes | Full computation | High CPU |
| Daily sync (144 blocks, single Bitcoin-style chain) | ~11.5 KB | Constant overhead |
| Daily sync (N shard chains, 37.5s blocks) | 144×16×N blocks, 136 B headers | ~306 KB × N |
| Reorg (100 blocks) | Header redownload | Inefficient |

Shard chains target a much faster ~37.5-second block interval than Bitcoin's 10 minutes —
**16×** more blocks per day per chain (the calibration ratio between beacon and shard block
cadence) — and each header carries more data than Bitcoin's 80 bytes (136 bytes per
[`LightShardHeader`](crates/common-types/src/common/blocks/shard_block.rs)). For **N** shard
chains, that's `144 × 16 × N` block headers a traditional SPV client would need daily, growing
linearly with shard count — exactly the load MMR proofs are designed to collapse to a
near-constant summary instead.

Every SPV client downloads headers for **every** block → O(n) load per client.
Supporting thousands of SPV clients makes running full nodes expensive and limits
decentralization.

### MMR light clients (solution)

| Operation | MMR client | Network load | Savings |
|-----------|------------|--------------|---------|
| Initial sync (1M blocks) | ~1–2 MB proof | Compact | **~98%** |
| Verify chain weight | Proof verification | Low CPU | **~99%** |
| Daily sync | Summary proof (~KB) | Minimal | **~99%** |
| Reorg (100 blocks) | Fork proof (~KB) | Efficient | Large |

**Key insight:** Proof size is **O(log n)**, not O(n). A million-block chain needs on
the order of tens of hashes in a proof — not a million headers.

### Why this matters for full nodes

**Security of the network is based on full nodes.** They enforce protocol rules and
are the only entities that should feed proofs to light clients.

Traditional SPV burdens full nodes with large header downloads. MMR proofs cut that
cost by ~50×, so more operators can afford to run full nodes → stronger decentralization.

### Low latency / heaviest-chain following

MMR clients request a **chain summary** (recent tips + cryptographic proof), verify
**cumulative chain weight** (heaviest-chain rule), and converge in roughly **one RTT** —
instead of downloading and re-checking long header sequences.

### Multi-chain merged mining

MMR-based SPV is especially valuable for **multi-chain merged-mining** designs with
high block frequency and large headers (beacon + many shards):

- Traditional header-only sync grows as *shards × blocks × header size*
- Nodes need not watch every shard — only chains they care about
- MMR proofs stay O(log n) per chain; no trusted checkpoints required for pruning

**Trustless pruning:** keep genesis + recent blocks + proofs — not every historical
header forever.

### Summary

1. **Network efficiency** — large bandwidth reduction per client  
2. **Full-node sustainability** — more clients per node  
3. **Decentralization** — cheaper full nodes → more full nodes  
4. **Low latency** — fast heaviest-chain decisions  
5. **Future-proof** — logarithmic growth with chain length  
6. **Security** — verify work without downloading all headers  

---

## What you get (current stack)

| Crate | Role |
|-------|------|
| `crates/filament` | Light client: `WeightedMMRLight`, `MultiChainClient`, HTTP API `:7380`, wallet/invoices, Path-2 P2P |
| `crates/common-types` | `WeightedHash`, weighted proofs, verification |
| `crates/p2p-proto` | Network codecs + `PeerManager` (Path-2) |

**Filament-Test verifies proofs. Full nodes (Keystone) serve them.**

Current cryptography uses **Weighted MMR** nodes (`WeightedHash`: compact hash +
cumulative difficulty / rBits). ASIC-oriented PoW hashing remains compatible with
Bitcoin-style verification where applicable. This is a **breaking upgrade** from the
April 2026 classic SHA-256 MMR library (local `archive/` / git tag
`archive/sha256-2026-04`; not published on this branch).

---

## Quick start

### Build

Requires a recent Rust stable toolchain.

```bash
cargo build --release -p filament --features full-node --bin filament
```

Lean library only (verify + client, no HTTP/P2P):

```bash
cargo check -p filament
```

### Run (testnet)

Replace the Keystone URL with a real endpoint (do **not** type the literal `<url>` —
shells treat `<` as redirection).

```bash
./target/release/filament \
  --network testnet1 \
  --keystone 'https://rpc.testnet.shisha.network' \
  --port 7380 \
  --disable-p2p
```

Regional RPC examples (confirm live status before relying on them):

| Region | URL |
|--------|-----|
| EU | `https://rpc.testnet.shisha.network` |
| US | `https://rpc-us.testnet.shisha.network` |
| AP | `https://rpc-ap.testnet.shisha.network` |

Local API (loopback): `http://127.0.0.1:7380`

```bash
curl -s http://127.0.0.1:7380/health
```

Multi-node trust (optional):

```bash
./target/release/filament \
  --network testnet1 \
  --keystone 'https://rpc.testnet.shisha.network' \
  --keystone-extra 'https://rpc-us.testnet.shisha.network'
```

Path-2 P2P (Keystone ShishaNet port often **18334**):

```bash
./target/release/filament \
  --network testnet1 \
  --keystone 'http://127.0.0.1:8080' \
  --keystone-p2p-port 18334 \
  --manual-peer '127.0.0.1:18334'
```

---

## Key features

### Verification levels

| Level | Use case | PoW |
|-------|----------|-----|
| Beacon block data | Beacon chain | Full where required |
| Full shard block data | Recent / weight-critical | Full |
| Light shard block data | Deep history | Compact / trusted hash path |

### Strategies

- **Full** — MMR structure for all blocks; PoW for full payloads  
- **Light** — MMR-focused (maximum efficiency)  
- **Paranoid** — MMR + PoW wherever applicable (maximum scrutiny)  

### Multi-chain

One beacon + N shards via `MultiChainClient`, independent sync per chain, selective
shard following.

### Product surface (Filament-Test)

- HTTP API on `:7380` (health, sync, wallet helpers, invoices, …)  
- Watch / invoice flows and optional Path-2 inclusion notifications  
- Multi-Keystone endpoints for heaviest-chain / trust floor checks (MNT)  

---

## Architecture (conceptual)

```text
MultiChainClient
  ├── BeaconChainHandler  (WeightedMMRLight + tip / weight)
  └── ShardChainHandlers  (per shard_id)
        └── proofs verified via common-types

Wallet / HTTP / P2P  →  Filament-Test :7380  →  verifies Weighted MMR proofs
                              │
                              ▼
                    Keystone full node (prove_*)
```

---

## Security model

### No zero-knowledge proofs

**This client does not use and is not designed around ZK light-client schemes.**

Position (mathematical, not fashion):

- ZK “proofs” in this setting are probabilistic arguments, not absolute proofs  
- Fork choice must not collapse to a **single** data provider  
- Heaviest-chain selection should be checkable from **independent** peers  
- Prefer long-studied hash / Merkle / PoW structure over novel trusted setups  

**What Filament-Test uses instead:**

- Weighted MMR + Merkle-style structure (hash trees)  
- Proof-of-work / cumulative **chain weight** (heaviest-chain rule)  
- Multi-peer / multi-Keystone verification where configured  
- Bitcoin-style anchoring at genesis (network-specific)  

### Core properties

- Verify cumulative work **without** all headers  
- Detect and follow heavier forks via proofs  
- No single Keystone as the sole trust root when MNT is enabled  
- Genesis + Bitcoin anchor from bootstrap config  

### Trust assumptions

- Correct genesis / anchor configuration  
- At least one honest proof-serving full node among those you query (stronger with many)  
- Hash function and PoW assumptions of the network  

Filament-Test does **not** mine and does **not** hold a full UTXO database.

---

## Documentation

| Doc | Contents |
|-----|----------|
| This README | Product narrative, build/run, security stance |
| [docs/reference.md](docs/reference.md) | **Deep technical reference** — HTTP API endpoint table, proof-size table, verification API, storage trait, security model, troubleshooting, P2P transport details |
| [DISCLAIMER.md](DISCLAIMER.md) | Legal / experimental notice |
| [docs/filament_engineering_review.md](docs/filament_engineering_review.md) | Current Filament-Test packaging status (Aug 2026) |
| [archive/](archive/) (local only; gitignored) | Classic-MMR snapshot — see tag `archive/sha256-2026-04` |

The long-form “why MMR / SPV / multi-chain” narrative is kept in this README (drawn from
the April README). Obsolete classic-MMR **source** is not published in this branch
(`archive/` is gitignored; recover via tag `archive/sha256-2026-04` if needed).

---

## Sync from private monorepo

```bash
./scripts/sync_from_shisha.sh /path/to/private-monorepo
cat VERSION   # SYNCED_FROM_SHISHA=<git-sha>
```

---

## License

MIT — see [LICENSE](LICENSE). Experimental / unaudited testnet software —
see [DISCLAIMER.md](DISCLAIMER.md).

## Acknowledgments

- FlyClient (Bünz et al.) for MMR-oriented light-client ideas  
- Bitcoin SPV / proof-of-work security model  
- Heaviest Chain Rule as the fork-choice foundation of this test-network design
