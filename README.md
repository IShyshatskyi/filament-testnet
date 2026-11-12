# Filament — MMR light client for the Heaviest Chain Rule Network (HCRN) test networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

Filament follows the chains of the Heaviest Chain Rule Network (HCRN) **without trusting one node and without storing the
chains**. It keeps a few kilobytes per chain (the Merkle Mountain Range peaks and the last 16
headers), checks every header's proof of work, computes chain weight itself, and compares several
full nodes before it believes anything. Full nodes (**Keystone**) serve data; Filament verifies it.

This repository is the public **test-network** packaging. It is experimental and unaudited:
read [DISCLAIMER.md](DISCLAIMER.md) before use. Cargo package and binary: **`filament`**.

## What it verifies

| Check | How |
|---|---|
| Genesis | Block 0 is generated locally from a network preset or the genesis file the nodes load. No peer supplies it. |
| Proof of work | Every beacon header, and every shard block's auxiliary beacon header, is checked against its target. |
| Linkage and weight | Each header must extend the root Filament computed; weight is computed from the leaves' work, never received. |
| Agreement | A state is trusted only when at least two Keystones hold it (one with `--allow-single-keystone`). |
| Payments | An invoice confirms only when the paying output is proved inside a block of a shard chain Filament verified. |

It does **not** validate transactions, run consensus rules, mine, or keep a UTXO set. It relies on
the network's proof of work like any light client. No zero-knowledge proofs are used, and none will be: see
[the critique below](#zero-knowledge-proofs-a-mathematical-critique).
Details and limits: [docs/reference.md](docs/reference.md), sections 1 and 11.

Traffic, measured on small test chains: a tip poll is about 110 bytes, a first sync 8–12 KB per
chain, and one new block 350–550 bytes (the older full summary was 134–159 KB per poll).

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
`LightShardHeader`). For **N** shard
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

---

## Networks

| Network | Chains | Note |
|---|---|---|
| `testnet2` | 15 | The announced community network (CPU mining) |
| `testnet3` | 3 | ASIC-oriented |
| `testnet1` | 3 | Historical |
| `testnet-stress` | 3 | Short-lived load-test network |
| `devnet` | 3 | Local development |
| `mainnet` | 3 | Not launched |

`--network` must match the chain your Keystone serves. A mismatch appears as
`Invalid chain summary proof`. For a local or custom chain, pass its genesis file with
`--genesis-file`.

There is **no always-on public Keystone** right now. Point Filament at one you run, or one whose
operator gave you its URL, and check it first: `curl -s http://KEYSTONE_HOST:8080/health`.

## Quick start

```bash
cargo build --release -p filament --features full-node --bin filament
```

```bash
./target/release/filament \
  --network testnet2 \
  --keystone 'http://KEYSTONE_A:8080' \
  --keystone-extra 'http://KEYSTONE_B:8080' \
  --thin-sync \
  --disable-p2p
```

After about 30 seconds:

```bash
curl -s http://127.0.0.1:7380/health
curl -s http://127.0.0.1:7380/sync/status      # phase: synced, tip_height > 0
```

Notes:

* Two Keystones give a quorum. With one, add `--allow-single-keystone` and accept the weaker trust.
* `--thin-sync` is off by default until it has run against a live fleet. Without it Filament polls the
  older, much larger chain summary.
* Add `--thin-shard N` to follow shard `N`; an open invoice also starts following its shard.
* The local API listens on loopback (`127.0.0.1:7380`). Keep a Keystone's wallet port off the public
  internet.
* Path-2 P2P (push notifications of payments) is on unless you pass `--disable-p2p`. The Keystone's
  node P2P port is usually 18334 (`--keystone-p2p-port`). Check a node with
  `./scripts/p2p_handshake_probe.sh HOST:18334 testnet2`.

The full flag list is in [docs/reference.md](docs/reference.md), section 7.

## As a library

```bash
cargo run -p filament --example quickstart -- crates/filament/src/mmr_client/light_client_config.toml http://KEYSTONE_HOST:8080
```

[`crates/filament/examples/quickstart.rs`](crates/filament/examples/quickstart.rs) shows the shape:
load a bootstrap config, initialise a network's genesis (the example uses `devnet`), reconcile a
Keystone's chain summary, and read the verified tip. The reference describes the rest of the API.

## Crates

| Crate | Role |
|---|---|
| [`crates/filament`](crates/filament) | The client, HTTP server, wallet, invoices, thin sync |
| [`crates/filament-types`](crates/filament-types) | Clean-room types and verification: weighted hashes, proofs, genesis, shard header and body, merged-mining check |
| [`crates/filament-p2p`](crates/filament-p2p) | Node P2P codec and peer manager (wire v17) for the light-client handshake |

`filament-types` and `filament-p2p` are independent re-implementations of the node's code. Every
consensus function in them is checked byte for byte against the node through
`crates/filament-types/tests/vectors/consensus_v1.json`, a file the node generates. A failing case
means this repository drifted from the node.

```bash
cargo test --workspace --features full-node
```

## Zero-knowledge proofs: a mathematical critique

**Filament does not use zero-knowledge proofs and never will.** This is a position of mathematics, not of fashion.

The problem with ZK is not complexity. It is mathematical unsoundness in trustless settings:

1. **Naive mathematics presented as rigor.**
   * ZK "proofs" rest on assumptions that do not hold under adversarial cryptanalysis.
   * The mathematics is not "complex". It is naive extrapolation of old ideas.
   * A ZK "proof" is a probabilistic argument, not an absolute proof. A security proof of such a scheme is incomplete by construction.
2. **Old assumptions pushed beyond their valid domain.**
   * They are not "novel" assumptions: they are old assumptions used outside the domain they were established for.
   * Elliptic-curve pairings are assumed secure in contexts they were never proven for.
   * A trusted setup violates the trustless requirement by definition: you trust the ceremony.
3. **The principle that is violated.**

   ```text
   In a trustless setting you trust ONLY mathematics.

   You do not trust:
   - cryptography PhDs (they can be wrong)
   - trusted-setup ceremonies (that defeats "trustless")
   - assumptions without mathematical proof
   - novel constructions without decades of cryptanalysis
   ```

**When the problem is purely mathematical, follow the laws of mathematics, not cryptographic fashion.**
No outside authority, consultancy or sign-off is needed to hold this position, and it is not an
"unverified claim" to be softened or dropped.

What Filament uses instead:

* **Proof of work** (SHA-256d): computational hardness, thermodynamics rather than assumptions.
* **Hash trees** (Merkle and Merkle Mountain Range structure with BLAKE3): pure mathematics, hash function plus tree shape.
* **Cumulative chain weight** and the heaviest-chain rule, as Bitcoin has verified since 2009.
* **Several independent full nodes**, so fork choice never collapses onto one data provider.
* **A Bitcoin-style anchor** in each network's genesis.

**The standard:** if the security argument needs assumptions beyond "the hash function is good and work cannot be forged",
it is not suitable for trustless money.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/reference.md](docs/reference.md) | Technical reference: data model, proofs, thin sync, genesis and networks, API, security model |
| [docs/thin-sync.md](docs/thin-sync.md) | How the sync works, the checks, the quorum, invoice assurance levels, status values, measured sizes |
| [docs/security.md](docs/security.md) | Threat model, what is verified, what is not, safe operation |
| [docs/vectors.md](docs/vectors.md) | The shared consensus vectors that keep this code equal to the node |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [docs/filament_engineering_review.md](docs/filament_engineering_review.md) | Status review of this packaging (Aug 2026, partly superseded) |
| [DISCLAIMER.md](DISCLAIMER.md) | Experimental-software notice |

## Repository boundary

This repository holds only the three crates above. Full-node and mining code never appears here.
`scripts/check_public_boundary.sh --strict` enforces it, and `scripts/sync_filament_public.sh`
brings the `filament` crate over from the node's repository (its header describes the process).
`VERSION` records the commit a sync came from.

## License

MIT, see [LICENSE](LICENSE). Experimental and unaudited testnet software.

## Acknowledgments

FlyClient (Bünz et al.) for MMR-based light-client ideas, and Bitcoin's SPV and proof-of-work model.
