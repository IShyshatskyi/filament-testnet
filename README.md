# Filament — MMR light client for the Shisha test networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

Filament follows the Shisha Network's chains **without trusting one node and without storing the
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
the network's proof of work like any light client. No zero-knowledge proofs are used.
Details and limits: [docs/reference.md](docs/reference.md), sections 1 and 11.

Traffic, measured on small test chains: a tip poll is about 110 bytes, a first sync 8–12 KB per
chain, and one new block 350–550 bytes (the older full summary was 134–159 KB per poll).

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
  ShishaNet port is usually 18334 (`--keystone-p2p-port`). Check a node with
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
| [`crates/filament-p2p`](crates/filament-p2p) | ShishaNet codec and peer manager (wire v17) for the light-client handshake |

`filament-types` and `filament-p2p` are independent re-implementations of the node's code. Every
consensus function in them is checked byte for byte against the node through
`crates/filament-types/tests/vectors/consensus_v1.json`, a file the node generates. A failing case
means this repository drifted from the node.

```bash
cargo test --workspace --features full-node
```

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
