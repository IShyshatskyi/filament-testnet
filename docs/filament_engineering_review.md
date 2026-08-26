# Filament-Test engineering review (public packaging)

**Date:** 2026-08-25  
**Scope:** Current `mmr-light-client` workspace (Filament-Test packaging of filament + common-types + p2p-proto)  
**Network name (public):** Heaviest Chain Rule Test Network  
**Synced from:** see [`VERSION`](../VERSION)  
**Supersedes:** February 2026 classic-MMR review (local archive / git tag `archive/sha256-2026-04` only)

---

## Executive summary

| Area | Assessment |
|------|------------|
| Weighted MMR verification / proof types | **Strong** — core library path |
| Multi-chain coordinator (`MultiChainClient`) | **Usable** — beacon + shards |
| Public packaging / sync from monorepo | **Works, fragile** — load-bearing patches |
| HTTP product surface (`:7380`) | **Testnet experimental** |
| Path-2 P2P / wallet / invoices | **Testnet experimental** |
| Public testnet bootstrap (genesis, seeds, RPC) | **Not ready** without operator-supplied Keystone + filled genesis |

**Overall:** suitable as a **synced public extract** of the Filament light-client stack for the **Heaviest Chain Rule Test Network**. This repo is **Filament-Test**, not a production Filament release. **Not** yet a turnkey “download and join with zero config” package.

---

## Layout

```text
mmr-light-client/
  crates/common-types/   # WeightedHash, proofs, genesis, verification
  crates/filament/       # library + `filament` binary (feature full-node/server)
  crates/p2p-proto/      # PeerManager / ShishaNet codecs (Path-2)
  scripts/sync_from_shisha.sh
  archive/2026-04-sha256/  # frozen classic SHA-256 source only
```

| Feature | Meaning |
|---------|---------|
| default | Verify + client helpers, no axum/P2P |
| `full-node` / `server` | HTTP API, DNS resolver, Path-2 P2P, env_logger |

Binary: `cargo build -p filament --features full-node --bin filament`

---

## What is solid

1. **Proof verification** — Weighted batch/range/fork/chain-weight paths live in `common-types`; Filament’s `verification` module is a thin re-export.
2. **`WeightedMMRLight`** — production light-MMR cache used by chain handlers (peaks + recent leaves with rBits).
3. **`MultiChainClient`** — beacon + N shards, summaries, peer bookkeeping, sync status / trust floor helpers.
4. **Crate boundary** — Filament does not depend on the full-node/mining monolith at runtime; public tree can build without Keystone/Kameniar.
5. **Unit test density in crates** — large number of inline unit tests in `common-types` / `filament` / `p2p-proto` (synced from monorepo). Not a substitute for live Keystone E2E.

---

## What is experimental

| Surface | Notes |
|---------|--------|
| HTTP `:7380` | Loopback-oriented product API; wallet, sync, invoices, SSE |
| Path-2 P2P | `WatchAddress` / inclusion notifs; enabled by default; use `--disable-p2p` for HTTP-only |
| Wallet | Watch-oriented; UTXO/fee/history from Keystone REST; Schnorr send gated on `full-node` |
| Invoices / F2F / contacts | App-layer; not a hardened vault |
| Storage in binary | Headless binary uses **`InMemoryStorage`** for chain state; `data_dir` mainly for config/peer/invoice files |

---

## Packaging patches (must stay intentional)

`scripts/sync_from_shisha.sh` applies two patches after rsync:

1. **`common-types`:** remove `rustmmrdb` path dependency (Cargo resolves optional path deps even when unused).
2. **`p2p-proto`:** `full-node = []` instead of enabling `common-types/full-node` (avoids rustmmrdb for Path-2).

**Risk:** monorepo `Cargo.toml` format drift can break the next sync. Treat the script as part of the public product contract.

---

## Public testnet readiness gaps

1. **Genesis / anchors** — `light_client_config.toml` still has all-zero TODOs for mainnet / testnet1 / testnet2 genesis hash, MMR root, and Bitcoin anchors (devnet partially filled). Without matching Keystone genesis, pin is meaningless.
2. **DNS / hardcoded seeds** — defaults still point at `*.shishanet.io`; lookups fail in local smoke. Port confusion: seed lists vs Keystone P2P **18334**.
3. **Public RPC hostnames** — documented in README; not proven live from this packaging environment.
4. **Ephemeral chain state** — restart loses in-memory MMR tip unless persistence is wired into the binary.
5. **Default P2P on** — noisy or confusing without working peers; document `--disable-p2p` for first sync.
6. **Network id footgun** — CLI `--network` vs internal `MultiChainClient` default (`Mainnet`) must stay consistent through bootstrap.
7. **Branding leftovers** — crate descriptions, URI schemes (`shishanet://`), seed domains still use legacy product DNS names; public names are **Filament-Test** / **Heaviest Chain Rule Test Network**.
8. **No dedicated public integration suite** — archive `tests/` are classic MMR only; live Filament↔Keystone smoke lives mainly in the private monorepo scripts.

---

## Security stance (unchanged intent)

- Heaviest-chain rule via cumulative work in Weighted MMR / proofs  
- Multi-Keystone / multi-peer where configured (MNT)  
- No ZK light-client dependency  
- Trust still requires correct genesis and at least one honest proof server among those queried  

See root [README.md](../README.md) and [DISCLAIMER.md](../DISCLAIMER.md).

---

## Recommended next engineering steps (public repo)

1. Fill **testnet1** genesis + Bitcoin anchor from the live Keystone network definition; fail fast if zeros.  
2. Persist chain state (`FileStorage` or better) in the headless binary when `--data-dir` is set.  
3. Replace or disable dead DNS seeds; align default P2P port with Keystone (**18334**).  
4. Add a minimal **public smoke** (build + `/health` + optional Keystone summary) in CI.  
5. Harden sync script (detect patch failure as hard error).  
6. Sweep investor-facing strings to **Heaviest Chain Rule Test Network** / Filament-Test; keep wire protocol names only where required.

---

## Relation to February 2026 review

The Feb review graded the **standalone classic SHA-256** library (~85% “near ready”) and listed ChainId, MMRLight wiring, network, SQLite gaps. That codebase is **obsolete on the wire**. Do not use it to prioritize Filament work. Historical file:

`archive/2026-04-sha256/docs/mmr_light_client_comprehensive_review.md`
