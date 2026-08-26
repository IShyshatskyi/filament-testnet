# MMR Client (Filament) — Doc Index

**Shisha Network · `src/mmr_client/`** | **Last updated: July 3, 2026**

The authoritative module documentation is **[`../README.md`](../README.md)** (the `mmr-light-client` crate README: FlyClient rationale, `MMRChainWeightProofV2` sampling, verification levels, parallel-verifier thresholds, k-parameter table). This folder holds the design-era supplements.

| Where | What |
|---|---|
| `../README.md` | **Current module doc — start here** |
| `verification_strategies.md` | Design rationale for the `VerificationStrategy` enum (Paranoid / Full / Light levels — still live code in `verification.rs`). Design-era prose; see its currency banner |
| `crates/filament/` | The crate facade Filament apps build against (crate-split Gap 8, ✅ Jun 26) |
| `docs/plan/Filament_UTXO_Discovery_Design.md`, `docs/plan/P2P_Phase10_Plan.md`, `filament_app/docs/` | Current Filament wallet/light-client planning |
| `archive/` | Superseded design-era documents (2025–early 2026, pre-rename JAX naming) — provenance only, do not cite as current behaviour |

## Archive contents and what superseded each

| File | Superseded by |
|---|---|
| `archive/README.md` (v0.2.0 "verification optimization" note) | `../README.md` |
| `archive/DEPENDENCIES_AND_OBSTACLES.md` ("80% ready for standalone release") | Crate split Gap 8 — `crates/filament/` exists |
| `archive/UPDATED_IMPLEMENTATION_PLAN.md`, `archive/architecture_summary.md` | The implemented architecture (`../README.md`, `HybridMMRState`, `WindowedWeightedMMR` ownership split) |
| `archive/integration_guide2.md` | `crates/filament/` facade + `filament_app/` Tauri scaffold |
| `archive/proof_sigs_download.md` (Jan 2026, v0.3.0 proof signatures) | WeightedHash migration (Mar 2026) — pre-`Weighted*` proof types |
| `archive/wallet_light_client_plan.md` | `docs/plan/Filament_UTXO_Discovery_Design.md` + P2P Phase 10 + `filament_app/docs/` plans |

Triaged Jul 3, 2026 (seven of eight files archived; `verification_strategies.md` retained with a currency banner).
