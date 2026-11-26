# Shared consensus vectors

This repository re-implements a slice of the node's consensus code (`filament-types`,
`filament-p2p`) instead of depending on it. Two implementations of one consensus function are only
safe when they produce **the same bytes**. The guarantee is one file that both repositories run.

## The file

`crates/filament-types/tests/vectors/consensus_v1.json` (about 250 KB). The node repository
generates it from its own code; this repository copies it and checks it against its own code. It
holds inputs and expected outputs, in hex or JSON, for:

| Section | What it pins |
|---|---|
| `sha256d`, `hash_pair`, `relay_id` | Base hashes |
| `weighted_hash` | `from_leaf_rbits`, `from_anchor`, `hash_pair_weighted`, `rbits_add`, `u128_to_rbits`, `rbits_to_u128_approx`, `bag_peaks_u128`, `peaks_after_append` |
| `mmr_math` | Peak decomposition, replay of appends, the genesis root, fork path positions |
| `merged_mining_hash` | Leaf and parent nodes, zero propagation, the packed count and height |
| `pow_target` | `rbits_to_target` (123 cases incl. saturation) and `hash_meets_target` |
| `hash_sorting` | `extract_sorting_bits`, `find_eligible_shard` |
| `sighash`, `txid` | `prevouts_hash`, `sighash_v2`, `txid_from_parts` |
| `wire_beacon_header`, `wire_pow` | The 148-byte header (serialization, commitment, PoW hash) and the per-header and batch PoW check |
| `expand_voting` | Count to width, the expansion step, the shard admissible count range |
| `genesis` | Six presets, four checked-in genesis files, the genesis block hash, shard genesis bits |
| `shard_body` | Transaction leaves (incl. the rule-amount marker), `tx_merkle_root`, output inclusion proofs |
| `shard_header` | Aux beacon header hashes, shard header identity, leaf and weighted hashes |
| `merged_mining_check` | The shard block check, 15 cases covering every error class |
| `wire` | Bincode of shard block records and `BlockData`; JSON of every thin-sync response |

## Running it

```bash
cargo test -p filament-types --test consensus_vectors
```

The same test runs in CI (`.github/workflows/test.yml`) as part of `cargo test --workspace`.

## A failing case

It means this repository drifted from the node (or the node changed on purpose and this repository
has not followed). Do not edit the file to make it pass. Find the function, fix it here, and compare
with the node's behaviour.

The first generation of the file found real divergences: a shift overflow in `extract_sorting_bits`
for widths of 32 and above, an auxiliary leaf hashed with SHA256d where the node uses BLAKE3, and a
stand-in genesis generator whose hash differed from the node's for every network.

## Changing the file

This repository cannot regenerate it. The generator is a test in the node repository
(`regenerate_vectors`, ignored by default). A change is made there, reviewed as a diff of the JSON
(an unexpected diff is a consensus break), merged, and then brought over by
`scripts/sync_filament_public.sh --apply`, which copies the file and runs the check. The same round
updates the code here.

## What it does not cover

* Behaviour that is not a pure function of its inputs: networking, storage, the HTTP server, the wallet.
* Full block validation (signatures, inputs, fees). Filament does not run it.
* Anything the node adds after the last sync; `VERSION` names the node commit this copy came from.
