#!/usr/bin/env bash
# Sync Filament stack crates from a local shisha checkout into this public repo.
#
# Usage:
#   ./scripts/sync_from_shisha.sh /path/to/shisha
#   ./scripts/sync_from_shisha.sh              # default: ../shisha relative to repo root
#
# After copy, strips common-types modules that filament/p2p-proto never use
# (difficulty_adjustment, cluster, storage — RocksDB/P1DB adapters included —
# and transport), strips the private reorg engine (chain/, replaced by the
# tiny chain_support/ subset common:: genuinely needs), and strips the real
# MMR write/construction engine (weighted_mmr_core.rs/windowed_weighted_mmr.rs)
# and the unused epoch_history_fast_start.rs — all deliberately excluded
# owner-IP, not needed by a read-only proof-verifying light client. Then
# patches p2p-proto so `full-node` does not pull rustmmrdb via common-types
# (public Path-2 packaging). Then runs:
#   cargo check -p filament --features full-node
#
# NOTE: as of the weighted_mmr_core/windowed_weighted_mmr removal, this final
# check is EXPECTED TO FAIL — common-types/src/common/genesis/genesis.rs and
# common-types/src/common/validation/beacon.rs still import WeightedMMR from
# the now-excluded module. Left broken deliberately (owner decision) until
# those two call sites are reworked to not need the real MMR engine.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SHISHA="${1:-$ROOT/../shisha}"

if [[ ! -d "$SHISHA/crates/filament" ]]; then
  echo "error: shisha filament crate not found at $SHISHA/crates/filament" >&2
  exit 1
fi

SHA="$(cd "$SHISHA" && git rev-parse HEAD)"
echo "Syncing from shisha @ $SHA"

mkdir -p "$ROOT/crates"

# common-types: only common/, transaction/, chain/, lib.rs, Cargo.toml are
# used by filament/p2p-proto (verified by grep) — exclude everything else so
# full-node-only internals (storage's RocksDB/P1DB adapters in particular)
# never land in this public repo.
rsync -a --delete --exclude target --exclude .DS_Store \
  --exclude difficulty_adjustment --exclude cluster.rs \
  --exclude storage --exclude transport.rs \
  --exclude chain \
  --exclude common/weighted_mmr_core.rs \
  --exclude common/windowed_weighted_mmr.rs \
  --exclude common/epoch_history_fast_start.rs \
  "$SHISHA/crates/common-types/" "$ROOT/crates/common-types/"
mkdir -p "$ROOT/crates/common-types/src/chain_support"
for f in chain_metrics phase1_delta side_block_eviction; do
  cp "$SHISHA/crates/common-types/src/chain/$f.rs" \
     "$ROOT/crates/common-types/src/chain_support/$f.rs"
done
cat > "$ROOT/crates/common-types/src/chain_support/mod.rs" <<'MODEOF'
// crates/common-types/src/chain_support/mod.rs
//
// Public Filament packaging note: this is NOT the reorg engine. Kameniar's
// and Keystone's real reorg logic (orphan pools, side-block managers,
// shard/beacon reorganization) is native to those binaries and stays in the
// private `shisha` monorepo's `chain/` module — it is never synced into this
// public repo. This folder holds only the three small, self-contained
// helpers that `common::` genuinely depends on (verified: zero dependency on
// any of the reorg-engine files) — `chain_metrics`, `phase1_delta`, and
// `side_block_eviction` — kept separate and named distinctly from `chain` so
// their presence here doesn't read as "the reorg engine is exposed."

#[cfg(feature = "full-node")]
pub mod chain_metrics;
#[cfg(feature = "full-node")]
pub mod phase1_delta;
pub mod side_block_eviction;
MODEOF
rsync -a --delete --exclude target --exclude .DS_Store \
  "$SHISHA/crates/filament/" "$ROOT/crates/filament/"
rsync -a --delete --exclude target --exclude .DS_Store \
  "$SHISHA/crates/p2p-proto/" "$ROOT/crates/p2p-proto/"

python3 - "$ROOT/crates/p2p-proto/Cargo.toml" "$ROOT/crates/common-types/Cargo.toml" "$ROOT/crates/common-types/src/lib.rs" "$ROOT/crates/common-types/src/common/mod.rs" <<'PY'
import re
import sys
from pathlib import Path

p2p = Path(sys.argv[1])
text = p2p.read_text()
old = 'full-node = ["common-types/full-node"]'
new = '''# Public Filament package: enable the `p2p` module without pulling rustmmrdb
# via common-types/full-node (Path-2 PeerManager does not need PositionalUtxoDb).
full-node = []'''
if old in text:
    p2p.write_text(text.replace(old, new, 1))
    print("patched p2p-proto full-node feature (no rustmmrdb)")
elif "Public Filament package: enable the `p2p` module" in text:
    print("p2p-proto full-node already patched")
else:
    print("warning: could not find p2p-proto full-node feature line to patch", file=sys.stderr)

ct = Path(sys.argv[2])
ct_text = ct.read_text()
orig = ct_text
ct_text = ct_text.replace('rustmmrdb  = { path = "../../rustmmrdb", optional = true }\n', '')
ct_text = ct_text.replace('"dep:rustmmrdb", ', '')
ct_text = ct_text.replace('"dep:rustmmrdb",', '')
if ct_text != orig:
    ct.write_text(ct_text)
    print("patched common-types: removed rustmmrdb path dep")
else:
    print("common-types rustmmrdb already absent or unexpected format")

# Strip the indexer/legacy-daa features and the deps only used by the
# excluded modules (snow: transport.rs; rocksdb/rayon: storage's
# rocks_db.rs/shard_manager.rs). metrics/tokio/libc/sysinfo stay — common::
# still uses them under full-node.
ct_text2 = ct.read_text()
orig2 = ct_text2
ct_text2 = re.sub(
    r'\n(?:#[^\n]*\n)*full-node = \[[^\]]*\]\n(?:# `storage.*?\nindexer   = \[[^\]]*\]\n)?(?:# difficulty_adjustment.*?\nlegacy-daa = \[\]\n)?',
    '\n# `dep:metrics`/`dep:tokio`/`dep:libc`/`dep:sysinfo`: needed by\n'
    '# `common::{testnet_telemetry,fatal_shutdown,notification_ring,startup_memory}`.\n'
    '# (snow/rocksdb/rayon and the indexer/legacy-daa features they backed were\n'
    '# stripped here — they only served transport/storage/difficulty_adjustment,\n'
    '# which this public Filament packaging excludes; see src/lib.rs.)\n'
    'full-node = ["dep:metrics", "dep:tokio", "dep:libc", "dep:sysinfo"]\n',
    ct_text2, count=1, flags=re.DOTALL,
)
for dep_line in (
    'snow       = { version = "0.9", features = ["default-resolver"], optional = true }\n',
    'rocksdb    = { version = "0.22.0", optional = true }\n',
    'rayon      = { version = "1.11", optional = true }\n',
):
    ct_text2 = ct_text2.replace(dep_line, '')
if ct_text2 != orig2:
    ct.write_text(ct_text2)
    print("patched common-types: stripped indexer/legacy-daa features + snow/rocksdb/rayon deps")
else:
    print("warning: common-types feature block not in expected shape — check full-node/indexer/legacy-daa by hand", file=sys.stderr)

lib_rs = Path(sys.argv[3])
lib_text = lib_rs.read_text()
orig_lib = lib_text
# Match `pub mod X;` with any trailing same-line comment, and the
# `#[cfg(feature = "full-node")]` guard line directly above `transport`.
for pattern in (
    r'^pub mod difficulty_adjustment;.*\n',
    r'^pub mod cluster;.*\n',
    r'^pub mod storage;.*\n',
    r'^#\[cfg\(feature = "full-node"\)\]\npub mod transport;.*\n',
    r'^pub mod chain;.*\n',
):
    lib_text = re.sub(pattern, '', lib_text, flags=re.MULTILINE)
if 'pub mod chain_support;' not in lib_text:
    lib_text = lib_text.replace(
        'pub mod transaction;\n',
        'pub mod transaction;\npub mod chain_support;\n',
        1,
    )
if lib_text != orig_lib:
    lib_rs.write_text(lib_text)
    print("patched common-types/src/lib.rs: removed difficulty_adjustment/cluster/storage/transport/chain mod declarations, added chain_support")
else:
    print("common-types/src/lib.rs: no matching mod declarations found (already patched, or shape changed upstream)")

# weighted_mmr_core / windowed_weighted_mmr / epoch_history_fast_start: the
# real MMR write/construction engine, deliberately excluded (owner IP
# decision) even though genesis.rs/validation/beacon.rs still import
# WeightedMMR from it today — this makes `cargo check` fail at those two
# call sites until they're reworked; left broken on purpose, see this
# script's own top-of-file note.
common_mod = Path(sys.argv[4])
cm_text = common_mod.read_text()
orig_cm = cm_text
cm_text = re.sub(
    r'^pub mod epoch_history_fast_start;.*\n', '', cm_text, flags=re.MULTILINE,
)
cm_text = re.sub(
    r'^pub mod weighted_mmr_core;.*\n', '', cm_text, flags=re.MULTILINE,
)
cm_text = re.sub(
    r'^pub mod windowed_weighted_mmr;.*\n', '', cm_text, flags=re.MULTILINE,
)
if cm_text != orig_cm:
    common_mod.write_text(cm_text)
    print("patched common-types/src/common/mod.rs: removed weighted_mmr_core/windowed_weighted_mmr/epoch_history_fast_start mod declarations")
else:
    print("common-types/src/common/mod.rs: no matching mod declarations found (already patched, or shape changed upstream)")
PY

echo "SYNCED_FROM_SHISHA=$SHA" > "$ROOT/VERSION"
echo "Wrote VERSION"

cd "$ROOT"
echo "cargo check -p filament --features full-node ..."
echo "(expected to fail until genesis.rs/validation/beacon.rs stop needing WeightedMMR — see top-of-file note)"
if RUSTFLAGS="${RUSTFLAGS:--Awarnings}" cargo check -p filament --features full-node; then
  echo "OK — synced $SHA"
else
  echo "SYNCED (with known build break) — $SHA"
  echo "Fix genesis.rs/validation/beacon.rs's WeightedMMR usage, or re-scope which files to exclude, before relying on this build."
fi
