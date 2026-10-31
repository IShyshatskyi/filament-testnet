#!/usr/bin/env bash
# Sync Filament public packaging from a local upstream checkout.
#
# filament-sync (--apply): copy crates/filament only, remap Cargo deps to
# filament-types / filament-p2p, restore clean-room overlays, scrub denylist
# hits (e.g. WindowedWeightedMMR test helpers), boundary-check + cargo check,
# then write VERSION. Does NOT touch filament-types / filament-p2p trees
# (types-port / p2p-port remain manual).
#
# Usage:
#   ./scripts/sync_filament_public.sh [--check-only]
#   ./scripts/sync_filament_public.sh --dry-run [/path/to/upstream]
#   ./scripts/sync_filament_public.sh --status [/path/to/upstream]
#   ./scripts/sync_filament_public.sh --apply [/path/to/upstream]
#
# Maintainer path maps: gitignored scripts/local/ (see scripts/local/README.md).
# Do NOT use scripts/sync_from_shisha.sh (legacy; disabled).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALLOW="$ROOT/scripts/public_allowlist.txt"
DENY="$ROOT/scripts/public_denylist.txt"
CHECK="$ROOT/scripts/check_public_boundary.sh"
KEEP_PUBLIC="$ROOT/scripts/filament_sync_keep_public.txt"
EXCLUDE_LIST="$ROOT/scripts/filament_sync_exclude.txt"
LOCAL_DIR="$ROOT/scripts/local"
LOCAL_ENV="$LOCAL_DIR/upstream.env"
LOCAL_TYPES_MAP="$LOCAL_DIR/types_port_map.txt"
LOCAL_TYPES_DENIED="$LOCAL_DIR/types_port_denied_siblings.txt"
# Backward-compatible gitignored names
[[ -f "$LOCAL_DIR/lane_b_map.txt" && ! -f "$LOCAL_TYPES_MAP" ]] && LOCAL_TYPES_MAP="$LOCAL_DIR/lane_b_map.txt"
[[ -f "$LOCAL_DIR/lane_b_denied_siblings.txt" && ! -f "$LOCAL_TYPES_DENIED" ]] && LOCAL_TYPES_DENIED="$LOCAL_DIR/lane_b_denied_siblings.txt"
FILAMENT_DST="$ROOT/crates/filament"

mode="status"
SHISHA=""
UPSTREAM_TYPES_ROOT=""

load_local_env() {
  if [[ ! -f "$LOCAL_ENV" ]]; then
    return 0
  fi
  set -a
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^(SHISHA|UPSTREAM_TYPES_ROOT)= ]]; then
      export "$line"
    fi
  done < "$LOCAL_ENV"
  set +a
}

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

load_local_env

SHISHA="${SHISHA:-$ROOT/../shisha}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only) mode="check-only"; shift ;;
    --dry-run)    mode="dry-run"; shift ;;
    --status)     mode="status"; shift ;;
    --apply)      mode="apply"; shift ;;
    -h|--help)    usage 0 ;;
    --*)          echo "error: unknown option: $1" >&2; usage 1 ;;
    *)            SHISHA="$1"; shift ;;
  esac
done

if [[ "$SHISHA" != /* ]]; then
  SHISHA="$ROOT/$SHISHA"
fi
SHISHA="$(cd "$SHISHA" 2>/dev/null && pwd || echo "$SHISHA")"

if [[ -n "${UPSTREAM_TYPES_ROOT:-}" && "$UPSTREAM_TYPES_ROOT" != /* ]]; then
  UPSTREAM_TYPES_ROOT="$SHISHA/$UPSTREAM_TYPES_ROOT"
fi

if [[ ! -x "$CHECK" ]]; then
  chmod +x "$CHECK" 2>/dev/null || true
fi

report_filament_sync_diff() {
  echo
  echo "== filament-sync — file diff vs upstream =="
  if command -v diff >/dev/null; then
    diff -rq \
      --exclude .DS_Store \
      --exclude target \
      "$SHISHA/crates/filament" \
      "$FILAMENT_DST" \
      2>/dev/null \
      | sed 's/^/  /' \
      || true
  else
    echo "  (diff not available)"
  fi
}

report_types_port() {
  echo
  echo "== types-port (filament-types) =="
  if [[ ! -f "$LOCAL_TYPES_MAP" || -z "${UPSTREAM_TYPES_ROOT:-}" || ! -d "${UPSTREAM_TYPES_ROOT:-}" ]]; then
    echo "  skipped detailed map (maintainer-only)."
    echo "  see scripts/local/README.md to enable types-port reporting."
    return 0
  fi

  local entry priv pub
  while IFS= read -r entry || [[ -n "${entry:-}" ]]; do
    [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ -z "$entry" || "$entry" != *:* ]] && continue
    priv="${entry%%:*}"
    pub="${entry#*:}"
    if [[ -f "$UPSTREAM_TYPES_ROOT/$priv" && -f "$ROOT/$pub" ]]; then
      if cmp -s "$UPSTREAM_TYPES_ROOT/$priv" "$ROOT/$pub"; then
        echo "  identical  $pub"
      else
        echo "  DIFFERS    $pub"
      fi
    elif [[ ! -f "$UPSTREAM_TYPES_ROOT/$priv" ]]; then
      echo "  missing-upstream  ($pub)"
    else
      echo "  missing-public   $pub"
    fi
  done < "$LOCAL_TYPES_MAP"

  if [[ -f "$LOCAL_TYPES_DENIED" ]]; then
    echo
    local blocked_n=0
    local denied
    while IFS= read -r denied || [[ -n "${denied:-}" ]]; do
      [[ -z "$denied" || "$denied" =~ ^[[:space:]]*# ]] && continue
      denied="${denied#"${denied%%[![:space:]]*}"}"
      denied="${denied%"${denied##*[![:space:]]}"}"
      [[ -z "$denied" ]] && continue
      if [[ -f "$UPSTREAM_TYPES_ROOT/$denied" ]]; then
        blocked_n=$((blocked_n + 1))
      fi
    done < "$LOCAL_TYPES_DENIED"
    echo "  blocked upstream siblings present: $blocked_n (names not printed)"
  fi
}

report_p2p_port() {
  echo
  echo "== p2p-port (filament-p2p) =="
  echo "  clean-room only; no automatic upstream P2P mirror."
  echo "  public files:"
  find "$ROOT/crates/filament-p2p" -type f ! -name .DS_Store | sed "s|^$ROOT/|  |"
}

# Remap upstream filament Cargo.toml onto public clean-room crate names.
remap_filament_cargo() {
  local cargo="$FILAMENT_DST/Cargo.toml"
  python3 - "$cargo" <<'PY'
import pathlib, re, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
orig = text

text = text.replace(
    'common-types = { path = "../common-types" }',
    'common_types = { package = "filament-types", path = "../filament-types" }',
)
text = text.replace(
    'p2p-proto        = { path = "../p2p-proto", optional = true }',
    'p2p_proto        = { package = "filament-p2p", path = "../filament-p2p", optional = true }',
)
text = text.replace(
    'p2p-proto = { path = "../p2p-proto", optional = true }',
    'p2p_proto = { package = "filament-p2p", path = "../filament-p2p", optional = true }',
)

text = text.replace('"dep:p2p-proto"', '"dep:p2p_proto"')
text = re.sub(
    r'\n\s*"p2p-proto/full-node",?\n',
    '\n',
    text,
)

if text == orig:
    print("warning: remap_filament_cargo: no substitutions applied — check Cargo.toml shape", file=sys.stderr)
    sys.exit(2)

needles = ['../common-types', '../p2p-proto', 'p2p-proto/full-node']
local = path.parents[2] / 'scripts' / 'local' / 'extra_denylist.txt'
if local.exists():
    section = ''
    for raw in local.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'cargo':
            needles.append(line)
bad = [n for n in needles if n in text]
if bad:
    print(f"error: remap left forbidden tokens: {bad}", file=sys.stderr)
    sys.exit(1)

path.write_text(text)
print("remapped crates/filament/Cargo.toml → filament-types / filament-p2p")
PY
}

restore_keep_public_overlays() {
  local list="$1"
  local backup_root="$2"
  if [[ ! -f "$list" ]]; then
    echo "warning: missing keep-public list: $list" >&2
    return 0
  fi
  local rel
  while IFS= read -r rel || [[ -n "${rel:-}" ]]; do
    [[ -z "$rel" || "$rel" =~ ^[[:space:]]*# ]] && continue
    rel="${rel#"${rel%%[![:space:]]*}"}"
    rel="${rel%"${rel##*[![:space:]]}"}"
    [[ -z "$rel" ]] && continue
    if [[ ! -f "$backup_root/$rel" ]]; then
      echo "error: keep-public overlay missing in backup: $rel" >&2
      return 1
    fi
    mkdir -p "$(dirname "$ROOT/$rel")"
    cp "$backup_root/$rel" "$ROOT/$rel"
    echo "  restored overlay: $rel"
  done < "$list"
}

# Strip denylist source hits from crates/filament (typically cfg(test) WMMR helpers).
# Strategy: delete entire #[cfg(test)] modules/blocks that reference WindowedWeightedMMR,
# and fail if any remaining non-test hit survives.
scrub_filament_denylist_hits() {
  python3 - "$FILAMENT_DST" <<'PY'
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
needles = (
    "WindowedWeightedMMR",
    "windowed_weighted_mmr",
    "common::windowed_weighted_mmr",
    "kameniar_common",
    "rustmmrdb::",
)

def scrub_file(path: pathlib.Path) -> bool:
    text = path.read_text()
    if not any(n in text for n in needles):
        return False
    # Remove cfg(test) modules that contain needles (mod name { ... } with brace match).
    pattern = re.compile(
        r"(?ms)^[ \t]*#\[cfg\(test\)\][ \t]*\n[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+\w+[ \t]*\{"
    )
    out = []
    i = 0
    changed = False
    while True:
        m = pattern.search(text, i)
        if not m:
            out.append(text[i:])
            break
        start = m.start()
        # find matching brace from m.end()-1
        brace_start = m.end() - 1
        depth = 0
        j = brace_start
        while j < len(text):
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        block = text[start:j]
        if any(n in block for n in needles):
            out.append(text[i:start])
            # drop trailing blank lines after removed block
            while j < len(text) and text[j] in "\r\n":
                j += 1
            i = j
            changed = True
        else:
            out.append(text[i:j])
            i = j
    new_text = "".join(out)
    # Also strip standalone doc comments that mention WindowedWeightedMMR outside tests
    # if they would trip the denylist as source hits — denylist scans .rs text.
    if any(n in new_text for n in needles):
        # Remove lines that are pure comments/docs mentioning needles when not in remaining code paths
        lines = new_text.splitlines(keepends=True)
        kept = []
        for line in lines:
            if any(n in line for n in needles) and line.lstrip().startswith(("///", "//!", "//")):
                changed = True
                continue
            kept.append(line)
        new_text = "".join(kept)
    if any(n in new_text for n in ("WindowedWeightedMMR", "windowed_weighted_mmr", "kameniar_common", "rustmmrdb::")):
        print(f"error: scrub left denylist hits in {path}", file=sys.stderr)
        for n in needles:
            if n in new_text:
                for li, line in enumerate(new_text.splitlines(), 1):
                    if n in line:
                        print(f"  {path}:{li}: {line.strip()[:120]}", file=sys.stderr)
                        break
        sys.exit(1)
    if changed or new_text != text:
        path.write_text(new_text)
        print(f"  scrubbed {path.relative_to(root.parent.parent)}")
        return True
    return False

changed_any = False
for path in sorted(root.rglob("*.rs")):
    if scrub_file(path):
        changed_any = True
if not changed_any:
    print("  scrub: no denylist hits in filament sources")
PY
}

apply_filament_sync() {
  local sha="$1"
  local backup
  backup="$(mktemp -d "${TMPDIR:-/tmp}/filament-public-backup.XXXXXX")"
  echo
  echo "== filament-sync apply =="
  echo "  backup: $backup"

  mkdir -p "$backup/crates"
  rsync -a --exclude target --exclude .DS_Store \
    "$FILAMENT_DST/" "$backup/crates/filament/"

  cleanup_on_fail() {
    echo "error: filament-sync apply failed — restoring filament from backup" >&2
    rsync -a --delete --exclude target --exclude .DS_Store \
      "$backup/crates/filament/" "$FILAMENT_DST/"
    # restore VERSION if we wrote it
    if [[ -f "$backup/VERSION" ]]; then
      cp "$backup/VERSION" "$ROOT/VERSION"
    fi
    rm -rf "$backup"
  }

  cp "$ROOT/VERSION" "$backup/VERSION" 2>/dev/null || true

  if ! command -v rsync >/dev/null; then
    echo "error: rsync is required for --apply" >&2
    rm -rf "$backup"
    return 1
  fi

  echo "  rsync upstream/crates/filament → crates/filament"
  rsync -a --delete \
    --exclude target \
    --exclude .DS_Store \
    "$SHISHA/crates/filament/" "$FILAMENT_DST/"

  echo "  remap Cargo.toml"
  if ! remap_filament_cargo; then
    cleanup_on_fail
    return 1
  fi

  echo "  restore keep-public overlays"
  if ! restore_keep_public_overlays "$KEEP_PUBLIC" "$backup"; then
    cleanup_on_fail
    return 1
  fi

  echo "  apply filament_sync_exclude.txt"
  if [[ -f "$EXCLUDE_LIST" ]]; then
    while IFS= read -r rel || [[ -n "${rel:-}" ]]; do
      [[ -z "$rel" || "$rel" =~ ^[[:space:]]*# ]] && continue
      rel="${rel#"${rel%%[![:space:]]*}"}"
      rel="${rel%"${rel##*[![:space:]]}"}"
      [[ -z "$rel" ]] && continue
      target="$FILAMENT_DST/$rel"
      if [[ -e "$target" ]]; then
        rm -rf "$target"
        echo "  excluded: crates/filament/$rel"
      fi
    done < "$EXCLUDE_LIST"
    # Drop mod declarations for excluded basenames from mod.rs files
    python3 - "$FILAMENT_DST" <<'PY2'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
removed = {"thin_shard","escrow_api","chain_views","keystone_submit","escrow","hot_key"}
for modrs in root.rglob("mod.rs"):
    text = modrs.read_text()
    lines = []
    changed = False
    for line in text.splitlines(True):
        m = re.search(r'\bmod\s+(\w+)\s*;', line)
        if m and m.group(1) in removed:
            changed = True
            continue
        lines.append(line)
    if changed:
        modrs.write_text(''.join(lines))
        print(f"  scrubbed mods in {modrs.relative_to(root)}")
PY2
  fi

  echo "  scrub denylist hits (WMMR test helpers, etc.)"
  if ! scrub_filament_denylist_hits; then
    cleanup_on_fail
    return 1
  fi

  echo "  boundary check --strict"
  if ! "$CHECK" --strict; then
    cleanup_on_fail
    return 1
  fi

  echo "  cargo check -p filament-types"
  if ! (
    cd "$ROOT"
    RUSTFLAGS="${RUSTFLAGS:--Awarnings}" cargo check -p filament-types
  ); then
    cleanup_on_fail
    return 1
  fi

  echo "  cargo check -p filament --features full-node"
  if ! (
    cd "$ROOT"
    RUSTFLAGS="${RUSTFLAGS:--Awarnings}" cargo check -p filament --features full-node
  ); then
    cleanup_on_fail
    return 1
  fi

  echo "SYNCED_FROM_SHISHA=$sha" > "$ROOT/VERSION"
  echo "  wrote VERSION → SYNCED_FROM_SHISHA=$sha"

  rm -rf "$backup"
  echo "filament-sync apply complete."
}

# ── main ──────────────────────────────────────────────────────────────────────

echo "== public boundary =="
"$CHECK" --strict

if [[ "$mode" == "check-only" ]]; then
  exit 0
fi

pin="(no VERSION)"
if [[ -f "$ROOT/VERSION" ]]; then
  pin="$(tr -d '\n' < "$ROOT/VERSION")"
fi
echo
echo "== pin =="
echo "  $pin"

echo
echo "== policy =="
echo "  allow: $ALLOW"
echo "  deny:  $DENY"
echo "  keep-public overlays: $KEEP_PUBLIC"
echo "  local maps: $LOCAL_DIR (gitignored; optional)"

if [[ ! -d "$SHISHA" ]]; then
  echo
  echo "error: upstream path not found: $SHISHA" >&2
  echo "       pass a path argument or set SHISHA in scripts/local/upstream.env" >&2
  exit 1
fi

if [[ ! -d "$SHISHA/crates/filament" ]]; then
  echo "error: expected $SHISHA/crates/filament" >&2
  exit 1
fi

sha="$(cd "$SHISHA" && git rev-parse HEAD)"
echo
echo "== upstream =="
echo "  path: $SHISHA"
echo "  HEAD: $sha"

report_filament_sync_diff
report_types_port
report_p2p_port

if [[ "$mode" == "dry-run" || "$mode" == "status" ]]; then
  echo
  echo "== status =="
  echo "  No files modified. Pass --apply to run filament-sync (crates/filament) only."
  exit 0
fi

if [[ "$mode" == "apply" ]]; then
  apply_filament_sync "$sha"
  echo
  echo "== post-apply filament-sync diff (overlays + remaps + scrub) =="
  report_filament_sync_diff
  exit 0
fi

echo "error: unknown mode: $mode" >&2
exit 1
