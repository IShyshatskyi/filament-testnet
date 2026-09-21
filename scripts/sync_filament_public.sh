#!/usr/bin/env bash
# Sync Filament public packaging from a local upstream checkout.
#
# Lane A (--apply): copy crates/filament only, remap Cargo deps to
# filament-types / filament-p2p, restore clean-room overlays, boundary-check,
# then write VERSION. Does NOT touch filament-types / filament-p2p trees
# (Lanes B/C remain manual / local-map driven).
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
KEEP_PUBLIC="$ROOT/scripts/lane_a_keep_public.txt"
LOCAL_DIR="$ROOT/scripts/local"
LOCAL_ENV="$LOCAL_DIR/upstream.env"
LOCAL_B_MAP="$LOCAL_DIR/lane_b_map.txt"
LOCAL_B_DENIED="$LOCAL_DIR/lane_b_denied_siblings.txt"
FILAMENT_DST="$ROOT/crates/filament"

mode="status"
SHISHA=""
UPSTREAM_TYPES_ROOT=""

load_local_env() {
  if [[ ! -f "$LOCAL_ENV" ]]; then
    return 0
  fi
  # shellcheck disable=SC1090
  set -a
  # Only allow simple KEY=VALUE lines (no command substitution).
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

# Resolve SHISHA relative to ROOT when not absolute.
if [[ "$SHISHA" != /* ]]; then
  SHISHA="$ROOT/$SHISHA"
fi
# Normalize
SHISHA="$(cd "$SHISHA" 2>/dev/null && pwd || echo "$SHISHA")"

if [[ -n "${UPSTREAM_TYPES_ROOT:-}" && "$UPSTREAM_TYPES_ROOT" != /* ]]; then
  UPSTREAM_TYPES_ROOT="$SHISHA/$UPSTREAM_TYPES_ROOT"
fi

if [[ ! -x "$CHECK" ]]; then
  chmod +x "$CHECK" 2>/dev/null || true
fi

report_lane_a_diff() {
  echo
  echo "== Lane A (filament) — file diff vs upstream =="
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

report_lane_b() {
  echo
  echo "== Lane B (filament-types) =="
  if [[ ! -f "$LOCAL_B_MAP" || -z "${UPSTREAM_TYPES_ROOT:-}" || ! -d "${UPSTREAM_TYPES_ROOT:-}" ]]; then
    echo "  skipped detailed map (maintainer-only)."
    echo "  see scripts/local/README.md to enable Lane B reporting."
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
  done < "$LOCAL_B_MAP"

  if [[ -f "$LOCAL_B_DENIED" ]]; then
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
    done < "$LOCAL_B_DENIED"
    echo "  blocked upstream siblings present: $blocked_n (names not printed)"
  fi
}

report_lane_c() {
  echo
  echo "== Lane C (filament-p2p) =="
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

bad = []
for needle in ('../common-types', '../p2p-proto', 'rustmmrdb', 'p2p-proto/full-node'):
    if needle in text:
        bad.append(needle)
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

apply_lane_a() {
  local sha="$1"
  local backup
  backup="$(mktemp -d "${TMPDIR:-/tmp}/filament-public-backup.XXXXXX")"
  echo
  echo "== Lane A apply =="
  echo "  backup: $backup"

  mkdir -p "$backup/crates"
  rsync -a --exclude target --exclude .DS_Store \
    "$FILAMENT_DST/" "$backup/crates/filament/"

  cleanup_on_fail() {
    echo "error: Lane A apply failed — restoring filament from backup" >&2
    rsync -a --delete --exclude target --exclude .DS_Store \
      "$backup/crates/filament/" "$FILAMENT_DST/"
    rm -rf "$backup"
  }

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

  echo "  boundary check"
  if ! "$CHECK"; then
    cleanup_on_fail
    return 1
  fi

  echo "SYNCED_FROM_SHISHA=$sha" > "$ROOT/VERSION"
  echo "  wrote VERSION → SYNCED_FROM_SHISHA=$sha"

  echo "  cargo check -p filament (advisory)"
  if (
    cd "$ROOT"
    RUSTFLAGS="${RUSTFLAGS:--Awarnings}" cargo check -p filament --features full-node
  ); then
    echo "  cargo check OK"
  else
    echo "  warning: cargo check failed — Lane A sources applied; types/p2p"
    echo "           APIs may need further ports before the public build is green."
  fi

  rm -rf "$backup"
  echo "Lane A apply complete."
}

# ── main ──────────────────────────────────────────────────────────────────────

echo "== public boundary =="
"$CHECK"

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

report_lane_a_diff
report_lane_b
report_lane_c

if [[ "$mode" == "dry-run" || "$mode" == "status" ]]; then
  echo
  echo "== status =="
  echo "  No files modified. Pass --apply to copy Lane A (filament) only."
  exit 0
fi

if [[ "$mode" == "apply" ]]; then
  apply_lane_a "$sha"
  echo
  echo "== post-apply Lane A diff (should be overlays + remaps only) =="
  report_lane_a_diff
  exit 0
fi

echo "error: unknown mode: $mode" >&2
exit 1
