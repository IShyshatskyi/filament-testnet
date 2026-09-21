#!/usr/bin/env bash
# Fail if the public repo violates the packaging boundary.
#
# Usage:
#   ./scripts/check_public_boundary.sh           # paths+cargo hard; sources warn
#   ./scripts/check_public_boundary.sh --strict  # sources warnings become failures
#
# Reads scripts/public_denylist.txt. If present, also merges gitignored
# scripts/local/extra_denylist.txt (maintainer-only patterns).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DENY_PUBLIC="$ROOT/scripts/public_denylist.txt"
DENY_LOCAL="$ROOT/scripts/local/extra_denylist.txt"
CRATES="$ROOT/crates"
STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
fi

if [[ ! -f "$DENY_PUBLIC" ]]; then
  echo "error: missing $DENY_PUBLIC" >&2
  exit 1
fi
if [[ ! -d "$CRATES" ]]; then
  echo "error: missing $CRATES" >&2
  exit 1
fi

ALLOWED_CRATES=(filament filament-types filament-p2p)
for required in "${ALLOWED_CRATES[@]}"; do
  if [[ ! -d "$CRATES/$required" ]]; then
    echo "error: required crate missing: crates/$required" >&2
    exit 1
  fi
done

# Only the three public workspace crates may exist under crates/.
fail=0
warn=0
while IFS= read -r -d '' entry; do
  name="$(basename "$entry")"
  # Ignore junk that is not a crate (OS metadata, etc.).
  case "$name" in
    .DS_Store|*.swp|*~) continue ;;
  esac
  if [[ -f "$entry" ]]; then
    echo "error: unexpected file under crates/: $name" >&2
    fail=1
    continue
  fi
  allowed=0
  for a in "${ALLOWED_CRATES[@]}"; do
    if [[ "$name" == "$a" ]]; then
      allowed=1
      break
    fi
  done
  if (( ! allowed )); then
    echo "error: unexpected crate under crates/: $name" >&2
    fail=1
  fi
done < <(find "$CRATES" -mindepth 1 -maxdepth 1 \( -type d -o -type f \) -print0)

hit_paths() {
  local pattern="$1"
  find "$CRATES" \( -type f -o -type d \) -path "*${pattern}*" 2>/dev/null | head -20
}

scan_denylist_file() {
  local file="$1"
  local section=""
  local line pattern matches

  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^\[(paths|cargo|sources)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      continue
    fi
    pattern="${line#"${line%%[![:space:]]*}"}"
    pattern="${pattern%"${pattern##*[![:space:]]}"}"
    [[ -z "$pattern" || -z "$section" ]] && continue

    case "$section" in
      paths)
        matches="$(hit_paths "$pattern" || true)"
        if [[ -n "$matches" ]]; then
          echo "error: denylist path hit: ${pattern}" >&2
          echo "$matches" | sed 's/^/  /' >&2
          fail=1
        fi
        ;;
      cargo)
        if grep -R --include='Cargo.toml' --fixed-strings -n -- "$pattern" "$CRATES" "$ROOT/Cargo.toml" 2>/dev/null | head -20 | grep -q .; then
          echo "error: denylist Cargo.toml hit: ${pattern}" >&2
          grep -R --include='Cargo.toml' --fixed-strings -n -- "$pattern" "$CRATES" "$ROOT/Cargo.toml" 2>/dev/null | head -20 | sed 's/^/  /' >&2
          fail=1
        fi
        ;;
      sources)
        if grep -R --include='*.rs' --fixed-strings -n -- "$pattern" "$CRATES" 2>/dev/null | head -20 | grep -q .; then
          if (( STRICT )); then
            echo "error: denylist source hit (--strict): ${pattern}" >&2
            fail=1
          else
            echo "warn: denylist source hit: ${pattern}" >&2
            warn=1
          fi
          grep -R --include='*.rs' --fixed-strings -n -- "$pattern" "$CRATES" 2>/dev/null | head -20 | sed 's/^/  /' >&2
        fi
        ;;
    esac
  done < "$file"
}

scan_denylist_file "$DENY_PUBLIC"
if [[ -f "$DENY_LOCAL" ]]; then
  echo "note: merging maintainer denylist $DENY_LOCAL"
  scan_denylist_file "$DENY_LOCAL"
fi

types_kb=$(du -sk "$CRATES/filament-types" | awk '{print $1}')
p2p_kb=$(du -sk "$CRATES/filament-p2p" | awk '{print $1}')
if (( types_kb > 512 )); then
  echo "error: crates/filament-types is ${types_kb}KiB (ceiling 512KiB) — possible scope leak" >&2
  fail=1
fi
if (( p2p_kb > 256 )); then
  echo "error: crates/filament-p2p is ${p2p_kb}KiB (ceiling 256KiB) — possible scope leak" >&2
  fail=1
fi

echo "public boundary sizes:"
echo "  filament-types: ${types_kb}KiB"
echo "  filament-p2p:   ${p2p_kb}KiB"

if (( fail != 0 )); then
  echo "public boundary check FAILED" >&2
  exit 1
fi

if (( warn != 0 )); then
  echo "public boundary check OK (with source warnings — use --strict to fail)"
  exit 0
fi

echo "public boundary check OK"
