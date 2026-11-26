#!/usr/bin/env bash
# Dial a Keystone (or any ShishaNet peer) and report whether the light-client
# handshake completes. Uses crates/filament-p2p/examples/handshake_probe.rs.
#
# Usage:
#   ./scripts/p2p_handshake_probe.sh <host:port> [network] [genesis-hash-hex]
#   ./scripts/p2p_handshake_probe.sh KEYSTONE_HOST:18334 devnet
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-}"
NETWORK="${2:-devnet}"
GENESIS="${3:-}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  echo "usage: $0 <host:port> [network] [genesis-hash-hex]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/filament-public-target}"
cd "$ROOT"
exec cargo run -q -p filament-p2p --example handshake_probe -- "$TARGET" "$NETWORK" ${GENESIS:+"$GENESIS"}
