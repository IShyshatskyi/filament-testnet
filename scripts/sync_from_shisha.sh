#!/usr/bin/env bash
# LEGACY — DISABLED.
#
# This script rsyncs legacy packaging crates into the public repo and is
# incompatible with clean-room filament-types / filament-p2p packaging.
# Running it would risk re-exposing scoped-out monorepo material.
#
# Use instead:
#   ./scripts/sync_filament_public.sh --dry-run /path/to/private-monorepo
#   ./scripts/check_public_boundary.sh
#
# Maintainer maps: scripts/local/ (gitignored).
set -euo pipefail

echo "error: scripts/sync_from_shisha.sh is disabled." >&2
echo "       Use ./scripts/sync_filament_public.sh (see --help)." >&2
echo "       Boundary: ./scripts/check_public_boundary.sh" >&2
exit 1
