# Maintainer-only sync config.
#
# This directory is gitignored except this README and `*.example` files.
# Examples use **placeholders only** — they must not name real private paths.
#
# Setup (once, on a machine that has the private monorepo):
#
#   cp scripts/local/upstream.env.example scripts/local/upstream.env
#   cp scripts/local/lane_b_map.example scripts/local/lane_b_map.txt
#   cp scripts/local/lane_b_denied_siblings.example scripts/local/lane_b_denied_siblings.txt
#   # optional:
#   cp scripts/local/extra_denylist.example scripts/local/extra_denylist.txt
#
# Then edit the copies with your real upstream paths. Never commit those copies.
#
# Without local files, `sync_filament_public.sh` still runs Lane A; Lane B
# detailed diff reporting is skipped. Public CI uses only `scripts/public_*.txt`.
