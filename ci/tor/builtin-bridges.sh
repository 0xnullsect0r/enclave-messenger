#!/usr/bin/env bash
# Refresh Enclave's built-in Tor bridges from the Tor Project's
# Circumvention Settings API (the list Tor Browser uses):
#   ci/tor/builtin-bridges.sh            write crates/enclave-tord/bridges/obfs4.txt
#   ci/tor/builtin-bridges.sh --check    fail if the committed list is out of date
# Only obfs4 bridges: enclave-tord runs obfs4 in its own process
# (docs/09-transport.md §7). Standard tools only (curl, python3).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$ROOT/crates/enclave-tord/bridges/obfs4.txt
json=$(curl -fsS --max-time 60 -X POST -H 'Content-Type: application/vnd.api+json' \
  https://bridges.torproject.org/moat/circumvention/builtin -d '{}')
new=$(printf '%s' "$json" | python3 -c '
import json, sys
lines = sorted(json.load(sys.stdin).get("obfs4", []))
assert lines and all(l.startswith("obfs4 ") for l in lines), "no obfs4 bridges"
print("\n".join(lines))
')
if [ "${1:-}" = --check ]; then
  if [ "$new" != "$(cat "$OUT")" ]; then
    echo "::warning::The Tor Project's built-in obfs4 bridges changed: run ci/tor/builtin-bridges.sh"
    diff <(cat "$OUT") <(printf '%s\n' "$new") || true
    exit 1
  fi
  echo "built-in bridges are current"
else
  printf '%s\n' "$new" > "$OUT"
  echo "$(wc -l < "$OUT") obfs4 bridges → $OUT"
fi
