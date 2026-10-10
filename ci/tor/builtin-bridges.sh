#!/usr/bin/env bash
# Refresh Enclave's built-in Tor bridges from the Tor Project's
# Circumvention Settings API (the list Tor Browser uses):
#   ci/tor/builtin-bridges.sh            write crates/enclave-tord/bridges/{obfs4,snowflake}.txt
#   ci/tor/builtin-bridges.sh --check    fail if a committed list is out of date
# obfs4 runs in enclave-tord's own process, Snowflake through lyrebird
# (docs/09-transport.md §7). Standard tools only (curl, python3).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
json=$(curl -fsS --max-time 60 -X POST -H 'Content-Type: application/vnd.api+json' \
  https://bridges.torproject.org/moat/circumvention/builtin -d '{}')
stale=0
for kind in obfs4 snowflake; do
  OUT=$ROOT/crates/enclave-tord/bridges/$kind.txt
  new=$(printf '%s' "$json" | python3 -c '
import json, sys
kind = sys.argv[1]
lines = sorted(json.load(sys.stdin).get(kind, []))
assert lines and all(l.startswith(kind + " ") for l in lines), "no " + kind + " bridges"
print("\n".join(lines))
' "$kind")
  if [ "${1:-}" = --check ]; then
    if [ "$new" != "$(cat "$OUT")" ]; then
      echo "::warning::The Tor Project's built-in $kind bridges changed: run ci/tor/builtin-bridges.sh"
      diff <(cat "$OUT") <(printf '%s\n' "$new") || true
      stale=1
    fi
  else
    printf '%s\n' "$new" > "$OUT"
    echo "$(wc -l < "$OUT") $kind bridges → $OUT"
  fi
done
if [ "${1:-}" = --check ]; then
  [ "$stale" = 0 ] || exit 1
  echo "built-in bridges are current"
fi
