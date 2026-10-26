#!/usr/bin/env bash
# netd from a macOS app bundle, started as the vault starts it (Tor's
# state in the profile; a spare standing by), kept running for two
# minutes while Tor comes up: it must still be there at the end, and
# everything it and Tor said is printed (mac-app-check.yml).
#
#   ci/macos/netd-check.sh /path/to/Enclave.app
set -uo pipefail
app=$1
bin="$app/Contents/MacOS"
profile=$(mktemp -d)/profile
mkdir -p "$profile"
# Its stdin stays open (the vault's pipe) and carries nothing; once
# the sleep ends it closes, and netd goes by itself.
(sleep 150 | "$bin/enclave-netd" --tor "$profile/tor" --report 2> "$profile/main.log") &
sleep 1
(sleep 150 | "$bin/enclave-netd" --tor "$profile/tor" --tor-standby --report 2> "$profile/spare.log") &
ok=1
for t in 10 30 60 120; do
  sleep $((t - ${prev:-0}))
  prev=$t
  echo "== after ${t}s"
  for which in main spare; do
    echo "-- $which:"
    cat "$profile/$which.log"
  done
  alive=$(pgrep -f "enclave-netd --tor $profile/tor" | wc -l | tr -d ' ')
  echo "netd processes alive: $alive"
  [ "$alive" -ge 2 ] || ok=0
done
ls -la "$profile/tor" 2>/dev/null | head -20
for f in ~/Library/Logs/DiagnosticReports/enclave*; do [ -f "$f" ] && { echo "== $f"; head -80 "$f"; }; done
[ "$ok" = 1 ] || { echo "netd stopped"; exit 1; }
echo "netd stayed up"
