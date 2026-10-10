#!/usr/bin/env bash
# The compose stack a release publishes (release.yml): ops/compose with the
# images pinned to this release, by digest when given.
#
#   ci/release/stack.sh VERSION SERVER_DIGEST NYM_DIGEST OUT
set -euo pipefail
V=$1 SERVER=$2 NYM=$3 OUT=$4
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REG=ghcr.io/enclavechat
rm -rf "$OUT" && mkdir -p "$OUT"
cp -r "$ROOT/ops/compose/compose.yml" "$ROOT/ops/compose/compose.postgres.yml" \
  "$ROOT/ops/compose/.env.example" "$ROOT/ops/compose/config" "$ROOT/ops/compose/foundation" "$OUT/"
server=$REG/enclave-server:$V${SERVER:+@$SERVER}
nym=$REG/enclave-nym:$V${NYM:+@$NYM}
for f in "$OUT/compose.yml" "$OUT/compose.postgres.yml"; do
  sed -i \
    -e "s|\${ENCLAVE_IMAGE:-$REG/enclave-server}:\${ENCLAVE_VERSION:-latest}|$server|g" \
    -e "s|\${ENCLAVE_NYM_IMAGE:-$REG/enclave-nym}:\${ENCLAVE_VERSION:-latest}|$nym|g" "$f"
done
# Every image is the release's now.
if grep -n 'ENCLAVE_VERSION\|ENCLAVE_IMAGE\|ENCLAVE_NYM_IMAGE' "$OUT/compose.yml" "$OUT/compose.postgres.yml"; then
  echo "stack: an image isn't pinned" >&2
  exit 1
fi
sed -i -e "/^ENCLAVE_IMAGE=/d" -e "/^ENCLAVE_NYM_IMAGE=/d" -e "s/^ENCLAVE_VERSION=.*/ENCLAVE_VERSION=$V/" "$OUT/.env.example"
echo "stack: $OUT ($server, $nym)"
