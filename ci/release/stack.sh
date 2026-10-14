#!/usr/bin/env bash
# The compose stack a release publishes (release.yml), as
# oci://ghcr.io/enclavechat/enclave-stack:VERSION and in the operator kit:
# ops/compose's production files. Its images follow ENCLAVE_VERSION
# (`latest`: the updater moves the stack to each new signed release; a
# version stays on it).
#
#   ci/release/stack.sh VERSION OUT
set -euo pipefail
V=$1 OUT=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
rm -rf "$OUT" && mkdir -p "$OUT"
cp -r "$ROOT/ops/compose/compose.yml" "$ROOT/ops/compose/compose.postgres.yml" \
  "$ROOT/ops/compose/.env.example" "$ROOT/ops/compose/config" "$ROOT/ops/compose/foundation" "$OUT/"
# Every image is one of the release's.
images=$(grep -h 'image:' "$OUT/compose.yml" | grep -v 'ghcr.io/enclavechat/enclave-' || true)
if [ -n "$images" ]; then
  echo "stack: an image isn't a release image: $images" >&2
  exit 1
fi
echo "stack: $OUT (release $V; images follow ENCLAVE_VERSION, default latest)"
