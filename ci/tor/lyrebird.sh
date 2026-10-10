#!/usr/bin/env bash
# lyrebird, the Tor Project's pluggable-transport program, for Snowflake
# and WebTunnel bridges (docs/09-transport.md §7; a declared Go exception,
# shipped next to enclave-tord).
#
#   ci/tor/lyrebird.sh build OUT [GOOS GOARCH]   build it at the pinned commit
#   ci/tor/lyrebird.sh licenses                  write LICENSES/lyrebird.txt
#
# The source is the pinned commit (checked after cloning); Go modules are
# checked against go.sum and the Go checksum database; the build is
# reproducible (-trimpath, no build id, no VCS stamp, no cgo).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REPO=https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git
VERSION=0.9.0
COMMIT=89d54872b176f936232ff39f7a8189b77d83d65e
SRC=$ROOT/target/lyrebird-src

fetch() {
  if [ ! -d "$SRC/.git" ]; then
    rm -rf "$SRC"
    git clone -q "$REPO" "$SRC"
  fi
  git -C "$SRC" fetch -q origin "$COMMIT" 2>/dev/null || git -C "$SRC" fetch -q origin
  git -C "$SRC" checkout -q --detach "$COMMIT"
  test "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT"
}

export GOTOOLCHAIN=${GOTOOLCHAIN:-auto} GOFLAGS=-mod=readonly CGO_ENABLED=0

case "${1:-}" in
  build)
    out=$2
    fetch
    mkdir -p "$(dirname "$out")"
    (cd "$SRC" && GOOS=${3:-$(go env GOOS)} GOARCH=${4:-$(go env GOARCH)} \
      go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.lyrebirdVersion=$VERSION" \
        -o "$(realpath -m "$out")" ./cmd/lyrebird)
    echo "lyrebird $VERSION ($COMMIT) → $out"
    ;;
  licenses)
    fetch
    out=$ROOT/LICENSES/lyrebird.txt
    # Every module the program is built from, and Go's standard library.
    (cd "$SRC" && go mod download \
      && go list -deps -f '{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}' ./cmd/lyrebird \
      && echo "go-stdlib $(go env GOVERSION) $(go env GOROOT)") \
      | sort -u | python3 -c '
import os, sys
version, commit = sys.argv[1], sys.argv[2]
seen = {}
for line in sys.stdin:
    parts = line.split()
    if len(parts) == 2:
        path, ver, d = parts[0], "", parts[1]
    elif len(parts) == 3:
        path, ver, d = parts
    else:
        continue
    texts = []
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        if not f.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
            continue
        # REUSE layout: a LICENSES/ folder of texts.
        files = [os.path.join(p, g) for g in sorted(os.listdir(p))] if os.path.isdir(p) else [p]
        for q in files:
            texts.append(open(q, encoding="utf-8", errors="replace").read().strip())
    if not texts:
        sys.exit(f"no licence text in {path}")
    name = f"{path} {ver or version}".strip()
    seen.setdefault("\n\n".join(texts), []).append(name)
print("lyrebird " + version + " (" + commit + ") and the Go modules it is built from.")
print("It runs Snowflake and WebTunnel bridges, next to enclave-tord.")
for text, names in seen.items():
    print()
    print("-" * 72)
    for n in sorted(names):
        print(n)
    print()
    print(text)
' "$VERSION" "$COMMIT" > "$out"
    echo "$(grep -c '^-----' "$out") licence texts → $out"
    ;;
  *)
    echo "usage: ci/tor/lyrebird.sh build OUT [GOOS GOARCH] | licenses" >&2
    exit 2
    ;;
esac
