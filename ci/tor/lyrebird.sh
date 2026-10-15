#!/usr/bin/env bash
# lyrebird, the Tor Project's pluggable-transport program, for Snowflake
# and WebTunnel bridges (docs/09-transport.md §7; a declared Go exception,
# shipped next to enclave-tord).
#
#   ci/tor/lyrebird.sh build OUT [GOOS GOARCH]   build it at the pinned commit
#   ci/tor/lyrebird.sh archive OUT TARGET        its clients as a library for the
#                                                phone app (ci/tor/lyrebird-lib;
#                                                TARGET a Rust phone target, CC set):
#                                                liblyrebird.so on Android (Go makes
#                                                no static archive there), .a on iOS
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
    mkdir -p "$(dirname "$2")"
    out=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
    fetch
    (cd "$SRC" && GOOS=${3:-$(go env GOOS)} GOARCH=${4:-$(go env GOARCH)} \
      go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.lyrebirdVersion=$VERSION" \
        -o "$out" ./cmd/lyrebird)
    echo "lyrebird $VERSION ($COMMIT) → $out"
    ;;
  archive)
    # A phone starts no programs: Snowflake and WebTunnel run in the app's
    # process (enclave_pt_start): on iOS linked into the program
    # (liblyrebird.a), on Android loaded by enclave-mobile from the APK
    # (liblyrebird.so). cgo, so the platform's C compiler comes from CC.
    # -checklinkname=0: Snowflake's WebRTC reads Android's interfaces
    # through github.com/wlynxg/anet, which links to a Go internal (as
    # Tor's own Android builds do).
    mkdir -p "$2"
    out=$(cd "$2" && pwd)
    case "$3" in
      aarch64-linux-android) goos=android goarch=arm64 mode=c-shared lib=liblyrebird.so ;;
      x86_64-linux-android) goos=android goarch=amd64 mode=c-shared lib=liblyrebird.so ;;
      aarch64-apple-ios) goos=ios goarch=arm64 mode=c-archive lib=liblyrebird.a ;;
      *) echo "lyrebird.sh: no phone target $3" >&2; exit 2 ;;
    esac
    fetch
    rm -rf "$SRC/cmd/enclave-pt" && mkdir -p "$SRC/cmd/enclave-pt"
    cp "$ROOT/ci/tor/lyrebird-lib/enclave_pt.go" "$SRC/cmd/enclave-pt/"
    (cd "$SRC" && CGO_ENABLED=1 GOOS=$goos GOARCH=$goarch \
      go build -buildmode=$mode -trimpath -buildvcs=false -ldflags="-s -w -buildid= -checklinkname=0" \
        -o "$out/$lib" ./cmd/enclave-pt)
    rm -rf "$SRC/cmd/enclave-pt" "$out/liblyrebird.h"
    echo "lyrebird $VERSION ($COMMIT) clients for $3 → $out/$lib"
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
