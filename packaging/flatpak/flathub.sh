#!/usr/bin/env bash
# The Flathub submission (External Gate G4): Flathub builds from source
# with no network, so every crate and Go module is listed as a source.
#
#   packaging/flatpak/flathub.sh TAG OUT
#
# writes OUT/com.aricummings.Enclave.yml (the release tag's commit,
# both Rust workspaces and lyrebird built with the Rust and Go SDK
# extensions), OUT/cargo-sources.json (the crates of Cargo.lock and
# nym/Cargo.lock), OUT/go-sources.json and OUT/modules.txt (lyrebird's
# Go modules), ready to copy into the flathub/com.aricummings.Enclave
# repository. nightly.yml builds the result with flatpak-builder.
set -euo pipefail
TAG=$1 OUT=$(realpath -m "$2")
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# flatpak-builder-tools at a fixed commit (its cargo generator).
FBT=https://github.com/flatpak/flatpak-builder-tools.git
FBT_COMMIT=74697c75b630d7330e77250fc13cb5ea688d9479
# flatpak-go-mod, for the Go modules.
GOMOD=github.com/dennwc/flatpak-go-mod@v0.1.0
LYREBIRD=https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git
LYREBIRD_COMMIT=$(sed -n 's/^COMMIT=//p' "$ROOT/ci/tor/lyrebird.sh")

commit=$(git -C "$ROOT" rev-list -n 1 "$TAG")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$OUT"

git clone -q "$FBT" "$work/fbt"
git -C "$work/fbt" checkout -q "$FBT_COMMIT"
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q 'aiohttp>=3.9.5,<4' 'PyYAML>=6.0.2,<7' 'tomlkit>=0.13.3,<1'
git -C "$ROOT" show "$commit:Cargo.lock" > "$work/main.lock"
git -C "$ROOT" show "$commit:nym/Cargo.lock" > "$work/nym.lock"
for l in main nym; do
  "$work/venv/bin/python" "$work/fbt/cargo/flatpak-cargo-generator.py" "$work/$l.lock" -o "$work/$l.json"
done
# One list for both workspaces: a crate both use is fetched once.
python3 - "$work/main.json" "$work/nym.json" "$OUT/cargo-sources.json" <<'PY'
import json, sys
seen, out = set(), []
for f in sys.argv[1:3]:
    for s in json.load(open(f)):
        key = json.dumps(s, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(s)
json.dump(out, open(sys.argv[3], "w"), indent=2)
PY

git clone -q "$LYREBIRD" "$work/lyrebird"
git -C "$work/lyrebird" checkout -q "$LYREBIRD_COMMIT"
(cd "$work/lyrebird" && GOTOOLCHAIN=auto go run "$GOMOD" .)
# flatpak-go-mod writes go.mod.yml (the module archives, and modules.txt
# into vendor/) and modules.txt.
python3 - "$work/lyrebird/go.mod.yml" "$OUT/go-sources.json" <<'PY'
import json, sys, yaml
srcs = yaml.safe_load(open(sys.argv[1]))
for s in srcs:
    # Under the lyrebird source's folder.
    if "dest" in s:
        s["dest"] = "lyrebird/" + s["dest"]
json.dump(srcs, open(sys.argv[2], "w"), indent=2)
PY
cp "$work/lyrebird/modules.txt" "$OUT/modules.txt"

cat > "$OUT/com.aricummings.Enclave.yml" <<YAML
app-id: com.aricummings.Enclave
runtime: org.freedesktop.Platform
runtime-version: '25.08'
sdk: org.freedesktop.Sdk
sdk-extensions:
  - org.freedesktop.Sdk.Extension.rust-stable
  - org.freedesktop.Sdk.Extension.golang
  - org.freedesktop.Sdk.Extension.llvm20
command: enclave
finish-args:
  - --share=ipc
  - --socket=wayland
  - --socket=fallback-x11
  - --device=dri
  - --share=network
  - --device=all
  - --talk-name=org.freedesktop.Notifications
  # The status icon when the window is closed (enclave_platform::tray).
  - --talk-name=org.kde.StatusNotifierWatcher
modules:
  - name: enclave
    buildsystem: simple
    build-options:
      append-path: /usr/lib/sdk/rust-stable/bin:/usr/lib/sdk/golang/bin:/usr/lib/sdk/llvm20/bin
      env:
        # bindgen (the camera's V4L2 bindings) needs libclang.
        LIBCLANG_PATH: /usr/lib/sdk/llvm20/lib
        CARGO_HOME: /run/build/enclave/cargo
        CARGO_NET_OFFLINE: 'true'
        GOFLAGS: -mod=vendor
        GOTOOLCHAIN: local
        CGO_ENABLED: '0'
    build-commands:
      - cargo build --release --locked --offline -p enclave-app -p enclave-vault -p enclave-netd -p enclave-mediad -p enclave-tord
      - cd nym && cargo build --release --locked --offline -p enclave-nymd
      - cd lyrebird && go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o ../target/release/lyrebird ./cmd/lyrebird
      - install -d /app/lib/enclave-messenger /app/bin
      - install -m755 target/release/enclave target/release/enclave-vault target/release/enclave-netd target/release/enclave-mediad target/release/enclave-tord nym/target/release/enclave-nymd target/release/lyrebird /app/lib/enclave-messenger/
      - ln -s ../lib/enclave-messenger/enclave /app/bin/enclave
      - install -Dm644 packaging/linux/com.aricummings.Enclave.desktop -t /app/share/applications
      - install -Dm644 packaging/linux/com.aricummings.Enclave.metainfo.xml -t /app/share/metainfo
      - install -Dm644 packaging/icons/enclave.svg /app/share/icons/hicolor/scalable/apps/com.aricummings.Enclave.svg
      - install -Dm644 packaging/icons/enclave-symbolic.svg /app/share/icons/hicolor/symbolic/apps/com.aricummings.Enclave-symbolic.svg
      - for s in 16 24 32 48 64 128 256 512; do install -Dm644 packaging/icons/png/enclave-\$s.png /app/share/icons/hicolor/\${s}x\${s}/apps/com.aricummings.Enclave.png; done
      - install -Dm644 crates/enclave-app/licenses.txt /app/share/doc/enclave/THIRD-PARTY-NOTICES.txt
    sources:
      - type: git
        url: https://github.com/0xnullsect0r/enclave-messenger.git
        tag: $TAG
        commit: $commit
      - type: git
        url: $LYREBIRD
        commit: $LYREBIRD_COMMIT
        dest: lyrebird
      - cargo-sources.json
      - go-sources.json
YAML
echo "flathub: $OUT ($TAG, $commit)"
