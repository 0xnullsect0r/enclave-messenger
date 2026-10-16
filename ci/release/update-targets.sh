#!/usr/bin/env bash
# The files the update channel's targets list (docs/19-ops.md §1):
#   ci/release/update-targets.sh VERSION DIST OUT
# copies every release file from DIST into OUT, and each program a desktop
# install runs as `program@triple` ("Verify this build" hashes the programs
# where they run): from the Linux and Windows archives, and on macOS from
# the signed app (signing changes the programs, so not the tarball's).
set -euo pipefail
V=$1 DIST=$2 OUT=$3
mkdir -p "$OUT"
for f in "$DIST"/*; do
  case "$(basename "$f")" in
    *.sigstore.json | MANIFEST.txt | enclave-targets.*) continue ;;
  esac
  cp "$f" "$OUT/"
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
programs() { # DIR TRIPLE: copy DIR's enclave programs as program@TRIPLE
  find "$1" -type f \( -name 'enclave' -o -name 'enclave-*' \) ! -name '*.*' -print0 |
    while IFS= read -r -d '' p; do cp "$p" "$OUT/$(basename "$p")@$2"; done
  find "$1" -type f -name 'enclave*.exe' -print0 |
    while IFS= read -r -d '' p; do cp "$p" "$OUT/$(basename "$p")@$2"; done
}
for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  a="$DIST/enclave-$V-$t.tar.gz"
  [ -f "$a" ] || continue
  mkdir "$tmp/$t" && tar -xzf "$a" -C "$tmp/$t" && programs "$tmp/$t" "$t"
done
for t in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
  a="$DIST/enclave-$V-$t.zip"
  [ -f "$a" ] || continue
  mkdir "$tmp/$t" && unzip -q "$a" -d "$tmp/$t" && programs "$tmp/$t" "$t"
done
a="$DIST/Enclave-$V-macos.app.zip"
if [ -f "$a" ]; then
  mkdir "$tmp/mac" && unzip -q "$a" -d "$tmp/mac"
  programs "$(find "$tmp/mac" -type d -path '*Enclave.app/Contents/MacOS' | head -n 1)" universal2-apple-darwin
fi
ls "$OUT"
