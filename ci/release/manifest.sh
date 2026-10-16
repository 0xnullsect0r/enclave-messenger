#!/usr/bin/env bash
# Every file a release must have (release.yml `finalize`, completion gate
# D8), one name per line: ci/release/manifest.sh VERSION
set -euo pipefail
V=$1
# Debian and RPM order a pre-release before its release with `~`.
P=${V/-/\~}
for a in x86_64 aarch64; do
  deb=$([ "$a" = x86_64 ] && echo amd64 || echo arm64)
  cat <<LIST
enclave-$V-$a-unknown-linux-gnu.tar.gz
enclave-messenger_${P}_$deb.deb
enclave-messenger-$P-1.$a.rpm
Enclave-$V-$a.AppImage
Enclave-$V-$a.flatpak
enclave-$V-$a-pc-windows-msvc.zip
Enclave-$V-$a.msi
Enclave-$V-$a.msix
Enclave-$V-$a-setup.exe
LIST
done
cat <<LIST
enclave-$V-universal2-apple-darwin.tar.gz
Enclave-$V-android.apk
Enclave-$V-android-arm64-v8a.apk
Enclave-$V-android-x86_64.apk
Enclave-$V.aab
Enclave-$V-ios.ipa
Enclave-$V-macos.dmg
Enclave-$V-macos.app.zip
enclave-operator-kit.tar.gz
enclave-$V-sbom.tar.gz
LIST
