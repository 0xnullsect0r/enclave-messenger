#!/usr/bin/env bash
# Update the AUR packages for a release (release.yml `aur`, in an Arch
# container): set pkgver and the -bin checksums from the release's
# SHA256SUMS, write .SRCINFO, and with `push` commit and push both to the
# AUR over SSH (AUR_SSH_PRIVATE_KEY, AUR_KNOWN_HOSTS).
#
#   ci/release/aur.sh VERSION DIST check|push
set -euo pipefail
V=$1 DIST=$(cd "$2" && pwd) MODE=$3
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
case "$V" in *-*) echo "aur: $V is a pre-release; the AUR gets stable releases only"; exit 0 ;; esac
sum() { awk -v f="$1" '$2 == f {print $1}' "$DIST/SHA256SUMS"; }
x86=$(sum "enclave-$V-x86_64-unknown-linux-gnu.tar.gz")
arm=$(sum "enclave-$V-aarch64-unknown-linux-gnu.tar.gz")
test -n "$x86" && test -n "$arm"

id builder >/dev/null 2>&1 || useradd -m builder
work=/home/builder/aur
rm -rf "$work" && mkdir -p "$work"
for pkg in enclave-messenger enclave-messenger-bin; do
  mkdir -p "$work/$pkg"
  sed -e "s/^pkgver=.*/pkgver=$V/" -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$x86')/" \
    -e "s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$arm')/" \
    "$ROOT/packaging/aur/$pkg/PKGBUILD" > "$work/$pkg/PKGBUILD"
done
chown -R builder "$work"
for pkg in enclave-messenger enclave-messenger-bin; do
  su builder -c "cd $work/$pkg && makepkg --printsrcinfo > .SRCINFO"
  cat "$work/$pkg/.SRCINFO"
done
[ "$MODE" = push ] || exit 0

pacman -Sy --noconfirm --needed openssh git
install -d -m700 -o builder /home/builder/.ssh
printf '%s\n' "$AUR_SSH_PRIVATE_KEY" > /home/builder/.ssh/aur
printf '%s\n' "$AUR_KNOWN_HOSTS" > /home/builder/.ssh/known_hosts
printf 'Host aur.archlinux.org\n  User aur\n  IdentityFile ~/.ssh/aur\n  IdentitiesOnly yes\n' > /home/builder/.ssh/config
chown -R builder /home/builder/.ssh && chmod 600 /home/builder/.ssh/*
for pkg in enclave-messenger enclave-messenger-bin; do
  su builder -c "set -e
    cd $work
    git clone -q ssh://aur@aur.archlinux.org/$pkg.git repo-$pkg
    cp $pkg/PKGBUILD $pkg/.SRCINFO repo-$pkg/
    cd repo-$pkg
    git config user.name 'Enclave release'
    git config user.email 'security@enclave.chat'
    git add PKGBUILD .SRCINFO
    git diff --cached --quiet || { git commit -q -m 'Update to $V'; git push -q origin HEAD:master; }"
  echo "aur: $pkg $V"
done
