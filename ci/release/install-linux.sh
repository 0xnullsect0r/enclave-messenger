#!/usr/bin/env bash
# Install a release's Linux package in a fresh container, start the app
# headless until its vault shows its first state, and uninstall
# (release.yml `install-linux`, docs/completion-plan.md D1/R1 checks).
#
#   ci/release/install-linux.sh deb|rpm|pkgbuild|appimage VERSION DIST
set -euo pipefail
KIND=$1 V=$2 DIST=$(cd "$3" && pwd)
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
P=${V/-/\~}
# What the window loads at run time, for the AppImage (the packages
# declare them).
DEB_GUI=(libxkbcommon0 libxkbcommon-x11-0 libwayland-client0 libwayland-egl1 libegl1 libgl1 libx11-6 libx11-xcb1 libxcursor1 libxi6 libxrandr2 libfontconfig1)

gone() { # PATH: uninstalling removed it
  if test -e "$1"; then
    echo "::error::$1 is still there after uninstalling"
    exit 1
  fi
}

smoke() { # COMMAND...
  "$@" --version | grep "^enclave "
  local home
  home=$(mktemp -d)
  Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
  local x=$!
  # The software renderer: no GPU in a container.
  if ! HOME=$home DISPLAY=:99 SLINT_BACKEND=winit-software timeout 120 "$@" --smoke-exit; then
    kill "$x" || true
    echo "::error::the app didn't start"
    exit 1
  fi
  kill "$x" || true
  # It made its profile where the system keeps app data.
  test -d "$home/.local/share/enclave" || find "$home" -maxdepth 4 -type d | grep -qi enclave
}

case "$KIND" in
  deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends xvfb ca-certificates
    apt-get install -y "$DIST/enclave-messenger_${P}_amd64.deb"
    smoke enclave
    test -x /usr/lib/enclave-messenger/lyrebird
    test -f /usr/share/applications/com.aricummings.Enclave.desktop
    apt-get remove -y enclave-messenger
    gone /usr/lib/enclave-messenger/enclave
    ;;
  rpm)
    dnf -y install xorg-x11-server-Xvfb
    dnf -y install "$DIST/enclave-messenger-$P-1.x86_64.rpm"
    smoke enclave
    test -x /usr/lib/enclave-messenger/lyrebird
    dnf -y remove enclave-messenger
    gone /usr/lib/enclave-messenger/enclave
    ;;
  pkgbuild)
    # The -bin package, from this release's tarball instead of the download.
    pacman -Syu --noconfirm --needed xorg-server-xvfb
    useradd -m builder
    work=/home/builder/pkg
    mkdir -p "$work"
    cp "$ROOT/packaging/aur/enclave-messenger-bin/PKGBUILD" "$work/"
    tarball=enclave-$V-x86_64-unknown-linux-gnu.tar.gz
    cp "$DIST/$tarball" "$work/"
    sed -i -e "s/^pkgver=.*/pkgver=${V//-/_}/" \
      -e "s|^source_x86_64=.*|source_x86_64=(\"$tarball\")|" \
      -e "s|^sha256sums_x86_64=.*|sha256sums_x86_64=('$(sha256sum "$DIST/$tarball" | cut -d' ' -f1)')|" "$work/PKGBUILD"
    chown -R builder "$work"
    # shellcheck disable=SC1091
    mapfile -t deps < <(cd "$work" && bash -c 'source PKGBUILD; printf "%s\n" "${depends[@]}"')
    pacman -S --noconfirm --needed "${deps[@]}"
    su builder -c "cd $work && makepkg --noconfirm && makepkg --printsrcinfo > .SRCINFO"
    pacman -U --noconfirm "$work"/enclave-messenger-bin-*.pkg.tar.*
    smoke enclave
    pacman -R --noconfirm enclave-messenger-bin
    gone /usr/lib/enclave-messenger/enclave
    ;;
  appimage)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends xvfb ca-certificates "${DEB_GUI[@]}"
    app="$DIST/Enclave-$V-x86_64.AppImage"
    chmod +x "$app"
    export APPIMAGE_EXTRACT_AND_RUN=1
    smoke "$app"
    ;;
  *)
    echo "usage: install-linux.sh deb|rpm|pkgbuild|appimage VERSION DIST" >&2
    exit 2
    ;;
esac
echo "install-linux: $KIND ok"
