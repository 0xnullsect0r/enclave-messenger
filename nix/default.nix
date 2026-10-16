# Enclave built with Nix (docs/19-ops.md §2: hermetic builds that
# independent rebuilders can repeat byte for byte).
#
#   nix build .#enclave         the desktop programs (as a release ships them)
#   nix build .#enclave-server  the server image's programs
#   nix build .#enclave-nym     the stack's Nym ingress
#
# nixpkgs is pinned by its release tarball and NAR hash, so evaluation is
# pure without flake inputs; Cargo.lock pins every crate (vendored by
# Nix), lyrebird's source and Go modules are pinned by hash. CI
# (`repro-nix`) builds each output on two machines and compares them.
{
  system ? builtins.currentSystem,
  pkgs ? import (builtins.fetchTarball {
    url = "https://releases.nixos.org/nixos/26.05/nixos-26.05.11829.a033e66ab94a/nixexprs.tar.xz";
    sha256 = "sha256-MdqpFMXQX2Vz1KgQ516wgEo4eiFzm3rEMyE3Qh4wyLA=";
  }) { inherit system; config = { }; overlays = [ ]; },
}:
let
  inherit (pkgs) lib;
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;

  # The repository without build output, editor files or CI state.
  src = lib.cleanSourceWith {
    name = "enclave-source";
    src = ../.;
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      !(builtins.elem base [ "target" ".git" "result" ".direnv" ])
      && !(lib.hasSuffix ".swp" base);
  };

  # Cargo's crates for one workspace, vendored by Nix from its lock file.
  vendor = lockFile: pkgs.rustPlatform.importCargoLock { inherit lockFile; };

  # cargo build --release --locked --offline in `dir` of the source, with
  # the paths that would end up in the programs remapped as the release
  # builds remap them.
  cargoBuild =
    {
      pname,
      dir ? ".",
      lockFile,
      args,
      programs,
      extraInstall ? "",
      nativeBuildInputs ? [ ],
    }:
    pkgs.stdenv.mkDerivation {
      inherit pname version src;
      nativeBuildInputs = [
        pkgs.cargo
        pkgs.rustc
        pkgs.pkg-config
        pkgs.perl
      ] ++ nativeBuildInputs;
      cargoVendor = vendor lockFile;
      dontConfigure = true;
      dontStrip = true;
      CARGO_INCREMENTAL = "0";
      CARGO_TERM_COLOR = "never";
      # Calls: cpal links ALSA (found by pkg-config).
      PKG_CONFIG_PATH = lib.makeSearchPath "lib/pkgconfig" [ pkgs.alsa-lib.dev ];
      buildPhase = ''
        runHook preBuild
        export CARGO_HOME=$TMPDIR/cargo
        mkdir -p $CARGO_HOME
        cat > $CARGO_HOME/config.toml <<CONFIG
        [source.crates-io]
        replace-with = "vendored"
        [source.vendored]
        directory = "$cargoVendor"
        CONFIG
        export RUSTFLAGS="--remap-path-prefix=$cargoVendor=/cargo --remap-path-prefix=$PWD=/src"
        cd ${dir}
        cargo build --release --locked --offline ${lib.concatStringsSep " " args}
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p $out/bin
        for p in ${lib.concatStringsSep " " programs}; do
          install -m755 target/release/$p $out/bin/
        done
        ${extraInstall}
        runHook postInstall
      '';
    };

  lyrebird = pkgs.buildGoModule {
    pname = "lyrebird";
    version = "0.9.0";
    src = pkgs.fetchzip {
      url = "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/archive/89d54872b176f936232ff39f7a8189b77d83d65e/lyrebird-89d54872b176f936232ff39f7a8189b77d83d65e.tar.gz";
      hash = "sha256-6zxGK6ZbYBEtsmlpNvQ9TVpiPPYKYv2hAE8Sq6mc/GM=";
    };
    vendorHash = "sha256-73ynRbmX3/Czv9juBbNA3/d0kPks222pfCnkVit8MpY=";
    subPackages = [ "cmd/lyrebird" ];
    env.CGO_ENABLED = "0";
    ldflags = [
      "-s"
      "-w"
      "-buildid="
      "-X main.lyrebirdVersion=0.9.0"
    ];
  };

  nymd = cargoBuild {
    pname = "enclave-nymd";
    dir = "nym";
    lockFile = ../nym/Cargo.lock;
    args = [ "-p enclave-nymd" ];
    programs = [ "enclave-nymd" ];
  };

  # What the window loads at run time (winit, its OpenGL and Wayland or
  # X11 back ends, fonts): on the library path, not linked.
  runtimeLibs = with pkgs; [
    libGL
    libxkbcommon
    wayland
    alsa-lib
    fontconfig
    freetype
    xorg.libX11
    xorg.libXcursor
    xorg.libXi
    xorg.libXrandr
    xorg.libxcb
  ];
in
rec {
  inherit lyrebird nymd;

  enclave = cargoBuild {
    pname = "enclave";
    lockFile = ../Cargo.lock;
    args = [
      "-p enclave-app"
      "-p enclave-vault"
      "-p enclave-netd"
      "-p enclave-mediad"
      "-p enclave-tord"
    ];
    programs = [
      "enclave"
      "enclave-vault"
      "enclave-netd"
      "enclave-mediad"
      "enclave-tord"
    ];
    nativeBuildInputs = [ pkgs.makeWrapper ];
    extraInstall = ''
      install -m755 ${nymd}/bin/enclave-nymd ${lyrebird}/bin/lyrebird $out/bin/
      # The programs start each other from their own folder; only the
      # window needs the libraries it loads.
      mkdir -p $out/libexec
      mv $out/bin/* $out/libexec/
      makeWrapper $out/libexec/enclave $out/bin/enclave \
        --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath runtimeLibs}
      install -Dm644 packaging/linux/com.aricummings.Enclave.desktop -t $out/share/applications
      install -Dm644 packaging/linux/com.aricummings.Enclave.metainfo.xml -t $out/share/metainfo
      install -Dm644 packaging/icons/enclave.svg $out/share/icons/hicolor/scalable/apps/com.aricummings.Enclave.svg
    '';
  };

  enclave-server = cargoBuild {
    pname = "enclave-server";
    lockFile = ../Cargo.lock;
    args = [
      "-p enclave-server"
      "-p enclave-witness"
      "-p enclave-front"
      "-p enclave-relay"
      "-p enclave-push-relay"
      "-p enclave-admin"
      "-p enclave-credgate"
      "-p enclave-tord"
      "--features enclave-tord/onion-service"
      "--bins"
    ];
    programs = [
      "enclave-server"
      "enclave-witness"
      "enclave-front"
      "enclave-relay"
      "enclave-push-relay"
      "enclave-admin"
      "enclave-credgate"
      "enclave-onion"
    ];
  };

  enclave-nym = cargoBuild {
    pname = "enclave-nym";
    dir = "nym";
    lockFile = ../nym/Cargo.lock;
    args = [ "-p enclave-ingress-bin" ];
    programs = [ "enclave-ingress" ];
  };

  default = enclave;
}
