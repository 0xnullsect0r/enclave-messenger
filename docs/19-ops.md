# Releases, Supply Chain, Crash Reports, Versioning

Status: Draft (M0) · Normative

Source: PLAN.md §17, §18 (license, export, regulation), §22, RT-13, RT-14. Crates: `enclave-update`, `enclave-crash`, `xtask`.

## 1. Releases and updates (RT-13)

### 1.1 Signing

- **TUF's roles** (root, targets, snapshot, timestamp) and checks, in Enclave's encoding with Enclave's signatures (`enclave-update`, ADR 0005; `tough` has no post-quantum keys).
- Every release target is co-signed by **2 of 3 maintainers**, each signature being **SLH-DSA-SHAKE-256s + composite**:
  - SLH-DSA with ctx `enclave/v1/update/release` over `role ‖ body` of the targets document;
  - composite Ed448 + ML-DSA-87 with the same context (the foundation's server-list key has the same two halves).
  - A maintainer signature is valid only if both halves verify.
- Maintainer keys live on offline HSMs held by 3 maintainers in 2 jurisdictions.

### 1.2 Transparency

- Release hashes are logged in **Sigsum** with witnesses (the same witness operators as KT where possible).
- Clients verify a Sigsum inclusion proof (with witness cosignatures) before installing an update, on every platform where Enclave controls installation.

### 1.3 Update fetch

- Update manifests are fetched **through the mixnet**, so they cannot be targeted by IP.
- "Verify this build" (compare the running binary's hash with the reproducible-build log) is available everywhere except iOS.

**As implemented** (R2):

- **Publishing.** The release workflow writes the release's targets unsigned (`enclave-targets.unsigned`: every release file, and each desktop program as `program@triple`, from `ci/release/update-targets.sh`; the `.deb` keeps programs unstripped so they are the same bytes). Two maintainers sign it offline (`enclave-admin release sign`) and attach `enclave-targets.bin`. `update-channel.yml` then submits every file to Sigsum once (`sigsum-submit`, proofs kept with the release), signs a snapshot and a 7-day timestamp with the online key, packs `enclave-update.bin` (`enclave-admin release bundle`), checks it as a client would (`release verify --bundle`), and attaches it; it runs again every Monday to renew the timestamp. Until the maintainers' ceremony made the root and the Sigsum policy (`packaging/update/root.bin`, `packaging/update/sigsum-policy`; External Gate G2) it says so and stops.
- **Relaying.** Each operator's front fetches `releases/latest/download/enclave-update.bin` every 6 hours (`front.update_url`; HTTPS, redirects only to HTTPS, 4 MiB at most) into the `updates` volume, keeping it only if it reads as a bundle and isn't older than the one held (`enclave_front::updates`). The server relays it as `DirKind::Update` (12) (`server.update_bundle`, re-read when it changes). Everything in it is signed; a server can only hold it back, which the timestamp's expiry shows.
- **Checking.** The app is built with the root (`ENCLAVE_UPDATE_ROOT`, or `packaging/update/root.bin`). Once a day the vault fetches the bundle from the home server over the mixnet and checks it (`Client::check_updates`: new roots one version at a time, TUF's chain, 2 of 3 maintainers, no rollback), keeping the newest root, the versions seen and the bundle in the profile. A newer release shows "Enclave X is available"; Settings → About has "Check for updates". Test `updates_come_from_the_home_server_and_a_minimum_stops_sending`.
- **Updating.** Where Enclave installs itself (the Windows `.msi`, the macOS `.dmg`, an AppImage), "Update" downloads the release file over HTTPS, checks its length, both hashes and its Sigsum proof against the bundle (`Client::check`), and only then installs: `msiexec /i … /passive`, or the `.dmg`'s app replacing the running bundle, or the AppImage replaced in place, and the new copy starts (`enclave_app::updater`). Packages managed by something else (`.deb`, `.rpm`, Flatpak, the AUR, the app stores) say to update them there.
- **Verify this build** (desktop): the window hashes its programs where they run and the vault checks each against the newest release's targets and its Sigsum proof, and says which matched or which didn't. Android and iOS builds are verified by their stores' signatures and, for F-Droid, its reproducible build.

### 1.4 Channels

| Platform | Channels |
|---|---|
| Android | Play, F-Droid (reproducible), direct APK |
| iOS | App Store |
| macOS | Notarized DMG plus updater |
| Windows | Signed MSIX plus updater |
| Linux | Flathub, Nix, .deb and .rpm |

### 1.5 Update verification algorithm (`enclave-update`)

```
VerifyUpdate(target):
    TUF-verify metadata chain (root → timestamp → snapshot → targets), rejecting rollback and freeze
    require ≥ 2 valid maintainer co-signatures (both halves) on targets, from distinct maintainers
    require a Sigsum inclusion proof for H(target) with ≥ 2 witness cosignatures
    require H(downloaded file) == target hash
    install only if all hold; otherwise keep the current version and log the failure
```

**As implemented** (`enclave-update`, R2): `Client::new` takes the root built into the app and the versions last seen; `update_root` moves one root version at a time; `refresh(timestamp, snapshot, targets, now)` checks the chain in TUF's order and returns the release; `check(release, name, file, proof)` checks the file's length and both hashes and its Sigsum proof (`sigsum::Proof`, sigsum-go's proof format version 2). Tests: `rt13_update_rejected_without_2_of_3`, `rt13_update_rejected_without_sigsum_inclusion`, rollback, freeze and mismatch, root rotation, and agreement with sigsum-go's proofs (`tests/sigsum`).

### 1.6 The release workflow (as implemented, R1)

`.github/workflows/release.yml` runs on a `v*` tag (a tag with a pre-release part, `v1.2.3-rc.1`, makes a pre-release) and, as a dry run that signs, pushes and publishes nothing, from CI whenever packaging changes (job `release-dry-run`) or by hand.

- **Version.** `cargo xtask version TAG` checks the tag names the workspace version and the AppStream metadata's newest release; a release candidate may name the next version's `X.Y.Z`.
- **Programs.** `cargo xtask dist --target T` builds what a desktop install ships (the window, vault, netd, mediad, tord, nymd from `nym/`, and lyrebird from its pinned Go source) with remapped paths and `SOURCE_DATE_EPOCH`, and packs `enclave-V-T.tar.gz` (`.zip` on Windows) with `LICENSE` and `THIRD-PARTY-NOTICES.txt`. Linux builds run in AlmaLinux 9 (glibc 2.34, so one build runs on every current distribution); Windows links the C runtime in (`+crt-static`); macOS builds both architectures and joins them (`universal2`), for macOS 12 and later.
- **Linux.** `.deb` (cargo-deb) and `.rpm` (cargo-generate-rpm) install the programs in `/usr/lib/enclave-messenger` with `enclave` on the PATH, the desktop entry, AppStream metadata and icons, and depend on the libraries the window loads at run time as well as those it links; an AppImage (cargo-packager); a Flatpak on the Freedesktop 25.08 runtime (`packaging/flatpak`); `enclave-messenger` and `enclave-messenger-bin` on the AUR (`packaging/aur`, pushed with stable releases only). Package name: `enclave` is taken in Debian and Arch.
- **macOS.** `cargo xtask bundle-macos` makes `Enclave.app` (`packaging/macos/Info.plist`), signs each program inside out with the hardened runtime and its entitlements, then the bundle, makes the `.dmg`, notarizes it with an App Store Connect API key and staples the ticket (environment `release-apple`; a dry run signs ad hoc).
- **Windows.** `cargo xtask packager --formats wix,nsis` (cargo-packager): a per-machine `.msi` (fixed upgrade code derived from the app id) and a per-user `-setup.exe`, whose Start menu shortcuts carry the app id toasts are sent under. `enclave.exe` carries the icon and version information (`crates/enclave-app/build.rs`). They are unsigned until a certificate exists; the repository variable `ENCLAVE_WIN_SIGN_CMD` (a command with `%1`) signs every program and installer. An MSIX package (`cargo xtask msix`: the programs, the package manifest with the app id, full trust, and its logos rendered from the icon; the SDK's `makeappx`) is made too; unsigned, its publisher carries the OID that lets `Add-AppxPackage -AllowUnsigned` install it, and with a certificate `ENCLAVE_MSIX_PUBLISHER` names its subject and the same command signs it. The install test installs, starts and removes the `.msi`, the setup `.exe` and the `.msix`; the updater replaces an MSIX install with the release's `.msix`.
- **Services.** `enclave-server`, `enclave-nym` and `enclave-updater` images for amd64 and arm64, pushed by digest, joined under the version tag and `latest` (stable releases), signed with cosign (keyless) and given build provenance; the compose stack published as `oci://ghcr.io/0xnullsect0r/enclave-stack:V` and, with the operator guide, as `enclave-operator-kit.tar.gz` (a fixed name, so `releases/latest/download/` finds it). Stacks follow `latest` by default: the stack's `updater` service (`ops/updater/update.sh`) checks each image's signature against the release workflow's identity, pulls the digest it verified, retags it and recreates what changed, then replaces itself through a helper container; `ENCLAVE_VERSION` pins a release and `ENCLAVE_AUTO_UPDATE=0` turns it off. The README carries the compose file (`ci/readme-compose.sh` keeps it current, checked in CI).
- **Records.** CycloneDX SBOMs for every shipped package; `SHA256SUMS` and `SHA3-512SUMS` (`cargo xtask checksums`) with Sigstore bundles; build provenance for every file; `ci/release/manifest.sh` lists every file a release must have, and the release isn't published unless all are there (completion gate D8).
- **Checks before publishing.** An independent rebuild of the Linux tarball must match it byte for byte (a stable release fails otherwise); install tests put the `.deb` on Ubuntu 22.04 and 24.04 and Debian 12, the `.rpm` on Fedora 42 and Rocky 9, the `-bin` PKGBUILD on Arch, and run the AppImage, each starting the app headless until its vault shows its first state (`enclave --smoke-exit`) and uninstalling (`ci/release/install-linux.sh`); the `.msi` and the setup `.exe` are installed silently, started and uninstalled on Windows (`ci/release/install-windows.ps1`); the Flatpak is installed and run; the macOS bundle's signature (and, on a release, Gatekeeper's verdict and the stapled ticket) are checked.

## 2. Supply chain (RT-14)

- `cargo vet` (importing the Mozilla and Google audit sets), `cargo deny` (licenses, advisories, bans, and an allowlist of crates that build C or C++), and `cargo audit` run in CI.
- Pinned lockfile and vendored sources.
- A `build.rs` and proc-macro allowlist; any new build script needs review.
- Hermetic Nix builds with **two independent rebuilders**; release hashes must match across both. **As implemented:** `flake.nix` / `nix/default.nix` build the desktop programs (with nymd and lyrebird), the server image's programs and the Nym ingress from the repository alone: nixpkgs 26.05 pinned by its release tarball's NAR hash (no flake inputs), every crate from `Cargo.lock` vendored by Nix, lyrebird's source and Go modules pinned by hash, build paths remapped as the release remaps them. The nightly workflow builds each output on two runner images and requires identical NAR hashes (`repro-nix`). Rebuilders run by other people on their own machines are the independent half (External Gate G16).
- SLSA v1 provenance for every release artifact.
- **CI hygiene:** third-party actions pinned by commit SHA, least-privilege tokens, no secrets in pull-request jobs.
- `cargo deny` enforces GPLv3-compatible licenses: MIT, Apache-2.0, BSD, ISC, MPL-2.0, and OFL (fonts). **AGPL and GPL-only crates are blocked from iOS builds.**
- `#![forbid(unsafe_code)]` in every crate except `enclave-platform`, `enclave-sandbox`, and `enclave-nse`.
- `cargo vet` must cover 100% of crypto and parser crates (`20-assurance.md`).

## 3. Crash reports without telemetry

- A panic hook and `minidumper` write a **scrubbed local report**: stack only, no heap. Secret types cannot be formatted into it (they implement neither `Debug` nor `Display`).
- The user can view the report and choose to send it through Enclave to "Enclave Support" (end-to-end encrypted, as a normal message) or export it as a file.
- Nothing is sent automatically. There are no analytics.

**As implemented** (`crates/enclave-crash`, `enclave_platform::fatal`): the app and the vault write reports into the profile's `crashes` folder (at most 10 kept). A report is text, not a minidump: the version, the process, the system, the kind (panic, or the native signal or Windows exception), the source file and line, a scrubbed message and the names of the functions on the stack. No memory is read or copied, not even the stack's, which is stricter than "stack only" and is why `minidumper` isn't used. The message is scrubbed on top of secret types having no `Debug` or `Display`: quoted text, anything in brackets, paths, numbers over three digits and any word with digits or longer than 24 characters become "…" (tests `messages_are_scrubbed`, `a_panic_leaves_a_scrubbed_report`, `a_native_crash_leaves_a_report`). Native crashes are caught with a handler armed at start that only writes prepared bytes (`open`, `write`, `close`) and re-raises the signal. On the next start the app shows "Enclave closed unexpectedly"; the person can read each report, save it as a file, delete it, or send it to Enclave Support as a message request (end-to-end encrypted like any other) when the build names Support's username (`ENCLAVE_SUPPORT`, set once the foundation publishes it, G5). The helpers (netd, mediad, tord, nymd) are confined with nowhere to write; their crashes show as a helper the vault replaces (15-client §1).

## 4. Versioning

- Suite and protocol IDs are carried in units and manifests. Capability sets (protocol min/max and feature bits) are signed in the manifest.
- Old peers are refused only for security-critical changes, after a 90-day overlap.
- Critical fixes can force an upgrade: a signed "minimum version" in the TUF metadata makes older clients show "Update Enclave to keep sending messages." and stop sending (receiving continues for 30 days). **As implemented:** the targets' `minimum` (`enclave-admin release targets --minimum X.Y.Z`); below it, sending personal content and group posts fails with `CoreError::UpdateRequired` and the app shows the notice, and 30 days on the vault stops receiving too ("Update Enclave to keep receiving messages."); a check from a version at or above the minimum lifts both.
- **Database migrations** are versioned, take a snapshot first, and have tested upgrade paths from every released version.
- Retiring a crypto suite requires 12 months of dual support.

## 5. Legal and governance items owned by ops

| Item | Requirement | When |
|---|---|---|
| License | GPLv3 plus §7 additional permissions (app-store conveyance with source available; Slint Royalty-free 2.0 with AboutSlint attribution; platform SDKs) in `legal/ADDITIONAL-PERMISSIONS.md` | M0, before any outside PR |
| DCO | Contributions need a DCO sign-off with an explicit grant of the §7 permissions | M0 |
| Export control | EAR §742.15(b) notification at the first public source release; App Store export answers and the France declaration with counsel | First public release; M11 |
| EU CRA | Vulnerability handling: 24 h early warning, 72 h notification, 14-day final report; the foundation acts as open-source steward | From M0 |
| Security policy | `SECURITY.md` with 90-day disclosure; bug bounty from M10 | M0, M10 |
| Client-side scanning, key escrow | Never shipped; withdraw from a store rather than comply | Always |
| Transparency | Annual report; no warrant canary | Yearly |

## Open questions

1. **Resolved:** neither. A maintainer signature is an SLH-DSA signature plus a composite Ed448 + ML-DSA-87 signature under `enclave/v1/update/release`, and the composite carries the context in its message representative, so both halves are bound to it (ADR 0005; `label-registry.md` Open question 1).
2. **Resolved:** the 30-day grace stays, as this spec's addition to PLAN.md. Below the signed minimum, sending stops at once (`CoreError::UpdateRequired`), and receiving stops 30 days later (`RECEIVE_GRACE` in `client/updates.rs`), so someone who can't update at once still gets messages and the notice while they do. Test `updates_come_from_the_home_server_and_a_minimum_stops_sending`.
