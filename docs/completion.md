# Completion tracker

Status: living document · checked by `cargo xtask done`

This is the 1.0 tracker for `completion-plan.md`. "Nothing left undone" is measured, not claimed: `cargo xtask done` counts every unfinished item the repository records about itself, and 1.0 ships only when the count is zero.

```
cargo xtask done --report    # list everything still open (exit 0)
cargo xtask done             # the gate: fails while anything is open
```

## What the gate counts

| Check | Counts | Closed when |
|---|---|---|
| D1 doc markers | "not implemented", "not done", "not built", "TODO", "TBD" in `docs/` (not `PLAN.md` or the plan files) | The feature is built and the text says "As implemented", or the marker names an External Gate below that is **prepared** |
| D2 reserved labels | Rows left in `label-registry.md` §3 | Every label is used by code (moved to §2) or retired with its replacement (§4) |
| D3 red-team tests | `rtNN_*` names in `redteam-matrix.md` with no test | A `fn rtNN_…` test exists and passes, or the name is a `cargo xtask shape` scenario, or a "Manual" row in `release-checklist.md` |
| D4 feature matrix | Rows of `16-features.md` §1 not "Done" | Status column says Done with a test, or the row is "Not planned" (payments, public group directory) |
| D5 open questions | Items under every `## Open questions` heading | The item is marked **Resolved** with the answer, or moved to an accepted ADR in `docs/rfcs/` |
| D6 platform constraints | Rows of `15b-platform-constraints.md` without a Handled status | Handled column says Done or N/A with the reason |
| D7 code markers | `TODO`, `FIXME`, `XXX`, `todo!`, `unimplemented!` in code and CI | Gone |

## Baseline

| Date | D1 | D2 | D3 | D4 | D5 | D6 | D7 | Total |
|---|---|---|---|---|---|---|---|---|
| 2026-10-01 (first run) | 90 | 89 | 73 | 51 | 92 | 54 | 1 | 450 |
| 2026-10-01 (registry reconciled) | 90 | 48 | 73 | 51 | 92 | 54 | 1 | 409 |

## Milestones

The milestones are the ones in `completion-plan.md`. Each closes the items that the gate lists in its area.

| Milestone | Area | Status |
|---|---|---|
| G0 | This tracker, `xtask done`, registry reconciled | Done |
| R0 | CI runs on every push, on Linux, macOS and Windows; actions pinned | Done (first fully green run: commit 6907c2d) |
| S1 | Server identity, keys, redb state (server, key transparency, relays), restart | Done |
| S2 | Federation: descriptors checked against KT, server list, Enclave TLS (OpenSSL 3.5 interop), witnesses, front with ACME, admin tools, server moves | Done |
| S3 | Image, compose stack, operator kit, 3-stack federation e2e in CI (images published to GHCR by R1) | Done (job `federation-e2e-tcp`) |
| S4 | Production compose reachable only through Nym | Done (development transports are cargo features off in every release build, checked in CI job `release-features` and the image build; the localnet e2e runs the production compose) |
| S5 | Server completeness: Unicode usernames, tombstones, absence proofs, replay cache, inbox and single-use proofs of work, clock warning, C2SP cosignatures, published split views, PostgreSQL, report tooling, 100k scale run | Done (verifiable On-the-record reports since P3) |
| N0–N4 | Full Nym integration, credentials, fallback, M4 gate report | Done (live-network numbers wait on G7 and G8; Snowflake and WebTunnel through lyrebird on desktop, R1; on Android and iOS with A1 and I1) |
| P1–P7 | Protocol completion | Done (P1 done: weekly inbox addresses, daily read credentials, address-bound tokens, session hints, adaptive request effort, polling rules. P2 done: self-copy always written, own-device sync, watermark after every device, PQ carrier rotation, inactive-device removal, new-device notice, groups on every device, history when both devices confirm; history over the LAN goes with D1. P3 done: Protobuf content with limits, continuation units up to 64 KiB, gap notices, "delivered late", held units, the v1 control set, On the record for 1:1 chats and groups (signed messages, admin updates and poll tallies, authenticated mode changes), verifiable reports. P4 done: blob uploads paid with Privacy Pass tokens (`BlobAlloc`), decoy and delayed fetches (RT-17), labelled chunk, group and rekey AD, the rekey unit's outer seal, group admins and hosting moves by admin vote; separate group read keys retired. P5 so far: recovery words in all ten BIP-39 lists, the spoken security code, key-derived contact art (RT-26), the https invite link, the link PSK, the 7-day braid for group-only peers, account records (manifest and attestations) in key transparency checked by contacts before they take a change, the recovering device's hold, its "stopped" notice and refusing to send while held, the "root lost, devices kept" migration, the notice for a group update whose migration never came, migrations in key transparency, social recovery's in-person release by scanning sealed codes, and taking a share back by changing the words, account deletion with every step and the other devices erasing themselves, the PIN for root actions, "Secure my account"; P5 done. P6 so far: notification key chains and 1,024-byte capsules for contacts and groups with the extension's key table, group-mailbox wakes, Poisson dummy wakes, re-sealing to the listed relay key, APNs (HTTP/2, ES256 provider token), FCM (HTTP v1, service-account OAuth) and UnifiedPush over TLS; the NSE and Android glue go with I1 and A1; P6 done. P7 so far: the device hedge secret kept in the keystore and refreshed, secret key bytes in locked memory, DIT around crypto on AArch64, no `Debug` on secret types; the recovery secret wrapped under a keystore secret and the PIN; the app lock, emergency PIN and panic wipe; the blinded search index, notes included; versioned store migrations with a snapshot first; profiles kept out of OS backups; backups with a header, notes and (by choice) files, kept on the home server and restored with the words alone, and "Check my backup"; P7 done. Screen security, keyboard flags, desktop notifications and platform keystores are D1/A1/I1 rows) |
| D1, R1 | Desktop shippable; release pipeline | Open. Done: the platform profile directory, the server picker (setting up, restoring, moving an account, voting a group onto another server), the demo as a feature release builds leave out, no console windows on Windows, the system's file dialogs, icons (`xtask icons`), About with the open-source notices (`xtask licenses`), the platform keystores (Keychain with a Secure Enclave wrap, DPAPI, Secret Service), screen-capture exclusion (and Linux's note), desktop notifications ("New message" unless previews are on), Touch ID and Windows Hello for the app lock, camera scanning of codes, the Seal animation with reduce motion and haptics. Also done: the allow-list seccomp profiles (vault, netd, media), Seatbelt profiles per helper on macOS with hardened-runtime entitlements, mediad in an AppContainer on Windows. History over the local network, window to window, with the server as fallback. D1 is done, except the macOS vault's Secure Enclave wrap in release builds: its Keychain group needs the vault moved into its own helper bundle with the Developer ID provisioning profile (`MACOS_PROVISIONING_PROFILE_BASE64`); until then it keeps its secret in the login Keychain. R1 so far: `cargo xtask dist`, `packager`, `bundle-macos`, `checksums`, `version`; the .deb, .rpm, AppImage, Flatpak, AUR PKGBUILDs, macOS bundle and Windows .msi and setup .exe; `release.yml` with images, the compose stack on GHCR, SBOMs, signatures, provenance, the independent rebuild and install tests; Snowflake and WebTunnel through lyrebird; the Flathub manifest. R1 is done when its dry run is green. |
| A1–A2, I1–I2 | Android and iOS | Done: one process with the helpers as threads (`nym/enclave-mobile`; Tor and the Nym client together on one SQLite), the Android app (NativeActivity with a small Java activity, `apps/android`, APKs per ABI and universal, app bundle) and the iOS app (`apps/ios/bundle.sh`, `.ipa`, TestFlight upload) built by the release workflow, with an emulator and a simulator start check; launcher and app icons from `xtask icons`; the Android Keystore (StrongBox where present) and the iOS Keychain with Secure Enclave keys; file pickers and saving (Storage Access Framework, UIDocumentPicker); camera scanning of codes (Camera2, AVFoundation); notifications; the clipboard (sensitive, local, cleared after 60 s); screen security (`FLAG_SECURE`; the iOS snapshot and capture blur); keyboards that don't learn (Android) and no third-party keyboards (iOS) (`enclave_platform::phone`); the vault outliving the window (one per process), the Background profile when not in front, Android's foreground service with "With the app closed" (stay connected, UnifiedPush AND_3, Google's push in the Play build), APNs device tokens and wakes on iOS and the notification service extension (`crates/enclave-nse`, `apps/ios/nse`; 10-push §7); Snowflake and WebTunnel on phones (lyrebird's clients as a library in the app's process, 09 §7). netd and mediad in processes of their own on Android (`:net`, and the `isolatedProcess` `:media`; A2, 15-client §1.2). mediad as WebAssembly in an interpreter sandbox on iOS (`enclave-wasmbox`, I2, 15-client §1.3). A1, A2, I1 and I2 are done in code; installs on devices are External Gate G8 |
| C1–C5 | Calls | Done: Opus calls at a constant 32 kbit/s with echo cancellation, noise suppression and gain control, and in-band FEC that follows the loss each side reports (`opus-pure`; scored with PESQ under 0–10 % loss, nightly `call-quality`); AV1 video in three tiers; constant-size, constant-rate packets muted or not (RT-19); WireGuard links to relays of different operator families with PQ PSKs between relays, tickets paid with proofs of work (ADR 0007); the call UI, CallKit and ConnectionService; direct mode; group calls through an SFU relay with call links and a lobby, raised hands, reactions and screen share on desktop and phones; the Maximum-mode tunnel; voice notes recorded, played and saved as Ogg Opus; on-device transcription. Left: the 360p30 check on the reference phone (External Gate G8) |
| F1–F6, L1–L2 | Feature parity; accessibility; translations | Open |
| Q1–Q6, R2 | Assurance; update channel | Open |
| V1 | `cargo xtask done` passes; `v1.0.0` | Open |

## External gates

Work that code alone cannot finish. Each is made ready so that it needs one action from a person or organisation. A doc marker that names a gate in parentheses, for example "(G3)", stops counting once that gate's status here is **prepared**.

| Gate | Item | Prepared by us | Needs | Status |
|---|---|---|---|---|
| G1 | Two external audits (crypto and protocol; app and infrastructure) | Scope documents, threat model, frozen audit tag | Funding and two audit firms | open |
| G2 | Maintainer signing ceremony (2 of 3, two jurisdictions) | `enclave-admin release keygen/root/targets/sign/online/bundle/verify`, the root spec format, `update-channel.yml` (Sigsum submission, online signing, bundle), the release's unsigned targets; builds pick up `packaging/update/root.bin` | Three maintainers' keys and the signed root, a Sigsum submitter key and policy, the online key as a secret | prepared |
| G3 | App Store and TestFlight review; export compliance (EAR §742.15(b), France) | Pipeline upload, `ITSAppUsesNonExemptEncryption`, filing drafts | Submission; counsel | open |
| G4 | Google Play, F-Droid, Flathub listings | `.aab`, F-Droid metadata with reproducible recipe, Flathub manifest (`packaging/flatpak/flathub.sh`: the manifest and offline sources, built nightly from source without network) | Store accounts; F-Droid and Flathub review | open (Flathub part prepared; Play and F-Droid with A1) |
| G5 | Foundation, server-list key, operator program (≥5 operators, ≥3 jurisdictions, ≥5 witnesses) | Operator kit, compose stack, `enclave-admin server-list` | People and an offline key | open |
| G6 | APNs, FCM and Apple notification-filtering entitlement | Push relay support and secret wiring | Credentials; Apple's grant | prepared |
| G7 | Nym mainnet funding for credentials | Credential gate, cost model | Funded accounts | open |
| G8 | Reference devices for the network and call gates | Diagnostics screen, benchmark | Runs on the devices | open |
| G9 | WCAG audit and moderated usability sessions | Scripts and builds | Auditor and five participants | open |
| G10 | Human translations for 14 locales | Weblate project, message catalogs | Translators | open |
| G11 | OSS-Fuzz acceptance | Integration | OSS-Fuzz maintainers | open |
| G12 | FIPS 207 (HQC) final | Draft-based implementation behind a flag (`enclave_crypto::hqc`, feature `hqc`, suite 0x04, official KATs) | NIST | prepared |
| G13 | Post-quantum Sphinx in nym-sdk | Adapter behind a feature | Nym | open |
| G14 | Licence grant for equix/hashx (LGPL-3.0-only) | Not needed: the proof of work is Enclave's own Equihash⟨60,3⟩ over BLAKE2b (ADR 0004) | — | resolved |
| G15 | Human `cargo vet` audits of the crypto, randomness, TLS, parser and Tor crates | `supply-chain/` (imports from six organisations; every other crate exempted at its locked version; CI job `cargo-vet`), the list of crates to audit in `supply-chain/README.md` | Reviewers who read each crate and run `cargo vet certify` | prepared |
| G16 | Independent rebuilders (people outside the project rebuilding releases and publishing their hashes) | `nix build .#enclave` / `.#enclave-server` / `.#enclave-nym` from the repository alone, `cargo xtask repro`, CI comparing two builds (`repro-nix`) | Two or more volunteers or organisations running the rebuild for each release | prepared |

Signing credentials the release pipeline needs (Apple Developer account, Android keystore, AUR SSH key) are provided by the maintainers as CI secrets; a Windows code-signing certificate is not, so Windows installers ship unsigned until one is added (`ENCLAVE_WIN_SIGN_CMD`).
