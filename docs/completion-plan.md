# Enclave to 1.0: completion plan (federation, full Nym, every platform, release CI, and every open item)

> The original master plan lives in `docs/PLAN.md` and is unchanged. This file is the plan to **finish** it.

## Context

Enclave's protocol, client engine, desktop app and dev server work and are tested on Linux, but the product is far from shippable. Verified gaps:

**CI and releases**
- `.github/workflows/ci.yml` runs only on `main` and PRs, so it has **never run**.
- No platform packages exist, and there is no release workflow.

**Servers and federation**
- The server id is hard-coded to zeros (`crates/enclave-server/src/lib.rs:77`), and all server state is in memory.
- A client can reach only one server (`crates/enclave-vault/src/engine.rs:516-523`).
- There is no witness service, no descriptors and no server list.

**Nym and mobile**
- Nym is an empty stub (`crates/enclave-net/src/transport.rs:175`).
- There is no Android or iOS code, no `enclave-platform` crate, and no icons or packaging metadata.

**Inventory of unfinished work, compiled this session**
- 86 "not done / not implemented" markers across `docs/*.md`.
- 48 reserved labels with no code. A further 41 are already in code but still listed as reserved.
- 73 of the 75 red-team test names required by `docs/redteam-matrix.md` don't exist.
- No UI string is translatable (0 `@tr`).
- About 90 open questions across the docs.
- Calls have no media engine, UI, WireGuard, direct mode or SFU.
- Only 7 ProVerif models exist: no Tamarin, CryptoVerif or EasyCrypt.
- There is no `cargo vet`, no `xtask shape` and no ctgrind.

**The user's goal:** every item finished, with:
- one GHCR-hosted docker compose per federated operator;
- full Nym integration;
- a release pipeline producing `.apk`/`.aab`, `.ipa`, `.app`/`.dmg`, `.msi`/`.exe`, `.deb`, `.rpm`, `.flatpak` and `.AppImage`, and pushing to the AUR.

**User decisions**
- Signing: an Apple Developer account, an Android release keystore and an AUR SSH key will be provided. There is no Windows certificate, so Windows ships unsigned behind a signing hook.
- Slint on mobile.
- Servers are reached through Nym. TCP stays only as a feature-gated dev transport.
- One compose stack per operator, plus a 3-stack federation test in CI.

---

## Definition of Done (mechanical, enforced in CI)

"Nothing left undone" is made checkable. **`cargo xtask done`** (new, `xtask/src/done.rs`) runs in CI as job `done-gate`. It is **required to pass before the `v1.0.0` tag**, and release.yml refuses a non-pre-release tag if it fails.

| # | Check | Source of truth |
|---|---|---|
| D1 | No unfinished markers in `docs/**/*.md` | Regex: `not (yet )?(implemented\|done\|built)`, `Not done`, `Not built`, `(reserved, not implemented)`, `TODO`, `TBD`. Allowlist only: `docs/PLAN.md` (historical), the two "Not planned" rows (Payments, Public group directory), and items in the External Gates register (G-table below) whose status is "prepared". |
| D2 | `docs/label-registry.md` §3 "Reserved" table is **empty** | Each label is implemented (in code, so it moves to §2) or retired with its replacement (§4). `xtask labels` also checks that every §2 label is used in code. |
| D3 | All 75 `rtNN_*` tests exist and pass | Names are parsed from `docs/redteam-matrix.md`. Each is found as `fn rtNN_…` and is green in CI, or is a named step in `cargo xtask shape` or the release checklist for "Manual" rows. |
| D4 | Every `docs/16-features.md` row is "Done" with a test link | New `Status` and `Test` columns. |
| D5 | Every `## Open questions` item is closed | Each is answered in the doc, or recorded as an ADR in `docs/rfcs/` (with an "Accepted" decision). |
| D6 | Every `docs/15b-platform-constraints.md` PC row has status "Done" or "N/A (reason)" | New status column. |
| D7 | No `TODO\|FIXME\|XXX\|todo!\|unimplemented!` in `crates/`, `xtask/`, `.github/` | |
| D8 | Every release artifact exists for the tag | `release.yml` `finalize` writes a manifest of expected files; the check compares it. |
| D9 | Every roadmap exit gate is green or an External Gate is "prepared" | `docs/roadmap.md` gets a gate table with links to the CI jobs and reports. |

**G0 (first work item): reconcile.** Go through every marker in the inventory and either fix the stale doc (for example `03-identity.md:413` says group invite links are not done, but they are built per `07-groups.md` §9) or turn it into a tracked item in this plan. Commit the inventory as `docs/completion.md`, with one row per item, its milestone and its status, generated and checked by `xtask done`.

---

## Decisions (one choice each)

### Servers and federation

| # | Decision |
|---|---|
| X1 | **Server id:** first 16 B of `SHAKE256("enclave/v1/net/server-id" ‖ identity composite pk)`. The identity is a persisted Ed448+ML-DSA-87 key, so ids are self-certifying. |
| X2 | **Persistence:** redb everywhere, using `InMemoryBackend` in tests and the simulator. Schema versioning lives in `src/migrate.rs`. |
| X3 | **Daily request keys** come from a forward-secure seed chain (`seed_{d+1}=KMAC(seed_d,"enclave/v1/server/request-chain")`). Keygen is deterministic, and only today's and tomorrow's seeds are stored. |
| X4 | **Key delivery:** request keys are delivered as an identity-signed `KeyCert` (current + next), fixing today's unauthenticated key fetch. |
| X5 | **Descriptor:** served at `https://<domain>/.well-known/enclave` (fetched only through Tor) and chunked over the mixnet (`DirKind::Descriptor=7`). Its hash is committed into KT every epoch. |
| X6 | **Foundation server list:** signed with SLH-DSA+Ed448 (ctx `enclave/v1/update/server-list`), embedded at build, and refreshed over the mixnet (`DirKind::ServerList=8`) with a monotonic sequence. It moves under TUF in R2. |
| X7 | **New crate `enclave-federation`:** `KeyCert`, `ServerDescriptor`, `WitnessDescriptor`, `RelayDescriptor`, `ServerList`. |
| X8 | **Nym runs in a sidecar, `enclave-ingress`** (separate crate, binary and image) that speaks the existing TCP framing to `enclave-server` on an internal network. The key-holding server never links nym-sdk. The same binary serves push relay ingress and push egress. |
| X9/X10 | **nym-sdk isolation:** only `enclave-nym` depends on `nym-sdk`, pinned `=1.21.5` (the spike found 1.21.6 unresolvable); every `nym-*` crate is pinned in the lock. Upstream fixes are applied as `third_party/` path patches. |
| X11 | **New crate `enclave-tls`:** a rustls CryptoProvider with SecP384r1MLKEM1024 (0x11ED) and AES-256-GCM-SHA384 inbound only, plus a compat outbound profile used only by ACME. Interop tested against OpenSSL 3.5. |
| X12 | **New crate `enclave-front`** (axum + enclave-tls + instant-acme) serves `.well-known`, the witness API and the credgate. The key-holding process has no HTTP surface. |
| X13 | **New crate `enclave-witness`** (HTTPS cosign API, redb state). `enclave-kt` gains `trait WitnessClient` with `LocalWitness` and `HttpWitness`. |
| X14 | **KT on redb:** an akd `Database` implemented over redb, with persisted heads and cosignatures, epochs every 600 s and an hourly heartbeat. |
| X15 | **Images:** two, `ghcr.io/enclavechat/enclave-server` (all non-Nym binaries) and `ghcr.io/enclavechat/enclave-nym` (ingress). Both are multi-arch amd64/arm64, distroless nonroot, digest-pinned, reproducible, with SBOM, provenance and cosign. The compose file itself is published as an OCI artifact, so operators run `docker compose -f oci://ghcr.io/enclavechat/enclave-stack:<v> up -d`. |

### Nym, network and credentials

| # | Decision |
|---|---|
| X16 | **Nym tests in three tiers:** (1) `FakeMixnet` + `enclave-sim`, deterministic, on every PR; (2) a local `nym-node` mixnet in Docker (`ghcr.io/enclavechat/nym-localnet`), blocking on `main` and nightly; (3) the Nym sandbox nightly and a mainnet benchmark weekly, both non-blocking. |
| X17 | **Dev features:** `dev-transport` (TCP) and `dev-networks` (custom topology) are cargo features that are off in every release build. CI checks this with `strings`. |
| X18 | **New service `enclave-credgate`** (Equi-X + Privacy Pass RFC 9578 type 0x0001, VOPRF over P-384: RFC 0001, chosen over 0x0002 for the RSA timing advisory) in front of a pinned upstream `nym-credential-proxy`. Clients reach it over Tor. Ticketbooks are stored in the vault and imported into netd. Operator ingresses buy their own tickets from a mnemonic held as a Docker secret. |

### Clients, packaging and licensing

| # | Decision |
|---|---|
| X19 | **Mobile process model:** phase 1 is a single process. Phase 2 adds Android `isolatedProcess` decoders and an iOS WASM decoder sandbox; both are in this plan (milestone A2/I2), not deferred. |
| X20 | **Demo mode** becomes the `enclave-vault/demo` feature, so mobile and release clients don't link `enclave-server` or `enclave-sim`. |
| X21 | **IDs:** `io.github.EnclaveChat.Enclave` (Flatpak/AppStream), `io.github.enclavechat.enclave` (+`.nse`) for Android and iOS, and Linux package name `enclave-messenger` (AUR `enclave-messenger` and `-bin`, `conflicts=('enclave-git')` because `enclave` is taken). **Store IDs are irreversible; confirm before the first upload.** |
| X22 | **Linux builds** run in a digest-pinned `almalinux:9` container (glibc 2.34 baseline). |
| X23 | **Packaging tools:** cargo-deb; cargo-generate-rpm; cargo-packager (WiX `.msi`, NSIS `.exe`, AppImage); `xtask bundle-macos` (codesign inside-out, notarytool, stapler, hdiutil); Gradle + cargo-ndk; xcodegen + xcodebuild; flatpak-builder + flatpak-cargo-generator; a plain `git push` from an `archlinux` container for the AUR. |
| X24 | **Release signing is not deferred:** TUF + 2-of-3 SLH-DSA+Ed448 + Sigsum + `enclave-update` are built in this plan (R2). The maintainer HSM ceremony is an External Gate. |
| X25 | **Equi-X licence (LGPL-3.0-only, a direct dependency of `enclave-tokens`):** ask the Tor Project for a §7-compatible grant. If there is none by I1, build a clean-room byte-compatible `enclave-equix` checked against upstream vectors. A `deny-ios.toml` job enforces the result. |
| X26 | **Translations:** Slint `@tr()` + gettext catalogs + Weblate. Machine translation is never shipped for security copy; locales without a human review stay as pseudo-locales and are hidden. |
| X27 | **Calls:** WireGuard via GotaTun (userspace) for client↔relay; upstream Rosenpass daemon (a declared C exception) for relay↔relay; ICE via webrtc-rs `rtc` for direct mode. The audio stack is `cpal` + opus-rs/opus-decoder + `sonora` echo cancellation (falling back to `webrtc-audio-processing` in the sandbox). Video is rav1e/rav1d plus platform capture shims. |

---

## Milestones and dependencies

```
G0 ─ R0 ─┬─ S1 ─ S2 ─ S3 ────────────┬─ S4 ─ S5
         │  N0 ─ N1 ─ N2 ─ N3 ─ N4 ───┘
         ├─ P1 … P7 (protocol completion; parallel with S/N)
         ├─ D1 ─ R1 ─ A1 ─ A2 ; I1 ─ I2
         ├─ C1 ─ C2 ─ C3 ─ C4 ─ C5 (calls; C1 needs D1 platform shims)
         ├─ F1 … F6 (feature parity)
         ├─ L1 ─ L2 (accessibility, i18n)
         ├─ Q1 … Q6 (assurance)
         └─ R2 (TUF/Sigsum/update, MSIX, Nix) ─ V1 (1.0 done-gate)
```

Every milestone ends with: fmt, clippy `-D warnings`, the tests named below green in CI on Linux, macOS and Windows; docs updated, with "As implemented" sections replacing "not implemented"; the `completion.md` rows flipped; and a DCO-signed commit pushed to `claude/kind-goodall-44koll`. When a milestone stabilises, a PR is opened so CI runs and is reviewed.

---

### R0: Make CI real (first)

`.github/workflows/ci.yml`:
- Triggers: `push` on all branches, `pull_request` and `merge_group`, with `concurrency`.
- Every action pinned to a full SHA (removing the TODO at line 2); `.github/dependabot.yml` added; per-job `permissions`; `Swatinem/rust-cache`.

Jobs:
- `check`, `deny`, `deny-ios` (non-blocking until I1), `repro`, `proverif`;
- **new:** `build-macos` (macos-15), `build-windows` (windows-2025), `done-gate` (reporting only until V1).

`deny.toml`: an allowlist entry, with a reason, for every C-building crate (aws-lc-sys, ring, libsqlite3-sys, zstd-sys, skia-bindings, fontconfig-sys, the Rosenpass toolchain).

**Exit:** every job is green on the branch, and no action uses a tag ref.

---

### Track S: federated servers

#### S1: identity, config, persistence, restart

`crates/enclave-server`:
- `src/keys.rs`: `ServerKeys { identity, kt_head, kt_vrf, request_chain }`, stored as 0600 files written by `init`.
- `Config.id` is computed (X1).
- `src/db.rs`: redb tables for inboxes, envelopes, tokens, manifests, devices_seen, attestations, migrations, moved, bundles, vaults, blobs, push, usernames, names_by_root, reports and meta. Claims, KT replies, wakes and uploads stay in memory with expiry.
- `src/config.rs`: `server.toml` with env overrides `ENCLAVE_<SECTION>__<KEY>`.
- `src/main.rs`: clap subcommands `init|run|show-id|descriptor|backup|restore|healthcheck`, and SIGTERM drains, commits and exits.
- Daily backup snapshots.

Other crates:
- `enclave-rpc`: `ServerSecret::from_seed`.
- `enclave-kt`: `store_redb.rs` (akd `Database`), `KtService::open`, persisted heads and cosignatures.
- `enclave-relay` and `enclave-push-relay`: `--config`, persisted seeds. The push relay moves to port 7445 and its key rotates every 30 days with a 7-day overlap.

New labels: `server/request-chain`, `server/request-key`, `net/request-key-cert`.

**Exit:**
- `tests/restart.rs`: the server id and pins survive a kill; envelopes persist; the witness accepts the next head.
- `tests/request_chain.rs`: an old seed cannot be recovered from the database.
- akd's storage test suite passes on redb.

#### S2: descriptors, server list, TLS, front, witness, admin CLI, client address book

New crates:
- `enclave-federation` (X7).
- `enclave-tls` (X11), with the OpenSSL interop test.
- `enclave-front` (X12): `/.well-known/enclave`, `/witness/v1/*`, `/credgate/v1/*`, `/healthz`, with no IP logging.
- `enclave-witness` (X13).
- `enclave-admin`: `foundation-keygen`, `server-list build|sign|verify`, `descriptor fetch|verify`, `kt-pins`.

Server:
- A zero-length request returns `KeyCert(cur)‖KeyCert(next)`.
- `DirKind::Descriptor=7` and `ServerList=8`.
- Descriptor hash committed to KT.
- **Moved records** for server migration (label `proto/moved`; closes `12-servers.md` §4). KT tombstones (`proto/tombstone`) go with account deletion and operator tombstones (S5, P5).

Client:
- `enclave-core` gets a `servers` table, and `Transport::server_key` verifies the KeyCert.
- Contact card v3/v4 adds `server_domain` (`crates/enclave-core/src/card.rs`).
- Server resolution order: server list → card domain → `@name@domain` → Moved record.
- `enclave-ipc::net` gets `Configure`, `SetRoutes(Route::{Tcp[dev],Nym,Onion})` and `FetchDescriptor`; `enclave-netd` gets a runtime route map.
- `engine.rs`: remove the zero id; `Mode::Server{home, server_list}`; embedded list in `crates/enclave-vault/assets/server-list.bin`.

**Exit:**
- An `enclave-sim` 3-server test: users find each other by card and by `@name@domain`, and a server Moved record is followed.
- A wrong-identity KeyCert is rejected.
- 2 remote witnesses meet threshold 2.

#### S3: compose, images, 3-stack e2e (dev transport)

- Rewrite `ops/docker/Dockerfile`: pinned builder, `snapshot.debian.org` packages, `--frozen`, remapped paths and `SOURCE_DATE_EPOCH`, targets `server` and `nym`, distroless runtime.
- `ops/compose/`: `compose.yml`, `compose.dev.yml`, `compose.localnet.yml`, `.env.example`, `config/*.toml.example` and `secrets/README.md` (service table below).
- `ops/operator-kit/`: the eight `13-operators.md` §4 files, plus `deployment.md` (deploying, backup and restore, key rotation, verifying image signatures).
- New `crates/enclave-e2e`: headless clients with `--transport tcp|nym`, running 7 scenarios:
  - cross-server 1:1 messages;
  - a group;
  - blobs;
  - usernames with cross-stack witness cosigns;
  - push via a UnifiedPush test endpoint;
  - a restart of one stack;
  - no split-view alert.
- `ci/federation/gen.sh`: test foundation keys, inits 3 stacks, signs the test list, and sets each server's witnesses to the other two.
- CI job `federation-e2e-tcp`.

**Exit:** the e2e job is green in ≤20 min, and images have no shell and run as nonroot.

#### S4: production compose is Nym-only (after N1–N4)

- The `backend` network is `internal: true`; only `compose.dev.yml` maps 7443.
- Release binaries and images contain no dev symbols (a `strings` CI check).

**Exit:** production-profile federation e2e passes over the local mixnet.

#### S5: server completeness

- **Unicode usernames:** NFKC plus UTS #39 skeletons, operator and account tombstones (`12-servers.md` §3.5).
- **KT:** non-existence proofs, the device clock-skew warning from trusted time (RT-23), C2SP cosignature interop, gossip publication to the witnesses.
- **Request-key replay cache** (`net/replay-id`; `09-transport.md` §2, RT-24).
- **Inbox PoW on creation** (`09` §3).
- **Postgres backend** behind a `Store` trait (PLAN M11; `12` §6), selected in `server.toml`, with the same test suite run against both backends.
- **Report tooling:** the descriptor's report address, an operator `enclave-admin reports` reader, PoW raised per reported capability, and verifiable On-the-record reports (`13-operators.md` §2).
- **Scale test:** 100k simulated accounts; the `12` §7 estimates measured and the doc updated.

---

### Track N: full Nym integration

#### N0: spike gates (2 weeks, GitHub runners)

A go/no-go is recorded in `docs/spikes/m4-network.md` for each question:

| # | Question |
|---|---|
| a | Does the nym-sdk version set build on all 7 targets? |
| b | Can every request get a fresh `AnonymousSenderTag`? |
| c | Can the Poisson stream be disabled and loop cover set (confirm it is not debug-only, PC-61)? |
| d | Is there a custom gateway connector, so WSS can run over an arti `DataStream`? |
| e | Can the server refuse "more SURBs" round-trips? |
| f | Does a local `nym-node` mixnet (3 mix, 2 gateways, zk-nym off) run in Docker? |
| g | How many packets do a unit and a poll take? |
| h | Does in-memory storage work? |
| i | Does the sandbox credential proxy issue ticketbooks? |

Each "no" becomes an upstream PR plus a `third_party/` patch, or an RFC per the roadmap.

#### N1: transport end to end

New crate `enclave-nym`:
- Profile → DebugConfig: Poisson off, loop cover 10 s, default delays.
- `Network::{Mainnet,Sandbox,Local[dev-networks]}`.
- The mixframe codec: request `ver‖kind‖req_id(16)‖body` in fixed classes U=16,384 B and P=2,048 B; reply `ver‖status‖req_id‖16,384 B`.
- `trait MixnetDriver` with `NymDriver` and `FakeMixnet` (loss, delay and reorder injection).

Other crates:
- `enclave-net`: `NymTransport` (feature `nym`, replacing the stub at `transport.rs:175`) with a request-id map, per-request tags, timeouts, and a new seal on retry.
- `enclave-netd`: `Configure` selects Nym; the seccomp `Netd` profile is extended, with a strace allowlist test.
- New `crates/enclave-ingress`:
  - `serve` (persistent identity, fixed gateway, SURB policy);
  - `--oneway` (push relay);
  - `forward` (push egress, replacing the TCP `--push-relay`);
  - writes `public/ingress.addr` into the descriptor;
  - `onion` mode (fallback, see N4).

**Exit:**
- Scenarios 1–7 pass over the local mixnet.
- A pcap shows a constant packet count per tick, whether real or cover (`ci/federation/pcap-check`). Done: `gen.sh shape` in `federation-e2e-localnet` (`09` §6.7).
- A sandbox smoke run passes.

#### N2: client behaviour

- **Tor under Nym:** netd bootstraps arti and dials the gateway's WSS through it. Maximum refuses to run without Tor. Done for the first part (N2.4): arti runs in `enclave-tord` (loopback SOCKS5), nymd dials its gateway and nym-api through it (`09` §1). Maximum's refusal is done in N2.5 (`09` §6.6).
- **Loop cover:** every 10 s in Foreground and Maximum, every tick in Background. Done: set at runtime with each profile change (no rebuild needed; profiles still change only at transitions, RT-12), `09` §6.3.
- **Packet pacing:** a tick's Sphinx packets are spread evenly across the tick (`09` §6.3). Done: 16 packets per tick in 20 slots, one per 150 ms.
- **Self-loop probes** (`net/loop-probe`) and **RT-02 gateway switching:** loss >10% or latency >5× the median over 50 exchanges, at most one switch per 10 min. Done (`09` §6.3; tests `rt02_*`).
- **One-way writes:** writes and cover carry 0 SURBs, so a tick is 1 unit + 1 poll up and 1 unit down (`09` open question 5). Done: messages, self-copies, group posts, typing and unit cover go one way, with delivery receipts and re-sends (`09` §6.1). Every other unit goes one way as well: its answer is kept by the server under a status id and fetched by a poll-sized `Status` request (`08` §2.2, `09` §6.1), so no unit carries reply blocks.
- **Bulk cap:** 40 packets/s (`09` §6.4). Done.
- **Maximum privacy:** push off, fallback forbidden, waits for all 3 KEMs (`09` §6.6, `04` §8). Done (N2.5): also no TCP route and nothing without Tor (`Transport::require_private`), held user content with "Extra protection: finishing…" on contact info, and the saved mode shown after a restart.

**Exit:**
- Measured data per profile is within ±20% of `math/cover-traffic.md`. Foreground (and so Maximum) measured on the local mixnet and by the real client in CI: 16.2–16.6 packets a tick against 16.3, 73–76 MB/h at the WebSocket level, ≈80 MB/h with Tor, inside the band (`math/cover-traffic.md` §10). Background and live networks: `enclave-e2e bench` (N4).
- The gateway-switch tests pass (fake loss injection and killing a localnet gateway).
- The Tor path works against the sandbox.

#### N3: credentials

- New `crates/enclave-credgate` (Equi-X → Privacy Pass → ticketbook via `nym-credential-proxy`; quotas, no logs; issuer key rotated monthly, published in the server list). Done (`09` §7): `enclave-tokens::privpass`, `enclave-credgate`, the front's proxy, compose profile `foundation`, image binary, and the issuer keys in the server list (`CredGateEntry`, list format 2, `enclave-admin` `[[credgate]]`, `enclave-credgate show-key --epochs N`).
- Client: a sealed ticketbook wallet in the vault, auto-refill, `netd FetchCredential` over Tor, `ImportTickets`. Done (`09` §7): `enclave_core::TicketWallet` (sealed in the profile, never backed up; refill below 10 tickets from kept tokens or new Equi-X work; spending followed from nymd's counter), netd/nymd fetch, buy and connect (pipe frames 6–10, IPC tags 7–10), books bought while connected imported into the running client, the vault starting netd with `--await-tickets` and buying a new device's first book before it has a profile. Localnet CI buys the e2e's book through stack a's gate from `enclave-dev-proxy`. Spending against checking gateways runs in the sandbox nightly (N4, G7).
- Ingress: mnemonic-funded auto top-up with a low-balance alert.
- Compose: a `foundation` profile.
- **Privacy Pass is also used for blob quotas (`BLOB_ALLOC`) and relay tickets** (P4, C2).

**Exit:**
- On the sandbox, install → first message needs no manual step.
- A cost model is recorded, and ≤$1/user/month is checked. Recorded (`math/cover-traffic.md` §11): expiry, not traffic, decides, so a typical device buys 5 books a month and the target holds while a book costs the proxy ≤ $0.20; the nightly checks it at the day's price (G7).

#### N4: fallback, measurement, gate report

- **Fallback:** `enclave-ingress onion` (an arti onion service), with the descriptor's `onion` field filled and the consent sheet "Backup route: slower to hide who you talk to". It is never used in Maximum.
- **Censorship mode:** obfs4 through `ptrs` in-process. Snowflake and WebTunnel run as declared Go-subprocess exceptions (IPtProxy on iOS), only in censorship mode, with "Try a bridge?" detection (`09` §7).
- **Measurement:** `enclave-e2e bench` (RSS, cold connect, throughput, packets per class, bytes per hour, credential cost), plus a hidden **Network diagnostics** screen on mobile that exports JSON.
- Workflow `nym-live.yml`: the sandbox nightly and mainnet weekly.
- **Post-quantum Nym:** an adapter for Nym's PQ Sphinx (Outfox/Lewes) behind a feature, switched on when nym-sdk exposes it (External Gate G13).

**Exit:** `docs/spikes/m4-network.md` is rewritten as the M4 gate report, with device numbers for the §7 gate. A failure triggers an RFC.

Doc updates across the track:
- `09-transport.md` §1/§6/§7 as implemented;
- `01-threat-model.md` residuals (the ingress operator sees gateway timing; the fallback route);
- `10-push.md` (Nym ingress);
- `12-servers.md`;
- `PLAN.md` §12.1 (sidecar).

---

### Track P: protocol completion

All of these are cross-checked against the 86-marker inventory.

| ID | Work | Docs and labels it closes |
|---|---|---|
| P1 | **Inboxes and tokens:**<br>• weekly inbox address rotation from the inbox seed with overlap-week polling (`net/inbox-addr`, `inbox-read-key`);<br>• daily address-bound read credentials (`net/read-cred`);<br>• per-contact token key from the seed (`net/token-key`), token hashes bound to the address, weekly re-registration, burned token returned as a session hint, self tokens;<br>• `MORE`-steered polling, a per-group 60 s poll floor, decoy re-fetches;<br>• request inbox: invite-capability hashes (`net/cap-hash`), adaptive effort, text-only/no-auto-download client rules | `09` §3–§5, RT-01/25 |
| P2 | **Multi-device (D5):**<br>• the always-sent self-copy, even for single-device accounts (`06` §4);<br>• intra-account sync of sent messages, read state, contacts, groups, settings including conversation preferences, verification and fetch positions (`06` §5);<br>• the watermark advanced only after every device reports (`06` §6);<br>• `DeviceListChanged` (`06` §7);<br>• PQ-slot carrier policy (`06` §3);<br>• group messages from our own devices shown, and pins from other devices (`07` notes);<br>• new-device group membership, the 7-day "new device" banner, automatic removal of inactive devices, the "both devices confirm" shortcut, handover of contacts without a card (`03` §4.x);<br>• **device transfer** over LAN or bulk blobs (`03` §4.3) | `06` all, `03` §4, RT-09 |
| P3 | **Modes and control messages:**<br>• On-the-record 1:1 signatures (`ctx/signed-msg`) and groups (`proto/grp-signed-msg`, `grp-admin-sig`, `poll-tally`);<br>• authenticated `ModeChange`;<br>• the full v1 control set: `SessionSetup`, `TokenRefill`, `ForcePQStep`, `Reroot` (`proto/bond-reroot`, used when meeting again), `Receipt`, `KTGossip` in content, `Moved`, `Closed`;<br>• gap notices after 60 s (RT-24), "Delivered late", held units;<br>• the Protobuf (`prost`) content schema with depth and unknown-field limits;<br>• **continuation units** for content up to 64 KB (`08` §5.6) | `05` §9/§11, `08` §5, `07` §3, RT-07/24 |
| P4 | **Blobs and attachments:**<br>• client-side blob sealing with chunk keys and IDs from a blob secret (`wire/chunk-key`, `chunk-id`, `ad-chunk`);<br>• `BLOB_ALLOC` with Privacy Pass quotas;<br>• delayed fetches plus 1–3 decoy fetches (RT-17);<br>• the rekey unit format (`08` §8, `wire/ad-rekey*`, `grp-rekey-outer`);<br>• group header and body AD prefixes (`wire/ad-grp-*`);<br>• group read keys and credentials (`net/grp-read-*`);<br>• group mailbox hosting moves by admin vote (`07`) | `08` §8–§9, `07` §4–§5, RT-17 |
| P5 | **Identity and EQXDH:**<br>• "Extra protection: finishing…" state, the 7-day braid deadline, group-only peers' 2→3 KEM upgrade (`04` §8);<br>• root-hash, conv-id and msg-id derivations where the code uses ad-hoc ones (`proto/root-hash`, `conv-id`, `msg-id`), or those labels retired;<br>• link labels (`link-psk`, `link-cap`) reconciled against `client/link.rs` (implement or retire);<br>• invite labels (`invite-psk`, `invite-cap`) likewise;<br>• the `https://<invite-host>/` link wrapper (`03` §9.2);<br>• **all BIP-39 languages**;<br>• the **10-word spoken code** (`02b` §3);<br>• **key-derived contact art** (`proto/contact-art`, RT-26);<br>• pending-root and veto records posted to KT, the recovering device's "stopped" notice, and refusing to send while held (`03` §8.1);<br>• the "root lost, devices kept" migration, a notice for a held group root update, migrations published to KT (`03` §8.2);<br>• **social recovery in-person release** with scan and confirmation, and re-splitting when a holder is removed (`03` §8.3);<br>• **account deletion** with tombstones, inbox and blob deletion, a closed notice and shred (`03` §8.5);<br>• **"Secure my account"** with full rotation (RT-21), the PIN gate, and inbox and vault-key rotation on device removal (`03` §5) | `03`, `04`, `02b` |
| P6 | **Push complete:**<br>• notification key chain (`proto/notify-key`, `grp-notify`) and 1,024 B sealed capsules (`wire/ad-capsule`);<br>• push token sealing (`net/push-seal`, `push-transcript`, `wire/ad-push-token`);<br>• relay key rotation and signed key list, dummy wakes, group-mailbox wakes;<br>• APNs and FCM delivery (credentials are External Gate G6), TLS for UnifiedPush, the Android distributor glue, and the iOS NSE (I1) | `10`, `08` §5.4, RT-16/20 |
| P7 | **Storage and crypto hardening:**<br>• root wrap (hardware + Argon2id PIN; `store/root-wrap`, `ad-root`);<br>• persisted device hedge secret;<br>• **blinded search index** (`store/search-key`, `search-token`), with notes included in search;<br>• versioned DB migrations with a snapshot first;<br>• OS-backup exclusion;<br>• backup archive header, **server-stored backups** (`store/backup-blob-id`), media selection, the "Check my backup" restore test;<br>• app lock with timeout, **emergency PIN**, **panic wipe**, screen security on every OS, IME no-learning and clipboard auto-clear, lock-screen "New message" (`14` §5);<br>• AArch64 DIT bit, `mlock`, a test that secret types have no `Debug` (`02` §10) | `14`, `02`, RT-08/15 |

**Exit for each:** the named rtNN tests green, the labels moved from §3 to §2 of the registry, and the "As implemented" doc sections written.

---

### Track D/R/A/I: clients on every platform and releases

#### D1: desktop shippable

App:
- `windows_subsystem` on all four executables, with `CREATE_NO_WINDOW` for helpers.
- `directories` profile dirs.
- `rfd` file picker (portal backend on Linux).
- Window icon.
- **About screen** with `AboutSlint` (PC-80) and a licences view from `cargo xtask licenses` (cargo-about).
- **Onboarding server picker** from the server list, and **Settings → Move to another server** (`Client::move_home`, progress from `move_pending`).
- **Camera QR scanning on desktop** via `nokhwa` + `rqrr`, replacing the pasted codes (`03` §7).
- **Seal animation and haptics** (`17` §4).

Icons:
- New: `design/icon/enclave.svg` plus adaptive and monochrome variants.
- `cargo xtask icons` (resvg, ico, icns) produces every size; CI runs `--check`.

New crate `crates/enclave-platform` (`unsafe` allowed and declared):
- Keystores: Apple Keychain plus Secure Enclave wrap, Windows DPAPI (+TPM via NCrypt), Linux Secret Service with a passphrase fallback, Android Keystore (A1).
- Screen-capture exclusion: `WDA_EXCLUDEFROMCAPTURE`, `NSWindow.sharingType`.
- Platform audio: `cpal`.
- Camera capture: nokhwa on desktop, CameraX and AVFoundation in A1/I1.
- OS video decoders for the person's own files: AVFoundation, MediaCodec, Media Foundation, GStreamer on Linux. These complete **camera video** (`15` §5.3).
- Location: CoreLocation and FusedLocation, plus "open in maps" (`16` §3).

Sandboxing:
- macOS App Sandbox with per-binary entitlements.
- **Windows AppContainer for mediad** (PC-43).
- Linux: Landlock and seccomp are already done. An **allow-list seccomp** policy replaces the deny-list (`15` §1.1a).

**Exit:** on all three OSes the installed build has no console, uses the platform profile dir, stores its secret in the OS keystore, offers the server picker, and shows the About screen with the Slint attribution.

#### R1: desktop packaging plus release pipeline plus GHCR

- `packaging/linux/` (`.desktop` and AppStream metainfo with the screenshots).
- `[package.metadata.deb]` and `[package.metadata.generate-rpm]`, installing to `/usr/lib/enclave-messenger/` with a `/usr/bin/enclave` symlink.
- `packaging/flatpak/io.github.EnclaveChat.Enclave.yml` (Freedesktop 25.08, rust-stable extension, committed `cargo-sources.json`, Secret Service and portals).
- `packaging/aur/{enclave-messenger,enclave-messenger-bin}/PKGBUILD`.
- `packaging/macos/Info.plist`, entitlements.
- `packaging/windows/Packager.toml` (WiX per-machine `.msi`, NSIS per-user `-setup.exe`, fixed upgrade code, `ENCLAVE_WIN_SIGN_CMD` hook).
- xtask additions: `dist`, `bundle-macos`, `checksums` (SHA-256 + SHA3-512), `version`.
- `.github/workflows/release.yml` (table below); `ci.yml` gets `package-smoke` and `docker-build`.

**Exit:** a `workflow_dispatch` dry run on `v0.1.0-rc.1` produces every artifact; install tests pass; the AUR job pushes to a throwaway staging package.

#### A1: Android (Slint)

New crate `crates/enclave-mobile`:
- cdylib and staticlib.
- `android_main` → `slint::android::init`, using `backend-android-activity-06` + Skia.
- A process-global runtime so the Service keeps the vault alive.
- The single-process vault without `demo`.
- Skia prebuilts mirrored with SHA-256 checks; F-Droid builds Skia from source.

`apps/android/` (Gradle 8):
- minSdk 28, targetSdk 36, arm64-v8a and x86_64, 16 KB page alignment, pinned NDK r28.
- `cargo ndk` exec task.
- Flavors `fdroid` (UnifiedPush) and `play` (FCM).
- `allowBackup=false`, `specialUse` foreground service, `FLAG_SECURE`, `IME_FLAG_NO_PERSONALIZED_LEARNING`.

Kotlin shims, at most 300 lines in total: `EnclaveActivity`, `CoverService`, `KeystoreBridge` (StrongBox), `UnifiedPushReceiver`, `FcmService`, `BootReceiver`.

Outputs: signed `.apk` per ABI plus universal, `.aab`, and F-Droid metadata with a reproducible recipe. CI runs an emulator smoke test (API 34).

#### A2: Android isolatedProcess decoders

- An `isolatedProcess` service hosts mediad (Binder IPC via `ndk` + a small AIDL shim within the 300-line budget).
- This re-enables AV1 clip decoding on Android (PC-24).

#### I1: iOS (Slint)

- `apps/ios/project.yml` (xcodegen). The app target's executable is the Rust binary (winit + Skia).
- Target `EnclaveNSE`: `NotificationService.swift` (≤60 lines) calls new `crates/enclave-nse` (staticlib, `unsafe` declared). It decrypts capsules with symmetric crypto under 24 MB, sharing an app group and Keychain group.
- Single process. Apple keystore; APNs; app-switcher blur and hide-while-captured; "Block third-party keyboards" setting.
- `deny-ios` becomes required (X25 resolved).
- Signing: App Store Connect API cloud signing → `.ipa` → TestFlight upload. CI: a simulator build, install and launch job.

#### I2: iOS WASM decoder sandbox

- Image, audio and AV1 parsers compiled to wasm32 and run under `wasmi` (no JIT) inside the app (`15` §1.3).
- This re-enables clip playback on iOS.

#### R2: update channel and remaining distribution

- New `crates/enclave-update`: `tough` TUF, 2-of-3 SLH-DSA+Ed448 maintainer co-signatures (`update/release`), a Sigsum inclusion proof with ≥2 witnesses, manifests fetched over the mixnet, "Verify this build" everywhere except iOS. The server list moves under TUF.
- New `crates/enclave-crash`: `minidumper`, a scrubbed local report, user-initiated E2EE send to "Enclave Support".
- **MSIX** packaging with the signing hook.
- **Nix flake** with two independent rebuilders (CI `repro-nix`).
- Flatpak `flatpak-spawn --sandbox` for mediad (PC-47).
- `xtask repro` extended to every shipped binary.
- `cargo vet` with the Mozilla and Google imports, at 100% coverage of crypto and parser crates.
- A build.rs/proc-macro allowlist check (RT-14).
- SLSA v1 provenance (already from `attest-build-provenance`).

---

### Track C: calls (`11-calls.md`, all M8 items)

| ID | Work |
|---|---|
| C1 | **Media engines in mediad:**<br>• Opus CBR 32 kbps, 20 ms frames, DTX off, FEC on;<br>• echo cancellation: `sonora`, or `webrtc-audio-processing` in the sandbox (declared exception);<br>• capture and playback via `enclave-platform` (cpal, mobile voice-processing paths);<br>• AV1 real-time encode with rav1e speed 10, decode with rav1d;<br>• video tiers 300/800/1500 kbps in fixed 1,200 B packets;<br>• padding while muted or with the camera off (RT-19);<br>• RFC 6464 audio-level extension rejected;<br>• **voice-note recording and playback in the app**;<br>• **on-device voice transcription** (optional model download, local only; `16` M11 row);<br>• on mobile, the OS voice-processing path |
| C2 | **Transport:**<br>• GotaTun WireGuard between client and relay, replacing the interim link framing (`11` §3.4);<br>• upstream Rosenpass daemon between relays (a sidecar in the compose `relay` service; declared exception);<br>• relay tickets paid with Privacy Pass (`calls/ticket-*`);<br>• relay descriptors (`calls/relay-descriptor`) published in server descriptors;<br>• each side picks a relay from a different operator family (RT-18);<br>• the **Maximum-privacy constant tunnel** |
| C3 | **1:1 call UI:**<br>• pre-call sheet "Private route / Direct (warning)";<br>• CallKit and PushKit on iOS, ConnectionService on Android;<br>• the 2-word call check (`calls/check-words`);<br>• picture-in-picture |
| C4 | **Direct mode:** ICE via webrtc-rs `rtc` (or str0m, chosen by benchmark), STUN only through Enclave relays, mDNS host candidates, a WireGuard PSK (`calls/direct-psk`), and a second confirmation for unchecked contacts |
| C5 | **Group calls:**<br>• an SFU in the relay forwarding SFrame frames with simulcast in fixed-rate slots;<br>• audio forwarded to everyone at CBR;<br>• a 2.5 Mbps receive budget;<br>• 32 video or 64 audio participants;<br>• **call links** (`calls/link-cap`) with a lobby;<br>• raise hand and reactions;<br>• **desktop and mobile screen share** (ScreenCaptureKit, Windows Graphics Capture, PipeWire portal, MediaProjection, ReplayKit) |

**Exit:**
- A call test matrix (relay, direct, group) under netem loss of 1%, 5% and 10%.
- MOS ≥4.0, measured with a POLQA-free proxy: ViSQOL (the C++ tool runs as a test oracle only).
- Constant rate verified by pcap (RT-19).
- The 360p30 AV1 gate decided on a reference phone (External Gate G8 for the device). If it fails, OS hardware H.264 encode as a declared exception.

---

### Track F: feature parity

All `16-features.md` rows must reach "Done".

| ID | Work |
|---|---|
| F1 | **Media:**<br>• picture previews in groups;<br>• a full-size viewer;<br>• export re-encoding;<br>• a gallery across all conversations;<br>• animated stickers (AV1 clips);<br>• removing a sticker pack;<br>• previewing a pack before adding it;<br>• Opus audio in clips;<br>• video files up to 100 MiB through the clip container at 30 fps;<br>• view-once (shredded after viewing) |
| F2 | **GIF search** (opt-in, fetched through Tor on the sender's side) and **link previews** (off by default, generated by the sender through Tor) |
| F3 | **Messaging:**<br>• typing indicators in groups;<br>• polls in 1:1 chats;<br>• anonymous polls;<br>• a list of pinned messages with jump-to;<br>• group invite links surviving the creator leaving, with uses and approval chosen in the app, and group-scoped request capabilities (`proto/grp-invite-cap`);<br>• replies, forwarding and mentions if any are missing after G0;<br>• formatting (bold, italic, strike, mono, spoiler);<br>• chat folders;<br>• **Stories** (24 h, delivered to a per-user audience like group messages) |
| F4 | **Profile:** encrypted photo and "about" text, shared only inside sessions |
| F5 | **Location:** read from the platform on phones; "open in maps" |
| F6 | **Message requests:** text-only enforcement checked by the RT-25 tests |

---

### Track L: accessibility and internationalisation (`18-a11y-i18n.md`)

#### L1: accessibility

- Upstream AccessKit wiring for Slint on Android (`accesskit_android`) and iOS (`accesskit_ios`), contributed to Slint.
- Full keyboard navigation and a 2 px focus ring.
- Labels on every control, including bubble metadata.
- 200% text with no truncation, reduce-motion, 48 dp targets.
- Screen-reader groups for the security code.
- TalkBack and VoiceOver test scripts.
- Gate: a WCAG 2.2 AA audit (External Gate G9 for the human audit).
- **If AccessKit mobile is still blocked 8 weeks after A1/I1:** the documented UniFFI + SwiftUI/Compose shells (PC-16/28) are built. Accessibility outranks purity.

#### L2: internationalisation

- Every string through `@tr()` plus gettext `.po` files; `xtask i18n extract|check`.
- ICU4X for plurals, dates and numbers.
- Bidi isolation in message text.
- Bundled Noto Sans per script.
- Pseudo-locale (+40%, RTL) in CI screenshots.
- The 15 tier-1 locales (en, es, pt-BR, fr, de, ru, uk, fa, ar, tr, zh-Hans, zh-Hant, hi, id, ja) through Weblate. Human translation is External Gate G10.
- RTL release gate for ar, fa and he.
- BIP-39 lists for each language (P5).

---

### Track Q: assurance (`20-assurance.md`, `redteam-matrix.md`)

| ID | Work |
|---|---|
| Q1 | **All 75 rtNN tests:**<br>• rename or alias existing equivalents;<br>• write the missing Sim, Unit and E2E tests;<br>• "Shape" rows go to the new `cargo xtask shape`: scripted workloads (idle, heavy chat, media, call setup) per profile; two-sample KS test p>0.01 that inter-packet times are independent of real traffic; byte budgets; a χ² check and a simple classifier that real and cover can't be told apart;<br>• "Manual" rows go into `docs/release-checklist.md` |
| Q2 | **Constant-time:**<br>• ctgrind (crabgrind under valgrind) for MAC compare, ML-KEM and McEliece decapsulation, token verification and Ed448, in CI;<br>• dudect extended;<br>• the DIT bit confirmed in a test |
| Q3 | **Formal methods:**<br>• Tamarin models of EQXDH including the PSK "all KEMs broken" lemma, the Lockstep ratchet (adapted from SPQR), the wrap table, groups (bounded), linking, the pending-root window, tokens, and the recovery-word migration;<br>• the remaining ProVerif models (`formal/README.md` boundaries);<br>• CryptoVerif or EasyCrypt proofs for EnclaveCombine and EnclaveSeal;<br>• hax extraction for `enclave-crypto` where the backend allows it;<br>• CI job `formal` (Tamarin + ProVerif) |
| Q4 | **Fuzzing:**<br>• cargo-fuzz targets for every new parser (descriptor, server list, KeyCert, mixframe, TUF metadata, SFrame, Protobuf content, AppStream-free inputs);<br>• a nightly fuzz campaign;<br>• OSS-Fuzz application (External Gate G11) |
| Q5 | **Supply chain:** `cargo vet`, the build.rs allowlist, independent rebuilders (R2) |
| Q6 | **Audit readiness:**<br>• scope documents per `20` §3;<br>• `SECURITY.md` process drills;<br>• a bug-bounty page;<br>• the audits themselves are External Gate G1 |

**HQC-256 suite:** implemented behind the reserved suite ID against the FIPS 207 draft with KATs, and enabled when FIPS 207 is final (External Gate G12).

---

### V1: the 1.0 gate

`cargo xtask done` passes with zero findings except External Gates whose status is "prepared". Then all of the following, and the `v1.0.0` tag:
- the release dry run;
- the federation e2e over localnet;
- the Nym sandbox e2e;
- the M4 gate report;
- the call matrix;
- install tests on every platform.

---

## External Gates (cannot be finished by code; each is prepared so it needs one human action)

| G | Item | What I prepare | What you or others must do |
|---|---|---|---|
| G1 | Two external audits (crypto and protocol; app and infrastructure) | Scope docs, threat model, build instructions, a frozen audit tag | Fund and engage the firms; fix the findings (as code work) |
| G2 | Maintainer HSM signing ceremony (2-of-3, two jurisdictions) | `enclave-admin` key ceremony scripts, TUF root template | Three maintainers with HSMs |
| G3 | App Store and TestFlight review; export compliance (EAR §742.15(b), France declaration) | Pipeline uploads, `ITSAppUsesNonExemptEncryption`, filing drafts | Submit; counsel files |
| G4 | Google Play listing, F-Droid inclusion, Flathub submission | `.aab`, F-Droid metadata with reproducible recipe, Flathub manifest PR text | Accounts and review (F-Droid and Flathub maintainers) |
| G5 | Foundation, server-list signing key, operator program (≥5 operators, ≥3 jurisdictions, ≥5 witnesses) | Operator kit, compose stack, `enclave-admin server-list` | Recruit operators; hold the offline key |
| G6 | APNs, FCM and Apple filtering-entitlement credentials | Push relay support and secrets wiring | Create the credentials; request the entitlement |
| G7 | Nym mainnet funding (credential proxy mnemonic, operator tickets) | credgate, cost model | Fund the accounts |
| G8 | Reference devices for the M4 and M8 gates (low-end Android, oldest supported iPhone) | Diagnostics screen and bench | Run on the devices (or a device farm) |
| G9 | WCAG audit and moderated usability sessions (5 non-technical users) | Scripts and builds | Recruit the auditor and participants |
| G10 | Human translations for 14 locales | Weblate project, `.po` files | Translators |
| G11 | OSS-Fuzz acceptance | Integration PR | OSS-Fuzz maintainers |
| G12 | FIPS 207 (HQC) final | Draft implementation behind a flag | NIST (expected 2027) |
| G13 | Nym post-quantum Sphinx in nym-sdk | Adapter behind a feature | Nym |
| G14 | Tor Project licence grant for equix/hashx (else clean-room) | The request letter; the clean-room fallback is built anyway if there is no reply | Tor Project |

---

## Release CI (`.github/workflows/release.yml`)

**Triggers:** a `v*` tag, or `workflow_dispatch(tag, dry_run)`.

**Permissions and secrets:** permissions are per job. Signing secrets live in Environments `release-apple`, `release-android` and `aur`, each with required reviewers.

| Job | Runner / container | Output | Secrets |
|---|---|---|---|
| prepare | ubuntu-24.04 | Draft release; `xtask version` checks the tag against the workspace, Android `versionCode` and iOS `CFBundleVersion` | — |
| linux ×{x64, arm64} | ubuntu-24.04(-arm), `almalinux:9` | `.tar.gz`, `.deb`, `.rpm`, `.AppImage` | — |
| flatpak ×{x64, arm64} | flathub-infra container (25.08) | `.flatpak` | — |
| macos | macos-15, universal2 via `lipo` | Signed and notarized `.app.zip` and `.dmg` | `APPLE_DEVELOPER_ID_P12_BASE64/_PASSWORD`, `APPLE_TEAM_ID`, `ASC_API_KEY_P8_BASE64/_ID/_ISSUER_ID` |
| windows ×{x64, arm64} | windows-2025, windows-11-arm | `.msi`, `-setup.exe`, portable `.zip` (unsigned; hook ready) | (later `AZURE_*`) |
| android | ubuntu-24.04 | `.apk` ×3, `.aab`; optional Play internal track | `ANDROID_KEYSTORE_BASE64/_PASSWORD`, `ANDROID_KEY_ALIAS/_PASSWORD`, optional `PLAY_SERVICE_ACCOUNT_JSON` |
| ios | macos-15 | `.ipa` (attached) and TestFlight upload | `ASC_API_KEY_*`, `APPLE_TEAM_ID` |
| images ×{amd64, arm64} → merge | ubuntu-24.04(-arm) | `ghcr.io/enclavechat/enclave-server:<v>` and `enclave-nym:<v>` (multi-arch), cosign keyless, provenance | `GITHUB_TOKEN` (OIDC) |
| compose-publish | ubuntu-24.04 | `oci://ghcr.io/enclavechat/enclave-stack:<v>` (digest-pinned) and the operator-kit tarball | `GITHUB_TOKEN` |
| sbom | ubuntu-24.04 | CycloneDX per binary set | — |
| repro-check | ubuntu-24.04 | An independent rebuild of the Linux tarball and server image; fails stable releases on mismatch | — |
| tuf-sign (R2) | ubuntu-24.04 | Unsigned TUF targets metadata for the offline co-signing step; Sigsum submission once signed | — |
| finalize | ubuntu-24.04 | `SHA256SUMS`, `SHA3-512SUMS`, `cosign sign-blob` bundles, `attest-build-provenance` for every file, the artifact manifest for D8; publish | OIDC |
| install-tests | Containers (Ubuntu 22.04/24.04, Debian 12, Fedora, Rocky 9, Arch), windows-2025, macos-15 | Pass/fail; blocks `aur` | — |
| aur | `archlinux:base-devel` | Push to `enclave-messenger-bin` and `enclave-messenger` | `AUR_SSH_PRIVATE_KEY`, `AUR_KNOWN_HOSTS` |

Other workflows:
- **`ci.yml`:** check, deny, deny-ios, repro, proverif, formal, build-macos, build-windows, android-emulator, ios-sim, docker-build, federation-e2e-tcp, package-smoke, icons and licences check, i18n check, done-gate.
- **`nightly.yml`:** federation-e2e-localnet, fuzz, the full repro, `xtask shape`, ctgrind.
- **`nym-live.yml`:** the sandbox nightly and a mainnet benchmark weekly.

---

## Compose stack (`ops/compose/compose.yml`, published as `oci://ghcr.io/enclavechat/enclave-stack`)

| Service | Image | Host ports | Networks | State | Profile |
|---|---|---|---|---|---|
| init | enclave-server | — | none | keys, witness, relay | `init` |
| server | enclave-server | none | backend (internal), egress | server-data, keys:ro, public, backups | default |
| ingress | enclave-nym | none (outbound WSS) | backend, egress | ingress-data, secret `nym_mnemonic` | default |
| push-egress | enclave-nym | none | backend, egress | push-egress-data | default |
| witness | enclave-server | none | backend | witness-data | default |
| front | enclave-server | 80, 443/tcp | backend, edge | front-data (ACME), public:ro | default |
| relay (+ rosenpass sidecar) | enclave-server | 51820/udp | edge | relay-data | default |
| push-relay, push-ingress | enclave-server, enclave-nym | none | backend, egress | push-data, secrets `apns_key`, `fcm_sa` | `push` |
| credgate, nym-credential-proxy | enclave-server, `ghcr.io/enclavechat/nym-credential-proxy` | none | backend, egress | credgate-data, secrets | `foundation` |
| nym-localnet | `ghcr.io/enclavechat/nym-localnet` | none | nymnet | — | `compose.localnet.yml` |

**Operations**
- Health checks use each binary's `healthcheck` subcommand.
- `.env.example` sets `ENCLAVE_VERSION`, `DOMAIN`, `OPERATOR`, `FAMILY`, `ACME_EMAIL`, `TLS_MODE`, `NYM_NETWORK`, `RELAY_PUBLIC_ADDR`, `PUSH_RELAY_NYM` and `SERVER_LIST_URL`.
- Restoring needs both the redb snapshots and the `keys` volume. The docs require an encrypted off-host key backup.

---

## Risks (top)

1. **nym-sdk gaps** (gateway connector for Tor-under-Nym, Poisson disable being supported, per-request tags, SURB policy). Mitigation: upstream PRs plus `third_party/` patches; residuals documented if Nym refuses.
2. **Nym economics and mainnet credentials (≤$1/user/month).** Mitigation: the N3 cost model; funding is G7.
3. **Slint mobile accessibility.** Mitigation: upstream AccessKit, with native shells as the fallback in L1.
4. **Skia cross-builds and F-Droid from-source builds.** Mitigation: mirrored, checksummed prebuilts.
5. **App Store issues:** LGPL equix (X25), E2EE export filings, Tor/Nym in-app.
6. **Flatpak vs the process split.**
7. **iOS memory with nym-sdk + arti in one process.**
8. **Unsigned Windows installers.** The hook is ready.
9. **The 16 B server id against a quantum second preimage.** Mitigation: also require server-list inclusion or a KT-logged descriptor; plan a 32 B id in wire v2.
10. **Store IDs are irreversible.**
11. **arm64 GitHub runners are free only for public repos.** Fallback: cross-compile.
12. **Scope:** this is many engineer-months of work. Order work by dependency, keep each milestone independently green, and never leave the branch red.

---

## Verification (per milestone; all automated unless the row is an External Gate)

| Milestone | Verification |
|---|---|
| R0 | All `ci.yml` jobs green on 3 OSes; no `uses: …@v<n>` refs remain. |
| S1/S2 | `cargo test -p enclave-server --test restart --test request_chain`; akd-on-redb storage tests; `enclave-federation`, `enclave-witness` and `enclave-tls` tests (OpenSSL 3.5 interop); 3-server sim; wrong KeyCert rejected. |
| S3/S4 | `ci/federation/gen.sh && docker compose -p a/b/c up -d && enclave-e2e --transport tcp`, then the same over localnet with the production profile; no shell in images; nonroot; `strings` finds no dev symbols. |
| N0–N4 | Decision table in the spike doc; `cargo test --features nym` (FakeMixnet with a packet-count invariant property test); localnet e2e; pcap constant-rate check; gateway-kill recovery; `enclave-e2e bench` within ±20%; the sandbox install-to-message flow with no manual step; the gate report. |
| P1–P7, F1–F6, C1–C5 | Each item's rtNN and unit/e2e tests; `xtask labels` (reserved table shrinking to empty); call matrix under netem; pcap constant rate. |
| D1/R1 | Release dry run on `v0.1.0-rc.1`, then the install tests:<br>• apt in Ubuntu 22.04/24.04 and Debian 12 (`enclave --version`, `xvfb-run enclave --demo --smoke-exit`);<br>• dnf in Fedora and Rocky 9;<br>• AppImage `--version`;<br>• `flatpak install` and run;<br>• `makepkg -si` in Arch;<br>• Windows `msiexec /qn` and NSIS `/S`, run, then uninstall;<br>• macOS `spctl -a -vv`, `stapler validate`, `codesign --verify --deep --strict`;<br>• `cosign verify-blob` on the sums; `gh attestation verify`; `cosign verify` on the images; `docker compose -f oci://… config`. |
| A1/A2 | Emulator: install, launch, onboarding visible in a uiautomator dump; `apksigner verify`; `bundletool validate`; `zipalign -c -P 16`; isolatedProcess decoder test. |
| I1/I2 | Simulator: install, launch, alive after 10 s; TestFlight processing; NSE capsule decrypt under 24 MB; WASM decoder tests; `deny-ios` green. |
| L1/L2 | Screen-reader scripts; pseudo-locale and RTL screenshots in CI; `xtask i18n check` (no untranslated strings in shipped locales). |
| Q1–Q6 | 75/75 rtNN green; `xtask shape` KS/χ² pass; ctgrind clean; the `formal` job (Tamarin + ProVerif); nightly fuzz; `cargo vet` 100% for crypto and parsers. |
| R2 | TUF metadata verifies with 2-of-3 test keys; Sigsum inclusion proof test; two Nix rebuilders match; MSIX installs. |
| V1 | `cargo xtask done` passes, apart from External Gates marked "prepared"; then `v1.0.0`. |

## Critical files

- **Servers:**
  - `crates/enclave-server/src/{lib.rs,main.rs}` plus new `keys.rs`, `db.rs`, `config.rs`, `migrate.rs`;
  - `crates/enclave-kt/src/{service.rs,log.rs}` plus new `store_redb.rs`;
  - `crates/enclave-rpc` (`ServerSecret::from_seed`).
- **Client network and vault:**
  - `crates/enclave-net/src/{transport.rs,shaped.rs,schedule.rs}`;
  - `crates/enclave-netd/src/main.rs` and `crates/enclave-ipc/src/net.rs`;
  - `crates/enclave-vault/src/engine.rs` (zero id at 516–523, `Mode`, demo feature);
  - `crates/enclave-core/src/card.rs` (card v3/v4).
- **App:** `crates/enclave-app/{Cargo.toml,src/main.rs,src/vault.rs,ui/app.slint}`.
- **New crates:** `enclave-federation`, `-tls`, `-front`, `-witness`, `-admin`, `-e2e`, `-nym`, `-ingress`, `-credgate`, `-platform`, `-mobile`, `-nse`, `-update`, `-crash`, `-equix` (fallback).
- **Build and release:** `ops/docker/Dockerfile`, `ops/compose/*`, `ops/operator-kit/*`, `packaging/**`, `apps/android/**`, `apps/ios/**`, `.github/workflows/{ci,release,nightly,nym-live}.yml`, `xtask/src/{main.rs,done.rs}`.
- **Docs:** `docs/completion.md` (new), `docs/label-registry.md`, `docs/redteam-matrix.md`, `docs/16-features.md`, `docs/15b-platform-constraints.md`, `docs/roadmap.md`, `docs/spikes/m4-network.md`.
