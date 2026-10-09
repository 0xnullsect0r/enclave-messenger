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
| N0–N4 | Full Nym integration, credentials, fallback, M4 gate report | Done (live-network numbers wait on G7 and G8; Snowflake and WebTunnel ship with the packages in D1, A1 and I1) |
| P1–P7 | Protocol completion | In progress (P1 done: weekly inbox addresses, daily read credentials, address-bound tokens, session hints, adaptive request effort, polling rules. P2 done: self-copy always written, own-device sync, watermark after every device, PQ carrier rotation, inactive-device removal, new-device notice, groups on every device, history when both devices confirm; history over the LAN goes with D1. P3 done: Protobuf content with limits, continuation units up to 64 KiB, gap notices, "delivered late", held units, the v1 control set, On the record for 1:1 chats and groups (signed messages, admin updates and poll tallies, authenticated mode changes), verifiable reports) |
| D1, R1 | Desktop shippable; release pipeline | Open |
| A1–A2, I1–I2 | Android and iOS | Open |
| C1–C5 | Calls | Open |
| F1–F6, L1–L2 | Feature parity; accessibility; translations | Open |
| Q1–Q6, R2 | Assurance; update channel | Open |
| V1 | `cargo xtask done` passes; `v1.0.0` | Open |

## External gates

Work that code alone cannot finish. Each is made ready so that it needs one action from a person or organisation. A doc marker that names a gate in parentheses, for example "(G3)", stops counting once that gate's status here is **prepared**.

| Gate | Item | Prepared by us | Needs | Status |
|---|---|---|---|---|
| G1 | Two external audits (crypto and protocol; app and infrastructure) | Scope documents, threat model, frozen audit tag | Funding and two audit firms | open |
| G2 | Maintainer signing ceremony (2 of 3, two jurisdictions) | `enclave-admin` ceremony scripts, TUF root template | Three maintainers with HSMs | open |
| G3 | App Store and TestFlight review; export compliance (EAR §742.15(b), France) | Pipeline upload, `ITSAppUsesNonExemptEncryption`, filing drafts | Submission; counsel | open |
| G4 | Google Play, F-Droid, Flathub listings | `.aab`, F-Droid metadata with reproducible recipe, Flathub manifest | Store accounts; F-Droid and Flathub review | open |
| G5 | Foundation, server-list key, operator program (≥5 operators, ≥3 jurisdictions, ≥5 witnesses) | Operator kit, compose stack, `enclave-admin server-list` | People and an offline key | open |
| G6 | APNs, FCM and Apple notification-filtering entitlement | Push relay support and secret wiring | Credentials; Apple's grant | open |
| G7 | Nym mainnet funding for credentials | Credential gate, cost model | Funded accounts | open |
| G8 | Reference devices for the network and call gates | Diagnostics screen, benchmark | Runs on the devices | open |
| G9 | WCAG audit and moderated usability sessions | Scripts and builds | Auditor and five participants | open |
| G10 | Human translations for 14 locales | Weblate project, message catalogs | Translators | open |
| G11 | OSS-Fuzz acceptance | Integration | OSS-Fuzz maintainers | open |
| G12 | FIPS 207 (HQC) final | Draft-based implementation behind a flag | NIST | open |
| G13 | Post-quantum Sphinx in nym-sdk | Adapter behind a feature | Nym | open |
| G14 | Licence grant for equix/hashx (LGPL-3.0-only) | Request letter; clean-room fallback is built regardless | Tor Project | open |

Signing credentials the release pipeline needs (Apple Developer account, Android keystore, AUR SSH key) are provided by the maintainers as CI secrets; a Windows code-signing certificate is not, so Windows installers ship unsigned until one is added (`ENCLAVE_WIN_SIGN_CMD`).
