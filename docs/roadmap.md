# Roadmap

Status: Draft (M0) · Normative

Source: PLAN.md §20. Every milestone has an exit gate. A milestone is complete only when its gate is met and its red-team tests (`redteam-matrix.md`) pass.

## 1. Milestones

| M | Deliverable | Exit gate |
|---|---|---|
| **M0** | All `docs/` (threat model, red-team matrix, label registry, byte layouts, `math/`, design spec, platform constraints). **LICENSE §7 permissions, DCO**, SECURITY, GOVERNANCE. Workspace scaffold, CI (fmt, clippy, deny, vet, audit), design tokens, README. | Spec review checklist (§2) done. §7 merged before any outside PR. |
| **M1** | `enclave-crypto` + `enclave-wire`: providers, KMAC256, EnclaveSeal (hedged), EnclaveCombine (2/3 KEM + PSK), composite signatures, hedged RNG, padding and size invariants, Argon2id calibration. KATs/ACVP, Wycheproof, SP 800-185, differential tests, dudect/ctgrind, ARM + x86 benchmarks. **Send the audit RFP.** | All vectors pass. Zero differential mismatches in 10⁷ fuzz iterations. EnclaveSeal ≥50 MB/s on the reference phone. SLH-DSA signing ≤10 s on the phone. McEliece keygen time and memory measured. |
| **M1.5** (parallel) | Time-boxed spikes: **(a)** nym-sdk over arti on Android, iOS, desktop (credentials, cost, cover-stream flags, `k` and `u`, Tor→gateway reachability); **(b)** Slint Android/iOS with TalkBack/VoiceOver, IME, RTL, emoji, 200% text; **(c)** a Rust iOS NSE decrypting a capsule in under 24 MB; **(d)** Play policy for the `specialUse`/`remoteMessaging` foreground service. | Written go/no-go for each spike |
| **M2** | `enclave-proto`: manifest, EQXDH (sealed initiator, vault KEM, auth ek, braid, PSK), Lockstep, wrap table, modes, replay caches. Loss, reorder, and replay simulation. Tamarin/ProVerif models, including the PSK "all KEMs broken" lemma. | Lemmas pass: secrecy, authentication, forward secrecy, post-compromise security, deniability, downgrade. Every unit is exactly 16,384 B. |
| **M3** | `enclave-server`, `enclave-kt` (akd), `enclave-witness`, `enclave-tokens`, `enclave-sim`, dev transport | E2E simulation with 3 clients × 2 devices: the server stores only opaque 14,336 B objects and burned tokens, and sees no device count. KT split view detected. |
| **M4** | **Hard gate.** `enclave-net`: arti + Nym, sealed requests, tick scheduler with three profiles, loop probes, bulk mode, credential proxy, push relay, fallback transport. Since RFC 0010: Tor onion services as the primary route, the Nym mixnet (with loop probes and the credential proxy) optional | The `09-transport.md` §7 go/no-go numbers (since RFC 0010, for the optional mixnet). Measured data within ±20% of `09-transport.md` §6.3. Battery ≤5 percentage points per hour above idle in the Foreground profile on the reference device (otherwise lengthen the tick, globally). |
| **M5** | `enclave-store`, `enclave-core`, `enclave-ipc`: process split, contacts, hardened linking, the 72 h veto, backups, crypto-shred, emergency PIN | Restore from words works. Forensic test shows shredded data cannot be recovered. |
| **M6** | Slint MVP (desktop, then Android, then iOS): design system, onboarding, all three add paths plus the in-person Seal, 1:1 chat, emoji, reactions, images, voice notes, disappearing messages, the push matrix, app lock, message requests. Upstream AccessKit and RTL work. Apply for the filtering entitlement. | **WCAG AA audit plus TalkBack/VoiceOver scripts pass.** 5 moderated sessions with non-technical users: ≥4 of 5 add a contact and check them without help. |
| **M7** | Groups: MAC vectors, exporter rekey, state chain, causal frontier, invites. Group formal model. | 100-member simulation: a rotation costs ≤ about 3 units per sender. Equivocation is detected. |
| **M8** | Calls: relay tickets, GotaTun, Rosenpass relay↔relay, SFrame, shaping, direct mode, SFU, call links. Codec gates. | Audio MOS ≥4.0 on the reference network. 360p30 AV1 gate decided. Constant rate verified by packet capture. |
| **M9** | Parity: video and files, stickers, GIFs, edits and deletes, polls, pins, previews, search, device transfer, social recovery, location, contact sharing, WebTunnel. | Parity rows up to M9 complete (`16-features.md`) |
| **M10** | Assurance: full fuzz campaign (apply to OSS-Fuzz), CryptoVerif/EasyCrypt proofs of the combiners and EnclaveSeal, reproducible builds, TUF + Sigsum, **two external audits**, public beta, bug bounty, McEliece literature re-review | All critical and high findings closed |
| **M11** | Launch: store submissions, export filings, operator program (≥5 operators, ≥3 jurisdictions, ≥5 witnesses), Postgres backend, stories, mobile screen share, transcription | 1.0 |
| **M12+** | HQC-256 suite after FIPS 207; Nym post-quantum Sphinx once available; libopus replaced by pure-Rust Opus; envelope v2 evaluated | — |

This session covers M0 and M1.

## 2. M0 spec review checklist

The M0 exit gate requires every item below to be checked by at least one reviewer other than the author.

- [ ] Every PLAN.md section maps to a spec file (`00-overview.md` §8).
- [ ] Every byte table in `08-envelope.md` sums exactly; the compile-time assertions in §10 match the tables.
- [ ] `math/envelope-budget.md` and `math/cover-traffic.md` reproduce every number they cite.
- [ ] Every label used in any spec file is in `label-registry.md`, exactly once, with a kind and output length.
- [ ] Every derivation in a spec file appears in `02b-key-schedule.md`.
- [ ] Every RT row has a spec section and at least one named test.
- [ ] Every PLAN.md inconsistency found is listed in `00-overview.md` §9 with a resolution.
- [ ] Every "Open questions" item has an owner and a milestone.
- [ ] Palette contrast ratios reproduce (`cargo xtask tokens-check` passes on `design/tokens.toml`).
- [ ] Copy in all spec files and `design/copy-glossary.md` passes the banned-words list.
- [ ] `legal/ADDITIONAL-PERMISSIONS.md` and the DCO are merged before any outside PR.

## 3. Dependencies between milestones

```
M0 ─▶ M1 ─▶ M2 ─▶ M3 ─▶ M4 ─▶ M5 ─▶ M6 ─▶ M7 ─▶ M8 ─▶ M9 ─▶ M10 ─▶ M11
       └─▶ M1.5 (parallel) ──▶ informs M4 (a, d), M6 (b, c)
```

M4 is a hard gate: if its go/no-go fails, the fallback transport and the scheduler design are revisited through an RFC before M5 starts. That RFC was taken: the mixnet's tickets are a recurring cost per stack and per user that nobody can pay, so RFC 0010 makes Tor onion services the primary route and the Nym mixnet optional, with the same scheduler.

## Open questions

1. **Resolved:** the M4 bulk-throughput gate (≥200 KB/s) measures nym-sdk raw throughput, because the Bulk profile's 40 packets/s cap allows at most ≈82 KB/s of payload (`00-overview.md` §9, I-12). Measured locally: 726 KiB/s raw and 55 KiB/s in the paced Bulk window (`docs/spikes/m4-network.md`, `live_bench`). Since RFC 0010 the mixnet is optional, so the live-network run is needed only by whoever funds it, and G7 is no longer needed.
2. **Resolved:** no separate owners. The maintainers own the open questions left in the specs, and new ones are raised and decided through an RFC (`rfcs/0000-template.md`), whose author owns it until it is accepted or rejected.
