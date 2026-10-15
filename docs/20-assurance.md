# Assurance: Verification, Formal Methods, Audits

Status: Draft (M0) · Normative

Source: PLAN.md §21, §2.2, §20 (M1, M2, M7, M10 gates), Appendix B. Red-team tests: `redteam-matrix.md`.

## 1. Test plan

### 1.1 Crypto primitives

| Target | Vectors and methods |
|---|---|
| ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256s, McEliece-8192128 | NIST ACVP / KAT vectors |
| X448, Ed448, P-384, AES, ChaCha20 | Wycheproof |
| KMAC256 | SP 800-185 samples #4 to #6, plus differential vs `libcrux-kmac` and OpenSSL |
| Composite signature | Draft -19 test vectors (components reordered to Enclave's pin) |
| Argon2id | RFC 9106 vectors |
| Privacy Pass | RFC 9578 vectors |
| SFrame | RFC 9605 vectors for framing; Enclave-suite vectors generated and frozen at M8 |
| All primitives | Rust vs. C differential tests on two or three backends (`02-cryptography.md` §13) |

### 1.2 EnclaveSeal

- round-trip tests at every length 0 to 1,024 and at selected lengths to 65,536;
- **every flipped bit is rejected** (each bit of `F`, `N`, `c`, `T`, and AD);
- **the tag is rejected before any keystream is generated** (instrumented keystream functions);
- **key commitment:** for two keys over one ciphertext, at most one verifies (randomized search plus a structured test);
- **nonce hedging:** the same key with a different plaintext always produces a different keystream, including after a simulated state rollback that replays the hedged-RNG state with a fixed OS RNG output;
- SealDN call-site allowlist (`seal_dn_call_sites_allowlisted`).

### 1.3 EnclaveCombine

- `psk_flag` downgrade test; 2-KEM vs. 3-KEM label test; stripping `H512(McE_pk)` is rejected; every `pks` and `cts` byte is bound (`02-cryptography.md` §5.4).

### 1.4 Invariants

- every wire unit is 16,384 B, every poll object 2,048 B, every stored object 14,336 B;
- the byte budgets of `08-envelope.md` are asserted at compile time;
- label-registry uniqueness and kind consistency (`cargo xtask labels`);
- no secret type implements `Debug`.

### 1.5 Adversary simulation (`enclave-sim`)

One test per red-team row (`redteam-matrix.md`), including: KT split view detected (RT-04); stripped McEliece rejected (RT-07); rollback produces no keystream reuse (RT-08); a link QR scanned from the wrong place is refused (RT-09); group fork and equivocation detected (RT-11); replayed initial message rejected (RT-05, RT-24); pending-root veto honored (RT-22); clock-skew warning shown (RT-23); the server sees no device count and no repeated tokens; the server never sees a plaintext initiator identity; every poll request contains at most one mailbox.

### 1.6 Traffic shape (`cargo xtask shape`)

- capture traffic for scripted workloads (idle, heavy chat, media, call setup) in each profile;
- a two-sample Kolmogorov-Smirnov test shows **inter-packet times do not depend on real traffic** (p > 0.01);
- byte rates are within the `math/cover-traffic.md` budget (±20%);
- real and cover units cannot be told apart with χ² tests or a trained classifier (accuracy within 1 percentage point of chance on a held-out set);
- call packets are a constant size and rate.

### 1.7 Timing

dudect and ctgrind on MAC compare, ML-KEM and McEliece decapsulation, token verification, and Ed448. The DIT bit is confirmed set during crypto calls on AArch64.

**Implemented so far** (`crates/enclave-crypto/tests/dudect.rs`, run with `cargo xtask dudect`; ignored in `cargo test` because it is slow and noise-sensitive): a dudect-style harness (Welch's t on two input classes; data also cropped at the 90th and 50th percentiles). Both classes share one buffer, rewritten before each untimed step, so allocation and alignment can't differ between them (an earlier version used one buffer per class and produced false positives). Gate: the control must exceed |t| = 10, and each operation must stay below 10 on every crop.

| Test | Classes | Result (x86-64 dev container, one run) |
|---|---|---|
| Control: early-exit `==` on 4 KiB | differ at the first byte vs the last | flagged: \|t\| 23 / 3085 / 4439 |
| `seal::open` rejecting forgeries (1 KiB) | tag differs at its first vs last byte | clean: 0.07 / 0.39 / 0.62 |
| ML-KEM-1024 decapsulation | valid vs corrupted ciphertext (implicit rejection) | clean: 0.19 / 0.51 / 1.04 |

Findings and limits:

- `std::time::Instant` can't resolve a 32-byte comparison: at that size even the leaky `==` looks constant. Tag comparisons are therefore only tested through `seal::open`, and comparisons in isolation only at 4 KiB.
- At 4 KiB, `subtle`'s slice `ct_eq` (4.85 µs, because of its per-byte optimization barrier) showed a consistent median shift of 4–12 ns between the classes (0.1–0.25 %) with **identical 10th percentiles**. A plain XOR-fold of the same data showed none. The pattern (no change in the fast path) points to a microarchitectural effect of the barrier rather than an early exit. Enclave uses `subtle` only on 32-byte tags, where no leak shows at the operation level. It is recorded here to be re-examined with cycle counters and ctgrind.
- Not yet: ctgrind (secret poisoning under Valgrind), cycle-accurate counters, McEliece decapsulation, token verification, Ed448, and the AArch64 DIT check.

### 1.8 Fuzzing

Wire unit, envelope (all layouts), poll object, manifest, bundle, KT proof, Protobuf content, IPC messages, SFrame, the chunk container, and every media decoder inside the sandbox. Continuous fuzzing via OSS-Fuzz is applied for at M10. As implemented: the targets are in `crates/enclave-fuzz` (`wire`, `proto`, `rpc`, `content`, `calls`, `server`, `relay`, `group_open`, `ipc`, `media`, and `net`: mixnet frames and pacing, held ticketbooks, Privacy Pass tokens, Equihash solutions, push relay keys and sealed tokens, the notification key table and capsules, backup archives); `cargo test -p enclave-fuzz` mutates seeded samples on every CI run, and `nightly.yml` runs each under cargo-fuzz for ten minutes a night, keeping any crashing input. M1 exit: zero differential mismatches in 10⁷ fuzz iterations.

### 1.9 End to end

Servers, a relay, and 3 clients × 2 devices. Covers 1:1, groups, revocation, migration, a vanished server, dropped messages (the gap notice fires), offline delivery, emergency PIN, and shredding.

### 1.10 Budgets

Data and battery per profile on a low-end Android, a mid-range Android, and the oldest supported iPhone. Measured at M4 and at every release. Foreground battery ≤5 percentage points per hour above idle on the reference device (M4 gate).

### 1.11 Clients

`slint::testing` headless tests; the contrast check; emulator smoke runs via `cargo xtask`; TalkBack and VoiceOver scripts; pseudo-locale and RTL screenshots; moderated usability sessions (M6 and M9) measuring onboarding success and whether users correctly understand security states.

### 1.12 Calls

A relay and direct test matrix; SFrame vectors; MOS under netem loss of 1%, 5%, and 10% (M8 gate: audio MOS ≥ 4.0 on the reference network).

### 1.13 Supply chain

Two independent rebuilders produce identical hashes; `cargo vet` covers 100% of crypto and parser crates.

**Implemented so far:** `cargo xtask repro [package] [bin]` builds a release binary twice from scratch in two target directories (`--locked`, no incremental builds, `SOURCE_DATE_EPOCH` fixed, and the target directory, source root and cargo home remapped to fixed names so no build path is embedded) and fails unless the two are byte-identical. `enclave-relay` reproduces (870,976 bytes, identical SHA3-512, in the dev container); CI runs it for `enclave-relay` and `enclave-server`. This checks determinism on one machine; independent rebuilders on other machines and toolchain pinning via Nix are still to come.

## 2. Formal-methods plan

**Implemented so far** (`formal/`, see `formal/README.md` for each model's boundary): ProVerif models of EQXDH (secrecy both ways, injective mutual authentication, forward secrecy), the "all KEMs broken" lemma (secret with an in-person PSK, attack found without one), downgrade resistance for the mode byte, the invite-link PSK against the same attacker acting as the server (secret from a private link, its capabilities notwithstanding; attacked from a public one), Lockstep post-compromise healing through the ML-KEM step (and an attack against an X448-only step), and group MAC-vector insider unforgeability. `cargo xtask proverif` checks each query against the result written before it, including sanity queries that must find an attack; CI runs it. Tamarin, deniability, the braid, linking, the 72-hour guard, the wrap table, tokens and the computational proofs are still open. Boundaries live in `formal/README.md` rather than one `BOUNDARY.md` per model.

| Model | Tool | Scope | Properties | Milestone |
|---|---|---|---|---|
| EQXDH | Tamarin and ProVerif | Two-stage handshake with vault KEM, auth eks, braid, PSK | Secrecy of `SK`; mutual authentication (classical + PSK immediately; PQ after the AUTH mix); initiator identity hidden from the responder's server; forward secrecy; deniability (Off the record); downgrade resistance (`kem_count`, `psk_flag`, mode, suite); **"all KEMs broken, optical exchange not recorded" lemma** | M2 |
| Lockstep Ratchet | ProVerif (adapted from Signal's public SPQR models) | DH ratchet with header keys, per-direction PQ epochs, chain-boundary mixes | Message secrecy, FS, PCS after one round trip, no key reuse across chains | M2 |
| Wrap table | Tamarin | 5 slots, self-copy | A recipient device learns `bk` only from its own slot; tampering with any slot fails the body | M2 |
| Linking | Tamarin | Link QR, phrase check, manifest update | An attacker who does not control the primary's user cannot add a device | M5 |
| Pending-root window | Tamarin | 72 h pending, veto, cosignature | Stolen words cannot take over an account with a live device | M5 |
| Tokens | ProVerif | Registration, burn, weekly rotation | Server cannot link two writes by the same sender through tokens | M3 |
| Groups (bounded) | Tamarin | MAC vectors, exporter rekey, state chain | Insider unforgeability; removed members lose access at the next epoch; group PCS within one epoch | M7 |
| EnclaveCombine | CryptoVerif or EasyCrypt | Combine2 and Combine3 with PSK | IND-CCA if any component KEM is IND-CCA, or the PSK is secret | M10 |
| EnclaveSeal | CryptoVerif or EasyCrypt | Cascade + KMAC tag + hedged nonce | IND-CCA if either cipher holds and KMAC is a PRF; key commitment | M10 |
| Code extraction | hax | `enclave-crypto` and the ratchet core, where the backend supports it | Experimental | M10 |

Rules:

- Each proof states its boundary (what is modelled, what is assumed) in `formal/<model>/BOUNDARY.md`.
- Proofs **add to** differential testing and never replace it (ePrint 2026/192 found bugs inside formally verified PQ code).
- Hand-written models can drift from code (Appendix B risk 18). Each model lists the spec sections it covers, and any change to those sections requires re-running the model in CI.

## 3. Audit scope

### 3.1 Funded audit (M1–M2)

- RustCrypto `slh-dsa` (never audited);
- `ed448-goldilocks` (not audited), and the X448 ladder in `enclave-crypto/src/x448_ladder.rs` (about 60 lines on `fiat-crypto`'s verified field arithmetic);
- `classic-mceliece-rust` (no audit found);
- EnclaveSeal-v1 and its implementation, KMAC256 implementation, EnclaveCombine.

The audit RFP is sent during M1. If a shipped crate fails review, the release is blocked (`02-cryptography.md` §13).

### 3.2 Two external audits before 1.0 (M10)

| Audit | Scope |
|---|---|
| A: crypto and protocol | `enclave-crypto`, `enclave-wire`, `enclave-proto`, `enclave-tokens`, `enclave-kt`; EQXDH, Lockstep, wrap table, groups, KT; formal models' boundaries |
| B: app and infrastructure | `enclave-core`, `enclave-ipc`, `enclave-store`, `enclave-net`, `enclave-sandbox`, `enclave-platform`, `enclave-calls`, servers, relays, push relay, update and build pipeline |

M10 exit: all critical and high findings closed. The McEliece cryptanalysis literature is re-reviewed at M10 (Appendix A: a 2026 distinguisher at about 2^124 is unresolved from one source).

## Open questions

1. The traffic-shape classifier threshold (within 1 percentage point of chance) is this spec's choice; PLAN says only "can't be told apart".
2. Whether audit A should include the Tamarin and ProVerif models themselves or only their boundaries.
