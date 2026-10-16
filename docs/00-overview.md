# Enclave Specification Overview

Status: Draft (M0) · Normative

This document is the entry point to the Enclave specification. It records the context, the fixed decisions, the honest limits, the project's position on new cryptography, the shared notation, a glossary, and a map of every other document. `docs/PLAN.md` is the approved master plan. Where this specification and PLAN.md disagree, PLAN.md wins and the specification is corrected through the RFC process (`rfcs/0000-template.md`). Every such disagreement found while writing M0 is listed in §9.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## 1. Context

Enclave is an open-source messenger, licensed under GPLv3 with §7 additional permissions. It aims to match Signal's features and to be usable by non-technical people. Signal is already post-quantum (PQXDH plus the SPQR Triple Ratchet), so Enclave's advantage has to come from these five properties:

1. Category-5 hybrid cryptography with three independent KEM families (X448, ML-KEM-1024, Classic McEliece-8192128), plus post-quantum authentication (Ed448 + ML-DSA-87 composite, SLH-DSA-SHAKE-256s root).
2. A full ML-KEM-1024 ratchet step on every round trip (the Lockstep Ratchet, `05-ratchet.md`).
3. Metadata hiding. Servers and a global observer do not learn sender, recipient, size, timing, device count, or group membership, within the limits of `01-threat-model.md` §4. This uses a mixnet, constant-size units, and cover traffic.
4. No phone number and no trusted server. This includes key-transparency servers, which are checked by independent witnesses.
5. Hardware-bound storage that can be crypto-shredded, plus a hardened endpoint that runs components in separate processes.

## 2. Fixed user decisions

These decisions are inputs. The specification MUST NOT contradict them.

| Topic | Decision |
|---|---|
| Platforms | Android, iOS, and desktop (Linux, macOS, Windows). Desktop is not an always-on node. No web client. |
| Topology | Federated, untrusted servers that anyone can run, reached through Nym over Tor. No server-to-server message relay: clients write directly to the recipient's server through the mixnet. |
| Identity | Key-based accounts. Optional `@name@server` usernames backed by key transparency (KT). Contacts are added by QR code, invite link, or username. No phone numbers. |
| Calls | Chosen per call. Private relays by default. Direct P2P is opt-in and shows an IP warning. |
| Cover traffic | Adaptive: constant rate in the foreground, a trickle in the background, and a "Maximum privacy" toggle. |
| Deniability | Set per conversation. "Off the record" (deniable) is the default. "On the record" signs every message. |
| Multi-device | Linked devices, each with its own keys, certified by the root. |
| Groups | Up to 100 members, built on pairwise sessions. No MLS. |
| Language | Rust wherever possible, including the UI. Non-Rust code only where unavoidable, isolated, and justified (PLAN §22). |
| Crypto stack | SLH-DSA-SHAKE-256s root; Ed448 + ML-DSA-87; X448 + ML-KEM-1024 + Classic McEliece-8192128 (HQC-256 later); KMAC256 and SHA3; a Double-Ratchet-family ratchet with an ML-KEM-1024 PQ ratchet; an XChaCha20 and AES-256 cascade with a KMAC256 256-bit tag; constant-size padding; TLS 1.3 SecP384r1MLKEM1024 with TLS_AES_256_GCM_SHA384; WireGuard to relays, X448 + ML-KEM-1024 links between them (RFC 0007); Nym over Tor; LUKS2 and Argon2id at rest. |

## 3. Decisions made in PLAN revision 2

| # | Decision | Specified in |
|---|---|---|
| D1 | Each message is one 16,384 B wire unit carrying a sealed request header and a 14,336 B stored envelope. | `08-envelope.md` |
| D2 | McEliece is used by the initiator only, from the first message, against the account vault key. The responder authenticates the initiator post-quantum through the initiator's per-device ML-KEM auth key. If the 1.36 MB key has not arrived, the session starts on two KEMs and McEliece is braided in later. | `04-eqxdh.md` |
| D3 | One root-signed account manifest. No intermediate signing key. | `03-identity.md` |
| D4 | The security code covers root keys only. | `03-identity.md` §6 |
| D5 | Multi-device uses a wrap table: the body is encrypted once, device slots are padded to 5, and a self-copy is always sent. | `06-multidevice.md` |
| D6 | Groups authenticate each message with a MAC vector and rekey with a DCGKA-style exporter-key broadcast. | `07-groups.md` |
| D7 | One account inbox. Writes need hash-registered single-use tokens. Each poll touches exactly one mailbox. | `09-transport.md` |
| D8 | The post-quantum exchange between relays (RFC 0007, in place of Rosenpass) runs only between relays. The client-to-relay WireGuard PSK comes from a sealed relay ticket. | `11-calls.md` |
| D9 | No DTLS-SRTP and no SCTP. Calls use WireGuard + SFrame. RingRTC is not used. | `11-calls.md` |
| D10 | Exactly three global cover profiles. No per-user or per-network rates. Nym per-hop delays stay at Nym defaults. | `09-transport.md` §6 |
| D11 | Hedged nonces and a hedged RNG. Backups never contain ratchet state. | `02-cryptography.md`, `14-storage.md` |
| D12 | Optional in-person PSK from a mutual QR scan. | `03-identity.md` §7 |
| D13 | GPLv3 §7 additional permissions and a DCO at M0. App Store builds use Slint under its Royalty-free 2.0 license. | `legal/`, `19-ops.md` |

## 4. Honest limits

These statements MUST appear in this document and in the app's help, in plain language. Product copy MUST NOT contradict them.

1. **The endpoint is the real attack surface.** Spyware on the device defeats everything in this specification.
2. **Using Enclave is visible. Who you talk to is what we hide.**
3. **Anonymity is not yet post-quantum.** Nym's Sphinx packets and Tor use classical cryptography, so recorded traffic could later reveal routes. Message content stays post-quantum safe. Sealed requests keep mailbox IDs and tokens hidden even then.
4. **The mixnet adds latency.** Text takes about 5 to 6 s. Calls take 3 to 10 s to start ringing.
5. **Metadata protection costs data.** Roughly 60 to 70 MB per hour while open, 35 to 40 MB per day in the background, and about 1.5 GB per day in Maximum privacy mode. The UI shows these numbers. Derivation: `math/cover-traffic.md`.
6. **iOS cannot run cover traffic in the background.** Apple sees push-wake timing. iPhone is the weakest platform for metadata.
7. **Calls hide IP addresses, but not call timing,** from a global observer (unless Maximum privacy mode is on and the app is open).
8. **Most post-quantum Rust crates are not audited yet.** Audits are budgeted in M1 to M2 and M10.
9. **Metadata protection depends on Nym's credential economics and capacity.** M4 is a go/no-go gate, and a fallback transport is specified (`09-transport.md` §7).

## 5. On inventing encryption

Enclave invents **no primitives**. Every published "unbreakable" cipher was somebody's invention, and most were broken. Enclave's novelty is limited to **composition**, and each composition is designed so that it stays secure if any one of its components holds:

| Composition | Claim | Argument | Proof plan |
|---|---|---|---|
| EnclaveCombine | IND-CCA output if any one of X448, ML-KEM-1024, or McEliece is secure, or if the PSK is secret. Binds every public key, every ciphertext, and the PSK flag. | GHP18 / KitchenSink (draft-irtf-cfrg-hybrid-kems) | CryptoVerif or EasyCrypt (M10) |
| EnclaveSeal-v1 | IND-CCA if either XChaCha20 or AES-256 is a secure stream cipher and KMAC256 is a PRF. Key-committing. Nonce hedged against RNG failure and state rollback. | Cascade of independent keystreams; encrypt-then-MAC | CryptoVerif or EasyCrypt (M10) |
| Lockstep Ratchet | Forward secrecy and post-compromise security with a full ML-KEM-1024 step every round trip | Triple Ratchet shape (Signal SPQR) | Tamarin/ProVerif adapted from Signal's public SPQR models (M2) |
| MAC-vector group authentication | Insiders cannot forge each other's messages; no transferable proof of authorship | Pairwise MAC keys delivered over PQ sessions | Bounded Tamarin model (M7) |

Proofs **add to** differential testing and never replace it. A 2026 paper (ePrint 2026/192) found bugs inside formally verified post-quantum code. Two independent external audits happen before 1.0 (`20-assurance.md`).

Product copy MUST NOT describe any of this as "unbreakable", "military-grade", or similar (`17-design.md` §8).

## 6. Notation and conventions

These conventions apply to every document in `docs/`.

| Notation | Meaning |
|---|---|
| `a ‖ b` | Byte-string concatenation |
| `u8(x)`, `u16(x)`, `u32(x)`, `u64(x)` | Unsigned big-endian integer encodings of 1, 2, 4, 8 bytes |
| `len(x)` | Length of `x` in bytes |
| `0^n` | `n` zero bytes |
| `x[a..b]` | Bytes `a` (inclusive) to `b` (exclusive) of `x` |
| `E(x)` | `encode_string(x)` from SP 800-185 (`02-cryptography.md` §2) |
| `T(x1, …, xn)` | `E(x1) ‖ … ‖ E(xn)`: the unambiguous tuple encoding |
| `KMAC256(K, X, L, S)` | SP 800-185 KMAC256 with key `K`, input `X`, output length `L` **in bits**, customization string `S` |
| `H512(x)` | SHA3-512(x) |
| `ID256(label, x)` | SHAKE256(E(label) ‖ x) truncated to 256 bits |
| `Seal(K, AD, P)` / `Open(K, AD, C)` | EnclaveSeal-v1 (`02-cryptography.md` §4) |
| `day(t)` | `floor(t / 86400)` as `u32`, where `t` is trusted Unix time in seconds (`12-servers.md` §3.5) |
| `week(t)` | `floor(t / 604800)` as `u32` |
| B, KiB, MiB | Bytes; 1 KiB = 1,024 B; 1 MiB = 1,048,576 B. "KB" and "MB" in prose are approximate decimal figures. |

Rules:

- Every multi-byte integer on the wire or in a hash input is big-endian.
- Every KMAC256 call MUST use a customization string `S` from `label-registry.md`. CI rejects any label string that appears in code but not in the registry, or that appears twice in the registry.
- Every KMAC256 input made of more than one variable-length field MUST use `T(…)`, unless the calling formula in this specification says otherwise.
- Label strings are ASCII, in the form `enclave/v1/<area>/<name>`, with no trailing NUL.
- All random bytes come from the hedged RNG (`02-cryptography.md` §6), including padding.
- Fields shown as "random" in a layout MUST be filled from the hedged RNG, never with zeros, unless marked "zero".

## 7. Glossary

| Term | Meaning |
|---|---|
| Account | An identity defined by one SLH-DSA-SHAKE-256s root key. It has up to 5 devices. |
| Root | The account's SLH-DSA-SHAKE-256s key pair, derived from the recovery secret. Signs only the manifest and root records. |
| Recovery words | 24 BIP-39 words encoding the 256-bit recovery secret. |
| Manifest | The root-signed object listing the account's devices and account-level public keys (`03-identity.md` §3). |
| Device | One installation. Has its own composite signing key and ML-KEM-1024 auth key. |
| Primary device | The device that holds the wrapped root secret. Exactly one per account. |
| Vault key | The account's Classic McEliece-8192128 key pair. Shared by the account's devices. |
| IK | The account's X448 identity key. |
| Auth ek | A device's static ML-KEM-1024 encapsulation key, used for PQ authentication of that device. |
| SPK, PQSPK | Signed prekey: X448 and ML-KEM-1024 halves. 14-day lifetime. |
| OPK, PQOPK | One-time prekey: X448 and ML-KEM-1024 halves. |
| Last-resort PQ prekey | An ML-KEM-1024 prekey used when one-time prekeys run out. 7-day lifetime. |
| EQXDH | Enclave's session-establishment protocol (`04-eqxdh.md`). |
| Braid | Adding McEliece to a session that started on two KEMs (`04-eqxdh.md` §7). |
| Lockstep Ratchet | Enclave's Triple-Ratchet-shaped message ratchet (`05-ratchet.md`). |
| PQ slot | The 3,264 B sealed region of a 1:1 envelope that carries one device pair's ML-KEM ratchet material. |
| Device slot | One of five 160 B entries in the wrap table. |
| Wrap table | The 5 device slots, each wrapping the single body key for one recipient device. |
| Lookup tag | A 128-bit tag that lets a receiver find its device slot in O(1). |
| Wire unit | The 16,384 B object that crosses the network for every request and reply. |
| Stored envelope | The 14,336 B object a server stores. |
| Poll object | The 2,048 B fixed-size read request. |
| Tick | One scheduling step of the cover-traffic scheduler. |
| Profile | One of the three global cover-traffic profiles (Foreground, Background, Maximum), plus the Bulk mode. |
| Account inbox | The single mailbox where an account receives 1:1 messages and self-copies. |
| Request inbox | The mailbox for first contact from strangers. |
| Write token | A single-use 32 B credential that authorizes one write to an account inbox. |
| Sealed request | A request encrypted to the destination server's daily X448 + ML-KEM-1024 request key. |
| Capsule | The 1,024 B notification field used for iOS previews. Random bytes when unused. |
| Off the record | Deniable mode. No signatures on messages. Default. |
| On the record | Every message carries a composite device signature. |
| Security code | The 60-digit code (or 10 words) computed from both roots (`03-identity.md` §6). Called "safety number" elsewhere; Enclave copy never uses that term. |
| Seal (UI) | The Saffron glyph that marks "confirmed by you". |
| Seal words | Three words shown on both phones after an in-person scan. |
| In-person PSK | The optical pre-shared key from a mutual QR scan (`03-identity.md` §7). |
| Epoch (group) | A period of stable group membership. Changes on every membership or device-list change. |
| Generation (group) | The index of a sender device's chain within an epoch. Changes on every lazy rotation. |
| MAC vector | 99 per-recipient-account 16 B tags on each group message. |
| Causal frontier | The last-seen message ID per group member, carried on each group message. |
| Witness | An independent party that cosigns KT tree heads. |
| Trusted time | The median of witness timestamps (`12-servers.md` §3.5). |
| Relay ticket | A sealed credential that provides the WireGuard PSK for a call relay. |
| Operator family | A declared group of servers and relays under common control. |
| Crypto-shredding | Making data unrecoverable by destroying the key that encrypts it. |
| Hedged | Mixing fresh OS randomness with a device secret and a counter, so failure of one source is survivable. |

## 8. Document map

| File | Covers | PLAN source |
|---|---|---|
| `00-overview.md` | This document | Context, decisions, limits |
| `01-threat-model.md` | Adversary NATION-2035, goals, leakage matrix, out of scope | §1 |
| `redteam-matrix.md` | RT-01 to RT-28: attack, fix, residual, spec section, test name | §1.4, §21 |
| `02-cryptography.md` | Primitives, KMAC256, EnclaveSeal-v1, EnclaveCombine, hedged RNG, composite signatures | §2.1 to §2.3 |
| `02b-key-schedule.md` | Key inventory and every derivation | §2.4 |
| `label-registry.md` | Every domain-separation label | §2 |
| `03-identity.md` | Account creation, manifest, linking, revocation, security code, in-person PSK, recovery | §3 |
| `04-eqxdh.md` | Session establishment | §4 |
| `05-ratchet.md` | Lockstep Ratchet | §5 |
| `06-multidevice.md` | Wrap table, self-copy, watermark | §6 |
| `07-groups.md` | Groups | §7 |
| `08-envelope.md` | Byte layouts: wire unit, envelopes, poll object, blobs | §8 |
| `09-transport.md` | Path, sealed requests, inboxes, tokens, polling, cover scheduler, fallback, TLS | §9 |
| `10-push.md` | Push relay and notifications | §10 |
| `11-calls.md` | Voice and video calls | §11 |
| `12-servers.md` | Server components, KT, discovery, relays, deployment | §12.1 to §12.3, §12.5 |
| `13-operators.md` | Moderation and the operator kit | §12.4 |
| `14-storage.md` | Local storage, shredding, backups, device protections | §13 |
| `15-client.md` | Process split, UI, accessibility gate, shims, media policy | §14 |
| `15b-platform-constraints.md` | Platform constraint register | §10, §13, §14, App. A |
| `16-features.md` | Feature-parity matrix | §14 |
| `17-design.md` | "Paper & Seal" design system | §15 |
| `18-a11y-i18n.md` | Accessibility and localization | §16 |
| `19-ops.md` | Releases, supply chain, crash reports, versioning | §17 |
| `20-assurance.md` | Verification, formal methods, audit scope | §21 |
| `roadmap.md` | Milestones and exit gates | §20 |
| `math/cover-traffic.md` | Data rates and latency from first principles | §9.4 |
| `math/envelope-budget.md` | Byte arithmetic behind §8 | §8 |
| `rfcs/0000-template.md` | RFC template for protocol and crypto changes | §18 |
| `../design/tokens.toml` | Design tokens (source for generated `tokens.slint`) | §15 |
| `../design/copy-glossary.md` | Copy glossary and banned words | §15.5, §15.6 |

## 9. Inconsistencies in PLAN.md found during M0

Each item below states what PLAN.md says, why it cannot be implemented exactly as written, and the resolution adopted in the specification. All of them are candidates for a PLAN.md correction RFC.

| # | PLAN.md says | Problem | Resolution | Where |
|---|---|---|---|---|
| I-1 | §8: sealed request header is 64 B and holds "op, mailbox ID 32, single-use token 32, flags". | 32 + 32 = 64 leaves no room for op and flags, and none for a PoW solution or cursor. | Header is 128 B (op 2, flags 2, reserved 4, mailbox 32, token 32, cursor 8, aux 48). Random padding shrinks from 284 B to 220 B. The unit stays 16,384 B and the envelope 14,336 B. | `08-envelope.md` §2, `math/envelope-budget.md` §2 |
| I-2 | §2.3 and elsewhere use shorthand labels (`enclave/v1/kem-extract`, `enclave/v1/kem`, `seal/nonce`, `enclave/v1/root`, `enclave/v1/msg`, `"confirm"`, `"gmbox"`, and others). | Not in the `enclave/v1/<area>/<name>` form. | Mapped to canonical labels. | `label-registry.md` §3 |
| I-3 | Fixed decisions: "XChaCha20→AES-256 cascade"; §2.3: `ChaCha20(k_c, nonce=0)`. | Two different stream ciphers named. | XChaCha20 with an all-zero 192-bit nonce, honoring the fixed decision. Equivalent security because `k_c` is unique per seal. | `02-cryptography.md` §4.3 |
| I-4 | §2.1: EnclaveSeal overhead 72 = 32 nonce + 32 tag + 8 framing; §2.3 output is `N‖c‖T` (64 B). | The 8 B framing is undefined. | 8 B header `F` (version, flags, reserved, `u32` plaintext length), bound into AD. | `02-cryptography.md` §4.2 |
| I-5 | §2.3 hedged nonce uses key `k_n`, never defined. | Undefined key. | `k_n = K`; separation by customization strings. | `02-cryptography.md` §4.3 |
| I-6 | §6: each 160 B device slot holds a lookup tag, "a sealed record" with the DR header and wrapped key, "a tag and padding". | 16 + 72 (full seal) leaves 72 B, less than the 96 B needed for a 56 B ratchet key, counters, and a 32 B wrapped key. | Slots use EnclaveSeal's detached-nonce form (nonce from the lookup-tag KMAC): 16 + 112 + 32 = 160, no padding. Rollback residual documented. | `05-ratchet.md` §6, `08-envelope.md` §5.2 |
| I-7 | §2.1: composite per draft-ietf-lamps-pq-composite-sigs; M0 pin `ed448_sig ‖ mldsa87_sig`, `ed448_pk ‖ mldsa87_pk`. | The draft serializes ML-DSA first. | Enclave's pin (Ed448 first) is normative for Enclave objects; `M'` follows the draft; draft vectors are run with components reordered. | `02-cryptography.md` §7 |
| I-8 | §3.2 lists an X448 IK per device and an account X448 IK; §2.4 lists IK as account-scoped. | Two identity keys, one unused. | One account IK, shared by devices like the vault key; device entries carry no X448 key. | `03-identity.md` §3 |
| I-9 | §9.3/§9.4: one poll per tick; "Slot 1 polls the inbox. Slot 2 rotates across groups"; Foreground text ≈5–6 s; Background ≤2 min. | With strict alternation the inbox is polled every other tick: Foreground median ≈6.5–7.5 s, Background median ≈140 s. | Foreground and Maximum alternate slots (≈5–6 s without groups due, ≈6.5–7.5 s with). Background uses slot 2 on every 4th tick (median ≈112 s). One poll per tick in all cases. | `09-transport.md` §5, `math/cover-traffic.md` §7 |
| I-10 | §9.4: Nym loop cover at 1 per 10 s "stays"; Background ≈35–40 MB/day. | Loop cover at 1 per 10 s alone is ≈41.7 MB/day. | Loop cover is 1 per 10 s in Foreground and Maximum, 1 per tick in Background (global values). | `09-transport.md` §6.3, `math/cover-traffic.md` §4 |
| I-11 | §9.4: in Maximum mode "a 1 MiB photo takes about 15 minutes". | The 1 MiB bucket (74 chunks) takes ≈3.7 min at 1 unit per 3 s; 15 min is the 4 MiB bucket (295 chunks). | UI states the time for the actual bucket. | `math/cover-traffic.md` §6 |
| I-12 | §9.5 M4 gate: bulk ≥200 KB/s; §9.4 Bulk: up to 40 packets/s. | 40 × 2,048 B ≤ 82 KB/s. | Gate measures nym-sdk raw throughput; the Bulk profile stays at 40 packets/s. | `09-transport.md` §7.2, `roadmap.md` |
| I-13 | §1.3: home server does not learn "your device count"; §12.1: directory stores manifests and bundles in the clear. | A plaintext manifest shows its device count. | Kept per §12.1; the manifest is never linked to an inbox, so the claim is narrowed to "device count behind your inbox". Encrypted directory objects are an open question. | `01-threat-model.md` §4, `12-servers.md` §2 |
| I-14 | §8 group table order: header, state hash, frontier, MAC vector, capsule, seal overhead, content. | State hash and frontier would be cleartext. | Same sizes (sum 14,336 exactly); state hash and frontier inside the body seal; MAC vector and capsule before it. | `08-envelope.md` §7 |
| I-15 | §7: rekey entries ≈72 B per device, ≈3 units for 100 × 5 devices. | A normal group envelope fits only 131 entries of 80 B, so 500 entries need 4 units. | Dedicated rekey layout (no MAC vector, frontier, or capsule): 174 entries per unit, exactly 3 units. | `07-groups.md` §5, `08-envelope.md` §8 |
| I-16 | §12.1: KT "hourly epochs"; §12.2: "10-minute to 1-hour epochs". | Two values. | Configurable 10 min to 1 h, default 1 h. | `12-servers.md` §3.1 |
| I-17 | §12.2: witness cosignature in C2SP format "with an added ML-DSA-87 cosignature"; §2.1: witness cosignatures use the Ed448 + ML-DSA-87 composite. | Two schemes. | Composite cosignature (which includes ML-DSA-87) is required; C2SP Ed25519 cosignature optional for interop. | `12-servers.md` §3.2 |
| I-18 | §4 and D2: Bob "mixes the result into the root key" in his first reply, with `KMAC(SK', "confirm")`. | Mixing at an arbitrary message desynchronizes the Double Ratchet's root chain between the two sides. | `conf` is computed from `SK'`; the RK mix (and the braid and re-root mixes) apply at a DH chain boundary announced by header flags. | `04-eqxdh.md` §6.3, `05-ratchet.md` §7.3 |
| I-19 | D5: "each message is exactly 2 units". | An EQXDH initial message per recipient device (≈3.5 KB each) cannot fit in the wrap table, and PLAN does not say how init messages travel. | Session establishment toward an account is always exactly 3 init units (2 device blocks each), in addition to the 2 steady-state units, so device count stays hidden. | `04-eqxdh.md` §6.1, `08-envelope.md` §6 |
| I-20 | §4: a signed prekey "with a composite signature" and a separate last-resort PQ prekey; "about 8 KB per device". | Two composite signatures make the bundle ≈12.7 KB. | One composite signature over the whole device bundle (SPK, PQSPK, LR): 8,025 B. | `04-eqxdh.md` §2.1 |
| I-21 | §7: one MAC tag "per other member account", padded to 99. | No entry covers the sender's own account, so a device cannot authenticate its sibling device's messages from the mailbox. | Own-account messages are shown after own-device sync confirms their IDs. | `07-groups.md` §3 |
| I-22 | §7: "Poll closes carry a tally hash signed by the poll's creator." | A signature breaks deniability in Off-the-record groups. | Signature only in On-the-record groups; MAC vector otherwise. | `07-groups.md` §7.5 |
| I-23 | §15.2 palette lists ratios for selected pairs. | Two unlisted dark-mode pairs fail AA: muted text on the outgoing bubble (2.74) and Pine-light links on it (3.09). | Derived tokens: Chalk for metadata and (underlined) links on the dark outgoing bubble. Palette values unchanged. | `17-design.md` §3, `design/tokens.toml` |

## 10. Open questions

1. Whether the PLAN.md corrections in §9 should be merged into PLAN.md now or through individual RFCs after M0 review.
2. Whether `day(t)` and `week(t)` should be anchored to a project epoch other than the Unix epoch, so that the week boundary is not Thursday 00:00 UTC.

## Implementation status (2026-09-30)

The code is normative where it and these documents disagree; each document lists its known differences under "Open questions".

| Milestone | Crates | State |
|---|---|---|
| M0 spec | `docs/`, `design/`, `legal/` | Drafted. Reconciliation with the code is complete for 02b, 03, 04, 05, 06, 09, 12, 14; the others still follow PLAN.md where the code is silent. |
| M1 crypto core | `enclave-crypto`, `enclave-wire` | Implemented; KATs and differential tests against RustCrypto, fips205, libcrux-kmac and OpenSSL pass. No external audit yet. |
| M2 protocol | `enclave-proto` | EQXDH, Lockstep ratchet, wrap table, request envelopes and state persistence implemented and tested. ProVerif models of EQXDH (secrecy, authentication, forward secrecy, the PSK "all KEMs broken" lemma), Lockstep healing and group MAC vectors, checked in CI (`formal/`); Tamarin and deniability not started. |
| M3 servers | `enclave-server`, `enclave-kt`, `enclave-tokens`, `enclave-rpc`, `enclave-sim` | Implemented; the end-to-end simulation and the KT split-view test pass. Usernames: signed claims, lookups verified against pinned logs and a witness quorum, one name per account (`12-servers.md` §3.7); the app claims and finds usernames. Gossip of head digests in message padding proves a split view (two signed heads for one epoch) to both contacts and alerts them (12 §3.8). |
| M4 network | `enclave-net` | Transport trait, dev TCP, Tor (arti) behind `tor`, cover scheduler, and the shaped transport that runs it in the client (one unit and one poll per tick, round-based sync, declared bulk windows, droppable requests; 09 §6.7). Push: sealed push tokens, server wake shaping and a relay with UnifiedPush delivery (10 §7). Nym not integrated; nothing measured on a live network (`docs/spikes/m4-network.md`). **Gate open.** |
| M5 client | `enclave-store`, `enclave-core`, `enclave-ipc`, `enclave-vault` | Sealed store, shred keyring, backups, client engine (accounts, contacts, requests, messaging, refills, restart, erase). Device linking with self-copies (03 §4.x), removing a linked device (03 §5.1), and restore from an encrypted backup (14, last section). Desktop process split into UI, vault and netd processes, with the vault sandboxed away from files and the network (15 §1.1a); message history for linked devices (03 §4.4), and the 72 h wait and veto on account changes no device co-signed (03 §8.1). A seccomp deny-list confines the vault (no new sockets) and netd (IP sockets only). Pictures are re-encoded before sending (metadata stripped) and decoded in `mediad`, a fourth process with no files, sockets or keys and a memory cap (15 §1.1a, §5). On Windows the UI and vault talk over a single-instance named pipe (compile-checked only). |
| M6 app | `enclave-design`, `enclave-app` | Desktop MVP in Slint: onboarding, message requests, 1:1 chat, contact codes and invite links, security-code check, privacy profile choice, recovery words. Runs as an offline demo or against a dev server. Usernames (claim in Settings, add by `@name@domain`), linking a new device from the welcome screen, removing linked devices, meeting in person (Seal words, bonded sessions), the account-recovery alert, reactions, edits and deletes on a selected message, disappearing-message timers, and sending and saving files. Screenshots render headlessly (`enclave-shots`, `docs/screenshots/`). App lock: an optional passphrase (at creation or later in Settings; Argon2id, 1 GiB, 4 passes; changing it rewraps the master key), an unlock screen, and Lock now. Picture previews in 1:1 chats (decoded in mediad). Backups and restore (from the words or from friends' SLIP-0039 shares) in the app (03 §8.3). Voice notes from WAV recordings, with waveforms (15 §5.2); recording and playback in the app need platform audio. Not done: Android/iOS packaging, push, the screen-reader audit. |
| M7 groups | `enclave-proto::group`, `enclave-core` | MAC vectors, three-unit rekeys over pairwise exporters, encrypted routing headers, state hash chain with admin rules, removal with a new epoch, welcomes, group introductions between strangers, persistence. Tested with 3 real clients and a 100 × 5 rotation. Adding members later (a new epoch first, so newcomers read nothing from before; welcomes and cards, with admins' cards accepted ahead of the state update). The app creates groups, shows members, and lets admins add and remove people; anyone can leave. Group invite links with admin approval (07 §9) and polls with a creator-authenticated tally (07 §7.5). The pre-rekey PQ step pings pairs that haven't stepped since the last epoch change and rotates again once they have (07 §5.2). |
| M8 calls | `enclave-calls`, `enclave-relay` | Per-call X448 + ML-KEM-1024 exchange, SFrame with the EnclaveSeal suite and 5 s key epochs, constant-rate shaping, hybrid-KEM relay tickets, two-relay forwarding (sans-I/O core plus UDP), WireGuard to relays and post-quantum relay links (RFC 0007), the media engines, direct mode and the call screens (see 11 §3.4).|
| M9 parity | `enclave-core` (`files`, `client/messages`) | Attachments (sealed chunks padded to size buckets, random chunk IDs, hash-verified download), reactions, advisory edits (24 h) and deletes for everyone, read receipts (setting), disappearing messages sealed under crypto-shred day keys with the timer starting on read. Local search over 1:1 and group messages (all words, case-insensitive; the app shows snippets). Pictures re-encoded with metadata stripped (15 §5), group polls (07 §7.5), social recovery with SLIP-0039 shares (03 §8.3), pinned messages in 1:1 and group conversations, on shared 16 B group message ids (07 §7.6), archive, pin to the top and mute for conversations (local to each device; 06 §5), blocking with token revocation (09 §3.2), note to self over the self-copy path (06 §4), contact sharing (03 §9.4), locations as coordinates only (16 §3), a per-conversation gallery of photos and files (16 §4), and reports to the reported account's server operator (13 §2). Sticker packs as sealed blobs, in 1:1 chats and groups (16 §5). Changing the recovery words as a root migration (03 §8.2). Typing indicators sent only in cover slots (16 §7). Animated pictures as AV1 clips: GIFs encoded by rav1e on the sender, posters and playback decoded by rav1d in mediad (15 §5.3). Not done: camera video, GIF search, link previews, a blinded search index, device transfer. Group messages have reactions, advisory edits (24 h), deletes for everyone, and photos and files (07 §7.6). |
| M10 assurance (part) | `enclave-fuzz`, `fuzz/`, `deny.toml` | Fuzz targets for every parser plus the server and relay request paths, run as a seeded mutation smoke test in CI and as cargo-fuzz targets. `cargo deny` passes (licenses, sources, bans, advisories) with documented exceptions. A dudect-style timing harness with a leaky control (`cargo xtask dudect`; seal rejection and ML-KEM decapsulation clean) and a reproducible-build check (`cargo xtask repro`; the relay reproduces bit for bit). Not done: formal models, CryptoVerif/EasyCrypt, ctgrind, independent rebuilders, external audits. |
| M11 launch (part) | `ops/`, `enclave-relay` binary | Dockerfile, hardened systemd unit, relay binary, daily server key rotation. Not done: store submissions, export filings, operator program (External Gates G3, G5). The Postgres backend is built (`12-servers.md` §6). |
| M12 | — | Waits on external work (HQC-256 FIPS 207, Nym PQ Sphinx). |

