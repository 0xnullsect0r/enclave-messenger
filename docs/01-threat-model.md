# Threat Model

Status: Draft (M0) · Normative

Source: PLAN.md §1. Red-team rows are in `redteam-matrix.md`. Conventions are in `00-overview.md` §6.

## 1. Assets

| Asset | Where it lives | Harm if lost |
|---|---|---|
| Message content and attachments | Endpoints; ciphertext on servers | Confidentiality |
| Who talks to whom (contact graph) | Inferred from traffic | Metadata exposure |
| Group membership | Endpoints | Metadata exposure |
| Timing, size, and frequency of communication | Network, servers | Traffic analysis |
| Device count per account | Endpoints; manifest | Fingerprinting |
| Recovery secret and root key | Primary device (wrapped), user's paper | Full account takeover |
| Device keys and ratchet state | Device vault | Impersonation, decryption of future messages until healed |
| IP address and location | Network | Deanonymization |
| Username to key binding | KT log | Man-in-the-middle at first contact |
| Release and update integrity | Build and update infrastructure | Targeted compromise |

## 2. Adversary NATION-2035

The adversary has all of these capabilities at once. Each capability is referenced by its tag in `redteam-matrix.md`.

| Tag | Capability | Details |
|---|---|---|
| A-GPO | Global passive observer | Sees every link on the internet and records everything indefinitely. |
| A-NET | Active network attacker | Injects, drops, delays, replays, and tags packets. Can block Nym or Tor, fully or selectively. |
| A-INF | Infrastructure control | Runs or coerces 50% or more of Nym nodes, and 50% or more of Enclave servers, relays, and witnesses. Any single operator MAY be malicious. |
| A-LEG | Legal reach | Subpoenas Apple, Google, and operators. Compels operators to begin logging from a given date. |
| A-QC | Quantum | A cryptographically relevant quantum computer (CRQC) is available in 2035 and is applied to every recording made before then. |
| A-DEV | Temporary device compromise | Gains full read access to a device for a bounded time, for example during a border search or a transient exploit. The compromise then ends. |
| A-SUP | Supply chain | Attacks crates, CI, app stores, and update mirrors. |
| A-SOC | Social engineering | Link phishing, lookalike usernames, malicious group admins, spam at scale. |

Assumptions the design relies on:

- At least one mix layer on a Nym route is honest (for unlinkability through the mixnet).
- At least one of X448, ML-KEM-1024, and McEliece-8192128 is secure, or the in-person PSK was not recorded.
- At least one of XChaCha20 and AES-256 is a secure stream cipher, and KMAC256 is a PRF.
- At least one of Ed448 and ML-DSA-87 is unforgeable, and SLH-DSA-SHAKE-256s is unforgeable.
- A client's pinned witness list contains at least 3 independent honest witnesses (at least 2 during beta).
- The device's OS is not persistently compromised. A-DEV compromises end.
- Hardware keystores delete keys when asked (used for crypto-shredding), except against physical attacks.

## 3. Security goals

| ID | Goal | Bound | Specified in |
|---|---|---|---|
| G-1 | Confidentiality, integrity, and authenticity of content, post-quantum at NIST Category 5 | Holds against A-QC for all recordings | `02-cryptography.md`, `04-eqxdh.md`, `05-ratchet.md` |
| G-2 | Forward secrecy | Keys for delivered messages are deleted; skipped keys expire after 7 days | `05-ratchet.md` |
| G-3 | Post-compromise security (PCS) | 1:1 heals in one round trip after an A-DEV compromise ends. Groups heal within one epoch or generation. | `05-ratchet.md` §8, `07-groups.md` §8 |
| G-4 | Deniability as configured | Off the record: no transferable proof of authorship. On the record: every message is signed. | `05-ratchet.md` §9, `07-groups.md` §3 |
| G-5 | Sender and recipient unlinkability against servers and the network | Within the leakage matrix (§4) | `09-transport.md` |
| G-6 | Hiding of size, timing, contact graph, device count, group membership | Within the leakage matrix (§4) | `08-envelope.md`, `09-transport.md` |
| G-7 | No stable identifier visible to servers | Inbox address rotates weekly; tokens single-use; push tokens re-randomized | `09-transport.md`, `10-push.md` |
| G-8 | Recovery from temporary compromise without a new account | "Secure my account" | `03-identity.md` §5 |
| G-9 | Detection of key-transparency equivocation | ≥3 witness cosignatures; gossip | `12-servers.md` §3 |
| G-10 | Detection of targeted updates | Reproducible builds, TUF, Sigsum | `19-ops.md` |

## 4. Metadata leakage matrix

This matrix is normative: an implementation that leaks more than the "Learns" column to an observer is non-conforming. Rows that depend on platform are marked.

| Observer | Learns | Does not learn |
|---|---|---|
| Your ISP | That you use Enclave (unless you use a pluggable transport). When you are online. Traffic volume, which is fixed per profile. On iOS, when the app is open. | Your contacts, recipients, or message timing (on Android and desktop in Foreground or Background profile, and in Maximum mode) |
| Tor guard | The same as your ISP | Which Nym gateway you use |
| Nym entry gateway | The Tor exit's IP, your rotating Nym identity, and Poisson-smoothed timing | Your real IP, content, or destination server |
| Mix nodes | Nothing linkable, as long as one layer is honest | |
| Your home server | Pseudonymous inbox write counts, poll timing (smoothed by the scheduler), object counts at fixed sizes. As directory host: the number of devices listed in a hosted manifest, which is not linked to any inbox (see note 1). | Who writes to you, your contacts, content, your IP, or the device count behind your inbox |
| Push relay | The push token and wake timing, quantized into 60 s windows | Your inbox, your server, or any content |
| Apple / Google | Wake timing for each device. Capsule ciphertext if previews are on (the capsule is always present, so they cannot tell whether previews are on). | Content |
| Call relay | Its own caller's IP, stream timing, and the IP of the peer relay | The other caller's IP, or content |
| Peer in a direct call | Your IP, which you opted into | |
| Group-mailbox host server | The number and timing of writes to one group mailbox address per day; that the address is a group mailbox | Who the members are, who wrote which message, content |
| Blob store | Chunk counts per bucket, fetch counts (including 1 to 3 decoys per real fetch) | Who uploaded, who fetched, content |
| KT operator | Username lookups (hidden behind the VRF from enumeration, classically only) | Who is looking up (requests arrive over the mixnet) |

Note 1. PLAN §1.3 says the home server does not learn your device count, while PLAN §12.1 stores manifests in plaintext at the directory. This specification keeps plaintext manifests (PLAN §12.1) and states the narrower claim above. See `00-overview.md` §9, I-13.

Note 2. After A-QC, recorded Sphinx and Tor traffic reveals routes (who connected to which gateway and server), but not mailbox IDs, tokens, or content, because every request is sealed to the server with X448 + ML-KEM-1024 (RT-27).

## 5. Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Enclave server | Availability (can drop, cannot read or forge) | Content, metadata, key directory honesty |
| KT server | Nothing without witness quorum | Username bindings |
| Witnesses | Honest-quorum cosignature and time (≥3 independent) | Individually |
| Nym network | Unlinkability if one layer is honest | Content, availability |
| Tor | Hiding client IP from the Nym entry gateway | Anything post-quantum |
| Push relay | Delivering wakes | Content, linking |
| Apple / Google | Delivering pushes, hosting store listings | Binary integrity (detectable via reproducible builds on non-iOS) |
| Call relay | Forwarding packets | Content, the other party's IP |
| Vault process | Holding long-term keys | |
| netd, mediad, UI processes | Their narrow roles | Key material (they never receive it) |

## 6. Out of scope

- A persistently compromised endpoint (spyware, malicious OS, malicious keyboard with full access).
- Physical, power, and electromagnetic side channels.
- Hiding the fact that someone uses Enclave (pluggable transports reduce but do not remove this).
- Screenshots or photos of the screen taken by the recipient.
- A user who hands over their recovery words.

## 7. Residual risk summary

The accepted residual for each attack is in `redteam-matrix.md`. The five largest are:

1. Long-term intersection attacks, strongest on iOS (RT-01, RT-16).
2. A small anonymity set at launch.
3. Call start and stop times without Maximum mode (RT-18).
4. Targeted app-store binaries: detectable but not preventable (RT-13).
5. Classical anonymity layer after A-QC (RT-27).

## Open questions

1. **Resolved:** manifests and bundles stay in plaintext at the directory, so the server keeps its checks: the root signature and version order of a manifest (`Server::accept_manifest`) and a listed device's signature on a publication (`Server::accept_publication`). The directory can count an account's devices; the claim is the narrower one in note 1. RFC 0009 records this, together with the one request envelope per device that session establishment sends. Encrypted directory objects would need a new RFC.
2. **Resolved:** no number is set. The client can't measure the anonymity set without telemetry, which Enclave doesn't collect (`19-ops.md` §3), so a threshold could never be checked. The small-set warning is disclosed for the whole public beta (residual 2 above, PLAN's "disclosed during beta") and is dropped at 1.0, which needs the operator program (G5) and the audits (G1). No warning text is in the app yet; it belongs in the beta release notes.
