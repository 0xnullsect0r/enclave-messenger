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
| A-NET | Active network attacker | Injects, drops, delays, replays, and tags packets. Can block Tor (bridges help: obfs4, Snowflake, WebTunnel, `09-transport.md` §7), or the optional Nym mixnet, fully or selectively. |
| A-INF | Infrastructure control | Runs or coerces a large share of Tor relays (enough to hold both ends of many circuits and match their timing, §4), 50% or more of Nym nodes (with the optional mixnet), and 50% or more of Enclave servers, relays, and witnesses. Any single operator MAY be malicious. |
| A-LEG | Legal reach | Subpoenas Apple, Google, and operators. Compels operators to begin logging from a given date. |
| A-QC | Quantum | A cryptographically relevant quantum computer (CRQC) is available in 2035 and is applied to every recording made before then. |
| A-DEV | Temporary device compromise | Gains full read access to a device for a bounded time, for example during a border search or a transient exploit. The compromise then ends. |
| A-SUP | Supply chain | Attacks crates, CI, app stores, and update mirrors. |
| A-SOC | Social engineering | Link phishing, lookalike usernames, malicious group admins, spam at scale. |

Assumptions the design relies on:

- At least one mix layer on a Nym route is honest (for unlinkability through the optional mixnet).
- Over Tor, Tor's own assumptions: no one watches both a device's link to its guard and the server's link to Tor. Someone who does can match timing (§4).
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
| Tor guard | The same as your ISP: that you use Tor, when you are online, and the traffic volume, which is fixed per profile | Which server you talk to (it is behind an onion service), or, with the optional mixnet, which Nym gateway you use |
| Nym entry gateway (only with the optional mixnet) | The Tor exit's IP, your rotating Nym identity, and Poisson-smoothed timing | Your real IP, content, or destination server |
| Mix nodes (only with the optional mixnet) | Nothing linkable, as long as one layer is honest | |
| Your home server | Pseudonymous inbox write counts, poll timing (smoothed by the scheduler), object counts at fixed sizes. As directory host: the number of devices listed in a hosted manifest, which is not linked to any inbox (see note 1). Nothing new from requests arriving over its onion service: every client is a Tor circuit. | Who writes to you, your contacts, content, your IP, or the device count behind your inbox |
| Push relay | The push token and wake timing, quantized into 60 s windows | Your inbox, your server (wakes arrive from Tor, from anonymous push egress clients), or any content |
| Apple / Google | Wake timing for each device. Capsule ciphertext if previews are on (the capsule is always present, so they cannot tell whether previews are on). | Content |
| Call relay | Its own caller's IP, stream timing, and the IP of the peer relay | The other caller's IP, or content |
| Peer in a direct call | Your IP, which you opted into | |
| Group-mailbox host server | The number and timing of writes to one group mailbox address per day; that the address is a group mailbox | Who the members are, who wrote which message, content |
| Blob store | Chunk counts per bucket, fetch counts (including 1 to 3 decoys per real fetch) | Who uploaded, who fetched, content |
| An observer of both your guard link and the server (a global passive observer, or your Tor guard working with the server's operator; onion route only) | Timing correlation: that your device is online and talking to that server. Tor relays forward cells at once, without mixing (RFC 0010). | When you send a message: constant-rate shaping makes idle and busy the same on the wire. Content or your contacts. (The optional mixnet's delays and cover defeat the correlation.) |
| KT operator | Username lookups (hidden behind the VRF from enumeration, classically only) | Who is looking up (requests arrive over Tor, or the optional mixnet) |

Note 1. PLAN §1.3 says the home server does not learn your device count, while PLAN §12.1 stores manifests in plaintext at the directory. This specification keeps plaintext manifests (PLAN §12.1) and states the narrower claim above. See `00-overview.md` §9, I-13.

Note 2. After A-QC, recorded Tor traffic (Tor's circuits use X25519), and Sphinx traffic with the optional mixnet, reveals routes (which server a device talked to; with the mixnet, which gateway too), but not mailbox IDs, tokens, or content, because every request is sealed to the server with X448 + ML-KEM-1024 (RT-27).

## 5. Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Enclave server | Availability (can drop, cannot read or forge) | Content, metadata, key directory honesty |
| KT server | Nothing without witness quorum | Username bindings |
| Witnesses | Honest-quorum cosignature and time (≥3 independent) | Individually |
| Nym network (optional) | Unlinkability if one layer is honest | Content, availability |
| Tor | Hiding client IP and server location (and, with the optional mixnet, the client IP from the Nym entry gateway) | Anything post-quantum; timing against an observer of both ends |
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

The accepted residual for each attack is in `redteam-matrix.md`. The six largest are:

1. Long-term intersection attacks, strongest on iOS (RT-01, RT-16).
2. A small anonymity set at launch.
3. Call start and stop times without Maximum mode (RT-18).
4. Targeted app-store binaries: detectable but not preventable (RT-13).
5. Classical anonymity layer after A-QC (RT-27).
6. Timing correlation over Tor by an observer of both ends, limited by constant-rate shaping to "online and talking to that server" (§4, RFC 0010).

## Open questions

1. **Resolved:** manifests and bundles stay in plaintext at the directory, so the server keeps its checks: the root signature and version order of a manifest (`Server::accept_manifest`) and a listed device's signature on a publication (`Server::accept_publication`). The directory can count an account's devices; the claim is the narrower one in note 1. RFC 0009 records this, together with the one request envelope per device that session establishment sends. Encrypted directory objects would need a new RFC.
2. **Resolved:** no number is set. The client can't measure the anonymity set without telemetry, which Enclave doesn't collect (`19-ops.md` §3), so a threshold could never be checked. The small-set warning is disclosed for the whole public beta (residual 2 above, PLAN's "disclosed during beta") and is dropped at 1.0, which needs the operator program (G5) and the audits (G1). No warning text is in the app yet; it belongs in the beta release notes.
