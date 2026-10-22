# M4 gate report: Nym and Tor

Status: Report (M4) · Informative

The M4 gate (`roadmap.md`): the `09-transport.md` §7 go/no-go numbers,
measured data within ±20% of `math/cover-traffic.md`, and battery. This
report says, for each criterion, what has been measured, what CI checks
on every run or every night, and what waits on an External Gate
(`completion-plan.md`: G7 funded Nym accounts, no longer needed since
RFC 0010; G8 reference devices). The history of the spike that preceded it
follows.

Since RFC 0010 (`rfcs/0010-tor-onion-primary.md`) devices reach their
servers over Tor onion services, and the Nym mixnet is optional and off by
default. The Nym rows below apply to the optional mixnet. The onion route's
numbers are in `09-transport.md` §6.3 and §6.7 (CI `federation-e2e-onion`,
nightly `onion-live` in `live.yml`).

## Verdict per criterion

| Criterion | Threshold | Measured | Checked by | Status |
|---|---|---|---|---|
| nym-sdk memory | ≤ 150 MB on Android and iOS | 26 MiB peak for an ingress-role client and a device client together (desktop Linux, release build, local mixnet) | `live_bench` (`peak_rss_kib_both_clients`), every CI run and nightly | Met on desktop; phones wait on G8 |
| Cold connect | ≤ 5 s | 0.05 s (device) and 0.09 s (ingress) on the local mixnet | `live_bench` `connect_ms`; live networks through Tor nightly | Met locally; live numbers only with a funded account (G7, no longer needed since RFC 0010) |
| Raw throughput | ≥ 200 KB/s of nym-sdk raw throughput (`roadmap.md` note 1) | 726 KiB/s unpaced; the Bulk profile's paced window 55 KiB/s, at its 40 packets/s cap | `live_bench` `raw` and `bulk` | Met locally; live networks only with a funded account (G7, no longer needed) |
| Round trips | — (informative) | p50 219 ms, p95 279 ms, none of 20 lost | `live_bench` `round_trips` | Measured |
| Credential path | Works end to end | A device's ticketbook bought through the credential gate (Equi-X, Privacy Pass, the device's own ecash keys) over Tor, imported into its client; CI run 37870818145 ("50 zk-nym tickets in hand") | `federation-e2e-localnet` on every run; spending against checking gateways in the sandbox nightly | Met in CI; live spending only with a funded account (G7, no longer needed) |
| Cost | ≤ $1 per user per month | Five books a month (expiry decides, `math/cover-traffic.md` §11): met while a book costs ≤ $0.20 | `live.yml` `nym-bench`: deposit × NYM price, fails above $1 on mainnet | Only with the optional mixnet; G7 no longer needed (RFC 0010). With the default onion route there is no recurring cost |
| Tor → gateway | Works | Gateway WebSocket dialled through `enclave-tord` (dev-direct in CI, real Tor nightly) | `federation-e2e-localnet` (through tord), `nym-bench` through real Tor | Met with dev-direct; live only with a funded account (G7, no longer needed) |
| Data per profile | ±20% of the model | Foreground 16.2–16.6 packets a tick against 16.3; 73–76 MB/h at the WebSocket level, ≈80 MB/h with Tor | `gen.sh shape` + `pcap-check.py` on every run | Met for Foreground (and so Maximum); Background scales by 3/120 |
| Poisson off, loop cover on | A supported configuration | Runs that way on the local mixnet and in CI | — | Confirm with Nym on live networks, if the optional mixnet is funded (G7, no longer needed) |
| Battery | ≤ 5 percentage points an hour above idle, Foreground | — | — | Waits on G8 (reference phones) |

Nothing measured so far fails a threshold. The rows marked G7 needed the
sandbox and mainnet accounts the nightly reads (`NYM_SANDBOX_MNEMONIC`,
`NYM_MAINNET_MNEMONIC`) to be funded, and then a token bill per stack and
per user every month, with nobody to pay it. So the roadmap's rule was
applied and the transport revisited in an RFC: RFC 0010 makes Tor onion
services the primary route and the Nym mixnet optional, and G7 is no longer
needed. The rows marked G8 still need `live_bench` (for the optional
mixnet) and a battery run (for every route) on the reference phones once
the mobile builds exist (A1, I1).

**Post-quantum Nym (G13, only with the optional mixnet).** nym-sdk 1.21.5 offers Sphinx and Outfox; both
use X25519 only (`nym-outfox` has no KEM), so there is no post-quantum
packet format to adopt yet. The point to switch is the client's packet
type in `nym/enclave-nym-sdk` (`build`), with the packet counts the pacing
uses (`POLL_PACKETS`, `UNIT_PACKETS`) re-measured by `localnet_roundtrip`.

## History: the spike (2026-09-30 to 2026-10-09)

### Environment limits

The build sandbox allows outbound HTTPS only, through a proxy. Raw TCP to
arbitrary hosts is blocked, so it cannot reach Tor relays (ORPort) or Nym
gateways (WSS on 9000/443 to gateway IPs). **No live Tor or Nym traffic was
exchanged.** Everything below is build-level evidence plus in-process tests.

### Findings

| Item | Result | Evidence |
|---|---|---|
| `nym-sdk` 1.21.6 (latest) | **Does not resolve** on crates.io: `nym-client-core-gateways-storage` 1.22.0 requires `nym-gateway-client` ^1.22.0, which conflicts with the 1.21.6 set | `cargo generate-lockfile` |
| `nym-sdk` 1.21.5 | Resolves and builds: 5 min 41 s cold build, 3.0 GB target directory | probe build |
| Native code under `nym-sdk` | `aws-lc-sys`, `ring` (several versions), `libsqlite3-sys`, `zstd-sys` | `cargo tree` |
| `arti-client` 0.46 (tokio + rustls + onion-service-client + compression) | Builds in about 1.5 min | probe build and `enclave-net --features tor` |
| Native code under `arti-client` | `zstd-sys`, `libsqlite3-sys` (and `openssl-sys` only with the default `native-tls` feature, which Enclave disables) | `cargo tree` |
| Tor transport code | `TorTransport` implemented against arti (onion-service addressing, same framing as the dev transport); compiles | `crates/enclave-net/src/transport.rs` |
| Nym transport code | Written (2026-10-02): `NymTransport`, `enclave-ingress`, `enclave-nym-sdk`; tested end to end over an in-process mixnet; live gateways still untested | `crates/enclave-ingress/tests/mixnet.rs` |
| Cover-traffic scheduler | Implemented; tick timing and poll pattern independent of real traffic (KS test, α = 0.01); real and cover units identical in size and byte distribution | `crates/enclave-net/tests/shape.rs` |

### Consequences for the plan

1. **Pin `nym-sdk` = 1.21.5** until upstream publishes a consistent set, and
   track the regression upstream.
2. **Declared C exceptions grow** (docs/PLAN.md §22): zstd, SQLite, aws-lc and
   ring arrive transitively through arti and nym-sdk. They run in the `netd`
   process, which never holds long-term keys (process split, §14).
3. **Nym over Tor** needed nym-sdk to accept a custom connector for its gateway
   connection. Resolved in N2.4 with a small nym-gateway-client patch
   (`set_stream_connector`) and `enclave-tord`, a separate arti process
   serving a loopback SOCKS5 port; see item d and `09-transport.md` §1.

### N0 answers

| # | Question | Answer |
|---|---|---|
| a | Does the nym-sdk version set build? | Yes, in its own workspace (`nym/`), with every `nym-*` crate pinned to 1.21.5: nym-sdk 1.21.5 no longer resolves on its own (1.22.0 helper crates were published under it and don't compile with it), and its SQLite (`sqlx`, libsqlite3-sys 0.30) can't share a lockfile with arti's (rusqlite, libsqlite3-sys 0.34). Linux builds in CI; the other targets come with A1, I1 and D1. |
| b | A fresh sender tag per request? | Not upstream: nym-client-core keeps one tag per recipient for the client's life. Patched (`third_party/PATCHES.md`): a fresh tag per message. |
| c | Poisson off, loop cover on? | The configuration has both switches (`disable_main_poisson_packet_distribution`, `loop_cover_traffic_average_delay`); whether Nym supports that setting on mainnet is still to confirm live. |
| d | A custom gateway connector (for Tor under Nym)? | **Yes, with a patch.** Neither `custom_gateway_transceiver` (needs a custom gateway registration, skips authentication) nor `connect_to_mixnet_via_socks5` (proxies the other way) works. A small patch to nym-gateway-client (`set_stream_connector`) lets the caller open the gateway stream; `enclave-nymd` opens it through `enclave-tord`'s SOCKS5 port (arti in its own process). Verified on the local mixnet and in CI (`09-transport.md` §1). |
| e | Can the server refuse "more SURBs" round trips? | Yes, with two settings: `maximum_reply_surbs_rerequests = 0`, and no reply blocks held in reserve (`minimum_reply_surb_storage_threshold = 0`; the default keeps 10 back for asking, which left a 16 KB reply 9 packets short and made the ingress ask anyway). The reply-block store takes those thresholds when it is created (`initialise_persistent_storage(&debug)`, not `new_with_default_storage`). Every request carries 12 reply blocks: the 11 regular packets nym-sphinx splits a 16,406 B reply into, plus one. Checked on the local mixnet. |
| f | A local mixnet in Docker? | Yes, with a small patch (`ci/nym-localnet/offline.patch`): nym-node 1.21.5 wants a chain at start (network monitors, chain watcher, initial topology) and ignores its LP bind-address flags. Three mix nodes and a gateway run on 127.0.0.1 (`run-local.sh`) or in Docker (`compose.localnet.yml`); a static file stands in for nym-api. Measured: connect ≈0.2 s; request plus full reply ≈0.37–0.42 s. |
| g | Packets per unit and poll | A unit is 11 regular packets, a poll with its 12 reply blocks 5, a reply 11 (`localnet_roundtrip` fails if they change). On the wire (`localnet_ticks` and `ci/federation/pcap-check.py`): 16.3 packets up a tick with loop cover and probes, frames of 2,452 B, 150 ms apart, the same idle and busy; 73 MB/h in Foreground at the WebSocket level, ≈80 MB/h with Tor (`math/cover-traffic.md` §10). CI checks the shape on every run (`09-transport.md` §6.7). |
| h | In-memory storage | Devices use nym-sdk's ephemeral (in-memory) storage; nymd confines itself with nothing writable, and the round trip works that way. The ingress keeps its identity and reply store on disk. |
| i | Sandbox credentials | The device path is built and runs end to end in CI against a stand-in proxy (N3, `09-transport.md` §7): Privacy Pass tokens from the credential gate, a ticketbook whose ecash keys never leave nymd, imported into the running client. Spending against the sandbox's gateways needs a funded account (External Gate G7, no longer needed since RFC 0010); `live.yml` runs `live_bench` there nightly when the `NYM_SANDBOX_MNEMONIC` secret exists. |

The TLS under nym's gateway connection was on rustls 0.21; the patched copies use tungstenite 0.24 on rustls 0.23.

### How the numbers are taken

`live_bench` (`nym/enclave-nym-sdk/examples/live_bench.rs`) measures the
mixnet path from one process: cold connect of an ingress-role client and a
device client, 20 round trips (a poll with its reply blocks, answered with a
unit), 40 units one way in a bulk window, peak resident memory, tickets
spent, and the ecash contract's ticketbook deposit. It runs on the local
mixnet in every CI run (`gen.sh bench`, job summary and artifact), and on
the sandbox nightly and mainnet weekly through real Tor (`live.yml`, when a funded account is configured),
which also turns the deposit into dollars per user per month and fails
above $1 on mainnet. The table above is a release build on the local mixnet (2026-10-09); a
debug build measured connect 0.07–0.19 s, p50 432 ms and 45 MiB.

