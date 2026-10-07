# Transport and Metadata

Status: Draft (M0, reconciled with the M3–M4 code) · Normative

Source: PLAN.md §9 (D7, D10). Crates: `enclave-rpc` (sealed requests, API payloads), `enclave-net` (transports, scheduler), `enclave-server`, `enclave-tokens`. Layouts: `08-envelope.md`. Rates: `math/cover-traffic.md`. Where this document and the code disagree, the code is normative.

## 1. Path

```
Client → Tor (embedded arti) → Nym entry gateway (WSS, port 443) → 3 mix layers → exit gateway
       → the destination Enclave server's own Nym client
```

- Writes go to the recipient's server. Polls go to your own server. There is no server-to-server relay.
- Every request uses fresh single-use SURBs and a fresh sender tag. Replies return over those SURBs.
- Servers have no clearnet message API.
- Tor always sits in front of Nym. It hides the client IP from the entry gateway and provides pluggable transports.

All transports implement one trait, `enclave_net::transport::Transport`: `exchange(server, request) -> reply` and `server_key(server)`. State of the implementations:

| Transport | Status |
|---|---|
| `TcpTransport` | Implemented. Development only: frames `u32(len) ‖ bytes` over TCP to the `enclave-server` dev binary. A zero-length frame asks for the server's current request key, returned as `u32(key_id) ‖ X448 (56) ‖ ML-KEM ek (1,568)`. |
| `TorTransport` | Implemented behind the `tor` feature (arti 0.46, embedded): same framing to a server's onion service. Compiles; not exercised against the live network. |
| `NymTransport` | Implemented behind the `nym` feature over any `enclave_nym::MixnetDriver` (below). |

**Over Nym, as implemented** (`enclave-nym`, `enclave-ingress`, `nym/`):
- A request crosses the mixnet as a mixframe: `u8(1) ‖ u8 kind ‖ req_id (16) ‖ body`, where kind 1 carries a sealed unit (16,384 B), kind 2 a sealed poll (2,048 B), kind 3 asks for the key bundle and is padded like a poll, so it can't be told from one. The reply is `u8(1) ‖ u8 status ‖ req_id ‖ u32 len ‖ data`, zero-padded to 16,406 B whatever it carries. `req_id` is random per request and only matches the reply at the client.
- `NymTransport` sends each request to the server's Nym address (its descriptor's `nym_address`) with enough single-use reply blocks for the whole reply (12: the 11 regular packets nym-sphinx splits a 16,406 B reply into, each carrying ≈1.6 KB after its acknowledgement, key digest and fragment header, plus one spare; `surbs_for` asks nym-sphinx rather than estimating), waits for the reply with that id (60 s by default), and otherwise fails as unreachable; the caller seals anew to retry. Replies arriving out of order reach their requests.
- Each server's stack runs `enclave-ingress`, a Nym client with a persistent identity that writes its address to `public/ingress.addr` (the server then publishes it in its descriptor), hands each request to the server over the internal network with the server's own framing, and answers over the reply blocks. It drops anything that doesn't parse or has no reply blocks, and keeps only aggregate counters.
- Push wakes cross the mixnet one way, from a stack's push egress to the push relay's ingress (`enclave-ingress forward` and `oneway`, `10-push.md` §7).
- nym-sdk keeps one sender tag per recipient for a client's lifetime, which would let a server link every request a device sends it; Enclave's copy of nym-client-core (`third_party/PATCHES.md`) uses a fresh tag per message, and the ingress never asks for more reply blocks (`maximum_reply_surbs_rerequests = 0`) and keeps none in reserve for asking (nym-sdk's default holds back 10, which left a reply short and made the ingress ask a device that can't answer: its tag is new). The reply-block store takes those thresholds when it is created, so the ingress builds it from its own configuration. Clients turn off Nym's Poisson stream (Enclave's scheduler paces) and send loop cover every 10 s.
- **Local mixnet** (`ci/nym-localnet`, X16 tier 2): nym-node at the release Enclave's crates pin (1.21.5), with `offline.patch` so it runs with no blockchain (with `ENCLAVE_NYM_OFFLINE=1` it skips the network-monitor and chain-watcher queries and the initial network fetch; `--local` lets it route between private addresses; it also applies the LP bind-address flags upstream parses but ignores, for hosts without IPv6). A static stand-in answers the one nym-api call clients make (key-rotation information), and `topology.py` builds the fixed topology from the nodes' own HTTP APIs with key rotation id 0, so nodes try both sphinx keys. Clients join it with `--env` and `ENCLAVE_NYM_TOPOLOGY`/`ENCLAVE_NYM_API` (`Network::Local`). `run-local.sh` runs three mix nodes and a gateway on 127.0.0.1; `ops/compose/compose.localnet.yml` runs them in Docker for CI (`gen.sh TRANSPORT=nym`, job `federation-e2e-localnet`). Measured on the local mixnet (example `localnet_roundtrip`): both clients connect in ≈0.2 s, and a poll-sized request with its full 16,406 B reply takes ≈0.37–0.42 s round trip with nym-sdk's default mixing delays.
- nym-sdk and arti need different SQLite versions, so they can't be in one Cargo lockfile: the nym-sdk driver (`enclave-nym-sdk`) and the `enclave-ingress` binary live in the separate `nym/` workspace, with every `nym-*` crate pinned to 1.21.5. Tests: `through_the_mixnet_to_a_server` and `a_dead_server_is_reported` run a client, the in-process fake mixnet (loss, delay, reordering) and the ingress against a real server.
- On a device the mixnet client is `enclave-nymd` (also in `nym/`): netd starts it next to itself before confining itself and drives it over its stdin and stdout (`enclave_nym::pipe`: frames `u32 len ‖ body`; to nymd `1 ‖ u16 len ‖ address ‖ u32 reply_len ‖ data` to send and `2 ‖ tag ‖ data` to reply; from nymd `1 ‖ address` once connected, then `2 ‖ has_tag ‖ [tag] ‖ data` per message). nymd holds no Enclave keys and sees only sealed requests; it uses a fresh identity each start. netd routes each server by its route: `--server ID=nym:ADDRESS` over the mixnet, `--server ID=HOST:PORT` over development TCP. The vault passes the routes it starts with and sends routes it learns later (`NetRequest::SetRoute`): every listed server's ingress address when it accepts a server list, and a server's address from each descriptor it accepts (which replaces the list's). netd starts nymd only when a Nym route is given at start, and ignores later Nym routes without it. With only Nym routes netd also refuses itself every socket (seccomp `Vault` profile, Landlock TCP denial) and ignores TCP routes; nymd confines itself before connecting (Landlock: read-only resolver configuration and CA certificates, nothing writable; seccomp: IPv4 and IPv6 sockets only, no programs). `--report` prints what took effect. `--nym-env` (vault and netd) takes the network from `NYM_*` variables, for a local mixnet or the sandbox. Tests: `through_a_pipe` (enclave-nym), `carries_requests_over_nym` and `learns_nym_routes` (netd with a stand-in nymd, `crates/enclave-netd/examples/fake_nymd.rs`, holding the fake mixnet and a real ingress), `nym_routes_from_the_list_and_descriptors` (enclave-core), `routes_parse_and_are_learned` (enclave-net).
- **Tor under Nym (as implemented).** On a device the mixnet client reaches its entry gateway only through Tor, so the gateway sees a Tor exit and never the device's address. nym-sdk can't link arti into the same process (the SQLite clash above), so `enclave-tord`, a small process in the main workspace, runs arti and serves a SOCKS5 port on loopback.
  - **The port.** It answers only `CONNECT`, only with the user/password secret netd gives it on its stdin (32 random bytes), and resolves names at the Tor exit. It confines itself: IP sockets only, and the filesystem limited to its state directory and what TLS needs.
  - **Startup.** netd starts tord with `--tor DIR` (the vault passes `<profile>/tor` whenever the build ships tord), waits up to 5 minutes for Tor to bootstrap, then starts nymd with the port and secret in its environment. Without Tor netd doesn't start the mixnet client at all.
  - **The gateway connection.** nymd hands nym-gateway-client a connector (our patch, `third_party/PATCHES.md`), so the WSS connection is a SOCKS5 `CONNECT` to the gateway's host. There is no local DNS, and TLS still checks the gateway's name.
  - **nym-api.** Requests to nym-api go through the same port: reqwest reads the `socks5h://` proxy variables netd sets, and Enclave enables reqwest's `socks` feature.
  - **Lifetime.** tord exits when netd closes its stdin.
  - **Tests.** `enclave-tord`'s SOCKS tests: the secret is required, and `BIND`, `UDP ASSOCIATE` and no-auth are refused. On the local mixnet, `localnet_roundtrip` through `enclave-tord --direct` (a test-only build that dials without Tor) sends every gateway connection and every nym-api request through the port, including after a gateway switch. CI's `federation-e2e-localnet` runs the whole end-to-end that way. Workflow `nym-live.yml` (nightly, non-blocking) bootstraps real Tor and checks that a request comes out of a Tor exit (`check.torproject.org`).

## 2. Sealed requests

Every request (wire unit or poll object) is sealed end to end to the destination server's **daily** X448 + ML-KEM-1024 key (`enclave-rpc`). Nym's Sphinx layer is classical, so this seal is what keeps mailbox addresses and tokens post-quantum confidential (RT-27).

### 2.1 Server request keys

- The server generates one key pair per day; `key_id` is the Unix day number (`u32`).
- `Server::rotate(day)` adds the new key and keeps at most two: the new one and the previous one. Older keys are deleted, which gives forward secrecy for request metadata. The previous day's key therefore stays until the next rotation.
- Clients learn the current public key from the server: a zero-length request returns a `KeyBundle`, the server's identity key and certificates for today's and tomorrow's keys, which the client checks against the server id it expects (`12-servers.md` §4.2).

### 2.2 Client side

```
seal_request(server_key, header, envelope):                 # envelope is 14,336 B
    (eph_sk, eph_pk) = fresh X448 pair
    (ct, ss_m) = ML-KEM-1024.Encaps(server.mlkem)
    ss = EnclaveCombine(TwoKem,
             secrets = [X448(eph_sk, server.x448), ss_m],
             public  = [eph_pk, ct, server.x448, server.mlkem, u32(key_id)],
             psk = none)
    k_req   = KMAC256(ss, "", 256, "enclave/v1/rpc/request")
    k_reply = KMAC256(ss, "", 256, "enclave/v1/rpc/reply")
    sealed  = seal(k_req, AD = u32(key_id), header (72) ‖ envelope (14,336))       # 14,472 B
    unit    = u16(1) ‖ u16(1) ‖ eph_pk ‖ ct ‖ sealed ‖ random padding (284)        # 16,384 B
    keep k_reply for the reply

seal_poll(server_key, header):                               # same, without the envelope
    sealed = seal(k_req, AD = u32(key_id), header)           # 136 B
    poll   = u16(1) ‖ u16(1) ‖ eph_pk ‖ ct ‖ sealed ‖ random padding (284)          # 2,048 B
```

The key ID is bound into the EnclaveCombine public items and used as the seal's AD, but it is **not on the wire**: one more cleartext field would be one more linkable value.

### 2.3 Server side

```
open_request(held keys, newest first, bytes):
    require len(bytes) in {16,384, 2,048}; version 1; suite 1              else fail
    for each held key:
        ss = EnclaveCombine(…) with the server's secrets; k_req = …
        pt = open(k_req, u32(key_id), sealed)                               else try the next key
        header = RequestHeader::decode(pt[0..72])                           else try the next key
        return (header, envelope = pt[72..] or empty for a poll, exchange keys)
    fail
```

A request that fails to open gets 16,384 random bytes as its reply. An opened request is dispatched (`12-servers.md` §1) and answered with `seal(k_reply, "reply", reply header ‖ reply envelope)` plus random padding (`08-envelope.md` §3).

**Replay cache.** Every request that opens is first looked up in a replay cache, keyed by `u32(key_id) ‖ SHAKE256("enclave/v1/net/replay-id" ‖ u32(key_id) ‖ eph_pk ‖ ct)`. The ephemeral key and KEM ciphertext are fresh for every sealing, so two sealings of the same request are two requests, and the same bytes sent twice are one. A request already in the cache is answered like one that fails to open (16,384 random bytes) and counted in `Stats::replays`; nothing is applied. The cache is a redb table (`replays`, schema 4), so a replay after a restart is refused too, and its entries go with the key that opened them: when a key is deleted (`Server::install_key`), and at start for keys deleted while the server was down. Test: `a_request_is_processed_once` (`crates/enclave-server/tests/replay.rs`). A server that can't record the id refuses the request (fail closed). The record is committed without its own sync (`Db::write_lazy`: redb `Durability::None`, PostgreSQL `synchronous_commit off`) and becomes durable with the request's own durable commit, so a request costs one sync; a crash can forget only the ids of requests that wrote nothing durable (polls, cover, refusals), whose replay changes nothing.

## 3. Inboxes, read credentials, write tokens (D7)

### 3.1 Inbox creation

An inbox is created with `RegisterTokens` and the `CREATE` flag (`08-envelope.md` §2.2):

- `mailbox` is the inbox address, 32 bytes chosen at random by the owner.
- `token` is the **owner secret**, 32 random bytes kept by the owner.
- The server stores `credential_hash(owner_secret)` and `credential_hash(read_credential(owner_secret))`, and refuses to create an address that exists (`Denied`).
- With `REQUEST_INBOX` also set, the inbox is a request inbox (§4).

```
read_credential(owner) = KMAC256(owner, "read", 256, "enclave/v1/rpc/read-credential")[0..24]    # 24 B
credential_hash(x)     = KMAC256(x, "", 256, "enclave/v1/rpc/credential-hash")
```

**Proof of work.** Creating an inbox costs an Equi-X proof over `"inbox-create" ‖ mailbox ‖ u64(day)` (`api::pow_context_inbox`) at the server's `effort_inbox` (default 16, published in the descriptor policy). The 32-byte proof is the framed payload of the creating `RegisterTokens`. The server takes today's or yesterday's day (a client near midnight) and checks it before anything else, so a missing or wrong proof is `Pow` whether or not the address exists. The client climbs the effort ladder until the server accepts (`Rpc::create_inbox`, used at account creation and when moving server). Test: `a_request_is_processed_once` (no proof, another address's proof and one from two days ago are refused; yesterday's is accepted).

Weekly address rotation from an inbox seed and daily address-bound read credentials are milestone P1 (`docs/completion.md`; the reserved labels are in `label-registry.md` §3.3). Until then the address and the read credential are static for the life of the inbox, and the server sees the owner secret whenever the owner creates the inbox or registers tokens.

### 3.2 Reading

- `Poll`: `token = read_credential ‖ u64(cursor)`. The server checks `credential_hash(token[0..24])` and returns the first envelope with a sequence number above the cursor, with `FOUND`, its sequence number in the reply token, and `MORE` if another follows. With nothing to return it replies `Ok` with an empty payload.
- `Ack`: `token = read_credential ‖ u64(watermark)`. The server deletes every envelope with sequence number ≤ watermark.
- A wrong credential gets `Denied`.

### 3.3 Write tokens

```
k_contact = HedgedRng.fill("tokens/contact-key", 32)                  # per contact, kept by the inbox owner
t_i       = KMAC256(k_contact, u64(i), 256, "enclave/v1/tokens/write")   # i = 0, 1, 2, …
h_i       = KMAC256(t_i, "", 256, "enclave/v1/tokens/hash")              # what the server stores
```

**As implemented: a shared pool** (`enclave-core/src/client/tokens.rs`). Registering one contact's tokens as their own batch, as the derivation above suggests, lets the server group writes by sender: every token of a batch that is ever burned belongs to the same person (the dummies never are). The client therefore registers tokens ahead of time in batches that later go to different contacts:

- **Pool.** Tokens are 32 random bytes from the hedged RNG (`core/write-token`). The owner registers 64 at a time (more if one hand-out needs more), shuffled with 16 dummies, and keeps the registered-but-unissued tokens as a per-device pool in the sealed store. The pool is never in a backup, and a restore clears it, so no token is handed out twice.
- **Issue.** A contact who needs tokens gets the oldest ones from the pool, inside the encrypted session; the pool is refilled first if it runs short. The owner keeps the hashes of the last 128 tokens each contact was given, for revocation.
- **Register.** `RegisterTokens` without `CREATE`, `token` = owner secret, payload = the hashes. `registration_batch(real, dummies)` appends `dummies` random 32 B values and shuffles the batch (Fisher-Yates with hedged randomness). The server checks the owner secret, that the payload length is a multiple of 32, and the per-inbox quota of 4,096 unspent hashes (`Quota`). One frame carries at most 447 hashes.

Test `token_batches_mix_contacts` plays a server that logs every batch and every burn, and checks that two contacts' writes used tokens from the same batch. `TokenIssuer` (the per-contact derivation) remains in `enclave-tokens` but the client no longer uses it. Residual: a batch still bounds a time window, and a contact who is the only one given tokens from a batch before it is used up could be grouped by it; the pool's order makes that rare but not impossible for an account with one active contact.
- **Use.** A `Write` carries `t_i` in the header's token field. The server computes `h_i`, accepts the write only if `h_i` is registered, and deletes it (burns it). Reuse gets `Denied` (RT-24). The server cannot tell which contact a token belongs to, and two writes by one contact are unlinkable.
- Hashing is the only cryptography in a token, so nothing here weakens under a quantum computer.

- **Block** (`enclave-core/src/client/blocks.rs`, RT-25). The owner keeps the hashes of the last 128 tokens each contact was given (above). Blocking someone sends `RegisterTokens` with `FLAG_REVOKE` and those hashes (more than anyone holds: 32 outstanding plus a refill in flight), so their writes to the inbox fail with `Denied`; they get no refills, and they are not told. Anything that still arrives from them is dropped without a trace: messages already in the inbox, a new greeting through the request inbox (its prekey is spent and the replay marker kept, but no contact or session is stored), and their messages, reactions and pins in groups we share (their group state updates still apply, so the membership stays consistent). We can't send to them either. Unblocking sends 32 fresh tokens. The app offers **Block** on a message request and in the conversation sheet, and a blocked conversation shows a notice with **Unblock** instead of the composer. Test `block_and_unblock` checks that the server refuses the blocked contact's write.

Not implemented yet: returning the burned token to the owner as a session hint, refill control messages, weekly re-registration under a new address, token hashes bound to the address, and self tokens.

## 4. Request inbox

- Created like an account inbox with `CREATE | REQUEST_INBOX`. Its address is in the account manifest (`request_inbox`, `03-identity.md` §3).
- `WriteRequest` needs an Equi-X proof of work in the header's token field over `"request-inbox" ‖ mailbox ‖ u64(day) ‖ SHA3-512(envelope region)` at the server's request effort (default 64; `12-servers.md` §1), for today or yesterday; each proof is accepted once. Account inboxes refuse `WriteRequest` and request inboxes refuse `Write` (`Denied`).
- It holds at most `request_quota` pending envelopes (default 100). When full, the oldest is dropped to make room (FIFO).
- The owner reads it with `Poll`/`Ack` and its own read credential.

Not implemented yet: invite capabilities, adaptive effort, and client-side rules for requests (text-only, no auto-download).

## 5. Polling

- **One mailbox per poll request, always.** A poll object names exactly one mailbox.
- The scheduler (`enclave_net::schedule::Scheduler`) keeps a list of mailboxes; index 0 is the account inbox. It counts ticks since the list was last set (`rr`):
  - on **even** ticks it polls the account inbox;
  - on **odd** ticks it polls one of the other mailboxes, chosen by **smooth weighted round robin**: each odd tick, every other mailbox's credit grows by its weight (minimum 1), the mailbox with the highest credit is chosen (the lowest index wins ties), and its credit drops by the sum of the weights;
  - with only the inbox in the list, every tick polls the inbox.
- This alternation is the same in all three profiles.
- Test `inbox_polled_every_other_tick_and_weights_respected`: over 400 ticks with weights 3 and 1, the inbox gets exactly 200 polls and the others 150 and 50.

Not implemented yet: the `MORE` flag steering the next poll to the same mailbox, overlap-week polling, a per-group floor of one poll per 60 s, and decoy re-fetches.

## 6. Cover-traffic scheduler (D10)

Nym's default client sends 50 + 5 packets per second (about 500 MB/h). Enclave disables Nym's Poisson main stream and drives its own tick scheduler.

### 6.1 Tick

`Scheduler::tick` returns, for every tick:

- `after`: the delay since the previous tick;
- `send`: the next queued real request, or `None`, in which case the caller sends a `Cover` unit;
- `poll`: the mailbox to poll (§5).

So each tick sends exactly **1 unit up** (real or cover) and **1 poll up**, and over the mixnet brings back **1 unit down**, the poll's reply (PLAN §9.4): messages, self-copies, group posts, typing indicators and cover units go **one way** (`Transport::exchange_oneway`, mixframe kind 5 with no reply blocks; the ingress hands them to the server and drops the answer), so nothing comes back for them (`math/cover-traffic.md` §1, §2.1). A one-way send is "on its way" once the device's Nym client has it. Before the device's network process exits (the app quits or closes), it waits up to 10 s for the far gateway to acknowledge every packet it sent (`Transport::flush`, `MixnetDriver::flush`, counted by our nym-client-core patch, `third_party/PATCHES.md`): a send still queued in the Nym client would otherwise be lost with the process. Whether a message arrived is learned from the recipient's **delivery receipt** (`client/outbox.rs`): receipts ride in the padding of the next envelope going the other way, or after 10 s go on their own; an unacknowledged message is sent again after 10 min, 1 h and 6 h (the recipient keeps one copy by message id), then shown as "Not delivered yet". Every other unit goes one way too: a request whose answer is needed (prekey claims, directory reads, inbox creation, first-contact requests, token registration, blob uploads) is marked `DEFER`, and the server keeps its answer for 10 minutes under a **status id** only the sender can name (`KMAC256(exchange secret, "", "enclave/v1/net/status-id")`, `08-envelope.md` §2.2). The client then fetches it with a poll-sized `Status` request, which comes back like any poll reply (`Rpc::call`, `fetch_answer`). So **no unit going up carries reply blocks**, and the only things that ever come down are poll-slot answers, each one 16 KiB. Key bundles (once a day per server) are poll-sized requests as well. Tests `deferred_answers_come_back_through_status_polls` and `clients_over_the_mixnet` (`crates/enclave-ingress/tests/mixnet.rs`). Test `writes_go_one_way` (`crates/enclave-ingress`), `receipts_resends_and_not_delivered_yet` (`crates/enclave-core/tests/delivery.rs`). Real traffic **replaces** cover; it never adds to it. Tick timing depends only on the profile and randomness, never on the queue. Test `crates/enclave-net/tests/shape.rs` checks that delays and poll targets have the same distribution whether or not real traffic is waiting (two-sample Kolmogorov-Smirnov, α = 0.001), and that real and cover units are identical in size.

### 6.2 Send priority

`enqueue` keeps the queue ordered by priority, first in first out within a class:

| Priority | Class |
|---|---|
| 0 | `Peer`: delivery to a contact |
| 1 | `Control`: token registration, acks, prekey refills |
| 2 | `Sync`: own-device sync |
| 3 | `Prefetch`: blobs the user has not opened |

### 6.3 Profiles

There are exactly three profiles, identical in every client, and no per-user or per-network parameters.

| Profile | When | Tick delay (`mean_tick`, `poisson`) | Bulk bursts (`allows_bulk`) | Data (estimate, PLAN's 1-down model; M4 must land within ±20%) | Median text latency (estimate) |
|---|---|---|---|---|---|
| **Foreground** | App visible | fixed 3 s | allowed | ≈60–70 MB/h | ≈5–6 s without other mailboxes; ≈6.5–7.5 s with |
| **Background** | Android foreground service, desktop tray | exponential, mean 120 s | allowed | ≈35–40 MB/day | ≈88 s without other mailboxes; ≈112 s with (other mailboxes on every 4th tick) |
| **Maximum privacy** | Opt-in; Android and desktop always, iOS only while open | fixed 3 s | not allowed | ≈1.5–1.7 GB/day | as Foreground |
| Background (iOS) | Not possible (the OS suspends the app) | none | — | 0 | On open, or on push |

The Background delay is `−ln(U) · 120 s` with `U` uniform in (0, 1], drawn from 53 bits of hedged randomness. Data and latency derivations: `math/cover-traffic.md`.

**Pacing (as implemented).** The device's Nym client releases real Sphinx packets at even intervals instead of in a burst: a tick sends 16 packets up (a one-way unit is 11 packets, a poll with the reply blocks for its answer 5, measured on the local mixnet by `nym/enclave-nym-sdk/examples/localnet_roundtrip.rs`, which fails if they change), so in every profile they leave one per 3 s / 16 = 187.5 ms. Background paces over the same 3 s: its ticks start at random times already, and pacing over the 120 s mean would delay every answer by up to 2 minutes. Loop cover is 1 per 10 s in Foreground and Maximum and 1 per 120 s (one per tick on average) in Background. The vault's shaper sets the pacing (`Profile::pacing`, `Transport::set_pacing`) at start, at each profile change and around bulk transfers, and only when it changes; it reaches nymd through netd (`NetRequest::SetPacing`, pipe frame 4), where our nym-client-core patch applies it without rebuilding the client (`third_party/PATCHES.md`). Tests `pacing_follows_the_profile_and_bulk` (`crates/enclave-net/tests/shaped.rs`), `a_tick_is_paced_evenly_and_bulk_at_the_cap` (`enclave-nym-sdk`), and the paced send in `localnet_roundtrip` (11 packets 100 ms apart take ≥ 1 s). 

**Self-loop probes and gateway switching (RT-02, as implemented).** A malicious gateway or mix can hold back or flood everything but one person's traffic to isolate one message (an n-1 attack). The device measures its own gateway path, and moves when the path goes bad:
- **Samples.** Every exchange with a server is a sample: its round-trip time, or a loss if no reply comes within the request timeout. Self-loop probes add samples on top: a one-packet `Probe` mixframe (kind 6, header only) sent to the device's own address, with id `KMAC256(probe secret, u64 counter, "enclave/v1/net/loop-probe")`. A probe not back within 60 s is lost.
- **Probe rate.** Probes leave at exponential intervals, one per 30 s on average in Foreground and Maximum and one per 480 s in Background, and Nym loop cover drops to one per 15 s (one per 160 s) to match. Packets to the device itself therefore stay at 1 per 10 s (1 per 120 s), and the gateway can't tell a probe from loop cover.
- **Rule** (`enclave_net::monitor::LinkMonitor`). Over a window of the last 50 samples, switch when more than 10% were lost, or when the median of the last 10 latencies exceeds 5× the median of the window. Never switch twice within 10 minutes, and start measuring afresh after a switch.
- **Switch** (`MixnetDriver::switch_gateway`). nymd connects a fresh ephemeral client through another gateway (nym-sdk picks uniformly at random, up to 8 tries for a different one). The old client keeps receiving for 90 s so replies already under way arrive. netd's log records the switch and its reason. An ingress never switches: its address is published.

Tests:
- `rt02_gateway_switch_on_loss_over_10pct`, `rt02_gateway_switch_on_latency_over_5x_median` and `rt02_no_switch_on_ordinary_loss` (`crates/enclave-ingress/tests/rt02.rs`, fake mixnet with per-gateway faults).
- The monitor's unit tests.
- The switch in `localnet_roundtrip`, on a local mixnet with two gateways: 63 ms, and a round trip through the new gateway.

### 6.4 Bulk

`Scheduler::bulk(max)` hands out up to `max` queued requests at once for a burst (media, the McEliece key, catch-up), if the profile allows it. In Maximum it returns nothing, so bulk traffic rides the normal ticks one request per tick. During a bulk transfer (a bulk window, or a tick that bursts) the Nym client sends at the 40 packets/s cap: one packet per 25 ms (`enclave_nym_sdk::packet_gap`).

### 6.5 Profile transitions

`set_profile` changes the profile only at a foreground/background transition or when the user toggles Maximum privacy (RT-12). The next tick follows the new profile; no extra ticks are added to "catch up".

### 6.6 Maximum privacy

- The 3 s tick runs constantly, including in the background on Android and desktop.
- No bulk bursts: a 1 MiB-bucket photo (74 chunks) takes about 3.7 minutes and a 4 MiB-bucket photo (295 chunks) about 15 minutes. The UI states the time for the actual bucket before sending.
- **As implemented** (`engine.rs::apply_privacy`, which follows the setting):
  - **The private route only** (`Transport::require_private`, IPC `NetRequest::RequirePrivate`). netd refuses development TCP routes and takes no new ones. Without Tor in front of the mixnet (netd started without `--tor`), it refuses everything: Maximum doesn't run without Tor. The vault's direct-TCP fallback (no netd) refuses too.
  - **No push.** `Client::register_push` refuses, and turning Maximum on asks the server to forget any token.
  - **All three KEMs before anything a person writes.** In `seal_content`, user content (text, files, reactions, recovery shares and the like; `Content::waits_for_three_kems`) goes only over sessions where `three_kem()` holds. Otherwise it is held in the outbox and leaves at the next upkeep after the braid, without using up a re-send. Protocol messages (the hello that accepts a request, write tokens, receipts, PQ steps, notices of moves and devices) still go, so the session can reach three KEMs. Contact info shows "Extra protection: finishing…" meanwhile.
  - **Tests.** `maximum_waits_for_three_kems` (a session started on two KEMs holds Ben's message until Ada's next message braids in the third, then delivers it) and `maximum_has_no_push` (`enclave-core`); `the_private_route_only` (`enclave-netd`); `a_direct_connection_is_refused_in_maximum_privacy` (`enclave-net`).

### 6.7 As implemented in the client

`enclave-net/src/shaped.rs`. `ShapedTransport` wraps whatever transport the app uses (TCP in development; Nym or Tor later) and only ever sends on the scheduler's clock. It runs in the vault process whenever the vault talks to a server; `--no-shaping` turns it off for development, and the offline demo has no network at all.

- **Every tick sends exactly one 16,384 B unit and one 2,048 B poll.** A queued request takes the slot of its size. An empty slot carries cover that the wrapper seals itself: an `Op::Cover` unit, or a poll of a random mailbox (which the server refuses). Cover is sealed to the same server key as real requests, so the two are the same size and look the same on the wire. Requests are sent concurrently, so a slow reply never holds up the next tick.
- **The client's requests are still issued one after another**, so the client is reorganized to need few requests per tick. `Client::sync_round(round)` replaces a full sync. Even rounds read the inboxes; odd rounds poll one group, in turn; every `UPKEEP_EVERY` (10) rounds it also does upkeep (manifest checks, token refills, expiry, pending PQ steps, prekeys). The vault runs one round per sync tick.
- **Bulk** (§6.4) is a burst of up to `BULK_PER_TICK` (12) extra requests of one size in a tick, once more than `BULK_AFTER` (4) are waiting. Some work is bulk by nature, so it is declared rather than inferred from the queue: `Transport::set_bulk` opens a bulk window in which requests skip the clock. The vault opens one for account creation and restore, sending and saving files, sticker packs, history transfer, joining a group, linking, adding a contact, and loading media; the client opens one for catch-up polls (a reply flagged "more pending") and for a group's polls, whose number depends on how many epochs the device holds, not on traffic. **Maximum privacy never bursts and ignores bulk windows**: everything waits for its slot.
- **Droppable requests** (`Transport::exchange_droppable`, used by typing indicators) only take a slot that would otherwise carry cover, never trigger a burst, and are dropped after `DROP_AFTER` (2) ticks without a free slot. They never add traffic.
- **Profiles:** the vault uses Foreground, or Maximum when the Maximum privacy setting is on (Settings → Privacy). The Background profile needs the platform's background service, which the desktop app doesn't run yet.

Tests (`crates/enclave-net/tests/shaped.rs`, paused tokio clock): every tick is one unit and one poll whatever the load; Foreground bursts and Maximum never does; droppable requests never change the sizes sent; `Off` sends at once; bulk windows skip the clock except in Maximum. `crates/enclave-core/tests/client.rs::sync_in_rounds` checks that round-based sync delivers 1:1 and group messages, and the vault process tests run with shaping on.

Residuals: the sequence of real requests in a bulk window is visible as a burst (the app discloses that); the development TCP transport is not packet-paced (only the Nym client paces, §6.3).

## 7. Nym access, fallback, censorship (not yet implemented)

- zk-nym credentials through a credential proxy gated by Equi-X plus Privacy Pass.
- M4 go/no-go (`roadmap.md`): nym-sdk ≤150 MB RAM on Android and iOS; cold connect ≤5 s; bulk ≥200 KB/s of nym-sdk raw throughput (the Bulk profile itself is capped at 40 packets/s, at most ≈82 KB/s of payload; `00-overview.md` §9, I-12); the credential path works; cost ≤ $1 per user per month; the Tor → gateway path works. The spike report is `spikes/m4-network.md`.
- Fallback transport: Tor onion services (`TorTransport`) with the same scheduler and objects, only with user consent and never in Maximum mode.
- Censorship: obfs4 bridges in process; Snowflake and WebTunnel as declared exceptions, only in censorship mode.
- Nym's post-quantum Sphinx is adopted when nym-sdk exposes it.

## 8. TLS 1.3 (never on the message path)

A rustls `CryptoProvider` with SecP384r1MLKEM1024 (codepoint 0x11ED) and `TLS_AES_256_GCM_SHA384` only, for server descriptors, witness gossip, update endpoints, the relay control plane and the push relay's front door.

**As implemented** (`enclave-tls`): `provider()` is rustls with `ring` for AES-256-GCM and certificate signatures, TLS 1.3 only, one cipher suite and one key exchange. The hybrid is built from two pure-Rust halves: the client share is an uncompressed P-384 point (97 B, RustCrypto `p384`) followed by an ML-KEM-1024 encapsulation key (1,568 B, `enclave-crypto`/libcrux); the server answers with its P-384 point and an ML-KEM-1024 ciphertext; the secret is the P-384 ECDH x-coordinate (48 B) followed by the ML-KEM shared secret (32 B), so a recording stays confidential if either half holds. Points not on the curve, compressed points, the identity and wrong lengths are refused. A client that offers only other groups (including X25519MLKEM768) can't connect. `compat_provider()` (rustls's defaults) is only for the outside world, such as an ACME CA. Tests: `crates/enclave-tls/tests/handshake.rs`, and `openssl35.rs` against OpenSSL 3.5's own SecP384r1MLKEM1024 both ways (OpenSSL's `s_client` to the Enclave profile and the Enclave client to `s_server`, each agreeing on the hybrid and `TLS_AES_256_GCM_SHA384` and carrying data; OpenSSL offering only X25519 is refused), run in CI's `tls-interop` job with Alpine 3.22's OpenSSL. In use by the witness service and the front (`12-servers.md` §3.3, §4.5). Not implemented yet: update endpoints (R2), the relay control plane (C2) and the push relay's front door (N3).

## 9. Blobs

- **Upload:** `BlobPut` with the chunk ID in the mailbox field and an Equi-X proof over `"blob-put" ‖ chunk_id ‖ SHA3-512(chunk)` at the server's blob effort (default 1). The first upload to an ID wins; a second gets `Denied`.
- **Fetch:** `BlobGet` with the chunk ID; no credential. The chunk ID is the capability.
- Blobs expire 30 days after upload.

Not implemented yet: `BLOB_ALLOC` with Privacy Pass quotas, client-side chunk sealing and ID derivation, delayed fetches and decoy fetches (RT-17).

## 10. Errors

| Condition | Client behavior |
|---|---|
| Reply cannot be opened | Treat as failure; retry in a later tick with a new seal |
| `Denied` on a write | The token was spent or never registered; use the next token |
| `Quota` | Inbox full; retry later |
| `Pow` | Solve again at the server's current effort |
| No tokens for a contact | Queue the message until the contact sends more |

## Open questions

1. **Resolved:** PLAN §9.3 polls the inbox in slot 1 and rotates groups in slot 2. Strict alternation put the Background median at ≈140 s with other mailboxes; Background now gives the other mailboxes every 4th tick (median ≈112 s, within "≤2 min"); Foreground and Maximum alternate (`math/cover-traffic.md` §7.3).
2. **Resolved:** PLAN §9.2's replay cache of request ciphertexts per key is built (§2.3).
3. PLAN §9.2 says old daily keys are deleted; the implementation keeps the previous day's key until the next rotation rather than for a short grace window. Deleting it after a grace period needs a timer in the server.
4. Read credentials are static and inbox addresses do not rotate (§3.1). PLAN §9.3 derives weekly addresses and daily credentials from an inbox seed; the implementation intentionally starts simpler. This needs to be implemented before a server can be prevented from linking a device's polls across weeks.
5. **Resolved:** every unit goes one way over the mixnet. Writes and cover need no answer, and delivery is confirmed by receipts. Requests that need an answer are marked `DEFER`, and their answers are fetched by poll-sized `Status` requests (§6.1). So a unit carries no reply blocks, whatever it is.
