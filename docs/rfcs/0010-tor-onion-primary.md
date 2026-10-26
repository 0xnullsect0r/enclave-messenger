# RFC 0010: Tor onion services are the primary route; the Nym mixnet is optional

- **Status:** Accepted
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-21
- **Comment period ends:** 2026-11-20
- **Affects:** `00-overview.md` §1–§3, `01-threat-model.md` §2, §4, §5, `09-transport.md` §1, §6, §7, `10-push.md` §1, `12-servers.md` §2, §6, `13-operators.md`, `math/cover-traffic.md` §1, §10, §11, `redteam-matrix.md` RT-01/02/03/12/13/20/27, `15b-platform-constraints.md` PC-60–63, `enclave-tord`, `enclave-netd`, `enclave-federation` (server list v3), `enclave-server` (stream framing), `enclave-admin`, `enclave-vault`, `ops/compose`
- **Crypto WG review required:** yes (metadata)

## Summary

Devices reach their servers over Tor, at each stack's onion service, through a persistent stream that tord carries for netd. The Nym mixnet stays in the code as an optional route, off by default (compose profile `nym`), for stacks and a foundation that choose to fund it. Running Enclave then costs nothing beyond a server: Tor is free and volunteer-run, call-relay tickets are paid with proof of work (RFC 0006), blob tokens are issued by each user's own server, and APNs and FCM cost nothing with the developer accounts already held.

## Motivation

The mixnet carries traffic only against zk-nym tickets bought with NYM tokens. Every operator's stack ran three paying Nym clients (ingress, push egress, push ingress), and the foundation would have paid for every user's tickets through the credential gate (`09-transport.md` §7, `math/cover-traffic.md` §11). At late-2026 prices that is tens of dollars a month per stack and several dollars a month per user, recurring, with nobody to pay it: the project has one maintainer and no funding. A messenger that only runs while someone pays a token bill per user doesn't run.

What was already built made the change small:

- The client ships arti (`enclave-tord`), and the server image ships an onion service (`enclave-onion`), both used until now only for the consent-gated fallback route.
- The server handles many framed requests per connection (`enclave-server` `serve`), so one long-lived stream per server carries a device's whole session.
- The traffic shaper (`enclave-net` `shaped`) is transport-independent: one 16 KiB unit and one 2 KiB poll each tick, whatever the route.

Found while checking the change, and fixed with it:

- netd confined itself with no `socket()` at all when it had a mixnet client, so the UDP sockets it opens for calls failed in release builds on Linux. netd now keeps datagram sockets only (seccomp `NetdUdp`, Landlock with TCP denied).
- Over any route but the mixnet, a one-way unit (a write, cover) came back with a full 16 KiB reply, doubling the downstream bytes. The stream framing now marks one-way requests (below).

## Specification

### 1. The carrier (`enclave-tord --carrier`, `crates/enclave-tord/src/carrier.rs`)

- After its `ready` line, tord started with `--carrier` reads requests from netd on stdin and answers on stdout, as `u32 len ‖ body` frames. An exchange is `1 ‖ u32 id ‖ u8 flags ‖ u16 len ‖ host ‖ u16 port ‖ request`; a fetch is `2 ‖ u32 id ‖ u16 len ‖ method ‖ u16 len ‖ url ‖ body`. Each answer repeats its kind and id, then `0` and the reply (a fetch: `u16 status ‖ body`), or `1` and a reason. Many requests are in flight at once.
- tord MUST make every request through its own Tor client. netd holds no TCP socket and can't open one.
- Per onion service tord keeps `STREAMS = 6` long-lived streams, one request at a time on each, so a poll never waits behind a unit and a burst doesn't queue behind one slow round trip (two were too few for the vault key's hundred chunks). A stream that fails is replaced and the request tried once more on a new one; opening one may take 30 s (`DIAL_TIMEOUT`). A server has 60 s to answer on a stream (`STREAM_TIMEOUT`); netd waits 90 s for tord (`TIMEOUT`).
- Fetches (the credential gate when the mixnet is on, GIF search, link previews, the transcription model) follow the mixnet client's rules: an Enclave service with the Enclave TLS profile; a `web+https://` site with `GET` only, at most 5 redirects, all `https`, at most 960 KiB, one user agent for every Enclave; a `#bytes=A-B` fragment becomes a `Range` header and never goes on the wire.

### 2. Routes (`crates/enclave-netd/src/lib.rs`)

- netd starts tord as the carrier whenever it is given `--tor`, with or without a mixnet.
- For each server, netd uses: the Nym route, if the server has one and the mixnet is configured; otherwise the onion route; otherwise, in a development build only, TCP. The onion route needs no consent.
- For a server with a Nym route, the onion route is the fallback it was before: only with the user's consent, never in Maximum.
- Maximum privacy (`require_private`) accepts the onion route and the Nym route, and refuses TCP.
- With no TCP route netd's confinement allows datagram sockets only (calls), never TCP (`Profile::NetdUdp` with Landlock `deny_tcp` on Linux). Its `--report` says `sockets udp`.

### 3. One-way requests on a stream (`enclave_wire::STREAM_ONEWAY`)

- On a stream to a server, a request's length MAY have its top bit set (`len | 0x8000_0000`; real lengths are at most a unit's). The server MUST handle the request as usual, discard its sealed reply, and answer an empty frame (`len = 0`).
- The carrier sends `exchange_oneway` and `exchange_deferred` with the bit. Their answers come later by a status poll, as over the mixnet (`09-transport.md` §6.1).
- The Nym ingress never sets the bit, so it is unaffected.

### 4. Server list v3 (`crates/enclave-federation/src/list.rs`)

- `VERSION = 3`. Each listed server carries `onion` (an onion address, or empty) after `nym_address`. Each push relay entry carries `onion` after its `nym_address`; either may be empty, not both.
- Readers MUST accept version 2 (every `onion` empty) and 3. Writers write 3.
- `enclave-admin server-list build` copies each descriptor's `onion`, and `[[push]]` takes `onion = "…"`, `nym_address` optional.
- The client sets `Route::Onion` for every listed server with one, from the list and from the server's descriptor. The vault starts the mixnet client, its ticket wallet and the credential gate only if some listed server has a Nym address.

### 5. Server side (`ops/compose/compose.yml`)

- `onion` (`enclave-onion run`) runs by default. It writes `public/onion.addr` only once Tor says the service is reachable, and removes a stale one at start. At most 16 streams per circuit (`STREAMS_PER_CIRCUIT`) and 4,096 open in all (`--max-streams`). Its identity key stays in the `onion-data` volume: losing it changes the address and needs a new list.
- Push wakes travel over Tor too: the server hands them to `push-egress` (`enclave-onion forward --to $PUSH_RELAY_ONION`), which sends them over one long-lived stream to the push relay's onion service (`push-onion`, profile `push`, forwarding to `push-relay:7445`). Without `PUSH_RELAY_ONION` the wakes are dropped.
- The Nym ingress, its push egress (`push-egress-nym`) and the push relay's Nym client (`push-ingress`) move to profiles `nym` and `push-nym`. The credential gate stays in profile `foundation` and is used only with the mixnet.
- Arti's proof-of-work defence for onion services is still experimental and stays off. Floods of introductions are limited by the introduction points' own rate limits and the stream caps above.

## Security and privacy analysis

**What Tor gives that the mixnet gave:**

- The server never sees a device's IP, and a device never sees the server's (both are behind Tor; the server's location is hidden by the onion service).
- The ISP and the Tor guard see a Tor connection with constant-rate traffic per profile. The shaper keeps idle and busy identical on the wire (`federation-e2e-onion` checks it on every change, ±20% of the model).
- Content and mailbox identifiers are sealed to the server with X448 + ML-KEM-1024, as before, whatever carries them.

**What it doesn't give:**

- **No mixing.** Tor relays forward cells at once, without delays or cover. An adversary who watches both the device's guard link and the server's (a global passive adversary, or the guard colluding with a server operator) can match timing. The mixnet's per-hop delays defeated that; Tor doesn't. Constant-rate shaping blunts it: in Foreground and Maximum a device sends the same unit and poll every 3 s whether or not anything is real, so what an observer at both ends can correlate is *that a device is online and talking to that server*, not when it sends a message. Background ticks are Poisson-timed and match the same way. The leakage matrix (`01-threat-model.md` §4) states this.
- **Circuit crypto is classical.** Tor's circuits use X25519; after a quantum computer, recorded traffic reveals which server a device talked to (as recorded Sphinx did), never content or mailbox ids (RT-27, unchanged).
- **The Tor guard learns that you use Tor**, and with timing, roughly how much: the constant rate makes that the same every hour.
- **The home server** still sees only sealed requests, now arriving over its onion service instead of its ingress. It can't tell two devices apart by route: every client is a Tor circuit.
- **The push relay** sees wakes arrive from Tor, not which stack sent them (the stacks' push egress clients are anonymous Tor clients).

Red-team rows: RT-02 (gateway switching) applies only with the Nym route enabled. RT-01, RT-12 (constant shape) are unchanged and now checked over the onion route too. RT-03 and RT-27 move from Sphinx to Tor's cells. RT-13 (updates) and RT-20 (push) now go over Tor.

The threat-model adversaries change accordingly: A-NET can block Tor (bridges: Snowflake, obfs4, WebTunnel, `09-transport.md` §7), and A-INF controlling a large share of Tor relays can de-anonymize circuits by timing as above.

## Compatibility and migration

- Lists v2 still read; a v2 list has no onion addresses, so its servers are reached only by their Nym routes. No released clients use a v2 list (rc.1 shipped without a built-in list).
- Stacks update their compose file; the onion service starts by default and its address enters the next descriptor the server signs. The foundation builds a v3 list from those descriptors.
- A stack that keeps the mixnet runs `COMPOSE_PROFILES=nym` and sets `[push] forward = "push-egress-nym:7446"`.

## Costs

Bytes per Foreground or Maximum tick on the stream: up, one unit and one poll with their 4-byte lengths (16,388 + 2,052 B); down, the poll's 16,384 B reply and the unit's empty acknowledgement (16,388 + 4 B). That is 34,832 B per 3 s: 41.8 MB an hour of payload, about 46 MB an hour on the wire with Tor's cells (498 data bytes in 514), TLS and TCP/IP (`o ≈ 1.10`). Background (a tick every 120 s on average): about 28 MB a day. Maximum all day: about 1.1 GB. Over the mixnet the same profiles cost about 80 MB an hour and 2 GB a day (`math/cover-traffic.md` §3).

To the Tor network: about 13 kB/s per device in the foreground, a small fraction of what a video stream uses, and nothing in the background beyond a few hundred bytes a second. The per-device rate is fixed and doesn't grow with use.

Money: nothing recurring, for operators, the foundation, or users.

## Alternatives considered

- **Keep Nym, find funding.** The mixnet gives stronger timing protection, and the code stays so it can return. But without someone paying per user it doesn't run at all.
- **I2P.** Mixing-free like Tor, smaller network, and no maintained Rust client to embed on phones.
- **Direct TLS to the front.** Free and fast, but every server sees every device's IP, which the threat model forbids.
- **Loopix-style mixnet run by the operators.** Operators would carry the cost of mixing for everyone; too few stacks exist to give anonymity.

## Test plan

- `enclave-tord` carrier tests: exchanges and one-way sends on reused streams; a poll not waiting behind a slow unit; a closed stream replaced; an unreachable service an error. `enclave-onion forward`: wakes from two connections arrive in order over one stream.
- `enclave-netd`: `onion_route_is_primary_without_consent`, `maximum_accepts_onion_refuses_tcp`, `fetch_goes_to_tord_without_nymd`; `carries_requests_over_nym` checks `sockets udp`.
- `enclave-sandbox`: `netd_udp_profile_carries_calls_but_makes_no_tcp`.
- `enclave-federation`: `list_v3_round_trips_onion`, `list_v2_still_reads`.
- `enclave-server`: `oneway_bit_gets_empty_ack`.
- CI `federation-e2e-onion`: three stacks with onion addresses in a v3 list, `enclave-e2e` reaching them only through the carrier (setup, push, a restart, the traffic shape on the carrier's streams, `pcap-check.py --stream`).
- Nightly `onion-live` (`live.yml`): a server's onion service on the live Tor network reached through the carrier, with the connect time and round trips in the job summary, and a wake through `enclave-onion forward` to a second onion service.

## Open questions

1. **Resolved:** Does a 3 s tick fit Tor's round trip to an onion service? Yes for the shaper, which sends requests concurrently and never waits on a reply to start the next tick; `onion-live` records the round trip each night (first run: 735 ms median, 1.24 s at the 90th percentile, `09-transport.md` §6.3).
2. **Resolved:** Arti's onion-service proof-of-work defence: off while arti marks it experimental; the stream caps and introduction-point rate limits apply meanwhile.
3. **Resolved:** What happens to the credential gate, the zk-nym wallet and the M4 cost gate: they apply only with the optional mixnet, and External Gate G7 (Nym funding) is no longer needed to ship.
