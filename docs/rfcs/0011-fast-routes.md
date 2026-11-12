# RFC 0011: The fast routes — a stack's front over Tor's exit, or straight to it

- **Status:** Proposed
- **Author(s):** Enclave maintainers
- **Created:** 2026-11-11
- **Comment period ends:** 2026-12-11
- **Affects:** `01-threat-model.md` §3, §4, `09-transport.md` §1, §7, `12-servers.md` §4.5, `13-operators.md`, `redteam-matrix.md`, `enclave-tord` (carrier kind 3, `SocksDialer`, `--tor-socks`), `enclave-front` (`POST /net`), `enclave-net` (`Route::Exit`/`Direct`/`Off`), `enclave-netd`, `enclave-core` (the `fastroute` setting), `enclave-ipc` (Cmd 153, the state's `fast_route`), `enclave-vault`, `ops/compose`, `ci/onion/front-bench.py`
- **Crypto WG review required:** yes (metadata)

## Summary

Two consented routes ask a stack's front (`POST /net`, the sealed request as
the body) instead of its onion service: `exit`, out of Tor's exit — three
hops instead of an onion service's six, the server still seeing only a Tor
exit — and `direct`, with no Tor at all. Both are a fast lane in front of the
onion route, which answers whenever the front doesn't; both are refused in
Maximum privacy; neither changes what a request is (sealed, fixed-size,
cover-paced by the shaper). Alongside them, tord can ride a system Tor's
SocksPort (`--tor-socks`, the profile's `tor-socks.txt`) instead of the
embedded arti — no security change at all, and often the faster ride.

## Motivation

The onion route's round trip crosses six Tor relays (three at each side of
the rendezvous) through arti's still-maturing onion-service client. Measured
by `ci/onion/carrier-bench.py`, a poll's round trip is commonly a second and
often several: the app works, but people feel it with every message. The
mixnet is no answer (slower, and it needs Tor in front of it anyway).

Three of the four changes need no new plumbing:

- Every stack already faces the web at its front (`enclave-front`, §4.5 of
  `12-servers.md`) with a certificate and the Enclave TLS profile, and its
  domain is already public — it is the descriptor's and the list's, and
  usernames are `@name@domain`.
- The carrier already does exactly this shape of request for fetches: TLS
  under the Enclave profile, `POST` `application/octet-stream`, through any
  `Dialer` (`enclave-tord` `fetch.rs`).
- The front already proxies whole bodies to internal services (the witness,
  the credential gate) and keeps no client addresses.

## Specification

### 1. The front (`POST /net`, `crates/enclave-front/src/lib.rs`)

- With `[front] net` set (a `host:port` on the internal network, such as
  `server:7443`; **empty by default**, an operator's choice), the front
  serves `POST /net`: the request body is one sealed request in the carrier's
  framing (`u32 len ‖ body`), carried to the server on a pooled connection
  kept warm, and the reply body is its sealed answer. Without `[front] net`
  the route answers 404, and the client's fast lane falls back to the onion
  route.
- An `Enclave-One-Way: 1` header marks a one-way request: the frame to the
  server sets the length's top bit (`enclave_wire::STREAM_ONEWAY`), the
  server discards its sealed reply and answers an empty frame, and the front
  answers an empty body — a write or a cover unit costs nothing coming back,
  as on the onion route.
- Bodies are limited (64 KiB in, 1 MiB back — a unit is 16,384 B); a request
  has 60 s. A stale pooled connection is dropped and the exchange tried once
  more on a new one.
- The front logs nothing and forwards no client address or header to the
  server, as for the witness proxy. It cannot read what it carries: every
  request is sealed to the server's keys.

### 2. The carrier's front request (kind 3, `crates/enclave-tord/src/carrier.rs`)

- A front exchange is `3 ‖ u32 id ‖ u8 flags ‖ u16 len ‖ domain ‖ u16 port ‖
  request`; the answer is as any other's. Flag `1` is one-way, flag `2`
  asks tord to dial the front itself with no Tor in between (the `direct`
  route); without it the request leaves through Tor's exit.
- tord keeps one warm TLS connection per `domain:port` (the Enclave TLS
  profile, the public roots — the front's certificate is a public CA's, as
  for its descriptor), so an exchange after the first costs one round trip
  and not a handshake. A stale one is dropped and the exchange tried once
  more.
- The `direct` flag rides the same carrier, so netd still opens no TCP
  socket: tord, which already holds outbound TCP for Tor's own connections,
  dials the front itself (`TcpDialer`).

### 3. Routes (`crates/enclave-net`, `crates/enclave-netd`)

- `Route::Exit(DOMAIN, port)` parses `exit:DOMAIN[:PORT]` (443 unless
  named); `Route::Direct(DOMAIN, port)` parses `direct:DOMAIN[:PORT]`;
  `Route::Off` parses `off` and takes a fast route back.
- netd tries a server's fast route first for every exchange, key fetch and
  one-way send; on any failure the onion route answers, and the front cools
  down for 60 s rather than costing every request a failed attempt. A front
  that answers is back in use.
- Maximum privacy (`require_private`) refuses the fast routes, at
  `front_for` and at `set_route`, as it refuses every route but the private
  ones.
- A server reached only by its onion service keeps that route alone: the
  fast lane is a preference in front of the ordinary one, never a
  replacement. A stack that didn't open its front (404) is simply always on
  its onion route.

### 4. Consent (`enclave-core`, `enclave-vault`, the app)

- The setting `fastroute` in the client's settings: 0 off (the default),
  1 `exit`, 2 `direct`. Settings → "Message speed": Tor only / Faster /
  Fastest, with what each gives up. `Cmd::FastRoute` (153) carries it.
- With the setting on, the client sends the fast route for every listed
  server (its `domain`) and each accepted descriptor's, exactly as it sends
  onion and Nym routes today; turning it off sends `Route::Off` for every
  server it was given to.
- The choice made under Maximum privacy is saved but has no effect there
  (the transport refuses it) and takes effect when Maximum is left.

### 5. A system Tor (`--tor-socks`, `tor-socks.txt`)

- A profile with `tor-socks.txt` (one line, `HOST:PORT`, such as
  `127.0.0.1:9050`) has the vault pass netd `--tor-socks HOST:PORT`, and
  netd's tord dial through that SocksPort (`socks::SocksDialer`, no
  authentication) instead of bootstrapping embedded arti. Readiness is the
  port answering; C-tor holds requests until it has finished bootstrapping,
  as our wait held them for arti. The state-directory claim, the standby and
  the stdin death all stay as they are. tord's own SocksPort for nymd
  chains through the system Tor.
- The system Tor owns its own bridges: `tor-bridges.txt` is ignored in this
  mode. Operators' docs suggest a dedicated `SocksPort` line with
  `IsolateDestAddr`, so the carrier's streams don't share circuits.
- No file: everything as before, embedded arti. Mobile is unchanged.

## Security and privacy analysis

Per route, against the tables in `01-threat-model.md` §3:

| | the server learns your IP | your link (ISP) sees | the stack's location | path |
|---|---|---|---|---|
| onion (default) | no | Tor only | hidden | 6 relays |
| onion over a system Tor | no | Tor only | hidden | 6 relays |
| `exit` | no (a Tor exit's) | Tor only | public domain | 3 relays |
| `direct` | **yes** | **TLS to the domain** | public domain | 1 hop |

- The stack's location is already public in practice: the domain is in the
  descriptor, the list and every username, DNS names the front, and the
  front already takes clearnet visitors (descriptor fetches). What `exit`
  and `direct` add is *the stack visibly taking message traffic* on it, and
  for `direct` the client's address in the front's hands (a process its
  operator controls; it logs none by design, but a coerced or malicious one
  could). This is the Signal-grade floor, not Enclave's default.
- Content protections are identical on every route: requests are sealed to
  the server's daily hybrid keys (RT-27 holds as before), fixed-size units,
  one-way writes, weekly inbox rotation, and the shaper paces cover traffic
  the same way — over `direct`, a local observer sees constant-rate TLS to
  one domain, not *when* a message is sent.
- Timing correlation by an observer of both ends is *easier* on the fast
  routes (fewer hops, no rendezvous): over `direct`, the observer of the
  client's link alone is enough. Residual 6 of `01-threat-model.md` §4
  strengthens for consenting users.
- On `direct` the domain is resolved locally (the system's resolver, as any
  HTTPS client does) and travels in the TLS SNI, which is plaintext without
  ECH: the domain reaches the resolver and the link's observer, both of
  whom the TLS connection to it already names. No new party learns
  anything the connection itself doesn't carry. On `exit` the exit's
  resolver sees it, as for any site it visits.
- The front sees request timing per connection, as the onion service's
  streams already do; the pooled connection to the server makes the front a
  fixed vantage for its stack, which the threat model already treats as the
  operator's.
- `exit` shares nothing new with the exit relay: it sees TLS to a public
  domain, the same as any visitor of the front's descriptor.
- A malicious front cannot read or forge (the seal and the key bundle's
  checks are end-to-end), but it *can* drop, delay or refuse, sending
  willing users back to the onion route — an availability cost only, the
  same class the operator already holds.

## Compatibility and migration

- No wire, list or descriptor format changes: the front's domain was
  already published. Old clients ignore the setting; new clients on stacks
  without `[front] net` see only the onion route.
- `Route::parse` accepts the new forms; `Route::Off` (`off`) is new IPC
  vocabulary, understood by the netd in this release and ignored harmlessly
  by an older spare (`not a route`).
- `Cmd` gains tag 153; `Snapshot` gains `fast_route` between `route` and
  `tor_blocked` (readers of the state are versioned as the UI is).

## Costs

- The front holds a small pool of connections to the server and answers
  `POST`s it cannot read — no key, no log.
- Operators opt in per stack (`[front] net`), taking the clearnet traffic
  and whatever a provider's abuse desk brings with it, in exchange for
  their users' latency.
- Users who consent to `direct` accept the IP↔server link. Everyone else is
  exactly where they were.

## Alternatives considered

- Tuning arti alone: its onion-service client's path is six relays however
  it is tuned; the preemptive-circuit bump in `ArtiDialer::bootstrap` helps
  fetches, not the onion round trip.
- I2P, Veilid, GNUnet: the same latency class or smaller networks; none is
  a faster anonymity hop than C-tor, let alone than a front.
- A paid mixnet is what RFC 0010 moved away from.
- ECH to hide the domain from the link observer is its own project (public
  CAs, DNS plumbing) and does not hide the client's address anyway.
- Making `direct` netd's own TLS (no tord): rejected — it would break
  netd's no-TCP confinement for nothing; the carrier keeps all sockets in
  tord either way.

## Test plan

- `enclave-front`: `net_carries_a_request_to_the_server` — a request carried
  to a framing server and answered, one connection kept warm across
  exchanges, the one-way bit reaching the server, 404 without `[front] net`.
- `enclave-netd`: `the_fast_route_rides_the_front_and_falls_back` — the
  front answers first, one-way gets no reply, Maximum privacy refuses, a
  failed front cools down and the onion route answers, the cooldown ends and
  the front carries again.
- `enclave-tord`: `dials_through_a_no_auth_proxy` and
  `carries_requests_through_a_system_tor` (a no-auth SOCKS proxy standing in
  for a system Tor carries a real exchange end to end, `--tor-socks` to a
  dead port fails at once with the reason);
  `a_missing_socks_port_fails_at_once`.
- `enclave-net`: `routes_parse_and_are_learned` extended with
  `exit:`/`direct:`/`off`, port and no-port forms.
- CI `federation-e2e` gains a `TRANSPORT=front` variant: three stacks with
  `[front] net` open, clients routed `direct:` to the fronts (no Tor in CI),
  every request through `POST /net`.
- Nightly `live.yml` runs `ci/onion/front-bench.py` beside
  `carrier-bench.py` against the live test stack and records both in the
  job summary: onion (arti) vs onion (system C-tor) vs `exit` vs `direct`.

## Open questions

- Should the front's pool cap concurrent connections to the server, or does
  the server's own accept backlog suffice? (Current answer: no cap; the
  onion route opens streams just as freely.)
- Should a 404 from a front cool it down for longer than a failure (the
  stack has said it takes no fast traffic)? (Current answer: the same 60 s;
  cheap either way.)
