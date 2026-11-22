# RFC 0012: Auto-federation — a new stack joins by proving itself to one address

- **Status:** Proposed
- **Author(s):** Enclave maintainers
- **Created:** 2026-11-19
- **Comment period ends:** 2026-12-19
- **Affects:** `12-servers.md` (§3 list building, new §6 registration), `13-operators.md`, `01-threat-model.md` §2 (A-INF, A-LEG), `redteam-matrix.md`, `enclave-server` (list ingestion), `enclave-front` (proxy paths), new `enclave-registrar`, `ops/compose`, `ops/setup.sh`
- **Crypto WG review required:** yes (list trust)

## Summary

A new operator copies the compose stack, fills a `.env` (or answers
`ops/setup.sh`), brings it up, and gives the stack the address of **one**
existing server. The stack's descriptor and a proof of work go to the
**registrar** (the foundation's always-on service, found through that one
address); the registrar checks the stack actually works from the outside,
and when satisfied builds and double-signs the next server list with the
new stack in it and pushes that list to **every** listed server. Clients
pick the new server up with their next daily list refresh. Nobody touches
`enclave-admin` by hand; the trust model doesn't move by an inch.

## Motivation

Today joining is manual: the operator submits a descriptor, a human runs
`enclave-admin server-list build … sign …` with the foundation key on an
offline machine, and the signed list is copied to every stack. That's a
fine ceremony for five servers and one maintainer, and an impossible one
for fifty — and the list expires in three days, so even unchanged
membership needs the ceremony forever. The single biggest barrier to
"anyone can run one" (`00-overview.md`) is not the stack; it is the list.

## Design

### 1. The rule that shapes everything

The list is double-signed under the foundation key and clients pin that
key in the binary (`ENCLAVE_FOUNDATION_PUB` at build). That is what makes
a listed server *vouched for*. So membership can only change under the
foundation key's signature — no existing server may add a newcomer on its
own, and this RFC does not change that. What it automates is everything
around the key: proving a stack worthy, building, signing, distributing.

### 2. The registrar (`enclave-registrar`)

An always-on HTTP service the foundation runs (compose profile
`registrar`, behind its front at `/registrar/v1/`). It holds the
foundation **signing** key — the one trust-relevant change, see Security —
and does two things:

**`POST /registrar/v1/apply`** — a new stack's application:
- Body: the stack's `ServerDescriptor` bytes, its witness's
  `WitnessDescriptor` bytes, a proof of work (the inbox-creation context
  and effort over `descriptor digest ‖ day`, so an application costs what
  an inbox costs), and an optional operator contact.
- Checks, in order: both descriptors decode, self-sign and validity
  window; the PoW; **reachability** — the registrar fetches
  `https://<domain>/.well-known/enclave` itself, over the Enclave TLS
  profile with public roots, and the bytes must equal the application's
  descriptor (so the domain, the certificate and the front all work, from
  the outside, now); the witness's cosigning API answers; the server's
  policy is sane (quotas and retention present); the operator and family
  are non-empty.
- Accepted applications queue (open enrollment) or wait for
  `registrar approve` (guarded mode) — the same key-online question as
  ACME, answered per deployment, not in code.

**Rebuild, sign, push** — periodically and after each acceptance: the
registrar re-fetches every listed server's descriptor over its front and
verifies it against the *previous* list entry (the identity key is the
continuity anchor: a server may change anything except who it is),
assembles the new list — servers and witnesses from the live descriptors,
the foundation's own relays, push relays and credential gates from a
static spec — bumps `seq`, signs twice, and pushes the signed bytes to
every listed stack. List expiry stops being a human's problem the same
way.

### 3. Servers become autonomous mirrors (`/federation/list`)

Each stack's front proxies `/federation/list` to its server. A `POST`
there carries a fully signed list; the server verifies **both signatures
against the foundation public key** (a new public `[server] foundation`
config item — a public key, no secret), requires `expires > now` and
`seq >` the list it holds, and only then swaps the file it serves. No
token, no shared secret: possession of the foundation's signature *is*
the authority, and anyone may POST — unsigned or stale lists are refused
by construction. A server that misses a push still heals: it takes the
newer list from the next push, or from the registrar's own mirror.

`/federation/apply` on every stack simply forwards an application to the
registrar (its address is in the server's config), so **the one address a
new operator types can be any listed server** — exactly the ask.

### 4. `ops/setup.sh`

Prompts (or takes flags) for the `.env` values (domain, operator, family,
ACME email, the one known server address), writes `.env` and configs from
the examples, `docker compose up -d`, waits for the front's healthcheck,
then fetches the stack's own descriptor, grinds the proof of work, and
POSTs the application to the known server's `/federation/apply`. The
answer says "queued" or "approved"; the operator is on the list when the
next list lands (minutes in open mode).

## Security and privacy analysis

- **The trust root does not move.** Clients still verify one pinned
  foundation key; servers verify pushes under the same public key; no new
  server and no listed server ever holds signing authority.
- **The registrar holds the signing key online.** That is the real
  trade. Mitigations: it is the only process with the key, on the
  foundation's stack, reachable only through its front; guarded mode
  (`approve` per application) keeps the human in the loop for
  enrollments while still automating rebuild/sign/push; the offline
  `enclave-admin` flow remains and the registrar can be run with the key
  absent (apply-only, answering "come back"). Rotation: the key file can
  be swapped and clients accept a new list under the new key at the next
  build — the pin is per-build, so rotation remains a release-time act
  (unchanged from today).
- **List spam and junk stacks.** An application costs proof of work (the
  inbox tier), reachability is checked from the outside *at application
  time and at every rebuild*. A failing application is retried for a day
  and let go, and never holds up the list. A listed stack whose front
  stops serving its verified descriptor keeps the entry it last proved
  (it is neither dropped on a blip nor able to stop the list renewing);
  removing one is the foundation's decision. Abuse of the foundation's listing remains the foundation's
  call, as today.
- **A malicious registrar operator** (if the foundation is ever someone
  else) can add or drop servers — but that is exactly the power the
  foundation key already confers; this RFC automates its exercise, it
  does not broaden it. Clients' descriptor checks (KT commitment,
  witness quorum) still apply per server after listing.
- **Nothing about messages changes.** Federation here is discovery and
  vouching only: there is still no server-to-server relay, no sharing of
  user data, and each message still travels sealed to its own server.

## Compatibility and migration

- The list format is unchanged (v3); clients need nothing new. Servers
  gain one config item (the foundation public key) and two endpoints;
  without them a stack simply keeps today's file-based list and
  everything works as before.
- The manual `enclave-admin` flow stays as the fallback and the
  ceremony of record for the very first list.

## Costs

- One new always-on service on the foundation stack, holding the key in
  open mode.
- Each listed stack serves a few extra POSTs a day.

## Alternatives considered

- **Any listed server can add newcomers** (gossip membership): breaks the
  single-signature vouching clients rely on; a threshold co-signed list
  is the honest version of this and is a much larger change to client
  verification — recorded as a possible future, not needed while the
  foundation is one maintainer.
- **A web form the foundation runs**: same trust, more code, no
  reachability proof from the applicant's own stack; the registrar is
  that form done properly.
- **TUF for the list** (R2): orthogonal and complementary; this RFC's
  push endpoint would become TUF's channel unchanged.

## Test plan

- Server: `a_pushed_list_is_taken_when_signed_and_fresher` (unsigned,
  stale-seq, expired and valid cases; the served list swaps).
- Registrar: application validation (bad PoW, descriptor mismatch with
  what the front serves, good path), rebuild-sign-push roundtrip with
  test keys against two in-process stacks, drop-on-broken-front.
- Federation CI: the three-stack e2e grows a fourth stack that joins via
  `setup.sh`'s apply path against stack a's registrar and appears in the
  list stacks serve.
- `ops/setup.sh` shellchecked; its PoW verified against the API in a
  unit test (python and Rust agree on a context).

## Open questions

1. **Resolved (deferred by decision):** the registrar does not dial the
   new stack's onion service in v1 — that means a Tor client on the
   foundation stack. The onion address is carried in the descriptor and
   clients verify it live; extending the rebuild's reachability checks to
   it is a later, small change.
2. **Resolved:** a fresh stack's witness is listed with the threshold
   unchanged — the threshold counts listed witnesses, so a joining stack
   widens the quorum rather than diluting it. Witness churn, if it ever
   grows, is a threshold-policy question, not a joining one.
