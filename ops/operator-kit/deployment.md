# Deploying an Enclave stack

One operator runs one stack: the server (keys, inboxes, key-transparency
log), a witness (cosigns other operators' logs), the front (the stack's
only HTTPS surface), a call relay and, optionally, a push relay. They come
as one image, `ghcr.io/enclavechat/enclave-server`, and one compose file,
`ops/compose/compose.yml`. See `docs/12-servers.md` for what each part does.

> **Status.** Production servers are reached only through the Nym mixnet,
> by the ingress sidecar (`ghcr.io/enclavechat/enclave-nym`, compose
> profile `nym`). It becomes the only way in once milestone S4 makes the
> production compose Nym-only. Until then a stack can be run and tested
> (the CI job `federation-e2e-tcp` runs three), but it is not ready for
> users.

## What you need

- A Linux host with Docker Engine 24 or later and the compose plugin.
- A domain name whose A/AAAA records point at the host.
- Open ports: 80 and 443/tcp (the front; 80 answers ACME challenges and
  redirects), 51820/udp (call relay). Nothing else is published.
- The foundation's public key and signed server list (`foundation.pub`,
  `server-list.bin`), from the foundation.

## First start

```sh
cd ops/compose
cp .env.example .env          # DOMAIN, OPERATOR, FAMILY, ACME_EMAIL, RELAY_PUBLIC_ADDR
for f in config/*.toml.example; do cp "$f" "${f%.example}"; done
cp /path/to/foundation.pub /path/to/server-list.bin foundation/

docker compose run --rm server init     # creates keys, prints the server id
docker compose run --rm witness init    # prints the witness id
docker compose run --rm relay init      # prints the relay descriptor
```

`OPERATOR` and `FAMILY` must be honest (see `operator-family.md`).

## Joining the foundation's list

Sign descriptors and send them to the foundation:

```sh
mkdir -p out && chmod 0777 out
docker compose run --rm -v "$PWD/out:/out" server  descriptor /out/server.bin  --config /etc/enclave/server.toml
docker compose run --rm -v "$PWD/out:/out" witness descriptor /out/witness.bin --config /etc/enclave/witness.toml
docker compose run --rm -v "$PWD/out:/out" relay   descriptor /out/relay.bin   --config /etc/enclave/relay.toml
```

The foundation checks them (`enclave-admin descriptor verify`), adds the
stack to the next list, and names the other operators' witnesses that will
cosign your log. Put those in `config/server.toml`:

```toml
[kt]
witnesses = ["https://witness-operator-b.example", "https://witness-operator-c.example"]
```

Then start everything:

```sh
docker compose up -d
docker compose ps                 # every service "healthy"
```

Check what the world sees:

```sh
enclave-admin descriptor fetch your.domain --id <server id>
```

## Updating the list

When the foundation publishes a new list, replace `foundation/server-list.bin`.
The server and the witness pick it up within a minute; nothing restarts.
They take it only if it verifies and is newer.

## Updating the software

Set `ENCLAVE_VERSION` in `.env` to the new release (or pin a digest:
`ENCLAVE_VERSION=1.2.0@sha256:…`), then:

```sh
docker compose pull && docker compose up -d
```

Releases are reproducible: building the published commit with
`ops/docker/Dockerfile` gives the same binaries (`cargo xtask repro`). From
the first release, images and their provenance are signed (cosign, keyless,
from the release workflow):

```sh
cosign verify ghcr.io/enclavechat/enclave-server:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/EnclaveChat/Enclave/'
```

## Backups

Two things must survive a lost host, and they are backed up differently:

1. **State** (`server-data` volume): the server writes consistent snapshots
   of its database and key-transparency log every `[backup] interval_hours`
   into the `backups` volume and keeps the newest `keep`. Copy that volume
   off the host regularly. You may also take one by hand while the server
   is stopped: `docker compose run --rm server backup /var/lib/enclave/backups`.
2. **Keys** (`server-keys`, `witness-keys`, `relay-keys`, `push-keys`
   volumes): written once by `init`. They are not in the snapshots. Back
   them up once, **encrypted**, to a place that is not the host, for
   example with `age`:

   ```sh
   docker run --rm -v enclave_server-keys:/k:ro alpine tar -C /k -cf - . | age -r <recipient> > server-keys.tar.age
   ```

   Losing the server's identity key means a new server id: every account
   on it would have to move (`docs/12-servers.md` §4.4). Losing the
   key-transparency head key or VRF secret breaks the pins every client
   holds for your log.

The key-transparency log must be backed up (`docs/13-operators.md` §5):
witnesses refuse a log that goes back in time.

## Restoring

```sh
docker compose stop server
# keys first, if the volume is new
docker run --rm -i -v enclave_server-keys:/k alpine tar -C /k -xf - < server-keys.tar   # decrypted
docker compose run --rm server restore /var/lib/enclave/backups/server-<time>.redb
docker compose start server
```

`restore` puts the server and key-transparency snapshots taken at the
same moment back, keeping the files it replaces as `*.redb.old`.

## State in PostgreSQL (optional)

The server keeps its state in a redb file in the `server-data` volume by
default. To keep it in PostgreSQL instead (`docs/12-servers.md` §6):

```sh
mkdir -p secrets
pw=$(openssl rand -hex 24)
printf '%s' "$pw" > secrets/postgres_password
printf 'postgres://enclave:%s@postgres/enclave' "$pw" > secrets/database_url
chmod 0444 secrets/database_url
docker compose -f compose.yml -f compose.postgres.yml up -d
```

Use the same `-f` pair for every later command. The database is reachable
only on the stack's internal network. Snapshots in the `backups` volume
stay redb files and are taken while the server runs; `restore` loads one
into PostgreSQL in a single transaction. The key-transparency log stays in
`server-data`, so keep backing that volume's snapshots up too. Moving an
existing stack: stop the server, take a `backup`, switch to
`compose.postgres.yml`, and `restore` that snapshot.

## Paying for the mixnet

Nym's gateways carry traffic against zk-nym tickets. Your stack's mixnet
clients (`ingress`, and with profile `push`, `push-egress` and
`push-ingress`) buy their own from a Nyx account you fund with NYM: put
its mnemonic in `secrets/nym/mnemonic`.

```sh
mkdir -p secrets/nym
printf '%s' 'word1 word2 … word24' > secrets/nym/mnemonic
chmod 0444 secrets/nym/mnemonic
```

Each buys a ticketbook (50 tickets of 200 MB, valid 7 days) at start and,
checked every 10 minutes, whenever fewer than 20 tickets are left. The
log says how many are left. When one runs low and can't buy (the account
is empty), it logs `LOW BALANCE` and its health check fails until a
purchase works again: watch for an unhealthy `ingress`. The account pays
only for your stack's own traffic; devices get their tickets from the
foundation's credential gate.

## Keys and rotation

- **Request keys** rotate every day by themselves, from a forward-secure
  chain. Yesterday's is kept for late requests; older ones can't be
  recovered from disk.
- **Push relay keys** rotate every 30 days with a 7-day overlap; the
  published file is `public/push-relay-keys.bin`. A push relay operator
  also runs `push-ingress` (profile `push`), whose Nym address
  (`public/push-ingress.addr`) goes into the foundation's list with the
  keys.
- **Call relay ticket keys** rotate daily.
- **Identity keys** (server, witness, relay) don't rotate: they are what
  the foundation's list names. Replacing one is leaving the list and
  joining again with a new descriptor.
- **TLS**: the front renews its certificate from Let's Encrypt when 30
  days are left (`TLS_MODE=acme`), or re-reads your files hourly
  (`TLS_MODE=files`).

## Backup route (onion service)

When the mixnet is unreachable, a device can offer its user a backup route
to your server through Tor, never in Maximum privacy. It needs your stack to
run the onion service (profile `onion`, recommended):

```sh
docker compose --profile nym --profile onion up -d
```

`onion` publishes an onion service in front of the server and writes its
address to `public/onion.addr`; the server puts it in its descriptor, so
devices learn it while the mixnet works. The service's Tor identity key is
in the `onion-data` volume: back it up with the keys, or the address
changes (devices learn the new one from the next descriptor).

## Push

With profile `nym`, `push-egress` carries the server's due wakes to the
push relay over the mixnet. Set `PUSH_RELAY_NYM` in `.env` to the relay's
Nym address from the foundation's list, and in `config/server.toml`:

```toml
[push]
forward = "push-egress:7446"
```

### Running the push relay

Only the operator the foundation names runs `push-relay` and
`push-ingress` (profile `push`). UnifiedPush endpoints need nothing
more; APNs and FCM need the project's credentials (External Gate G6),
kept in `secrets/push/` and named in `config/push-relay.toml`:

```sh
mkdir -p secrets/push
cp AuthKey_KEYID.p8 secrets/push/apns.p8          # Apple: the .p8 provider key
cp service-account.json secrets/push/fcm.json     # Google: the FCM service account
chmod 0444 secrets/push/*
```

```toml
[apns]
team_id = "TEAMID1234"
key_id = "KEYID12345"
key_file = "/run/secrets/push/apns.p8"
topic = "io.github.enclavechat.enclave"
# endpoint = "https://api.sandbox.push.apple.com"   # development builds

[fcm]
service_account_file = "/run/secrets/push/fcm.json"
```

The relay logs the platforms it delivers to when it starts. It keeps no
logs of wakes, only counts. APNs gets the generic alert "New message"
with the 1,024-byte capsule for the notification extension; FCM and
UnifiedPush get content-free wakes.

## Descriptor publishing

The server signs a fresh descriptor at start and at every daily key
rotation. It serves it to clients, writes it for the front
(`https://your.domain/.well-known/enclave`), and commits its digest to its
key-transparency log, so it can't show different clients different
descriptors.

## Nix

A Nix flake with the same pinned toolchain arrives with the release
pipeline (milestone R2). Until then, use the image or build from source
(`cargo build --release --locked -p enclave-server`).
