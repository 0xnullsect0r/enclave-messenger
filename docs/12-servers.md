# Servers, Key Transparency, Discovery, Relays

Status: Draft (M0, reconciled with the M3 code) · Normative

Source: PLAN.md §12.1 to §12.3 and §12.5. Crates: `enclave-server`, `enclave-kt`, `enclave-tokens`, `enclave-rpc`; later `enclave-witness`, `enclave-relay`, `enclave-push-relay`. Moderation and the operator kit are in `13-operators.md`. Where this document and the code disagree, the code is normative.

## 1. `enclave-server`

`enclave_server::Server` is an untrusted mailbox. `Server::handle(request, now)` maps one sealed request (unit or poll) to one sealed reply unit and is transport-agnostic: the dev binary serves it over TCP (`09-transport.md` §1), and a Nym service provider will serve it in production. The server keeps **no accounts, no phone numbers and no IP addresses**; everything it stores is keyed by random addresses, hashes, or public keys. State lives in one redb database file (§1.3); the long-term keys live in a separate key directory (§1.4). Tests, the simulator and the offline demo use the same code over an in-memory database.

### 1.1 Configuration

Operators write `server.toml` (`config.rs`, `FileConfig`). Every key can be overridden from the environment as `ENCLAVE_<SECTION>__<KEY>` (for example `ENCLAVE_SERVER__DOMAIN=a.example`), which is how the compose file sets per-deployment values; integers and `true`/`false` keep their type. Unknown keys are refused, so a typo never silently falls back to a default. `load` also checks that `server.domain` is a domain name, that `policy.ttl_days` and `policy.inbox_quota` are positive. `run` also requires `server.operator` when key transparency is on: clients never count a witness run by the log's own operator, so the log has to name it.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[server]` | `domain` | `localhost` | Public domain (descriptor, usernames) |
| | `operator`, `family` | empty | Operator name; operator family (servers of one family never count as independent) |
| | `data_dir` | `/var/lib/enclave/server` | Holds `server.redb` |
| | `keys_dir` | `/var/lib/enclave/keys` | Long-term keys (§1.4) |
| | `listen` | `127.0.0.1:7443` | Where the ingress reaches the server |
| | `public_dir` | `/var/lib/enclave/public` | Files the front serves (KT pins, descriptor) |
| | `nym_address` | empty | The ingress's Nym address, published in the descriptor |
| | `server_list` | none | A copy of the foundation's signed list to serve (`DirKind::ServerList`), re-read when it changes |
| `[policy]` | `effort_request`, `effort_claim`, `effort_blob`, `effort_username`, `effort_inbox`, `inbox_quota`, `request_quota`, `token_quota`, `ttl_days` | as `Config` below | Abuse controls |
| `[kt]` | `enabled` | `true` | Username log (`data_dir/kt.redb`, §3.1) |
| `[push]` | `forward` | none | Push egress address for due wakes |
| `[backup]` | `dir`, `interval_hours`, `keep` | none, 24, 7 | Snapshots (§1.5) |
| `[database]` | `url`, `url_file` | empty (redb in `data_dir`) | PostgreSQL instead (§6) |

`FileConfig::policy(id)` gives the in-process `Config`:

| Field (`Config`) | Default | Meaning |
|---|---|---|
| `id` | — | 16 B server identifier |
| `effort_request` | 64 | Equi-X effort for `WriteRequest` |
| `effort_claim` | 8 | Equi-X effort for a bundle claim |
| `effort_blob` | 1 | Equi-X effort for `BlobPut` |
| `effort_username` | 64 | Equi-X effort for a username claim (§3.5) |
| `effort_inbox` | 16 | Equi-X effort for creating an inbox; 0 turns the check off (tests) |
| `inbox_quota` | 5,000 | Stored envelopes per account inbox |
| `request_quota` | 100 | Pending envelopes per request inbox |
| `token_quota` | 4,096 | Registered unspent token hashes per inbox |
| `ttl_secs` | 30 days | Lifetime of envelopes and blobs |

Proof-of-work contexts (`enclave_rpc::api`), each passed to `enclave_tokens::verify` (`02-cryptography.md` §10):

| Action | Context | Proof carried in |
|---|---|---|
| Request-inbox write | `"request-inbox" ‖ mailbox (32) ‖ u64(day) ‖ SHA3-512(envelope region)` | header token field |
| Report | `"report" ‖ mailbox (32) ‖ u64(day) ‖ SHA3-512(envelope region)` | header token field |
| Username claim | `"claim-username" ‖ key (32) ‖ u64(day)` | `DirRequest.proof` |
| Bundle claim | `"claim-bundle" ‖ key (32) ‖ u64(day)`, `day = floor(now / 86,400)` | `DirRequest.proof` |
| Blob upload | `"blob-put" ‖ chunk ID (32) ‖ SHA3-512(chunk)` | header token field |
| Inbox creation | `"inbox-create" ‖ mailbox (32) ‖ u64(day)`, today or yesterday | framed payload of `RegisterTokens` + `CREATE` |

**Every proof is single-use.** A day-bound proof (all but the blob upload) is accepted for today or yesterday (`day = floor(now / 86,400)`, so a client near midnight isn't refused) and only once: the server records `u32(day) ‖ proof` in the redb table `pow-spent` (schema 5) in the same step it accepts the proof, and drops a day's records once that day can no longer be proven for (`Server::expire`). A spent proof gets `Pow`, and a client simply solves a new one. So one solution claims one one-time prekey (RT-06, test `rt06_opk_claim_requires_pow`) and writes one request (RT-25, test `rt25_request_requires_pow_or_capability`). A blob proof is bound to the chunk ID, and an ID is stored once (`Denied` after), so it needs no record.

### 1.2 Operations

| Op | Server behavior |
|---|---|
| `Cover` | Count it; reply `Ok`. |
| `RegisterTokens` + `EFFORT` (0x40) | Owner only (`Denied`), request inboxes only (`Denied`): the payload's `u32` (≤ 16,384, else `Malformed`) becomes the effort writers to it need, 0 for the server's (`13-operators.md` §2). |
| `RegisterTokens` + `CREATE` | Verify the PoW (`Pow`). If the address exists: `Denied`. Otherwise create the inbox with `owner = credential_hash(token)`, `read = credential_hash(read_credential(token))`, request flag from `REQUEST_INBOX`, sequence numbers starting at 1. |
| `RegisterTokens` | Inbox must exist (`NotFound`) and `credential_hash(token)` must equal `owner` (`Denied`). The payload must be a multiple of 32 B (`Malformed`); the unspent total must stay ≤ `token_quota` (`Quota`). Insert the hashes; with `REVOKE` (0x08), remove them instead (cancelled invite links). On a request inbox the hashes are invite capabilities. |
| `Write` | Inbox must exist and not be a request inbox (`Denied`). Burn `token_hash(token)` or reply `Denied`. Store the envelope under the next sequence number, or `Quota` if the inbox holds `inbox_quota` envelopes. |
| `WriteRequest` | Inbox must be a request inbox (`Denied`). With `INVITE` (0x08), burn `token_hash(token)` (an invite capability, `03-identity.md` §9.2) or reply `Denied`; otherwise verify the PoW at the larger of the server's effort and the one the inbox's owner set (`Pow`). Store; when `request_quota` envelopes are pending, drop the oldest first (FIFO). |
| `Poll` | `credential_hash(token[0..24])` must equal `read` (`Denied`). Return the first envelope with sequence number > `u64(token[24..32])`, with `FOUND`, the sequence number in the reply token, and `MORE` if another follows; or `Ok` with no envelope. |
| `Ack` | Same credential check. Delete every envelope with sequence number ≤ `u64(token[24..32])`. |
| `BlobPut` | If the chunk ID exists: `Denied`. Verify the PoW (`Pow`). Store the envelope region under the ID. |
| `BlobGet` | Return the chunk, or `NotFound`. No credential. |
| `Directory` | §2. A payload that does not parse gets `Malformed`. |
| `KeyTransparency` | Not wired to `enclave-kt` yet: `NotFound`. |
| `Status` | Return the kept answer whose status id is the mailbox, once, sealed to this poll; or `Status` with `NotFound`. |
| any unit op + `DEFER` (0x80) | Handled as usual; the reply is also kept in memory (not in the database) under the request's status id for 10 minutes, at most 65,536 answers and 64 MiB of them (`08-envelope.md` §2.2). |
| `Report` | The mailbox must be one of this server's request inboxes (`NotFound`). Verify and spend the PoW at the request effort (`Pow`); the payload must parse as a `ReportBody` (`Malformed`). Queue it for the operator with the day it arrived; at most 1,000 are kept, oldest dropped first. `Server::take_reports()` hands them to the operator and `Server::disable_request_inbox()` closes a reported account's request inbox. |

A storage failure answers `Unavailable` (status 7) and applies nothing; the client tries again later.

`Server::expire(now)` deletes envelopes and blobs older than `ttl_secs`, bundle claims older than 600 s, unfinished uploads older than 600 s and kept answers older than 600 s. `Server::install_key(key)` makes a request key from the chain (§1.4) current and keeps one previous (`09-transport.md` §2.1); in-memory servers use `Server::rotate(day)`, which draws a random one. `Server::stats()` returns aggregate counters only (requests, cover, stored, tokens burned, denied). `Server::reports()` lists queued reports without removing them; `Server::take_reports()` removes them.

### 1.3 State the server holds

| Store | Key | Value | Retention |
|---|---|---|---|
| Inbox | 32 B address | owner-secret hash, read-credential hash, request flag, unspent token hashes, envelopes with sequence numbers and receive time | Envelopes: until acknowledged or 30 days |
| Manifest | manifest key (§2.1) | latest version and signed manifest bytes | Until replaced by a higher version |
| Prekey publication | 16 B device ID | publication and the index of the next unserved one-time prekey | Until replaced |
| Claim | 32 B random claim ID | encoded bundle | 600 s |
| Vault object | 32 B locator | owner-secret hash and opaque bytes | Until replaced by the same owner |
| Blob | 32 B chunk ID | 14,336 B chunk | 30 days |
| Upload | (kind, key) | chunks received so far | Until complete |

Nothing in this table is an IP address, a Nym identity or an account identifier. Receive times are stored only to expire envelopes.

**Persistence (`db.rs`).** Everything above except claims and unfinished uploads (both short-lived) is kept in redb tables: inboxes, tokens (keyed `mailbox ‖ hash`), envelopes (keyed `mailbox ‖ seq`), manifests, devices seen, attestations, migrations, moved records, server moves (§4.4), tombstones (§3.5), the request replay cache (`replays`, `09-transport.md` §2.3), spent proofs of work (`pow-spent`, §1.1), device owners, bundles, vaults, blobs, push registrations, usernames, names by root, reports and a `meta` table holding the schema version (5; each version only added tables, and older files gain them on open). Each request runs in one write transaction that commits before its reply is sealed, so a server killed at any point either did all of a request or none of it: a burned token stays burned, and an envelope that was acknowledged as stored survives (`tests/restart.rs`). Key-transparency replies, push wakes and bundle claims are held in memory and expire within minutes; losing them in a restart costs a client one retry.

### 1.4 Identity and daily request keys

`enclave-server init` creates the key directory (mode 0700) with four files (mode 0600, written atomically, never overwritten):

| File | Contents |
|---|---|
| `identity.key` | The server's composite Ed448 + ML-DSA-87 signing key |
| `kt-head.key` | The key-transparency head-signing key (composite) |
| `kt-vrf.key` | The key-transparency VRF secret (32 B) |
| `request-chain.key` | `u32(day) ‖ today's chain seed (32) ‖ 0x00`, or `… ‖ 0x01 ‖ yesterday's chain seed (32)` while yesterday's key is still served |

The **server id** is the first 16 bytes of `SHAKE256("enclave/v1/net/server-id" ‖ identity public key)`: self-certifying, so a descriptor or key certificate signed by the identity proves which id it speaks for.

**Request keys** come from a forward-secure seed chain. Day `d`'s key is derived deterministically: `KMAC256(seed_d, u32(d), "enclave/v1/server/request-key")` gives 120 bytes, the X448 secret (56 B) and the ML-KEM-1024 key-generation seed (64 B). The next seed is `seed_{d+1} = KMAC256(seed_d, "", "enclave/v1/server/request-chain")`. At midnight UTC the server steps the chain, rewrites the file with today's and yesterday's seeds, and drops older ones, so nothing on disk can recompute a request key older than yesterday's (`tests/restart.rs`, `request_keys_roll_forward_and_old_seeds_are_gone`). Because keys are deterministic, a server that restarts serves the same key and clients' cached keys keep working. Today's seed also yields tomorrow's key, which the descriptor publishes in advance.

### 1.5 Running a server

```text
enclave-server init        [--config FILE]   create keys; print the server id
enclave-server run         [--config FILE]   serve (state in redb, keys from disk)
enclave-server show-id     [--config FILE]   print the server id
enclave-server backup DIR  [--config FILE]   snapshot the database (server stopped)
enclave-server restore SNAPSHOT [--config FILE]   put a snapshot back (server stopped)
enclave-server descriptor  [--config FILE]   verify and print the published descriptor
enclave-server healthcheck [--config FILE]   exit 0 if the server answers
enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]
```

`run` listens on `server.listen` with the length-prefixed frame transport (`09-transport.md` §1); in a deployment only the Nym ingress on the stack's internal network can reach it. Once a minute it steps the request-key chain if the day changed and expires old objects. With `[backup] dir` set it writes `server-<unix time>.redb` and `kt-<unix time>.redb` snapshots at start and every `interval_hours`, and keeps the newest `keep` of each. On SIGTERM or Ctrl-C it waits for the request in flight (which has already committed) and exits. A restore needs both a snapshot and the key directory; the key directory must be backed up separately, encrypted and off the host. `restore` refuses while `run` holds the database, keeps the files it replaces as `*.redb.old`, and restores `kt-<t>.redb` with `server-<t>.redb`. Restoring a key-transparency log older than the last head witnesses cosigned makes the next heads look like a fork to them (they refuse heads that don't extend the one they hold), so restore the newest snapshot. `dev` is the all-in-memory development server: random keys every start, nothing persisted; a bare `enclave-server [ADDR]` runs it.

## 2. Directory

### 2.1 Objects and keys

| Kind | Key | Object | Published by | Fetched by |
|---|---|---|---|---|
| 1 `Manifest` | `SHAKE256("enclave/v1/dir/manifest" ‖ root_pk, 32)` (`manifest_key`) | `SignedManifest` encoding (`03-identity.md` §3) | The account | Anyone with the root public key |
| 2 `Bundle` | `device_id (16) ‖ 0^16` (`device_key`) | `Publication` on put; `Bundle` on claim | The device | Initiators, through claims |
| 3 `Vault` | 32 B random locator | Opaque bytes (the client-sealed vault key) | The account | Holders of the locator and its key (contact card) |
| 4 `Username` | The name's bytes, zero-padded to 32 (`name_key`) on put and on the first get; the reply ID on later gets | `UsernameClaim` on put; `LookupReply` on get (§3.7) | A device of the account | Anyone who knows the name |
| 5 `Attest` | Like the manifest | Device attestations (co-sign or veto, `03-identity.md` §8.1) | A listed device | Contacts and our own devices |
| 6 `Migration` | The **old** root's `manifest_key` | `Migration` record (`03-identity.md` §8.2) | The account, after changing its recovery words | Anyone holding an old code |
| 7 `Descriptor` | Ignored | The server's signed `ServerDescriptor` (§4.3); never uploaded | The operator | Clients |
| 8 `ServerList` | Ignored | The foundation's signed list as mirrored (§4.1); never uploaded | The operator | Clients |
| 9 `Moved` | Like the manifest | Root-signed `ServerMove` (§4.4) | The account, leaving | Contacts |
| 10 `Tombstone` | Like the manifest | Root-signed `Tombstone` (§3.5) | The account, deleting itself | Anyone |
| 11 `Equivocation` | The log's server id, zero-padded | Two heads of one epoch (§3.8) | A client that found them | Anyone |

Objects travel in `DirRequest`/`DirReply` payloads as chunks of at most 14,000 B (`08-envelope.md` §9.3).

### 2.2 Put

`DirAction::Put` sends one chunk: `total` must be 1 to 200 and `index < total` (`Malformed`). Chunks accumulate per `(kind, key)`; a chunk with a different `total` than the upload in progress discards it (`Malformed`). Until every chunk has arrived the reply is `Ok`. When the last one arrives, the chunks are concatenated in index order and validated:

- **Manifest:** decode the signed manifest and its body (`Malformed`); the key must equal `manifest_key(root)` of the manifest's own root (`Invalid`); the root signature and validity window must verify (`SignedManifest::verify` with the manifest's root, `Invalid`); the version must be higher than the stored one (`Invalid`). Then store it.
- **Bundle:** decode the publication (`Malformed`); the key must equal `device_key` of the signed prekey's device (`Invalid`); some stored manifest must list that device (`NotFound`), and `Publication::verify` must pass with that device's composite key (`Invalid`). Then store it and reset the one-time-prekey pointer to 0.
- **Username:** see §3.7.
- **Migration:** decode the record (`Malformed`); the key must be the old root's `manifest_key` and the old root must have cross-signed it (`Invalid`); the new root's manifest must already be stored (`NotFound`) and the record must verify against it (`Migration::verify`, `Invalid`); only one per key (`Invalid`). From then on a `Manifest` put under the old key is `Denied`, a `Manifest` get under it is `NotFound` (so old codes don't lead to the account), and a username the old root held may be claimed by the new root (§3.5).
- **Vault:** `DirRequest.proof` is the owner secret. If the locator exists with a different owner hash: `Denied`. Otherwise store the bytes with `credential_hash(owner secret)`. The server does not interpret the bytes.

### 2.3 Get and claim

- `Manifest`/`Get` and `Vault`/`Get` return chunk `index` of the stored object with the total chunk count, or `NotFound`.
- `Bundle`/`Claim`: verify the PoW in `proof` (`Pow`); look up the publication of `key[0..16]` (`NotFound`); build a `Bundle` with the signed prekey, the next unserved one-time prekey and its batch header (none if all 100 are served), and the last-resort prekey; advance the pointer; store the encoded bundle under a fresh random 32 B claim ID for 600 s; reply with chunk 0 and the claim ID.
- `Bundle`/`Get` with `key` = claim ID returns further chunks of a claimed bundle.
- `Username`/`Get` with `index` 0 and `key` = `name_key(name)` runs a lookup (§3.7), stores the encoded reply under a fresh random 32 B reply ID for 600 s and returns chunk 0 with that ID; `index` > 0 with `key` = reply ID returns further chunks. A lookup of an unknown name, or on a server without a log, is `NotFound`.
- Any other kind and action combination: `Malformed`.

Each one-time prekey is served once. Manifests and publications are stored in the clear (`01-threat-model.md` §4 note 1).

## 3. Key transparency (`enclave-kt`)

### 3.1 Tree and configuration

- `KtLog` wraps Meta's **akd** 0.13 (NCC-audited 2023). Its storage is `KtStore` (`store.rs`), akd's `Database` trait over redb in its own file, `kt.redb`; akd's own storage-layer test suite runs against it (`tests/store.rs`). Next to the tree it keeps the signed heads with their cosignatures, the confusable-skeleton index, and, for witnesses run with a store, the head each last cosigned. akd commits an epoch in one `batch_set`, which is one redb transaction. `KtLog::open` refuses a store whose heads don't verify under the head key or whose tree root doesn't match the last signed head; if the process stopped between committing an epoch and storing its head, that head is signed on open. The head-signing key and the VRF secret are files in the server's key directory (§1.4), so the pins clients hold survive restarts. Each `publish` call is one epoch; batching claims into one epoch per window (so claims made together can't be told apart by epoch) is not implemented (S5). `heartbeat` starts an epoch with no username change (label `0x00 ‖ "heartbeat"`, which no valid username can equal) so heads stay fresh.
- `KtService` runs the log on its own thread with its own tokio runtime (akd spawns tasks), so the synchronous request handler can call it from any context. After every epoch it asks each attached witness to cosign (§3.3). A lookup against a head older than 1 h first starts a heartbeat epoch.
- `EnclaveKtConfig` replaces every akd hash with domain-separated SHAKE256-256:

```
H(x)                     = SHAKE256("enclave/v1/kt/akd" ‖ x, 32)
i2osp(x)                 = u64(len(x)) ‖ x
empty root / empty node  = 0^32
leaf commitment(v, n)    = H(i2osp(v) ‖ i2osp(n))
leaf with epoch          = H(commitment ‖ u64(epoch))
commitment nonce         = H(commitment_key ‖ u32(label_len) ‖ label_val)
fresh value              = H(i2osp(v) ‖ i2osp(nonce))
label hash input         = H(i2osp(label) ‖ u8(freshness) ‖ u64(version))
parent                   = H(left_value ‖ left_label ‖ right_value ‖ right_label)
root hash                = root value
stale value              = akd EMPTY_DIGEST
empty label              = { value: 0x01 ‖ 0^31, length: 0 }
```

- Label privacy uses akd's classical ECVRF (Ed25519); it only hides usernames from enumeration. Binding is hash-based and post-quantum.
- The leaf value is `root_pk (64) ‖ ContactCard` (`03-identity.md`). A bare `root_pk` is a released name. `KtLog::publish` performs no authorization; the server's `Username` put does (§3.7).

### 3.2 Signed tree heads

```
head       = server (16) ‖ u64(epoch) ‖ root (32) ‖ u64(time)                          # 64 B
server sig = CompositeSign(server_sk, ctx = "enclave/v1/kt/head", head)
cosign msg = head (64) ‖ u64(witness_time)
cosig      = CompositeSign(witness_sk, ctx = "enclave/v1/kt/cosign", cosign msg)
gossip     = SHAKE256("enclave/v1/kt/gossip" ‖ head, 32)                                 # 32 B digest
```

A `Cosignature` is `(witness id (16), witness time, signature)`.

### 3.3 Witnesses

`Witness::cosign(server_key, heads, proof, now)` cosigns the newest of a run of heads:

1. every head's server signature verifies, all heads name the same server, and their epochs are consecutive;
2. if the witness has cosigned this server before, the first head's epoch is the last cosigned epoch + 1, and the akd append-only proof from the last cosigned root through every new root verifies (`NotAppendOnly` otherwise);
3. the first time a witness sees a server, it cosigns without a proof (trust on first use);
4. it signs `newest head ‖ u64(now)` and remembers the newest head.

A witness never cosigns two inconsistent heads for one server, because step 2 requires consecutive epochs and a valid append-only proof from its last head.

**As a service** (`enclave-witness`, test `crates/enclave-witness/tests/witness.rs`): a witness runs as `enclave-witness run` with a composite cosigning key (`init`; the witness id is `SHAKE256("enclave/v1/kt/witness-id" ‖ key)`), remembers what it cosigned in redb (`Witness::with_store`), and witnesses only the logs in the foundation's server list, under the head key the list pins for each server, re-reading the list when its file changes. It serves `GET /witness/v1/descriptor`, `GET /witness/v1/last/<server id>` and `POST /witness/v1/cosign` (body `u8(1) ‖ u32(n) ‖ n × (u32 len ‖ SignedHead) ‖ u8(has proof) [‖ u32 len ‖ AppendOnlyProof as akd protobuf]`, answer the cosignature; 403 for an unlisted log or a bad signature, 409 for a head that doesn't extend the last cosigned one). It serves HTTPS with the Enclave TLS profile when given a certificate (`tls_cert`, `tls_key`), plain HTTP otherwise for a front on the same network. A log's server reaches witnesses through `enclave_kt::WitnessClient`: `Witness` in process, `enclave_witness::HttpWitness` over HTTPS (`[kt] witnesses = [URLs]`, `witness_ca` for a private CA). A witness that refuses is asked for its last head, and the next round sends the heads and append-only proof from there. The test runs a log against two witness services and checks that a lookup verifies at threshold 2 under pins derived from the list, that a fork of the log is refused (409), and that a log the list doesn't name is refused (403).

### 3.3a C2SP checkpoints and cosignatures

Each witness also publishes what it cosigned in the formats of the transparency-log ecosystem, so tools built for it (monitors, other witness networks) can follow Enclave's logs (`enclave_kt::c2sp`; [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint), [tlog-cosignature](https://c2sp.org/tlog-cosignature), [signed-note](https://c2sp.org/signed-note)):

```
checkpoint = "enclave-kt/" hex(server id) "\n" decimal(epoch) "\n" base64(root) "\n"
key name   = "enclave-witness/" hex(witness id)
key id     = SHA-256(key name ‖ "\n" ‖ type ‖ public key)[0..4]           type 0x04 Ed25519, 0x06 ML-DSA-44
Ed25519    signs "cosignature/v1\ntime " decimal(time) "\n" ‖ checkpoint
ML-DSA-44  signs "subtree/v1\n\0" ‖ u8 len ‖ key name ‖ u64(time) ‖ u8 len ‖ origin ‖ u64(0) ‖ u64(epoch) ‖ root
note       = checkpoint "\n" + one "— key name base64(key id ‖ u64(time) ‖ signature)" line per key
```

The checkpoint's tree size is the akd epoch and its hash the akd root. Both keys are derived from the witness's composite seed (KMAC label `enclave/v1/kt/c2sp-key`, data `ed25519` or `ml-dsa-44`), so they need no new key file, and the witness descriptor (signed by the composite key) lists their verifier keys (`c2sp_vkeys`). The witness signs both at the moment it makes its composite cosignature, with the same time, and serves the note at `GET /witness/v1/checkpoint/<server hex>` and the verifier keys at `GET /witness/v1/c2sp-key` (`HttpWitness::checkpoint`, `c2sp_vkeys`). Clients never rely on these: their check (§3.4) is the composite cosignature, ML-DSA-87 + Ed448. Test: `two_remote_witnesses_meet_threshold_two` checks the note under both keys; in CI (job `tls-interop`) the same note is verified by the reference Go implementation (`ci/c2sp`, `golang.org/x/mod/sumdb/note` with `github.com/transparency-dev/formats/note`), which also parses the checkpoint.

### 3.4 Client policy and lookups

`WitnessPolicy { witnesses: [(id, key, operator)], threshold }`. `check(signed_head, server_key, server_operator, now)`:

1. the server signature verifies (`Signature`);
2. each cosignature counts once per witness ID, only if the witness is pinned, only if its operator differs from `server_operator` (operator independence), and only if it verifies;
3. at least `threshold` and at least one cosignature count (`Quorum`);
4. **trusted time** is the median of the counted witness times (`times[len / 2]` after sorting, the upper median for an even count);
5. the head is stale (`Stale`) if `now > head.time + 24 h + 1 h` or `trusted + 24 h < head.time`.

`verify_lookup(policy, server_key, server_operator, vrf_public, signed_head, name, proof, now)` runs `check`, normalizes the name (§3.5), verifies the akd lookup proof against the head's root and epoch, and returns `(value, version, trusted time)`.

PLAN's quorum values (≥3 independent witnesses, ≥2 during beta) are policy inputs; the code takes `threshold` as a parameter.

### 3.5 Usernames

`username::normalize(name)` (`enclave-kt/src/username.rs`):

- trim, NFKC, lowercase (Unicode), and NFKC again;
- 2 to 32 characters and 3 to 32 bytes of UTF-8 (the directory key is 32 bytes): `ada`, `zoë`, `мария`, `محمد` and `田中` are names, `田` isn't;
- every character a letter, a digit or `_` that UTS #39 allows in identifiers (no symbols, emoji, invisible or deprecated characters);
- one script, at UTS #39's *highly restrictive* level: one script, or Latin with Han and Japanese kana, Han with Bopomofo, or Han with Hangul (so `pаypal` with a Cyrillic `а` is refused);
- the first character is a letter;
- its skeleton must not equal the skeleton of a reserved name: `admin`, `enclave`, `support`, `security`, `root`, `help`, `official`, `system` (in any script).

`username::skeleton(name)` maps look-alikes to one form:
1. Take the UTS #39 skeleton: every character goes to its prototype in Unicode's confusables table, so an all-Cyrillic `раul` and `paul` share one.
2. Lowercase it.
3. Remove `_`, and map the characters Unicode's table leaves apart in lowercase Latin text: `0` → `o`; `1`, `i`, `j` → `l`; `3` → `e`; `4` → `a`; `5` → `s`; `6`, `8` → `b`; `7` → `t`; `9` → `g`; `u`, `y` → `v`.
4. Then replace the pairs: `rn` → `m`, `vv` → `w`, `cl` → `d` (after step 3, so `uu` and `w`, or `c1` and `d`, collide too).

`KtLog::publish` refuses a new name whose skeleton equals that of a different registered name (RT-26). The index is rebuilt from the stored names at every start, so a log is held to the current rules.

A name held by a root that has a stored migration (§2.2) moves to the new root when the new root claims it; the old root no longer holds any name. The username format is `@name@domain`.

**Tombstones.** A withdrawn name's log value is a tombstone, `0xFF "tombstone" ‖ u8 why`. That is never a root, so older clients read it as "nobody has that name"; current ones as `UsernameError::Withdrawn`. Nobody can claim it again: the server records it as held by no root. Names are withdrawn in two ways:
- **By the account's owner**, when the account is deleted. The root signs a `Tombstone` (`enclave_proto::tombstone`, `u8(1) ‖ root ‖ u64 time`, ctx `enclave/v1/proto/tombstone`) and puts it to its home server as `DirKind::Tombstone` (10), keyed like the manifest (`Client::publish_tombstone`). The server checks the signature and that it is under a day old. It withdraws the account's name, deletes its manifest and its devices' prekeys, keeps the record (anyone can fetch it), and refuses any later manifest for that root (redb table `tombstones`, schema version 3).
- **By the operator**, for breaking its policy: `[kt] withdrawn = ["name", …]` in `server.toml`, applied at start (`Server::withdraw_username`; doing it again changes nothing).

Test `withdrawn_usernames`. Releasing a name when its owner takes another (a bare root as its value, kept for the same account) is unchanged.

### 3.6 The device clock (RT-23)

Trusted time (§3.4) checks the device clock (`client/clock.rs`). Every head a client verifies gives one: username lookups and absence proofs, descriptor lookups, and every 6 hours (`CHECK_EVERY_SECS`, and whenever the clock went back past the last check) a fresh head of the home server's log, fetched like a descriptor lookup and checked for its server signature and witness quorum but not its freshness, which is what's in question. Witnesses sign at the time they cosign, so a device clock more than 10 minutes behind trusted time (`BEHIND_SECS`) is wrong. A log's heads can be up to a day old (a heartbeat every hour, refused as stale past 25 hours), so a clock ahead is only certainly wrong past 25 hours (`AHEAD_SECS`); a clock between is indistinguishable from a quiet log. The client keeps the last judgment (`Client::clock_skew`, device time minus trusted time) and raises `Event::ClockSkew { skew: Some(s) }` when the clock becomes wrong and `{ skew: None }` when it's right again, once each. The app shows "This device's clock is wrong", with how far off it is, until then. Test `rt23_clock_skew_warning_shown` (`crates/enclave-core/tests/federation.rs`: right, two hours behind, right again, days ahead). Disappearing timers already run from receipt on the device (RT-23's second test, milestone Q1).

### 3.7 Claims and lookups

**Pins.** A client pins `KtPolicy { servers: [KtInfo], witnesses: WitnessPolicy }`, shipped with the app's server list; nothing about a log is learned from the log at lookup time. `KtInfo` is `server (16) ‖ domain ‖ operator ‖ head key ‖ VRF public key` (each variable field `u32 length ‖ bytes`).

**Claim** (`Username`/`Put`, `key` = `name_key(name)`, `proof` = Equi-X over `"claim-username" ‖ key ‖ u64(day)` at `effort_username`, default 64):

```
UsernameClaim = u32 len ‖ name ‖ u32 len ‖ value ‖ u32 len ‖ signature ‖ device (16) ‖ u64(time)
value         = root_pk (64) ‖ ContactCard
signature     = CompositeSign(device_sk, ctx = "enclave/v1/kt/claim",
                  server (16) ‖ u32(len) ‖ name ‖ u32(len) ‖ value ‖ u64(time))
```

The server checks, in order: the PoW (`Pow`); the claim decodes (`Malformed`); the name is valid, already normalized and equal to the key's name, and `time` is within 1 h of the server clock (`Invalid`); the server holds a manifest for the value's root (`NotFound`); a device in that manifest with the claim's device ID verifies the signature (`Invalid`); the name is unowned or owned by the same root (`Denied`) and `time` is later than the owner's last accepted claim (`Invalid`, stops replays). One name per account: if the root owns a different name, that name is republished as the bare root (released, but still reserved for this root). Then the name is published; a confusable skeleton of another root's name is `Denied`.

**Lookup reply** = `u32 len ‖ SignedHead ‖ u32 len ‖ akd LookupProof (akd's protobuf encoding)`, with `SignedHead = head (64) ‖ u32 len ‖ server sig ‖ u8 n ‖ n × (witness (16) ‖ u64(time) ‖ u32 len ‖ sig)`.

**Name answers** (`KtService::lookup_name`, what a `Username`/`Get` returns): `NameAnswer = u8(1) ‖ LookupReply` when the name has an entry. Otherwise it is `u8(2) ‖ u32 len ‖ SignedHead ‖ u32 len ‖ VRF proof ‖ u32 len ‖ akd NonMembershipProof (protobuf)`, a proof that the name was never registered. The server makes the VRF proof for the label of the name's first version (`(name, fresh, version 1)`, the label every registered name has for good) and akd's proof that the tree under the head's root has no such label (`KtLog::lookup_absent`). akd's directory doesn't produce absence proofs, so the log builds them from akd's public parts.

The client (`verify_absence`) does three things:
1. Checks the head under its witness policy.
2. Verifies the VRF proof under the pinned VRF key for its own normalized name, and recomputes the label from it: RFC 9381 proof-to-hash, `SHA-512(0x03 ‖ 0x03 ‖ 8·Γ ‖ 0x00)`, first 32 bytes, as akd computes it. The label must equal the proof's.
3. Checks non-membership against the signed root with akd's own verification.

A server can't claim a name is free without the witnesses' signed root agreeing. A bare `NotFound` status, with no proof, is now `Unverified` on the client (tests `service_round_trip_from_sync_code` in `crates/enclave-kt/tests/kt.rs` and `usernames_through_key_transparency`).

**Self-audit** (`Client::audit_username`, run from `sync` once every 24 h): a client that has a username looks itself up exactly as anyone else would. If the verified answer names another account or server, says the name is free, or fails verification, the client raises `Event::UsernameProblem` and the app shows a persistent notice. Network errors retry at the next sync. The operator can't target a lie at one person without the witnesses signing it for everyone, and the owner is one of those everyones.

**Client** (`Client::find_username`): parse `@name@domain` (a bare name means the home server), pick the pinned log by domain (`Unavailable`), normalize (`NotAllowed`), fetch, then `verify_lookup` with the pinned head key, operator, VRF key and witness policy. Any decoding or verification failure is `Unverified`, never "not found", and the UI refuses to add anyone. A verified absence proof, or a bare root (a released name), is `NotFound`; a tombstone is `Withdrawn` (§3.5). The card's root must equal the value's root and its server the log's server (`Unverified`). The result is only a contact card: the usual message request and security-code check follow.


### 3.8 Gossip (RT-04, `client/gossip.rs`)

A server whose witnesses collude can show different people different logs, each properly signed and cosigned. Contacts compare notes:

- Every head a client verifies (lookups, claims, the daily self-audit) is kept (the newest 64).
- Every direct message carries, when the content leaves room, up to three `(server (16) ‖ u64 epoch ‖ gossip digest (32))` items for the newest heads held. The payload becomes `0xFE ‖ u32 len ‖ content ‖ u8 n ‖ items` (content kinds are small numbers, so a bare content never starts with `0xFE`); this uses space the envelope pads anyway and never costs a unit.
- A received item for an epoch the receiver also holds, with a different digest, means one of them saw a fork. The receiver sends its signed head (≈19 KB with cosignatures, so as a sealed blob with a `Content::KtHead` reference, kind 16) to that contact, once per contact and epoch. An item for an epoch not held yet is remembered and compared when that epoch is verified.
- A received head is checked against the pinned server key and the witness quorum (signatures only, not freshness). If it verifies and its root differs from the held head of the same epoch, the server has **provably equivocated**: both heads are stored as proof, `Event::KtSplitView { server, epoch }` is raised, and the receiver sends its own head back so the other side holds the proof too. A verified head for an epoch not held is kept like any other.
- The app shows a persistent notice ("A username server showed people different lists … check security codes, ideally in person").
- Test `rt04_split_view_detected_by_gossip`: twin logs under one server key and one set of (colluding) witnesses (`KtService::start_dev_twins`, server test hooks `enable_kt_fork`, `kt_fork_force`, `kt_serve_fork`); Ada sees the real binding of a name, Ben the forked one, each view verifies alone, and one message from Ada to Ben leaves both holding the proof. Honest views raise nothing.
- **Publication.** A client holding a proof publishes it (`enclave_kt::Equivocation`: `u8(1) ‖ u32 len ‖ SignedHead ‖ u32 len ‖ SignedHead`) as `DirKind::Equivocation` (11), keyed by the log's server id, to a server other than the one that equivocated: its home server, or another the list names. The server takes it only for its own log or one its server list names (`NotFound` otherwise), checks that both heads are signed with that log's head key for one epoch with two roots (`Invalid`), keeps the first per log (redb table `equivocations`, schema 6; anyone can get it), and its process hands it to every witness it knows (`[kt] witnesses` and the list's witness URLs) at the next minute's tick. A witness takes it at `POST /witness/v1/equivocation` for a log it witnesses, under the head key the list pins, keeps it (`kt-equivocations`, KT store schema 2), serves it at `GET /witness/v1/equivocation/<server hex>`, and **never cosigns that log again** (`410 Gone`, `KtError::Equivocated`), so the log stops meeting any client's quorum and every lookup in it fails as unverified. `Equivocation::colluders` names the witnesses that cosigned both heads. Tests: `rt04_split_view_detected_by_gossip` (Ben's home server receives the proof), `two_remote_witnesses_meet_threshold_two` (a witness takes it once, serves it and refuses the log; two copies of one head are refused).
- Limits: gossip only compares heads of logs the client pins, the fork is found only if two people who talk saw different heads for the same epoch, and group messages carry no gossip yet (P2).
## 4. Discovery and migration

`enclave-federation` holds the signed objects (all in the canonical encoding of `enclave_proto::codec`: one byte string per value, trailing bytes refused, every signature over every byte before it; test `crates/enclave-federation/tests/federation.rs` flips bytes across each object and requires every one to be refused).

### 4.1 Server list

The foundation's list of vetted servers, witnesses, call relays, push relays and credential gates (`list.rs`, format version 2 in its module docs). It carries what changes rarely and what the foundation vouches for: identity keys, domains, operators and families, weights for new accounts, the key-transparency keys clients pin (head key and VRF key per server), the witness threshold, witnesses' cosigning keys and URLs, relays' link keys, push relays' Nym addresses with their current and next keys, and each credential gate's origin, issuer name and Privacy Pass issuer key per 30-day epoch (`CredGateEntry`, at most 8 keys, HTTPS only, epochs in order; `09-transport.md` §7). Short-lived keys are not in it: they come from the services, signed by the identity keys it lists.

The list is signed twice under ctx `enclave/v1/update/server-list`: SLH-DSA-SHAKE-256s (the foundation key's SLH-DSA half is derived from a 32-byte secret under `enclave/v1/update/foundation-keygen`) and composite Ed448 + ML-DSA-87. `ServerList::verify` requires both, an unexpired list, and a sequence number higher than the one the client holds. `pick(draw)` chooses a server for a new account by weight. A server serves the copy named by `server.server_list` as `DirKind::ServerList` (8), in chunks; it can't check the list (it holds no foundation key) and doesn't need to, since clients do. **Building the list** (`enclave-admin`, test `crates/enclave-admin/tests/admin.rs`): `foundation-keygen SECRET PUBLIC` writes the foundation key (mode 0600, never overwritten) and its public key; `server-list build SPEC.toml --key SECRET --out LIST` reads a spec naming the signed descriptors operators submit (servers with weights, witnesses, relays, push relays' Nym addresses with their published key files, and credential gates with the `EPOCH HEX` lines `enclave-credgate show-key --epochs N` prints, one of which must be the current epoch's), verifies every descriptor (signature, validity window, every key certificate), refuses duplicates and a witness threshold above the number of witnesses, signs, and checks the result before writing it; without `--key` it writes the list unsigned, so the foundation key can stay on an offline machine, where `server-list sign UNSIGNED --key SECRET --out LIST` prints what it is about to sign, signs, and checks the result; `server-list verify LIST --foundation PUBLIC [--held-seq N]` prints it; `kt-pins LIST --foundation PUBLIC --out PINS` derives the key-transparency pins (`KtPolicy::from_server_list`: every listed log, every listed witness with its derived id, the list's threshold); `descriptor verify server|witness|relay FILE [--id HEX]` checks a descriptor; `descriptor fetch DOMAIN --out FILE [--id HEX] [--ca PEM]` gets a server's descriptor from its front (`https://DOMAIN/.well-known/enclave`, §4.5) over the Enclave TLS profile and writes it only if it verifies (test `fetch_a_descriptor_from_a_front`). **On the client** (`enclave-core/src/client/servers.rs`, test `crates/enclave-core/tests/federation.rs`): the app hands the client the foundation's public key at every start (`set_foundation`); the client keeps the newest list it verified in its store (not in backups) and reloads it with the key. `offer_server_list` takes a list only if both signatures verify, it hasn't expired and its sequence number is higher than the one held (`ListUpdate::Unchanged` otherwise); `refresh_server_list` fetches the home server's mirror (`DirKind::ServerList`), which the vault does once a day. The key-transparency pins are derived from the list and merged with any the app adds (`set_kt_policy`, for development servers), so usernames on every listed server resolve with no other configuration. The client's card carries its home server's domain from the list. The vault takes the foundation key and a list from `--foundation FILE` and `--server-list FILE`, or from the build (`ENCLAVE_FOUNDATION_PUB` and `ENCLAVE_SERVER_LIST` name the files at build time; the release pipeline sets them once the foundation key exists, external gate G5). Several `--server ID=ROUTE` flags (`nym:ADDRESS`, or `HOST:PORT` in development) give routes to more than the home server. The client hands the transport every listed server's Nym address, and each accepted descriptor's (`09-transport.md` §1). Moving the list under TUF is R2.

### 4.2 Request-key certificates

A server's daily request key is certified by its identity key (`keycert.rs`):

```
KeyCert   = u8(1) ‖ server_id (16) ‖ ServerKey (1,628) ‖ u64(not_before) ‖ u64(not_after)
            ‖ CompositeSign(identity, "enclave/v1/net/request-key-cert", all of the above)
KeyBundle = u8(1) ‖ identity public key (2,649) ‖ u8(n) ‖ n × KeyCert
```

Day `d`'s key is valid from the start of day `d` to the end of day `d + 1`. A zero-length request is answered with a `KeyBundle` of today's and tomorrow's certificates (`Server::key_bundle`, set by the binary at start and at every rotation). A client checks the bundle against the server id it expects: the id must be derived from the bundle's identity key and every certificate must verify (`KeyBundle::verify`); a bundle signed by any other identity is refused (`NetError::Untrusted`, tests `a_key_from_the_wrong_identity_is_refused` in `enclave-net` and `carries_requests_and_keys` in `enclave-netd`). TCP and Tor transports and netd verify bundles; the in-process simulator transport hands keys over directly. Clients name their home server as `--server SERVER_ID=nym:ADDRESS` (over the mixnet) or `--server SERVER_ID=HOST:PORT` (development TCP) (`enclave-server show-id` prints the id; `enclave-server dev` prints its fresh id at start).

### 4.3 Server descriptors

`ServerDescriptor` (`descriptor.rs`) is what a server says about itself, self-signed under `enclave/v1/net/server-descriptor`: identity key, domain, operator, family, Nym address, onion address, policy (efforts, quotas, retention), key-transparency keys, request-key certificates for today and tomorrow, and a validity window of at most 3 days. Witnesses and call relays have the same kind of self-signed descriptor (`WitnessDescriptor` under `enclave/v1/kt/witness-descriptor`, id `SHAKE256("enclave/v1/kt/witness-id" ‖ key)`; `RelayDescriptor` under `enclave/v1/calls/relay-descriptor`, id `SHAKE256("enclave/v1/calls/relay-id" ‖ identity key)`). `enclave-server run` signs a descriptor at start and at every daily key rotation (valid two days, today's and tomorrow's key certificates), serves it as `DirKind::Descriptor` (7), writes it to `public_dir/descriptor.bin` for the front, and commits its SHA3-512 digest to its key-transparency log under the label `0x00 ‖ "descriptor"`, which no username can equal (`KtLog::commit_descriptor`, `lookup_descriptor`; test `descriptor_digests_are_committed`). Uploads of either kind are `Denied` (test `descriptor_and_list_are_served_not_uploaded`). `enclave-server descriptor` verifies and prints the file. The front (§4.5) serves it at `https://<domain>/.well-known/enclave`. A `DirKind::Username` get keyed by `DESCRIPTOR_LOOKUP_KEY` (the empty name, which no username can be) answers with the lookup proof for the committed digest, against a fresh cosigned head like any username lookup (`KtService::lookup_descriptor`). A client takes a descriptor (`Client::fetch_descriptor`) only if it is self-signed and valid now, its identity is the one the server id is derived from and the one the server list gives, its key-transparency keys are the pinned ones, and, for a server with a pinned log, its SHA3-512 is the digest the log commits to under the witness quorum (`verify_descriptor_lookup`), so a server can't show one client a descriptor it doesn't show everyone; a mismatch is retried once (a fetch between signing and committing) and then refused as `NotLogged`. The descriptor accepted last is kept in the store (`server_descriptor`). Test: `three_servers_one_list` (`crates/enclave-core/tests/federation.rs`): every server's descriptor verifies; one shown but not committed is refused and the one held kept; once committed it's taken; another server's genuine descriptor served as one's own is refused. Routes from descriptors (the Nym address) are used from N1.

### 4.4 Moving an account

An account moves to another server from the device that holds the recovery words (`Client::move_home`, `enclave-core/src/client/moves.rs`). The new server gets fresh inboxes with fresh owner secrets, since the old operator knows the old ones and must not be able to read or empty the new inboxes. The move is staged once and then carried out step by step, each step safe to repeat and retried from `sync` until done (`move_pending`):

1. Create the account inbox and the request inbox on the new server.
2. Publish a new manifest version naming the new request inbox, signed once and posted to both servers, with this device's co-signature.
3. Put this device's prekeys and the vault key (under a fresh locator) on the new server.
4. Tell our other devices the new inboxes and owner secrets (`Content::HomeMoved`, kind 26). This goes to the old account inbox, where they still read, before the switch. A device applies it after its poll, takes the new manifest from the new home, and publishes its own prekeys there.
5. Switch the profile. The old home is kept and its inboxes are still read for 30 days (`DRAIN_SECS`, the longest an envelope is kept), so messages already on their way arrive. The write-token pool, registered at the old inbox, is dropped.
6. Leave the root-signed `ServerMove` on the old server.
7. Register outstanding invite links' capabilities with the new request inbox.
8. Claim the username again on the new server. If it's taken there, the old one stays where it was.
9. Tell every contact with a session in that session (`Content::ServerMoved`, kind 25): the new server, account inbox, request inbox and vault locator, and fresh write tokens. A contact who hasn't answered our greeting yet is told once they do.

A contact takes the notice like a `Hello` (authenticated by the session, no root signature needed). It writes to the new server from then on, drops the old tokens, updates its copy of our card, and refreshes our manifest.

```
ServerMove = u8(1) ‖ root (64) ‖ from (16) ‖ to (16) ‖ u32 len ‖ to_domain ‖ request_inbox (32) ‖ vault_locator (32) ‖ u64 time
             ‖ RootSign(root, "enclave/v1/proto/moved", all of the above)
```

The record stays on the server the account left, as `DirKind::Moved` (9), keyed like the manifest. The server keeps it only if all of these hold:
- the account has a manifest there;
- it is signed by that root;
- it leaves this server;
- it is less than a day old;
- it is newer than any record already held (redb table `server-moves`, schema version 2).

Anyone can fetch it. Someone holding an old card or invite link follows records, up to four hops, before adding the person (`Client::follow_moves`), so they reach the new request inbox. Restoring from a backup also follows contacts' moves. Restoring a backup taken before our own move is refused (`CoreError::BackupBeforeMove`): it holds only the old inboxes.

Tests:
- `move_to_another_server` (`crates/enclave-core/tests/client.rs`):
  - the second device follows;
  - a message already on its way to the old server arrives;
  - a contact writes to the new server after the notice, and both devices receive;
  - an old card and an old invite link reach the account on the new server;
  - a pre-move backup is refused, and a newer one restores onto the new server.
- `a_move_is_kept_only_from_its_root_leaving_here` (`crates/enclave-server/tests/moves.rs`): forged, misfiled, stale and damaged records are refused; a newer record replaces an older one.

Groups we host stay on the old server until hosting moves by admin vote (P4). Push registrations are per server and are made again by the app (P6).

### 4.5 The front (`enclave-front`)

The key-holding server has no HTTP surface. `enclave-front` is the one process of an operator's stack that faces the web, and holds no key but its TLS key:

| URL | Serves |
|---|---|
| `https://<domain>/.well-known/enclave` | `public_dir/descriptor.bin`, as the server wrote it (`application/octet-stream`, cached 5 min); 404 before the first one |
| `https://<domain>/witness/v1/…` | The stack's witness (§3.3), proxied to it on the internal network (`front.witness`, such as `http://witness:7446`); 404 when none is set |
| `https://<domain>/healthz` | `ok` |
| `http://<domain>/.well-known/acme-challenge/<token>` | ACME HTTP-01 answers in flight |
| `http://<domain>/…` | 308 to the same path on `https://<domain>` |

HTTPS uses the Enclave TLS profile only (`09-transport.md` §8): a client that offers no SecP384r1MLKEM1024 gets no connection. The proxy passes on the method, the path and the body; no header of the client's (address, `Forwarded`, user agent, cookies) reaches the witness, and bodies over 8 MiB are refused. Client addresses are dropped at `accept` and nothing is logged per request.

Certificates (`front.tls`):

- `acme` (default): from `front.acme_directory` (Let's Encrypt unless set) by HTTP-01, so `front.listen_http` (default `0.0.0.0:80`) must be reachable. The ACME account (`acme-account.json`) and the certificate (`cert.pem`, `key.pem` mode 0600) are kept in `front.data_dir`; the certificate on disk is used while it has more than 30 days left and is renewed after that, checked every 12 hours (every 10 minutes until one is held). The new certificate replaces the old one in place; connections after it get the new one. ACME traffic to the CA uses rustls's default profile (`compat_provider`), since public CAs don't offer the hybrid; `front.acme_ca_root` adds a root for a private or test CA.
- `files`: `front.cert` and `front.key` (PEM), re-read every hour.
- `self-signed`: made at start, for development.

Configuration is `[front]` in the TOML file given by `--config`, or `ENCLAVE_FRONT__<KEY>`: `listen_https` (default `0.0.0.0:443`), `listen_http`, `domain` (required), `public_dir`, `witness`, `tls`, `acme_email`, `acme_directory`, `acme_ca_root`, `cert`, `key`, `data_dir`. `enclave-front run` serves; `enclave-front healthcheck` checks that both ports accept connections. Tests (`crates/enclave-front/tests/front.rs`): the descriptor and a real witness reached through the front by `HttpWitness` over the Enclave profile, a classical-only client refused, a certificate replaced while serving, the proxy dropping client headers, the HTTP side's challenge answers and redirect, and the whole ACME flow against pebble (CI job `tls-interop`): an account, the HTTP-01 answer, a certificate trusted under pebble's root and served over the Enclave profile, and a second check that keeps it.

`/credgate/v1/*` is the foundation's credential gate (`enclave-credgate`, `09-transport.md` §7), proxied by the front of the stack that runs it (`[front] credgate`, compose profile `foundation`); other stacks answer 404.

## 5. Relays

`enclave-relay` as built: the relay-ticket service and the data plane with the interim link framing (`11-calls.md` §3.4). Its keys live in a key directory created by `enclave-relay init` (`keys.rs`): `identity.key` (a composite signing key; the relay id is `SHAKE256("enclave/v1/calls/relay-id" ‖ identity key)` and the key signs the relay's descriptor), `link.key` (the X448 secret for relay↔relay links, published in the descriptor) and `ticket-chain.key`, a daily seed chain (`enclave_service::SeedChain`). Day `d`'s ticket key is `KMAC256(seed_d, u32(d), 960, "enclave/v1/calls/ticket-key")` split into the X448 secret and the ML-KEM-1024 seed; `seed_{d+1} = KMAC256(seed_d, "", 256, "enclave/v1/calls/ticket-chain")`. The relay serves today's key and yesterday's (for requests sealed just before midnight), and publishes tomorrow's ahead. Spent Privacy Pass tokens are recorded in `data_dir/relay.redb` (`ledger.rs`) and committed before the ticket is issued, so a restart never accepts a token twice; they are kept 62 days. `enclave-relay run --config FILE` reads `[relay] listen` (default `0.0.0.0:51820`), `public_addr`, `family` (required), `operator`, `keys_dir`, `data_dir` and `peers` (peer descriptors in hex); `enclave-relay descriptor OUT` writes the signed `RelayDescriptor` (today's and tomorrow's ticket keys) that operators submit for the foundation's list; `healthcheck` checks the heartbeat file `run` writes every 30 s. Calls in progress do not survive a restart (sessions last at most 4 h and are held in memory).

Not implemented yet (C2–C5): GotaTun WireGuard endpoints, a Rosenpass daemon for relay↔relay links, and the SFU for group calls. `enclave-push-relay` is in `10-push.md`; the witness service is §3.3.

## 6. Deployment

An operator runs one stack (`ops/compose/compose.yml`) from one image (`ops/docker/Dockerfile`, published as `ghcr.io/enclavechat/enclave-server`), following `ops/operator-kit/deployment.md`.

**The image** has these properties:
- Built from digest-pinned base images, the pinned toolchain and `Cargo.lock` (`--locked`), with fixed paths and `SOURCE_DATE_EPOCH`, as `cargo xtask repro` checks.
- Holds `enclave-server`, `enclave-witness`, `enclave-front`, `enclave-relay`, `enclave-push-relay` and `enclave-admin`.
- Runs on distroless with no shell, as the unprivileged `nonroot` user (65532).
- Ships its state directories under `/var/lib/enclave` owned by that user, so named volumes start out writable; the key directories are 0700.

**Services** (each runs with a read-only root filesystem, no capabilities and `no-new-privileges`; each has a health check that is the binary's own `healthcheck`):

| Service | Role | Networks | Published |
|---|---|---|---|
| `server` | The server (§1), keys in `server-keys` | `backend` (internal), `egress` | Nothing; Nym ingress at N1 |
| `witness` | The stack's witness (§3.3), plain HTTP inside | `backend` | Through the front |
| `front` | §4.5 | `backend`, `edge` | 80, 443/tcp |
| `relay` | Call relay (§5) | `edge` | 51820/udp |
| `push-relay` | Push relay (profile `push`) | `backend`, `egress` | Nothing |

**Configuration:**
- Per-deployment values (domain, operator, family, TLS mode, relay address) come from `.env` as `ENCLAVE_<SECTION>__<KEY>` overrides; an empty one counts as unset.
- The rest is in `config/*.toml` (examples alongside).
- The foundation's key and list are in `foundation/`.
- `init` subcommands create keys.
- `descriptor OUT` subcommands sign the descriptors the foundation lists, before the first start.
- The server connects its witnesses lazily and retries ones that are down.

**Overrides:**
- `compose.dev.yml` publishes the server's TCP port on 127.0.0.1 and makes the front self-signed.
- `compose.e2e.yml` puts three stacks' witnesses on a shared network.

**CI:** the job `federation-e2e-tcp` (`ci/federation/gen.sh`, `crates/enclave-e2e`) runs three stacks from these files under a test foundation:
- each front's descriptor is fetched over the Enclave TLS profile;
- usernames verify with cosignatures from the other stacks' witnesses;
- messages, a group and a file cross servers;
- push wakes travel through a push relay;
- a restarted stack keeps its data;
- no client sees a split view.

The image has no shell and runs as nonroot.

**Other notes:**
- Backups and restore are in §1 and the deployment guide.
- Metrics are local aggregates only.
- `enclave-server dev` (TCP, random keys, nothing kept) remains for development and is **not for production**: production servers are reachable only through Nym (N1).
- **PostgreSQL.** An operator can keep the server's state in PostgreSQL instead of the redb file: `[database] url` (or `url_file`, a Docker secret) in `server.toml`, and `compose.postgres.yml` adds a pinned `postgres:17-alpine` on the internal network with its password and URL as secrets. Every table becomes rows of one relation `enclave_kv (tbl text, k bytea, v bytea, PRIMARY KEY (tbl, k))`, in the same per-request transactions; `bytea` compares bytewise, so key order and prefix scans match redb's (`db.rs`, `pg.rs`). The blocking client runs under `block_in_place` in the server's runtime, and its connection is closed the same way. Backups are redb snapshots whatever the backend (one read transaction, taken while the server runs), and `restore` loads one into PostgreSQL in one transaction (`Db::copy_from`). The key-transparency log stays a redb file in `data_dir` (it is per-server and small). The same tests run on both backends (`tests/backends.rs`, `restart.rs`, `replay.rs`, through `tests/common`: each test gets a fresh database), in CI job `postgres` against a PostgreSQL service, and stack c of `federation-e2e-tcp` runs on PostgreSQL.
- A Nix flake arrives with R2.

## 7. Scale estimate (100k accounts)

Assumptions: 1.5 devices per account (150,000 devices), 5% of devices in Foreground or Maximum at any moment (7,500), the rest in Background (142,500); PLAN's model of one 16,384 B reply unit per tick.

| Quantity | Computation | Result |
|---|---|---|
| Reply egress, Foreground | 7,500 × 16,384 B × 8 / 3 s | 327.7 Mbit/s |
| Reply egress, Background | 142,500 × 16,384 B × 8 / 120 s | 155.6 Mbit/s |
| Total reply egress (Enclave layer) | | ≈483 Mbit/s (PLAN: 400 to 500) |
| Sealed requests per second | 7,500 × 2 / 3 + 142,500 × 2 / 120 | ≈7,375 /s |
| Decapsulation cost | ≈0.3 ms per request (X448 + ML-KEM-1024 decaps + EnclaveCombine + one open) | ≈2.2 cores (PLAN: 2 to 3) |

As implemented, every request (including writes and cover) gets a reply unit, which doubles reply egress (`math/cover-traffic.md` §2.1). A server that holds two daily keys may try both on a request, so the decapsulation cost is up to twice as high around rotation.

**Measured** (`cargo run --release -p enclave-server --example scale -- --accounts 100000`; a 4-vCPU cloud VM, redb on its virtual disk, 2026-10-02). The run fills a server with 100,000 accounts (an inbox and a request inbox each, 16 write tokens, one stored message: 400,000 sealed requests), then times 20,000 requests of each kind against that state, on one core:

| Quantity | Measured |
|---|---|
| State on disk | 3.4 GiB, 35 KiB per account (mostly the stored 14 KiB envelope and redb's page overhead) |
| Poll | 0.66 ms per request (1,513/s per core) |
| Cover unit | 0.74 ms (1,361/s) |
| Write (stored, synced to disk) | 2.0 ms (495/s), most of it the disk sync |
| A replayed request, refused | 0.52 ms |
| Resident memory | 1.4 GiB (redb's page cache) |
| Cores for 7,375 requests/s (50% polls, 45% cover, 5% writes) | ≈5.6 |

Where a request's time goes (`--example open_cost`): opening it is 0.42 ms, of which X448 is 0.29 ms (on `fiat-crypto`'s verified arithmetic; the `x448` crate took 0.52 ms) and ML-KEM-1024 decapsulation 0.03 ms; the 16 KiB random reply 0.05 ms; the replay-cache record and the operation's transaction the rest. So the estimate above (0.3 ms, 2 to 3 cores) was low by about two: a 100,000-account server needs about 6 cores of this class at peak, or fewer, faster ones. Writes are bounded by the disk's sync rate, which the replay cache doesn't add to (its records are committed without their own sync, `09-transport.md` §2.3). CI runs the same example with 2,000 accounts on every push (job `scale-smoke`) so it keeps working; the numbers above are rerun by hand on release candidates (`release-checklist.md`).

## 8. Errors

| Condition | Server reply |
|---|---|
| Wrong size, unsupported version or suite, no key opens it, bad header | 16,384 random bytes |
| Token not registered or already used; wrong credential; wrong inbox type; inbox exists | `Denied` |
| Inbox, object, chunk or claim missing | `NotFound` |
| Inbox or token quota exceeded | `Quota` |
| Malformed payload or chunking | `Malformed` |
| Proof of work invalid | `Pow` |
| Directory object fails validation | `Invalid` |

## Open questions

1. **Resolved:** proofs of work are single-use and day-bound (§1.1, table `pow-spent`), so one solution can't drain a device's one-time prekeys or rewrite the same request.
2. **Directory uploads are unauthenticated until complete.** Anyone can send chunks for any `(kind, key)`: a chunk with a different `total` discards an upload in progress, and partial uploads are kept in memory without expiry.
3. **Bundle publication is authorized by device ID alone.** The server accepts a publication signed by the key of any stored manifest that lists the device ID. A second account whose manifest reuses another account's device ID could replace that device's publication; initiators then reject the bundle (they verify it against the right manifest), so the effect is denial of first contact. Binding the bundle key to the root (as for manifests) would close this.
4. **Resolved:** inbox creation costs an Equi-X proof for the address and the day at `effort_inbox` (§1.1; `09-transport.md` §3.1).
5. PLAN §12.1 says "hourly epochs" and §12.2 "10-minute to 1-hour epochs". The implementation makes one epoch per publish; a batching interval is open.
6. **Resolved:** PLAN §12.2's "C2SP format with an added ML-DSA cosignature": witnesses publish C2SP checkpoints with an Ed25519 `cosignature/v1` and an ML-DSA-44 cosignature (§3.3a), checked against the Go reference implementation in CI, beside the composite cosignature clients rely on.
7. Whether the KT value should carry the vault-key locator, given that the KT operator is usually the same server as the directory and could then link vault-key fetches to usernames.
8. **Resolved:** the skeleton is Unicode's UTS #39 confusables skeleton plus the lowercase-Latin rules (§3.5), so Unicode names are allowed.
