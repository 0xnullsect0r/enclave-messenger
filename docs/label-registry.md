# Label Registry

Status: Draft (M0, reconciled with the M1–M5 code) · Normative

Source: PLAN.md §2.1 ("every call has a unique label from `label-registry.md`; CI rejects duplicate labels") and §21 ("label-registry uniqueness"). This file is the single source of truth for every domain-separation string in Enclave. Derivations using these labels are in `02b-key-schedule.md`. Where this file and the code disagree, the code is normative and this file is corrected.

## 1. Rules

1. Every label is ASCII, starts with the prefix `enclave/v1/`, and has the form `enclave/v1/<area>/<name>` with exactly four `/`-separated segments. `<area>` and `<name>` use lowercase letters, digits, and `-`.
2. Every KMAC256 customization string, every raw hash prefix, and every signature context string in the Rust sources that starts with `enclave/v1/` MUST appear in this registry.
3. A label is used at one kind of call site (the "Kind" column). Where one label has more than one call site of the same kind, the inputs are made disjoint and the row says how.
4. Labels are never reused with a different meaning. A draft label that the implementation replaced is kept in §4 with status "Retired" and its replacement; it MUST NOT be reused.
5. CI (`cargo xtask labels`) extracts every string literal that starts with `enclave/v1/` from the Rust sources under `crates/` and fails if:
   - a literal is missing from this file (the checker splits this file on backticks, whitespace and `|`, and collects every token that starts with `enclave/v1/`; the bare prefix `enclave/v1/` used by the uniqueness test in `enclave-crypto` is registered by rule 1 above); or
   - the same label is defined by more than one `const` in code.

   Uniqueness inside each crate is also checked by unit tests (`enclave-crypto` `labels::tests`, `enclave-proto` `labels::tests`, which also checks that the proto labels are disjoint from the crypto labels). Checking that each call site matches the "Kind" column is not automated yet; reviewers check it.
6. A new label in §2.1 (crypto) requires an RFC; any other new label needs a reviewed PR that updates this file and `02b-key-schedule.md` together.

Kinds:

| Kind | Meaning |
|---|---|
| KMAC | Customization string `S` of `KMAC256(K, X, L, S)`. "Output" is `L` in bits. |
| XOF | Customization string `S` of KMACXOF256 (SP 800-185 `right_encode(0)`). "Output" is whatever the caller reads. |
| HASH | Raw ASCII prefix inside a SHAKE256 input: `SHAKE256(label ‖ …)`. No length prefix. "Output" is the hash output length in bits. |
| CTX-C | The `ctx` argument of a composite (Ed448 + ML-DSA-87) signature: it goes into the message representative `M'` (`02-cryptography.md` §7). |
| CTX-M | The ML-DSA-87 context string (FIPS 204 `ctx`) used inside every composite signature. |
| CTX-R | The FIPS 205 `ctx` of an SLH-DSA-SHAKE-256s root signature. |
| AD | Prefix at the start of an EnclaveSeal associated-data string. Used only by reserved rows; implemented seals use the ADs listed in §4. |
| TR | First element of a transcript. Used only by reserved rows. |
| INFO | The `info` string of an RFC 9497 `DeriveKeyPair` (a Privacy Pass issuer key from a seed). |

Status values: **Implemented** (used by code today), **Reserved (not yet implemented)** (specified for a later milestone, not in code), **Retired** (a draft label replaced by the implementation; never reuse).

## 2. Implemented labels

Every label in this section appears in the code. "Where" names the crate, file and function.

### 2.1 Crypto (`enclave-crypto`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/seal/nonce` | KMAC | 256 | `seal.rs` `hedged_nonce`, `compact_nonce` | EnclaveSeal nonce `N`. The hedged form absorbs `frame(r) ‖ frame(AD) ‖ SHA3-512(P)`; the compact form absorbs `frame("compact") ‖ frame(nonce_material) ‖ frame(AD)`. The first framed field has length 32 in the hedged form and 7 in the compact form, so the two input sets are disjoint. |
| `enclave/v1/seal/keys` | KMAC | 1088 (136 B) | `seal.rs` `subkeys` | EnclaveSeal subkeys `k_x ‖ k_a ‖ k_m ‖ n_x ‖ iv_a` (32 + 32 + 32 + 24 + 16) |
| `enclave/v1/seal/tag` | KMAC | 256 | `seal.rs` `tag` | EnclaveSeal tag `T` |
| `enclave/v1/kem/extract` | KMAC | 512 | `kem.rs` `combine` (`Suite::ThreeKem`) | EnclaveCombine extract `prk`, 3-KEM suite |
| `enclave/v1/kem/combine` | KMAC | 512 | `kem.rs` `combine` (`Suite::ThreeKem`) | EnclaveCombine output, 3-KEM suite |
| `enclave/v1/kem2/extract` | KMAC | 512 | `kem.rs` `combine` (`Suite::TwoKem`) | EnclaveCombine extract `prk`, 2-KEM suite |
| `enclave/v1/kem2/combine` | KMAC | 512 | `kem.rs` `combine` (`Suite::TwoKem`) | EnclaveCombine output, 2-KEM suite |
| `enclave/v1/rng/hedge` | XOF | caller's length | `rng.rs` `HedgedRng::fill` | Hedged RNG output |
| `enclave/v1/root/keygen` | KMAC | 768 | `sig.rs` `RootSigningKey::from_recovery_secret` | SLH-DSA root seeds `SK.seed ‖ SK.prf ‖ PK.seed` from the recovery secret |
| `enclave/v1/sig/composite` | CTX-M | — (24 B string) | `sig.rs` `CompositeSigningKey::sign`, `CompositePublic::verify`; `tests/differential.rs` | ML-DSA-87 context string inside every composite signature |
| `enclave/v1/store/record` | KMAC | 256 | `seal.rs` `record_key` (called by `enclave-store` `Store::put`, `open_record`) | Per-record storage key |
| `enclave/v1/backup/key` | KMAC | 256 | `enclave-store` `backup.rs` `backup_key` | Backup archive key from the recovery secret |
| `enclave/v1/fp/root` | KMAC | 512 | `hash.rs` `root_fingerprint` | First step of the security-code hash chain: `KMAC256(root_pk, "", 512, label)` |

### 2.2 Protocol (`enclave-proto`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/ctx/manifest` | CTX-R | — | `manifest.rs` `Manifest::sign`, `SignedManifest::verify` | Root signature on the account manifest |
| `enclave/v1/ctx/signed-prekey` | CTX-C | — | `bundle.rs` `SignedPrekey::verify`, `PrekeyStore::publish` | Signed prekey (X448 + ML-KEM-1024) |
| `enclave/v1/ctx/opk-batch` | CTX-C | — | `bundle.rs` `OpkBatchHeader::verify`, `PrekeyStore::publish` | One-time-prekey batch header (Merkle root) |
| `enclave/v1/ctx/last-resort` | CTX-C | — | `bundle.rs` `LastResortPrekey::verify`, `PrekeyStore::publish` | Last-resort ML-KEM-1024 prekey |
| `enclave/v1/ctx/signed-msg` | CTX-C | — | `otr.rs` `sign`, `verify` (`Kind::Message`); `enclave-core` `client/record.rs`, `enclave-server` `verify_quotes` | On-the-record 1:1 message signature (`05-ratchet.md` §9) |
| `enclave/v1/proto/grp-signed-msg` | CTX-C | — | `otr.rs` (`Kind::Group`); `enclave-core` `client/group_record.rs` | On-the-record group message signature (07 §3) |
| `enclave/v1/proto/grp-admin-sig` | CTX-C | — | `otr.rs` (`Kind::Admin`); `client/group_record.rs` | On-the-record admin state-update signature (07 §7.3) |
| `enclave/v1/proto/poll-tally` | CTX-C | — | `otr.rs` (`Kind::Tally`); `client/group_record.rs` | Poll creator's tally signature in On-the-record groups (07 §7.5) |
| `enclave/v1/ctx/eqxdh-transcript` | CTX-C | — | `eqxdh.rs` `initiate`, `verify_transcript_sig` | On-the-record initiator transcript signature |
| `enclave/v1/ctx/manifest-cosign` | CTX-C | — | `attest.rs` `Attestation::sign`, `verify` | A listed device approves a manifest update |
| `enclave/v1/ctx/manifest-veto` | CTX-C | — | `attest.rs` `Attestation::sign`, `verify` | A listed device vetoes a manifest update |
| `enclave/v1/ctx/migration` | CTX-R | — | `migration.rs` `Migration::sign`, `verify` | Old and new roots sign a change of recovery words (03 §8.2) |
| `enclave/v1/proto/moved` | CTX-R | — | `server_move.rs` `ServerMove::sign`, `verify` | The root signs where the account moved (new server, domain, request inbox, vault locator), kept by the server it left (12 §4.4) |
| `enclave/v1/proto/tombstone` | CTX-R | — | `tombstone.rs` `Tombstone::sign`, `verify` | The root signs its account's deletion; the home server withdraws the username for good (12 §3.5, 03 §8.5) |
| `enclave/v1/eqxdh/identity` | KMAC | 256 | `eqxdh.rs` `stage1_key` (through `seal::derive_key`) | Stage-1 key `k_id` that seals the initiator identity |
| `enclave/v1/ratchet/init-rk` | KMAC | 256 | `ratchet.rs` `Session::new` | Initial root key `RK0` from `SK` |
| `enclave/v1/ratchet/init-hk` | KMAC | 256 | `ratchet.rs` `Session::new` | Initial header keys; two calls with inputs `frame("a")` (HKA) and `frame("b")` (NHKB) |
| `enclave/v1/ratchet/init-pq` | KMAC | 256 | `ratchet.rs` `Session::new` | Initial PQ roots; two calls with inputs `frame("a2b")` and `frame("b2a")` |
| `enclave/v1/ratchet/rk` | KMAC | 768 | `ratchet.rs` `kdf_rk` | DH root step `RK' ‖ CK ‖ NHK` |
| `enclave/v1/ratchet/ck` | KMAC | 512 | `ratchet.rs` `kdf_ck` | Chain step `CK' ‖ mk_DR` |
| `enclave/v1/ratchet/tag` | KMAC | 128 | `ratchet.rs` `lookup_tag` | 16 B lookup tag `KMAC256(HK, u32(n), 128, label)` |
| `enclave/v1/ratchet/msg` | KMAC | 256 | `ratchet.rs` `Session::seal`, `Session::open` | Message key `mk` from `mk_DR` and the PQ key |
| `enclave/v1/ratchet/wrap` | KMAC | 256 | `ratchet.rs` `Session::seal`, `Session::open` | Body-key wrap pad `KMAC(mk, frame(body_hash))` |
| `enclave/v1/ratchet/pq-slot` | KMAC | 256 | `ratchet.rs` `build_pq_slot`, `process_pq_slot` | PQ-slot seal key from `mk_DR` |
| `enclave/v1/pq/step` | KMAC | 256 | `ratchet.rs` `PqState::step` | PQ root step (ML-KEM, and McEliece when braided) |
| `enclave/v1/pq/key` | KMAC | 256 | `ratchet.rs` `key_as_sender`, `key_as_receiver` | Per-message PQ key from the two directional PQ roots |
| `enclave/v1/prekey/merkle` | HASH | 256 | `bundle.rs` `merkle_leaf`, `merkle_node`, `merkle_empty` | One-time-prekey Merkle tree. The label follows a type byte (0 leaf, 1 node, 2 empty leaf), so the three input sets are disjoint. |
| `enclave/v1/bond/psk` | KMAC | 256 | `eqxdh.rs` `bond_psk` | In-person bond PSK |
| `enclave/v1/bond/seal-words` | KMAC | 256 (48 bits used) | `eqxdh.rs` `seal_words` | Three Seal words after an in-person scan |
| `enclave/v1/invite/psk` | KMAC | 256 | `eqxdh.rs` `invite_psk` | One-way PSK from an invite link's secret (03 §7.3) |
| `enclave/v1/invite/cap` | KMAC | 256 | `eqxdh.rs` `invite_cap` | The i-th request-inbox capability of an invite link (03 §9.2) |
| `enclave/v1/proto/contact-art` | KMAC | 256 | `enclave-core/src/art.rs` `contact_art` | Seed for key-derived contact art (02b §4.3, RT-26) |
| `enclave/v1/proto/link-psk` | KMAC | 256 | `enclave-core/src/client/link.rs` `link_key` | Device-link PSK from the link code's secret (02b §5, §11) |

### 2.3 Sealed requests and server API (`enclave-rpc`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/rpc/request` | KMAC | 256 | `lib.rs` `derive` | Request seal key `k_req` |
| `enclave/v1/rpc/reply` | KMAC | 256 | `lib.rs` `derive` | Reply seal key `k_reply` |
| `enclave/v1/rpc/read-credential` | KMAC | 256 (first 192 bits used) | `api.rs` `read_credential` | 24 B inbox read credential from the owner secret |
| `enclave/v1/rpc/credential-hash` | KMAC | 256 | `api.rs` `credential_hash` | Server-stored hash of an owner secret or read credential |
| `enclave/v1/net/replay-id` | HASH | 256 | `lib.rs` `replay_id` | Replay-cache key of a sealed request: `SHAKE256(label ‖ u32 key_id ‖ eph X448 ‖ ML-KEM ct)` (09 §2.3) |
| `enclave/v1/net/status-id` | KMAC | 256 | `lib.rs` `derive` | Where a deferred answer waits for its status poll: `KMAC256(exchange secret, "", label)`, known to both ends of one request (09 §6.1) |
| `enclave/v1/net/inbox-addr-seed` | KMAC | 256 | `api.rs` `inbox_addr_seed` | The account's address seed from its inbox seed, given to contacts (09 §3.1) |
| `enclave/v1/net/inbox-addr` | KMAC | 256 | `api.rs` `inbox_addr` | Weekly account-inbox address: `KMAC256(addr_seed, u32 week, label)` (09 §3.1) |
| `enclave/v1/net/inbox-owner` | KMAC | 256 | `api.rs` `inbox_owner` | Owner secret of one weekly address: `KMAC256(inbox_seed, address, label)` (09 §3.1) |
| `enclave/v1/net/inbox-read-key` | KMAC | 256 | `api.rs` `inbox_read_key` | Inbox read key from the inbox seed (09 §3.1) |
| `enclave/v1/net/read-cred` | KMAC | 256 (first 192 bits used) | `api.rs` `daily_read_credential` | Daily read credential bound to an address: `KMAC256(read_key, address ‖ u32 day, label)` (09 §3.1) |
| `enclave/v1/net/cap-hash` | KMAC | 256 | `api.rs` `cap_hash` | Server-stored invite-capability hash, bound to the request inbox: `KMAC256(cap, inbox, label)` (09 §4) |
| `enclave/v1/server/request-key` | KMAC | 960 | `lib.rs` `ServerSecret::from_seed` | A day's X448 secret (56 B) and ML-KEM-1024 seed (64 B) from that day's chain seed; data is the day index (12 §1.4) |
| `enclave/v1/server/request-chain` | KMAC | 256 | `lib.rs` `ServerSecret::next_seed` | Next day's chain seed; the old one is erased (forward secrecy, 12 §1.4) |

### 2.4 Tokens and proof of work (`enclave-tokens`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/tokens/write` | KMAC | 256 | `lib.rs` `write_token` | Single-use write token `t_i` |
| `enclave/v1/tokens/hash` | KMAC | 256 | `lib.rs` `token_hash` | Server-stored token hash, bound to the inbox address: `KMAC256(t, address, label)` (09 §3.3) |
| `enclave/v1/tokens/pow` | HASH | 32 | `lib.rs` `accepted` | Proof-of-work effort check: `SHAKE256(label ‖ challenge ‖ solution)`, first 4 B |
| `enclave/v1/tokens/equihash-kat` | INFO | — | `equihash.rs` tests | Challenge of the Equihash known-answer test (test only; ADR 0004) |
| `enclave/v1/tokens/pp-issuer` | INFO | — | `privpass.rs` `IssuerKey::derive` | Privacy Pass issuer key for an epoch: RFC 9497 `DeriveKeyPair(seed, label ‖ u32 epoch)` (RFC 0001) |

### 2.5 Server (`enclave-server`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/dir/manifest` | HASH | 256 | `lib.rs` `manifest_key` | Directory key of a manifest: `SHAKE256(label ‖ root_pk)` |

### 2.5a Federation (`enclave-federation`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/net/server-id` | HASH | 256 (first 128 bits used) | `lib.rs` `server_id` | 16 B server id: `SHAKE256(label ‖ identity composite pk)` (12 §1.4) |
| `enclave/v1/net/request-key-cert` | CTX-C | — | `keycert.rs` | Identity signature on a daily request key (12 §4.2) |
| `enclave/v1/net/server-descriptor` | CTX-C | — | `descriptor.rs` | Server descriptor self-signature (12 §4.3) |
| `enclave/v1/kt/witness-descriptor` | CTX-C | — | `witness.rs` | Witness descriptor self-signature (12 §3.3) |
| `enclave/v1/kt/witness-id` | HASH | 256 (first 128 bits used) | `witness.rs` `witness_id` | 16 B witness id from its cosigning key |
| `enclave/v1/calls/relay-descriptor` | CTX-C | — | `relay.rs` | Relay descriptor self-signature (declares operator family) (12 §5) |
| `enclave/v1/calls/relay-id` | HASH | 256 (first 128 bits used) | `relay.rs` `relay_id` | 16 B relay id from its identity key |
| `enclave/v1/update/server-list` | CTX-R + CTX-C | — | `list.rs` | Foundation's server list: both an SLH-DSA and a composite signature, each required (12 §4.1) |
| `enclave/v1/update/foundation-keygen` | KMAC | 768 | `list.rs` `FoundationKey` | SLH-DSA seeds of the foundation's list key from its 32-byte secret |
| `enclave/v1/update/release` | CTX-R + CTX-C | — | `enclave-update` `metadata.rs` | Maintainer signature on a release document (root, targets, snapshot, timestamp): an SLH-DSA and a composite signature over `role ‖ body`, each required (19 §1) |
| `enclave/v1/update/maintainer-keygen` | KMAC | 768 | `enclave-update` `MaintainerKey` | SLH-DSA seeds of a maintainer's release key from its 32-byte secret |

### 2.6 Key transparency (`enclave-kt`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/kt/akd` | HASH | 256 | `config.rs` `EnclaveKtConfig::hash` | Domain prefix of every akd hash |
| `enclave/v1/kt/head` | CTX-C | — | `head.rs` `SignedHead::sign`, `verify_server` | Server tree-head signature |
| `enclave/v1/kt/cosign` | CTX-C | — | `head.rs` `WitnessPolicy::check`; `log.rs` `Witness::cosign` | Witness cosignature |
| `enclave/v1/kt/gossip` | HASH | 256 | `head.rs` `TreeHead::gossip_digest` | 32 B head digest for gossip |
| `enclave/v1/kt/claim` | CTX-C | — | `wire.rs` `UsernameClaim`; server `accept_username`; core `claim_username` | Device signature on a username claim |
| `enclave/v1/kt/c2sp-key` | KMAC | 256 | `c2sp.rs` `C2spKey::derive` | A witness's Ed25519 and ML-DSA-44 C2SP cosigning seeds from its composite seed (data `ed25519`, `ml-dsa-44`; 12 §3.3a) |

### 2.7 Local storage (`enclave-store`)

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/store/master` | KMAC | 256 | `store.rs` `derive_master` | Profile master key |
| `enclave/v1/store/index` | KMAC | 256 | `store.rs` `Store::create`, `Store::open` | Index (key-blinding) key from the master key |
| `enclave/v1/store/namespace` | KMAC | 256 (first 64 bits used) | `store.rs` `Store::ns_tag` | 8 B namespace tag at the front of every blinded key |
| `enclave/v1/store/blind` | KMAC | 256 | `store.rs` `Store::blind` | 32 B blinded record key |

Total: 50 implemented labels.

### 2.8 Built after the M0 draft

These labels were first reserved in §3 and are now used by code. "Where" names the defining files.

| Label | Kind | Output | Where | Purpose |
|---|---|---|---|---|
| `enclave/v1/proto/link-transcript` | TR | — | `enclave-core/src/client/link.rs` | Device-link transcript prefix (spec: 02b §11) |
| `enclave/v1/net/push-group-id` | KMAC | 256 | `enclave-core/src/client/push.rs` `push_group_at` | A device's id (first 8 bytes) for its push registration on a group mailbox, keyed by the device id over the mailbox (spec: 10 §3) |
| `enclave/v1/proto/notify-key` | KMAC | 256 | `enclave-proto/src/notify.rs` `step` | Daily step of a contact's notification key chain; data `u32(day)` (spec: 10 §4) |
| `enclave/v1/proto/grp-notify` | KMAC | 256 | `enclave-proto/src/notify.rs` `group_key` | A group's notification key for a day, from the epoch secret; data `u32(day)` (spec: 10 §4) |
| `enclave/v1/wire/ad-capsule` | AD | — | `enclave-proto/src/notify.rs` | Notification capsule AD prefix, then `u32(day)` (spec: 10 §4, 08 §5.4) |
| `enclave/v1/store/pin-check` | KMAC | 256 | `enclave-core/src/client/pin.rs` | Check value of a PIN set before the root wrap, keyed by Argon2id(PIN, salt); read only to upgrade such a profile at its next unlock (spec: 03 §5, 14 §1.3) |
| `enclave/v1/store/root-wrap` | KMAC | 256 | `enclave-core/src/client/root_wrap.rs` `kek` | Key wrapping the recovery secret: keyed by the keystore's root secret over Argon2id(PIN, salt), or nothing without a PIN (spec: 14 §1.3) |
| `enclave/v1/store/ad-root` | AD | — | `enclave-core/src/client/root_wrap.rs` | Wrapped recovery secret AD prefix, then the record header (spec: 14 §1.3) |
| `enclave/v1/store/search-key` | KMAC | 256 | `enclave-core/src/client/search_index.rs` | Search index key, from the store's master key (`Store::derive_key`) (spec: 14 §2.4) |
| `enclave/v1/store/search-token` | KMAC | 256 (first 128 used) | `enclave-core/src/client/search_index.rs` | A word prefix's token in the search index (spec: 14 §2.4) |
| `enclave/v1/store/backup-blob-id` | KMAC | 256 | `enclave-core/src/client/backup.rs`, `server_backup.rs` | The server-backup secret from the recovery secret, and (data `locator`, `owner`, `pointer`) the slot's locator, owner secret and pointer key from it (spec: 14 §4) |
| `enclave/v1/store/app-lock` | KMAC | 256 | `enclave-vault/src/lock.rs` | Check value of the app PIN in `lock.bin`, keyed by Argon2id(PIN, salt) (spec: 14 §5) |
| `enclave/v1/store/emergency-pin` | KMAC | 256 | `enclave-vault/src/lock.rs` | Check value of the emergency PIN in `lock.bin`, from the same Argon2id output (spec: 14 §5) |
| `enclave/v1/net/vault-owner` | KMAC | 256 | `enclave-rpc/src/api.rs` `vault_owner` | Owner secret of the account's vault-key blob, from the key it's sealed under, so the account can replace or delete it (spec: 03 §8.5) |
| `enclave/v1/proto/share-release` | KMAC | 256 | `enclave-core/src/client/social.rs` `release_key` | Seal key for a recovery share given back in person, from the X448 and ML-KEM-1024 secrets to the request code, combined over both codes (spec: 03 §8.3) |
| `enclave/v1/proto/share-words` | KMAC | 256 | `enclave-core/src/client/social.rs` `check_words` | Three check words from a share request, shown on both screens; key SHA3-512 of the request (spec: 03 §8.3) |
| `enclave/v1/proto/link-keys` | KMAC | 512 | `enclave-core/src/client/link.rs` | Link channel keys `k_p2n ‖ k_n2p` (spec: 02b §11) |
| `enclave/v1/proto/link-phrase` | KMAC | 256 (33 bits used) | `enclave-core/src/client/link.rs` | Three-word link phrase (spec: 02b §11) |
| `enclave/v1/proto/grp-chain` | KMAC | 512 | `enclave-proto/src/labels.rs` | Group sender chain `cs' ‖ gmk` (spec: 07 §2) |
| `enclave/v1/proto/grp-mac` | KMAC | 128 | `enclave-proto/src/labels.rs` | MAC-vector entry (spec: 07 §3) |
| `enclave/v1/proto/grp-admin-mac` | KMAC | 128 | `enclave-proto/src/labels.rs` | Admin MAC-vector entry on state updates (spec: 07 §7) |
| `enclave/v1/proto/grp-export` | KMAC | 256 | `enclave-proto/src/labels.rs` | Pairwise exporter key `K_exp` for rekey (spec: 07 §5) |
| `enclave/v1/proto/grp-rekey-pad` | KMAC | 512 | `enclave-proto/src/labels.rs` | Pad that encrypts a rekey entry (spec: 07 §5) |
| `enclave/v1/proto/grp-rekey-check` | KMAC | 96 | `enclave-proto/src/labels.rs` | Rekey entry authenticator (spec: 07 §5) |
| `enclave/v1/proto/grp-bucket` | KMAC | 256 | `enclave-proto/src/labels.rs` | Epoch bucket key (spec: 07 §5) |
| `enclave/v1/proto/grp-bucket-index` | KMAC | 256 (16 bits used) | `enclave-proto/src/labels.rs` | Recipient bucket index (spec: 07 §5) |
| `enclave/v1/proto/grp-header` | KMAC | 256 | `enclave-proto/src/labels.rs` | Group routing-header seal key (spec: 07 §4) |
| `enclave/v1/proto/grp-state` | HASH | 256 | `enclave-proto/src/labels.rs` | Group state hash chain (spec: 07 §7) |
| `enclave/v1/proto/root-hash` | HASH | 256 | `enclave-proto/src/otr.rs` `root_hash` | `root_hash` of a root public key, in signed-message payloads and conversation ids (02b §2.1) |
| `enclave/v1/proto/conv-id` | HASH | 256 | `enclave-proto/src/otr.rs` `conv_id`, `conv_id_of` | 1:1 conversation id over the two root hashes, lower first (02b §7) |
| `enclave/v1/proto/grp-msg-id` | HASH | 256 (first 64 used) | `enclave-proto/src/labels.rs` | Group message ID for the causal frontier (spec: 07 §7) |
| `enclave/v1/proto/poll-tally-hash` | HASH | 512 | `enclave-core/src/client/polls.rs`, `enclave-proto/src/labels.rs` | Poll-close tally hash (spec: 07 §7) |
| `enclave/v1/net/grp-mailbox` | KMAC | 256 | `enclave-proto/src/labels.rs` | Daily group-mailbox address (spec: 07 §4) |
| `enclave/v1/net/grp-rekey-mailbox` | KMAC | 256 | `enclave-proto/src/labels.rs` | Daily per-bucket rekey sub-mailbox address (spec: 07 §5.5) |
| `enclave/v1/net/grp-write-key` | KMAC | 256 | `enclave-proto/src/labels.rs` | Group write-token key (spec: 07 §4) |
| `enclave/v1/net/grp-write-token` | KMAC | 256 | `enclave-proto/src/labels.rs` | Epoch MAC write token for one address (spec: 07 §4) |
| `enclave/v1/net/push-transcript` | TR | — | `enclave-push-relay/src/lib.rs` | Push-token sealing transcript prefix (spec: 10 §2) |
| `enclave/v1/net/push-seal` | KMAC | 256 | `enclave-push-relay/src/lib.rs` | Push-token seal key (spec: 10 §2) |
| `enclave/v1/net/loop-probe` | KMAC | 256 | `enclave-net/src/transport.rs` `GatewayPath::probe_forever` | Self-loop probe id: `KMAC256(probe secret, u64 counter, label)`, first 16 B (RT-02; spec: 09 §6.3) |
| `enclave/v1/wire/chunk-key` | KMAC | 256 | `enclave-core/src/files.rs` | Blob chunk seal key (spec: 08 §9) |
| `enclave/v1/wire/chunk-id` | KMAC | 256 | `enclave-core/src/files.rs` | Blob chunk ID (spec: 08 §9) |
| `enclave/v1/wire/ad-chunk` | AD | — | `enclave-core/src/files.rs` `chunk_ad` | Blob chunk AD prefix (spec: 08 §9.1) |
| `enclave/v1/proto/grp-rekey-outer` | KMAC | 256 | `enclave-proto/src/group.rs` `outer_key` | Outer seal key of a rekey unit, from the announcing epoch's secret (spec: 08 §8) |
| `enclave/v1/wire/ad-rekey` | AD | — | `group.rs` `rotate`, `apply_rekey` | Rekey unit outer-seal AD prefix (spec: 08 §8) |
| `enclave/v1/wire/ad-rekey-common` | AD | — | `group.rs` `rotate`, `apply_rekey` | Rekey common-blob AD prefix (spec: 08 §8) |
| `enclave/v1/wire/ad-grp-header` | AD | — | `group.rs` `mac_input` | Prefix of what a group message's MAC vector covers (spec: 08 §7) |
| `enclave/v1/wire/ad-grp-body` | AD | — | `group.rs` `body_ad` | Group message body AD prefix (spec: 08 §7) |
| `enclave/v1/tokens/blob-issuer-seed` | KMAC | 256 | `enclave-server/src/keys.rs` `ServerKeys::blob_seed` | Seed of a server's blob-token issuer keys, from its identity seed (spec: 09 §9) |
| `enclave/v1/wire/ad-link` | AD | — | `enclave-core/src/client/link.rs` | Device-link channel AD prefix (spec: 03 §4) |
| `enclave/v1/wire/ad-push-token` | AD | — | `enclave-push-relay/src/lib.rs` | Sealed push token AD prefix (spec: 10 §2) |
| `enclave/v1/push/relay-key` | KMAC | 960 | `enclave-push-relay/src/lib.rs` `RelaySecret::from_seed` | A key epoch's X448 secret (56 B) and ML-KEM-1024 seed (64 B) from that epoch's chain seed; data is the epoch (spec: 10 §7) |
| `enclave/v1/push/relay-chain` | KMAC | 256 | `enclave-push-relay/src/lib.rs` `RelaySecret::next_seed` | Next key epoch's chain seed (spec: 10 §7) |
| `enclave/v1/calls/transcript` | TR | — | `enclave-calls/src/lib.rs` | Per-call transcript prefix (spec: 11 §2) |
| `enclave/v1/calls/secret` | KMAC | 512 | `enclave-calls/src/lib.rs` | Call secret (spec: 11 §2) |
| `enclave/v1/calls/sframe-base` | KMAC | 256 | `enclave-calls/src/lib.rs` | Per-sender SFrame base key (spec: 11 §5) |
| `enclave/v1/calls/sframe-ratchet` | KMAC | 256 | `enclave-calls/src/lib.rs` | 5 s base-key ratchet step (spec: 11 §5) |
| `enclave/v1/calls/sframe-key` | KMAC | 512 | `enclave-calls/src/lib.rs` | SFrame key and salt per KID (spec: 11 §5) |
| `enclave/v1/calls/check-words` | KMAC | 256 (22 bits used) | `enclave-calls/src/lib.rs` | 2-word call check (spec: 11 §9) |
| `enclave/v1/calls/direct-psk` | KMAC | 256 | `enclave-calls/src/lib.rs` | WireGuard PSK in direct mode (spec: 11 §4) |
| `enclave/v1/calls/ticket-transcript` | TR | — | `enclave-calls/src/lib.rs` | Relay-ticket transcript prefix (spec: 11 §3) |
| `enclave/v1/calls/ticket-secret` | KMAC | 256 | `enclave-calls/src/lib.rs` | Relay-ticket secret (spec: 11 §3) |
| `enclave/v1/calls/ticket-seal` | KMAC | 256 | `enclave-calls/src/lib.rs` | Seal key for the relay-ticket request body (spec: 11 §3.3) |
| `enclave/v1/calls/wg-psk` | KMAC | 256 | `enclave-calls/src/lib.rs` | WireGuard PSK for one 120 s period (spec: 11 §3) |
| `enclave/v1/calls/ticket-pow` | KMAC / context | 256 | `enclave-calls/src/lib.rs` | Proof of work paying for a relay ticket (context with relay id, epoch, ephemeral key and ciphertext), and the id a relay burns from the ephemeral key (spec: 11 §3.3, ADR 0006) |
| `enclave/v1/calls/relay-wg` | KMAC | 256 | `enclave-calls/src/lib.rs` | A relay's static WireGuard key from its link key (spec: 11 §3.1) |
| `enclave/v1/calls/relay-link` | KMAC | 256 | `enclave-calls/src/lib.rs` | Per-direction relay↔relay link key from the relays' static X448 keys, until the first post-quantum epoch (spec: 11 §3.4, RFC 0007) |
| `enclave/v1/calls/relay-kem` | KMAC | 256 | `enclave-calls/src/lib.rs` | A relay's static ML-KEM-1024 link key seed (`d`, `z`) from its link key (spec: RFC 0007) |
| `enclave/v1/calls/relay-pq` | KMAC | 256 | `enclave-calls/src/lib.rs` | Per-direction relay↔relay link key for one 120 s epoch, from the X448 exchange and three ML-KEM secrets (spec: RFC 0007) |
| `enclave/v1/calls/rendezvous` | KMAC | 128 | `enclave-calls/src/lib.rs` | Rendezvous id joining the two relay legs of a call (spec: 11 §3.4) |
| `enclave/v1/calls/participant` | KMAC | 32 | `enclave-calls/src/signal.rs` `CallKeys::participant` | A group call participant's id (SFrame KID's upper half) from the call secret and their root, so only members can tell who is who (spec: 11 §8) |
| `enclave/v1/calls/ad-ticket` | AD | — | `enclave-calls/src/lib.rs` | Relay-ticket seal AD prefix (spec: 11 §3) |
| `enclave/v1/calls/ad-sframe` | AD | — | `enclave-calls/src/lib.rs` | Prefix of SFrame AAD (spec: 11 §5) |
| `enclave/v1/calls/ticket-key` | KMAC | 960 | `enclave-calls/src/ticket.rs` `TicketSecretKey::from_seed` | A day's ticket-key X448 secret (56 B) and ML-KEM-1024 seed (64 B) from that day's chain seed; data is the day (spec: 12 §5) |
| `enclave/v1/calls/ticket-chain` | KMAC | 256 | `enclave-calls/src/ticket.rs` `TicketSecretKey::next_seed` | Next day's ticket-key chain seed (spec: 12 §5) |

## 3. Reserved labels (not yet implemented)

These labels belong to features that are specified but not in code. They are reserved; the code MUST use exactly these strings when the feature is built, unless an RFC changes this file first.

### 3.1 Identity, linking, conversations

| Label | Kind | Output | Purpose | Defined in |
|---|---|---|---|---|

### 3.2 Groups

| Label | Kind | Output | Purpose | Defined in |
|---|---|---|---|---|
| `enclave/v1/proto/grp-invite-cap` | KMAC | 256 | Group invite capability | 07 §9 |

### 3.3 Transport, push, servers

| Label | Kind | Output | Purpose | Defined in |
|---|---|---|---|---|

### 3.4 KT, releases, storage, calls

| Label | Kind | Output | Purpose | Defined in |
|---|---|---|---|---|
| `enclave/v1/kt/leaf` | HASH | 512 | KT leaf value commitment | 12 §3 |
| `enclave/v1/calls/link-cap` | KMAC | 256 | Call-link capability | 11 §8 |

## 4. Retired draft labels

The M0 draft named these labels. The implementation replaced them, so they are retired and MUST NOT be reused.

| Retired label | Replaced by |
|---|---|
| `enclave/v1/net/grp-read-key`, `enclave/v1/net/grp-read-cred` | `enclave/v1/rpc/read-credential` of the mailbox's write token (`grp-write-token`): the server derives the read credential's hash from the first write, so a group mailbox is created and readable in one unit. A separate read key would need a registration request per mailbox per day (four per epoch) and protects against nobody: only members and the server ever hold the write token |
| `enclave/v1/proto/invite-psk`, `enclave/v1/proto/invite-cap` | `enclave/v1/invite/psk` and `enclave/v1/invite/cap` (`eqxdh.rs` `invite_psk`, `invite_cap`): the same derivations, built under the invite namespace |
| `enclave/v1/calls/link-dir` | WireGuard (`enclave_calls::wg`): the client↔relay hop is a WireGuard tunnel whose pre-shared key is `calls/wg-psk` for the period |
| `enclave/v1/proto/link-cap` | None: the link rendezvous mailbox's owner secret is random (`link/owner`) and travels in the link code, so the server never sees anything derived from the link secret that keys the exchange |
| `enclave/v1/proto/pending-root` | None: an update without a co-signature is the manifest itself, held by each contact from when it first saw it (`guard.rs`); a root-signed `not_before` would be chosen by whoever holds the root. The manifest and its attestations go into key transparency together as the account record (03 §8.1) |
| `enclave/v1/proto/veto` | `enclave/v1/ctx/manifest-cosign` and `enclave/v1/ctx/manifest-veto` (`attest.rs`): one context per verdict, signing the root, version and manifest hash |
| `enclave/v1/proto/msg-id` | None: a 1:1 message id is 16 random bytes its sender picks (`core/msg-id`), which a re-send keeps; a derived id would need a counter both sides agree on and add nothing |
| `enclave/v1/proto/bond-reroot` | None: meeting again replaces the sessions with new bonded ones (an EQXDH greeting with the new bond PSK, `client/meet.rs`), which heals more than mixing a PSK into the old root would |
| `enclave/v1/net/token-key` | Write tokens from a shared, per-device pool of hedged random values (`core/write-token`, 09 §3.3): per-contact keys let the server group writes by registration batch |
| `enclave/v1/proto/manifest` | `enclave/v1/ctx/manifest` |
| `enclave/v1/proto/migration` | `enclave/v1/ctx/migration` |
| `enclave/v1/proto/manifest-hash` | Plain SHA3-512 of the signed manifest encoding (no label; `SignedManifest::hash`) |
| `enclave/v1/proto/spk` | `enclave/v1/ctx/signed-prekey` and `enclave/v1/ctx/last-resort` (separate signatures) |
| `enclave/v1/proto/opk-root` | `enclave/v1/ctx/opk-batch` |
| `enclave/v1/proto/opk-leaf` | `enclave/v1/prekey/merkle` (type byte 0 or 2) |
| `enclave/v1/proto/opk-node` | `enclave/v1/prekey/merkle` (type byte 1) |
| `enclave/v1/proto/bond` | `enclave/v1/bond/psk` |
| `enclave/v1/proto/bond-words` | `enclave/v1/bond/seal-words` |
| `enclave/v1/proto/eqxdh-hint` | None: the implemented initial message has no hint or selector (`04-eqxdh.md`) |
| `enclave/v1/proto/eqxdh-t1` | Transcript prefix `"EQXDH-v1/stage1"` (first framed public item, not a label) |
| `enclave/v1/proto/eqxdh-t2` | Transcript prefix `"EQXDH-v1"` (first framed item, not a label) |
| `enclave/v1/proto/eqxdh-id` | `enclave/v1/eqxdh/identity` |
| `enclave/v1/proto/eqxdh-sig` | `enclave/v1/ctx/eqxdh-transcript` |
| `enclave/v1/proto/eqxdh-replay` | Plain SHA3-512 (`InitialMessage::replay_id`) |
| `enclave/v1/proto/ratchet-init` | `enclave/v1/ratchet/init-rk`, `enclave/v1/ratchet/init-hk`, `enclave/v1/ratchet/init-pq` |
| `enclave/v1/proto/eqxdh-auth-mix` | None: PQ authentication of the initiator is the responder's first PQ ratchet step to the initiator's auth key (`05-ratchet.md` §7) |
| `enclave/v1/proto/eqxdh-confirm` | None (no separate key confirmation) |
| `enclave/v1/proto/braid-mix` | `enclave/v1/pq/step` (the braid is folded into a PQ step) |
| `enclave/v1/proto/dr-root` | `enclave/v1/ratchet/rk` |
| `enclave/v1/proto/dr-chain` | `enclave/v1/ratchet/ck` |
| `enclave/v1/proto/pq-epoch` | `enclave/v1/pq/step` |
| `enclave/v1/proto/pq-chain-init` | None: there is no PQ symmetric chain; see `enclave/v1/pq/key` |
| `enclave/v1/proto/pq-chain` | `enclave/v1/pq/key` |
| `enclave/v1/proto/msg-key` | `enclave/v1/ratchet/msg` |
| `enclave/v1/proto/lookup-tag` | `enclave/v1/ratchet/tag` |
| `enclave/v1/proto/slot-wrap` | `enclave/v1/ratchet/wrap` |
| `enclave/v1/proto/pq-slot-key` | `enclave/v1/ratchet/pq-slot` |
| `enclave/v1/proto/signed-msg` | `enclave/v1/ctx/signed-msg` |
| `enclave/v1/net/dir-object` | `enclave/v1/dir/manifest` (manifests); the raw device ID (bundles) |
| `enclave/v1/net/request-transcript` | None: the request transcript is the framed public items (`09-transport.md` §2) |
| `enclave/v1/net/request-key` | `enclave/v1/rpc/request` |
| `enclave/v1/net/reply-key` | `enclave/v1/rpc/reply` |
| `enclave/v1/net/cred-hash` | `enclave/v1/rpc/credential-hash` |
| `enclave/v1/net/write-token` | `enclave/v1/tokens/write` |
| `enclave/v1/net/token-hash` | `enclave/v1/tokens/hash` (not bound to the inbox address) |
| `enclave/v1/wire/ad-request` | AD = `u32(key_id) ‖ padding` (the unit's last 284 B; `09-transport.md` §2) |
| `enclave/v1/wire/ad-reply` | AD = ASCII `"reply"` |
| `enclave/v1/wire/ad-poll` | AD = `u32(key_id) ‖ padding` (the poll's last 284 B) |
| `enclave/v1/wire/ad-device-slot` | AD = the 16 B envelope header |
| `enclave/v1/wire/ad-pq-slot` | AD = the 16 B envelope header |
| `enclave/v1/wire/ad-body` | AD = the 16 B envelope header (request envelopes: header ‖ initial block) |
| `enclave/v1/wire/ad-init-id` | AD = `u8(suite_id) ‖ u8(mode)` |
| `enclave/v1/store/blind-key` | `enclave/v1/store/index` |
| `enclave/v1/store/keyring` | None: the keyring wrap key is a random secret held in the keystore (`14-storage.md` §3) |
| `enclave/v1/store/ad-record` | AD = the 40 B blinded key plus the segment index and last flag |
| `enclave/v1/store/ad-keyring` | AD = ASCII `"keyring"` |
| `enclave/v1/store/ad-backup` | AD = ASCII `"enclave-backup-v1"` |

## 5. Mapping from PLAN.md shorthand

| PLAN.md text | Canonical label |
|---|---|
| `"enclave/v1/kem-extract"` (§2.3) | `enclave/v1/kem/extract` (3-KEM), `enclave/v1/kem2/extract` (2-KEM) |
| `"enclave/v1/kem"` (§2.3) | `enclave/v1/kem/combine`, `enclave/v1/kem2/combine` |
| `"seal/nonce"`, `"seal/keys"`, `"seal/tag"` (§2.3) | `enclave/v1/seal/nonce`, `enclave/v1/seal/keys`, `enclave/v1/seal/tag` |
| `label` in the hedged RNG (§2.3) | `enclave/v1/rng/hedge` |
| `"enclave/v1/root"` (§3.1) | `enclave/v1/root/keygen` |
| `SHAKE256^5200(root_pk)` (§3.5) | `enclave/v1/fp/root` (first step; then SHA3-512 iterations, `02b-key-schedule.md` §4.1) |
| `"enclave/v1/bond"` (§3.6) | `enclave/v1/bond/psk` |
| `KMAC(recovery, "backup")` (§13) | `enclave/v1/backup/key` |
| `KMAC(master, salt‖record_id)` (§2.3) | `enclave/v1/store/record` |
| `KMAC(SK', "confirm")` (§4) | None (retired; see §4) |
| `"enclave/v1/msg"` (§5) | `enclave/v1/ratchet/msg` |
| `KMAC(hk, "tag"‖N)` (§5) | `enclave/v1/ratchet/tag` |
| `"enclave/v1/signed-msg"` (§5) | `enclave/v1/ctx/signed-msg` |
| `KMAC(epoch_secret, "gmbox"‖day)` (§7) | `enclave/v1/net/grp-mailbox` (reserved) |
| `"grp-export"` (§7) | `enclave/v1/proto/grp-export` (reserved) |
| `KMAC(inbox_seed, "inbox"‖week)` (§9.3) | `enclave/v1/net/inbox-addr` over `enclave/v1/net/inbox-addr-seed` |
| `KMAC(read_key, day)` (§9.3) | `enclave/v1/net/read-cred` (bound to the address too); request inboxes keep the static `enclave/v1/rpc/read-credential` |
| `KMAC(k_contact, i)` (§9.3) | `enclave/v1/tokens/write` |
| `KMAC256(hw_secret‖Argon2id(passphrase)?)` (§13) | `enclave/v1/store/master` |

## 6. Hedged-RNG purposes (not labels)

Purpose strings are framed inputs to `enclave/v1/rng/hedge`, not labels. They are listed so that reviewers can check that no purpose is reused for a different kind of value. Purposes used by the code today:

`api/padding`, `app/lock-fill`, `app/lock-salt`, `app/vault-dir`, `app/vault-token`, `blob/padding`, `blob/secret`, `calls/call-id`, `calls/group-secret`, `calls/id`, `calls/relay-pick`, `core/blob-redeem`, `core/decoy`, `core/group-msg-id`, `core/held-id`, `core/inbox`, `core/inbox-owner`, `core/inbox-seed`, `core/invite`, `core/meet`, `core/migration-in`, `core/msg-id`, `core/part-id`, `core/poll-id`, `core/request-inbox`, `core/request-owner`, `core/slip39`, `core/vault-key`, `core/vault-locator`, `core/vault-owner`, `core/write-token`, `device/id`, `envelope/body-key`, `envelope/capsule`, `envelope/dummy-pq`, `envelope/dummy-slot`, `envelope/padding`, `envelope/shuffle`, `group/capsule`, `group/chain-seed`, `group/epoch-secret`, `group/id`, `group/mac-fill`, `group/mac-key`, `group/nonce`, `group/padding`, `group/rekey-fill`, `group/rekey-kb`, `group/rekey-padding`, `group/shuffle`, `kt/dev-twin-seed`, `kt/dev-vrf`, `link/choice`, `link/decoy`, `link/mailbox`, `link/owner`, `link/secret`, `mlkem/encaps`, `mlkem/keygen`, `net/loop-probe-delay`, `net/loop-probe-secret`, `net/nym-request-id`, `push/relay-chain`, `rand_core`, `recovery/secret`, `relay/id`, `relay/link-key`, `relay/session`, `relay/ticket-chain`, `rpc/poll-padding`, `rpc/reply-padding`, `rpc/status-token`, `rpc/unit-padding`, `schedule/delay`, `seal/key`, `seal/nonce`, `server/blob-alloc`, `server/blob-seed`, `server/claim-id`, `server/garbage-reply`, `server/kt-reply-id`, `server/kt-vrf`, `server/push-jitter`, `server/request-chain`, `sig/composite/keygen`, `sig/composite/sign`, `sig/mldsa44/sign`, `sig/root/sign`, `store/device-secret`, `store/hedge`, `store/root-secret`, `store/pw-salt`, `store/salt`, `store/shred-key`, `store/shred-wrap`, `tokens/contact-key`, `tokens/dummy`, `tokens/pow-nonce`, `tokens/pp-nonce`, `tokens/shuffle`, `update/foundation-key`, `update/maintainer-key`, `x448/keygen`. (`rand_core` is McEliece key generation and encapsulation through the `rand_core` adapter.) The simulator (`enclave-sim`) uses `sim` for test-only values.

## Open questions

1. **Resolved.** Whether the Ed448 half of a maintainer release co-signature (`enclave/v1/update/release`) should use the Ed448 context parameter instead of a message prefix: neither; a maintainer signature is an SLH-DSA signature and a composite (Ed448 + ML-DSA-87) signature, as the foundation's server list has, and the composite carries the context in its message representative (`sig.rs`), so both halves are bound to it (ADR 0005).
2. Whether `cargo xtask labels` should also check the "Kind" column, for example by requiring each `const` to carry a kind attribute.
3. Several implemented AD strings (`"reply"`, `"keyring"`, `"enclave-backup-v1"`, `"verifier"`) and transcript prefixes (`"EQXDH-v1"`, `"EQXDH-v1/stage1"`, `"ENCLAVE-POW1"`, `"request-inbox"`, `"report"`, `"claim-bundle"`, `"blob-put"`, `"compact"`) are short ASCII strings outside the `enclave/v1/` namespace, so CI does not check them. Each is unique within its call site today. Whether to move them into the registry namespace is open; doing so changes wire and storage formats.
