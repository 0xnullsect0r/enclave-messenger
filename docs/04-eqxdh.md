# Session Establishment: EQXDH v1

Status: Draft (M0, reconciled with the M2 code) · Normative

Source: PLAN.md §4 (D2, D12). Crate: `enclave-proto` (`eqxdh.rs`, `bundle.rs`, `envelope.rs`). Derivations: `02b-key-schedule.md` §6. Byte layout of the request envelope and the initial-message block: `08-envelope.md` §6. Ratchet initialization: `05-ratchet.md` §4. Where this document and the code disagree, the code is normative.

## 1. Overview

EQXDH establishes one pairwise session between an initiator device `a` (account A, "Alice") and a responder device `b` (account B, "Bob"). Every device pair has its own session. It combines:

- four X448 exchanges (DH1 to DH4, as in X3DH; DH4 only when a one-time prekey was served);
- one ML-KEM-1024 encapsulation to a Bob prekey (PQ confidentiality);
- one ML-KEM-1024 encapsulation to Bob's device **auth key** (PQ authentication of Bob);
- one McEliece-8192128 encapsulation to Bob's account **vault key** when Alice has it (3-KEM suite), otherwise none (2-KEM suite, braided later, §7);
- an optional 32 B PSK (in-person bond or none);
- in Bob's first reply, the first PQ ratchet step encapsulates to Alice's device auth key, which authenticates Alice post-quantum (`05-ratchet.md` §7.3).

It runs in two stages. Stage 1 derives `k_id`, which seals Alice's identity, from secrets that do not involve Alice's identity key, so Bob's server never learns who is initiating. Stage 2 adds the identity-bound exchanges and derives the 64 B session key `SK`.

There is no negotiation in v1. The suite and mode are bound into the transcript and the sealed-identity AD (RT-07).

## 2. Bob's prekeys

Each device publishes one **prekey publication** (`bundle::Publication`) to its directory (`12-servers.md` §2): a signed prekey, a batch of one-time prekeys, and a last-resort PQ prekey. Each part carries its own composite signature by the device's signing key from the manifest.

Every signature also covers `u64(bundle_epoch)`, the bundle epoch of the manifest that lists the device (`03-identity.md` §3.1). It is not sent: the publisher signs for its current manifest's epoch, and the server (on upload) and the initiator (on use) verify with the epoch of the verified manifest they hold. Prekeys signed for another epoch, such as ones a directory kept from before the account moved its epoch on, fail with `BadSignature` (RT-05, test `rt05_bundle_epoch_mismatch_rejected`). The encoded sizes below do not change.

### 2.1 Signed prekey

```
signed bytes = device_id (16) ‖ u32(spk_id) ‖ SPK X448 (56) ‖ PQSPK ML-KEM-1024 ek (1,568) ‖ u64(expires_at)
signature    = CompositeSign(device_sk, ctx = "enclave/v1/ctx/signed-prekey", signed bytes ‖ u64(bundle_epoch))
```

Encoded as the signed bytes followed by the 4,741 B signature: 6,393 B. Lifetime 14 days (`SPK_LIFETIME_SECS`). `SignedPrekey::verify` checks the signature and `now ≤ expires_at`.

### 2.2 One-time prekey batches

A batch has 100 one-time prekeys `(OPK_i, PQOPK_i)` (`OPK_BATCH`), `i = 0..99`, under one Merkle root in a tree of 128 leaf positions (`MERKLE_DEPTH = 7`):

```
leaf_i  = SHAKE256(u8(0) ‖ "enclave/v1/prekey/merkle" ‖ u32(batch_id) ‖ u16(i) ‖ OPK_i (56) ‖ PQOPK_i (1,568), 32)
empty_j = SHAKE256(u8(2) ‖ "enclave/v1/prekey/merkle" ‖ u16(j), 32)             # positions j = 100..127
node    = SHAKE256(u8(1) ‖ "enclave/v1/prekey/merkle" ‖ left ‖ right, 32)
header  = device_id (16) ‖ u32(batch_id) ‖ u16(count) ‖ root (32)
signature = CompositeSign(device_sk, ctx = "enclave/v1/ctx/opk-batch", header ‖ u64(bundle_epoch))
```

Each served one-time prekey is `u16(index) ‖ OPK (56) ‖ PQOPK (1,568) ‖ path (7 × 32, siblings from the leaf up)` = 1,850 B. `OneTimePrekey::verify` checks that the batch IDs match, `index < count`, the path has 7 entries, and the path leads to the signed root. Its identifier is `(batch_id << 16) | index`. One signature per batch instead of 100 saves 469,359 B of signatures per batch.

### 2.3 Last-resort PQ prekey

```
signed bytes = device_id (16) ‖ u32(lr_id) ‖ LR ML-KEM-1024 ek (1,568) ‖ u64(expires_at)
signature    = CompositeSign(device_sk, ctx = "enclave/v1/ctx/last-resort", signed bytes ‖ u64(bundle_epoch))
```

6,337 B encoded. Lifetime 7 days (`LAST_RESORT_LIFETIME_SECS`).

### 2.4 Publication and bundles

- `PrekeyStore::publish` generates a signed prekey, a batch of 100 one-time prekeys and a last-resort prekey, keeps their secrets, and returns the `Publication` (202,527 B encoded). The signed-prekey ID, batch ID and last-resort ID are consecutive values of one per-store counter.
- The directory serves a **bundle** per claim: the signed prekey, the next unserved one-time prekey with its batch header (if any remain), and the last-resort prekey (`Bundle`, 19,376 B with a one-time prekey, 12,731 B without).
- `Bundle::verify(device_key, bundle_epoch, now)` checks every signature (for the manifest's bundle epoch), both expiries, the Merkle path, and that all parts name the same device. An expired signed or last-resort prekey fails with `Expired`, and its expiry can't be changed without breaking its signature (test `rt05_expired_spk_rejected`). The initiator MUST verify the bundle against the device key in Bob's verified manifest before `initiate`; `initiate` itself does not.
- The client republishes (`maintain_prekeys`, on every sync) when one-time prekeys run low **or** the signed or last-resort prekey is within 2 days of expiry. Before this rule counted the last-resort key (7 days), a quiet account's bundle stopped verifying after a week and nobody new could reach it; the invite-link test found it by advancing the clock 8 days.
- `PrekeyStore::prune(now, grace)` deletes signed and last-resort prekeys more than `grace` seconds past expiry. A one-time prekey secret is deleted when a handshake that used it succeeds.

### 2.5 Prekey selection

`initiate` uses:

| Bundle | X448 prekeys used | ML-KEM prekey used | `PqPrekeyRef` |
|---|---|---|---|
| Has a one-time prekey | `SPK`, `OPK_i` | `PQOPK_i` | `OneTime((batch_id << 16) ‖ index)` |
| No one-time prekey | `SPK` | `LR` (the last-resort prekey) | `LastResort(lr_id)` |

The responder also accepts `Signed` (the signed prekey's ML-KEM half, `PQSPK`), which earlier initiators used without a one-time prekey.

RT-06: draining one-time prekeys forces the last-resort case; forward secrecy of the first message's ML-KEM part then rests on the last-resort key's 7-day lifetime rather than the signed prekey's 14 (test `rt06_last_resort_used_when_drained`).

### 2.6 Vault key

Bob's McEliece vault public key (1,357,824 B) is published to the directory as an opaque object under a random locator and sealed by the client under a key given only in Bob's contact card (`12-servers.md` §2). Alice checks it against the manifest commitment `vault_hash = SHA3-512(vault_pk)` before use; a mismatch fails `initiate` with `BadSignature`.

## 3. The initial message

The initial message travels in a request envelope (`08-envelope.md` §6) together with Alice's first message to that device. Its public block (`InitialMessage::encode`, `INITIAL_BLOCK_LEN` = 8,537 B):

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | suite ID: 2 (2-KEM) or 3 (3-KEM) |
| 1 | 1 | mode: 0 Off the record, 1 On the record |
| 2 | 1 | PSK flag: 0 or 1 |
| 3 | 1 | reserved (written as zero; not checked) |
| 4 | 4 | `spk_id` |
| 8 | 1 | PQ prekey kind: 1 one-time, 2 signed, 3 last-resort |
| 9 | 8 | PQ prekey ID |
| 17 | 56 | `EK_A` |
| 73 | 1,568 | `ct_pq` |
| 1,641 | 208 | `ct_mce` (zero bytes in the 2-KEM suite; not checked) |
| 1,849 | 1,568 | `ct_auth` |
| 3,417 | 5,120 | sealed identity (§4) |

`InitialMessage::replay_id() = SHA3-512(EK_A ‖ ct_pq ‖ ct_auth)` identifies an initial message for the responder's replay cache (§8).

## 4. Stage 1: hide the initiator

```
(EK_sk, EK_A) = fresh X448 pair
DH3 = X448(EK_sk, SPK_B)
DH4 = X448(EK_sk, OPK_B)                               # only with a one-time prekey; otherwise ""
(ct_pq, ss_pq) = ML-KEM-1024.Encaps(PQ prekey per §2.5)
(ct_mce, ss_mce) = McEliece.Encaps(vault_pk_B)          # 3-KEM only; otherwise both ""
s1   = EnclaveCombine(suite,
           secrets = [DH3, DH4, ss_pq, ss_mce],
           public  = ["EQXDH-v1/stage1", EK_A, SPK_B, OPK_B or "", ct_pq, ct_mce or "", root_pk_B (64), device_id_B (16)],
           psk)
k_id = KMAC256(s1, "", 256, "enclave/v1/eqxdh/identity")
```

Identity plaintext (`InitiatorIdentity`), zero-padded to 5,088 B:

| Field | Length |
|---|---|
| Alice's root public key | 64 |
| Alice's manifest version (`u64`) | 8 |
| Alice's device ID | 16 |
| locator length (`u32`) | 4 |
| locator (where to fetch Alice's manifest; at most 256 B) | ≤ 256 |
| signature flag: 0 none, 1 present | 1 |
| On-the-record transcript signature (§5) | 0 or 4,741 |
| zero padding (checked on decode) | rest |

```
sealed_identity = seal_compact(k_id, nonce_material = EK_A, AD = u8(suite_id) ‖ u8(mode), identity)   # 5,120 B
```

The PSK is an input to stage 1, so the responder must know which PSK applies (or try each candidate) before it can open the identity (Open questions).

## 5. Stage 2: authenticate and derive SK

```
DH1 = X448(IK_A_sk, SPK_B)
DH2 = X448(EK_sk, IK_B)
(ct_auth, ss_auth) = ML-KEM-1024.Encaps(auth_ek_b)       # PQ authentication of Bob's device
SK  = EnclaveCombine(suite,
          secrets = [DH1, DH2, DH3, DH4, ss_pq, ss_mce, ss_auth],   # absent values as ""
          public  = transcript items (§5.1),
          psk)                                                     # 64 B
th  = SHA3-512-parts(transcript items)
```

### 5.1 Transcript items

In this order, each framed by EnclaveCombine and `SHA3-512-parts`:

| # | Item | Length |
|---|---|---|
| 1 | ASCII `EQXDH-v1` | 8 |
| 2 | `u8(suite_id) ‖ u8(mode)` | 2 |
| 3 | Alice's root public key | 64 |
| 4 | Bob's root public key | 64 |
| 5 | Alice's device ID | 16 |
| 6 | Bob's device ID | 16 |
| 7 | `IK_A` | 56 |
| 8 | `IK_B` | 56 |
| 9 | `SPK_B` | 56 |
| 10 | ML-KEM prekey used (PQOPK, LR, or PQSPK) | 1,568 |
| 11 | `OPK_B` (empty without a one-time prekey) | 56 or 0 |
| 12 | `EK_A` | 56 |
| 13 | `ct_pq` | 1,568 |
| 14 | Bob's `vault_hash` (always, also in the 2-KEM suite) | 64 |
| 15 | `ct_mce` (empty in the 2-KEM suite) | 208 or 0 |
| 16 | Bob's device auth key | 1,568 |
| 17 | `ct_auth` | 1,568 |
| 18 | Alice's device auth key | 1,568 |
| 19 | Alice's manifest version (`u64`) | 8 |
| 20 | Bob's manifest version (`u64`) | 8 |

`vault_hash` is in the transcript in both suites, so a stripped McEliece component changes `SK` (RT-07). The suite also selects different EnclaveCombine labels and keys.

**On the record.** Alice signs `th`: `CompositeSign(device_sk_a, ctx = "enclave/v1/ctx/eqxdh-transcript", th)` and puts the signature in the sealed identity. Bob verifies it with Alice's device key from her manifest and fails with `BadSignature` if it is missing or invalid.

**Session.** Alice initializes the ratchet as initiator with `SK`, Bob's `SPK_B` as the first remote DH key, her device auth key as PQ key id 0, and `three_kem = (suite == 3)` (`05-ratchet.md` §4.1).

## 6. Responder processing

`respond(local, prekeys, msg, psk, resolver)`:

```
require msg.psk == (psk is present)                                        else Crypto
SPK = prekeys.signed[msg.spk_id] (with its X448 half)                      else Missing
match msg.pq_prekey:
    OneTime(id):    OPK = prekeys.one_time[id]                               else Missing
                    DH4 = X448(OPK_sk, EK_A); ss_pq = Decaps(OPK.pq, ct_pq)
    Signed:         ss_pq = Decaps(SPK.pq, ct_pq)
    LastResort(id): LR = prekeys.last_resort[id]                             else Missing
                    ss_pq = Decaps(LR.pq, ct_pq)
DH3 = X448(SPK_sk, EK_A)
ss_mce = Decaps(vault_sk, ct_mce) if suite 3
k_id = stage 1 (§4) with Bob's own root and device ID
identity = open_compact(k_id, EK_A, u8(suite) ‖ u8(mode), sealed_identity)  else Crypto
decode identity (strict: flag 0 or 1, zero padding)                         else Decode
A = resolver.resolve(identity)          # Alice's verified manifest, from cache or directory
require A.root == identity.root and A.version == identity.manifest_version  else BadSignature
alice_dev = A.device(identity.device)                                        else BadSignature
DH1 = X448(SPK_sk, IK_A); DH2 = X448(IK_B_sk, EK_A); ss_auth = Decaps(auth_dk_b, ct_auth)
rebuild the transcript with Bob's local values and Alice's manifest
if On the record: verify the transcript signature                           else BadSignature
SK = EnclaveCombine(...)
session = responder session: PQ key id 1 fresh, peer PQ key (id 0) = Alice's device auth key
delete the used one-time prekey secret
return (identity, A, mode, session)
```

The caller then opens the first message in the request envelope with the new session (`envelope::open_request`) and commits it only if the body authenticates. A one-time prekey is deleted only after the handshake succeeds, so a forged initial message cannot burn it. All failures are silent to the network.

## 7. Braid fallback (D2)

If Alice does not have Bob's vault key when she initiates, she uses the 2-KEM suite: `ct_mce` is zero, the McEliece secret is empty, and Bob's `vault_hash` is still in the transcript. When the vault key later arrives and verifies against the manifest commitment, Alice's client calls `Session::schedule_braid(vault_pk)`; the McEliece encapsulation is then folded into Alice's next PQ ratchet out-step (`05-ratchet.md` §7.4), after which both sides report `three_kem() == true`.

As implemented:
- Enclave's initiator fetches the vault key before greeting anyone it adds itself (a card, a link, a username, meeting in person), so those sessions start on all three KEMs; a session that still starts on two (the vault key was missing, or another client) has the braid scheduled at once (`initiate_to`).
- **Group-only peers** (PLAN: "for people you share only a group with, sessions start on two KEMs; they must upgrade to three within 7 days, on an unmetered network"): when a member introduces themselves to another member through a group (`connect_members`), the initiator skips the 1.36 MB vault-key fetch and starts on two KEMs, and remembers the contact as due (`client/braid.rs`). Each upkeep round fetches one due contact's vault key, checks it against their manifest's `vault_hash`, schedules the braid on every session with them that lacks it, and sends a `PqStep { reply: true }` so the next PQ step carries it at once, since people who share only a group may never write to each other. On a metered network (`Client::set_metered`, set by the platform) the fetch waits, but no longer than 7 days after the session started (`BRAID_DEADLINE_SECS`). In Maximum privacy the vault key is fetched before the greeting, so nothing starts on two KEMs. Test `group_only_peers_braid_within_seven_days`.
- Bob accepts a 2-KEM initial message. In Maximum privacy, though, he sends nothing a person wrote until `three_kem()` holds; contact info shows "Extra protection: finishing…" meanwhile (`09-transport.md` §6.6; test `maximum_waits_for_three_kems`).

## 8. Replay protection

- The directory serves each one-time prekey once, and the responder deletes the secret on first successful use, so a replayed initial message that used a one-time prekey fails with `Missing`.
- For initial messages that used the signed or last-resort prekey, the responder keeps a cache of `replay_id` values (the cache lives in the client engine, not in `enclave-proto`) for the signed prekey's lifetime plus 7 days (RT-05, RT-24).

## 9. Seal words and the in-person PSK

The in-person bond PSK and the three Seal words (`03-identity.md` §7) are computed by `eqxdh::bond_psk` and `eqxdh::seal_words` (`02b-key-schedule.md` §4.2). A session established with that PSK passes it to both `initiate` and `respond`.

## 10. Errors

| Condition | Responder | Initiator |
|---|---|---|
| Vault key does not match the manifest commitment | — | `BadSignature` |
| PSK presence does not match the message's PSK flag | `Crypto` | — |
| Unknown signed, one-time or last-resort prekey | `Missing` | — |
| Sealed identity fails to open | `Crypto` | — |
| Identity malformed | `Decode` | — |
| Manifest does not match the identity, device not listed | `BadSignature` | — |
| On-the-record signature missing or invalid | `BadSignature` | — |
| Locator longer than 256 B | — | `Limit` |

Tests (`crates/enclave-proto/tests/session.rs`): `full_three_kem_conversation`, `mceliece_braid_upgrades_two_kem_session`, `on_the_record_and_psk`, `psk_mismatch_fails_closed`.

## Open questions

1. **Last-resort prekey.** PLAN §4 has Alice encapsulate to "PQOPK_B (or to PQSPK / the last-resort key)". Resolved: without a one-time prekey the initiator uses the last-resort key (§2.5), the shorter-lived of the two.
2. **PSK in stage 1.** The implementation mixes the PSK into the stage-1 key, so the responder must know the PSK (or try each candidate) before it learns who the initiator is. The M0 draft kept the PSK out of stage 1 for this reason. This needs a decision before bond PSKs are used in practice.
3. **Transcript contents.** PLAN §4 asks the transcript to cover both manifest hashes, both capability sets and the bundle epoch. The implementation binds both root keys and both manifest versions, the auth keys and every prekey, ciphertext and the vault hash, but not manifest hashes, capabilities or the bundle epoch. This intentionally differs from PLAN.md; whether the missing items are needed is open.
4. **Initial units and device count.** PLAN D5 and the M0 draft send session establishment toward an account as exactly 3 init units so that the responder's server cannot count devices. The implementation sends one request envelope per responder device. This hides nothing about device count yet.
5. **Separate prekey signatures.** The signed prekey and the last-resort prekey each carry a composite signature, as PLAN §4 describes, so a claimed bundle is 12,731 to 19,376 B rather than PLAN's "about 8 KB per device".
6. **Locator length in On-the-record mode.** The identity plaintext has 5,088 B. With a signature, 4,834 + `L` bytes are needed, so a locator longer than 254 B does not fit; `encode` accepts up to 256 B and the padding step then truncates the signature. Locators SHOULD be kept at or below 254 B until this is fixed in code.
7. The responder accepts an initial message for any manifest version Alice claims, as long as the resolver returns exactly that version. A policy for how old that version may be is open.
