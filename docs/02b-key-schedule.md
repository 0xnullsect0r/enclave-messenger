# Key Schedule

Status: Draft (M0, reconciled with the M1–M5 code) · Normative

Source: PLAN.md §2.4, with derivations from §3 to §13. This document lists every long-lived key and every derivation in Enclave. If a key or derivation is not listed here, implementations MUST NOT create it; add it here (and to `label-registry.md`) first. Notation is in `00-overview.md` §6; primitives are in `02-cryptography.md`. Where this document and the code disagree, the code is normative.

All KMAC calls are written `KMAC256(K, X, L, S)` with `L` in bits. `frame(x) = u64(len(x)) ‖ x` (`02-cryptography.md` §2.3). "Random" means from `HedgedRng.fill` (`02-cryptography.md` §6). Sections marked **reserved** are specified but not implemented; their labels are in `label-registry.md` §3.

## 1. Key inventory

| Key | Type / size | Scope | Lifetime (PLAN) | Implemented where |
|---|---|---|---|---|
| Recovery secret `rs` | 32 B random | Account | Permanent | `enclave-proto` `recovery.rs` (24 BIP-39 words) |
| Root (SLH-DSA-SHAKE-256s) | pk 64, seeds 96 | Account | Permanent | Derived from `rs` (`enclave-crypto` `sig.rs`) |
| Vault KEM (McEliece-8192128) | pk 1,357,824, sk 14,120 | Account; shared with devices | 1 year | `identity.rs` `AccountKeys` |
| Account IK (X448) | 56 / 56 | Account; shared with devices | 1 year | `AccountKeys` |
| Device composite signing key | pk 2,649, seed 89 | Device | 1 year | `identity.rs` `DeviceKeys` |
| Device auth key (ML-KEM-1024) | ek 1,568, dk 3,168 | Device | 1 year | `DeviceKeys` |
| Signed prekey (X448 + ML-KEM-1024) | 56 + 1,568 | Device | 14 days | `bundle.rs` `PrekeyStore` |
| One-time prekeys (X448 + ML-KEM-1024) | 100 per batch | Device | Single use | `PrekeyStore` |
| Last-resort PQ prekey (ML-KEM-1024) | 1,568 | Device | 7 days | `PrekeyStore` |
| Hedge secret | 32 B | Per `HedgedRng` | Not persisted yet | `rng.rs` |
| Inbox owner secret | 32 B random | Per inbox | Life of the inbox | Client (`enclave-sim`; `enclave-core` in progress) |
| Inbox and request-inbox addresses | 32 B random | Per inbox | Static (PLAN: weekly rotation, reserved) | Client |
| Write-token key per contact `k_contact` | 32 B random | Per contact (inbound) | Until replaced | `enclave-tokens` `TokenIssuer` |
| Write tokens | 32 B | Per contact | Single use | `enclave-tokens` |
| Server request KEM (X448 + ML-KEM-1024) | 56 + 1,568 | Server | 1 day; kept until the next rotation | `enclave-rpc` `ServerSecret`, `enclave-server` |
| KT head-signing key, witness keys (composite) | 2,649 | Server, witness | 1 year | `enclave-kt` |
| KT VRF key | 32 B | Server | Life of the log | `enclave-kt` |
| Device secret (storage) | 32 B random | Profile | Until crypto-erase | `enclave-store` (keystore) |
| Local master key | 32 B | Profile | Derived at unlock | `enclave-store` |
| Shred keys and keyring wrap key | 32 B each | Per conversation per day; per keyring generation | Until shredded; one generation | `enclave-store` `shred.rs` |
| Notification key chain, group secrets, blob secrets, link secrets, call secrets, push relay keys, relay ticket keys | — | — | — | Reserved (§8–§12) |

## 2. Account keys

### 2.1 Recovery secret and root

```
rs      = HedgedRng.fill("recovery/secret", 32)
words   = BIP39_encode(rs)                                   # 24 English words with the BIP-39 checksum
seeds   = KMAC256(rs, "", 768, "enclave/v1/root/keygen")
(root_sk, root_pk) = slh_keygen_internal(SK.seed = seeds[0..32], SK.prf = seeds[32..64], PK.seed = seeds[64..96])
```

BIP-39 is used only as an encoding of `rs`; the BIP-39 PBKDF2 seed derivation is not used. `RecoverySecret::from_words` ignores case and extra whitespace and rejects a bad checksum.

Reserved: `root_hash = ID256("enclave/v1/proto/root-hash", root_pk)`. The code uses the full 64 B `root_pk` wherever a root identifier is needed (transcripts, the directory key in §10.3).

### 2.2 Backup key

```
backup_key = KMAC256(rs, "", 256, "enclave/v1/backup/key")
```

### 2.3 Vault key

```
(vault_pk, vault_sk) = McEliece8192128.KeyGen(HedgedRng as rand_core, purpose "rand_core")
vault_hash           = SHA3-512(vault_pk)                     # committed in the manifest
```

The vault public key is published as an opaque directory object under a random locator; the reference client seals it under a random key given in the contact card (`12-servers.md` §2.1).

### 2.4 Account IK

```
IK_sk = HedgedRng.fill("x448/keygen", 56); IK_pk = X448(IK_sk, 5)
```

### 2.5 Inboxes and read credentials

The account inbox rotates weekly, everything from the inbox seed `is` (`09-transport.md` §3.1):

```
is            = HedgedRng.fill("core/inbox-seed", 32)                            # in the profile, shared by the account's devices
addr_seed     = KMAC256(is, "", 256, "enclave/v1/net/inbox-addr-seed")            # what contacts get
addr(w)       = KMAC256(addr_seed, u32(w), 256, "enclave/v1/net/inbox-addr")      # w = Unix seconds / 604,800
owner(a)      = KMAC256(is, a, 256, "enclave/v1/net/inbox-owner")
read_key      = KMAC256(is, "", 256, "enclave/v1/net/inbox-read-key")
read_cred(a, d) = KMAC256(read_key, a ‖ u32(d), 256, "enclave/v1/net/read-cred")[0..24]   # d = Unix seconds / 86,400
stored at the server: credential_hash(owner(a)), credential_hash(read_cred(a, d)) for each registered day
credential_hash(x) = KMAC256(x, "", 256, "enclave/v1/rpc/credential-hash")
```

Request inboxes, group mailboxes and linking mailboxes keep a random address and owner secret with the static credential:

```
read_cred     = KMAC256(owner_secret, "read", 256, "enclave/v1/rpc/read-credential")[0..24]
```

### 2.6 Write tokens (inbound)

```
t         = HedgedRng.fill("core/write-token", 32)                          # from the device's pool (09 §3.3)
h(t, a)   = KMAC256(t, a, 256, "enclave/v1/tokens/hash")                    # what the server stores at address a
dummy     = HedgedRng.fill("tokens/dummy", 32)                              # padding in registration batches
```

The hash is bound to the address, so a token re-registered at the next week's address gives an unrelated value. PLAN §9.3's per-contact `t_i = KMAC(k_contact, i)` survives as `enclave_tokens::TokenIssuer` (`enclave/v1/tokens/write`), used only by the simulator; `enclave/v1/net/token-key` is retired (`label-registry.md` §4).

### 2.7 Request inbox and invite capabilities

The request inbox has a random address in the manifest and the static credential (§2.5). An invite link's capabilities `cap_i = KMAC256(secret, u32(i), 256, "enclave/v1/invite/cap")` are registered as `KMAC256(cap_i, request_inbox, 256, "enclave/v1/net/cap-hash")`, bound to the inbox (`09-transport.md` §4).

### 4.1 Security code (per side)

```
d = KMAC256(root_pk, "", 512, "enclave/v1/fp/root")            # root_pk is the KMAC key
repeat 5,200 times:
    d = SHA3-512(d ‖ root_pk)
digest = d                                                      # 64 B
digits = for j in 0..6: decimal( u40_be(digest[5j..5j+5]) mod 100000, zero-padded to 5 )   # 30 digits
```

The pair code (`hash::security_code`) is the two 30-digit strings in ascending order of their 64 B digests (byte-wise comparison), concatenated: 60 digits, shown as 12 groups of 5. Both sides compute the same code. This is PLAN §3.5's `SHAKE256^5200(root_pk)` realized as one KMAC256 step followed by 5,200 SHA3-512 iterations that re-absorb `root_pk`.

Reserved: the 10-word spoken form (PLAN §3.5); it is not implemented.

### 4.2 In-person bond PSK and Seal words

```
(s_1, Q_1), (s_2, Q_2) = the two (secret, QR payload) pairs, ordered so that Q_1 ≤ Q_2 (byte-wise)
psk_bond   = KMAC256(s_1 ‖ s_2, SHA3-512(frame(Q_1) ‖ frame(Q_2)), 256, "enclave/v1/bond/psk")
d          = KMAC256(psk_bond, "", 256, "enclave/v1/bond/seal-words")
seal_words = BIP-39 English words at indices u16_be(d[2i..2i+2]) mod 2048, i = 0, 1, 2
```

This is PLAN §3.6's `KMAC256(s_A‖s_B (ordered), "enclave/v1/bond", SHA3-512(QR_A‖QR_B))` with the key, input framing and length made explicit (`eqxdh::bond_psk`, `eqxdh::seal_words`).

### 4.3 Contact art (reserved)

`art_seed = KMAC256(root_hash, "", 256, "enclave/v1/proto/contact-art")`.

## 5. PSKs

The implemented PSK is `psk_bond` (§4.2), passed as the 32 B PSK to EnclaveCombine with `psk_flag = 1`. Reserved: the invite PSK (`enclave/v1/proto/invite-psk`) and the device-link PSK (`enclave/v1/proto/link-psk`), and distinct `psk_flag` values per PSK source.

## 6. Session establishment (EQXDH)

Full message flow: `04-eqxdh.md`.

```
s1   = EnclaveCombine(suite, [DH3, DH4 or "", ss_pq, ss_mce or ""],
                      ["EQXDH-v1/stage1", EK_A, SPK_B, OPK_B or "", ct_pq, ct_mce or "", root_pk_B, device_id_B], psk)
k_id = KMAC256(s1, "", 256, "enclave/v1/eqxdh/identity")
sealed_identity = seal_compact(k_id, EK_A, u8(suite_id) ‖ u8(mode), identity)
SK   = EnclaveCombine(suite, [DH1, DH2, DH3, DH4 or "", ss_pq, ss_mce or "", ss_auth], transcript items (04 §5.1), psk)
th   = SHA3-512-parts(transcript items)                      # signed in On-the-record mode
sig  = CompositeSign(device_sk, ctx = "enclave/v1/ctx/eqxdh-transcript", th)
replay_id = SHA3-512(EK_A ‖ ct_pq ‖ ct_auth)
```

## 7. Lockstep Ratchet

Full algorithms: `05-ratchet.md`. `kmac32(K, [x…], S) = KMAC256(K, frame(x1) ‖ …, 256, S)`.

```
RK0    = kmac32(SK, [], "enclave/v1/ratchet/init-rk")
HKA    = kmac32(SK, ["a"], "enclave/v1/ratchet/init-hk");   NHKB   = kmac32(SK, ["b"], "enclave/v1/ratchet/init-hk")
PQ_A2B = kmac32(SK, ["a2b"], "enclave/v1/ratchet/init-pq"); PQ_B2A = kmac32(SK, ["b2a"], "enclave/v1/ratchet/init-pq")

KDF_RK(RK, dh) = KMAC256(RK, frame(dh), 768, "enclave/v1/ratchet/rk")  -> RK' ‖ CK ‖ NHK
KDF_CK(CK)     = KMAC256(CK, "", 512, "enclave/v1/ratchet/ck")         -> CK' ‖ mk_DR
tag(HK, n)     = KMAC256(HK, u32(n), 128, "enclave/v1/ratchet/tag")
root'          = kmac32(root, [ss, ct, SHA3-512(ek)] (‖ [mce_ss, mce_ct] when braided), "enclave/v1/pq/step")
pq_key         = kmac32(out_root[e_out], [in_root[e_in]], "enclave/v1/pq/key")      # sender's view
mk             = kmac32(mk_DR, [pq_key], "enclave/v1/ratchet/msg")
wrapped        = body_key ⊕ kmac32(mk, [SHA3-512(sealed body)], "enclave/v1/ratchet/wrap")
pq_slot_key    = kmac32(mk_DR, [], "enclave/v1/ratchet/pq-slot")
body_key       = HedgedRng.fill("envelope/body-key", 32)                             # fresh per envelope
```

Reserved: the notification key chain `nk_d = KMAC256(nk_{d−1}, u32(d), 256, "enclave/v1/proto/notify-key")`, the conversation ID and message ID (`enclave/v1/proto/conv-id`, `enclave/v1/proto/msg-id`), and the re-root mix (`enclave/v1/proto/bond-reroot`).

## 8. Groups (reserved)

The M0 derivations are kept for M7 with their reserved labels (`label-registry.md` §3.2):

```
gmbox(d)         = KMAC256(epoch_secret, u32(d), 256, "enclave/v1/net/grp-mailbox")
k_gw             = KMAC256(epoch_secret, "", 256, "enclave/v1/net/grp-write-key")
grp_write_tok(a) = KMAC256(k_gw, a, 256, "enclave/v1/net/grp-write-token")
k_gr             = KMAC256(epoch_secret, "", 256, "enclave/v1/net/grp-read-key")
grp_read_cred(a) = KMAC256(k_gr, a, 256, "enclave/v1/net/grp-read-cred")
HKg              = KMAC256(epoch_secret, "", 256, "enclave/v1/proto/grp-header")
k_rekey_outer    = KMAC256(epoch_secret, "", 256, "enclave/v1/proto/grp-rekey-outer")
k_bucket         = KMAC256(epoch_secret, "", 256, "enclave/v1/proto/grp-bucket")
gnk(d)           = KMAC256(epoch_secret, u32(d), 256, "enclave/v1/proto/grp-notify")
(cs_{n+1}, gmk_n) = split32( KMAC256(cs_n, "", 512, "enclave/v1/proto/grp-chain") )
mac_tag_j        = KMAC256(mac_key[s→j], SHA3-512(covered bytes), 128, "enclave/v1/proto/grp-mac")
admin_tag_j      = KMAC256(mac_key[s→j], SHA3-512(update bytes), 128, "enclave/v1/proto/grp-admin-mac")
K_exp            = KMAC256(P ‖ RK, frame(group_id) ‖ u32(epoch) ‖ u8(generation), 256, "enclave/v1/proto/grp-export")
pad              = KMAC256(K_exp, "", 512, "enclave/v1/proto/grp-rekey-pad")
check            = KMAC256(K_exp, ct64, 96, "enclave/v1/proto/grp-rekey-check")
bucket(dev)      = u16(KMAC256(k_bucket, device_id, 256, "enclave/v1/proto/grp-bucket-index")[0..2]) mod 3
gbkt(d, b)       = KMAC256(k_bucket, u32(d) ‖ u8(b), 256, "enclave/v1/net/grp-rekey-mailbox")
state_hash_n     = SHAKE256("enclave/v1/proto/grp-state" ‖ state_hash_{n−1} ‖ SHA3-512(update_n), 32)
grp_msg_id       = SHAKE256("enclave/v1/proto/grp-msg-id" ‖ group_id ‖ u32(epoch) ‖ u8(member) ‖ u8(device) ‖ u8(gen) ‖ u32(counter), 32)[0..8]
grp_invite_cap   = KMAC256(grp_invite_secret, "", 256, "enclave/v1/proto/grp-invite-cap")
tally_hash       = SHA3-512("enclave/v1/proto/poll-tally-hash" ‖ poll_id ‖ canonical_tally)
```

`P ‖ RK` in `K_exp` assumed the M0 draft's PQ epoch secrets and root-key snapshots, which the implemented ratchet does not keep (`05-ratchet.md`). The exporter must be re-specified against the implemented ratchet before M7.

## 9. Blobs (reserved)

```
blob_secret = HedgedRng.fill("blob", 32)
k_chunk     = KMAC256(blob_secret, "", 256, "enclave/v1/wire/chunk-key")
chunk_id_i  = KMAC256(blob_secret, u32(i), 256, "enclave/v1/wire/chunk-id")
backup_blob_secret = KMAC256(backup_key, u64(archive_seq), 256, "enclave/v1/store/backup-blob-id")
```

## 10. Transport and server

### 10.1 Sealed requests and replies

```
ss      = EnclaveCombine(TwoKem, [X448(eph_sk, S_x448), ss_mlkem],
                         [eph_pk, ct, S_x448, S_mlkem_ek, u32(key_id)], psk = none)
k_req   = KMAC256(ss, "", 256, "enclave/v1/rpc/request")
k_reply = KMAC256(ss, "", 256, "enclave/v1/rpc/reply")
```

Also in this layer (all implemented, `label-registry.md` §2): `server_id = ID256("enclave/v1/net/server-id", server_composite_pk)`, `replay_id` (`enclave/v1/net/replay-id`), self-loop probe ids (`enclave/v1/net/loop-probe`, `09-transport.md` §6.3), push-token sealing (`enclave/v1/net/push-transcript`, `enclave/v1/net/push-seal`).

### 10.2 Proof of work

```
challenge = "ENCLAVE-POW1" ‖ u32(len(ctx)) ‖ ctx ‖ nonce (16)
accept    = u32_be(SHAKE256("enclave/v1/tokens/pow" ‖ challenge ‖ solution, 4)) · max(effort, 1) ≤ 2^32 − 1
```

### 10.3 Directory keys

```
manifest_key(root_pk) = SHAKE256("enclave/v1/dir/manifest" ‖ root_pk, 32)
device_key(device_id) = device_id ‖ 0^16
```

## 11. Device linking (reserved)

```
link_secret = HedgedRng.fill("link-secret", 16)
ss_link     = EnclaveCombine(TwoKem, [X448(…), ss_mlkem], [… , "enclave/v1/proto/link-transcript", SHA3-512(link_qr), root_pk], psk = link_psk)
(k_p2n, k_n2p) = split32( KMAC256(ss_link, "", 512, "enclave/v1/proto/link-keys") )
phrase_words   = first three 11-bit groups of KMAC256(ss_link, "", 256, "enclave/v1/proto/link-phrase")
link_cap       = KMAC256(link_secret, "", 256, "enclave/v1/proto/link-cap")
```

## 12. Calls (reserved)

```
ss_call     = EnclaveCombine(TwoKem, [X448(…)], [ss_mlkem], [… , "enclave/v1/calls/transcript", call_id, conv_id])
call_secret = KMAC256(ss_call, "", 512, "enclave/v1/calls/secret")
base_{p,0}  = KMAC256(call_secret, frame(participant_id) ‖ u32(join_gen), 256, "enclave/v1/calls/sframe-base")
base_{p,i+1} = KMAC256(base_{p,i}, u32(i + 1), 256, "enclave/v1/calls/sframe-ratchet")
(sf_key, sf_salt) = split32( KMAC256(base_{p,i}, u64(KID), 512, "enclave/v1/calls/sframe-key") )
check_words = first two 11-bit groups of KMAC256(call_secret, "", 256, "enclave/v1/calls/check-words")
direct_psk  = KMAC256(call_secret, "", 256, "enclave/v1/calls/direct-psk")
ticket_secret = KMAC256(ss_ticket, "", 256, "enclave/v1/calls/ticket-secret")
k_ticket_seal = KMAC256(ss_ticket, "", 256, "enclave/v1/calls/ticket-seal")
wg_psk_i    = KMAC256(ticket_secret, u32(i), 256, "enclave/v1/calls/wg-psk")
call_link_cap = KMAC256(call_link_secret, "", 256, "enclave/v1/calls/link-cap")
```

## 13. Local storage

Full description: `14-storage.md`.

```
device_secret = HedgedRng.fill("store/device-secret", 32)                 # in the keystore
salt          = HedgedRng.fill("store/salt", 32)
pw            = Argon2id(passphrase, salt, params)                         # only with a passphrase
master        = KMAC256(device_secret, frame(pw or ""), 256, "enclave/v1/store/master")
index         = KMAC256(master, "", 256, "enclave/v1/store/index")
ns_tag(ns)    = KMAC256(index, ns, 256, "enclave/v1/store/namespace")[0..8]
blind(ns, k)  = ns_tag(ns) ‖ KMAC256(index, frame(ns) ‖ frame(k), 256, "enclave/v1/store/blind")    # 40 B
record_key    = KMAC256(master, frame(salt) ‖ frame(blind(ns, k)), 256, "enclave/v1/store/record")
shred_key     = HedgedRng.fill("store/shred-key", 32)                      # per (conversation, day)
wrap_key_g    = HedgedRng.fill("store/shred-wrap", 32)                     # per keyring generation, in the keystore
```

Reserved: search keys and tokens (`enclave/v1/store/search-key`, `enclave/v1/store/search-token`) and the root wrap (`enclave/v1/store/root-wrap`).

## 14. Key transparency

```
H(x)          = SHAKE256("enclave/v1/kt/akd" ‖ x, 32)                     # every akd hash (12-servers.md §3.1)
head          = server (16) ‖ u64(epoch) ‖ root (32) ‖ u64(time)
head_sig      = CompositeSign(server_sk, ctx = "enclave/v1/kt/head", head)
cosig         = CompositeSign(witness_sk, ctx = "enclave/v1/kt/cosign", head ‖ u64(witness_time))
gossip_digest = SHAKE256("enclave/v1/kt/gossip" ‖ head, 32)
```

Reserved: `kt_leaf_value = SHA3-512("enclave/v1/kt/leaf" ‖ …)`; today the leaf value is chosen by the publisher.

## Open questions

1. The security code uses one KMAC256 step and 5,200 SHA3-512 iterations over `d ‖ root_pk` rather than 5,200 SHAKE256 calls. The work factor per guess is similar; whether to align the wording of PLAN §3.5 or the code is open.
2. The notification key chain gives per-day forward secrecy only. Recorded for audit; not implemented.
3. The group exporter (§8) must be re-specified against the implemented ratchet, which keeps no root-key snapshots.
