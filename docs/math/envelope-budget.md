# Envelope Byte Budget

Status: Draft (M0, reconciled with the M1–M3 code) · Normative

Source: PLAN.md §8, §2.1, §3.2, §4, §6, §7, Appendix A; `enclave-wire`, `enclave-rpc`, `enclave-proto`. This document derives every size in `08-envelope.md` from primitive sizes, so that a reviewer can check the layouts without trusting the tables. All figures are exact byte counts. The main equalities are compile-time assertions in `enclave-wire` (`08-envelope.md` §10).

## 1. Primitive sizes

| Item | Bytes | Source |
|---|---|---|
| X448 public key / shared secret | 56 | RFC 7748 |
| ML-KEM-1024 ek / ciphertext | 1,568 | FIPS 203 |
| ML-KEM-1024 shared secret | 32 | FIPS 203 |
| McEliece-8192128 public key | 1,357,824 | Classic McEliece round 4 |
| McEliece-8192128 ciphertext | 208 | Classic McEliece round 4 |
| Ed448 public key / signature | 57 / 114 | RFC 8032 |
| ML-DSA-87 public key / signature | 2,592 / 4,627 | FIPS 204 |
| Composite public key | 57 + 2,592 = 2,649 | `02-cryptography.md` §7 |
| Composite signature | 114 + 4,627 = 4,741 | `02-cryptography.md` §7 |
| SLH-DSA-SHAKE-256s public key / signature | 64 / 29,792 | FIPS 205 |
| EnclaveSeal overhead | 32 (`N`) + 32 (`T`) = 64 | `02-cryptography.md` §4.2 |
| Compact seal overhead | 32 (`T`) | `02-cryptography.md` §4.5 |
| Content framing | 8 (`u64` length) | `enclave_wire::CONTENT_FRAMING` |
| Body overhead | 64 + 8 = 72 | `enclave_wire::BODY_OVERHEAD` |
| Lookup tag | 16 | `05-ratchet.md` §6 |
| Request header | 72 | `08-envelope.md` §2.1 |

## 2. Wire unit: 16,384 = 2^14

```
prefix            = version 2 + suite 2                                  = 4
server KEM        = X448 eph 56 + ML-KEM ct 1,568                        = 1,624
sealed region     = N 32 + request header 72 + envelope 14,336 + T 32    = 14,472
padding           = 16,384 − 4 − 1,624 − 14,472                          = 284
check             = 4 + 1,624 + 14,472 + 284                             = 16,384
```

PLAN's split was 4 + 1,624 + 72 (seal overhead with 8 B framing) + 64 (header) + 14,336 + 284 = 16,384. The implementation has no seal framing (overhead 64) and a 72 B header (op 1, flags 1, reserved 6, mailbox 32, token 32), so the same 136 B hold the seal overhead and the header, and the padding stays at PLAN's 284 B.

Reply unit:

```
sealed region = N 32 + reply header 72 + envelope 14,336 + T 32 = 14,472
padding       = 16,384 − 14,472                                  = 1,912
```

## 3. Poll object: 2,048

```
poll   = prefix 4 + server KEM 1,624 + sealed header (32 + 72 + 32) 136 + padding 284 = 2,048
       = wire unit − envelope = 16,384 − 14,336
```

## 4. Direct stored envelope: 14,336

### 4.1 Device slots

```
slot header plaintext = DH pk 56 + pn 4 + n 4 + e_out 4 + e_in 4 + flags 1
                      + wrapped body key 32 + zero 7                        = 112
slot                  = lookup tag 16 + header 112 + compact-seal tag 32    = 160
table                 = 5 slots × 160                                        = 800
```

A full EnclaveSeal (64) plus a 16 B tag would leave 160 − 80 = 80 B, less than the 105 B of header fields. This is why slots use the compact seal, whose nonce is derived from the lookup tag and the body hash (`02-cryptography.md` §4.5).

### 4.2 PQ slot

```
plaintext (kind 0) = kind 1 + ek id 4 + ek 1,568 + ct-for id 4 + ct 1,568 + ct epoch 4 = 3,149
plaintext (kind 1) = kind 1 + ek id 4 + ct-for id 4 + ct 1,568 + ct epoch 4 + McE ct 208 = 1,789
padded plaintext   = 3,264 − 32                                                      = 3,232
sealed             = 3,232 + compact tag 32                                          = 3,264
```

Both kinds fit with room to spare (83 B for kind 0). PLAN's "about 3.26 KB" is exactly 3,264.

### 4.3 Capsule

```
capsule = 1,024 random bytes (sealed previews not implemented)
```

### 4.4 Content

```
fixed      = header 16 + slots 800 + PQ slot 3,264 + capsule 1,024 = 5,104   (body offset)
body       = 14,336 − 5,104                                          = 9,232
content    = body − seal 64 − length 8                               = 9,160
on record  = 9,160 − composite signature 4,741                       = 4,419  (not implemented)
```

Both match PLAN §8 (9,160 and "≈4,419"): PLAN's 72 B body overhead is now 64 B of seal plus the 8 B content length.

## 5. Request envelope: 14,336

```
sealed identity   = 5,120                         (compact seal: 5,088 plaintext + 32 tag)
initial block     = suite 1 + mode 1 + psk 1 + reserved 1 + spk id 4
                  + PQ prekey kind 1 + PQ prekey id 8
                  + EK 56 + ct_pq 1,568 + ct_mce 208 + ct_auth 1,568
                  + sealed identity 5,120                                  = 8,537
slot              = tag 16 + sealed header 144                             = 160
body offset       = header 16 + initial block 8,537 + slot 160             = 8,713
body              = 14,336 − 8,713                                         = 5,623
content           = 5,623 − 64 − 8                                         = 5,551
```

Identity plaintext (`04-eqxdh.md` §4): root 64 + manifest version 8 + device ID 16 + locator (4 + `L`) + signature flag 1 + signature (0 or 4,741), zero-padded to 5,088. Off the record this needs 93 + `L` ≤ 5,088; On the record 4,834 + `L` ≤ 5,088, so `L` ≤ 254 (see `04-eqxdh.md` Open questions).

## 6. Group stored envelope (reserved constant layout): 14,336

```
fixed      = sender header 88 + state hash 32 + frontier 100 × 8 = 800
           + MAC vector 99 × 16 = 1,584 + capsule 1,024           = 3,528   (body offset)
body       = 14,336 − 3,528                                       = 10,808
content    = 10,808 − 64 − 8                                      = 10,736
on record  = 10,736 − 4,741                                       = 5,995
```

PLAN's table (88 + 32 + 800 + 1,584 + 1,024 + 72 + "≈10,736") sums to exactly 14,336, and PLAN's "≈6,000" is 5,995.

## 7. Rekey unit (reserved)

```
payload = state hash 32 + common blob (64 + 128) 192 + bucket info 8
        + entries 174 × 80 + zero 32                                     = 14,184
unit    = routing header 88 + seal overhead 64 + payload 14,184           = 14,336
capacity = 3 units × 174 = 522 ≥ 100 members × 5 devices = 500
```

## 8. Blob chunks, buckets, directory objects

### 8.1 Blob chunks and buckets

```
chunk data = 14,336 − header 16 − body overhead 72 = 14,248     (BLOB_CHUNK_CAPACITY)
n_B        = ⌈B / 14,248⌉
capacity   = 14,248 × n_B                                        (each chunk has its own length field)
```

| Bucket | `B` | `B` / 14,248 | `n_B` | Capacity | Wire bytes (16,384 × `n_B`) | Overhead vs `B` |
|---|---|---|---|---|---|---|
| 64 KiB | 65,536 | 4.60 | 5 | 71,240 | 81,920 | 25.0% |
| 256 KiB | 262,144 | 18.40 | 19 | 270,712 | 311,296 | 18.8% |
| 1 MiB | 1,048,576 | 73.59 | 74 | 1,054,352 | 1,212,416 | 15.6% |
| 4 MiB | 4,194,304 | 294.38 | 295 | 4,203,160 | 4,833,280 | 15.2% |
| 16 MiB | 16,777,216 | 1,177.51 | 1,178 | 16,784,144 | 19,300,352 | 15.0% |
| 64 MiB | 67,108,864 | 4,710.06 | 4,711 | 67,122,328 | 77,185,024 | 15.0% |
| 128 MiB | 134,217,728 | 9,420.11 | 9,421 | 134,230,408 | 154,353,664 | 15.0% |

"Overhead vs `B`" is wire bytes over nominal bucket size, before Sphinx and Tor overhead.

### 8.2 Directory objects

Directory objects travel in API frames as chunks of at most 14,000 B (`CHUNK_DATA`); a `DirRequest` needs 78 + 14,000 = 14,078 ≤ 14,332 B.

```
manifest body     = format 2 + version 8 + prev hash 64 + issued 8 + expires 8 + root 64
                  + identity 56 + vault hash 64 + locator (4 + L) + bundle epoch 8
                  + device count 1 + n × device entry                     = 287 + L + 4,250·n
device entry      = id 16 + role 1 + added 8 + capabilities 8 + composite pk 2,649
                  + auth ek 1,568                                          = 4,250
signed manifest   = body length 4 + body + SLH-DSA signature 29,792
                  n = 1, L = 32: 4 + 4,569 + 29,792 = 34,365  → ⌈34,365 / 14,000⌉ = 3 chunks
                  n = 5, L = 32: 4 + 21,569 + 29,792 = 51,365 → 4 chunks
signed prekey     = device 16 + id 4 + X448 56 + ML-KEM 1,568 + expiry 8 + signature 4,741 = 6,393
batch header      = device 16 + batch id 4 + count 2 + root 32 + signature 4,741          = 4,795
one-time prekey   = index 2 + X448 56 + ML-KEM 1,568 + path 7 × 32                       = 1,850
last-resort       = device 16 + id 4 + ML-KEM 1,568 + expiry 8 + signature 4,741         = 6,337
publication       = 6,393 + 4,795 + count 2 + 100 × 1,850 + 6,337 = 202,527 → 15 chunks
claimed bundle    = 6,393 + flag 1 + (4,795 + 1,850) + 6,337 = 19,376 → 2 chunks
                    (without a one-time prekey: 6,393 + 1 + 6,337 = 12,731 → 1 chunk)
vault object (sim)= 1,357,824 + 23 segments × (seal 64 + length 4) = 1,359,388 → 98 chunks
```

PLAN's "about 52 KB" manifest is 51,365 B for five devices with a 32 B locator. PLAN's "about 8 KB per device" bundle is 12,731 to 19,376 B as implemented, because the signed prekey and the last-resort prekey each carry their own composite signature (`04-eqxdh.md` Open questions). Signing 100 OPKs under one Merkle root instead of 100 composite signatures saves 99 × 4,741 = 469,359 B per batch (PLAN: "about 470 KB"); each OPK carries a 224 B path (7 × 32, for a 128-leaf tree).

## 9. Contact-add cost

In the reference client (`enclave-sim`), adding a contact fetches the manifest (3 or 4 chunks), one claimed bundle per device (1 or 2 chunks each, after one `Claim` request), and the vault-key object (98 chunks):

```
5 devices: manifest 4 + 5 × (claim 1 + 1 more chunk) + vault 98 = 112 request/reply exchanges
         ≈ 112 × 16,384 B ≈ 1.84 MB of reply units at the Enclave layer
```

PLAN: manifest ≈52 KB + bundles ≈8 KB per device + McEliece 1.36 MB ≈ 1.42 MB of objects; the difference is unit padding and the larger bundles.

## Open questions

1. **Resolved:** blob sealing adds no per-blob framing, so the capacities in §8.1 stand. Each chunk holds only its length and data (`files::seal_file`, `pad_content`); the file's size, chunk count, hash, name and MIME type travel in the attachment reference inside the message (`Attachment`).
