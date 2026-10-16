# Wire Units and Envelopes

Status: Draft (M0, reconciled with the M1–M3 code) · Normative

Source: PLAN.md §8 (D1). Crates: `enclave-wire` (sizes, unit and poll framing, content padding), `enclave-rpc` (sealing, API payloads), `enclave-proto` `envelope.rs` (direct and request envelopes). Arithmetic: `math/envelope-budget.md`. Cryptography: `02-cryptography.md` §4 (EnclaveSeal overhead is 64 B: `N` 32 ‖ … ‖ `T` 32).

Every table below gives offsets in bytes from the start of the object. Every table sums exactly, and the sum is shown under it. `enclave-wire` asserts the main sizes at compile time (§10). Where this document and the code disagree, the code is normative.

## 1. Conventions

- All objects that cross the network or sit on a server have fixed sizes.
- "Random" regions are filled from the hedged RNG (`02-cryptography.md` §6). "Zero" regions are zero on send; where the table says "checked", the receiver rejects non-zero bytes.
- The plaintext length of content is carried only inside a seal (an 8 B `u64` in content framing, §5.5, or a 4 B `u32` in API framing, §2.3).

| Object | Size | Where |
|---|---|---|
| Wire unit (request) | 16,384 | Every request with a payload |
| Reply unit | 16,384 | Every reply, including replies to polls and to undecryptable requests |
| Poll object | 2,048 | Header-only requests (`Poll`, `Ack` in the reference client) |
| Envelope region | 14,336 | Inside every wire unit and reply unit: a stored envelope, a blob chunk, or an API payload |

## 2. Wire unit (request): 16,384 B

| Offset | Length | Field | Notes |
|---|---|---|---|
| 0 | 2 | version | `u16` = 1 |
| 2 | 2 | suite | `u16` = 1 (`SUITE_V1`) |
| 4 | 56 | X448 ephemeral public key | server seal |
| 60 | 1,568 | ML-KEM-1024 ciphertext | server seal, to the server's daily key |
| 1,628 | 32 | seal nonce `N` | |
| 1,660 | 72 | request header (encrypted) | §2.1 |
| 1,732 | 14,336 | envelope region (encrypted) | §5 to §9, or an API payload (§2.3) |
| 16,068 | 32 | seal tag `T` | |
| 16,100 | 284 | random padding | outside the seal, bound into its AD |

Sum: 2 + 2 + 56 + 1,568 + 32 + 72 + 14,336 + 32 + 284 = **16,384**.

Grouped: prefix 4 + server KEM 1,624 + sealed region 14,472 (`N` 32 + header 72 + envelope 14,336 + `T` 32) + padding 284 = 16,384.

The sealed region is `seal(k_req, u32(key_id) ‖ padding, header ‖ envelope)` with `k_req` from `09-transport.md` §2, where `padding` is the unit's last 284 B. The daily key ID is not on the wire; it is part of the associated data, so the server tries each key it holds (newest first). The seal plaintext is 72 + 14,336 = 14,408 B.

Compared with PLAN §8 (4 + 1,624 + 72 seal overhead + 64 header + 14,336 + 284), the implementation has a 64 B seal overhead (no 8 B framing header) and a 72 B request header. The total and the 284 B padding are PLAN's.

### 2.1 Request header: 72 B

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | `op` (§2.2) |
| 1 | 1 | `flags` (op-specific) |
| 2 | 6 | reserved (zero, checked) |
| 8 | 32 | mailbox, object ID, or random |
| 40 | 32 | token, credential, proof, or random (op-specific) |

Sum: 1 + 1 + 6 + 32 + 32 = **72**.

`RequestHeader::decode` rejects a wrong length, non-zero reserved bytes, and an unknown `op`. The same 72 B layout is used for the reply header (§3.1).

### 2.2 Operations

| Op | Name | Object | Mailbox field | Token field | Envelope region | Reply |
|---|---|---|---|---|---|---|
| 0 | `Cover` | unit | random | random | random | `Ok`, empty; the server drops the request after authenticating the seal |
| 1 | `Write` | unit | account-inbox address | single-use write token | stored envelope (§5), stored as is | status only |
| 2 | `WriteRequest` | unit | request-inbox address | proof of work (`nonce 16 ‖ solution 16`) | request envelope (§6), stored as is | status only |
| 3 | `Poll` | poll | inbox address | read credential (24) ‖ `u64` cursor | — | one stored envelope, or empty |
| 4 | `Ack` | poll | inbox address | read credential (24) ‖ `u64` watermark | — | status only |
| 5 | `BlobPut` | unit | chunk ID | allocation secret (`BlobAlloc`) | blob chunk (§9), stored as is | status only |
| 6 | `BlobGet` | unit or poll | chunk ID | unused | — | the chunk |
| 7 | `Directory` | unit | unused (zero) | unused (zero) | API payload: `DirRequest` (§9.3) | API payload: `DirReply` |
| 8 | `RegisterTokens` | unit | inbox address | owner secret | API payload: concatenated 32 B token hashes (ignored on create) | status only |
| 9 | `KeyTransparency` | — | — | — | — | reserved: KT queries and writes ride on `Directory` (Q1), and the server answers op 9 with `NotFound` |
| 10 | `PushRegister` | unit | inbox address | owner secret | API payload: sealed push token (empty removes it) | status only |
| 11 | `Report` | unit | the reported account's request inbox | proof of work | API payload: `ReportBody` (`13-operators.md` §2) | status only |
| 12 | `Status` | poll | status id of an earlier `DEFER` request | random | — | that request's reply (its op, status and payload), or `Status` with `NotFound` while it hasn't arrived |
| 13 | `BlobAlloc` | unit | issue: an inbox here; else random | issue: its owner secret; else random | API payload: `1 ‖ u8 n ‖ n × TokenRequest (52)` issue, `2 ‖ Token (146)` redeem, `3` key | API payload: `1 ‖ u32 epoch ‖ key (49) ‖ u8 n ‖ n × TokenResponse (145)`, or `2 ‖ allocation (32) ‖ u32 uploads` (`09-transport.md` §9) |

`flags` for `RegisterTokens`: bit 0 (`0x01`) `CREATE` creates the inbox; bit 1 (`0x02`) `REQUEST_INBOX` makes the new inbox a request inbox. Other ops ignore the low bits.

`DEFER` (`0x80`, any unit op): the sender went one way and will fetch the answer with a `Status` poll. The server keeps the reply for 10 minutes under the request's **status id**, `KMAC256(exchange secret, "", "enclave/v1/net/status-id")` (only the sender and server know it), and hands it over once. It keeps at most 65,536 answers and 64 MiB of them; past that, new answers are not kept (`docs/09-transport.md` §6.1).

The server accepts any op in either object size; a poll object has an empty envelope region. The reference client sends `Poll`, `Ack`, `BlobGet` and `Status` as poll objects and every other op as a unit, with `DEFER` on each unit that needs an answer. Server semantics are in `12-servers.md` §1.

### 2.3 API framing

Ops whose envelope region carries a control payload use:

```
frame(payload) = u32(len(payload)) ‖ payload ‖ random padding         # exactly 14,336 B
```

`MAX_PAYLOAD` = 14,336 − 4 = 14,332 B. `unframe` rejects a region that is not 14,336 B or whose length field points past the end. (This `frame` is `enclave_rpc::api::frame`; it is unrelated to the KMAC framing of `02-cryptography.md` §2.3.)

## 3. Reply unit: 16,384 B

| Offset | Length | Field |
|---|---|---|
| 0 | 32 | seal nonce `N` |
| 32 | 72 | reply header (encrypted, §3.1) |
| 104 | 14,336 | reply envelope region (encrypted) |
| 14,440 | 32 | seal tag `T` |
| 14,472 | 1,912 | random padding |

Sum: 32 + 72 + 14,336 + 32 + 1,912 = **16,384**.

The sealed region is `seal(k_reply, "reply", header ‖ envelope)` (AD is the 5 ASCII bytes `reply`), written at offset 0. A reply unit has no cleartext version, suite or KEM fields, so it looks uniformly random. A request the server cannot open (wrong size, unknown version or suite, no key opens it, bad header) gets 16,384 random bytes instead; the client's `open_reply` fails and it treats the request as failed.

### 3.1 Reply header: 72 B

Same layout as §2.1:

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | `op` of the request, echoed |
| 1 | 1 | `flags`: status in bits 0–3; `FOUND` (`0x10`) a poll returned an envelope; `MORE` (`0x20`) more envelopes follow it |
| 2 | 6 | reserved (zero) |
| 8 | 32 | mailbox of the request, echoed |
| 40 | 32 | op-specific: for a `Poll` that found an envelope, `0^24 ‖ u64(sequence number)`; otherwise zero |

Sum: 1 + 1 + 6 + 32 + 32 = **72**.

Status codes (`enclave_rpc::api::Status`):

| Value | Status | Meaning |
|---|---|---|
| 0 | `Ok` | Success (including "nothing to return") |
| 1 | `Denied` | Bad or spent token, bad credential, inbox exists, wrong inbox type |
| 2 | `NotFound` | No such inbox, object, chunk, or claim |
| 3 | `Quota` | Inbox or token quota exceeded |
| 4 | `Malformed` | Malformed payload (also used for unknown status values when parsing) |
| 5 | `Pow` | Proof of work missing or too weak |
| 6 | `Invalid` | Stored object failed validation (bad signature, rollback, wrong key) |

Reply envelope region: for a `Poll` that found an envelope and for `BlobGet`, the stored bytes exactly as written; for every other reply, an API frame (§2.3) holding a `DirReply` or an empty payload.

## 4. Poll object: 2,048 B

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version (`u16` = 1) |
| 2 | 2 | suite (`u16` = 1) |
| 4 | 56 | X448 ephemeral public key |
| 60 | 1,568 | ML-KEM-1024 ciphertext |
| 1,628 | 32 | seal nonce `N` |
| 1,660 | 72 | request header (encrypted) |
| 1,732 | 32 | seal tag `T` |
| 1,764 | 284 | random padding |

Sum: 2 + 2 + 56 + 1,568 + 32 + 72 + 32 + 284 = **2,048**.

The sealed region is 136 B: `seal(k_req, u32(key_id) ‖ padding, header)`, with the poll's last 284 B as `padding`. The poll object is exactly the wire unit without its 14,336 B envelope region (16,384 − 14,336 = 2,048), with the same 1,628 B prefix and 284 B padding. It carries **exactly one mailbox** (D7). The reply to a poll is a full reply unit (§3). Whether a poll object plus its Nym reply SURBs fits in one or two Sphinx packets is measured in M4 (`math/cover-traffic.md` §2).

## 5. Direct stored envelope: 14,336 B

A direct envelope carries one message to up to five devices of one account (`06-multidevice.md`). Built by `envelope::seal_direct`, opened by `envelope::open_direct`.

### 5.1 Layout

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | version = 1 |
| 1 | 1 | kind = 1 (`Direct`) |
| 2 | 14 | zero |
| 16 | 800 | device-slot table: 5 × 160 (§5.2), shuffled |
| 816 | 3,264 | PQ slot (§5.3) |
| 4,080 | 1,024 | notification capsule (§5.4): random |
| 5,104 | 32 | body `N` |
| 5,136 | 8 | content length `u64` (encrypted) |
| 5,144 | 9,160 | content and random padding (encrypted) |
| 14,304 | 32 | body `T` |

Sum: 16 + 800 + 3,264 + 1,024 + 32 + 8 + 9,160 + 32 = **14,336**.

Grouped as in PLAN §8: header 16, device slots 800, PQ slot 3,264, capsule 1,024, body overhead 72 (seal 64 + length 8), content 9,160. The offsets are `enclave_wire::direct::{SLOTS = 16, PQ = 816, CAPSULE = 4,080, BODY = 5,104}` and `CONTENT_CAPACITY = 9,160`.

The first 16 B (`hdr16`) are the only cleartext besides random-looking slots. They are the associated data of every seal in the envelope. Envelope kinds (`enclave_wire::EnvelopeKind`): 1 `Direct`, 2 `Group`, 3 `Blob`, 4 `Cover`, 5 `Request`. Only `Direct` and `Request` envelopes are built by the code today. `open_direct` checks the length, the version and the kind; the 14 zero bytes are not checked but are bound by every seal's AD.

### 5.2 Device slot: 160 B

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | lookup tag (`05-ratchet.md` §6) |
| 16 | 112 | compact-sealed slot header (ciphertext) |
| 128 | 32 | compact-seal tag |

Sum: 16 + 112 + 32 = **160**.

The slot header plaintext (112 B) is in `05-ratchet.md` §6.1. It is sealed with `seal_compact(HKs, tag ‖ SHA3-512(sealed body), hdr16, header)`. Unused slots are 160 random bytes. The five slots are shuffled (Fisher-Yates with hedged randomness) so that position carries no information.

### 5.3 PQ slot: 3,264 B

| Offset (in slot) | Length | Field |
|---|---|---|
| 0 | 3,232 | compact-sealed PQ plaintext (ciphertext) |
| 3,232 | 32 | compact-seal tag |

Sum: 3,232 + 32 = **3,264**. The plaintext (3,232 B, zero-padded) is in `05-ratchet.md` §8.1. Key: `KMAC256(mk_DR, "", 256, "enclave/v1/ratchet/pq-slot")` of the carrying session; nonce material and AD as for that session's device slot. When no session carries the PQ slot, it is 3,264 random bytes.

### 5.4 Notification capsule: 1,024 B

Random bytes unless the recipient turned previews on (`10-push.md` §4). Then the sender seals its name and a preview under the day's notification key (the recipient's chain key `nk_d` for that contact, or the group's day key):

```
capsule = Seal(key_d, "enclave/v1/wire/ad-capsule" ‖ u32(day), u8 name_len ‖ name (≤ 64) ‖ u16 preview_len ‖ preview (≤ 600) ‖ zeros to 960)   # 960 + 64 = 1,024
```

A filled capsule and a random one look the same to the server and to Apple. The recipient's devices, and the iOS notification extension (`enclave-nse`), open it with their key table (`enclave-proto/src/notify.rs` `seal_capsule`, `open_capsule`; tests `capsules`, `previews_in_capsules`).

### 5.5 Body and content framing

```
body_key = HedgedRng.fill("envelope/body-key", 32)            # fresh per envelope
framed   = u64(len(content)) ‖ content ‖ random padding      # exactly 8 + 9,160 = 9,168 B
body     = seal(body_key, hdr16, framed)                      # 9,168 + 64 = 9,232 B
```

`pad_content` rejects content over the capacity; `unpad_content` rejects a length field larger than the region. The body key reaches each recipient device wrapped in its device slot (`05-ratchet.md` §5).

Content is opaque bytes at this layer. Receipts and key-transparency gossip ride in the content region's free space (`outbox::wrap_receipts`, `gossip::wrap`). On the record a content carries its sender's 4,741 B signature (`05-ratchet.md` §9), leaving 4,419 B before it goes in continuation units.

**Content encoding, as implemented** (`enclave-core/src/content_pb.rs`, `content.rs`): content is a Protobuf message (proto3, through `prost`'s derive, no generated code) with one `oneof` whose field numbers are the content kinds (1 `Hello` … 34 `Closed`). Unknown fields are skipped, so a later version can add fields to a message and older clients read the rest; content of a kind a client doesn't know fails to decode and is dropped. Limits are checked on both sides: the encoding is at most 65,536 + 1,024 B before it is parsed (Protobuf nesting is at most two levels, a kind inside the `oneof`, so there is no depth to bound beyond that), and every field's length and count is checked against the same limits as before (`Content::check`: texts 4,096 B, or 60,000 B for a long text; at most 32 tokens; signatures 4,741 B; …). The earlier hand-made encoding is kept only as the yardstick for those limits. A Protobuf content never starts with `0xFE` or `0xFD` (they would be field 15 with wire types 6 and 5), the markers of gossip and receipts. Tests `forward_compatible` and `roundtrip_and_limits` (`content.rs`).

### 5.6 Continuation units

**As implemented** (`enclave-core/src/client/parts.rs`): content whose encoding doesn't fit one direct envelope, with 360 B left for receipts and gossip, travels as up to 8 `Part` contents (content kind 31): `id (16) ‖ u8 index ‖ u8 total ‖ bytes(slice)`, each slice at most 8,192 B of the encoded content, each part an ordinary envelope with its own write token, so the largest content is 64 KiB. The receiver keeps parts in its sealed store until all have arrived, then handles the whole as if it had come in one envelope; parts of content that never completes are dropped after 7 days. Self-copies split the same way. A 1:1 text may be up to 60,000 B (`MAX_LONG_TEXT`); group texts stay within one unit (4,096 B). In Maximum privacy every part waits for all three KEMs, like the content it carries. Test `long_text_in_parts`.

## 6. Request envelope: 14,336 B

A request envelope carries an EQXDH initial message plus the first message to one device (`04-eqxdh.md`). Built by `envelope::seal_request`, parsed by `envelope::request_initial` and opened by `envelope::open_request`.

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | version = 1 |
| 1 | 1 | kind = 5 (`Request`) |
| 2 | 14 | zero |
| 16 | 8,537 | initial-message block (`INITIAL_BLOCK_LEN`, §6.1) |
| 8,553 | 16 | lookup tag |
| 8,569 | 144 | compact-sealed slot header (112 + 32) |
| 8,713 | 32 | body `N` |
| 8,745 | 8 | content length `u64` (encrypted) |
| 8,753 | 5,551 | content and random padding (encrypted) |
| 14,304 | 32 | body `T` |

Sum: 16 + 8,537 + 16 + 144 + 32 + 8 + 5,551 + 32 = **14,336**. Content capacity `REQUEST_CAPACITY` = 5,551 B.

The AD of the slot header and of the body is `hdr16 ‖ initial block` (8,553 B), so the initial block cannot be swapped. A request envelope has no PQ slot and no capsule; its slot header never sets the PQ-slot flag.

### 6.1 Initial-message block: 8,537 B

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | EnclaveCombine suite ID: 2 or 3 |
| 1 | 1 | mode: 0 Off the record, 1 On the record |
| 2 | 1 | PSK flag: 0 or 1 |
| 3 | 1 | reserved (written as zero; not checked) |
| 4 | 4 | `spk_id` (`u32`) |
| 8 | 1 | PQ prekey kind: 1 one-time, 2 signed prekey, 3 last-resort |
| 9 | 8 | PQ prekey ID (`u64`): one-time `(batch_id << 16) ‖ index`; signed 0; last-resort `u32` ID |
| 17 | 56 | initiator ephemeral X448 key `EK_A` |
| 73 | 1,568 | `ct_pq` (ML-KEM-1024 to the chosen PQ prekey) |
| 1,641 | 208 | `ct_mce` (McEliece to the vault key; zero in the 2-KEM suite, not checked) |
| 1,849 | 1,568 | `ct_auth` (ML-KEM-1024 to the responder's device auth key) |
| 3,417 | 5,120 | sealed identity (`SEALED_IDENTITY_LEN`; compact seal, `04-eqxdh.md` §4) |

Sum: 1 + 1 + 1 + 1 + 4 + 1 + 8 + 56 + 1,568 + 208 + 1,568 + 5,120 = **8,537** (`INITIAL_BLOCK_LEN = 4 + 4 + 9 + 56 + 1,568 + 208 + 1,568 + 5,120`).

## 7. Group stored envelope: 14,336 B

Implemented in `enclave-proto::group` (M7). The sender header (bytes 16–88), state hash and frontier are encrypted under the epoch header key and authenticated by the MAC vector (`07-groups.md`, implementation note 3). Byte 2 is the subkind: 2 a message, 3 a rekey unit (§8). Each MAC-vector tag covers `H512("enclave/v1/wire/ad-grp-header" ‖ bytes 0–920 ‖ bytes 2,504–14,336)` and the body is sealed with AD `"enclave/v1/wire/ad-grp-body" ‖ bytes 0–920`. Subkinds 0 and 1 are the first versions of both, without the label prefixes (and a rekey unit without its outer seal); clients still read them, so units already stored when a client updates open. Layout from `enclave_wire::group`:

| Offset | Length | Field |
|---|---|---|
| 0 | 88 | sender header (the 16 B envelope header is folded into it) |
| 88 | 32 | state hash |
| 120 | 800 | causal frontier: 100 × 8 |
| 920 | 1,584 | MAC vector: 99 × 16 |
| 2,504 | 1,024 | capsule |
| 3,528 | 32 | body `N` |
| 3,560 | 8 | content length `u64` (encrypted) |
| 3,568 | 10,736 | content and random padding (encrypted) |
| 14,304 | 32 | body `T` |

Sum: 88 + 32 + 800 + 1,584 + 1,024 + 32 + 8 + 10,736 + 32 = **14,336**. Body offset 3,528 and content capacity 10,736 are compile-time assertions. In On-the-record groups the 4,741 B signature leaves 5,995 B (`07-groups.md` §3).

This is PLAN §8's field order. The contents of the 88 B sender header and the protection of the state hash and frontier (which reveal group structure if left in the clear) are decided when groups are implemented (`07-groups.md`; `00-overview.md` §9, I-14).

## 8. Rekey unit: 14,336 B

**As implemented** (`enclave-proto::group`, `Group::rotate`, `apply_rekey`; `07-groups.md` §5.4):

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | clear: version 1, kind `Group`, subkind 3, bucket, announcing epoch `u32`, 0^8 |
| 16 | 32 | nonce |
| 48 | 40 | encrypted under the epoch's header key: member, device, generation, flags, target epoch `u32`, 0^32 |
| 88 | 32 | outer seal `N` |
| 120 | 14,184 | sealed payload: common blob 192 (128 + 64) ‖ 174 entries × 80 (`u32 e ‖ check (12) ‖ ct (64)`) ‖ 72 random |
| 14,304 | 32 | outer seal `T` |

Sum: 88 + 32 + 14,184 + 32 = **14,336**. The outer seal key is `KMAC256(epoch secret, "", "enclave/v1/proto/grp-rekey-outer")` of the announcing epoch and its AD is `"enclave/v1/wire/ad-rekey" ‖ bytes 0–88`; the common blob's AD is `"enclave/v1/wire/ad-rekey-common" ‖ bytes 0–88` with the bucket byte zeroed (the same blob is in all three units). Unused entry positions are random, and entries are shuffled. A rotation is always three units, one per bucket. Test `old_formats_still_open` (`group.rs`): a unit the server changed fails the outer seal, and subkind-1 units (no outer seal) still apply.

## 9. Blobs and directory objects

### 9.1 Blob chunk: 14,336 B

`enclave_wire::BLOB_CHUNK_CAPACITY` = 14,336 − 16 − 72 = 14,248 B of data per chunk. The chunk layout this reserves:

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | header (version 1, kind 3 `Blob`, 14 zero) |
| 16 | 32 | `N` |
| 48 | 8 | data length `u64` (encrypted) |
| 56 | 14,248 | chunk data and padding (encrypted) |
| 14,304 | 32 | `T` |

Sum: 16 + 32 + 8 + 14,248 + 32 = **14,336**.

The server stores a `BlobPut` envelope region as is under its 32 B chunk ID and returns it on `BlobGet`. The client seals it (`enclave-core/src/files.rs`, `02b-key-schedule.md` §9): a random blob secret per file gives the chunk key and each chunk's ID, the body is sealed under that key with AD `"enclave/v1/wire/ad-chunk" ‖ header ‖ u32 i ‖ u32 n` (so a chunk can't be moved to another position or file; chunks sealed before the prefix existed open without it), and the message carries the secret, size, chunk count and SHA3-512 of the file.

### 9.2 Attachment buckets

An attachment is padded to the smallest bucket that holds it (`enclave_wire::bucket_for`); attachments over 100 MiB (`MAX_ATTACHMENT`) are refused. A bucket needs `n_B = ⌈B / 14,248⌉` chunks (`chunks_for_bucket`). Each chunk carries its own length field, so a bucket's capacity is 14,248 · `n_B`.

| Bucket | Nominal size (B) | Chunks `n_B` | Capacity (B) = 14,248·`n_B` | Stored bytes (14,336·`n_B`) |
|---|---|---|---|---|
| 64 KiB | 65,536 | 5 | 71,240 | 71,680 |
| 256 KiB | 262,144 | 19 | 270,712 | 272,384 |
| 1 MiB | 1,048,576 | 74 | 1,054,352 | 1,060,864 |
| 4 MiB | 4,194,304 | 295 | 4,203,160 | 4,229,120 |
| 16 MiB | 16,777,216 | 1,178 | 16,784,144 | 16,887,808 |
| 64 MiB | 67,108,864 | 4,711 | 67,122,328 | 67,536,896 |
| 128 MiB | 134,217,728 | 9,421 | 134,230,408 | 135,059,456 |

Each chunk crosses the network as one 16,384 B wire unit (upload) or reply unit (download).

### 9.3 Directory payloads

Directory objects (manifests, prekey publications, claimed bundles, the vault-key object) travel as chunks of at most `CHUNK_DATA` = 14,000 B inside API frames (§2.3). They are not blob chunks.

`DirRequest` (78 B fixed part):

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | kind: 1 `Manifest`, 2 `Bundle`, 3 `Vault` |
| 1 | 1 | action: 1 `Put`, 2 `Get`, 3 `Claim` |
| 2 | 32 | key (manifest key, device key, vault locator, or claim ID) |
| 34 | 4 | chunk index (`u32`) |
| 38 | 4 | total chunks (`u32`; `Put` only) |
| 42 | 32 | proof: PoW for `Claim`, owner secret for `Vault` `Put`, otherwise unused |
| 74 | 4 | data length (`u32`, at most 14,000) |
| 78 | ≤ 14,000 | chunk data (`Put` only) |

`DirReply` (40 B fixed part):

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | total chunks of the object |
| 4 | 32 | claim ID (bundle claims) or zero |
| 36 | 4 | data length |
| 40 | variable | chunk data |

Both fit the 14,332 B payload limit: 78 + 14,000 = 14,078.

Object sizes (canonical encodings, `enclave-proto`):

| Object | Size (B) | Chunks of 14,000 B |
|---|---|---|
| Signed manifest, `n` devices, request-inbox locator of `L` B | 4 + (287 + `L` + 4,250·`n`) + 29,792 | 3 for `n` = 1 (34,365 B with `L` = 32); 4 for `n` = 5 (51,365 B with `L` = 32) |
| Prekey publication (signed prekey, batch of 100 OPKs with paths, last-resort) | 202,527 | 15 |
| Claimed bundle with a one-time prekey | 19,376 | 2 |
| Claimed bundle without a one-time prekey | 12,731 | 1 |
| Vault-key object | opaque to the server (`enclave-sim` seals the 1,357,824 B key as 23 segments of ≤ 60,000 B: 1,359,388 B) | 98 in the simulator |

Derivations: `math/envelope-budget.md` §8.

## 10. Size invariants

`enclave-wire` contains these compile-time assertions:

```
UNIT_SEALED_OFFSET == 1_628                      # 4 + 56 + 1_568
UNIT_SEALED_LEN    == 14_472                     # 72 + 14_336 + 64
UNIT_PADDING_LEN   == 284                        # 16_384 − 1_628 − 14_472
POLL_PADDING_LEN   == 284                        # 2_048 − 1_628 − 136
direct::PQ == 816 && direct::CAPSULE == 4_080 && direct::BODY == 5_104
direct::CONTENT_CAPACITY == 9_160                # 14_336 − 5_104 − 72
group::BODY == 3_528
group::CONTENT_CAPACITY == 10_736                # 14_336 − 3_528 − 72
```

Run-time checks and tests: `WireUnit::decode` and `PollRequest::decode` reject any length other than 16,384 and 2,048; `seal_direct` checks that every slot is 160 B, the PQ slot 3,264 B, and the envelope 14,336 B; `seal_request` checks the initial block (8,537 B) and the envelope length; `enclave-wire` tests `unit_roundtrip_and_exact_size`, `poll_roundtrip`, `header_roundtrip_and_reserved_check`, `padding_roundtrip`, `body_fits_sealed_region`, `buckets`; `enclave-sim` checks that the server only ever stores 14,336 B objects (`Server::stored_lengths`).

## 11. Parsing and errors

- A receiver checks the exact object size first, then version and suite (units and polls) or version and kind (envelopes), and only then attempts any cryptographic operation.
- Every parse or authentication failure on a network path is a silent drop. The server's answer to an undecryptable request is 16,384 random bytes; its answer to a well-formed request that fails authorization is a sealed reply with a non-`Ok` status. Both are full reply units.
- Parsers are fuzzed (`20-assurance.md` §1; not yet set up).

## Open questions

1. **Resolved:** op codes 0 to 13 (§2.2, `enclave_wire::Op`) are fixed for wire version 1. PLAN's other operations ride on them: group writes are `Write` with `FLAG_GROUP`, blob allocation with Privacy Pass is `BlobAlloc`, inbox creation and deletion are `RegisterTokens` with `CREATE` or `FLAG_DELETE`, push is `PushRegister`, capabilities for invites are `WriteRequest` with `FLAG_INVITE`, and account deletion and KT writes and queries are `Directory` objects (`Tombstone`, `Username`). Op 9 `KeyTransparency` stays reserved and answers `NotFound`. A new op needs a new code and an RFC.
2. **Resolved:** the kind byte stays. The server learns nothing from it that the inbox type doesn't already tell it. Merging request and account inboxes would need an RFC, which would have to revisit this byte.
3. **Resolved:** directory objects are not padded to a common chunk count. The server learns the kind from the `DirRequest` anyway; only an observer of the network could use the count. Large fetches (the vault key) run in a bulk window, whose burst the app already discloses (`09-transport.md` §6.7), and in Maximum privacy there are no bursts, so each chunk takes a normal tick slot with cover around it. Padding every manifest fetch to the vault key's size would cost about 1.4 MB per fetch.
4. **Resolved:** settled in M7: the state hash and frontier stay in PLAN §8's positions but are encrypted under the epoch header key and covered by the MAC vector (I-14).
