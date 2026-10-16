# Lockstep Ratchet

Status: Draft (M0, reconciled with the M2 code) · Normative

Source: PLAN.md §5. Crate: `enclave-proto` (`ratchet.rs`, `envelope.rs`). KDFs: `02b-key-schedule.md` §7. Envelope layout: `08-envelope.md` §5. Multi-device use: `06-multidevice.md`. Where this document and `ratchet.rs` disagree, the code is normative.

## 1. Structure

The Lockstep Ratchet runs two ratchets side by side, and every message key depends on both:

1. a **Double Ratchet over X448 with header encryption** (the DR-HE variant), which gives per-message forward secrecy and classical post-compromise security;
2. a **post-quantum ratchet over ML-KEM-1024** with explicit per-direction epochs. Each side keeps one current encapsulation key and repeats it until the peer answers with a ciphertext; each answer is one PQ **step** that advances the root of that direction.

```
mk = KMAC256(mk_DR, frame(pq_key(e_out, e_in)), 256, "enclave/v1/ratchet/msg")
```

Every PQ exchange is a full, unchunked ML-KEM-1024 key or ciphertext carried in a **PQ slot** (one per envelope), so PQ healing takes one round trip. Receivers never trial-decrypt: every device slot starts with a 16 B lookup tag, and each session keeps an index of the tags it expects. All receive-side updates happen on a copy of the session that is committed only after the message body authenticates.

The design adapts Signal's published SPQR/Triple Ratchet ProVerif models (`formal/proverif/`). Signal's AGPL SPQR code MUST NOT be linked or copied.

One session exists per ordered pair of devices. A session never spans devices.

## 2. Session state

```
Session {
  role: Initiator | Responder
  RK: [32]
  DHs: X448 keypair; DHr: X448 pk | None
  CKs, CKr: [32] | None
  Ns, Nr, PN: u32
  HKs, HKr: [32] | None; NHKs, NHKr: [32]
  skipped: map tag[16] -> { hk: [32], n: u32, mk_DR: [32] }    # at most 1,000 entries
  pq: {
    out_root, in_root: [32]                  # current root per direction
    e_out, e_in: u32                         # epochs: steps I made, steps the peer made
    out_hist, in_hist: list of (epoch, root) # last 16 epochs per direction (PQ_HISTORY)
    my: { id: u32, sk, pk }                  # my current ML-KEM-1024 key
    peer: (id, pk) | None                    # peer key I have not answered yet
    highest_peer_id: u32
    outstanding: { for_id, ct, e_out, mce_ct? } | None   # my last step, not yet acknowledged
    braid_to: McEliece pk | None             # vault key to fold into my next step (initiator, 2-KEM)
  }
  pq_authenticated: bool
  three_kem: bool
  tag_cache: lookup index (rebuilt on demand)
}
```

## 3. KDFs

```
kmac32(K, [x1, …, xn], S) = KMAC256(K, frame(x1) ‖ … ‖ frame(xn), 256, S)    # empty list: nothing absorbed

KDF_RK(RK, dh)  = KMAC256(RK, frame(dh), 768, "enclave/v1/ratchet/rk")    -> RK' ‖ CK ‖ NHK
KDF_CK(CK)      = KMAC256(CK, "", 512, "enclave/v1/ratchet/ck")           -> CK' ‖ mk_DR
TAG(HK, n)      = KMAC256(HK, u32(n), 128, "enclave/v1/ratchet/tag")      # 16 B, n absorbed raw
PQ_STEP(root, ss, ct, ek_hash)              = kmac32(root, [ss, ct, ek_hash], "enclave/v1/pq/step")
PQ_STEP(root, ss, ct, ek_hash, mss, mct)    = kmac32(root, [ss, ct, ek_hash, mss, mct], "enclave/v1/pq/step")   # braid
PQ_KEY(out, in) = kmac32(out, [in], "enclave/v1/pq/key")
MSG(mk_DR, k)   = kmac32(mk_DR, [k], "enclave/v1/ratchet/msg")
WRAP(mk, bh)    = kmac32(mk, [bh], "enclave/v1/ratchet/wrap")             # bh = SHA3-512(sealed body)
PQ_SLOT_KEY(mk_DR) = kmac32(mk_DR, [], "enclave/v1/ratchet/pq-slot")
```

`ek_hash` is SHA3-512 of the ML-KEM encapsulation key being answered. `ss` and `ct` are the ML-KEM shared secret and ciphertext; `mss` and `mct` the McEliece ones.

The PQ key of a message sent with sender epochs `(e_out, e_in)` is `PQ_KEY(sender_out_root[e_out], sender_in_root[e_in])`. The receiver computes the same value from its own history: the sender's out root is the receiver's in root and vice versa.

## 4. Initialization

From EQXDH (`04-eqxdh.md`), with the 64 B session key `SK`:

```
RK0    = kmac32(SK, [], "enclave/v1/ratchet/init-rk")
HKA    = kmac32(SK, ["a"], "enclave/v1/ratchet/init-hk")
NHKB   = kmac32(SK, ["b"], "enclave/v1/ratchet/init-hk")
PQ_A2B = kmac32(SK, ["a2b"], "enclave/v1/ratchet/init-pq")
PQ_B2A = kmac32(SK, ["b2a"], "enclave/v1/ratchet/init-pq")
```

Both directions start at epoch 0: `out_hist = [(0, out_root)]`, `in_hist = [(0, in_root)]`.

### 4.1 Initiator (Alice)

```
out_root = PQ_A2B; in_root = PQ_B2A
DHs = fresh X448 pair; DHr = SPK_B (the responder's signed prekey)
RK, CKs, NHKs = KDF_RK(RK0, X448(DHs, SPK_B))
HKs = HKA; HKr = None; NHKr = NHKB; Ns = Nr = PN = 0
my = (id 0, the device auth key)          # the responder already holds its public half from the manifest
peer = None; highest_peer_id = 0
```

The initiator can send immediately. Its first message travels in the request envelope with `e_out = e_in = 0` and no PQ slot.

### 4.2 Responder (Bob)

```
out_root = PQ_B2A; in_root = PQ_A2B
RK = RK0; DHs = the X448 signed-prekey pair; DHr = None; CKs = CKr = None
HKs = HKr = None; NHKs = NHKB; NHKr = HKA; Ns = Nr = PN = 0
my = (id 1, a fresh ML-KEM-1024 key)
peer = (id 0, the initiator's device auth key from its manifest); highest_peer_id = 0
```

The responder cannot send until it has received (`can_send()` is false while `CKs` is `None`). Its first received message is a "next-chain" hit (§6.2) that runs the first DH ratchet step.

## 5. Sending

`Session::seal(body_key, body_hash, AD, carry_pq)` produces one device slot and, if `carry_pq`, the envelope's PQ slot:

```
seal(S, body_key, body_hash, AD, carry_pq):
    require S.CKs and S.HKs                                             else NoSession
    (CK', mk_DR) = KDF_CK(S.CKs); n = S.Ns
    tag = TAG(S.HKs, n); nonce_material = tag ‖ body_hash
    flags = 0
    if carry_pq: flags |= 0x01; pq_slot = BuildPQSlot(S, mk_DR, nonce_material, AD)    # §7.1; may advance e_out
    e_out = (S.pq.outstanding.e_out − 1) if (S.pq.outstanding and not carry_pq) else S.pq.e_out
    e_in  = S.pq.e_in
    mk = MSG(mk_DR, PQ_KEY(S.pq.out_root[e_out], S.pq.in_root[e_in]))
    wrapped = body_key ⊕ WRAP(mk, body_hash)
    header = DHs.pk (56) ‖ u32(PN) ‖ u32(n) ‖ u32(e_out) ‖ u32(e_in) ‖ u8(flags) ‖ wrapped (32) ‖ 0^7    # 112 B
    sealed_header = seal_compact(S.HKs, nonce_material, AD, header)     # 144 B
    S.CKs = CK'; S.Ns = n + 1
    return (tag, sealed_header, pq_slot?)
```

**Epoch rule for `e_out`.** A new out-step is used only by messages that carry its ciphertext. While the step is outstanding (not yet acknowledged, §7.2 step 3), messages without the PQ slot use the previous epoch `outstanding.e_out − 1`, which the receiver can always compute. Once the peer acknowledges the step, every message uses the new epoch.

The body key, the body hash, the AD and the envelope layout come from the envelope builder (`06-multidevice.md` §2, `08-envelope.md` §5 and §6). Sending changes the session immediately; the caller persists the session before the envelope leaves the device.

## 6. Device slots and lookup

### 6.1 Slot layout (160 B)

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | lookup tag `TAG(HKs, n)` |
| 16 | 112 | compact-sealed header (ciphertext) |
| 128 | 32 | compact-seal tag |

Header plaintext (112 B):

| Offset | Length | Field |
|---|---|---|
| 0 | 56 | sender's current DH ratchet public key |
| 56 | 4 | `pn`: length of the sender's previous sending chain |
| 60 | 4 | `n`: index in the current chain |
| 64 | 4 | `e_out`: sender's PQ out-epoch used for this message |
| 68 | 4 | `e_in`: sender's PQ in-epoch used for this message |
| 72 | 1 | flags: bit 0 (`0x01`) the envelope's PQ slot belongs to this session; other bits zero |
| 73 | 32 | wrapped body key `body_key ⊕ WRAP(mk, body_hash)` |
| 105 | 7 | zero (checked) |

Sum: 56 + 4 + 4 + 4 + 4 + 1 + 32 + 7 = 112. `Header::decode` rejects non-zero padding bytes. Undefined flag bits are not rejected today.

The header seal is `seal_compact(HKs, tag ‖ SHA3-512(sealed body), AD, header)` (`02-cryptography.md` §4.5). The nonce material binds the slot to the body, so a slot cannot be moved to another envelope.

### 6.2 Lookup index

Each session builds (and caches until its next commit) an index from 16 B tags to hits:

- `Current(n)`: `TAG(HKr, n)` for `n ∈ [Nr, Nr + 64)` (`TAG_WINDOW = 64`), if `HKr` is set;
- `Next(n)`: `TAG(NHKr, n)` for `n ∈ [0, 64)`;
- `Skipped`: the tag of every stored skipped key.

Lookup is a hash-map probe per slot, with no trial decryption. There is no slow path: a message more than 63 positions ahead of `Nr` on the current chain, or 63 into the next chain, is not found (`NoSession`).

### 6.3 Why the nonce is derived

The slot has no room for a 32 B nonce. The compact seal derives it from the lookup tag, which is unique per `(HK, n)` in normal operation, and from the body hash, which differs for different content (`02-cryptography.md` §4.5).

### 6.4 Rollback residual (RT-08)

If a sender's stored state is rolled back, it can reuse `(HKs, n)`. The lookup tag then repeats, so the server can link the two envelopes as coming from the same device pair. The header nonce still differs unless the sealed body is identical, because the body is sealed under a fresh random key with a hedged nonce. This residual is accepted and listed in `redteam-matrix.md` RT-08.

## 7. PQ ratchet

### 7.1 PQ slot and the sender

The PQ slot plaintext is zero-padded to 3,232 B and sealed with `seal_compact(PQ_SLOT_KEY(mk_DR), nonce_material, AD, pt)` using the same nonce material and AD as the carrying session's device slot (3,264 B sealed, `08-envelope.md` §5.3).

Kind 0 (normal):

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | kind = 0 |
| 1 | 4 | `ek_id`: id of the sender's current key |
| 5 | 1,568 | sender's current ML-KEM-1024 encapsulation key |
| 1,573 | 4 | `ct_for`: id of the peer key the ciphertext answers (0 if none) |
| 1,577 | 1,568 | ciphertext (zero if none) |
| 3,145 | 4 | `ct_e_out`: the sender's out-epoch this ciphertext creates (0 if none) |

Kind 0 is 1 + 4 + 1,568 + 4 + 1,568 + 4 = 3,149 B before padding.

Kind 1 (braid step outstanding; no key this time):

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | kind = 1 |
| 1 | 4 | `ek_id` (sender's current key id; the key itself is not sent) |
| 5 | 4 | `ct_for` |
| 9 | 1,568 | ML-KEM ciphertext |
| 1,577 | 4 | `ct_e_out` |
| 1,581 | 208 | McEliece ciphertext to the peer's vault key |

Kind 1 is 1 + 4 + 4 + 1,568 + 4 + 208 = 1,789 B before padding. Any other kind is rejected.

```
BuildPQSlot(S, mk_DR, nonce_material, AD):
    if S.pq.outstanding is None and S.pq.peer = (pid, pek) is set:          # answer the peer's key once
        (ct, ss) = ML-KEM-1024.Encaps(pek); ek_hash = SHA3-512(pek)
        mce = McEliece.Encaps(S.pq.braid_to) if S.pq.braid_to is set (and clear braid_to)
        S.pq.out_root = PQ_STEP(S.pq.out_root, ss, ct, ek_hash [, mce.ss, mce.ct])
        S.pq.e_out += 1; push (e_out, out_root) to out_hist (keep 16)
        S.pq.outstanding = { for_id: pid, ct, e_out: S.pq.e_out, mce_ct: mce.ct? }
        S.pq.peer = None
    if S.pq.outstanding has mce_ct:  kind 1 with outstanding's fields
    else:                            kind 0 with my key, and outstanding's fields or zeros
    return seal_compact(PQ_SLOT_KEY(mk_DR), nonce_material, AD, pad(pt, 3232))
```

The ciphertext of an outstanding step is repeated in every PQ slot the session carries until the peer acknowledges it. A new step is made only when nothing is outstanding and the peer has announced a key not yet answered.

### 7.2 The receiver

`process_pq_slot` runs before the message key is computed, whenever the header's PQ flag is set (the slot is required; its absence is an error):

```
ProcessPQSlot(S, mk_DR, nonce_material, AD, slot, vault):
    pt = open_compact(PQ_SLOT_KEY(mk_DR), nonce_material, AD, slot)        else fail the message
    parse kind, their_ek_id, their_ek (kind 0), ct_for, ct, ct_e_out, mce_ct (kind 1)
    # 1. their answer to my key: one in-step, strictly in order
    if ct_e_out != 0 and ct_for == S.pq.my.id and ct_e_out == S.pq.e_in + 1:
        ss = ML-KEM-1024.Decaps(S.pq.my.sk, ct); ek_hash = SHA3-512(S.pq.my.pk)
        mss = McEliece.Decaps(vault, mce_ct) if kind 1  (vault required, else Missing)
        S.pq.in_root = PQ_STEP(S.pq.in_root, ss, ct, ek_hash [, mss, mce_ct])
        S.pq.e_in += 1; push (e_in, in_root) to in_hist (keep 16)
        if kind 1: S.three_kem = true
        S.pq.my = (S.pq.my.id + 1, fresh ML-KEM-1024 key)                 # post-compromise security
    else if ct_e_out != 0 and ct_e_out > S.pq.e_in + 1:
        fail the message (Counter)
    # otherwise: duplicate or stale ciphertext, ignored
    # 2. their current key, if new
    if their_ek_id > S.pq.highest_peer_id and their_ek is present:
        S.pq.peer = (their_ek_id, their_ek); S.pq.highest_peer_id = their_ek_id
    # 3. acknowledgement: they moved past the key my outstanding ciphertext answered
    if S.pq.outstanding and their_ek_id > S.pq.outstanding.for_id:
        if S.pq.outstanding.mce_ct: S.three_kem = true
        S.pq.outstanding = None
```

The receiver generates a new key only after its current one is answered, so each session stores at most one ratchet decapsulation key (plus the device auth key, which is key id 0 on the initiator side).

### 7.3 PQ authentication

- **Initiator.** The session key already includes an encapsulation to the responder's device auth key (`04-eqxdh.md` §5), so the initiator sets `pq_authenticated` on the first message it decrypts from the responder.
- **Responder.** The responder's first PQ step answers peer key id 0, which is the initiator's device auth key. Only a holder of that key's decapsulation key can compute the responder's out root at epoch 1. The responder sets `pq_authenticated` on the first authenticated message whose header has `e_in ≥ 1`, because that message's key depends on that root. Until then the responder's view of the initiator is classical (DH1) plus the PSK, if any.

Both flags are set on the session copy and committed only after the body authenticates.

### 7.4 McEliece braid

A session that started on the 2-KEM suite (`04-eqxdh.md` §7) is upgraded by folding a McEliece encapsulation into the initiator's next ML-KEM out-step:

1. When the vault key arrives and verifies against the manifest commitment, the initiator calls `schedule_braid(vault_pk)`. This has an effect only on an initiator session with `three_kem = false`.
2. The next out-step (§7.1) also encapsulates to the vault key and mixes both McEliece values into `PQ_STEP`. While that step is outstanding, the session sends kind-1 slots (the ciphertexts, no new key).
3. The responder decapsulates with its vault secret key (passed to `open`), applies the step, and sets `three_kem = true`.
4. The initiator sets `three_kem = true` when the responder acknowledges the step (announces a newer key).

From that step on, every message key in the braided direction, and every later step in both directions (through the key announced after it), depends on the McEliece secret. EQXDH never schedules the braid itself; the caller does after fetching the vault key (test `mceliece_braid_upgrades_two_kem_session`).

### 7.5 Healing

- A party that generates a fresh key after a compromise ends, and whose peer encapsulates to it, gets a peer-send epoch whose secret depends on a decapsulation key the attacker never saw. In steady state this happens within one round trip.
- Monologues: if one side keeps sending without replies, only the symmetric DH chain advances, and at most one PQ step per peer key is made. Post-compromise security needs a round trip; this is inherent to KEM ratchets.
- The PQ key is the same for every message sent in one `(e_out, e_in)` pair. Per-message forward secrecy within an epoch pair comes from the DH chain (`mk_DR`).

## 8. Receiving

`Session::open(tag, sealed_header, pq_slot, body_hash, AD, vault, rng)` returns the body key and the would-be next state; the caller opens the body and then calls `commit(next)`. A forged or corrupted message therefore never changes state.

```
open(S, tag, sealed_header, pq_slot, body_hash, AD, vault):
    hit = S.index[tag]                                                   else NoSession
    s = copy of S; nonce_material = tag ‖ body_hash
    match hit:
      Skipped:  entry = s.skipped.remove(tag)
                h = Header(open_compact(entry.hk, nonce_material, AD, sealed_header))
                require h.n == entry.n; mk_DR = entry.mk_DR
      Current(n):
                h = Header(open_compact(s.HKr, …)); require h.n == n and h.dh == s.DHr
                SkipTo(s, n); (s.CKr, mk_DR) = KDF_CK(s.CKr); s.Nr = n + 1
      Next(n):  h = Header(open_compact(s.NHKr, …)); require h.n == n
                if s.CKr is set: SkipTo(s, h.pn)                         # finish the old chain
                DHRatchet(s, h.dh); SkipTo(s, n)
                (s.CKr, mk_DR) = KDF_CK(s.CKr); s.Nr = n + 1
    if h.flags & 0x01: ProcessPQSlot(s, mk_DR, nonce_material, AD, pq_slot, vault)     # §7.2
    k  = PQ_KEY(s.in_root[h.e_out], s.out_root[h.e_in])                  else Counter (epoch not in history)
    if s.role == Initiator or h.e_in >= 1: s.pq_authenticated = true
    mk = MSG(mk_DR, k); body_key = h.wrapped ⊕ WRAP(mk, body_hash)
    return (body_key, s)

DHRatchet(s, their):
    s.PN = s.Ns; s.Ns = 0; s.Nr = 0
    s.HKs = s.NHKs; s.HKr = s.NHKr; s.DHr = their
    s.RK, s.CKr, s.NHKr = KDF_RK(s.RK, X448(s.DHs, their))
    s.DHs = fresh X448 pair
    s.RK, s.CKs, s.NHKs = KDF_RK(s.RK, X448(s.DHs, their))

SkipTo(s, until):
    if s.CKr is None or until < s.Nr: return
    if until − s.Nr > 1000: fail (Counter)
    for i in s.Nr..until: store skipped[TAG(s.HKr, i)] = { s.HKr, i, mk_DR_i }; advance s.CKr
    s.Nr = until
    while |skipped| > 1000: remove the entry with the smallest tag
```

Messages that arrive late within the 16-epoch PQ history and within the skipped-key store decrypt normally; each skipped key is deleted when used, so a second delivery of the same message is not found (RT-24).

## 9. Modes

The session mode is bound into the EQXDH transcript (`04-eqxdh.md` §5), so every key of the session, including every device-slot and body key, depends on it: a peer that believes a different mode derives different keys and every message fails to open. Sessions are always started Off the record, so the greeting stays deniable; a conversation goes on the record in-band.

**As implemented** (`enclave-core/src/client/record.rs`, `enclave-proto/src/otr.rs`, RT-07):

- **Switching.** Either person can put the conversation on the record or take it off (`Client::set_on_the_record`). That sends `ModeChange { on_record, seq }` (content kind 32) to them and to our other devices. It is content of the session like any other, so only the two of them can switch the mode, and both sides show who changed it (`Event::ModeChanged`). Changes are numbered: the higher number wins, and of two with the same number, off wins.
- **Signing.** On the record, everything a person writes (`Content::is_personal`: texts, files, reactions, edits, deletes, the timer, locations, stickers, shared contacts, pins) goes as `Content::Signed { counter, sig, content, tokens }` (kind 33). `content` is the encoded content with any write tokens taken out (they ride beside it, outside the signature, so a quote shown to someone else doesn't carry them). The signature is

  ```
  conv_id = ID256("enclave/v1/proto/conv-id", lower root_hash ‖ higher root_hash)
  payload = conv_id (32) ‖ sender_device_id (16) ‖ recipient_root_hash (32) ‖ u64(counter) ‖ u8(1) ‖ SHA3-512(content)
  sig     = CompositeSign(device_sk, ctx = "enclave/v1/ctx/signed-msg", payload)
  ```

  where `counter` counts the device's signed messages in the conversation. The signature takes 4,741 B; content that no longer fits one envelope goes in continuation units (`08-envelope.md` §5.6).
- **Checking.** The receiver checks the signature against that device's entry in the sender's manifest. A personal message that arrives unsigned in a conversation on the record, or whose signature fails, is still shown, marked "not signed" (`Message::signed`); one that verifies keeps its signature in its own sealed record (`Message::evidence`), shredded with it, so a report can carry it (`13-operators.md` §2).
- **The app** shows the mode in the conversation header ("On the record" / "Off the record"), switches it in the conversation sheet with the words of `17-design.md`, and says in the status line who changed it.
- Test `rt07_mode_switch_requires_authenticated_event` (`tests/on_record.rs`): a change made in another conversation doesn't switch this one; a message written before the other side heard of the change is marked not signed; signed messages verify; a report's signatures verify at the operator and a changed one doesn't; switching back off.

Groups have their own mode in the group state (`07-groups.md` §3).

## 10. Skipped keys

- `SkipTo` fails the message if it would skip more than 1,000 keys in one chain (`MAX_SKIP`).
- At most 1,000 skipped keys are stored per session. When the store is full, the oldest entries (by insertion order) are evicted first.
- Skipped keys expire after 7 days (`SKIPPED_MAX_AGE`). `Session::expire_skipped(now, max_age)` stamps new entries with `now` on its first pass and deletes entries older than `max_age`; `enclave-core` calls it on every sync. The stamp is persisted with the session.
- A skipped key is deleted as soon as it is used.

## 11. Gaps and control messages

**Gaps, as implemented** (`enclave-core/src/client/gaps.rs`, RT-24):

- `Session::oldest_skipped` says when the oldest key still held for a message that was skipped (later ones arrived first) was first seen; `expire_skipped` stamps them on every sync. When it is more than 60 s old (and less than a day), the conversation shows "A message may not have arrived" (`Client::gap`, `Event::Gap` once per gap). It goes when the message arrives.
- `Opened::skipped_at` says when a message's key was first seen skipped. A message that arrives more than 60 s after that is marked "delivered late" (`Message::late`).
- An envelope from the account inbox that no session opens yet is held (at most 64, for 7 days) and tried again after each sync's inboxes; our own cover self-copies never are.
- Tests: `rt24_gap_notice_after_60s` (a held-back message: the notice after a minute, then "delivered late"), `rt24_replayed_message_rejected` (in order and out of order).

**Control messages, as implemented.** Content is opaque bytes to `enclave-proto`; `enclave-core` encodes it as Protobuf (`08-envelope.md` §5.5). The v1 control set maps onto content kinds as follows:

| Control message | As built |
|---|---|
| `SessionSetup` | `Hello` (kind 1): the greeting's first content, with the server, inbox seed, write tokens and card |
| `TokenRefill` | `Tokens` (kind 3), and tokens riding on a `Text` |
| `DeviceListChanged` | `Devices` (kind 13): the new manifest version, fetched and checked against key transparency |
| `ForcePQStep` | `PqStep { reply }` (kind 21) |
| `ModeChange` | `ModeChange { on_record, seq }` (kind 32), §9 |
| `Reroot` | A new bonded greeting when people meet again (`client/meet.rs`): the sessions are replaced, which heals more than mixing a PSK into the old root (`proto/bond-reroot` retired) |
| `Receipt` | `Read` (kind 10) and `Delivered` (kind 27), and delivery receipts riding in free space (`outbox::wrap_receipts`) |
| `Typing` | `Typing { on }` (kind 23, `16-features.md` §7) |
| `KTGossip` | Gossip items riding in free space (`gossip::wrap`) and `KtHead` (kind 16) |
| `Moved` | `ServerMoved` and `HomeMoved` (kinds 25 and 26, `12-servers.md` §4.4) |
| `Closed` | `Closed` (kind 34): the sender closed their account; the conversation stays, read-only, and nothing more is sent to them (`client/closing.rs`, `Event::ContactClosed`; sent by account deletion, `03-identity.md` §8.5) |

## 12. Errors

`enclave_proto::ProtoError`:

| Error | Cause | Action |
|---|---|---|
| `NoSession` | Tag not in the index; sending before the first receive | Try the next session or slot; else drop |
| `Crypto` | Header or PQ slot fails to open; `n` or DH key mismatch | Drop; state unchanged |
| `Counter` | More than 1,000 skipped keys; PQ epoch not in the 16-epoch history; PQ epoch gap | Drop; state unchanged |
| `Decode` | PQ flag set but no PQ slot; malformed slot or header | Drop; state unchanged |
| `Missing` | A braid step arrives but no vault key was supplied | Drop; retry with the vault key |

Tests (`crates/enclave-proto/tests/session.rs`): `full_three_kem_conversation`, `out_of_order_loss_replay_and_tamper`, `crossing_messages_and_lost_pq_slots`, `mceliece_braid_upgrades_two_kem_session`, `multi_device_wrap_table`, `on_the_record_and_psk`, `psk_mismatch_fails_closed`.

## Open questions

1. **Resolved:** the structure stays: the PQ key is fixed per `(e_out, e_in)` pair and `mk = KMAC(mk_DR, pq_key)`, with no per-message `mk_PQ` as in PLAN §5. Per-message forward secrecy within an epoch pair rests on the DH chain; post-quantum healing comes from each ML-KEM step, which `formal/proverif/lockstep_pcs.pv` and `formal/tamarin/lockstep.spthy` model. The full state machine is not modelled yet (`formal/README.md`) and is in audit A's scope (G1; RFC 0008, item 9).
2. **Resolved:** Alice's auth key is the first PQ ratchet key (id 0), so Bob's first PQ step authenticates Alice (§7.3), and there is no confirmation value. This intentionally differs from PLAN §4 (RFC 0008, item 9).
3. **Resolved:** the braided McEliece secret is folded into the next ML-KEM out-step (§7.4), not into the root key as in PLAN §4. Test `mceliece_braid_upgrades_two_kem_session`. The braid is modelled in Tamarin (`formal/tamarin/braid.spthy`: a session that started on two KEMs is secure after the McEliece step against an attacker that breaks X448 and ML-KEM; CI job `tamarin`; RFC 0008, item 9).
4. **Resolved:** the window stays at 64 (`TAG_WINDOW`), with no slow path. It costs 128 KMAC calls per session per commit and covers far more loss than PLAN's 8; a message more than 63 positions ahead is not found (§6.2).
5. **Resolved:** skipped keys are evicted oldest first and expire after 7 days (§10; `MAX_SKIP`, `SKIPPED_MAX_AGE`).
6. **Resolved:** the mode is bound through the EQXDH transcript into every session key (§9). In-band mode switches must bind the new mode when they are added.
7. **Resolved:** undefined flag bits stay accepted and ignored (`Header::decode` checks only the zero padding). The flags are inside the compact-sealed header, so only the session's peer can set them, and a future flag can then be added without a format break.
