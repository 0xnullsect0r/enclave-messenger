# Multi-Device Fan-Out

Status: Draft (M0, reconciled with the M2 code) · Normative

Source: PLAN.md §6 (D5). Crates: `enclave-proto` (`envelope.rs`: wrap table), `enclave-core` (sync, in progress). Slot and PQ-slot cryptography: `05-ratchet.md` §5 to §7. Byte layout: `08-envelope.md` §5. Where this document and the code disagree, the code is normative.

## 1. Goals

- A message to an account with up to 5 devices costs one envelope per recipient account, not one per device.
- No server learns how many devices an account has from envelope counts or sizes.
- Each device pair keeps its own Lockstep session.

## 2. Wrap table (D5)

The body of a direct envelope is encrypted **once**, under a fresh random body key. The envelope carries a table of **exactly 5 device slots of 160 B** (`DEVICE_SLOTS`, the per-account device cap), one per recipient device session, and fills unused slots with random bytes. Each used slot holds a 16 B lookup tag and a 144 B compact-sealed header that includes the body key wrapped under that pair's message key (`05-ratchet.md` §6).

### 2.1 Building an envelope

`envelope::seal_direct(sessions, content, pq_carrier, rng)`:

```
require 1 <= len(sessions) <= 5                                         else Limit
hdr16 = u8(1) ‖ u8(1 /* Direct */) ‖ 0^14
body_key = HedgedRng.fill("envelope/body-key", 32)
body = seal(body_key, hdr16, u64(len(content)) ‖ content ‖ random padding)    # 9,232 B; content ≤ 9,160 B
body_hash = SHA3-512(body)
slots = []
for (i, s) in sessions:
    (tag, sealed_header, pq_slot?) = s.seal(body_key, body_hash, hdr16, carry_pq = (i == pq_carrier))
    slots += tag ‖ sealed_header                                        # 160 B
    keep pq_slot if this session carried it
while len(slots) < 5: slots += HedgedRng.fill("envelope/dummy-slot", 160)
shuffle(slots)                                                          # Fisher-Yates, hedged "envelope/shuffle"
pq = carried PQ slot (3,264 B) or HedgedRng.fill("envelope/dummy-pq", 3264)
capsule = HedgedRng.fill("envelope/capsule", 1024)
return hdr16 ‖ slots ‖ pq ‖ capsule ‖ body                              # 14,336 B
```

Rules:

- Every session in the list must be able to send (`Session::can_send`); a responder session that has not yet received cannot.
- The body hash is in every slot's nonce material, so a slot cannot be moved to another envelope, and every slot and the PQ slot use `hdr16` as AD.
- The slot order is shuffled per envelope so that position carries no information.
- Devices without a session are reached through request envelopes (`04-eqxdh.md`), one per device.

### 2.2 Receiving

`envelope::open_direct(sessions, env, vault, rng)` checks the length, version and kind, computes the body hash, and walks the 5 slots in order. For each slot it asks each of the caller's sessions whether the slot's tag is in its lookup index (`05-ratchet.md` §6.2). On the first match it opens the slot header (and the PQ slot if the header's flag is set), unwraps the body key, opens the body, and only then commits the session. It returns the index of the matching session and the content, or `NoSession` if no slot matches. At most one slot matches a given device.

## 3. PQ slot rotation

Each envelope has **one** PQ slot, which serves one session. The caller chooses which session carries it (`pq_carrier`); `Session::wants_pq_slot()` tells it which sessions have something to send (an unanswered peer key, an unacknowledged ciphertext, a pending braid, or a key id above 0 to announce). The intended policy, not yet implemented in a client:

```
ChoosePQCarrier(sessions):
    due = [s for s in sessions if s.wants_pq_slot()]
    if due is empty: return None
    return the s in due whose pair last carried a PQ slot longest ago
```

- With one recipient device, every envelope carries that pair's PQ slot, so every round trip takes a PQ step.
- With 5 due pairs, each pair gets a PQ slot every 5 envelopes.

## 4. Self-copy (not yet implemented)

PLAN D5: each message is exactly 2 envelopes, one to the recipient's account inbox and one self-copy to the sender's own account inbox, wrapped for the sender's other devices through their intra-account sessions. The self-copy is sent even for a single-device account (all slots random), so the server sees 2 writes per message regardless of device count. The recipient's envelope and the self-copy are built separately, each with its own body key and slot table, so identical ciphertexts never appear in two inboxes. Self-copies are sent with priority "own-device sync" (`09-transport.md` §6.2).

**Note to self, as implemented** (`enclave-core/src/client/notes.rs`): notes are messages stored under the account's own root in the sealed store, and each one (and each delete) goes to our other devices as `Content::SelfCopy { to: own root, Text | Delete }` over the intra-account sessions. Nothing is written to anyone else's inbox; a single-device account sends nothing at all for a note today (the always-sent self-copy above is not built yet). The app always lists **Note to self** ("Me"), with no delivery marks, reactions or pins, and it can be pinned, muted or archived like any conversation. Notes are not in local search yet. Tested in `link_a_second_device`.

## 5. Intra-account sessions and sync (not yet implemented)

Every pair of the account's own devices has a Lockstep session, established by EQXDH when a device is linked. Own-device sync carries sent messages, read state, contact and group changes, settings, verification states and fetch positions, but never ratchet state.

**Conversation list settings, as implemented** (`enclave-core/src/client/prefs.rs`): archive, pin to the top and mute are kept per conversation, 1:1 or group, in the sealed store. They are local: nothing about them is sent to anyone, including our other devices, which keep their own until this sync exists. At most four conversations are pinned to the top (they list first, newest first). A message from someone else brings an archived conversation back unless it is muted; a muted conversation still counts unread messages but shows the count without the Pine fill. The app has a conversation sheet with the three switches (on a phone it also holds the disappearing-messages timer) and an "Archived (n)" section at the end of the list. Test `conversation_prefs`.

## 6. Deletion watermark

Implemented at the server (`12-servers.md` §1.2):

- The account inbox is an append-only log. Each stored envelope has a server-assigned `u64` sequence number starting at 1.
- A poll carries a cursor and returns the first envelope with a higher sequence number, plus `MORE` if another follows. The server does not know which device is polling.
- `Ack` with a watermark `W` deletes every envelope with sequence number `≤ W`.
- The server deletes envelopes 30 days after they were written regardless of the watermark (`Server::expire`).

Not implemented yet: devices reporting their positions to each other through own-device sync, and the rule that a device advances the watermark only after every device in the manifest has reported at least `W`. Decoy re-fetches are built: a device's account-inbox poll starts one envelope back one time in eight (`09-transport.md` §5), so a caught-up device's polls still bring envelopes.

## 7. Device-list changes (not yet implemented)

When the account publishes a new manifest, each device sends a `DeviceListChanged{manifest_version, manifest_hash}` control message to each contact; the contact fetches and verifies the manifest (`03-identity.md` §3.4), deletes sessions with removed devices, and establishes sessions with new ones on the next send.

## 8. Errors

| Condition | Action |
|---|---|
| More than 5 sessions, or none | `seal_direct` fails with `Limit` |
| A session cannot send yet | `seal_direct` fails with `NoSession` |
| Content over 9,160 B | `seal_direct` fails with `TooLarge` |
| No slot matches | `open_direct` returns `NoSession`; drop |
| A matched slot or the body fails to open | Error; no session state changes |

## Open questions

1. PLAN §6 says slots hold "a tag and padding". With the 160 B layout there is no padding left: 16 + 144 = 160. The slot header has 7 zero bytes inside the seal instead (`05-ratchet.md` §6.1).
2. Whether the self-copy may be omitted in Maximum privacy mode on a single-device account, to save 50% of write bandwidth, at the cost of revealing single-device accounts. This spec says no.
