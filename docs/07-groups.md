# Groups (up to 100 members)

Status: Implemented in `enclave-proto::group` (M7) · Normative

Source: PLAN.md §7 (D6). Crate: `enclave-proto` (MAC vectors, exporter rekey, frontier). Derivations: `02b-key-schedule.md` §8. Layouts: `08-envelope.md` §7 (message unit) and §8 (rekey unit). There is no MLS.

## 1. Model

- A group has a random 32 B `group_id`, a **state** (§7), an **epoch** (a `u32` that increments on every membership or device-list change), and an `epoch_secret` known to current members.
- Every member device `s` has a **sender chain** per **generation** `g` (`u8`, increments on each rotation, wraps with the epoch). Messages from `s` are encrypted with keys from its chain.
- Every member device `s` also has, per generation, one **MAC key per other member account** `j`, `mac_key[s→j]`, delivered only to account `j`'s devices.
- Delivery is one unit per message to the group mailbox on the host server (normally the creator's home server). Pairwise Lockstep sessions between member devices carry all key material.
- Maximum 100 member accounts. Each account may have up to 5 devices, so up to 500 devices.

## 2. Sender chains

```
cs_0 = HedgedRng.fill("grp-chain-seed", 32)                  # per (sender device, generation)
(cs_{n+1}, gmk_n) = split32( KMAC256(cs_n, "", 512, "enclave/v1/proto/grp-chain") )
```

Message `n` of generation `g` from device `s` is sealed under `gmk_n`. Receivers keep skipped `gmk` values under the same limits as 1:1 (1,000 per sender device, 7 days). `cs_n` and used `gmk_n` are deleted as the chain advances.

## 3. Message authentication (MAC vectors)

Every group message carries a MAC vector of **99 entries × 16 B = 1,584 B**, always full.

- Entry position: members are ordered by the member index in the group state (0 to 99). The vector has one entry for every member index except the sender's own account; position `p` holds the tag for the member with index `p` if `p` is less than the sender's index, otherwise index `p + 1`. Positions with no member hold random bytes.
- Tag computation:

  ```
  covered = unit[0..88] ‖ unit[2696..14336]                   # routing header and sealed body (08-envelope.md §7)
  tag_j   = KMAC256(mac_key[s→j], H512(covered), 128, "enclave/v1/proto/grp-mac")
  ```

- A receiving device of account `j` verifies its entry in constant time **before** opening the body. A failed MAC drops the unit.
- Insiders cannot forge each other's messages (they lack `mac_key[s→j]` for other `j`), and there is no signature that proves authorship to outsiders. This makes group messages deniable and post-quantum.
- **Own devices.** The vector has no entry for the sender's own account. A device does not accept, from the mailbox alone, a message that claims to come from another device of its own account. It shows it after own-device sync (`06-multidevice.md` §5) confirms the message's `grp_msg_id`; sync of sent group-message IDs is batched and sent within 60 s in the Foreground profile.
- **On-the-record groups** additionally carry a composite device signature in the content:

  ```
  sig = CompositeSign(device_sk, "enclave/v1/proto/grp-signed-msg",
                      group_id ‖ u32(epoch) ‖ sender_device_id ‖ u8(generation) ‖ u32(counter)
                      ‖ state_hash ‖ H512(plaintext_content))
  ```

## 4. Delivery

- **Mailbox address:** `gmbox(d) = KMAC256(epoch_secret, u32(d), 256, "enclave/v1/net/grp-mailbox")` for day `d` (PLAN: `KMAC(epoch_secret, "gmbox"‖day)`). A sender writes to the address for the current trusted day. Readers poll today's and yesterday's address.
- **Write authorization (epoch MAC tokens):** `grp_write_tok(a) = KMAC256(k_gw, a, 256, "enclave/v1/net/grp-write-token")`. The first write to an address that does not exist yet carries the `CREATE` flag; the server stores `KMAC256(a, token, 256, "enclave/v1/net/token-hash")` and accepts later writes that present the same token. Group write tokens are multi-use for one address; the server can already link writes to one mailbox.
- **Read authorization:** `grp_read_cred(a) = KMAC256(k_gr, a, 256, "enclave/v1/net/grp-read-cred")`, registered the same way with `cred-hash`.
- **Routing header:** the 88 B header is sealed under `HKg = KMAC256(epoch_secret, "", 256, "enclave/v1/proto/grp-header")` and carries epoch, sender member index, sender device index, generation, flags, and counter (`08-envelope.md` §7.1).
- **Cost:** 1 unit per group message. No self-copy (own devices read the mailbox).
- **Hosting move:** admins may move the mailbox host to another server by an admin vote (a state update naming the new host, applied by a majority of admins). The new host takes effect from the next day's address.

## 5. Rekey (DCGKA-style exporter broadcast)

### 5.1 When

- **Membership or device-list change:** the member who performs the change (the remover, or the admin who adds) creates a new epoch and rotates immediately. Every other member rotates before its next send in the new epoch.
- **Otherwise (lazy):** a sender device rotates on its first send after 24 h or after 200 messages in its current generation.
- **"Secure my account"** rotates the user's sender chains in every group.

### 5.2 Pre-rekey PQ step

Before a rekey, the rotating device `s` checks each pairwise session with a recipient device. If the pair's most recent PQ epoch in either direction was established before the group's last epoch change, `s` sends a `ForcePQStep` control message and waits for a completed PQ exchange (up to 10 minutes in the Foreground profile, up to 1 hour otherwise). Pairs that do not complete in time are still included, and the rotation is marked "pre-step incomplete" locally so the next rotation retries them. This makes the rekey post-compromise secure against a compromise that ended before the rekey.

**As implemented** (`enclave-core/src/client/group_pq.rs`): the device records each member pair's PQ epochs (`Session::pq_epochs`) when the group epoch changes. Before a rotation, every pair whose epochs haven't moved since then gets `Content::PqStep { reply: true }` (content kind 21) over the pairwise session; every unit carries a full PQ slot, so the ping and the peer's `PqStep { reply: false }` answer are one ML-KEM round trip. The client doesn't make the send wait: it rotates at once (the "pre-step incomplete" case), and as soon as every pinged pair has stepped it rotates again, so the new chain is wrapped under exporters from the healed roots. A pair that never answers is pinged at the next rotation. With several devices on one side, the wrap table's single PQ slot per unit may step another pair first; such a pair is retried the same way. Test `pre_rekey_pq_step`.

### 5.3 Exporter key

For each recipient device `r`, `s` uses its pairwise session with `r`:

```
k  = chain_index of the most recent chain in (s, r) created by r        # r certainly has its RK snapshot
e  = epoch of the most recent PQ epoch in r's send direction as seen by s   # r has this P as its pq_s snapshot
K_exp = KMAC256(P_e ‖ RK_k, T(group_id, u32(epoch), u8(generation)), 256, "enclave/v1/proto/grp-export")
```

This is PLAN's `K_exp = KMAC(PQ_epoch_secret‖DR_root, "grp-export"‖group_id‖epoch)`. Both `RK_k` and `P_e` come from the snapshots kept by `05-ratchet.md` §2 (at most 4 each, 7-day expiry). The entry carries `k mod 2^16` and `e mod 2^16` so that `r` can find them.

### 5.4 Broadcast contents

```
kb     = HedgedRng.fill("grp-rekey-kb", 32)
common = Seal(kb, E("enclave/v1/wire/ad-rekey-common") ‖ group_id ‖ u32(epoch) ‖ sender_device_id ‖ u8(generation),
              new_cs_0 (32) ‖ u8(generation) ‖ u8(flags) ‖ new_epoch_secret or random (32)
              ‖ u32(new_epoch) ‖ state_hash (32) ‖ 0^26)                           # 128 B plaintext, 200 B sealed
for each recipient device r (every device of every other member, and this account's other devices):
    j   = account of r
    pad = KMAC256(K_exp_r, "", 512, "enclave/v1/proto/grp-rekey-pad")
    ct  = (kb ‖ mac_key[s→j]) ⊕ pad                             # own-account devices get 32 zero bytes as MAC key
    chk = KMAC256(K_exp_r, ct, 96, "enclave/v1/proto/grp-rekey-check")
    entry_r = u16(k) ‖ u16(e) ‖ chk (12) ‖ ct (64)              # 80 B
```

Each entry is about 72 B of key material plus 8 B of indexing (PLAN: "about 72 B per device").

### 5.5 Buckets

- `bucket(r) = u16(KMAC256(k_bucket, device_id_r, 256, "enclave/v1/proto/grp-bucket-index")[0..2]) mod 3`, where `k_bucket = KMAC256(epoch_secret, "", 256, "enclave/v1/proto/grp-bucket")`. Only members can compute it.
- A rekey is always **exactly 3 rekey units**, one per bucket, each holding up to 174 entries (`08-envelope.md` §8). Unused entry positions are random.
- If a bucket has more than 174 entries, the excess goes to the next bucket (`b + 1 mod 3`). Capacity is 522 ≥ 500.
- Unit `b` is written to the bucket sub-mailbox `gbkt(d, b) = KMAC256(k_bucket, u32(d) ‖ u8(b), 256, "enclave/v1/net/grp-rekey-mailbox")` for the current day `d`. A device fetches only its own bucket's sub-mailbox (and the next one only if its entry is not found).
- A device learns that it needs a rekey when it sees a message header from `s` with a generation it does not have. It then fetches its bucket.
- **As implemented** (polling): a shaped client (`Client::sync_round_every`) reads one group per group round, and for each held epoch reads today's message mailbox and all three bucket sub-mailboxes, each in an ordinary poll slot (`09-transport.md` §6.7); yesterday's are read too during the first 2 h of the UTC day. Reading every bucket keeps which bucket is ours hidden from the server, at three polls instead of one.

Cost: 3 units per rotation for 100 members × 5 devices, versus about 500 units for pairwise delivery.

### 5.6 Processing a rekey entry

```
for each entry in the fetched bucket unit (and the next bucket if needed):
    look up snapshots RK_k, P_e by (k, e); if missing, continue
    K_exp = …; chk' = KMAC256(K_exp, entry.ct, 96, …)
    if ct_eq(chk', entry.chk):
        (kb, mac_key) = entry.ct ⊕ KMAC256(K_exp, "", 512, …)
        common = Open(kb, AD, common)                       else drop rekey
        install sender chain (s, generation) and mac_key; if new epoch: install epoch secret
        return
report "missing rekey from s" locally; ask s with a pairwise control message after 60 s
```

## 6. Cadence summary

| Event | Who rotates | When |
|---|---|---|
| Member removed | The remover | Immediately (new epoch) |
| Member or device added | The adding admin | Immediately (new epoch) |
| Device list of a member changes | That member | Immediately (new epoch); others before next send |
| Other members after an epoch change | Each member device | Before its next send |
| Lazy | Each sender device | First send after 24 h or 200 messages |
| "Secure my account" | That account's devices | Immediately |

**Group post-compromise security is one epoch** (or one generation for a single sender's chain), documented in the help.

## 7. Group state

### 7.1 Contents

The state is a canonical Protobuf message (`08-envelope.md` §5.6 limits) with: `group_id`, `epoch`, name, avatar (blob pointer), disappearing timer, join policy (invite links on/off, admin approval on/off), "only admins can send", member list (per member: `root_hash`, member index, role admin or member, joined time, group-scoped request capability, current manifest hash), and host server.

### 7.2 Hash chain

```
state_hash_0 = ID256("enclave/v1/proto/grp-state", 0^32 ‖ H512(creation_update))
state_hash_n = ID256("enclave/v1/proto/grp-state", state_hash_{n-1} ‖ H512(update_n))
```

### 7.3 Updates

- A state update is a group message with flag `STATE_UPDATE`. Its MAC vector uses the **admin MAC** label: `KMAC256(mac_key[s→j], H512(covered), 128, "enclave/v1/proto/grp-admin-mac")`. Receivers accept it only if the sender is an admin in the parent state (or the update is a member leaving, which any member may post about themselves).
- On-the-record groups additionally require a composite signature with use label `enclave/v1/proto/grp-admin-sig` over `group_id ‖ state_hash_{n-1} ‖ H512(update_n)`.
- **Every membership change is shown in the chat** as an inline event ("Alex added Priya.") with no option to hide it.
- If the last admin leaves, the longest-standing member (earliest `joined`, ties broken by lowest `root_hash`) is promoted automatically by every client.

### 7.4 State hash and causal frontier on every message

- Every group message carries, inside its body seal, the sender's current `state_hash` (32 B) and a **causal frontier**: for each member index 0 to 99, the 8 B `grp_msg_id` of the last message the sender has seen from that member (zero if none). 100 × 8 = 800 B.

  ```
  grp_msg_id = ID256("enclave/v1/proto/grp-msg-id", group_id ‖ u32(epoch) ‖ u8(member) ‖ u8(device) ‖ u8(gen) ‖ u32(counter))[0..8]
  ```

- A receiver compares the message's `state_hash` with its own and checks that every frontier entry names a message it has seen (or one it is missing, which triggers a fetch). If a mismatch persists for more than 10 minutes, the chat shows: "Some people in this group may be seeing different messages." (RT-11)
- **Forks:** two valid updates with the same parent resolve by lowest resulting `state_hash`. The losing update's author re-applies its change on top of the winner if it is still valid, and the UI shows the result.

### 7.5 Polls

A poll close carries `tally_hash = H512(E("enclave/v1/proto/poll-tally-hash") ‖ poll_id ‖ canonical_tally)`, authenticated by the poll creator. In On-the-record groups the creator signs it with use label `enclave/v1/proto/poll-tally`. In Off-the-record groups the close message's MAC vector authenticates it (deniable).

**As implemented** (`client/polls.rs`): polls, votes and closes are ordinary group messages with the new flag `FLAG_RICH` (0x02, inside the sealed and MAC-authenticated sender header), content `u8 kind ‖ …`: `1` poll (`poll_id (16) ‖ question ‖ u8 n ‖ n options`, 2–10 options of at most 200 B), `2` vote (`poll_id ‖ u8 choice`), `3` close (`poll_id ‖ tally_hash (64)`). `tally_hash = SHA3-512("enclave/v1/proto/poll-tally-hash" ‖ poll_id ‖ u32 count per option)` (the label is hashed as a prefix, not framed). A member's later vote replaces their earlier one; votes after the close, votes for options that don't exist and closes from anyone but the creator are ignored. Every member compares the creator's tally hash with the tally they counted; a mismatch is shown ("some votes may not have reached everyone"). Only the poll opens a line in the conversation; votes update it (`Event::PollChanged`). Test `polls_in_groups` includes a close that missed a late vote. Not done: the On-the-record signature, polls in 1:1 chats, anonymous polls.

### 7.6 Message ids and pinned messages

**As implemented** (`client/groups.rs`, `client/pins.rs`). Every group text message now starts with a 16 B id the sender picks at random: content `id (16) ‖ UTF-8 text`. Every member stores it with the message, so later messages can name it; a second copy of an id already stored is dropped. A poll's id is its poll id.

Any member can pin or unpin a message for everyone with a `FLAG_RICH` message of kind `4`: `id (16) ‖ u8 on`. It is sealed and MAC-authenticated like any group message, so outsiders learn nothing and members can't prove to others who pinned what. At most three messages stay pinned per conversation, most recently pinned first; pinning a fourth drops the oldest. Each device keeps the pins it has received (`Event::PinsChanged`), and a pin naming a message the device never received is ignored, so someone who joins later sees no earlier pins, just as they see no earlier messages. 1:1 conversations use `Content::Pin { target, on }` (content kind 18), copied to our other devices like reactions, and a message deleted for everyone drops out of the pins. The app shows the latest pin in a bar above the conversation, with the count, and a **Pin** / **Unpin** action on a selected message. Test `pinned_messages`.

Reactions, edits and deletes (`client/group_edits.rs`) are `FLAG_RICH` kinds `5` (`id ‖ emoji`, at most 32 B; empty removes the reaction), `6` (`id ‖ new text`) and `7` (`id`). Each member keeps one reaction per member on a message; a later one replaces it. Edits and deletes are advisory, as in 1:1 conversations (`docs/16-features.md`): receivers apply them only to the sender's own messages, edits only within 24 hours of the original and never to a poll, and a deleted message loses its text and reactions and drops out of the pins. The app offers the same reaction row, **Edit** and **Delete** on a selected group message as in a 1:1 conversation (`Event::GroupMessageChanged`). Test `group_reactions_edits_deletes`.

Photos and files (`client/group_files.rs`) work as in 1:1 conversations (`08-envelope.md` §9): the sender seals the file in chunks padded to a size bucket and uploads them to its own server at random chunk IDs; the group message is `FLAG_RICH` kind `8`, `id ‖ attachment reference ‖ caption`, so the server sees only another unit. Each member downloads every chunk of the bucket when they open it (pictures from members are fetched and decoded in `mediad` for previews, as for contacts) and checks the hash. Deleting for everyone drops the reference. Test `files_in_groups`. Pins, like messages, from our other devices apply as ours (note 6). Not done: a list of every pinned message, and jumping to the pinned message.

## 8. Post-compromise security

- A device compromise that ends is healed for that device's outgoing messages when it next rotates (new `cs_0` and MAC keys, distributed under fresh `K_exp` after the pre-rekey PQ step).
- It is healed for incoming messages when every other sender rotates, which the next epoch change forces.
- Removed members lose access at the new epoch: they receive no rekey entry, and the mailbox address changes.

## 9. Joining

- **Invite links** carry a capability in the URL fragment: `https://<invite-host>/g#<payload>`, where the payload holds `group_id`, an admin's contact fields (as `03-identity.md` §9.2), and `grp_invite_secret`. `grp_invite_cap = KMAC256(grp_invite_secret, "", 256, "enclave/v1/proto/grp-invite-cap")`.
- Links are limited-use (default 1 use for links sent to contacts), expire (default 7 days), and can be revoked by any admin. **Admin approval is on by default.**
- Flow: the joiner sends a `JoinRequest{grp_invite_cap}` to the admin as a first-contact message (`04-eqxdh.md`). The admin (after approval, if required) posts a state update adding the joiner, starts a new epoch, and sends the joiner the state and epoch secret over their pairwise session.
- The joiner then establishes pairwise sessions with every member device, starting with `kem_count = 2` (group-only peers, `04-eqxdh.md` §8), using each member's group-scoped request capability so these first contacts are not shown as message requests. Joining costs about 99 × 60 KB ≈ 6 MB of manifests and bundles in bulk mode, with a progress bar.
- **New members cannot read history from before they joined.** They receive no chain seeds from earlier epochs.

**As implemented** (`client/invites.rs`):

- A group invite link is the admin's contact invite link (`03-identity.md` §9.2 as implemented: one-way PSK, request-inbox capabilities in place of proof of work, limited uses, 7 days, cancellable) bound to the group: `enclave:join#` + base64url(`u8(1) ‖ bytes(card v2) ‖ group_id (32) ‖ bytes(name)`). The admin's stored invite records the group and whether joins need approval; there is no separate `grp_invite_cap` and no `JoinRequest` message: the greeting through that invite *is* the join request. Only admins make links (`create_group_invite`).
- The admin's client turns such a greeting into `Event::JoinRequest { root, group, name }` instead of a message request. With approval (the default, and the only choice in the app) it waits: **Accept** (`approve_join`) accepts the conversation and adds them with `add_group_members`, which starts a new epoch first, so they read nothing from before; **Decline** (`decline_join`) drops them silently. Without approval, the same happens on arrival.
- The joiner (`join_group`) greets the admin through the link and shows "Waiting to join <name>" until the group's welcome arrives. Someone who already talks to the admin can't use a link (an existing conversation carries no invite) and is told to ask to be added.
- The app: admins get **Copy invite link** in the members sheet; join requests appear among message requests as "Asks to join <group>"; the Add field takes `enclave:join#` links. Test `group_invite_links` covers approval, no history before joining, non-admins refused, joining without approval, and declining.
- Not done: links from non-creating admins surviving the creator leaving, choosing uses or approval in the app, and the group-scoped request capabilities for member-to-member first contact (introductions still go through the existing group-introduction path).

## 10. Errors

| Condition | Action |
|---|---|
| MAC entry fails | Drop |
| Unknown generation | Fetch bucket; hold the message up to 7 days |
| State update from a non-admin | Drop; show nothing |
| State hash mismatch > 10 min | Inline warning (§7.4) |
| Rekey entry not found in bucket or next | Ask the sender after 60 s |
| Group exceeds 100 members | Refuse the add with "Groups can have up to 100 people." |

## Implementation notes (M7)

`crates/enclave-proto/src/group.rs`, tests in `crates/enclave-proto/tests/group.rs`. Where this section and the text above differ, this section describes the code.

1. **Stable member indices.** Removing a member leaves a tombstone slot (`active = false`) that a later joiner can reuse. Indices never shift, so MAC-vector positions computed from the sender's state stay valid while an update is in flight.
2. **Exporter key.** `K_exp` is derived from the pairwise session's PQ root history instead of retained DR root snapshots (open question 3): the sender uses the newest root of the recipient's sending direction (`Session::export_for_peer`), and the recipient looks up the same root by its epoch in its own history of 16 (`Session::export_from_peer`). Every root comes from ML-KEM-1024 steps seeded by the handshake, so the key is post-quantum and heals with each PQ round trip. The entry carries the epoch as a `u32`.
3. **Header protection** (resolves `08-envelope.md` I-14). The sender identity, state hash and causal frontier are encrypted under a KMAC256 keystream keyed by the epoch's header key and a per-unit 32 B nonce. The MAC vector (over `unit[0..920] ‖ unit[2504..]`) authenticates them. The server sees only the epoch number and the unit kind.
4. **Rekey units.** Layout: clear header 16 (kind Group, subkind 1, bucket, announce epoch) ‖ nonce 32 ‖ encrypted sender 40 (member, device, generation, flags, target epoch) ‖ common blob 192 (sealed under `kb`, AD = header with the bucket byte zeroed) ‖ 174 × 80 B entries ‖ random padding. Entries are shuffled within each bucket.
5. **New epochs.** A rotation that starts an epoch is announced under the previous epoch, which current members hold; a removed member can read the header but finds no entry. A joiner never gets the previous epoch: its welcome (sent pairwise) carries the state, the new epoch secret, and the welcoming admin's current chain seed and MAC key for the joiner.
6. **Own-account messages** are marked `own_account` and not MAC-checked (there is no entry for the sender's own account, and every member holds our chain key, so anyone in the group could forge one). The client holds one until the device that sent it vouches for its id through own-device sync (`GroupSent`, flushed at its next sync), then shows it as our own (no sender name, not counted unread); reactions, edits, deletes and pins from our other devices apply as ours the same way.
7. **Client** (`enclave-core/src/client/groups.rs`): the creator sends each member a welcome and the members' contact cards over pairwise sessions. Members who are not contacts introduce themselves through the group: a Hello naming the group is accepted automatically when the sender is a member, and such contacts stay out of the conversation list. Each sync polls the mailbox and the three rekey buckets of every held epoch for today and yesterday; units that cannot be processed yet (unknown epoch or generation, sender not yet reachable) are held and retried. A sender rotates before its first send, when its chain is due, and whenever a member it has not yet keyed becomes reachable. Group mailboxes are created by their first write; the write token is the mailbox's owner secret, so every member can write and read (`FLAG_GROUP`).
8. **Adding members** (`Client::add_group_members`, admins only): a new epoch first, so newcomers can't open anything sent before they joined; a rotation announced under the previous epoch keys current members; the state update is posted in the new epoch; each newcomer gets a welcome and every member's card pairwise; existing members get the newcomers' cards. A card from an admin is kept even when the state update that adds its owner hasn't been read yet (the inbox is read before group mailboxes); introductions only ever go to active members.
9. **App:** create a group from accepted contacts, a members sheet (who's in it, checked or met in person), admins add and remove people, and anyone can leave with an inline confirmation.
10. **Our other devices** (`client/group_devices.rs`, `06-multidevice.md` §5): each device uses its index in our manifest as its group device index. A device that holds a group hands it to each of our other active devices that lacks it (a newly linked one, or after this device created or joined it): its whole view (epoch secrets, receiving chains, member cards, mailbox positions) with its own sending chain turned into one the other device receives (`Group::hand_over`), as a sealed file whose reference goes in an own-sync item naming that device. The other device starts a chain of its own at its first send, and every rotation keys our other active devices too (rekeys between our own devices carry no MAC key). Group history is not handed over. Test `groups_on_every_device`.
11. **Not implemented yet:** On-the-record signatures, hosting moves. (The pre-rekey PQ step, polls, invite links and join requests have since been built: §5.2, §7.5, §9.)

## Open questions

1. Own-device messages are not covered by the MAC vector (§3). The fix chosen here (confirm through own-device sync) delays display of one's own messages sent from another device by up to 60 s. An alternative is to reserve one MAC-vector entry for the sender's own account, which requires 100 entries (1,600 B) and changes the group envelope budget.
2. In Off-the-record groups PLAN §7 says poll closes are "signed by the poll's creator". A signature would make the creator's poll results non-deniable, so this spec uses the MAC vector there and a signature only in On-the-record groups.
3. Resolved in M7: the exporter uses the PQ root history, which is already retained (implementation note 2). The formal model must still confirm it.
4. Group-scoped request capabilities (§9) are a new object not named in PLAN; they let a joiner reach members without PoW. Their abuse limits (per group, per day) need to be set.
