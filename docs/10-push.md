# Push and Notifications

Status: Draft (M0) · Normative

Source: PLAN.md §10. Crates: `enclave-push-relay`, `enclave-server` (push forwarder), `enclave-nse` (iOS), `enclave-platform`. Capsule layout: `08-envelope.md` §5.4. Platform limits: `15b-platform-constraints.md`.

## 1. Architecture

```
Enclave server (inbox write) ──Nym──▶ push relay (project-run) ──TLS──▶ APNs / FCM / UnifiedPush ──▶ device
```

- The push relay is **run by the project**, because APNs and FCM accept only the publisher's credentials.
- Servers reach the relay **through Nym**, so the relay cannot tell which server is waking which device.
- **Maximum privacy disables push entirely.** As implemented: `Client::register_push` refuses in Maximum, and turning Maximum on asks the server to forget any token (`engine.rs`, test `maximum_has_no_push`).

## 2. Token registration (RT-20)

```
RegisterPush(inbox_addr, platform_token):
    (eph, ct) = fresh X448 + ML-KEM-1024 encapsulation to the relay's current key
    ss_push = Combine2(… transcript = E("enclave/v1/net/push-transcript") ‖ relay_id ‖ u32(relay_key_epoch))
    k_push  = KMAC256(ss_push, "", 256, "enclave/v1/net/push-seal")
    sealed  = u32(relay_key_epoch) ‖ eph_pk ‖ ct
              ‖ Seal(k_push, E("enclave/v1/wire/ad-push-token") ‖ u32(relay_key_epoch),
                     platform (1) ‖ token_len (2) ‖ token (≤ 256, zero-padded) ‖ wake_class (1))
    send PUSH_REGISTER(inbox_addr, read_cred, sealed)          # 08-envelope.md §2.2
```

- The sealed token is **re-randomized on every registration** (fresh encapsulation and hedged nonce), so the server never sees the plain token and two mailboxes of one device cannot be linked through it.
- A device registers a fresh sealed token for each mailbox it wants wakes for (account inbox; optionally group mailboxes) and re-registers at every weekly address rotation.
- The relay's key rotates every 30 days with a 7-day overlap; its public key is in the foundation's signed list.

## 3. Rate shaping

At the **server** (push forwarder):

- when an envelope is written to a mailbox with a registered sealed token, the server schedules one wake for that sealed token in the current **60 s window** (windows aligned to trusted time);
- at most **one wake per sealed token per window**;
- each wake is released at a uniformly random offset of **0 to 30 s** into the window;
- wakes are sent to the relay over Nym as a `PUSH_WAKE` message holding the sealed token and, for iOS previews, the envelope's capsule (1,024 B).

At the **relay**:

- the relay opens the sealed token, enforces the same one-wake-per-window rule per platform token, and forwards to APNs, FCM, or the UnifiedPush endpoint;
- the relay keeps no logs beyond per-minute counters.

## 4. Notification keys and capsules

- Each account gives each contact a notification key root `nk_0` in `SessionSetup`. Keys advance daily: `nk_d = KMAC256(nk_{d−1}, u32(d), 256, "enclave/v1/proto/notify-key")` (`02b-key-schedule.md` §7). Both sides step the chain; the recipient's NSE keeps today's and yesterday's key and deletes older ones.
- Group capsules use `gnk(d) = KMAC256(epoch_secret, u32(d), 256, "enclave/v1/proto/grp-notify")`.
- **Capsule contents:** sender name plus up to 600 B of preview (`08-envelope.md` §5.4), sealed under today's key. The capsule is always 1,024 B and is **random bytes when unused**, so neither the server nor Apple can tell whether previews are on.
- A sender fills the capsule only if the recipient has told it (in `SessionSetup` or a settings control message) that previews are on. The sender never learns whether a push was actually sent.

## 5. Platform matrix

| Platform | Default | Opt-in |
|---|---|---|
| Android (F-Droid) | The always-on Background profile in a foreground service. No FCM. | UnifiedPush (self-hostable distributor) |
| Android (Play) | Same, if Play policy accepts the `specialUse` or `remoteMessaging` foreground-service type (checked in the M1.5 spike). Otherwise FCM content-free wakes plus Poisson dummy wakes (mean 1 per hour) sent by the client's own server through the relay. | "Battery saver delivery" (FCM) |
| iOS | APNs **generic alert** ("New message"). Content is fetched when the app opens. | **Show previews**: the capsule is decrypted by the Rust NSE with symmetric crypto only, well within 24 MB / ≈30 s. The NSE never runs arti or Nym. |
| iOS dummy wakes | Only if Apple grants `com.apple.developer.usernotifications.filtering` (requested at M6): the relay sends Poisson dummy wakes that the NSE suppresses. Otherwise jitter only. | |
| iOS calls | PushKit VoIP → CallKit (mandatory and disclosed). CallKit is unavailable in China; the app falls back to a notification there (unverified). | Maximum: calls ring only while the app is open |
| Desktop | Background profile while running | |

### 5.1 iOS NSE algorithm

```
NSE(payload):                                   # runs in the Notification Service Extension
    if payload has no capsule or previews are off: show "New message"; return
    for each contact c (and each group g) with a key for today or yesterday:
        p = Open(nk, E("enclave/v1/wire/ad-capsule") ‖ u32(day), capsule)
        if p is Ok: show "{name}: {preview}" with the conversation hint; return
    show "New message"
```

- The NSE loads only the notification key table (a small sealed file in the shared app-group container, readable by the NSE, containing no ratchet or identity keys).
- Trial decryption over all contacts is bounded: at 1,000 contacts × 2 days, 2,000 tag checks of a 1 KB capsule, well under 1 s.
- The NSE never writes the decrypted preview to disk.

### 5.2 Notifications off

A user may turn notifications off entirely. The device then registers no push tokens.

## 6. What each party learns

| Party | Learns |
|---|---|
| Home server | That a mailbox has a registered sealed token; wake counts per window |
| Push relay | Platform token and wake timing in 60 s windows; nothing about inbox or server |
| Apple / Google | Wake timing per device; capsule ciphertext (always present) |

## 7. As implemented (`enclave-push-relay`, server push forwarder)

- **Sealed tokens** (`enclave_push_relay::seal_token`): `u32 epoch ‖ X448 ephemeral (56) ‖ ML-KEM-1024 ct (1,568) ‖ Seal(k, "enclave/v1/wire/ad-push-token" ‖ u32 epoch, platform (1) ‖ u16 len ‖ token padded to 256 ‖ wake_class (1))`, where `k = KMAC256(Combine2(dh, ss; "enclave/v1/net/push-transcript" ‖ eph ‖ ct ‖ relay keys ‖ epoch), "", 256, "enclave/v1/net/push-seal")`. Every sealed token is 1,952 B whatever the platform or token length, and every sealing is fresh. Platforms: UnifiedPush (the token is the endpoint URL), APNs, FCM.
- **Registration**: `Client::register_push(relay key, platform, token)` sends `Op::PushRegister` (10) for the account inbox, authenticated like token registration by the inbox owner credential; an empty payload removes it (`unregister_push`). The server stores the sealed bytes and can't open them.
- **Server shaping** (`Server::due_wakes`): a write to an inbox with a sealed token schedules one wake per sealed token per window, released in the **next** 60 s window at a random 0–30 s offset (the spec says the current window; the next one decouples the wake's time from the write's, at the cost of at most 90 s). Each wake is handed out once. The server forwards due wakes over TCP on the stack's network (`[push] forward`, or `--push-relay HOST:PORT` in `dev`) as `u32 len ‖ sealed token`.
- **Over the mixnet** (`enclave-ingress`, `enclave_nym::frame::Wake`): the server forwards to the stack's **push egress** (`enclave-ingress forward`, compose service `push-egress`), which sends each wake one way, with no reply blocks and a fresh mixnet identity each start, to every push relay address it's given (`--to`, from the foundation's list); a relay that holds no key for a wake drops it. A wake on the mixnet is `u8(1) ‖ u8(4) ‖ u16 len ‖ data`, zero-padded to 3,074 B, room for the sealed token and later the 1,024 B preview capsule (P6). The relay's **push ingress** (`enclave-ingress oneway`, compose service `push-ingress`, profile `push`) has a persistent identity, writes its address to `public/push-ingress.addr` for the list, hands each wake to the relay on the same TCP framing, and drops anything that isn't a wake. The relay sees neither the server's address nor its stack's identity. Test: `wakes_cross_the_mixnet_one_way` (`crates/enclave-ingress/tests/mixnet.rs`).
- **Relay** (`Relay::wake`): opens the token with any key it holds for that epoch, enforces one wake per *platform token* per window (two sealings of one token count as one), keeps no logs, only the counters `forwarded` and `shaped`, and forgets windows older than two. UnifiedPush delivery is a content-free `POST` (`Content-Length: 0`, `TTL: 60`); only `http://` endpoints for now.
- **Relay keys** (`keys::RelayKeys`): one key per 30-day epoch (`epoch = day / 30`), derived from a forward-secure seed chain in `push-relay-chain.key` (`enclave_service::SeedChain`): epoch `e`'s key is `KMAC256(seed_e, u32(e), 960, "enclave/v1/push/relay-key")` split into the X448 secret and the ML-KEM-1024 seed, and `seed_{e+1} = KMAC256(seed_e, "", 256, "enclave/v1/push/relay-chain")`. The relay holds the current epoch's key and, for the first 7 days of an epoch, the previous one; then the previous seed is erased from memory and disk. `published()` is the current and the next epoch's public keys, which `run` writes to `public_dir/push-relay-keys.bin` for the foundation's list, so devices can seal to the next key before it takes over. Keys are deterministic, so a restarted relay holds the keys it published. The window table is in memory: a restart can let one extra wake per token through in that minute.
- **Binary**: `enclave-push-relay init|run|show-key|healthcheck [--config FILE]` with `[relay] listen` (default `127.0.0.1:7445`), `keys_dir`, `public_dir` and `ENCLAVE_RELAY__*` overrides; `dev [--listen ADDR]` keeps the old random-key mode.
- Tests: `enclave-push-relay` (sealing, re-randomization, fixed size, wrong key, tampering, window shaping, HTTP delivery, key persistence, rotation and the 7-day overlap) and `push_wakes` in `enclave-core` (two messages in a window give one wake, the server never sees the endpoint, unregistering stops wakes).
- **Notification keys and capsules** (`enclave_proto::notify`, `client/notify.rs`): Settings → Notifications → **Show previews** gives every accepted contact a fresh chain root and its day (`Content::NotifyKey`, kind 35, with `previews`); new contacts get one at the next sync, and turning previews off tells everyone (`previews: false`) and forgets our chains. A sender holding a chain with previews on steps it to today (forgetting older keys) and seals into the envelope's capsule `Seal(nk_d, "enclave/v1/wire/ad-capsule" ‖ u32(d), u8 len ‖ name (≤ 64 B) ‖ u16 len ‖ preview (≤ 600 B, cut at a character) ‖ zeros)` to exactly 1,024 B; the preview is the text, a file's caption or "Sent a file", "Sent a sticker", "Shared a location", or "New message", and control content keeps a random capsule. Our own chains are stepped daily to yesterday. The server hands each wake out as `sealed token ‖ capsule` (2,976 B; the capsule of the newest envelope in the window, random for an envelope without one), the mixnet wake frame carries it, and the relay's `Delivery` has it for APNs (the extension opens it; UnifiedPush stays content-free). `Client::notify_table` is the extension's key table (`KeyTable`: for each contact we gave a chain, a label and today's and yesterday's keys; tomorrow's is derived, for a sender whose clock is past midnight), opened by `KeyTable::open` as in §5.1; it holds no ratchet or identity key. "Secure my account" gives everyone fresh chains. Test `previews_in_capsules` (`tests/previews.rs`), and `capsules` in `enclave-proto`.
- **Group capsules and group-mailbox wakes**: a group unit's capsule holds the sender's name and a preview (text, "Poll: …", a caption or "Sent a file", "Sent a sticker"; state updates and votes stay random) under `KMAC256(epoch secret, u32(day), "enclave/v1/proto/grp-notify")` (`Group::seal_with`), and the extension's table holds each group's keys for today and yesterday (`Group::notify_keys`, labelled with the group's name). Each member device registers on today's mailbox of each of its groups, at the group's host (`Op::PushRegister` with `FLAG_GROUP`, authenticated by the mailbox's write token, which creates the mailbox like a first write): `id (8) ‖ sealed token`, sealed afresh for every mailbox so registrations can't be linked, under `KMAC256(device id, mailbox, "enclave/v1/net/push-group-id")[..8]` so a device replaces or removes only its own (at most 256 per mailbox; table `push-group`, kept with its day and swept after two). A write to the mailbox wakes every device registered there. `Client::push_groups` runs from `sync`; unregistering removes today's.
- **Dummy wakes**: a registration with `FLAG_PUSH_DUMMIES` (`register_push_with(…, dummies)`) also gets Poisson dummy wakes at a mean of one an hour (`DUMMY_WAKE_MEAN_SECS`), scheduled and shaped like real ones with a random capsule, so a wake's timing says nothing; the app finds nothing new and shows nothing. The platform glue decides who asks (Android Play builds on FCM, iOS with Apple's filtering entitlement, G6). Table `push-dummy`, schema 9; the schedule is kept in memory and redrawn after a restart.
- **The relay's key from the list**: `register_push_listed(platform, token, dummies)` seals to the foundation's server list's push relay key for this epoch (`listed_relay_key`), which the list signs (S2).
- Tests: `group_wakes_and_dummies` (`tests/previews.rs`).
- **Not done**: APNs and FCM delivery (need the project's credentials), TLS for UnifiedPush endpoints, the iOS NSE itself (I1, which reads `notify_table`), and the platform glue (UnifiedPush distributor on Android, A1).

## Open questions

1. PLAN §10 says Play builds fall back to "FCM content-free wakes plus Poisson dummy wakes (about 1/h)" if the foreground-service type is refused. Who generates the dummy wakes is not stated; this spec has the client's own server generate them through the relay so the relay cannot tell dummy from real.
2. The NSE's key table must be readable by the NSE without the app's master key (the NSE has 24 MB and cannot run Argon2id). This spec stores it sealed under a Keychain item with `AfterFirstUnlockThisDeviceOnly`, which is weaker than the main database's protection. To be reviewed at the M1.5 NSE spike.
