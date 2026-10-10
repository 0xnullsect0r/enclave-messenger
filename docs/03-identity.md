# Identity, Devices, and Recovery

Status: Draft (M0) · Normative

Source: PLAN.md §3 (D3, D4, D12). Crate: `enclave-proto` (manifest, linking), `enclave-core` (flows), `enclave-store` (root wrap). Derivations: `02b-key-schedule.md` §2 to §5, §11.

## 1. Account creation

1. The client generates the recovery secret `rs = HedgedRng.fill("recovery", 32)` and derives the root key pair (`02b-key-schedule.md` §2.1).
2. It generates the device keys (§3.2), the account IK, the vault key and `vbs`, the inbox seed, the request-inbox address, and the first prekey batch.
3. While the user types a display name, it solves an Equi-X proof-of-work for account creation (target 20 to 30 s on a median phone, `02-cryptography.md` §10) against the chosen server's daily seed. The UI shows one line: "Setting up your private address…". The PoW is presented with the first directory publish.
4. The server is chosen automatically, weighted by capacity from the foundation's signed server list (`12-servers.md` §4). The user can change it.
5. The client builds manifest version 1 (§3), root-signs it, and publishes the manifest, the account bundle object (`04-eqxdh.md` §2), the vault-key blob, and the OPK batch to the directory. It registers the inbox (this week's and next week's addresses, each with read-credential hashes through the end of the week after its own, `09-transport.md` §3.1) and the request inbox.
6. The recovery words are not shown yet. They are shown as a persistent card after the first conversation or after 24 hours, whichever comes first (`17-design.md` §6.1). The words MUST be saved (the 3-word check passed) before the user can link a device or claim a username.

Account creation MUST NOT require a phone number, email, or any other identifier.

## 2. Recovery secret and root key

- `rs` is 256 bits, shown as 24 BIP-39 words with the BIP-39 checksum (`recovery::RecoverySecret`), in any of BIP-39's ten lists (English, Spanish, French, Italian, Portuguese, Czech, Japanese, Korean, Simplified and Traditional Chinese; `to_words_in`). The words stand for the same secret in every list, so the account is the same whichever was written down; the recovery-words sheet shows them in the list the person picks (setting `words-language`, English by default). Import finds the list from the words and ignores case, extra whitespace and Unicode form, and MUST reject a failed checksum with "These words don't match. Check each word and try again." Test `every_language`. Showing the CJK lists needs fonts for those scripts, which ship with L2 (`18-a11y-i18n.md`).
- The root is derived as `SLH-DSA.KeyGen(KMAC256(rs, "", 768, "enclave/v1/root/keygen"))` (`02b-key-schedule.md` §2.1). `AccountKeys::create` derives it, generates the X448 identity key, and generates the McEliece vault key (a few seconds; run in the background).
- **Not implemented yet:** storing `rs` wrapped on the primary device under `k_root = KMAC256(hw_root_secret, Argon2id(PIN), 256, "enclave/v1/store/root-wrap")` (`14-storage.md` §1.3), where both the hardware key and the PIN are needed and biometrics MUST NOT unlock root operations.
- Root operations unwrap `rs`, derive the root secret key, sign, and zeroize both within one call in the vault process. Linked devices without the "may add devices" role hold no root key (`AccountKeys.root` is `None`).

## 3. Account manifest

The manifest (`manifest.rs`) is the only object the root signs day to day (D3). It is hash-chained, versioned, and valid for at most 13 months (395 days, `MAX_VALIDITY_SECS`).

### 3.1 Contents

- version (starting at 1) and the SHA3-512 hash of the previous signed manifest (zero for version 1);
- issue and expiry times;
- the root public key;
- the account X448 identity key (the only X448 identity key; `00-overview.md` §9, I-8);
- `vault_hash = SHA3-512(vault_pk)`;
- the request-inbox locator (opaque bytes, at most 256 B);
- the bundle epoch (1 in the genesis manifest);
- 1 to 5 device entries (1 primary plus up to 4 linked), each with: device ID, role, time added, capability bits, composite signing public key, and ML-KEM-1024 auth key.

The account inbox address, its owner secret and read credential are **never** in the manifest or in KT. Contacts receive the inbox address and tokens inside the encrypted session.

### 3.2 Encoding (manifest format 1)

The canonical encoding (`Manifest::encode`) is variable-length; all integers are big-endian:

| Field | Length |
|---|---|
| format | `u16` = 1 |
| `version` | `u64` |
| `prev_hash` | 64 |
| `issued_at` | `u64` |
| `expires_at` | `u64` |
| root public key | 64 |
| account X448 identity key | 56 |
| `vault_hash` | 64 |
| request-inbox locator | `u32` length ‖ bytes (≤ 256) |
| `bundle_epoch` | `u64` |
| device count `n` | `u8` (1 to 5) |
| `n` device entries | 4,250 each |

Device entry (4,250 B): device ID 16 ‖ role `u8` (1 primary, 2 linked, 3 linked and may add devices) ‖ `added_at` `u64` ‖ capability bits `u64` ‖ composite public key 2,649 ‖ ML-KEM-1024 auth key 1,568. 16 + 1 + 8 + 8 + 2,649 + 1,568 = 4,250.

The body is 287 + `L` + 4,250·`n` bytes for an `L`-byte locator (`math/envelope-budget.md` §8.2).

The signed form (`SignedManifest`) is

```
signed = u32(len(body)) ‖ body ‖ SLH-DSA-SHAKE-256s signature (29,792 B)
signature = RootSign(root_sk, ctx = "enclave/v1/ctx/manifest", body)
hash(signed) = SHA3-512(signed)                     # the next manifest's prev_hash
```

34,365 B for one device and a 32 B locator; 51,365 B for five devices (PLAN: "about 52 KB").

### 3.3 Manifest update cosignatures

Every manifest update the primary makes (linking, removing a device) is co-signed by the primary's device key, which the previous manifest lists; an update without such a co-signature is held for 72 h (§8.1). Implemented as `enclave_proto::attest` (§8.1, "Implementation").

### 3.4 Validation

`Manifest::decode` rejects, in addition to malformed encodings and trailing bytes: format ≠ 1; version 0; `expires_at ≤ issued_at`; a validity longer than 395 days (`Expired`); zero or more than 5 devices (`Limit`); duplicate device IDs; anything other than exactly one primary device; a locator over 256 B; an unknown role; an invalid Ed448 point in a composite key.

`SignedManifest::verify(expected_root, now)`:

1. decode the body (above);
2. the manifest's root equals `expected_root`, the root the caller already trusts (from a QR code, an invite link, or a KT lookup) (`BadSignature`);
3. the SLH-DSA signature verifies with ctx `enclave/v1/ctx/manifest` (`BadSignature`);
4. `now + 48 h ≥ issued_at` and `now ≤ expires_at + 48 h` (`SKEW_SECS`; `Expired`).

`SignedManifest::verify_successor(previous, expected_root, now)` additionally requires `version > previous.version` and, when `version = previous.version + 1`, `prev_hash = hash(previous)` (`Rollback`). A jump of more than one version is accepted without checking the intermediate chain.

`now` is trusted time where available (the median witness time, `12-servers.md` §3.4). ML-KEM auth keys are validated when used, not at decode.

## 4. Device linking (RT-09)

### 4.1 Link QR code

The new device shows a link QR code. Its URI uses a distinct scheme, `enclave-link:`, followed by base32 (RFC 4648, no padding) of:

| Field | Length |
|---|---|
| version 0x01 | 1 |
| ephemeral X448 public key | 56 |
| ephemeral ML-KEM-1024 ek | 1,568 |
| `link_secret` | 16 |
| rendezvous server ID | 32 |
| rendezvous mailbox address | 32 |

1,705 B in total (QR version 32 or larger at error-correction level L; the new device's screen shows it large).

### 4.2 Where it can be scanned

- The link QR MUST be accepted only by the scanner opened from **Settings → Your devices → Link a new device** on a device whose role is primary or "may add devices".
- The general scanner, the contact-add scanner, deep links, and pasted text MUST refuse `enclave-link:` URIs and show: "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one." (`17-design.md` §6.6).
- Contact QR codes (`enclave:` scheme, §9.1) MUST be refused by the link scanner with an explanation.

### 4.3 Link protocol

The rendezvous mailbox accepts writes and reads authorized by `link_cap` (`02b-key-schedule.md` §11). It expires after 30 minutes.

1. **P (primary) scans** the QR. P generates an ephemeral X448 key and encapsulates ML-KEM to the QR's ek. It computes `ss_link` with Combine2 using `psk = link_psk`, `psk_flag = 0x03`, and derives `k_p2n`, `k_n2p`.
2. **P → N:** P's ephemeral X448 public key, the ML-KEM ciphertext, and `Seal(k_p2n, E("enclave/v1/wire/ad-link") ‖ u8(1), {root_pk, P.device_id})`.
3. **Phrase check.** Both devices compute the 3-word phrase (`02b-key-schedule.md` §11). N shows the phrase. P shows 4 phrases (the real one plus 3 random decoys, in random order) and asks "Which words does your new device show?". A wrong pick aborts the link, deletes all link state, and shows "The words didn't match, so nothing was linked." After 1 wrong pick the QR is void; N must show a new one.
4. **N → P:** N's device ID, composite public key, auth ek, capabilities, and a user-visible device name (from the OS model name, editable), sealed with `k_n2p`.
5. **P asks for the PIN**, builds the next manifest with N as role 2, root-signs it, cosigns it with P's composite key (§8.1), and publishes it.
6. **P → N** (bulk mode, sealed with `k_p2n` in chunks): the vault key pair and `vbs`, the IK, the inbox seed, the request-inbox address, contacts (root pins, manifests cache, security-code states, bond PSKs), group states, notification key chains, and settings. It does **not** send ratchet state; N establishes its own pairwise sessions.
7. Every existing device of the account and N establish intra-account pairwise sessions (EQXDH between own devices, `06-multidevice.md` §5).
8. **History transfer** begins 24 hours after step 5, unless both devices confirm "Transfer now" sooner. History moves over the LAN when both devices are on it (mDNS discovery, a TCP connection carrying EnclaveSeal chunks under a key derived from the intra-account session), and otherwise as bulk blobs.

### 4.4 After linking

- Every device of the account shows a persistent in-app banner for 7 days: "New device linked: *Pixel 9*, 30 Sep 14:02. Not you? Remove it". "Remove it" starts revocation (§5.1) and requires the PIN on the primary.
- A linked device that has not sent any intra-account sync message for 30 days is treated as inactive: the account's other devices stop wrapping keys for it immediately, and the primary publishes a manifest without it the next time the root is unlocked. The UI asks for the PIN at the next app open when such a removal is pending.
- The device cap is 5 (1 primary plus 4 linked). Linking a sixth device MUST be refused with "You can link up to 4 devices. Remove one first."

### 4.x Implementation status (M5 follow-up)

`crates/enclave-core/src/client/link.rs`, test `link_a_second_device`. Where this differs from §4.1–4.3 above, the code is normative:

- **Code.** `enclave:link#` + base64url of `version ‖ server 16 ‖ mailbox 32 ‖ owner 32 ‖ X448 56 ‖ link_secret 32 ‖ commit 32` (201 B), not base32 with the ML-KEM key inline. The new device writes its ML-KEM ek and device keys (composite signing key, ML-KEM auth key) to the rendezvous mailbox first; `commit` is the first 32 bytes of SHA3-512 of that record, so the QR code stays small and the primary can check it read the right record. The general scanner refuses the code (`ContactCard::from_link` → `DeviceLinkCode`).
- **Key.** `EnclaveCombine(TwoKem, [X448, ML-KEM-1024], [X_new, ek, X_primary, ct, transcript], psk = link_secret)` with transcript `"enclave/v1/proto/link-transcript" ‖ commit ‖ mailbox`. Both screens derive three BIP-39 words (`link-phrase`); the primary shows four choices and links only on the right one.
- **Handover.** The primary signs and publishes manifest `version + 1` (with `prev_hash`), then uploads the account as a sealed blob: profile, shared account keys, the signed manifest, and every accepted contact's card, name, checked state, timer, inbox and **half of its write tokens** (tokens are single use, so each device needs its own). The blob reference travels sealed under `link-keys`.
- **After linking.** The new device publishes its prekeys and opens sessions with every contact's devices (contacts accept them silently: the device is in the root-signed manifest) and with the account's other devices. Every message sent from one device is copied to the others (`Content::SelfCopy`) through the shared account inbox.
- **History transfer** (`client/history.rs`): not part of the link. The device holding the root sends history to a linked device 24 h after it was added (checked on every `sync`), or at once when the person taps "Send history now" on that device. History is one sealed file in our server's blob store (`files::seal_file`, bucket-padded chunks) whose reference goes to our devices as `Content::History` (kind 14). It holds every 1:1 conversation's messages except disappearing and deleted ones: `u8(1) ‖ u32(n) ‖ n × (root (64) ‖ u32(m) ‖ m × bytes(message record))`. A receiver merges it into conversations with contacts it knows, skipping message ids it already has, and renumbers each conversation by time. Sending is recorded per device, so it happens once; a repeat adds nothing. Group history is not sent.
- **After linking, as implemented** (`06-multidevice.md` §5, §7): every device shows a notice for 7 days after a device was linked, with the way to the devices screen; devices show when each other device was last used; a device unheard of for 30 days is inactive (nothing is encrypted to it) and the device holding the root removes it at its next sync. Contacts made after linking reach the other devices through own-device sync, and a contact without a card is asked for it first (`Content::CardAsk`).
- **History, both devices confirm** (`client/history.rs`): the new device asks for history ("Ask for history now", an own-sync item), and only then can the device holding the root send it before the 24 hours ("Send history now"). Test `link_a_second_device`.
- **Groups** reach the new device from a device that holds them (`07-groups.md` note 10).
- **History over the LAN, as implemented** (`client/history.rs`, `enclave-app::lan`): where the app can (the desktop app, `Client::set_history_lan`), the sealed history chunks go window to window first. The vault hands its window the chunks and a one-time token; the window listens on the local network and gives them, in order, to a connection presenting the token; the reference, the token and the window's addresses reach the new device through own-device sync (`HistoryLan`, end to end encrypted, so nothing is announced on the network: no mDNS, unlike step 8's wording). The new device's window fetches the chunks whole and its vault opens them, so only ciphertext crosses the network or either window. It answers `HistoryDone` (fetched or not); on "not", or nothing within 15 minutes, the chunks go through our server as blobs as before, and they always do without the local network. Tests `history_over_the_lan` (including chunks altered on the way, which fall back to the server) and `serves_with_the_token_only`.

## 5. Revocation and "Secure my account"

### 5.1 Revocation

Revocation publishes a new manifest without the device (PIN required on the primary). Contacts learn of it through a ratchet control message and the manifest refresh. Other devices delete their pairwise sessions with the revoked device. If the revoked device was possibly compromised, the UI offers "Secure my account" next.

**Implementation (`client/devices.rs`).** `Client::remove_device(id)` runs only on the device holding the root and never on itself:

1. sign and publish manifest version `v + 1` without the device (`publish_manifest`);
2. send `Content::Devices(v + 1)` (kind 13, `u64` version) to our other devices, the removed one included so it can tell its user, then drop our sessions with the removed device;
3. send the same notice to every accepted contact.

A greeting names the manifest versions its writer saw, of its own account and of ours, and both go into the transcript. One written just before a change (a second device linked before the first one's greeting was read) is still answered: if the writer's manifest is now newer than it named, the greeting counts when the current one still lists its device, with the named version in the transcript (a removed device fails here); and if ours changed since, the receiver tries again with our previous manifest (kept as `manifest-prev` when it lists this device and has the same identity key). Test `securing_an_account` links two devices back to back.

A receiver records `(root, version)` and, at the end of the same `sync`, fetches the account's manifest from its server, verifies the root signature, ignores it if its version is lower than announced or not newer than the one held, then adopts it and deletes its sessions with devices it no longer lists. A device that finds itself missing from its own account's manifest reports `Event::RemovedFromAccount`. The removed device is then shut out both ways: nothing new is encrypted to it, and its new initial messages name an old manifest version, which fails the rollback check. Rotating the inbox and vault key (so the removed device no longer sees envelopes arrive at addresses it knows) is §5.2's "Secure my account", which the app offers right after a removal.

**The PIN gate (`client/pin.rs`).** Root actions (removing a device, changing or replacing the recovery words, giving or taking back recovery shares, securing and deleting the account) refuse with `CoreError::PinRequired` once a PIN is set, until `Client::unlock_root(pin)` (good for 120 s). The PIN (at least 6 characters) is stretched with Argon2id under the profile passphrase's parameters, which are kept with a random salt and the check value `KMAC256(Argon2id(PIN, salt), "", "enclave/v1/store/pin-check")` (compared in constant time); the PIN itself is never stored. Three wrong PINs are free; then each try waits 30 s, doubling to at most an hour (`PinWait(until)`). Changing the PIN needs the old one. Steps a root action carries on from `sync` (a change of words reaching contacts, the new shares) don't ask again. The app: Settings → PIN (set or change), and a PIN field on each root action's confirmation. Wrapping the recovery secret itself under the PIN and a hardware key (`14-storage.md` §1.3) is P7. Test `root_actions_need_the_pin`.

### 5.2 "Secure my account"

A single action, PIN-gated, that:

1. rotates the vault key (new `vault_pk`, `vbs`, and blob), the account IK, the inbox seed (new addresses, new read credentials), and all signed prekeys, and publishes a new manifest;
2. re-issues write tokens to every contact (new token generation `g`, so all outstanding tokens die when the old address expires);
3. forces a PQ ratchet step with every contact by sending a control message that carries a fresh ek (`05-ratchet.md` §12);
4. rekeys every group (new sender chain and MAC keys; if the user is an admin and a device was removed, a new group epoch);
5. rotates the notification key chains and the request-inbox address.

The security code does not change (D4). Contacts see no warning.

**As implemented** (`client/secure.rs`, test `securing_an_account`): `Client::secure_account` runs on the device holding the words (PIN-gated) and is a move to the server the account is on (`12-servers.md` §4.4, `moves.rs`) with new keys:

1. a new account X448 identity key and McEliece vault key, staged until the switch; the new manifest (co-signed by this device, so contacts take it at once, and logged in key transparency) names them, the vault blob goes up sealed under a new vault key at a new locator, and the old blob is deleted;
2. a new inbox seed and request inbox: new weekly addresses, owner secrets and read credentials; contacts are told in their session (`Content::ServerMoved` with fresh write tokens, so tokens for the old addresses die with them), and the old addresses are still read for 30 days for what was on its way. No `ServerMove` record is left (there is no other server), so old cards and invite links stop working once the old request inbox goes;
3. our other devices get `Content::HomeMoved` with the new vault key and a sealed file reference to the new shared account keys (1.4 MB with the McEliece key), adopt them, and switch; read positions are reported per address, so the new addresses are acknowledged only once every device has read them;
4. fresh signed prekeys; a `Content::PqStep` to every contact we have a session with; and every group rekeyed: a new sending chain and MAC keys for every member device, and a new epoch in groups we administer.

Each step goes on from `sync` until done (`Client::securing`). The app: Settings → Secure my account (with the PIN), and removing a device suggests it. With previews on, every contact also gets a fresh notification key chain (`10-push.md` §4).

## 6. Security code (D4)

### 6.1 Computation

For each side, `fp = SHAKE256^5200(root_pk)` as specified in `02b-key-schedule.md` §4.1, giving 64 B, 30 digits, and 5 words.

### 6.2 Display

- Order: the two fingerprints are sorted lexicographically by their 64 B values; call them `fp_lo` and `fp_hi`. Both phones show the same order.
- Digits: `digits(fp_lo) ‖ digits(fp_hi)`, 60 digits in 12 groups of 5, in Atkinson Hyperlegible Mono (`17-design.md`).
- Words: `words(fp_lo) ‖ words(fp_hi)`, 10 BIP-39 words in the user's language (110 bits). **As implemented** (`recovery::security_words`): each side's five words are the 55 bits after the 30 bytes the digits use, in the recovery words' list, with "Show in English" when the two people's lists differ (`18-a11y-i18n.md`). The code sheet shows the words under the digits, and the contact's art (`17-design.md` §6.7). Test `spoken_security_code`.
- QR: the contact QR (§9.1) carries the full `root_pk`, from which the scanner computes the full 64 B digest.
- Screen readers read one group of 5 digits at a time.

### 6.3 Changes

The code covers root keys only and changes only after a root migration (§8.2). Yearly key rotation, relinking, and "Secure my account" never change it. A changed code produces the in-conversation card of `17-design.md` §6.4.

### 6.4 States

Each contact has a verification state: `unchecked` (default), `checked_remote` (the user tapped "They match"), `checked_in_person` (mutual scan, §7), `changed` (root migrated since last check). The first send after a change to `changed` needs a tap-through. If "Only send to checked contacts" is on, sending to `unchecked` or `changed` contacts is blocked.

## 7. In-person PSK (D12)

### 7.1 Mutual scan

Both users open "Scan a code" and point their phones at each other. Each contact QR shown for scanning carries a fresh 32 B secret `s` (regenerated every time the QR is shown). After both scans, each phone has both payloads `Q_A`, `Q_B` and both secrets. Both compute `psk_bond` (`02b-key-schedule.md` §4.2).

- If the two are not yet contacts, the side with the lexicographically lower `root_hash` initiates EQXDH with `psk = psk_bond`, `psk_flag = 0x01`. If both initiate, the session initiated by the lower `root_hash` is kept.
- If they are contacts, both re-root existing sessions (§7.4).
- The contact becomes `checked_in_person`, which also verifies the security code.

### 7.2 Seal check

Both screens show three Seal words from `psk_bond` (`02b-key-schedule.md` §4.2) and the Seal animation (`17-design.md` §6.2). The copy asks the users to confirm the words match. A mismatch means one phone scanned a different code; the flow shows "The words don't match. Scan again." and discards `psk_bond`.

### 7.3 One-way fallback

Invite QR codes and invite links carry a 256-bit `invite_secret` in the fragment. It becomes a one-way PSK (`psk_flag = 0x02`). It is weaker than the bond PSK because the link may have been copied.

**As implemented** (`client/invites.rs`): the PSK is `invite_psk = KMAC256(invite_secret, "psk", 256, "enclave/v1/invite/psk")`. The combiner's `psk_flag` is still 1 (the same flag as a bond); bond and invite PSKs are kept apart by their derivation labels rather than by the flag, and the initial message's PSK bit says only "some PSK". The responder tries its bonds, then every invite link that hasn't lapsed. An invite PSK never marks a contact checked, and such a greeting still lands in Message requests.

### 7.4 Meeting again

A new mutual scan with an existing contact produces a new `psk_bond`. Each device pair session mixes it into its root key at the next DH ratchet step after both sides have processed the "re-root" control message: `RK = KMAC256(RK, psk_bond_new, 256, "enclave/v1/proto/bond-reroot")`. This heals the session through a physical channel even if every KEM has been broken.

### 7.4a Implementation (`client/meet.rs`)

- The code is `enclave:meet#` + base64url(`u8(1) ‖ bytes(ContactCard) ‖ s (32)`), made fresh each time the Meet sheet opens; the secret lives in memory only and is dropped when the sheet closes. The general "Add" field and invite parser refuse it.
- After scanning, both phones compute `psk_bond = eqxdh::bond_psk(s_A, s_B, Q_A, Q_B)` (ordered by payload) and show `seal_words(psk_bond)`. Nothing is stored until the person taps **They match**; then the bond is kept per contact root and the contact is marked checked.
- **Re-rooting differs from §7.4**: instead of mixing the PSK into the running ratchet, the side with the lower root key drops its sessions with the other account and starts new EQXDH sessions with `psk = psk_bond` to each of their devices (a greeting with fresh tokens), which the other side takes in place of the old ones. Strangers who meet become contacts this way; the receiving side accepts a bonded greeting without a message request.
- A greeting with the PSK flag is tried against each stored bond (the responder can't know the sender before opening it). A failed try burns nothing: one-time prekeys are removed only after a handshake succeeds.
- The header shows "Met in person" for bonded contacts. **As implemented on the desktop:** the sheet's Seal closes when both codes are scanned (two halves meet in 240 ms, instantly under the system's reduce-motion setting) with a haptic pulse where the computer has one (a Mac's Force Touch trackpad), and every code field (invite links, in-person and link codes, friends' shares) has **Scan**, which reads the code with the camera (`enclave-app::camera`: `nokhwa` capture, `rqrr` reading, frames kept in the window's process and never stored); pasting still works.

### 7.5 Formal model and copy

A Tamarin lemma covers the case "all KEMs broken, the optical exchange not recorded" (`20-assurance.md` §2). Product copy MUST NOT claim this makes messages "unbreakable" or similar.

## 8. Recovery, migration, deletion

### 8.1 Pending root actions (RT-22)

A device decision is a composite signature by a device listed in the current manifest:

```
device_decision = CompositeSign(device_sk, "enclave/v1/proto/veto", u8(decision) ‖ manifest_hash)
decision        = 0x01 approve | 0x02 veto
```

A manifest update is **cosigned** if its update envelope (§3.3) carries a valid `device_decision` with `decision = 0x01` from a device listed in the previous manifest with an unexpired key.

Rules:

- A cosigned update takes effect immediately.
- An update without a valid cosignature (for example, recovery on a new phone after losing every device) is published as a **pending** record: `Pending = {manifest_hash, not_before = trusted_now + 72 h}`, root-signed with ctx `enclave/v1/proto/pending-root`, and posted to the directory and to KT.
- Any device in the current manifest MAY veto the pending update with a `device_decision` with `decision = 0x02`, posted to the directory and KT. A vetoed pending update is dead; the UI on the recovering device says "One of your other devices stopped this change."
- Contacts' clients MUST NOT accept a pending manifest before `not_before`, and MUST NOT accept it at all if a valid veto exists. Contacts' clients check for a veto when they fetch the manifest after `not_before`.
- Every device of the account shows a persistent alert while a pending action exists: "Someone is setting up your account on a new device. If this isn't you, tap Stop."
- After a successful recovery, contacts see "Sam set up a new device". The security code does not change.

**Implementation** (`enclave_proto::attest`, `client/guard.rs`; differs from the draft above where noted):

- An **attestation** is `u8(verdict) ‖ u64(version) ‖ manifest_hash (64) ‖ device (16) ‖ u32 len ‖ signature`, where `verdict` is 1 co-sign or 2 veto and the signature is `CompositeSign(device_sk, ctx, root_pk (64) ‖ u64(version) ‖ manifest_hash)` with ctx `enclave/v1/ctx/manifest-cosign` or `enclave/v1/ctx/manifest-veto`. It counts only if the device is listed in the manifest the judge currently holds for that account.
- Attestations live in the directory (`DirKind::Attest`, keyed like the manifest). The server keeps at most 16 per account and stores one only if its signature verifies against a device that some manifest of the account has listed, so strangers can't fill the slot. The primary uploads its co-signature **before** the manifest, so no contact ever sees the update unsigned.
- **The wait is counted from when each contact first saw the update**, not from a `not_before` in a root-signed record: whoever signs with the root chooses every time in the manifest, and there is no trusted (witnessed) time yet. The first sighting is stored per account (`version ‖ hash ‖ first_seen`).
- A contact that receives a greeting whose sender's manifest is held keeps the envelope and re-runs it every 10 minutes and when the wait ends; if the update is vetoed, the greeting is dropped. The `refresh` after a `Devices` notice applies the same rule.
- Our own devices fetch our manifest every 10 minutes. A newer version that no listed device co-signed raises `Event::RecoveryPending { until }` and a persistent card ("Someone is setting up your account on another device… Stop it / It's me"). **Stop it** signs a veto, publishes it, and also sends it as `Content::Veto` (kind 15) to every contact and our devices, so a server that withholds it doesn't win. **It's me** signs a co-signature, and contacts accept the update on their next look.
- **Key transparency.** There is no separate pending record: the manifest and the attestation list together are the account's state, and the server commits them to its log as one **account record** whenever either changes. The label is `0x01 ‖ manifest_key[1..]` (not a valid username, and not the descriptor's `0x00` label); the value is `SHA3-512(signed manifest as served) ‖ SHA3-512(attestation list as served)`, the second hash over the empty string when there are none. A server enabling its log for the first time commits every stored account in one epoch, once per log. A lookup is a `DirKind::Username` get with key `0xFF ‖ manifest_key[1..]` (`0xFF` never starts a UTF-8 name), answered like a descriptor lookup and checked with `enclave_kt::verify_label_lookup` against the pinned log and witnesses. A contact whose client pins the account's server takes a manifest change (co-signed, or after the wait) only if the logged record matches the manifest and attestations it was served; otherwise it holds the change (`Judgement::Unlogged`) and asks again in 10 minutes. So everyone sees the same co-signatures and vetoes, or the log shows that they didn't. Servers without a pinned log (development) are trusted as before.
- **The recovering device.** A restore that no device co-signed keeps `since ‖ the backup's manifest ‖ the manifest it replaced` and checks our attestations every 10 minutes. The devices that may judge it are those in the backup's manifest, and those in the replaced manifest unless that one was itself vetoed by them (the replaced manifest may be an earlier stopped attempt). A co-signature, or 72 hours, ends the hold (`Event::RecoveryDone`); a veto raises `Event::RecoveryStopped` and a red card, "One of your other devices stopped this change", for good. While held or stopped the device refuses to create anything a person wrote (texts, files, locations, group posts): `CoreError::RecoveryHeld`, shown as "You can send once your contacts accept this device", so nothing is sent that contacts would throw away. A yellow card says until when contacts wait.

### 8.2 Changing the recovery words (root migration)

Someone who thinks their recovery words were seen (a photo, a lost notebook) needs new words. The root key is derived from the words (§2), so new words mean a **new root**: a migration from the old root to the new one. This section is the design; "As implemented" below says what the code does.

#### 8.2.1 What changes and what doesn't

Only the root changes. The account X448 identity key, the McEliece vault key, every device key, the inboxes, tokens, sessions, groups and history are kept: none of them is derived from the words. So the migration is a re-signing of the same account under a new root, not a new account.

| Changes | Stays |
|---|---|
| recovery words and root key pair | identity and vault keys (same `vault_hash`) |
| the manifest (re-signed under the new root, version + 1) | devices and their keys, sessions, inboxes, tokens |
| the security code (it covers the root, D4) | conversations, groups, history, settings |
| backups and recovery shares made from the old words (no longer restore anything) | who is in which group, and admin roles |

#### 8.2.2 The migration record

```
Migration = u8(1) ‖ old_root_pk (64) ‖ new_root_pk (64) ‖ new_manifest_hash (64) ‖ u64(time)
            ‖ new_sig (29,792) ‖ u8(has_old) ‖ [old_sig (29,792)]
new_sig = RootSign(new_root_sk, ctx = "enclave/v1/ctx/migration", payload)
old_sig = RootSign(old_root_sk, ctx = "enclave/v1/ctx/migration", payload)
payload = old_root_pk ‖ new_root_pk ‖ new_manifest_hash ‖ u64(time)
```

`new_manifest_hash` is SHA3-512 of the new signed manifest, which lists the same devices and keys as the last one under the old root, with `prev_hash` = the hash of that last manifest and `version` one higher. Both signatures cover the same payload. The device the person migrates from holds the old words (only a device with the recovery secret can do it), so in practice the old signature is always present; the format allows it to be missing for a future "root lost, devices kept" case.

#### 8.2.3 Who accepts it, and why

A contact accepts a migration of `old → new` only if all of these hold:

1. it arrives **inside an existing session** with `old`, from a device listed in the manifest the contact currently accepts for `old`;
2. `new_sig` verifies under `new`, and `old_sig`, if present, under `old`;
3. the new manifest verifies under `new`, hashes to `new_manifest_hash`, and lists the sending device.

Rule 1 is what makes this safe against the threat that motivates it. Someone who has the old words but none of the person's devices can sign with the old root, but can't send in a session: to add a device of their own they would need a manifest update, which waits 72 hours and can be vetoed (§8.1). Rule 3 ties the new root to the devices the contact already talks to. Signatures alone are never enough, so a migration found anywhere else (the directory, a shared card) is never followed automatically.

What the contact sees:

- with the old root's signature: "Sam changed their recovery words. Their security code changed too: check it again before sharing anything private." The contact is no longer marked checked;
- without it: "Sam's account was moved to a new key, but Enclave can't confirm it was Sam who did it. Check the security code in person before sharing anything private."

#### 8.2.4 On the migrating device

`change_recovery_words` runs on a device that holds the recovery secret, in this order (each step is safe to repeat, and a journal record makes a crash resume where it stopped):

1. Generate a new recovery secret and root; build and sign the new manifest; co-sign it with this device's key (§8.1), and sign the migration with both roots.
2. Publish the co-signature and the new manifest under the new root's directory key, and the migration under the **old** key (`DirKind::Migration`). From then on the server refuses manifests under the old key, so the old words can no longer publish one; a lookup of the old key finds the migration, and the app says "This code is out of date. Ask Sam for a new one." instead of following it.
3. Store the new secret, root and manifest. The old secret is deleted.
4. Send the migration (with the new manifest, about 100 KB, so as a sealed file reference) to every contact and every group member we have a session with, and to our own devices.
5. In every group, post a state update that changes only our own member entry's root (§8.2.6).
6. Re-claim our username for the new root (the server allows it because it holds the migration).
7. If friends hold shares of the old words, give them shares of the new words (same friends, same threshold); the new shares replace the old ones.
8. Show the new words and ask the person to save them again; a new backup is needed (the old one was made from the old words).

Linked devices adopt the new root from the migration their primary sends them; they never had the words.

#### 8.2.5 On a contact's device

Everything the contact stores about us is keyed by our root. Accepting the migration **renames** `old` to `new` everywhere, so that afterwards the contact's state is exactly what it would be had we always had the new root, and every existing code path keeps working unchanged:

- records keyed by root: the contact, its sessions (`root ‖ device`), blocks, conversation settings, pins, in-person bonds, recovery shares we hold for them, pending join requests, token issuers, PQ-step marks, and the manifest guard's state for that account;
- the 1:1 message namespaces (`msg_ns`, `id_ns`), with disappearing messages re-sealed under the new conversation's shred keys;
- values that name the root: group member cards, the `from` of their group messages and reactions, and poll votes.

The rename is journaled (`old ‖ new`) before it starts and the journal is removed when it ends; opening the profile finishes an interrupted rename. A verified `old → new` is also kept in a small migrations table, which is how group updates (§8.2.6) are checked and how a late message that still names `old` is understood.

#### 8.2.6 Groups

Changing a member's root is not a membership change: the same person keeps the same slot, admin role and join time. So it doesn't need an admin. `GroupState::accepts` allows an update from any member that changes **only that member's own root**; a member's client additionally applies it only once it holds a verified migration from that member's old root to the new one (§8.2.3), and holds the update until then (the pairwise migration and the group update can arrive in either order). A member who never gets the migration keeps holding the update and sees a notice; a later state update from an admin that includes the new root is accepted as usual.

#### 8.2.7 What this doesn't do

- **History stays.** The contact keeps the conversation and its history: the person is the same, only their key changed.
- **Old codes and links stop working.** Invite links and QR codes carry the old root; they lead to the migration notice, not to the account.
- **Not hidden from contacts.** Every contact learns the account moved to a new key, which is the point.
- **Can't recover from a thief who also has a device.** If someone has the old words and a linked device, they can migrate too; that is "Secure my account" plus removing the device (§5), first.

#### 8.2.8 As implemented

`enclave-proto/src/migration.rs` (the record; ctx `enclave/v1/ctx/migration`), `GroupState::root_change` and the self-only rule in `GroupState::accepts` and `Group::apply_state`, `enclave-core/src/client/migrate.rs`, and `DirKind::Migration` in the server (`12-servers.md` §2.2).

- `change_recovery_words` stages the new secret, account keys, manifest and record under temporary keys, writes a `migrating` flag (the commit point), then moves them into place; `Client::open` finishes a staged migration before reading anything. Further steps are tracked as bits in the `migration-step` setting and retried from `sync` until all are done; `migration_pending` reports it. A second change waits for the first to finish.
- The migration travels as `Content::Migration` (content kind 24): a sealed file reference to `record ‖ new signed manifest`, at most 128 KiB. Receivers queue it and check it in `sync`; two changes in a row are applied in order whatever order they arrive in.
- The checks are §8.2.3's, plus: the new manifest's identity key and `vault_hash` are the old ones and its version is higher.
- The rename covers the contact record (and its card), sessions, 1:1 history (re-sealed), blocks, held recovery shares, pending PQ-step replies, join requests, token issuers, pins, conversation settings, group cards and the "keyed" sets; in-person bonds and the manifest-guard state are dropped, so the contact shows as not checked and not met. Group messages, reactions and polls are rewritten when the group update arrives. Until then, group code resolves a member's old root through the migrations table.
- **The app**: Settings → Recovery words → "Someone may have seen them? Change them" explains what happens and shows the new words. A contact who changed theirs gets a card in the conversation (Saffron rule) with **Check now**; checking clears it. Screenshots 49–50.
- Test `change_recovery_words` (`enclave-core/tests/client.rs`) changes the words twice in a row and checks: the contact receives both, in order, and knows the account only by the newest root, unchecked, with its history (including a disappearing message), mute setting and pin; the conversation continues both ways; the group (whose admin is someone else) takes the self-only updates, the old group message is attributed to the new root, and a message after a rekey arrives; friends hold shares of the new words; the old card can't be added. `migration.rs` and `group.rs` unit tests cover signatures, tampering, and the self-only rule.
- **Root lost, devices kept.** `replace_lost_root` runs on a device that doesn't hold the words (a linked device, after the words and the first device are lost): the same steps as `change_recovery_words`, but the migration carries only the new root's signature, this device becomes the primary in the new manifest (it holds the new words), and two steps are skipped because the server can't take them without the old root's signature: the directory keeps the old key's manifest (anyone could otherwise retire someone's key) and the username stays with the old root. A device without a sending chain in a group makes one (`prepare_group_send`) before posting its root update. Contacts follow it as for any migration, under §8.2.3's rules, and see "…'s account moved to a new key: Enclave can't confirm it was them" with **Check now**. The app offers it on a linked device under Settings → Recovery words → "Make new words" (the change-words sheet with its own wording). Test `a_linked_device_replaces_lost_words` (`tests/lost_root.rs`). A device that holds the words never adopts a migration of its own account (one made elsewhere leaves it on the old words), and now refuses it before writing anything.
- **A group update held for good.** A member who never gets the migration (it couldn't be fetched, or never came) keeps the group update on hold. After an hour (`HELD_MOVE_NOTICE_SECS`) `sync` raises `Event::GroupMoveHeld { group_id, root }` once, and `GroupInfo::held_moves` lists the member; the group conversation shows "… changed their recovery words, but this device didn't hear it from them: their new key is on hold in this group until it does" (Saffron). An admin's later state update with the new root is accepted as usual, which ends it. Same test.
- **In key transparency.** Once the server holds a migration, the old key's account record (§8.1) becomes `"M" ‖ SHA3-512(migration record)` (65 bytes, told apart from a 128-byte manifest record by its length), committed with the migration. A contact whose client pins the old server's log takes a cross-signed migration only once the log shows that record, and keeps it queued until then (`FedError::NotLogged`); a migration without the old signature is never in the directory or the log, and is shown as unconfirmed anyway. Test `migrations_wait_for_the_log` (`tests/account_kt.rs`).

### 8.3 Social recovery (M9, optional)

- `rs` is split with SLIP-0039 into 3-of-5 shares, each sent inside an existing session to a chosen contact.
- A holder releases a share only after an in-person mutual scan (§7.1) with the recovering person and an explicit confirmation ("Sam asked for your recovery share. Only continue if you're with Sam right now.").
- The reconstructed `rs` leads to a pending root action (§8.1): 72 h wait, all devices notified, veto possible.

**As implemented** (`enclave-slip39`, `client/social.rs`):

- `enclave-slip39` is a port of the SLIP-0039 reference (`shamir-mnemonic` 0.3, MIT; word list and license in `LICENSES/`): Feistel encryption of the master secret with PBKDF2-HMAC-SHA256, two-level GF(256) Shamir with the HMAC digest share, 10-bit words and the RS1024 checksum. Its tests replay vectors the reference produced from a deterministic byte stream and must reproduce the **same words**, including two-level groups, a passphrase and the non-extendable variant; they also check that too few, too many, mistyped or mixed shares are refused.
- `give_recovery_shares(holders, threshold)` splits `rs` (one group, extendable, iteration exponent 1) and sends each accepted contact its share as `Content::RecoveryShare` (kind 17). Holders keep it in their sealed store (`Event::RecoveryShareReceived`). The app chooses 3–5 friends with `⌊n/2⌋ + 1` needed.
- **Release, in person, by scanning.** The share is never shown as words. The recovering person's new device (Restore → **Ask a friend in person**) makes a `ShareRequest`: fresh X448 and ML-KEM-1024 key pairs, held only in memory, shown as `enclave:release#` ‖ base64url(`1 ‖ X448 public (56) ‖ ML-KEM-1024 public (1568)`) in a QR code, with three check words (`KMAC256(SHA3-512(request), "", "enclave/v1/proto/share-words")`, three BIP-39 English words). The holder's conversation shows "You hold part of Sam's recovery" with **Help them get back in**: the sheet says "Sam asked for your part of their recovery. Only continue if you're with Sam right now.", takes the scanned code, and `release_recovery_share` answers with `enclave:share#` ‖ base64url(`1 ‖ ephemeral X448 public ‖ ML-KEM ciphertext ‖ u32 len ‖ sealed share`), sealed with EnclaveSeal under `KMAC256(EnclaveCombine(two KEMs; DH, ML-KEM secret; request, ephemeral key, ciphertext), "", "enclave/v1/proto/share-release")` with the request as AD. The holder's screen shows the same three words ("If the words differ, close this: you scanned the wrong screen") and the answer as a QR code (Low error correction: about 2.6 KB). The new device opens each answer with its request; the Restore boxes take answers or words. A code scanned anywhere else (an invite, the add field) is refused as a recovery code. The codes never touch a server.
- **Taking a share back.** Old shares always rebuild the words they were made from, so dropping a holder changes the words: `reshare_recovery(holders, threshold)` makes a new split when everyone holding a share is kept, and otherwise stores the new holders, sends each dropped one an empty `RecoveryShare` (forget it), and runs `change_recovery_words`, whose last step gives the new holders shares of the new words (`remove_recovery_holder` drops one). The old words then restore nothing (the server holds the migration). The Friends sheet warns that leaving someone out changes the words, and shows the new ones.
- The new device's **Restore** screen takes the 24 words *or* the friends' answers, plus the backup file (read by the UI, not the vault); `words_from_shares` rebuilds the words and the ordinary restore follows, so the 72-hour guard applies. Settings has **Save a backup** (an encrypted file in Downloads); backups stored on the server come with P7.
- Test `social_recovery`: Ada drops one of three holders, so her words change, the dropped holder forgets the share and the others hold shares of the new words, and the old words restore nothing; her new device's request is answered by the two remaining holders, an answer for another screen doesn't open, the dropped holder has nothing to give, one share isn't enough, two rebuild the new words, and the restore has the new root.

### 8.4 Lost words and all devices, no social recovery

The account cannot be recovered. The user creates a new identity. Onboarding says so plainly: "If you lose your recovery words and all your devices, you'll need to start a new account."

### 8.5 Account deletion (App Store rule 5.1.1(v))

Deletion, PIN-gated, performs in order:

1. sends a "closed" control message to every contact and group;
2. writes a KT tombstone: `Tombstone{root_hash, time}` root-signed with ctx `enclave/v1/proto/tombstone`;
3. deletes the inbox, request inbox, directory objects, and every blob the account uploaded (each delete op authenticated by the corresponding credential);
4. crypto-shreds local data (`14-storage.md` §3) on every device (each device receives a deletion control message; devices offline for 30 days are covered by inbox deletion and manifest expiry).

**As implemented** (`client/closing_own.rs`, `12-servers.md` §3.5):

- `Client::delete_account` runs on a device holding the recovery words (a linked device can only erase itself). In order: `Content::Closed` (kind 34) to every accepted contact, who see "… closed their account" and stop sending; leave every group (a state update removing us); `publish_tombstone` (`Tombstone = u8(1) ‖ root ‖ u64 time`, root-signed; the record carries the root, not its hash, so the server can check the signature): the server withdraws the username for good, deletes the manifest, attestations and the devices' prekeys, refuses any later manifest for the root, and logs `"T" ‖ SHA3-512(tombstone)` as the account's key-transparency record; unregister push; delete every weekly inbox address and the request inbox with their owner secrets (`FLAG_DELETE`); delete the vault-key blob (its owner secret is now derived from the vault key, `net/vault-owner`). Each step is safe to repeat, so a deletion cut short by the network is finished by trying again. The vault then crypto-erases the device (`Client::erase`: the store's key leaves the keystore) and removes the profile's files.
- **Blobs** the account uploaded are not deleted one by one: nothing links them to the account (allocations are bought with unlinkable Privacy Pass tokens, `09-transport.md` §9) and they expire within 30 days.
- **Our other devices** check our manifest every 10 minutes; when it is gone and a valid tombstone for our root is there instead (or when reading our deleted inboxes is refused), `Event::AccountDeleted` is raised once and the app erases the device ("Your account was deleted from another of your devices…"). A device offline for good is covered by the deleted inboxes and the manifest's expiry.
- **The app**: Settings → Delete → "Delete my account" (or, on a linked device, "Erase this device"), confirmed by typing *delete*; the PIN gate for root actions comes with "Secure my account" (§5). A device removed from the account shows "This device was removed from your account" with **Erase this device**.
- Test `deleting_an_account` (`tests/deletion.rs`): a linked device can't delete; deleting twice is fine; the server holds fewer inboxes and no vault blob for her; her contact sees the account closed and both group members see her gone; her linked device is told once.

## 9. Adding contacts

### 9.1 Contact QR ("Show my code")

URI scheme `enclave:` followed by `c/` and base32 of:

| Field | Length |
|---|---|
| version 0x01 | 1 |
| `root_pk` | 64 |
| home `server_id` | 32 |
| `manifest_version` hint | 8 |
| `vbs` (vault-key blob secret) | 32 |
| `invite_secret` | 32 |
| `s` (in-person secret, fresh per display) | 32 |

201 B. Scanning resolves the contact by fetching the manifest (by `root_hash` at `server_id`), bundles, and the vault-key blob in bulk mode while the UI shows "Adding Sam…".

**As implemented** (`enclave-core/src/card.rs`): `enclave:add#` + base64url of the card, version 3:

```
u8(3) ‖ root_pk (64) ‖ server_id (16) ‖ request_inbox (32) ‖ vault_locator (32) ‖ vault_key (32)
‖ bytes(name, ≤ 64) ‖ bytes(server_domain, ≤ 253) ‖ u8(has invite) [‖ invite_secret (32) ‖ uses (u8, 1–20)]
```

`server_domain` is the home server's domain from the server list (empty if the client holds none); a client that doesn't know the server id finds the server through it (`12-servers.md` §4). Versions 1 (no domain, no invite) and 2 (no domain, with invite) are still read. Test `card_links`.

### 9.2 Invite links

`https://<invite-host>/i#<base32 payload>`, where the payload is the §9.1 fields without `s`. The secret part is only in the URL fragment, which browsers do not send to servers. Invite links:

- are limited-use (default 1 use for contacts) and expire (default 7 days);
- can be revoked from Settings → Invite links, which deletes the `cap_hash` registration at the request inbox;
- deliver the first message to the recipient's request inbox, authorized by `invite_cap`, where it waits as a message request.

**As implemented** (`card.rs`, `client/invites.rs`, server `write_request`):

- The link is the contact link (`enclave:add#`, §9.1 as implemented) with card version 2: the version-1 fields, then `invite_secret (32) ‖ uses (u8, 1–20)`. The plain QR code stays version 1 with no secret.
- **The https form.** "Copy invite link" gives `https://<home server domain>/i#<the same payload>` (`ContactCard::to_share_link`) when the card names the home server's domain, for apps that don't open `enclave:` links; the scanner and the Add screen take either form. The invite host is the inviter's own server's front (`enclave-front`): its `/i` page is the same static page for every link, with no script and no outside resources (a strict content security policy, `no-referrer`), says to open the link in Enclave, and never sees the invite, which is in the fragment. Opening such links in the app directly (Android App Links, iOS universal links) needs the app's identifiers in files the front serves, added with A1 and I1. Tests `card_links` (core) and `front_serves_descriptor_and_witness_over_enclave_tls` (front).
- **Capabilities**: `invite_cap_i = KMAC256(invite_secret, u32(i), 256, "enclave/v1/invite/cap")` for `i < uses × 5` (one per device of each person joining; a greeting goes to each of the host's devices). The host registers `token_hash(invite_cap_i)` on its request inbox (`RegisterTokens`), and a writer sets `FLAG_INVITE` on `WriteRequest` with a capability as the token instead of a proof of work. The server burns it on use. The writer tries the capabilities in order, skipping ones others have spent; if none is left it gets `InviteUsed` ("This invite link was already used, has expired or was cancelled") and nothing is kept.
- **Limits**: the host counts the distinct accounts each link opened; once it has brought `uses` people it cancels the remaining capabilities (`RegisterTokens` with `FLAG_REVOKE`), and later greetings with its PSK from anyone else are dropped. More devices of someone it already brought are fine. Links lapse after 7 days (cancelled at the next sync). "Cancel them" cancels every unused link.
- A contact never keeps the invite: the card stored for them has it stripped, so later greetings (new devices, restores) use the proof of work as before.
- **App**: "Copy invite link" makes a new single-use link each time and copies it (cleared from the clipboard after 60 s); the code sheet shows how many links are unused, with "Cancel them".
- Group invite links and admin approval of joins are built (`07-groups.md` §9). Not done: choosing more than one use in the app (F3).

### 9.3 Usernames

- Format `@name@server`. One username per account. Registration needs an Equi-X PoW (≈30 s) and is checked for UTS #39 confusable-skeleton uniqueness per server (`12-servers.md` §3.3).
- KT maps the name to `{root_hash, manifest_hash, manifest_version, locator}` where the locator contains the request-inbox server and address and `vbs` (`12-servers.md` §3).
- Username contacts land in Message requests until accepted, like any stranger.
- The UI says: "A username is public, like an email address."

### 9.4 Sharing a contact

**As implemented** (`enclave-core/src/client/sharing.rs`): `Content::ContactShare { id, card }` (content kind 19) carries a contact's card inside the session, so the recipient can add that person as if they had scanned the code: an ordinary message request, trusted on first use. Only a card the person gave us can be shared (their QR fields; any invite secret is stripped on both ends), only with an accepted contact, and never a contact to themselves. The person shared is not told, and the request they receive doesn't say who shared them. The card's name is what that person typed and is shown as such; the app reminds the recipient to check the security code when they meet. Cards are kept per conversation, by message id, and removed with the conversation. The app shares from the attach sheet ("Share a contact instead") and shows a card with **Add** in the conversation. Test `share_a_contact`.

## 10. Errors

| Condition | Behavior | User-facing copy |
|---|---|---|
| Manifest signature invalid | Reject, keep cached | "Couldn't check Sam's account. We'll try again." |
| Manifest expired and no newer one | Stop sending new sessions; existing sessions continue for 7 days | "Sam's account needs to update. Messages may not arrive." |
| Pending root without veto after 72 h | Accept | "Sam set up a new device" |
| Pending root with veto | Reject | none to contacts |
| Link phrase mismatch | Abort link | "The words didn't match, so nothing was linked." |
| Sixth device | Refuse | "You can link up to 4 devices. Remove one first." |
| Link QR in general scanner | Refuse | §4.2 text |
| BIP-39 checksum failure | Refuse | "These words don't match. Check each word and try again." |

## Open questions

1. Resolved: the invite-link host is the inviter's own home server's front (§9.2 as implemented), so no foundation-run domain sees who shares links; its `/i` page is static and never sees the fragment.
2. The rendezvous mailbox for linking is hosted on the new device's chosen default server. Whether the primary should instead choose it (so the new device's first network activity is not tied to a server choice) is open.
3. Whether the 30-day inactivity removal should be performed by any device with role 3 as well as the primary, to avoid a PIN prompt on the primary.
4. The manifest carries `expires` per device key (1 year). PLAN.md does not say whether an expired device key blocks that device from sending until relinking or whether the primary can extend it in place with a new manifest. This spec allows in-place extension by the primary.
