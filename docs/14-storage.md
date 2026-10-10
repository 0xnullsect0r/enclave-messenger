# Local Storage

Status: Draft (M0, reconciled with the M5 code) · Normative

Source: PLAN.md §13 (D11), RT-08, RT-21. Crates: `enclave-store`; later `enclave-platform` (keystore adapters). Derivations: `02b-key-schedule.md` §13. Where this document and the code disagree, the code is normative.

## 1. Keys

### 1.1 Device secret and keystore

Each profile has one random 32 B **device secret**, created with the store (`HedgedRng.fill("store/device-secret", 32)`) and kept in a platform keystore under the name `enclave-profile-secret`. The `Keystore` trait has three operations: `create(name, secret)`, `load(name)`, `destroy(name)`.

| Adapter | Status | Use |
|---|---|---|
| `MemoryKeystore` | Implemented | Tests |
| `FileKeystore` | Implemented | One file per secret; overwritten with zeros before removal. Development, and Linux desktops without a Secret Service on full-disk-encrypted machines only (flash wear levelling makes overwriting unreliable). |
| Keychain, with a Secure Enclave wrap (macOS) | Implemented (`enclave_platform::keystore::keychain`, `enclave-vault::keystore`) | Desktop. A generic password per secret in the login Keychain, service `io.github.EnclaveChat.Enclave`, account `ID/name`. In a build signed with a keychain access group each secret is also sealed to its own Secure Enclave P-256 key (ECIES, cofactor, X9.63-SHA-256, AES-GCM; `AccessibleWhenUnlockedThisDeviceOnly`, private-key use only), so the stored item alone opens nothing; unsigned builds keep the item under the Keychain's protection only (a tag byte says which). |
| DPAPI (Windows) | Implemented (`enclave_platform::keystore::dpapi`) | Desktop. Each secret sealed with `CryptProtectData` to the user's logon credentials, its name as extra entropy, and kept as `keys/<name>.dpapi` in the profile: another user, or the files on another machine, can't open it. |
| Secret Service / secret portal (Linux, BSD) | Implemented (`enclave_platform::keystore::secret_service`, through `oo7`) | Desktop. Items with attributes `application` and `account` in the default collection (GNOME Keyring, KWallet); in a Flatpak the secret portal's keyring file. The vault connects before it confines itself (it can't open the bus socket afterwards) and keeps the connection; in a Flatpak the portal keyring's directory stays writable. Without one: files. |
| Keychain + Secure Enclave (iOS), StrongBox/Keystore (Android) | With I1 and A1 | Phones: on iOS a Keychain item (`WhenUnlockedThisDeviceOnly`) sealed to a Secure Enclave key as on macOS; on Android a StrongBox (or TEE Keystore) AES-256-GCM key that unwraps a stored secret. |

**As implemented (desktop).** A profile records its keystore in a `keystore` file next to the database (`file`, `dpapi`, `keychain ID` or `secret-service ID`, `ID` 16 random bytes in hex so profiles don't share secrets). A new profile takes the platform keystore when it answers a probe; a profile made with files moves into it when it opens and the keystore is there: each secret is copied and read back, the choice recorded, then the files are overwritten and removed. A profile whose recorded keystore isn't reachable (a locked keyring, no Secret Service in this session) doesn't open, rather than starting over in files. The panic wipe and the emergency PIN destroy every secret of the profile wherever it is (`keystore::erase`). `ENCLAVE_KEYSTORE=file` keeps secrets in files (tests). Test `profiles_move_into_the_platform_keystore` runs against the Keychain and DPAPI on the macOS and Windows CI runners. The root secret's own policy (§1.3) is the platform's unlocked-session rule: the login Keychain and DPAPI release secrets only to the logged-in, unlocked user, and nothing here accepts a fingerprint alone. Where secrets are in files (a Linux desktop without a keyring), setting up recommends a passphrase, which then protects them. TPM-bound keys on Windows (CNG with the Platform Crypto Provider) aren't used: DPAPI already binds to the user and machine, and a TPM wrap would add protection only against an attacker who has the user's password and the disk but not the machine, which the passphrase (§1.2) covers.

### 1.2 Master key

```
salt   = HedgedRng.fill("store/salt", 32)                                  # stored in the database
pw     = Argon2id(passphrase, salt, params)       # 32 B, only if the user set a passphrase (02-cryptography.md §9)
master = KMAC256(device_secret, frame(pw or ""), 256, "enclave/v1/store/master")
index  = KMAC256(master, "", 256, "enclave/v1/store/index")
```

This is PLAN §13's `KMAC256(hw_secret‖Argon2id(passphrase)?)` with the device secret as the KMAC key and the passphrase output framed.

The `meta` table holds `salt`, the Argon2id parameters (`u32(memory_kib) ‖ u32(iterations) ‖ u32(parallelism)`, or empty without a passphrase), and a **verifier** `seal(master, "verifier", "enclave")`. `Store::open` recomputes the master key and opens the verifier; a wrong passphrase, a missing passphrase where one is set (or the reverse), or a wrong device secret fails with `StoreError::Crypto`.

**Changing the passphrase** (`Store::change_passphrase`) keeps the master key and so every record, blinded index and verifier: it derives `kek = KMAC256(device_secret, LABEL_MASTER, framed(Argon2id(new, pwsalt)))` (or with nothing framed to remove the passphrase) from a fresh 32 B `pwsalt`, and stores `wrapped = seal(kek, "wrapped-master", master)`, `pwsalt` and the new parameters in `meta` in one transaction. `Store::open` then derives `kek` the same way (with `pwsalt`) and unwraps; stores never changed keep deriving the master key directly. The record salt `salt` never changes.

### 1.3 Root wrap

On the device that holds the recovery words, the recovery secret (from which the account root is derived) is never stored as it is (`client/root_wrap.rs`). It is sealed under

```
kek = KMAC256(root_secret, Argon2id(PIN, salt) or "", 256, "enclave/v1/store/root-wrap")
record = u8 version (1) ‖ u8 pin (0/1) ‖ u32 memory ‖ u32 iterations ‖ u32 parallelism ‖ salt (32)
         ‖ Seal(kek, "enclave/v1/store/ad-root" ‖ header, recovery secret (32))
```

and kept as the store record `("secrets", "root-wrap")`. `root_secret` is a keystore secret of its own, `enclave-root-secret` (32 random bytes, purpose `store/root-secret`), separate from the device secret: the platform keystore adapters (`enclave-platform`, D1/A1/I1) give it a policy that needs the device unlocked and that biometrics alone can't satisfy. A copy of the database and the device secret without it can't unwrap the root, PIN or no PIN.

- **Without a PIN** the kek is the keystore secret's alone: the device unwraps the root when it needs it.
- **With a PIN** (`Client::set_root_pin`, Argon2id with the profile's parameters), only `Client::unlock_root` can: it unwraps the root, which stays in memory (locked pages) with the kek for 120 s and is then dropped (`lock_root`, and every sync once the unlock lapses). The PIN is needed to *have* the root, not just to use it. A wrong PIN simply fails to unwrap; after three wrong tries each further try waits 30 s, doubling up to an hour (open question 2). Everything the root signs for a server move is signed when the move starts, while it is unlocked, so a move never waits for the PIN.
- **New words** (changing them, or a device making new ones) are wrapped the way the old ones were, under the same PIN; the staged migration carries the wrapped record.
- **Upgrade**: a profile from before the wrap kept the recovery secret only under the store's sealing; `Client::open` wraps it (without a PIN) and deletes the old record. A PIN set before the wrap left a check value (`enclave/v1/store/pin-check`); its next good unlock wraps the root under it and deletes the check value.
- A crypto-erase destroys `enclave-root-secret` with the device secret, so the wrapped root goes with the profile.

Tests: `the_pin_wraps_the_root` (`client/pin.rs`), `the_root_stays_wrapped_on_disk` (`tests/root_wrap.rs`: restart, new words under the same PIN, a copied database without the root secret).

## 2. Database

### 2.1 Engine and tables

One redb database per profile (a file, or in memory for tests) with two tables: `records` (bytes → bytes) and `meta` (string → bytes).

### 2.2 Blinded keys

Every record is addressed by a `(namespace, key)` pair. The stored key is a 40 B **blinded key**:

```
ns_tag(ns)       = KMAC256(index, ns, 256, "enclave/v1/store/namespace")[0..8]                 # 8 B
blind(ns, key)   = ns_tag(ns) ‖ KMAC256(index, frame(ns) ‖ frame(key), 256, "enclave/v1/store/blind")   # 8 + 32 B
```

The file reveals no namespace or key names. Because every blinded key starts with its namespace tag, `Store::scan(ns)` is one range query over `[ns_tag ‖ 0^32, ns_tag ‖ 0xff^32]`. An observer of the file can count records per (unnamed) namespace.

### 2.3 Sealed records

```
record_key = KMAC256(master, frame(salt) ‖ frame(blinded_key), 256, "enclave/v1/store/record")
plaintext  = u32(len(key)) ‖ key ‖ value            # the plain key is kept inside the seal so scans can return it
stored     = seal_chunked(record_key, blinded_key, plaintext)
```

**Chunked sealing** (`seal_chunked`, `open_chunked`) handles data of any size:

```
seal_chunked(K, AD, P):
    segments = P split into 60,000 B pieces (one empty segment if P is empty)
    for i, seg in segments:
        last  = u8(1) if seg is the final segment else u8(0)
        out  ‖= u32(len(s_i)) ‖ s_i   where s_i = seal(K, AD ‖ u64(i) ‖ last, seg)
open_chunked(K, AD, S):
    read segments in order; a segment is "last" exactly when it ends at the end of S;
    open each with AD ‖ u64(i) ‖ last; any failure is StoreError::Crypto
```

The segment index and the last flag are in each segment's AD, so reordering, dropping a final segment (the new final segment was sealed with `last = 0`), and appending all fail. The blinded key is the AD of every record, so records cannot be swapped.

### 2.4 Search index, migrations, OS backups

**Blinded search index** (`client/search_index.rs`). Every word of a message (its text, and an attachment's name) is indexed by its prefixes of 3 to 8 characters, lowercased, as `token = KMAC256(search_key, prefix, 256, "enclave/v1/store/search-token")[0..16]` with `search_key = KMAC256(master, "", 256, "enclave/v1/store/search-key")`. A conversation's index is the namespace `sx/…`: token → the positions of the messages that have it (so the index holds no word, only tokens, under the store's sealing like everything else). A disappearing message's positions are kept apart under `token ‖ day`, sealed with the shred key of its day like the message, and dropped when the day is shredded, so shredding takes them too; an edit or a deletion takes the old words out at once. A query looks up its words of 3 characters or more (cut to 8), intersects the positions, reads only those messages, and checks each against the message as it is: every word of the query must start a word of the message (a word inside another isn't found; words shorter than 3 characters only narrow). Notes are searched too. A profile without the index (from before it, restored, linked) builds it when it opens. Test: `the_index_follows_the_messages`.

**Versioned migrations.** The store keeps a schema version (`meta["schema"]`, `Store::schema`); this version writes 2 (1: the recovery secret wrapped, §1.3; 2: the search index). `Client::open` on an older profile first copies the whole database to `profile.redb.pre-migration` (`Store::snapshot`, one read transaction), then migrates and records the version; if a step fails the copy is put back over the half-migrated file, and once the profile is open it is deleted. A new, restored or linked profile starts at the current version. Test: `old_profiles_migrate_with_a_snapshot_first`.

**Out of OS backups.** A profile is useless without this device's keystore, and a copy in a backup outlives shredding and erasing, so the vault marks the profile directory when it makes it (`enclave_platform::backup::exclude`): the sticky Time Machine exclusion on macOS (the attribute `tmutil addexclusion` writes) and a `CACHEDIR.TAG` everywhere (restic, borg, tar `--exclude-caches` and others skip it). Android's `allowBackup="false"` and iOS's `NSURLIsExcludedFromBackupKey` are set in the app shells (A1, I1); Windows has no per-folder exclusion for File History, and the profile stays in local, not roaming, AppData (D1). Enclave's own backups (§4) are the way to keep a copy.

As PLAN §13 says, there is no monotonic rollback counter on mobile; hedged nonces keep a rolled-back state from reusing a keystream (RT-08).

## 3. Crypto-shredding

Disappearing messages and deletions are sealed under **per-conversation, per-day shred keys** kept in a keyring (`shred::Shredder`).

- A shred key is 32 random bytes (`HedgedRng.fill("store/shred-key", 32)`), created on first use for a `(conversation, day)` pair.
- A message body is sealed with `seal(shred_key, conversation, body)`; `open_msg` fails with `NotFound` once its key is gone.
- The keyring plaintext is a sequence of entries `u32(len(conversation)) ‖ conversation ‖ u64(day) ‖ key (32)`.
- The keyring is sealed with `seal_chunked(wrap_key, "keyring", keyring)` and stored as the record `("__shred", "keyring")`, so it is also sealed under its record key. The current generation `g` is the record `("__shred", "generation")` (`u64`).
- `wrap_key` is a random 32 B secret (`HedgedRng.fill("store/shred-wrap", 32)`) held in the keystore under the name `enclave-shred-{g}`.

**Rewrap** runs whenever a shred key is created and on every shred event:

```
Rewrap():
    g' = g + 1
    wrap' = fresh random 32 B; keystore.create("enclave-shred-{g'}", wrap')
    store ("__shred", "keyring") = seal_chunked(wrap', "keyring", keyring)
    store ("__shred", "generation") = u64(g')
    keystore.destroy("enclave-shred-{g}")
    g = g'

Shred(conversation, before_day):
    remove every key of conversation with day < before_day
    if any was removed: Rewrap()
```

After a shred, any earlier copy of the keyring (for example in a disk image or in unreclaimed database pages) is sealed under a wrap key the keystore has destroyed. Deleted data is therefore unrecoverable from a forensic image taken **after** the shred, as long as the keystore really deleted the old key. With `FileKeystore` that depends on the file system.

Opening a store with no shred generation starts at generation 0 with an empty keyring and rewraps once (generation 1).

## 4. Backups

- `backup_key = KMAC256(rs, "", 256, "enclave/v1/backup/key")`, where `rs` is the 256-bit recovery secret (PLAN: `KMAC(recovery, "backup")`).
- `backup::export(store, namespaces, key, header)` walks the requested namespaces, skips the excluded ones, and encodes every record as `u32(len(ns)) ‖ ns ‖ u32(len(key)) ‖ key ‖ u32(len(value)) ‖ value`. The archive is `"ENCLBAK2" ‖ u64 sequence ‖ u64 created ‖ u8 flags (1: photos and files) ‖ seal_chunked(backup_key, "enclave-backup-v2" ‖ header, records)`: the header is readable without the key (which backup a file is) and bound into the sealing. Archives from before headers (sealed with AD `"enclave-backup-v1"`) still import. No compression.
- **Excluded namespaces** (`backup::EXCLUDED`): `sessions`, `sender-keys`, `__shred`, `prekeys`. Ratchet sessions, sender keys, the shred keyring and prekey secrets therefore never enter a backup, so a restored backup cannot cause key reuse.
- `backup::import(store, archive, key)` opens the archive, skips any excluded namespace it finds, writes every other record into the store, and returns the header and the count.
- **Restoring creates a new device that re-establishes sessions.** Restore needs the recovery words.

**As implemented** (`client/backup.rs`, `client/server_backup.rs`):

- **What goes in**: the profile, the account's shared keys, contacts, every conversation's messages, **notes**, and settings; with **photos and files** only when chosen (the local copies, `files`). The sequence number counts up per account. The device keeps the backup key and the server-backup secret (`backup-keys`, both from the recovery secret), so backups need neither the words nor the PIN; they open backups but can't act as the account, and new words replace them in the same migration step.
- **Kept on the server** (Settings → Keep a backup on my server): the archive (without files) goes up as an ordinary blob, renewed every 7 days from sync so it never reaches the blobs' 30-day expiry, and a pointer sealed under a key from `s = KMAC256(recovery, "", 256, "enclave/v1/store/backup-blob-id")` (the blob reference) is kept as a `DirKind::Vault` object, which doesn't expire, at a locator from `s`, replaceable and deletable only with an owner secret from `s`. A new device with only the words and the server finds and restores it (`Client::fetch_server_backup`, `restore_from_server`; "Restore from my server" when no file is given). Turning it off deletes the pointer.
- **Check my backup**: the words written down open the archive (a file, or the server's) in memory, without restoring anything; it reports the contacts and messages in it and whether its keys are this account's (`Client::check_backup`, `check_archive`).
- **Restoring** builds the search index afresh (it is never backed up) and doesn't stop at a contact it can't start a session with yet (say, their prekeys lapsed while they were away): they reach the new device when they next write.
- Test: `backups_local_and_on_the_server` (`tests/backups.rs`), `backups_exclude_sessions_and_need_the_recovery_secret` (`enclave-store`).

## 5. Device protections

`Store::crypto_erase` destroys the device secret in the keystore, which makes the database file unreadable. It is the primitive for the emergency PIN and panic wipe. The specification:

| Protection | Specification |
|---|---|
| App lock | PIN or biometrics; locks after a user-chosen timeout (default 5 minutes); never unlocks root operations |
| Emergency PIN | A second PIN that crypto-erases the profile (`crypto_erase`), deletes the wrapped root secret, and opens an empty profile. The UI states the caveat: "A copy of your phone made before you used the emergency PIN isn't affected." |
| Panic wipe | Settings action (and optional OS shortcut) that performs the erase without opening a decoy profile |
| Screen security | Android `FLAG_SECURE`; Windows `WDA_EXCLUDEFROMCAPTURE`; macOS `NSWindow.sharingType = .none` (best effort); iOS cannot block screenshots, so the app blurs its snapshot and hides content while the screen is captured |
| Input and clipboard | Android `IME_FLAG_NO_PERSONALIZED_LEARNING`; optional "Block third-party keyboards" on iOS; clipboard cleared 60 s after copying codes or recovery words |
| Lock screen | Shows "New message" by default |

**As implemented** (`enclave-vault/src/lock.rs`, the engine, Settings → Screen lock):

- **Lock settings** live beside the profile in `lock.bin`, readable before it opens: `u8 version ‖ u8 app PIN set ‖ Argon2id parameters ‖ salt (32) ‖ app check (32) ‖ emergency check (32) ‖ u32 timeout`, each check `KMAC256(Argon2id(PIN, salt), "", 256, "enclave/v1/store/app-lock" | "enclave/v1/store/emergency-pin")`. A PIN that isn't set has random bytes in its place, so the file doesn't say whether there is an emergency PIN. One Argon2id run checks an entry against both.
- **App lock**: after the chosen time without a command from the window (1, 5 (default), 15, 60 minutes or never), a profile with a passphrase closes (its keys leave memory; the passphrase opens it); one without gets locked by its **app PIN** (at least 4 digits): the profile stays open and keeps receiving, but the window gets nothing (an empty snapshot) and every command but `Unlock` is refused until the PIN comes. With an app PIN the window also starts locked. Wrong entries: after five, 30 s between tries, doubling to an hour. The app lock never unlocks root actions (the root PIN, §1.3, does). Biometrics: below.
- **Emergency PIN**: accepted wherever the PIN or the passphrase is asked for; it erases the profile (every keystore secret overwritten and removed, then the database and `lock.bin`) and the window goes back to the welcome screen, as on a new install. It can't be the app PIN or the passphrase (`Store::is_passphrase`). Settings shows the caveat.
- **Panic wipe**: Settings → Erase this device, and `enclave --profile DIR --panic-wipe` (`lock::erase_profile`, without opening the profile) for an OS keyboard shortcut.
- **Clipboard**: everything the app copies (codes, links, usernames, message text) is cleared 60 s later if still there.
- Test: `app_lock_and_emergency_pin` (`enclave-vault/tests/process.rs`), `pins_are_told_apart` and `panic_wipe_from_outside` (`lock.rs`).
- **Screen security, as implemented on the desktop**: Settings → Hide from screenshots, on by default and while no profile is open (`NS_SETTINGS` `screen-security`), sets `WDA_EXCLUDEFROMCAPTURE` on Windows and `NSWindow.sharingType = .none` on macOS from the first frame (`enclave_platform::window`). Linux has no such control; Settings says so there. Android's `FLAG_SECURE`, the iOS snapshot blur and the keyboard flags come with A1 and I1.
- **Desktop notifications, as implemented**: after a sync the vault sends the window a notice for new messages in conversations that aren't muted and for message requests (`Out::Notify`); the window shows it through the system (`notify-rust`: the notification service on Linux, the notification centre on macOS, a toast on Windows) unless it is in front. Unless "Show previews" is on, a notice says only "New message", so the lock screen shows nothing more; more than three from one sync become one "N new messages".
- **Biometrics, as implemented**: with an app PIN, Settings → Unlock with Touch ID (macOS, LocalAuthentication) or Windows Hello (`UserConsentVerifier`, attached to the window) lets the lock screen open with it. The vault runs the check and records the choice in `lock.bin` (version 2 adds the byte; version 1 still reads); the passphrase lock and root actions never take it, and removing the app PIN turns it off. Linux has no common biometric API: the PIN only.

## 6. Errors

`enclave_store::StoreError`:

| Error | Cause | Behavior |
|---|---|---|
| `Crypto` | Wrong passphrase or device secret; a record, segment or keyring fails to open | Refuse to open; skip a corrupt record and log locally |
| `Keystore` | Keystore unavailable or failing | Refuse to open the profile |
| `NotFound` | Missing keystore secret; shredded message key | Treat as deleted |
| `Malformed` | Bad metadata, keyring or backup encoding | Refuse the object |
| `Db` | redb error | Retry; report |

## Open questions

1. PLAN §13 describes the Apple master key as a Keychain secret "combined with" a Secure Enclave P-256 unwrap. This spec reads "combined" as two nested wraps of the device secret (both must be removed). An alternative is to feed two independent secrets into the master-key KMAC.
2. ~~The PIN attempt limit and wipe behavior for the wrapped root secret.~~ Decided (§1.3): no wipe on wrong PINs (that would hand anyone holding the phone a way to destroy the account); three free tries, then 30 s doubling to an hour between tries, kept in the profile. Wiping is the emergency PIN's job (§5).
3. ~~A shred rewrap wrote the keyring and the generation in two transactions.~~ Fixed: they are one transaction (`Store::write_batch`), after the new keystore entry is made and before the old one is destroyed.
4. ~~The backup format has no header or version.~~ Decided: archives have a header (§4), version 2.


## Implementation status: backup and restore (M5 follow-up)

`Client::export_backup` (primary only) seals, under `KMAC256(recovery, "", 256, "enclave/v1/backup/key")`, the profile, the shared account keys, contacts, message history (the `m/…` and `mid/…` namespaces) and settings. It never includes sessions, prekeys, the device keys, the shred keyring or group state. `Client::restore(words, archive, …)` re-derives the root from the words, imports the archive, creates a new device, signs and publishes the next manifest listing only that device as primary, publishes its prekeys, and opens fresh sessions with every contact that shared a card. Disappearing messages are not recoverable (their keys were never backed up) and groups are not restored. Token issuers start fresh, and a contact who sees a known account talk from a new device sends it fresh write tokens, so stale tokens in the archive do no harm. The 72 h pending period for root actions without an existing device (RT-22) is `client/guard.rs` (`03-identity.md` §8.1). Server-stored backups and the restore test are §4.
