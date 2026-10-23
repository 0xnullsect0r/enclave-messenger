# Release checklist

Status: living document · steps a person runs before tagging a release

Everything that can be automated runs in CI (`.github/workflows/ci.yml`);
this list is what can't, or what measures hardware rather than code,
including the red-team matrix's "Manual" rows (`redteam-matrix.md`).

## The first release

- [ ] **Package visibility.** GHCR makes a new package private. After the
  first release, set `enclave-server`, `enclave-nym`, `enclave-updater` and
  `enclave-stack` to public (the organization's Packages, each package's
  settings, "Change visibility"), and check that an anonymous
  `docker pull ghcr.io/0xnullsect0r/enclave-server:latest` works.
- [ ] **TestFlight.** Make the public TestFlight link and put it in
  `ci/release/notes.md`.
- [ ] **Export compliance.** In App Store Connect (App Information → App
  Encryption Documentation), copy the approved document's key into the
  repository variable `IOS_EXPORT_COMPLIANCE_CODE`; `apps/ios/bundle.sh`
  writes it into the app's Info.plist, so builds upload without the
  question.
- [ ] **Google Play.** Upload the first `Enclave-VERSION.aab` by hand
  (Play Console → Testing → Internal testing; Google takes an app's first
  bundle only that way), then create a Google Cloud service account, invite
  it in Play Console (Users and permissions) with release rights for the
  app, and put its JSON key in the `release-android` environment's secret
  `PLAY_SERVICE_ACCOUNT_JSON`. Release `play` (`ci/release/play.sh`) then
  sends every release to the internal track (the repository variable
  `PLAY_TRACK` picks another).

## Tor bridges

- [ ] **WebTunnel.** Get a WebTunnel bridge line from bridges.torproject.org
  (it has no built-in ones), paste it under Settings → Tor bridges on an
  installed build, restart, and check Enclave connects (CI's `tor-smoke`
  covers obfs4 and Snowflake on the live network).

## Server

- [ ] **Scale.** On a machine of the class operators are told to use, run
  `cargo run --release -p enclave-server --example scale -- --accounts 100000`
  (and `--postgres URL` for the PostgreSQL backend) and update the
  measured table in `12-servers.md` §7 if it moved by more than 20%.

## Red-team manual checks

- [ ] `rt08_db_excluded_from_os_backup` (RT-08). On an installed build of
  each platform, create a profile, send one message, then:
  - **macOS:** `tmutil isexcluded ~/Library/Application\ Support/com.aricummings.Enclave`
    says `[Excluded]`, and the folder holds a `CACHEDIR.TAG`.
  - **Linux:** the profile folder (`~/.local/share/enclave`, or the
    Flatpak's `~/.var/app/com.aricummings.Enclave/data/enclave`) holds a
    `CACHEDIR.TAG`; `restic backup --exclude-caches ~` and
    `tar --exclude-caches -c ~ | tar t` leave it out.
  - **Windows:** the profile is `%LOCALAPPDATA%\aricummings\Enclave\data`
    (not the roaming AppData), and holds a `CACHEDIR.TAG`.
  - **Android:** `adb shell bmgr backupnow com.aricummings.enclave`
    reports the package isn't eligible, and a device-to-device transfer
    (Settings → System → Backup) doesn't offer Enclave.
  - **iOS:** make an encrypted computer backup (Finder) and list it with
    `idevicebackup2` or another backup reader: no file of the app's
    profile directory is in it; Settings → [name] → iCloud → Manage
    Storage → Backups shows Enclave at a few kilobytes at most.

  Any profile file in a backup fails the check (`14-storage.md` §2.4).

## Screen readers

Run each script with the screen reader on and the screen covered (or
the display off), on an installed build; every step must be possible
by gestures alone, and every control must be announced by name and role.

- [ ] **TalkBack (Android)** and **VoiceOver (iOS, macOS)**:
  1. Welcome: "Get started" is announced as a button; activate it; enter
     a name; finish setup.
  2. Chat list: swipe through the conversations; each is read with its
     name, last message and unread count; open one.
  3. Composer: focus the message field, type with the keyboard, send;
     the sent message is read back with its state ("On its way",
     "Delivered").
  4. Verification: open the contact's sheet, "Check code"; the security
     code is read in groups; activate "They match"; the contact is
     announced as verified.
  5. Settings: change the privacy profile and back; open "About Enclave".
- [ ] **Narrator (Windows)** and **Orca (Linux)**: the same five steps
  with the keyboard only (Tab, arrows, Enter, Escape), with the focus
  ring visible at every step.

## Running in the background (desktop)

- [ ] On Windows, macOS, KDE Plasma and GNOME with the AppIndicator
  extension: close the window; Enclave's icon stays in the notification
  area or menu bar; a message from another device arrives as a
  notification; the icon's "Open Enclave" (and, on Windows and Linux, a
  click on it) brings the window back; starting Enclave again also does;
  "Quit Enclave" ends every Enclave process.
- [ ] On GNOME without the extension: closing the window quits.

## Before 1.0

- [ ] `cargo test -p xtask -- --ignored --exact supply::tests::rt14_cargo_vet_complete_for_crypto_and_parsers`
  passes: every crate `supply-chain/README.md` lists is covered by an
  audit, not an exemption (External Gate G15).
