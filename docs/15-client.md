# Client App and Endpoint Hardening

Status: Draft (M0) · Normative

Source: PLAN.md §14, §22, RT-14. Crates: `enclave-core`, `enclave-ipc`, `enclave-app`, `enclave-sandbox`, `enclave-media`, `enclave-platform`, `enclave-nse`. Platform limits: `15b-platform-constraints.md`. Design: `17-design.md`. Accessibility: `18-a11y-i18n.md`.

## 1. Process split (RT-14)

### 1.1 Desktop: four processes

| Process | Holds | Talks to | Sandbox |
|---|---|---|---|
| `vault` | All long-term keys, ratchet state, the database; runs `enclave-core` (crypto, protocol, storage) | `netd`, `mediad`, UI via IPC | Minimal dependencies; no network sockets; seccomp + Landlock on Linux, App Sandbox on macOS, AppContainer on Windows |
| `netd` | arti and nym-sdk; sees only sealed 16,384 B and 2,048 B objects | `vault` | Network only; no file access beyond its cache |
| `mediad` | Decoders and encoders (images, Opus, AV1), capture | `vault`, UI (decoded RGBA and PCM only) | seccomp + Landlock, the macOS App Sandbox via XPC, or AppContainer; no network |
| UI (Slint) | Rendering, input; never key material | `vault` (typed commands and events), `mediad` (frames) | Standard user process |

IPC is typed `postcard` messages over a Unix domain socket (Linux, macOS) or a named pipe (Windows), defined in `enclave-ipc`. Each message type has a fixed maximum size; parsing is fuzzed. The `vault` process authenticates its peers by OS credentials (peer UID/PID checks) and by a per-launch random 32 B secret passed through inherited handles.

### 1.1a Implemented: UI, vault, netd and mediad

Today the desktop app runs as **four** processes: the Slint UI (`enclave`), the vault (`enclave-vault`, crate `enclave-vault`), which runs the client engine and holds every key and the sealed store, `enclave-mediad` (crate `enclave-mediad`), which decodes and re-encodes pictures, and, when connected to a server, `enclave-netd` (crate `enclave-netd`), which holds the network. Over the mixnet netd starts two helpers of its own: `enclave-tord` (Tor, a loopback SOCKS5 port) and `enclave-nymd` (the Nym client, which reaches its gateway only through tord), `09-transport.md` §1. With Snowflake or WebTunnel bridges, tord starts `lyrebird` (`09-transport.md` §7).

- **Messages** (`enclave-ipc`) are exactly three kinds: `Cmd` (UI → vault: what the person did), `Snapshot` (vault → UI: display data only — names, message text, previews, security-code digits) and `Effect` (vault → UI: a few one-off UI resets). They use a strict hand-written codec rather than `postcard` (no serde in the workspace): every field is length-bounded, counts are checked against the bytes left before allocating, trailing bytes are an error, and a hostile-input test flips bytes and truncates at every offset.
- **Files** cross as bytes (at most 15 MiB per message for now): the UI reads a file the person picks and writes a saved attachment into their Downloads folder, so the confined vault never touches the person's files. Saved names keep only their last path component and never overwrite an existing file.
- **Recovery words** are the one secret the UI must display. They are in snapshots only while the recovery sheet is open (`Cmd::RevealWords`), so the UI process holds them only then.
- **Framing**: `u32 BE length ‖ body`, at most 16 MiB.
- **Launch and authentication** (Unix): the UI creates a directory with mode 0700 under the temp dir, listens on `vault.sock` inside it, and starts `enclave-vault --connect <socket> <mode args>` from next to its own executable with a fresh 32-byte token (from the hedged RNG) written to the child's **stdin**. The vault connects and sends the token first; the UI compares it in constant time, then unlinks the socket and the directory, so no other process can connect. A command that does not decode ends the connection. When the UI goes away the vault's engine loop ends and it exits; when the vault dies the UI says so ("Enclave's vault stopped… Restart Enclave.").
- **App lock**: a profile on disk can have a passphrase, chosen when the account is created (`Options::passphrase`, Argon2id with `PwParams::DESKTOP_DEFAULT`, 1 GiB and 4 passes). The vault starts locked when opening fails without it and shows only the unlock screen; **Lock now** drops the client, and with it the keys and the open database, from the vault's memory. It can be set, changed or removed later in Settings (`Store::change_passphrase`): the store's master key never changes, it is wrapped under a key from the device secret and the new passphrase with a fresh salt, in one transaction, so no record is re-encrypted.
- **Launch on Windows**: the same flow over a **named pipe**. The UI creates `\\.\pipe\enclave-<32 random hex>` as the first and only instance (`first_pipe_instance`, `max_instances(1)`, remote clients rejected), so no other process can create the name before or after it, starts `enclave-vault --connect <pipe>`, writes the token to its stdin and waits up to 30 s for the connection. The vault opens the pipe as a client and sends the token first, as on Unix. There is no client-pid check yet (`GetNamedPipeClientProcessId` needs `unsafe`, which is kept out of these crates); the single instance and the token stand in for it. This path is compile-checked for `x86_64-pc-windows-gnu`, not yet run on Windows.
- **Fallback**: where the vault binary is missing, on platforms that are neither Unix nor Windows, and with `--single-process`, the same engine runs on a thread in the UI process.
- **Peer check**: the UI also asks the kernel who connected (`SO_PEERCRED`, where available) and requires the child's pid.
- **Vault hardening** (`enclave-sandbox`, used by `enclave-vault::harden`): core-dump limit 0; on Linux `PR_SET_DUMPABLE 0` (no same-user debugger attach or `/proc/<pid>/mem`) and `no_new_privs`; and, once connected, a **Landlock** sandbox: read-write only under the profile directory, read-only for the pin file and time-zone data, and (with netd running) **no TCP connect or bind at all** (Landlock ABI 4 network rules, handled with no port allowed). Best effort on older kernels; `--report` prints what took effect (`filesystem`, `network: "netd"`), and a test runs the sandboxed vault against a TCP dev server to prove the profile and the server both still work through netd. A unit test confines one thread and checks that TCP connects and reads outside the allowed directory fail while the allowed directory stays writable.
- **Starting** (`enclave-vault::Mode`): an installed build starts with no arguments. The profile is in the platform's local data directory (`directories`: `~/.local/share/enclave`, `~/Library/Application Support/io.github.EnclaveChat.Enclave`, `%LOCALAPPDATA%\EnclaveChat\Enclave\data`, or a Flatpak's own), `--profile DIR` otherwise. The home server is the profile's; setting up, restoring from the server or linking, it is one picked from the checked server list, weighted by the list (`ServerList::pick`), which the person can change on the name screen (the server sheet: domain and operator). The vault routes to every listed server over the mixnet from the start, and netd starts nymd with `--mixnet` even before a route is known. `--server ID=ROUTE` still names a home directly (development, tests). The demo (`--demo`) is the `demo` feature of `enclave-vault` and `enclave-app`, off in release builds, so they link neither `enclave-server` nor `enclave-sim`.
- **netd** (server mode): the vault starts `enclave-netd --server <id>=<addr>` from next to its own executable *before* it confines itself, and talks to it over the child's stdin and stdout (`enclave-ipc::net`: `NetRequest::{Exchange, ServerKey}` with request ids so several can be in flight, `NetReply` with the bytes or an error; same framing and strict codec). netd only moves sealed requests and sealed replies and fetches servers' public request keys, checking each server's signed key bundle against its id before handing the key (`key_id ‖ x448 ‖ mlkem`) to the vault (`12-servers.md` §4.2); it holds no keys, hardens itself the same way and takes **no filesystem access**. It links neither `enclave-store`, `enclave-core` nor `enclave-proto` (test `rt14_netd_has_no_key_material` walks its dependencies). If netd is missing or fails to start, the vault uses the network itself and reports `network: "in-process"`. Demo mode needs no network and starts no netd.
- **seccomp** (`enclave_sandbox::syscalls`, Linux): after Landlock, an **allow-list** on every thread: the calls a process of its kind makes (memory, threads, time, signals, polling, I/O on descriptors it holds, waiting for and ending the helpers it started), and `EPERM` for every other, so starting programs, debugging others, namespaces, mounts, `bpf`, `io_uring`, the keyring, modules and anything a future kernel adds are all refused. Arguments are checked where a call can do more: `clone` never with `CLONE_NEWUSER` (`clone3` passes its flags by pointer, so a user namespace through it is stopped by `unshare` and `setns` not being allowed), `ioctl` only for terminal and non-blocking requests, `prctl` only to name threads and read state (never `PR_SET_DUMPABLE` or `PR_SET_PTRACER`). Three profiles: **vault** adds files (Landlock limits which) and opens no socket at all; **netd** (also tord and nymd) adds new IPv4 and IPv6 sockets only (`socket` checked), `connect`, `bind`, `listen`, `accept`; **media** (mediad) has neither files nor sockets, only its pipes. The list came from tracing the processes under their tests (`strace`); `ENCLAVE_SECCOMP_LOG=1` logs a refused call instead of refusing it, to find one a new library version makes. `--report` shows `syscalls: "filtered"`; unit tests confine one thread per profile and check files, TCP, UDP, Unix sockets, `exec` and `PR_SET_DUMPABLE`, and the process tests run the whole vault, netd and mediad under it.
- **macOS**: each helper confines itself with a Seatbelt profile (`sandbox_init`, what the App Sandbox is built on; `enclave_platform::seatbelt`, written by `enclave_sandbox::filesystem` from the same paths as Landlock): no programs started, no writes outside its directories, nothing read in the home folder beyond them (the vault keeps its Keychain files readable), and for the vault (with netd) and mediad no IP connections. The App Sandbox proper isn't used: helpers started by a sandboxed app must inherit its sandbox and entitlements, which would give the window the network and the Keychain. Binaries are signed with the hardened runtime and their own entitlements (`packaging/macos/`).
- **Windows**: mediad starts in an **AppContainer** with no capabilities (`enclave_platform::appcontainer`: no network, no files or registry keys not granted to all app containers, low integrity), its pipes its only channel; where the program isn't readable from the container (a development build outside Program Files) it starts as an ordinary process.
- **mediad**: the vault starts `enclave-mediad` next to netd, before confining itself, and talks to it over the child's stdin and stdout (`enclave-ipc::media`: `MediaRequest { id, Sanitize | Thumbnail(side), bytes }`, `MediaReply` with a re-encoded file, RGBA pixels whose length must equal `width × height × 4` with checked arithmetic, or an error). mediad hardens itself before reading anything: the same process steps, a **2 GiB address-space cap** (`RLIMIT_AS`, so a picture that decodes to more than it claimed fails an allocation), Landlock with **no filesystem and no TCP**, and the **media** seccomp profile (**no files, no sockets**, no `exec`). It links neither the store, the engine, the protocol, the crypto crate nor the network crate (test `mediad_has_no_key_material`). It sees pictures only: ones the person is sending, and decrypted attachments. The vault then forwards previews to the UI as `Out::Preview` (conversation, message position, RGBA), so the UI never decodes a file either. Without the binary (single-process mode, tests), the same `enclave-media` code runs in the vault on a blocking thread and `--report` says `media: "in-process"`.
- **Spares**: after its seccomp filter the vault can't start programs, so it starts spares up front: two extra `mediad` processes and one extra `netd`, each confined the same way. Requests go to the first helper still running; one that dies (a picture that crashes the decoder, say) fails what it had in flight and the next request goes to a spare. A request is never retried on a spare (a picture that killed one decoder would kill the next), and the engine never asks for a preview that failed again, so one bad picture costs at most one helper. When every spare is gone, previews (or the network) stop until the app restarts. Test `a_dead_mediad_is_replaced_by_a_spare`.

### 1.2 Android

- The network service runs in its own `android:process` (the netd role).
- Decoders run in an `isolatedProcess` service (the mediad role).
- The app process holds the vault role and the Slint UI (the UI never receives key material through the command API).

### 1.3 iOS

- A single app process plus the Notification Service Extension. This is an accepted residual risk (RT-14).
- Image and audio parsers run inside a **WASM isolation sandbox** (wasmi or the Pulley interpreter; no JIT) in `enclave-sandbox`.
- The NSE (`enclave-nse`) decrypts capsules only (`10-push.md` §5.1).

### 1.4 Rules

- `netd` MUST NOT link `enclave-store` or hold any key other than transport session keys (test `rt14_netd_has_no_key_material`).
- `mediad` receives only encrypted-then-decrypted media bytes from `vault`, never keys; it returns only raw RGBA, PCM, or re-encoded outbound media.
- **Traffic shaping** runs in the vault, not netd: the vault wraps its transport (netd's pipe, or the in-process fallback) in `ShapedTransport`, so netd only ever sees one unit and one poll per tick, real or cover (`09-transport.md` §6.7). The vault picks the profile from the Maximum privacy setting and opens bulk windows around the commands that need them. `enclave-vault --no-shaping` turns shaping off for development.
- A crash in `netd` or `mediad` is recovered by restarting that process; `vault` state is unaffected.

## 2. UI

- **Slint ≥ 1.18**, one codebase for desktop, Android, and iOS.
- The UI never touches key material. It talks to `enclave-core` through a typed async command/event API (with a UniFFI feature for the fallback shells of §3.3).
- **Skia (C++) is required on Android and iOS** because Slint's mobile backends depend on it. It is fed only Enclave's own paths, text, and decoded RGBA, with its codecs disabled (PLAN §22 exception).
- **Unicode hygiene** for all names (contacts, groups, devices, file names): NFKC normalization; at most 8 combining marks per base character (excess removed); bidi control characters (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C) removed from names and isolated in message text with first-strong isolation; zero-width characters removed from names.
- Security events are shown inline and persistently, never as toasts (`17-design.md` §8).

## 3. Accessibility gate (M1.5 and M6, hard)

### 3.1 Must pass

- TalkBack and VoiceOver can operate the chat list, composer, and the verification flow (security code, in-person scan, "They match").
- CJK and Indic IME input, RTL layout, color emoji, 200% text, and text selection and copy all work.

### 3.2 Current gap

Slint's Android backend has no AccessKit wiring today. The project will fund or build, and upstream, the `accesskit_android` and `accesskit_ios` integration.

### 3.3 Fallback

If the gate is still blocked **8 weeks after M6**, mobile gets thin SwiftUI and Jetpack Compose shells over the same Rust core via UniFFI, as a declared exception. **Accessibility outranks language purity.** The shells hold no keys and no protocol logic.

## 4. Platform shims

- `enclave-platform` is the only crate (with `enclave-sandbox` and `enclave-nse`) allowed `unsafe`; every `unsafe` block gets two reviews and a tracking comment.
- **Desktop chrome, as implemented**: the app is a GUI program on Windows (`windows_subsystem = "windows"`; started from a terminal it attaches to that console for its messages), and every helper (vault, netd, mediad, tord, nymd) is started with `CREATE_NO_WINDOW` (`enclave_platform::process`), so no console window appears. File dialogs are the system's (`rfd`; the desktop portal on Linux, so they work in a Flatpak): choosing a backup to restore or check, a file to send and sticker pictures, next to the path fields, and saving an attachment or a backup asks where, starting in Downloads. The icon is drawn in `design/icon/` (a Pine letter whose flap is held by a paper-colored Seal; a full-bleed variant for masks and stores, a one-colour one for themed and symbolic icons); `cargo xtask icons` renders every size, the `.ico` and the `.icns` into `packaging/icons/`, and CI checks they match. Settings → About Enclave shows the version, the licence, `AboutSlint` (PC-80) and the open-source notices, which `cargo xtask licenses` collects from every package the desktop binaries ship (with nymd's) into `crates/enclave-app/licenses.txt`, checked in CI.
- **As implemented so far**, `enclave-platform` holds the AArch64 DIT guard and the locked-memory slab for secret key bytes (`dit`, `mem`; `02-cryptography.md` §12), with only `libc`/`windows-sys` beneath it so `enclave-crypto` can depend on it; the keystores and capture, audio and camera shims join it with the desktop and mobile milestones, behind features. Its unsafe blocks carry SAFETY comments and `undocumented_unsafe_blocks` is denied; their two reviews are owed.
- **Exception, `enclave-av1`**: rav1d exposes only dav1d's C interface, so the AV1 decoder wrapper needs `unsafe` (§5.3). It is ~150 lines, every block has a SAFETY comment and clippy's `undocumented_unsafe_blocks` is denied; only `mediad` (through `enclave-media`'s `av1` feature) and the fuzz harness call it. A whole-workspace build unifies features, so the code can end up in the vault binary too, but nothing there reaches it: the vault's own media fallback refuses `ClipFrames`. Its two reviews are still owed.
- Android: `jni` and `ndk`, with Kotlin shims of at most 300 lines total and Slint's Java helper.
- Apple: `objc2` for APNs, PushKit, CallKit, Keychain, Secure Enclave, VoiceProcessingIO, and `define_class!` for the NSE principal class.
- Windows: the `windows` crate (CNG, DPAPI, window display affinity).
- Linux: `zbus` (Secret Service, notifications, portals).
- The ARM DIT bit is set around cryptographic operations (`02-cryptography.md` §12).

## 5. Media policy (few formats, few decoders)

| Kind | Sender | Receiver |
|---|---|---|
| Images | Re-encode to JPEG or PNG, at most 4,096 px on the long edge, with EXIF and GPS stripped | Decode in the sandbox (`zune-jpeg`, `png`) to raw RGBA, 25 MP cap. Re-encode only on export. |

**Images as implemented** (`enclave-media`, used by mediad):

- A picture is recognised by its first bytes only (JPEG `FF D8 FF`, PNG signature); names and MIME types never decide what gets decoded. A file named `.jpg` that isn't one is sent as a plain file (`application/octet-stream`).
- **Sending**: decode, apply the EXIF orientation (the only tag read; a bounded TIFF walk), shrink by area averaging to at most 4,096 px on the long side, and encode a new file: JPEG at quality 85, or PNG when any pixel is not fully opaque. The original file never leaves the device, so EXIF (GPS, camera, time), XMP, ICC profiles, text chunks and trailing data are gone; the name keeps its stem with the new extension. A picture that doesn't decode is not sent ("Enclave couldn't read that picture, so it wasn't sent.").
- **Receiving**: pictures (JPEG or PNG attachments of at most 16 MiB) in the open conversation, from **accepted contacts only**, are downloaded and decoded to a preview of at most 560 px, a few per pass. Message requests never download anything. The bubble shows the picture above its caption, and "Photo: <name>" until the preview arrives or if it can't be decoded.
- **Limits** before any pixel is decoded: input ≤ 64 MiB, picture ≤ 25 MP (from the header), and the PNG decoder's own byte limit. Tests cover forged header sizes, truncation and bit flips, and a fuzz target (`media`) runs the receiver's path.
- Not done: previews in groups, a full-size viewer, animated images, export re-encoding.
| Animated images | Sent as short AV1 clips (no GIF, APNG, or WebP decoders) | AV1 decode in the sandbox |
| Video | AV1 + Opus in Enclave's own fixed-chunk container (no MP4 or WebM demuxer). The sender's own camera files are read with the OS decoder and transcoded. | rav1d and Opus in the sandbox |
| Voice notes | Opus | Opus in the sandbox |
| Files | Sent as-is | **Never previewed.** "Open with…" shows a warning: "Files can contain harmful content. Only open files you expect." |
| From strangers | — | **Nothing auto-downloads.** Message requests show text only. |
| Link previews, GIF search | **Off by default.** When on, generated on the sender side only, fetched through Tor | Shown as a static image and title |

### 5.1 Fixed-chunk container

The container is a sequence of 64 KiB records, each `u8(track) ‖ u32(pts_ms) ‖ u16(frames) ‖ payload`, with a header record listing tracks (AV1 or Opus, with fixed parameters). It has no variable-length boxes, no nesting, and no index; it is fuzzed as a parser (`20-assurance.md` §1).

### 5.2 As implemented: voice notes

`enclave-media/src/voice.rs`. Voice notes use a simpler audio-only container than §5.1 (video isn't built): `"EVN1" ‖ u32 frames ‖ u16 packet_len ‖ 64 B waveform ‖ frames × packet_len`. Every frame is 20 ms of 48 kHz mono Opus at a constant 24 kbit/s (60 B), so a note's size follows from its length alone, and at most 15 minutes. The codec is pure Rust, so PLAN §22's libopus exception isn't needed for voice notes: `opus-rs` encodes (it only ever sees our own audio) and `opus-decoder` (RFC 8251 conformant, no unsafe code) decodes what other people send; both run in `mediad` (`MediaOp::VoiceNote`, `VoiceInfo`, `VoiceWav`), and `enclave-fuzz`'s `media` target covers the container and the decoder.

On the desktop a voice note comes from a WAV recording sent from the attach sheet (16- or 8-bit PCM, mono or stereo, 8–96 kHz): it is resampled and re-encoded, so nothing of the file but its sound leaves the device (no name, no `LIST`/`INFO` chunks). It travels as an ordinary sealed attachment (`audio/x-enclave-voice`). The conversation shows a waveform and the length, read by `mediad` from the note; **Save** writes a WAV decoded by `mediad`. Tests in `enclave-media` and `voice_note_through_the_engine`. Not done: recording from the microphone and playing in the app, which need the platform audio shims (`cpal` over ALSA/PulseAudio, CoreAudio, WASAPI; this build environment has no audio stack), and speech-to-text.

### 5.3 As implemented: animated pictures (AV1 clips)

`enclave-media/src/video.rs`, `enclave-av1`, mediad's `Clip`, `ClipPoster` and `ClipFrames` operations.

- **Sending**: a GIF chosen in the attach sheet (recognised by its first bytes) is never sent as a GIF. mediad reads it (the person's own file), composites its frames (disposal and transparency handled, flattened onto white), resamples them to 15 frames a second, shrinks them to at most 480 px, cuts the result at 15 s, and encodes AV1 with **rav1e** (pure Rust, built without assembly or threads; speed preset 10, about 400 kbit/s, no frame reordering). The first frame also becomes a JPEG poster. The attachment is `name.clip`, `video/x-enclave-clip`.
- **Container**: §5.1's fixed records, 64 KiB each: a header record (`"EVC1"`, version, size, frame rate, frame count, length, codec, poster) and records of `u32 len ‖ temporal unit` entries, one per displayed frame, zero-padded. `parse_clip` checks every length, count, timestamp and padding byte; at most 64 records (4 MiB).
- **Receiving**: in the open conversation (accepted contacts and groups only, like pictures), the clip is downloaded and mediad decodes **only the poster** (the ordinary JPEG path) for the bubble, which shows the poster and **Play · 0:03**. Play has mediad decode the AV1 with **rav1d** (pure Rust, no assembly, one thread, 8-bit 4:2:0 only, a frame-size limit) and returns at most 64 evenly spaced frames of at most 360 px, which loop in a player sheet (the first frame only with reduce motion).
- **The vault never decodes other people's AV1**: without mediad (single-process mode), Play shows "Enclave couldn't play this one."
- **Tests**: GIF → clip → frames round trip with colours checked (`enclave-media`, feature `av1`); container tampering (padding, counts, frame rate, truncation) refused; long and wide GIFs cut and shrunk; through the engine (`clips_through_the_engine`: the file goes out as `.clip`, the poster and length show, the vault refuses to decode); and in the **confined mediad** (`mediad_plays_clips`: encode, poster and full decode under its sandbox). The `media` fuzz target runs the parser, the poster path and the decoder on raw units. Screenshots 51–52.
- **Not built, and why**: video from a camera or a video file. There is no camera here, and reading the person's own MP4/MOV needs the platform's decoder (AVFoundation, MediaCodec, Media Foundation), which the platform shims don't have yet; the clip path above is what a camera recording would be transcoded into. Sound in clips (the container has room for an Opus track; voice notes already use the codec), 30 fps and larger sizes for real video, and the M8 gate (360p30 on the reference phone) are open.

## 6. Feature parity

The feature matrix is in `16-features.md`.

## Open questions

1. The fixed-chunk container (§5.1) record layout is a proposal; `enclave-media` finalizes it at M9 with fuzzing.
2. Whether the Android vault role should also be split from the UI process (PLAN §14 splits only network and decoders on Android).
3. The Unicode bidi handling in message text (isolation rather than removal) is this spec's choice; PLAN §14 says "bidi controls neutralized in names" only.
