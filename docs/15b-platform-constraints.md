# Platform Constraint Register

Status: Draft (M0) · Normative

Source: PLAN.md §10, §13, §14, §17, §18, §22, Appendix A. This register lists every platform rule or limit that shapes Enclave's design. Each row has a status from PLAN Appendix A (**V** verified, **V\*** standard value from memory, **U** unresolved with an assigned check) and the milestone where it is checked or re-checked. Design responses MUST NOT assume a constraint away; if a constraint changes, update this register first.

## 1. iOS and iPadOS

| ID | Constraint | Status | Consequence for Enclave | Spec | Check |
|---|---|---|---|---|---|
| PC-01 | Notification Service Extension limits: about 24 MB memory and about 30 s run time | V | The NSE decrypts the 1 KB capsule with symmetric crypto only; it never runs arti, Nym, Argon2id, or ratchet code | `10-push.md` §5.1 | M1.5 spike (c): capsule decrypt under 24 MB |
| PC-02 | PushKit VoIP pushes MUST be reported to CallKit, or the app is terminated and loses VoIP push | V | Incoming calls use PushKit → CallKit; the use is disclosed in the privacy policy | `11-calls.md` §2 | M8 |
| PC-03 | CallKit is unavailable for apps in mainland China | U | Fall back to a regular notification there | `10-push.md` §5 | M6 |
| PC-04 | Apps cannot block screenshots or screen recording | V | Blur in the app switcher; hide content while `UIScreen.isCaptured`; copy never promises screenshot blocking on iPhone | `14-storage.md` §5 | M6 |
| PC-05 | Background execution is suspended; no long-running background network | V | No cover traffic in the background on iOS; the iOS Background profile is "none"; Maximum works only while open; UI says so | `09-transport.md` §6.3 | M4 |
| PC-06 | The notification-filtering entitlement (`com.apple.developer.usernotifications.filtering`) needs Apple's approval | V | Dummy wakes only if granted; otherwise jitter only (RT-16) | `10-push.md` §5 | Apply at M6 |
| PC-07 | No helper processes other than app extensions | V | Single process plus NSE; image and audio parsers in a WASM sandbox | `15-client.md` §1.3 | M6 |
| PC-08 | No JIT for third-party apps | V | WASM sandbox uses an interpreter (wasmi or Pulley) | `15-client.md` §1.3 | M6 |
| PC-09 | App Store terms conflict with plain GPLv3 | V | GPLv3 §7 additional permissions at M0; AGPL and GPL-only crates blocked from iOS builds by `cargo deny` | `19-ops.md` §2 | M0 |
| PC-10 | Store binaries cannot be reproduced or verified by users | V | "Verify this build" is not offered on iOS; residual RT-13 | `19-ops.md` §1 | — |
| PC-11 | Apps with account creation must offer in-app account deletion (App Store Review Guideline 5.1.1(v)) | V\* | Account deletion flow | `03-identity.md` §8.5 | M6 |
| PC-12 | The Secure Enclave supports only P-256 keys | V\* | Secure Enclave is one of two nested wraps, never the only one | `14-storage.md` §1.1 | M5 |
| PC-13 | Third-party keyboards can see typed text | V\* | Optional "Block third-party keyboards" | `14-storage.md` §5 | M6 |
| PC-14 | APNs payload limit 4 KB | V\* | Capsule is 1,024 B (1,368 B in base64) | `08-envelope.md` §5.4 | M4 |
| PC-15 | NSE reads shared data only from an app-group container; Keychain items must be `AfterFirstUnlock` to be readable while locked | V\* | Notification key table stored separately from the main database | `10-push.md` Open questions | M1.5 |
| PC-16 | Slint iOS backend is a tech preview and needs Skia; no AccessKit iOS wiring in Slint yet | V | Hard accessibility gate; fallback SwiftUI shell | `15-client.md` §3 | M1.5, M6 |
| PC-17 | Export-compliance questions at submission; France declaration | V | Handled with counsel | `19-ops.md` | M11 |

## 2. Android

| ID | Constraint | Status | Consequence for Enclave | Spec | Check |
|---|---|---|---|---|---|
| PC-20 | Foreground services must declare a type (Android 14+); `specialUse` needs Play review justification; `remoteMessaging` has its own policy | U | Play build uses `specialUse`/`remoteMessaging` if accepted; otherwise FCM content-free wakes plus Poisson dummy wakes | `10-push.md` §5 | M1.5 spike (d) |
| PC-21 | Android 15 caps `dataSync` foreground services at 6 h per 24 h | V | `dataSync` is not used for the always-on Background profile | `09-transport.md` §6.3 | M4 |
| PC-22 | Doze, App Standby, and OEM battery managers may stop background work | V\* | The foreground service with an ongoing notification is required; the app guides users through battery-optimization exemptions where OEMs require it | `09-transport.md` §6.3 | M4 |
| PC-23 | F-Droid forbids proprietary dependencies (no Firebase) | V\* | F-Droid build has no FCM; UnifiedPush is the opt-in; reproducible build | `10-push.md` §5, `19-ops.md` | M6 |
| PC-24 | `isolatedProcess` services have no network, no file access, and minimal permissions | V\* | Decoders run there and receive data only over binder | `15-client.md` §1.2 | M6 |
| PC-25 | `android:allowBackup` and cloud backup include app data unless disabled | V\* | `allowBackup=false`, `fullBackupContent=false` | `14-storage.md` §2 | M5 |
| PC-26 | `FLAG_SECURE` blocks screenshots and recording of a window | V\* | Set on all windows by default | `14-storage.md` §5 | M6 |
| PC-27 | StrongBox is not present on all devices | V\* | Fall back to TEE-backed Keystore | `14-storage.md` §1.1 | M5 |
| PC-28 | Slint's Android backend needs Skia and has no AccessKit wiring | V | Hard gate; fund `accesskit_android`; fallback Compose shell | `15-client.md` §3 | M1.5, M6 |
| PC-29 | FCM data payload limit 4 KB; high-priority messages are rate-limited if they do not show notifications | V\* | FCM wakes are content-free; dummy wakes at about 1 per hour | `10-push.md` §5 | M4 |
| PC-30 | Kotlin/Java entry points are required for services and activities | V | Kotlin shims ≤300 lines, no logic, no keys | `15-client.md` §4 | M6 |

## 3. Desktop

| ID | Platform | Constraint | Status | Consequence | Spec | Check |
|---|---|---|---|---|---|---|
| PC-40 | macOS | Distribution outside the store needs notarization and the hardened runtime | V\* | Notarized DMG plus updater | `19-ops.md` §1 | M6 |
| PC-41 | macOS | App Sandbox; helper processes via XPC | V\* | `mediad` is an XPC service | `15-client.md` §1.1 | M5 |
| PC-42 | macOS | Screen-capture exclusion is best effort | V\* | `sharingType = .none`; copy does not promise blocking | `14-storage.md` §5 | M6 |
| PC-43 | Windows | MSIX packages must be signed; AppContainer for sandboxing | V\* | Signed MSIX plus updater; `mediad` in AppContainer | `19-ops.md` §1 | M6 |
| PC-44 | Windows | `WDA_EXCLUDEFROMCAPTURE` needs Windows 10 2004 or later | V\* | Minimum supported version is Windows 10 2004 | `14-storage.md` §5 | M6 |
| PC-45 | Linux | Secret Service may be absent | V\* | Passphrase fallback, mandatory in that case | `14-storage.md` §1.1 | M5 |
| PC-46 | Linux | Landlock needs kernel 5.13+; seccomp everywhere | V\* | Degrade to seccomp only on older kernels and warn in Settings | `15-client.md` §1.1 | M5 |
| PC-47 | Linux | Flatpak sandbox limits process spawning and IPC paths | V\* | Use portals; `mediad` spawned via `flatpak-spawn --sandbox` or an in-sandbox subprocess | `15-client.md` §1.1 | M6 |
| PC-48 | All desktop | Not an always-on node; background profile only while running | V (decision) | Tray mode runs the Background profile; no server role | `09-transport.md` §6.3 | M4 |

## 4. Network and third-party services

| ID | Constraint | Status | Consequence | Spec | Check |
|---|---|---|---|---|---|
| PC-60 | Nym entry gateways require zk-nym credentials | V | Credential proxy with proof of work plus Privacy Pass | `09-transport.md` §7.1 | M4 |
| PC-61 | Disabling Nym's Poisson stream must be a supported production configuration | U | M4 gate; otherwise the scheduler design is revisited | `09-transport.md` §6 | M1.5, M4 |
| PC-62 | nym-sdk memory on mobile | U | Gate ≤150 MB | `09-transport.md` §7.2 | M1.5, M4 |
| PC-63 | Nym Sphinx is classical; PQ links not yet in the SDK | V / U | Sealed requests keep mailbox IDs PQ; adopt PQ Sphinx when available | `09-transport.md` §2, §7.5 | M12+ |
| PC-64 | Tor exit capacity and exits blocking gateways | U | Load estimate uses exit capacity; coordinate with the Tor Project | `09-transport.md` §1 | M4 |
| PC-65 | Snowflake and WebTunnel exist only in Go | V | Subprocess or IPtProxy, censorship mode only | `09-transport.md` §7.4 | M9 |
| PC-66 | APNs and FCM accept only the publisher's credentials | V\* | The project runs the push relay | `10-push.md` §1 | M4 |
| PC-67 | No stock rustls provider ships SecP384r1MLKEM1024 | C (corrected) | Enclave's own provider | `09-transport.md` §8 | M1 |

## 5. Legal and licensing

| ID | Constraint | Status | Consequence | Spec | Check |
|---|---|---|---|---|---|
| PC-80 | Slint Royalty-free License 2.0 requires attribution (AboutSlint) | V | Attribution in About | `19-ops.md` | M6 |
| PC-81 | EAR §742.15(b) notification at first public source release | V | File at first public release | `19-ops.md` | M0/M11 |
| PC-82 | EU CRA vulnerability-handling timelines (24 h / 72 h / 14 days) | V | Process in place from M0 | `19-ops.md` | M0 |
| PC-83 | Store removal risk if a jurisdiction mandates client-side scanning or key escrow | Policy | Enclave withdraws from that store rather than comply | `19-ops.md` | ongoing |

## Open questions

1. PC-03 and PC-20 are unresolved and each has a spike; the fallbacks are already specified.
2. PC-22: whether to ship OEM-specific guidance screens (per manufacturer) or link to external documentation.
3. PC-44: whether Windows 10 versions older than 2004 should be supported with a warning instead of refused.
