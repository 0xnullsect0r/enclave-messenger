# macOS signing material

Every binary in `Enclave.app/Contents/MacOS` is signed with the hardened
runtime (`codesign --options runtime`) and the entitlements here:

| Binary | Entitlements | Why |
|---|---|---|
| `enclave` (the window) | `enclave.entitlements` | The camera, for scanning codes. |
| `enclave-vault` | `enclave-vault.entitlements` | Its Keychain access group, so keystore secrets are also sealed to Secure Enclave keys. `TEAMID` becomes the signing team. |
| `enclave-netd`, `enclave-nymd`, `enclave-tord`, `enclave-mediad` | `helper.entitlements` | None beyond the hardened runtime. |

The App Sandbox isn't used: helpers started by a sandboxed app must
inherit its sandbox and entitlements, so the window, the vault and the
network helpers would share one. Instead each helper applies its own
Seatbelt profile as it starts (`enclave_sandbox::filesystem`, through
`sandbox_init`): no programs started, no writes outside its own directory,
no reading the rest of the home folder, and for the vault and mediad no IP
connections. This is the macOS counterpart of Landlock and seccomp on
Linux. A Mac App Store build, which requires the App Sandbox, would need
the helpers as XPC services instead.
