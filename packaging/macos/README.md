# macOS signing material

Every binary in `Enclave.app/Contents/MacOS` is signed with the hardened
runtime (`codesign --options runtime`) and the entitlements here:

| Binary | Entitlements | Why |
|---|---|---|
| `enclave` (the window) | `enclave.entitlements` | The camera, for scanning codes. |
| `enclave-vault` | `helper.entitlements` (`enclave-vault.entitlements` with `ENCLAVE_MAC_KEYCHAIN_GROUP=1`) | The Keychain access group would seal keystore secrets to Secure Enclave keys, but on macOS it is a restricted entitlement that only a provisioning profile allows, and a profile can only be embedded in a bundle. Until the vault moves into its own helper bundle (`Contents/Helpers`) with the Developer ID profile (`MACOS_PROVISIONING_PROFILE_BASE64`), it is signed without the group and keeps its secret in the login Keychain unwrapped. `TEAMID` becomes the signing team. |
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
