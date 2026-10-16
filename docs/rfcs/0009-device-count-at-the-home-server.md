# RFC 0009: The home server may count an account's devices

- **Status:** Accepted
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-16
- **Affects:** `01-threat-model.md` §4 (note 1), `04-eqxdh.md` §6, `08-envelope.md` §6, `12-servers.md` §2, `enclave-server`, `enclave-core`
- **Crypto WG review required:** yes

## Summary

Manifests and prekey bundles stay in plaintext at the directory, and session establishment sends one request envelope per responder device. PLAN D5 and the M0 draft wanted session establishment toward an account to be exactly 3 init units, and PLAN §1.3 says the home server does not learn your device count. As built, the home server can count the devices in an account's manifest, and the manifest names the account's request inbox. The narrower claim in `01-threat-model.md` §4 note 1 holds: the server doesn't learn the device count behind your account inbox.

## Design

- **Directory.** The server stores manifests and publications as they are and checks them: the root signature, a version above the stored one, and for a publication a signature by a device the stored manifest lists, for the manifest's bundle epoch (`Server::accept_manifest`, `Server::accept_publication`). With manifests encrypted under a key from the QR code, link or KT record, the server could no longer make these checks, so it couldn't stop anyone from replacing an account's directory objects.
- **Request envelopes.** `Client::initiate_to` claims one bundle and writes one request envelope per device in the responder's manifest (at most 5). Padding this to a fixed count would hide nothing while the same server holds the plaintext manifest, and it would cost every first contact with a one-device account two extra units.

## Security and privacy considerations

- The leakage matrix row "Device count per account" (`01-threat-model.md` §4) stays: the home server learns it from the manifest.
- Messages after session establishment are unchanged: one wrap table per message, slots padded to 5 devices, and a self-copy always sent (`06-multidevice.md` §4), so envelope counts and sizes don't show the device count.

## Alternatives considered

- **Encrypted directory objects.** Hides the count from the directory. It needs a new way to authorize writes, and claimed one-time prekeys couldn't be checked. A future RFC can propose it; the request-envelope count would then be revisited with it.
- **Exactly 3 init units per account.** Hides nothing while manifests are plaintext.
