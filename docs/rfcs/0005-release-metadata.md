# RFC 0005: Release metadata in TUF's shape, with Enclave's signatures

- **Status:** Accepted (milestone R2).
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-15
- **Affects:** `19-ops.md` §1, `label-registry.md` (`update/release`, `update/maintainer-keygen`), `enclave-update`
- **Crypto WG review required:** yes

## Summary

`19-ops.md` §1 asked for TUF through the `tough` crate, with each maintainer's SLH-DSA and Ed448 signatures on the targets. `tough` (like TUF's JSON metadata) knows only RSA, ECDSA and Ed25519 keys, so the maintainers' post-quantum signatures would sit beside TUF rather than in it, and the timestamp and snapshot roles would stay classical. `enclave-update` instead keeps TUF's four roles and every check TUF makes (threshold signatures by distinct keys, versions that never go back, expiry, root rotation signed by the old root and the new), in a binary encoding whose every signature is a maintainer signature.

## Design

- **Signature.** SLH-DSA-SHAKE-256s and composite Ed448 + ML-DSA-87, both under context `enclave/v1/update/release`, over `role ‖ body`; both must verify. The same pair the foundation's server list uses (12 §4.1), so one kind of offline key ceremony (G2) serves both. The SLH-DSA key is derived from a 32-byte secret (`update/maintainer-keygen`).
- **Document.** `"ENCLUPD1" ‖ role ‖ u32 len ‖ body ‖ u8 n ‖ n × (u8 key index ‖ signature)`.
- **Root.** Version, expiry, the keys (maintainers and the release workflow's online key), for each role the key indices and threshold (targets at least 2, whatever a root says), and the Sigsum policy (log key, submit keys, witness keys, quorum). A new root is exactly one version ahead and signed by enough root keys of both the old root and itself.
- **Targets.** Version, expiry, the release tag, and each file's name, length, SHA-256 and SHA3-512; at least 2 maintainers. A key listed twice counts once.
- **Snapshot** (targets version and hash) and **timestamp** (snapshot version and hash, a week's expiry) are signed by the online key, so a client kept from new releases notices within a week (freeze).
- **Sigsum.** A file is installed only with a Sigsum proof (the text `sigsum-submit` writes) that its SHA-256 is logged by the root's log, submitted by a listed key, in a tree head cosigned by the quorum of listed witnesses. The verifier is checked against proofs made by sigsum-go (`ci/sigsum`).

## Security and privacy considerations

Compared with `tough`: no JSON canonicalisation to get wrong, and no classical-only role. What TUF gives that this keeps: compromise of the online key lets an attacker only delay or replay within the timestamp's week, never install; two maintainers are needed for any release and for any change of keys; a lost maintainer key is replaced by a new root.

## Alternatives considered

- `tough` with Ed25519 roles and a side file of maintainer signatures: two trust paths to keep in step, one classical.
- Sigstore alone: identity-based, no threshold of maintainers, and a single log.
