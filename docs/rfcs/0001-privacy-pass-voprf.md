# RFC 0001: Privacy Pass tokens use VOPRF (type 0x0001), not blind RSA

- **Status:** Proposed. Implemented on the project owner's decision of 2026-10-09; open for comment as `0000-template.md` requires.
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-09
- **Comment period ends:** 2026-11-08
- **Affects:** `PLAN.md` (Privacy Pass parameters), `09-transport.md` §7 and §9, `12-servers.md` (`/credgate`), `label-registry.md` §2.4, `completion-plan.md` X18 and N3
- **Crypto WG review required:** yes

## Summary

PLAN specified Privacy Pass with blind RSA-2048 (RFC 9578 token type `0x0002`) for zk-nym credentials, blob quotas and relay tickets. Enclave uses token type `0x0001` instead: VOPRF over P-384 with SHA-384 (RFC 9497), through the `voprf` crate on RustCrypto's `p384`.

## Motivation

The only RSA implementation in the dependency tree is the `rsa` crate 0.9. It carries RUSTSEC-2023-0071 (Marvin): its private-key operation is not constant-time, so an issuer that signs blinded messages for anyone over the network could leak its key through timing. That is exactly what a credential gate does. Moving to a C library (aws-lc, OpenSSL) for the issuer would fix it, but at the cost of a C cryptography dependency in a new service. The VOPRF suite needs no RSA at all, its arithmetic is constant-time, and its tokens are smaller: a 52 B request, a 145 B response and a 146 B token, against 256 B blinded messages and signatures for RSA-2048.

## Design

- `crates/enclave-tokens/src/privpass.rs`: `IssuerKey`, which can be derived from a seed and an epoch (`DeriveKeyPair` with info `enclave/v1/tokens/pp-issuer ‖ u32 epoch`); `TokenChallenge`; `Pending::begin` / `finish` for the client; `IssuerKey::issue` and `verify`. The wire formats are RFC 9578's for type `0x0001`. They are tested against the RFC 9497 A.4.2 vectors.
- **Private verifiability.** Only the issuer's secret key verifies a token, so every service that redeems tokens also issues them:
  - the credential gate (N3);
  - each server for its own blob quota (P4);
  - each relay for its own tickets (C2).
  
  No service accepts another's tokens. Publicly verifiable tokens would have let one issuer serve many verifiers, and Enclave doesn't need that.
- **Key rotation.** A new key each month. The credential gate's key is published in the signed server list.

## Security and privacy considerations

- **Unlinkability.** The VOPRF hides the token input from the issuer, so issuance and redemption cannot be linked.
- **What a broken curve costs.** Breaking P-384 (for example with a quantum computer) lets an attacker mint tokens, which means free quota. It does not deanonymise anyone, the same as for RSA in PLAN.
- **Spent tokens.** Each issuer keeps its own spent set, for the key's lifetime.

## Alternatives

1. **Blind RSA through aws-lc or OpenSSL:** rejected, because it adds a C cryptography dependency to the gate.
2. **Blind RSA through the `rsa` crate:** rejected, because of the Marvin advisory.
