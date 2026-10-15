# RFC 0004: Proof of work on Equihash⟨60,3⟩ over BLAKE2b, not Equi-X

- **Status:** Accepted (completion plan X25 and External Gate G14 resolved).
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-15
- **Affects:** `02-cryptography.md` §1 and §10, `enclave-tokens`, `deny-ios.toml`, `completion-plan.md` X25 and G14
- **Crypto WG review required:** yes

## Summary

Enclave's proof of work used Equi-X through arti's `equix` crate. That crate and its `hashx` dependency are LGPL-3.0-only, which the iOS App Store build can't ship: LGPL-3.0 requires that users can install a modified library, which iOS doesn't allow, and only the copyright holders (the Tor Project, tevador) could grant an exception. Enclave now uses its own Equihash⟨60,3⟩ over BLAKE2b (`enclave-tokens::equihash`), written from the Equihash paper (Biryukov and Khovratovich, NDSS 2016).

## Why not a byte-compatible Equi-X

The completion plan's fallback was a clean-room Equi-X checked against upstream vectors. There is nothing to write it from: Tor's own specification says "there is no formal specification for Equi-X or the underlying HashX function" (`torspec` hspow-spec, v1-equix), so HashX's exact program generation exists only as the LGPL code. And byte compatibility buys nothing: Enclave's proofs use Enclave's own challenge format and are only ever checked by Enclave servers and gates.

## Design

The same puzzle shape as Equi-X, so effort settings, proof size (32 bytes: nonce and solution) and memory needs carry over:

- n = 60, k = 3: eight distinct indices below 2^16 whose 60-bit hashes XOR to zero, as Wagner's tree with each round zeroing the next 15 bits (the last round 30).
- `H(i)` = the low 60 bits of BLAKE2b-64(BLAKE2b-256(challenge) ‖ u16le(i)).
- The tree's order is fixed (each pair ascending; the smaller first index on the left at every level), so one set of indices is one solution; a verifier checks order, distinctness, and the three XOR conditions with eight hashes.
- The linear effort check above it (`accepted`, SHAKE256) is unchanged.

## Security and privacy considerations

HashX made each hash a randomly generated program tuned to 64-bit CPUs, to narrow the gap between a phone and a GPU or ASIC. BLAKE2b doesn't: an attacker with GPUs solves these puzzles more cheaply relative to a phone than they would Equi-X's. Proof of work in Enclave is a speed bump, not the only control: request inboxes are rate-limited per address and day, blob uploads and credentials are paid with Privacy Pass tokens from per-proof quotas, and servers raise effort for an abused capability (`12-servers.md`). The asymmetry the puzzle exists for (a solve costs about 16 ms and 1 MiB, a verification eight hashes) is unchanged.

## Alternatives considered

- **Keep Equi-X off iOS only:** impossible, because a server checks one puzzle for every client.
- **A grant from the Tor Project:** not in our control or schedule (G14). If one comes, switching back is a new proof format behind the same API.
- **RandomX (BSD-3-Clause):** needs 256 MiB to verify in light mode, too heavy for a server checking many proofs and for phones.
- **A HashX-like randomized hash of our own design:** new cryptography with no review.
