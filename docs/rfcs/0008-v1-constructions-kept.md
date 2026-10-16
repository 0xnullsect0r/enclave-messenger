# RFC 0008: Keep the v1 constructions that differ from PLAN.md

- **Status:** Accepted
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-16
- **Affects:** `02-cryptography.md` §4, §5, §7; `02b-key-schedule.md` §4.1; `04-eqxdh.md` §4, §5.1; `05-ratchet.md` §7; `label-registry.md`
- **Crypto WG review required:** yes

## Summary

Several v1 constructions in the code differ from PLAN.md or from the IETF draft they follow. Each was an open question in its spec. This RFC keeps all of them for wire version 1 and the current suites. Changing any of them changes signatures, keys, safety codes or wire bytes, so it would need a new suite or version (`0000-template.md`, process step 6). None of the alternatives fixes a known weakness.

## Decisions

| # | Construction (spec question) | As implemented | Why it stays |
|---|---|---|---|
| 1 | Composite signature (`02-cryptography.md` Q1) | ML-DSA-87 context `enclave/v1/sig/composite`, Ed448 first, message representative modelled on draft-ietf-lamps-pq-composite-sigs (`enclave-crypto/src/sig.rs`) | The draft is not final. Only Enclave code verifies these signatures, so draft interoperability buys nothing. Each half is checked against another implementation (`tests/differential.rs`: `mldsa_keygen_and_cross_verify`, `composite_uses_standard_ed448_half`). Aligning with a final RFC would be a new signature suite. |
| 2 | EnclaveSeal overhead (Q2) | 64 B: 32 nonce + 32 tag, no framing header (`seal::OVERHEAD`) | The 8 B PLAN gave to framing live in the request header and the content length field (`08-envelope.md`). |
| 3 | Seal nonces (Q3) | XChaCha20 nonce and AES IV come from `KMAC256(K, N, 1088, "enclave/v1/seal/keys")` with the subkeys (`seal.rs` `subkeys`) | Per-seal keys are already unique, so PLAN's zero nonces would also be safe; derived ones cost nothing and add margin. |
| 4 | McEliece key in EnclaveCombine (Q4) | `SHA3-512(McE_pk)`, the manifest's `vault_hash`, not the 1,357,824 B key (`kem::combine`) | Equivalent binding under SHA3-512 collision resistance, and the hash is already committed in the root-signed manifest. Test `combine_binds_everything`. |
| 5 | Compact seal (Q6) | `seal_compact` where a layout has no room for a nonce: device slots, PQ slots, the EQXDH identity, SFrame, relay datagrams | Existing layouts stay as they are. A new layout that has room uses the hedged `seal`. |
| 6 | Security code (`02b-key-schedule.md` Q1) | One KMAC256 step, then 5,200 SHA3-512 iterations over `d ‖ root_pk` (`hash::root_fingerprint`, `FINGERPRINT_ITERATIONS`) | The work per guess matches PLAN's 5,200 SHAKE256 calls. Changing it would change every safety code, which PLAN D4 forbids. `02b-key-schedule.md` §4.1 is the normative text. |
| 7 | PSK in EQXDH stage 1 (`04-eqxdh.md` Q2) | The PSK is an input to the stage-1 key. When the PSK flag is set, the responder tries each PSK it holds, bond PSKs first and then invite PSKs (`Client::handle_request`) | Without the PSK, even an attacker who breaks every KEM and DH can't open the sealed identity, so a bonded or invited initiator stays hidden. A one-time prekey is deleted only after a successful handshake, so failed candidates burn nothing. Tests `on_the_record_and_psk`, `psk_mismatch_fails_closed`, `meeting_in_person`, `invite_links`. |
| 8 | EQXDH transcript (Q3) | Binds both roots, both manifest versions, both device auth keys, every prekey and ciphertext, and the vault hash (§5.1) | Manifest hashes add nothing: the root and version name the manifest, and the responder accepts only that version from its resolver. Capabilities are not negotiated in the handshake. The bundle epoch is covered by every prekey signature (`Bundle::verify`, RT-05). |
| 9 | Lockstep PQ ratchet (`05-ratchet.md` Q1–Q3) | PQ key fixed per `(e_out, e_in)` with `mk = KMAC(mk_DR, pq_key)`; Alice's auth key is PQ key id 0 instead of a confirmation value; the McEliece braid is folded into the next ML-KEM out-step | Healing through the ML-KEM step is modelled in ProVerif and Tamarin (`formal/proverif/lockstep_pcs.pv`, `formal/tamarin/lockstep.spthy`), and the braid in Tamarin (`formal/tamarin/braid.spthy`). Both reduce the ratchet to one step; the full state machine, its skipped keys and counters are in audit A's scope (External Gate G1). |
| 10 | Short ASCII strings outside `enclave/v1/` (`label-registry.md` Q3) | `"reply"`, `"keyring"`, `"EQXDH-v1"`, `"compact"` and the others listed there | Each is unique at its call site. Moving them changes wire and storage formats. New strings use the `enclave/v1/` namespace and are registered. |

## Security and privacy considerations

None of these changes what any observer learns (`01-threat-model.md` §4). Items 4, 7, 8 and 9 rest on arguments, not on running code alone. The crypto and protocol audit (G1) checks them, and its findings can reopen any item through a new RFC.

## Alternatives considered

- **Align everything with PLAN.md and the drafts before 1.0.** It would invalidate every stored signature, safety code and v1 session, for no identified security gain.
