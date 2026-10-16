# RFC 0007: Post-quantum relay links without Rosenpass

- **Status:** Accepted
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-16
- **Affects:** `11-calls.md` §3.1 and §3.4, `12-servers.md` §5, `enclave-relay`, `enclave-federation` (`RelayDescriptor` v3)
- **Crypto WG review required:** yes

## Summary

The link between the two relays of a call is keyed by the relays' static X448 exchange and, each 120 s epoch, three ML-KEM-1024 shared secrets, in an exchange built into the relay. It does not run upstream Rosenpass next to WireGuard.

## Why not Rosenpass

`11-calls.md` §3.1 asked for WireGuard plus upstream Rosenpass between relays. Rosenpass is a separate daemon (and a declared C exception through liboqs) that hands WireGuard a fresh pre-shared key every two minutes; it needs a kernel or userspace WireGuard device per relay pair, its own key files and its own UDP port. A relay link carries only SFrame packets already encrypted end to end under the call's X448 + ML-KEM keys; what the link protects is the rendezvous id and which datagrams belong together. The same property, a key that changes every two minutes and holds against a quantum adversary recording traffic, comes from the exchange below inside the relay, with no device, daemon or second port.

## Design

```text
static:   each relay's ML-KEM-1024 key from its link key (KMAC "calls/relay-kem"), published in its signed descriptor (v3)
epoch e:  e = ⌊now / 120⌋ + 1; the relay with the lower id starts
  msg1 (initiator → responder):  ephemeral ML-KEM pk ‖ ct1 = Encaps(responder static)
  msg2 (responder → initiator):  ct2 = Encaps(ephemeral) ‖ ct3 = Encaps(initiator static)
  key(from → to) = KMAC256(dh ‖ ss1 ‖ ss2 ‖ ss3, from ‖ to ‖ u32 e, "calls/relay-pq")
data:     T_RELAY ‖ rendezvous ‖ u32 epoch ‖ u64 counter ‖ Seal(key, …)      (epoch 0: the X448 key alone)
```

- Messages go in parts (`T_KX ‖ kind ‖ epoch ‖ index ‖ count ‖ ≤1,100 bytes`), only between relays that peer.
- **Authentication.** ss1 only the responder can have (its static key), ss3 only the initiator. Anyone can forge msg1 (the static keys are public), so neither side sends under an epoch's keys until it has received something sealed under them: a forged msg1 makes the responder derive keys nobody else has, and it keeps sending under the previous epoch. A side that switches confirms with an empty sealed datagram, so the other switches too.
- **Forward secrecy.** ss2 is under an ephemeral key, dropped after the epoch; the previous epoch's keys are kept only for datagrams in flight.
- **Peers** come from the foundation's signed server list (`relay.server_list`, `relay.foundation_key`): every listed relay, its ML-KEM key from its signed descriptor fetched over `T_DESC` and checked against the listed identity and address. A relay whose descriptor can't be fetched, or one configured by hand, stays classical (epoch 0) until it can.

## Consequences

- No Rosenpass, no WireGuard device between relays, no extra port; relays need nothing but their link key.
- The relay link isn't WireGuard on the wire. The client hop still is (RFC 0006).
- Tests: `relay_links_turn_post_quantum_each_epoch` (two epochs, and a forged first message never switches), and `audio_goes_both_ways_through_two_relays` checks both relays' links went post-quantum within the first second.
