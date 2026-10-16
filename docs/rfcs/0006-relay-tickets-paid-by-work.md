# RFC 0006: Call relay tickets paid by proof of work; WireGuard on the client hop

- **Status:** Accepted
- **Author(s):** Enclave maintainers
- **Created:** 2026-10-16
- **Affects:** `11-calls.md` §3.3 and §3.4, `enclave-calls` (`ticket`, `wg`), `enclave-relay`
- **Crypto WG review required:** yes

## Summary

A call relay issues a ticket for proof of work bound to the ticket request, not for a Privacy Pass token, and clients reach their relay over WireGuard (boringtun) whose pre-shared key is the ticket's for each 120 s period.

## Why not Privacy Pass

`11-calls.md` §3.3 asked for tickets "paid with Privacy Pass", so a relay can't tie a ticket to an account. Enclave's Privacy Pass is privately verifiable (VOPRF, RFC 0001): only the issuer can redeem a token. But a caller deliberately uses a relay run by an operator family other than its home server's and the callee's (§3.2, RT-18), so the issuer (the home server, which knows the account) and the redeemer (a foreign relay) are always different operators. Publicly verifiable tokens (RSA blind signatures) would bring back the dependency RFC 0001 removed.

Proof of work has the property tickets need without an issuer: it is anonymous by construction (nothing in it comes from the account), any relay can check it whoever runs it, and it makes each ticket cost the asker something. The relay checks the work first (eight hashes), then opens the request; it burns `KMAC256(eph, "", "calls/ticket-pow")` so a request, and its work, is spent once.

## Design

```text
request = u32 epoch ‖ X448 eph ‖ ML-KEM ct ‖ bytes(Seal(k_seal, ad("request"), wg_public 32 ‖ u32 duration)) ‖ pow 32
pow     = enclave_tokens::solve(ticket-pow ‖ relay_id ‖ u32 epoch ‖ eph ‖ ct, effort)
reply   = Seal(k_seal, ad("reply"), session 16 ‖ u64 t0 ‖ u64 expiry ‖ relay WireGuard public 32 ‖ u64 relay now)
```

- The request travels in two UDP datagrams (`T_TICKET ‖ id 8 ‖ index ‖ count ‖ part`; it is about 1.7 KB), the reply in one.
- The client's WireGuard key pair is fresh per call; the relay's is static (`KMAC256(link key, "", "calls/relay-wg")`).
- The WireGuard pre-shared key for period `i` is `wg_psk_i` (§3.3), so the tunnel is as post-quantum as the ticket exchange (X448 + ML-KEM-1024). At each period the client starts a new tunnel with the new key; periods are counted on the relay's clock, whose time the reply carries.
- WireGuard carries IP packets, so each payload rides behind a fixed 20-byte IPv4 header: a stream's datagrams still have one size.
- Effort: `enclave_relay::TICKET_EFFORT` (16) by default, `relay.ticket_effort` in the relay's configuration.

## Why boringtun now

§3.4 kept an EnclaveSeal framing because "every published Rust WireGuard uses ring or aws-lc". boringtun 0.7 uses RustCrypto's ChaCha20-Poly1305 for data and ring only for parts of the handshake, and ring is already in every client (rustls for the updater and TLS, the push relay). GotaTun still needs aws-lc-rs and a newer toolchain, so boringtun it is.

## Security and privacy considerations

Proof of work is a speed bump: a well-funded attacker can buy tickets faster than a phone. What a ticket buys is bounded (at most 4 hours, one session, forwarding only between two joined legs of one rendezvous), and a relay can raise its effort. Nothing in a ticket request identifies the asker beyond its IP address, which the relay sees anyway for the call itself.

## Alternatives considered

- Privacy Pass with publicly verifiable RSA tokens: brings back RSA (RUSTSEC-2023-0071) and an issuer per foreign operator.
- Tickets from the caller's home server for its own operator's relays: breaks the family rule (§3.2).
