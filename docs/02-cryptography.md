# Cryptography

Status: Draft (M0, reconciled with the M1 code) · Normative

Source: PLAN.md §2.1 to §2.3, Appendix A. Crate: `crates/enclave-crypto`. Key inventory and derivations: `02b-key-schedule.md`. Labels: `label-registry.md`. Conventions: `00-overview.md` §6.

This document specifies every cryptographic construction that `enclave-crypto` exports. Protocol documents MUST use only these constructions. Where this document and `enclave-crypto` disagree, the code is normative and this document is corrected.

## 1. Primitives

Sizes are from the FIPS and RFC documents (PLAN Appendix A) and are asserted by tests in `enclave-crypto`.

| Role | Primitive | Sizes (B) | Used for |
|---|---|---|---|
| Account root | SLH-DSA-SHAKE-256s (FIPS 205), pure mode, hedged | pk 64, sig 29,792 | Account manifest (other root records are not implemented yet) |
| Device signature | Composite Ed448 + ML-DSA-87 (§7). Both components MUST verify. | pk 2,649 (57 + 2,592); sig 4,741 (114 + 4,627); seed 89 (57 + 32) | Signed prekeys, OPK batch roots, last-resort prekeys, the On-the-record EQXDH transcript, KT heads, witness cosignatures |
| Handshake KEM | X448 (RFC 7748) + ML-KEM-1024 (FIPS 203) + Classic McEliece-8192128 | X448 pk/ss 56; ML-KEM ek 1,568, dk 3,168, ct 1,568, ss 32; McE pk 1,357,824, sk 14,120, ct 208, ss 32 | EQXDH |
| Device auth KEM | ML-KEM-1024 static key per device | ek 1,568 | PQ authentication of a device |
| Ratchet and request KEM | X448 + ML-KEM-1024 | as above | Lockstep ratchet, sealed requests |
| KDF / PRF / MAC / XOF | KMAC256 and KMACXOF256 (SP 800-185), only | — | Every derivation |
| AEAD | EnclaveSeal-v1 (§4) | overhead 64 (32 nonce + 32 tag); compact form 32 | Everything |
| Transcript and binding hash | SHA3-512 | 64 | Transcripts, manifest hash chain, body hashes, the McEliece key commitment |
| Short hash | SHAKE256 | 4, 32 or 64 | Merkle nodes, directory keys, KT hashes, gossip digests, PoW check |
| Password KDF | Argon2id (RFC 9106) | — | Optional app passphrase |
| Anti-spam | Equi-X (arti `equix` crate) (§10) | proof 32 | Request-inbox writes, OPK claims, blob uploads |
| KT privacy VRF | akd's ECVRF over Ed25519 | — | Username enumeration resistance only (classical) |
| Reserved (not yet implemented) | Privacy Pass (RFC 9578), TLS SecP384r1MLKEM1024, HQC-256 suite | — | See §11 and `09-transport.md` §8 |
| Not used | AEGIS-256, HKDF, HMAC, AES-GCM (outside TLS), compression before encryption | — | — |

HKDF-SHA3 is not used: it rests on the same Keccak assumption as KMAC and adds a second construction to review.

**Compression.** No data is compressed before encryption anywhere in Enclave, including backups and attachments. Codecs that compress media (JPEG, PNG, Opus, AV1) are applied before encryption as content formats; general-purpose compression (DEFLATE, zstd, brotli) MUST NOT be.

### 1.1 Version and suite identifiers

There is no negotiation in v1. The implementation uses these identifiers:

| Where | Field | Value | Meaning |
|---|---|---|---|
| Wire unit and poll object (`enclave-wire`) | version `u16` | 1 | Wire format v1 |
| Wire unit and poll object | suite `u16` | 1 (`SUITE_V1`) | X448 + ML-KEM-1024 server sealing with EnclaveSeal-v1 |
| EnclaveCombine (§5) | suite ID `u8` | 0x02 | 2-KEM suite (X448 + ML-KEM-1024) |
| EnclaveCombine (§5) | suite ID `u8` | 0x03 | 3-KEM suite (X448 + ML-KEM-1024 + McEliece-8192128) |
| Stored envelope header (`enclave-proto`) | version `u8` | 1 | Envelope format v1 |
| Manifest | format `u16` | 1 | Manifest format v1 |

A receiver MUST reject any object whose version or suite it does not implement. `enclave-wire` returns `WireError::Unsupported`; other parsers return a decode error.

## 2. KMAC256

KMAC256 and KMACXOF256 are implemented in-house in `kmac.rs` (about 100 lines) on top of the `cshake` crate's cSHAKE256 with function name `"KMAC"`, exactly as SP 800-185 specifies. Tests check NIST SP 800-185 KMAC samples #4, #5 and #6, the `left_encode`/`right_encode` examples, and agreement with `libcrux-kmac` (`tests/differential.rs`).

### 2.1 Encoding functions

```
left_encode(x):   u8(n) ‖ x as n bytes big-endian, n the smallest n >= 1 with x < 2^(8n)
right_encode(x):  x as n bytes big-endian ‖ u8(n)
encode_string(S): left_encode(8 * len(S)) ‖ S          # E(S) in this spec; length in bits
bytepad(X, 136):  left_encode(136) ‖ X ‖ zero bytes up to a multiple of 136
```

Examples: `left_encode(0) = 01 00`, `left_encode(136) = 01 88`, `left_encode(256) = 02 01 00`, `right_encode(0) = 00 01`, `right_encode(512) = 02 00 02`.

### 2.2 KMAC256 and KMACXOF256

```
KMAC256(K, X, L, S)    = cSHAKE256(bytepad(E(K), 136) ‖ X ‖ right_encode(L), L, "KMAC", S)
KMACXOF256(K, X, S)    = cSHAKE256(bytepad(E(K), 136) ‖ X ‖ right_encode(0), ∞, "KMAC", S)
```

Requirements:

- `L` is a multiple of 8. Every call site fixes `L`. KMACXOF256 is used only by the hedged RNG (§6) and by `XofRng`, a deterministic stream used in tests.
- `S` MUST be a label from `label-registry.md`. `S` is never empty.
- `K` MAY be any length, including public constants (the EnclaveCombine suite key is 5 B). Secret keys are at least 32 B.
- Streaming API: `Kmac256::new(K, S)`, `update(x)`, `update_framed(x)`, `finalize_into(out)` (KMAC256 with `L = 8·len(out)`), `finalize_xof()` (KMACXOF256).

### 2.3 Framing

Every variable-length field inside a KMAC or SHA3-512 input is framed:

```
frame(x) = u64(len(x)) ‖ x              # 64-bit big-endian length in BYTES, then the bytes
```

`kmac256_parts(K, [x1, …, xn], S) = KMAC256(K, frame(x1) ‖ … ‖ frame(xn), 256, S)` and `sha3_512_parts([x1, …, xn]) = SHA3-512(frame(x1) ‖ … ‖ frame(xn))`. An empty list absorbs nothing, so `kmac256_parts(K, [], S) = KMAC256(K, "", 256, S)`. Fixed-length fields are sometimes absorbed raw; each formula below says which.

The M0 draft used `E()` (`encode_string`, a bit-length prefix) as the framing inside KMAC inputs. The implementation uses `frame()` everywhere; `E()` appears only inside KMAC itself.

## 3. Hashes

| Function | Definition | Output | Code |
|---|---|---|---|
| `SHA3-512(x)` | FIPS 202 | 64 B | `hash::sha3_512` |
| `SHA3-512-parts(x1, …, xn)` | `SHA3-512(frame(x1) ‖ … ‖ frame(xn))` | 64 B | `hash::sha3_512_parts` |
| `SHAKE256(x, N)` | FIPS 202 SHAKE256 with `N` bytes of output (cSHAKE256 with empty `N` and `S`) | `N` B | `hash::shake256::<N>` |

SHA3-512 is used for transcripts, the manifest hash chain, the McEliece key commitment `SHA3-512(McE_pk)`, and body hashes. SHAKE256 is used with a raw ASCII label prefix (kind HASH in `label-registry.md`) for Merkle nodes, the manifest directory key, akd hashes, KT gossip digests, and the proof-of-work check. The M0 notations `ID256` and `FP512` (`SHAKE256(E(label) ‖ x)`) are not used by the code; they remain reserved notation for later features.

## 4. EnclaveSeal-v1

EnclaveSeal-v1 (`seal.rs`) is the only AEAD in Enclave. It is a cascade of two independent keystreams (XChaCha20 and AES-256-CTR) under per-seal subkeys, with a KMAC256 256-bit tag in encrypt-then-MAC order, a hedged nonce, and key commitment.

### 4.1 Interface

```
seal(K: 32 B, AD: bytes, P: bytes, rng) -> N ‖ C ‖ T          # len(P) <= 65,536
seal_with_randomness(K, AD, P, r: 32 B) -> N ‖ C ‖ T          # tests and deterministic callers
open(K, AD, N ‖ C ‖ T) -> P | Auth | TooLarge
seal_compact(K, nonce_material, AD, P) -> C ‖ T               # §4.5
open_compact(K, nonce_material, AD, C ‖ T) -> P | Auth
```

- `K` is exactly 32 B (`SealKey`, zeroized on drop).
- `len(P)` is at most `MAX_PLAINTEXT = 65,536` B. Larger data is chunked by the caller (for example `enclave-store`, `14-storage.md` §2.3). `len(P)` MAY be 0.
- `AD` is any byte string. Each call site's AD is listed in the document that owns the call site.

### 4.2 Layout

`len(output) = len(P) + 64`.

| Offset | Length | Field |
|---|---|---|
| 0 | 32 | `N`: hedged nonce |
| 32 | `len(P)` | `C`: ciphertext |
| 32 + `len(P)` | 32 | `T`: tag |

Overhead: 32 (`N`) + 32 (`T`) = **64 B** (`seal::OVERHEAD`, `enclave_wire::SEAL_OVERHEAD`). There is no framing header and no plaintext length field; the plaintext length is `len(output) − 64`.

### 4.3 Seal

```
seal(K, AD, P):
    require len(P) <= 65536                                            else TooLarge
    r    = HedgedRng.fill("seal/nonce", 32)                             # §6
    N    = KMAC256(K, frame(r) ‖ frame(AD) ‖ SHA3-512(P), 256, "enclave/v1/seal/nonce")
    k    = KMAC256(K, N, 1088, "enclave/v1/seal/keys")                  # 136 B
    k_x  = k[0..32]     # XChaCha20 key
    k_a  = k[32..64]    # AES-256 key
    k_m  = k[64..96]    # MAC key
    n_x  = k[96..120]   # XChaCha20 nonce (24 B)
    iv_a = k[120..136]  # AES-256-CTR initial counter block (16 B)
    C    = P ⊕ XChaCha20(k_x, n_x) ⊕ AES-256-CTR(k_a, iv_a)
    T    = KMAC256(k_m, frame(AD) ‖ N ‖ frame(C), 256, "enclave/v1/seal/tag")
    zeroize(k_x, k_a, k_m)
    return N ‖ C ‖ T
```

Keystream details:

- **XChaCha20**: the XChaCha20 construction (HChaCha20 subkey from the first 16 nonce bytes), RustCrypto `chacha20` with the `xchacha` feature, key `k_x`, 24-byte nonce `n_x`, block counter starting at 0.
- **AES-256-CTR**: RustCrypto `ctr::Ctr128BE<Aes256>`: key `k_a`, 128-bit counter block initialized to `iv_a` and incremented as a 128-bit big-endian integer.
- The code applies XChaCha20 first, then AES-256-CTR. XOR is commutative, so the order does not matter.

The nonce input is unambiguous: `r` and `AD` are framed and `SHA3-512(P)` is fixed-length. The tag input is unambiguous: `AD` and `C` are framed and `N` is fixed-length.

This is PLAN §2.3's `N = KMAC256(k_n, rand32‖AD‖SHA3-512(P), 256, "seal/nonce")` with `k_n = K`, framing added; `k_c‖k_a‖k_m = KMAC256(K, N, 768, "seal/keys")` extended to 1,088 bits so that the XChaCha20 nonce and the AES counter block are also derived rather than fixed at zero; and `T = KMAC256(k_m, len(AD)‖AD‖N‖c, 256, "seal/tag")` with `c` framed too.

### 4.4 Open

```
open(K, AD, S):
    if len(S) < 64:                     return Auth
    if len(S) − 64 > 65536:             return TooLarge
    N = S[0..32]; C = S[32..len(S)−32]; T = S[len(S)−32..]
    k = KMAC256(K, N, 1088, "enclave/v1/seal/keys"); split as in §4.3
    T' = KMAC256(k_m, frame(AD) ‖ N ‖ frame(C), 256, "enclave/v1/seal/tag")
    if not ct_eq(T, T'):                return Auth           # subtle::ConstantTimeEq
    # only now is any keystream generated
    return C ⊕ XChaCha20(k_x, n_x) ⊕ AES-256-CTR(k_a, iv_a)
```

Requirements:

- The tag is verified before any keystream is generated.
- Tag mismatch, wrong key, wrong AD and truncation all return the same `Error::Auth`. `TooLarge` depends only on the public length.
- A failed `open` releases no plaintext.

Tests (`seal::tests`): round trips at lengths 0 to 65,536; every single-bit flip of a sealed object is rejected; wrong AD, wrong key and truncation are rejected; identical inputs give identical output; same key and randomness with different plaintext give different nonces.

### 4.5 Compact form (nonce not transmitted)

Some call sites have no room for a 32 B nonce but have a value that is unique per message. For these, `seal_compact` derives the nonce from caller-supplied `nonce_material` and does not transmit it:

```
seal_compact(K, nonce_material, AD, P):
    require len(P) <= 65536                                            else TooLarge
    N = KMAC256(K, frame("compact") ‖ frame(nonce_material) ‖ frame(AD), 256, "enclave/v1/seal/nonce")
    subkeys, keystreams and T exactly as §4.3 (T = KMAC256(k_m, frame(AD) ‖ N ‖ frame(C), 256, …))
    return C ‖ T                                                         # overhead 32 B
```

`open_compact` recomputes `N` and then follows §4.4; every failure (including a length out of range) returns `Auth`.

The framed prefix `"compact"` (7 B) keeps compact nonce inputs disjoint from hedged nonce inputs, whose first framed field is 32 B.

Rules:

- `nonce_material` MUST NOT repeat under one key with a different plaintext. A caller SHOULD make it depend on the content, so that a rolled-back state that reuses a counter with other content still gets a different keystream.
- Permitted call sites (all in `enclave-proto`):

| Call site | Key | `nonce_material` | AD |
|---|---|---|---|
| Device-slot header (`05-ratchet.md` §6) | sending header key `HKs` | lookup tag (16 B) ‖ SHA3-512 of the sealed body (64 B) | envelope header (request envelopes: header ‖ initial block) |
| PQ slot (`05-ratchet.md` §8) | `KMAC256(mk_DR, "", 256, "enclave/v1/ratchet/pq-slot")` | same as the device slot it belongs to | same |
| EQXDH sealed identity (`04-eqxdh.md` §4) | `k_id` | initiator's ephemeral X448 public key (56 B) | `u8(suite_id) ‖ u8(mode)` |

**Rollback residual.** If a sender's state is rolled back and it reuses a header key and counter, the lookup tag repeats; the nonce still differs unless the sealed body is also identical, because the body hash is part of the nonce material and the body is sealed with a fresh hedged nonce under a fresh key. The EQXDH identity key `k_id` is fresh per initiation.

The M0 draft specified a "detached-nonce" form `SealDN(K, N, AD, P)` with a caller-supplied nonce. It is not implemented; `seal_compact` replaces it for the ratchet and EQXDH. `11-calls.md` still refers to SealDN for SFrame; calls are not implemented, and that call site will be specified against `seal_compact` when they are.

### 4.6 Properties and argument

| Property | Argument |
|---|---|
| IND-CPA | The ciphertext is `P` XORed with two keystreams under independent keys `k_x`, `k_a` (and independent nonce/IV). If either XChaCha20 or AES-256-CTR is a secure stream cipher, the XOR of both is pseudorandom. The subkeys are independent because KMAC256 is a PRF. |
| INT-CTXT, hence IND-CCA | Encrypt-then-MAC with KMAC256 over `AD`, `N` and `C`, with a 256-bit tag. |
| Key commitment | `T` is a PRF output under `k_m`, which is a PRF output of `(K, N)`. Finding `K ≠ K'` that both verify one sealed object needs a 256-bit KMAC256 collision. |
| Nonce misuse resistance | `N` depends on fresh randomness `r`, `AD`, and `SHA3-512(P)`. Keystream reuse under one `K` requires `r`, `AD` and `P` all to repeat, in which case the outputs are identical and nothing new leaks. The compact form's argument is in §4.5. |
| Multi-key | Each seal derives fresh subkeys from `(K, N)`; a 256-bit `N` makes subkey collisions negligible. |

The computational proof is an M10 deliverable (`20-assurance.md` §2).

### 4.7 Limits

| Limit | Value |
|---|---|
| Plaintext per seal | 65,536 B |
| Seals per key | No practical limit (256-bit nonces) |
| AD length | Any (framed with a 64-bit length) |

### 4.8 Key derivation helpers

```
record_key(master, salt, record_id) = KMAC256(master, frame(salt) ‖ frame(record_id), 256, "enclave/v1/store/record")
derive_key(secret, context, label)  = KMAC256(secret, context, 256, label)          # context absorbed raw
```

`record_key` is used by `enclave-store` with the 32 B database salt and the 40 B blinded key (`14-storage.md` §2). `derive_key` is used for the EQXDH identity key and the request and reply keys, each with an empty context.

## 5. EnclaveCombine

EnclaveCombine (`kem::combine`) turns the shared secrets of several KEMs (X448 treated as a KEM) and an optional PSK into one 64 B secret. It follows the GHP18 and KitchenSink combiner arguments (draft-irtf-cfrg-hybrid-kems): the output is IND-CCA secure if any one component KEM is IND-CCA secure, or if the PSK is secret. It binds every public key, every ciphertext, the transcript, the PSK flag, and the suite.

### 5.1 Suites

| Suite | `suite_id` | Suite key `K_s` | Extract label | Combine label | Used for |
|---|---|---|---|---|---|
| `Suite::TwoKem` | 0x02 | `"ENCL" ‖ 0x02` | `enclave/v1/kem2/extract` | `enclave/v1/kem2/combine` | EQXDH without McEliece, sealed requests |
| `Suite::ThreeKem` | 0x03 | `"ENCL" ‖ 0x03` | `enclave/v1/kem/extract` | `enclave/v1/kem/combine` | EQXDH with the vault key |

The suite key is the 5-byte ASCII `ENCL` followed by the suite ID byte. The two suites use different labels and different suite keys, so a 2-KEM output is never related to a 3-KEM output (RT-07).

### 5.2 Algorithm

```
combine(suite, secrets = [s_1, …, s_n], public = [p_1, …, p_m], psk: 32 B or absent):
    K_s      = "ENCL" ‖ u8(suite_id)
    psk_in   = psk if present else 0^32
    prk      = KMAC256(K_s, frame(s_1) ‖ … ‖ frame(s_n) ‖ frame(psk_in), 512, extract_label)
    psk_flag = u8(1) if psk present else u8(0)
    th       = SHA3-512(frame(p_1) ‖ … ‖ frame(p_m) ‖ frame(psk_flag) ‖ frame(u8(suite_id)))
    out      = KMAC256(prk, th, 512, combine_label)
    return out                                                           # 64 B, zeroized on drop
```

Rules:

- `secrets` are passed in protocol order. An absent component (for example DH4 without a one-time prekey, or the McEliece secret in a 2-KEM session) is passed as an empty string, so it still occupies a framed position.
- `public` holds every public key, ciphertext and transcript item, in protocol order. The McEliece public key is represented by `SHA3-512(McE_pk)`, the value committed in the manifest.
- `psk_flag` is 0 or 1. A zero PSK and no PSK give different outputs because of `psk_flag`.
- X448 shared secrets are checked before they reach `combine`: `X448Secret::diffie_hellman` returns `InvalidKey` for an all-zero result (RFC 7748 §6.2).

This is PLAN §2.3's `prk = KMAC256(suite_label, ss_x448‖ss_mlkem‖ss_mce‖psk_or_zero, 512, …)` and `ss = KMAC256(prk, SHA3-512(all pks‖all cts‖transcript‖psk_flag‖suite), 512, …)`, with framing added and the public keys, ciphertexts and transcript items merged into one ordered list.

Using the public suite key as the KMAC key in the extract step is the SP 800-56C one-step construction with a public salt. The secret inputs are all in the message.

### 5.3 Tests

- `kem::tests::combine_binds_everything`: changing the suite, any secret, any public item, or the PSK presence changes the output; identical inputs give identical output.
- `kem::tests::x448_agreement_and_low_order_rejection`: an all-zero X448 result is rejected.
- Not yet written: a test that a responder expecting the 3-KEM suite rejects a 2-KEM initial message when the braid rules do not allow it (`04-eqxdh.md` §7).

## 6. Hedged RNG

Every key generation, encapsulation, signature randomizer, seal nonce, and random padding byte comes from `HedgedRng` (`rng.rs`). It survives a weak OS RNG (as long as the hedge secret is secret) and a VM snapshot (as long as the OS RNG is healthy after the restore).

### 6.1 State

| Item | Size | Lifetime |
|---|---|---|
| `hedge` | 32 B | The device's hedge secret (`enclave_store::device_rng`), or drawn from the OS RNG (`HedgedRng::new`, for short-lived generators and tests). In locked memory, zeroized on drop. |
| `counter` | `u64` | Per generator, in memory. Starts at 0 and increments (wrapping) after every draw. |

### 6.2 Algorithm

```
HedgedRng.fill(purpose: ASCII, out):
    os  = os_random(64)                                          # getrandom
    out = KMACXOF256(hedge, frame(os) ‖ u64(counter) ‖ frame(purpose), "enclave/v1/rng/hedge")[0..len(out)]
    counter = counter + 1
```

This is PLAN §2.3's `KMAC256(os_rng(64)‖device_hedge_secret‖counter, label)` with the hedge secret in the key position, framing added, and a purpose string.

Requirements:

- `purpose` names the call site (for example `"seal/nonce"`, `"mlkem/keygen"`). Purposes in use are listed in `label-registry.md` §6. They are not labels, but a purpose MUST NOT be reused for a different kind of value.
- If `os_random` fails, `fill` fails with `Error::Rng` and produces no output. It never falls back to the hedge alone.
- Libraries that take seeds receive them from `fill`: ML-KEM `d ‖ z` (64 B), X448 scalar (56 B), composite seed (89 B), ML-DSA signing randomness (32 B), SLH-DSA `opt_rand` (32 B).
- Classic McEliece takes a `rand_core` 0.6 RNG. `HedgedRng` implements `RngCore + CryptoRng` with purpose `"rand_core"`; `try_fill_bytes` reports an OS failure as an error and `fill_bytes` panics, because the 0.6 trait method cannot return one.
- The SLH-DSA root key is not generated from the hedged RNG; it is derived from the recovery secret (§8).
- **Device hedge secret** (PLAN: "device hedge secret"): a profile's generator (`Client::create`, `open`, restoring and linking) takes its hedge from the platform keystore entry `enclave-hedge-secret`, never from the database, so a copied profile can't predict it, and in hardware where the keystore is. Every time it is taken it is refreshed: the next hedge is 32 bytes from a generator keyed with the old one (fresh OS entropy, purpose `store/hedge`) and replaces it, so the stored value is never the one that produced earlier output. With no entry, or an unreadable one, a new hedge comes from the OS. A crypto-erase destroys it with the device secret. Test: `hedge_secret_is_kept_refreshed_and_erased` (`enclave-store`).

`XofRng::new(seed, label)` is a deterministic KMACXOF256 stream `KMACXOF256(seed, "", label)` for expanding a seed and for reproducible tests. It is never a source of fresh randomness.

## 7. Composite signature

### 7.1 Encodings

```
composite_pk   = ed448_pk (57 B) ‖ mldsa87_pk (2,592 B)          # 2,649 B
composite_sig  = ed448_sig (114 B) ‖ mldsa87_sig (4,627 B)       # 4,741 B
composite_seed = ed448_seed (57 B) ‖ mldsa87_seed ξ (32 B)       # 89 B; the stored secret
```

Ed448 comes first. Both components have fixed lengths, so the encoding is unambiguous. Decoding a composite public key validates the Ed448 point.

### 7.2 Message representative

The representative follows draft-ietf-lamps-pq-composite-sigs for `COMPSIG-MLDSA87-Ed448-SHAKE256`:

```
M' = "CompositeAlgorithmSignatures2025"        # Prefix, 32 B ASCII
   ‖ "COMPSIG-MLDSA87-Ed448-SHAKE256"          # Label, ASCII
   ‖ u8(len(ctx)) ‖ ctx                         # ctx is the caller's context, at most 255 B
   ‖ SHAKE256(M, 64)                            # 64-byte pre-hash of the message
```

`ctx` is the caller's context string: one of the CTX-C labels in `label-registry.md` (for example `enclave/v1/ctx/signed-prekey`, `enclave/v1/kt/head`). The message `M` is signed as given; no label is prepended to it. A `ctx` longer than 255 B is rejected with `TooLarge`.

### 7.3 Sign and verify

```
CompositeSign(sk, ctx, M):
    M'  = representative(ctx, M)
    s_e = Ed448.Sign(ed448_sk, M')                                       # RFC 8032 pure Ed448, empty context (sign_raw)
    rnd = HedgedRng.fill("sig/composite/sign", 32)
    s_m = ML-DSA-87.Sign(mldsa_sk, M', ctx = "enclave/v1/sig/composite", rnd)   # FIPS 204, hedged
    return s_e ‖ s_m

CompositeVerify(pk, ctx, M, sig):
    if len(sig) != 4741: return Auth
    M'   = representative(ctx, M)
    ok_e = Ed448.Verify(pk[0..57], M', sig[0..114])
    ok_m = ML-DSA-87.Verify(pk[57..2649], M', ctx = "enclave/v1/sig/composite", sig[114..4741])
    return Ok if ok_e AND ok_m else Auth                                 # both evaluated; never says which failed
```

Requirements:

- Both component verifications run, and the result is the logical AND. There is no "either" mode.
- The composite signature is not relied on to be strongly unforgeable. Protocols MUST NOT use a signature as a unique identifier.

Tests: `sig::tests::composite_sign_verify`, `composite_needs_both_components` (a valid Ed448 half with a foreign ML-DSA half fails, and the reverse), `composite_seed_roundtrip`; `tests/differential.rs` `composite_uses_standard_ed448_half` (OpenSSL verifies the Ed448 half over `M'`) and ML-DSA cross-verification against RustCrypto `ml-dsa`.

## 8. Root signatures (SLH-DSA-SHAKE-256s)

```
RootKeyGen(rs):                                   # rs = 32 B recovery secret
    seeds = KMAC256(rs, "", 768, "enclave/v1/root/keygen")
    (root_sk, root_pk) = slh_keygen_internal(SK.seed = seeds[0..32], SK.prf = seeds[32..64], PK.seed = seeds[64..96])

RootSign(root_sk, ctx, M):
    opt_rand = HedgedRng.fill("sig/root/sign", 32)
    return SLH-DSA-SHAKE-256s.Sign(root_sk, M, ctx, opt_rand)            # FIPS 205 pure, hedged; 29,792 B

RootVerify(root_pk, ctx, M, sig):
    len(sig) == 29792 and len(ctx) <= 255 and SLH-DSA-SHAKE-256s.Verify(root_pk, M, ctx, sig)
```

- `ctx` is a CTX-R label. The only one implemented is `enclave/v1/ctx/manifest`.
- Signing takes about a second on a desktop and several seconds on a phone. It MUST run off the UI thread.
- On the device that holds the words the recovery secret is wrapped under a keystore secret and the PIN (`14-storage.md` §1.3); `RootSigningKey` is derived from it when needed and, behind a PIN, dropped when the unlock lapses.

## 9. Password KDF

Argon2id (RFC 9106), version 0x13, 32 B output, 32 B salt (`pwhash.rs`).

| Preset | Memory | Iterations `t` | Parallelism `p` |
|---|---|---|---|
| `DESKTOP_DEFAULT` | 1 GiB | 4 | 4 |
| `DESKTOP_MAX` (largest the UI offers) | 4 GiB | 4 | 4 |
| `MOBILE_DEFAULT` | 256 MiB | 4 | 2 |
| `FLOOR` (minimum accepted) | 64 MiB | 3 | 1 |

`derive` rejects parameters below the floor in memory or iterations, with zero parallelism, or above 4 GiB, with `Error::Params`. `calibrate(candidates, t, p, target)` returns the largest candidate memory whose derivation finishes within `target` on this device, never below the floor; the caller applies the platform RAM ceiling. The chosen parameters are stored with the salt (`14-storage.md` §1).

## 10. Equi-X proof of work

Implemented in `enclave-tokens` with arti's `equix` crate (`09-transport.md` §3.3):

```
challenge(ctx, nonce) = "ENCLAVE-POW1" ‖ u32(len(ctx)) ‖ ctx ‖ nonce          # nonce 16 B
accepted(chal, sol, effort) = u32_be(SHAKE256("enclave/v1/tokens/pow" ‖ chal ‖ sol, 4)) · max(effort, 1) ≤ 2^32 − 1
proof = nonce (16 B) ‖ Equi-X solution (16 B)                                  # 32 B
verify(ctx, effort, proof) = equix::verify(challenge(ctx, nonce), sol) AND accepted(challenge(ctx, nonce), sol, effort)
```

The solver starts from a random 16 B nonce, tries every Equi-X solution of the challenge, and increments the nonce (little-endian) until one is accepted. Expected work grows linearly with `effort`; effort 1 accepts every valid solution. Verification costs one Equi-X verification and one SHAKE256 call. Contexts and default efforts are in `12-servers.md` §1.

The M0 draft's Tor onion-service challenge format (40 B with a seed head and an effort field) is not used. The effort is not carried in the proof; the server applies its configured effort. Solutions are not tracked as single-use (see `12-servers.md` Open questions).

## 11. Privacy Pass

RFC 9578 privately verifiable tokens, type 0x0001 (VOPRF over P-384 with SHA-384, RFC 9497), not PLAN's type 0x0002 (blind RSA, which would need the `rsa` crate and its timing advisory): `docs/rfcs/0001-privacy-pass-voprf.md`. Each issuer redeems its own tokens: the credential gate (`09-transport.md` §7), each server's blob uploads (`09-transport.md` §9) and, with calls, each relay's tickets. `enclave-tokens::privpass`, with the RFC 9497 test vectors.

## 12. Side-channel and hygiene requirements

Implemented:

- Secret comparisons use `subtle::ConstantTimeEq` (seal tags).
- Secret keys and intermediate subkeys are held in `zeroize::Zeroizing` or zeroized in `Drop` (`SealKey`, `X448Secret`, `MlKemSecret`, `McElieceSecret`, composite seeds, EnclaveCombine output).
- Composite verification evaluates both components before deciding and does not report which failed.
- ML-KEM and McEliece use implicit rejection: a bad ciphertext yields a pseudorandom secret, never an error.
- McEliece key generation, encapsulation and decapsulation run on a dedicated thread with a 32 MiB stack (`MCELIECE_STACK`), because the implementation keeps large matrices on the stack.
- **Data-independent timing**: on AArch64 CPUs with FEAT_DIT, sealing and opening, X448, ML-KEM and McEliece (on their own thread), signing and key expansion, and Argon2id run under `enclave_platform::dit::Guard`, which sets PSTATE.DIT and restores it after (`rt15_dit_bit_set_during_crypto`). x86's equivalent (DOITM) is the kernel's to set.
- **Locked memory**: secret key bytes (`SealKey`, `X448Secret`, `MlKemSecret`, `McElieceSecret`, the composite seed and expanded keys, the root key, the recovery secret, the hedge) live in `enclave_platform::mem` slots in `mlock`ed (`VirtualLock`) pages, kept out of Linux core dumps and zeroized when freed; small secrets share pages. Locking is best effort and counted (`mem::stats`). McEliece decapsulation's working copy of the key is locked and zeroized too (it was a plain heap copy).
- **No `Debug` on secrets**: a compile-time probe asserts that the secret types above, `HedgedRng`, `AccountKeys`, `DeviceKeys`, `RecoverySecret`, ratchet sessions and group state don't implement `Debug` (`tests/hygiene.rs` in `enclave-crypto` and `enclave-proto`).
- `#![forbid(unsafe_code)]` in every crate except `enclave-platform` (DIT and locked memory; every block has a SAFETY comment), `enclave-sandbox`, `enclave-nse` and the declared `enclave-av1` exception.

Required but not yet implemented: ctgrind constant-time testing (`20-assurance.md` §1, Q2); dudect runs today (`tests/dudect.rs`).

## 13. Libraries and backends

| Primitive | Shipped crate | Test-only oracle (`tests/differential.rs`) |
|---|---|---|
| ML-KEM-1024 | `libcrux-ml-kem` 0.0.10 (formally verified) | RustCrypto `ml-kem` |
| ML-DSA-87 | `libcrux-ml-dsa` 0.0.10 | RustCrypto `ml-dsa` |
| SLH-DSA-SHAKE-256s | RustCrypto `slh-dsa` 0.2 | `fips205` |
| Ed448 | `ed448-goldilocks` | OpenSSL (system) |
| X448 | RFC 7748's Montgomery ladder (`x448_ladder.rs`) on `fiat-crypto`'s formally verified p448 field arithmetic, with fiat's constant-time select for the swap; 1.8× faster than the `x448` crate, which is every server request's main cost | RFC 7748 vectors (both single ones, 1 and 1,000 iterations), the `x448` crate on random inputs, OpenSSL (system) |
| McEliece-8192128 | `classic-mceliece-rust` 3.1 (safe Rust) | — (round-trip and implicit-rejection tests only) |
| XChaCha20, AES-256, CTR, SHA3, cSHAKE | RustCrypto `chacha20`, `aes`, `ctr`, `sha3`, `cshake` | — |
| KMAC256 | In-house on `cshake` | `libcrux-kmac`, NIST SP 800-185 samples |
| Argon2id | RustCrypto `argon2` | RFC 9106 §5.3 vector |
| Equi-X | arti `equix` 0.7 | — |
| Key hygiene | `zeroize`, `subtle` | — |

Rules:

- All shipped crypto is pure Rust. C libraries (OpenSSL) appear only as `dev-dependencies` for differential tests.
- If a shipped crate fails review, the release is blocked. A C backend may ship only as a written PLAN §22 exception. No silent substitution.

## 14. Errors

`enclave-crypto` returns `enclave_crypto::Error`:

| Error | Raised by | Handling |
|---|---|---|
| `Auth` | `open`, `open_compact`, signature verification | Silent drop on network paths; `StoreError::Crypto` on storage |
| `Malformed` | Key and ciphertext parsers | Reject the object |
| `TooLarge` | `seal`, `open` (length only), composite `ctx` over 255 B | Programming error; the caller must chunk |
| `InvalidKey` | ML-KEM public-key validation, X448 all-zero result, Ed448 point decoding | Reject; treat an all-zero DH as an attack indicator |
| `Rng` | `HedgedRng` | Abort the operation |
| `Params` | Argon2id parameters | Reject the parameters |

## Open questions

1. The composite signature uses `enclave/v1/sig/composite` as the ML-DSA-87 context, where the draft uses its algorithm label, and puts Ed448 first. Draft test vectors therefore cannot be run unmodified; `tests/differential.rs` checks each component separately instead. Whether to align the ML-DSA context with the draft before 1.0 is open.
2. PLAN §2.1 gives EnclaveSeal an overhead of 72 B (32 nonce + 32 tag + 8 framing). The implementation has no framing header and an overhead of 64 B; the 8 B moved into the request header and the content length field (`08-envelope.md`). This intentionally differs from PLAN.md.
3. PLAN §2.3 fixes the XChaCha20 nonce and the AES IV at zero. The implementation derives both from `(K, N)` with the subkeys (1,088-bit output). This intentionally differs from PLAN.md; the security argument is unchanged.
4. Representing the McEliece public key by `SHA3-512(McE_pk)` in the EnclaveCombine binding instead of the full 1,357,824 B. The binding is equivalent under SHA3-512 collision resistance, and the hash is already committed in the manifest. Confirm with the crypto working group.
5. ~~Whether the hedge secret should be kept by the hardware keystore.~~ Decided: it lives in the keystore, not the database, and is refreshed at every open (§6.1).
6. Whether the compact seal (§4.5) should be replaced by a transmitted nonce where a future layout has room.
