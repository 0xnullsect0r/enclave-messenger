# Supply chain: `cargo vet`

`cargo vet --locked` runs in CI (job `cargo-vet`) for this workspace and
for `nym/` (its own `nym/supply-chain/`, same imports). Every crate in
each `Cargo.lock` is either

* **audited**: covered by an audit imported from Mozilla, Google, the
  Bytecode Alliance, Embark, ISRG or Zcash (`config.toml` `[imports]`,
  pinned in `imports.lock`), or by one of ours in `audits.toml`; or
* **exempted**: listed under `[[exemptions]]` at the version in the lock.

An exemption is not an audit. It records that the crate was in the tree
when vetting started. A new crate or a new version fails CI until someone
audits it (`cargo vet certify`, after reading the diff) or adds an
exemption on purpose in a reviewed commit.

## What still needs a human audit (External Gate G15)

Audits are a person's statement that they read the code, so none are
written here on anyone's behalf. Before 1.0, every crate below must move
from `[[exemptions]]` to an audit in `audits.toml` (or an import), at
`safe-to-deploy`. They are the crates that hold keys, parse untrusted
bytes, or make randomness:

| Area | Crates |
|---|---|
| Post-quantum and classical primitives | `libcrux-ml-kem`, `libcrux-ml-dsa`, `libcrux-sha3`, `libcrux-kmac`, `ml-kem`, `ml-dsa`, `slh-dsa`, `classic-mceliece-rust`, `ed448`, `ed448-goldilocks`, `x448`, `curve25519-dalek`, `x25519-dalek`, `ed25519-dalek`, `voprf`, `p256`, `p384`, `ecdsa`, `elliptic-curve`, `primeorder`, `hash2curve`, `crypto-bigint` |
| Symmetric and hashing | `aes`, `aead`, `chacha20`, `chacha20poly1305`, `poly1305`, `polyval`, `universal-hash`, `ctr`, `cipher`, `crypto_secretbox`, `sha2`, `sha3`, `shake`, `cshake`, `keccak`, `blake2`, `hmac`, `hkdf`, `pbkdf2`, `argon2`, `digest`, `crypto-common`, `signature` |
| Randomness and secrets | `rand`, `rand_core`, `rand_chacha`, `getrandom`, `rdrand`, `zeroize`, `zeroize_derive` |
| WireGuard | `boringtun` (the call links) |
| TLS and certificates | `rustls`, `rustls-webpki`, `rustls-pki-types`, `rustls-platform-verifier`, `ring`, `tokio-rustls`, `hyper-rustls`, `x509-parser`, `der`, `der-parser`, `spki`, `pkcs8`, `sec1`, `pem` |
| Parsers of untrusted input | `prost`, `prost-derive`, `png`, `gif`, `zune-jpeg`, `image-webp`, `image`, `rav1d`, `opus-decoder`, `opus-rs`, `redb`, `httparse`, `h2`, `hyper`, `serde_json`, `toml`, `url`, `bip39` |
| Tor (arti) | every `tor-*` and `arti-client` crate (arti 0.46) |
| Nym (`nym/` only) | every `nym-*` crate, including the patched ones in `third_party/` (`nym-client-core`, `nym-gateway-client`, `nym-gateway-requests`, `nym-credential-storage`), `sphinx-packet`, `x25519-dalek`, `curve25519-dalek` |

`cargo vet suggest` lists the cheapest next audits (smallest diffs from
an already audited version). The vendored patches in `third_party/`
(`ptrs`, the Slint Android backend) are audited as if from crates.io
(`audit-as-crates-io`), so our changes to them are reviewed like any
other diff.
