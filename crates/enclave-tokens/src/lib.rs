//! Anti-abuse without identities (`docs/09-transport.md` §9.3, `docs/12-servers.md`).
//!
//! * **Write tokens.** An inbox owner gives each contact a batch of single-use
//!   tokens `t_i = KMAC256(k_contact, i)` over the encrypted session, and
//!   registers only `H(t_i)` with its server, in shuffled batches padded with
//!   dummies. The server burns each token on use, so it can authorize writes
//!   without learning which contact wrote, and it cannot link two writes by the
//!   same contact. Hashes are the only cryptography involved, so nothing here
//!   weakens under a quantum computer.
//! * **Equi-X proof of work** (the puzzle Tor uses for onion services) gates
//!   anonymous actions: first contact through a request inbox, claiming a
//!   one-time prekey, registering a username. The proof is 32 bytes: a 16-byte
//!   nonce and a 16-byte Equi-X solution, bound to a context string.
//! * **Privacy Pass** ([`privpass`]): RFC 9578 tokens of type `0x0001`
//!   (VOPRF over P-384), for credentials an issuer hands out after a proof
//!   of work and later recognises without linking.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod gate;
pub mod privpass;

use enclave_crypto::hash::shake256;
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;

/// Label for write-token derivation.
pub const TOKEN_LABEL: &str = "enclave/v1/tokens/write";
/// Label for token hashing (the server stores only these).
pub const TOKEN_HASH_LABEL: &str = "enclave/v1/tokens/hash";
/// Label for proof-of-work acceptance hashing.
pub const POW_LABEL: &str = "enclave/v1/tokens/pow";

/// A 32-byte single-use write token.
pub type Token = [u8; 32];

/// Derive token `i` for one contact.
pub fn write_token(k_contact: &[u8; 32], i: u64) -> Token {
    kmac256(k_contact, &i.to_be_bytes(), TOKEN_LABEL)
}

/// Hash a token for registration at the inbox `mailbox`. The hash is bound
/// to the address, so the same token registered at two of an owner's
/// addresses (weekly rotation, `docs/09-transport.md` §3) gives the server
/// two unrelated values.
pub fn token_hash(t: &Token, mailbox: &[u8; 32]) -> [u8; 32] {
    kmac256(t, mailbox, TOKEN_HASH_LABEL)
}

/// Owner-side token issuer for one contact.
pub struct TokenIssuer {
    k_contact: [u8; 32],
    next: u64,
}

impl TokenIssuer {
    /// Create an issuer with a fresh per-contact key.
    pub fn new(rng: &mut HedgedRng) -> enclave_crypto::Result<Self> {
        Ok(Self {
            k_contact: rng.array("tokens/contact-key")?,
            next: 0,
        })
    }

    /// Serialize for sealed local storage.
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[..32].copy_from_slice(&self.k_contact);
        b[32..].copy_from_slice(&self.next.to_be_bytes());
        b
    }

    /// Inverse of [`TokenIssuer::to_bytes`].
    pub fn from_bytes(b: &[u8; 40]) -> Self {
        let mut k_contact = [0u8; 32];
        k_contact.copy_from_slice(&b[..32]);
        let mut n = [0u8; 8];
        n.copy_from_slice(&b[32..]);
        Self {
            k_contact,
            next: u64::from_be_bytes(n),
        }
    }

    /// Issue `n` tokens: returns the tokens (for the contact) and their hashes
    /// at `mailbox` (for the server).
    pub fn issue(&mut self, n: usize, mailbox: &[u8; 32]) -> (Vec<Token>, Vec<[u8; 32]>) {
        let mut toks = Vec::with_capacity(n);
        let mut hashes = Vec::with_capacity(n);
        for _ in 0..n {
            let t = write_token(&self.k_contact, self.next);
            self.next += 1;
            hashes.push(token_hash(&t, mailbox));
            toks.push(t);
        }
        (toks, hashes)
    }

    /// Hashes at `mailbox` of the last `n` tokens issued (fewer if fewer
    /// were), to revoke them at the server when the contact is blocked.
    pub fn recent_hashes(&self, n: usize, mailbox: &[u8; 32]) -> Vec<[u8; 32]> {
        let from = self.next.saturating_sub(n as u64);
        (from..self.next)
            .map(|i| token_hash(&write_token(&self.k_contact, i), mailbox))
            .collect()
    }
}

/// Mix `real` token hashes with `dummies` random hashes and shuffle, so the
/// server cannot count contacts from registration batch sizes.
pub fn registration_batch(
    real: &[[u8; 32]],
    dummies: usize,
    rng: &mut HedgedRng,
) -> enclave_crypto::Result<Vec<[u8; 32]>> {
    let mut v: Vec<[u8; 32]> = real.to_vec();
    for _ in 0..dummies {
        v.push(rng.array("tokens/dummy")?);
    }
    for i in (1..v.len()).rev() {
        let r: [u8; 4] = rng.array("tokens/shuffle")?;
        let j = (u32::from_be_bytes(r) as usize) % (i + 1);
        v.swap(i, j);
    }
    Ok(v)
}

/// A proof of work: `nonce ‖ Equi-X solution`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowProof(pub [u8; 32]);

fn challenge(context: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
    let mut c = Vec::with_capacity(context.len() + 24);
    c.extend_from_slice(b"ENCLAVE-POW1");
    c.extend_from_slice(&(context.len() as u32).to_be_bytes());
    c.extend_from_slice(context);
    c.extend_from_slice(nonce);
    c
}

fn accepted(chal: &[u8], sol: &[u8; 16], effort: u32) -> bool {
    let mut buf = Vec::with_capacity(chal.len() + 16 + POW_LABEL.len());
    buf.extend_from_slice(POW_LABEL.as_bytes());
    buf.extend_from_slice(chal);
    buf.extend_from_slice(sol);
    let h: [u8; 4] = shake256(&buf);
    u64::from(u32::from_be_bytes(h)) * u64::from(effort.max(1)) <= u64::from(u32::MAX)
}

/// Solve a proof of work for `context` at `effort` (expected work grows
/// linearly with effort; effort 1 is a single Equi-X solve).
pub fn solve(context: &[u8], effort: u32, rng: &mut HedgedRng) -> enclave_crypto::Result<PowProof> {
    let mut nonce: [u8; 16] = rng.array("tokens/pow-nonce")?;
    loop {
        let chal = challenge(context, &nonce);
        if let Ok(solutions) = equix::solve(&chal) {
            for s in solutions.iter() {
                let bytes = s.to_bytes();
                if accepted(&chal, &bytes, effort) {
                    let mut out = [0u8; 32];
                    out[..16].copy_from_slice(&nonce);
                    out[16..].copy_from_slice(&bytes);
                    return Ok(PowProof(out));
                }
            }
        }
        // Next nonce (little-endian increment).
        for b in nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

/// Verify a proof of work.
pub fn verify(context: &[u8], effort: u32, proof: &PowProof) -> bool {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&proof.0[..16]);
    let mut sol = [0u8; 16];
    sol.copy_from_slice(&proof.0[16..]);
    let chal = challenge(context, &nonce);
    equix::verify_bytes(&chal, &sol).is_ok() && accepted(&chal, &sol, effort)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_distinct_and_hash_consistently() {
        let mut rng = HedgedRng::new().unwrap();
        let mut iss = TokenIssuer::new(&mut rng).unwrap();
        let mb = [7u8; 32];
        let (t, h) = iss.issue(10, &mb);
        for i in 0..10 {
            assert_eq!(token_hash(&t[i], &mb), h[i]);
            assert_ne!(token_hash(&t[i], &[8; 32]), h[i], "bound to the address");
        }
        let mut u = t.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), 10);
        let batch = registration_batch(&h, 22, &mut rng).unwrap();
        assert_eq!(batch.len(), 32);
        assert!(h.iter().all(|x| batch.contains(x)));
        assert_eq!(iss.recent_hashes(4, &mb), h[6..].to_vec());
        assert_eq!(iss.recent_hashes(50, &mb), h, "no more than were issued");
    }

    #[test]
    fn pow_solve_and_verify() {
        let mut rng = HedgedRng::new().unwrap();
        let p = solve(b"request-inbox:abc", 4, &mut rng).unwrap();
        assert!(verify(b"request-inbox:abc", 4, &p));
        assert!(!verify(b"request-inbox:abd", 4, &p), "bound to context");
        let mut bad = p;
        bad.0[20] ^= 1;
        assert!(!verify(b"request-inbox:abc", 4, &bad));
    }
}
