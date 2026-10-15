//! The device's side of the credential gate (`enclave-credgate`,
//! `docs/09-transport.md` §7): the work and token requests a device makes,
//! and the epochs the gate's issuer keys rotate on.
//!
//! ```text
//! POST /credgate/v1/challenge  → nonce (32) ‖ u32 effort
//! POST /credgate/v1/tokens     nonce ‖ proof (32) ‖ u8 n ‖ n × TokenRequest (52)
//!                              → n × TokenResponse (145)
//! ```

use crate::privpass::{self, IssuerPublic, RESPONSE_LEN, Token, TokenChallenge};
use enclave_crypto::rng::HedgedRng;

/// Length of an issuer epoch.
pub const EPOCH_SECS: u64 = 30 * 86_400;
/// Most tokens one proof of work buys.
pub const MAX_TOKENS_PER_PROOF: usize = 32;
/// The `origin_info` of the token challenge a ticketbook redeems.
pub const TICKETBOOK_ORIGIN: &str = "ticketbook";
/// Most effort a device spends on one challenge (about a minute on a
/// phone); a gate asking more is refused rather than obeyed.
pub const MAX_EFFORT: u32 = 20_000;

/// The token challenge every ticketbook token answers.
pub fn ticketbook_challenge(issuer_name: &str) -> TokenChallenge {
    TokenChallenge {
        issuer_name: issuer_name.to_string(),
        redemption_context: Vec::new(),
        origin_info: TICKETBOOK_ORIGIN.into(),
    }
}

/// The proof-of-work context of a challenge.
pub fn pow_context(nonce: &[u8; 32]) -> Vec<u8> {
    [b"credgate".as_slice(), nonce].concat()
}

/// The epoch of Unix time `now`.
pub fn epoch_of(now: u64) -> u32 {
    (now / EPOCH_SECS) as u32
}

/// Build the tokens request for `challenge` (from `/challenge`) and `n`
/// tokens, solving the puzzle.
pub fn tokens_request(
    challenge: &[u8],
    public: IssuerPublic,
    issuer_name: &str,
    n: usize,
    rng: &mut HedgedRng,
) -> Option<(Vec<u8>, Vec<privpass::Pending>)> {
    if challenge.len() != 36 || n == 0 || n > MAX_TOKENS_PER_PROOF {
        return None;
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&challenge[..32]);
    let effort = u32::from_be_bytes(challenge[32..36].try_into().ok()?);
    if effort > MAX_EFFORT {
        return None;
    }
    let proof = crate::solve(&pow_context(&nonce), effort, rng).ok()?;
    let digest = ticketbook_challenge(issuer_name).digest().ok()?;
    let mut body = nonce.to_vec();
    body.extend_from_slice(&proof.0);
    body.push(n as u8);
    let mut pending = Vec::with_capacity(n);
    for _ in 0..n {
        let (req, p) = privpass::Pending::begin(public, digest, rng).ok()?;
        body.extend_from_slice(&req);
        pending.push(p);
    }
    Some((body, pending))
}

/// Finish the tokens from a `/tokens` answer.
pub fn tokens_finish(pending: Vec<privpass::Pending>, answer: &[u8]) -> Option<Vec<Token>> {
    if answer.len() != pending.len() * RESPONSE_LEN {
        return None;
    }
    pending
        .into_iter()
        .zip(answer.chunks(RESPONSE_LEN))
        .map(|(p, r)| p.finish(r).ok())
        .collect()
}
