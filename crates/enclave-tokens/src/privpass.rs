//! Privacy Pass tokens, RFC 9578 token type `0x0001`: VOPRF(P-384,
//! SHA-384) from RFC 9497 (`docs/rfcs/0001-privacy-pass-voprf.md`).
//!
//! An issuer blindly evaluates a client's token input; the client then
//! holds a token the issuer can recognise as its own but cannot link to the
//! issuance. Only the issuer's secret key verifies a token (privately
//! verifiable), so each service issues and redeems its own: the credential
//! gate (`enclave-credgate`), later each server's blob quota and each
//! relay's tickets. The arithmetic is the `voprf` crate's (constant-time,
//! RustCrypto `p384`), not RSA.
//!
//! Wire formats are RFC 9578's:
//!
//! ```text
//! TokenRequest  = u16 token_type ‖ u8 truncated_token_key_id ‖ blinded_msg (49)
//! TokenResponse = evaluate_msg (49) ‖ evaluate_proof (96)
//! Token         = u16 token_type ‖ nonce (32) ‖ challenge_digest (32)
//!                 ‖ token_key_id (32) ‖ authenticator (48)
//! ```
//!
//! `token_key_id = SHA-256(pkI)` with `pkI` the 49-byte compressed point,
//! `challenge_digest = SHA-256(TokenChallenge)`, and the authenticator is
//! the VOPRF output over `token_type ‖ nonce ‖ challenge_digest ‖
//! token_key_id`.

use enclave_crypto::rng::HedgedRng;
use p384::NistP384;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use voprf::{BlindedElement, EvaluationElement, Group, Proof, VoprfClient, VoprfServer};

/// RFC 9578 token type for VOPRF(P-384, SHA-384).
pub const TOKEN_TYPE: u16 = 0x0001;
/// Authenticator length (`Nh`, SHA-384).
pub const NK: usize = 48;
/// Serialized group element (`Ne`, compressed P-384 point).
pub const NE: usize = 49;
/// Serialized scalar (`Ns`).
pub const NS: usize = 48;
/// `TokenRequest` length.
pub const REQUEST_LEN: usize = 2 + 1 + NE;
/// `TokenResponse` length.
pub const RESPONSE_LEN: usize = NE + 2 * NS;
/// `Token` length.
pub const TOKEN_LEN: usize = 2 + 32 + 32 + 32 + NK;
/// Key-derivation info for issuer keys derived from a seed (`IssuerKey::derive`).
pub const ISSUER_KEY_LABEL: &str = "enclave/v1/tokens/pp-issuer";

type Suite = NistP384;

/// Something wrong with a token, request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivPassError {
    /// Wrong length, token type or encoding.
    Malformed,
    /// Not for this issuer's key.
    WrongKey,
    /// The issuer's proof or the token's authenticator doesn't check.
    Invalid,
}

impl core::fmt::Display for PrivPassError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed Privacy Pass message",
            Self::WrongKey => "Privacy Pass message for another key",
            Self::Invalid => "Privacy Pass proof or token doesn't verify",
        })
    }
}

impl std::error::Error for PrivPassError {}

type R<T> = core::result::Result<T, PrivPassError>;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// RFC 9578 §2.1.1 `TokenChallenge`, as the redeemer asks for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenChallenge {
    /// The issuer's name (here, the credential gate's host).
    pub issuer_name: String,
    /// Up to 32 bytes binding the token to a context; empty for none.
    pub redemption_context: Vec<u8>,
    /// Origin names, comma-separated; empty for any.
    pub origin_info: String,
}

impl TokenChallenge {
    /// The encoding RFC 9578 hashes.
    pub fn encode(&self) -> R<Vec<u8>> {
        let name = self.issuer_name.as_bytes();
        let origin = self.origin_info.as_bytes();
        if name.is_empty()
            || name.len() > u16::MAX as usize
            || !(self.redemption_context.is_empty() || self.redemption_context.len() == 32)
            || origin.len() > u16::MAX as usize
        {
            return Err(PrivPassError::Malformed);
        }
        let mut out = Vec::with_capacity(2 + 2 + name.len() + 1 + 32 + 2 + origin.len());
        out.extend_from_slice(&TOKEN_TYPE.to_be_bytes());
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name);
        out.push(self.redemption_context.len() as u8);
        out.extend_from_slice(&self.redemption_context);
        out.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        out.extend_from_slice(origin);
        Ok(out)
    }

    /// `challenge_digest = SHA-256(TokenChallenge)`.
    pub fn digest(&self) -> R<[u8; 32]> {
        Ok(sha256(&self.encode()?))
    }
}

/// The challenge of blob-upload tokens issued by server `id` (`BlobAlloc`,
/// `docs/09-transport.md` §9): issuer `blob.<server id in hex>`, no
/// redemption context (tokens are interchangeable), no origin.
pub fn blob_challenge(id: &[u8; 16]) -> TokenChallenge {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    TokenChallenge {
        issuer_name: format!("blob.{hex}"),
        redemption_context: Vec::new(),
        origin_info: String::new(),
    }
}

/// An issuer's public key (`pkI`, compressed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerPublic(pub [u8; NE]);

impl IssuerPublic {
    /// `token_key_id = SHA-256(pkI)`.
    pub fn key_id(&self) -> [u8; 32] {
        sha256(&self.0)
    }

    fn point(&self) -> R<<<Suite as voprf::CipherSuite>::Group as Group>::Elem> {
        <Suite as voprf::CipherSuite>::Group::deserialize_elem(&self.0)
            .map_err(|_| PrivPassError::Malformed)
    }
}

/// An issuer's secret key.
pub struct IssuerKey {
    server: VoprfServer<Suite>,
    /// The same key's scalar, for the constant-time [`IssuerKey::evaluate`]
    /// (`voprf` keeps its own private).
    sk: p384::Scalar,
    public: IssuerPublic,
}

impl Drop for IssuerKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.sk);
    }
}

impl IssuerKey {
    fn wrap(server: VoprfServer<Suite>) -> R<Self> {
        let pk = <Suite as voprf::CipherSuite>::Group::serialize_elem(server.get_public_key());
        let public = IssuerPublic(
            pk.as_slice()
                .try_into()
                .map_err(|_| PrivPassError::Malformed)?,
        );
        use p384::elliptic_curve::PrimeField;
        let bytes = zeroize::Zeroizing::new(server.serialize());
        let mut repr = p384::FieldBytes::default();
        repr.copy_from_slice(&bytes[..NS]);
        let sk = Option::from(p384::Scalar::from_repr(repr)).ok_or(PrivPassError::Malformed)?;
        zeroize::Zeroize::zeroize(&mut repr);
        Ok(Self { server, sk, public })
    }

    /// A fresh random key.
    pub fn generate(rng: &mut HedgedRng) -> R<Self> {
        Self::wrap(VoprfServer::new(rng).map_err(|_| PrivPassError::Malformed)?)
    }

    /// RFC 9497 `DeriveKeyPair(seed, info)`: the key for `epoch` (a month
    /// number) from an issuer's long-term seed, so rotation needs no new
    /// secret.
    pub fn derive(seed: &[u8; 32], epoch: u32) -> R<Self> {
        let mut info = ISSUER_KEY_LABEL.as_bytes().to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        Self::derive_raw(seed, &info)
    }

    fn derive_raw(seed: &[u8], info: &[u8]) -> R<Self> {
        Self::wrap(VoprfServer::new_from_seed(seed, info).map_err(|_| PrivPassError::Malformed)?)
    }

    /// The public key.
    pub fn public(&self) -> IssuerPublic {
        self.public
    }

    /// Answer a `TokenRequest`: evaluate the blinded element and prove it
    /// was done with this key.
    pub fn issue(&self, request: &[u8], rng: &mut HedgedRng) -> R<Vec<u8>> {
        if request.len() != REQUEST_LEN || request[..2] != TOKEN_TYPE.to_be_bytes() {
            return Err(PrivPassError::Malformed);
        }
        if request[2] != self.public.key_id()[31] {
            return Err(PrivPassError::WrongKey);
        }
        let blinded = BlindedElement::<Suite>::deserialize(&request[3..])
            .map_err(|_| PrivPassError::Malformed)?;
        let r = self.server.blind_evaluate(rng, &blinded);
        let mut out = Vec::with_capacity(RESPONSE_LEN);
        out.extend_from_slice(&r.message.serialize());
        out.extend_from_slice(&r.proof.serialize());
        if out.len() != RESPONSE_LEN {
            return Err(PrivPassError::Malformed);
        }
        Ok(out)
    }

    /// Whether `token` is one this key issued for `challenge_digest`. The
    /// caller keeps the spent set (a token is good once).
    pub fn verify(&self, token: &Token, challenge_digest: &[u8; 32]) -> bool {
        if token.challenge_digest != *challenge_digest || token.key_id != self.public.key_id() {
            return false;
        }
        bool::from(self.evaluate(&token.input()).ct_eq(&token.authenticator))
    }

    /// RFC 9497 `Evaluate` (VOPRF mode, P384-SHA384) in constant time in
    /// the key: `SHA-384(len ‖ input ‖ len ‖ SerializeElement(k·H(input)) ‖
    /// "Finalize")`. `voprf`'s own `evaluate` gives the same bytes, but its
    /// SEC1 encoding picks the 02/03 tag with a branch on the parity of
    /// `k·H(input)`'s y (found by ctgrind): a timing oracle on one bit of
    /// the issuer's PRF per verification. Here the tag is arithmetic.
    fn evaluate(&self, input: &[u8]) -> [u8; NK] {
        use p384::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
        use p384::elliptic_curve::point::AffineCoordinates;
        use sha2::Sha384;
        const DST: &[u8] = b"HashToGroup-OPRFV1-\x01-P384-SHA384";
        // The input is public: hashing it to the curve may branch.
        let Ok(h) = NistP384::hash_from_bytes::<ExpandMsgXmd<Sha384>>(&[input], &[DST]) else {
            return [0; NK];
        };
        let y = (h * self.sk).to_affine();
        let mut element = [0u8; NE];
        // `|`, not `+`: an overflow check would branch on the bit.
        element[0] = 2 | y.y_is_odd().unwrap_u8();
        element[1..].copy_from_slice(&y.x());
        let mut f = Sha384::new();
        f.update((input.len() as u16).to_be_bytes());
        f.update(input);
        f.update((NE as u16).to_be_bytes());
        f.update(element);
        f.update(b"Finalize");
        f.finalize().into()
    }
}

/// A redeemable token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Client-chosen nonce.
    pub nonce: [u8; 32],
    /// `SHA-256(TokenChallenge)`.
    pub challenge_digest: [u8; 32],
    /// `SHA-256(pkI)`.
    pub key_id: [u8; 32],
    /// The VOPRF output.
    pub authenticator: [u8; NK],
}

impl Token {
    fn input_from(nonce: &[u8; 32], digest: &[u8; 32], key_id: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(2 + 96);
        m.extend_from_slice(&TOKEN_TYPE.to_be_bytes());
        m.extend_from_slice(nonce);
        m.extend_from_slice(digest);
        m.extend_from_slice(key_id);
        m
    }

    fn input(&self) -> Vec<u8> {
        Self::input_from(&self.nonce, &self.challenge_digest, &self.key_id)
    }

    /// The `Token` encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.input();
        out.extend_from_slice(&self.authenticator);
        out
    }

    /// Parse a `Token`.
    pub fn decode(b: &[u8]) -> R<Self> {
        if b.len() != TOKEN_LEN || b[..2] != TOKEN_TYPE.to_be_bytes() {
            return Err(PrivPassError::Malformed);
        }
        let arr = |r: core::ops::Range<usize>| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b[r]);
            a
        };
        let mut authenticator = [0u8; NK];
        authenticator.copy_from_slice(&b[98..]);
        Ok(Self {
            nonce: arr(2..34),
            challenge_digest: arr(34..66),
            key_id: arr(66..98),
            authenticator,
        })
    }
}

/// A client's half-finished issuance: the request to send, kept until the
/// response comes back.
pub struct Pending {
    state: VoprfClient<Suite>,
    nonce: [u8; 32],
    challenge_digest: [u8; 32],
    public: IssuerPublic,
}

impl Pending {
    /// Start one token for `public` and `challenge_digest`: returns the
    /// `TokenRequest` to send and what finishes it.
    pub fn begin(
        public: IssuerPublic,
        challenge_digest: [u8; 32],
        rng: &mut HedgedRng,
    ) -> R<(Vec<u8>, Self)> {
        let nonce: [u8; 32] = rng
            .array("tokens/pp-nonce")
            .map_err(|_| PrivPassError::Malformed)?;
        let input = Token::input_from(&nonce, &challenge_digest, &public.key_id());
        let blind =
            VoprfClient::<Suite>::blind(&input, rng).map_err(|_| PrivPassError::Malformed)?;
        let mut req = Vec::with_capacity(REQUEST_LEN);
        req.extend_from_slice(&TOKEN_TYPE.to_be_bytes());
        req.push(public.key_id()[31]);
        req.extend_from_slice(&blind.message.serialize());
        if req.len() != REQUEST_LEN {
            return Err(PrivPassError::Malformed);
        }
        Ok((
            req,
            Self {
                state: blind.state,
                nonce,
                challenge_digest,
                public,
            },
        ))
    }

    /// Check the issuer's proof and unblind: the token.
    pub fn finish(self, response: &[u8]) -> R<Token> {
        if response.len() != RESPONSE_LEN {
            return Err(PrivPassError::Malformed);
        }
        let eval = EvaluationElement::<Suite>::deserialize(&response[..NE])
            .map_err(|_| PrivPassError::Malformed)?;
        let proof =
            Proof::<Suite>::deserialize(&response[NE..]).map_err(|_| PrivPassError::Malformed)?;
        let key_id = self.public.key_id();
        let input = Token::input_from(&self.nonce, &self.challenge_digest, &key_id);
        let out = self
            .state
            .finalize(&input, &eval, &proof, self.public.point()?)
            .map_err(|_| PrivPassError::Invalid)?;
        let mut authenticator = [0u8; NK];
        authenticator.copy_from_slice(&out);
        Ok(Token {
            nonce: self.nonce,
            challenge_digest: self.challenge_digest,
            key_id,
            authenticator,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The constant-time `evaluate` gives `voprf`'s bytes.
    #[test]
    fn evaluate_matches_voprf() {
        let mut rng = HedgedRng::new().unwrap();
        let key = IssuerKey::generate(&mut rng).unwrap();
        for n in [0usize, 1, 32, 98, 300] {
            let input: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            let theirs = key.server.evaluate(&input).unwrap();
            assert_eq!(key.evaluate(&input)[..], theirs[..], "{n} bytes");
        }
    }

    /// RFC 9497 A.4.2 (P384-SHA384, VOPRF mode): key derivation and the
    /// outputs of test vectors 1 and 2.
    #[test]
    fn rfc9497_p384_voprf_vectors() {
        let seed = hex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
        let key = IssuerKey::derive_raw(&seed, &hex("74657374206b6579")).unwrap();
        assert_eq!(
            key.public().0.to_vec(),
            hex(
                "031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b
                 46acf59b7c0d4a9077b3da21c25dd482229a0"
            )
        );
        for (input, output) in [
            (
                "00",
                "3333230886b562ffb8329a8be08fea8025755372817ec969d114d1203d0
                 26b4a622beab60220bf19078bca35a529b35c",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "b91c70ea3d4d62ba922eb8a7d03809a441e1c3c7af915cbc2226f485213
                 e895942cd0f8580e6d99f82221e66c40d274f",
            ),
        ] {
            assert_eq!(
                key.server.evaluate(&hex(input)).unwrap().to_vec(),
                hex(output)
            );
        }
    }

    fn challenge() -> TokenChallenge {
        TokenChallenge {
            issuer_name: "credgate.example".into(),
            redemption_context: vec![],
            origin_info: String::new(),
        }
    }

    #[test]
    fn issue_and_redeem() {
        let mut rng = HedgedRng::new().unwrap();
        let key = IssuerKey::derive(&[7; 32], 1).unwrap();
        let digest = challenge().digest().unwrap();
        let (req, pending) = Pending::begin(key.public(), digest, &mut rng).unwrap();
        assert_eq!(req.len(), REQUEST_LEN);
        let resp = key.issue(&req, &mut rng).unwrap();
        let token = pending.finish(&resp).unwrap();
        let bytes = token.encode();
        assert_eq!(bytes.len(), TOKEN_LEN);
        let back = Token::decode(&bytes).unwrap();
        assert!(key.verify(&back, &digest));
        // Another challenge, another epoch's key, a changed authenticator.
        let other = TokenChallenge {
            origin_info: "elsewhere".into(),
            ..challenge()
        };
        assert!(!key.verify(&back, &other.digest().unwrap()));
        let next = IssuerKey::derive(&[7; 32], 2).unwrap();
        assert_ne!(next.public(), key.public());
        assert!(!next.verify(&back, &digest));
        let mut bad = back.clone();
        bad.authenticator[0] ^= 1;
        assert!(!key.verify(&bad, &digest));
    }

    #[test]
    fn wrong_key_and_bad_proofs_are_refused() {
        let mut rng = HedgedRng::new().unwrap();
        let key = IssuerKey::generate(&mut rng).unwrap();
        let other = loop {
            // A key whose truncated id differs from `key`'s.
            let k = IssuerKey::generate(&mut rng).unwrap();
            if k.public().key_id()[31] != key.public().key_id()[31] {
                break k;
            }
        };
        let digest = challenge().digest().unwrap();
        let (req, pending) = Pending::begin(key.public(), digest, &mut rng).unwrap();
        assert_eq!(other.issue(&req, &mut rng), Err(PrivPassError::WrongKey));
        // A response from another key fails the proof.
        let (req2, _) = Pending::begin(other.public(), digest, &mut rng).unwrap();
        let resp2 = other.issue(&req2, &mut rng).unwrap();
        assert_eq!(pending.finish(&resp2).err(), Some(PrivPassError::Invalid));
        assert_eq!(
            key.issue(&req[..10], &mut rng),
            Err(PrivPassError::Malformed)
        );
        assert!(Token::decode(&[0; TOKEN_LEN]).is_err());
    }
}

/// Token verification under Valgrind (RT-15, `cargo xtask ctgrind`): the
/// issuer's secret key is poisoned, and Memcheck must see no branch or
/// address that depends on it while a token is checked.
#[cfg(test)]
mod ctgrind {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use enclave_platform::ctgrind;
    use std::hint::black_box;

    #[test]
    #[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
    fn token_verification_is_constant_time() {
        assert!(
            ctgrind::on_valgrind(),
            "run under Valgrind: cargo xtask ctgrind"
        );
        let mut rng = HedgedRng::new().unwrap();
        let seed = black_box([0x51u8; 32]);
        let digest = blob_challenge(&[3; 16]).digest().unwrap();
        // A token from the key, before anything is poisoned.
        let key = IssuerKey::derive(&seed, 7).unwrap();
        let (req, pending) = Pending::begin(key.public(), digest, &mut rng).unwrap();
        let token = pending.finish(&key.issue(&req, &mut rng).unwrap()).unwrap();
        let mut forged = Token::decode(&token.encode()).unwrap();
        forged.authenticator[0] ^= 1;
        // The key again, from a poisoned seed: its scalar is secret; its
        // public half is public (it is published).
        ctgrind::poison(&seed);
        let key = IssuerKey::derive(&seed, 7).unwrap();
        ctgrind::unpoison(&seed);
        ctgrind::unpoison(&key.public.0);
        let mut answers = [0u8; 2];
        let before = ctgrind::errors();
        for (i, t) in [&token, &forged].into_iter().enumerate() {
            answers[i] = u8::from(key.verify(t, &digest));
        }
        // The answers are what may depend on the key: looked at only now.
        ctgrind::unpoison(black_box(&answers));
        let n = ctgrind::errors() - before;
        assert_eq!(n, 0, "token verification depends on the issuer key");
        assert_eq!(answers, [1, 0]);
    }
}
