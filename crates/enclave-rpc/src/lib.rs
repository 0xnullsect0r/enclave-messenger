//! Sealed requests and replies (`docs/09-transport.md` §9.2).
//!
//! Nym's Sphinx layer uses classical cryptography, so every request is sealed
//! again, end to end, to the destination server's **daily** X448 + ML-KEM-1024
//! key. Mailbox addresses and tokens therefore stay post-quantum confidential
//! even if recorded mixnet traffic is later decrypted. The reply is sealed under
//! a key derived from the same exchange, so only the requester can read it.
//!
//! ```text
//! request key = KMAC( EnclaveCombine(2-KEM; DH(eph, S), ML-KEM ss;
//!                     eph ‖ ct ‖ server pks ‖ key id), "enclave/v1/rpc/request")
//! reply key   = KMAC( same, "enclave/v1/rpc/reply")
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod api;

use enclave_crypto::kem::{
    self, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448Public, X448Secret,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_wire::{
    ENVELOPE_LEN, POLL_LEN, POLL_PADDING_LEN, POLL_SEALED_LEN, PollRequest, REQUEST_HEADER_LEN,
    RequestHeader, SUITE_V1, UNIT_LEN, UNIT_PADDING_LEN, UNIT_SEALED_LEN, WireUnit,
};

/// Label for the request key.
pub const RPC_REQUEST: &str = "enclave/v1/rpc/request";
/// Label deriving a day's X448 and ML-KEM key seeds from the request-key
/// chain seed (`docs/12-servers.md` §1.4).
pub const SERVER_REQUEST_KEY: &str = "enclave/v1/server/request-key";
/// Label stepping the request-key chain forward one day.
pub const SERVER_REQUEST_CHAIN: &str = "enclave/v1/server/request-chain";
/// Label for the reply key.
pub const RPC_REPLY: &str = "enclave/v1/rpc/reply";
/// What a server remembers of each request it opened, to refuse a replay:
/// `SHAKE256(label ‖ u32 key_id ‖ ephemeral X448 key ‖ ML-KEM ciphertext)`.
pub const NET_REPLAY_ID: &str = "enclave/v1/net/replay-id";
/// Names a request's answer kept for a later status poll
/// (`docs/09-transport.md` §6.1): both ends derive it from the request's
/// own key exchange, so the request carries no id of its own.
pub const NET_STATUS_ID: &str = "enclave/v1/net/status-id";

/// Errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum RpcError {
    /// Decryption or authentication failed.
    #[error("sealed request failed to open")]
    Crypto,
    /// Wrong size or unsupported format.
    #[error("malformed request")]
    Malformed,
}

impl From<enclave_crypto::Error> for RpcError {
    fn from(_: enclave_crypto::Error) -> Self {
        RpcError::Crypto
    }
}
impl From<enclave_wire::WireError> for RpcError {
    fn from(_: enclave_wire::WireError) -> Self {
        RpcError::Malformed
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, RpcError>;

/// A server's public request key for one day.
#[derive(Clone)]
pub struct ServerKey {
    /// Day index (Unix days).
    pub key_id: u32,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub mlkem: MlKemPublic,
}

impl ServerKey {
    /// Encoded size: `key_id(4) ‖ x448(56) ‖ mlkem(1568)`.
    pub const ENCODED_LEN: usize = 4 + 56 + 1568;

    /// Encode `key_id ‖ x448 ‖ mlkem`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::ENCODED_LEN);
        v.extend_from_slice(&self.key_id.to_be_bytes());
        v.extend_from_slice(&self.x448.0);
        v.extend_from_slice(&self.mlkem.0[..]);
        v
    }

    /// Decode [`ServerKey::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != Self::ENCODED_LEN {
            return Err(RpcError::Malformed);
        }
        let key_id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut x = [0u8; 56];
        x.copy_from_slice(&b[4..60]);
        let mlkem = MlKemPublic::from_slice(&b[60..]).map_err(|_| RpcError::Malformed)?;
        Ok(Self {
            key_id,
            x448: X448Public(x),
            mlkem,
        })
    }
}

impl PartialEq for ServerKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && self.x448.0 == other.x448.0
            && self.mlkem.0[..] == other.mlkem.0[..]
    }
}
impl Eq for ServerKey {}

impl core::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fp: [u8; 8] = enclave_crypto::kmac::kmac256(&self.to_bytes(), b"", "debug");
        write!(f, "ServerKey(day {}, {:02x?})", self.key_id, fp)
    }
}

/// The server's secret request key for one day. Deleted after its day plus a
/// short grace period, which gives forward secrecy for request metadata.
pub struct ServerSecret {
    /// Day index.
    pub key_id: u32,
    x448: X448Secret,
    mlkem: MlKemSecret,
    public: ServerKey,
}

impl ServerSecret {
    /// Generate the key for `key_id`.
    pub fn generate(key_id: u32, rng: &mut HedgedRng) -> Result<Self> {
        let (x448, xp) = X448Secret::generate(rng)?;
        let (mlkem, mp) = MlKemSecret::generate(rng)?;
        Ok(Self {
            key_id,
            x448,
            mlkem,
            public: ServerKey {
                key_id,
                x448: xp,
                mlkem: mp,
            },
        })
    }

    /// The key for `key_id`, derived from that day's chain seed: a server
    /// that restarts derives the same key, so clients' cached keys keep
    /// working, and erasing old seeds erases old keys (forward secrecy).
    pub fn from_seed(key_id: u32, seed: &[u8; 32]) -> Self {
        let material: zeroize::Zeroizing<[u8; 56 + 64]> = zeroize::Zeroizing::new(
            enclave_crypto::kmac::kmac256(seed, &key_id.to_be_bytes(), SERVER_REQUEST_KEY),
        );
        let mut x = [0u8; 56];
        x.copy_from_slice(&material[..56]);
        let x448 = X448Secret::from_bytes(x);
        let xp = x448.public();
        let mut ms = [0u8; 64];
        ms.copy_from_slice(&material[56..]);
        let (mlkem, mp) = MlKemSecret::from_seed(&ms);
        x.fill(0);
        ms.fill(0);
        Self {
            key_id,
            x448,
            mlkem,
            public: ServerKey {
                key_id,
                x448: xp,
                mlkem: mp,
            },
        }
    }

    /// The chain seed for the next day; the caller erases `seed`.
    pub fn next_seed(seed: &[u8; 32]) -> [u8; 32] {
        enclave_crypto::kmac::kmac256(seed, b"", SERVER_REQUEST_CHAIN)
    }

    /// Public half.
    pub fn public(&self) -> &ServerKey {
        &self.public
    }
}

/// Keys for one request/reply exchange.
pub struct Exchange {
    request: SealKey,
    reply: SealKey,
    status: [u8; 32],
}

impl Exchange {
    /// Where a deferred answer to this request waits for a status poll
    /// (`Op::Status`): the same on both ends, unknown to anyone else.
    pub fn status_id(&self) -> [u8; 32] {
        self.status
    }

    /// Seal a reply (header ‖ envelope) into a 16,384-byte reply unit.
    pub fn seal_reply(
        &self,
        header: &RequestHeader,
        envelope: &[u8],
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        if envelope.len() != ENVELOPE_LEN {
            return Err(RpcError::Malformed);
        }
        let pt = [&header.encode()[..], envelope].concat();
        let sealed = seal::seal(&self.reply, b"reply", &pt, rng)?;
        let mut out = vec![0u8; UNIT_LEN];
        out[..sealed.len()].copy_from_slice(&sealed);
        rng.fill("rpc/reply-padding", &mut out[sealed.len()..])?;
        Ok(out)
    }

    /// Open a reply unit.
    pub fn open_reply(&self, unit: &[u8]) -> Result<(RequestHeader, Vec<u8>)> {
        if unit.len() != UNIT_LEN {
            return Err(RpcError::Malformed);
        }
        let pt = seal::open(&self.reply, b"reply", &unit[..UNIT_SEALED_LEN])?;
        let h = RequestHeader::decode(&pt[..REQUEST_HEADER_LEN])?;
        Ok((h, pt[REQUEST_HEADER_LEN..].to_vec()))
    }
}

fn derive(suite_secrets: &[&[u8]], public: &[&[u8]]) -> Exchange {
    let s = kem::combine(Suite::TwoKem, suite_secrets, public, None);
    Exchange {
        request: seal::derive_key(&s[..], b"", RPC_REQUEST),
        reply: seal::derive_key(&s[..], b"", RPC_REPLY),
        status: enclave_crypto::kmac::kmac256(&s[..], b"", NET_STATUS_ID),
    }
}

fn client_exchange(
    server: &ServerKey,
    rng: &mut HedgedRng,
) -> Result<(X448Public, MlKemCiphertext, Exchange)> {
    let (eph, eph_pub) = X448Secret::generate(rng)?;
    let dh = eph.diffie_hellman(&server.x448)?;
    let (ct, ss) = server.mlkem.encapsulate(rng)?;
    let kid = server.key_id.to_be_bytes();
    let ex = derive(
        &[&dh[..], &ss[..]],
        &[
            &eph_pub.0,
            &ct.0[..],
            &server.x448.0,
            &server.mlkem.0[..],
            &kid,
        ],
    );
    Ok((eph_pub, ct, ex))
}

fn server_exchange(
    secret: &ServerSecret,
    eph: &X448Public,
    ct: &MlKemCiphertext,
) -> Result<Exchange> {
    let dh = secret.x448.diffie_hellman(eph)?;
    let ss = secret.mlkem.decapsulate(ct);
    let p = &secret.public;
    let kid = p.key_id.to_be_bytes();
    Ok(derive(
        &[&dh[..], &ss[..]],
        &[&eph.0, &ct.0[..], &p.x448.0, &p.mlkem.0[..], &kid],
    ))
}

/// Associated data of a request's seal: `u32(key_id) ‖ padding`. The random
/// padding at the end of a unit or poll sits outside the seal, so it is
/// bound here instead: a request with any byte changed, padding included,
/// fails the seal's tag check at the server (RT-03), and nothing in a
/// request can be altered in transit and still be accepted.
fn request_ad(key_id: u32, padding: &[u8]) -> Vec<u8> {
    [&key_id.to_be_bytes()[..], padding].concat()
}

/// Client: seal `header ‖ envelope` into a 16,384-byte request unit.
pub fn seal_request(
    server: &ServerKey,
    header: &RequestHeader,
    envelope: &[u8],
    rng: &mut HedgedRng,
) -> Result<(Vec<u8>, Exchange)> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(RpcError::Malformed);
    }
    let (eph, ct, ex) = client_exchange(server, rng)?;
    let mut padding = [0u8; UNIT_PADDING_LEN];
    rng.fill("rpc/unit-padding", &mut padding)?;
    let pt = [&header.encode()[..], envelope].concat();
    let sealed = seal::seal(&ex.request, &request_ad(server.key_id, &padding), &pt, rng)?;
    let mut sealed_arr = Box::new([0u8; UNIT_SEALED_LEN]);
    sealed_arr.copy_from_slice(&sealed);
    let unit = WireUnit {
        suite: SUITE_V1,
        eph_x448: eph.0,
        kem_ct: ct.0,
        sealed: sealed_arr,
    };
    let mut fill = |b: &mut [u8]| b.copy_from_slice(&padding);
    Ok((unit.encode(&mut fill), ex))
}

/// Client: seal a header-only poll request (2,048 bytes).
pub fn seal_poll(
    server: &ServerKey,
    header: &RequestHeader,
    rng: &mut HedgedRng,
) -> Result<(Vec<u8>, Exchange)> {
    let (eph, ct, ex) = client_exchange(server, rng)?;
    let mut padding = [0u8; POLL_PADDING_LEN];
    rng.fill("rpc/poll-padding", &mut padding)?;
    let sealed = seal::seal(
        &ex.request,
        &request_ad(server.key_id, &padding),
        &header.encode(),
        rng,
    )?;
    let mut s = [0u8; POLL_SEALED_LEN];
    s.copy_from_slice(&sealed);
    let p = PollRequest {
        eph_x448: eph.0,
        kem_ct: ct.0,
        sealed: s,
    };
    let mut fill = |b: &mut [u8]| b.copy_from_slice(&padding);
    Ok((p.encode(&mut fill), ex))
}

/// An opened request.
pub struct Opened {
    /// Request header.
    pub header: RequestHeader,
    /// Envelope (empty for polls).
    pub envelope: Vec<u8>,
    /// Keys for the reply.
    pub exchange: Exchange,
    /// The daily key it was sealed to.
    pub key_id: u32,
    /// Identifies this request (its ephemeral values are fresh for every
    /// sealing): a server refuses the same id twice.
    pub replay_id: [u8; 32],
}

fn replay_id(key_id: u32, eph: &[u8], ct: &[u8]) -> [u8; 32] {
    enclave_crypto::hash::shake256(
        &[NET_REPLAY_ID.as_bytes(), &key_id.to_be_bytes(), eph, ct].concat(),
    )
}

/// Server: open a request unit or poll. The unit does not name the daily key
/// (that would be one more linkable field), so the server tries each key it
/// still holds, newest first; normally that is today's and yesterday's.
pub fn open_request(keys: &[&ServerSecret], bytes: &[u8]) -> Result<Opened> {
    for secret in keys {
        if let Ok(o) = open_with(secret, bytes) {
            return Ok(o);
        }
    }
    Err(RpcError::Crypto)
}

fn open_with(secret: &ServerSecret, bytes: &[u8]) -> Result<Opened> {
    match bytes.len() {
        UNIT_LEN => {
            let ad = request_ad(secret.key_id, &bytes[UNIT_LEN - UNIT_PADDING_LEN..]);
            let u = WireUnit::decode(bytes)?;
            let rid = replay_id(secret.key_id, &u.eph_x448, &u.kem_ct[..]);
            let ex = server_exchange(secret, &X448Public(u.eph_x448), &MlKemCiphertext(u.kem_ct))?;
            let pt = seal::open(&ex.request, &ad, &u.sealed[..])?;
            let header = RequestHeader::decode(&pt[..REQUEST_HEADER_LEN])?;
            Ok(Opened {
                header,
                envelope: pt[REQUEST_HEADER_LEN..].to_vec(),
                exchange: ex,
                key_id: secret.key_id,
                replay_id: rid,
            })
        }
        POLL_LEN => {
            let ad = request_ad(secret.key_id, &bytes[POLL_LEN - POLL_PADDING_LEN..]);
            let p = PollRequest::decode(bytes)?;
            let rid = replay_id(secret.key_id, &p.eph_x448, &p.kem_ct[..]);
            let ex = server_exchange(secret, &X448Public(p.eph_x448), &MlKemCiphertext(p.kem_ct))?;
            let pt = seal::open(&ex.request, &ad, &p.sealed)?;
            let header = RequestHeader::decode(&pt)?;
            Ok(Opened {
                header,
                envelope: Vec::new(),
                exchange: ex,
                key_id: secret.key_id,
                replay_id: rid,
            })
        }
        _ => Err(RpcError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_wire::Op;

    #[test]
    fn request_reply_roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let s = ServerSecret::generate(20_000, &mut rng).unwrap();
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: [1; 32],
            token: [2; 32],
        };
        let env = vec![7u8; ENVELOPE_LEN];
        let (unit, client_ex) = seal_request(s.public(), &h, &env, &mut rng).unwrap();
        assert_eq!(unit.len(), UNIT_LEN);
        let opened = open_request(&[&s], &unit).unwrap();
        assert_eq!(opened.header, h);
        assert_eq!(opened.envelope, env);
        let reply_h = RequestHeader {
            op: Op::Write,
            flags: 1,
            mailbox: [0; 32],
            token: [0; 32],
        };
        let reply = opened
            .exchange
            .seal_reply(&reply_h, &vec![9u8; ENVELOPE_LEN], &mut rng)
            .unwrap();
        let (rh, renv) = client_ex.open_reply(&reply).unwrap();
        assert_eq!(rh, reply_h);
        assert_eq!(renv, vec![9u8; ENVELOPE_LEN]);
        // A key from another day fails; the right key among several works.
        let other = ServerSecret::generate(20_001, &mut rng).unwrap();
        assert!(open_request(&[&other], &unit).is_err());
        assert!(open_request(&[&other, &s], &unit).is_ok());
        let mut t = unit.clone();
        t[5000] ^= 1;
        assert!(open_request(&[&s], &t).is_err());
    }

    #[test]
    fn poll_roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let s = ServerSecret::generate(1, &mut rng).unwrap();
        let h = RequestHeader {
            op: Op::Poll,
            flags: 0,
            mailbox: [3; 32],
            token: [4; 32],
        };
        let (p, _) = seal_poll(s.public(), &h, &mut rng).unwrap();
        assert_eq!(p.len(), POLL_LEN);
        let o = open_request(&[&s], &p).unwrap();
        assert_eq!(o.header, h);
        assert!(o.envelope.is_empty());
    }
}
