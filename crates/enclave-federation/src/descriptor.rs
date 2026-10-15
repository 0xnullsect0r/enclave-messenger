//! Server descriptors (`docs/12-servers.md` §4.3).
//!
//! ```text
//! descriptor = u8(1) ‖ identity pk (2,649)
//!            ‖ bytes(domain) ‖ bytes(operator) ‖ bytes(family)
//!            ‖ bytes(nym address) ‖ bytes(onion address)
//!            ‖ policy: 8 × u32
//!            ‖ u8(has kt) [‖ head key (2,649) ‖ bytes(VRF public key)]
//!            ‖ u8(n) ‖ n × KeyCert
//!            ‖ u64(published) ‖ u64(expires)
//!            ‖ CompositeSign(identity, "enclave/v1/net/server-descriptor", all of the above)
//! ```
//!
//! Served at `https://<domain>/.well-known/enclave` and over the mixnet
//! (`DirKind::Descriptor`), re-signed daily with fresh key certificates.

use crate::codec::{Reader, Writer};
use crate::keycert::{KeyCert, MAX_CERTS};
use crate::{
    FedError, MAX_ADDRESS, MAX_DOMAIN, MAX_NAME, Result, read_composite, read_sig, server_id, utf8,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};
use enclave_rpc::ServerKey;

/// Signature context of a server descriptor.
pub const CTX_SERVER_DESCRIPTOR: &str = "enclave/v1/net/server-descriptor";
const VERSION: u8 = 2;
/// Most blob-token issuer keys a descriptor lists (this month's, next).
pub const MAX_BLOB_ISSUERS: usize = 2;

/// A blob-upload token issuer key (`docs/09-transport.md` §9): the public
/// key Privacy Pass tokens of one month are issued under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobIssuer {
    /// The issuer-key epoch (`enclave_rpc::api::issuer_epoch`).
    pub epoch: u32,
    /// The compressed P-384 public key.
    pub public: [u8; 49],
}
/// Longest VRF public key.
const MAX_VRF: usize = 64;
/// Longest a descriptor may stay valid.
pub const MAX_VALIDITY_SECS: u64 = 3 * 86_400;

/// A server's abuse-control policy, as clients need to know it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Proof-of-work effort for request-inbox writes.
    pub effort_request: u32,
    /// Proof-of-work effort for a bundle claim.
    pub effort_claim: u32,
    /// Blob-upload tokens one inbox may be issued a day (`BlobAlloc`).
    pub blob_tokens_per_day: u32,
    /// Proof-of-work effort for a username claim.
    pub effort_username: u32,
    /// Proof-of-work effort for creating an inbox.
    pub effort_inbox: u32,
    /// Stored envelopes per inbox.
    pub inbox_quota: u32,
    /// Pending requests per request inbox.
    pub request_quota: u32,
    /// Unspent tokens per inbox.
    pub token_quota: u32,
    /// Days envelopes and blobs are kept.
    pub ttl_days: u32,
}

/// The keys clients pin for a server's key-transparency log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtKeys {
    /// Head-signing key.
    pub head_key: CompositePublic,
    /// VRF public key.
    pub vrf_public: Vec<u8>,
}

/// What a server says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDescriptor {
    /// Identity public key; the server id is derived from it.
    pub identity: CompositePublic,
    /// Public domain.
    pub domain: String,
    /// Operator name.
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// Nym address of the server's ingress (empty until it has one).
    pub nym_address: String,
    /// Onion address of the fallback route (empty if none).
    pub onion: String,
    /// Policy.
    pub policy: Policy,
    /// Key-transparency log, if the server runs one.
    pub kt: Option<KtKeys>,
    /// Request-key certificates (current and next).
    pub certs: Vec<KeyCert>,
    /// Blob-upload token issuer keys (this month's and next).
    pub blob_issuers: Vec<BlobIssuer>,
    /// When signed.
    pub published: u64,
    /// Valid until.
    pub expires: u64,
    /// Encoding version (a version-1 descriptor has no blob issuers).
    version: u8,
    signature: Vec<u8>,
}

impl ServerDescriptor {
    /// The server id.
    pub fn id(&self) -> [u8; 16] {
        server_id(&self.identity)
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version)
            .fixed(&self.identity.to_bytes())
            .bytes(self.domain.as_bytes())
            .bytes(self.operator.as_bytes())
            .bytes(self.family.as_bytes())
            .bytes(self.nym_address.as_bytes())
            .bytes(self.onion.as_bytes());
        let p = &self.policy;
        for v in [
            p.effort_request,
            p.effort_claim,
            p.blob_tokens_per_day,
            p.effort_username,
            p.effort_inbox,
            p.inbox_quota,
            p.request_quota,
            p.token_quota,
            p.ttl_days,
        ] {
            w.u32(v);
        }
        match &self.kt {
            Some(k) => {
                w.u8(1).fixed(&k.head_key.to_bytes()).bytes(&k.vrf_public);
            }
            None => {
                w.u8(0);
            }
        }
        w.u8(self.certs.len() as u8);
        let mut b = w.finish();
        for c in &self.certs {
            b.extend_from_slice(&c.encode());
        }
        if self.version >= 2 {
            b.push(self.blob_issuers.len() as u8);
            for i in &self.blob_issuers {
                b.extend_from_slice(&i.epoch.to_be_bytes());
                b.extend_from_slice(&i.public);
            }
        }
        b.extend_from_slice(&self.published.to_be_bytes());
        b.extend_from_slice(&self.expires.to_be_bytes());
        b
    }

    /// Build and sign a descriptor. `keys` are the request keys to certify
    /// (today's and tomorrow's).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &CompositeSigningKey,
        domain: &str,
        operator: &str,
        family: &str,
        nym_address: &str,
        onion: &str,
        policy: Policy,
        kt: Option<KtKeys>,
        keys: &[ServerKey],
        blob_issuers: &[BlobIssuer],
        published: u64,
        expires: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        if domain.is_empty()
            || domain.len() > MAX_DOMAIN
            || operator.len() > MAX_NAME
            || family.len() > MAX_NAME
            || nym_address.len() > MAX_ADDRESS
            || onion.len() > MAX_ADDRESS
            || keys.is_empty()
            || keys.len() > MAX_CERTS
            || blob_issuers.len() > MAX_BLOB_ISSUERS
            || expires <= published
            || expires - published > MAX_VALIDITY_SECS
        {
            return Err(FedError::Malformed);
        }
        let certs = keys
            .iter()
            .map(|k| KeyCert::sign(identity, k, rng))
            .collect::<Result<Vec<_>>>()?;
        let mut d = Self {
            identity: identity.public().clone(),
            domain: domain.into(),
            operator: operator.into(),
            family: family.into(),
            nym_address: nym_address.into(),
            onion: onion.into(),
            policy,
            kt,
            certs,
            blob_issuers: blob_issuers.to_vec(),
            published,
            expires,
            version: VERSION,
            signature: Vec::new(),
        };
        d.signature = identity
            .sign(CTX_SERVER_DESCRIPTOR.as_bytes(), &d.body(), rng)
            .map_err(|_| FedError::Crypto)?;
        Ok(d)
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode (without checking signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if !(1..=VERSION).contains(&version) {
            return Err(FedError::Malformed);
        }
        let identity = read_composite(&mut r)?;
        let domain = utf8(r.bytes(MAX_DOMAIN)?)?;
        let operator = utf8(r.bytes(MAX_NAME)?)?;
        let family = utf8(r.bytes(MAX_NAME)?)?;
        let nym_address = utf8(r.bytes(MAX_ADDRESS)?)?;
        let onion = utf8(r.bytes(MAX_ADDRESS)?)?;
        let mut v = [0u32; 9];
        for x in &mut v {
            *x = r.u32()?;
        }
        let policy = Policy {
            effort_request: v[0],
            effort_claim: v[1],
            blob_tokens_per_day: v[2],
            effort_username: v[3],
            effort_inbox: v[4],
            inbox_quota: v[5],
            request_quota: v[6],
            token_quota: v[7],
            ttl_days: v[8],
        };
        let kt = match r.u8()? {
            0 => None,
            1 => Some(KtKeys {
                head_key: read_composite(&mut r)?,
                vrf_public: r.bytes(MAX_VRF)?.to_vec(),
            }),
            _ => return Err(FedError::Malformed),
        };
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_CERTS {
            return Err(FedError::Malformed);
        }
        let mut certs = Vec::with_capacity(n);
        for _ in 0..n {
            certs.push(KeyCert::decode(r.fixed(crate::keycert::CERT_LEN)?)?);
        }
        // Version 1 had none.
        let mut blob_issuers = Vec::new();
        if version >= 2 {
            let n = usize::from(r.u8()?);
            if n > MAX_BLOB_ISSUERS {
                return Err(FedError::Malformed);
            }
            for _ in 0..n {
                blob_issuers.push(BlobIssuer {
                    epoch: r.u32()?,
                    public: r.fixed(49)?.try_into().map_err(|_| FedError::Malformed)?,
                });
            }
        }
        let published = r.u64()?;
        let expires = r.u64()?;
        let signature = read_sig(&mut r)?.to_vec();
        r.end()?;
        Ok(Self {
            identity,
            domain,
            operator,
            family,
            nym_address,
            onion,
            policy,
            kt,
            certs,
            blob_issuers,
            published,
            expires,
            version,
            signature,
        })
    }

    /// Check the self-signature, every key certificate, and that `now` is
    /// within the validity window.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.identity
            .verify(
                CTX_SERVER_DESCRIPTOR.as_bytes(),
                &self.body(),
                &self.signature,
            )
            .map_err(|_| FedError::Signature)?;
        for c in &self.certs {
            c.verify(&self.identity)?;
        }
        if now < self.published.saturating_sub(3600) || now >= self.expires {
            return Err(FedError::Expired);
        }
        Ok(())
    }

    /// The request key to use at `now`.
    pub fn key_at(&self, now: u64) -> Option<&ServerKey> {
        self.certs
            .iter()
            .filter(|c| c.valid_at(now))
            .max_by_key(|c| c.not_before)
            .map(|c| &c.key)
    }

    /// The blob-token issuer key for `epoch`, if listed.
    pub fn blob_issuer(&self, epoch: u32) -> Option<[u8; 49]> {
        self.blob_issuers
            .iter()
            .find(|i| i.epoch == epoch)
            .map(|i| i.public)
    }

    /// SHA3-512 of the encoding (committed to the key-transparency log).
    pub fn digest(&self) -> [u8; 64] {
        enclave_crypto::hash::sha3_512(&self.encode())
    }
}
