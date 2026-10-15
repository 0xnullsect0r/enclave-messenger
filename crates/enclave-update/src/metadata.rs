//! The four roles, their encoding and signatures, and the client's checks.

use crate::sigsum::{Policy, Proof, SigsumError};
use enclave_crypto::hash::sha3_512;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{
    COMPOSITE_PK_LEN, COMPOSITE_SEED_LEN, COMPOSITE_SIG_LEN, CompositePublic, CompositeSigningKey,
    ROOT_PK_LEN, ROOT_SIG_LEN, RootPublic, RootSigningKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Signature context of every release document.
pub const CTX_RELEASE: &str = "enclave/v1/update/release";
/// KMAC label deriving a maintainer's SLH-DSA key from its secret.
pub const MAINTAINER_KEYGEN: &str = "enclave/v1/update/maintainer-keygen";
const MAGIC: &[u8; 8] = b"ENCLUPD1";
/// Bytes of a maintainer's secret: SLH-DSA secret (32) ‖ composite seed.
pub const MAINTAINER_SECRET_LEN: usize = 32 + COMPOSITE_SEED_LEN;
/// Bytes of a maintainer's public key.
pub const MAINTAINER_PUBLIC_LEN: usize = ROOT_PK_LEN + COMPOSITE_PK_LEN;
const SIG_LEN: usize = ROOT_SIG_LEN + COMPOSITE_SIG_LEN;
/// Most keys a root names, files a targets document lists, signatures.
const MAX_KEYS: usize = 16;
const MAX_TARGETS: usize = 512;
/// Fewest maintainers that co-sign targets, whatever a root says.
pub const MIN_TARGETS_THRESHOLD: u8 = 2;

/// Why an update isn't accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    /// Not a document this reads.
    #[error("malformed release metadata")]
    Malformed,
    /// The wrong role where another was expected.
    #[error("expected {0:?} metadata")]
    WrongRole(Role),
    /// Too few valid signatures from distinct keys of the role.
    #[error("{0:?} has {1} valid signatures, needs {2}")]
    Threshold(Role, usize, u8),
    /// Expired (or a freeze: no fresh timestamp).
    #[error("{0:?} metadata expired")]
    Expired(Role),
    /// An older version than one already seen.
    #[error("{0:?} version {1} is older than {2}")]
    Rollback(Role, u32, u32),
    /// A hash or version doesn't match what the role above names.
    #[error("{0:?} doesn't match what the role above it names")]
    Mismatch(Role),
    /// A root more than one version ahead.
    #[error("root versions must come one at a time")]
    RootSkip,
    /// The file isn't in the targets, or its hashes or length differ.
    #[error("the file isn't the release it claims to be")]
    Target,
    /// The Sigsum proof doesn't hold.
    #[error(transparent)]
    Sigsum(#[from] SigsumError),
    /// A signing operation failed.
    #[error("signing failed")]
    Crypto,
}

type Result<T> = std::result::Result<T, UpdateError>;

/// The roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Keys and thresholds.
    Root = 1,
    /// The release files.
    Targets = 2,
    /// The targets' version.
    Snapshot = 3,
    /// The snapshot's version; short-lived.
    Timestamp = 4,
}

impl Role {
    fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            1 => Role::Root,
            2 => Role::Targets,
            3 => Role::Snapshot,
            4 => Role::Timestamp,
            _ => return Err(UpdateError::Malformed),
        })
    }
}

/// A maintainer's signing key (kept offline, G2): an SLH-DSA key derived
/// from a 32-byte secret, and a composite key.
pub struct MaintainerKey {
    slh: RootSigningKey,
    composite: CompositeSigningKey,
    secret: Zeroizing<Vec<u8>>,
}

/// A maintainer's public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintainerPublic {
    /// SLH-DSA half.
    pub slh: RootPublic,
    /// Composite half.
    pub composite: CompositePublic,
}

impl MaintainerKey {
    /// A fresh key.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        let s: [u8; 32] = rng
            .array("update/maintainer-key")
            .map_err(|_| UpdateError::Crypto)?;
        let c = *CompositeSigningKey::generate(rng)
            .map_err(|_| UpdateError::Crypto)?
            .seed();
        Self::from_bytes(&[&s[..], &c[..]].concat())
    }

    /// The key from its secret encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != MAINTAINER_SECRET_LEN {
            return Err(UpdateError::Malformed);
        }
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&b[..32]);
        let mut c = Zeroizing::new([0u8; COMPOSITE_SEED_LEN]);
        c.copy_from_slice(&b[32..]);
        Ok(Self {
            slh: RootSigningKey::derive(&s, MAINTAINER_KEYGEN),
            composite: CompositeSigningKey::from_seed(&c).map_err(|_| UpdateError::Malformed)?,
            secret: Zeroizing::new(b.to_vec()),
        })
    }

    /// The secret encoding (keep it offline).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.secret.clone()
    }

    /// The public key.
    pub fn public(&self) -> MaintainerPublic {
        MaintainerPublic {
            slh: self.slh.public(),
            composite: self.composite.public().clone(),
        }
    }

    fn sign(&self, msg: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
        let ctx = CTX_RELEASE.as_bytes();
        let a = self
            .slh
            .sign(ctx, msg, rng)
            .map_err(|_| UpdateError::Crypto)?;
        let b = self
            .composite
            .sign(ctx, msg, rng)
            .map_err(|_| UpdateError::Crypto)?;
        Ok([a, b].concat())
    }
}

impl MaintainerPublic {
    /// `SLH-DSA public ‖ composite public`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.slh.0[..], &self.composite.to_bytes()].concat()
    }

    /// Inverse of [`MaintainerPublic::to_bytes`].
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != MAINTAINER_PUBLIC_LEN {
            return Err(UpdateError::Malformed);
        }
        let mut slh = [0u8; ROOT_PK_LEN];
        slh.copy_from_slice(&b[..ROOT_PK_LEN]);
        Ok(Self {
            slh: RootPublic(slh),
            composite: CompositePublic::from_slice(&b[ROOT_PK_LEN..])
                .map_err(|_| UpdateError::Malformed)?,
        })
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let ctx = CTX_RELEASE.as_bytes();
        sig.len() == SIG_LEN
            && self.slh.verify(ctx, msg, &sig[..ROOT_SIG_LEN]).is_ok()
            && self
                .composite
                .verify(ctx, msg, &sig[ROOT_SIG_LEN..])
                .is_ok()
    }
}

// A small reader and writer for the encodings.

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX)).raw(v)
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(UpdateError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| UpdateError::Malformed)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(UpdateError::Malformed);
        }
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(UpdateError::Malformed)
        }
    }
}

/// Which of the root's keys sign a role, and how many must.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleKeys {
    /// Indices into [`Root::keys`].
    pub keys: Vec<u8>,
    /// Valid signatures from distinct keys needed.
    pub threshold: u8,
}

/// The root role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// Version (each new root is the previous one's plus one).
    pub version: u32,
    /// Expiry, Unix seconds.
    pub expires: u64,
    /// Maintainer (and online) keys.
    pub keys: Vec<MaintainerPublic>,
    /// The roles, in the order root, targets, snapshot, timestamp.
    pub roles: [RoleKeys; 4],
    /// What a Sigsum proof must satisfy.
    pub sigsum: Policy,
}

/// One release file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Its file name in the release.
    pub name: String,
    /// Its length.
    pub length: u64,
    /// SHA-256 (what Sigsum logs).
    pub sha256: [u8; 32],
    /// SHA3-512.
    pub sha3_512: [u8; 64],
}

impl Target {
    /// A file's entry.
    pub fn of(name: &str, file: &[u8]) -> Self {
        Self {
            name: name.into(),
            length: file.len() as u64,
            sha256: Sha256::digest(file).into(),
            sha3_512: sha3_512(file),
        }
    }
}

/// The targets role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Targets {
    /// Version.
    pub version: u32,
    /// Expiry.
    pub expires: u64,
    /// The release name (the tag, `v1.2.3`).
    pub release: String,
    /// Every file.
    pub targets: Vec<Target>,
}

/// The snapshot role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Version.
    pub version: u32,
    /// Expiry.
    pub expires: u64,
    /// The targets document's version.
    pub targets_version: u32,
    /// SHA-256 of the signed targets document.
    pub targets_hash: [u8; 32],
}

/// The timestamp role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// Version.
    pub version: u32,
    /// Expiry (days, not months: a freeze shows).
    pub expires: u64,
    /// The snapshot's version.
    pub snapshot_version: u32,
    /// SHA-256 of the signed snapshot.
    pub snapshot_hash: [u8; 32],
}

fn encode_policy(w: &mut W, p: &Policy) {
    w.raw(&p.log);
    w.u8(p.submitters.len() as u8);
    for k in &p.submitters {
        w.raw(k);
    }
    w.u8(p.witnesses.len() as u8);
    for k in &p.witnesses {
        w.raw(k);
    }
    w.u8(p.quorum as u8);
}

fn decode_policy(r: &mut R<'_>) -> Result<Policy> {
    let log = r.arr()?;
    let n = r.u8()? as usize;
    let submitters = (0..n).map(|_| r.arr()).collect::<Result<_>>()?;
    let n = r.u8()? as usize;
    let witnesses: Vec<[u8; 32]> = (0..n).map(|_| r.arr()).collect::<Result<_>>()?;
    let quorum = r.u8()? as usize;
    if quorum == 0 || quorum > witnesses.len() {
        return Err(UpdateError::Malformed);
    }
    Ok(Policy {
        log,
        submitters,
        witnesses,
        quorum,
    })
}

impl Root {
    fn body(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.version)
            .u64(self.expires)
            .u8(self.keys.len() as u8);
        for k in &self.keys {
            w.raw(&k.to_bytes());
        }
        for r in &self.roles {
            w.u8(r.threshold).u8(r.keys.len() as u8).raw(&r.keys);
        }
        encode_policy(&mut w, &self.sigsum);
        w.0
    }

    /// Decode the body (its [`Signed`] document checks the signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = R(b);
        let version = r.u32()?;
        let expires = r.u64()?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_KEYS {
            return Err(UpdateError::Malformed);
        }
        let keys: Vec<MaintainerPublic> = (0..n)
            .map(|_| MaintainerPublic::from_slice(r.take(MAINTAINER_PUBLIC_LEN)?))
            .collect::<Result<_>>()?;
        let mut role = || -> Result<RoleKeys> {
            let threshold = r.u8()?;
            let m = r.u8()? as usize;
            let idx = r.take(m)?.to_vec();
            if threshold == 0
                || usize::from(threshold) > m
                || idx.iter().any(|&i| usize::from(i) >= n)
            {
                return Err(UpdateError::Malformed);
            }
            Ok(RoleKeys {
                keys: idx,
                threshold,
            })
        };
        let roles = [role()?, role()?, role()?, role()?];
        if roles[1].threshold < MIN_TARGETS_THRESHOLD {
            return Err(UpdateError::Malformed);
        }
        let sigsum = decode_policy(&mut r)?;
        r.end()?;
        Ok(Root {
            version,
            expires,
            keys,
            roles,
            sigsum,
        })
    }
}

impl Targets {
    fn body(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.version)
            .u64(self.expires)
            .bytes(self.release.as_bytes());
        w.u16(self.targets.len() as u16);
        for t in &self.targets {
            w.bytes(t.name.as_bytes())
                .u64(t.length)
                .raw(&t.sha256)
                .raw(&t.sha3_512);
        }
        w.0
    }

    /// Decode the body (its [`Signed`] document checks the signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = R(b);
        let version = r.u32()?;
        let expires = r.u64()?;
        let release =
            String::from_utf8(r.bytes(64)?.to_vec()).map_err(|_| UpdateError::Malformed)?;
        let n = r.u16()? as usize;
        if n > MAX_TARGETS {
            return Err(UpdateError::Malformed);
        }
        let mut targets = Vec::with_capacity(n);
        for _ in 0..n {
            let name =
                String::from_utf8(r.bytes(255)?.to_vec()).map_err(|_| UpdateError::Malformed)?;
            if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
                return Err(UpdateError::Malformed);
            }
            targets.push(Target {
                name,
                length: r.u64()?,
                sha256: r.arr()?,
                sha3_512: r.arr()?,
            });
        }
        r.end()?;
        Ok(Targets {
            version,
            expires,
            release,
            targets,
        })
    }
}

impl Snapshot {
    fn body(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.version)
            .u64(self.expires)
            .u32(self.targets_version)
            .raw(&self.targets_hash);
        w.0
    }

    /// Decode the body (its [`Signed`] document checks the signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = R(b);
        let s = Snapshot {
            version: r.u32()?,
            expires: r.u64()?,
            targets_version: r.u32()?,
            targets_hash: r.arr()?,
        };
        r.end()?;
        Ok(s)
    }
}

impl Timestamp {
    fn body(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.version)
            .u64(self.expires)
            .u32(self.snapshot_version)
            .raw(&self.snapshot_hash);
        w.0
    }

    /// Decode the body (its [`Signed`] document checks the signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = R(b);
        let t = Timestamp {
            version: r.u32()?,
            expires: r.u64()?,
            snapshot_version: r.u32()?,
            snapshot_hash: r.arr()?,
        };
        r.end()?;
        Ok(t)
    }
}

/// A signed document: `"ENCLUPD1" ‖ role ‖ u32 len ‖ body ‖ u8 n ‖ n ×
/// (u8 key index ‖ signature)`, each signature over `role ‖ body`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The role.
    pub role: Role,
    /// Its body.
    pub body: Vec<u8>,
    /// `(key index in the root, signature)`.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl Signed {
    fn new(role: Role, body: Vec<u8>) -> Self {
        Self {
            role,
            body,
            signatures: Vec::new(),
        }
    }

    fn message(&self) -> Vec<u8> {
        [&[self.role as u8][..], &self.body].concat()
    }

    /// An unsigned root, for the maintainers to sign.
    pub fn root(root: &Root) -> Self {
        Self::new(Role::Root, root.body())
    }
    /// An unsigned targets document.
    pub fn targets(t: &Targets) -> Self {
        Self::new(Role::Targets, t.body())
    }
    /// An unsigned snapshot.
    pub fn snapshot(s: &Snapshot) -> Self {
        Self::new(Role::Snapshot, s.body())
    }
    /// An unsigned timestamp.
    pub fn timestamp(t: &Timestamp) -> Self {
        Self::new(Role::Timestamp, t.body())
    }

    /// Add `key`'s signature as the root's key number `index`.
    pub fn sign(&mut self, index: u8, key: &MaintainerKey, rng: &mut HedgedRng) -> Result<()> {
        let sig = key.sign(&self.message(), rng)?;
        self.signatures.retain(|(i, _)| *i != index);
        self.signatures.push((index, sig));
        Ok(())
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(MAGIC.to_vec());
        w.u8(self.role as u8)
            .bytes(&self.body)
            .u8(self.signatures.len() as u8);
        for (i, s) in &self.signatures {
            w.u8(*i).raw(s);
        }
        w.0
    }

    /// Inverse of [`Signed::encode`].
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = R(b);
        if r.take(8)? != MAGIC {
            return Err(UpdateError::Malformed);
        }
        let role = Role::from_u8(r.u8()?)?;
        let body = r.bytes(1 << 20)?.to_vec();
        let n = r.u8()? as usize;
        if n > MAX_KEYS {
            return Err(UpdateError::Malformed);
        }
        let signatures = (0..n)
            .map(|_| Ok((r.u8()?, r.take(SIG_LEN)?.to_vec())))
            .collect::<Result<_>>()?;
        r.end()?;
        Ok(Signed {
            role,
            body,
            signatures,
        })
    }

    /// Check its signatures against `root`'s keys for its role.
    fn check(&self, root: &Root, want: Role) -> Result<()> {
        if self.role != want {
            return Err(UpdateError::WrongRole(want));
        }
        let rk = &root.roles[want as usize - 1];
        let msg = self.message();
        let mut seen: Vec<u8> = Vec::new();
        for (i, sig) in &self.signatures {
            // Each key counts once, and only keys of this role count.
            if seen.contains(i) || !rk.keys.contains(i) {
                continue;
            }
            if root
                .keys
                .get(usize::from(*i))
                .is_some_and(|k| k.verify(&msg, sig))
            {
                seen.push(*i);
            }
        }
        // Distinct keys, and distinct maintainers: the same public key may
        // not be listed twice to make one maintainer count as two.
        let mut distinct: Vec<Vec<u8>> = seen
            .iter()
            .filter_map(|i| {
                root.keys
                    .get(usize::from(*i))
                    .map(MaintainerPublic::to_bytes)
            })
            .collect();
        distinct.sort();
        distinct.dedup();
        if distinct.len() < usize::from(rk.threshold) {
            return Err(UpdateError::Threshold(want, distinct.len(), rk.threshold));
        }
        Ok(())
    }
}

/// What a client keeps between updates: the root it trusts and the newest
/// versions it has seen.
#[derive(Clone, Debug)]
pub struct Client {
    root: Root,
    timestamp: u32,
    snapshot: u32,
    targets: u32,
}

/// The checked chain: the release's files.
pub type Release = Targets;

impl Client {
    /// Start from the root built into the app (`root` encoded and signed),
    /// with the versions last seen (0 the first time).
    pub fn new(root: &[u8], seen: [u32; 3]) -> Result<Self> {
        let s = Signed::decode(root)?;
        let r = Root::decode(&s.body)?;
        s.check(&r, Role::Root)?;
        Ok(Self {
            root: r,
            timestamp: seen[0],
            snapshot: seen[1],
            targets: seen[2],
        })
    }

    /// The trusted root.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The versions seen (timestamp, snapshot, targets), to keep.
    pub fn seen(&self) -> [u32; 3] {
        [self.timestamp, self.snapshot, self.targets]
    }

    /// Move to the next root: one version ahead, signed by enough of the
    /// current root's root keys and of its own.
    pub fn update_root(&mut self, next: &[u8]) -> Result<()> {
        let s = Signed::decode(next)?;
        let r = Root::decode(&s.body)?;
        if r.version <= self.root.version {
            return Err(UpdateError::Rollback(
                Role::Root,
                r.version,
                self.root.version,
            ));
        }
        if r.version != self.root.version + 1 {
            return Err(UpdateError::RootSkip);
        }
        s.check(&self.root, Role::Root)?;
        s.check(&r, Role::Root)?;
        self.root = r;
        Ok(())
    }

    /// Check timestamp → snapshot → targets at `now` (TUF's order),
    /// rejecting rollback, expiry and freeze; the release they describe.
    pub fn refresh(
        &mut self,
        timestamp: &[u8],
        snapshot: &[u8],
        targets: &[u8],
        now: u64,
    ) -> Result<Release> {
        if self.root.expires <= now {
            return Err(UpdateError::Expired(Role::Root));
        }
        let ts = Signed::decode(timestamp)?;
        ts.check(&self.root, Role::Timestamp)?;
        let t = Timestamp::decode(&ts.body)?;
        if t.version < self.timestamp {
            return Err(UpdateError::Rollback(
                Role::Timestamp,
                t.version,
                self.timestamp,
            ));
        }
        if t.expires <= now {
            return Err(UpdateError::Expired(Role::Timestamp));
        }
        if t.snapshot_version < self.snapshot {
            return Err(UpdateError::Rollback(
                Role::Snapshot,
                t.snapshot_version,
                self.snapshot,
            ));
        }

        let sn = Signed::decode(snapshot)?;
        let snap_hash: [u8; 32] = Sha256::digest(snapshot).into();
        if snap_hash != t.snapshot_hash {
            return Err(UpdateError::Mismatch(Role::Snapshot));
        }
        sn.check(&self.root, Role::Snapshot)?;
        let s = Snapshot::decode(&sn.body)?;
        if s.version != t.snapshot_version {
            return Err(UpdateError::Mismatch(Role::Snapshot));
        }
        if s.expires <= now {
            return Err(UpdateError::Expired(Role::Snapshot));
        }
        if s.targets_version < self.targets {
            return Err(UpdateError::Rollback(
                Role::Targets,
                s.targets_version,
                self.targets,
            ));
        }

        let tg = Signed::decode(targets)?;
        let tg_hash: [u8; 32] = Sha256::digest(targets).into();
        if tg_hash != s.targets_hash {
            return Err(UpdateError::Mismatch(Role::Targets));
        }
        tg.check(&self.root, Role::Targets)?;
        let release = Targets::decode(&tg.body)?;
        if release.version != s.targets_version {
            return Err(UpdateError::Mismatch(Role::Targets));
        }
        if release.expires <= now {
            return Err(UpdateError::Expired(Role::Targets));
        }
        self.timestamp = t.version;
        self.snapshot = s.version;
        self.targets = release.version;
        Ok(release)
    }

    /// Check a downloaded file against the release and its Sigsum proof:
    /// install it only if this passes.
    pub fn check(
        &self,
        release: &Release,
        name: &str,
        file: &[u8],
        sigsum_proof: &str,
    ) -> Result<()> {
        let want = release
            .targets
            .iter()
            .find(|t| t.name == name)
            .ok_or(UpdateError::Target)?;
        let got = Target::of(name, file);
        if got.length != want.length || got.sha256 != want.sha256 || got.sha3_512 != want.sha3_512 {
            return Err(UpdateError::Target);
        }
        Proof::parse(sigsum_proof)?.verify(&got.sha256, &self.root.sigsum)?;
        Ok(())
    }
}
