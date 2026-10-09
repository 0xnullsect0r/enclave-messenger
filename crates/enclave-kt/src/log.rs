//! The server-side log (`KtLog`), witnesses, and client lookup verification.

use crate::config::EnclaveKtConfig;
use crate::head::{
    CTX_COSIGN, Cosignature, Equivocation, SignedHead, TreeHead, WitnessPolicy, cosign_message,
};
use crate::store::KtStore;
use crate::username::{normalize, skeleton};
use crate::{KtError, Result};
use akd::ecvrf::{VRFKeyStorage, VrfError};
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, AppendOnlyProof, AzksParallelismConfig, Directory, LookupProof};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};
use std::collections::HashMap;
use std::sync::Arc;

/// The key-transparency label under which a server commits its
/// descriptor's digest (not a valid username: it starts with a zero byte).
pub const DESCRIPTOR_LABEL: &[u8] = b"\0descriptor";

/// First byte of an account record's label (`03-identity.md` §8.1): the
/// label is this byte and the last 31 bytes of the account's manifest
/// directory key. Not a valid username (a control character), and not the
/// descriptor's (a zero byte).
pub const ACCOUNT_TAG: u8 = 0x01;

/// Length of an account record's value: [`account_record`].
pub const ACCOUNT_RECORD_LEN: usize = 128;

/// The label of the account whose manifest directory key ends in `tail`
/// (its last 31 bytes).
pub fn account_label(tail: &[u8; 31]) -> Vec<u8> {
    [&[ACCOUNT_TAG][..], tail].concat()
}

/// An account's record: SHA3-512 of its signed manifest as the server
/// serves it, then SHA3-512 of its attestation list as served (the empty
/// string when there is none). Everyone who checks it against the log sees
/// the same manifest and the same co-signatures and vetoes.
pub fn account_record(manifest: &[u8], attestations: &[u8]) -> [u8; ACCOUNT_RECORD_LEN] {
    let mut r = [0u8; ACCOUNT_RECORD_LEN];
    r[..64].copy_from_slice(&enclave_crypto::hash::sha3_512(manifest));
    r[64..].copy_from_slice(&enclave_crypto::hash::sha3_512(attestations));
    r
}

/// VRF key held in memory for the life of the process.
#[derive(Clone)]
pub struct VrfKey(Arc<[u8; 32]>);

#[async_trait::async_trait]
impl VRFKeyStorage for VrfKey {
    async fn retrieve(&self) -> core::result::Result<Vec<u8>, VrfError> {
        Ok(self.0.to_vec())
    }
}

fn akd_err(e: impl core::fmt::Display) -> KtError {
    KtError::Directory(e.to_string())
}

type Dir = Directory<EnclaveKtConfig, KtStore, VrfKey>;

/// A server's key-transparency log.
pub struct KtLog {
    server: [u8; 16],
    store: KtStore,
    dir: Dir,
    signing: CompositeSigningKey,
    heads: Vec<SignedHead>,
    vrf_public: Vec<u8>,
    /// The VRF key (for absence proofs, which akd's directory doesn't make).
    vrf: VrfKey,
    /// skeleton → registered name
    skeletons: HashMap<String, String>,
}

impl KtLog {
    /// Create an empty log in memory. `vrf_secret` must stay fixed for the
    /// life of the log.
    pub async fn new(
        server: [u8; 16],
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
    ) -> Result<Self> {
        let mut rng = HedgedRng::new().map_err(|_| KtError::Directory("rng".into()))?;
        Self::open(KtStore::memory()?, server, signing, vrf_secret, 0, &mut rng).await
    }

    /// Open the log kept in `store` (empty or written by an earlier run with
    /// the same keys). The signing key and VRF secret must be the ones the
    /// log was started with: a head that doesn't verify under the signing
    /// key, or a tree whose root doesn't match the last signed head, is
    /// refused rather than served. If the process stopped between
    /// committing an epoch and storing its head, that one head is signed
    /// now (at `now`).
    pub async fn open(
        store: KtStore,
        server: [u8; 16],
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let storage = StorageManager::new_no_cache(store.clone());
        let vrf = VrfKey(Arc::new(vrf_secret));
        let dir = Directory::new(storage, vrf.clone(), AzksParallelismConfig::default())
            .await
            .map_err(akd_err)?;
        let vrf_public = dir
            .get_public_key()
            .await
            .map_err(akd_err)?
            .as_bytes()
            .to_vec();
        let heads = store.heads()?;
        for (i, h) in heads.iter().enumerate() {
            h.verify_server(signing.public())?;
            if h.head.server != server || h.head.epoch != i as u64 + 1 {
                return Err(KtError::Directory(
                    "stored heads don't belong to this log".into(),
                ));
            }
        }
        let mut log = Self {
            server,
            store,
            dir,
            signing,
            heads,
            vrf_public,
            vrf,
            skeletons: HashMap::new(),
        };
        // The names are what's stored; their skeletons are recomputed, so
        // a log written under older confusable rules is held to the
        // current ones.
        log.skeletons = log
            .store
            .skeletons()?
            .into_values()
            .map(|n| (skeleton(&n), n))
            .collect();
        let tree = log.dir.get_epoch_hash().await.map_err(akd_err)?;
        let signed = log.heads.last().map_or(0, |h| h.head.epoch);
        if tree.epoch() == signed + 1 {
            log.sign_head(tree.epoch(), tree.hash(), now, rng)?;
        } else if tree.epoch() != signed
            || log.heads.last().is_some_and(|h| h.head.root != tree.hash())
        {
            return Err(KtError::Directory(format!(
                "tree is at epoch {}, last signed head at {signed}",
                tree.epoch()
            )));
        }
        Ok(log)
    }

    /// Server identifier.
    pub fn server(&self) -> [u8; 16] {
        self.server
    }

    /// The server's head-signing public key.
    pub fn public_key(&self) -> &CompositePublic {
        self.signing.public()
    }

    /// VRF public key clients need to verify lookups.
    pub fn vrf_public(&self) -> &[u8] {
        &self.vrf_public
    }

    /// Register or update `name → value` (value = SHA3-512 of the root key and
    /// the manifest locator). A new name must not share a confusable skeleton
    /// with an existing different name.
    pub async fn publish(
        &mut self,
        name: &str,
        value: Vec<u8>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let n = normalize(name)?;
        let sk = skeleton(&n);
        if let Some(existing) = self.skeletons.get(&sk)
            && existing != &n
        {
            return Err(KtError::Username);
        }
        let sh = self
            .publish_raw(AkdLabel::from(n.as_str()), value, now, rng)
            .await?;
        self.store.put_skeleton(&sk, &n)?;
        self.skeletons.insert(sk, n);
        Ok(sh)
    }

    /// Start a new epoch with no username changes, so heads stay fresh for
    /// clients (they refuse heads older than a day). The label is not a valid
    /// username, so no lookup can reach it.
    pub async fn heartbeat(&mut self, now: u64, rng: &mut HedgedRng) -> Result<SignedHead> {
        self.publish_raw(
            AkdLabel(b"\0heartbeat".to_vec()),
            now.to_be_bytes().to_vec(),
            now,
            rng,
        )
        .await
    }

    /// Commit the digest of the server's current descriptor
    /// (`12-servers.md` §4.3) in a new epoch, under a label no username
    /// can equal, so a server can't show different people different
    /// descriptors without the log showing it.
    pub async fn commit_descriptor(
        &mut self,
        digest: [u8; 64],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        self.commit_labels(vec![(DESCRIPTOR_LABEL.to_vec(), digest.to_vec())], now, rng)
            .await
    }

    /// Commit raw `(label, value)` pairs in one new epoch. Labels must not
    /// be usernames: callers use [`DESCRIPTOR_LABEL`] or
    /// [`account_label`].
    pub async fn commit_labels(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        if entries
            .iter()
            .any(|(l, _)| !matches!(l.first(), Some(&b) if b == 0 || b == ACCOUNT_TAG))
        {
            return Err(KtError::Username);
        }
        let eh = self
            .dir
            .publish(
                entries
                    .into_iter()
                    .map(|(l, v)| (AkdLabel(l), AkdValue(v)))
                    .collect(),
            )
            .await
            .map_err(akd_err)?;
        self.sign_head(eh.epoch(), eh.hash(), now, rng)
    }

    /// Lookup proof for a raw label (see [`Self::commit_labels`]) against
    /// the latest head.
    pub async fn lookup_raw(&self, label: &[u8]) -> Result<(LookupProof, SignedHead)> {
        let head = self.latest().cloned().ok_or(KtError::Lookup)?;
        let (proof, eh) = self
            .dir
            .lookup(AkdLabel(label.to_vec()))
            .await
            .map_err(|_| KtError::Lookup)?;
        if eh.epoch() != head.head.epoch {
            return Err(KtError::Stale);
        }
        Ok((proof, head))
    }

    /// Proof that `name` was never registered, against the latest head:
    /// the VRF proof for the label its first version would have, and akd's
    /// proof that the tree has no such label. Fails if it was registered.
    pub async fn lookup_absent(&self, name: &str) -> Result<(AbsenceProof, SignedHead)> {
        use akd::ecvrf::VRFKeyStorage as _;
        let head = self.latest().cloned().ok_or(KtError::Lookup)?;
        let n = normalize(name)?;
        let storage = StorageManager::new_no_cache(self.store.clone());
        let azks = match storage
            .get::<akd::Azks>(&akd::append_only_zks::DEFAULT_AZKS_KEY)
            .await
            .map_err(|_| KtError::Lookup)?
        {
            akd::storage::types::DbRecord::Azks(a) => a,
            _ => return Err(KtError::Lookup),
        };
        if azks.get_latest_epoch() != head.head.epoch {
            return Err(KtError::Stale);
        }
        let label = AkdLabel::from(n.as_str());
        let vrf_proof = self
            .vrf
            .get_label_proof::<EnclaveKtConfig>(&label, akd::VersionFreshness::Fresh, 1)
            .await
            .map_err(|_| KtError::Lookup)?;
        let node = self.vrf.get_node_label_from_vrf_proof(vrf_proof).await;
        let proof = azks
            .get_non_membership_proof::<EnclaveKtConfig, _>(&storage, node)
            .await
            .map_err(|_| KtError::Lookup)?;
        let root: [u8; 32] = head.head.root;
        // A label that is in the tree has no non-membership proof that
        // verifies; check before answering.
        akd_core::verify::verify_nonmembership_for_tests_only::<EnclaveKtConfig>(root, &proof)
            .map_err(|_| KtError::Lookup)?;
        Ok((
            AbsenceProof {
                vrf_proof: vrf_proof.to_bytes().to_vec(),
                proof,
            },
            head,
        ))
    }

    /// Lookup proof for the committed descriptor digest against the latest
    /// head.
    pub async fn lookup_descriptor(&self) -> Result<(LookupProof, SignedHead)> {
        self.lookup_raw(DESCRIPTOR_LABEL).await
    }

    async fn publish_raw(
        &mut self,
        label: AkdLabel,
        value: Vec<u8>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let eh = self
            .dir
            .publish(vec![(label, AkdValue(value))])
            .await
            .map_err(akd_err)?;
        self.sign_head(eh.epoch(), eh.hash(), now, rng)
    }

    fn sign_head(
        &mut self,
        epoch: u64,
        root: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let head = TreeHead {
            server: self.server,
            epoch,
            root,
            time: now,
        };
        let sh = SignedHead::sign(head, &self.signing, rng)?;
        self.store.put_head(&sh)?;
        self.heads.push(sh.clone());
        Ok(sh)
    }

    /// Latest head (with whatever cosignatures it has collected).
    pub fn latest(&self) -> Option<&SignedHead> {
        self.heads.last()
    }

    /// Heads with epochs in `(after, upto]`, oldest first.
    pub fn heads_after(&self, after: u64, upto: u64) -> Vec<SignedHead> {
        self.heads
            .iter()
            .filter(|h| h.head.epoch > after && h.head.epoch <= upto)
            .cloned()
            .collect()
    }

    /// Attach a witness cosignature to the head of `epoch`.
    pub fn add_cosignature(&mut self, epoch: u64, c: Cosignature) -> Result<()> {
        if let Some(h) = self.heads.iter_mut().find(|h| h.head.epoch == epoch)
            && !h.cosignatures.iter().any(|x| x.witness == c.witness)
        {
            h.cosignatures.push(c);
            self.store.put_head(h)?;
        }
        Ok(())
    }

    /// Lookup proof for `name` against the latest head.
    pub async fn lookup(&self, name: &str) -> Result<(LookupProof, SignedHead)> {
        let n = normalize(name)?;
        let head = self.latest().cloned().ok_or(KtError::Lookup)?;
        let (proof, eh) = self
            .dir
            .lookup(AkdLabel::from(n.as_str()))
            .await
            .map_err(|_| KtError::Lookup)?;
        if eh.epoch() != head.head.epoch {
            return Err(KtError::Stale);
        }
        Ok((proof, head))
    }

    /// Append-only proof from epoch `from` to epoch `to`.
    pub async fn audit(&self, from: u64, to: u64) -> Result<AppendOnlyProof> {
        self.dir.audit(from, to).await.map_err(akd_err)
    }
}

/// Client: verify a lookup, returning `(value, version, trusted time)`.
pub fn verify_lookup(
    policy: &WitnessPolicy,
    server_key: &CompositePublic,
    server_operator: &str,
    vrf_public: &[u8],
    sh: &SignedHead,
    name: &str,
    proof: LookupProof,
    now: u64,
) -> Result<(Vec<u8>, u64, u64)> {
    let trusted = policy.check(sh, server_key, server_operator, now)?;
    let n = normalize(name)?;
    let r = akd::verify::lookup_verify::<EnclaveKtConfig>(
        vrf_public,
        sh.head.root,
        sh.head.epoch,
        AkdLabel::from(n.as_str()),
        proof,
    )
    .map_err(|_| KtError::Lookup)?;
    Ok((r.value.0, r.version, trusted))
}

/// Proof that a name was never registered in a log (as of a head).
#[derive(Clone, Debug)]
pub struct AbsenceProof {
    /// VRF proof for the label of the name's first version.
    pub vrf_proof: Vec<u8>,
    /// akd's proof that the tree holds no such label.
    pub proof: akd::NonMembershipProof,
}

/// Verify that `name` was never registered in the log whose head `sh` is,
/// under `policy`'s witnesses: the VRF proof binds the label to the name
/// (under the pinned VRF key), and the tree under the signed root has no
/// such label. Returns the trusted head time.
#[allow(clippy::too_many_arguments)]
pub fn verify_absence(
    policy: &WitnessPolicy,
    server_key: &CompositePublic,
    server_operator: &str,
    vrf_public: &[u8],
    sh: &SignedHead,
    name: &str,
    proof: &AbsenceProof,
    now: u64,
) -> Result<u64> {
    use akd::Configuration as _;
    let trusted = policy.check(sh, server_key, server_operator, now)?;
    let n = normalize(name)?;
    let pk = akd::ecvrf::VRFPublicKey::try_from(vrf_public).map_err(|_| KtError::Lookup)?;
    let hashed = EnclaveKtConfig::get_hash_from_label_input(
        &AkdLabel::from(n.as_str()),
        akd::VersionFreshness::Fresh,
        1,
    );
    let vrf =
        akd::ecvrf::Proof::try_from(proof.vrf_proof.as_slice()).map_err(|_| KtError::Lookup)?;
    pk.verify(&vrf, &hashed).map_err(|_| KtError::Lookup)?;
    if akd::NodeLabel::new(vrf_label(&proof.vrf_proof)?, 256) != proof.proof.label {
        return Err(KtError::Lookup);
    }
    akd_core::verify::verify_nonmembership_for_tests_only::<EnclaveKtConfig>(
        sh.head.root,
        &proof.proof,
    )
    .map_err(|_| KtError::Lookup)?;
    Ok(trusted)
}

/// The tree label a verified VRF proof gives: the first 32 bytes of the
/// ECVRF output (RFC 9381 proof-to-hash, as akd computes it:
/// `SHA-512(0x03 ‖ 0x03 ‖ compress(8·Γ) ‖ 0x00)`, Γ the proof's first 32
/// bytes). akd keeps this step to itself.
fn vrf_label(proof: &[u8]) -> Result<[u8; 32]> {
    use sha2::Digest as _;
    let gamma = curve25519_dalek::edwards::CompressedEdwardsY(
        proof
            .get(..32)
            .and_then(|b| b.try_into().ok())
            .ok_or(KtError::Lookup)?,
    )
    .decompress()
    .ok_or(KtError::Lookup)?;
    let out = sha2::Sha512::new()
        .chain_update([0x03, 0x03])
        .chain_update(gamma.mul_by_cofactor().compress().as_bytes())
        .chain_update([0x00])
        .finalize();
    let mut label = [0u8; 32];
    label.copy_from_slice(&out[..32]);
    Ok(label)
}

/// Verify a lookup of a server's committed descriptor digest
/// ([`KtLog::commit_descriptor`]) the way [`verify_lookup`] verifies a
/// name. Returns the 64-byte digest and the trusted head time.
#[allow(clippy::too_many_arguments)]
pub fn verify_descriptor_lookup(
    policy: &WitnessPolicy,
    server_key: &CompositePublic,
    server_operator: &str,
    vrf_public: &[u8],
    sh: &SignedHead,
    proof: LookupProof,
    now: u64,
) -> Result<([u8; 64], u64)> {
    let (value, trusted) = verify_label_lookup(
        policy,
        server_key,
        server_operator,
        vrf_public,
        sh,
        DESCRIPTOR_LABEL,
        proof,
        now,
    )?;
    let digest = value.try_into().map_err(|_| KtError::Lookup)?;
    Ok((digest, trusted))
}

/// Verify a lookup of a raw label ([`KtLog::commit_labels`]): the head is
/// signed and cosigned per `policy`, and the proof binds `label` to the
/// returned value under it. Returns the value and the trusted head time.
#[allow(clippy::too_many_arguments)]
pub fn verify_label_lookup(
    policy: &WitnessPolicy,
    server_key: &CompositePublic,
    server_operator: &str,
    vrf_public: &[u8],
    sh: &SignedHead,
    label: &[u8],
    proof: LookupProof,
    now: u64,
) -> Result<(Vec<u8>, u64)> {
    let trusted = policy.check(sh, server_key, server_operator, now)?;
    let r = akd::verify::lookup_verify::<EnclaveKtConfig>(
        vrf_public,
        sh.head.root,
        sh.head.epoch,
        AkdLabel(label.to_vec()),
        proof,
    )
    .map_err(|_| KtError::Lookup)?;
    Ok((r.value.0, trusted))
}

/// A witness as the log's server reaches it: in the same process
/// ([`Witness`], development and tests) or another operator's service
/// over HTTPS (`enclave_witness::HttpWitness`).
#[async_trait::async_trait]
pub trait WitnessClient: Send {
    /// The witness id.
    fn witness_id(&self) -> [u8; 16];
    /// The last epoch the witness cosigned for `server`, if it knows it.
    async fn last_epoch(&mut self, server: &[u8; 16]) -> Option<u64>;
    /// Ask for a cosignature on the newest of `heads` (see
    /// [`Witness::cosign`]).
    async fn cosign(
        &mut self,
        server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        now: u64,
    ) -> Result<Cosignature>;
}

#[async_trait::async_trait]
impl WitnessClient for Witness {
    fn witness_id(&self) -> [u8; 16] {
        self.id
    }

    async fn last_epoch(&mut self, server: &[u8; 16]) -> Option<u64> {
        Witness::last_epoch(self, server)
    }

    async fn cosign(
        &mut self,
        server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        now: u64,
    ) -> Result<Cosignature> {
        let mut rng = HedgedRng::new().map_err(|_| KtError::Directory("rng".into()))?;
        Witness::cosign(self, server_key, heads, proof, now, &mut rng).await
    }
}

/// A witness: cosigns heads only after checking they extend what it saw before.
pub struct Witness {
    /// Identifier.
    pub id: [u8; 16],
    /// Operator (for the independence rule).
    pub operator: String,
    signing: CompositeSigningKey,
    last: HashMap<[u8; 16], TreeHead>,
    /// Logs proven to have equivocated: never cosigned again.
    equivocated: HashMap<[u8; 16], Equivocation>,
    store: Option<KtStore>,
}

impl Witness {
    /// New witness that remembers what it cosigned only in memory.
    pub fn new(id: [u8; 16], operator: &str, signing: CompositeSigningKey) -> Self {
        Self {
            id,
            operator: operator.to_string(),
            signing,
            last: HashMap::new(),
            equivocated: HashMap::new(),
            store: None,
        }
    }

    /// A witness that keeps what it last cosigned for each server in
    /// `store`, so after a restart it still refuses a head that doesn't
    /// extend the one it cosigned before.
    pub fn with_store(
        id: [u8; 16],
        operator: &str,
        signing: CompositeSigningKey,
        store: KtStore,
    ) -> Result<Self> {
        Ok(Self {
            id,
            operator: operator.to_string(),
            signing,
            last: store.witnessed(&id)?,
            equivocated: store.equivocations()?,
            store: Some(store),
        })
    }

    /// The last epoch this witness cosigned for `server`.
    pub fn last_epoch(&self, server: &[u8; 16]) -> Option<u64> {
        self.last.get(server).map(|h| h.epoch)
    }

    /// The head this witness last cosigned for `server`.
    pub fn last_head(&self, server: &[u8; 16]) -> Option<TreeHead> {
        self.last.get(server).copied()
    }

    /// Public key clients pin.
    pub fn public_key(&self) -> &CompositePublic {
        self.signing.public()
    }

    /// Take a proof that `server_key`'s log signed two trees for one epoch
    /// (`docs/12-servers.md` §3.8): keep it (the first per log), and never
    /// cosign that log again. Returns whether it was new.
    pub fn record_equivocation(
        &mut self,
        server_key: &CompositePublic,
        e: &Equivocation,
    ) -> Result<bool> {
        e.verify(server_key)?;
        if self.equivocated.contains_key(&e.server()) {
            return Ok(false);
        }
        if let Some(store) = &self.store {
            store.put_equivocation(e)?;
        }
        self.equivocated.insert(e.server(), e.clone());
        Ok(true)
    }

    /// The proof held that `server`'s log equivocated.
    pub fn equivocation(&self, server: &[u8; 16]) -> Option<&Equivocation> {
        self.equivocated.get(server)
    }

    /// Cosign the newest of `heads` (consecutive epochs following the last head
    /// this witness cosigned for that server). `proof` is the append-only proof
    /// from the last cosigned epoch to the newest. The first time a witness sees
    /// a server it cosigns on first use.
    pub async fn cosign(
        &mut self,
        server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Cosignature> {
        let newest = heads.last().ok_or(KtError::Stale)?;
        if self.equivocated.contains_key(&newest.head.server) {
            return Err(KtError::Equivocated);
        }
        for h in heads {
            h.verify_server(server_key)?;
            if h.head.server != newest.head.server {
                return Err(KtError::Signature);
            }
        }
        for w in heads.windows(2) {
            if w[1].head.epoch != w[0].head.epoch + 1 {
                return Err(KtError::NotAppendOnly);
            }
        }
        let server = newest.head.server;
        if let Some(last) = self.last.get(&server).copied() {
            let first = &heads[0].head;
            if first.epoch != last.epoch + 1 {
                return Err(KtError::NotAppendOnly);
            }
            let mut hashes = vec![last.root];
            hashes.extend(heads.iter().map(|h| h.head.root));
            let p = proof.ok_or(KtError::NotAppendOnly)?;
            akd::auditor::audit_verify::<EnclaveKtConfig>(hashes, p)
                .await
                .map_err(|_| KtError::NotAppendOnly)?;
        }
        let signature = self
            .signing
            .sign(CTX_COSIGN, &cosign_message(&newest.head, now), rng)
            .map_err(|_| KtError::Signature)?;
        // Remember the head before handing out the cosignature: a witness
        // that forgot it could later be talked into cosigning a fork.
        if let Some(store) = &self.store {
            store.put_witnessed(&self.id, &newest.head)?;
        }
        self.last.insert(server, newest.head);
        Ok(Cosignature {
            witness: self.id,
            time: now,
            signature,
        })
    }
}
