//! EQXDH v1: session establishment (`docs/04-eqxdh.md`).
//!
//! PQXDH extended to three KEM families with post-quantum mutual
//! authentication and a hidden initiator.
//!
//! ```text
//! DH1 = X448(IK_A, SPK_B)      DH2 = X448(EK_A, IK_B)
//! DH3 = X448(EK_A, SPK_B)      DH4 = X448(EK_A, OPK_B)            (if an OPK was served)
//! ss_pq   = ML-KEM-1024.Encaps(PQOPK_B | PQSPK_B | last-resort)
//! ss_mce  = McEliece-8192128.Encaps(vault_B)                     (3-KEM suite)
//! ss_auth = ML-KEM-1024.Encaps(auth_B)                           (PQ auth of Bob)
//!
//! stage 1:  k_id = KMAC(EnclaveCombine(DH3, DH4, ss_pq, ss_mce; public stage-1 items))
//!           seals Alice's identity, so Bob's server never learns who initiates
//! final:    SK = EnclaveCombine(DH1..DH4, ss_pq, ss_mce, ss_auth; full transcript; psk)
//! ```
//!
//! Bob's first PQ ratchet step encapsulates to Alice's device auth key, which
//! authenticates Alice post-quantum after one round trip while keeping the
//! session deniable. In On-the-record mode Alice also signs the transcript.

use crate::bundle::{Bundle, PrekeyStore};
use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::identity::{AccountKeys, DeviceId, DeviceKeys};
use crate::labels;
use crate::manifest::{DeviceEntry, Manifest};
use crate::ratchet::{InitialDh, Role, Session, SessionInit};
use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::{
    self, MCELIECE_CT_LEN, MLKEM_CT_LEN, McElieceCiphertext, McEliecePublic, MlKemCiphertext,
    MlKemSecret, Suite, X448Public, X448Secret,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_crypto::sig::{COMPOSITE_SIG_LEN, CompositePublic};
use zeroize::Zeroizing;

/// Conversation mode, bound into the handshake transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Deniable: authentication by shared secrets only (default).
    OffTheRecord = 0,
    /// Every message carries a composite signature.
    OnTheRecord = 1,
}

impl Mode {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Mode::OffTheRecord),
            1 => Ok(Mode::OnTheRecord),
            _ => Err(ProtoError::Decode),
        }
    }
}

/// Which PQ prekey the initiator encapsulated to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPrekeyRef {
    /// A one-time prekey (also supplies DH4).
    OneTime(u64),
    /// The signed prekey's ML-KEM half (accepted from initiators; this
    /// one uses the last-resort key when no one-time prekey is left).
    Signed,
    /// The last-resort prekey.
    LastResort(u32),
}

/// Maximum identity-block locator length.
pub const MAX_LOCATOR: usize = 256;
/// Fixed size of the sealed identity region.
pub const SEALED_IDENTITY_LEN: usize = 5_120;
const IDENTITY_PT_LEN: usize = SEALED_IDENTITY_LEN - seal::TAG_LEN;

/// Fixed size of an encoded initial-message block.
pub const INITIAL_BLOCK_LEN: usize =
    4 + 4 + 9 + 56 + MLKEM_CT_LEN + MCELIECE_CT_LEN + MLKEM_CT_LEN + SEALED_IDENTITY_LEN;

/// The public part of Alice's first message.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialMessage {
    /// Suite (2 or 3 KEMs).
    pub suite: Suite,
    /// Mode.
    pub mode: Mode,
    /// Whether a pre-shared key is mixed in.
    pub psk: bool,
    /// Bob's signed-prekey id.
    pub spk_id: u32,
    /// PQ prekey used.
    pub pq_prekey: PqPrekeyRef,
    /// Alice's ephemeral X448 key.
    pub ek: X448Public,
    /// ML-KEM ciphertext to the PQ prekey.
    pub ct_pq: MlKemCiphertext,
    /// McEliece ciphertext to Bob's vault key (3-KEM suite only).
    pub ct_mce: Option<McElieceCiphertext>,
    /// ML-KEM ciphertext to Bob's device auth key.
    pub ct_auth: MlKemCiphertext,
    /// Sealed identity block (fixed size).
    pub sealed_identity: Vec<u8>,
}

impl core::fmt::Debug for InitialMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitialMessage")
            .field("suite", &self.suite)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl InitialMessage {
    /// Encode to exactly [`INITIAL_BLOCK_LEN`] bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.suite.id())
            .u8(self.mode as u8)
            .u8(u8::from(self.psk))
            .u8(0)
            .u32(self.spk_id);
        match self.pq_prekey {
            PqPrekeyRef::OneTime(id) => w.u8(1).u64(id),
            PqPrekeyRef::Signed => w.u8(2).u64(0),
            PqPrekeyRef::LastResort(id) => w.u8(3).u64(u64::from(id)),
        };
        w.fixed(&self.ek.0).fixed(&self.ct_pq.0[..]);
        match &self.ct_mce {
            Some(c) => w.fixed(&c.0),
            None => w.fixed(&[0u8; MCELIECE_CT_LEN]),
        };
        w.fixed(&self.ct_auth.0[..]).fixed(&self.sealed_identity);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != INITIAL_BLOCK_LEN {
            return Err(ProtoError::Decode);
        }
        let mut r = Reader::new(b);
        let suite = match r.u8()? {
            2 => Suite::TwoKem,
            3 => Suite::ThreeKem,
            _ => return Err(ProtoError::Decode),
        };
        let mode = Mode::from_u8(r.u8()?)?;
        let psk = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtoError::Decode),
        };
        let _reserved = r.u8()?;
        let spk_id = r.u32()?;
        let kind = r.u8()?;
        let id = r.u64()?;
        let pq_prekey = match kind {
            1 => PqPrekeyRef::OneTime(id),
            2 => PqPrekeyRef::Signed,
            3 => PqPrekeyRef::LastResort(u32::try_from(id).map_err(|_| ProtoError::Decode)?),
            _ => return Err(ProtoError::Decode),
        };
        let ek = X448Public(r.array()?);
        let ct_pq = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
        let mce_bytes: [u8; MCELIECE_CT_LEN] = r.array()?;
        let ct_mce = match suite {
            Suite::ThreeKem => Some(McElieceCiphertext(mce_bytes)),
            Suite::TwoKem => None,
        };
        let ct_auth = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
        let sealed_identity = r.fixed(SEALED_IDENTITY_LEN)?.to_vec();
        r.end()?;
        Ok(Self {
            suite,
            mode,
            psk,
            spk_id,
            pq_prekey,
            ek,
            ct_pq,
            ct_mce,
            ct_auth,
            sealed_identity,
        })
    }

    /// Hash used for the responder's replay cache.
    pub fn replay_id(&self) -> [u8; 64] {
        let mut w = Writer::new();
        w.fixed(&self.ek.0)
            .fixed(&self.ct_pq.0[..])
            .fixed(&self.ct_auth.0[..]);
        sha3_512(w.as_slice())
    }
}

/// Alice's identity as revealed to Bob inside the sealed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorIdentity {
    /// Alice's root public key.
    pub root: [u8; 64],
    /// Version of Alice's manifest Bob should fetch (or have).
    pub manifest_version: u64,
    /// Alice's device.
    pub device: DeviceId,
    /// Where to fetch Alice's manifest (server id ‖ locator), opaque here.
    pub locator: Vec<u8>,
    /// Transcript signature in On-the-record mode.
    pub signature: Option<Vec<u8>>,
}

impl InitiatorIdentity {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.locator.len() > MAX_LOCATOR {
            return Err(ProtoError::Limit);
        }
        let mut w = Writer::new();
        w.fixed(&self.root)
            .u64(self.manifest_version)
            .fixed(&self.device)
            .bytes(&self.locator);
        match &self.signature {
            Some(s) => w.u8(1).fixed(s),
            None => w.u8(0),
        };
        let mut v = w.finish();
        v.resize(IDENTITY_PT_LEN, 0);
        Ok(v)
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let root = r.array()?;
        let manifest_version = r.u64()?;
        let device = r.array()?;
        let locator = r.bytes(MAX_LOCATOR)?.to_vec();
        let signature = match r.u8()? {
            0 => None,
            1 => Some(r.fixed(COMPOSITE_SIG_LEN)?.to_vec()),
            _ => return Err(ProtoError::Decode),
        };
        if r.fixed(r.remaining())?.iter().any(|b| *b != 0) {
            return Err(ProtoError::Decode);
        }
        Ok(Self {
            root,
            manifest_version,
            device,
            locator,
            signature,
        })
    }
}

/// Everything about the peer device Alice needs.
pub struct Peer<'a> {
    /// Bob's verified manifest.
    pub manifest: &'a Manifest,
    /// The Bob device being addressed.
    pub device: &'a DeviceEntry,
    /// Bob's verified bundle for that device.
    pub bundle: &'a Bundle,
    /// Bob's McEliece vault key if already fetched (checked against the manifest hash).
    pub vault: Option<&'a McEliecePublic>,
}

/// Our own side of a handshake.
pub struct Local<'a> {
    /// Account keys.
    pub account: &'a AccountKeys,
    /// This device's keys.
    pub device: &'a DeviceKeys,
    /// Our current manifest.
    pub manifest: &'a Manifest,
    /// Where contacts fetch our manifest.
    pub locator: &'a [u8],
}

struct Transcript<'a> {
    suite: Suite,
    mode: Mode,
    root_a: &'a [u8; 64],
    root_b: &'a [u8; 64],
    device_a: &'a DeviceId,
    device_b: &'a DeviceId,
    ik_a: &'a X448Public,
    ik_b: &'a X448Public,
    spk_b: &'a X448Public,
    pq_prekey: &'a [u8],
    opk_b: Option<&'a X448Public>,
    ek_a: &'a X448Public,
    ct_pq: &'a [u8],
    vault_hash_b: &'a [u8; 64],
    ct_mce: Option<&'a [u8]>,
    auth_b: &'a [u8],
    ct_auth: &'a [u8],
    auth_a: &'a [u8],
    manifest_version_a: u64,
    manifest_version_b: u64,
}

impl Transcript<'_> {
    fn items(&self) -> Vec<Vec<u8>> {
        vec![
            b"EQXDH-v1".to_vec(),
            vec![self.suite.id(), self.mode as u8],
            self.root_a.to_vec(),
            self.root_b.to_vec(),
            self.device_a.to_vec(),
            self.device_b.to_vec(),
            self.ik_a.0.to_vec(),
            self.ik_b.0.to_vec(),
            self.spk_b.0.to_vec(),
            self.pq_prekey.to_vec(),
            self.opk_b.map(|k| k.0.to_vec()).unwrap_or_default(),
            self.ek_a.0.to_vec(),
            self.ct_pq.to_vec(),
            self.vault_hash_b.to_vec(),
            self.ct_mce.map(<[u8]>::to_vec).unwrap_or_default(),
            self.auth_b.to_vec(),
            self.ct_auth.to_vec(),
            self.auth_a.to_vec(),
            self.manifest_version_a.to_be_bytes().to_vec(),
            self.manifest_version_b.to_be_bytes().to_vec(),
        ]
    }

    fn hash(&self) -> [u8; 64] {
        let items = self.items();
        let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
        enclave_crypto::hash::sha3_512_parts(&refs)
    }
}

fn stage1_key(
    suite: Suite,
    secrets: &[&[u8]],
    ek_a: &X448Public,
    spk_b: &X448Public,
    opk_b: Option<&X448Public>,
    ct_pq: &[u8],
    ct_mce: Option<&[u8]>,
    root_b: &[u8; 64],
    device_b: &DeviceId,
    psk: Option<&[u8; 32]>,
) -> SealKey {
    let opk = opk_b.map(|k| k.0.to_vec()).unwrap_or_default();
    let mce = ct_mce.map(<[u8]>::to_vec).unwrap_or_default();
    let public: [&[u8]; 8] = [
        b"EQXDH-v1/stage1",
        &ek_a.0,
        &spk_b.0,
        &opk,
        ct_pq,
        &mce,
        root_b,
        device_b,
    ];
    let s1 = kem::combine(suite, secrets, &public, psk);
    seal::derive_key(&s1[..], b"", labels::EQXDH_IDENTITY)
}

/// Result of initiating.
pub struct Initiated {
    /// Public first-message block to put in the request envelope.
    pub message: InitialMessage,
    /// The new session (can send immediately).
    pub session: Session,
}

/// Alice: start a session with one of Bob's devices.
pub fn initiate(
    local: &Local<'_>,
    peer: &Peer<'_>,
    mode: Mode,
    psk: Option<&[u8; 32]>,
    rng: &mut HedgedRng,
) -> Result<Initiated> {
    let bundle = peer.bundle;
    // The vault key, if present, must match the manifest commitment.
    let vault = match peer.vault {
        Some(v) if sha3_512(&v.0[..]) == peer.manifest.vault_hash => Some(v),
        Some(_) => return Err(ProtoError::BadSignature),
        None => None,
    };
    let suite = if vault.is_some() {
        Suite::ThreeKem
    } else {
        Suite::TwoKem
    };

    let (ek_sk, ek_a) = X448Secret::generate(rng)?;
    let spk_b = bundle.spk.x448;
    let dh1 = local.account.identity.diffie_hellman(&spk_b)?;
    let dh2 = ek_sk.diffie_hellman(&peer.manifest.identity)?;
    let dh3 = ek_sk.diffie_hellman(&spk_b)?;
    // Without a one-time prekey (the directory ran out, or someone drained
    // it) the ML-KEM half goes to the last-resort prekey: it rotates every
    // 7 days, the signed prekey every 14, so the first message's forward
    // secrecy rests on the shorter-lived key (RT-06).
    let (dh4, opk_b, pq_key, pq_ref) = match &bundle.opk {
        Some((_, o)) => (
            Some(ek_sk.diffie_hellman(&o.x448)?),
            Some(o.x448),
            o.pq.to_key()?,
            PqPrekeyRef::OneTime(o.id()),
        ),
        None => (
            None,
            None,
            bundle.last_resort.pq.to_key()?,
            PqPrekeyRef::LastResort(bundle.last_resort.id),
        ),
    };
    let (ct_pq, ss_pq) = pq_key.encapsulate(rng)?;
    let (ct_mce, ss_mce) = match vault {
        Some(v) => {
            let (c, s) = v.encapsulate(rng)?;
            (Some(c), Some(s))
        }
        None => (None, None),
    };
    let auth_b = peer.device.auth.to_key()?;
    let (ct_auth, ss_auth) = auth_b.encapsulate(rng)?;

    let dh4_bytes: Vec<u8> = dh4.as_ref().map(|d| d.to_vec()).unwrap_or_default();
    let mce_bytes: Vec<u8> = ss_mce.as_ref().map(|s| s.to_vec()).unwrap_or_default();
    let k_id = stage1_key(
        suite,
        &[&dh3[..], &dh4_bytes, &ss_pq[..], &mce_bytes],
        &ek_a,
        &spk_b,
        opk_b.as_ref(),
        &ct_pq.0[..],
        ct_mce.as_ref().map(|c| &c.0[..]),
        &peer.manifest.root.0,
        &peer.device.id,
        psk,
    );

    let t = Transcript {
        suite,
        mode,
        root_a: &local.account.root_public.0,
        root_b: &peer.manifest.root.0,
        device_a: &local.device.id,
        device_b: &peer.device.id,
        ik_a: &local.account.identity_public,
        ik_b: &peer.manifest.identity,
        spk_b: &spk_b,
        pq_prekey: &pq_key.0[..],
        opk_b: opk_b.as_ref(),
        ek_a: &ek_a,
        ct_pq: &ct_pq.0[..],
        vault_hash_b: &peer.manifest.vault_hash,
        ct_mce: ct_mce.as_ref().map(|c| &c.0[..]),
        auth_b: &auth_b.0[..],
        ct_auth: &ct_auth.0[..],
        auth_a: &local.device.auth_public.0[..],
        manifest_version_a: local.manifest.version,
        manifest_version_b: peer.manifest.version,
    };
    let items = t.items();
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    let sk = kem::combine(
        suite,
        &[
            &dh1[..],
            &dh2[..],
            &dh3[..],
            &dh4_bytes,
            &ss_pq[..],
            &mce_bytes,
            &ss_auth[..],
        ],
        &refs,
        psk,
    );

    let signature = match mode {
        Mode::OnTheRecord => Some(local.device.signing.sign(
            labels::CTX_EQXDH_TRANSCRIPT.as_bytes(),
            &t.hash(),
            rng,
        )?),
        Mode::OffTheRecord => None,
    };
    let identity = InitiatorIdentity {
        root: local.account.root_public.0,
        manifest_version: local.manifest.version,
        device: local.device.id,
        locator: local.locator.to_vec(),
        signature,
    };
    let sealed_identity = seal::seal_compact(
        &k_id,
        &ek_a.0,
        &[suite.id(), mode as u8],
        &identity.encode()?,
    )?;

    let auth_sk = MlKemSecret::from_slice(local.device.auth.as_bytes())?;
    let session = Session::new(
        SessionInit {
            sk,
            role: Role::Initiator,
            initial_dh: InitialDh::Initiator(spk_b),
            my_pq: (0, auth_sk, local.device.auth_public.clone()),
            peer_pq: None,
            three_kem: suite == Suite::ThreeKem,
            braid_to: None,
        },
        rng,
    )?;
    let message = InitialMessage {
        suite,
        mode,
        psk: psk.is_some(),
        spk_id: bundle.spk.id,
        pq_prekey: pq_ref,
        ek: ek_a,
        ct_pq,
        ct_mce,
        ct_auth,
        sealed_identity,
    };
    Ok(Initiated { message, session })
}

/// Looks up and verifies the initiator's manifest (from cache or directory).
pub trait ManifestResolver {
    /// Return Alice's verified manifest for `identity`, or an error.
    fn resolve(&mut self, identity: &InitiatorIdentity) -> Result<Manifest>;
}

/// Result of responding.
pub struct Responded {
    /// Who the initiator is.
    pub identity: InitiatorIdentity,
    /// The initiator's manifest.
    pub manifest: Manifest,
    /// Mode of the conversation.
    pub mode: Mode,
    /// The new session. It can receive now and send after the first message is
    /// processed.
    pub session: Session,
}

/// Bob: process an initial message addressed to this device.
pub fn respond(
    local: &Local<'_>,
    prekeys: &mut PrekeyStore,
    msg: &InitialMessage,
    psk: Option<&[u8; 32]>,
    resolver: &mut dyn ManifestResolver,
    rng: &mut HedgedRng,
) -> Result<Responded> {
    if msg.psk != psk.is_some() {
        return Err(ProtoError::Crypto);
    }
    let (spk_secret, _) = prekeys.signed.get(&msg.spk_id).ok_or(ProtoError::Missing)?;
    let spk_x = spk_secret.x448.as_ref().ok_or(ProtoError::Missing)?;
    let spk_b = spk_x.public();

    // PQ prekey and optional OPK. The OPK is only removed once the whole
    // handshake succeeds, so a forged message cannot burn it.
    let (pq_ss, opk_b, dh4, pq_pub, used_opk) = match msg.pq_prekey {
        PqPrekeyRef::OneTime(id) => {
            let s = prekeys.one_time.get(&id).ok_or(ProtoError::Missing)?;
            let x = s.x448.as_ref().ok_or(ProtoError::Missing)?;
            let opk_pub = x.public();
            let dh4 = x.diffie_hellman(&msg.ek)?;
            (
                s.pq.decapsulate(&msg.ct_pq),
                Some(opk_pub),
                Some(dh4),
                mlkem_public_of(&s.pq)?,
                Some(id),
            )
        }
        PqPrekeyRef::Signed => (
            spk_secret.pq.decapsulate(&msg.ct_pq),
            None,
            None,
            mlkem_public_of(&spk_secret.pq)?,
            None,
        ),
        PqPrekeyRef::LastResort(id) => {
            let (s, _) = prekeys.last_resort.get(&id).ok_or(ProtoError::Missing)?;
            (
                s.pq.decapsulate(&msg.ct_pq),
                None,
                None,
                mlkem_public_of(&s.pq)?,
                None,
            )
        }
    };
    let dh3 = spk_x.diffie_hellman(&msg.ek)?;
    let ss_mce = match &msg.ct_mce {
        Some(c) => Some(local.account.vault.decapsulate(c)?),
        None => None,
    };
    let dh4_bytes: Vec<u8> = dh4.as_ref().map(|d| d.to_vec()).unwrap_or_default();
    let mce_bytes: Vec<u8> = ss_mce.as_ref().map(|s| s.to_vec()).unwrap_or_default();
    let k_id = stage1_key(
        msg.suite,
        &[&dh3[..], &dh4_bytes, &pq_ss[..], &mce_bytes],
        &msg.ek,
        &spk_b,
        opk_b.as_ref(),
        &msg.ct_pq.0[..],
        msg.ct_mce.as_ref().map(|c| &c.0[..]),
        &local.account.root_public.0,
        &local.device.id,
        psk,
    );
    let id_pt = seal::open_compact(
        &k_id,
        &msg.ek.0,
        &[msg.suite.id(), msg.mode as u8],
        &msg.sealed_identity,
    )?;
    let identity = InitiatorIdentity::decode(&id_pt)?;
    let alice = resolver.resolve(&identity)?;
    if alice.root.0 != identity.root || alice.version != identity.manifest_version {
        return Err(ProtoError::BadSignature);
    }
    let alice_dev = alice
        .device(&identity.device)
        .ok_or(ProtoError::BadSignature)?;

    let dh1 = spk_x.diffie_hellman(&alice.identity)?;
    let dh2 = local.account.identity.diffie_hellman(&msg.ek)?;
    let ss_auth = local.device.auth.decapsulate(&msg.ct_auth);

    let t = Transcript {
        suite: msg.suite,
        mode: msg.mode,
        root_a: &identity.root,
        root_b: &local.account.root_public.0,
        device_a: &identity.device,
        device_b: &local.device.id,
        ik_a: &alice.identity,
        ik_b: &local.account.identity_public,
        spk_b: &spk_b,
        pq_prekey: &pq_pub,
        opk_b: opk_b.as_ref(),
        ek_a: &msg.ek,
        ct_pq: &msg.ct_pq.0[..],
        vault_hash_b: &local.manifest.vault_hash,
        ct_mce: msg.ct_mce.as_ref().map(|c| &c.0[..]),
        auth_b: &local.device.auth_public.0[..],
        ct_auth: &msg.ct_auth.0[..],
        auth_a: &alice_dev.auth.0[..],
        manifest_version_a: alice.version,
        manifest_version_b: local.manifest.version,
    };
    if msg.mode == Mode::OnTheRecord {
        let sig = identity
            .signature
            .as_ref()
            .ok_or(ProtoError::BadSignature)?;
        verify_transcript_sig(&alice_dev.signing, &t.hash(), sig)?;
    }
    let items = t.items();
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    let sk = kem::combine(
        msg.suite,
        &[
            &dh1[..],
            &dh2[..],
            &dh3[..],
            &dh4_bytes,
            &pq_ss[..],
            &mce_bytes,
            &ss_auth[..],
        ],
        &refs,
        psk,
    );
    let (my_sk, my_pk) = MlKemSecret::generate(rng)?;
    let session = Session::new(
        SessionInit {
            sk,
            role: Role::Responder,
            initial_dh: InitialDh::Responder(spk_x.clone()),
            my_pq: (1, my_sk, my_pk),
            peer_pq: Some((0, alice_dev.auth.to_key()?)),
            three_kem: msg.suite == Suite::ThreeKem,
            braid_to: None,
        },
        rng,
    )?;
    if let Some(id) = used_opk {
        prekeys.one_time.remove(&id);
    }
    Ok(Responded {
        identity,
        manifest: alice.clone(),
        mode: msg.mode,
        session,
    })
}

fn verify_transcript_sig(signer: &CompositePublic, th: &[u8; 64], sig: &[u8]) -> Result<()> {
    signer
        .verify(labels::CTX_EQXDH_TRANSCRIPT.as_bytes(), th, sig)
        .map_err(|_| ProtoError::BadSignature)
}

/// ML-KEM public key of a stored secret (the encapsulation key is embedded in
/// the FIPS 203 decapsulation key at offset 1536).
fn mlkem_public_of(sk: &MlKemSecret) -> Result<Vec<u8>> {
    let b = sk.as_bytes();
    b.get(1536..1536 + 1568)
        .map(<[u8]>::to_vec)
        .ok_or(ProtoError::Decode)
}

/// Derive the in-person PSK from both QR secrets (`docs/03-identity.md` §3.6).
pub fn bond_psk(s_a: &[u8; 32], s_b: &[u8; 32], qr_a: &[u8], qr_b: &[u8]) -> Zeroizing<[u8; 32]> {
    // Order by QR content so both sides compute the same value.
    let (first, second, qa, qb) = if qr_a <= qr_b {
        (s_a, s_b, qr_a, qr_b)
    } else {
        (s_b, s_a, qr_b, qr_a)
    };
    let key = [&first[..], &second[..]].concat();
    let th = enclave_crypto::hash::sha3_512_parts(&[qa, qb]);
    Zeroizing::new(enclave_crypto::kmac::kmac256(&key, &th, labels::BOND))
}

/// The one-way PSK an invite link's secret gives (`docs/03-identity.md`
/// §7.3). Weaker than a bond: the link may have been copied on its way.
pub fn invite_psk(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(enclave_crypto::kmac::kmac256(
        secret,
        b"psk",
        labels::INVITE_PSK,
    ))
}

/// The `i`-th request-inbox capability of an invite link (§9.2): the
/// server holds only its capability hash (`api::cap_hash`) and burns it on
/// use.
pub fn invite_cap(secret: &[u8; 32], i: u32) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(secret, &i.to_be_bytes(), labels::INVITE_CAP)
}

/// Three "Seal" words both phones show after an in-person scan, from the BIP-39
/// list, so people can confirm they scanned each other and not a bystander.
pub fn seal_words(psk: &[u8; 32]) -> Result<[String; 3]> {
    let d: [u8; 32] = enclave_crypto::kmac::kmac256(psk, b"", labels::BOND_SEAL_WORDS);
    let words = bip39::Language::English.word_list();
    let pick = |i: usize| -> String {
        let v = u16::from_be_bytes([d[2 * i], d[2 * i + 1]]) as usize % 2048;
        words[v].to_string()
    };
    Ok([pick(0), pick(1), pick(2)])
}
