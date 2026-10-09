//! The Lockstep ratchet (`docs/05-ratchet.md`).
//!
//! Two ratchets run side by side and every message key depends on both:
//!
//! 1. A **Double Ratchet over X448 with header encryption** (the DR-HE variant).
//!    It gives per-message forward secrecy and classical post-compromise
//!    security.
//! 2. A **post-quantum ratchet over ML-KEM-1024**. Each side keeps one current
//!    encapsulation key (`ek`) and repeats it until the peer answers with a
//!    ciphertext. Each answered `ek` is one PQ *step* that updates the root for
//!    that direction. Epochs are explicit, so steps apply in the same order on
//!    both sides even when messages cross, arrive out of order, or are lost.
//!
//! `mk = KMAC256(mk_DR, pq_key(e_out, e_in), "enclave/v1/ratchet/msg")`
//!
//! The PQ material travels in a *PQ slot* (one per envelope, rotated between the
//! device pairs that are due), so it never has to be split into chunks.
//!
//! Receivers never trial-decrypt: every header carries a 16-byte lookup tag
//! `KMAC256(HK, n)`, and each session keeps an index of the tags it expects.
//!
//! All updates happen on a copy of the session state that is committed only after
//! the message body authenticates, so a forged or corrupted message never
//! changes state.

use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::labels;
use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::{
    MCELIECE_CT_LEN, MLKEM_CT_LEN, MLKEM_PK_LEN, McElieceCiphertext, McEliecePublic,
    McElieceSecret, MlKemCiphertext, MlKemPublic, MlKemSecret, X448Public, X448Secret,
};
use enclave_crypto::kmac::Kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use std::collections::{BTreeMap, HashMap, VecDeque};
use zeroize::Zeroizing;

/// Skipped message keys are deleted after this long (seconds).
pub const SKIPPED_MAX_AGE: u64 = 7 * 86_400;
/// Maximum message keys skipped in one chain.
pub const MAX_SKIP: u32 = 1000;
/// Look-ahead window for lookup tags in the current and next receiving chains.
pub const TAG_WINDOW: u32 = 64;
/// PQ epochs of history kept for late messages.
pub const PQ_HISTORY: usize = 16;
/// Lookup tag length.
pub const TAG_LEN: usize = 16;
/// Plaintext length of a sealed header record inside a device slot.
pub const HEADER_PT_LEN: usize = 112;
/// Sealed PQ slot length (fixed).
pub const PQ_SLOT_LEN: usize = enclave_wire::PQ_SLOT_LEN;
const PQ_SLOT_PT_LEN: usize = PQ_SLOT_LEN - seal::TAG_LEN;

type Key = [u8; 32];

fn kmac32(key: &[u8], data: &[&[u8]], label: &str) -> Key {
    let mut out = [0u8; 32];
    let mut k = Kmac256::new(key, label.as_bytes());
    for d in data {
        k.update_framed(d);
    }
    k.finalize_into(&mut out);
    out
}

/// `KDF_RK_HE(rk, dh) -> (rk', ck, nhk)`.
fn kdf_rk(rk: &Key, dh: &[u8]) -> (Key, Key, Key) {
    let mut out = Zeroizing::new([0u8; 96]);
    let mut k = Kmac256::new(rk, labels::RATCHET_RK.as_bytes());
    k.update_framed(dh);
    k.finalize_into(&mut out[..]);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..64]);
    c.copy_from_slice(&out[64..]);
    (a, b, c)
}

/// `KDF_CK(ck) -> (ck', mk)`.
fn kdf_ck(ck: &Key) -> (Key, Key) {
    let mut out = Zeroizing::new([0u8; 64]);
    Kmac256::new(ck, labels::RATCHET_CK.as_bytes()).finalize_into(&mut out[..]);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

/// Lookup tag for message `n` under header key `hk`.
pub fn lookup_tag(hk: &Key, n: u32) -> [u8; TAG_LEN] {
    let mut out = [0u8; TAG_LEN];
    let mut k = Kmac256::new(hk, labels::RATCHET_TAG.as_bytes());
    k.update(&n.to_be_bytes());
    k.finalize_into(&mut out);
    out
}

/// Session role in EQXDH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sent the first message.
    Initiator,
    /// Received the first message.
    Responder,
}

// ---------------------------------------------------------------------------
// PQ ratchet
// ---------------------------------------------------------------------------

/// Our current PQ encapsulation key.
struct MyPqKey {
    id: u32,
    sk: MlKemSecret,
    pk: MlKemPublic,
}

impl Clone for MyPqKey {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            sk: MlKemSecret::from_slice(self.sk.as_bytes())
                .unwrap_or_else(|_| unreachable!("valid length")),
            pk: self.pk.clone(),
        }
    }
}

#[derive(Clone)]
struct Outstanding {
    for_id: u32,
    ct: MlKemCiphertext,
    e_out: u32,
    mce_ct: Option<McElieceCiphertext>,
}

#[derive(Clone)]
struct PqState {
    out_root: Key,
    in_root: Key,
    e_out: u32,
    e_in: u32,
    out_hist: VecDeque<(u32, Key)>,
    in_hist: VecDeque<(u32, Key)>,
    my: MyPqKey,
    peer: Option<(u32, MlKemPublic)>,
    highest_peer_id: u32,
    outstanding: Option<Outstanding>,
    /// McEliece vault key of the peer, set when we still owe the braid step.
    braid_to: Option<Box<McEliecePublic>>,
}

impl PqState {
    fn root_at(hist: &VecDeque<(u32, Key)>, e: u32) -> Option<Key> {
        hist.iter().find(|(x, _)| *x == e).map(|(_, k)| *k)
    }

    fn push(hist: &mut VecDeque<(u32, Key)>, e: u32, k: Key) {
        hist.push_back((e, k));
        while hist.len() > PQ_HISTORY {
            hist.pop_front();
        }
    }

    /// Key for a message sent with sender epochs (`s_out`, `s_in`), computed by
    /// the receiver: sender's out root is our in root and vice versa.
    fn key_as_receiver(&self, s_out: u32, s_in: u32) -> Result<Key> {
        let their_out = Self::root_at(&self.in_hist, s_out).ok_or(ProtoError::Counter)?;
        let their_in = Self::root_at(&self.out_hist, s_in).ok_or(ProtoError::Counter)?;
        Ok(kmac32(&their_out, &[&their_in], labels::PQ_KEY))
    }

    fn key_as_sender(&self, e_out: u32, e_in: u32) -> Result<Key> {
        let out = Self::root_at(&self.out_hist, e_out).ok_or(ProtoError::Counter)?;
        let inn = Self::root_at(&self.in_hist, e_in).ok_or(ProtoError::Counter)?;
        Ok(kmac32(&out, &[&inn], labels::PQ_KEY))
    }

    fn step(root: &Key, ss: &[u8], ct: &[u8], ek_hash: &[u8], mce: Option<(&[u8], &[u8])>) -> Key {
        match mce {
            None => kmac32(root, &[ss, ct, ek_hash], labels::PQ_STEP),
            Some((mss, mct)) => kmac32(root, &[ss, ct, ek_hash, mss, mct], labels::PQ_STEP),
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Skipped {
    hk: Key,
    n: u32,
    mk: Key,
    /// Insertion order, for oldest-first eviction.
    seq: u64,
    /// When first seen by [`Session::expire_skipped`] (0 = not yet stamped).
    at: u64,
}

/// What a lookup tag points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagHit {
    Current(u32),
    Next(u32),
    Skipped,
}

/// A pairwise ratchet session between two devices.
#[derive(Clone)]
pub struct Session {
    role: Role,
    rk: Key,
    dhs: X448Secret,
    dhs_pub: X448Public,
    dhr: Option<X448Public>,
    cks: Option<Key>,
    ckr: Option<Key>,
    ns: u32,
    nr: u32,
    pn: u32,
    hks: Option<Key>,
    hkr: Option<Key>,
    nhks: Key,
    nhkr: Key,
    skipped: BTreeMap<[u8; TAG_LEN], Skipped>,
    pq: PqState,
    /// True once a message protected by a PQ step that authenticates the peer
    /// (our auth-key step) has been decrypted.
    pq_authenticated: bool,
    /// Suite in use (2-KEM until the McEliece braid completes, then 3-KEM).
    three_kem: bool,
    tag_cache: Option<HashMap<[u8; TAG_LEN], TagHit>>,
}

/// Material the handshake passes to [`Session::new`].
pub struct SessionInit {
    /// 64-byte handshake output (EnclaveCombine).
    pub sk: Zeroizing<[u8; 64]>,
    /// Our role.
    pub role: Role,
    /// Responder: the X448 signed-prekey pair used as the first ratchet key.
    /// Initiator: the responder's signed-prekey public key.
    pub initial_dh: InitialDh,
    /// Our current PQ key: the device auth key (initiator) or a fresh key (responder).
    pub my_pq: (u32, MlKemSecret, MlKemPublic),
    /// The peer's PQ key we still have to answer (responder: initiator's auth key).
    pub peer_pq: Option<(u32, MlKemPublic)>,
    /// Whether the handshake already used all three KEM families.
    pub three_kem: bool,
    /// Initiator only: McEliece key to braid in later if the handshake was 2-KEM.
    pub braid_to: Option<Box<McEliecePublic>>,
}

/// First ratchet key material.
pub enum InitialDh {
    /// Initiator: the responder's signed-prekey X448 public key.
    Initiator(X448Public),
    /// Responder: our signed-prekey X448 pair.
    Responder(X448Secret),
}

/// Decrypted header of one device slot.
#[derive(Clone, Copy, Debug)]
struct Header {
    dh: X448Public,
    pn: u32,
    n: u32,
    e_out: u32,
    e_in: u32,
    flags: u8,
    wrapped: Key,
}

const FLAG_PQ_SLOT: u8 = 0x01;

impl Header {
    fn encode(&self) -> [u8; HEADER_PT_LEN] {
        let mut out = [0u8; HEADER_PT_LEN];
        let mut w = Writer::new();
        w.fixed(&self.dh.0)
            .u32(self.pn)
            .u32(self.n)
            .u32(self.e_out)
            .u32(self.e_in)
            .u8(self.flags)
            .fixed(&self.wrapped);
        let b = w.finish();
        out[..b.len()].copy_from_slice(&b);
        out
    }
    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != HEADER_PT_LEN {
            return Err(ProtoError::Decode);
        }
        let mut r = Reader::new(b);
        let h = Header {
            dh: X448Public(r.array()?),
            pn: r.u32()?,
            n: r.u32()?,
            e_out: r.u32()?,
            e_in: r.u32()?,
            flags: r.u8()?,
            wrapped: r.array()?,
        };
        if r.fixed(r.remaining())?.iter().any(|b| *b != 0) {
            return Err(ProtoError::Decode);
        }
        Ok(h)
    }
}

/// Output of sealing one message for one session.
pub struct SealedSlot {
    /// Lookup tag (first 16 bytes of the device slot).
    pub tag: [u8; TAG_LEN],
    /// Sealed header record (144 bytes).
    pub header: Vec<u8>,
    /// Sealed PQ slot, if this session carried it.
    pub pq_slot: Option<Vec<u8>>,
}

/// Result of opening a slot, before the caller has authenticated the body.
pub struct Opened {
    /// The body key recovered from the wrap.
    pub body_key: Key,
    /// Session state to commit if the body authenticates.
    pub next: Box<Session>,
    /// When the message's key was first seen skipped (it arrived after
    /// later ones; 0 if not stamped yet), or `None` if it came in order.
    pub skipped_at: Option<u64>,
}

impl Session {
    /// Build a session from handshake output.
    pub fn new(init: SessionInit, rng: &mut HedgedRng) -> Result<Self> {
        let rk0 = kmac32(&init.sk[..], &[], labels::RATCHET_INIT_RK);
        let hka = kmac32(&init.sk[..], &[b"a"], labels::RATCHET_INIT_HK);
        let nhkb = kmac32(&init.sk[..], &[b"b"], labels::RATCHET_INIT_HK);
        let pq_a2b = kmac32(&init.sk[..], &[b"a2b"], labels::RATCHET_INIT_PQ);
        let pq_b2a = kmac32(&init.sk[..], &[b"b2a"], labels::RATCHET_INIT_PQ);
        let (out_root, in_root) = match init.role {
            Role::Initiator => (pq_a2b, pq_b2a),
            Role::Responder => (pq_b2a, pq_a2b),
        };
        let mut out_hist = VecDeque::new();
        let mut in_hist = VecDeque::new();
        out_hist.push_back((0, out_root));
        in_hist.push_back((0, in_root));
        let (my_id, my_sk, my_pk) = init.my_pq;
        let pq = PqState {
            out_root,
            in_root,
            e_out: 0,
            e_in: 0,
            out_hist,
            in_hist,
            my: MyPqKey {
                id: my_id,
                sk: my_sk,
                pk: my_pk,
            },
            highest_peer_id: init.peer_pq.as_ref().map_or(0, |(i, _)| *i),
            peer: init.peer_pq,
            outstanding: None,
            braid_to: init.braid_to,
        };
        match init.initial_dh {
            InitialDh::Initiator(bob_spk) => {
                let (dhs, dhs_pub) = X448Secret::generate(rng)?;
                let dh = dhs.diffie_hellman(&bob_spk)?;
                let (rk, cks, nhks) = kdf_rk(&rk0, &dh[..]);
                Ok(Self {
                    role: Role::Initiator,
                    rk,
                    dhs,
                    dhs_pub,
                    dhr: Some(bob_spk),
                    cks: Some(cks),
                    ckr: None,
                    ns: 0,
                    nr: 0,
                    pn: 0,
                    hks: Some(hka),
                    hkr: None,
                    nhks,
                    nhkr: nhkb,
                    skipped: BTreeMap::new(),
                    pq,
                    pq_authenticated: false,
                    three_kem: init.three_kem,
                    tag_cache: None,
                })
            }
            InitialDh::Responder(spk) => {
                let dhs_pub = spk.public();
                Ok(Self {
                    role: Role::Responder,
                    rk: rk0,
                    dhs: spk,
                    dhs_pub,
                    dhr: None,
                    cks: None,
                    ckr: None,
                    ns: 0,
                    nr: 0,
                    pn: 0,
                    hks: None,
                    hkr: None,
                    nhks: nhkb,
                    nhkr: hka,
                    skipped: BTreeMap::new(),
                    pq,
                    pq_authenticated: false,
                    three_kem: init.three_kem,
                    tag_cache: None,
                })
            }
        }
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Whether the peer is post-quantum authenticated yet.
    pub fn pq_authenticated(&self) -> bool {
        self.pq_authenticated
    }

    /// Whether all three KEM families protect the session.
    pub fn three_kem(&self) -> bool {
        self.three_kem
    }

    /// Schedule the McEliece braid: the next PQ step this side makes also
    /// encapsulates to the peer's vault key. Only for 2-KEM sessions.
    pub fn schedule_braid(&mut self, vault: McEliecePublic) {
        if !self.three_kem && self.role == Role::Initiator {
            self.pq.braid_to = Some(Box::new(vault));
        }
    }

    /// Current PQ epochs `(out, in)`.
    pub fn pq_epochs(&self) -> (u32, u32) {
        (self.pq.e_out, self.pq.e_in)
    }

    /// Whether this session has PQ material to send (an unanswered peer key, an
    /// unacknowledged ciphertext, a pending braid, or a new key to announce).
    pub fn wants_pq_slot(&self) -> bool {
        // Key id 0 is the initiator's device auth key, which the responder
        // already holds from the manifest, so it never needs announcing.
        self.pq.peer.is_some()
            || self.pq.outstanding.is_some()
            || self.pq.braid_to.is_some()
            || self.pq.my.id > 0
    }

    /// Whether the session can send (the responder must receive first).
    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    fn invalidate(&mut self) {
        self.tag_cache = None;
    }

    fn tag_index(&mut self) -> &HashMap<[u8; TAG_LEN], TagHit> {
        if self.tag_cache.is_none() {
            let mut m = HashMap::new();
            if let Some(hkr) = &self.hkr {
                for n in self.nr..self.nr.saturating_add(TAG_WINDOW) {
                    m.insert(lookup_tag(hkr, n), TagHit::Current(n));
                }
            }
            for n in 0..TAG_WINDOW {
                m.insert(lookup_tag(&self.nhkr, n), TagHit::Next(n));
            }
            for t in self.skipped.keys() {
                m.insert(*t, TagHit::Skipped);
            }
            self.tag_cache = Some(m);
        }
        self.tag_cache.get_or_insert_with(HashMap::new)
    }

    /// Whether `tag` belongs to this session.
    pub fn matches(&mut self, tag: &[u8; TAG_LEN]) -> bool {
        self.tag_index().contains_key(tag)
    }

    // ----- sending ---------------------------------------------------------

    /// Seal the per-session parts of one message.
    ///
    /// * `body_key`: the random key the shared body is sealed under.
    /// * `body_hash`: SHA3-512 of the sealed body (binds the slot to it).
    /// * `ad`: envelope header bytes.
    /// * `carry_pq`: whether this session gets the envelope's PQ slot.
    pub fn seal(
        &mut self,
        body_key: &Key,
        body_hash: &[u8; 64],
        ad: &[u8],
        carry_pq: bool,
        rng: &mut HedgedRng,
    ) -> Result<SealedSlot> {
        let cks = self.cks.ok_or(ProtoError::NoSession)?;
        let hks = self.hks.ok_or(ProtoError::NoSession)?;
        let (ck2, mk_dr) = kdf_ck(&cks);
        let n = self.ns;
        let tag = lookup_tag(&hks, n);
        let nonce_material = [&tag[..], &body_hash[..]].concat();

        // PQ slot first: it may advance our out epoch.
        let mut flags = 0u8;
        let pq_slot = if carry_pq {
            flags |= FLAG_PQ_SLOT;
            Some(self.build_pq_slot(&mk_dr, &nonce_material, ad, rng)?)
        } else {
            None
        };
        // Epochs the receiver can compute: an unacknowledged step is only used
        // in messages that carry its ciphertext.
        let e_out = match (&self.pq.outstanding, carry_pq) {
            (Some(o), false) => o.e_out - 1,
            _ => self.pq.e_out,
        };
        let e_in = self.pq.e_in;
        let pq_key = self.pq.key_as_sender(e_out, e_in)?;
        let mk = kmac32(&mk_dr, &[&pq_key], labels::RATCHET_MSG);
        let wrap_ks = kmac32(&mk, &[body_hash], labels::RATCHET_WRAP);
        let mut wrapped = [0u8; 32];
        for i in 0..32 {
            wrapped[i] = body_key[i] ^ wrap_ks[i];
        }
        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n,
            e_out,
            e_in,
            flags,
            wrapped,
        };
        let sealed = seal::seal_compact(
            &SealKey::from_bytes(hks),
            &nonce_material,
            ad,
            &header.encode(),
        )?;
        self.cks = Some(ck2);
        self.ns = n.checked_add(1).ok_or(ProtoError::Counter)?;
        Ok(SealedSlot {
            tag,
            header: sealed,
            pq_slot,
        })
    }

    fn build_pq_slot(
        &mut self,
        mk_dr: &Key,
        nonce_material: &[u8],
        ad: &[u8],
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        // Answer the peer's key if nothing is outstanding.
        if self.pq.outstanding.is_none()
            && let Some((pid, pek)) = self.pq.peer.take()
        {
            {
                let (ct, ss) = pek.encapsulate(rng)?;
                let ek_hash = sha3_512(&pek.0[..]);
                let mce = match self.pq.braid_to.take() {
                    Some(vault) => Some(vault.encapsulate(rng)?),
                    None => None,
                };
                let new_root = PqState::step(
                    &self.pq.out_root,
                    &ss[..],
                    &ct.0[..],
                    &ek_hash,
                    mce.as_ref().map(|(c, s)| (&s[..], &c.0[..])),
                );
                self.pq.e_out += 1;
                self.pq.out_root = new_root;
                PqState::push(&mut self.pq.out_hist, self.pq.e_out, new_root);
                self.pq.outstanding = Some(Outstanding {
                    for_id: pid,
                    ct,
                    e_out: self.pq.e_out,
                    mce_ct: mce.map(|(c, _)| c),
                });
            }
        }
        let mut w = Writer::new();
        match &self.pq.outstanding {
            Some(o) if o.mce_ct.is_some() => {
                // Kind 1: braid (no new ek this time; it goes in the next slot).
                w.u8(1)
                    .u32(self.pq.my.id)
                    .u32(o.for_id)
                    .fixed(&o.ct.0[..])
                    .u32(o.e_out);
                if let Some(m) = &o.mce_ct {
                    w.fixed(&m.0);
                }
            }
            other => {
                w.u8(0).u32(self.pq.my.id).fixed(&self.pq.my.pk.0[..]);
                match other {
                    Some(o) => {
                        w.u32(o.for_id).fixed(&o.ct.0[..]).u32(o.e_out);
                    }
                    None => {
                        w.u32(0).fixed(&[0u8; MLKEM_CT_LEN]).u32(0);
                    }
                }
            }
        }
        let mut pt = w.finish();
        pt.resize(PQ_SLOT_PT_LEN, 0);
        let key = SealKey::from_bytes(kmac32(mk_dr, &[], labels::RATCHET_PQ_SLOT));
        Ok(seal::seal_compact(&key, nonce_material, ad, &pt)?)
    }

    // ----- receiving -------------------------------------------------------

    /// Try to open one device slot addressed to this session. Returns the body
    /// key and the would-be next state; commit with [`Session::commit`] only
    /// after the body authenticates.
    ///
    /// * `vault`: our McEliece key, needed only if the peer braids.
    pub fn open(
        &mut self,
        tag: &[u8; TAG_LEN],
        sealed_header: &[u8],
        pq_slot: Option<&[u8]>,
        body_hash: &[u8; 64],
        ad: &[u8],
        vault: Option<&McElieceSecret>,
        rng: &mut HedgedRng,
    ) -> Result<Opened> {
        let hit = *self.tag_index().get(tag).ok_or(ProtoError::NoSession)?;
        let mut s = self.clone();
        s.tag_cache = None;
        let nonce_material = [&tag[..], &body_hash[..]].concat();

        let mut skipped_at = None;
        let (header, mk_dr) = match hit {
            TagHit::Skipped => {
                let sk = s.skipped.remove(tag).ok_or(ProtoError::NoSession)?;
                skipped_at = Some(sk.at);
                let pt = seal::open_compact(
                    &SealKey::from_bytes(sk.hk),
                    &nonce_material,
                    ad,
                    sealed_header,
                )?;
                let h = Header::decode(&pt)?;
                if h.n != sk.n {
                    return Err(ProtoError::Crypto);
                }
                (h, sk.mk)
            }
            TagHit::Current(n) => {
                let hkr = s.hkr.ok_or(ProtoError::NoSession)?;
                let pt = seal::open_compact(
                    &SealKey::from_bytes(hkr),
                    &nonce_material,
                    ad,
                    sealed_header,
                )?;
                let h = Header::decode(&pt)?;
                if h.n != n || Some(h.dh) != s.dhr {
                    return Err(ProtoError::Crypto);
                }
                s.skip_to(n)?;
                let (ck2, mk) = kdf_ck(&s.ckr.ok_or(ProtoError::NoSession)?);
                s.ckr = Some(ck2);
                s.nr = n + 1;
                (h, mk)
            }
            TagHit::Next(n) => {
                let nhkr = s.nhkr;
                let pt = seal::open_compact(
                    &SealKey::from_bytes(nhkr),
                    &nonce_material,
                    ad,
                    sealed_header,
                )?;
                let h = Header::decode(&pt)?;
                if h.n != n {
                    return Err(ProtoError::Crypto);
                }
                // Finish the old receiving chain, then ratchet.
                if s.ckr.is_some() {
                    s.skip_to(h.pn)?;
                }
                s.dh_ratchet(&h.dh, rng)?;
                s.skip_to(n)?;
                let (ck2, mk) = kdf_ck(&s.ckr.ok_or(ProtoError::NoSession)?);
                s.ckr = Some(ck2);
                s.nr = n + 1;
                (h, mk)
            }
        };

        if header.flags & FLAG_PQ_SLOT != 0 {
            let slot = pq_slot.ok_or(ProtoError::Decode)?;
            s.process_pq_slot(&mk_dr, &nonce_material, ad, slot, vault, rng)?;
        }
        let pq_key = s.pq.key_as_receiver(header.e_out, header.e_in)?;
        // Initiator: the handshake key already includes an encapsulation to the
        // responder's device auth key, so any authentic message proves the peer.
        // Responder: the initiator is proven once it uses an in-epoch ≥ 1, which
        // depends on our encapsulation to its device auth key.
        if s.role == Role::Initiator || header.e_in >= 1 {
            s.pq_authenticated = true;
        }
        let mk = kmac32(&mk_dr, &[&pq_key], labels::RATCHET_MSG);
        let wrap_ks = kmac32(&mk, &[body_hash], labels::RATCHET_WRAP);
        let mut body_key = [0u8; 32];
        for i in 0..32 {
            body_key[i] = header.wrapped[i] ^ wrap_ks[i];
        }
        Ok(Opened {
            body_key,
            next: Box::new(s),
            skipped_at,
        })
    }

    /// Commit the state returned by [`Session::open`].
    pub fn commit(&mut self, next: Box<Session>) {
        *self = *next;
        self.invalidate();
    }

    fn skip_to(&mut self, until: u32) -> Result<()> {
        let Some(mut ck) = self.ckr else {
            return Ok(());
        };
        if until < self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(ProtoError::Counter);
        }
        let hkr = self.hkr.ok_or(ProtoError::NoSession)?;
        let mut seq = self
            .skipped
            .values()
            .map(|s| s.seq)
            .max()
            .map_or(0, |m| m + 1);
        while self.nr < until {
            let (ck2, mk) = kdf_ck(&ck);
            self.skipped.insert(
                lookup_tag(&hkr, self.nr),
                Skipped {
                    hk: hkr,
                    n: self.nr,
                    mk,
                    seq,
                    at: 0,
                },
            );
            seq += 1;
            ck = ck2;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        // Bound total skipped keys, evicting the oldest first.
        if self.skipped.len() > MAX_SKIP as usize {
            let mut order: Vec<([u8; TAG_LEN], u64)> =
                self.skipped.iter().map(|(t, s)| (*t, s.seq)).collect();
            order.sort_by_key(|(_, q)| *q);
            let excess = self.skipped.len() - MAX_SKIP as usize;
            for (t, _) in order.into_iter().take(excess) {
                self.skipped.remove(&t);
            }
            self.tag_cache = None;
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, their: &X448Public, rng: &mut HedgedRng) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(*their);
        let dh = self.dhs.diffie_hellman(their)?;
        let (rk, ckr, nhkr) = kdf_rk(&self.rk, &dh[..]);
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = nhkr;
        let (dhs, dhs_pub) = X448Secret::generate(rng)?;
        self.dhs = dhs;
        self.dhs_pub = dhs_pub;
        let dh2 = self.dhs.diffie_hellman(their)?;
        let (rk2, cks, nhks) = kdf_rk(&self.rk, &dh2[..]);
        self.rk = rk2;
        self.cks = Some(cks);
        self.nhks = nhks;
        Ok(())
    }

    fn process_pq_slot(
        &mut self,
        mk_dr: &Key,
        nonce_material: &[u8],
        ad: &[u8],
        slot: &[u8],
        vault: Option<&McElieceSecret>,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let key = SealKey::from_bytes(kmac32(mk_dr, &[], labels::RATCHET_PQ_SLOT));
        let pt = seal::open_compact(&key, nonce_material, ad, slot)?;
        let mut r = Reader::new(&pt);
        let kind = r.u8()?;
        let their_ek_id = r.u32()?;
        let their_ek = if kind == 0 {
            Some(MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?)
        } else {
            None
        };
        let ct_for = r.u32()?;
        let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
        let ct_e_out = r.u32()?;
        let mce_ct = if kind == 1 {
            let mut m = [0u8; MCELIECE_CT_LEN];
            m.copy_from_slice(r.fixed(MCELIECE_CT_LEN)?);
            Some(McElieceCiphertext(m))
        } else {
            None
        };
        if kind > 1 {
            return Err(ProtoError::Decode);
        }

        // 1. Their answer to our key: one in-step, in order.
        if ct_e_out != 0 && ct_for == self.pq.my.id && ct_e_out == self.pq.e_in + 1 {
            let ss = self.pq.my.sk.decapsulate(&ct);
            let ek_hash = sha3_512(&self.pq.my.pk.0[..]);
            let mce_ss = match &mce_ct {
                Some(c) => Some(vault.ok_or(ProtoError::Missing)?.decapsulate(c)?),
                None => None,
            };
            let new_root = PqState::step(
                &self.pq.in_root,
                &ss[..],
                &ct.0[..],
                &ek_hash,
                mce_ss
                    .as_ref()
                    .zip(mce_ct.as_ref())
                    .map(|(s, c)| (&s[..], &c.0[..])),
            );
            self.pq.e_in += 1;
            self.pq.in_root = new_root;
            PqState::push(&mut self.pq.in_hist, self.pq.e_in, new_root);
            if mce_ct.is_some() {
                self.three_kem = true;
            }
            // Fresh key for the next step (post-compromise security).
            let (sk, pk) = MlKemSecret::generate(rng)?;
            self.pq.my = MyPqKey {
                id: self.pq.my.id + 1,
                sk,
                pk,
            };
        } else if ct_e_out != 0 && ct_e_out > self.pq.e_in + 1 {
            return Err(ProtoError::Counter);
        }

        // 2. Their current key: remember it if it is new.
        if their_ek_id > self.pq.highest_peer_id
            && let Some(ek) = their_ek
        {
            self.pq.highest_peer_id = their_ek_id;
            self.pq.peer = Some((their_ek_id, ek));
        }
        // 3. They moved past the key our outstanding ciphertext answered.
        if let Some(o) = &self.pq.outstanding
            && their_ek_id > o.for_id
        {
            if o.mce_ct.is_some() {
                self.three_kem = true;
            }
            self.pq.outstanding = None;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Version byte of the exported session format.
const STATE_VERSION: u8 = 1;
/// Largest exported session accepted (a pending McEliece braid dominates).
pub const MAX_STATE_LEN: usize = 2 * 1024 * 1024;

fn put_opt_key(w: &mut Writer, k: &Option<Key>) {
    match k {
        Some(k) => w.u8(1).fixed(k),
        None => w.u8(0),
    };
}

fn get_opt_key(r: &mut Reader<'_>) -> Result<Option<Key>> {
    Ok(match r.u8()? {
        0 => None,
        1 => Some(r.array()?),
        _ => return Err(ProtoError::Decode),
    })
}

fn put_hist(w: &mut Writer, h: &VecDeque<(u32, Key)>) {
    w.u16(h.len() as u16);
    for (e, k) in h {
        w.u32(*e).fixed(k);
    }
}

fn get_hist(r: &mut Reader<'_>) -> Result<VecDeque<(u32, Key)>> {
    let n = r.u16()? as usize;
    if n > PQ_HISTORY {
        return Err(ProtoError::Decode);
    }
    let mut h = VecDeque::with_capacity(n);
    for _ in 0..n {
        h.push_back((r.u32()?, r.array()?));
    }
    Ok(h)
}

impl Session {
    /// Group exporter, sender side (`07-groups.md` §5.3): a key bound to
    /// `context` and to the newest PQ root of the **peer's** sending direction,
    /// which the peer still holds. Returns that root's epoch, which the peer
    /// needs to find it, and the key. Both halves of every root are
    /// ML-KEM-1024 steps seeded by the handshake, so the key is post-quantum
    /// and heals with each PQ round trip.
    pub fn export_for_peer(&self, context: &[u8]) -> (u32, [u8; 32]) {
        let (e, root) = self
            .pq
            .in_hist
            .back()
            .copied()
            .unwrap_or((self.pq.e_in, self.pq.in_root));
        (e, kmac32(&root, &[context], labels::GRP_EXPORT))
    }

    /// Group exporter, receiver side: the key the peer derived with
    /// [`Session::export_for_peer`] for our sending-direction epoch `e`, if we
    /// still hold that root (the last 16 epochs).
    pub fn export_from_peer(&self, e: u32, context: &[u8]) -> Option<[u8; 32]> {
        PqState::root_at(&self.pq.out_hist, e)
            .map(|root| kmac32(&root, &[context], labels::GRP_EXPORT))
    }

    /// Delete skipped message keys held longer than `max_age` seconds. Keys
    /// are stamped with `now` the first time this runs after they were
    /// skipped, so call it regularly (the client does on every sync).
    /// Returns how many were deleted.
    pub fn expire_skipped(&mut self, now: u64, max_age: u64) -> usize {
        let before = self.skipped.len();
        for s in self.skipped.values_mut() {
            if s.at == 0 {
                s.at = now.max(1);
            }
        }
        self.skipped
            .retain(|_, s| s.at.saturating_add(max_age) > now);
        let removed = before - self.skipped.len();
        if removed > 0 {
            self.tag_cache = None;
        }
        removed
    }

    /// Number of skipped message keys held.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// When the oldest skipped key still held was first seen (stamped by
    /// [`Session::expire_skipped`]): a message the peer sent before later
    /// ones that has not arrived since (`05-ratchet.md` §11).
    pub fn oldest_skipped(&self) -> Option<u64> {
        self.skipped.values().map(|s| s.at).filter(|a| *a > 0).min()
    }

    /// Serialize the full session state for sealed local storage. The output
    /// holds secrets: callers must seal it and zeroize it after use.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(STATE_VERSION);
        w.u8(match self.role {
            Role::Initiator => 0,
            Role::Responder => 1,
        });
        w.fixed(&self.rk).fixed(&self.dhs.to_bytes()[..]);
        match &self.dhr {
            Some(p) => w.u8(1).fixed(&p.0),
            None => w.u8(0),
        };
        put_opt_key(&mut w, &self.cks);
        put_opt_key(&mut w, &self.ckr);
        w.u32(self.ns).u32(self.nr).u32(self.pn);
        put_opt_key(&mut w, &self.hks);
        put_opt_key(&mut w, &self.hkr);
        w.fixed(&self.nhks).fixed(&self.nhkr);
        w.u32(self.skipped.len() as u32);
        for (tag, sk) in &self.skipped {
            w.fixed(tag)
                .fixed(&sk.hk)
                .u32(sk.n)
                .fixed(&sk.mk)
                .u64(sk.seq)
                .u64(sk.at);
        }
        let pq = &self.pq;
        w.fixed(&pq.out_root)
            .fixed(&pq.in_root)
            .u32(pq.e_out)
            .u32(pq.e_in);
        put_hist(&mut w, &pq.out_hist);
        put_hist(&mut w, &pq.in_hist);
        w.u32(pq.my.id)
            .bytes(pq.my.sk.as_bytes())
            .fixed(&pq.my.pk.0[..]);
        match &pq.peer {
            Some((id, pk)) => w.u8(1).u32(*id).fixed(&pk.0[..]),
            None => w.u8(0),
        };
        w.u32(pq.highest_peer_id);
        match &pq.outstanding {
            Some(o) => {
                w.u8(1).u32(o.for_id).fixed(&o.ct.0[..]).u32(o.e_out);
                match &o.mce_ct {
                    Some(c) => w.u8(1).fixed(&c.0),
                    None => w.u8(0),
                };
            }
            None => {
                w.u8(0);
            }
        }
        match &pq.braid_to {
            Some(pk) => w.u8(1).fixed(&pk.0[..]),
            None => w.u8(0),
        };
        w.u8(u8::from(self.pq_authenticated))
            .u8(u8::from(self.three_kem));
        Zeroizing::new(w.finish())
    }

    /// Inverse of [`Session::export`].
    pub fn import(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_STATE_LEN {
            return Err(ProtoError::Decode);
        }
        let mut r = Reader::new(b);
        if r.u8()? != STATE_VERSION {
            return Err(ProtoError::Decode);
        }
        let role = match r.u8()? {
            0 => Role::Initiator,
            1 => Role::Responder,
            _ => return Err(ProtoError::Decode),
        };
        let rk = r.array()?;
        let dhs = X448Secret::from_bytes(r.array()?);
        let dhs_pub = dhs.public();
        let dhr = match r.u8()? {
            0 => None,
            1 => Some(X448Public(r.array()?)),
            _ => return Err(ProtoError::Decode),
        };
        let cks = get_opt_key(&mut r)?;
        let ckr = get_opt_key(&mut r)?;
        let (ns, nr, pn) = (r.u32()?, r.u32()?, r.u32()?);
        let hks = get_opt_key(&mut r)?;
        let hkr = get_opt_key(&mut r)?;
        let nhks = r.array()?;
        let nhkr = r.array()?;
        let n_skipped = r.u32()?;
        if n_skipped > 4 * MAX_SKIP {
            return Err(ProtoError::Decode);
        }
        let mut skipped = BTreeMap::new();
        for _ in 0..n_skipped {
            let tag = r.array()?;
            skipped.insert(
                tag,
                Skipped {
                    hk: r.array()?,
                    n: r.u32()?,
                    mk: r.array()?,
                    seq: r.u64()?,
                    at: r.u64()?,
                },
            );
        }
        let out_root = r.array()?;
        let in_root = r.array()?;
        let (e_out, e_in) = (r.u32()?, r.u32()?);
        let out_hist = get_hist(&mut r)?;
        let in_hist = get_hist(&mut r)?;
        let my = MyPqKey {
            id: r.u32()?,
            sk: MlKemSecret::from_slice(r.bytes(8192)?)?,
            pk: MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?,
        };
        let peer = match r.u8()? {
            0 => None,
            1 => Some((r.u32()?, MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?)),
            _ => return Err(ProtoError::Decode),
        };
        let highest_peer_id = r.u32()?;
        let outstanding = match r.u8()? {
            0 => None,
            1 => {
                let for_id = r.u32()?;
                let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
                let e_out = r.u32()?;
                let mce_ct = match r.u8()? {
                    0 => None,
                    1 => Some(McElieceCiphertext(r.array::<MCELIECE_CT_LEN>()?)),
                    _ => return Err(ProtoError::Decode),
                };
                Some(Outstanding {
                    for_id,
                    ct,
                    e_out,
                    mce_ct,
                })
            }
            _ => return Err(ProtoError::Decode),
        };
        let braid_to = match r.u8()? {
            0 => None,
            1 => Some(Box::new(McEliecePublic::from_slice(
                r.fixed(enclave_crypto::kem::MCELIECE_PK_LEN)?,
            )?)),
            _ => return Err(ProtoError::Decode),
        };
        let flag = |v: u8| match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtoError::Decode),
        };
        let pq_authenticated = flag(r.u8()?)?;
        let three_kem = flag(r.u8()?)?;
        r.end()?;
        Ok(Self {
            role,
            rk,
            dhs,
            dhs_pub,
            dhr,
            cks,
            ckr,
            ns,
            nr,
            pn,
            hks,
            hkr,
            nhks,
            nhkr,
            skipped,
            pq: PqState {
                out_root,
                in_root,
                e_out,
                e_in,
                out_hist,
                in_hist,
                my,
                peer,
                highest_peer_id,
                outstanding,
                braid_to,
            },
            pq_authenticated,
            three_kem,
            tag_cache: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_is_strict() {
        let h = Header {
            dh: X448Public([3; 56]),
            pn: 1,
            n: 2,
            e_out: 3,
            e_in: 4,
            flags: 1,
            wrapped: [9; 32],
        };
        let e = h.encode();
        let d = Header::decode(&e).unwrap();
        assert_eq!(d.n, 2);
        let mut bad = e;
        bad[HEADER_PT_LEN - 1] = 1;
        assert!(Header::decode(&bad).is_err());
    }
}
