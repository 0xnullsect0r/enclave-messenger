//! Groups of up to 100 members (`docs/07-groups.md`).
//!
//! * Each member device sends on a **sender chain**. Chain seeds and MAC keys
//!   are distributed by a **rekey broadcast**: always exactly three units, one
//!   per bucket, each entry wrapped under a key exported from the pairwise
//!   Lockstep session with that recipient device. No MLS.
//! * Every message carries a **MAC vector**: one 16-byte tag per other member
//!   account, always 99 entries. Insiders cannot forge each other's messages
//!   and no signature proves authorship to outsiders (deniable, post-quantum).
//! * Every message carries the sender's **state hash** and **causal frontier**
//!   so forks and withheld messages show up. Both, and the sender's identity,
//!   travel encrypted under the epoch's header key, authenticated by the MAC
//!   vector; the server sees only the epoch number.
//!
//! Group envelope (14,336 B, offsets from `enclave_wire::group`):
//!
//! ```text
//!   0  16  clear: version, kind=Group, subkind 2, 0, epoch u32, 0^8
//!  16  32  nonce
//!  48  40  enc: member, device, generation, flags, counter u32, 0^32
//!  88  32  enc: state hash
//! 120 800  enc: causal frontier (100 × 8)
//! 920 1584 MAC vector (99 × 16) over
//!          H512("enclave/v1/wire/ad-grp-header" ‖ unit[0..920] ‖ unit[2504..])
//! 2504 1024 capsule (random)
//! 3528 ... body: EnclaveSeal(gmk, AD = "enclave/v1/wire/ad-grp-body" ‖
//!          unit[0..920], padded content)
//! ```
//!
//! Rekey unit (subkind 3): the same 88-byte header (bucket in byte 3,
//! sender, generation, flags and target epoch encrypted), then
//! `EnclaveSeal(KMAC256(epoch secret, "", "enclave/v1/proto/grp-rekey-outer"),
//! AD = "enclave/v1/wire/ad-rekey" ‖ header, common (192) ‖ 174 entries × 80
//! ‖ random)`. Subkinds 0 and 1 are the first versions of both (no labels,
//! no outer seal), still read.

use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::labels;
use crate::ratchet::Session;
use enclave_crypto::hash::sha3_512_parts;
use enclave_crypto::kmac::{Kmac256, kmac256, kmac256_parts};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_wire::{ENVELOPE_LEN, EnvelopeKind, group as off, pad_content, unpad_content};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum member accounts.
pub const MAX_MEMBERS: usize = 100;
/// MAC-vector entries (every member but the sender).
pub const MAC_ENTRIES: usize = MAX_MEMBERS - 1;
/// Rekey units per rotation.
pub const BUCKETS: usize = 3;
/// Entries per rekey unit.
pub const ENTRIES_PER_BUCKET: usize = 174;
/// Rekey entry size.
pub const ENTRY_LEN: usize = 80;
/// A sender rotates after this many messages in one generation.
pub const ROTATE_AFTER_MESSAGES: u32 = 200;
/// ... or after this long.
pub const ROTATE_AFTER_SECS: u64 = 86_400;
/// Skipped group message keys kept per sender device and generation.
pub const MAX_SKIP: u32 = 1000;
/// Message flag: this message is a state update (admin MAC label).
pub const FLAG_STATE_UPDATE: u8 = 0x01;
/// Message flag: structured content (polls, votes) rather than text. Like
/// every flag it is inside the sealed, MAC-authenticated sender header.
pub const FLAG_RICH: u8 = 0x02;
/// Sender-header flag: the content starts with the sender device's
/// composite signature (On-the-record groups, `07-groups.md` §3), 4,741 B.
pub const FLAG_SIGNED: u8 = 0x04;
/// Rekey flag: the rotation starts a new epoch.
const REKEY_NEW_EPOCH: u8 = 0x01;

const VERSION: u8 = 1;
/// Subtypes (byte 2). 0 and 1 are the first formats, without label
/// prefixes and without a rekey unit's outer seal; they are still read, so
/// units already stored when a client updates open.
const SUB_MESSAGE_V1: u8 = 0;
const SUB_REKEY_V1: u8 = 1;
const SUB_MESSAGE: u8 = 2;
const SUB_REKEY: u8 = 3;

#[cfg(test)]
thread_local! {
    /// Tests: write the first formats (subkinds 0 and 1).
    static LEGACY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn legacy() -> bool {
    #[cfg(test)]
    return LEGACY.with(|l| l.get());
    #[cfg(not(test))]
    false
}

/// Whether `unit` is a rekey unit (else a message).
pub fn is_rekey(unit: &[u8]) -> bool {
    matches!(unit.get(2), Some(&SUB_REKEY) | Some(&SUB_REKEY_V1))
}

/// What a message's MAC vector covers: `H512(label ‖ unit[0..920] ‖
/// unit[2504..])` (version 1 had no label).
fn mac_input(unit: &[u8], v1: bool) -> [u8; 64] {
    if v1 {
        sha3_512_parts(&[&unit[..off::MACS], &unit[off::CAPSULE..]])
    } else {
        sha3_512_parts(&[
            labels::WIRE_AD_GRP_HEADER.as_bytes(),
            &unit[..off::MACS],
            &unit[off::CAPSULE..],
        ])
    }
}

/// A message body's AD: `label ‖ unit[0..920]` (version 1: no label).
fn body_ad(unit: &[u8], v1: bool) -> Vec<u8> {
    if v1 {
        unit[..off::MACS].to_vec()
    } else {
        [labels::WIRE_AD_GRP_BODY.as_bytes(), &unit[..off::MACS]].concat()
    }
}

/// A rekey unit's payload inside its outer seal: the common blob, the
/// entries, then random filler.
const REKEY_PAYLOAD: usize = ENVELOPE_LEN - COMMON - seal::OVERHEAD;
const _: () = assert!(COMMON_LEN + ENTRIES_PER_BUCKET * ENTRY_LEN <= REKEY_PAYLOAD);

fn outer_key(es: &Key) -> SealKey {
    SealKey::from_bytes(kmac256(es, b"", labels::GRP_REKEY_OUTER))
}
const NONCE: usize = 16;
const ENC: usize = 48;
const SENDER_ENC_LEN: usize = 40;
const COMMON: usize = 88;
const COMMON_PT_LEN: usize = 128;
const COMMON_LEN: usize = COMMON_PT_LEN + seal::OVERHEAD;
const _: () = assert!(off::MACS == 920 && off::CAPSULE == 2504);
const _: () = assert!(BUCKETS * ENTRIES_PER_BUCKET >= MAX_MEMBERS * crate::manifest::MAX_DEVICES);

/// Identifier of one group message (8 bytes).
pub type MsgId = [u8; 8];

type Key = [u8; 32];

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A member slot. Indices never shift: someone who leaves or is removed
/// leaves a tombstone (`active = false`) that a later joiner may reuse, so
/// MAC-vector positions stay valid while an update is in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Root public key.
    pub root: [u8; 64],
    /// Admin.
    pub admin: bool,
    /// When they joined (for last-admin promotion).
    pub joined: u64,
    /// Still a member.
    pub active: bool,
}

impl Member {
    /// A new active member.
    pub fn new(root: [u8; 64], admin: bool, joined: u64) -> Self {
        Self {
            root,
            admin,
            joined,
            active: true,
        }
    }
}

/// Group state. Every version names its parent, so versions form a hash chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupState {
    /// Random group identifier.
    pub group_id: [u8; 32],
    /// Epoch this state belongs to.
    pub epoch: u32,
    /// Hash of the previous state (zero for the first).
    pub parent: [u8; 32],
    /// Name.
    pub name: String,
    /// Server hosting the group mailbox (from day `host_since` on).
    pub host: [u8; 16],
    /// The server that hosted it before the last move (`07-groups.md` §4).
    pub prev_host: [u8; 16],
    /// The first day (Unix days) of `host`; earlier days' mailboxes are on
    /// `prev_host`. 0: the group never moved.
    pub host_since: u32,
    /// Only admins can send.
    pub admins_only: bool,
    /// On the record: messages carry their sender device's signature, and
    /// state updates their admin's (`07-groups.md` §3, §7.3).
    pub on_record: bool,
    /// Members; a member's index is its position.
    pub members: Vec<Member>,
}

impl GroupState {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        // Version 2 for a group on the record, 3 for one that moved its
        // mailboxes, so the states (and state hashes) of every other group
        // stay as they were.
        let version = if self.host_since != 0 {
            3
        } else if self.on_record {
            2
        } else {
            1
        };
        let mut w = Writer::new();
        w.u8(version)
            .fixed(&self.group_id)
            .u32(self.epoch)
            .fixed(&self.parent);
        w.bytes(self.name.as_bytes())
            .fixed(&self.host)
            .u8(u8::from(self.admins_only));
        if version >= 2 {
            w.u8(u8::from(self.on_record));
        }
        if version >= 3 {
            w.fixed(&self.prev_host).u32(self.host_since);
        }
        w.u8(self.members.len() as u8);
        for m in &self.members {
            w.fixed(&m.root)
                .u8(u8::from(m.admin))
                .u64(m.joined)
                .u8(u8::from(m.active));
        }
        w.finish()
    }

    /// Strict decoding.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if !(1..=3).contains(&version) {
            return Err(ProtoError::Decode);
        }
        let group_id = r.array()?;
        let epoch = r.u32()?;
        let parent = r.array()?;
        let name = String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
        let host = r.array()?;
        let admins_only = r.u8()? == 1;
        let on_record = match if version >= 2 { r.u8()? } else { 0 } {
            0 => false,
            1 => true,
            _ => return Err(ProtoError::Decode),
        };
        let (prev_host, host_since) = if version >= 3 {
            (r.array()?, r.u32()?)
        } else {
            ([0; 16], 0)
        };
        // Canonical: the lowest version that holds it.
        if (version == 2 && !on_record) || (version == 3 && host_since == 0) {
            return Err(ProtoError::Decode);
        }
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_MEMBERS {
            return Err(ProtoError::Decode);
        }
        let mut members = Vec::with_capacity(n);
        for _ in 0..n {
            members.push(Member {
                root: r.array()?,
                admin: r.u8()? == 1,
                joined: r.u64()?,
                active: r.u8()? == 1,
            });
        }
        r.end()?;
        let s = Self {
            group_id,
            epoch,
            parent,
            name,
            host,
            prev_host,
            host_since,
            admins_only,
            on_record,
            members,
        };
        s.check()?;
        Ok(s)
    }

    fn check(&self) -> Result<()> {
        if self.members.is_empty() || self.members.len() > MAX_MEMBERS {
            return Err(ProtoError::Limit);
        }
        let active: Vec<&[u8; 64]> = self
            .members
            .iter()
            .filter(|m| m.active)
            .map(|m| &m.root)
            .collect();
        let unique: HashSet<&[u8; 64]> = active.iter().copied().collect();
        if active.is_empty() || unique.len() != active.len() {
            return Err(ProtoError::Decode);
        }
        Ok(())
    }

    /// `state_hash = KMAC256(group_id, encode(state), "grp-state")`; the
    /// encoding includes the parent hash, so this chains.
    pub fn hash(&self) -> [u8; 32] {
        kmac256(&self.group_id, &self.encode(), labels::GRP_STATE)
    }

    /// The server hosting the mailboxes of day `day`.
    pub fn host_for(&self, day: u32) -> [u8; 16] {
        if day < self.host_since {
            self.prev_host
        } else {
            self.host
        }
    }

    /// Index of an active member.
    pub fn index_of(&self, root: &[u8; 64]) -> Option<u8> {
        self.members
            .iter()
            .position(|m| m.active && &m.root == root)
            .map(|i| i as u8)
    }

    /// Active members with their indices.
    pub fn active(&self) -> impl Iterator<Item = (u8, &Member)> {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.active)
            .map(|(i, m)| (i as u8, m))
    }

    /// Add a member, reusing a tombstone slot if there is one.
    pub fn add(&mut self, root: [u8; 64], admin: bool, joined: u64) -> Result<u8> {
        if self.index_of(&root).is_some() {
            return Err(ProtoError::Decode);
        }
        if let Some(i) = self.members.iter().position(|m| !m.active) {
            self.members[i] = Member::new(root, admin, joined);
            return Ok(i as u8);
        }
        if self.members.len() >= MAX_MEMBERS {
            return Err(ProtoError::Limit);
        }
        self.members.push(Member::new(root, admin, joined));
        Ok((self.members.len() - 1) as u8)
    }

    /// Remove (tombstone) a member.
    pub fn remove(&mut self, index: u8) {
        if let Some(m) = self.members.get_mut(index as usize) {
            m.active = false;
            m.admin = false;
        }
    }

    /// A child state: `f` edits a copy whose parent is this state.
    pub fn child(&self, f: impl FnOnce(&mut GroupState)) -> Result<GroupState> {
        let mut next = self.clone();
        next.parent = self.hash();
        f(&mut next);
        next.check()?;
        if next.group_id != self.group_id {
            return Err(ProtoError::Decode);
        }
        // With no admin left, the longest-standing member is promoted.
        if !next.members.iter().any(|m| m.active && m.admin) {
            let oldest = next
                .members
                .iter()
                .enumerate()
                .filter(|(_, m)| m.active)
                .min_by(|(_, a), (_, b)| (a.joined, a.root).cmp(&(b.joined, b.root)));
            if let Some((i, _)) = oldest {
                next.members[i].admin = true;
            }
        }
        Ok(next)
    }

    /// If `next` differs from this state only in one member's root (same
    /// slot, role and join time), that member's index and old and new
    /// roots: a change of recovery words (`03-identity.md` §8.2.6).
    pub fn root_change(&self, next: &GroupState) -> Option<(u8, [u8; 64], [u8; 64])> {
        if next.name != self.name
            || next.host != self.host
            || next.prev_host != self.prev_host
            || next.host_since != self.host_since
            || next.admins_only != self.admins_only
            || next.on_record != self.on_record
            || next.epoch != self.epoch
            || next.members.len() != self.members.len()
        {
            return None;
        }
        let mut changed = None;
        for (i, (a, b)) in self.members.iter().zip(&next.members).enumerate() {
            if a == b {
                continue;
            }
            if changed.is_some()
                || !a.active
                || a.admin != b.admin
                || a.joined != b.joined
                || a.active != b.active
            {
                return None;
            }
            changed = Some((i as u8, a.root, b.root));
        }
        changed
    }

    /// Whether `next` is a valid update posted by member `author`: same group,
    /// parent is this state, and the author is an admin here, or the update
    /// only removes the author (they leave) or only changes the author's
    /// own root (new recovery words; the caller also checks the migration).
    pub fn accepts(&self, next: &GroupState, author: u8) -> bool {
        if next.group_id != self.group_id || next.parent != self.hash() || next.check().is_err() {
            return false;
        }
        let Some(a) = self.members.get(author as usize).filter(|m| m.active) else {
            return false;
        };
        if a.admin {
            return true;
        }
        if self.root_change(next).is_some_and(|(i, _, _)| i == author) {
            return true;
        }
        // A non-admin may otherwise only leave (automatic admin promotion
        // aside).
        let mut expected = self.clone();
        expected.remove(author);
        let strip = |s: &GroupState| {
            s.members
                .iter()
                .map(|m| (m.root, m.joined, m.active))
                .collect::<Vec<_>>()
        };
        next.name == self.name
            && next.host == self.host
            && next.prev_host == self.prev_host
            && next.host_since == self.host_since
            && next.admins_only == self.admins_only
            && next.on_record == self.on_record
            && next.epoch == self.epoch
            && strip(next) == strip(&expected)
    }
}

// ---------------------------------------------------------------------------
// Keys derived from the epoch secret
// ---------------------------------------------------------------------------

fn header_key(es: &Key) -> Key {
    kmac256(es, b"", labels::GRP_HEADER)
}

fn bucket_key(es: &Key) -> Key {
    kmac256(es, b"", labels::GRP_BUCKET)
}

fn bucket_of(es: &Key, device_id: &[u8; 16]) -> usize {
    let b: [u8; 2] = kmac256(&bucket_key(es), device_id, labels::GRP_BUCKET_INDEX);
    u16::from_be_bytes(b) as usize % BUCKETS
}

/// Group mailbox address for day `d` under an epoch secret.
pub fn mailbox(es: &Key, day: u32) -> [u8; 32] {
    kmac256(es, &day.to_be_bytes(), labels::NET_GRP_MAILBOX)
}

/// Rekey sub-mailbox of bucket `b` for day `d`.
pub fn rekey_mailbox(es: &Key, day: u32, b: u8) -> [u8; 32] {
    kmac256_parts(
        &bucket_key(es),
        &[&day.to_be_bytes(), &[b]],
        labels::NET_GRP_REKEY_MAILBOX,
    )
}

/// Write token for a group mailbox address. Every member may both write and
/// read, so the same secret is the mailbox's owner secret: the first write
/// creates the mailbox, later writes present it again, and polls use the
/// read credential derived from it.
pub fn write_token(es: &Key, addr: &[u8; 32]) -> [u8; 32] {
    let k: Key = kmac256(es, b"", labels::NET_GRP_WRITE_KEY);
    kmac256(&k, addr, labels::NET_GRP_WRITE_TOKEN)
}

fn keystream(es: &Key, nonce: &[u8], out: &mut [u8]) {
    let mut k = Kmac256::new(&header_key(es), labels::GRP_HEADER.as_bytes());
    k.update_framed(nonce);
    let mut x = k.finalize_xof();
    let mut ks = vec![0u8; out.len()];
    x.read(&mut ks);
    for (o, k) in out.iter_mut().zip(ks) {
        *o ^= k;
    }
}

fn msg_id(
    group_id: &[u8; 32],
    epoch: u32,
    member: u8,
    device: u8,
    generation: u8,
    counter: u32,
) -> MsgId {
    let mut w = Writer::new();
    w.fixed(group_id)
        .u32(epoch)
        .u8(member)
        .u8(device)
        .u8(generation)
        .u32(counter);
    kmac256(group_id, w.as_slice(), labels::GRP_MSG_ID)
}

fn export_context(
    group_id: &[u8; 32],
    epoch: u32,
    member: u8,
    device: u8,
    generation: u8,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(group_id)
        .u32(epoch)
        .u8(member)
        .u8(device)
        .u8(generation);
    w.finish()
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Chain {
    cs: Key,
    n: u32,
}

impl Chain {
    fn step(&mut self) -> (u32, Key) {
        let out: [u8; 64] = kmac256(&self.cs, b"", labels::GRP_CHAIN);
        let n = self.n;
        self.cs.copy_from_slice(&out[..32]);
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&out[32..]);
        self.n += 1;
        (n, mk)
    }
}

#[derive(Clone)]
struct MyChain {
    epoch: u32,
    generation: u8,
    /// Seed of this generation, kept only so a welcome can hand the chain to
    /// a joiner who cannot read the rekey that started the epoch.
    seed: Key,
    chain: Chain,
    /// MAC keys indexed by member index (ours unused).
    mac_keys: Vec<Key>,
    created_at: u64,
}

#[derive(Clone)]
struct RecvChain {
    epoch: u32,
    chain: Chain,
    skipped: BTreeMap<u32, Key>,
    /// `mac_key[sender → our account]`.
    mac_key: Key,
}

/// One member device that should receive our rekey.
pub struct RekeyTarget<'a> {
    /// Member index.
    pub member: u8,
    /// Device index within that member's manifest.
    pub device: u8,
    /// Device identifier (for the bucket).
    pub device_id: [u8; 16],
    /// Our pairwise session with that device.
    pub session: &'a Session,
}

/// A decrypted group message.
#[derive(Clone, Debug)]
pub struct GroupMessage {
    /// Sender member index.
    pub member: u8,
    /// Sender device index.
    pub device: u8,
    /// Epoch it was sent in.
    pub epoch: u32,
    /// The sender's chain generation.
    pub generation: u8,
    /// Its counter in that chain.
    pub counter: u32,
    /// Message identifier.
    pub id: MsgId,
    /// The sender's state hash.
    pub state_hash: [u8; 32],
    /// The sender's causal frontier (one id per member index; zero = none).
    pub frontier: Vec<MsgId>,
    /// Flags (`FLAG_STATE_UPDATE`).
    pub flags: u8,
    /// Sent by another device of our own account. The MAC vector cannot
    /// authenticate these; show them only after own-device sync confirms the
    /// id (`07-groups.md` §3).
    pub own_account: bool,
    /// Content.
    pub content: Vec<u8>,
}

/// Header of a rekey unit, readable by current members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeySender {
    /// Member index of the rotating device.
    pub member: u8,
    /// Its device index.
    pub device: u8,
    /// New generation.
    pub generation: u8,
    /// Epoch the rekey was announced under.
    pub epoch: u32,
    /// Epoch the new chain belongs to.
    pub target_epoch: u32,
}

/// Result of processing a rekey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyOutcome {
    /// Installed the sender's new chain (and the new epoch, if any).
    Installed {
        /// New epoch if the rotation started one.
        new_epoch: Option<u32>,
    },
    /// No entry for this device in this unit: try the next bucket.
    NotForUs,
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

/// One device's view of a group.
pub struct Group {
    /// Current state.
    pub state: GroupState,
    /// Our member index.
    pub me: u8,
    /// Our device index.
    pub my_device: u8,
    epochs: BTreeMap<u32, Key>,
    mine: Option<MyChain>,
    recv: HashMap<(u8, u8, u8), RecvChain>,
    frontier: Vec<MsgId>,
    seen: VecDeque<MsgId>,
    seen_set: HashSet<MsgId>,
}

impl Group {
    /// Create a group with ourselves as the only member and admin.
    pub fn create(
        name: &str,
        my_root: [u8; 64],
        host: [u8; 16],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let state = GroupState {
            group_id: rng.array("group/id")?,
            epoch: 0,
            parent: [0; 32],
            name: name.to_string(),
            host,
            prev_host: [0; 16],
            host_since: 0,
            admins_only: false,
            on_record: false,
            members: vec![Member::new(my_root, true, now)],
        };
        let es: Key = rng.array("group/epoch-secret")?;
        Ok(Self::with(state, 0, 0, BTreeMap::from([(0, es)])))
    }

    fn with(state: GroupState, me: u8, my_device: u8, epochs: BTreeMap<u32, Key>) -> Self {
        Self {
            state,
            me,
            my_device,
            epochs,
            mine: None,
            recv: HashMap::new(),
            frontier: vec![[0; 8]; MAX_MEMBERS],
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
        }
    }

    /// Current epoch secret.
    fn epoch_secret(&self) -> Result<Key> {
        self.epochs
            .get(&self.state.epoch)
            .copied()
            .ok_or(ProtoError::Missing)
    }

    /// Today's mailbox address for the current epoch.
    pub fn mailbox(&self, day: u32) -> Result<[u8; 32]> {
        Ok(mailbox(&self.epoch_secret()?, day))
    }

    /// Mailbox of every held epoch for `day` (readers poll all of them).
    pub fn mailboxes(&self, day: u32) -> Vec<(u32, [u8; 32])> {
        self.epochs
            .iter()
            .map(|(e, es)| (*e, mailbox(es, day)))
            .collect()
    }

    /// Owner secret (write token) of a mailbox address of epoch `e`.
    pub fn mailbox_secret(&self, e: u32, addr: &[u8; 32]) -> Result<[u8; 32]> {
        let es = self.epochs.get(&e).ok_or(ProtoError::Missing)?;
        Ok(write_token(es, addr))
    }

    /// The bucket and rekey mailbox this device reads for epoch `e`.
    pub fn my_rekey_mailbox(
        &self,
        e: u32,
        device_id: &[u8; 16],
        day: u32,
    ) -> Result<(u8, [u8; 32])> {
        let es = self.epochs.get(&e).ok_or(ProtoError::Missing)?;
        let b = bucket_of(es, device_id) as u8;
        Ok((b, rekey_mailbox(es, day, b)))
    }

    /// Rekey mailbox of bucket `b` for epoch `e` (for writers and overflow).
    pub fn rekey_mailbox(&self, e: u32, day: u32, b: u8) -> Result<[u8; 32]> {
        Ok(rekey_mailbox(
            self.epochs.get(&e).ok_or(ProtoError::Missing)?,
            day,
            b,
        ))
    }

    /// Our causal frontier.
    pub fn frontier(&self) -> &[MsgId] {
        &self.frontier
    }

    /// Whether we must rotate before sending: no chain for the current
    /// epoch, or the chain is too old or too long.
    pub fn needs_rotation(&self, now: u64) -> bool {
        match &self.mine {
            None => true,
            Some(m) => {
                m.epoch != self.state.epoch
                    || m.chain.n >= ROTATE_AFTER_MESSAGES
                    || now.saturating_sub(m.created_at) >= ROTATE_AFTER_SECS
                    || m.mac_keys.len() < self.state.members.len()
            }
        }
    }

    /// Install a new state (after checking it with [`GroupState::accepts`]).
    /// A new epoch needs its secret first (from a rekey or a welcome).
    pub fn apply_state(&mut self, next: GroupState) -> Result<()> {
        if next.epoch != self.state.epoch && !self.epochs.contains_key(&next.epoch) {
            return Err(ProtoError::Missing);
        }
        let my_root = self
            .state
            .members
            .get(self.me as usize)
            .map(|m| m.root)
            .ok_or(ProtoError::Missing)?;
        // Our own change of recovery words keeps our slot (§8.2.6).
        let me = match self.state.root_change(&next) {
            Some((i, _, new)) if i == self.me => next.index_of(&new),
            _ => next.index_of(&my_root),
        }
        .ok_or(ProtoError::NoSession)?;
        // Member indices can shift; frontiers and receive chains are per index.
        if me != self.me || next.members.len() != self.state.members.len() {
            self.recv.retain(|_, c| c.epoch >= next.epoch);
        }
        self.me = me;
        self.state = next;
        // Keep the current and previous epoch only.
        let keep = self.state.epoch.saturating_sub(1);
        self.epochs.retain(|e, _| *e >= keep);
        Ok(())
    }

    /// Start a new epoch locally (the rotating admin does this after
    /// `child()`), returning its secret for the rekey.
    pub fn new_epoch(&mut self, rng: &mut HedgedRng) -> Result<(u32, Key)> {
        let e = self.epochs.keys().max().copied().unwrap_or(0) + 1;
        let es: Key = rng.array("group/epoch-secret")?;
        self.epochs.insert(e, es);
        Ok((e, es))
    }

    // ------------------------------------------------------------------
    // Messages
    // ------------------------------------------------------------------

    /// What the next [`Group::seal`] will send under: `(epoch,
    /// generation, counter, state_hash)`, for a signature over them.
    pub fn next_send(&self) -> Result<(u32, u8, u32, [u8; 32])> {
        let mine = self.mine.as_ref().ok_or(ProtoError::NoSession)?;
        if mine.epoch != self.state.epoch {
            return Err(ProtoError::NoSession);
        }
        Ok((
            self.state.epoch,
            mine.generation,
            mine.chain.n,
            self.state.hash(),
        ))
    }

    /// Seal `content` for the group mailbox.
    pub fn seal(&mut self, content: &[u8], flags: u8, rng: &mut HedgedRng) -> Result<Vec<u8>> {
        let es = self.epoch_secret()?;
        let state_hash = self.state.hash();
        let members = self.state.members.len();
        let mine = self.mine.as_mut().ok_or(ProtoError::NoSession)?;
        if mine.epoch != self.state.epoch || mine.mac_keys.len() < members {
            return Err(ProtoError::NoSession);
        }
        let (n, gmk) = mine.chain.step();
        let generation = mine.generation;
        let mac_keys = mine.mac_keys.clone();

        let mut unit = vec![0u8; ENVELOPE_LEN];
        unit[0] = VERSION;
        unit[1] = EnvelopeKind::Group as u8;
        let v1 = legacy();
        unit[2] = if v1 { SUB_MESSAGE_V1 } else { SUB_MESSAGE };
        unit[4..8].copy_from_slice(&self.state.epoch.to_be_bytes());
        rng.fill("group/nonce", &mut unit[NONCE..ENC])?;
        let e = &mut unit[ENC..ENC + SENDER_ENC_LEN];
        e[0] = self.me;
        e[1] = self.my_device;
        e[2] = generation;
        e[3] = flags;
        e[4..8].copy_from_slice(&n.to_be_bytes());
        unit[off::STATE..off::FRONTIER].copy_from_slice(&state_hash);
        for (i, id) in self.frontier.iter().enumerate() {
            unit[off::FRONTIER + 8 * i..off::FRONTIER + 8 * i + 8].copy_from_slice(id);
        }
        let nonce: [u8; 32] = unit[NONCE..ENC]
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        keystream(&es, &nonce, &mut unit[ENC..off::MACS]);
        rng.fill("group/capsule", &mut unit[off::CAPSULE..off::BODY])?;

        let mut pad = |b: &mut [u8]| {
            if rng.fill("group/padding", b).is_err() {
                b.fill(0);
            }
        };
        let framed = Zeroizing::new(pad_content(content, off::CONTENT_CAPACITY, &mut pad)?);
        let body = seal::seal(&SealKey::from_bytes(gmk), &body_ad(&unit, v1), &framed, rng)?;
        if body.len() != off::BODY_LEN {
            return Err(ProtoError::Decode);
        }
        unit[off::BODY..].copy_from_slice(&body);

        let h = mac_input(&unit, v1);
        let label = if flags & FLAG_STATE_UPDATE != 0 {
            labels::GRP_ADMIN_MAC
        } else {
            labels::GRP_MAC
        };
        for p in 0..MAC_ENTRIES {
            let target = if p < self.me as usize { p } else { p + 1 };
            let slot = &mut unit[off::MACS + 16 * p..off::MACS + 16 * p + 16];
            if target < members && self.state.members[target].active {
                let tag: [u8; 16] = kmac256(&mac_keys[target], &h, label);
                slot.copy_from_slice(&tag);
            } else {
                rng.fill("group/mac-fill", slot)?;
            }
        }
        let id = msg_id(
            &self.state.group_id,
            self.state.epoch,
            self.me,
            self.my_device,
            generation,
            n,
        );
        self.frontier[self.me as usize] = id;
        self.remember(id);
        Ok(unit)
    }

    fn remember(&mut self, id: MsgId) {
        if self.seen_set.insert(id) {
            self.seen.push_back(id);
            while self.seen.len() > 20_000 {
                if let Some(old) = self.seen.pop_front() {
                    self.seen_set.remove(&old);
                }
            }
        }
    }

    /// Open a group message. State is committed only after the MAC and the
    /// body authenticate.
    pub fn open(&mut self, unit: &[u8]) -> Result<GroupMessage> {
        if unit.len() != ENVELOPE_LEN
            || unit[0] != VERSION
            || unit[1] != EnvelopeKind::Group as u8
            || !matches!(unit[2], SUB_MESSAGE | SUB_MESSAGE_V1)
        {
            return Err(ProtoError::Decode);
        }
        let epoch = u32::from_be_bytes(unit[4..8].try_into().map_err(|_| ProtoError::Decode)?);
        let es = *self.epochs.get(&epoch).ok_or(ProtoError::Missing)?;
        let mut hdr = unit[..off::MACS].to_vec();
        let nonce: [u8; 32] = unit[NONCE..ENC]
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        keystream(&es, &nonce, &mut hdr[ENC..off::MACS]);
        let (member, device, generation, flags) =
            (hdr[ENC], hdr[ENC + 1], hdr[ENC + 2], hdr[ENC + 3]);
        let counter = u32::from_be_bytes(
            hdr[ENC + 4..ENC + 8]
                .try_into()
                .map_err(|_| ProtoError::Decode)?,
        );
        let own_account = member == self.me;
        if own_account && device == self.my_device {
            return Err(ProtoError::Counter); // our own message echoed back
        }
        let key = (member, device, generation);
        let mut rc = self.recv.get(&key).cloned().ok_or(ProtoError::Missing)?;
        if rc.epoch != epoch {
            return Err(ProtoError::Missing);
        }

        // MAC first (constant time), unless it is from our own account.
        if !own_account {
            let h = mac_input(unit, unit[2] == SUB_MESSAGE_V1);
            let p = if (self.me as usize) < member as usize {
                self.me as usize
            } else {
                self.me as usize - 1
            };
            let label = if flags & FLAG_STATE_UPDATE != 0 {
                labels::GRP_ADMIN_MAC
            } else {
                labels::GRP_MAC
            };
            let want: [u8; 16] = kmac256(&rc.mac_key, &h, label);
            let got = &unit[off::MACS + 16 * p..off::MACS + 16 * p + 16];
            if !bool::from(want.ct_eq(got)) {
                return Err(ProtoError::Crypto);
            }
        }

        let gmk = if counter < rc.chain.n {
            rc.skipped.remove(&counter).ok_or(ProtoError::Counter)?
        } else {
            if counter - rc.chain.n > MAX_SKIP {
                return Err(ProtoError::Counter);
            }
            loop {
                let (n, mk) = rc.chain.step();
                if n == counter {
                    break mk;
                }
                rc.skipped.insert(n, mk);
            }
        };
        while rc.skipped.len() > MAX_SKIP as usize {
            if let Some(k) = rc.skipped.keys().next().copied() {
                rc.skipped.remove(&k);
            }
        }
        let framed = Zeroizing::new(seal::open(
            &SealKey::from_bytes(gmk),
            &body_ad(unit, unit[2] == SUB_MESSAGE_V1),
            &unit[off::BODY..],
        )?);
        let content = unpad_content(&framed)?.to_vec();
        let id = msg_id(
            &self.state.group_id,
            epoch,
            member,
            device,
            generation,
            counter,
        );
        if self.seen_set.contains(&id) {
            return Err(ProtoError::Counter);
        }
        // Commit.
        self.recv.insert(key, rc);
        self.remember(id);
        if (member as usize) < MAX_MEMBERS {
            self.frontier[member as usize] = id;
        }
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(&hdr[off::STATE..off::FRONTIER]);
        let frontier = hdr[off::FRONTIER..off::MACS]
            .chunks(8)
            .map(|c| {
                let mut id = [0u8; 8];
                id.copy_from_slice(c);
                id
            })
            .collect();
        Ok(GroupMessage {
            member,
            device,
            epoch,
            generation,
            counter,
            id,
            state_hash,
            frontier,
            flags,
            own_account,
            content,
        })
    }

    /// Frontier entries of `msg` that name messages we have not seen: fetch
    /// them, and warn if they stay missing (`07-groups.md` §7.4).
    pub fn missing(&self, msg: &GroupMessage) -> Vec<(u8, MsgId)> {
        msg.frontier
            .iter()
            .enumerate()
            .filter(|(i, id)| {
                **id != [0; 8] && *i != self.me as usize && !self.seen_set.contains(*id)
            })
            .map(|(i, id)| (i as u8, *id))
            .collect()
    }

    // ------------------------------------------------------------------
    // Rekey
    // ------------------------------------------------------------------

    /// Rotate our sender chain and build the three rekey units for
    /// `targets` (every device of every other member, and our own other
    /// devices). With `new_epoch`, the rotation also hands out that epoch's
    /// secret; the units are announced under the current epoch so current
    /// members can read them, and the new state must already name the
    /// epoch. Returns the units, indexed by bucket.
    pub fn rotate(
        &mut self,
        targets: &[RekeyTarget<'_>],
        new_epoch: Option<(u32, Key)>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<Vec<u8>>> {
        // A rotation that starts an epoch is announced under the previous one,
        // which current members hold; joiners get the chain in the welcome.
        let target_epoch = new_epoch.map_or(self.state.epoch, |(e, _)| e);
        let announce = match new_epoch {
            Some((e, _)) => self
                .epochs
                .range(..e)
                .next_back()
                .map(|(k, _)| *k)
                .ok_or(ProtoError::Missing)?,
            None => self.state.epoch,
        };
        let es = *self.epochs.get(&announce).ok_or(ProtoError::Missing)?;
        let generation = self
            .mine
            .as_ref()
            .map_or(0, |m| m.generation.wrapping_add(1));
        let members = self.state.members.len();
        if targets.len() > BUCKETS * ENTRIES_PER_BUCKET {
            return Err(ProtoError::Limit);
        }

        let cs0: Key = rng.array("group/chain-seed")?;
        let mut mac_keys = Vec::with_capacity(members);
        for _ in 0..members {
            mac_keys.push(rng.array::<32>("group/mac-key")?);
        }
        let kb: Key = rng.array("group/rekey-kb")?;

        // Header shared by the three units (bucket byte differs).
        let mut header = vec![0u8; COMMON];
        header[0] = VERSION;
        header[1] = EnvelopeKind::Group as u8;
        let v1 = legacy();
        header[2] = if v1 { SUB_REKEY_V1 } else { SUB_REKEY };
        header[4..8].copy_from_slice(&announce.to_be_bytes());
        rng.fill("group/nonce", &mut header[NONCE..ENC])?;
        header[ENC] = self.me;
        header[ENC + 1] = self.my_device;
        header[ENC + 2] = generation;
        header[ENC + 3] = if new_epoch.is_some() {
            REKEY_NEW_EPOCH
        } else {
            0
        };
        header[ENC + 4..ENC + 8].copy_from_slice(&target_epoch.to_be_bytes());
        let nonce: [u8; 32] = header[NONCE..ENC]
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        keystream(&es, &nonce, &mut header[ENC..COMMON]);

        let mut common_pt = Zeroizing::new(vec![0u8; COMMON_PT_LEN]);
        common_pt[..32].copy_from_slice(&cs0);
        common_pt[32] = generation;
        common_pt[33] = if new_epoch.is_some() {
            REKEY_NEW_EPOCH
        } else {
            0
        };
        match new_epoch {
            Some((e, s)) => {
                common_pt[34..66].copy_from_slice(&s);
                common_pt[66..70].copy_from_slice(&e.to_be_bytes());
            }
            None => rng.fill("group/rekey-fill", &mut common_pt[34..66])?,
        }
        common_pt[70..102].copy_from_slice(&self.state.hash());
        // The header's bucket byte is not covered: AD is the label and the
        // header with it zeroed.
        let common_ad = if v1 {
            header.clone()
        } else {
            [labels::WIRE_AD_REKEY_COMMON.as_bytes(), &header].concat()
        };
        let common = seal::seal(&SealKey::from_bytes(kb), &common_ad, &common_pt, rng)?;

        // Entries into buckets (overflow to the next bucket).
        let ctx = export_context(
            &self.state.group_id,
            target_epoch,
            self.me,
            self.my_device,
            generation,
        );
        let mut buckets: Vec<Vec<[u8; ENTRY_LEN]>> = vec![Vec::new(); BUCKETS];
        for t in targets {
            let (e, kexp) = t.session.export_for_peer(&ctx);
            let pad: [u8; 64] = kmac256(&kexp, b"", labels::GRP_REKEY_PAD);
            let mut ct = [0u8; 64];
            ct[..32].copy_from_slice(&kb);
            if t.member != self.me {
                let mk = mac_keys.get(t.member as usize).ok_or(ProtoError::Limit)?;
                ct[32..].copy_from_slice(mk);
            }
            for (c, p) in ct.iter_mut().zip(pad) {
                *c ^= p;
            }
            let chk: [u8; 12] = kmac256(&kexp, &ct, labels::GRP_REKEY_CHECK);
            let mut entry = [0u8; ENTRY_LEN];
            entry[..4].copy_from_slice(&e.to_be_bytes());
            entry[4..16].copy_from_slice(&chk);
            entry[16..].copy_from_slice(&ct);
            let mut b = bucket_of(&es, &t.device_id);
            while buckets[b].len() >= ENTRIES_PER_BUCKET {
                b = (b + 1) % BUCKETS;
            }
            buckets[b].push(entry);
        }

        let mut units = Vec::with_capacity(BUCKETS);
        for (b, entries) in buckets.iter_mut().enumerate() {
            // Shuffle so entry position reveals nothing about the target.
            for i in (1..entries.len()).rev() {
                let r: [u8; 4] = rng.array("group/shuffle")?;
                entries.swap(i, u32::from_be_bytes(r) as usize % (i + 1));
            }
            // Common blob, entries, random filler, all under the outer seal
            // (any member opens it; the server can't change or move a part).
            let mut payload = Zeroizing::new(vec![0u8; REKEY_PAYLOAD]);
            rng.fill("group/rekey-padding", &mut payload)?;
            payload[..COMMON_LEN].copy_from_slice(&common);
            for (i, e) in entries.iter().enumerate() {
                let at = COMMON_LEN + ENTRY_LEN * i;
                payload[at..at + ENTRY_LEN].copy_from_slice(e);
            }
            let mut hdr = header.clone();
            hdr[3] = b as u8;
            let unit = if v1 {
                let mut u = [hdr, payload.to_vec()].concat();
                let fill: Vec<u8> = (0..ENVELOPE_LEN - u.len()).map(|i| i as u8).collect();
                u.extend_from_slice(&fill);
                u
            } else {
                let ad = [labels::WIRE_AD_REKEY.as_bytes(), &hdr].concat();
                let sealed = seal::seal(&outer_key(&es), &ad, &payload, rng)?;
                [hdr, sealed].concat()
            };
            if unit.len() != ENVELOPE_LEN {
                return Err(ProtoError::Decode);
            }
            units.push(unit);
        }

        if let Some((e, s)) = new_epoch {
            self.epochs.insert(e, s);
        }
        self.mine = Some(MyChain {
            epoch: target_epoch,
            generation,
            seed: cs0,
            chain: Chain { cs: cs0, n: 0 },
            mac_keys,
            created_at: now,
        });
        Ok(units)
    }

    /// Read who sent a rekey unit (so the caller can pick the pairwise
    /// session) and which bucket it is.
    pub fn rekey_sender(&self, unit: &[u8]) -> Result<(RekeySender, u8)> {
        if unit.len() != ENVELOPE_LEN
            || unit[0] != VERSION
            || unit[1] != EnvelopeKind::Group as u8
            || !is_rekey(unit)
        {
            return Err(ProtoError::Decode);
        }
        let epoch = u32::from_be_bytes(unit[4..8].try_into().map_err(|_| ProtoError::Decode)?);
        let es = self.epochs.get(&epoch).ok_or(ProtoError::Missing)?;
        let nonce: [u8; 32] = unit[NONCE..ENC]
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        let mut h = unit[ENC..ENC + 8].to_vec();
        keystream(es, &nonce, &mut h);
        let target_epoch = u32::from_be_bytes(h[4..8].try_into().map_err(|_| ProtoError::Decode)?);
        let valid = if h[3] & REKEY_NEW_EPOCH != 0 {
            target_epoch > epoch
        } else {
            target_epoch == epoch
        };
        if !valid {
            return Err(ProtoError::Decode);
        }
        Ok((
            RekeySender {
                member: h[0],
                device: h[1],
                generation: h[2],
                epoch,
                target_epoch,
            },
            unit[3],
        ))
    }

    /// Apply a rekey unit using our pairwise session with its sender.
    pub fn apply_rekey(&mut self, unit: &[u8], session: &Session) -> Result<RekeyOutcome> {
        let (sender, _) = self.rekey_sender(unit)?;
        let mut header = unit[..COMMON].to_vec();
        header[3] = 0;
        // Version 1: no outer seal, no label on the common blob's AD.
        let v1 = unit[2] == SUB_REKEY_V1;
        let (common_ad, body): (Vec<u8>, Zeroizing<Vec<u8>>) = if v1 {
            (header.clone(), Zeroizing::new(unit[COMMON..].to_vec()))
        } else {
            let es = self.epochs.get(&sender.epoch).ok_or(ProtoError::Missing)?;
            let ad = [labels::WIRE_AD_REKEY.as_bytes(), &unit[..COMMON]].concat();
            (
                [labels::WIRE_AD_REKEY_COMMON.as_bytes(), &header].concat(),
                Zeroizing::new(seal::open(&outer_key(es), &ad, &unit[COMMON..])?),
            )
        };
        let candidates = [sender.target_epoch];
        for i in 0..ENTRIES_PER_BUCKET {
            let at = COMMON_LEN + ENTRY_LEN * i;
            let entry = &body[at..at + ENTRY_LEN];
            let e = u32::from_be_bytes(entry[..4].try_into().map_err(|_| ProtoError::Decode)?);
            for target_epoch in &candidates {
                let ctx = export_context(
                    &self.state.group_id,
                    *target_epoch,
                    sender.member,
                    sender.device,
                    sender.generation,
                );
                let Some(kexp) = session.export_from_peer(e, &ctx) else {
                    continue;
                };
                let chk: [u8; 12] = kmac256(&kexp, &entry[16..], labels::GRP_REKEY_CHECK);
                if !bool::from(chk.ct_eq(&entry[4..16])) {
                    continue;
                }
                let pad: [u8; 64] = kmac256(&kexp, b"", labels::GRP_REKEY_PAD);
                let mut pt = Zeroizing::new([0u8; 64]);
                for (j, (c, p)) in entry[16..].iter().zip(pad).enumerate() {
                    pt[j] = c ^ p;
                }
                let kb: Key = pt[..32].try_into().map_err(|_| ProtoError::Decode)?;
                let mac_key: Key = pt[32..].try_into().map_err(|_| ProtoError::Decode)?;
                let common = Zeroizing::new(seal::open(
                    &SealKey::from_bytes(kb),
                    &common_ad,
                    &body[..COMMON_LEN],
                )?);
                let cs0: Key = common[..32].try_into().map_err(|_| ProtoError::Decode)?;
                if common[32] != sender.generation {
                    return Err(ProtoError::Decode);
                }
                let new_epoch = if common[33] & REKEY_NEW_EPOCH != 0 {
                    let s: Key = common[34..66].try_into().map_err(|_| ProtoError::Decode)?;
                    let e = u32::from_be_bytes(
                        common[66..70].try_into().map_err(|_| ProtoError::Decode)?,
                    );
                    if e != *target_epoch {
                        return Err(ProtoError::Decode);
                    }
                    self.epochs.insert(e, s);
                    Some(e)
                } else {
                    None
                };
                self.recv.insert(
                    (sender.member, sender.device, sender.generation),
                    RecvChain {
                        epoch: *target_epoch,
                        chain: Chain { cs: cs0, n: 0 },
                        skipped: BTreeMap::new(),
                        mac_key,
                    },
                );
                // Older generations of this sender stay for late messages
                // until the next rotation after this one.
                let keep = sender.generation.wrapping_sub(1);
                self.recv.retain(|(m, d, g), _| {
                    !(*m == sender.member && *d == sender.device)
                        || *g == sender.generation
                        || *g == keep
                });
                return Ok(RekeyOutcome::Installed { new_epoch });
            }
        }
        Ok(RekeyOutcome::NotForUs)
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Serialize for sealed local storage (holds secrets).
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1)
            .bytes(&self.state.encode())
            .u8(self.me)
            .u8(self.my_device);
        w.u8(self.epochs.len() as u8);
        for (e, s) in &self.epochs {
            w.u32(*e).fixed(s);
        }
        match &self.mine {
            Some(m) => {
                w.u8(1)
                    .u32(m.epoch)
                    .u8(m.generation)
                    .fixed(&m.seed)
                    .fixed(&m.chain.cs)
                    .u32(m.chain.n)
                    .u64(m.created_at);
                w.u8(m.mac_keys.len() as u8);
                for k in &m.mac_keys {
                    w.fixed(k);
                }
            }
            None => {
                w.u8(0);
            }
        }
        w.u16(self.recv.len() as u16);
        for ((m, d, g), c) in &self.recv {
            w.u8(*m)
                .u8(*d)
                .u8(*g)
                .u32(c.epoch)
                .fixed(&c.chain.cs)
                .u32(c.chain.n)
                .fixed(&c.mac_key);
            w.u16(c.skipped.len() as u16);
            for (n, k) in &c.skipped {
                w.u32(*n).fixed(k);
            }
        }
        for id in &self.frontier {
            w.fixed(id);
        }
        let recent: Vec<&MsgId> = self.seen.iter().rev().take(4096).collect();
        w.u16(recent.len() as u16);
        for id in recent.into_iter().rev() {
            w.fixed(id);
        }
        Zeroizing::new(w.finish())
    }

    /// This device's view of the group for another device of the same
    /// account (index `their_device` in our manifest): every epoch secret
    /// and chain it can read with, and our sending chain from where it is
    /// now as one it receives. It starts a sending chain of its own at its
    /// first send (`docs/06-multidevice.md` §5).
    pub fn hand_over(&self, their_device: u8) -> Result<Zeroizing<Vec<u8>>> {
        let mut g = Self::import(&self.export())?;
        if let Some(m) = g.mine.take() {
            g.recv.insert(
                (g.me, g.my_device, m.generation),
                RecvChain {
                    epoch: m.epoch,
                    chain: m.chain,
                    skipped: BTreeMap::new(),
                    mac_key: [0; 32],
                },
            );
        }
        g.my_device = their_device;
        Ok(g.export())
    }

    /// Inverse of [`Group::export`].
    pub fn import(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let state = GroupState::decode(r.bytes(64 * 1024)?)?;
        let (me, my_device) = (r.u8()?, r.u8()?);
        let mut epochs = BTreeMap::new();
        for _ in 0..r.u8()? {
            epochs.insert(r.u32()?, r.array()?);
        }
        let mut g = Self::with(state, me, my_device, epochs);
        if r.u8()? == 1 {
            let (epoch, generation, seed, cs, n, created_at) = (
                r.u32()?,
                r.u8()?,
                r.array()?,
                r.array()?,
                r.u32()?,
                r.u64()?,
            );
            let k = r.u8()? as usize;
            if k > MAX_MEMBERS {
                return Err(ProtoError::Decode);
            }
            let mac_keys = (0..k).map(|_| r.array()).collect::<Result<Vec<Key>>>()?;
            g.mine = Some(MyChain {
                epoch,
                generation,
                seed,
                chain: Chain { cs, n },
                mac_keys,
                created_at,
            });
        }
        for _ in 0..r.u16()? {
            let key = (r.u8()?, r.u8()?, r.u8()?);
            let (epoch, cs, n, mac_key) = (r.u32()?, r.array()?, r.u32()?, r.array()?);
            let mut skipped = BTreeMap::new();
            let k = r.u16()?;
            if u32::from(k) > MAX_SKIP {
                return Err(ProtoError::Decode);
            }
            for _ in 0..k {
                skipped.insert(r.u32()?, r.array()?);
            }
            g.recv.insert(
                key,
                RecvChain {
                    epoch,
                    chain: Chain { cs, n },
                    skipped,
                    mac_key,
                },
            );
        }
        for i in 0..MAX_MEMBERS {
            g.frontier[i] = r.array()?;
        }
        for _ in 0..r.u16()? {
            let id = r.array()?;
            g.remember(id);
        }
        r.end()?;
        Ok(g)
    }

    /// Current epoch number.
    pub fn epoch(&self) -> u32 {
        self.state.epoch
    }

    /// Epochs we hold secrets for.
    pub fn epochs(&self) -> Vec<u32> {
        self.epochs.keys().copied().collect()
    }

    // ------------------------------------------------------------------
    // Joining
    // ------------------------------------------------------------------

    /// Welcome for a new member (sent over the pairwise session after the
    /// state update that adds them and the new epoch): the state and the
    /// current epoch secret. Earlier epochs are never shared.
    /// It also carries our current chain (seed and the MAC key for the
    /// joiner), because the rekey that started the epoch was announced under
    /// the previous epoch, which the joiner must not get.
    pub fn welcome(&self, joiner: u8) -> Result<Zeroizing<Vec<u8>>> {
        let mine = self
            .mine
            .as_ref()
            .filter(|m| m.epoch == self.state.epoch)
            .ok_or(ProtoError::NoSession)?;
        let mac = mine
            .mac_keys
            .get(joiner as usize)
            .ok_or(ProtoError::Limit)?;
        let mut w = Writer::new();
        w.u8(1)
            .bytes(&self.state.encode())
            .u32(self.state.epoch)
            .fixed(&self.epoch_secret()?);
        w.u8(self.me)
            .u8(self.my_device)
            .u8(mine.generation)
            .fixed(&mine.seed)
            .fixed(mac);
        Ok(Zeroizing::new(w.finish()))
    }

    /// Join from a welcome.
    pub fn join(welcome: &[u8], my_root: &[u8; 64], my_device: u8) -> Result<Self> {
        let mut r = Reader::new(welcome);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let state = GroupState::decode(r.bytes(64 * 1024)?)?;
        let e = r.u32()?;
        let es: Key = r.array()?;
        let (am, ad, ag) = (r.u8()?, r.u8()?, r.u8()?);
        let seed: Key = r.array()?;
        let mac_key: Key = r.array()?;
        r.end()?;
        if e != state.epoch {
            return Err(ProtoError::Decode);
        }
        let me = state.index_of(my_root).ok_or(ProtoError::NoSession)?;
        let mut g = Self::with(state, me, my_device, BTreeMap::from([(e, es)]));
        g.recv.insert(
            (am, ad, ag),
            RecvChain {
                epoch: e,
                chain: Chain { cs: seed, n: 0 },
                skipped: BTreeMap::new(),
                mac_key,
            },
        );
        Ok(g)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn state_chain_and_admin_rules() {
        let mut rng = HedgedRng::new().unwrap();
        let mut g = Group::create("Book club", [1; 64], [9; 16], 100, &mut rng).unwrap();
        let s1 = g
            .state
            .child(|s| {
                s.add([2; 64], false, 200).unwrap();
            })
            .unwrap();
        assert!(g.state.accepts(&s1, 0), "admin adds");
        assert!(!g.state.accepts(&s1, 1), "non-member cannot");
        g.apply_state(s1.clone()).unwrap();
        // Member 1 leaving is allowed; member 1 renaming is not.
        let leave = s1.child(|s| s.remove(1));
        assert!(s1.accepts(&leave.unwrap(), 1));
        let rename = s1.child(|s| s.name = "Mine now".into()).unwrap();
        assert!(!s1.accepts(&rename, 1));
        // A member may change its own root (new recovery words), and only
        // its own; nothing else may change with it.
        let reroot = s1.child(|s| s.members[1].root = [4; 64]).unwrap();
        assert_eq!(s1.root_change(&reroot), Some((1, [2; 64], [4; 64])));
        assert!(s1.accepts(&reroot, 1));
        let theirs = s1.child(|s| s.members[0].root = [4; 64]).unwrap();
        assert!(!s1.accepts(&theirs, 1), "not someone else's");
        let more = s1
            .child(|s| {
                s.members[1].root = [4; 64];
                s.members[1].admin = true;
            })
            .unwrap();
        assert_eq!(s1.root_change(&more), None);
        assert!(!s1.accepts(&more, 1), "no promotion with it");
        // Wrong parent is rejected.
        let mut orphan = rename.clone();
        orphan.parent = [7; 32];
        assert!(!s1.accepts(&orphan, 0));
        // Last admin leaves: the longest-standing member is promoted.
        let s2 = s1.child(|s| s.remove(0)).unwrap();
        assert!(s2.members[1].admin, "promoted");
        assert!(!s2.members[0].active);
        assert_eq!(s2.index_of(&[1; 64]), None);
        // A joiner reuses the tombstone slot.
        let s3 = s2
            .child(|s| assert_eq!(s.add([3; 64], false, 300).unwrap(), 0))
            .unwrap();
        assert_eq!(s3.index_of(&[3; 64]), Some(0));
        assert_eq!(GroupState::decode(&s2.encode()).unwrap(), s2);
        assert_ne!(s1.hash(), s2.hash());
        // A move: version 3, earlier days stay on the old host.
        let moved = s2
            .child(|s| {
                s.prev_host = s.host;
                s.host = [8; 16];
                s.host_since = 20_001;
            })
            .unwrap();
        assert_eq!(moved.encode()[0], 3);
        assert_eq!(GroupState::decode(&moved.encode()).unwrap(), moved);
        assert_eq!(moved.host_for(20_000), [9; 16]);
        assert_eq!(moved.host_for(20_001), [8; 16]);
        assert_eq!(s2.encode()[0], 1, "an unmoved group keeps version 1");
    }

    fn pair(rng: &mut HedgedRng) -> (Session, Session) {
        use crate::ratchet::{InitialDh, Role, SessionInit};
        use enclave_crypto::kem::{MlKemSecret, X448Secret};
        let sk: [u8; 64] = rng.array("test").unwrap();
        let (spk, spk_pub) = X448Secret::generate(rng).unwrap();
        let (auth_sk, auth_pk) = MlKemSecret::generate(rng).unwrap();
        let (b_sk, b_pk) = MlKemSecret::generate(rng).unwrap();
        let init = |role, initial_dh, my_pq, peer_pq| SessionInit {
            sk: Zeroizing::new(sk),
            role,
            initial_dh,
            my_pq,
            peer_pq,
            three_kem: true,
            braid_to: None,
        };
        let a = Session::new(
            init(
                Role::Initiator,
                InitialDh::Initiator(spk_pub),
                (0, auth_sk, auth_pk.clone()),
                None,
            ),
            rng,
        )
        .unwrap();
        let b = Session::new(
            init(
                Role::Responder,
                InitialDh::Responder(spk),
                (1, b_sk, b_pk),
                Some((0, auth_pk)),
            ),
            rng,
        )
        .unwrap();
        (a, b)
    }

    /// Units written before the label prefixes and the rekey unit's outer
    /// seal (subkinds 0 and 1) still open; the outer seal catches a unit
    /// the server changed.
    #[test]
    fn old_formats_still_open() {
        let mut rng = HedgedRng::new().unwrap();
        let (s_ab, s_ba) = pair(&mut rng);
        let mut a = Group::create("G", [1; 64], [9; 16], 100, &mut rng).unwrap();
        let st = a
            .state
            .child(|s| {
                s.add([2; 64], false, 100).unwrap();
            })
            .unwrap();
        a.apply_state(st).unwrap();
        a.rotate(&[], None, 100, &mut rng).unwrap();
        let mut b = Group::join(&a.welcome(1).unwrap(), &[2; 64], 0).unwrap();
        let target = |session| RekeyTarget {
            member: 0,
            device: 0,
            device_id: [0xa0; 16],
            session,
        };
        for v1 in [true, false] {
            LEGACY.with(|l| l.set(v1));
            let units = b.rotate(&[target(&s_ba)], None, 100, &mut rng).unwrap();
            assert!(units.iter().all(|u| is_rekey(u)));
            assert_eq!(units[0][2], if v1 { SUB_REKEY_V1 } else { SUB_REKEY });
            if !v1 {
                // The server changes a byte of the sealed part: refused.
                let mut bad = units.clone();
                for u in &mut bad {
                    u[COMMON + 500] ^= 1;
                }
                assert!(bad.iter().all(|u| a.apply_rekey(u, &s_ab).is_err()));
            }
            let got = units
                .iter()
                .map(|u| a.apply_rekey(u, &s_ab).unwrap())
                .find(|o| matches!(o, RekeyOutcome::Installed { .. }));
            assert!(got.is_some(), "v1 {v1}");
            let unit = b.seal(b"hello", 0, &mut rng).unwrap();
            assert!(!is_rekey(&unit));
            assert_eq!(a.open(&unit).unwrap().content, b"hello");
        }
        LEGACY.with(|l| l.set(false));
    }
}
