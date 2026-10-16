//! Groups in the client (`docs/07-groups.md`).
//!
//! The crypto lives in `enclave_proto::group`; this module moves it over
//! the network. The creator sends each member a welcome and the members'
//! contact cards over their pairwise sessions. Members who are not contacts
//! reach each other through group introductions, which are accepted
//! automatically. Each sync polls, for every held epoch and for today and
//! yesterday, the group mailbox and the three rekey buckets. A sender
//! rotates before its first send, whenever its chain is due, and whenever a
//! member it has not yet keyed becomes reachable.

use super::search::Place;
use super::{Client, ContactState, Event, sanitize_name};
use crate::card::ContactCard;
use crate::content::{Content, MAX_ATTACHMENT_REF, MAX_CARDS_PER_MESSAGE, MAX_REACTION, MAX_TEXT};
use crate::files::Attachment;
use crate::{CoreError, Result};
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::group::{
    BUCKETS, FLAG_RICH, FLAG_STATE_UPDATE, Group, GroupState, RekeyOutcome, RekeyTarget,
};
use enclave_rpc::api::{FLAG_GROUP, Status};
use enclave_store::Store;
use enclave_wire::{Op, RequestHeader};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const NS_GROUPS: &str = "groups";
/// Units held for later (unknown epoch or generation, sender not reachable yet).
const MAX_PENDING: usize = 256;
/// Seconds into a UTC day during which a shaped client still reads
/// yesterday's group message mailboxes (late messages of the day before).
pub(crate) const YESTERDAY_GRACE: u64 = 2 * 3600;

fn msg_ns(gid: &[u8; 32]) -> String {
    let mut s = String::from("gm/");
    for b in &gid[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A group as the UI sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    /// Group id.
    pub id: [u8; 32],
    /// Name.
    pub name: String,
    /// Active members other than us: root and display name.
    pub members: Vec<([u8; 64], String)>,
    /// We are an admin.
    pub admin: bool,
    /// Unread messages.
    pub unread: u32,
    /// We are no longer a member.
    pub left: bool,
    /// On the record (`group_record.rs`).
    pub on_record: bool,
    /// The server its mailboxes are on now (`group_hosts.rs`).
    pub host: [u8; 16],
    /// Its admins.
    pub admins: Vec<[u8; 64]>,
    /// Members whose change of recovery words is on hold here (their old
    /// roots; `Client::held_moves`).
    pub held_moves: Vec<[u8; 64]>,
    /// Some members seem to see a different group state or different
    /// messages (`group_check.rs`, RT-11): the chat says "Some people in
    /// this group may be seeing different messages."
    pub diverged: bool,
}

/// A reaction to a group message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReaction {
    /// Who (`None` = us).
    pub from: Option<[u8; 64]>,
    /// The emoji.
    pub emoji: String,
}

/// Most reactions kept on one group message (one per member).
const MAX_GROUP_REACTIONS: usize = 100;

/// A stored group message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    /// Position in the conversation.
    pub seq: u64,
    /// Sender root (`None` = us).
    pub from: Option<[u8; 64]>,
    /// Sender name at the time.
    pub from_name: String,
    /// Text.
    pub text: String,
    /// Local time.
    pub at: u64,
    /// Accepted by the group's server (ours only).
    pub delivered: bool,
    /// The poll this message opened, if any ([`Client::poll`]).
    pub poll: Option<[u8; 16]>,
    /// Id chosen by the sender (the poll id for a poll), so later messages
    /// can refer to it.
    pub id: [u8; 16],
    /// Reactions, at most one per member.
    pub reactions: Vec<GroupReaction>,
    /// Edited by its author.
    pub edited: bool,
    /// Deleted by its author.
    pub deleted: bool,
    /// Attached file (for a sticker, its pack).
    pub attachment: Option<Attachment>,
    /// A sticker: its index in the pack.
    pub sticker: Option<u8>,
    /// On the record (`group_record.rs`): `Some(true)` signed by its
    /// sender's device, `Some(false)` should have been and wasn't ("Not
    /// signed"), `None` off the record.
    pub signed: Option<bool>,
    /// A line the group itself shows, not a message anyone wrote: a
    /// membership change ("Ada added Ben.", `07-groups.md` §7.3), stored
    /// for every member as it is applied, with no way to hide it. `from`
    /// is who made the change.
    pub notice: bool,
    /// A voice note's words, transcribed on this device.
    pub transcript: String,
}

fn put_who(w: &mut Writer, who: &Option<[u8; 64]>) {
    match who {
        Some(r) => w.u8(1).fixed(r),
        None => w.u8(0),
    };
}

fn get_who(r: &mut Reader<'_>) -> enclave_proto::Result<Option<[u8; 64]>> {
    Ok(match r.u8()? {
        0 => None,
        1 => Some(r.array()?),
        _ => return Err(ProtoError::Decode),
    })
}

impl GroupMessage {
    /// What search looks at: the text and an attachment's name (nothing,
    /// once deleted).
    pub(crate) fn search_text(&self) -> String {
        if self.deleted {
            return String::new();
        }
        match &self.attachment {
            Some(a) if self.text.is_empty() => a.name.clone(),
            Some(a) => format!("{} {}", a.name, self.text),
            None => self.text.clone(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(9).u64(self.seq);
        put_who(&mut w, &self.from);
        w.bytes(self.from_name.as_bytes())
            .bytes(self.text.as_bytes())
            .u64(self.at)
            .u8(u8::from(self.delivered));
        match &self.poll {
            Some(p) => w.u8(1).fixed(p),
            None => w.u8(0),
        };
        w.fixed(&self.id);
        w.u8(self.reactions.len().min(MAX_GROUP_REACTIONS) as u8);
        for x in self.reactions.iter().take(MAX_GROUP_REACTIONS) {
            put_who(&mut w, &x.from);
            w.bytes(x.emoji.as_bytes());
        }
        w.u8(u8::from(self.edited)).u8(u8::from(self.deleted));
        w.bytes(
            &self
                .attachment
                .as_ref()
                .map(Attachment::encode)
                .unwrap_or_default(),
        );
        match self.sticker {
            Some(i) => w.u8(1).u8(i),
            None => w.u8(0),
        };
        w.u8(match self.signed {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        w.u8(u8::from(self.notice));
        w.bytes(self.transcript.as_bytes());
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if !(1..=9).contains(&version) {
            return Err(ProtoError::Decode);
        }
        let seq = r.u64()?;
        let from = get_who(&mut r)?;
        let s = |r: &mut Reader<'_>, max| {
            String::from_utf8(r.bytes(max)?.to_vec()).map_err(|_| ProtoError::Decode)
        };
        let from_name = s(&mut r, 1 << 16)?;
        let text = s(&mut r, 1 << 16)?;
        let at = r.u64()?;
        let delivered = r.u8()? == 1;
        let poll = if version >= 2 && r.u8()? == 1 {
            Some(r.array()?)
        } else {
            None
        };
        let id = if version >= 3 { r.array()? } else { [0; 16] };
        let mut reactions = Vec::new();
        let (mut edited, mut deleted) = (false, false);
        if version >= 4 {
            for _ in 0..usize::from(r.u8()?).min(MAX_GROUP_REACTIONS) {
                reactions.push(GroupReaction {
                    from: get_who(&mut r)?,
                    emoji: s(&mut r, MAX_REACTION)?,
                });
            }
            edited = r.u8()? == 1;
            deleted = r.u8()? == 1;
        }
        let attachment = if version >= 5 {
            let a = r.bytes(MAX_ATTACHMENT_REF)?;
            if a.is_empty() {
                None
            } else {
                Some(Attachment::decode(a)?)
            }
        } else {
            None
        };
        let sticker = if version >= 6 && r.u8()? == 1 {
            Some(r.u8()?)
        } else {
            None
        };
        let signed = match if version >= 7 { r.u8()? } else { 0 } {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(ProtoError::Decode),
        };
        let notice = version >= 8 && r.u8()? == 1;
        let transcript = if version >= 9 {
            String::from_utf8(r.bytes(super::messages::MAX_TRANSCRIPT)?.to_vec())
                .map_err(|_| ProtoError::Decode)?
        } else {
            String::new()
        };
        r.end()?;
        Ok(Self {
            seq,
            from,
            from_name,
            text,
            at,
            delivered,
            poll,
            id,
            reactions,
            edited,
            deleted,
            attachment,
            sticker,
            signed,
            notice,
            transcript,
        })
    }
}

/// Local state of one group.
pub(crate) struct GroupEntry {
    pub group: Group,
    /// Members' cards, by root.
    pub cards: BTreeMap<[u8; 64], ContactCard>,
    /// Poll cursors by mailbox address.
    pub cursors: HashMap<[u8; 32], u64>,
    /// Units we could not process yet.
    pub pending: Vec<Vec<u8>>,
    /// Members our current chain was distributed to.
    pub keyed: BTreeSet<[u8; 64]>,
    pub next_seq: u64,
    pub unread: u32,
    pub left: bool,
}

impl GroupEntry {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).bytes(&self.group.export());
        w.u16(self.cards.len() as u16);
        for c in self.cards.values() {
            w.bytes(&c.encode());
        }
        w.u16(self.cursors.len() as u16);
        for (a, c) in &self.cursors {
            w.fixed(a).u64(*c);
        }
        w.u16(self.pending.len() as u16);
        for u in &self.pending {
            w.bytes(u);
        }
        w.u16(self.keyed.len() as u16);
        for r in &self.keyed {
            w.fixed(r);
        }
        w.u64(self.next_seq)
            .u32(self.unread)
            .u8(u8::from(self.left));
        w.finish()
    }

    pub(crate) fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let group = Group::import(r.bytes(1 << 22)?)?;
        let mut cards = BTreeMap::new();
        for _ in 0..r.u16()? {
            let c = ContactCard::decode(r.bytes(crate::content::MAX_CARD)?)
                .map_err(|_| ProtoError::Decode)?;
            cards.insert(c.root, c);
        }
        let mut cursors = HashMap::new();
        for _ in 0..r.u16()? {
            cursors.insert(r.array()?, r.u64()?);
        }
        let mut pending = Vec::new();
        for _ in 0..r.u16()? {
            pending.push(r.bytes(enclave_wire::ENVELOPE_LEN)?.to_vec());
        }
        let mut keyed = BTreeSet::new();
        for _ in 0..r.u16()? {
            keyed.insert(r.array()?);
        }
        let e = Self {
            group,
            cards,
            cursors,
            pending,
            keyed,
            next_seq: r.u64()?,
            unread: r.u32()?,
            left: r.u8()? == 1,
        };
        r.end()?;
        Ok(e)
    }
}

/// Load every group from the store.
pub(crate) fn load(store: &Store) -> Result<BTreeMap<[u8; 32], GroupEntry>> {
    let mut out = BTreeMap::new();
    for (k, v) in store.scan(NS_GROUPS)? {
        let id: [u8; 32] = k.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
        out.insert(id, GroupEntry::decode(&v)?);
    }
    Ok(out)
}

pub(crate) fn day(now: u64) -> u32 {
    (now / 86_400) as u32
}

impl Client {
    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// All groups.
    pub fn groups(&self) -> Vec<GroupInfo> {
        let me = self.account.root_public.0;
        self.groups
            .values()
            .map(|e| {
                let st = &e.group.state;
                GroupInfo {
                    id: st.group_id,
                    name: st.name.clone(),
                    members: st
                        .active()
                        .filter(|(_, m)| m.root != me)
                        .map(|(_, m)| (m.root, self.member_name(e, &m.root)))
                        .collect(),
                    admin: st.active().any(|(_, m)| m.root == me && m.admin),
                    unread: e.unread,
                    left: e.left,
                    on_record: st.on_record,
                    host: st.host_for(day(self.now())),
                    admins: st
                        .active()
                        .filter(|(_, m)| m.admin)
                        .map(|(_, m)| m.root)
                        .collect(),
                    held_moves: self.held_moves(&st.group_id),
                    diverged: self.group_diverged(&st.group_id),
                }
            })
            .collect()
    }

    /// Messages of a group, oldest first.
    pub fn group_messages(&self, gid: &[u8; 32]) -> Result<Vec<GroupMessage>> {
        let mut v: Vec<GroupMessage> = self
            .store
            .scan(&msg_ns(gid))?
            .into_iter()
            .filter_map(|(_, b)| GroupMessage::decode(&b).ok())
            .collect();
        v.sort_by_key(|m| m.seq);
        Ok(v)
    }

    /// The group message at `seq`, if there is one.
    pub(crate) fn find_group_message(
        &self,
        gid: &[u8; 32],
        seq: u64,
    ) -> Result<Option<GroupMessage>> {
        Ok(self
            .store
            .get(&msg_ns(gid), &seq.to_be_bytes())?
            .and_then(|b| GroupMessage::decode(&b).ok()))
    }

    /// Mark a group as read.
    pub fn mark_group_read(&mut self, gid: &[u8; 32]) -> Result<()> {
        if let Some(e) = self.groups.get_mut(gid) {
            e.unread = 0;
        }
        self.save_group(gid)
    }

    pub(crate) fn member_name(&self, e: &GroupEntry, root: &[u8; 64]) -> String {
        self.contacts
            .get(root)
            .map(|c| c.name.clone())
            .or_else(|| e.cards.get(root).map(|c| sanitize_name(&c.name)))
            .unwrap_or_else(|| "Unknown".into())
    }

    pub(crate) fn is_group_member(&self, gid: &[u8; 32], root: &[u8; 64]) -> bool {
        self.groups
            .get(gid)
            .is_some_and(|e| !e.left && e.group.state.index_of(root).is_some())
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Create a group with some of our contacts. Each must have accepted us
    /// and shared their card.
    pub async fn create_group(&mut self, name: &str, members: &[[u8; 64]]) -> Result<[u8; 32]> {
        if name.len() > crate::card::MAX_NAME
            || members.len() + 1 > enclave_proto::group::MAX_MEMBERS
        {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        let me = self.account.root_public.0;
        let mut cards = BTreeMap::from([(me, self.card())]);
        for r in members {
            let c = self.contacts.get(r).ok_or(CoreError::NotFound)?;
            if c.state != ContactState::Accepted {
                return Err(CoreError::NotAccepted);
            }
            cards.insert(*r, c.card.clone().ok_or(CoreError::NotFound)?);
        }
        let mut group = Group::create(name, me, self.profile.server, now, &mut self.rng)?;
        group.my_device = self.my_device_index();
        let st = group.state.child(|s| {
            for r in members {
                let _ = s.add(*r, false, now);
            }
        })?;
        group.apply_state(st)?;
        // Our first chain: members get it in their welcome.
        group.rotate(&[], None, now, &mut self.rng)?;
        let gid = group.state.group_id;
        let keyed: BTreeSet<[u8; 64]> = members.iter().copied().collect();
        self.groups.insert(
            gid,
            GroupEntry {
                group,
                cards: cards.clone(),
                cursors: HashMap::new(),
                pending: Vec::new(),
                keyed,
                next_seq: 0,
                unread: 0,
                left: false,
            },
        );
        self.save_group(&gid)?;

        let encoded: Vec<Vec<u8>> = cards.values().map(ContactCard::encode).collect();
        for r in members {
            let welcome = {
                let e = self.groups.get(&gid).ok_or(CoreError::NotFound)?;
                let idx = e.group.state.index_of(r).ok_or(CoreError::NotFound)?;
                e.group.welcome(idx)?.to_vec()
            };
            self.send_content(r, &Content::GroupWelcome(welcome), now)
                .await?;
            for chunk in encoded.chunks(MAX_CARDS_PER_MESSAGE) {
                self.send_content(
                    r,
                    &Content::GroupCards {
                        group_id: gid,
                        cards: chunk.to_vec(),
                    },
                    now,
                )
                .await?;
            }
        }
        Ok(gid)
    }

    /// Check we may send to `gid` now, and rotate our sender chain first if
    /// it is due.
    pub(crate) async fn prepare_group_send(&mut self, gid: &[u8; 32], now: u64) -> Result<()> {
        self.prepare_group_post(gid, now, false).await
    }

    /// As [`Self::prepare_group_send`] for a vote, reaction, pin, call or
    /// the like, which every member may post in an announcement-only group.
    pub(crate) async fn prepare_group_reply(&mut self, gid: &[u8; 32], now: u64) -> Result<()> {
        self.prepare_group_post(gid, now, true).await
    }

    async fn prepare_group_post(&mut self, gid: &[u8; 32], now: u64, reply: bool) -> Result<()> {
        {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            if e.left {
                return Err(CoreError::NotAccepted);
            }
            if !reply
                && e.group.state.admins_only
                && !e
                    .group
                    .state
                    .members
                    .get(e.group.me as usize)
                    .is_some_and(|m| m.admin)
            {
                return Err(CoreError::NotAccepted);
            }
        }
        if self
            .groups
            .get(gid)
            .is_some_and(|e| e.group.needs_rotation(now))
        {
            self.rotate_group(gid, None, None, now).await?;
        }
        Ok(())
    }

    /// Send text to a group.
    pub async fn send_group_text(&mut self, gid: &[u8; 32], text: &str) -> Result<GroupMessage> {
        if text.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        let id: [u8; 16] = self.rng.array("core/group-msg-id")?;
        let mut msg = self.store_group_message(gid, id, None, text, now)?;
        let content = [&id[..], text.as_bytes()].concat();
        self.post_group(gid, &content, 0, now).await?;
        msg.delivered = true;
        self.put_group_message(gid, &msg)?;
        Ok(msg)
    }

    /// Remove a member (admins only): a new epoch the removed member never
    /// learns, then a state update in it.
    pub async fn remove_group_member(&mut self, gid: &[u8; 32], root: &[u8; 64]) -> Result<()> {
        let now = self.now();
        let (next, removed, prev) = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let idx = e.group.state.index_of(root).ok_or(CoreError::NotFound)?;
            let me = e.group.me;
            if !e
                .group
                .state
                .members
                .get(me as usize)
                .is_some_and(|m| m.admin)
            {
                return Err(CoreError::NotAccepted);
            }
            let (epoch, secret) = e.group.new_epoch(&mut self.rng)?;
            let next = e.group.state.child(|s| {
                s.remove(idx);
                s.epoch = epoch;
            })?;
            let prev = e.group.state.clone();
            e.group.apply_state(next.clone())?;
            (next, (epoch, secret), prev)
        };
        self.note_membership(gid, &prev, None, now)?;
        self.rotate_group(gid, Some(removed), Some(*root), now)
            .await?;
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        Ok(())
    }

    /// Add contacts to a group (admins only). A new epoch starts first, so
    /// the newcomers can't read anything sent before they joined; they get a
    /// welcome and every member's card, and existing members get theirs so
    /// strangers can introduce themselves.
    pub async fn add_group_members(&mut self, gid: &[u8; 32], roots: &[[u8; 64]]) -> Result<()> {
        let now = self.now();
        let mut new_cards = Vec::new();
        for r in roots {
            let c = self.contacts.get(r).ok_or(CoreError::NotFound)?;
            if c.state != ContactState::Accepted {
                return Err(CoreError::NotAccepted);
            }
            new_cards.push(c.card.clone().ok_or(CoreError::NotFound)?);
        }
        let (next, epoch, prev) = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let me = e.group.me;
            if e.left
                || !e
                    .group
                    .state
                    .members
                    .get(me as usize)
                    .is_some_and(|m| m.admin)
            {
                return Err(CoreError::NotAccepted);
            }
            let fresh: Vec<[u8; 64]> = roots
                .iter()
                .filter(|r| e.group.state.index_of(r).is_none())
                .copied()
                .collect();
            if fresh.is_empty() {
                return Ok(());
            }
            if e.group.state.active().count() + fresh.len() > enclave_proto::group::MAX_MEMBERS {
                return Err(CoreError::TooLong);
            }
            let (epoch, secret) = e.group.new_epoch(&mut self.rng)?;
            let next = e.group.state.child(|s| {
                for r in &fresh {
                    let _ = s.add(*r, false, now);
                }
                s.epoch = epoch;
            })?;
            let prev = e.group.state.clone();
            e.group.apply_state(next.clone())?;
            for c in &new_cards {
                e.cards.insert(c.root, c.clone());
            }
            (next, (epoch, secret), prev)
        };
        self.note_membership(gid, &prev, None, now)?;
        self.save_group(gid)?;
        let existing: Vec<[u8; 64]> = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            let me = self.account.root_public.0;
            e.group
                .state
                .active()
                .map(|(_, m)| m.root)
                .filter(|r| *r != me && !roots.contains(r))
                .collect()
        };
        self.rotate_group(gid, Some(epoch), None, now).await?;
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        // Newcomers: the welcome, then every card.
        let all: Vec<Vec<u8>> = self
            .groups
            .get(gid)
            .map(|e| e.cards.values().map(ContactCard::encode).collect())
            .unwrap_or_default();
        for r in roots {
            let welcome = {
                let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
                let idx = e.group.state.index_of(r).ok_or(CoreError::NotFound)?;
                e.group.welcome(idx)?.to_vec()
            };
            self.send_content(r, &Content::GroupWelcome(welcome), now)
                .await?;
            for chunk in all.chunks(MAX_CARDS_PER_MESSAGE) {
                self.send_content(
                    r,
                    &Content::GroupCards {
                        group_id: *gid,
                        cards: chunk.to_vec(),
                    },
                    now,
                )
                .await?;
            }
        }
        // Existing members: the newcomers' cards, so strangers can reach
        // each other. Members we can't reach learn them from the state and
        // a later message.
        let fresh: Vec<Vec<u8>> = new_cards.iter().map(ContactCard::encode).collect();
        for r in existing {
            if self.contacts.get(&r).is_some_and(|c| c.inbox.is_some()) {
                for chunk in fresh.chunks(MAX_CARDS_PER_MESSAGE) {
                    let _ = self
                        .send_content(
                            &r,
                            &Content::GroupCards {
                                group_id: *gid,
                                cards: chunk.to_vec(),
                            },
                            now,
                        )
                        .await;
                }
            }
        }
        Ok(())
    }

    /// Leave a group.
    pub async fn leave_group(&mut self, gid: &[u8; 32]) -> Result<()> {
        let now = self.now();
        let me = self.account.root_public.0;
        let next = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            let idx = e.group.state.index_of(&me).ok_or(CoreError::NotFound)?;
            e.group.state.child(|s| s.remove(idx))?
        };
        if self
            .groups
            .get(gid)
            .is_some_and(|e| e.group.needs_rotation(now))
        {
            self.rotate_group(gid, None, None, now).await?;
        }
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        if let Some(e) = self.groups.get_mut(gid) {
            e.left = true;
        }
        self.save_group(gid)?;
        // Our links to it stop working with us gone.
        self.expire_invites(now).await
    }

    // ------------------------------------------------------------------
    // Network
    // ------------------------------------------------------------------

    pub(crate) async fn post_group(
        &mut self,
        gid: &[u8; 32],
        content: &[u8],
        flags: u8,
        now: u64,
    ) -> Result<()> {
        // A restore contacts still hold can't be read by them yet.
        if flags & FLAG_STATE_UPDATE == 0 {
            self.require_not_held()?;
            self.require_current()?;
        }
        // What members' notifications show (under the group's key for the
        // day; `notify.rs`).
        let preview = super::notify::group_preview(content, flags);
        let name = self.profile.name.clone();
        let today = day(now);
        // On the record, signed (`group_record.rs`).
        let (content, flags) = self.sign_group(gid, content, flags)?;
        let (unit, host, addr, secret) = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let unit = e.group.seal_with(
                &content,
                flags,
                preview.as_deref().map(|p| (name.as_str(), p, today)),
                &mut self.rng,
            )?;
            let epoch = e.group.epoch();
            let addr = e.group.mailbox(day(now))?;
            let secret = e.group.mailbox_secret(epoch, &addr)?;
            (unit, e.group.state.host_for(day(now)), addr, secret)
        };
        // The chain advanced: persist before the unit leaves.
        self.save_group(gid)?;
        // Our other devices show it once we vouch for its id.
        if let Some(e) = self.groups.get(gid) {
            let id = e.group.frontier()[e.group.me as usize];
            self.queue_group_sent(gid, id)?;
        }
        let h = RequestHeader {
            op: Op::Write,
            flags: FLAG_GROUP,
            mailbox: addr,
            token: secret,
        };
        self.rpc.write(&host, h, &unit, now, &mut self.rng).await
    }

    /// Rotate our chain for every reachable member device and post the
    /// three rekey units.
    pub(crate) async fn rotate_group(
        &mut self,
        gid: &[u8; 32],
        new_epoch: Option<(u32, [u8; 32])>,
        exclude: Option<[u8; 64]>,
        now: u64,
    ) -> Result<()> {
        self.pre_rekey_step(gid, now).await?;
        self.rotate_group_now(gid, new_epoch, exclude, now).await?;
        self.refresh_pq_marks(gid)
    }

    /// The rotation a completed pre-rekey PQ step asks for (`group_pq.rs`).
    pub(crate) async fn rotate_group_after_pre_step(
        &mut self,
        gid: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        self.rotate_group_now(gid, None, None, now).await
    }

    async fn rotate_group_now(
        &mut self,
        gid: &[u8; 32],
        new_epoch: Option<(u32, [u8; 32])>,
        exclude: Option<[u8; 64]>,
        now: u64,
    ) -> Result<()> {
        let own_quiet: Vec<[u8; 16]> = self
            .own_devices()
            .into_iter()
            .filter(|d| d.inactive)
            .map(|d| d.id)
            .collect();
        let (units, host, keyed) = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let me = e.group.me;
            let mut targets = Vec::new();
            let mut keyed = BTreeSet::new();
            // Our other active devices read what this one sends.
            let own = self.account.root_public.0;
            let quiet: Vec<[u8; 16]> = own_quiet.clone();
            for (di, dev) in self.manifest.devices.iter().enumerate() {
                if di as u8 == e.group.my_device || quiet.contains(&dev.id) {
                    continue;
                }
                if let Some(s) = self.sessions.get(&(own, dev.id)) {
                    targets.push(RekeyTarget {
                        member: me,
                        device: di as u8,
                        device_id: dev.id,
                        session: s,
                    });
                }
            }
            for (m, member) in e.group.state.active() {
                if m == me || Some(member.root) == exclude {
                    continue;
                }
                let root = super::migrate::resolve(&self.store, &member.root);
                let Some(c) = self.contacts.get(&root) else {
                    continue;
                };
                for (di, dev) in c.manifest.devices.iter().enumerate() {
                    if let Some(s) = self.sessions.get(&(root, dev.id)) {
                        targets.push(RekeyTarget {
                            member: m,
                            device: di as u8,
                            device_id: dev.id,
                            session: s,
                        });
                        keyed.insert(member.root);
                    }
                }
            }
            let units = e.group.rotate(&targets, new_epoch, now, &mut self.rng)?;
            (units, e.group.state.host_for(day(now)), keyed)
        };
        if let Some(e) = self.groups.get_mut(gid) {
            e.keyed = keyed;
        }
        self.save_group(gid)?;
        for (b, unit) in units.iter().enumerate() {
            let announce = u32::from_be_bytes([unit[4], unit[5], unit[6], unit[7]]);
            let (addr, secret) = {
                let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
                let addr = e.group.rekey_mailbox(announce, day(now), b as u8)?;
                (addr, e.group.mailbox_secret(announce, &addr)?)
            };
            let h = RequestHeader {
                op: Op::Write,
                flags: FLAG_GROUP,
                mailbox: addr,
                token: secret,
            };
            self.rpc.call_ok(&host, h, unit, now, &mut self.rng).await?;
        }
        Ok(())
    }

    /// Poll a group mailbox; a mailbox nobody has written to yet is empty.
    async fn poll_group(
        &mut self,
        gid: &[u8; 32],
        host: [u8; 16],
        addr: [u8; 32],
        secret: [u8; 32],
        now: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let cursor = self
            .groups
            .get(gid)
            .and_then(|e| e.cursors.get(&addr).copied())
            .unwrap_or(0);
        match self
            .rpc
            .poll(
                &host,
                addr,
                enclave_rpc::api::read_credential(&secret),
                cursor,
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(items) => {
                if let (Some(last), Some(e)) = (items.last(), self.groups.get_mut(gid)) {
                    e.cursors.insert(addr, last.cursor);
                }
                Ok(items.into_iter().map(|p| p.envelope).collect())
            }
            Err(CoreError::Server(Status::Denied | Status::NotFound)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Everything group-related a sync does.
    pub(crate) async fn sync_groups(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let ids: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(k, _)| *k)
            .collect();
        for gid in ids {
            events.append(&mut self.sync_group(&gid, now).await?);
        }
        Ok(events)
    }

    /// Read one group's mailboxes (every held epoch, today and yesterday),
    /// apply what arrived, and key members who became reachable.
    pub(crate) async fn sync_group(&mut self, gid: &[u8; 32], now: u64) -> Result<Vec<Event>> {
        self.sync_group_with(gid, now, false).await
    }

    /// Read one group as a shaped client does (`Client::sync_round_every`,
    /// `docs/09-transport.md` §6.7): today's mailboxes of every held epoch
    /// (the message mailbox and its rekey buckets), and yesterday's only
    /// during the first [`YESTERDAY_GRACE`] seconds of the day, for what
    /// arrived late the day before. `shaped == false`: both days always.
    pub(crate) async fn sync_group_with(
        &mut self,
        gid: &[u8; 32],
        now: u64,
        shaped: bool,
    ) -> Result<Vec<Event>> {
        let gid = *gid;
        let mut events = Vec::new();
        self.connect_members(&gid).await;

        let polls = {
            let e = self.groups.get(&gid).ok_or(CoreError::NotFound)?;
            let mut polls = Vec::new();
            let today = day(now);
            let days: &[u32] = if shaped && now % 86_400 >= YESTERDAY_GRACE {
                &[today]
            } else {
                &[today.saturating_sub(1), today]
            };
            for epoch in e.group.epochs() {
                for &d in days {
                    // A day's mailboxes are where the group was that day.
                    let host = e.group.state.host_for(d);
                    for b in 0..BUCKETS as u8 {
                        let addr = e.group.rekey_mailbox(epoch, d, b)?;
                        polls.push((host, addr, e.group.mailbox_secret(epoch, &addr)?));
                    }
                    let addr = e
                        .group
                        .mailboxes(d)
                        .into_iter()
                        .find(|(x, _)| *x == epoch)
                        .map(|(_, a)| a);
                    if let Some(addr) = addr {
                        polls.push((host, addr, e.group.mailbox_secret(epoch, &addr)?));
                    }
                }
            }
            polls
        };
        // Each poll takes its slot like any other: how many a group needs
        // depends on the epochs held, but a burst of them every few
        // seconds would cost more than the whole Foreground budget.
        let mut units = Vec::new();
        for (host, addr, secret) in polls {
            units.extend(self.poll_group(&gid, host, addr, secret, now).await?);
        }
        // Forget cursors of mailboxes we no longer poll.
        if let Some(e) = self.groups.get_mut(&gid) {
            let live: BTreeSet<[u8; 32]> = e
                .group
                .epochs()
                .into_iter()
                .flat_map(|ep| {
                    [day(now).saturating_sub(1), day(now)]
                        .into_iter()
                        .flat_map(move |d| (0..=BUCKETS as u8).map(move |b| (ep, d, b)))
                })
                .filter_map(|(ep, d, b)| {
                    if (b as usize) < BUCKETS {
                        e.group.rekey_mailbox(ep, d, b).ok()
                    } else {
                        e.group
                            .mailboxes(d)
                            .into_iter()
                            .find(|(x, _)| *x == ep)
                            .map(|(_, a)| a)
                    }
                })
                .collect();
            e.cursors.retain(|a, _| live.contains(a));
        }
        if let Some(e) = self.groups.get_mut(&gid) {
            units.append(&mut e.pending);
        }
        // Rekeys first (they may unlock messages in the same batch), and
        // a second pass for anything a rekey unlocked.
        let mut rest = units;
        for _ in 0..2 {
            let mut held = Vec::new();
            rest.sort_by_key(|u| !enclave_proto::group::is_rekey(u)); // rekeys first
            for u in rest {
                match self.process_group_unit(&gid, &u, now) {
                    Ok(Some(ev)) => events.push(ev),
                    Ok(None) => {}
                    Err(CoreError::Proto(ProtoError::Missing)) => held.push(u),
                    Err(_) => {}
                }
            }
            rest = held;
        }
        if let Some(e) = self.groups.get_mut(&gid) {
            rest.truncate(MAX_PENDING);
            e.pending = rest;
        }
        events.append(&mut self.group_events);
        self.save_group(&gid)?;

        // Key members that became reachable since our last rotation.
        let due = {
            let e = self.groups.get(&gid).ok_or(CoreError::NotFound)?;
            let me = e.group.me;
            !e.left
                && e.group.state.active().any(|(m, member)| {
                    m != me && !e.keyed.contains(&member.root) && {
                        let root = super::migrate::resolve(&self.store, &member.root);
                        self.contacts.get(&root).is_some_and(|c| {
                            c.manifest
                                .devices
                                .iter()
                                .any(|d| self.sessions.contains_key(&(root, d.id)))
                        })
                    }
                })
        };
        if due
            && !self
                .groups
                .get(&gid)
                .is_some_and(|e| e.group.needs_rotation(now))
        {
            self.rotate_group(&gid, None, None, now).await?;
        }
        Ok(events)
    }

    /// Reach members we have no session with (group introduction), and
    /// accept pending requests from members.
    async fn connect_members(&mut self, gid: &[u8; 32]) {
        let me = self.account.root_public.0;
        let Some(e) = self.groups.get(gid) else {
            return;
        };
        let cards: Vec<ContactCard> = e
            .group
            .state
            .active()
            .filter(|(_, m)| m.root != me)
            .filter_map(|(_, m)| e.cards.get(&m.root).cloned())
            .collect();
        for card in cards {
            match self.contacts.get(&card.root).map(|c| c.state) {
                None => {
                    let _ = self.add_contact_with(&card, "", Some(*gid), None).await;
                }
                Some(ContactState::Request) => {
                    let _ = self.accept_with(&card.root, Some(*gid)).await;
                }
                _ => {}
            }
        }
    }

    fn process_group_unit(
        &mut self,
        gid: &[u8; 32],
        unit: &[u8],
        now: u64,
    ) -> Result<Option<Event>> {
        if unit.len() != enclave_wire::ENVELOPE_LEN {
            return Ok(None);
        }
        if enclave_proto::group::is_rekey(unit) {
            let (sender, _) = self
                .groups
                .get(gid)
                .ok_or(CoreError::NotFound)?
                .group
                .rekey_sender(unit)?;
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let own = sender.member == e.group.me;
            if own && sender.device == e.group.my_device {
                return Ok(None);
            }
            let root = e
                .group
                .state
                .members
                .get(sender.member as usize)
                .map(|m| m.root)
                .ok_or(ProtoError::Decode)?;
            let root = super::migrate::resolve(&self.store, &root);
            // Another device of ours rotated: its chain comes over our
            // intra-account session.
            let dev_id = if own {
                self.manifest
                    .devices
                    .get(sender.device as usize)
                    .map(|d| d.id)
            } else {
                self.contacts
                    .get(&root)
                    .and_then(|c| c.manifest.devices.get(sender.device as usize))
                    .map(|d| d.id)
            }
            .ok_or(ProtoError::Missing)?;
            let root = if own {
                self.account.root_public.0
            } else {
                root
            };
            let session = self
                .sessions
                .get(&(root, dev_id))
                .ok_or(ProtoError::Missing)?;
            return match e.group.apply_rekey(unit, session)? {
                RekeyOutcome::Installed { .. } => Ok(None),
                RekeyOutcome::NotForUs => Ok(None),
            };
        }
        let msg = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            match e.group.open(unit) {
                Ok(m) => m,
                Err(ProtoError::Counter) => return Ok(None), // our own, or a replay
                Err(err) => return Err(err.into()),
            }
        };
        // From another device of ours: no MAC vouches for it (any member
        // holds our chain key), so it waits for own-device sync to confirm
        // its id (`07-groups.md` §3), then shows as our own.
        if msg.flags & enclave_proto::group::FLAG_EPHEMERAL != 0 {
            let root = self
                .groups
                .get(gid)
                .and_then(|e| e.group.state.members.get(msg.member as usize))
                .map(|m| self.current_root(&m.root));
            return Ok(root.and_then(|r| self.on_group_ephemeral(gid, &r, &msg.content, now)));
        }
        if msg.own_account && !self.own_group_confirmed(gid, &msg.id) {
            self.hold_own_group_message(gid, &msg)?;
            return Ok(None);
        }
        self.on_group_message(gid, msg, now)
    }

    /// A group message that opened (and, from another device of ours, was
    /// confirmed by it).
    pub(crate) fn on_group_message(
        &mut self,
        gid: &[u8; 32],
        msg: enclave_proto::group::GroupMessage,
        now: u64,
    ) -> Result<Option<Event>> {
        let (sender_root, prev_state) = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            let root = e
                .group
                .state
                .members
                .get(msg.member as usize)
                .map(|m| m.root)
                .ok_or(ProtoError::Decode)?;
            // A member who changed their recovery words, before their group
            // update arrived, is known here by the new root.
            (self.current_root(&root), e.group.state.clone())
        };
        // On the record: the sender device's signature (`group_record.rs`).
        let mut msg = msg;
        let signed = self.check_group_signature(&prev_state, &sender_root, &mut msg);
        if msg.flags & FLAG_STATE_UPDATE != 0 {
            let next = GroupState::decode(&msg.content)?;
            if !prev_state.accepts(&next, msg.member)
                || (prev_state.on_record && signed != Some(true))
                || !self.accepts_host_change(gid, &prev_state, &next, now)?
            {
                return Ok(None);
            }
            // Someone's root changes in place: only with their migration.
            if let Some((_, old, new)) = prev_state.root_change(&next) {
                let applied = self.on_group_root_change(gid, msg.member, next, &old, &new)?;
                return Ok(applied.then_some(Event::GroupChanged { group_id: *gid }));
            }
            let mode = (next.on_record != prev_state.on_record).then_some(next.on_record);
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            match e.group.apply_state(next) {
                Ok(()) => {}
                Err(ProtoError::NoSession) => e.left = true,
                Err(err) => return Err(err.into()),
            }
            self.note_group_state(gid)?;
            self.note_membership(gid, &prev_state, Some(sender_root), now)?;
            if let Some(on_record) = mode {
                return Ok(Some(Event::GroupModeChanged {
                    group_id: *gid,
                    on_record,
                    by: sender_root,
                }));
            }
            return Ok(Some(Event::GroupChanged { group_id: *gid }));
        }
        // Its state hash and frontier against ours (RT-11).
        let diverged = self.check_group_message(gid, &msg, now)?;
        // A message on the record without a good signature is shown
        // marked; one signed off the record shows as signed.
        self.group_unit_signed = match (prev_state.on_record, signed) {
            (true, s) => Some(s == Some(true)),
            (false, Some(true)) => Some(true),
            (false, _) => None,
        };
        let r = self.on_group_content(gid, &sender_root, msg, now);
        self.group_unit_signed = None;
        // The mark goes out with the rest of this group's events.
        self.group_events.extend(diverged);
        r
    }

    /// A group message's content (not a state update), its signature
    /// checked.
    fn on_group_content(
        &mut self,
        gid: &[u8; 32],
        sender_root: &[u8; 64],
        msg: enclave_proto::group::GroupMessage,
        now: u64,
    ) -> Result<Option<Event>> {
        let sender_root = *sender_root;
        if self.is_blocked(&sender_root) {
            return Ok(None); // their state updates still apply, above
        }
        // Announcement-only: from a member who isn't an admin only votes,
        // reactions, pins, calls and the like, never posts.
        let gated = self.groups.get(gid).is_some_and(|e| {
            e.group.state.admins_only
                && !e
                    .group
                    .state
                    .members
                    .get(msg.member as usize)
                    .is_some_and(|m| m.admin)
        });
        if gated
            && !(msg.flags & FLAG_RICH != 0
                && super::polls::Rich::decode(&msg.content).is_ok_and(|r| r.is_reply()))
        {
            return Ok(None);
        }
        if msg.flags & FLAG_RICH != 0 {
            let name = {
                let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
                self.member_name(e, &sender_root)
            };
            return self.on_group_rich(gid, &sender_root, name, &msg.content, now);
        }
        let (id, text) = msg
            .content
            .split_first_chunk::<16>()
            .ok_or(ProtoError::Decode)?;
        let id = *id;
        if self.group_messages(gid)?.iter().any(|m| m.id == id) {
            return Ok(None); // a duplicate
        }
        let text = String::from_utf8(text.to_vec()).map_err(|_| ProtoError::Decode)?;
        let name = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            self.member_name(e, &sender_root)
        };
        let m = self.store_group_message(gid, id, Some((sender_root, name)), &text, now)?;
        self.bump_group_unread(gid, &sender_root)?;
        Ok(Some(Event::GroupMessage {
            group_id: *gid,
            message: m,
        }))
    }

    // ------------------------------------------------------------------
    // Pairwise group content
    // ------------------------------------------------------------------

    /// A welcome from `from`, who must be an admin of the group it describes.
    pub(crate) fn on_group_welcome(
        &mut self,
        from: &[u8; 64],
        welcome: &[u8],
        _now: u64,
    ) -> Result<Option<Event>> {
        let me = self.account.root_public.0;
        let group = Group::join(welcome, &me, self.my_device_index())?;
        let st = &group.state;
        let from_admin = st
            .index_of(from)
            .and_then(|i| st.members.get(i as usize))
            .is_some_and(|m| m.admin);
        if !from_admin {
            return Ok(None);
        }
        let gid = st.group_id;
        if self.groups.contains_key(&gid) {
            return Ok(None);
        }
        let name = st.name.clone();
        let mut cards = BTreeMap::new();
        if let Some(c) = self.contacts.get(from).and_then(|c| c.card.clone()) {
            cards.insert(*from, c);
        }
        self.groups.insert(
            gid,
            GroupEntry {
                group,
                cards,
                cursors: HashMap::new(),
                pending: Vec::new(),
                keyed: BTreeSet::new(),
                next_seq: 0,
                unread: 0,
                left: false,
            },
        );
        self.save_group(&gid)?;
        Ok(Some(Event::GroupJoined {
            group_id: gid,
            name: sanitize_name(&name),
        }))
    }

    /// Member cards from a member of the group.
    pub(crate) fn on_group_cards(
        &mut self,
        from: &[u8; 64],
        gid: &[u8; 32],
        cards: &[Vec<u8>],
    ) -> Result<()> {
        let Some(e) = self.groups.get_mut(gid) else {
            return Ok(());
        };
        let Some(sender) = e.group.state.index_of(from) else {
            return Ok(());
        };
        // An admin's cards may arrive before the state update that adds
        // those members (the inbox is read before group mailboxes); keep
        // them. Introductions only ever go to active members.
        let from_admin = e
            .group
            .state
            .members
            .get(sender as usize)
            .is_some_and(|m| m.admin);
        for b in cards {
            if let Ok(c) = ContactCard::decode(b)
                && (from_admin || e.group.state.index_of(&c.root).is_some())
            {
                e.cards.entry(c.root).or_insert(c);
            }
        }
        self.save_group(gid)
    }

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    pub(crate) fn save_group(&mut self, gid: &[u8; 32]) -> Result<()> {
        let Some(e) = self.groups.get(gid) else {
            return Ok(());
        };
        let bytes = zeroize::Zeroizing::new(e.encode());
        self.store.put(NS_GROUPS, gid, &bytes, &mut self.rng)?;
        self.note_group_state(gid)
    }

    /// Save a changed group message.
    pub(crate) fn put_group_message(&mut self, gid: &[u8; 32], m: &GroupMessage) -> Result<()> {
        let old = self
            .store
            .get(&msg_ns(gid), &m.seq.to_be_bytes())?
            .and_then(|b| GroupMessage::decode(&b).ok())
            .map(|o| o.search_text())
            .unwrap_or_default();
        self.store.put(
            &msg_ns(gid),
            &m.seq.to_be_bytes(),
            &m.encode(),
            &mut self.rng,
        )?;
        self.index_message(
            super::search_index::Conv::Group(*gid),
            m.seq,
            (&old, None),
            (&m.search_text(), None),
        )
    }

    /// Someone else's message in `gid`: one more unread, and back from the
    /// archive. Ours, sent from another device of ours, is neither.
    pub(crate) fn bump_group_unread(&mut self, gid: &[u8; 32], from: &[u8; 64]) -> Result<()> {
        if *from == self.account.root_public.0 {
            return Ok(());
        }
        if let Some(e) = self.groups.get_mut(gid) {
            e.unread = e.unread.saturating_add(1);
        }
        self.unarchive_on_message(&Place::Group(*gid))
    }

    /// Who a group message, reaction or edit is from as stored: `None` for
    /// us (from any of our devices).
    pub(crate) fn group_author(&self, root: &[u8; 64]) -> Option<[u8; 64]> {
        (*root != self.account.root_public.0).then_some(*root)
    }

    pub(crate) fn store_group_message(
        &mut self,
        gid: &[u8; 32],
        id: [u8; 16],
        from: Option<([u8; 64], String)>,
        text: &str,
        now: u64,
    ) -> Result<GroupMessage> {
        // Ours, from this device: refused while contacts hold its restore.
        if from.is_none() {
            self.require_not_held()?;
        }
        // Sent by another device of ours: our own message.
        let from = from.filter(|(r, _)| *r != self.account.root_public.0);
        let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
        let on_record = e.group.state.on_record;
        let seq = e.next_seq;
        e.next_seq += 1;
        let (from, from_name) = match from {
            Some((r, n)) => (Some(r), n),
            None => (None, self.profile.name.clone()),
        };
        let m = GroupMessage {
            seq,
            from,
            from_name,
            text: text.to_string(),
            at: now,
            delivered: false,
            poll: None,
            id,
            reactions: Vec::new(),
            edited: false,
            deleted: false,
            attachment: None,
            sticker: None,
            signed: if from.is_some() {
                self.group_unit_signed
            } else {
                on_record.then_some(true)
            },
            notice: false,
            transcript: String::new(),
        };
        self.put_group_message(gid, &m)?;
        self.save_group(gid)?;
        Ok(m)
    }
}
