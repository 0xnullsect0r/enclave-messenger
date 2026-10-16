//! Forks and withheld messages in groups (`docs/07-groups.md` §7.3–§7.4,
//! RT-11), and the inline lines membership changes leave in the chat.
//!
//! Every group message carries its sender's state hash and causal frontier
//! (the last message it has seen from each member). A receiver compares
//! them with what it holds:
//!
//! * **State hash.** A hash that is ours, or one of our last
//!   [`MAX_HASHES`] states (a sender who is behind, or a message that was
//!   sent before an update reached us), is fine. Any other hash means the
//!   sender holds a state we don't: an update on its way to us, or a fork.
//! * **Frontier.** An entry naming a message we never received means it is
//!   on its way, or someone keeps it from us while others see it. Entries
//!   are checked only for members we have heard from since we joined: a
//!   newcomer never receives what was said before it joined, and the
//!   entries of quiet members still name such messages.
//!
//! Either is normal for a moment. When a message that arrives
//! [`DIVERGE_SECS`] or more after we first noticed it still shows the same
//! difference, the group is marked: [`Event::GroupDiverged`] and
//! [`GroupInfo::diverged`](super::GroupInfo::diverged) ("Some people in
//! this group may be seeing different messages"). The mark goes once
//! nothing is outstanding any more.
//!
//! Membership changes are always shown in the chat: each state update that
//! adds, removes or loses a member stores a line for it
//! ([`GroupMessage::notice`](super::GroupMessage::notice)), on the admin's
//! own device too.

use super::groups::GroupMessage;
use super::{Client, Event};
use crate::Result;
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::group::GroupState;
use std::collections::BTreeSet;

const NS_GROUP_CHECKS: &str = "group-checks";
/// How long a difference may last, as shown by later messages, before the
/// group is marked.
pub const DIVERGE_SECS: u64 = 600;
/// Our recent state hashes kept per group.
const MAX_HASHES: usize = 32;
/// Differences kept per group (the oldest go first).
const MAX_ODD: usize = 128;

const ODD_HASH: u8 = 0;
const ODD_MISSING: u8 = 1;

/// Something a message showed that we don't hold.
#[derive(Clone, PartialEq, Eq)]
struct Odd {
    /// [`ODD_HASH`] or [`ODD_MISSING`].
    kind: u8,
    /// For a hash, the member reporting it; for a missing message, the
    /// member who sent it.
    member: u8,
    /// The state hash, or the message id (8 B, zero-padded).
    value: [u8; 32],
    /// When we first noticed.
    since: u64,
}

/// What a group remembers for the check.
#[derive(Default)]
struct Check {
    /// Our recent state hashes, newest last.
    hashes: Vec<[u8; 32]>,
    /// Member indices we have received a message from since we joined.
    heard: BTreeSet<u8>,
    odd: Vec<Odd>,
    /// The group is marked.
    alert: bool,
}

impl Check {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).u8(u8::from(self.alert));
        w.u16(self.hashes.len() as u16);
        for h in &self.hashes {
            w.fixed(h);
        }
        w.u16(self.heard.len() as u16);
        for m in &self.heard {
            w.u8(*m);
        }
        w.u16(self.odd.len() as u16);
        for o in &self.odd {
            w.u8(o.kind).u8(o.member).fixed(&o.value).u64(o.since);
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let alert = r.u8()? == 1;
        let n = usize::from(r.u16()?);
        if n > MAX_HASHES {
            return Err(ProtoError::Decode);
        }
        let hashes = (0..n)
            .map(|_| r.array())
            .collect::<enclave_proto::Result<_>>()?;
        let heard = (0..r.u16()?)
            .map(|_| r.u8())
            .collect::<enclave_proto::Result<_>>()?;
        let n = usize::from(r.u16()?);
        if n > MAX_ODD {
            return Err(ProtoError::Decode);
        }
        let odd = (0..n)
            .map(|_| {
                Ok(Odd {
                    kind: r.u8()?,
                    member: r.u8()?,
                    value: r.array()?,
                    since: r.u64()?,
                })
            })
            .collect::<enclave_proto::Result<_>>()?;
        r.end()?;
        Ok(Self {
            hashes,
            heard,
            odd,
            alert,
        })
    }

    /// Remember `hash` as one of ours; differences it explains go.
    fn ours(&mut self, hash: [u8; 32]) {
        if self.hashes.last() != Some(&hash) {
            self.hashes.retain(|h| *h != hash);
            self.hashes.push(hash);
            let drop = self.hashes.len().saturating_sub(MAX_HASHES);
            self.hashes.drain(..drop);
        }
        self.odd
            .retain(|o| !(o.kind == ODD_HASH && o.value == hash));
    }

    /// Note a difference; true if a message shows it again after
    /// [`DIVERGE_SECS`].
    fn noticed(&mut self, kind: u8, member: u8, value: [u8; 32], now: u64) -> bool {
        match self
            .odd
            .iter()
            .find(|o| o.kind == kind && o.member == member && o.value == value)
        {
            Some(o) => now >= o.since.saturating_add(DIVERGE_SECS),
            None => {
                if self.odd.len() >= MAX_ODD {
                    self.odd.remove(0);
                }
                self.odd.push(Odd {
                    kind,
                    member,
                    value,
                    since: now,
                });
                false
            }
        }
    }
}

fn id_value(id: &[u8; 8]) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[..8].copy_from_slice(id);
    v
}

impl Client {
    fn group_check(&self, gid: &[u8; 32]) -> Check {
        self.store
            .get(NS_GROUP_CHECKS, gid)
            .ok()
            .flatten()
            .and_then(|b| Check::decode(&b).ok())
            .unwrap_or_default()
    }

    fn save_group_check(&mut self, gid: &[u8; 32], c: &Check) -> Result<()> {
        self.store
            .put(NS_GROUP_CHECKS, gid, &c.encode(), &mut self.rng)?;
        Ok(())
    }

    /// Record the group's current state hash as one of ours (after every
    /// change of state).
    pub(crate) fn note_group_state(&mut self, gid: &[u8; 32]) -> Result<()> {
        let Some(hash) = self.groups.get(gid).map(|e| e.group.state.hash()) else {
            return Ok(());
        };
        let mut c = self.group_check(gid);
        if c.hashes.last() == Some(&hash) {
            return Ok(());
        }
        c.ours(hash);
        self.save_group_check(gid, &c)
    }

    /// Whether the group is marked: some members seem to see a different
    /// group state or different messages (see the module docs).
    pub fn group_diverged(&self, gid: &[u8; 32]) -> bool {
        self.group_check(gid).alert
    }

    /// Compare a group message (not a state update) with what we hold.
    pub(crate) fn check_group_message(
        &mut self,
        gid: &[u8; 32],
        msg: &enclave_proto::group::GroupMessage,
        now: u64,
    ) -> Result<Option<Event>> {
        let Some((current, missing, me)) = self
            .groups
            .get(gid)
            .map(|e| (e.group.state.hash(), e.group.missing(msg), e.group.me))
        else {
            return Ok(None);
        };
        let mut c = self.group_check(gid);
        c.ours(current);
        // This message is no longer missing.
        let this = id_value(&msg.id);
        c.odd
            .retain(|o| !(o.kind == ODD_MISSING && o.value == this));
        let mut diverged = false;
        if c.hashes.contains(&msg.state_hash) {
            // The sender holds one of our states: earlier differences it
            // reported are over.
            c.odd
                .retain(|o| !(o.kind == ODD_HASH && o.member == msg.member));
        } else {
            diverged |= c.noticed(ODD_HASH, msg.member, msg.state_hash, now);
        }
        for (member, id) in missing {
            if c.heard.contains(&member) {
                diverged |= c.noticed(ODD_MISSING, member, id_value(&id), now);
            }
        }
        if msg.member != me {
            c.heard.insert(msg.member);
        }
        let event = if diverged && !c.alert {
            c.alert = true;
            Some(Event::GroupDiverged { group_id: *gid })
        } else {
            if c.odd.is_empty() {
                c.alert = false;
            }
            None
        };
        self.save_group_check(gid, &c)?;
        Ok(event)
    }

    /// Lines for the membership changes from `prev` to the group's state
    /// now, made by `by` (`None`: us).
    pub(crate) fn note_membership(
        &mut self,
        gid: &[u8; 32],
        prev: &GroupState,
        by: Option<[u8; 64]>,
        now: u64,
    ) -> Result<()> {
        let me = self.account.root_public.0;
        let by = by.filter(|r| *r != me);
        let lines: Vec<String> = {
            let Some(e) = self.groups.get(gid) else {
                return Ok(());
            };
            let next = &e.group.state;
            // A member's change of recovery words is no membership change.
            if prev.root_change(next).is_some() {
                return Ok(());
            }
            let was: BTreeSet<[u8; 64]> = prev.active().map(|(_, m)| m.root).collect();
            let is: BTreeSet<[u8; 64]> = next.active().map(|(_, m)| m.root).collect();
            let name = |r: &[u8; 64], start: bool| {
                if *r == me {
                    if start { "You" } else { "you" }.to_string()
                } else {
                    self.member_name(e, r)
                }
            };
            let actor = by.map_or_else(|| "You".to_string(), |r| name(&r, true));
            let mut lines = Vec::new();
            for r in is.difference(&was) {
                lines.push(format!("{actor} added {}.", name(r, false)));
            }
            for r in was.difference(&is) {
                if Some(*r) == by || (by.is_none() && *r == me) {
                    lines.push(format!("{actor} left."));
                } else {
                    lines.push(format!("{actor} removed {}.", name(r, false)));
                }
            }
            lines
        };
        if lines.is_empty() {
            return Ok(());
        }
        for text in lines {
            let id: [u8; 16] = self.rng.array("core/group-notice-id")?;
            let from_name = {
                let e = self.groups.get(gid).ok_or(crate::CoreError::NotFound)?;
                by.map_or_else(|| self.profile.name.clone(), |r| self.member_name(e, &r))
            };
            let e = self.groups.get_mut(gid).ok_or(crate::CoreError::NotFound)?;
            let seq = e.next_seq;
            e.next_seq += 1;
            let m = GroupMessage {
                seq,
                from: by,
                from_name,
                text,
                at: now,
                delivered: true,
                poll: None,
                id,
                reactions: Vec::new(),
                edited: false,
                deleted: false,
                attachment: None,
                sticker: None,
                signed: None,
                notice: true,
                transcript: String::new(),
                reply_to: None,
                forwarded: false,
                mentions_me: false,
                view_once: false,
                once: None,
                link: None,
            };
            self.put_group_message(gid, &m)?;
        }
        self.save_group(gid)
    }
}
