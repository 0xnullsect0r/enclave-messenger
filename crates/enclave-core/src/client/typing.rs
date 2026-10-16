//! Typing indicators (`docs/16-features.md` §7, `docs/09-transport.md`
//! §6.7), in 1:1 conversations and groups.
//!
//! Off by default. With them on, we tell contacts when we type and see
//! when they do; with them off, neither. A typing indicator is
//! `Content::Typing`, end-to-end encrypted like any message, and sent only
//! in a tick slot that would otherwise carry cover
//! ([`Transport::exchange_droppable`](enclave_net::transport::Transport::exchange_droppable)):
//! one that finds no free slot within two ticks is dropped. So turning them
//! on never changes what an observer sees, and an indicator can always be
//! lost. It carries no PQ slot (a dropped unit must not take a PQ step
//! with it) and no copy for our other devices.
//!
//! Each one spends a write token, so none is sent while fewer than
//! [`TYPING_RESERVE`] are left: real messages always come first.
//!
//! In a group it is an ephemeral group message
//! ([`enclave_proto::group::FLAG_EPHEMERAL`]): a unit like any other to the
//! server, sealed without a step on our sender chain, so one that is
//! dropped leaves no gap for members to be warned about; it carries the
//! time it was sent, and members ignore one older than
//! [`GROUP_TYPING_MAX_AGE`] (a replay by the server).

use super::{Client, ContactState, Event};
use crate::content::Content;
use crate::rpc::Sending;
use crate::{CoreError, Result};
use enclave_rpc::api::FLAG_GROUP;
use enclave_wire::{Op, RequestHeader};

const SETTING: &str = "typing";
/// Write tokens kept back from typing indicators for real messages.
pub const TYPING_RESERVE: usize = 8;
/// How long the app shows "typing…" after the last indicator, since a
/// "stopped" may never arrive. Senders repeat "typing" more often than this.
pub const TYPING_SHOW_SECS: u64 = 10;
/// A group typing indicator older than this (seconds, either way) is
/// ignored.
pub const GROUP_TYPING_MAX_AGE: u64 = 30;
/// What a group typing indicator's content starts with.
const GROUP_TYPING: u8 = 1;

impl Client {
    /// Whether read receipts are on (on unless turned off), both ways: off,
    /// we send none and show none; contacts still see "Delivered".
    pub fn receipts_enabled(&self) -> bool {
        !matches!(self.setting("receipts"), Ok(Some(v)) if v == [0])
    }

    /// Turn read receipts on or off (synced to our other devices).
    pub fn set_receipts_enabled(&mut self, on: bool) -> Result<()> {
        self.set_setting("receipts", &[u8::from(on)])
    }

    /// Whether typing indicators are on (off unless turned on).
    pub fn typing_enabled(&self) -> bool {
        matches!(self.setting(SETTING), Ok(Some(v)) if v == [1])
    }

    /// Turn typing indicators on or off, both ways.
    pub fn set_typing_enabled(&mut self, on: bool) -> Result<()> {
        self.set_setting(SETTING, &[u8::from(on)])
    }

    /// Tell `root` that we started (`on`) or stopped typing. Returns the
    /// sending, which the caller can leave to run on its own (it waits for a
    /// free slot and fails with `NetError::Dropped` if none comes), or
    /// `None` when typing indicators are off, the contact isn't accepted or
    /// is blocked, or tokens are short.
    pub async fn send_typing(&mut self, root: &[u8; 64], on: bool) -> Result<Option<Sending>> {
        if !self.typing_enabled() || self.is_blocked(root) {
            return Ok(None);
        }
        match self.contacts.get(root) {
            Some(c) if c.state == ContactState::Accepted && c.tokens.len() > TYPING_RESERVE => {}
            _ => return Ok(None),
        }
        let now = self.now();
        let (server, h, env) = self.seal_content(root, &Content::Typing { on }, true)?;
        Ok(Some(
            self.rpc
                .prepare_droppable(&server, h, &env, now, &mut self.rng)
                .await?,
        ))
    }

    /// Tell group `gid` that we started (`on`) or stopped typing; as
    /// [`Self::send_typing`] (`None` with typing indicators off, or when we
    /// can't post to the group).
    pub async fn send_group_typing(&mut self, gid: &[u8; 32], on: bool) -> Result<Option<Sending>> {
        if !self.typing_enabled() {
            return Ok(None);
        }
        let now = self.now();
        let mut content = vec![GROUP_TYPING, u8::from(on)];
        content.extend_from_slice(&now.to_be_bytes());
        let me = self.account.root_public.0;
        let (unit, host, addr, secret) = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            let day = super::groups::day(now);
            let st = &e.group.state;
            let admin = st.members.iter().any(|m| m.root == me && m.admin);
            if e.left || (st.admins_only && !admin) {
                return Ok(None);
            }
            let Ok(unit) = e.group.seal_ephemeral(&content, &mut self.rng) else {
                return Ok(None);
            };
            let addr = e.group.mailbox(day)?;
            let secret = e.group.mailbox_secret(e.group.epoch(), &addr)?;
            (unit, st.host_for(day), addr, secret)
        };
        let h = RequestHeader {
            op: Op::Write,
            flags: FLAG_GROUP,
            mailbox: addr,
            token: secret,
        };
        Ok(Some(
            self.rpc
                .prepare_droppable(&host, h, &unit, now, &mut self.rng)
                .await?,
        ))
    }

    /// A group's ephemeral message from `root` (a typing indicator).
    pub(crate) fn on_group_ephemeral(
        &self,
        gid: &[u8; 32],
        root: &[u8; 64],
        content: &[u8],
        now: u64,
    ) -> Option<Event> {
        let [GROUP_TYPING, on, t @ ..] = content else {
            return None;
        };
        let at = u64::from_be_bytes(t.get(..8)?.try_into().ok()?);
        if !self.typing_enabled()
            || self.is_blocked(root)
            || now.abs_diff(at) > GROUP_TYPING_MAX_AGE
        {
            return None;
        }
        let e = self.groups.get(gid)?;
        Some(Event::GroupTyping {
            group_id: *gid,
            root: *root,
            name: self.member_name(e, root),
            on: *on == 1,
        })
    }

    pub(crate) fn on_typing(&self, root: &[u8; 64], on: bool) -> Option<Event> {
        let accepted = self
            .contacts
            .get(root)
            .is_some_and(|c| c.state == ContactState::Accepted);
        (self.typing_enabled() && accepted && !self.is_blocked(root))
            .then_some(Event::Typing { root: *root, on })
    }
}
