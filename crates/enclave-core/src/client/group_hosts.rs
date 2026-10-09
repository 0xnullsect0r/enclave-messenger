//! Admins, and moving a group's mailboxes to another server
//! (`docs/07-groups.md` §4, §7.3).
//!
//! An admin makes another member an admin (or stops being one) with a state
//! update. Moving the mailboxes is a vote: each admin who wants the group on
//! another server posts a `HostVote` naming it (a `FLAG_RICH` message, kind
//! 10). Votes count for 7 days. The admin whose vote makes a majority of the
//! current admins posts the state update that moves the group: `host`
//! becomes the new server from the next day (`host_since`), and earlier
//! days' mailboxes stay on `prev_host`, so nothing already written is lost.
//! Every member refuses an update that changes the host without having seen
//! a majority of admins vote for it; the votes come first in the mailbox,
//! so a member has them by the time the update arrives.

use super::Client;
use super::polls::Rich;
use crate::{CoreError, Result};
use enclave_proto::group::FLAG_STATE_UPDATE;
use enclave_proto::group::GroupState;

const NS_HOST_VOTES: &str = "group-host-votes";
/// How long a vote counts.
pub const HOST_VOTE_SECS: u64 = 7 * 86_400;

fn vote_key(gid: &[u8; 32], admin: &[u8; 64]) -> Vec<u8> {
    [&gid[..], &admin[..]].concat()
}

impl Client {
    /// Make `root` an admin of group `gid`, or no longer one (admins only).
    pub async fn set_group_admin(
        &mut self,
        gid: &[u8; 32],
        root: &[u8; 64],
        admin: bool,
    ) -> Result<()> {
        let now = self.now();
        let next = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            self.require_admin(&e.group.state, e.group.me)?;
            let i = e.group.state.index_of(root).ok_or(CoreError::NotFound)?;
            if e.group.state.members[i as usize].admin == admin {
                return Ok(());
            }
            e.group
                .state
                .child(|s| s.members[i as usize].admin = admin)?
        };
        self.prepare_group_send(gid, now).await?;
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        self.apply_own_update(gid, next)
    }

    /// Vote to move group `gid`'s mailboxes to server `host` (admins only).
    /// The group moves once a majority of its admins voted for the same
    /// server.
    pub async fn vote_group_host(&mut self, gid: &[u8; 32], host: [u8; 16]) -> Result<()> {
        let now = self.now();
        {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            self.require_admin(&e.group.state, e.group.me)?;
            if e.group.state.host == host {
                return Ok(());
            }
        }
        self.post_group_rich(gid, &Rich::HostVote { host }).await?;
        let me = self.account.root_public.0;
        self.record_host_vote(gid, &me, host, now)?;
        if !self.host_majority(gid, &host, now)? {
            return Ok(());
        }
        let today = (now / 86_400) as u32;
        let next = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            e.group.state.child(|s| {
                s.prev_host = s.host_for(today);
                s.host = host;
                s.host_since = today + 1;
            })?
        };
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        self.apply_own_update(gid, next)
    }

    /// Who may vote: an active admin of the group's current state.
    fn require_admin(&self, state: &GroupState, me: u8) -> Result<()> {
        if state
            .members
            .get(me as usize)
            .is_some_and(|m| m.active && m.admin)
        {
            Ok(())
        } else {
            Err(CoreError::NotAccepted)
        }
    }

    fn apply_own_update(&mut self, gid: &[u8; 32], next: GroupState) -> Result<()> {
        let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
        e.group.apply_state(next)?;
        self.save_group(gid)
    }

    /// A `HostVote` from `from`: kept if they are an admin.
    pub(crate) fn on_host_vote(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        host: [u8; 16],
        now: u64,
    ) -> Result<()> {
        let admin = self.groups.get(gid).is_some_and(|e| {
            e.group
                .state
                .active()
                .any(|(_, m)| &m.root == from && m.admin)
        });
        if admin {
            self.record_host_vote(gid, from, host, now)?;
        }
        Ok(())
    }

    fn record_host_vote(
        &mut self,
        gid: &[u8; 32],
        admin: &[u8; 64],
        host: [u8; 16],
        now: u64,
    ) -> Result<()> {
        let v = [&host[..], &now.to_be_bytes()].concat();
        self.store
            .put(NS_HOST_VOTES, &vote_key(gid, admin), &v, &mut self.rng)?;
        Ok(())
    }

    /// Whether more than half of `gid`'s admins voted for `host` within
    /// [`HOST_VOTE_SECS`].
    fn host_majority(&self, gid: &[u8; 32], host: &[u8; 16], now: u64) -> Result<bool> {
        let Some(e) = self.groups.get(gid) else {
            return Ok(false);
        };
        let admins: Vec<[u8; 64]> = e
            .group
            .state
            .active()
            .filter(|(_, m)| m.admin)
            .map(|(_, m)| m.root)
            .collect();
        let mut yes = 0;
        for a in &admins {
            let Some(v) = self.store.get(NS_HOST_VOTES, &vote_key(gid, a))? else {
                continue;
            };
            let at = v
                .get(16..24)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            if v.get(..16) == Some(&host[..]) && at + HOST_VOTE_SECS >= now {
                yes += 1;
            }
        }
        Ok(yes * 2 > admins.len())
    }

    /// Whether a received update from `prev` to `next` may move the group:
    /// only to a server a majority of admins voted for, from a later day.
    pub(crate) fn accepts_host_change(
        &self,
        gid: &[u8; 32],
        prev: &GroupState,
        next: &GroupState,
        now: u64,
    ) -> Result<bool> {
        if next.host == prev.host
            && next.prev_host == prev.prev_host
            && next.host_since == prev.host_since
        {
            return Ok(true);
        }
        let today = (now / 86_400) as u32;
        let fresh = next.host_since >= today && next.host_since <= today.saturating_add(2);
        Ok(fresh && self.host_majority(gid, &next.host, now)?)
    }
}
