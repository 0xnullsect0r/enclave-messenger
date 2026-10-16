//! On-the-record groups (`docs/07-groups.md` §3, §7.3, §7.5).
//!
//! An admin puts a group on the record (or takes it off) with a state
//! update (`GroupState::on_record`), which every member applies like any
//! other and which the conversation shows. In a group on the record, every
//! unit a device posts carries its composite signature ahead of the
//! content (sender-header flag `FLAG_SIGNED`):
//!
//! - a message over [`otr::group_payload`] (`proto/grp-signed-msg`: group,
//!   epoch, the device's id, its chain generation and counter, the sender's
//!   state hash, SHA3-512 of the content);
//! - a state update over [`otr::admin_payload`] (`proto/grp-admin-sig`:
//!   group, parent state hash, SHA3-512 of the update): without a good one
//!   the update is refused;
//! - a poll close over [`otr::tally_payload`] (`proto/poll-tally`: group,
//!   poll, tally hash).
//!
//! The receiver checks the signature against the sender device's entry in
//! the sender's manifest (every member is a contact, `groups.rs`; our own
//! devices against our manifest). A message that should have been signed
//! and isn't, or whose signature fails, is shown marked "Not signed"
//! (`GroupMessage::signed`).

use super::Client;
use super::polls::Rich;
use crate::{CoreError, Result};
use enclave_proto::group::{FLAG_RICH, FLAG_SIGNED, FLAG_STATE_UPDATE, GroupMessage, GroupState};
use enclave_proto::manifest::Manifest;
use enclave_proto::otr;

/// A composite signature's length.
const SIG_LEN: usize = 4_741;

/// Which signature a unit with these flags and content carries in group
/// `state`, and over what (given the sender's device id, and for a message
/// its `(epoch, generation, counter, state_hash)`).
fn payload(
    state: &GroupState,
    flags: u8,
    content: &[u8],
    device: &[u8; 16],
    send: (u32, u8, u32, [u8; 32]),
) -> (otr::Kind, Vec<u8>) {
    let gid = &state.group_id;
    if flags & FLAG_STATE_UPDATE != 0 {
        // Over the parent the update names (whether that is the state it
        // applies to is checked apart, `GroupState::accepts`).
        let parent = GroupState::decode(content).map_or([0; 32], |s| s.parent);
        return (otr::Kind::Admin, otr::admin_payload(gid, &parent, content));
    }
    if flags & FLAG_RICH != 0
        && let Ok(Rich::Close { poll, tally }) = Rich::decode(content)
    {
        return (otr::Kind::Tally, otr::tally_payload(gid, &poll, &tally));
    }
    let (epoch, generation, counter, state_hash) = send;
    (
        otr::Kind::Group,
        otr::group_payload(
            gid,
            epoch,
            device,
            generation,
            counter,
            &state_hash,
            content,
        ),
    )
}

impl Client {
    /// Content and flags as they go to group `gid`: signed if the group
    /// is on the record.
    pub(crate) fn sign_group(
        &mut self,
        gid: &[u8; 32],
        content: &[u8],
        flags: u8,
    ) -> Result<(Vec<u8>, u8)> {
        let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
        if !e.group.state.on_record {
            return Ok((content.to_vec(), flags));
        }
        let send = e.group.next_send()?;
        let (kind, p) = payload(&e.group.state, flags, content, &self.device.id, send);
        let sig = otr::sign(&self.device.signing, kind, &p, &mut self.rng)?;
        Ok(([sig, content.to_vec()].concat(), flags | FLAG_SIGNED))
    }

    /// Take the signature off a group unit and check it: `None` if it
    /// carries none, else whether it verifies. `state` is the receiver's
    /// state before the unit (a state update's parent).
    pub(crate) fn check_group_signature(
        &self,
        state: &GroupState,
        sender: &[u8; 64],
        msg: &mut GroupMessage,
    ) -> Option<bool> {
        if msg.flags & FLAG_SIGNED == 0 {
            return None;
        }
        if msg.content.len() < SIG_LEN {
            msg.content.clear();
            return Some(false);
        }
        let sig: Vec<u8> = msg.content.drain(..SIG_LEN).collect();
        let manifest: Option<&Manifest> = if msg.own_account {
            Some(&self.manifest)
        } else {
            self.contacts.get(sender).map(|c| &c.manifest)
        };
        let Some(dev) = manifest.and_then(|m| m.devices.get(msg.device as usize)) else {
            return Some(false);
        };
        let send = (msg.epoch, msg.generation, msg.counter, msg.state_hash);
        let (kind, p) = payload(state, msg.flags, &msg.content, &dev.id, send);
        Some(otr::verify(&dev.signing, kind, &p, &sig).is_ok())
    }

    /// Whether group `gid` is on the record.
    pub fn group_on_the_record(&self, gid: &[u8; 32]) -> bool {
        self.groups
            .get(gid)
            .is_some_and(|e| e.group.state.on_record)
    }

    /// Whether only admins may post in group `gid`.
    pub fn group_announcement_only(&self, gid: &[u8; 32]) -> bool {
        self.groups
            .get(gid)
            .is_some_and(|e| e.group.state.admins_only)
    }

    /// Make group `gid` announcement-only (only admins post; everyone may
    /// still vote and react), or open it again (admins only).
    pub async fn set_group_announcement_only(&mut self, gid: &[u8; 32], on: bool) -> Result<()> {
        let now = self.now();
        let next = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            if e.group.state.admins_only == on {
                return Ok(());
            }
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
            e.group.state.child(|s| s.admins_only = on)?
        };
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
        e.group.apply_state(next)?;
        self.save_group(gid)
    }

    /// Put group `gid` on the record, or take it off (admins only).
    pub async fn set_group_on_the_record(&mut self, gid: &[u8; 32], on: bool) -> Result<()> {
        let now = self.now();
        let next = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            if e.group.state.on_record == on {
                return Ok(());
            }
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
            e.group.state.child(|s| s.on_record = on)?
        };
        // Signed (or not) under the state it changes, then applied.
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await?;
        let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
        e.group.apply_state(next)?;
        self.save_group(gid)
    }
}
