//! Groups on every device of the account (`docs/06-multidevice.md` §5,
//! `docs/07-groups.md`).
//!
//! A device that holds a group hands it to each of our other active
//! devices that doesn't have it yet (a newly linked one, or after this
//! device created or joined the group): its whole view of the group (every
//! epoch secret and receiving chain, the member cards, where it has read
//! the mailboxes), with its own sending chain turned into one the other
//! device receives (`Group::hand_over`). The view is a sealed file in our
//! server's blob store; its reference goes to the other device in an
//! own-sync item that names it. The receiving device starts a sending chain
//! of its own at its first send, and every rotation of every device of ours
//! keys our other devices too, so each reads what the others send, shown as
//! our own messages. Group history is not handed over.

use super::groups::GroupEntry;
use super::own_sync::SyncItem;
use super::{Client, Event};
use crate::files::{self, Attachment};
use crate::{CoreError, Result};
use enclave_proto::group::Group;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Ids of group messages our other devices sent, as they vouched for them:
/// `group id ‖ message id`.
const NS_OWN_OK: &str = "group-own-ok";
/// Group messages from our other devices waiting for that: `group id ‖
/// message id` → `member ‖ device ‖ flags ‖ state hash ‖ content`.
const NS_OWN_HELD: &str = "group-own-held";
/// Confirmed ids kept per group.
const OWN_OK_KEPT: usize = 2_000;

/// Groups handed to one of our devices: `group id ‖ device id`.
const NS_HANDED: &str = "group-handed";
/// Group files handed to this device, still to fetch: attachment → sender
/// device.
const NS_GROUP_IN: &str = "group-in";

fn handed_key(gid: &[u8; 32], dev: &[u8; 16]) -> Vec<u8> {
    [&gid[..], &dev[..]].concat()
}

fn own_key(gid: &[u8; 32], id: &[u8; 8]) -> Vec<u8> {
    [&gid[..], &id[..]].concat()
}

impl Client {
    /// Vouch to our other devices for a group message this one sent.
    pub(crate) fn queue_group_sent(&mut self, gid: &[u8; 32], id: [u8; 8]) -> Result<()> {
        let probe = SyncItem::GroupSent {
            group: *gid,
            ids: Vec::new(),
        };
        let mut ids = match self.queued_own(&probe)? {
            Some(SyncItem::GroupSent { ids, .. }) => ids,
            _ => Vec::new(),
        };
        ids.push(id);
        let drop = ids.len().saturating_sub(200);
        ids.drain(..drop);
        self.queue_own(SyncItem::GroupSent { group: *gid, ids })
    }

    /// Whether another device of ours vouched for `id` in `gid`.
    pub(crate) fn own_group_confirmed(&self, gid: &[u8; 32], id: &[u8; 8]) -> bool {
        matches!(self.store.get(NS_OWN_OK, &own_key(gid, id)), Ok(Some(_)))
    }

    /// Keep an unconfirmed message from another device of ours.
    pub(crate) fn hold_own_group_message(
        &mut self,
        gid: &[u8; 32],
        msg: &enclave_proto::group::GroupMessage,
    ) -> Result<()> {
        let v = [
            &[msg.member, msg.device, msg.flags][..],
            &msg.state_hash,
            &msg.content,
        ]
        .concat();
        self.store
            .put(NS_OWN_HELD, &own_key(gid, &msg.id), &v, &mut self.rng)?;
        Ok(())
    }

    /// Another device of ours vouched for messages it sent in `gid`: show
    /// the ones held, and remember the rest for when they arrive.
    pub(crate) fn on_group_sent(
        &mut self,
        gid: &[u8; 32],
        ids: &[[u8; 8]],
        now: u64,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for id in ids {
            let key = own_key(gid, id);
            self.store
                .put(NS_OWN_OK, &key, &now.to_be_bytes(), &mut self.rng)?;
            let Some(v) = self.store.get(NS_OWN_HELD, &key)? else {
                continue;
            };
            self.store.delete(NS_OWN_HELD, &key)?;
            if v.len() < 35 || !self.groups.contains_key(gid) {
                continue;
            }
            let msg = enclave_proto::group::GroupMessage {
                member: v[0],
                device: v[1],
                id: *id,
                state_hash: v[3..35].try_into().map_err(|_| CoreError::NotFound)?,
                frontier: Vec::new(),
                flags: v[2],
                own_account: true,
                content: v[35..].to_vec(),
            };
            if let Some(e) = self.on_group_message(gid, msg, now)? {
                events.push(e);
            }
        }
        // Keep the newest confirmations per group.
        let mut ok: Vec<(Vec<u8>, u64)> = self
            .store
            .scan(NS_OWN_OK)?
            .into_iter()
            .filter(|(k, _)| k.starts_with(gid))
            .map(|(k, v)| {
                let at = v.as_slice().try_into().map_or(0, u64::from_be_bytes);
                (k, at)
            })
            .collect();
        if ok.len() > OWN_OK_KEPT {
            ok.sort_by_key(|(_, at)| *at);
            for (k, _) in &ok[..ok.len() - OWN_OK_KEPT] {
                self.store.delete(NS_OWN_OK, k)?;
            }
        }
        Ok(events)
    }

    /// This device's index in our manifest (how group members address it).
    pub(crate) fn my_device_index(&self) -> u8 {
        self.manifest
            .devices
            .iter()
            .position(|d| d.id == self.device.id)
            .unwrap_or(0) as u8
    }

    /// Hand every group we're in to our other active devices that don't
    /// have it from us yet.
    pub(crate) async fn hand_over_groups(&mut self, now: u64) -> Result<()> {
        let own = self.account.root_public.0;
        let quiet: Vec<[u8; 16]> = self
            .own_devices()
            .into_iter()
            .filter(|d| d.inactive)
            .map(|d| d.id)
            .collect();
        let devices: Vec<(u8, [u8; 16])> = self
            .manifest
            .devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.id != self.device.id && !quiet.contains(&d.id))
            .filter(|(_, d)| self.sessions.contains_key(&(own, d.id)))
            .map(|(i, d)| (i as u8, d.id))
            .collect();
        let groups: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(g, _)| *g)
            .collect();
        for gid in groups {
            for (index, dev) in &devices {
                if self.store.get(NS_HANDED, &handed_key(&gid, dev))?.is_some() {
                    continue;
                }
                let bytes = {
                    let e = self.groups.get(&gid).ok_or(CoreError::NotFound)?;
                    let group = Group::import(&e.group.hand_over(*index)?)?;
                    Zeroizing::new(
                        GroupEntry {
                            group,
                            cards: e.cards.clone(),
                            cursors: e.cursors.clone(),
                            pending: e.pending.clone(),
                            // Its own chain has keyed nobody yet.
                            keyed: BTreeSet::new(),
                            next_seq: 0,
                            unread: 0,
                            left: false,
                        }
                        .encode(),
                    )
                };
                let host = self.profile.server;
                let (att, chunks) = files::seal_file(
                    &bytes,
                    "group",
                    "application/x-enclave-group",
                    host,
                    &mut self.rng,
                )?;
                for (id, chunk) in &chunks {
                    self.rpc
                        .blob_put(&host, *id, chunk, now, &mut self.rng)
                        .await?;
                }
                let item = SyncItem::Group {
                    device: *dev,
                    attachment: att.encode(),
                };
                self.send_own_now(item).await?;
                self.store
                    .put(NS_HANDED, &handed_key(&gid, dev), &[], &mut self.rng)?;
            }
        }
        Ok(())
    }

    /// A group file another device of ours handed to this one (from
    /// `on_own_sync`): fetched at the end of the sync.
    pub(crate) fn queue_group_file(&mut self, from: &[u8; 16], attachment: &[u8]) -> Result<()> {
        self.store
            .put(NS_GROUP_IN, attachment, from, &mut self.rng)?;
        Ok(())
    }

    /// Fetch and take in the groups handed to this device.
    pub(crate) async fn take_handed_groups(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, from) in self.store.scan(NS_GROUP_IN)? {
            let Ok(att) = Attachment::decode(&k) else {
                self.store.delete(NS_GROUP_IN, &k)?;
                continue;
            };
            let mut parts = Vec::with_capacity(att.chunks as usize);
            for i in 0..att.chunks {
                match self
                    .rpc
                    .blob_get(&att.host, att.chunk_id(i), now, &mut self.rng)
                    .await
                {
                    Ok(c) => parts.push(files::open_chunk(&att, i, &c)?),
                    Err(e @ CoreError::Net(_)) => return Err(e),
                    Err(_) => break,
                }
            }
            self.store.delete(NS_GROUP_IN, &k)?;
            if parts.len() != att.chunks as usize {
                continue;
            }
            let bytes = Zeroizing::new(files::finish(&att, &parts)?);
            let Ok(entry) = GroupEntry::decode(&bytes) else {
                continue;
            };
            let gid = entry.group.state.group_id;
            if self.groups.contains_key(&gid) || entry.group.my_device != self.my_device_index() {
                continue;
            }
            let name = super::sanitize_name(&entry.group.state.name);
            self.groups.insert(gid, entry);
            self.save_group(&gid)?;
            // The device that handed it over has it.
            if let Ok(dev) = <[u8; 16]>::try_from(from.as_slice()) {
                self.store
                    .put(NS_HANDED, &handed_key(&gid, &dev), &[], &mut self.rng)?;
            }
            events.push(Event::GroupJoined {
                group_id: gid,
                name,
            });
        }
        Ok(events)
    }
}
