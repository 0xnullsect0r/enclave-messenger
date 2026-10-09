//! Removing a linked device, and following other accounts' device changes.
//!
//! The primary signs a manifest without the device, publishes it, drops its
//! own sessions with the device and tells every contact and our other devices
//! (`Content::Devices`). Each of them fetches the manifest from the account's
//! server, checks the root signature and that the version is at least the one
//! announced, and deletes its sessions with devices no longer listed, so
//! nothing new is encrypted to the removed device. A removed device that tries
//! to start a new session is refused: its initial message names a manifest
//! version older than the one its contacts now hold.
//!
//! Not yet: rotating the account inbox and vault key (the removed device can
//! still see that envelopes arrive, but not read them). That belongs to
//! "Secure my account" (`03-identity.md` §3.4).

use super::{Client, ContactState, Event, session_key};
use crate::persist::NS_SESSIONS;
use crate::{CoreError, Result, content::Content};
use enclave_crypto::sig::RootPublic;
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_rpc::api::{DirAction, DirKind, manifest_key};

impl Client {
    /// Remove one of our other devices (primary only). Returns once the new
    /// manifest is published; contacts that are offline catch up when they
    /// next sync.
    pub async fn remove_device(&mut self, id: &[u8; 16]) -> Result<()> {
        self.require_root_unlocked()?;
        if !self.can_link() {
            return Err(CoreError::NotAccepted);
        }
        if *id == self.device.id || self.manifest.device(id).is_none() {
            return Err(CoreError::NotFound);
        }
        let now = self.now();
        let gone = *id;
        self.publish_manifest(|m| m.devices.retain(|d| d.id != gone), now)
            .await?;
        let version = self.manifest.version;
        let own = self.account.root_public.0;
        let notice = Content::Devices(version);
        // Our devices first, including the removed one so it can tell its
        // user, then every contact. A contact we can't reach now learns when
        // it next syncs after a message from us arrives.
        let _ = self.send_own(&notice.encode()?, now).await;
        self.drop_sessions(&own, &self.manifest.clone())?;
        let roots: Vec<[u8; 64]> = self
            .contacts
            .values()
            .filter(|c| c.state == ContactState::Accepted && c.inbox.is_some())
            .map(|c| c.root)
            .collect();
        for root in roots {
            let _ = self.send_content(&root, &notice, now).await;
        }
        Ok(())
    }

    /// Delete sessions with devices of `root` that `m` no longer lists.
    fn drop_sessions(&mut self, root: &[u8; 64], m: &Manifest) -> Result<()> {
        let gone: Vec<[u8; 16]> = self
            .sessions
            .keys()
            .filter(|(r, d)| r == root && m.device(d).is_none())
            .map(|(_, d)| *d)
            .collect();
        for d in gone {
            self.sessions.remove(&(*root, d));
            self.store.delete(NS_SESSIONS, &session_key(root, &d))?;
        }
        Ok(())
    }

    /// Fetch manifests announced as changed during this sync and apply them.
    pub(crate) async fn refresh_manifests(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let own = self.account.root_public.0;
        let due = std::mem::take(&mut self.stale_manifests);
        for (root, announced) in due {
            let server = if root == own {
                self.profile.server
            } else {
                match self.contacts.get(&root) {
                    Some(c) => c.server,
                    None => continue,
                }
            };
            let bytes = match self
                .rpc
                .dir_get(
                    &server,
                    DirKind::Manifest,
                    DirAction::Get,
                    manifest_key(&root),
                    [0; 32],
                    now,
                    &mut self.rng,
                )
                .await
            {
                Ok(b) => b,
                Err(e @ CoreError::Net(_)) => {
                    self.stale_manifests.insert(root, announced);
                    return Err(e);
                }
                Err(_) => continue,
            };
            let Ok(signed) = SignedManifest::from_bytes(&bytes) else {
                continue;
            };
            let Ok(m) = signed.verify(&RootPublic(root), now) else {
                continue;
            };
            // Older than announced: the server is behind or rolling back.
            if m.version < announced {
                continue;
            }
            // Only changes a listed device co-signed, or past the 72-hour
            // guard (`guard.rs`).
            let old = if root == own {
                self.manifest.clone()
            } else {
                match self.contacts.get(&root) {
                    Some(c) => c.manifest.clone(),
                    None => continue,
                }
            };
            if m.version <= old.version
                || self.judge(&root, &server, &old, &signed, &m, now).await?
                    != super::guard::Judgement::Accept
            {
                continue;
            }
            if root == own {
                self.set_manifest(m.clone(), &signed)?;
                self.drop_sessions(&own, &m)?;
                events.push(if m.device(&self.device.id).is_none() {
                    Event::RemovedFromAccount
                } else {
                    Event::DevicesChanged
                });
            } else if let Some(mut c) = self.contacts.get(&root).cloned() {
                c.manifest = m.clone();
                self.drop_sessions(&root, &m)?;
                self.contacts.insert(root, c.clone());
                self.save_contact(&c)?;
            }
        }
        Ok(events)
    }
}
