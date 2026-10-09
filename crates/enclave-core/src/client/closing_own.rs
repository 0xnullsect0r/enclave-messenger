//! Deleting our own account (`docs/03-identity.md` §8.5).
//!
//! On a device that holds the recovery words, [`Client::delete_account`]
//! tells every contact (`Content::Closed`) and leaves every group, publishes
//! the root-signed tombstone (the server then drops the manifest,
//! attestations, prekeys and username, refuses the account for good, and
//! logs the tombstone in key transparency), and deletes the inboxes and the
//! vault-key blob with their owner secrets. Each step is safe to repeat, so
//! a deletion cut short by the network is finished by trying again. The
//! caller then erases the device ([`Client::erase`]).
//!
//! Our other devices find the tombstone when they next check our manifest
//! (every 10 minutes) and raise [`Event::AccountDeleted`]; the app erases
//! them too. A device offline for good is covered by the deleted inboxes
//! and the manifest's expiry. Blobs we uploaded aren't deleted one by one:
//! nothing links them to the account (allocations are bought with unlinkable
//! tokens), and they expire within 30 days.

use super::{Client, Event};
use crate::content::Content;
use crate::persist::NS_PROFILE;
use crate::{CoreError, Result};
use enclave_rpc::api::{self, DirAction, DirKind, Status, manifest_key};

/// `NS_PROFILE` key set once our account's tombstone was seen.
const DELETED: &[u8] = b"account-deleted";

impl Client {
    /// Delete this account everywhere (see the module docs). Only on a
    /// device holding the recovery words; erase the device afterwards.
    pub async fn delete_account(&mut self) -> Result<()> {
        if self.account.root.is_none() {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        let fail = |e: CoreError| -> Result<()> {
            match e {
                CoreError::Net(_) => Err(e),
                _ => Ok(()),
            }
        };
        // Contacts and groups first, while the inboxes still exist.
        let roots: Vec<[u8; 64]> = self
            .contacts
            .values()
            .filter(|c| c.state == super::ContactState::Accepted)
            .map(|c| c.root)
            .filter(|r| !self.is_closed(r))
            .collect();
        for root in roots {
            if let Err(e) = self.send_content(&root, &Content::Closed, now).await {
                fail(e)?;
            }
        }
        let gids: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(g, _)| *g)
            .collect();
        for gid in gids {
            if let Err(e) = self.leave_group(&gid).await {
                fail(e)?;
            }
        }
        self.publish_tombstone().await?;
        if let Err(e) = self.unregister_push().await {
            fail(e)?;
        }
        let server = self.profile.server;
        let seed = self.profile.inbox_seed;
        let addr_seed = self.profile.addr_seed();
        let mut inboxes: Vec<([u8; 32], [u8; 32])> = self
            .profile
            .weeks
            .iter()
            .map(|(w, _)| {
                let addr = api::inbox_addr(&addr_seed, *w);
                (addr, api::inbox_owner(&seed, &addr))
            })
            .collect();
        inboxes.push((self.profile.request_inbox, self.profile.request_owner));
        for (mailbox, owner) in inboxes {
            match self
                .rpc
                .delete_inbox(&server, mailbox, owner, now, &mut self.rng)
                .await
            {
                Ok(()) | Err(CoreError::Server(Status::NotFound)) => {}
                Err(e) => fail(e)?,
            }
        }
        match self
            .rpc
            .dir_put(
                &server,
                DirKind::Vault,
                self.profile.vault_locator,
                api::vault_owner(&self.profile.vault_key),
                api::VAULT_DELETE,
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => fail(e),
        }
    }

    /// Our account was deleted from another device: its tombstone is on our
    /// server.
    pub fn account_deleted(&self) -> bool {
        matches!(self.store.get(NS_PROFILE, DELETED), Ok(Some(_)))
    }

    /// Reading our inboxes failed with `e`: if the server refused because
    /// the account was deleted from another device, say so
    /// ([`Event::AccountDeleted`]) instead of failing.
    pub(crate) async fn deleted_or(&mut self, e: CoreError, now: u64) -> Result<Vec<Event>> {
        if !matches!(e, CoreError::Server(_)) {
            return Err(e);
        }
        let events = self.check_tombstone(now).await?;
        if events.is_empty() {
            Err(e)
        } else {
            Ok(events)
        }
    }

    /// Our manifest is gone from our server: if a valid tombstone for our
    /// root is there instead, the account was deleted (once:
    /// [`Event::AccountDeleted`]).
    pub(crate) async fn check_tombstone(&mut self, now: u64) -> Result<Vec<Event>> {
        if self.account_deleted() {
            return Ok(Vec::new());
        }
        let root = self.account.root_public.0;
        let server = self.profile.server;
        let bytes = match self
            .rpc
            .dir_get(
                &server,
                DirKind::Tombstone,
                DirAction::Get,
                manifest_key(&root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(b) => b,
            Err(e @ CoreError::Net(_)) => return Err(e),
            Err(_) => return Ok(Vec::new()),
        };
        let Ok(t) = enclave_proto::tombstone::Tombstone::decode(&bytes) else {
            return Ok(Vec::new());
        };
        if t.root.0 != root || t.verify().is_err() {
            return Ok(Vec::new());
        }
        self.store.put(NS_PROFILE, DELETED, &[], &mut self.rng)?;
        Ok(vec![Event::AccountDeleted])
    }
}
