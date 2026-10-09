//! "Secure my account" (`docs/03-identity.md` §5.2).
//!
//! After a device was removed that may be in someone else's hands, or any
//! time the person worries, [`Client::secure_account`] (on the device that
//! holds the recovery words, PIN-gated) replaces everything that device
//! could still use, keeping the root, the devices and the security code:
//!
//! 1. a new account identity key and McEliece vault key, published in a new
//!    manifest (co-signed by this device, so contacts take it at once) with
//!    the vault blob under a new locator and key; the old blob is deleted;
//! 2. a new inbox seed (new weekly addresses, owner secrets and read
//!    credentials) and a new request inbox: the account "moves" to the
//!    server it is on (`moves.rs`), so contacts get fresh write tokens for
//!    the new addresses in their session and the old ones die with the old
//!    addresses; our other devices get the new keys as a sealed file;
//! 3. fresh signed prekeys;
//! 4. a PQ ratchet step with every contact (`Content::PqStep`);
//! 5. every group rekeyed: a new sending chain and MAC keys for every
//!    member device, and a new epoch in groups we administer.
//!
//! 6. new notification key chains (`10-push.md` §4) for every contact.
//!
//! Each step goes on from `sync` until done ([`Client::securing`]).

use super::Client;
use super::moves::KEY_NEW_KEYS;
use crate::content::Content;
use crate::persist::NS_SECRETS;
use crate::{CoreError, Result};
use enclave_crypto::kem::{McElieceSecret, X448Secret};
use enclave_proto::group::FLAG_STATE_UPDATE;
use enclave_proto::identity::AccountKeys;
use enclave_proto::recovery::RecoverySecret;
use zeroize::Zeroizing;

/// Setting: the steps after the move still to do (present while securing).
const SECURING: &str = "securing";

impl Client {
    /// Secure the account (see the module docs). Only on the device holding
    /// the recovery words; needs the PIN if one is set.
    pub async fn secure_account(&mut self) -> Result<()> {
        self.require_root_unlocked()?;
        if self.account.root.is_none()
            || self.migration_pending()
            || self.move_pending()
            || self.securing()
        {
            return Err(CoreError::NotAccepted);
        }
        let (identity, identity_public) = X448Secret::generate(&mut self.rng)?;
        let (vault, vault_public) = McElieceSecret::generate(&mut self.rng)?;
        let keys = AccountKeys {
            root: None,
            root_public: self.account.root_public,
            identity,
            identity_public,
            vault,
            vault_public,
        };
        self.store.put(
            NS_SECRETS,
            KEY_NEW_KEYS,
            &keys.export_shared(),
            &mut self.rng,
        )?;
        self.set_setting(SECURING, &[1])?;
        let (server, vault_key) = (self.profile.server, self.rng.array("core/vault-key")?);
        self.start_home_move(server, vault_key).await
    }

    /// "Secure my account" hasn't finished yet.
    pub fn securing(&self) -> bool {
        matches!(self.setting(SECURING), Ok(Some(_)))
    }

    /// The new account keys a securing move publishes, until it switches.
    pub(crate) fn staged_keys(&self) -> Result<Option<AccountKeys>> {
        match self.store.get(NS_SECRETS, KEY_NEW_KEYS)? {
            Some(b) => Ok(Some(AccountKeys::import_shared(&Zeroizing::new(b), None)?)),
            None => Ok(None),
        }
    }

    /// At the switch: the staged keys become ours. Whether there were any.
    pub(crate) fn adopt_staged_keys(&mut self) -> Result<bool> {
        let Some(b) = self.store.get(NS_SECRETS, KEY_NEW_KEYS)? else {
            return Ok(false);
        };
        self.adopt_account_keys(&Zeroizing::new(b))?;
        self.store.delete(NS_SECRETS, KEY_NEW_KEYS)?;
        Ok(true)
    }

    /// Take new shared account keys (from our own securing move, or another
    /// device's), keeping the root if this device holds the words.
    pub(crate) fn adopt_account_keys(&mut self, shared: &[u8]) -> Result<()> {
        let rs = self
            .store
            .get(NS_SECRETS, b"recovery")?
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .map(RecoverySecret::from_bytes);
        let keys = AccountKeys::import_shared(shared, rs.as_ref())?;
        if keys.root_public != self.account.root_public {
            return Err(CoreError::NotAccepted);
        }
        self.account = keys;
        self.store.put(
            NS_SECRETS,
            b"account",
            &self.account.export_shared(),
            &mut self.rng,
        )?;
        Ok(())
    }

    /// After the move: a PQ step with every contact and every group
    /// rekeyed (from `sync`).
    pub(crate) async fn secure_upkeep(&mut self, now: u64) -> Result<()> {
        if !self.securing() || self.move_pending() {
            return Ok(());
        }
        // Fresh signed prekeys, published where we are.
        let publication = self.prekeys.publish(&self.device, now, &mut self.rng)?;
        self.save_prekeys()?;
        let server = self.profile.server;
        self.rpc
            .dir_put(
                &server,
                enclave_rpc::api::DirKind::Bundle,
                enclave_rpc::api::device_key(&self.device.id),
                [0; 32],
                &publication.encode(),
                now,
                &mut self.rng,
            )
            .await?;
        let me = self.account.root_public.0;
        let mut roots: Vec<[u8; 64]> = self
            .sessions
            .keys()
            .map(|(r, _)| *r)
            .filter(|r| *r != me && !self.is_blocked(r) && !self.is_closed(r))
            .collect();
        roots.sort_unstable();
        roots.dedup();
        for root in roots {
            if let Err(e @ CoreError::Net(_)) = self
                .send_content(&root, &Content::PqStep { reply: true }, now)
                .await
            {
                return Err(e);
            }
        }
        let gids: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(g, _)| *g)
            .collect();
        for gid in gids {
            if let Err(e @ CoreError::Net(_)) = self.rekey_group(&gid, now).await {
                return Err(e);
            }
        }
        // New notification chains for every contact (`notify.rs`).
        self.forget_notify_keys()?;
        self.store
            .delete(crate::persist::NS_SETTINGS, SECURING.as_bytes())?;
        Ok(())
    }

    /// A new sending chain for every member device; in a group we
    /// administer, a new epoch too.
    async fn rekey_group(&mut self, gid: &[u8; 32], now: u64) -> Result<()> {
        let me = self.account.root_public.0;
        let admin = self
            .groups
            .get(gid)
            .is_some_and(|e| e.group.state.active().any(|(_, m)| m.root == me && m.admin));
        if !admin {
            return self.rotate_group(gid, None, None, now).await;
        }
        let (next, epoch) = {
            let e = self.groups.get_mut(gid).ok_or(CoreError::NotFound)?;
            let (epoch, secret) = e.group.new_epoch(&mut self.rng)?;
            let next = e.group.state.child(|s| s.epoch = epoch)?;
            e.group.apply_state(next.clone())?;
            (next, (epoch, secret))
        };
        self.save_group(gid)?;
        self.rotate_group(gid, Some(epoch), None, now).await?;
        self.post_group(gid, &next.encode(), FLAG_STATE_UPDATE, now)
            .await
    }
}
