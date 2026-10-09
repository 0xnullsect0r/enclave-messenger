//! Moving the account to another server (`docs/12-servers.md` §4.4).
//!
//! Only the device that holds the recovery words starts a move
//! ([`Client::move_home`]): the root signs where the account went. The new
//! server gets fresh inboxes with fresh owner secrets (the old operator
//! knows the old ones, and must not be able to read or empty the new
//! inboxes), a new manifest version naming the new request inbox, this
//! device's prekeys and the vault key under a fresh locator. Then, step by
//! step and retried from `sync` until done:
//!
//! 1. our other devices are told the new inboxes and secrets, in the old
//!    account inbox where they still read (before the switch);
//! 2. the profile switches to the new server; the old one is kept and its
//!    inboxes are still read for [`DRAIN_SECS`], for whatever was on its way;
//! 3. the root-signed [`ServerMove`] is left on the old server, for people
//!    who hold an old card or invite link ([`Client::follow_moves`]);
//! 4. outstanding invite links are registered with the new request inbox;
//! 5. the username is claimed again on the new server;
//! 6. every contact is told in its session (`Content::ServerMoved`, with
//!    fresh write tokens for the new inbox).
//!
//! Groups we host stay where they are (hosting moves by admin vote).

use super::Client;
use crate::content::Content;
use crate::persist::{self, NS_PROFILE, NS_SECRETS, Profile};
use crate::{CoreError, Result};
use enclave_crypto::seal::SealKey;
use enclave_proto::manifest::{MAX_VALIDITY_SECS, Manifest, SignedManifest};
use enclave_proto::server_move::ServerMove;
use enclave_rpc::api::{
    self as api, DirAction, DirKind, FLAG_CREATE, FLAG_REQUEST_INBOX, Status, device_key,
    manifest_key,
};

/// How long the old server's inboxes are still read after a move (the
/// longest an envelope is kept).
pub const DRAIN_SECS: u64 = 30 * 86_400;
/// Contacts told about our move (root → empty).
const NS_MOVE_TOLD: &str = "home-move-told";
/// The staged new home (secrets): encoded [`Profile`].
const KEY_NEXT: &[u8] = b"move/next";
/// The staged new manifest (signed), until both servers hold it.
const KEY_MANIFEST: &[u8] = b"move/manifest";
/// When the move started (contacts added since need no telling).
const KEY_AT: &str = "home-move-at";
/// The home we left: encoded [`Profile`] ‖ u64 until.
const KEY_OLD: &[u8] = b"old-home";
/// A move announced by another device of ours, applied after the poll.
const KEY_IN: &[u8] = b"home-moved-in";
/// Publish this device's prekeys on the new home (a device told of a move).
const KEY_BUNDLE: &[u8] = b"home-bundle";
const STEP: &str = "home-move-step";

const M_INBOXES: u8 = 1;
const M_MANIFEST: u8 = 2;
const M_BUNDLE: u8 = 4;
const M_OWN: u8 = 8;
const M_SWITCH: u8 = 16;
const M_RECORD: u8 = 32;
const M_INVITES: u8 = 64;
const M_USERNAME: u8 = 128;
const M_ALL: u8 = 255;

/// Longest chain of moves followed from one card.
const MAX_HOPS: usize = 4;

impl Client {
    /// Move the account to server `to`. Only on the device that holds the
    /// recovery words. The move goes on from `sync` until it reached
    /// everything ([`Client::move_pending`]).
    pub async fn move_home(&mut self, to: [u8; 16]) -> Result<()> {
        if self.account.root.is_none() || self.migration_pending() || self.move_pending() {
            return Err(CoreError::NotAccepted);
        }
        if to == self.profile.server {
            return Ok(());
        }
        let next = Profile {
            server: to,
            inbox_seed: self.rng.array("core/inbox-seed")?,
            request_inbox: self.rng.array("core/request-inbox")?,
            request_owner: self.rng.array("core/request-owner")?,
            vault_locator: self.rng.array("core/vault-locator")?,
            vault_key: self.profile.vault_key,
            name: self.profile.name.clone(),
            weeks: Vec::new(),
            request_cursor: 0,
            created_at: self.profile.created_at,
        };
        self.store
            .put(NS_SECRETS, KEY_NEXT, &next.encode(), &mut self.rng)?;
        for (k, _) in self.store.scan(NS_MOVE_TOLD)? {
            self.store.delete(NS_MOVE_TOLD, &k)?;
        }
        let now = self.now();
        self.set_setting(KEY_AT, &now.to_be_bytes())?;
        self.set_setting(STEP, &[0])?;
        match self.push_home_move(now).await {
            Err(CoreError::Net(_)) | Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Our move hasn't reached everything yet (contacts who haven't
    /// answered our greeting yet are told when they do, and don't count).
    pub fn move_pending(&self) -> bool {
        self.move_step() != M_ALL
            || self
                .untold_contacts()
                .any(|r| self.contacts.get(&r).is_some_and(|c| !c.tokens.is_empty()))
    }

    fn move_step(&self) -> u8 {
        self.setting(STEP)
            .ok()
            .flatten()
            .and_then(|v| v.first().copied())
            .unwrap_or(M_ALL)
    }

    fn untold_contacts(&self) -> impl Iterator<Item = [u8; 64]> + '_ {
        // Contacts added since got the new home in their greeting.
        let at = self
            .setting(KEY_AT)
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes);
        self.contacts
            .values()
            .filter(move |c| {
                at.is_some_and(|at| c.added_at <= at)
                    && !self.is_blocked(&c.root)
                    && self.sessions.keys().any(|(r, _)| *r == c.root)
                    && self
                        .store
                        .get(NS_MOVE_TOLD, &c.root)
                        .ok()
                        .flatten()
                        .is_none()
            })
            .map(|c| c.root)
    }

    /// The home we left and until when its inboxes are read.
    fn old_home(&self) -> Result<Option<(Profile, u64)>> {
        let Some(b) = self.store.get(NS_PROFILE, KEY_OLD)? else {
            return Ok(None);
        };
        let n = b.len().checked_sub(8).ok_or(CoreError::NotFound)?;
        let until = u64::from_be_bytes(b[n..].try_into().map_err(|_| CoreError::NotFound)?);
        Ok(Some((Profile::decode(&b[..n])?, until)))
    }

    fn set_old_home(&mut self, p: &Profile, until: u64) -> Result<()> {
        let v = [p.encode(), until.to_be_bytes().to_vec()].concat();
        self.store.put(NS_PROFILE, KEY_OLD, &v, &mut self.rng)?;
        Ok(())
    }

    /// Leave `old` for the staged home: keep the old one to drain, and
    /// forget the write-token pool (registered at the old inbox).
    fn switch_home(&mut self, next: Profile, now: u64) -> Result<()> {
        let old = std::mem::replace(&mut self.profile, next);
        self.set_old_home(&old, now + DRAIN_SECS)?;
        self.save_profile()?;
        // Tokens handed out were registered at the old home's addresses.
        for (k, _) in self.store.scan(crate::persist::NS_ISSUERS)? {
            self.store.delete(crate::persist::NS_ISSUERS, &k)?;
        }
        self.clear_pool()
    }

    /// Carry our move further (from `move_home`, then from `sync`). Each
    /// step is safe to repeat.
    pub(crate) async fn push_home_move(&mut self, now: u64) -> Result<()> {
        let mut step = self.move_step();
        if step == M_ALL {
            return self.tell_move(now).await;
        }
        // Before the switch the new home is staged; after it, it's ours.
        let mut next = match self.store.get(NS_SECRETS, KEY_NEXT)? {
            Some(b) => Profile::decode(&b)?,
            None => Profile::decode(&self.profile.encode())?,
        };
        let to = next.server;
        let save = |c: &mut Self, step: u8| c.set_setting(STEP, &[step]);
        // Repeating an upload the server already holds is refused: done.
        let done = |r: Result<()>| match r {
            Ok(()) | Err(CoreError::Server(Status::Invalid | Status::Denied)) => Ok(()),
            Err(e) => Err(e),
        };
        if step & M_INBOXES == 0 {
            done(
                self.rpc
                    .create_inbox(
                        &to,
                        next.request_inbox,
                        next.request_owner,
                        FLAG_CREATE | FLAG_REQUEST_INBOX,
                        &[],
                        now,
                        &mut self.rng,
                    )
                    .await,
            )?;
            let week = api::week_of(now);
            for w in [week, week + 1] {
                self.create_week(&mut next, w, now).await?;
            }
            if self.store.get(NS_SECRETS, KEY_NEXT)?.is_some() {
                self.store
                    .put(NS_SECRETS, KEY_NEXT, &next.encode(), &mut self.rng)?;
            }
            step |= M_INBOXES;
            save(self, step)?;
        }
        if step & M_MANIFEST == 0 {
            // A new version naming the new request inbox, signed once (a
            // retry posts the very same one), on both servers: contacts who
            // look at the old home until they're told see it too.
            let (m, signed) = match self.store.get(NS_SECRETS, KEY_MANIFEST)? {
                Some(b) => {
                    let signed = SignedManifest::from_bytes(&b)?;
                    (Manifest::decode(&signed.body)?, signed)
                }
                None => {
                    let prev = self.current_signed_manifest(now).await?;
                    let mut m = self.manifest.clone();
                    m.version += 1;
                    m.prev_hash = prev.hash();
                    m.issued_at = now;
                    m.expires_at = now + MAX_VALIDITY_SECS;
                    m.request_inbox = next.request_inbox.to_vec();
                    let signed = m.sign(&self.account, &mut self.rng)?;
                    self.store
                        .put(NS_SECRETS, KEY_MANIFEST, &signed.to_bytes(), &mut self.rng)?;
                    (m, signed)
                }
            };
            let key = manifest_key(&self.account.root_public.0);
            let from = self.profile.server;
            for server in [to, from] {
                // The manifest first: a server takes a device's co-signature
                // only from a device a manifest there lists.
                done(
                    self.rpc
                        .dir_put(
                            &server,
                            DirKind::Manifest,
                            key,
                            [0; 32],
                            &signed.to_bytes(),
                            now,
                            &mut self.rng,
                        )
                        .await,
                )?;
                done(self.cosign_own_on(&server, &signed, m.version, now).await)?;
            }
            self.set_manifest(m, &signed)?;
            self.store.delete(NS_SECRETS, KEY_MANIFEST)?;
            step |= M_MANIFEST;
            save(self, step)?;
        }
        if step & M_BUNDLE == 0 {
            let publication = self.prekeys.publish(&self.device, now, &mut self.rng)?;
            self.save_prekeys()?;
            self.rpc
                .dir_put(
                    &to,
                    DirKind::Bundle,
                    device_key(&self.device.id),
                    [0; 32],
                    &publication.encode(),
                    now,
                    &mut self.rng,
                )
                .await?;
            let owner = enclave_rpc::api::vault_owner(&next.vault_key);
            let blob = persist::seal_large(
                &SealKey::from_bytes(next.vault_key),
                &self.account.vault_public.0[..],
                &mut self.rng,
            )?;
            done(
                self.rpc
                    .dir_put(
                        &to,
                        DirKind::Vault,
                        next.vault_locator,
                        owner,
                        &blob,
                        now,
                        &mut self.rng,
                    )
                    .await,
            )?;
            step |= M_BUNDLE;
            save(self, step)?;
        }
        if step & M_OWN == 0 {
            // Written to the old account inbox, where they still read.
            let c = Content::HomeMoved {
                server: next.server,
                inbox_seed: next.inbox_seed,
                request_inbox: next.request_inbox,
                request_owner: next.request_owner,
                vault_locator: next.vault_locator,
            };
            self.send_own(&c.encode()?, now).await?;
            step |= M_OWN;
            save(self, step)?;
        }
        if step & M_SWITCH == 0 {
            self.switch_home(next, now)?;
            self.store.delete(NS_SECRETS, KEY_NEXT)?;
            step |= M_SWITCH;
            save(self, step)?;
        }
        if step & M_RECORD == 0 {
            let (old, _) = self.old_home()?.ok_or(CoreError::NotFound)?;
            let root = self.account.root.as_ref().ok_or(CoreError::NotAccepted)?;
            let record = ServerMove::sign(
                root,
                old.server,
                self.profile.server,
                &self.server_domain(&self.profile.server).unwrap_or_default(),
                self.profile.request_inbox,
                self.profile.vault_locator,
                now,
                &mut self.rng,
            )?;
            done(
                self.rpc
                    .dir_put(
                        &old.server,
                        DirKind::Moved,
                        manifest_key(&self.account.root_public.0),
                        [0; 32],
                        &record.encode(),
                        now,
                        &mut self.rng,
                    )
                    .await,
            )?;
            step |= M_RECORD;
            save(self, step)?;
        }
        if step & M_INVITES == 0 {
            self.reregister_invites(now).await?;
            step |= M_INVITES;
            save(self, step)?;
        }
        if step & M_USERNAME == 0 {
            if let Some(name) = self.setting("username")?
                && let Ok(name) = String::from_utf8(name)
            {
                // A server without usernames, or the name taken there: the
                // old one stays where it was.
                if let Err(CoreError::Net(e)) = self.claim_username(&name).await {
                    return Err(CoreError::Net(e));
                }
            }
            step |= M_USERNAME;
            save(self, step)?;
        }
        self.tell_move(now).await
    }

    /// Tell every contact we have a session with where to write now.
    async fn tell_move(&mut self, now: u64) -> Result<()> {
        let roots: Vec<[u8; 64]> = self
            .untold_contacts()
            .filter(|r| self.contacts.get(r).is_some_and(|c| !c.tokens.is_empty()))
            .collect();
        for root in roots {
            let tokens = self.issue_tokens(&root, super::HELLO_TOKENS, now).await?;
            let c = Content::ServerMoved {
                server: self.profile.server,
                inbox: self.profile.addr_seed(),
                request_inbox: self.profile.request_inbox,
                vault_locator: self.profile.vault_locator,
                tokens,
            };
            match self.send_content(&root, &c, now).await {
                Ok(()) => self.store.put(NS_MOVE_TOLD, &root, &[], &mut self.rng)?,
                Err(CoreError::Net(e)) => return Err(CoreError::Net(e)),
                // No tokens of theirs yet (they haven't answered our
                // greeting): told once they do.
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// A contact moved: write to the new server, with the new tokens.
    pub(crate) fn on_server_moved(
        &mut self,
        c: &mut super::Contact,
        moved: (&[u8; 16], &[u8; 32], &[u8; 32], &[u8; 32]),
        tokens: Vec<enclave_tokens::Token>,
    ) {
        let (server, inbox, request_inbox, vault_locator) = moved;
        c.server = *server;
        c.inbox = Some(*inbox);
        c.request_inbox = *request_inbox;
        // The old tokens were registered at the old server.
        c.tokens = self.my_share(tokens);
        // Their manifest now names the new request inbox.
        self.stale_manifests.insert(c.root, c.manifest.version);
        let domain = self.server_domain(server).unwrap_or_default();
        if let Some(card) = c.card.as_mut() {
            card.server = *server;
            card.request_inbox = *request_inbox;
            card.vault_locator = *vault_locator;
            card.server_domain = domain;
        }
    }

    /// Another device of ours moved the account: apply it after the poll
    /// (the poll is still saving the old inbox's cursor).
    pub(crate) fn queue_home_moved(&mut self, content: &[u8]) -> Result<()> {
        self.store.put(NS_PROFILE, KEY_IN, content, &mut self.rng)?;
        Ok(())
    }

    /// Apply a move announced by another device of ours, read the old home
    /// until it's drained, and publish our prekeys on the new one.
    pub(crate) async fn home_upkeep(&mut self, now: u64) -> Result<Vec<super::Event>> {
        let mut events = Vec::new();
        if let Some(b) = self.store.get(NS_PROFILE, KEY_IN)? {
            if let Ok(Content::HomeMoved {
                server,
                inbox_seed,
                request_inbox,
                request_owner,
                vault_locator,
            }) = Content::decode(&b)
                && server != self.profile.server
            {
                // The weekly addresses the moving device made are found
                // (and given our tokens) by the next upkeep.
                let next = Profile {
                    server,
                    inbox_seed,
                    request_inbox,
                    request_owner,
                    vault_locator,
                    vault_key: self.profile.vault_key,
                    name: self.profile.name.clone(),
                    weeks: Vec::new(),
                    request_cursor: 0,
                    created_at: self.profile.created_at,
                };
                self.switch_home(next, now)?;
                self.store
                    .put(NS_PROFILE, KEY_BUNDLE, &[1], &mut self.rng)?;
                // The move published a manifest naming the new request
                // inbox: take it from the new home, or greetings that name
                // it would look like a rollback.
                let own = self.account.root_public.0;
                self.stale_manifests.insert(own, self.manifest.version);
            }
            self.store.delete(NS_PROFILE, KEY_IN)?;
        }
        if self.store.get(NS_PROFILE, KEY_BUNDLE)?.is_some() {
            let publication = self.prekeys.publish(&self.device, now, &mut self.rng)?;
            self.save_prekeys()?;
            let server = self.profile.server;
            self.rpc
                .dir_put(
                    &server,
                    DirKind::Bundle,
                    device_key(&self.device.id),
                    [0; 32],
                    &publication.encode(),
                    now,
                    &mut self.rng,
                )
                .await?;
            self.store.delete(NS_PROFILE, KEY_BUNDLE)?;
        }
        events.append(&mut self.drain_old_home(now).await?);
        Ok(events)
    }

    /// Read what reached the old home's inboxes after we left it.
    async fn drain_old_home(&mut self, now: u64) -> Result<Vec<super::Event>> {
        let Some((mut old, until)) = self.old_home()? else {
            return Ok(Vec::new());
        };
        if now > until {
            self.store.delete(NS_PROFILE, KEY_OLD)?;
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        let reqs = self
            .rpc
            .poll(
                &old.server,
                old.request_inbox,
                api::read_credential(&old.request_owner),
                old.request_cursor,
                now,
                &mut self.rng,
            )
            .await?;
        for polled in reqs {
            match self.handle_request(&polled.envelope, now).await {
                Ok(Some(e)) => events.push(e),
                Err(e @ CoreError::Net(_)) => {
                    self.set_old_home(&old, until)?;
                    return Err(e);
                }
                _ => {}
            }
            old.request_cursor = polled.cursor;
            self.set_old_home(&old, until)?;
        }
        let weeks: Vec<u32> = old.weeks.iter().map(|(w, _)| *w).collect();
        for week in weeks {
            let mut got = self
                .read_week(&mut old, week, now, |c, p| c.set_old_home(p, until))
                .await?;
            events.append(&mut got);
        }
        Ok(events)
    }

    /// Follow root-signed moves from `card`'s server to where the account
    /// lives now (someone holding an old card or invite link). A server
    /// with no record for the account answers `NotFound`: the card stands.
    pub async fn follow_moves(
        &mut self,
        card: &crate::card::ContactCard,
    ) -> Result<crate::card::ContactCard> {
        let mut card = card.clone();
        let now = self.now();
        for _ in 0..MAX_HOPS {
            let got = self
                .rpc
                .dir_get(
                    &card.server,
                    DirKind::Moved,
                    DirAction::Get,
                    manifest_key(&card.root),
                    [0; 32],
                    now,
                    &mut self.rng,
                )
                .await;
            let bytes = match got {
                Ok(b) => b,
                Err(CoreError::Server(Status::NotFound | Status::Malformed)) => break,
                Err(e) => return Err(e),
            };
            let m = ServerMove::decode(&bytes)?;
            m.verify()?;
            if m.root.0 != card.root || m.from != card.server {
                return Err(enclave_proto::ProtoError::BadSignature.into());
            }
            card.server = m.to;
            card.request_inbox = m.request_inbox;
            card.vault_locator = m.vault_locator;
            card.server_domain = m.to_domain;
        }
        Ok(card)
    }
}
