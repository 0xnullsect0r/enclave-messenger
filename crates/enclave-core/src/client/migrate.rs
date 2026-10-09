//! Changing the recovery words: a migration to a new root
//! (`docs/03-identity.md` §8.2).
//!
//! Only the root changes. On the device that holds the recovery secret,
//! [`Client::change_recovery_words`] signs the same manifest under a new
//! root, signs the migration with both roots, and commits all of it locally
//! in one step (staged, then flagged, so a crash either loses nothing or
//! resumes on open). Then, step by step and retried until done: the new
//! manifest and the migration go to the directory, the migration (with the
//! manifest, as a sealed file) to every contact, group member and our other
//! devices, a self-only root update to every group, the username to the new
//! root, and fresh recovery shares to the same friends.
//!
//! A contact accepts a migration only inside a session with the old root,
//! from a device both manifests list, with the same identity and vault keys
//! (§8.2.3). It then **renames** the old root to the new one everywhere it
//! keys anything by it (journaled), so afterwards nothing tells the contact
//! apart from one that always had the new root. Group updates that change a
//! member's root wait until the matching migration was accepted.

use super::blocks::NS_BLOCKED;
use super::group_pq::NS_PQ_REPLIES;
use super::guard::NS_PENDING;
use super::invites::NS_JOIN_REQS;
use super::meet::NS_BONDS;
use super::messages::id_ns;
use super::pins::NS_PINS;
use super::prefs::NS_PREFS;
use super::social::NS_HELD_SHARES;
use super::{Client, Event, SessionKey, session_key};
use crate::content::Content;
use crate::files::{self, Attachment};
use crate::persist::{NS_CONTACTS, NS_ISSUERS, NS_PROFILE, NS_SECRETS, NS_SESSIONS, msg_ns};
use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::RootSigningKey;
use enclave_federation::FedError;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::group::{FLAG_STATE_UPDATE, GroupState};
use enclave_proto::manifest::{MAX_VALIDITY_SECS, Manifest, Role, SignedManifest};
use enclave_proto::migration::{MIGRATION_LEN, Migration};
use enclave_proto::recovery::RecoverySecret;
use enclave_rpc::api::{DirKind, Status, manifest_key};
use enclave_store::Store;

/// Verified migrations: old root → new root ‖ cross-signed ‖ time.
const NS_MIGRATIONS: &str = "migrations";
/// Contacts whose account moved, until the person checks them again:
/// new root → old root ‖ cross-signed ‖ time.
const NS_MOVED: &str = "moved-notice";
/// A rename in progress: `b"j"` → old ‖ new.
const NS_RENAME: &str = "rename-journal";
/// Migrations received, waiting to be fetched and checked.
const NS_MIG_IN: &str = "migrations-in";
/// Who has been told about our migration (root, or `b"own"`).
const NS_MIG_TOLD: &str = "migrations-told";
/// Our group root updates not posted yet: group id → state.
const NS_MIG_GROUPS: &str = "migrations-groups";
/// Group updates that change a member's root, waiting for the migration:
/// group id ‖ state hash → author ‖ state.
const NS_HELD_STATES: &str = "held-states";
/// When each held root update was first held: same key → u64 time ‖
/// u8 noticed.
const NS_HELD_SINCE: &str = "held-states-since";
/// How long a root update waits for its migration before the group shows
/// it is on hold (03 §8.2.6).
pub const HELD_MOVE_NOTICE_SECS: u64 = 3600;

/// Progress of our own migration (a bit per step; all set when done).
const STEP: &str = "migration-step";
const S_MANIFEST: u8 = 1;
const S_COSIGN: u8 = 2;
const S_DIRECTORY: u8 = 4;
const S_FILE: u8 = 8;
const S_USERNAME: u8 = 16;
const S_SHARES: u8 = 32;
const S_ALL: u8 = 63;

/// Largest migration file accepted (the record and a five-device manifest).
const MAX_MIGRATION_FILE: u64 = 128 * 1024;

/// A contact's account moved to a new root ([`Client::moved`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Moved {
    /// The old root signed it too: it was them (or someone with their old
    /// words *and* one of their devices).
    pub cross_signed: bool,
    /// When they made the change (their clock).
    pub at: u64,
}

/// Finish a migration committed on this device before a crash: copy the
/// staged secrets and manifest to their places (`Client::open` calls this
/// before reading them).
pub(crate) fn finish_staged(store: &Store, rng: &mut HedgedRng) -> Result<()> {
    if store.get(NS_SECRETS, b"migrating")?.is_none() {
        return Ok(());
    }
    let get = |k: &[u8]| store.get(NS_SECRETS, k)?.ok_or(CoreError::NotFound);
    let record = get(b"mig/record")?;
    let mig = Migration::decode(&record)?;
    store.put(NS_SECRETS, b"recovery", &get(b"mig/recovery")?, rng)?;
    store.put(NS_SECRETS, b"account", &get(b"mig/account")?, rng)?;
    store.put(NS_PROFILE, b"manifest", &get(b"mig/manifest")?, rng)?;
    store.put(NS_PROFILE, b"signed-manifest", &get(b"mig/signed")?, rng)?;
    store.put(NS_PROFILE, b"migration", &record, rng)?;
    store.put(
        NS_RENAME,
        b"j",
        &[&mig.old.0[..], &mig.new.0[..]].concat(),
        rng,
    )?;
    store.put(crate::persist::NS_SETTINGS, STEP.as_bytes(), &[0], rng)?;
    store.delete(crate::persist::NS_SETTINGS, b"recovery-saved")?;
    for (k, _) in store.scan(NS_MIG_TOLD)? {
        store.delete(NS_MIG_TOLD, &k)?;
    }
    for k in [
        &b"mig/recovery"[..],
        b"mig/account",
        b"mig/manifest",
        b"mig/signed",
        b"mig/record",
    ] {
        store.delete(NS_SECRETS, k)?;
    }
    store.delete(NS_SECRETS, b"migrating")?;
    Ok(())
}

/// The root `root` has moved to, following verified migrations.
pub(crate) fn resolve(store: &Store, root: &[u8; 64]) -> [u8; 64] {
    let mut r = *root;
    for _ in 0..8 {
        match store.get(NS_MIGRATIONS, &r) {
            Ok(Some(b)) if b.len() >= 64 => r.copy_from_slice(&b[..64]),
            _ => break,
        }
    }
    r
}

fn two_roots(b: &[u8]) -> Option<([u8; 64], [u8; 64])> {
    if b.len() != 128 {
        return None;
    }
    let mut old = [0u8; 64];
    let mut new = [0u8; 64];
    old.copy_from_slice(&b[..64]);
    new.copy_from_slice(&b[64..]);
    Some((old, new))
}

impl Client {
    // ------------------------------------------------------------------
    // Our own migration
    // ------------------------------------------------------------------

    /// Replace the recovery words (03 §8.2): returns the new 24 words, to
    /// show and have saved. Only on a device that holds the recovery
    /// secret. Contacts, groups and our other devices are told as the
    /// network allows; [`Client::migration_pending`] says when that's done.
    pub async fn change_recovery_words(&mut self) -> Result<Vec<String>> {
        if self.account.root.is_none() {
            return Err(CoreError::NotAccepted);
        }
        self.migrate_root().await
    }

    /// The recovery words are lost, and the device that held them too, but
    /// this device is still in the account ("root lost, devices kept", 03
    /// §8.2): make new words and move the account to them, signed by the
    /// new root only. Contacts are told it can't be confirmed by the old
    /// key and asked to check the security code in person; the directory
    /// keeps the old key's manifest (only the old root could retire it) and
    /// the username stays with the old root. This device becomes the
    /// primary. Only on a device that doesn't hold the words.
    pub async fn replace_lost_root(&mut self) -> Result<Vec<String>> {
        if self.account.root.is_some() {
            return Err(CoreError::NotAccepted);
        }
        self.migrate_root().await
    }

    async fn migrate_root(&mut self) -> Result<Vec<String>> {
        self.require_root_unlocked()?;
        if self.migration_pending() {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        let prev = self.current_signed_manifest(now).await?;
        let old_public = self.account.root_public;
        let rs = RecoverySecret::generate(&mut self.rng)?;
        let words = rs.to_words()?;
        let old_key = self.account.root.take();
        let new_key = RootSigningKey::from_recovery_secret(rs.as_bytes());
        self.account.root_public = new_key.public();
        self.account.root = Some(new_key);
        let me = self.device.id;
        let built = (|| -> Result<(Manifest, SignedManifest, Migration)> {
            let mut m = self.manifest.clone();
            m.version += 1;
            m.prev_hash = prev.hash();
            m.issued_at = now;
            m.expires_at = now + MAX_VALIDITY_SECS;
            m.root = self.account.root_public;
            if old_key.is_none() {
                // The words live here now.
                for d in &mut m.devices {
                    if d.id == me {
                        d.role = Role::Primary;
                    } else if d.role == Role::Primary {
                        d.role = Role::Linked;
                    }
                }
            }
            let signed = m.sign(&self.account, &mut self.rng)?;
            let new_key = self.account.root.as_ref().ok_or(CoreError::NotAccepted)?;
            let mig = Migration::sign(
                old_key.as_ref(),
                old_public,
                new_key,
                &signed,
                now,
                &mut self.rng,
            )?;
            Ok((m, signed, mig))
        })();
        let (m, signed, mig) = match built {
            Ok(b) => b,
            Err(e) => {
                self.account.root = old_key;
                self.account.root_public = old_public;
                return Err(e);
            }
        };
        // Stage everything, then flag it: the commit point.
        let account = self.account.export_shared();
        let s = &self.store;
        s.put(NS_SECRETS, b"mig/recovery", rs.as_bytes(), &mut self.rng)?;
        s.put(NS_SECRETS, b"mig/account", &account, &mut self.rng)?;
        s.put(NS_SECRETS, b"mig/manifest", &m.encode()?, &mut self.rng)?;
        s.put(NS_SECRETS, b"mig/signed", &signed.to_bytes(), &mut self.rng)?;
        s.put(NS_SECRETS, b"mig/record", &mig.encode(), &mut self.rng)?;
        s.put(NS_SECRETS, b"migrating", &[1], &mut self.rng)?;
        finish_staged(&self.store, &mut self.rng)?;
        self.manifest = m;
        self.resume_rename()?;
        // Our votes and polls follow us; group roots change as we post.
        let gids: Vec<[u8; 32]> = self.groups.keys().copied().collect();
        let new_root = self.account.root_public.0;
        for gid in gids {
            self.rename_in_polls(&gid, &old_public.0, &new_root)?;
        }
        if let Err(e) = self.push_migration(now).await
            && !matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        Ok(words)
    }

    /// This device holds the recovery words, so it can change them.
    pub fn holds_recovery_words(&self) -> bool {
        self.account.root.is_some()
    }

    /// Our change of recovery words hasn't reached everything yet (the
    /// directory, the file contacts fetch, the username, recovery shares).
    pub fn migration_pending(&self) -> bool {
        self.store
            .get(NS_PROFILE, b"migration")
            .ok()
            .flatten()
            .is_some()
            && self.step() != S_ALL
    }

    fn step(&self) -> u8 {
        self.setting(STEP)
            .ok()
            .flatten()
            .and_then(|v| v.first().copied())
            .unwrap_or(S_ALL)
    }

    /// Carry our migration further (from `change_recovery_words`, then from
    /// `sync` until everything is done). Each step is safe to repeat.
    pub(crate) async fn push_migration(&mut self, now: u64) -> Result<()> {
        let Some(record) = self.store.get(NS_PROFILE, b"migration")? else {
            return Ok(());
        };
        let mig = Migration::decode(&record)?;
        let (old, new) = (mig.old.0, mig.new.0);
        let server = self.profile.server;
        let mut step = self.step();
        let save = |c: &mut Self, step: u8| c.set_setting(STEP, &[step]);
        let signed = self.current_signed_manifest(now).await?;
        // A repeated upload of something the server already holds is
        // refused as invalid: that step was done.
        let done = |r: Result<()>| match r {
            Ok(()) | Err(CoreError::Server(Status::Invalid)) => Ok(()),
            Err(e) => Err(e),
        };
        if step & S_MANIFEST == 0 {
            done(
                self.rpc
                    .dir_put(
                        &server,
                        DirKind::Manifest,
                        manifest_key(&new),
                        [0; 32],
                        &signed.to_bytes(),
                        now,
                        &mut self.rng,
                    )
                    .await,
            )?;
            step |= S_MANIFEST;
            save(self, step)?;
        }
        if step & S_COSIGN == 0 {
            let version = self.manifest.version;
            self.cosign_own(&signed, version, now).await?;
            step |= S_COSIGN;
            save(self, step)?;
        }
        // Without the old root's signature the server won't retire the old
        // key (anyone could otherwise), so there is nothing to publish.
        if step & S_DIRECTORY == 0 && !mig.cross_signed() {
            step |= S_DIRECTORY;
            save(self, step)?;
        }
        if step & S_DIRECTORY == 0 {
            done(
                self.rpc
                    .dir_put(
                        &server,
                        DirKind::Migration,
                        manifest_key(&old),
                        [0; 32],
                        &record,
                        now,
                        &mut self.rng,
                    )
                    .await,
            )?;
            step |= S_DIRECTORY;
            save(self, step)?;
        }
        if step & S_FILE == 0 {
            let mut w = Writer::new();
            w.bytes(&record).bytes(&signed.to_bytes());
            let (att, chunks) = files::seal_file(
                &w.finish(),
                "migration",
                "application/x-enclave-migration",
                server,
                &mut self.rng,
            )?;
            for (id, chunk) in &chunks {
                self.put_chunk(&server, *id, chunk, now).await?;
            }
            self.store
                .put(NS_PROFILE, b"migration-ref", &att.encode(), &mut self.rng)?;
            step |= S_FILE;
            save(self, step)?;
        }
        self.tell_migration(now).await?;
        self.post_group_roots(&old, &new, now).await?;
        if step & S_USERNAME == 0 {
            if let Some(name) = self.setting("username")?
                && let Ok(name) = String::from_utf8(name)
                && self.kt.is_some()
            {
                match self.claim_username(&name).await {
                    Ok(_) => {}
                    // The name stays with the old root when the server
                    // holds no migration for it (a lost root).
                    Err(CoreError::Net(e)) => return Err(CoreError::Net(e)),
                    Err(_) if !mig.cross_signed() => {}
                    Err(e) => return Err(e),
                }
            }
            step |= S_USERNAME;
            save(self, step)?;
        }
        if step & S_SHARES == 0 {
            if let Some((threshold, holders)) = self.recovery_holders() {
                self.split_recovery(&holders, threshold).await?;
            }
            step |= S_SHARES;
            save(self, step)?;
        }
        Ok(())
    }

    /// Send the migration file to everyone we have a session with who
    /// hasn't had it, and to our other devices.
    async fn tell_migration(&mut self, now: u64) -> Result<()> {
        let Some(att) = self.store.get(NS_PROFILE, b"migration-ref")? else {
            return Ok(());
        };
        let me = self.account.root_public.0;
        let content = Content::Migration(att);
        let mut peers: Vec<[u8; 64]> = self
            .sessions
            .keys()
            .map(|(r, _)| *r)
            .filter(|r| *r != me && !self.is_blocked(r))
            .collect();
        peers.sort_unstable();
        peers.dedup();
        for root in peers {
            if self.store.get(NS_MIG_TOLD, &root)?.is_some() {
                continue;
            }
            match self.send_content(&root, &content, now).await {
                Ok(()) => self.store.put(NS_MIG_TOLD, &root, &[1], &mut self.rng)?,
                // The network: try again later. Anything else (no tokens
                // yet, a contact who never answered): try again later too.
                Err(CoreError::Net(e)) => return Err(CoreError::Net(e)),
                Err(_) => {}
            }
        }
        if self.store.get(NS_MIG_TOLD, b"own")?.is_none()
            && self.sessions.keys().any(|(r, _)| *r == me)
        {
            self.send_own(&content.encode()?, now).await?;
            self.store.put(NS_MIG_TOLD, b"own", &[1], &mut self.rng)?;
        }
        Ok(())
    }

    /// Our root in every group: change it locally and post the update. The
    /// update is stored before it is applied, so a failed post is repeated
    /// with the very same state.
    async fn post_group_roots(&mut self, old: &[u8; 64], new: &[u8; 64], now: u64) -> Result<()> {
        let gids: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(g, _)| *g)
            .collect();
        for gid in gids {
            let next = match self.store.get(NS_MIG_GROUPS, &gid)? {
                Some(b) => GroupState::decode(&b)?,
                None => {
                    let Some(e) = self.groups.get(&gid) else {
                        continue;
                    };
                    let Some(i) = e.group.state.index_of(old) else {
                        continue;
                    };
                    let next = e
                        .group
                        .state
                        .child(|s| s.members[usize::from(i)].root = *new)?;
                    self.store
                        .put(NS_MIG_GROUPS, &gid, &next.encode(), &mut self.rng)?;
                    next
                }
            };
            // A device that hasn't sent here yet (a linked one, after a
            // lost root) needs its sending chain first, under the old root.
            if self
                .groups
                .get(&gid)
                .is_some_and(|e| e.group.state.index_of(old).is_some())
            {
                self.prepare_group_send(&gid, now).await?;
            }
            self.apply_root_change(&gid, &next, old, new)?;
            self.post_group(&gid, &next.encode(), FLAG_STATE_UPDATE, now)
                .await?;
            self.store.delete(NS_MIG_GROUPS, &gid)?;
        }
        Ok(())
    }

    /// Apply a state update that changes `old` to `new` in group `gid`
    /// (unless it already is the current state), and carry the member's
    /// cards, messages, reactions and votes over.
    fn apply_root_change(
        &mut self,
        gid: &[u8; 32],
        next: &GroupState,
        old: &[u8; 64],
        new: &[u8; 64],
    ) -> Result<()> {
        let Some(e) = self.groups.get_mut(gid) else {
            return Ok(());
        };
        if e.group.state.hash() == next.hash() {
            return Ok(());
        }
        if next.parent != e.group.state.hash() {
            return Err(CoreError::NotAccepted);
        }
        e.group.apply_state(next.clone())?;
        if let Some(mut card) = e.cards.remove(old) {
            card.root = *new;
            e.cards.insert(*new, card);
        }
        if e.keyed.remove(old) {
            e.keyed.insert(*new);
        }
        self.save_group(gid)?;
        for mut m in self.group_messages(gid)? {
            let mut changed = false;
            if m.from == Some(*old) {
                m.from = Some(*new);
                changed = true;
            }
            for r in &mut m.reactions {
                if r.from == Some(*old) {
                    r.from = Some(*new);
                    changed = true;
                }
            }
            if changed {
                self.put_group_message(gid, &m)?;
            }
        }
        self.rename_in_polls(gid, old, new)
    }

    // ------------------------------------------------------------------
    // Someone else's migration
    // ------------------------------------------------------------------

    /// A migration arrived in a session with `root` from device `dev`: keep
    /// it until `sync` fetches and checks it.
    pub(crate) fn queue_migration(
        &mut self,
        root: &[u8; 64],
        dev: &[u8; 16],
        att: &[u8],
    ) -> Result<()> {
        let key: [u8; 16] = self.rng.array("core/migration-in")?;
        let v = [&root[..], &dev[..], att].concat();
        self.store.put(NS_MIG_IN, &key, &v, &mut self.rng)?;
        Ok(())
    }

    /// Fetch and check the migrations received (from `sync`).
    pub(crate) async fn process_migrations(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        // Two changes in a row may be queued in either order, and the second
        // only checks out after the first: go round until nothing more does.
        let mut waiting = self.store.scan(NS_MIG_IN)?;
        loop {
            let mut left = Vec::new();
            let before = waiting.len();
            for (k, v) in waiting {
                if v.len() < 80 {
                    self.store.delete(NS_MIG_IN, &k)?;
                    continue;
                }
                let mut root = [0u8; 64];
                let mut dev = [0u8; 16];
                root.copy_from_slice(&v[..64]);
                dev.copy_from_slice(&v[64..80]);
                match self.accept_migration(&root, &dev, &v[80..], now).await {
                    Ok(ev) => {
                        events.extend(ev);
                        self.store.delete(NS_MIG_IN, &k)?;
                    }
                    Err(e @ CoreError::Net(_)) => return Err(e),
                    // Not in their server's log yet: asked again next sync.
                    Err(CoreError::Federation(FedError::NotLogged)) => {}
                    Err(_) => left.push((k, v)),
                }
            }
            if left.is_empty() || left.len() == before {
                // Whatever is left doesn't check out: dropped.
                for (k, _) in left {
                    self.store.delete(NS_MIG_IN, &k)?;
                }
                break;
            }
            waiting = left;
        }
        if !events.is_empty() {
            events.extend(self.retry_held_states()?);
        }
        Ok(events)
    }

    async fn accept_migration(
        &mut self,
        root: &[u8; 64],
        dev: &[u8; 16],
        att: &[u8],
        now: u64,
    ) -> Result<Option<Event>> {
        // Queued before an earlier migration of theirs was accepted: the
        // session is the same, under the root it moved to.
        let root = &self.current_root(root);
        let att = Attachment::decode(att).map_err(|_| CoreError::NotAccepted)?;
        if att.size > MAX_MIGRATION_FILE {
            return Err(CoreError::NotAccepted);
        }
        let data = self.fetch_file(&att).await?;
        let mut r = Reader::new(&data);
        let mig = Migration::decode(r.bytes(MIGRATION_LEN)?)?;
        let signed = SignedManifest::from_bytes(r.bytes(1 << 20)?)?;
        r.end()?;
        // §8.2.3: the old root is the one this session is with; the device
        // is listed before and after; only the root changed.
        let own = *root == self.account.root_public.0;
        let prev = if own {
            self.manifest.clone()
        } else {
            self.contacts
                .get(root)
                .ok_or(CoreError::NotFound)?
                .manifest
                .clone()
        };
        let m = mig.verify(&signed, now)?;
        if mig.old.0 != *root
            || !prev.devices.iter().any(|d| d.id == *dev)
            || !m.devices.iter().any(|d| d.id == *dev)
            || m.identity != prev.identity
            || m.vault_hash != prev.vault_hash
            || m.version <= prev.version
        {
            return Err(CoreError::NotAccepted);
        }
        // Our own: only a device without the words adopts it (one holding
        // them made it, or keeps the account under the old words).
        if own && self.account.root.is_some() {
            return Err(CoreError::NotAccepted);
        }
        // A migration the old root signed is in the directory and the old
        // server's log: take it only once the log shows it, so the same
        // move is shown to everyone (one without that signature is never
        // in either, and is shown as unconfirmed).
        if !own && mig.cross_signed() {
            let server = self.contacts.get(root).map(|c| c.server);
            if let Some(server) = server
                && let Some(v) = self.logged_record(&server, root, now).await?
                && v != enclave_kt::migration_record(&mig.encode())
            {
                return Err(CoreError::Federation(FedError::NotLogged));
            }
        }
        let new = mig.new.0;
        let mut w = Writer::new();
        w.fixed(&new).u8(u8::from(mig.cross_signed())).u64(mig.time);
        self.store
            .put(NS_MIGRATIONS, root, &w.finish(), &mut self.rng)?;
        self.store.put(
            NS_RENAME,
            b"j",
            &[&root[..], &new[..]].concat(),
            &mut self.rng,
        )?;
        if own {
            // A linked device: our primary changed the words.
            self.account.adopt_root(mig.new);
            self.store.put(
                NS_SECRETS,
                b"account",
                &self.account.export_shared(),
                &mut self.rng,
            )?;
            self.set_manifest(m, &signed)?;
            self.resume_rename()?;
            // Our group states change the same way our primary changes them.
            let gids: Vec<[u8; 32]> = self.groups.keys().copied().collect();
            for gid in gids {
                let next = self.groups.get(&gid).and_then(|e| {
                    let i = e.group.state.index_of(root)?;
                    e.group
                        .state
                        .child(|s| s.members[usize::from(i)].root = new)
                        .ok()
                });
                if let Some(next) = next {
                    let _ = self.apply_root_change(&gid, &next, root, &new);
                }
            }
            return Ok(Some(Event::DevicesChanged));
        }
        let mut w = Writer::new();
        w.fixed(root).u8(u8::from(mig.cross_signed())).u64(mig.time);
        self.store.put(NS_MOVED, &new, &w.finish(), &mut self.rng)?;
        self.resume_rename()?;
        if let Some(c) = self.contacts.get_mut(&new) {
            c.manifest = m;
            c.verified = false;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        Ok(Some(Event::ContactMoved {
            old: *root,
            root: new,
            cross_signed: mig.cross_signed(),
        }))
    }

    /// How the contact `root` moved to that root, until they are checked
    /// again ([`Client::set_verified`] clears it).
    pub fn moved(&self, root: &[u8; 64]) -> Option<Moved> {
        let b = self.store.get(NS_MOVED, root).ok()??;
        let mut r = Reader::new(&b);
        let _old: [u8; 64] = r.array().ok()?;
        Some(Moved {
            cross_signed: r.u8().ok()? == 1,
            at: r.u64().ok()?,
        })
    }

    pub(crate) fn clear_moved(&mut self, root: &[u8; 64]) -> Result<()> {
        self.store.delete(NS_MOVED, root)?;
        Ok(())
    }

    /// The root `root` has moved to, if a verified migration says so
    /// (following a chain of them).
    pub(crate) fn current_root(&self, root: &[u8; 64]) -> [u8; 64] {
        resolve(&self.store, root)
    }

    /// Whether a verified migration took `old` directly to `new`.
    fn migrated(&self, old: &[u8; 64], new: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_MIGRATIONS, old), Ok(Some(b)) if b.get(..64) == Some(&new[..]))
    }

    // ------------------------------------------------------------------
    // Group updates that change a member's root
    // ------------------------------------------------------------------

    /// A group update from member `author` that changes only a member's
    /// root. Applied if the migration is known, else held. Returns whether
    /// it was applied.
    pub(crate) fn on_group_root_change(
        &mut self,
        gid: &[u8; 32],
        author: u8,
        next: GroupState,
        old: &[u8; 64],
        new: &[u8; 64],
    ) -> Result<bool> {
        if self.migrated(old, new) {
            self.apply_root_change(gid, &next, old, new)?;
            return Ok(true);
        }
        let key = [&gid[..], &next.hash()[..]].concat();
        let v = [&[author][..], &next.encode()].concat();
        self.store.put(NS_HELD_STATES, &key, &v, &mut self.rng)?;
        if self.store.get(NS_HELD_SINCE, &key)?.is_none() {
            let since = [&self.now().to_be_bytes()[..], &[0]].concat();
            self.store.put(NS_HELD_SINCE, &key, &since, &mut self.rng)?;
        }
        Ok(false)
    }

    fn drop_held_state(&mut self, key: &[u8]) -> Result<()> {
        self.store.delete(NS_HELD_STATES, key)?;
        self.store.delete(NS_HELD_SINCE, key)?;
        Ok(())
    }

    /// The members of group `gid` whose change of recovery words reached
    /// the group but not us, for an hour or more (their old roots): their
    /// key change is on hold here until we get it from them (03 §8.2.6).
    pub fn held_moves(&self, gid: &[u8; 32]) -> Vec<[u8; 64]> {
        self.held_moves_at(self.now())
            .into_iter()
            .filter(|(g, _, _)| g == gid)
            .map(|(_, old, _)| old)
            .collect()
    }

    /// Held root updates past the notice time: group, old root, key.
    fn held_moves_at(&self, now: u64) -> Vec<([u8; 32], [u8; 64], Vec<u8>)> {
        let Ok(held) = self.store.scan(NS_HELD_STATES) else {
            return Vec::new();
        };
        held.into_iter()
            .filter_map(|(k, v)| {
                let gid: [u8; 32] = k.get(..32)?.try_into().ok()?;
                let since = self.store.get(NS_HELD_SINCE, &k).ok()??;
                let since = u64::from_be_bytes(since.get(..8)?.try_into().ok()?);
                if since + HELD_MOVE_NOTICE_SECS > now {
                    return None;
                }
                let next = GroupState::decode(v.get(1..)?).ok()?;
                let current = &self.groups.get(&gid)?.group.state;
                // The group moved past it: nothing is on hold.
                if next.parent != current.hash() {
                    return None;
                }
                let (_, old, _) = current.root_change(&next)?;
                Some((gid, old, k))
            })
            .collect()
    }

    /// Tell the app, once each, about root updates held past the notice
    /// time (from `sync`).
    pub(crate) fn notice_held_moves(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (gid, old, k) in self.held_moves_at(now) {
            let Some(mut since) = self.store.get(NS_HELD_SINCE, &k)? else {
                continue;
            };
            if since.get(8) == Some(&1) {
                continue;
            }
            since.truncate(8);
            since.push(1);
            self.store.put(NS_HELD_SINCE, &k, &since, &mut self.rng)?;
            events.push(Event::GroupMoveHeld {
                group_id: gid,
                root: old,
            });
        }
        Ok(events)
    }

    /// Apply held root updates whose migration has arrived since; drop the
    /// ones the group has moved past.
    fn retry_held_states(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, v) in self.store.scan(NS_HELD_STATES)? {
            let (Some(gid), Some((&author, state))) = (
                k.get(..32).and_then(|g| <[u8; 32]>::try_from(g).ok()),
                v.split_first(),
            ) else {
                self.drop_held_state(&k)?;
                continue;
            };
            let Ok(next) = GroupState::decode(state) else {
                self.drop_held_state(&k)?;
                continue;
            };
            let Some(e) = self.groups.get(&gid) else {
                self.drop_held_state(&k)?;
                continue;
            };
            let current = e.group.state.clone();
            if next.parent != current.hash() || !current.accepts(&next, author) {
                self.drop_held_state(&k)?;
                continue;
            }
            let Some((_, old, new)) = current.root_change(&next) else {
                self.drop_held_state(&k)?;
                continue;
            };
            if !self.migrated(&old, &new) {
                continue; // still waiting
            }
            self.apply_root_change(&gid, &next, &old, &new)?;
            self.drop_held_state(&k)?;
            events.push(Event::GroupChanged { group_id: gid });
        }
        Ok(events)
    }

    // ------------------------------------------------------------------
    // Renaming a root everywhere
    // ------------------------------------------------------------------

    /// Finish a rename recorded in the journal (after a migration, or on
    /// open after a crash).
    pub(crate) fn resume_rename(&mut self) -> Result<()> {
        let Some(j) = self.store.get(NS_RENAME, b"j")? else {
            return Ok(());
        };
        if let Some((old, new)) = two_roots(&j) {
            self.rename_root(&old, &new)?;
        }
        self.store.delete(NS_RENAME, b"j")?;
        Ok(())
    }

    /// Everything keyed by `old` is keyed by `new` afterwards. Safe to run
    /// again after an interruption.
    fn rename_root(&mut self, old: &[u8; 64], new: &[u8; 64]) -> Result<()> {
        if let Some(mut c) = self.contacts.remove(old) {
            c.root = *new;
            if let Some(card) = c.card.as_mut() {
                card.root = *new;
            }
            c.verified = false;
            self.save_contact(&c)?;
            self.contacts.insert(*new, c);
        }
        self.store.delete(NS_CONTACTS, old)?;
        let keys: Vec<SessionKey> = self
            .sessions
            .keys()
            .filter(|(r, _)| r == old)
            .copied()
            .collect();
        for (_, dev) in keys {
            if let Some(s) = self.sessions.remove(&(*old, dev)) {
                self.save_session(new, &dev, &s)?;
                self.sessions.insert((*new, dev), s);
            }
            self.store.delete(NS_SESSIONS, &session_key(old, &dev))?;
        }
        // 1:1 history (disappearing messages are sealed again under the
        // new conversation's shred keys by `put_message`).
        for m in self.messages(old)? {
            self.put_message(new, &m)?;
        }
        for ns in [msg_ns(old), id_ns(old)] {
            for (k, _) in self.store.scan(&ns)? {
                self.store.delete(&ns, &k)?;
            }
        }
        let keyed = |r: &[u8; 64]| r.to_vec();
        let prefixed = |r: &[u8; 64]| [&b"c"[..], &r[..]].concat();
        for (ns, key) in [
            (NS_BLOCKED, keyed as fn(&[u8; 64]) -> Vec<u8>),
            (NS_HELD_SHARES, keyed),
            (NS_PQ_REPLIES, keyed),
            (NS_JOIN_REQS, keyed),
            (NS_ISSUERS, keyed),
            (NS_PINS, prefixed),
            (NS_PREFS, prefixed),
        ] {
            if let Some(v) = self.store.get(ns, &key(old))? {
                self.store.put(ns, &key(new), &v, &mut self.rng)?;
                self.store.delete(ns, &key(old))?;
            }
        }
        // A bond was for the old code; the manifest guard starts afresh.
        self.store.delete(NS_BONDS, old)?;
        self.store.delete(NS_PENDING, old)?;
        self.stale_manifests.remove(old);
        let gids: Vec<[u8; 32]> = self.groups.keys().copied().collect();
        for gid in gids {
            let Some(e) = self.groups.get_mut(&gid) else {
                continue;
            };
            let mut changed = false;
            if let Some(mut card) = e.cards.remove(old) {
                card.root = *new;
                e.cards.insert(*new, card);
                changed = true;
            }
            if e.keyed.remove(old) {
                e.keyed.insert(*new);
                changed = true;
            }
            if changed {
                self.save_group(&gid)?;
            }
        }
        Ok(())
    }
}
