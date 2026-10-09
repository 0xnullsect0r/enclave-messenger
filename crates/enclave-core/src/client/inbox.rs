//! The account inbox's weekly addresses (`docs/09-transport.md` §3).
//!
//! Everything comes from the inbox seed in the profile:
//!
//! - **Addresses.** `addr(w)` for week `w` (Unix seconds / 604,800), from
//!   the address seed, which is what contacts get in our greeting: they
//!   follow the weeks without being able to read the inbox or act as its
//!   owner.
//! - **Owner secrets.** One per address, so the server can't link an
//!   account's weeks by the owner hash.
//! - **Read credentials.** One per address and day, registered as hashes
//!   when the address is created (through the end of the week after its
//!   own, when it is still read).
//!
//! Writers use the current week's address, and the week before's when a
//! re-send falls back (the owner may not have been online to create the
//! new one). The owner creates each address in the week before its own,
//! with the write tokens still outstanding registered there too, bound to
//! that address so the server sees unrelated hashes. It reads the current
//! week's address every inbox round and the previous week's one round in
//! four (overlap-week polling).

use super::{Client, Event};
use crate::persist::Profile;
use crate::rpc::Polled;
use crate::{CoreError, Result};
use enclave_rpc::api::{self, FLAG_CREATE};
use enclave_tokens::{Token, token_hash};
use enclave_wire::{Op, RequestHeader};
use std::collections::HashMap;

/// Most token hashes in one registration frame (with its dummies).
const HASHES_PER_FRAME: usize = 400;

/// Outstanding tokens of one contact registered at a new address (more
/// than a contact holds: 32 and a refill in flight).
const REREGISTER_PER_CONTACT: usize = 64;

/// Most tokens registered at a new address, below the server's quota of
/// 4,096 unspent hashes with room for refills.
const REREGISTER_MAX: usize = 3_000;

/// The previous week's address is read one inbox round in this many.
pub(crate) const OVERLAP_EVERY: u64 = 4;

/// A caught-up inbox is re-read one envelope back one poll in this many
/// (a decoy re-fetch: whether a poll brings something says nothing about
/// whether it was new).
const DECOY_EVERY: u8 = 8;

/// Session hints of outstanding tokens at one address: who holds each.
type Hints = HashMap<[u8; 24], ([u8; 64], Token)>;

/// The daily read credentials an address of `week` gets when it's created
/// at `now`: from today through the last day of the week after its own.
pub(crate) fn read_days(p: &Profile, week: u32, now: u64) -> Vec<(u32, [u8; 32])> {
    let today = api::day_of(now);
    let last = (week + 2) * 7 - 1;
    (today..=last)
        .take(api::MAX_READ_DAYS)
        .map(|d| (d, api::credential_hash(&p.read_cred(week, d))))
        .collect()
}

impl Client {
    /// The time the inbox's weeks and days go by: the device's clock,
    /// corrected by the skew the clock check measured (RT-23). A device
    /// whose clock is days off would otherwise write to the wrong week's
    /// address and read with credentials the server refuses.
    pub(crate) fn inbox_now(&self, now: u64) -> u64 {
        match self.clock_skew() {
            Ok(Some(skew)) => now.saturating_add_signed(-skew),
            _ => now,
        }
    }

    /// Create this week's and next week's addresses if they don't exist
    /// yet, and forget ones nobody writes to any more.
    pub(crate) async fn ensure_weeks(&mut self, now: u64) -> Result<()> {
        let now = self.inbox_now(now);
        let w = api::week_of(now);
        for week in [w, w + 1] {
            if self.profile.has_week(week) {
                continue;
            }
            // Made, given our tokens and push registration, and only then
            // recorded: an interrupted step is repeated next time (the
            // server answers `Denied` to a second creation, and registering
            // a hash twice changes nothing).
            let mut p = Profile::decode(&self.profile.encode())?;
            self.create_week(&mut p, week, now).await?;
            self.reregister_tokens(week, now).await?;
            self.reapply_push(week, now).await?;
            self.profile.add_week(week);
            self.save_profile()?;
        }
        if self.profile.weeks.iter().any(|(x, _)| *x + 1 < w) {
            self.profile.drop_before(w - 1);
            self.save_profile()?;
        }
        Ok(())
    }

    /// Create the address of `week` for profile `p` at its server (another
    /// of our devices may have: then it's there already).
    pub(crate) async fn create_week(&mut self, p: &mut Profile, week: u32, now: u64) -> Result<()> {
        let days = read_days(p, week, now);
        match self
            .rpc
            .create_inbox(
                &p.server,
                p.addr(week),
                p.owner(week),
                FLAG_CREATE,
                &days,
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(()) | Err(CoreError::Server(api::Status::Denied)) => {
                p.add_week(week);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Register `tokens` at the address of `week`, bound to it, in shuffled
    /// batches with dummies (`flags` `FLAG_REVOKE` takes them back).
    pub(crate) async fn register_at(
        &mut self,
        week: u32,
        tokens: &[Token],
        dummies: usize,
        flags: u8,
        now: u64,
    ) -> Result<()> {
        let addr = self.profile.addr(week);
        let owner = self.profile.owner(week);
        let hashes: Vec<[u8; 32]> = tokens.iter().map(|t| token_hash(t, &addr)).collect();
        let per = HASHES_PER_FRAME - dummies.min(HASHES_PER_FRAME / 2);
        let mut chunks: Vec<&[[u8; 32]]> = hashes.chunks(per).collect();
        if chunks.is_empty() {
            if dummies == 0 {
                return Ok(());
            }
            chunks.push(&[]);
        }
        for chunk in chunks {
            let batch = if flags & api::FLAG_REVOKE != 0 {
                chunk.to_vec()
            } else {
                enclave_tokens::registration_batch(chunk, dummies, &mut self.rng)?
            };
            let payload = api::frame(&batch.concat(), &mut self.rng)?;
            let h = RequestHeader {
                op: Op::RegisterTokens,
                flags,
                mailbox: addr,
                token: owner,
            };
            let server = self.profile.server;
            self.rpc
                .call_ok(&server, h, &payload, now, &mut self.rng)
                .await?;
        }
        Ok(())
    }

    /// Register every token still outstanding (the pool, and what contacts
    /// were given and haven't used) at the new address of `week`.
    async fn reregister_tokens(&mut self, week: u32, now: u64) -> Result<()> {
        let mut all: Vec<Token> = self.token_pool.clone();
        for (_, toks) in self.all_issued()? {
            // Each contact's newest first, within the server's quota.
            let keep = toks.len().saturating_sub(REREGISTER_PER_CONTACT);
            all.extend(&toks[keep..]);
        }
        all.truncate(REREGISTER_MAX);
        self.register_at(week, &all, super::tokens::POOL_DUMMIES, 0, now)
            .await
    }

    /// The addresses to read this inbox round: the current week's, and in
    /// one round of [`OVERLAP_EVERY`] (every round when `all`) the week
    /// before's, for writers whose clocks are behind or who fell back.
    pub(crate) fn weeks_to_read(&mut self, now: u64, all: bool) -> Vec<u32> {
        let w = api::week_of(self.inbox_now(now));
        let round = self.inbox_rounds;
        self.inbox_rounds = self.inbox_rounds.wrapping_add(1);
        let mut out = Vec::new();
        if self.profile.has_week(w) {
            out.push(w);
        }
        if w > 0 && self.profile.has_week(w - 1) && (all || round % OVERLAP_EVERY == 1) {
            out.push(w - 1);
        }
        out
    }

    /// Read the account inbox's address of `week` in profile `p` (ours, or
    /// an old home being drained), handling what arrived; the cursor is
    /// kept in `p`. `save` persists `p` after each envelope.
    pub(crate) async fn read_week(
        &mut self,
        p: &mut Profile,
        week: u32,
        now: u64,
        save: impl Fn(&mut Self, &Profile) -> Result<()>,
    ) -> Result<Vec<Event>> {
        let now = self.inbox_now(now);
        let cursor = p.cursor(week);
        // A decoy re-fetch now and then: start one envelope back.
        let decoy = cursor > 0 && self.rng.array::<1>("core/decoy-refetch")?[0] % DECOY_EVERY == 0;
        let from = if decoy { cursor - 1 } else { cursor };
        let cred = p.read_cred(week, api::day_of(now));
        let polled = match self
            .rpc
            .poll(&p.server, p.addr(week), cred, from, now, &mut self.rng)
            .await
        {
            Ok(v) => v,
            // A credential refused (a clock the check hasn't caught yet, an
            // address that expired): nothing to read, and the rest of the
            // sync still runs.
            Err(CoreError::Server(api::Status::Denied | api::Status::NotFound)) => Vec::new(),
            Err(e) => return Err(e),
        };
        let addr = p.addr(week);
        let mut hints: Option<Hints> = None;
        let mut events = Vec::new();
        for Polled {
            envelope,
            cursor: seq,
            hint,
        } in polled
        {
            if seq <= cursor {
                continue; // the decoy's repeat
            }
            let from_root = if hint == [0; 24] {
                None
            } else {
                let idx = match &mut hints {
                    Some(h) => h,
                    None => hints.insert(self.hint_index(&addr)?),
                };
                match idx.remove(&hint) {
                    Some((root, token)) => {
                        self.burned(&root, &token)?;
                        Some(root)
                    }
                    None => None,
                }
            };
            match self.handle_direct_from(&envelope, from_root, now) {
                Ok(mut e) => {
                    // A contact who accepted us here: our other devices learn
                    // of them too.
                    for ev in &e {
                        if let Event::Accepted { root } = ev {
                            self.sync_contact_to_own(root, true)?;
                        }
                    }
                    events.append(&mut e);
                }
                // No session opens it yet: held and tried again
                // (`gaps.rs`). Our own cover self-copies never open.
                Err(CoreError::Proto(enclave_proto::ProtoError::NoSession))
                    if from_root != Some(self.account.root_public.0) =>
                {
                    self.hold_unit(&envelope, now)?;
                }
                Err(_) => {}
            }
            p.set_cursor(week, seq);
            save(self, p)?;
        }
        Ok(events)
    }

    /// The hints of every outstanding token at `addr`: who wrote an
    /// envelope that burned it.
    fn hint_index(&self, addr: &[u8; 32]) -> Result<Hints> {
        let mut m = HashMap::new();
        for (root, toks) in self.all_issued()? {
            for t in toks {
                let mut h = [0u8; 24];
                h.copy_from_slice(&token_hash(&t, addr)[..24]);
                m.insert(h, (root, t));
            }
        }
        Ok(m)
    }
}
