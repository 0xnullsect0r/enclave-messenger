//! Invite links (`docs/03-identity.md` §7.3, §9.2).
//!
//! An invite link is our contact card plus a fresh 256-bit secret. The
//! secret gives
//!
//! * a **one-way PSK** mixed into the session (`eqxdh::invite_psk`): someone
//!   who breaks every KEM but never saw the link still can't read it;
//! * **request-inbox capabilities** (`eqxdh::invite_cap`) whose token hashes
//!   we register at our server, standing in for the proof of work. The
//!   server burns each on use, and cancelling a link removes the rest.
//!
//! A link brings at most `uses` people (default one) and lapses after
//! [`INVITE_TTL_SECS`]. Requests that come through one still wait in
//! Message requests. The plain QR code (no secret) keeps working as before.
//!
//! **Group invite links** (`docs/07-groups.md` §9) are an admin's invite
//! link bound to a group: `enclave:join#` + base64url(`u8(1) ‖
//! bytes(card with invite) ‖ group id (32) ‖ bytes(group name)`). A
//! greeting through one is a **join request**: with admin approval (the
//! default) it waits until the admin approves, which accepts the person and
//! adds them to the group (a new epoch, so they read nothing from before);
//! without approval that happens as soon as it arrives.

use super::Client;
use crate::card::{ContactCard, Invite, LinkError, MAX_INVITE_USES, b64url_decode, b64url_encode};
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::eqxdh;
use enclave_proto::manifest::MAX_DEVICES;
use enclave_rpc::api::{self, FLAG_REVOKE};
use enclave_wire::{Op, RequestHeader};
use zeroize::Zeroizing;

const NS_INVITES: &str = "invites";
/// Join requests waiting for approval: root → group id.
pub(crate) const NS_JOIN_REQS: &str = "join-requests";
/// Groups we asked to join: group id → name.
const NS_JOINING: &str = "joining";
/// URI prefix of group invite links.
pub const JOIN_PREFIX: &str = "enclave:join#";
/// Longest group name carried in a link.
const MAX_GROUP_NAME: usize = 64;
/// How long an invite link works.
pub const INVITE_TTL_SECS: u64 = 7 * 86_400;
/// Capabilities per use: one per device of the person joining.
pub(crate) const CAPS_PER_USE: u32 = MAX_DEVICES as u32;

/// An invite's store key and its PSK.
pub(crate) type InvitePsk = ([u8; 32], Zeroizing<[u8; 32]>);

/// An invite link we made that still works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteInfo {
    /// People it can bring.
    pub uses: u8,
    /// People it has brought.
    pub used: u8,
    /// When it stops working (Unix seconds).
    pub expires: u64,
}

struct Stored {
    secret: Zeroizing<[u8; 32]>,
    uses: u8,
    expires: u64,
    used_by: Vec<[u8; 64]>,
    /// A group invite: the group, and whether joins need approval.
    group: Option<([u8; 32], bool)>,
}

/// A parsed group invite link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinLink {
    /// The admin's card, with the invite.
    pub card: ContactCard,
    /// The group.
    pub group: [u8; 32],
    /// Its name (as the admin gave it; shown as a suggestion).
    pub name: String,
}

impl JoinLink {
    /// `enclave:join#…`.
    pub fn to_link(&self) -> String {
        let mut w = Writer::new();
        w.u8(1)
            .bytes(&self.card.encode())
            .fixed(&self.group)
            .bytes(self.name.as_bytes());
        format!("{JOIN_PREFIX}{}", b64url_encode(&w.finish()))
    }

    /// Parse a group invite link.
    pub fn parse(s: &str) -> std::result::Result<Self, LinkError> {
        let body = s
            .trim()
            .strip_prefix(JOIN_PREFIX)
            .ok_or(LinkError::NotEnclave)?;
        let b = b64url_decode(body).ok_or(LinkError::Malformed)?;
        let m = |_| LinkError::Malformed;
        let mut r = Reader::new(&b);
        if r.u8().map_err(m)? != 1 {
            return Err(LinkError::Malformed);
        }
        let card = ContactCard::decode(r.bytes(crate::content::MAX_CARD).map_err(m)?)?;
        let group = r.array().map_err(m)?;
        let name = String::from_utf8(r.bytes(MAX_GROUP_NAME).map_err(m)?.to_vec())
            .map_err(|_| LinkError::Malformed)?;
        r.end().map_err(m)?;
        if card.invite.is_none() {
            return Err(LinkError::Malformed);
        }
        Ok(Self { card, group, name })
    }
}

impl Stored {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(2)
            .fixed(&self.secret[..])
            .u8(self.uses)
            .u64(self.expires)
            .u8(self.used_by.len() as u8);
        for r in &self.used_by {
            w.fixed(r);
        }
        match &self.group {
            Some((g, approve)) => w.u8(1).fixed(g).u8(u8::from(*approve)),
            None => w.u8(0),
        };
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let version = r.u8().ok()?;
        if version != 1 && version != 2 {
            return None;
        }
        let secret = Zeroizing::new(r.array().ok()?);
        let uses = r.u8().ok()?;
        let expires = r.u64().ok()?;
        let n = r.u8().ok()?;
        let used_by = (0..n)
            .map(|_| r.array())
            .collect::<std::result::Result<_, _>>()
            .ok()?;
        let group = if version == 2 && r.u8().ok()? == 1 {
            Some((r.array().ok()?, r.u8().ok()? == 1))
        } else {
            None
        };
        r.end().ok()?;
        Some(Self {
            secret,
            uses,
            expires,
            used_by,
            group,
        })
    }

    fn key(&self) -> [u8; 32] {
        eqxdh::invite_cap(&self.secret, u32::MAX)
    }

    /// What the request inbox's server stores for each capability, bound
    /// to that inbox.
    fn cap_hashes(&self, request_inbox: &[u8; 32]) -> Vec<[u8; 32]> {
        (0..u32::from(self.uses) * CAPS_PER_USE)
            .map(|i| api::cap_hash(&eqxdh::invite_cap(&self.secret, i), request_inbox))
            .collect()
    }
}

impl Client {
    /// A new invite link for up to `uses` people (1 to 20), good for
    /// [`INVITE_TTL_SECS`].
    pub async fn create_invite(&mut self, uses: u8) -> Result<String> {
        Ok(self.make_invite(uses, None).await?.to_link())
    }

    /// A group invite link for up to `uses` people. `approve`: each join
    /// waits for an admin (the app's default). Admins only.
    pub async fn create_group_invite(
        &mut self,
        gid: &[u8; 32],
        uses: u8,
        approve: bool,
    ) -> Result<String> {
        let g = self
            .groups()
            .into_iter()
            .find(|g| g.id == *gid && !g.left)
            .ok_or(CoreError::NotFound)?;
        if !g.admin {
            return Err(CoreError::NotAccepted);
        }
        let card = self.make_invite(uses, Some((*gid, approve))).await?;
        let mut name = g.name.clone();
        while name.len() > MAX_GROUP_NAME {
            name.pop();
        }
        Ok(JoinLink {
            card,
            group: *gid,
            name,
        }
        .to_link())
    }

    async fn make_invite(
        &mut self,
        uses: u8,
        group: Option<([u8; 32], bool)>,
    ) -> Result<ContactCard> {
        let uses = uses.clamp(1, MAX_INVITE_USES);
        let now = self.now();
        let inv = Stored {
            secret: Zeroizing::new(self.rng.array("core/invite")?),
            uses,
            expires: now + INVITE_TTL_SECS,
            used_by: Vec::new(),
            group,
        };
        self.register_caps(&inv.cap_hashes(&self.profile.request_inbox), 0, now)
            .await?;
        self.store
            .put(NS_INVITES, &inv.key(), &inv.encode(), &mut self.rng)?;
        let mut card = self.card();
        card.invite = Some(Invite {
            secret: *inv.secret,
            uses,
        });
        Ok(card)
    }

    /// Ask to join the group of a group invite link: greet its admin
    /// through the link. Returns the group's name. Once an admin approves,
    /// the group arrives like any other.
    pub async fn join_group(&mut self, link: &str) -> Result<String> {
        let j = JoinLink::parse(link)?;
        if self.groups().iter().any(|g| g.id == j.group && !g.left) {
            return Ok(j.name);
        }
        if self.contact(&j.card.root).is_some() {
            // An existing conversation carries no invite; they can add us.
            return Err(LinkError::AlreadyContact.into());
        }
        self.add_contact(&j.card, "").await?;
        self.store
            .put(NS_JOINING, &j.group, j.name.as_bytes(), &mut self.rng)?;
        Ok(j.name)
    }

    /// Groups we asked to join that haven't let us in yet: (id, name).
    pub fn joining(&self) -> Vec<([u8; 32], String)> {
        let joined: Vec<[u8; 32]> = self.groups().iter().map(|g| g.id).collect();
        self.store
            .scan(NS_JOINING)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                let id: [u8; 32] = k.try_into().ok()?;
                (!joined.contains(&id)).then(|| (id, String::from_utf8_lossy(&v).into_owned()))
            })
            .collect()
    }

    /// The group `root` asked to join through one of our links, if waiting
    /// for approval.
    pub fn join_request(&self, root: &[u8; 64]) -> Option<[u8; 32]> {
        self.store.get(NS_JOIN_REQS, root).ok()??.try_into().ok()
    }

    /// Let them in: accept the conversation and add them to the group.
    pub async fn approve_join(&mut self, root: &[u8; 64]) -> Result<()> {
        let gid = self.join_request(root).ok_or(CoreError::NotFound)?;
        self.accept(root).await?;
        self.add_group_members(&gid, &[*root]).await?;
        self.store.delete(NS_JOIN_REQS, root)?;
        Ok(())
    }

    /// Turn a join request down (they are not told).
    pub fn decline_join(&mut self, root: &[u8; 64]) -> Result<()> {
        self.store.delete(NS_JOIN_REQS, root)?;
        self.remove_contact(root)
    }

    /// The group bound to invite `key`, with its approval setting.
    pub(crate) fn invite_group(&self, key: &[u8; 32]) -> Option<([u8; 32], bool)> {
        Stored::decode(&self.store.get(NS_INVITES, key).ok()??)?.group
    }

    /// Remember a join request from `root` for `gid`.
    pub(crate) fn note_join_request(&mut self, root: &[u8; 64], gid: &[u8; 32]) -> Result<()> {
        self.store.put(NS_JOIN_REQS, root, gid, &mut self.rng)?;
        Ok(())
    }

    /// Invite links that still work.
    pub fn invites(&self) -> Result<Vec<InviteInfo>> {
        let now = self.now();
        Ok(self
            .stored_invites()?
            .into_iter()
            .filter(|i| i.expires > now && (i.used_by.len() as u8) < i.uses)
            .map(|i| InviteInfo {
                uses: i.uses,
                used: i.used_by.len() as u8,
                expires: i.expires,
            })
            .collect())
    }

    /// Cancel every invite link: our server forgets their capabilities and
    /// we stop accepting their PSKs.
    pub async fn cancel_invites(&mut self) -> Result<()> {
        let now = self.now();
        for inv in self.stored_invites()? {
            self.drop_invite(&inv, now).await?;
        }
        Ok(())
    }

    /// Cancel links that lapsed or brought everyone they could.
    pub(crate) async fn expire_invites(&mut self, now: u64) -> Result<()> {
        for inv in self.stored_invites()? {
            if inv.expires <= now {
                self.drop_invite(&inv, now).await?;
            }
        }
        Ok(())
    }

    /// PSKs of links that still work, with their keys, for opening a
    /// greeting that says it used one.
    pub(crate) fn invite_psks(&self) -> Result<Vec<InvitePsk>> {
        let now = self.now();
        Ok(self
            .stored_invites()?
            .into_iter()
            .filter(|i| i.expires > now)
            .map(|i| (i.key(), eqxdh::invite_psk(&i.secret)))
            .collect())
    }

    /// A greeting from `root` opened with the invite `key`'s PSK. Counts
    /// them against the link; false if it has already brought everyone
    /// it could (the greeting is then dropped). More devices of someone it
    /// already brought are fine. Once a link is used up, its remaining
    /// capabilities are cancelled, so the next person is told at once.
    pub(crate) async fn use_invite(&mut self, key: &[u8; 32], root: &[u8; 64]) -> Result<bool> {
        let Some(b) = self.store.get(NS_INVITES, key)? else {
            return Ok(false);
        };
        let mut inv = Stored::decode(&b).ok_or(CoreError::NotFound)?;
        if inv.used_by.contains(root) {
            return Ok(true);
        }
        if inv.used_by.len() >= usize::from(inv.uses) {
            return Ok(false);
        }
        inv.used_by.push(*root);
        self.store
            .put(NS_INVITES, key, &inv.encode(), &mut self.rng)?;
        if inv.used_by.len() >= usize::from(inv.uses) {
            // Keep the record (its PSK still opens greetings from the other
            // devices of the people it brought) until it lapses.
            let now = self.now();
            self.register_caps(
                &inv.cap_hashes(&self.profile.request_inbox),
                FLAG_REVOKE,
                now,
            )
            .await?;
        }
        Ok(true)
    }

    fn stored_invites(&self) -> Result<Vec<Stored>> {
        Ok(self
            .store
            .scan(NS_INVITES)?
            .into_iter()
            .filter_map(|(_, v)| Stored::decode(&v))
            .collect())
    }

    async fn drop_invite(&mut self, inv: &Stored, now: u64) -> Result<()> {
        self.register_caps(
            &inv.cap_hashes(&self.profile.request_inbox),
            FLAG_REVOKE,
            now,
        )
        .await?;
        self.store.delete(NS_INVITES, &inv.key())?;
        Ok(())
    }

    /// Register every outstanding invite's capabilities again (with a new
    /// request inbox, after moving to another server).
    pub(crate) async fn reregister_invites(&mut self, now: u64) -> Result<()> {
        for inv in self.stored_invites()? {
            if inv.expires > now {
                self.register_caps(&inv.cap_hashes(&self.profile.request_inbox), 0, now)
                    .await?;
            }
        }
        Ok(())
    }

    async fn register_caps(&mut self, hashes: &[[u8; 32]], flags: u8, now: u64) -> Result<()> {
        let payload = api::frame(&hashes.concat(), &mut self.rng)?;
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags,
            mailbox: self.profile.request_inbox,
            token: self.profile.request_owner,
        };
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &payload, now, &mut self.rng)
            .await?;
        Ok(())
    }
}
