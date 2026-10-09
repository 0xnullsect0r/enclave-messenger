//! Encodings of client records kept in the sealed store.

use crate::card::ContactCard;
use crate::client::{Contact, ContactState};
use crate::content::Token;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::manifest::Manifest;
use enclave_proto::{ProtoError, Result};

pub(crate) const NS_PROFILE: &str = "profile";
pub(crate) const NS_SECRETS: &str = "secrets";
pub(crate) const NS_CONTACTS: &str = "contacts";
pub(crate) const NS_SESSIONS: &str = "sessions";
pub(crate) const NS_ISSUERS: &str = "issuers";
pub(crate) const NS_REPLAY: &str = "replay";
pub(crate) const NS_SETTINGS: &str = "settings";

/// Namespace holding one contact's messages.
pub(crate) fn msg_ns(root: &[u8; 64]) -> String {
    let mut s = String::from("m/");
    for b in &root[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Where this account lives and how to read it.
pub(crate) struct Profile {
    pub server: [u8; 16],
    /// The account inbox's seed: its weekly addresses, their owner secrets
    /// and its read credentials all come from it (`docs/09-transport.md`
    /// §3.1).
    pub inbox_seed: [u8; 32],
    pub request_inbox: [u8; 32],
    pub request_owner: [u8; 32],
    pub vault_locator: [u8; 32],
    pub vault_key: [u8; 32],
    pub name: String,
    /// The weekly addresses that exist at the server, with how far each
    /// has been read, oldest first.
    pub weeks: Vec<(u32, u64)>,
    pub request_cursor: u64,
    pub created_at: u64,
}

/// Most weekly addresses a profile keeps track of.
const MAX_WEEKS: usize = 8;

impl Profile {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(2)
            .fixed(&self.server)
            .fixed(&self.inbox_seed)
            .fixed(&self.request_inbox)
            .fixed(&self.request_owner)
            .fixed(&self.vault_locator)
            .fixed(&self.vault_key)
            .bytes(self.name.as_bytes())
            .u8(self.weeks.len() as u8);
        for (week, cursor) in &self.weeks {
            w.u32(*week).u64(*cursor);
        }
        w.u64(self.request_cursor).u64(self.created_at);
        w.finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 2 {
            return Err(ProtoError::Decode);
        }
        let server = r.array()?;
        let inbox_seed = r.array()?;
        let request_inbox = r.array()?;
        let request_owner = r.array()?;
        let vault_locator = r.array()?;
        let vault_key = r.array()?;
        let name = String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
        let n = usize::from(r.u8()?);
        if n > MAX_WEEKS {
            return Err(ProtoError::Decode);
        }
        let mut weeks = Vec::with_capacity(n);
        for _ in 0..n {
            weeks.push((r.u32()?, r.u64()?));
        }
        let p = Self {
            server,
            inbox_seed,
            request_inbox,
            request_owner,
            vault_locator,
            vault_key,
            name,
            weeks,
            request_cursor: r.u64()?,
            created_at: r.u64()?,
        };
        r.end()?;
        Ok(p)
    }

    /// What contacts are given to follow the weekly addresses.
    pub fn addr_seed(&self) -> [u8; 32] {
        enclave_rpc::api::inbox_addr_seed(&self.inbox_seed)
    }

    /// The account inbox's address in `week`.
    pub fn addr(&self, week: u32) -> [u8; 32] {
        enclave_rpc::api::inbox_addr(&self.addr_seed(), week)
    }

    /// The owner secret of the address of `week`.
    pub fn owner(&self, week: u32) -> [u8; 32] {
        enclave_rpc::api::inbox_owner(&self.inbox_seed, &self.addr(week))
    }

    /// The read credential of the address of `week` on `day`.
    pub fn read_cred(&self, week: u32, day: u32) -> [u8; 24] {
        let key = enclave_rpc::api::inbox_read_key(&self.inbox_seed);
        enclave_rpc::api::daily_read_credential(&key, &self.addr(week), day)
    }

    /// Whether the address of `week` exists at the server.
    pub fn has_week(&self, week: u32) -> bool {
        self.weeks.iter().any(|(w, _)| *w == week)
    }

    /// How far the address of `week` has been read.
    pub fn cursor(&self, week: u32) -> u64 {
        self.weeks
            .iter()
            .find(|(w, _)| *w == week)
            .map_or(0, |(_, c)| *c)
    }

    /// Record how far the address of `week` has been read.
    pub fn set_cursor(&mut self, week: u32, cursor: u64) {
        if let Some(e) = self.weeks.iter_mut().find(|(w, _)| *w == week) {
            e.1 = cursor;
        }
    }

    /// Note that the address of `week` exists, forgetting ones too old to
    /// be read any more.
    pub fn add_week(&mut self, week: u32) {
        if !self.has_week(week) {
            self.weeks.push((week, 0));
            self.weeks.sort_unstable();
        }
        let drop = self.weeks.len().saturating_sub(MAX_WEEKS);
        self.weeks.drain(..drop);
    }

    /// Forget addresses before `week`.
    pub fn drop_before(&mut self, week: u32) {
        self.weeks.retain(|(w, _)| *w >= week);
    }

    /// The weeks whose addresses writers may use now (the current one,
    /// the one before for a writer whose clock is behind or whose re-send
    /// falls back, the next one ahead of a boundary) and that exist.
    pub fn live_weeks(&self, now: u64) -> Vec<u32> {
        let w = enclave_rpc::api::week_of(now);
        self.weeks
            .iter()
            .map(|(x, _)| *x)
            .filter(|x| *x + 1 >= w && *x <= w + 1)
            .collect()
    }
}

fn state_byte(s: ContactState) -> u8 {
    match s {
        ContactState::Pending => 0,
        ContactState::Request => 1,
        ContactState::Accepted => 2,
    }
}

pub(crate) fn encode_contact(c: &Contact) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(1)
        .fixed(&c.root)
        .bytes(c.name.as_bytes())
        .u8(state_byte(c.state));
    w.u8(u8::from(c.verified))
        .fixed(&c.server)
        .fixed(&c.request_inbox);
    match &c.inbox {
        Some(i) => w.u8(1).fixed(i),
        None => w.u8(0),
    };
    w.u16(c.tokens.len() as u16);
    for t in &c.tokens {
        w.fixed(t);
    }
    w.bytes(&c.manifest.encode()?);
    w.u64(c.next_seq)
        .u32(c.received_since_refill)
        .u32(c.unread)
        .u64(c.added_at);
    w.bytes(&c.card.as_ref().map(ContactCard::encode).unwrap_or_default());
    w.u8(u8::from(c.group_only)).u32(c.timer);
    Ok(w.finish())
}

pub(crate) fn decode_contact(b: &[u8]) -> Result<Contact> {
    let mut r = Reader::new(b);
    if r.u8()? != 1 {
        return Err(ProtoError::Decode);
    }
    let root = r.array()?;
    let name = String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
    let state = match r.u8()? {
        0 => ContactState::Pending,
        1 => ContactState::Request,
        2 => ContactState::Accepted,
        _ => return Err(ProtoError::Decode),
    };
    let verified = r.u8()? == 1;
    let server = r.array()?;
    let request_inbox = r.array()?;
    let inbox = match r.u8()? {
        0 => None,
        1 => Some(r.array()?),
        _ => return Err(ProtoError::Decode),
    };
    let n = r.u16()? as usize;
    let tokens: Vec<Token> = (0..n).map(|_| r.array()).collect::<Result<_>>()?;
    let manifest = Manifest::decode(r.bytes(1 << 20)?)?;
    let c = Contact {
        root,
        name,
        state,
        verified,
        server,
        request_inbox,
        inbox,
        tokens,
        manifest,
        next_seq: r.u64()?,
        received_since_refill: r.u32()?,
        unread: r.u32()?,
        added_at: r.u64()?,
        card: {
            let b = r.bytes(crate::content::MAX_CARD)?;
            if b.is_empty() {
                None
            } else {
                Some(ContactCard::decode(b).map_err(|_| ProtoError::Decode)?)
            }
        },
        group_only: r.u8()? == 1,
        timer: r.u32()?,
    };
    r.end()?;
    Ok(c)
}

/// Seal a large public object (the McEliece vault key) for the directory.
pub(crate) fn seal_large(key: &SealKey, data: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 60_000 * 72 + 72);
    let n = data.len().div_ceil(60_000);
    for (i, seg) in data.chunks(60_000).enumerate() {
        let ad = [&(i as u64).to_be_bytes()[..], &[u8::from(i + 1 == n)]].concat();
        let s = seal::seal(key, &ad, seg, rng)?;
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(&s);
    }
    Ok(out)
}

/// Inverse of [`seal_large`]; truncation is caught by the last-segment flag.
pub(crate) fn open_large(key: &SealKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut i = 0u64;
    while off < data.len() {
        let len: [u8; 4] = data
            .get(off..off + 4)
            .ok_or(ProtoError::Decode)?
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        off += 4;
        let n = u32::from_be_bytes(len) as usize;
        let seg = data.get(off..off + n).ok_or(ProtoError::Decode)?;
        off += n;
        let ad = [&i.to_be_bytes()[..], &[u8::from(off == data.len())]].concat();
        out.extend_from_slice(&seal::open(key, &ad, seg)?);
        i += 1;
    }
    if i == 0 {
        return Err(ProtoError::Decode);
    }
    Ok(out)
}
