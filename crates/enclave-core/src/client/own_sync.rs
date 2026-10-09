//! Keeping the account's own devices in step (`docs/06-multidevice.md`
//! §5–§6, PLAN D5).
//!
//! What one device does that the others should know travels to them as
//! `Content::OwnSync` over the intra-account sessions, through the shared
//! account inbox:
//!
//! - **Read** — a conversation was read here (the messages' ids), so the
//!   others stop counting it unread. Read receipts go from the device that
//!   read.
//! - **Prefs** — a conversation was archived, pinned or muted.
//! - **Setting** — a synced setting changed (read receipts, typing).
//! - **Contact** — a contact was accepted, added or changed here (its card,
//!   name, checked state, timer, inbox and half of this device's write
//!   tokens for it), so the others can greet it from their own devices.
//! - **Blocked** — someone was blocked or unblocked.
//! - **Position** — how far this device has read each weekly address
//!   (also sent at least once a day, which says the device is in use).
//!
//! Items are queued in the sealed store as they happen (most changes come
//! from synchronous calls) and leave together at the next sync. A device
//! that has no other devices queues nothing.
//!
//! **Watermark.** A device acknowledges an address up to the lowest
//! position every active device of the account has reported (its own
//! included), so the server deletes only what all of them have read.
//!
//! **Inactive devices.** A device none of whose sync messages arrived for
//! [`INACTIVE_SECS`] is inactive: nothing is encrypted to it any more, it
//! doesn't hold the watermark back, and the device holding the root
//! removes it from the account at its next sync (`03-identity.md` §4.4).

use super::{Client, Contact, ContactState, Event};
use crate::card::ContactCard;
use crate::content::{Content, MsgId, Token};
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_rpc::api;
use enclave_wire::{Op, RequestHeader};

pub(crate) const NS_OWN_QUEUE: &str = "own-sync-queue";
/// Contacts who asked for our card (answered at the next sync).
pub(crate) const NS_CARD_OWED: &str = "card-owed";
/// Contacts without a card we have asked for theirs.
const NS_CARD_ASKED: &str = "card-asked";
pub(crate) const NS_OWN_DEVICES: &str = "own-devices";
const NS_ACKED: &str = "own-acked";

/// A device unheard of for this long is inactive.
pub const INACTIVE_SECS: u64 = 30 * 86_400;
/// A device's position is sent at least this often, as a sign of life.
pub const HEARTBEAT_SECS: u64 = 86_400;
/// How long a newly linked device is pointed out on every device.
pub const NEW_DEVICE_SECS: u64 = 7 * 86_400;
/// Settings kept the same on every device of the account.
pub const SYNCED_SETTINGS: [&str; 2] = ["receipts", "typing"];

const T_READ: u8 = 1;
const T_PREFS: u8 = 2;
const T_SETTING: u8 = 3;
const T_CONTACT: u8 = 4;
const T_BLOCKED: u8 = 5;
const T_POSITION: u8 = 6;
const T_GROUP: u8 = 7;
const T_HISTORY_ASK: u8 = 8;
const T_GROUP_SENT: u8 = 9;

/// One thing our other devices should know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncItem {
    Read {
        to: [u8; 64],
        ids: Vec<MsgId>,
    },
    Prefs {
        /// `c ‖ root` or `g ‖ group id` (`prefs.rs`).
        place: Vec<u8>,
        prefs: Vec<u8>,
    },
    Setting {
        key: String,
        value: Vec<u8>,
    },
    Contact {
        card: Vec<u8>,
        name: String,
        verified: bool,
        timer: u32,
        server: [u8; 16],
        inbox: [u8; 32],
        tokens: Vec<Token>,
    },
    Blocked {
        root: [u8; 64],
        on: bool,
    },
    Position {
        week: u32,
        cursor: u64,
    },
    /// A group handed to our device `device` (`group_devices.rs`): a sealed
    /// file reference.
    Group {
        device: [u8; 16],
        attachment: Vec<u8>,
    },
    /// The sending device asks for message history now (`history.rs`).
    HistoryAsk,
    /// Ids of group messages the sending device sent: it vouches for them
    /// (`07-groups.md` §3, `group_devices.rs`).
    GroupSent {
        group: [u8; 32],
        ids: Vec<[u8; 8]>,
    },
}

impl SyncItem {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            SyncItem::Read { to, ids } => {
                w.u8(T_READ).fixed(to).u8(ids.len() as u8);
                for id in ids {
                    w.fixed(id);
                }
            }
            SyncItem::Prefs { place, prefs } => {
                w.u8(T_PREFS).bytes(place).bytes(prefs);
            }
            SyncItem::Setting { key, value } => {
                w.u8(T_SETTING).bytes(key.as_bytes()).bytes(value);
            }
            SyncItem::Contact {
                card,
                name,
                verified,
                timer,
                server,
                inbox,
                tokens,
            } => {
                w.u8(T_CONTACT)
                    .bytes(card)
                    .bytes(name.as_bytes())
                    .u8(u8::from(*verified))
                    .u32(*timer)
                    .fixed(server)
                    .fixed(inbox)
                    .u8(tokens.len() as u8);
                for t in tokens {
                    w.fixed(t);
                }
            }
            SyncItem::Blocked { root, on } => {
                w.u8(T_BLOCKED).fixed(root).u8(u8::from(*on));
            }
            SyncItem::Position { week, cursor } => {
                w.u8(T_POSITION).u32(*week).u64(*cursor);
            }
            SyncItem::Group { device, attachment } => {
                w.u8(T_GROUP).fixed(device).bytes(attachment);
            }
            SyncItem::HistoryAsk => {
                w.u8(T_HISTORY_ASK);
            }
            SyncItem::GroupSent { group, ids } => {
                w.u8(T_GROUP_SENT).fixed(group).u8(ids.len() as u8);
                for id in ids {
                    w.fixed(id);
                }
            }
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let item = match r.u8().ok()? {
            T_READ => {
                let to = r.array().ok()?;
                let n = usize::from(r.u8().ok()?);
                let ids = (0..n)
                    .map(|_| r.array())
                    .collect::<enclave_proto::Result<_>>()
                    .ok()?;
                SyncItem::Read { to, ids }
            }
            T_PREFS => SyncItem::Prefs {
                place: r.bytes(65).ok()?.to_vec(),
                prefs: r.bytes(64).ok()?.to_vec(),
            },
            T_SETTING => SyncItem::Setting {
                key: String::from_utf8(r.bytes(64).ok()?.to_vec()).ok()?,
                value: r.bytes(256).ok()?.to_vec(),
            },
            T_CONTACT => {
                let card = r.bytes(crate::content::MAX_CARD).ok()?.to_vec();
                let name = String::from_utf8(r.bytes(256).ok()?.to_vec()).ok()?;
                let verified = r.u8().ok()? == 1;
                let timer = r.u32().ok()?;
                let server = r.array().ok()?;
                let inbox = r.array().ok()?;
                let n = usize::from(r.u8().ok()?).min(crate::content::MAX_TOKENS);
                let tokens = (0..n)
                    .map(|_| r.array())
                    .collect::<enclave_proto::Result<_>>()
                    .ok()?;
                SyncItem::Contact {
                    card,
                    name,
                    verified,
                    timer,
                    server,
                    inbox,
                    tokens,
                }
            }
            T_BLOCKED => SyncItem::Blocked {
                root: r.array().ok()?,
                on: r.u8().ok()? == 1,
            },
            T_POSITION => SyncItem::Position {
                week: r.u32().ok()?,
                cursor: r.u64().ok()?,
            },
            T_HISTORY_ASK => SyncItem::HistoryAsk,
            T_GROUP_SENT => {
                let group = r.array().ok()?;
                let n = usize::from(r.u8().ok()?);
                let ids = (0..n)
                    .map(|_| r.array())
                    .collect::<enclave_proto::Result<_>>()
                    .ok()?;
                SyncItem::GroupSent { group, ids }
            }
            T_GROUP => SyncItem::Group {
                device: r.array().ok()?,
                attachment: r.bytes(crate::content::MAX_ATTACHMENT_REF).ok()?.to_vec(),
            },
            _ => return None,
        };
        r.end().ok()?;
        Some(item)
    }

    /// Items of the same key replace each other in the queue.
    fn queue_key(&self) -> Vec<u8> {
        match self {
            SyncItem::Read { to, .. } => [&b"r"[..], to].concat(),
            SyncItem::Prefs { place, .. } => [&b"p"[..], place].concat(),
            SyncItem::Setting { key, .. } => [b"s", key.as_bytes()].concat(),
            SyncItem::Contact { card, .. } => [&b"c"[..], &card[..card.len().min(64)]].concat(),
            SyncItem::Blocked { root, .. } => [&b"b"[..], root].concat(),
            SyncItem::Position { week, .. } => [&b"w"[..], &week.to_be_bytes()].concat(),
            SyncItem::Group { device, attachment } => {
                [&b"g"[..], device, &attachment[..attachment.len().min(32)]].concat()
            }
            SyncItem::HistoryAsk => b"h".to_vec(),
            SyncItem::GroupSent { group, .. } => [&b"m"[..], group].concat(),
        }
    }
}

/// `u8 n ‖ n × bytes(item)`.
fn encode_items(items: &[SyncItem]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(items.len() as u8);
    for i in items {
        w.bytes(&i.encode());
    }
    w.finish()
}

fn decode_items(b: &[u8]) -> Vec<SyncItem> {
    let mut r = Reader::new(b);
    let Ok(n) = r.u8() else {
        return Vec::new();
    };
    (0..n)
        .filter_map(|_| r.bytes(crate::content::MAX_SELF_COPY).ok())
        .filter_map(SyncItem::decode)
        .collect()
}

/// What we know of one of our devices: when we last heard from it, and
/// how far it has read each weekly address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OwnDevice {
    seen: u64,
    positions: Vec<(u32, u64)>,
}

impl OwnDevice {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.seen).u8(self.positions.len() as u8);
        for (wk, c) in &self.positions {
            w.u32(*wk).u64(*c);
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let seen = r.u64().ok()?;
        let n = usize::from(r.u8().ok()?);
        let positions = (0..n)
            .map(|_| Some((r.u32().ok()?, r.u64().ok()?)))
            .collect::<Option<_>>()?;
        Some(Self { seen, positions })
    }
}

/// What a device that is not this one looks like to the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnDeviceState {
    /// Device id.
    pub id: [u8; 16],
    /// When one of its sync messages last arrived (its link time if none
    /// has).
    pub last_seen: u64,
    /// Unheard of for [`INACTIVE_SECS`].
    pub inactive: bool,
    /// Linked within the last [`NEW_DEVICE_SECS`].
    pub new: bool,
}

impl Client {
    /// Whether we have another device to keep in step.
    fn has_other_devices(&self) -> bool {
        self.manifest.devices.iter().any(|d| d.id != self.device.id)
    }

    /// Queue `item` for our other devices (replacing a queued item of the
    /// same kind and subject).
    pub(crate) fn queue_own(&mut self, item: SyncItem) -> Result<()> {
        if !self.has_other_devices() {
            return Ok(());
        }
        self.store.put(
            NS_OWN_QUEUE,
            &item.queue_key(),
            &item.encode(),
            &mut self.rng,
        )?;
        Ok(())
    }

    /// The item queued under `probe`'s key, if any.
    pub(crate) fn queued_own(&self, probe: &SyncItem) -> Result<Option<SyncItem>> {
        Ok(self
            .store
            .get(NS_OWN_QUEUE, &probe.queue_key())?
            .and_then(|b| SyncItem::decode(&b)))
    }

    /// Queue `ids` of `to` as read for our other devices, with what is
    /// already queued for that conversation (the latest 200).
    pub(crate) fn queue_read(&mut self, to: &[u8; 64], ids: &[MsgId]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let probe = SyncItem::Read {
            to: *to,
            ids: Vec::new(),
        };
        let mut all = match self
            .store
            .get(NS_OWN_QUEUE, &probe.queue_key())?
            .and_then(|b| SyncItem::decode(&b))
        {
            Some(SyncItem::Read { ids, .. }) => ids,
            _ => Vec::new(),
        };
        all.extend_from_slice(ids);
        let drop = all.len().saturating_sub(200);
        all.drain(..drop);
        self.queue_own(SyncItem::Read { to: *to, ids: all })
    }

    /// Send what is queued for our other devices, and a sign of life if
    /// nothing went for [`HEARTBEAT_SECS`].
    pub(crate) async fn flush_own_sync(&mut self, now: u64) -> Result<()> {
        if !self.has_other_devices() {
            for (k, _) in self.store.scan(NS_OWN_QUEUE)? {
                self.store.delete(NS_OWN_QUEUE, &k)?;
            }
            return Ok(());
        }
        let last = self
            .setting("own-sync-sent")?
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_be_bytes);
        let mut queued: Vec<(Vec<u8>, SyncItem)> = self
            .store
            .scan(NS_OWN_QUEUE)?
            .into_iter()
            .filter_map(|(k, v)| Some((k, SyncItem::decode(&v)?)))
            .collect();
        if queued.is_empty() && now < last.saturating_add(HEARTBEAT_SECS) {
            return Ok(());
        }
        // Every flush says how far we've read.
        for (week, cursor) in self.profile.weeks.clone() {
            let item = SyncItem::Position { week, cursor };
            let key = item.queue_key();
            if !queued.iter().any(|(k, _)| *k == key) {
                queued.push((key, item));
            }
        }
        // As many items as fit in one content each time.
        let mut batch: Vec<SyncItem> = Vec::new();
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let limit = crate::content::MAX_SELF_COPY - 64;
        for (k, item) in queued {
            batch.push(item);
            if encode_items(&batch).len() > limit || batch.len() > 200 {
                let item = batch.pop().ok_or(CoreError::TooLong)?;
                self.send_own_items(&batch, &keys).await?;
                batch = vec![item];
                keys.clear();
            }
            keys.push(k);
        }
        if !batch.is_empty() {
            self.send_own_items(&batch, &keys).await?;
        }
        self.set_setting("own-sync-sent", &now.to_be_bytes())
    }

    /// Send one item to our other devices now, outside the queue.
    pub(crate) async fn send_own_now(&mut self, item: SyncItem) -> Result<()> {
        self.send_own_items(&[item], &[]).await
    }

    async fn send_own_items(&mut self, items: &[SyncItem], keys: &[Vec<u8>]) -> Result<()> {
        let now = self.now();
        let c = Content::OwnSync(encode_items(items)).encode()?;
        self.send_own(&c, now).await?;
        for k in keys {
            self.store.delete(NS_OWN_QUEUE, k)?;
        }
        Ok(())
    }

    /// Something from another device of ours arrived: it's alive.
    pub(crate) fn seen_own(&mut self, dev: &[u8; 16], now: u64) -> Result<()> {
        let mut d = self.own_device(dev);
        if d.seen < now {
            d.seen = now;
            self.save_own_device(dev, &d)?;
        }
        Ok(())
    }

    fn own_device(&self, dev: &[u8; 16]) -> OwnDevice {
        self.store
            .get(NS_OWN_DEVICES, dev)
            .ok()
            .flatten()
            .and_then(|b| OwnDevice::decode(&b))
            .unwrap_or_default()
    }

    fn save_own_device(&mut self, dev: &[u8; 16], d: &OwnDevice) -> Result<()> {
        self.store
            .put(NS_OWN_DEVICES, dev, &d.encode(), &mut self.rng)?;
        Ok(())
    }

    /// Our other devices: when each was last heard of, and whether it is
    /// inactive or new.
    pub fn own_devices(&self) -> Vec<OwnDeviceState> {
        let now = self.now();
        self.manifest
            .devices
            .iter()
            .filter(|d| d.id != self.device.id)
            .map(|d| {
                let last_seen = self.own_device(&d.id).seen.max(d.added_at);
                OwnDeviceState {
                    id: d.id,
                    last_seen,
                    inactive: last_seen.saturating_add(INACTIVE_SECS) < now,
                    new: d.added_at.saturating_add(NEW_DEVICE_SECS) > now,
                }
            })
            .collect()
    }

    /// A sync message from our device `dev`.
    pub(crate) fn on_own_sync(&mut self, dev: &[u8; 16], b: &[u8]) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for item in decode_items(b) {
            match item {
                SyncItem::Read { to, ids } => {
                    if self.mark_read_here(&to, &ids)? {
                        events.push(Event::Synced);
                    }
                }
                SyncItem::Prefs { place, prefs } => {
                    self.apply_synced_prefs(&place, &prefs)?;
                    events.push(Event::Synced);
                }
                SyncItem::Setting { key, value } => {
                    if SYNCED_SETTINGS.contains(&key.as_str()) {
                        self.set_setting(&key, &value)?;
                        events.push(Event::Synced);
                    }
                }
                SyncItem::Contact {
                    card,
                    name,
                    verified,
                    timer,
                    server,
                    inbox,
                    tokens,
                } => {
                    if let Some(e) =
                        self.on_synced_contact(&card, name, verified, timer, server, inbox, tokens)?
                    {
                        events.push(e);
                    }
                }
                SyncItem::Blocked { root, on } => {
                    if on != self.is_blocked(&root) {
                        if on {
                            self.store.put(
                                super::blocks::NS_BLOCKED,
                                &root,
                                &[1],
                                &mut self.rng,
                            )?;
                        } else {
                            self.store.delete(super::blocks::NS_BLOCKED, &root)?;
                        }
                        events.push(Event::Synced);
                    }
                }
                SyncItem::Group { device, attachment } => {
                    if device == self.device.id {
                        self.queue_group_file(dev, &attachment)?;
                    }
                }
                SyncItem::HistoryAsk => {
                    if self.can_link() {
                        self.on_history_ask(dev)?;
                        events.push(Event::Synced);
                    }
                }
                SyncItem::GroupSent { group, ids } => {
                    let now = self.now();
                    events.append(&mut self.on_group_sent(&group, &ids, now)?);
                }
                SyncItem::Position { week, cursor } => {
                    let mut d = self.own_device(dev);
                    match d.positions.iter_mut().find(|(w, _)| *w == week) {
                        Some(p) => p.1 = p.1.max(cursor),
                        None => d.positions.push((week, cursor)),
                    }
                    d.positions.sort_unstable();
                    let drop = d.positions.len().saturating_sub(8);
                    d.positions.drain(..drop);
                    self.save_own_device(dev, &d)?;
                }
            }
        }
        Ok(events)
    }
}

impl Client {
    /// Mark `ids` of `to` read on this device (another device read them).
    fn mark_read_here(&mut self, to: &[u8; 64], ids: &[MsgId]) -> Result<bool> {
        let mut changed = false;
        for id in ids {
            if let Ok(mut m) = self.find(to, id)
                && !m.outgoing
                && !m.read
            {
                m.read = true;
                self.put_message(to, &m)?;
                changed = true;
            }
        }
        if let Some(c) = self.contacts.get_mut(to)
            && c.unread > 0
        {
            c.unread = c.unread.saturating_sub(ids.len() as u32);
            let c = c.clone();
            self.save_contact(&c)?;
            changed = true;
        }
        Ok(changed)
    }

    /// A contact another device of ours accepted, added or changed. One we
    /// know is updated now; a new one is kept and set up at the end of the
    /// sync (its manifest fetched, a greeting from this device: its devices
    /// accept us silently, we're in our root-signed manifest).
    #[allow(clippy::too_many_arguments)]
    fn on_synced_contact(
        &mut self,
        card: &[u8],
        name: String,
        verified: bool,
        timer: u32,
        server: [u8; 16],
        inbox: [u8; 32],
        tokens: Vec<Token>,
    ) -> Result<Option<Event>> {
        let Ok(parsed) = ContactCard::decode(card) else {
            return Ok(None);
        };
        let root = parsed.root;
        if root == self.account.root_public.0 {
            return Ok(None);
        }
        let Some(c) = self.contacts.get_mut(&root) else {
            let item = SyncItem::Contact {
                card: card.to_vec(),
                name,
                verified,
                timer,
                server,
                inbox,
                tokens,
            };
            self.store
                .put(NS_GREET, &root, &item.encode(), &mut self.rng)?;
            return Ok(None);
        };
        c.name = super::sanitize_name(&name);
        c.verified |= verified;
        c.timer = timer;
        if c.inbox.is_none() {
            c.inbox = Some(inbox);
            c.server = server;
        }
        c.state = ContactState::Accepted;
        super::add_tokens(&mut c.tokens, tokens);
        if c.card.is_none() {
            c.card = Some(parsed);
        }
        let c = c.clone();
        self.save_contact(&c)?;
        Ok(Some(Event::Synced))
    }

    /// Set up contacts another device of ours added: store them and open
    /// sessions with their devices from this one (at the end of a sync).
    pub(crate) async fn greet_synced_contacts(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, v) in self.store.scan(NS_GREET)? {
            let Some(SyncItem::Contact {
                card,
                name,
                verified,
                timer,
                server,
                inbox,
                tokens,
            }) = SyncItem::decode(&v)
            else {
                self.store.delete(NS_GREET, &k)?;
                continue;
            };
            let Ok(card) = ContactCard::decode(&card) else {
                self.store.delete(NS_GREET, &k)?;
                continue;
            };
            let root = card.root;
            if self.contacts.contains_key(&root) {
                self.store.delete(NS_GREET, &k)?;
                continue;
            }
            let (manifest, vault) = match self.fetch_peer(&card, now).await {
                Ok(v) => v,
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(_) => {
                    self.store.delete(NS_GREET, &k)?;
                    continue;
                }
            };
            let c = Contact {
                root,
                name: super::sanitize_name(&name),
                state: ContactState::Accepted,
                verified,
                server,
                request_inbox: card.request_inbox,
                inbox: Some(inbox),
                tokens,
                manifest: manifest.clone(),
                next_seq: 0,
                received_since_refill: 0,
                unread: 0,
                added_at: now,
                card: Some(card.clone()),
                group_only: false,
                timer,
            };
            self.contacts.insert(root, c.clone());
            self.save_contact(&c)?;
            self.store.delete(NS_GREET, &k)?;
            let hello = self.hello_for(&root, now).await?;
            self.initiate_to(&card, &manifest, &vault, &hello, None, now, None)
                .await?;
            events.push(Event::Synced);
        }
        Ok(events)
    }

    /// Tell our other devices about contact `root` (accepted or added
    /// here, with half of our write tokens for it when `tokens`; changed,
    /// without).
    pub(crate) fn sync_contact_to_own(&mut self, root: &[u8; 64], tokens: bool) -> Result<()> {
        if !self.has_other_devices() {
            return Ok(());
        }
        let Some(c) = self.contacts.get_mut(root) else {
            return Ok(());
        };
        let (Some(card), Some(inbox)) = (c.card.clone(), c.inbox) else {
            return Ok(());
        };
        let give = if tokens { c.tokens.len() / 2 } else { 0 };
        let tokens: Vec<Token> = c.tokens.drain(..give).collect();
        let item = SyncItem::Contact {
            card: card.encode(),
            name: c.name.clone(),
            verified: c.verified,
            timer: c.timer,
            server: c.server,
            inbox,
            tokens,
        };
        let c = c.clone();
        self.save_contact(&c)?;
        self.queue_own(item)
    }

    /// Acknowledge each weekly address up to what every active device of
    /// ours has read, so the server deletes it (`06-multidevice.md` §6).
    pub(crate) async fn advance_watermarks(&mut self, now: u64) -> Result<()> {
        let others: Vec<OwnDevice> = self
            .own_devices()
            .into_iter()
            .filter(|d| !d.inactive)
            .map(|d| self.own_device(&d.id))
            .collect();
        for (week, mine) in self.profile.weeks.clone() {
            let w = others.iter().fold(mine, |w, d| {
                w.min(
                    d.positions
                        .iter()
                        .find(|(x, _)| *x == week)
                        .map_or(0, |(_, c)| *c),
                )
            });
            let key = week.to_be_bytes();
            let acked = self
                .store
                .get(NS_ACKED, &key)?
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            if w <= acked {
                continue;
            }
            let inow = self.inbox_now(now);
            let mut token = [0u8; 32];
            token[..24].copy_from_slice(&self.profile.read_cred(week, api::day_of(inow)));
            token[24..].copy_from_slice(&w.to_be_bytes());
            let h = RequestHeader {
                op: Op::Ack,
                flags: 0,
                mailbox: self.profile.addr(week),
                token,
            };
            let server = self.profile.server;
            match self.rpc.call(&server, h, &[], inow, &mut self.rng).await {
                Ok(_) => {}
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(_) => continue,
            }
            self.store
                .put(NS_ACKED, &key, &w.to_be_bytes(), &mut self.rng)?;
        }
        // Weeks no longer kept.
        for (k, _) in self.store.scan(NS_ACKED)? {
            let week = k.as_slice().try_into().map(u32::from_be_bytes).unwrap_or(0);
            if !self.profile.has_week(week) {
                self.store.delete(NS_ACKED, &k)?;
            }
        }
        Ok(())
    }

    /// On the device holding the root: take inactive devices off the
    /// account (`03-identity.md` §4.4).
    pub(crate) async fn remove_inactive_devices(&mut self) -> Result<Vec<Event>> {
        if !self.can_link() {
            return Ok(Vec::new());
        }
        let gone: Vec<[u8; 16]> = self
            .own_devices()
            .into_iter()
            .filter(|d| d.inactive)
            .map(|d| d.id)
            .collect();
        let mut events = Vec::new();
        for id in gone {
            match self.remove_device(&id).await {
                Ok(()) => events.push(Event::DevicesChanged),
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(_) => {}
            }
        }
        Ok(events)
    }
}

/// Contacts another device of ours added, still to be greeted from here.
const NS_GREET: &str = "own-greet";

impl Client {
    /// Everything that keeps our devices in step, from `sync`: contacts
    /// another device added, cards, what changed here, how far everyone
    /// has read, devices that went quiet. Only network trouble stops it.
    pub(crate) async fn own_upkeep(&mut self, now: u64) -> Result<Vec<Event>> {
        let net = |r: Result<()>| match r {
            Err(e @ CoreError::Net(_)) => Err(e),
            _ => Ok(()),
        };
        let mut events = match self.greet_synced_contacts(now).await {
            Ok(e) => e,
            Err(e @ CoreError::Net(_)) => return Err(e),
            Err(_) => Vec::new(),
        };
        match self.take_handed_groups(now).await {
            Ok(mut e) => events.append(&mut e),
            Err(e @ CoreError::Net(_)) => return Err(e),
            Err(_) => {}
        }
        net(self.exchange_cards(now).await)?;
        net(self.hand_over_groups(now).await)?;
        net(self.flush_own_sync(now).await)?;
        net(self.advance_watermarks(now).await)?;
        match self.remove_inactive_devices().await {
            Ok(mut e) => events.append(&mut e),
            Err(e @ CoreError::Net(_)) => return Err(e),
            Err(_) => {}
        }
        Ok(events)
    }

    /// Cards: answer contacts who asked for ours, and ask contacts we hold
    /// no card for (from before cards were exchanged) for theirs, once, so
    /// they can be handed to our other devices (`03-identity.md` §4.x).
    pub(crate) async fn exchange_cards(&mut self, now: u64) -> Result<()> {
        for (k, _) in self.store.scan(NS_CARD_OWED)? {
            if let Ok(root) = <[u8; 64]>::try_from(k.as_slice()) {
                let card = Content::Card(self.card().encode());
                match self.send_content(&root, &card, now).await {
                    Err(e @ CoreError::Net(_)) => return Err(e),
                    Err(CoreError::OutOfTokens) => continue,
                    _ => {}
                }
            }
            self.store.delete(NS_CARD_OWED, &k)?;
        }
        let ask: Vec<[u8; 64]> = self
            .contacts
            .values()
            .filter(|c| c.state == ContactState::Accepted && c.card.is_none() && c.inbox.is_some())
            .map(|c| c.root)
            .collect();
        for root in ask {
            if self.store.get(NS_CARD_ASKED, &root)?.is_some() || self.is_blocked(&root) {
                continue;
            }
            match self.send_content(&root, &Content::CardAsk, now).await {
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(CoreError::OutOfTokens) => continue,
                _ => {}
            }
            self.store.put(NS_CARD_ASKED, &root, &[], &mut self.rng)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_round_trip() {
        let items = vec![
            SyncItem::Read {
                to: [1; 64],
                ids: vec![[2; 16], [3; 16]],
            },
            SyncItem::Prefs {
                place: vec![b'c'; 65],
                prefs: vec![1, 0, 1],
            },
            SyncItem::Setting {
                key: "receipts".into(),
                value: vec![0],
            },
            SyncItem::Contact {
                card: vec![9; 300],
                name: "Ben".into(),
                verified: true,
                timer: 3600,
                server: [4; 16],
                inbox: [5; 32],
                tokens: vec![[6; 32]; 8],
            },
            SyncItem::Blocked {
                root: [7; 64],
                on: true,
            },
            SyncItem::Position {
                week: 3000,
                cursor: 42,
            },
            SyncItem::Group {
                device: [8; 16],
                attachment: vec![1; 200],
            },
            SyncItem::HistoryAsk,
            SyncItem::GroupSent {
                group: [3; 32],
                ids: vec![[1; 8], [2; 8]],
            },
        ];
        assert_eq!(decode_items(&encode_items(&items)), items);
        let d = OwnDevice {
            seen: 5,
            positions: vec![(1, 2), (3, 4)],
        };
        assert_eq!(OwnDevice::decode(&d.encode()), Some(d));
    }
}
