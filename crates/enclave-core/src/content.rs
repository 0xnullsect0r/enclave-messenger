//! Message content inside ratchet envelopes (`docs/08-envelope.md`).
//!
//! Encoded as Protobuf (`content_pb.rs`), so a later version may add fields
//! an older one skips. Every field has a hard limit, checked on encoding and
//! after decoding by a canonical binary form kept for that purpose
//! (`Content::check`). Write tokens, inbox addresses and contact cards
//! travel only here, inside the end-to-end encrypted body, never in anything
//! a server can read.

use crate::card::MAX_NAME;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::{ProtoError, Result};

/// Most write tokens one message may carry.
pub const MAX_TOKENS: usize = 32;
/// Maximum text in one message (bytes of UTF-8). Longer text is refused
/// until continuation units land.
pub const MAX_TEXT: usize = 4096;
/// Longest text of a 1:1 message, which goes in continuation units when it
/// doesn't fit one envelope (`client/parts.rs`).
pub const MAX_LONG_TEXT: usize = 60_000;
/// Largest content split into continuation units.
pub const MAX_SPLIT_CONTENT: usize = 65_536;
/// Bytes of encoded content one continuation unit carries.
pub const MAX_PART: usize = 8_192;
/// Longest call signalling message (an offer is about 1.7 KB).
pub const MAX_CALL: usize = 4_096;
/// Largest encoded card accepted.
pub const MAX_CARD: usize = 512;
/// Most cards in one `GroupCards` message.
pub const MAX_CARDS_PER_MESSAGE: usize = 40;
/// Largest group welcome accepted.
pub const MAX_WELCOME: usize = 9_000;
/// Most message ids one read receipt may carry.
pub const MAX_RECEIPTS: usize = 64;
/// Longest reaction (one emoji, possibly with modifiers).
pub const MAX_REACTION: usize = 32;
/// Longest disappearing timer: four weeks.
pub const MAX_TIMER: u32 = 28 * 86_400;
/// Largest encoded attachment reference.
pub const MAX_ATTACHMENT_REF: usize = 1024;

/// A write token for someone's inbox.
pub type Token = [u8; 32];

/// Identifier of a message, chosen by its sender.
pub type MsgId = [u8; 16];

/// Decrypted message content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// First message in each direction: where and how to reach the sender.
    Hello {
        /// Sender's home server.
        server: [u8; 16],
        /// Sender's account inbox: its address seed, from which each
        /// week's address follows (`docs/09-transport.md` §3.1).
        inbox: [u8; 32],
        /// Write tokens for that inbox.
        tokens: Vec<Token>,
        /// Sender's display name.
        name: String,
        /// Optional first text.
        text: String,
        /// Sender's encoded contact card, so contacts can introduce each
        /// other into groups.
        card: Vec<u8>,
        /// Set when a group introduced us: the receiver accepts automatically
        /// if the sender is a member of that group.
        group: Option<[u8; 32]>,
        /// Id of the first text.
        id: MsgId,
    },
    /// A text message, optionally carrying fresh tokens.
    Text {
        /// Write tokens for the sender's inbox.
        tokens: Vec<Token>,
        /// The text.
        text: String,
        /// Message id.
        id: MsgId,
        /// Disappearing timer in seconds (0 = off).
        expires: u32,
        /// The message this one answers (its id), shown quoted above it.
        reply: Option<MsgId>,
        /// Forwarded from another conversation: shown "Forwarded".
        forwarded: bool,
        /// The sender's preview of a link in the text.
        link: Option<LinkPreview>,
    },
    /// Token refill with no user-visible content.
    Tokens(Vec<Token>),
    /// You were added to a group (`enclave_proto::group::Group::welcome`).
    GroupWelcome(Vec<u8>),
    /// Contact cards of a group's members, so members can reach each other.
    GroupCards {
        /// Group.
        group_id: [u8; 32],
        /// Encoded cards.
        cards: Vec<Vec<u8>>,
    },
    /// A file (`crate::files::Attachment`, encoded) with an optional caption.
    Attachment {
        /// Message id.
        id: MsgId,
        /// Encoded attachment reference.
        attachment: Vec<u8>,
        /// Caption.
        caption: String,
        /// Disappearing timer.
        expires: u32,
        /// View once: the recipient can open it once, and it isn't kept.
        view_once: bool,
    },
    /// Set (or, with an empty emoji, remove) our reaction to a message.
    React {
        /// Target message.
        target: MsgId,
        /// Emoji.
        emoji: String,
    },
    /// Replace the text of one of our messages (advisory, 24 h).
    Edit {
        /// Target message.
        target: MsgId,
        /// New text.
        text: String,
    },
    /// Delete one of our messages for everyone (advisory).
    Delete {
        /// Target message.
        target: MsgId,
    },
    /// Read receipts.
    Read(Vec<MsgId>),
    /// Delivery receipts: these messages reached one of our devices.
    /// Messages go one way over the mixnet, so this is how their sender
    /// learns they arrived (`docs/09-transport.md` §6.1).
    Delivered(Vec<MsgId>),
    /// The conversation's disappearing timer changed.
    Timer(u32),
    /// The sender's device list changed: fetch its manifest, at least this
    /// version, and stop encrypting to devices no longer in it.
    Devices(u64),
    /// Our message history, as a sealed file reference (own devices only).
    History(Vec<u8>),
    /// A device of the sender vetoes a change to the sender's account
    /// (an encoded `Attestation`).
    Veto(Vec<u8>),
    /// A share of the sender's recovery secret for us to keep (SLIP-0039
    /// words; `docs/03-identity.md` §8.3).
    RecoveryShare(String),
    /// Our signed key-transparency head for an epoch where the sender's
    /// gossip disagreed, as a sealed file reference (RT-04).
    KtHead(Vec<u8>),
    /// A place: coordinates and an optional label (encoded `Location`).
    Location {
        /// Message id.
        id: MsgId,
        /// The encoded location.
        location: Vec<u8>,
        /// Disappearing timer (seconds, 0 = off).
        expires: u32,
    },
    /// A PQ round trip for the pre-rekey step (`07-groups.md` §5.2): the
    /// unit's PQ slot is the point; `reply` asks the peer to answer.
    PqStep {
        /// Answer with a `PqStep` of our own.
        reply: bool,
    },
    /// The sender changed their recovery words: a sealed file reference to
    /// the migration record and their new manifest (`03-identity.md` §8.2).
    Migration(Vec<u8>),
    /// To our other devices only: what keeps the account's devices in step
    /// (`06-multidevice.md` §5), encoded by `client/own_sync.rs`.
    OwnSync(Vec<u8>),
    /// Asks a contact for their current contact card (we hold none).
    CardAsk,
    /// The sender's current contact card (encoded), answering a `CardAsk`.
    Card(Vec<u8>),
    /// The conversation goes on the record (messages signed by their
    /// sender's device) or off it (`05-ratchet.md` §9). Authenticated as
    /// any content in the session; `seq` orders changes.
    ModeChange {
        /// On the record (else off).
        on_record: bool,
        /// Change number in this conversation.
        seq: u32,
    },
    /// Content signed by its sender's device, in a conversation on the
    /// record (`05-ratchet.md` §9).
    Signed {
        /// The sender's signing counter in this conversation.
        counter: u64,
        /// Composite signature (`ctx/signed-msg`).
        sig: Vec<u8>,
        /// The signed content (encoded), with any write tokens taken out:
        /// they ride in `tokens`, so a quote shown to someone else (a
        /// report) doesn't carry them.
        content: Vec<u8>,
        /// Write tokens for the sender, outside the signature.
        tokens: Vec<Token>,
    },
    /// The sender closed their account (`03-identity.md` §8.5).
    Closed,
    /// Call signalling (`enclave_calls::message::CallMessage`, encoded;
    /// `11-calls.md` §2).
    Call(Vec<u8>),
    /// A poll in a 1:1 conversation, a vote or its close (the group
    /// encoding, `client/polls.rs`).
    Poll(Vec<u8>),
    /// Our profile (`client/profile.rs`): name, about, and a sealed photo
    /// reference (empty: none), sent only inside sessions; a lower
    /// `version` than the one held is stale.
    Profile {
        /// Display name.
        name: String,
        /// A few words about us.
        about: String,
        /// Encoded attachment reference of the photo, or empty.
        photo: Vec<u8>,
        /// Increases with every change.
        version: u64,
    },
    /// The sender's notification key chain for capsules sent to them, from
    /// `day` on, and whether they want previews (`10-push.md` §4).
    NotifyKey {
        /// The chain's key for `day`.
        key: [u8; 32],
        /// Its day.
        day: u32,
        /// Fill capsules (else leave them random).
        previews: bool,
    },
    /// One continuation unit of content too large for one envelope
    /// (`client/parts.rs`).
    Part {
        /// The same random id for every part of one content.
        id: MsgId,
        /// This part's place.
        index: u8,
        /// How many parts.
        total: u8,
        /// Its slice of the encoded content.
        data: Vec<u8>,
    },
    /// The sender started (`on`) or stopped typing in this conversation.
    /// Sent only in cover slots, so it may never arrive (`docs/16-features.md`).
    Typing {
        /// Typing (else stopped).
        on: bool,
    },
    /// A sticker: index `index` in the pack behind the sealed file
    /// reference `pack`.
    Sticker {
        /// Message id.
        id: MsgId,
        /// The pack's encoded file reference.
        pack: Vec<u8>,
        /// Which sticker.
        index: u8,
        /// Disappearing timer (seconds, 0 = off).
        expires: u32,
    },
    /// A contact card, shared so the recipient can add that person.
    ContactShare {
        /// Message id.
        id: MsgId,
        /// The encoded card (never with an invite).
        card: Vec<u8>,
    },
    /// Pin (or unpin) a message of the conversation, for both people.
    Pin {
        /// Target message.
        target: MsgId,
        /// Pinned (else unpinned).
        on: bool,
    },
    /// The sender's account moved to another server (`12-servers.md`
    /// §4.4): where to write from now on, with fresh write tokens (the old
    /// ones were for the old server).
    ServerMoved {
        /// The new home server.
        server: [u8; 16],
        /// The account inbox there (its address seed).
        inbox: [u8; 32],
        /// The request inbox there (for their card).
        request_inbox: [u8; 32],
        /// The vault key's locator there (for their card).
        vault_locator: [u8; 32],
        /// Fresh write tokens for the new inbox.
        tokens: Vec<Token>,
    },
    /// To our other devices: the account moved to another server, with the
    /// new inboxes and their secrets.
    HomeMoved {
        /// The new home server.
        server: [u8; 16],
        /// The account inbox's new seed.
        inbox_seed: [u8; 32],
        /// Request inbox.
        request_inbox: [u8; 32],
        /// Its owner secret.
        request_owner: [u8; 32],
        /// The vault key's locator.
        vault_locator: [u8; 32],
        /// The key the vault-key blob is sealed under.
        vault_key: [u8; 32],
        /// Empty for a move; after "Secure my account", a sealed file
        /// reference to the account's new shared keys
        /// (`AccountKeys::export_shared`, `client/secure.rs`).
        keys: Vec<u8>,
    },
    /// A copy, for our other devices, of content we sent to `to`.
    SelfCopy {
        /// The conversation it belongs to.
        to: [u8; 64],
        /// The content we sent (encoded).
        content: Vec<u8>,
    },
}

impl Content {
    /// What a person wrote (or did) in a conversation, which On the record
    /// carries its sender's signature (`05-ratchet.md` §9); not protocol
    /// messages.
    pub fn is_personal(&self) -> bool {
        matches!(
            self,
            Content::Text { .. }
                | Content::Attachment { .. }
                | Content::React { .. }
                | Content::Edit { .. }
                | Content::Delete { .. }
                | Content::Timer(_)
                | Content::Location { .. }
                | Content::Sticker { .. }
                | Content::ContactShare { .. }
                | Content::Pin { .. }
                | Content::Poll(_)
        )
    }

    /// Take out the write tokens content carries (they never go under a
    /// signature).
    pub fn take_tokens(&mut self) -> Vec<Token> {
        match self {
            Content::Text { tokens, .. } => core::mem::take(tokens),
            _ => Vec::new(),
        }
    }

    /// Put write tokens back into content that carries them.
    pub fn put_tokens(&mut self, t: Vec<Token>) {
        if let Content::Text { tokens, .. } = self {
            *tokens = t;
        }
    }

    /// The id of the message this content makes, if it makes one.
    pub fn message_id(&self) -> Option<MsgId> {
        match self {
            Content::Text { id, .. }
            | Content::Attachment { id, .. }
            | Content::Location { id, .. }
            | Content::Sticker { id, .. }
            | Content::ContactShare { id, .. } => Some(*id),
            _ => None,
        }
    }

    /// Whether this waits, in Maximum privacy, for all three KEMs to
    /// protect the session (`docs/04-eqxdh.md` §7): everything a person
    /// wrote or shared does. Protocol messages don't, so the session can
    /// get there: the hello that accepts a request, write tokens, receipts,
    /// PQ steps (which carry the braid), and notices of moves and devices.
    pub fn waits_for_three_kems(&self) -> bool {
        !matches!(
            self,
            Content::Hello { .. }
                | Content::Tokens { .. }
                | Content::Read { .. }
                | Content::Delivered { .. }
                | Content::PqStep { .. }
                | Content::KtHead { .. }
                | Content::Devices { .. }
                | Content::Migration { .. }
                | Content::OwnSync { .. }
                | Content::CardAsk
                | Content::Card { .. }
                | Content::ModeChange { .. }
                | Content::Closed
                | Content::NotifyKey { .. }
                | Content::ServerMoved { .. }
                | Content::HomeMoved { .. }
        )
    }
}

const K_HELLO: u8 = 1;
const K_TEXT: u8 = 2;
const K_TOKENS: u8 = 3;
const K_GROUP_WELCOME: u8 = 4;
const K_GROUP_CARDS: u8 = 5;
const K_ATTACHMENT: u8 = 6;
const K_REACT: u8 = 7;
const K_EDIT: u8 = 8;
const K_DELETE: u8 = 9;
const K_READ: u8 = 10;
const K_TIMER: u8 = 11;
const K_SELF_COPY: u8 = 12;
const K_DEVICES: u8 = 13;
const K_HISTORY: u8 = 14;
const K_VETO: u8 = 15;
const K_KT_HEAD: u8 = 16;
const K_RECOVERY_SHARE: u8 = 17;
const K_PIN: u8 = 18;
const K_CONTACT_SHARE: u8 = 19;
const K_LOCATION: u8 = 20;
const K_PQ_STEP: u8 = 21;
const K_STICKER: u8 = 22;
const K_TYPING: u8 = 23;
const K_MIGRATION: u8 = 24;
const K_SERVER_MOVED: u8 = 25;
const K_HOME_MOVED: u8 = 26;
const K_DELIVERED: u8 = 27;
const K_OWN_SYNC: u8 = 28;
const K_CARD_ASK: u8 = 29;
const K_CARD: u8 = 30;
const K_PART: u8 = 31;
const K_MODE_CHANGE: u8 = 32;
const K_SIGNED: u8 = 33;
const K_CLOSED: u8 = 34;
const K_NOTIFY_KEY: u8 = 35;
const K_CALL: u8 = 36;
const K_POLL: u8 = 37;
const K_PROFILE: u8 = 38;

/// Longest "about" text, in bytes.
pub const MAX_ABOUT: usize = 280;
/// Longest link-preview address.
pub const MAX_LINK_URL: usize = 2_048;
/// Longest link-preview title, in bytes.
pub const MAX_LINK_TITLE: usize = 512;
/// Longest link-preview description, in bytes.
pub const MAX_LINK_DESCRIPTION: usize = 1_024;
/// Largest link-preview picture (a small JPEG).
pub const MAX_LINK_IMAGE: usize = 12 * 1024;
/// Largest encoded link preview.
pub const MAX_LINK_PREVIEW: usize =
    MAX_LINK_URL + MAX_LINK_TITLE + MAX_LINK_DESCRIPTION + MAX_LINK_IMAGE + 16;
/// Longest text that may carry a link preview (the two fit in one
/// split message).
pub const MAX_LINKED_TEXT: usize = 40_000;

/// A link preview the sender made (`docs/15-client.md` §5, off by
/// default): the page's title and description and a small picture, fetched
/// by the sender through Tor and sent with the text. The receiver fetches
/// nothing; it only shows these, and only if the text contains the link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkPreview {
    /// The link (`https://…`), as it is in the text.
    pub url: String,
    /// The page's title.
    pub title: String,
    /// The page's description (may be empty).
    pub description: String,
    /// A small JPEG, or empty.
    pub image: Vec<u8>,
}

impl LinkPreview {
    /// Within the limits, an `https` link the text contains, a title, and
    /// a JPEG or no picture.
    pub fn fits(&self, text: &str) -> bool {
        self.url.starts_with("https://")
            && self.url.len() <= MAX_LINK_URL
            && text.contains(&self.url)
            && text.len() <= MAX_LINKED_TEXT
            && !self.title.trim().is_empty()
            && self.title.len() <= MAX_LINK_TITLE
            && self.description.len() <= MAX_LINK_DESCRIPTION
            && self.image.len() <= MAX_LINK_IMAGE
            && (self.image.is_empty() || self.image.starts_with(&[0xFF, 0xD8, 0xFF]))
    }

    /// `url ‖ title ‖ description ‖ image`, each length-prefixed.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.url.as_bytes())
            .bytes(self.title.as_bytes())
            .bytes(self.description.as_bytes())
            .bytes(&self.image);
        w.finish()
    }

    /// The reverse of [`LinkPreview::encode`], with every limit checked.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let l = Self::read(&mut r)?;
        r.end()?;
        Ok(l)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(LinkPreview {
            url: get_str(r, MAX_LINK_URL)?,
            title: get_str(r, MAX_LINK_TITLE)?,
            description: get_str(r, MAX_LINK_DESCRIPTION)?,
            image: r.bytes(MAX_LINK_IMAGE)?.to_vec(),
        })
    }
}
/// Largest encoded 1:1 poll message.
pub const MAX_POLL: usize = 8_192;
/// Longest composite signature (ML-DSA-87 and Ed448).
pub const MAX_SIG: usize = 4_741;
/// Largest encoded location.
const MAX_LOCATION: usize = 512;
/// Longest recovery share (33 words of at most 8 letters).
pub const MAX_RECOVERY_SHARE: usize = 512;
/// Largest content a self-copy can wrap.
pub const MAX_SELF_COPY: usize = 9_000;

fn put_tokens(w: &mut Writer, t: &[Token]) {
    w.u8(t.len() as u8);
    for x in t {
        w.fixed(x);
    }
}

fn get_tokens(r: &mut Reader<'_>) -> Result<Vec<Token>> {
    let n = r.u8()? as usize;
    if n > MAX_TOKENS {
        return Err(ProtoError::Decode);
    }
    (0..n).map(|_| r.array()).collect()
}

fn get_str(r: &mut Reader<'_>, max: usize) -> Result<String> {
    String::from_utf8(r.bytes(max)?.to_vec()).map_err(|_| ProtoError::Decode)
}

fn timer(secs: u32) -> Result<u32> {
    if secs > MAX_TIMER {
        Err(ProtoError::Decode)
    } else {
        Ok(secs)
    }
}

impl Content {
    /// Encode (Protobuf). Fails if a limit is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        Ok(crate::content_pb::encode(self))
    }

    /// Decode (Protobuf), then check every limit.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_SPLIT_CONTENT + 1024 {
            return Err(ProtoError::TooLarge);
        }
        let c = crate::content_pb::decode(b)?;
        c.check()?;
        Ok(c)
    }

    /// Every limit: the content survives its canonical binary form.
    fn check(&self) -> Result<()> {
        Self::canonical_decode(&self.canonical()?).map(|_| ())
    }

    /// The canonical binary form (limits only; not on the wire).
    fn canonical(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let too_large = Err(ProtoError::TooLarge);
        match self {
            Content::Hello {
                server,
                inbox,
                tokens,
                name,
                text,
                card,
                group,
                id,
            } => {
                if tokens.len() > MAX_TOKENS
                    || name.len() > MAX_NAME
                    || text.len() > MAX_TEXT
                    || card.len() > MAX_CARD
                {
                    return too_large;
                }
                w.u8(K_HELLO).fixed(server).fixed(inbox);
                put_tokens(&mut w, tokens);
                w.bytes(name.as_bytes()).bytes(text.as_bytes()).bytes(card);
                match group {
                    Some(g) => w.u8(1).fixed(g),
                    None => w.u8(0),
                };
                w.fixed(id);
            }
            Content::Text {
                tokens,
                text,
                id,
                expires,
                reply,
                forwarded,
                link,
            } => {
                if tokens.len() > MAX_TOKENS || text.len() > MAX_LONG_TEXT || *expires > MAX_TIMER {
                    return too_large;
                }
                if link
                    .as_ref()
                    .is_some_and(|l| text.len() > MAX_LINKED_TEXT || l.image.len() > MAX_LINK_IMAGE)
                {
                    return too_large;
                }
                w.u8(K_TEXT);
                put_tokens(&mut w, tokens);
                w.bytes(text.as_bytes()).fixed(id).u32(*expires);
                match reply {
                    Some(r) => w.u8(1).fixed(r),
                    None => w.u8(0),
                };
                w.u8(u8::from(*forwarded));
                match link {
                    Some(l) => w.u8(1).fixed(&l.encode()),
                    None => w.u8(0),
                };
            }
            Content::Tokens(tokens) => {
                if tokens.len() > MAX_TOKENS {
                    return too_large;
                }
                w.u8(K_TOKENS);
                put_tokens(&mut w, tokens);
            }
            Content::GroupWelcome(b) => {
                if b.len() > MAX_WELCOME {
                    return too_large;
                }
                w.u8(K_GROUP_WELCOME).bytes(b);
            }
            Content::GroupCards { group_id, cards } => {
                if cards.len() > MAX_CARDS_PER_MESSAGE || cards.iter().any(|c| c.len() > MAX_CARD) {
                    return too_large;
                }
                w.u8(K_GROUP_CARDS).fixed(group_id).u8(cards.len() as u8);
                for c in cards {
                    w.bytes(c);
                }
            }
            Content::Attachment {
                id,
                attachment,
                caption,
                expires,
                view_once,
            } => {
                if attachment.len() > MAX_ATTACHMENT_REF
                    || caption.len() > MAX_TEXT
                    || *expires > MAX_TIMER
                {
                    return too_large;
                }
                w.u8(K_ATTACHMENT)
                    .fixed(id)
                    .bytes(attachment)
                    .bytes(caption.as_bytes())
                    .u32(*expires)
                    .u8(u8::from(*view_once));
            }
            Content::React { target, emoji } => {
                if emoji.len() > MAX_REACTION {
                    return too_large;
                }
                w.u8(K_REACT).fixed(target).bytes(emoji.as_bytes());
            }
            Content::Edit { target, text } => {
                if text.len() > MAX_TEXT {
                    return too_large;
                }
                w.u8(K_EDIT).fixed(target).bytes(text.as_bytes());
            }
            Content::Delete { target } => {
                w.u8(K_DELETE).fixed(target);
            }
            Content::Read(ids) | Content::Delivered(ids) => {
                if ids.len() > MAX_RECEIPTS {
                    return too_large;
                }
                let k = if matches!(self, Content::Read(_)) {
                    K_READ
                } else {
                    K_DELIVERED
                };
                w.u8(k).u8(ids.len() as u8);
                for i in ids {
                    w.fixed(i);
                }
            }
            Content::Timer(secs) => {
                if *secs > MAX_TIMER {
                    return too_large;
                }
                w.u8(K_TIMER).u32(*secs);
            }
            Content::Devices(version) => {
                w.u8(K_DEVICES).u64(*version);
            }
            Content::History(att) => {
                if att.len() > MAX_ATTACHMENT_REF {
                    return too_large;
                }
                w.u8(K_HISTORY).bytes(att);
            }
            Content::Veto(a) => {
                if a.len() > enclave_proto::attest::MAX_ATTESTATION {
                    return too_large;
                }
                w.u8(K_VETO).bytes(a);
            }
            Content::RecoveryShare(s) => {
                if s.len() > MAX_RECOVERY_SHARE {
                    return too_large;
                }
                w.u8(K_RECOVERY_SHARE).bytes(s.as_bytes());
            }
            Content::KtHead(att) => {
                if att.len() > MAX_ATTACHMENT_REF {
                    return too_large;
                }
                w.u8(K_KT_HEAD).bytes(att);
            }
            Content::Pin { target, on } => {
                w.u8(K_PIN).fixed(target).u8(u8::from(*on));
            }
            Content::PqStep { reply } => {
                w.u8(K_PQ_STEP).u8(u8::from(*reply));
            }
            Content::Typing { on } => {
                w.u8(K_TYPING).u8(u8::from(*on));
            }
            Content::Migration(att) => {
                if att.len() > MAX_ATTACHMENT_REF {
                    return too_large;
                }
                w.u8(K_MIGRATION).bytes(att);
            }
            Content::OwnSync(b) => {
                if b.len() > MAX_SELF_COPY {
                    return too_large;
                }
                w.u8(K_OWN_SYNC).bytes(b);
            }
            Content::CardAsk => {
                w.u8(K_CARD_ASK);
            }
            Content::Part {
                id,
                index,
                total,
                data,
            } => {
                if data.len() > MAX_PART {
                    return too_large;
                }
                w.u8(K_PART).fixed(id).u8(*index).u8(*total).bytes(data);
            }
            Content::Card(card) => {
                if card.len() > MAX_CARD {
                    return too_large;
                }
                w.u8(K_CARD).bytes(card);
            }
            Content::Sticker {
                id,
                pack,
                index,
                expires,
            } => {
                if pack.len() > MAX_ATTACHMENT_REF || *expires > MAX_TIMER {
                    return too_large;
                }
                w.u8(K_STICKER)
                    .fixed(id)
                    .bytes(pack)
                    .u8(*index)
                    .u32(*expires);
            }
            Content::ContactShare { id, card } => {
                if card.len() > MAX_CARD {
                    return too_large;
                }
                w.u8(K_CONTACT_SHARE).fixed(id).bytes(card);
            }
            Content::Location {
                id,
                location,
                expires,
            } => {
                if location.len() > MAX_LOCATION || *expires > MAX_TIMER {
                    return too_large;
                }
                w.u8(K_LOCATION).fixed(id).bytes(location).u32(*expires);
            }
            Content::ServerMoved {
                server,
                inbox,
                request_inbox,
                vault_locator,
                tokens,
            } => {
                if tokens.len() > MAX_TOKENS {
                    return too_large;
                }
                w.u8(K_SERVER_MOVED)
                    .fixed(server)
                    .fixed(inbox)
                    .fixed(request_inbox)
                    .fixed(vault_locator);
                put_tokens(&mut w, tokens);
            }
            Content::HomeMoved {
                server,
                inbox_seed,
                request_inbox,
                request_owner,
                vault_locator,
                vault_key,
                keys,
            } => {
                w.u8(K_HOME_MOVED)
                    .fixed(server)
                    .fixed(inbox_seed)
                    .fixed(request_inbox)
                    .fixed(request_owner)
                    .fixed(vault_locator)
                    .fixed(vault_key)
                    .bytes(keys);
            }
            Content::SelfCopy { to, content } => {
                if content.len() > MAX_SPLIT_CONTENT {
                    return too_large;
                }
                w.u8(K_SELF_COPY).fixed(to).bytes(content);
            }
            Content::ModeChange { on_record, seq } => {
                w.u8(K_MODE_CHANGE).u8(u8::from(*on_record)).u32(*seq);
            }
            Content::Signed {
                counter,
                sig,
                content,
                tokens,
            } => {
                if sig.len() > MAX_SIG
                    || content.len() > MAX_SPLIT_CONTENT
                    || tokens.len() > MAX_TOKENS
                {
                    return too_large;
                }
                w.u8(K_SIGNED).u64(*counter).bytes(sig).bytes(content);
                put_tokens(&mut w, tokens);
            }
            Content::Closed => {
                w.u8(K_CLOSED);
            }
            Content::Call(b) => {
                if b.len() > MAX_CALL {
                    return too_large;
                }
                w.u8(K_CALL).bytes(b);
            }
            Content::Poll(b) => {
                if b.len() > MAX_POLL {
                    return too_large;
                }
                w.u8(K_POLL).bytes(b);
            }
            Content::Profile {
                name,
                about,
                photo,
                version,
            } => {
                if name.len() > crate::card::MAX_NAME
                    || about.len() > MAX_ABOUT
                    || photo.len() > MAX_ATTACHMENT_REF
                {
                    return too_large;
                }
                w.u8(K_PROFILE)
                    .bytes(name.as_bytes())
                    .bytes(about.as_bytes())
                    .bytes(photo)
                    .u64(*version);
            }
            Content::NotifyKey { key, day, previews } => {
                w.u8(K_NOTIFY_KEY)
                    .fixed(key)
                    .u32(*day)
                    .u8(u8::from(*previews));
            }
        }
        Ok(w.finish())
    }

    fn canonical_decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let c = match r.u8()? {
            K_HELLO => Content::Hello {
                server: r.array()?,
                inbox: r.array()?,
                tokens: get_tokens(&mut r)?,
                name: get_str(&mut r, MAX_NAME)?,
                text: get_str(&mut r, MAX_TEXT)?,
                card: r.bytes(MAX_CARD)?.to_vec(),
                group: match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(ProtoError::Decode),
                },
                id: r.array()?,
            },
            K_TEXT => Content::Text {
                tokens: get_tokens(&mut r)?,
                text: get_str(&mut r, MAX_LONG_TEXT)?,
                id: r.array()?,
                expires: timer(r.u32()?)?,
                reply: match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(ProtoError::Decode),
                },
                forwarded: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
                link: match r.u8()? {
                    0 => None,
                    1 => Some(LinkPreview::read(&mut r)?),
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_TOKENS => Content::Tokens(get_tokens(&mut r)?),
            K_GROUP_WELCOME => Content::GroupWelcome(r.bytes(MAX_WELCOME)?.to_vec()),
            K_GROUP_CARDS => {
                let group_id = r.array()?;
                let n = r.u8()? as usize;
                if n > MAX_CARDS_PER_MESSAGE {
                    return Err(ProtoError::Decode);
                }
                let cards = (0..n)
                    .map(|_| r.bytes(MAX_CARD).map(<[u8]>::to_vec))
                    .collect::<Result<_>>()?;
                Content::GroupCards { group_id, cards }
            }
            K_ATTACHMENT => Content::Attachment {
                id: r.array()?,
                attachment: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                caption: get_str(&mut r, MAX_TEXT)?,
                expires: timer(r.u32()?)?,
                view_once: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_REACT => Content::React {
                target: r.array()?,
                emoji: get_str(&mut r, MAX_REACTION)?,
            },
            K_EDIT => Content::Edit {
                target: r.array()?,
                text: get_str(&mut r, MAX_TEXT)?,
            },
            K_DELETE => Content::Delete { target: r.array()? },
            K_READ => {
                let n = r.u8()? as usize;
                if n > MAX_RECEIPTS {
                    return Err(ProtoError::Decode);
                }
                Content::Read((0..n).map(|_| r.array()).collect::<Result<_>>()?)
            }
            K_DELIVERED => {
                let n = r.u8()? as usize;
                if n > MAX_RECEIPTS {
                    return Err(ProtoError::Decode);
                }
                Content::Delivered((0..n).map(|_| r.array()).collect::<Result<_>>()?)
            }
            K_TIMER => Content::Timer(timer(r.u32()?)?),
            K_DEVICES => Content::Devices(r.u64()?),
            K_HISTORY => Content::History(r.bytes(MAX_ATTACHMENT_REF)?.to_vec()),
            K_VETO => Content::Veto(r.bytes(enclave_proto::attest::MAX_ATTESTATION)?.to_vec()),
            K_KT_HEAD => Content::KtHead(r.bytes(MAX_ATTACHMENT_REF)?.to_vec()),
            K_RECOVERY_SHARE => Content::RecoveryShare(get_str(&mut r, MAX_RECOVERY_SHARE)?),
            K_STICKER => Content::Sticker {
                id: r.array()?,
                pack: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                index: r.u8()?,
                expires: timer(r.u32()?)?,
            },
            K_PQ_STEP => Content::PqStep {
                reply: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_MIGRATION => Content::Migration(r.bytes(MAX_ATTACHMENT_REF)?.to_vec()),
            K_SERVER_MOVED => Content::ServerMoved {
                server: r.array()?,
                inbox: r.array()?,
                request_inbox: r.array()?,
                vault_locator: r.array()?,
                tokens: get_tokens(&mut r)?,
            },
            K_HOME_MOVED => Content::HomeMoved {
                server: r.array()?,
                inbox_seed: r.array()?,
                request_inbox: r.array()?,
                request_owner: r.array()?,
                vault_locator: r.array()?,
                vault_key: r.array()?,
                keys: r.bytes(4096)?.to_vec(),
            },
            K_OWN_SYNC => Content::OwnSync(r.bytes(MAX_SELF_COPY)?.to_vec()),
            K_CARD_ASK => Content::CardAsk,
            K_MODE_CHANGE => Content::ModeChange {
                on_record: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
                seq: r.u32()?,
            },
            K_SIGNED => Content::Signed {
                counter: r.u64()?,
                sig: r.bytes(MAX_SIG)?.to_vec(),
                content: r.bytes(MAX_SPLIT_CONTENT)?.to_vec(),
                tokens: get_tokens(&mut r)?,
            },
            K_CLOSED => Content::Closed,
            K_CALL => Content::Call(r.bytes(MAX_CALL)?.to_vec()),
            K_POLL => Content::Poll(r.bytes(MAX_POLL)?.to_vec()),
            K_PROFILE => Content::Profile {
                name: get_str(&mut r, crate::card::MAX_NAME)?,
                about: get_str(&mut r, MAX_ABOUT)?,
                photo: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                version: r.u64()?,
            },
            K_NOTIFY_KEY => Content::NotifyKey {
                key: r.array()?,
                day: r.u32()?,
                previews: r.u8()? == 1,
            },
            K_PART => Content::Part {
                id: r.array()?,
                index: r.u8()?,
                total: r.u8()?,
                data: r.bytes(MAX_PART)?.to_vec(),
            },
            K_CARD => Content::Card(r.bytes(MAX_CARD)?.to_vec()),
            K_TYPING => Content::Typing {
                on: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_LOCATION => Content::Location {
                id: r.array()?,
                location: r.bytes(MAX_LOCATION)?.to_vec(),
                expires: timer(r.u32()?)?,
            },
            K_CONTACT_SHARE => Content::ContactShare {
                id: r.array()?,
                card: r.bytes(MAX_CARD)?.to_vec(),
            },
            K_PIN => Content::Pin {
                target: r.array()?,
                on: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_SELF_COPY => {
                let to = r.array()?;
                let content = r.bytes(MAX_SPLIT_CONTENT)?.to_vec();
                Content::SelfCopy { to, content }
            }
            _ => return Err(ProtoError::Decode),
        };
        r.end()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A later version's extra field is skipped; a kind this version
    /// doesn't know is refused (and the caller ignores it).
    #[test]
    fn forward_compatible() {
        use prost::Message as _;
        let c = Content::Typing { on: true };
        let mut b = c.encode().unwrap();
        // Field 99 of the outer message, length-delimited, 3 bytes.
        prost::encoding::encode_key(99, prost::encoding::WireType::LengthDelimited, &mut b);
        prost::encoding::encode_varint(3, &mut b);
        b.extend_from_slice(b"new");
        assert_eq!(Content::decode(&b).unwrap(), c);
        let unknown = crate::content_pb::Pb { kind: None }.encode_to_vec();
        assert!(Content::decode(&unknown).is_err());
        // Limits hold after decoding too.
        let long = crate::content_pb::to_pb(&Content::RecoveryShare("x".repeat(600)));
        assert!(Content::decode(&long.encode_to_vec()).is_err());
    }

    #[test]
    fn roundtrip_and_limits() {
        let all = [
            Content::Hello {
                server: [1; 16],
                inbox: [2; 32],
                tokens: vec![[3; 32]; 16],
                name: "Sam".into(),
                text: "hi".into(),
                card: vec![1; 180],
                group: Some([4; 32]),
                id: [8; 16],
            },
            Content::Text {
                tokens: vec![],
                text: "héllo 👋 https://example.org/a".into(),
                id: [1; 16],
                expires: 3600,
                reply: Some([7; 16]),
                forwarded: true,
                link: Some(LinkPreview {
                    url: "https://example.org/a".into(),
                    title: "A page".into(),
                    description: "About it".into(),
                    image: vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2],
                }),
            },
            Content::Tokens(vec![[9; 32]; 8]),
            Content::GroupWelcome(vec![5; 7000]),
            Content::GroupCards {
                group_id: [6; 32],
                cards: vec![vec![7; 180]; 30],
            },
            Content::Attachment {
                id: [2; 16],
                attachment: vec![3; 300],
                caption: "look".into(),
                expires: 0,
                view_once: true,
            },
            Content::React {
                target: [4; 16],
                emoji: "👍🏽".into(),
            },
            Content::Edit {
                target: [4; 16],
                text: "fixed".into(),
            },
            Content::Delete { target: [4; 16] },
            Content::Read(vec![[5; 16]; 10]),
            Content::Delivered(vec![[6; 16]; 3]),
            Content::Timer(86_400),
            Content::Pin {
                target: [4; 16],
                on: true,
            },
            Content::ContactShare {
                id: [3; 16],
                card: vec![7; 200],
            },
            Content::Location {
                id: [5; 16],
                location: vec![1; 40],
                expires: 3600,
            },
            Content::PqStep { reply: true },
            Content::Typing { on: true },
            Content::Typing { on: false },
            Content::Migration(vec![8; 300]),
            Content::OwnSync(vec![9; 4000]),
            Content::CardAsk,
            Content::Card(vec![4; 300]),
            Content::Part {
                id: [5; 16],
                index: 1,
                total: 3,
                data: vec![6; 8192],
            },
            Content::ModeChange {
                on_record: true,
                seq: 2,
            },
            Content::Signed {
                counter: 9,
                sig: vec![1; MAX_SIG],
                content: vec![2; 4000],
                tokens: vec![[3; 32]; 4],
            },
            Content::Closed,
            Content::Call(vec![1; 1800]),
            Content::Poll(vec![2; 300]),
            Content::Profile {
                name: "Ada".into(),
                about: "Out walking".into(),
                photo: vec![3; 200],
                version: 4,
            },
            Content::NotifyKey {
                key: [3; 32],
                day: 20_000,
                previews: true,
            },
            Content::ServerMoved {
                server: [1; 16],
                inbox: [2; 32],
                request_inbox: [3; 32],
                vault_locator: [4; 32],
                tokens: vec![[5; 32]; MAX_TOKENS],
            },
            Content::HomeMoved {
                server: [1; 16],
                inbox_seed: [2; 32],
                request_inbox: [4; 32],
                request_owner: [5; 32],
                vault_locator: [6; 32],
                vault_key: [7; 32],
                keys: vec![8; 300],
            },
            Content::Sticker {
                id: [6; 16],
                pack: vec![2; 300],
                index: 3,
                expires: 0,
            },
            Content::SelfCopy {
                to: [9; 64],
                content: vec![K_TEXT, 0, 0, 0, 0, 0],
            },
        ];
        for c in all {
            let e = c.encode().unwrap();
            assert!(
                e.len() <= enclave_wire::direct::CONTENT_CAPACITY,
                "fits one unit"
            );
            assert_eq!(Content::decode(&e).unwrap(), c);
            let mut longer = e.clone();
            longer.push(0);
            assert!(Content::decode(&longer).is_err());
        }
        let long = "x".repeat(MAX_LONG_TEXT + 1);
        assert!(
            Content::Text {
                tokens: vec![],
                text: long,
                id: [0; 16],
                expires: 0,
                reply: None,
                forwarded: false,
                link: None,
            }
            .encode()
            .is_err()
        );
        // A preview rides only on a text short enough for both.
        assert!(
            Content::Text {
                tokens: vec![],
                text: "x".repeat(MAX_LINKED_TEXT + 1),
                id: [0; 16],
                expires: 0,
                reply: None,
                forwarded: false,
                link: Some(LinkPreview {
                    url: "https://example.org/".into(),
                    title: "t".into(),
                    ..Default::default()
                }),
            }
            .encode()
            .is_err()
        );
        assert!(Content::Timer(MAX_TIMER + 1).encode().is_err());
        assert!(
            Content::Tokens(vec![[0; 32]; MAX_TOKENS + 1])
                .encode()
                .is_err()
        );
        assert!(
            Content::decode(&[K_TEXT, 0, 0, 0, 0, 1, 0xff]).is_err(),
            "invalid UTF-8"
        );
    }
}
