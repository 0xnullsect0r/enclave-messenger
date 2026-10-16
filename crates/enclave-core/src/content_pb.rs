//! The Protobuf schema of message content (`docs/08-envelope.md` §5.5,
//! PLAN §8): what `Content::encode` writes and `Content::decode` reads.
//!
//! Messages are declared with `prost`'s derive macros (no generated code,
//! no build script). Field numbers are the content kinds of the format
//! before it. Decoding skips fields it doesn't know, so a later version
//! may add some; a kind it doesn't know decodes to nothing and is ignored.
//! Every limit is checked after decoding (`Content::check`), the input is
//! at most 64 KiB, and nesting is at most two messages deep (well inside
//! `prost`'s recursion limit).

use crate::content::{Content, MsgId, Token};
use enclave_proto::{ProtoError, Result};
use prost::Message as _;

/// The whole content: exactly one kind.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Pb {
    #[prost(
        oneof = "Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37"
    )]
    pub kind: Option<Kind>,
}

/// One kind of content.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Kind {
    #[prost(message, tag = "1")]
    Hello(Hello),
    #[prost(message, tag = "2")]
    Text(Text),
    #[prost(message, tag = "3")]
    Tokens(Tokens),
    #[prost(bytes, tag = "4")]
    GroupWelcome(Vec<u8>),
    #[prost(message, tag = "5")]
    GroupCards(GroupCards),
    #[prost(message, tag = "6")]
    Attachment(Attachment),
    #[prost(message, tag = "7")]
    React(React),
    #[prost(message, tag = "8")]
    Edit(Edit),
    #[prost(bytes, tag = "9")]
    Delete(Vec<u8>),
    #[prost(message, tag = "10")]
    Read(Ids),
    #[prost(uint32, tag = "11")]
    Timer(u32),
    #[prost(message, tag = "12")]
    SelfCopy(SelfCopy),
    #[prost(uint64, tag = "13")]
    Devices(u64),
    #[prost(bytes, tag = "14")]
    History(Vec<u8>),
    #[prost(bytes, tag = "15")]
    Veto(Vec<u8>),
    #[prost(bytes, tag = "16")]
    KtHead(Vec<u8>),
    #[prost(string, tag = "17")]
    RecoveryShare(String),
    #[prost(message, tag = "18")]
    Pin(Pin),
    #[prost(message, tag = "19")]
    ContactShare(ContactShare),
    #[prost(message, tag = "20")]
    Location(Location),
    #[prost(bool, tag = "21")]
    PqStep(bool),
    #[prost(message, tag = "22")]
    Sticker(Sticker),
    #[prost(bool, tag = "23")]
    Typing(bool),
    #[prost(bytes, tag = "24")]
    Migration(Vec<u8>),
    #[prost(message, tag = "25")]
    ServerMoved(ServerMoved),
    #[prost(message, tag = "26")]
    HomeMoved(HomeMoved),
    #[prost(message, tag = "27")]
    Delivered(Ids),
    #[prost(bytes, tag = "28")]
    OwnSync(Vec<u8>),
    #[prost(bool, tag = "29")]
    CardAsk(bool),
    #[prost(bytes, tag = "30")]
    Card(Vec<u8>),
    #[prost(message, tag = "31")]
    Part(Part),
    #[prost(message, tag = "32")]
    ModeChange(ModeChange),
    #[prost(message, tag = "33")]
    Signed(Signed),
    #[prost(bool, tag = "34")]
    Closed(bool),
    #[prost(message, tag = "35")]
    NotifyKey(NotifyKey),
    #[prost(bytes, tag = "36")]
    Call(Vec<u8>),
    #[prost(bytes, tag = "37")]
    Poll(Vec<u8>),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct NotifyKey {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub day: u32,
    #[prost(bool, tag = "3")]
    pub previews: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    #[prost(bytes = "vec", tag = "1")]
    pub server: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub inbox: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub tokens: Vec<Vec<u8>>,
    #[prost(string, tag = "4")]
    pub name: String,
    #[prost(string, tag = "5")]
    pub text: String,
    #[prost(bytes = "vec", tag = "6")]
    pub card: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub group: Option<Vec<u8>>,
    #[prost(bytes = "vec", tag = "8")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Text {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub tokens: Vec<Vec<u8>>,
    #[prost(string, tag = "2")]
    pub text: String,
    #[prost(bytes = "vec", tag = "3")]
    pub id: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub expires: u32,
    /// The message this one answers (empty: none).
    #[prost(bytes = "vec", tag = "5")]
    pub reply: Vec<u8>,
    #[prost(bool, tag = "6")]
    pub forwarded: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Tokens {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub tokens: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GroupCards {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub cards: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Attachment {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub attachment: Vec<u8>,
    #[prost(string, tag = "3")]
    pub caption: String,
    #[prost(uint32, tag = "4")]
    pub expires: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct React {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub emoji: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Edit {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub text: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Ids {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SelfCopy {
    #[prost(bytes = "vec", tag = "1")]
    pub to: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Pin {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub on: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ContactShare {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub card: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Location {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub location: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub expires: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Sticker {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub pack: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub index: u32,
    #[prost(uint32, tag = "4")]
    pub expires: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMoved {
    #[prost(bytes = "vec", tag = "1")]
    pub server: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub inbox: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub request_inbox: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub vault_locator: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub tokens: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HomeMoved {
    #[prost(bytes = "vec", tag = "1")]
    pub server: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub inbox_seed: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub request_inbox: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub request_owner: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub vault_locator: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub vault_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub keys: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Part {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub index: u32,
    #[prost(uint32, tag = "3")]
    pub total: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ModeChange {
    #[prost(bool, tag = "1")]
    pub on_record: bool,
    #[prost(uint32, tag = "2")]
    pub seq: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Signed {
    #[prost(uint64, tag = "1")]
    pub counter: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub sig: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub content: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub tokens: Vec<Vec<u8>>,
}

fn arr<const N: usize>(b: Vec<u8>) -> Result<[u8; N]> {
    b.try_into().map_err(|_| ProtoError::Decode)
}

fn arrs<const N: usize>(v: Vec<Vec<u8>>) -> Result<Vec<[u8; N]>> {
    v.into_iter().map(arr).collect()
}

fn id(b: Vec<u8>) -> Result<MsgId> {
    arr(b)
}

fn small(n: u32) -> Result<u8> {
    u8::try_from(n).map_err(|_| ProtoError::Decode)
}

fn toks(t: &[Token]) -> Vec<Vec<u8>> {
    t.iter().map(|x| x.to_vec()).collect()
}

/// Content into its Protobuf message.
pub fn to_pb(c: &Content) -> Pb {
    let kind = match c.clone() {
        Content::Hello {
            server,
            inbox,
            tokens,
            name,
            text,
            card,
            group,
            id,
        } => Kind::Hello(Hello {
            server: server.to_vec(),
            inbox: inbox.to_vec(),
            tokens: toks(&tokens),
            name,
            text,
            card,
            group: group.map(|g| g.to_vec()),
            id: id.to_vec(),
        }),
        Content::Text {
            tokens,
            text,
            id,
            expires,
            reply,
            forwarded,
        } => Kind::Text(Text {
            tokens: toks(&tokens),
            text,
            id: id.to_vec(),
            expires,
            reply: reply.map(|r| r.to_vec()).unwrap_or_default(),
            forwarded,
        }),
        Content::Tokens(t) => Kind::Tokens(Tokens { tokens: toks(&t) }),
        Content::GroupWelcome(b) => Kind::GroupWelcome(b),
        Content::GroupCards { group_id, cards } => Kind::GroupCards(GroupCards {
            group_id: group_id.to_vec(),
            cards,
        }),
        Content::Attachment {
            id,
            attachment,
            caption,
            expires,
        } => Kind::Attachment(Attachment {
            id: id.to_vec(),
            attachment,
            caption,
            expires,
        }),
        Content::React { target, emoji } => Kind::React(React {
            target: target.to_vec(),
            emoji,
        }),
        Content::Edit { target, text } => Kind::Edit(Edit {
            target: target.to_vec(),
            text,
        }),
        Content::Delete { target } => Kind::Delete(target.to_vec()),
        Content::Read(ids) => Kind::Read(Ids {
            ids: ids.iter().map(|i| i.to_vec()).collect(),
        }),
        Content::Delivered(ids) => Kind::Delivered(Ids {
            ids: ids.iter().map(|i| i.to_vec()).collect(),
        }),
        Content::Timer(t) => Kind::Timer(t),
        Content::Devices(v) => Kind::Devices(v),
        Content::History(b) => Kind::History(b),
        Content::Veto(b) => Kind::Veto(b),
        Content::RecoveryShare(s) => Kind::RecoveryShare(s),
        Content::KtHead(b) => Kind::KtHead(b),
        Content::Location {
            id,
            location,
            expires,
        } => Kind::Location(Location {
            id: id.to_vec(),
            location,
            expires,
        }),
        Content::PqStep { reply } => Kind::PqStep(reply),
        Content::Migration(b) => Kind::Migration(b),
        Content::OwnSync(b) => Kind::OwnSync(b),
        Content::CardAsk => Kind::CardAsk(true),
        Content::Card(b) => Kind::Card(b),
        Content::Part {
            id,
            index,
            total,
            data,
        } => Kind::Part(Part {
            id: id.to_vec(),
            index: u32::from(index),
            total: u32::from(total),
            data,
        }),
        Content::Typing { on } => Kind::Typing(on),
        Content::Sticker {
            id,
            pack,
            index,
            expires,
        } => Kind::Sticker(Sticker {
            id: id.to_vec(),
            pack,
            index: u32::from(index),
            expires,
        }),
        Content::ContactShare { id, card } => Kind::ContactShare(ContactShare {
            id: id.to_vec(),
            card,
        }),
        Content::Pin { target, on } => Kind::Pin(Pin {
            target: target.to_vec(),
            on,
        }),
        Content::ServerMoved {
            server,
            inbox,
            request_inbox,
            vault_locator,
            tokens,
        } => Kind::ServerMoved(ServerMoved {
            server: server.to_vec(),
            inbox: inbox.to_vec(),
            request_inbox: request_inbox.to_vec(),
            vault_locator: vault_locator.to_vec(),
            tokens: toks(&tokens),
        }),
        Content::HomeMoved {
            server,
            inbox_seed,
            request_inbox,
            request_owner,
            vault_locator,
            vault_key,
            keys,
        } => Kind::HomeMoved(HomeMoved {
            server: server.to_vec(),
            inbox_seed: inbox_seed.to_vec(),
            request_inbox: request_inbox.to_vec(),
            request_owner: request_owner.to_vec(),
            vault_locator: vault_locator.to_vec(),
            vault_key: vault_key.to_vec(),
            keys,
        }),
        Content::SelfCopy { to, content } => Kind::SelfCopy(SelfCopy {
            to: to.to_vec(),
            content,
        }),
        Content::ModeChange { on_record, seq } => Kind::ModeChange(ModeChange { on_record, seq }),
        Content::Signed {
            counter,
            sig,
            content,
            tokens,
        } => Kind::Signed(Signed {
            counter,
            sig,
            content,
            tokens: toks(&tokens),
        }),
        Content::Closed => Kind::Closed(true),
        Content::Call(b) => Kind::Call(b.clone()),
        Content::Poll(b) => Kind::Poll(b.clone()),
        Content::NotifyKey { key, day, previews } => Kind::NotifyKey(NotifyKey {
            key: key.to_vec(),
            day,
            previews,
        }),
    };
    Pb { kind: Some(kind) }
}

/// The Protobuf message back into content (limits are checked after).
pub fn from_pb(p: Pb) -> Result<Content> {
    Ok(match p.kind.ok_or(ProtoError::Decode)? {
        Kind::Hello(h) => Content::Hello {
            server: arr(h.server)?,
            inbox: arr(h.inbox)?,
            tokens: arrs(h.tokens)?,
            name: h.name,
            text: h.text,
            card: h.card,
            group: h.group.map(arr).transpose()?,
            id: id(h.id)?,
        },
        Kind::Text(t) => Content::Text {
            tokens: arrs(t.tokens)?,
            text: t.text,
            id: id(t.id)?,
            expires: t.expires,
            reply: if t.reply.is_empty() {
                None
            } else {
                Some(id(t.reply)?)
            },
            forwarded: t.forwarded,
        },
        Kind::Tokens(t) => Content::Tokens(arrs(t.tokens)?),
        Kind::GroupWelcome(b) => Content::GroupWelcome(b),
        Kind::GroupCards(g) => Content::GroupCards {
            group_id: arr(g.group_id)?,
            cards: g.cards,
        },
        Kind::Attachment(a) => Content::Attachment {
            id: id(a.id)?,
            attachment: a.attachment,
            caption: a.caption,
            expires: a.expires,
        },
        Kind::React(r) => Content::React {
            target: id(r.target)?,
            emoji: r.emoji,
        },
        Kind::Edit(e) => Content::Edit {
            target: id(e.target)?,
            text: e.text,
        },
        Kind::Delete(t) => Content::Delete { target: id(t)? },
        Kind::Read(i) => Content::Read(arrs(i.ids)?),
        Kind::Delivered(i) => Content::Delivered(arrs(i.ids)?),
        Kind::Timer(t) => Content::Timer(t),
        Kind::Devices(v) => Content::Devices(v),
        Kind::History(b) => Content::History(b),
        Kind::Veto(b) => Content::Veto(b),
        Kind::RecoveryShare(s) => Content::RecoveryShare(s),
        Kind::KtHead(b) => Content::KtHead(b),
        Kind::Location(l) => Content::Location {
            id: id(l.id)?,
            location: l.location,
            expires: l.expires,
        },
        Kind::PqStep(reply) => Content::PqStep { reply },
        Kind::Migration(b) => Content::Migration(b),
        Kind::OwnSync(b) => Content::OwnSync(b),
        Kind::CardAsk(_) => Content::CardAsk,
        Kind::Card(b) => Content::Card(b),
        Kind::Part(p) => Content::Part {
            id: id(p.id)?,
            index: small(p.index)?,
            total: small(p.total)?,
            data: p.data,
        },
        Kind::Typing(on) => Content::Typing { on },
        Kind::Sticker(s) => Content::Sticker {
            id: id(s.id)?,
            pack: s.pack,
            index: small(s.index)?,
            expires: s.expires,
        },
        Kind::ContactShare(c) => Content::ContactShare {
            id: id(c.id)?,
            card: c.card,
        },
        Kind::Pin(p) => Content::Pin {
            target: id(p.target)?,
            on: p.on,
        },
        Kind::ServerMoved(m) => Content::ServerMoved {
            server: arr(m.server)?,
            inbox: arr(m.inbox)?,
            request_inbox: arr(m.request_inbox)?,
            vault_locator: arr(m.vault_locator)?,
            tokens: arrs(m.tokens)?,
        },
        Kind::HomeMoved(m) => Content::HomeMoved {
            server: arr(m.server)?,
            inbox_seed: arr(m.inbox_seed)?,
            request_inbox: arr(m.request_inbox)?,
            request_owner: arr(m.request_owner)?,
            vault_locator: arr(m.vault_locator)?,
            vault_key: arr(m.vault_key)?,
            keys: m.keys,
        },
        Kind::SelfCopy(s) => Content::SelfCopy {
            to: arr(s.to)?,
            content: s.content,
        },
        Kind::ModeChange(m) => Content::ModeChange {
            on_record: m.on_record,
            seq: m.seq,
        },
        Kind::Signed(s) => Content::Signed {
            counter: s.counter,
            sig: s.sig,
            content: s.content,
            tokens: arrs(s.tokens)?,
        },
        Kind::Closed(_) => Content::Closed,
        Kind::Call(b) => {
            if b.len() > crate::content::MAX_CALL {
                return Err(ProtoError::Decode);
            }
            Content::Call(b)
        }
        Kind::Poll(b) => {
            if b.len() > crate::content::MAX_POLL {
                return Err(ProtoError::Decode);
            }
            Content::Poll(b)
        }
        Kind::NotifyKey(n) => Content::NotifyKey {
            key: arr(n.key)?,
            day: n.day,
            previews: n.previews,
        },
    })
}

/// Encode content as Protobuf.
pub fn encode(c: &Content) -> Vec<u8> {
    to_pb(c).encode_to_vec()
}

/// Decode Protobuf content (unknown fields skipped; an unknown kind is an
/// error the caller ignores).
pub fn decode(b: &[u8]) -> Result<Content> {
    from_pb(Pb::decode(b).map_err(|_| ProtoError::Decode)?)
}
