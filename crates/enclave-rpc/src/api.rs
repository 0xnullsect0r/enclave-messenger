//! Request and reply payloads shared by clients and servers
//! (`docs/12-servers.md`).
//!
//! Control operations carry a small payload inside the 14,336-byte envelope
//! region: `u32 length ‖ bytes ‖ random padding`. Large objects (manifests,
//! prekey publications, the 1.36 MB McEliece key) travel as numbered chunks of
//! at most [`CHUNK_DATA`] bytes.

use crate::{Result, RpcError};
use enclave_crypto::rng::HedgedRng;
use enclave_wire::ENVELOPE_LEN;

/// Reply status, carried in the reply header's `flags` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Success.
    Ok = 0,
    /// Not authorized (bad or spent token, bad credential).
    Denied = 1,
    /// Nothing there.
    NotFound = 2,
    /// Quota exceeded.
    Quota = 3,
    /// Malformed request.
    Malformed = 4,
    /// Proof of work missing or too weak.
    Pow = 5,
    /// Stored object failed validation (bad signature, rollback).
    Invalid = 6,
    /// The server can't serve this right now (storage trouble); try later.
    Unavailable = 7,
}

impl Status {
    /// Parse.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x0f {
            0 => Status::Ok,
            1 => Status::Denied,
            2 => Status::NotFound,
            3 => Status::Quota,
            5 => Status::Pow,
            6 => Status::Invalid,
            7 => Status::Unavailable,
            _ => Status::Malformed,
        }
    }
}

/// Reply flag: a poll found a message.
pub const FLAG_FOUND: u8 = 0x10;
/// Reply flag: more messages are waiting.
pub const FLAG_MORE: u8 = 0x20;
/// Request flag on `RegisterTokens`: create the inbox.
pub const FLAG_CREATE: u8 = 0x01;
/// Request flag on `RegisterTokens` with create: make it a request inbox.
pub const FLAG_REQUEST_INBOX: u8 = 0x02;
/// Request flag on `RegisterTokens`: delete the inbox (its owner closing
/// the account, `docs/03-identity.md` §8.5), with its envelopes, tokens,
/// read credentials, hints and push registration.
pub const FLAG_DELETE: u8 = 0x04;

/// Request flag on `Write`: a group mailbox. The token is the mailbox's
/// owner secret; the first write creates the mailbox, later writes must
/// present the same token, and it is not burned.
pub const FLAG_GROUP: u8 = 0x04;

/// Request flag on `WriteRequest`: the token is an invite capability whose
/// hash the inbox owner registered (`docs/03-identity.md` §9.2), burned on
/// use, instead of a proof of work.
pub const FLAG_INVITE: u8 = 0x08;
/// Request flag on `RegisterTokens`: remove the listed hashes (cancelling
/// invite capabilities) instead of adding them.
pub const FLAG_REVOKE: u8 = 0x08;
/// `RegisterTokens` on a request inbox: set the proof-of-work effort its
/// writers need (payload `u32`, 0 for the server's), at most
/// [`MAX_INBOX_EFFORT`]. Its owner raises it after reporting spam
/// (`13-operators.md` §2).
pub const FLAG_EFFORT: u8 = 0x40;
/// Request flag: the request goes one way (no reply over the mixnet), so
/// the server keeps its answer for a status poll (`Op::Status`) under the
/// request's status id (`Exchange::status_id`), for [`DEFER_TTL_SECS`].
pub const FLAG_DEFER: u8 = 0x80;
/// How long a deferred answer waits for its status poll.
pub const DEFER_TTL_SECS: u64 = 600;
/// Highest effort an owner can ask of writers to its request inbox (the
/// top of the clients' effort ladder).
pub const MAX_INBOX_EFFORT: u32 = 16_384;

/// Maximum payload bytes in one envelope.
pub const MAX_PAYLOAD: usize = ENVELOPE_LEN - 4;
/// Data bytes per directory chunk.
pub const CHUNK_DATA: usize = 14_000;

/// Frame a payload into a full envelope region with random padding.
pub fn frame(payload: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(RpcError::Malformed);
    }
    let mut env = vec![0u8; ENVELOPE_LEN];
    env[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    env[4..4 + payload.len()].copy_from_slice(payload);
    rng.fill("api/padding", &mut env[4 + payload.len()..])?;
    Ok(env)
}

/// Extract a framed payload.
pub fn unframe(env: &[u8]) -> Result<&[u8]> {
    if env.len() != ENVELOPE_LEN {
        return Err(RpcError::Malformed);
    }
    let n = u32::from_be_bytes([env[0], env[1], env[2], env[3]]) as usize;
    env.get(4..4 + n).ok_or(RpcError::Malformed)
}

/// Directory object kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DirKind {
    /// Signed account manifest, keyed by SHAKE256-256 of the root key.
    Manifest = 1,
    /// A device's prekey publication (put) or a claimed bundle (get).
    Bundle = 2,
    /// Encrypted McEliece vault key, keyed by a random locator.
    Vault = 3,
    /// Username claims (put, keyed by the name) and key-transparency lookups
    /// (get: index 0 keyed by the name, later chunks by the returned reply id).
    /// A get keyed by [`DESCRIPTOR_LOOKUP_KEY`] (no name) looks up the
    /// server's committed descriptor digest instead.
    Username = 4,
    /// Device attestations about an account's manifest changes (co-sign or
    /// veto), keyed like the manifest.
    Attest = 5,
    /// A change of recovery words (`03-identity.md` §8.2), keyed like the
    /// old root's manifest, which it replaces.
    Migration = 6,
    /// The server's own signed descriptor (`12-servers.md` §4.3); get only,
    /// key ignored.
    Descriptor = 7,
    /// The foundation's signed server list as this server mirrors it
    /// (`12-servers.md` §4.1); get only, key ignored.
    ServerList = 8,
    /// Where an account went when it left this server: a root-signed
    /// `ServerMove` (`12-servers.md` §4.4), keyed like the manifest.
    Moved = 9,
    /// An account's root-signed deletion (`03-identity.md` §8.5), keyed like
    /// the manifest: put to delete the account here, get to see it was.
    Tombstone = 10,
    /// Proof that a key-transparency log signed two trees for one epoch
    /// (`12-servers.md` §3.8), keyed by that log's server id (zero-padded):
    /// put by a client that found it, kept and passed on to the witnesses;
    /// get to see it.
    Equivocation = 11,
}

/// Directory action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DirAction {
    /// Upload a chunk.
    Put = 1,
    /// Download a chunk.
    Get = 2,
    /// Claim a bundle (burns one one-time prekey; returns a claim id).
    Claim = 3,
}

/// A directory request payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirRequest {
    /// Object kind.
    pub kind: DirKind,
    /// Action.
    pub action: DirAction,
    /// Object key (root hash, device id padded, locator, or claim id).
    pub key: [u8; 32],
    /// Chunk index.
    pub index: u32,
    /// Total chunks (put only).
    pub total: u32,
    /// Proof of work or owner secret, depending on the action.
    pub proof: [u8; 32],
    /// Chunk data (put only).
    pub data: Vec<u8>,
}

impl DirRequest {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(78 + self.data.len());
        v.push(self.kind as u8);
        v.push(self.action as u8);
        v.extend_from_slice(&self.key);
        v.extend_from_slice(&self.index.to_be_bytes());
        v.extend_from_slice(&self.total.to_be_bytes());
        v.extend_from_slice(&self.proof);
        v.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.data);
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 78 {
            return Err(RpcError::Malformed);
        }
        let kind = match b[0] {
            1 => DirKind::Manifest,
            2 => DirKind::Bundle,
            3 => DirKind::Vault,
            4 => DirKind::Username,
            5 => DirKind::Attest,
            6 => DirKind::Migration,
            7 => DirKind::Descriptor,
            8 => DirKind::ServerList,
            9 => DirKind::Moved,
            10 => DirKind::Tombstone,
            11 => DirKind::Equivocation,
            _ => return Err(RpcError::Malformed),
        };
        let action = match b[1] {
            1 => DirAction::Put,
            2 => DirAction::Get,
            3 => DirAction::Claim,
            _ => return Err(RpcError::Malformed),
        };
        let mut key = [0u8; 32];
        key.copy_from_slice(&b[2..34]);
        let index = u32::from_be_bytes([b[34], b[35], b[36], b[37]]);
        let total = u32::from_be_bytes([b[38], b[39], b[40], b[41]]);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&b[42..74]);
        let n = u32::from_be_bytes([b[74], b[75], b[76], b[77]]) as usize;
        if n > CHUNK_DATA {
            return Err(RpcError::Malformed);
        }
        let data = b.get(78..78 + n).ok_or(RpcError::Malformed)?.to_vec();
        Ok(Self {
            kind,
            action,
            key,
            index,
            total,
            proof,
            data,
        })
    }
}

/// A directory reply payload: `total chunks ‖ claim id ‖ data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirReply {
    /// Total chunks of the object.
    pub total: u32,
    /// Claim id (bundle claims) or zeros.
    pub claim: [u8; 32],
    /// Chunk data.
    pub data: Vec<u8>,
}

impl DirReply {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(40 + self.data.len());
        v.extend_from_slice(&self.total.to_be_bytes());
        v.extend_from_slice(&self.claim);
        v.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.data);
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 40 {
            return Err(RpcError::Malformed);
        }
        let total = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut claim = [0u8; 32];
        claim.copy_from_slice(&b[4..36]);
        let n = u32::from_be_bytes([b[36], b[37], b[38], b[39]]) as usize;
        let data = b.get(40..40 + n).ok_or(RpcError::Malformed)?.to_vec();
        Ok(Self { total, claim, data })
    }
}

/// Split an object into directory chunks.
pub fn chunks(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return vec![&[]];
    }
    data.chunks(CHUNK_DATA).collect()
}

/// Context string for a request-inbox proof of work.
pub fn pow_context_request(mailbox: &[u8; 32], day: u64, envelope_hash: &[u8]) -> Vec<u8> {
    [
        b"request-inbox".as_slice(),
        mailbox,
        &day.to_be_bytes(),
        envelope_hash,
    ]
    .concat()
}

/// Context string for a report's proof of work.
pub fn pow_context_report(mailbox: &[u8; 32], day: u64, envelope_hash: &[u8]) -> Vec<u8> {
    [
        b"report".as_slice(),
        mailbox,
        &day.to_be_bytes(),
        envelope_hash,
    ]
    .concat()
}

/// Privacy Pass `TokenRequest` length (RFC 9578, token type 0x0001).
pub const PP_REQUEST_LEN: usize = 52;
/// Privacy Pass `TokenResponse` length.
pub const PP_RESPONSE_LEN: usize = 145;
/// Privacy Pass `Token` length.
pub const PP_TOKEN_LEN: usize = 146;
/// An issuer public key (compressed P-384 point).
pub const PP_PUBLIC_LEN: usize = 49;
/// Most tokens one `BlobAlloc` issue asks for.
pub const BLOB_ISSUE_MAX: usize = 8;
/// Chunk uploads one allocation (one token) allows.
pub const ALLOC_CHUNKS: u32 = 512;
/// How long an allocation lasts.
pub const ALLOC_SECS: u64 = 86_400;
/// Length of an issuer-key epoch (a month of 30 days).
pub const ISSUER_EPOCH_SECS: u64 = 30 * 86_400;

/// The issuer-key epoch at `now`.
pub fn issuer_epoch(now: u64) -> u32 {
    (now / ISSUER_EPOCH_SECS) as u32
}

/// A `BlobAlloc` request (`docs/09-transport.md` §9). An issue proves an
/// inbox on the server (mailbox and owner secret in the header) and asks
/// for blind tokens; a redemption spends one, unlinkably, for an
/// allocation of [`ALLOC_CHUNKS`] chunk uploads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobAlloc {
    /// `1 ‖ u8 n ‖ n × TokenRequest`.
    Issue(Vec<[u8; PP_REQUEST_LEN]>),
    /// `2 ‖ Token`.
    Redeem([u8; PP_TOKEN_LEN]),
    /// `3`: this month's issuer key (answered as an `Issued` with no
    /// responses), for a client that holds no descriptor of the server.
    Key,
}

impl BlobAlloc {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            BlobAlloc::Issue(reqs) => {
                let mut b = vec![1, reqs.len().min(BLOB_ISSUE_MAX) as u8];
                for r in reqs.iter().take(BLOB_ISSUE_MAX) {
                    b.extend_from_slice(r);
                }
                b
            }
            BlobAlloc::Redeem(t) => [&[2u8][..], t].concat(),
            BlobAlloc::Key => vec![3],
        }
    }

    /// Decode (strict).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let m = RpcError::Malformed;
        match b.split_first() {
            Some((1, rest)) => {
                let (&n, rest) = rest.split_first().ok_or(m)?;
                let n = usize::from(n);
                if n == 0 || n > BLOB_ISSUE_MAX || rest.len() != n * PP_REQUEST_LEN {
                    return Err(m);
                }
                Ok(BlobAlloc::Issue(
                    rest.chunks(PP_REQUEST_LEN)
                        .map(|c| c.try_into().map_err(|_| m))
                        .collect::<Result<_>>()?,
                ))
            }
            Some((2, rest)) => Ok(BlobAlloc::Redeem(rest.try_into().map_err(|_| m)?)),
            Some((3, [])) => Ok(BlobAlloc::Key),
            _ => Err(m),
        }
    }
}

/// The answer to a [`BlobAlloc`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobAllocReply {
    /// `1 ‖ u32 epoch ‖ issuer public key ‖ u8 n ‖ n × TokenResponse`.
    Issued {
        /// The issuer-key epoch.
        epoch: u32,
        /// The issuer key the responses were made with.
        public: [u8; PP_PUBLIC_LEN],
        /// One response per request.
        responses: Vec<[u8; PP_RESPONSE_LEN]>,
    },
    /// `2 ‖ alloc (32) ‖ u32 chunks`: put this in a `BlobPut`'s token field.
    Allocated {
        /// The allocation's secret.
        alloc: [u8; 32],
        /// Chunk uploads it allows.
        chunks: u32,
    },
}

impl BlobAllocReply {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            BlobAllocReply::Issued {
                epoch,
                public,
                responses,
            } => {
                let mut b = vec![1];
                b.extend_from_slice(&epoch.to_be_bytes());
                b.extend_from_slice(public);
                b.push(responses.len().min(BLOB_ISSUE_MAX) as u8);
                for r in responses.iter().take(BLOB_ISSUE_MAX) {
                    b.extend_from_slice(r);
                }
                b
            }
            BlobAllocReply::Allocated { alloc, chunks } => {
                [&[2u8][..], alloc, &chunks.to_be_bytes()].concat()
            }
        }
    }

    /// Decode (strict).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let m = RpcError::Malformed;
        match b.split_first() {
            Some((1, rest)) => {
                let (epoch, rest) = rest.split_first_chunk::<4>().ok_or(m)?;
                let (public, rest) = rest.split_first_chunk::<PP_PUBLIC_LEN>().ok_or(m)?;
                let (&n, rest) = rest.split_first().ok_or(m)?;
                let n = usize::from(n);
                if n > BLOB_ISSUE_MAX || rest.len() != n * PP_RESPONSE_LEN {
                    return Err(m);
                }
                Ok(BlobAllocReply::Issued {
                    epoch: u32::from_be_bytes(*epoch),
                    public: *public,
                    responses: rest
                        .chunks(PP_RESPONSE_LEN)
                        .map(|c| c.try_into().map_err(|_| m))
                        .collect::<Result<_>>()?,
                })
            }
            Some((2, rest)) => {
                let (alloc, rest) = rest.split_first_chunk::<32>().ok_or(m)?;
                let chunks = u32::from_be_bytes(rest.try_into().map_err(|_| m)?);
                Ok(BlobAllocReply::Allocated {
                    alloc: *alloc,
                    chunks,
                })
            }
            _ => Err(m),
        }
    }
}

/// Most messages one report may quote.
pub const MAX_REPORT_MESSAGES: usize = 10;
/// Longest quoted message in a report, in bytes.
pub const MAX_REPORT_TEXT: usize = 1024;

/// Why someone reported an account (`docs/13-operators.md` §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportReason {
    /// Unwanted bulk messages.
    Spam = 1,
    /// Harassment or threats.
    Abuse = 2,
    /// Anything else.
    Other = 3,
}

/// The text a person wrote in signed content: a Protobuf `Text` (field 2,
/// its text in field 2) or an `Attachment`'s caption (field 6, caption in
/// field 3) (`docs/08-envelope.md` §5.6). The field numbers never change, so
/// an operator's server reads them without the client's schema.
pub fn quoted_text(content: &[u8]) -> Option<String> {
    let (field, inner) = only_field(content)?;
    let want = match field {
        2 => 2,
        6 => 3,
        _ => return None,
    };
    let mut text = String::new();
    let mut b = inner;
    while !b.is_empty() {
        let (key, r) = varint(b)?;
        let (f, wire) = (key >> 3, key & 7);
        b = match wire {
            0 => varint(r)?.1,
            2 => {
                let (len, r) = varint(r)?;
                let len = usize::try_from(len).ok()?;
                if r.len() < len {
                    return None;
                }
                if f == want {
                    text = String::from_utf8(r[..len].to_vec()).ok()?;
                }
                &r[len..]
            }
            _ => return None,
        };
    }
    Some(text)
}

/// The one length-delimited top-level field of encoded content.
fn only_field(b: &[u8]) -> Option<(u64, &[u8])> {
    let (key, r) = varint(b)?;
    if key & 7 != 2 {
        return None;
    }
    let (len, r) = varint(r)?;
    let len = usize::try_from(len).ok()?;
    (r.len() == len).then_some((key >> 3, r))
}

fn varint(b: &[u8]) -> Option<(u64, &[u8])> {
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate().take(10) {
        v |= u64::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            return Some((v, &b[i + 1..]));
        }
    }
    None
}

/// Most signed messages one report carries (each with its 4,741 B
/// signature; what fits one frame).
pub const MAX_SIGNED_QUOTES: usize = 2;
/// Longest signed content in a report, in bytes.
pub const MAX_SIGNED_CONTENT: usize = 2_048;
/// A composite signature's length.
const SIG_LEN: usize = 4_741;

/// A quoted message's signature, from a conversation on the record
/// (`docs/05-ratchet.md` §9): what the reported account's device signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedQuote {
    /// The signing device (in the reported account's manifest).
    pub device: [u8; 16],
    /// Its counter in the conversation.
    pub counter: u64,
    /// The recipient's root hash (the reporter's: needed to check the
    /// signature, so a verifiable report shows whom it was sent to).
    pub recipient: [u8; 32],
    /// The composite signature.
    pub sig: Vec<u8>,
    /// The signed content (Protobuf, `docs/08-envelope.md` §5.6).
    pub content: Vec<u8>,
}

/// A user report to the operator of the reported account's server
/// (`Op::Report`). The header's mailbox is the reported account's request
/// inbox; nothing in it names the reporter, except that signed quotes
/// carry the recipient's root hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportBody {
    /// Why.
    pub reason: ReportReason,
    /// The conversation was on the record: `signed` carries the quotes'
    /// signatures, which the operator can check.
    pub on_record: bool,
    /// Messages the reporter chose to quote, oldest first.
    pub quotes: Vec<String>,
    /// On the record: the reported account's root.
    pub reported: Option<[u8; 64]>,
    /// On the record: the latest quotes' signatures, oldest first.
    pub signed: Vec<SignedQuote>,
}

impl ReportBody {
    /// `u8 version ‖ u8 reason ‖ u8 on_record ‖ u8 n ‖ n × (u16 len ‖
    /// UTF-8)`, and on the record `‖ reported root (64) ‖ u8 m ‖ m × (u16 len
    /// ‖ content ‖ device (16) ‖ u64 counter ‖ recipient root hash (32) ‖ sig
    /// (4,741))`. Signed quotes come first: to fit one frame, the oldest
    /// text quotes are left out.
    pub fn encode(&self) -> Vec<u8> {
        let on_record = self.on_record && self.reported.is_some();
        let mut fit: Vec<&SignedQuote> = if on_record {
            self.signed
                .iter()
                .filter(|s| s.sig.len() == SIG_LEN && s.content.len() <= MAX_SIGNED_CONTENT)
                .collect()
        } else {
            Vec::new()
        };
        fit.drain(..fit.len().saturating_sub(MAX_SIGNED_QUOTES));
        let signed_len = if on_record {
            64 + 1
                + fit
                    .iter()
                    .map(|s| 2 + s.content.len() + 56 + SIG_LEN)
                    .sum::<usize>()
        } else {
            0
        };
        let mut b = vec![1, self.reason as u8, u8::from(on_record)];
        let mut quotes: Vec<&[u8]> = self
            .quotes
            .iter()
            .take(MAX_REPORT_MESSAGES)
            .map(|q| {
                let mut end = q.len().min(MAX_REPORT_TEXT);
                while !q.is_char_boundary(end) {
                    end -= 1;
                }
                &q.as_bytes()[..end]
            })
            .collect();
        let text_len = |q: &[&[u8]]| 4 + q.iter().map(|x| 2 + x.len()).sum::<usize>();
        while !quotes.is_empty() && text_len(&quotes) + signed_len > MAX_PAYLOAD {
            quotes.remove(0);
        }
        b.push(quotes.len() as u8);
        for q in quotes {
            b.extend_from_slice(&(q.len() as u16).to_be_bytes());
            b.extend_from_slice(q);
        }
        if let (true, Some(root)) = (on_record, self.reported) {
            b.extend_from_slice(&root);
            b.push(fit.len() as u8);
            for s in fit {
                b.extend_from_slice(&(s.content.len() as u16).to_be_bytes());
                b.extend_from_slice(&s.content);
                b.extend_from_slice(&s.device);
                b.extend_from_slice(&s.counter.to_be_bytes());
                b.extend_from_slice(&s.recipient);
                b.extend_from_slice(&s.sig);
            }
        }
        b
    }

    /// Decode (strict).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let m = RpcError::Malformed;
        let (&[1, reason, on_record, n], mut rest) = b.split_first_chunk::<4>().ok_or(m)? else {
            return Err(m);
        };
        let reason = match reason {
            1 => ReportReason::Spam,
            2 => ReportReason::Abuse,
            3 => ReportReason::Other,
            _ => return Err(m),
        };
        if on_record > 1 || usize::from(n) > MAX_REPORT_MESSAGES {
            return Err(m);
        }
        let mut quotes = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let (len, r) = rest.split_first_chunk::<2>().ok_or(m)?;
            let len = usize::from(u16::from_be_bytes(*len));
            if len > MAX_REPORT_TEXT || r.len() < len {
                return Err(m);
            }
            let (q, r) = r.split_at(len);
            quotes.push(String::from_utf8(q.to_vec()).map_err(|_| m)?);
            rest = r;
        }
        let (mut reported, mut signed) = (None, Vec::new());
        if on_record == 1 {
            let (root, r) = rest.split_first_chunk::<64>().ok_or(m)?;
            let (&k, mut r) = r.split_first().ok_or(m)?;
            if usize::from(k) > MAX_SIGNED_QUOTES {
                return Err(m);
            }
            for _ in 0..k {
                let (len, x) = r.split_first_chunk::<2>().ok_or(m)?;
                let len = usize::from(u16::from_be_bytes(*len));
                if len > MAX_SIGNED_CONTENT || x.len() < len + 56 + SIG_LEN {
                    return Err(m);
                }
                let (content, x) = x.split_at(len);
                let (device, x) = x.split_first_chunk::<16>().ok_or(m)?;
                let (counter, x) = x.split_first_chunk::<8>().ok_or(m)?;
                let (recipient, x) = x.split_first_chunk::<32>().ok_or(m)?;
                let (sig, x) = x.split_at(SIG_LEN);
                signed.push(SignedQuote {
                    device: *device,
                    counter: u64::from_be_bytes(*counter),
                    recipient: *recipient,
                    sig: sig.to_vec(),
                    content: content.to_vec(),
                });
                r = x;
            }
            reported = Some(*root);
            rest = r;
        }
        if !rest.is_empty() {
            return Err(m);
        }
        Ok(Self {
            reason,
            on_record: on_record == 1,
            quotes,
            reported,
            signed,
        })
    }
}

/// Context for the proof of work that creates an inbox (`09-transport.md`
/// §3.1): `"inbox-create" ‖ mailbox ‖ u64 day`. The proof is the payload of
/// the creating `RegisterTokens`.
pub fn pow_context_inbox(mailbox: &[u8; 32], day: u64) -> Vec<u8> {
    [b"inbox-create".as_slice(), mailbox, &day.to_be_bytes()].concat()
}

/// Context string for a bundle-claim proof of work.
pub fn pow_context_claim(device: &[u8; 32], day: u64) -> Vec<u8> {
    [b"claim-bundle".as_slice(), device, &day.to_be_bytes()].concat()
}

/// Context string for a username-claim proof of work.
pub fn pow_context_username(name: &[u8; 32], day: u64) -> Vec<u8> {
    [b"claim-username".as_slice(), name, &day.to_be_bytes()].concat()
}

/// A username as a directory key: its bytes, zero-padded (names are at most
/// 32 ASCII characters).
pub fn name_key(name: &str) -> Option<[u8; 32]> {
    let b = name.as_bytes();
    if b.len() > 32 || b.contains(&0) {
        return None;
    }
    let mut k = [0u8; 32];
    k[..b.len()].copy_from_slice(b);
    Some(k)
}

/// The key of a `DirKind::Username` get for the server's committed
/// descriptor digest: the empty name, which no username can be.
pub const DESCRIPTOR_LOOKUP_KEY: [u8; 32] = [0; 32];

/// First byte of a `DirKind::Username` get for an account record: never
/// the first byte of a UTF-8 name.
pub const ACCOUNT_LOOKUP_TAG: u8 = 0xFF;

/// The key of a `DirKind::Username` get for the key-transparency record of
/// the account whose manifest directory key is `manifest_key`
/// (`03-identity.md` §8.1): [`ACCOUNT_LOOKUP_TAG`] then its last 31 bytes.
pub fn account_lookup_key(manifest_key: &[u8; 32]) -> [u8; 32] {
    let mut k = *manifest_key;
    k[0] = ACCOUNT_LOOKUP_TAG;
    k
}

/// Inverse of [`name_key`].
pub fn key_name(key: &[u8; 32]) -> Option<String> {
    let n = key.iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8(key[..n].to_vec()).ok()
}

/// Read credential for an inbox, derived from the owner secret.
pub fn read_credential(owner_secret: &[u8; 32]) -> [u8; 24] {
    let k: [u8; 32] =
        enclave_crypto::kmac::kmac256(owner_secret, b"read", "enclave/v1/rpc/read-credential");
    let mut out = [0u8; 24];
    out.copy_from_slice(&k[..24]);
    out
}

/// Seconds in an inbox week: account-inbox addresses rotate every week
/// (`docs/09-transport.md` §3.1).
pub const WEEK_SECS: u64 = 7 * 86_400;

/// Most daily read credentials registered with one inbox (three weeks:
/// created early in the week before its own, polled through the week
/// after).
pub const MAX_READ_DAYS: usize = 21;

/// The week of `now` (Unix seconds).
pub fn week_of(now: u64) -> u32 {
    u32::try_from(now / WEEK_SECS).unwrap_or(u32::MAX)
}

/// The day of `now` (Unix seconds).
pub fn day_of(now: u64) -> u32 {
    u32::try_from(now / 86_400).unwrap_or(u32::MAX)
}

/// The account's address seed, from its inbox seed: what contacts are
/// given, so they can follow the weekly addresses without being able to
/// read the inbox or act as its owner.
pub fn inbox_addr_seed(inbox_seed: &[u8; 32]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(inbox_seed, b"", "enclave/v1/net/inbox-addr-seed")
}

/// The account inbox's address for `week`.
pub fn inbox_addr(addr_seed: &[u8; 32], week: u32) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(addr_seed, &week.to_be_bytes(), "enclave/v1/net/inbox-addr")
}

/// The owner secret of one weekly address (a different one per address,
/// so the server can't link an owner's weeks by it).
pub fn inbox_owner(inbox_seed: &[u8; 32], addr: &[u8; 32]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(inbox_seed, addr, "enclave/v1/net/inbox-owner")
}

/// The owner secret of the account's vault-key blob (`DirKind::Vault`),
/// from the key it is sealed under, so the account can replace or delete
/// it later.
pub fn vault_owner(vault_key: &[u8; 32]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(vault_key, b"", "enclave/v1/net/vault-owner")
}

/// A `DirKind::Vault` upload of this one byte, with the blob's owner
/// secret, deletes the blob (a sealed blob is never one byte).
pub const VAULT_DELETE: &[u8] = &[0];

/// The inbox read key, from the inbox seed.
pub fn inbox_read_key(inbox_seed: &[u8; 32]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(inbox_seed, b"", "enclave/v1/net/inbox-read-key")
}

/// The read credential for `addr` on `day`: valid that day only (the
/// server accepts a day either side for clocks that disagree).
pub fn daily_read_credential(read_key: &[u8; 32], addr: &[u8; 32], day: u32) -> [u8; 24] {
    let k: [u8; 32] = enclave_crypto::kmac::kmac256(
        read_key,
        &[addr.as_slice(), &day.to_be_bytes()].concat(),
        "enclave/v1/net/read-cred",
    );
    let mut out = [0u8; 24];
    out.copy_from_slice(&k[..24]);
    out
}

/// Daily read credentials registered with an inbox: `(day, hash)`.
pub type ReadDays = Vec<(u32, [u8; 32])>;

/// The payload of a `RegisterTokens` that creates an inbox: the proof of
/// work, then each daily read credential's day and hash (none: the
/// credential is the static one derived from the owner secret).
pub fn create_payload(proof: &[u8; 32], days: &[(u32, [u8; 32])]) -> Vec<u8> {
    let mut v = proof.to_vec();
    for (d, h) in days {
        v.extend_from_slice(&d.to_be_bytes());
        v.extend_from_slice(h);
    }
    v
}

/// Inverse of [`create_payload`].
pub fn parse_create_payload(p: &[u8]) -> Option<([u8; 32], ReadDays)> {
    let proof: [u8; 32] = p.get(..32)?.try_into().ok()?;
    let rest = &p[32..];
    if !rest.len().is_multiple_of(36) || rest.len() / 36 > MAX_READ_DAYS {
        return None;
    }
    let days = rest
        .chunks_exact(36)
        .filter_map(|c| {
            Some((
                u32::from_be_bytes(c[..4].try_into().ok()?),
                c[4..].try_into().ok()?,
            ))
        })
        .collect();
    Some((proof, days))
}

/// What a request inbox's server stores for an invite capability: bound
/// to the inbox, so a capability says nothing at another address.
pub fn cap_hash(cap: &[u8; 32], mailbox: &[u8; 32]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(cap, mailbox, "enclave/v1/net/cap-hash")
}

/// Server-side hash of an owner secret or read credential.
pub fn credential_hash(secret: &[u8]) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(secret, b"", "enclave/v1/rpc/credential-hash")
}

/// Directory key for a root public key.
pub fn manifest_key(root: &[u8; 64]) -> [u8; 32] {
    enclave_crypto::hash::shake256(&[b"enclave/v1/dir/manifest".as_slice(), root].concat())
}

/// Directory key for a device.
pub fn device_key(device: &[u8; 16]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(device);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_alloc_codec() {
        let issue = BlobAlloc::Issue(vec![[7; PP_REQUEST_LEN]; 3]);
        assert_eq!(BlobAlloc::decode(&issue.encode()).unwrap(), issue);
        let redeem = BlobAlloc::Redeem([9; PP_TOKEN_LEN]);
        assert_eq!(BlobAlloc::decode(&redeem.encode()).unwrap(), redeem);
        assert_eq!(BlobAlloc::decode(&[3]).unwrap(), BlobAlloc::Key);
        for bad in [vec![1, 0], vec![1, 9], vec![2, 1, 2], vec![3, 0], vec![4]] {
            assert!(BlobAlloc::decode(&bad).is_err(), "{bad:?}");
        }
        let issued = BlobAllocReply::Issued {
            epoch: 700,
            public: [2; PP_PUBLIC_LEN],
            responses: vec![[3; PP_RESPONSE_LEN]; 2],
        };
        assert_eq!(BlobAllocReply::decode(&issued.encode()).unwrap(), issued);
        let got = BlobAllocReply::Allocated {
            alloc: [4; 32],
            chunks: ALLOC_CHUNKS,
        };
        assert_eq!(BlobAllocReply::decode(&got.encode()).unwrap(), got);
        assert!(BlobAllocReply::decode(&[2, 1]).is_err());
        assert_eq!(issuer_epoch(ISSUER_EPOCH_SECS * 3 + 5), 3);
    }

    #[test]
    fn signed_report_codec() {
        // A Protobuf `Text`: field 2 { tokens (1), text (2) = "hi", id (3) }.
        let text = [
            0x12, 0x0a, 0x0a, 0x00, 0x12, 0x02, b'h', b'i', 0x1a, 0x02, 7, 7,
        ];
        assert_eq!(quoted_text(&text).as_deref(), Some("hi"));
        assert_eq!(quoted_text(&[0x0a, 0x00]), None, "not a text");
        assert_eq!(quoted_text(&text[..5]), None, "cut short");
        let q = |i: u8| SignedQuote {
            device: [i; 16],
            counter: u64::from(i),
            recipient: [9; 32],
            sig: vec![i; SIG_LEN],
            content: vec![i; MAX_SIGNED_CONTENT],
        };
        let r = ReportBody {
            reason: ReportReason::Abuse,
            on_record: true,
            quotes: vec!["x".repeat(MAX_REPORT_TEXT); MAX_REPORT_MESSAGES],
            reported: Some([3; 64]),
            signed: vec![q(1), q(2), q(3)],
        };
        let b = r.encode();
        assert!(b.len() <= MAX_PAYLOAD, "fits one frame");
        let d = ReportBody::decode(&b).unwrap();
        assert!(d.on_record);
        assert_eq!(d.reported, Some([3; 64]));
        assert_eq!(d.signed, vec![q(2), q(3)], "the latest two");
        assert!(d.quotes.len() < MAX_REPORT_MESSAGES, "older text left out");
        let mut cut = b.clone();
        cut.pop();
        assert!(ReportBody::decode(&cut).is_err());
    }

    #[test]
    fn report_codec() {
        let r = ReportBody {
            reason: ReportReason::Spam,
            on_record: false,
            quotes: vec!["buy now".into(), "é".repeat(600)],
            reported: None,
            signed: Vec::new(),
        };
        let b = r.encode();
        let d = ReportBody::decode(&b).unwrap();
        assert_eq!(d.quotes[0], "buy now");
        assert!(
            d.quotes[1].len() <= MAX_REPORT_TEXT,
            "cut on a char boundary"
        );
        let mut most = r.clone();
        most.quotes = vec!["x".repeat(5000); 20];
        let b = most.encode();
        assert!(
            b.len() + 4 <= ENVELOPE_LEN,
            "the largest report fits one frame"
        );
        assert_eq!(
            ReportBody::decode(&b).unwrap().quotes.len(),
            MAX_REPORT_MESSAGES
        );
        for bad in [
            vec![2, 1, 0, 0],
            vec![1, 9, 0, 0],
            vec![1, 1, 0, 1, 0],
            vec![1, 1, 0, 0, 7],
        ] {
            assert!(ReportBody::decode(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn frames_and_dir_codec() {
        let mut rng = HedgedRng::new().unwrap();
        let env = frame(b"payload", &mut rng).unwrap();
        assert_eq!(env.len(), ENVELOPE_LEN);
        assert_eq!(unframe(&env).unwrap(), b"payload");
        let r = DirRequest {
            kind: DirKind::Bundle,
            action: DirAction::Put,
            key: [1; 32],
            index: 2,
            total: 3,
            proof: [4; 32],
            data: vec![5; 100],
        };
        assert_eq!(DirRequest::decode(&r.encode()).unwrap(), r);
        let d = DirReply {
            total: 7,
            claim: [8; 32],
            data: vec![9; 10],
        };
        assert_eq!(DirReply::decode(&d.encode()).unwrap(), d);
        assert_eq!(chunks(&vec![0u8; 30_000]).len(), 3);
    }
}
