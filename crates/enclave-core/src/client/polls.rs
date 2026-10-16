//! Polls in groups (`docs/07-groups.md` §7.5, `docs/16-features.md`), and
//! the other structured group content (`FLAG_RICH`): pins, reactions,
//! edits and deletes.
//!
//! A poll, each vote and the close are group messages flagged `FLAG_RICH`,
//! so they are sealed and MAC-authenticated like any other: members know
//! who voted how, outsiders learn nothing, and nobody can prove it to
//! outsiders (the MAC vector is deniable). A later vote from the same
//! member replaces their earlier one. Only the creator can close a poll;
//! the close carries `tally_hash = SHA3-512("enclave/v1/proto/poll-tally-hash"
//! ‖ poll_id ‖ u32 counts…)`, and every member compares it with the tally
//! they counted themselves, so a vote that didn't reach someone shows.
//!
//! **Anonymous polls** (groups): the poll carries a fresh X448 + ML-KEM-1024
//! key of its creator's, and each vote goes to the group sealed to it
//! (`proto/poll-vote-seal`), so members see that someone voted but not
//! how; only the creator can open the votes. At the close the creator posts
//! the counts. The creator therefore sees who voted what, and the app says
//! so when the poll is made.
//!
//! **1:1 polls** are the same structures sent as `Content::Poll` inside the
//! pairwise session; a poll's records are kept under its conversation (the
//! group id, or the first 32 bytes of the contact's root).

use super::search::Place;
use super::{Client, Event};
use crate::content::{Content, MAX_ATTACHMENT_REF, MAX_REACTION, MAX_TEXT};
use crate::{CoreError, Result};
use enclave_crypto::hash::sha3_512_parts;
use enclave_crypto::kem::{
    self, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448Public, X448Secret,
};
use enclave_crypto::seal;
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::group::FLAG_RICH;
use enclave_proto::labels;
use std::collections::BTreeMap;

const NS_POLLS: &str = "polls";
/// Options per poll.
pub const MAX_OPTIONS: usize = 10;
/// Longest option, in bytes.
pub const MAX_OPTION: usize = 200;

const K_POLL: u8 = 1;
const K_VOTE: u8 = 2;
const K_CLOSE: u8 = 3;
const K_PIN: u8 = 4;
const K_REACT: u8 = 5;
const K_EDIT: u8 = 6;
const K_DELETE: u8 = 7;
const K_ATTACHMENT: u8 = 8;
const K_STICKER: u8 = 9;
const K_HOST_VOTE: u8 = 10;
const K_CALL: u8 = 11;
const K_TEXT: u8 = 12;
const K_SEALED_VOTE: u8 = 13;
const K_RESULTS: u8 = 14;
/// A sealed vote: ephemeral X448 key, ML-KEM ciphertext, sealed choice.
const MAX_SEALED_VOTE: usize = 56 + kem::MLKEM_CT_LEN + seal::OVERHEAD + 1;
/// Most members one message mentions.
pub const MAX_MENTIONS: usize = 32;
/// Most bytes of a group call message (`enclave_calls::group`).
const MAX_CALL: usize = 256;

pub(crate) enum Rich {
    Poll {
        id: [u8; 16],
        question: String,
        options: Vec<String>,
        /// Anonymous: the key votes are sealed to (X448, ML-KEM-1024).
        vote_key: Option<([u8; 56], Vec<u8>)>,
    },
    /// An anonymous poll's vote, sealed to its creator.
    SealedVote {
        poll: [u8; 16],
        sealed: Vec<u8>,
    },
    /// An anonymous poll's counts, posted by its creator at the close.
    Results {
        poll: [u8; 16],
        counts: Vec<u32>,
    },
    Vote {
        poll: [u8; 16],
        choice: u8,
    },
    Close {
        poll: [u8; 16],
        tally: [u8; 64],
    },
    /// Pin or unpin a message (`pins.rs`).
    Pin {
        id: [u8; 16],
        on: bool,
    },
    /// Set (or, empty, remove) our reaction to a message (`group_edits.rs`).
    React {
        id: [u8; 16],
        emoji: String,
    },
    /// Replace the text of one of our messages (advisory, 24 h).
    Edit {
        id: [u8; 16],
        text: String,
    },
    /// Delete one of our messages for everyone (advisory).
    Delete {
        id: [u8; 16],
    },
    /// A file (`group_files.rs`): its sealed reference and a caption.
    Attachment {
        id: [u8; 16],
        attachment: Vec<u8>,
        caption: String,
        /// View once (`group_files.rs`).
        view_once: bool,
    },
    /// A sticker (`stickers.rs`): the pack's reference and an index.
    Sticker {
        id: [u8; 16],
        pack: Vec<u8>,
        index: u8,
    },
    /// An admin's vote to move the group's mailboxes to `host`
    /// (`group_hosts.rs`).
    HostVote {
        host: [u8; 16],
    },
    /// Group call signalling (`enclave_calls::group`; the vault runs the
    /// call).
    Call {
        message: Vec<u8>,
    },
    /// A text that answers another message, was forwarded, or mentions
    /// members (a plain text is just `id ‖ text`, not rich).
    Text {
        id: [u8; 16],
        text: String,
        reply: Option<[u8; 16]>,
        forwarded: bool,
        /// Mentioned members: the first 16 bytes of each root.
        mentions: Vec<[u8; 16]>,
        /// The sender's preview of a link in the text.
        link: Option<crate::content::LinkPreview>,
    },
}

fn get_str(r: &mut Reader<'_>, max: usize) -> enclave_proto::Result<String> {
    String::from_utf8(r.bytes(max)?.to_vec()).map_err(|_| ProtoError::Decode)
}

impl Rich {
    /// Something every member may post in an announcement-only group (not
    /// a poll, file or sticker of their own).
    pub(crate) fn is_reply(&self) -> bool {
        !matches!(
            self,
            Rich::Poll { .. } | Rich::Attachment { .. } | Rich::Sticker { .. } | Rich::Text { .. }
        )
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Rich::Poll {
                id,
                question,
                options,
                vote_key,
            } => {
                w.u8(K_POLL)
                    .fixed(id)
                    .bytes(question.as_bytes())
                    .u8(options.len() as u8);
                for o in options {
                    w.bytes(o.as_bytes());
                }
                // Absent (an open poll) as earlier versions wrote it.
                if let Some((x, m)) = vote_key {
                    w.u8(1).fixed(x).bytes(m);
                }
            }
            Rich::SealedVote { poll, sealed } => {
                w.u8(K_SEALED_VOTE).fixed(poll).bytes(sealed);
            }
            Rich::Results { poll, counts } => {
                w.u8(K_RESULTS).fixed(poll).u8(counts.len() as u8);
                for c in counts {
                    w.u32(*c);
                }
            }
            Rich::Vote { poll, choice } => {
                w.u8(K_VOTE).fixed(poll).u8(*choice);
            }
            Rich::Close { poll, tally } => {
                w.u8(K_CLOSE).fixed(poll).fixed(tally);
            }
            Rich::Pin { id, on } => {
                w.u8(K_PIN).fixed(id).u8(u8::from(*on));
            }
            Rich::React { id, emoji } => {
                w.u8(K_REACT).fixed(id).bytes(emoji.as_bytes());
            }
            Rich::Edit { id, text } => {
                w.u8(K_EDIT).fixed(id).bytes(text.as_bytes());
            }
            Rich::Delete { id } => {
                w.u8(K_DELETE).fixed(id);
            }
            Rich::Attachment {
                id,
                attachment,
                caption,
                view_once,
            } => {
                w.u8(K_ATTACHMENT)
                    .fixed(id)
                    .bytes(attachment)
                    .bytes(caption.as_bytes())
                    .u8(u8::from(*view_once));
            }
            Rich::Sticker { id, pack, index } => {
                w.u8(K_STICKER).fixed(id).bytes(pack).u8(*index);
            }
            Rich::HostVote { host } => {
                w.u8(K_HOST_VOTE).fixed(host);
            }
            Rich::Call { message } => {
                w.u8(K_CALL).bytes(message);
            }
            Rich::Text {
                id,
                text,
                reply,
                forwarded,
                mentions,
                link,
            } => {
                w.u8(K_TEXT).fixed(id).bytes(text.as_bytes());
                match reply {
                    Some(r) => w.u8(1).fixed(r),
                    None => w.u8(0),
                };
                w.u8(u8::from(*forwarded));
                w.u8(mentions.len().min(MAX_MENTIONS) as u8);
                for m in mentions.iter().take(MAX_MENTIONS) {
                    w.fixed(m);
                }
                w.bytes(
                    &link
                        .as_ref()
                        .map(crate::content::LinkPreview::encode)
                        .unwrap_or_default(),
                );
            }
        }
        w.finish()
    }

    pub(crate) fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let v = match r.u8()? {
            K_POLL => {
                let id = r.array()?;
                let question = get_str(&mut r, MAX_TEXT)?;
                let n = usize::from(r.u8()?);
                if !(2..=MAX_OPTIONS).contains(&n) {
                    return Err(ProtoError::Decode);
                }
                let options = (0..n)
                    .map(|_| get_str(&mut r, MAX_OPTION))
                    .collect::<enclave_proto::Result<_>>()?;
                let vote_key = if r.remaining() == 0 {
                    None
                } else {
                    if r.u8()? != 1 {
                        return Err(ProtoError::Decode);
                    }
                    let x = r.array()?;
                    let m = r.bytes(kem::MLKEM_PK_LEN)?.to_vec();
                    if m.len() != kem::MLKEM_PK_LEN {
                        return Err(ProtoError::Decode);
                    }
                    Some((x, m))
                };
                Rich::Poll {
                    id,
                    question,
                    options,
                    vote_key,
                }
            }
            K_SEALED_VOTE => Rich::SealedVote {
                poll: r.array()?,
                sealed: r.bytes(MAX_SEALED_VOTE)?.to_vec(),
            },
            K_RESULTS => {
                let poll = r.array()?;
                let n = usize::from(r.u8()?);
                if n > MAX_OPTIONS {
                    return Err(ProtoError::Decode);
                }
                let counts = (0..n)
                    .map(|_| r.u32())
                    .collect::<enclave_proto::Result<_>>()?;
                Rich::Results { poll, counts }
            }
            K_VOTE => Rich::Vote {
                poll: r.array()?,
                choice: r.u8()?,
            },
            K_CLOSE => Rich::Close {
                poll: r.array()?,
                tally: r.array()?,
            },
            K_REACT => Rich::React {
                id: r.array()?,
                emoji: get_str(&mut r, MAX_REACTION)?,
            },
            K_EDIT => Rich::Edit {
                id: r.array()?,
                text: get_str(&mut r, MAX_TEXT)?,
            },
            K_DELETE => Rich::Delete { id: r.array()? },
            K_STICKER => Rich::Sticker {
                id: r.array()?,
                pack: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                index: r.u8()?,
            },
            K_ATTACHMENT => Rich::Attachment {
                id: r.array()?,
                attachment: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                caption: get_str(&mut r, MAX_TEXT)?,
                view_once: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            K_HOST_VOTE => Rich::HostVote { host: r.array()? },
            K_CALL => Rich::Call {
                message: r.bytes(MAX_CALL)?.to_vec(),
            },
            K_TEXT => {
                let id = r.array()?;
                let text = get_str(&mut r, MAX_TEXT)?;
                let reply = match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(ProtoError::Decode),
                };
                let forwarded = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                };
                let n = usize::from(r.u8()?);
                if n > MAX_MENTIONS {
                    return Err(ProtoError::Decode);
                }
                let mentions = (0..n)
                    .map(|_| r.array())
                    .collect::<enclave_proto::Result<_>>()?;
                let link = r.bytes(crate::content::MAX_LINK_PREVIEW)?;
                let link = if link.is_empty() {
                    None
                } else {
                    Some(crate::content::LinkPreview::decode(link)?)
                };
                Rich::Text {
                    id,
                    text,
                    reply,
                    forwarded,
                    mentions,
                    link,
                }
            }
            K_PIN => Rich::Pin {
                id: r.array()?,
                on: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Decode),
                },
            },
            _ => return Err(ProtoError::Decode),
        };
        r.end()?;
        Ok(v)
    }
}

/// The creator's secret halves of an anonymous poll's vote key.
type VoteSecret = (zeroize::Zeroizing<[u8; 56]>, zeroize::Zeroizing<Vec<u8>>);

/// A stored poll.
struct Poll {
    creator: [u8; 64],
    question: String,
    options: Vec<String>,
    /// Who voted what: everyone's in an open poll; in an anonymous one,
    /// everyone's for its creator and only our own for everyone else.
    votes: BTreeMap<[u8; 64], u8>,
    /// The creator's tally hash, once closed.
    closed: Option<[u8; 64]>,
    /// Anonymous: the key votes are sealed to (X448, ML-KEM-1024), and,
    /// for its creator, the secret halves.
    vote_key: Option<([u8; 56], Vec<u8>)>,
    secret: Option<VoteSecret>,
    /// Anonymous: who sent a sealed vote (everyone sees that much).
    voters: std::collections::BTreeSet<[u8; 64]>,
    /// Anonymous: the counts the creator posted at the close.
    results: Option<Vec<u32>>,
}

impl Poll {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(2)
            .fixed(&self.creator)
            .bytes(self.question.as_bytes())
            .u8(self.options.len() as u8);
        for o in &self.options {
            w.bytes(o.as_bytes());
        }
        w.u32(self.votes.len() as u32);
        for (r, c) in &self.votes {
            w.fixed(r).u8(*c);
        }
        match &self.closed {
            Some(t) => w.u8(1).fixed(t),
            None => w.u8(0),
        };
        match &self.vote_key {
            Some((x, m)) => w.u8(1).fixed(x).bytes(m),
            None => w.u8(0),
        };
        match &self.secret {
            Some((x, m)) => w.u8(1).fixed(&x[..]).bytes(&m[..]),
            None => w.u8(0),
        };
        w.u32(self.voters.len() as u32);
        for v in &self.voters {
            w.fixed(v);
        }
        match &self.results {
            Some(c) => {
                w.u8(1).u8(c.len() as u8);
                for x in c {
                    w.u32(*x);
                }
            }
            None => {
                w.u8(0);
            }
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if !(1..=2).contains(&version) {
            return Err(ProtoError::Decode);
        }
        let creator = r.array()?;
        let question = get_str(&mut r, MAX_TEXT)?;
        let n = usize::from(r.u8()?);
        let options = (0..n)
            .map(|_| get_str(&mut r, MAX_OPTION))
            .collect::<enclave_proto::Result<_>>()?;
        let mut votes = BTreeMap::new();
        for _ in 0..r.u32()?.min(1000) {
            votes.insert(r.array()?, r.u8()?);
        }
        let closed = match r.u8()? {
            1 => Some(r.array()?),
            _ => None,
        };
        let (mut vote_key, mut secret, mut voters, mut results) =
            (None, None, std::collections::BTreeSet::new(), None);
        if version >= 2 {
            if r.u8()? == 1 {
                vote_key = Some((r.array()?, r.bytes(kem::MLKEM_PK_LEN)?.to_vec()));
            }
            if r.u8()? == 1 {
                secret = Some((
                    zeroize::Zeroizing::new(r.array()?),
                    zeroize::Zeroizing::new(r.bytes(1 << 13)?.to_vec()),
                ));
            }
            for _ in 0..r.u32()?.min(1000) {
                voters.insert(r.array()?);
            }
            if r.u8()? == 1 {
                let n = usize::from(r.u8()?).min(MAX_OPTIONS);
                results = Some(
                    (0..n)
                        .map(|_| r.u32())
                        .collect::<enclave_proto::Result<_>>()?,
                );
            }
        }
        r.end()?;
        Ok(Self {
            creator,
            question,
            options,
            votes,
            closed,
            vote_key,
            secret,
            voters,
            results,
        })
    }

    fn counts(&self) -> Vec<u32> {
        let mut c = vec![0u32; self.options.len()];
        for &v in self.votes.values() {
            if let Some(x) = c.get_mut(usize::from(v)) {
                *x += 1;
            }
        }
        c
    }
}

/// `SHA3-512(label ‖ poll_id ‖ u32 counts…)`.
fn tally_hash(poll: &[u8; 16], counts: &[u32]) -> [u8; 64] {
    let counts: Vec<u8> = counts.iter().flat_map(|c| c.to_be_bytes()).collect();
    sha3_512_parts(&[labels::POLL_TALLY_HASH.as_bytes(), poll, &counts])
}

/// The key a vote is sealed under, from both shared secrets and
/// everything public about the exchange.
fn vote_seal_key(
    dh: &[u8],
    ss: &[u8],
    eph: &[u8],
    ct: &[u8],
    x: &[u8],
    m: &[u8],
    poll: &[u8; 16],
) -> seal::SealKey {
    let s = kem::combine(
        Suite::TwoKem,
        &[dh, ss],
        &[labels::POLL_VOTE.as_bytes(), poll, eph, ct, x, m],
        None,
    );
    seal::derive_key(&s[..], poll, labels::POLL_VOTE_SEAL)
}

/// Seal `choice` to an anonymous poll's key.
fn seal_vote(
    key: &([u8; 56], Vec<u8>),
    poll: &[u8; 16],
    choice: u8,
    rng: &mut enclave_crypto::rng::HedgedRng,
) -> Result<Vec<u8>> {
    let (eph, eph_pub) = X448Secret::generate(rng)?;
    let dh = eph.diffie_hellman(&X448Public(key.0))?;
    let (ct, ss) = MlKemPublic::from_slice(&key.1)?.encapsulate(rng)?;
    let k = vote_seal_key(
        &dh[..],
        &ss[..],
        &eph_pub.0,
        &ct.0[..],
        &key.0,
        &key.1,
        poll,
    );
    let sealed = seal::seal(&k, poll, &[choice], rng)?;
    Ok([&eph_pub.0[..], &ct.0[..], &sealed].concat())
}

/// Open a sealed vote with the creator's secret halves.
fn open_vote(p: &Poll, poll: &[u8; 16], sealed: &[u8]) -> Option<u8> {
    let (xs, ms) = p.secret.as_ref()?;
    let (xp, mp) = p.vote_key.as_ref()?;
    let (eph, rest) = sealed.split_first_chunk::<56>()?;
    let (ct, body) = (
        rest.get(..kem::MLKEM_CT_LEN)?,
        rest.get(kem::MLKEM_CT_LEN..)?,
    );
    let dh = X448Secret::from_bytes(**xs)
        .diffie_hellman(&X448Public(*eph))
        .ok()?;
    let ss = MlKemSecret::from_slice(ms)
        .ok()?
        .decapsulate(&MlKemCiphertext::from_slice(ct).ok()?);
    let k = vote_seal_key(&dh[..], &ss[..], eph, ct, xp, mp, poll);
    match seal::open(&k, poll, body).ok()?.as_slice() {
        [c] => Some(*c),
        _ => None,
    }
}

/// A poll as the app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollView {
    /// Poll id.
    pub id: [u8; 16],
    /// The question.
    pub question: String,
    /// Options with their vote counts.
    pub options: Vec<(String, u32)>,
    /// Our vote.
    pub mine: Option<u8>,
    /// We created it (and so may close it).
    pub ours: bool,
    /// Closed by its creator.
    pub closed: bool,
    /// Once closed: whether the creator's tally matches ours (`None` for
    /// an anonymous poll, whose votes only its creator counts).
    pub tally_agrees: Option<bool>,
    /// Anonymous: how members voted is sealed to its creator.
    pub anonymous: bool,
    /// How many have voted (anonymous polls show this before the counts).
    pub voters: u32,
}

fn key(gid: &[u8; 32], id: &[u8; 16]) -> Vec<u8> {
    [&gid[..], &id[..]].concat()
}

/// The conversation a poll's records are kept under.
fn scope(place: &Place) -> [u8; 32] {
    match place {
        Place::Group(g) => *g,
        Place::Contact(r) => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&r[..32]);
            s
        }
    }
}

impl Client {
    fn load_poll(&self, gid: &[u8; 32], id: &[u8; 16]) -> Result<Option<Poll>> {
        Ok(match self.store.get(NS_POLLS, &key(gid, id))? {
            Some(b) => Some(Poll::decode(&b)?),
            None => None,
        })
    }

    fn save_poll(&mut self, gid: &[u8; 32], id: &[u8; 16], p: &Poll) -> Result<()> {
        self.store
            .put(NS_POLLS, &key(gid, id), &p.encode(), &mut self.rng)?;
        Ok(())
    }

    /// A member of `gid` changed their recovery words: their polls and
    /// votes follow (`03-identity.md` §8.2.6).
    pub(crate) fn rename_in_polls(
        &mut self,
        gid: &[u8; 32],
        old: &[u8; 64],
        new: &[u8; 64],
    ) -> Result<()> {
        for (k, b) in self.store.scan(NS_POLLS)? {
            if !k.starts_with(gid) {
                continue;
            }
            let Ok(mut p) = Poll::decode(&b) else {
                continue;
            };
            let mut changed = false;
            if p.creator == *old {
                p.creator = *new;
                changed = true;
            }
            if let Some(v) = p.votes.remove(old) {
                p.votes.insert(*new, v);
                changed = true;
            }
            if changed {
                self.store.put(NS_POLLS, &k, &p.encode(), &mut self.rng)?;
            }
        }
        Ok(())
    }

    /// Ask the group a question with 2 to 10 options.
    pub async fn create_poll(
        &mut self,
        gid: &[u8; 32],
        question: &str,
        options: &[String],
    ) -> Result<[u8; 16]> {
        self.create_poll_in(&Place::Group(*gid), question, options, false)
            .await
    }

    /// Ask a question with 2 to 10 options, in a group or a 1:1
    /// conversation. `anonymous` (groups only): votes are sealed to us,
    /// and members see the counts when we close it.
    pub async fn create_poll_in(
        &mut self,
        place: &Place,
        question: &str,
        options: &[String],
        anonymous: bool,
    ) -> Result<[u8; 16]> {
        let options: Vec<String> = options
            .iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        if question.trim().is_empty()
            || !(2..=MAX_OPTIONS).contains(&options.len())
            || question.len() > MAX_TEXT
            || options.iter().any(|o| o.len() > MAX_OPTION)
        {
            return Err(CoreError::TooLong);
        }
        if anonymous && matches!(place, Place::Contact(_)) {
            // Between two people a vote can't hide who cast it.
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        if let Place::Group(gid) = place {
            self.prepare_group_send(gid, now).await?;
        }
        let id: [u8; 16] = self.rng.array("core/poll-id")?;
        let me = self.account.root_public.0;
        let (vote_key, secret) = if anonymous {
            let (xs, xp) = X448Secret::generate(&mut self.rng)?;
            let (ms, mp) = MlKemSecret::generate(&mut self.rng)?;
            (
                Some((xp.0, mp.0.to_vec())),
                Some((
                    xs.to_bytes(),
                    zeroize::Zeroizing::new(ms.as_bytes().to_vec()),
                )),
            )
        } else {
            (None, None)
        };
        let poll = Poll {
            creator: me,
            question: question.trim().to_string(),
            options: options.clone(),
            votes: BTreeMap::new(),
            closed: None,
            vote_key: vote_key.clone(),
            secret,
            voters: Default::default(),
            results: None,
        };
        self.save_poll(&scope(place), &id, &poll)?;
        let rich = Rich::Poll {
            id,
            question: poll.question.clone(),
            options,
            vote_key,
        };
        match place {
            Place::Group(gid) => {
                let mut m = self.store_group_message(gid, id, None, &poll.question, now)?;
                m.poll = Some(id);
                self.post_group(gid, &rich.encode(), FLAG_RICH, now).await?;
                m.delivered = true;
                self.put_group_message(gid, &m)?;
            }
            Place::Contact(root) => {
                let mut m = self.new_message(root, id, true, &poll.question, 0, now)?;
                m.poll = Some(id);
                self.put_message(root, &m)?;
                let content = Content::Poll(rich.encode());
                let sent = self.send_tracked(root, id, &content, now).await?;
                self.send_self_copy(root, &content, now).await?;
                m.sent = sent;
                self.put_message(root, &m)?;
            }
        }
        Ok(id)
    }

    /// Vote (again, to change it) while the poll is open.
    pub async fn vote(&mut self, gid: &[u8; 32], id: &[u8; 16], choice: u8) -> Result<()> {
        self.vote_in(&Place::Group(*gid), id, choice).await
    }

    /// Vote in a poll of a group or a 1:1 conversation.
    pub async fn vote_in(&mut self, place: &Place, id: &[u8; 16], choice: u8) -> Result<()> {
        let sc = scope(place);
        let mut p = self.load_poll(&sc, id)?.ok_or(CoreError::NotFound)?;
        if p.closed.is_some() || usize::from(choice) >= p.options.len() {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        let me = self.account.root_public.0;
        p.votes.insert(me, choice);
        let rich = match &p.vote_key {
            Some(k) if p.creator != me => {
                p.voters.insert(me);
                Rich::SealedVote {
                    poll: *id,
                    sealed: seal_vote(k, id, choice, &mut self.rng)?,
                }
            }
            _ => Rich::Vote { poll: *id, choice },
        };
        self.save_poll(&sc, id, &p)?;
        self.send_poll_rich(place, &rich, now).await
    }

    /// Close our poll: no more votes, and everyone checks the tally (or,
    /// for an anonymous poll, gets the counts).
    pub async fn close_poll(&mut self, gid: &[u8; 32], id: &[u8; 16]) -> Result<()> {
        self.close_poll_in(&Place::Group(*gid), id).await
    }

    /// Close our poll in a group or a 1:1 conversation.
    pub async fn close_poll_in(&mut self, place: &Place, id: &[u8; 16]) -> Result<()> {
        let sc = scope(place);
        let mut p = self.load_poll(&sc, id)?.ok_or(CoreError::NotFound)?;
        if p.creator != self.account.root_public.0 {
            return Err(CoreError::NotAccepted);
        }
        if p.closed.is_some() {
            return Ok(());
        }
        let now = self.now();
        let counts = p.counts();
        let tally = tally_hash(id, &counts);
        p.closed = Some(tally);
        if p.vote_key.is_some() {
            p.results = Some(counts.clone());
        }
        self.save_poll(&sc, id, &p)?;
        if p.vote_key.is_some() {
            let results = Rich::Results { poll: *id, counts };
            self.send_poll_rich(place, &results, now).await?;
        }
        let rich = Rich::Close { poll: *id, tally };
        self.send_poll_rich(place, &rich, now).await
    }

    /// A vote or close, to the poll's conversation.
    async fn send_poll_rich(&mut self, place: &Place, rich: &Rich, now: u64) -> Result<()> {
        match place {
            Place::Group(gid) => {
                self.prepare_group_reply(gid, now).await?;
                self.post_group(gid, &rich.encode(), FLAG_RICH, now).await
            }
            Place::Contact(root) => {
                let content = Content::Poll(rich.encode());
                self.send_content(root, &content, now).await?;
                self.send_self_copy(root, &content, now).await
            }
        }
    }

    /// A poll in a 1:1 conversation, or from one of our own devices'
    /// copies of one (`ours`): its creation, votes and close.
    pub(crate) fn on_contact_poll(
        &mut self,
        root: &[u8; 64],
        ours: bool,
        content: &[u8],
        now: u64,
    ) -> Result<Vec<Event>> {
        let place = Place::Contact(*root);
        let sc = scope(&place);
        let from = if ours {
            self.account.root_public.0
        } else {
            *root
        };
        let changed = |poll| vec![Event::PollChanged { place, poll }];
        match Rich::decode(content)? {
            Rich::Poll {
                id,
                question,
                options,
                vote_key: None,
            } => {
                if self.load_poll(&sc, &id)?.is_some() {
                    return Ok(Vec::new());
                }
                let poll = Poll {
                    creator: from,
                    question: question.clone(),
                    options,
                    votes: BTreeMap::new(),
                    closed: None,
                    vote_key: None,
                    secret: None,
                    voters: Default::default(),
                    results: None,
                };
                self.save_poll(&sc, &id, &poll)?;
                let mut m = self.new_message(root, id, ours, &question, 0, now)?;
                m.poll = Some(id);
                m.sent = ours;
                self.put_message(root, &m)?;
                if !ours {
                    self.bump_unread(root)?;
                }
                Ok(vec![Event::Message {
                    root: *root,
                    message: m,
                }])
            }
            Rich::Vote { poll, choice } => {
                let Some(mut p) = self.load_poll(&sc, &poll)? else {
                    return Ok(Vec::new());
                };
                if p.closed.is_some() || usize::from(choice) >= p.options.len() {
                    return Ok(Vec::new());
                }
                p.votes.insert(from, choice);
                self.save_poll(&sc, &poll, &p)?;
                Ok(changed(poll))
            }
            Rich::Close { poll, tally } => {
                let Some(mut p) = self.load_poll(&sc, &poll)? else {
                    return Ok(Vec::new());
                };
                if p.creator != from || p.closed.is_some() {
                    return Ok(Vec::new());
                }
                p.closed = Some(tally);
                self.save_poll(&sc, &poll, &p)?;
                Ok(changed(poll))
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Tell the group we pinned (or unpinned) message `id`.
    pub(crate) async fn post_group_pin(
        &mut self,
        gid: &[u8; 32],
        id: &[u8; 16],
        on: bool,
    ) -> Result<()> {
        self.post_group_rich(gid, &Rich::Pin { id: *id, on }).await
    }

    /// Send structured content to the group.
    pub(crate) async fn post_group_rich(&mut self, gid: &[u8; 32], rich: &Rich) -> Result<()> {
        let now = self.now();
        self.prepare_group_reply(gid, now).await?;
        self.post_group(gid, &rich.encode(), FLAG_RICH, now).await
    }

    /// A poll in `gid`.
    pub fn poll(&self, gid: &[u8; 32], id: &[u8; 16]) -> Option<PollView> {
        self.poll_in(&Place::Group(*gid), id)
    }

    /// A poll in a group or a 1:1 conversation.
    pub fn poll_in(&self, place: &Place, id: &[u8; 16]) -> Option<PollView> {
        let p = self.load_poll(&scope(place), id).ok()??;
        let me = self.account.root_public.0;
        let anonymous = p.vote_key.is_some();
        // An anonymous poll's counts: the creator's own count, or the
        // results posted at the close; nothing before.
        let counts = match (&p.results, anonymous && p.creator != me) {
            (Some(r), true) if r.len() == p.options.len() => r.clone(),
            (_, true) => vec![0; p.options.len()],
            _ => p.counts(),
        };
        let agrees = if anonymous {
            None
        } else {
            p.closed.map(|t| t == tally_hash(id, &counts))
        };
        let voters = if anonymous && p.creator != me {
            p.voters.len() as u32
        } else {
            p.votes.len() as u32
        };
        Some(PollView {
            id: *id,
            question: p.question.clone(),
            options: p.options.iter().cloned().zip(counts).collect(),
            mine: p.votes.get(&me).copied(),
            ours: p.creator == me,
            closed: p.closed.is_some(),
            tally_agrees: agrees,
            anonymous,
            voters,
        })
    }

    /// Structured content from a member.
    pub(crate) fn on_group_rich(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        name: String,
        content: &[u8],
        now: u64,
    ) -> Result<Option<Event>> {
        match Rich::decode(content)? {
            Rich::Poll {
                id,
                question,
                options,
                vote_key,
            } => {
                if self.load_poll(gid, &id)?.is_some() {
                    return Ok(None);
                }
                let poll = Poll {
                    creator: *from,
                    question: question.clone(),
                    options,
                    votes: BTreeMap::new(),
                    closed: None,
                    vote_key,
                    secret: None,
                    voters: Default::default(),
                    results: None,
                };
                self.save_poll(gid, &id, &poll)?;
                let mut m =
                    self.store_group_message(gid, id, Some((*from, name)), &question, now)?;
                m.poll = Some(id);
                self.put_group_message(gid, &m)?;
                self.bump_group_unread(gid, from)?;
                Ok(Some(Event::GroupMessage {
                    group_id: *gid,
                    message: m,
                }))
            }
            Rich::Vote { poll, choice } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                // An anonymous poll takes only sealed votes.
                if p.closed.is_some()
                    || usize::from(choice) >= p.options.len()
                    || (p.vote_key.is_some() && *from != p.creator)
                {
                    return Ok(None);
                }
                p.votes.insert(*from, choice);
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    place: Place::Group(*gid),
                    poll,
                }))
            }
            Rich::SealedVote { poll, sealed } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                if p.closed.is_some() || p.vote_key.is_none() {
                    return Ok(None);
                }
                p.voters.insert(*from);
                // Only its creator can open it (a vote of our own from
                // another device: we know it already, or not at all).
                if let Some(choice) = open_vote(&p, &poll, &sealed)
                    && usize::from(choice) < p.options.len()
                {
                    p.votes.insert(*from, choice);
                }
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    place: Place::Group(*gid),
                    poll,
                }))
            }
            Rich::Results { poll, counts } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                if p.creator != *from || p.vote_key.is_none() || counts.len() != p.options.len() {
                    return Ok(None);
                }
                p.results = Some(counts);
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    place: Place::Group(*gid),
                    poll,
                }))
            }
            Rich::Close { poll, tally } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                if p.creator != *from || p.closed.is_some() {
                    return Ok(None);
                }
                p.closed = Some(tally);
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    place: Place::Group(*gid),
                    poll,
                }))
            }
            Rich::React { id, emoji } => self.on_group_react(gid, from, &id, emoji),
            Rich::Edit { id, text } => self.on_group_edit(gid, from, &id, text, now),
            Rich::Delete { id } => self.on_group_delete(gid, from, &id),
            Rich::Attachment {
                id,
                attachment,
                caption,
                view_once,
            } => {
                self.on_group_attachment(gid, from, name, id, &attachment, &caption, view_once, now)
            }
            Rich::Sticker { id, pack, index } => {
                self.on_group_sticker(gid, from, name, id, &pack, index, now)
            }
            Rich::Pin { id, on } => {
                let place = Place::Group(*gid);
                let known = self.group_messages(gid)?.iter().any(|m| m.id == id);
                Ok((known && self.apply_pin(&place, &id, on)?)
                    .then_some(Event::PinsChanged { place }))
            }
            Rich::HostVote { host } => {
                self.on_host_vote(gid, from, host, now)?;
                Ok(None)
            }
            Rich::Call { message } => Ok(Some(Event::GroupCall {
                group_id: *gid,
                from: *from,
                message,
            })),
            Rich::Text {
                id,
                text,
                reply,
                forwarded,
                mentions,
                link,
            } => {
                if self.group_messages(gid)?.iter().any(|m| m.id == id) {
                    return Ok(None); // a duplicate
                }
                let mut me = [0u8; 16];
                me.copy_from_slice(&self.account.root_public.0[..16]);
                let ours = *from == self.account.root_public.0;
                let mut m = self.store_group_message(gid, id, Some((*from, name)), &text, now)?;
                m.reply_to = reply;
                m.forwarded = forwarded;
                m.mentions_me = !ours && mentions.contains(&me);
                m.link = link.filter(|l| l.fits(&text));
                if ours {
                    m.delivered = true;
                }
                self.put_group_message(gid, &m)?;
                if !ours {
                    self.bump_group_unread(gid, from)?;
                }
                Ok(Some(Event::GroupMessage {
                    group_id: *gid,
                    message: m,
                }))
            }
        }
    }
}
