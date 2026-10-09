//! Meeting in person (`03-identity.md` §7, decision D12).
//!
//! Two people show each other a code (`enclave:meet#…`) holding their contact
//! card and 32 fresh random bytes, and each scans the other's. Both phones
//! then derive the same pre-shared key from both secrets and both codes
//! (`eqxdh::bond_psk`) and show three **Seal words** from it; the people
//! compare them. On "They match", each side stores the bond and marks the
//! contact checked in person, and the side with the lower root key starts
//! fresh sessions with the PSK mixed into the key agreement, replacing any
//! old ones. So the conversation now also rests on a secret that crossed the
//! room optically: even if every KEM were broken, someone who didn't see both
//! screens can't recover it. Strangers who meet become contacts directly.
//!
//! The codes never reach a server, and the secrets live only in memory until
//! the words are confirmed.

use super::{Client, ContactState};
use crate::card::{ContactCard, LinkError, b64url_decode, b64url_encode};
use crate::persist::NS_SESSIONS;
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::eqxdh;
use zeroize::Zeroizing;

/// Prefix of an in-person code.
pub const MEET_PREFIX: &str = "enclave:meet#";
/// Bonds: root → PSK.
pub(crate) const NS_BONDS: &str = "bonds";

/// What the person compares after scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeetMatch {
    /// Who they scanned.
    pub root: [u8; 64],
    /// Their name.
    pub name: String,
    /// The three Seal words both phones should show.
    pub words: [String; 3],
}

impl Client {
    /// Our in-person code, with a fresh secret. Show it as a QR code; it is
    /// good until the next call or until a meeting is confirmed.
    pub fn meet_code(&mut self) -> Result<String> {
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(self.rng.array("core/meet")?);
        let mut w = Writer::new();
        w.u8(1).bytes(&self.card().encode()).fixed(&secret[..]);
        let payload = w.finish();
        let code = format!("{MEET_PREFIX}{}", b64url_encode(&payload));
        self.meet = Some((secret, payload));
        Ok(code)
    }

    /// We scanned their in-person code (ours must be on screen). Returns the
    /// Seal words to compare.
    pub fn meet_scan(&mut self, code: &str) -> Result<MeetMatch> {
        let body = code
            .trim()
            .strip_prefix(MEET_PREFIX)
            .ok_or(LinkError::NotEnclave)?;
        let payload = b64url_decode(body).ok_or(LinkError::Malformed)?;
        let (card, theirs) = parse(&payload).ok_or(LinkError::Malformed)?;
        if card.root == self.account.root_public.0 {
            return Err(LinkError::OwnCode.into());
        }
        let (ours, mine) = self.meet.as_ref().ok_or(CoreError::NotFound)?;
        let psk = eqxdh::bond_psk(ours, &theirs, mine, &payload);
        let words = eqxdh::seal_words(&psk)?;
        let m = MeetMatch {
            root: card.root,
            name: card.name.clone(),
            words,
        };
        self.pending_bond = Some((card, psk));
        Ok(m)
    }

    /// The Seal words matched: keep the bond, mark them checked in person,
    /// and (on one side) start sessions that use it.
    pub async fn meet_confirm(&mut self) -> Result<[u8; 64]> {
        let (card, psk) = self.pending_bond.take().ok_or(CoreError::NotFound)?;
        self.meet = None;
        let root = card.root;
        let now = self.now();
        self.store.put(NS_BONDS, &root, &psk[..], &mut self.rng)?;
        if let Some(c) = self.contacts.get_mut(&root) {
            c.verified = true;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        // Both sides confirm; the lower root starts, so they don't race.
        if self.account.root_public.0 >= root {
            return Ok(root);
        }
        let known = self
            .contacts
            .get(&root)
            .is_some_and(|c| c.state != ContactState::Pending || c.inbox.is_some());
        if !known {
            if self.contacts.contains_key(&root) {
                self.remove_contact(&root)?;
            }
            self.add_contact_with(&card, "", None, Some(&psk)).await?;
            return Ok(root);
        }
        // Meeting settles a request they sent us.
        if let Some(c) = self.contacts.get_mut(&root)
            && c.state == ContactState::Request
        {
            c.state = ContactState::Accepted;
            let c = c.clone();
            self.save_contact(&c)?;
            self.sync_contact_to_own(&root, true)?;
        }
        // Replace our sessions with them by bonded ones.
        let (manifest, vault) = self.fetch_peer(&card, now).await?;
        let old: Vec<[u8; 16]> = self
            .sessions
            .keys()
            .filter(|(r, _)| *r == root)
            .map(|(_, d)| *d)
            .collect();
        for d in old {
            self.sessions.remove(&(root, d));
            self.store
                .delete(NS_SESSIONS, &super::session_key(&root, &d))?;
        }
        let hello = self.hello_for(&root, now).await?;
        self.initiate_to(&card, &manifest, &vault, &hello, None, now, Some(&psk))
            .await?;
        Ok(root)
    }

    /// Stop an in-person meeting without keeping anything.
    pub fn meet_cancel(&mut self) {
        self.meet = None;
        self.pending_bond = None;
    }

    /// Whether we met `root` in person and confirmed the Seal words.
    pub fn met_in_person(&self, root: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_BONDS, root), Ok(Some(_)))
    }

    /// Every bond PSK.
    pub(crate) fn bonds(&self) -> Result<Vec<Zeroizing<[u8; 32]>>> {
        Ok(self
            .store
            .scan(NS_BONDS)?
            .into_iter()
            .filter_map(|(_, v)| <[u8; 32]>::try_from(v.as_slice()).ok())
            .map(Zeroizing::new)
            .collect())
    }
}

fn parse(payload: &[u8]) -> Option<(ContactCard, [u8; 32])> {
    let mut r = Reader::new(payload);
    if r.u8().ok()? != 1 {
        return None;
    }
    let card = ContactCard::decode(r.bytes(crate::content::MAX_CARD).ok()?).ok()?;
    let secret: [u8; 32] = r.array().ok()?;
    r.end().ok()?;
    Some((card, secret))
}
