//! The blinded search index (`docs/14-storage.md` §2.4).
//!
//! Every word of a message (its text, and an attachment's name) is indexed
//! by its prefixes of 3 to 8 characters, lowercased, each as a token
//!
//! ```text
//! search_key = KMAC256(master, "", 256, "enclave/v1/store/search-key")
//! token(t)   = KMAC256(search_key, t, 256, "enclave/v1/store/search-token")[0..16]
//! ```
//!
//! A conversation's index is the store namespace `sx/…` mapping each token
//! to the positions of the messages that have it. Like every record, these
//! are sealed and their keys blinded by the store; the tokens add that not
//! even the store's own index holds a word. A disappearing message's
//! positions are kept apart, under `token ‖ day`, sealed with the shred key
//! of that day like the message itself, so shredding the day takes them
//! too. Editing or deleting a message takes its old words out.
//!
//! A query looks up each of its words of 3 characters or more (cut to 8),
//! intersects the positions, and checks every candidate against the
//! message as it is now, so the result is the same as reading every
//! message: every word of the query must start a word of the message (or
//! occur in it, for the check). Words shorter than 3 characters only
//! narrow what the longer ones found; a query of only short words reads
//! the conversations through.

use super::Client;
use crate::persist::NS_SETTINGS;
use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_store::shred::Shredder;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const L_KEY: &str = "enclave/v1/store/search-key";
const L_TOKEN: &str = "enclave/v1/store/search-token";
/// Shortest and longest indexed prefix (characters).
pub(crate) const MIN_PREFIX: usize = 3;
pub(crate) const MAX_PREFIX: usize = 8;
/// `NS_SETTINGS` key: the index version built (absent: build it).
const KEY_BUILT: &[u8] = b"search-index";
const VERSION: u8 = 1;
/// The record listing the days with sealed positions.
const KEY_DAYS: &[u8] = b"days";

/// A conversation, as the index sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conv {
    /// A contact, or our notes (our own root).
    Contact([u8; 64]),
    /// A group.
    Group([u8; 32]),
}

impl Conv {
    fn ns(&self) -> String {
        let (kind, id): (&str, &[u8]) = match self {
            Conv::Contact(r) => ("c", &r[..16]),
            Conv::Group(g) => ("g", &g[..16]),
        };
        let mut s = format!("sx/{kind}/");
        for b in id {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The shredder's conversation (as messages use it).
    fn shred_conv(&self) -> &[u8] {
        match self {
            Conv::Contact(r) => &r[..32],
            Conv::Group(g) => &g[..],
        }
    }
}

/// The words of `text`, lowercased.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
}

/// The prefixes `text` is found by.
pub(crate) fn terms(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for w in words(text) {
        let chars: Vec<char> = w.chars().collect();
        for n in MIN_PREFIX..=chars.len().min(MAX_PREFIX) {
            out.insert(chars[..n].iter().collect());
        }
    }
    out
}

/// The index lookups for a query: its words of at least [`MIN_PREFIX`]
/// characters, cut to [`MAX_PREFIX`].
pub(crate) fn query_terms(query: &str) -> Vec<String> {
    let mut v: Vec<String> = words(query)
        .filter(|w| w.chars().count() >= MIN_PREFIX)
        .map(|w| w.chars().take(MAX_PREFIX).collect())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn decode_positions(b: &[u8]) -> BTreeSet<u64> {
    b.chunks_exact(8)
        .filter_map(|c| c.try_into().ok().map(u64::from_be_bytes))
        .collect()
}

fn encode_positions(p: &BTreeSet<u64>) -> Vec<u8> {
    p.iter().flat_map(|s| s.to_be_bytes()).collect()
}

impl Client {
    fn search_key(&self) -> Zeroizing<[u8; 32]> {
        self.store.derive_key(L_KEY)
    }

    fn token(key: &[u8; 32], term: &str) -> [u8; 16] {
        let t: [u8; 32] = enclave_crypto::kmac::kmac256(key, term.as_bytes(), L_TOKEN);
        let mut o = [0u8; 16];
        o.copy_from_slice(&t[..16]);
        o
    }

    /// The index is built (absent for profiles from before it, and after a
    /// restore, until `ensure_search_index`).
    pub(crate) fn search_index_built(&self) -> bool {
        matches!(self.store.get(NS_SETTINGS, KEY_BUILT), Ok(Some(v)) if v == [VERSION])
    }

    /// A message's searchable text changed from `old` to `new` (either
    /// may be empty), each with the shred day it is sealed under if it
    /// disappears: take out what it lost, put in what it gained.
    pub(crate) fn index_message(
        &mut self,
        conv: Conv,
        seq: u64,
        old: (&str, Option<u64>),
        new: (&str, Option<u64>),
    ) -> Result<()> {
        let key = self.search_key();
        let keyed = |text: &str, day: Option<u64>| -> BTreeMap<Vec<u8>, Option<u64>> {
            terms(text)
                .iter()
                .map(|t| (Self::record_key(&key, t, day), day))
                .collect()
        };
        let (before, after) = (keyed(old.0, old.1), keyed(new.0, new.1));
        let mut changes: Vec<(Vec<u8>, Option<u64>, bool)> = Vec::new();
        for (k, d) in &before {
            if !after.contains_key(k) {
                changes.push((k.clone(), *d, false));
            }
        }
        for (k, d) in &after {
            if !before.contains_key(k) {
                changes.push((k.clone(), *d, true));
            }
        }
        if changes.is_empty() {
            return Ok(());
        }
        let ns = conv.ns();
        let mut shred = if old.1.is_some() || new.1.is_some() {
            Some(Shredder::open(&self.store, &mut self.rng)?)
        } else {
            None
        };
        let mut writes: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for (k, day, add) in changes {
            let mut p = match (self.store.get(&ns, &k)?, day, shred.as_ref()) {
                (None, _, _) => BTreeSet::new(),
                (Some(b), Some(d), Some(s)) => s
                    .open_msg(conv.shred_conv(), d, &b)
                    .map(|pt| decode_positions(&pt))
                    .unwrap_or_default(),
                (Some(b), _, _) => decode_positions(&b),
            };
            if add {
                p.insert(seq);
            } else {
                p.remove(&seq);
            }
            let value = if p.is_empty() {
                None
            } else {
                let plain = encode_positions(&p);
                Some(match (day, shred.as_mut()) {
                    (Some(d), Some(s)) => s.seal(conv.shred_conv(), d, &plain, &mut self.rng)?,
                    _ => plain,
                })
            };
            writes.push((k, value));
        }
        if let Some(d) = new.1 {
            let mut days = self.index_days(conv)?;
            if days.insert(d) {
                writes.push((KEY_DAYS.to_vec(), Some(encode_positions(&days))));
            }
        }
        self.store.write_batch(&ns, &writes, &mut self.rng)?;
        Ok(())
    }

    fn record_key(key: &[u8; 32], term: &str, day: Option<u64>) -> Vec<u8> {
        let t = Self::token(key, term);
        match day {
            Some(d) => [&t[..], &d.to_be_bytes()].concat(),
            None => t.to_vec(),
        }
    }

    fn index_days(&self, conv: Conv) -> Result<BTreeSet<u64>> {
        Ok(self
            .store
            .get(&conv.ns(), KEY_DAYS)?
            .map(|b| decode_positions(&b))
            .unwrap_or_default())
    }

    /// Positions in `conv` that have every term (`None`: the query has no
    /// word long enough to look up).
    pub(crate) fn candidates(&self, conv: Conv, query: &[String]) -> Result<Option<BTreeSet<u64>>> {
        if query.is_empty() {
            return Ok(None);
        }
        let key = self.search_key();
        let ns = conv.ns();
        let days = self.index_days(conv)?;
        let mut rng = HedgedRng::new()?;
        let shred = if days.is_empty() {
            None
        } else {
            Some(Shredder::open(&self.store, &mut rng)?)
        };
        let mut result: Option<BTreeSet<u64>> = None;
        for t in query {
            let mut found = self
                .store
                .get(&ns, &Self::record_key(&key, t, None))?
                .map(|b| decode_positions(&b))
                .unwrap_or_default();
            if let Some(s) = shred.as_ref() {
                for d in &days {
                    if let Some(b) = self.store.get(&ns, &Self::record_key(&key, t, Some(*d)))?
                        && let Ok(pt) = s.open_msg(conv.shred_conv(), *d, &b)
                    {
                        found.extend(decode_positions(&pt));
                    }
                }
            }
            result = Some(match result {
                None => found,
                Some(r) => r.intersection(&found).copied().collect(),
            });
            if result.as_ref().is_some_and(BTreeSet::is_empty) {
                break;
            }
        }
        Ok(result)
    }

    /// Sealed positions of days before `today` go (their shred keys are
    /// gone, or about to be).
    pub(crate) fn drop_index_days(&mut self, conv: Conv, today: u64) -> Result<()> {
        let days = self.index_days(conv)?;
        let old: Vec<u64> = days.iter().copied().filter(|d| *d < today).collect();
        if old.is_empty() {
            return Ok(());
        }
        let ns = conv.ns();
        let mut writes = Vec::new();
        for (k, _) in self.store.scan(&ns)? {
            if k.len() == 24 {
                let d = u64::from_be_bytes(k[16..].try_into().map_err(|_| CoreError::NotFound)?);
                if d < today {
                    writes.push((k, None));
                }
            }
        }
        let keep: BTreeSet<u64> = days.into_iter().filter(|d| *d >= today).collect();
        writes.push((
            KEY_DAYS.to_vec(),
            (!keep.is_empty()).then(|| encode_positions(&keep)),
        ));
        self.store.write_batch(&ns, &writes, &mut self.rng)?;
        Ok(())
    }

    /// Forget a conversation's index (it was removed).
    pub(crate) fn drop_index(&mut self, conv: Conv) -> Result<()> {
        let ns = conv.ns();
        let writes: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .store
            .scan(&ns)?
            .into_iter()
            .map(|(k, _)| (k, None))
            .collect();
        self.store.write_batch(&ns, &writes, &mut self.rng)?;
        Ok(())
    }

    /// Build the index if this profile doesn't have it yet (from before
    /// it, or restored): every conversation, every message.
    pub(crate) fn ensure_search_index(&mut self) -> Result<()> {
        if self.search_index_built() {
            return Ok(());
        }
        let mut convs: Vec<Conv> = self.contacts.keys().map(|r| Conv::Contact(*r)).collect();
        convs.push(Conv::Contact(self.account.root_public.0));
        convs.extend(self.groups.keys().map(|g| Conv::Group(*g)));
        for conv in convs {
            self.drop_index(conv)?;
            let items: Vec<(u64, String, Option<u64>)> = match conv {
                Conv::Contact(r) => self
                    .messages(&r)?
                    .into_iter()
                    .filter(|m| !m.deleted)
                    .map(|m| (m.seq, m.search_text(), m.sealed_day()))
                    .collect(),
                Conv::Group(g) => self
                    .group_messages(&g)?
                    .into_iter()
                    .filter(|m| !m.deleted)
                    .map(|m| (m.seq, m.search_text(), None))
                    .collect(),
            };
            for (seq, text, day) in items {
                self.index_message(conv, seq, ("", None), (&text, day))?;
            }
        }
        self.store
            .put(NS_SETTINGS, KEY_BUILT, &[VERSION], &mut self.rng)?;
        Ok(())
    }

    /// Mark the index built (a new profile: nothing to index).
    pub(crate) fn search_index_new(&mut self) -> Result<()> {
        self.store
            .put(NS_SETTINGS, KEY_BUILT, &[VERSION], &mut self.rng)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let t = terms("Meet at the Café, 7pm! — Grüße");
        for want in ["mee", "meet", "caf", "café", "7pm", "grü", "grüße", "the"] {
            assert!(t.contains(want), "{want} in {t:?}");
        }
        assert!(!t.contains("at"), "too short to index");
        let long = terms("internationalisation");
        assert!(long.contains("internat") && !long.contains("internati"));
        assert_eq!(
            query_terms("INTERNATIONAL at Gr"),
            vec!["internat".to_string()]
        );
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use crate::{Options, Place};
    use enclave_crypto::pwhash::PwParams;
    use enclave_sim::LocalTransport;
    use enclave_store::MemoryKeystore;
    use std::sync::Arc;

    async fn pair() -> (LocalTransport, Client, Client) {
        let net = LocalTransport::new();
        net.add_server(enclave_server::Config {
            id: [1; 16],
            effort_inbox: 1,
            effort_request: 1,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            ..Default::default()
        })
        .unwrap();
        let opts = || Options {
            path: None,
            keystore: Arc::new(MemoryKeystore::default()),
            passphrase: None,
            pw_params: PwParams::FLOOR,
        };
        let (mut a, _) = Client::create(opts(), Arc::new(net.clone()), [1; 16], "Ada")
            .await
            .unwrap();
        let (mut b, _) = Client::create(opts(), Arc::new(net.clone()), [1; 16], "Ben")
            .await
            .unwrap();
        a.add_contact(&b.card(), "hi").await.unwrap();
        b.sync().await.unwrap();
        b.accept(&a.root()).await.unwrap();
        a.sync().await.unwrap();
        (net, a, b)
    }

    fn found(c: &Client, q: &str) -> Vec<u64> {
        c.search(q, 50).unwrap().iter().map(|h| h.seq).collect()
    }

    /// The index follows edits and deletions, holds notes, can be rebuilt,
    /// and a disappearing message's words go with its shred day.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_index_follows_the_messages() {
        let (net, mut a, mut b) = pair().await;
        let rb = b.root();
        assert!(a.search_index_built());
        let m = a
            .send_text(&rb, "Lunch tomorrow at the harbour")
            .await
            .unwrap();
        assert_eq!(found(&a, "harb"), [m.seq], "a prefix finds it");
        assert_eq!(found(&a, "lunch TOMORROW"), [m.seq]);
        assert!(found(&a, "arbour").is_empty(), "inside a word isn't a word");
        a.edit_message(&rb, m.seq, "Dinner tomorrow").await.unwrap();
        assert!(found(&a, "lunch").is_empty(), "the old words are gone");
        assert_eq!(found(&a, "dinner"), [m.seq]);
        a.delete_for_everyone(&rb, m.seq).await.unwrap();
        assert!(found(&a, "dinner").is_empty());
        let key = a.search_key();
        let ns = Conv::Contact(rb).ns();
        assert!(
            a.store
                .get(&ns, &Client::record_key(&key, "dinner", None))
                .unwrap()
                .is_none(),
            "no positions left for a deleted message"
        );

        // Notes are searched too.
        let n = a.send_note("buy oat milk").await.unwrap();
        let hits = a.search("milk", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            (hits[0].place, hits[0].seq),
            (Place::Contact(a.root()), n.seq)
        );

        // A profile without the index (from before it) builds it.
        a.store.delete(NS_SETTINGS, KEY_BUILT).unwrap();
        a.drop_index(Conv::Contact(a.root())).unwrap();
        assert_eq!(found(&a, "milk"), [n.seq], "read through meanwhile");
        a.ensure_search_index().unwrap();
        assert!(a.search_index_built());
        assert_eq!(found(&a, "milk"), [n.seq]);

        // Disappearing: its words are sealed under its shred day, and gone
        // with it.
        a.set_timer(&rb, 3600).await.unwrap();
        let d = a.send_text(&rb, "Secret rendezvous").await.unwrap();
        assert_eq!(found(&a, "rendez"), [d.seq]);
        assert!(
            a.store
                .get(&ns, &Client::record_key(&key, "rendez", None))
                .unwrap()
                .is_none(),
            "not kept in the open index"
        );
        net.advance(2 * 86_400);
        a.purge_expired(a.now()).unwrap();
        assert!(found(&a, "rendez").is_empty());
        assert!(
            a.store
                .scan(&ns)
                .unwrap()
                .iter()
                .all(|(k, _)| k.len() != 24),
            "no sealed positions left"
        );
        let _ = b.sync().await;
    }
}
