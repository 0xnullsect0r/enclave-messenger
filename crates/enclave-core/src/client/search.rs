//! Local message search (`docs/16-features.md`). Everything happens on the
//! device over the sealed store; nothing about a search leaves it.

use super::Client;
use super::search_index::{self, Conv};
use crate::Result;

/// Where a hit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// A 1:1 conversation.
    Contact([u8; 64]),
    /// A group.
    Group([u8; 32]),
}

/// A message that matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Conversation.
    pub place: Place,
    /// Conversation name.
    pub name: String,
    /// Position in the conversation.
    pub seq: u64,
    /// Text around the first match.
    pub snippet: String,
    /// When it was sent or received.
    pub at: u64,
    /// Ours.
    pub outgoing: bool,
}

/// Characters of context on each side of the match.
const CONTEXT: usize = 40;

/// Whether every term of the query occurs in `text` (case-insensitive), and
/// if so a snippet around the first term.
fn matches(text: &str, terms: &[String]) -> Option<String> {
    let lower = text.to_lowercase();
    if !terms.iter().all(|t| lower.contains(t.as_str())) {
        return None;
    }
    // Lowercasing can change byte offsets, so find the match by characters.
    let chars: Vec<char> = text.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();
    let first: Vec<char> = terms[0].chars().collect();
    let at = if lower_chars.len() == chars.len() {
        lower_chars
            .windows(first.len())
            .position(|w| w == first.as_slice())
            .unwrap_or(0)
    } else {
        0
    };
    let start = at.saturating_sub(CONTEXT);
    let end = (at + first.len() + CONTEXT).min(chars.len());
    let mut s: String = chars[start..end].iter().collect();
    s = s.replace('\n', " ");
    if start > 0 {
        s.insert(0, '…');
    }
    if end < chars.len() {
        s.push('…');
    }
    Some(s)
}

impl Client {
    /// Messages (and notes) containing every word of `query`, newest
    /// first, at most `limit`. Queries shorter than two characters find
    /// nothing. With the index (`search_index.rs`) only the candidates it
    /// gives are read; every hit is checked against the message as it is.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        let terms: Vec<String> = query
            .to_lowercase()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if terms.is_empty() || query.trim().chars().count() < 2 {
            return Ok(Vec::new());
        }
        let lookup = if self.search_index_built() {
            search_index::query_terms(query)
        } else {
            Vec::new()
        };
        let own = self.account.root_public.0;
        let mut convs: Vec<([u8; 64], String)> = self
            .contacts()
            .into_iter()
            .map(|c| (c.root, c.name))
            .collect();
        convs.push((own, "Note to self".into()));
        let mut hits = Vec::new();
        for (root, name) in convs {
            let wanted = self.candidates(Conv::Contact(root), &lookup)?;
            if wanted.as_ref().is_some_and(|w| w.is_empty()) {
                continue;
            }
            let found = match &wanted {
                Some(w) => w
                    .iter()
                    .filter_map(|seq| self.message_at(&root, *seq).transpose())
                    .collect::<Result<Vec<_>>>()?,
                None => self.messages(&root)?,
            };
            for m in found {
                if m.deleted {
                    continue;
                }
                if let Some(snippet) = matches(&m.search_text(), &terms) {
                    hits.push(Hit {
                        place: Place::Contact(root),
                        name: name.clone(),
                        seq: m.seq,
                        snippet,
                        at: m.at,
                        outgoing: m.outgoing,
                    });
                }
            }
        }
        for g in self.groups() {
            let wanted = self.candidates(Conv::Group(g.id), &lookup)?;
            if wanted.as_ref().is_some_and(|w| w.is_empty()) {
                continue;
            }
            let found = match &wanted {
                Some(w) => w
                    .iter()
                    .filter_map(|seq| self.find_group_message(&g.id, *seq).transpose())
                    .collect::<Result<Vec<_>>>()?,
                None => self.group_messages(&g.id)?,
            };
            for m in found {
                if m.deleted {
                    continue;
                }
                if let Some(snippet) = matches(&m.search_text(), &terms) {
                    hits.push(Hit {
                        place: Place::Group(g.id),
                        name: g.name.clone(),
                        seq: m.seq,
                        snippet,
                        at: m.at,
                        outgoing: m.from.is_none(),
                    });
                }
            }
        }
        hits.sort_by(|a, b| b.at.cmp(&a.at).then(b.seq.cmp(&a.seq)));
        hits.truncate(limit);
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn terms_and_snippets() {
        let t = |q: &str| -> Vec<String> { q.split_whitespace().map(str::to_string).collect() };
        assert_eq!(
            matches("See you at the Café", &t("café")).as_deref(),
            Some("See you at the Café")
        );
        assert!(matches("See you at the café", &t("café tomorrow")).is_none());
        let long = format!("{}needle{}", "a".repeat(100), "b".repeat(100));
        let s = matches(&long, &t("needle")).unwrap();
        assert!(s.starts_with('…') && s.ends_with('…') && s.contains("needle"));
        assert!(s.chars().count() <= 2 * 40 + 6 + 2);
    }
}
