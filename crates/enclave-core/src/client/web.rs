//! Link previews and GIF search (`docs/15-client.md` §5): both off until
//! the person turns them on, both synced to their other devices. When on,
//! only the sender's device reaches the web, through Tor (the vault fetches
//! and mediad reads what comes back); a receiver never fetches anything for
//! a preview, and a GIF goes out as an ordinary AV1 clip.

use super::Client;
use crate::Result;

/// The setting for link previews (synced).
pub(crate) const LINK_PREVIEWS: &str = "link-previews";
/// The setting for GIF search (synced).
pub(crate) const GIF_SEARCH: &str = "gif-search";
/// Where GIF search looks: Wikimedia Commons' API (no account, no key,
/// no tracking of who asks; reached through Tor).
pub const GIF_SEARCH_API: &str = "https://commons.wikimedia.org/w/api.php";
/// Longest search, in characters.
pub const MAX_GIF_QUERY: usize = 100;
/// Width of the GIF copies a search asks Commons for.
pub const GIF_WIDTH: u32 = 320;

impl Client {
    /// Link previews are on.
    pub fn link_previews_enabled(&self) -> bool {
        matches!(self.setting(LINK_PREVIEWS), Ok(Some(v)) if v == [1])
    }

    /// Turn link previews on or off.
    pub fn set_link_previews_enabled(&mut self, on: bool) -> Result<()> {
        self.set_setting(LINK_PREVIEWS, &[u8::from(on)])
    }

    /// GIF search is on.
    pub fn gif_search_enabled(&self) -> bool {
        matches!(self.setting(GIF_SEARCH), Ok(Some(v)) if v == [1])
    }

    /// Turn GIF search on or off.
    pub fn set_gif_search_enabled(&mut self, on: bool) -> Result<()> {
        self.set_setting(GIF_SEARCH, &[u8::from(on)])
    }
}

/// The first `https://` link in `text`, as it is written there (up to
/// whitespace, without trailing punctuation or an unmatched closing
/// bracket). Plain `http://` links get no preview: the fetch is https only.
pub fn first_link(text: &str) -> Option<&str> {
    let start = text.find("https://")?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '`'))
        .unwrap_or(rest.len());
    let mut link = &rest[..end];
    loop {
        let trimmed = link.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*', '_']);
        let trimmed = match trimmed.chars().last() {
            Some(c @ (')' | ']' | '}')) => {
                let open = match c {
                    ')' => '(',
                    ']' => '[',
                    _ => '{',
                };
                if trimmed.matches(open).count() < trimmed.matches(c).count() {
                    &trimmed[..trimmed.len() - 1]
                } else {
                    trimmed
                }
            }
            _ => trimmed,
        };
        if trimmed == link {
            break;
        }
        link = trimmed;
    }
    (link.len() > "https://".len() + 2
        && link.len() <= crate::content::MAX_LINK_URL
        && link["https://".len()..].contains('.'))
    .then_some(link)
}

/// The Commons search for animated GIFs matching `query`, with a copy of
/// each [`GIF_WIDTH`] pixels wide.
pub fn gif_search_url(query: &str) -> String {
    let q: String = query.trim().chars().take(MAX_GIF_QUERY).collect();
    format!(
        "{GIF_SEARCH_API}?action=query&format=json&formatversion=2&generator=search\
         &gsrnamespace=6&gsrlimit=24&gsrsearch={}&prop=imageinfo&iiprop=url%7Csize%7Cmime\
         &iiurlwidth={GIF_WIDTH}",
        percent(&format!("filemime:image/gif {q}"))
    )
}

/// Percent-encoding for a query value: everything but unreserved characters.
fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_in_text() {
        assert_eq!(
            first_link("see https://example.org/a?b=1."),
            Some("https://example.org/a?b=1")
        );
        assert_eq!(
            first_link("(https://en.wikipedia.org/wiki/Rust_(programming_language))"),
            Some("https://en.wikipedia.org/wiki/Rust_(programming_language)")
        );
        assert_eq!(
            first_link("[link](https://example.org/x)"),
            Some("https://example.org/x")
        );
        assert_eq!(first_link("plain http://example.org"), None);
        assert_eq!(first_link("https:// nothing"), None);
        assert_eq!(first_link("https://localhost"), None);
        assert_eq!(
            first_link("two: https://a.example/1 https://b.example/2"),
            Some("https://a.example/1")
        );
    }

    #[test]
    fn the_search_address() {
        let u = gif_search_url("  happy cat & dog ");
        assert!(u.starts_with(GIF_SEARCH_API));
        assert!(u.contains("gsrsearch=filemime%3Aimage%2Fgif%20happy%20cat%20%26%20dog&"));
        assert!(u.contains("iiurlwidth=320"));
        let long = gif_search_url(&"x".repeat(500));
        assert!(long.matches('x').count() <= MAX_GIF_QUERY + 2);
    }
}
