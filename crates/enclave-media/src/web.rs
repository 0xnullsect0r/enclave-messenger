//! What the sender reads from the web, in `mediad` (`docs/15-client.md`
//! §5, "Link previews, GIF search"): a page's title, description and
//! picture for a link preview, and a GIF search's results. Both come from
//! sites the person chose to reach, through Tor, and are parsed here rather
//! than in the vault: a bug in a parser of web pages can't reach keys.
//!
//! Nothing is rendered or run: a page is only scanned for its `<title>` and
//! its `og:`/`twitter:` `<meta>` tags, and a search answer (the Wikimedia
//! Commons API, JSON) only read for its files' addresses and sizes.

use crate::{MediaError, Result, Rgba};

/// Most of a page that is read (the tags are in its head).
pub const MAX_PAGE: usize = 512 * 1024;
/// Longest title kept, in characters.
pub const MAX_TITLE_CHARS: usize = 120;
/// Longest description kept, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 240;
/// Longest address kept.
pub const MAX_URL: usize = 2048;
/// Most search results.
pub const MAX_HITS: usize = 12;

/// A page's preview.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageMeta {
    /// Its title (`og:title`, `twitter:title` or `<title>`).
    pub title: String,
    /// Its description (`og:description`, `twitter:description` or
    /// `description`); may be empty.
    pub description: String,
    /// Its picture's address (`og:image` or `twitter:image`), `https`
    /// only; empty for none.
    pub image: String,
}

impl PageMeta {
    /// `title ‖ description ‖ image`, each `u16 length ‖ UTF-8`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in [&self.title, &self.description, &self.image] {
            put(&mut out, s);
        }
        out
    }

    /// The reverse of [`PageMeta::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = b;
        let p = PageMeta {
            title: take(&mut r)?,
            description: take(&mut r)?,
            image: take(&mut r)?,
        };
        r.is_empty().then_some(p)
    }
}

/// One GIF a search found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GifHit {
    /// Its name, without the `File:` and the extension.
    pub title: String,
    /// The address of a small copy of it (`https`).
    pub url: String,
    /// The small copy's size in pixels.
    pub width: u32,
    /// Likewise.
    pub height: u32,
}

/// A list of [`GifHit`]s: `u8 n ‖ n × (title ‖ url ‖ u32 width ‖ u32
/// height)`, strings as in [`PageMeta::encode`].
pub fn encode_hits(hits: &[GifHit]) -> Vec<u8> {
    let mut out = vec![hits.len().min(MAX_HITS) as u8];
    for h in hits.iter().take(MAX_HITS) {
        put(&mut out, &h.title);
        put(&mut out, &h.url);
        out.extend_from_slice(&h.width.to_be_bytes());
        out.extend_from_slice(&h.height.to_be_bytes());
    }
    out
}

/// The reverse of [`encode_hits`].
pub fn decode_hits(b: &[u8]) -> Option<Vec<GifHit>> {
    let (&n, mut r) = b.split_first()?;
    if usize::from(n) > MAX_HITS {
        return None;
    }
    let mut hits = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        let title = take(&mut r)?;
        let url = take(&mut r)?;
        let width = u32::from_be_bytes(r.get(..4)?.try_into().ok()?);
        let height = u32::from_be_bytes(r.get(4..8)?.try_into().ok()?);
        r = &r[8..];
        hits.push(GifHit {
            title,
            url,
            width,
            height,
        });
    }
    r.is_empty().then_some(hits)
}

fn put(out: &mut Vec<u8>, s: &str) {
    let b = &s.as_bytes()[..s.len().min(u16::MAX as usize)];
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn take(r: &mut &[u8]) -> Option<String> {
    let n = usize::from(u16::from_be_bytes(r.get(..2)?.try_into().ok()?));
    let s = std::str::from_utf8(r.get(2..2 + n)?).ok()?.to_string();
    *r = &r[2 + n..];
    Some(s)
}

/// Read a page's preview. `url` is the page's own address (the one asked
/// for), to resolve a relative picture address against.
pub fn page_meta(url: &str, html: &[u8]) -> Result<PageMeta> {
    let html = &html[..html.len().min(MAX_PAGE)];
    let text = String::from_utf8_lossy(html);
    let mut meta: Vec<(String, String)> = Vec::new();
    let mut title_tag = String::new();
    let lower = text.to_ascii_lowercase();
    let mut at = 0;
    while let Some(i) = lower[at..].find('<') {
        let start = at + i;
        let rest = &lower[start..];
        if rest.starts_with("<!--") {
            at = match lower[start..].find("-->") {
                Some(e) => start + e + 3,
                None => break,
            };
            continue;
        }
        // Scripts and styles hold no tags we want, and may hold text that
        // looks like one.
        let skip = ["<script", "<style"]
            .iter()
            .find(|t| rest.starts_with(**t))
            .map(|t| format!("</{}", &t[1..]));
        let Some(end) = tag_end(&lower, start) else {
            break;
        };
        if let Some(close) = skip {
            at = match lower[end..].find(&close) {
                Some(e) => end + e + close.len(),
                None => break,
            };
            continue;
        }
        let tag = &text[start + 1..end - 1];
        let name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        match name.as_str() {
            "meta" => {
                let attrs = attributes(&tag[4..]);
                let key = attrs
                    .iter()
                    .find(|(k, _)| k == "property" || k == "name")
                    .map(|(_, v)| v.to_ascii_lowercase());
                let content = attrs.iter().find(|(k, _)| k == "content").map(|(_, v)| v);
                if let (Some(k), Some(c)) = (key, content) {
                    meta.push((k, c.clone()));
                }
            }
            "title" if title_tag.is_empty() => {
                if let Some(e) = lower[end..].find("</title") {
                    title_tag = text[end..end + e].to_string();
                }
            }
            "body" => break,
            _ => {}
        }
        at = end;
    }
    let pick = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| meta.iter().find(|(m, _)| m == k).map(|(_, v)| v.clone()))
    };
    let title = pick(&["og:title", "twitter:title"]).unwrap_or(title_tag);
    let description =
        pick(&["og:description", "twitter:description", "description"]).unwrap_or_default();
    let image = pick(&[
        "og:image",
        "og:image:url",
        "og:image:secure_url",
        "twitter:image",
    ])
    .map(|i| resolve(url, &unescape(&i)))
    .unwrap_or_default();
    let title = clean(&title, MAX_TITLE_CHARS);
    if title.is_empty() {
        return Err(MediaError::Unsupported);
    }
    Ok(PageMeta {
        title,
        description: clean(&description, MAX_DESCRIPTION_CHARS),
        image: if image.len() <= MAX_URL && image.starts_with("https://") {
            image
        } else {
            String::new()
        },
    })
}

/// Where the tag starting at `start` ends (just past its `>`), with quoted
/// attribute values skipped.
fn tag_end(s: &str, start: usize) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in s[start..].char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(start + i + 1),
            _ => {}
        }
    }
    None
}

/// A tag's attributes, names lower-cased, values unquoted.
fn attributes(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_whitespace() || b[i] == '/') {
            i += 1;
        }
        let n0 = i;
        while i < b.len() && !b[i].is_whitespace() && b[i] != '=' && b[i] != '/' {
            i += 1;
        }
        let name: String = b[n0..i].iter().collect::<String>().to_ascii_lowercase();
        while i < b.len() && b[i].is_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == '=' {
            i += 1;
            while i < b.len() && b[i].is_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == '"' || b[i] == '\'') {
                let q = b[i];
                i += 1;
                let v0 = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                value = b[v0..i].iter().collect();
                i += 1;
            } else {
                let v0 = i;
                while i < b.len() && !b[i].is_whitespace() {
                    i += 1;
                }
                value = b[v0..i].iter().collect();
            }
        }
        if !name.is_empty() {
            out.push((name, value));
        } else if i == n0 {
            i += 1;
        }
    }
    out
}

/// HTML character references: the named few pages use in titles, and
/// numeric ones.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest[..rest.len().min(12)].find(';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let name = &rest[1..end];
        let c = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            n if n.starts_with("#x") || n.starts_with("#X") => u32::from_str_radix(&n[2..], 16)
                .ok()
                .and_then(char::from_u32),
            n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Unescaped, without control or bidi-override characters, whitespace
/// collapsed, cut at `max` characters.
fn clean(s: &str, max: usize) -> String {
    let s = unescape(s);
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control()
            || ('\u{202A}'..='\u{202E}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
        {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    if out.chars().count() > max {
        out = out
            .chars()
            .take(max - 1)
            .collect::<String>()
            .trim_end()
            .to_string();
        out.push('…');
    }
    out
}

/// `link` as an absolute address, given the page's own.
fn resolve(base: &str, link: &str) -> String {
    let link = link.trim();
    if link.starts_with("https://") || link.starts_with("http://") {
        return link.to_string();
    }
    let Some(rest) = base.strip_prefix("https://") else {
        return String::new();
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = &base[..8 + host_end];
    if let Some(l) = link.strip_prefix("//") {
        return format!("https://{l}");
    }
    if link.starts_with('/') {
        return format!("{origin}{link}");
    }
    let path = &rest[host_end..];
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
    let dir = if dir.is_empty() { "/" } else { dir };
    format!("{origin}{dir}{link}")
}

/// The files a Wikimedia Commons search answered with
/// (`action=query&generator=search&prop=imageinfo&iiurlwidth=…`,
/// `formatversion=2`), in the order it ranked them: GIFs only, each with
/// its small copy's address.
pub fn commons_gifs(json: &[u8]) -> Result<Vec<GifHit>> {
    let v: serde_json::Value = serde_json::from_slice(json).map_err(|_| MediaError::Damaged)?;
    let Some(pages) = v.pointer("/query/pages").and_then(|p| p.as_array()) else {
        // No results: Commons leaves `query` out.
        return Ok(Vec::new());
    };
    let mut ranked: Vec<(u64, GifHit)> = Vec::new();
    for p in pages {
        let Some(info) = p.pointer("/imageinfo/0") else {
            continue;
        };
        if info.get("mime").and_then(|m| m.as_str()) != Some("image/gif") {
            continue;
        }
        let url = info
            .get("thumburl")
            .or_else(|| info.get("url"))
            .and_then(|u| u.as_str())
            .unwrap_or_default();
        if !url.starts_with("https://") || url.len() > MAX_URL {
            continue;
        }
        let dim = |k: &str, full: &str| {
            info.get(k)
                .or_else(|| info.get(full))
                .and_then(|n| n.as_u64())
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0)
        };
        let title = p.get("title").and_then(|t| t.as_str()).unwrap_or_default();
        let title = title.strip_prefix("File:").unwrap_or(title);
        let title = title.rsplit_once('.').map_or(title, |(t, _)| t);
        ranked.push((
            p.get("index").and_then(|i| i.as_u64()).unwrap_or(u64::MAX),
            GifHit {
                title: clean(&title.replace('_', " "), MAX_TITLE_CHARS),
                url: url.to_string(),
                width: dim("thumbwidth", "width"),
                height: dim("thumbheight", "height"),
            },
        ));
    }
    ranked.sort_by_key(|(i, _)| *i);
    Ok(ranked.into_iter().map(|(_, h)| h).take(MAX_HITS).collect())
}

/// A GIF's first frame, shrunk to at most `max_side` pixels (search
/// results; the GIF that is sent becomes an AV1 clip as ever).
pub fn gif_poster(bytes: &[u8], max_side: u32) -> Result<Rgba> {
    crate::video::gif_first_frame(bytes).map(|f| crate::resize::fit(&f, max_side.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_open_graph_tags_first() {
        let html = br#"<!doctype html><html><head>
            <title>Fallback &amp; title</title>
            <!-- <meta property="og:title" content="commented out"> -->
            <script>var x = '<meta property="og:title" content="in a script">';</script>
            <meta name="description" content="Plain description">
            <meta property="og:title" content="The &quot;real&quot; title" />
            <meta content='Swapped &#8212; order' property=og:description>
            <meta property="og:image" content="/img/card.jpg?x=1">
            </head><body><meta property="og:title" content="in the body"></body></html>"#;
        let m = page_meta("https://example.org/news/item?id=3", html).unwrap();
        assert_eq!(m.title, "The \"real\" title");
        assert_eq!(m.description, "Swapped — order");
        assert_eq!(m.image, "https://example.org/img/card.jpg?x=1");
        assert_eq!(PageMeta::decode(&m.encode()), Some(m));
    }

    #[test]
    fn falls_back_to_the_title_tag() {
        let html = "<html><head><TITLE>\n  Just   a\ttitle \u{202E}\n</TITLE></head></html>";
        let m = page_meta("https://example.org/", html.as_bytes()).unwrap();
        assert_eq!(m.title, "Just a title");
        assert_eq!(m.description, "");
        assert_eq!(m.image, "");
        assert!(
            page_meta(
                "https://example.org/",
                b"<html><body>no title</body></html>"
            )
            .is_err()
        );
    }

    #[test]
    fn picture_addresses() {
        let base = "https://example.org/a/b/page.html";
        assert_eq!(resolve(base, "pic.png"), "https://example.org/a/b/pic.png");
        assert_eq!(
            resolve(base, "//cdn.example.net/p.png"),
            "https://cdn.example.net/p.png"
        );
        assert_eq!(
            resolve("https://example.org", "p.png"),
            "https://example.org/p.png"
        );
        // Plain http pictures are dropped: the preview fetch is https only.
        let html =
            br#"<title>t</title><meta property="og:image" content="http://example.org/p.png">"#;
        assert_eq!(page_meta(base, html).unwrap().image, "");
    }

    #[test]
    fn long_text_is_cut() {
        let long = "word ".repeat(100);
        let html = format!("<title>{long}</title><meta name=description content=\"{long}\">");
        let m = page_meta("https://example.org/", html.as_bytes()).unwrap();
        assert_eq!(m.title.chars().count(), MAX_TITLE_CHARS);
        assert!(m.title.ends_with('…'));
        assert!(m.description.chars().count() <= MAX_DESCRIPTION_CHARS);
    }

    #[test]
    fn a_gif_poster() {
        let mut out = Vec::new();
        {
            let mut e = gif::Encoder::new(&mut out, 40, 20, &[]).unwrap();
            let mut px = [200u8, 10, 10, 255].repeat(40 * 20);
            e.write_frame(&gif::Frame::from_rgba_speed(40, 20, &mut px, 10))
                .unwrap();
        }
        let p = gif_poster(&out, 10).unwrap();
        assert_eq!((p.width, p.height), (10, 5));
        assert!(p.pixels[0] > 150 && p.pixels[1] < 60);
        assert!(gif_poster(b"GIF89a", 10).is_err());
        assert!(gif_poster(b"\x89PNG", 10).is_err());
    }

    #[test]
    fn commons_search_results() {
        let json = br#"{"batchcomplete":true,"query":{"pages":[
            {"pageid":2,"ns":6,"title":"File:Second_cat.gif","index":2,"imageinfo":[{"mime":"image/gif","url":"https://upload.wikimedia.org/a/Second_cat.gif","width":800,"height":600,"thumburl":"https://upload.wikimedia.org/thumb/a/Second_cat.gif/240px-Second_cat.gif","thumbwidth":240,"thumbheight":180}]},
            {"pageid":1,"ns":6,"title":"File:First cat.gif","index":1,"imageinfo":[{"mime":"image/gif","url":"https://upload.wikimedia.org/b/First_cat.gif","width":200,"height":100}]},
            {"pageid":3,"ns":6,"title":"File:Not a gif.png","index":3,"imageinfo":[{"mime":"image/png","url":"https://upload.wikimedia.org/c.png"}]},
            {"pageid":4,"ns":6,"title":"File:Plain.gif","index":4,"imageinfo":[{"mime":"image/gif","url":"http://upload.wikimedia.org/d.gif"}]}
        ]}}"#;
        let hits = commons_gifs(json).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "First cat");
        assert_eq!((hits[0].width, hits[0].height), (200, 100));
        assert_eq!(hits[1].title, "Second cat");
        assert!(hits[1].url.contains("240px"));
        assert_eq!((hits[1].width, hits[1].height), (240, 180));
        assert_eq!(decode_hits(&encode_hits(&hits)), Some(hits));
        assert_eq!(commons_gifs(br#"{"batchcomplete":true}"#).unwrap(), vec![]);
        assert!(commons_gifs(b"<html>").is_err());
    }
}
