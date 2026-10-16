//! Link previews and GIF search (`docs/15-client.md` §5), both off until
//! the person turns them on in Settings. Only the sender's device reaches
//! the web, through Tor ([`Transport::fetch`] with the [`WEB`] prefix):
//! netd's nymd fetches, and mediad reads what comes back (a page's tags, a
//! search answer, a GIF's first frame), so nothing from a web site is
//! parsed here. A receiver never fetches anything for a preview: it comes
//! inside the message, and a searched GIF goes out as an ordinary AV1 clip.

use super::{Engine, GIF_SIDE, LINK_PICTURE_SIDE};
use enclave_core::content::{
    LinkPreview, MAX_LINK_DESCRIPTION, MAX_LINK_IMAGE, MAX_LINK_TITLE, MAX_LINKED_TEXT,
};
use enclave_ipc::{GIF_RESULTS, MAX_GIFS, Out};
use enclave_net::transport::{Transport, WEB};
use std::sync::Arc;
use std::time::Duration;

/// How long a page may take to come.
const PAGE_WAIT: Duration = Duration::from_secs(20);
/// How long a picture or a GIF may take to come.
const PICTURE_WAIT: Duration = Duration::from_secs(15);

/// `GET` an ordinary web address through Tor: the body of a 2xx answer.
async fn get(transport: &Arc<dyn Transport>, url: &str, wait: Duration) -> Option<Vec<u8>> {
    match tokio::time::timeout(
        wait,
        transport.fetch("GET", &format!("{WEB}{url}"), Vec::new()),
    )
    .await
    {
        Ok(Ok((status, body))) if (200..300).contains(&status) => Some(body),
        _ => None,
    }
}

/// `s` cut at a character boundary to at most `max` bytes.
fn cut(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

impl Engine {
    /// A preview of the first `https` link in `text`, when link previews
    /// are on: the page's title and description and a small picture, or
    /// nothing if the page can't be reached or read.
    pub(super) async fn link_preview(&mut self, text: &str) -> Option<LinkPreview> {
        let c = self.client.as_ref()?;
        if !c.link_previews_enabled() || text.len() > MAX_LINKED_TEXT {
            return None;
        }
        let url = enclave_core::client::web::first_link(text)?.to_string();
        self.status = "Making a link preview…".into();
        self.push();
        let preview = self.make_preview(&url).await;
        self.status.clear();
        preview
    }

    async fn make_preview(&mut self, url: &str) -> Option<LinkPreview> {
        let page = get(&self.web, url, PAGE_WAIT).await?;
        let meta = self.media.page_meta(url, &page).await.ok()?;
        let mut image = Vec::new();
        if !meta.image.is_empty()
            && let Some(picture) = get(&self.web, &meta.image, PICTURE_WAIT).await
        {
            // Redrawn small in mediad (only a JPEG goes; a picture with
            // transparency comes back as PNG and is left out).
            for side in [
                LINK_PICTURE_SIDE,
                LINK_PICTURE_SIDE * 2 / 3,
                LINK_PICTURE_SIDE / 2,
            ] {
                match self.media.shrink(picture.clone(), side).await {
                    Ok(s)
                        if s.format == enclave_media::Format::Jpeg
                            && s.bytes.len() <= MAX_LINK_IMAGE =>
                    {
                        image = s.bytes;
                        break;
                    }
                    Ok(s) if s.format == enclave_media::Format::Jpeg => continue,
                    _ => break,
                }
            }
        }
        Some(LinkPreview {
            url: url.to_string(),
            title: cut(&meta.title, MAX_LINK_TITLE),
            description: cut(&meta.description, MAX_LINK_DESCRIPTION),
            image,
        })
    }

    /// Search Wikimedia Commons for GIFs, when GIF search is on: the names
    /// go to the window ([`Out::Gifs`]), then each one's first frame as a
    /// preview, while the GIFs are kept for [`enclave_ipc::Cmd::SendGif`].
    pub(super) async fn gif_search(&mut self, query: &str) {
        let on = self.client.as_ref().is_some_and(|c| c.gif_search_enabled());
        let query = query.trim();
        if !on || query.is_empty() {
            return;
        }
        self.gifs.clear();
        self.busy = true;
        self.status = "Searching through Tor…".into();
        self.push();
        let url = enclave_core::client::web::gif_search_url(query);
        let hits = match get(&self.web, &url, PAGE_WAIT).await {
            Some(answer) => self.media.gif_hits(answer).await.ok(),
            None => None,
        };
        let Some(mut hits) = hits else {
            self.busy = false;
            self.status =
                "GIF search couldn't reach Wikimedia Commons. Try again in a moment.".into();
            let _ = self.out.send(Out::Gifs(Vec::new()));
            return;
        };
        hits.truncate(MAX_GIFS);
        let _ = self
            .out
            .send(Out::Gifs(hits.iter().map(|h| h.title.clone()).collect()));
        // The GIFs come at once, each in its own Tor stream.
        let mut fetches = tokio::task::JoinSet::new();
        for (i, h) in hits.iter().enumerate() {
            let t = Arc::clone(&self.web);
            let u = h.url.clone();
            fetches.spawn(async move { (i, get(&t, &u, PICTURE_WAIT).await) });
        }
        let mut gifs: Vec<Vec<u8>> = vec![Vec::new(); hits.len()];
        while let Some(done) = fetches.join_next().await {
            let Ok((i, Some(gif))) = done else {
                continue;
            };
            if let Ok(t) = self.media.gif_poster(gif.clone(), GIF_SIDE).await {
                let _ = self.out.send(Out::Preview(enclave_ipc::Preview {
                    conversation: GIF_RESULTS.into(),
                    seq: i as u64,
                    width: t.width,
                    height: t.height,
                    pixels: t.pixels,
                }));
                gifs[i] = gif;
            }
        }
        self.gifs = hits.into_iter().map(|h| h.title).zip(gifs).collect();
        self.busy = false;
        self.status = if self.gifs.is_empty() {
            "No GIFs found. Try other words.".into()
        } else {
            String::new()
        };
    }
}
