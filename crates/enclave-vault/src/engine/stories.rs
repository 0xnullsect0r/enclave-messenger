//! Stories in the window (`enclave_core::client` `stories.rs`): posting
//! one (a picture is re-encoded in mediad first, a GIF becomes a clip, as
//! for any file), and opening one (its picture fetched and decoded like a
//! message's, the story marked viewed; nothing goes back to the poster).

use super::{Engine, send_preview, story_key, with_extension};
use enclave_core::{CoreError, StoryPicture};

impl Engine {
    pub(super) async fn post_story(&mut self, text: &str, name: &str, bytes: Vec<u8>) {
        self.busy = true;
        self.push();
        let picture = if bytes.is_empty() {
            None
        } else if enclave_media::video::is_gif(&bytes) {
            match self.media.clip(bytes).await {
                Ok((clip, ..)) => Some((
                    with_extension(name, "clip"),
                    enclave_media::video::CLIP_MIME,
                    clip,
                )),
                Err(_) => None,
            }
        } else if enclave_media::detect(&bytes).is_some() {
            match self.media.sanitize(bytes).await {
                Ok(s) => Some((
                    with_extension(name, s.format.extension()),
                    s.format.mime(),
                    s.bytes,
                )),
                Err(_) => None,
            }
        } else {
            None
        };
        let wanted = !name.is_empty();
        if wanted && picture.is_none() {
            self.status =
                "Stories take pictures and animations. Enclave couldn't read that one.".into();
            self.busy = false;
            return;
        }
        if let Some(c) = self.client.as_mut() {
            let p = picture
                .as_ref()
                .map(|(name, mime, bytes)| StoryPicture { name, mime, bytes });
            self.status = match c.post_story(text, p).await {
                Ok(s) if s.waiting() == 0 => {
                    "Posted. Nobody sees it: your stories are hidden from everyone.".into()
                }
                Ok(_) => {
                    "Posted. It reaches your contacts over the next minutes, for 24 hours.".into()
                }
                Err(CoreError::TooLong) => {
                    "A story needs a picture or a few words (at most 700 bytes).".into()
                }
                Err(_) => "Couldn't post it. Check your connection.".into(),
            };
        }
        self.busy = false;
    }

    pub(super) async fn open_story(&mut self, key: &str) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        let Some(story) = c.stories().into_iter().find(|s| story_key(s) == key) else {
            return;
        };
        if let Some(from) = story.from {
            let _ = c.mark_story_viewed(&from, &story.id);
        }
        let conversation = format!("story/{key}");
        if story.attachment.is_none() || self.previews.contains(&(conversation.clone(), 0)) {
            return;
        }
        let Ok(bytes) = c.story_picture(&story).await else {
            self.status = "Couldn't load the picture. Check your connection.".into();
            return;
        };
        self.previews.insert((conversation.clone(), 0));
        send_preview(
            &self.media,
            &mut self.clips,
            &self.out,
            &conversation,
            0,
            bytes,
        )
        .await;
    }
}
