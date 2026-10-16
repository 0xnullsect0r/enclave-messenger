//! Videos (`docs/15-client.md` §5.5): one being made, from the camera or a
//! video file the app reads with the platform's decoder, and one playing.
//!
//! The window streams frames (RGBA, 30 a second) and sound (48 kHz mono)
//! here; mediad encodes them as they come (`enclave_media::movie`), and the
//! finished file goes out as a clip attachment like an animated picture. A
//! video someone sent is played by mediad half a second at a time, the
//! window asking for the next piece as it shows each one.

use super::Engine;
use crate::media::{VideoPlay, VideoWrite};
use enclave_core::CoreError;
use enclave_ipc::{MAX_PIECE_FRAMES, Out, VideoPiece};

/// Longest side of a video's frames as played.
const PLAY_SIDE: u16 = 480;
/// Each piece played: half a second.
const PIECE_MS: u16 = 500;

/// A video being made: its conversation, name and encoder.
pub(super) struct Recording {
    conversation: String,
    name: String,
    writer: VideoWrite,
    /// The encoder refused more (the video is full or a frame was bad).
    stopped: bool,
    /// Frames handled.
    frames: u32,
}

/// A video playing: which, and the player.
pub(super) struct Playing {
    key: String,
    play: VideoPlay,
}

impl Engine {
    pub(super) async fn record_start(
        &mut self,
        conversation: &str,
        name: &str,
        width: u32,
        height: u32,
    ) {
        self.recording = None;
        let (w, h) = enclave_media::movie::video_size(width, height);
        if (w, h) != (width, height)
            || (self.root_of(conversation).is_none() && self.group_of(conversation).is_none())
        {
            self.status = "Couldn't start the video.".into();
            return;
        }
        match self.media.write_video(w as u16, h as u16).await {
            Ok(writer) => {
                self.recording = Some(Recording {
                    conversation: conversation.to_string(),
                    name: name.to_string(),
                    writer,
                    stopped: false,
                    frames: 0,
                });
            }
            Err(_) => self.status = "Couldn't start the video.".into(),
        }
    }

    pub(super) async fn record_frame(&mut self, rgba: Vec<u8>) {
        let Some(r) = self.recording.as_mut() else {
            return;
        };
        if !r.stopped && r.writer.frame(rgba).await.is_err() {
            // Full (10 minutes or 100 MiB): what came is kept.
            r.stopped = true;
            self.status = "That's as long as a video can be. Send it, or start again.".into();
            self.push();
        }
        // Counted either way, so a file being read never waits on us.
        if let Some(r) = self.recording.as_mut() {
            r.frames += 1;
            let _ = self.out.send(Out::RecordProgress(r.frames));
        }
    }

    pub(super) async fn record_sound(&mut self, pcm: &[u8]) {
        if let Some(r) = self.recording.as_mut()
            && !r.stopped
        {
            let pcm: Vec<i16> = pcm
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            let _ = r.writer.sound(&pcm).await;
        }
    }

    pub(super) async fn record_end(&mut self, caption: &str) {
        let Some(r) = self.recording.take() else {
            return;
        };
        self.busy = true;
        self.status = "Finishing the video…".into();
        self.push();
        let video = r.writer.finish().await;
        self.status.clear();
        let Ok((bytes, ..)) = video else {
            self.status = "Couldn't make the video. Try again.".into();
            self.busy = false;
            return;
        };
        let name = super::with_extension(&r.name, "clip");
        let mime = enclave_media::video::CLIP_MIME;
        let (root, gid) = (
            self.root_of(&r.conversation),
            self.group_of(&r.conversation),
        );
        if let Some(c) = self.client.as_mut() {
            let sent = match (root, gid) {
                (Some(root), _) => c
                    .send_attachment(&root, &name, mime, &bytes, caption.trim())
                    .await
                    .map(|_| ()),
                (None, Some(gid)) => c
                    .send_group_file(&gid, &name, mime, &bytes, caption.trim())
                    .await
                    .map(|_| ()),
                _ => Err(CoreError::NotFound),
            };
            match sent {
                Ok(()) => self.effect(enclave_ipc::Effect::FileSent),
                Err(CoreError::TooLong) => self.status = "That video is too large to send.".into(),
                Err(_) => self.status = "Couldn't send the video. Check your connection.".into(),
            }
        }
        self.busy = false;
    }

    /// Play a video (a version 2 clip) from its first piece.
    pub(super) async fn play_video(&mut self, key: String, bytes: Vec<u8>) {
        self.playing = None;
        match self.media.play_video(bytes, PLAY_SIDE).await {
            Ok(play) => {
                self.playing = Some(Playing { key, play });
                self.video_piece(true).await;
            }
            Err(_) => self.status = "Enclave couldn't play this one.".into(),
        }
    }

    /// The next piece of the video playing, to the window.
    pub(super) async fn video_piece(&mut self, first: bool) {
        let Some(p) = self.playing.as_mut() else {
            return;
        };
        let (fps, duration_ms) = (p.play.info.2, p.play.info.3);
        match p.play.piece(PIECE_MS).await {
            Ok((width, height, mut frames, pcm, done)) => {
                frames.truncate(MAX_PIECE_FRAMES);
                let piece = VideoPiece {
                    key: p.key.clone(),
                    fps,
                    duration_ms,
                    width,
                    height,
                    frames,
                    pcm,
                    first,
                    done,
                };
                let _ = self.out.send(Out::VideoPiece(piece));
                if done {
                    self.playing = None;
                }
            }
            Err(_) => {
                self.playing = None;
                self.status = "Enclave couldn't play this one.".into();
            }
        }
    }

    pub(super) async fn video_more(&mut self, key: &str) {
        if self.playing.as_ref().is_some_and(|p| p.key == key) {
            self.video_piece(false).await;
        }
    }
}
