//! The engine's calls: signalling with the contact, the two legs, and what
//! the window shows (`docs/11-calls.md`; `crate::calls` runs the media).
//!
//! ```text
//! caller:  StartCall → Offer ─────────────→ (ringing) ← Ringing
//!                      leg to our relay      Answer → keys → media
//! callee:  Offer → Ringing ──→ AnswerCall → Answer, leg to our relay → media
//! either:  End / Decline / Busy, or 60 s without an answer
//! direct:  the offer asks; the callee answers directly → its Candidates;
//!          then the caller's Candidates → the caller's WireGuard probes
//!          reach the callee; the relays carry the call meanwhile
//! ```

use super::{Engine, hex_id};
use crate::calls::{self, CallEvent, DirectPath, DirectSide, FromCall, Leg, ToCall};
use enclave_calls::direct::Candidates;
use enclave_calls::message::CallMessage;
use enclave_calls::route;
use enclave_calls::signal::{self, CallKeys, Media, OFFER_TTL, Offer, Pending, Route};
use enclave_crypto::rng::HedgedRng;
use enclave_federation::ListedRelay;
use enclave_ipc::{CallView, Out};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long an ended call stays on screen.
const ENDED_SHOWN: Duration = Duration::from_secs(4);
/// The standby tunnel's leg reports under this id.
const STANDBY: [u8; 16] = [0xff; 16];
/// What the window says when no private route exists.
const NO_ROUTE: &str = "Couldn't find a private route right now. Try again later.";

/// Where a call is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// We called; no answer yet.
    Calling,
    /// They call us; we haven't answered.
    Ringing,
    /// Answered; the media is starting.
    Connecting,
    /// Media flows.
    Live,
}

/// The call in progress (one at a time).
pub(super) struct Call {
    pub(super) id: [u8; 16],
    pub(super) root: [u8; 64],
    pub(super) outgoing: bool,
    pub(super) video: bool,
    pub(super) phase: Phase,
    pub(super) muted: bool,
    /// Our camera is on (a video call).
    pub(super) camera: bool,
    /// Their device rings (they sent Ringing).
    pub(super) ringing_there: bool,
    pending: Option<Pending>,
    offer: Option<Offer>,
    keys: Option<CallKeys>,
    pub(super) words: String,
    our_relay: Option<ListedRelay>,
    leg: Option<Leg>,
    peer_relay: Option<std::net::SocketAddr>,
    tx: Option<mpsc::UnboundedSender<ToCall>>,
    created: Instant,
    pub(super) connected_at: u64,
    /// Direct mode: we asked for it (calling) or agreed to it (answering).
    direct_wanted: bool,
    /// Our side of the direct link, once ready.
    direct_side: Option<DirectSide>,
    /// Our side is being set up.
    direct_opening: bool,
    /// Their candidates.
    direct_peer: Option<Candidates>,
    /// The call's direct-mode key (kept when the keys go to the media).
    direct_psk: Option<[u8; 32]>,
    /// The media goes directly now.
    pub(super) on_direct: bool,
    /// We share our screen instead of the camera.
    pub(super) sharing: bool,
}

/// "3:02" from seconds.
fn duration_text(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

impl Engine {
    /// Relays in the server list (the profile's, else the build's).
    pub(super) fn relays(&self) -> Vec<ListedRelay> {
        match self
            .client
            .as_ref()
            .and_then(enclave_core::Client::server_list)
        {
            Some(l) => l.relays.clone(),
            None => self.listed_relays.clone(),
        }
    }

    /// A server's operator family ("" when it isn't listed).
    pub(super) fn family_of(&self, server: &[u8; 16]) -> String {
        self.servers()
            .iter()
            .find(|s| &s.id() == server)
            .map(|s| s.family.clone())
            .unwrap_or_default()
    }

    pub(super) fn relay_by_id(&self, id: &[u8]) -> Option<ListedRelay> {
        self.relays()
            .into_iter()
            .find(|r| enclave_federation::relay_id(&r.identity)[..] == *id)
    }

    /// Send call signalling; false when it couldn't go.
    async fn signal(&mut self, root: &[u8; 64], m: &CallMessage) -> bool {
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        match c.send_call(root, &m.encode()).await {
            Ok(()) => true,
            Err(e) => {
                eprintln!("enclave-vault: call signalling: {e}");
                false
            }
        }
    }

    /// Our end at `relay`, set up in the background.
    pub(super) fn open_leg(&self, id: [u8; 16], relay: ListedRelay) {
        let transport = std::sync::Arc::clone(&self.transport);
        let tx = self.call_tx.clone();
        tokio::spawn(async move {
            let leg = calls::open_leg(&*transport, &relay).await;
            let _ = tx.send(CallEvent::Leg(id, leg.map(Box::new)));
        });
    }

    /// Our end at `relay` for call `id`: the standby tunnel's leg when it
    /// goes to that relay (Maximum privacy: the call starts unseen), else
    /// a new one.
    pub(super) fn leg_for(&mut self, id: [u8; 16], relay: ListedRelay) {
        match self.call_standby.take() {
            Some(s) if s.relay.identity == relay.identity => {
                let tx = self.call_tx.clone();
                tokio::spawn(async move {
                    let leg = s
                        .take()
                        .await
                        .ok_or_else(|| "the standby tunnel had stopped".to_string());
                    let _ = tx.send(CallEvent::Leg(id, leg.map(Box::new)));
                });
            }
            other => {
                self.call_standby = other;
                self.open_leg(id, relay);
            }
        }
    }

    /// The relay to pick when the standby's fits the family rule: the
    /// standby's if its family is none of `avoid`.
    fn standby_relay(&self, avoid: &[&str]) -> Option<ListedRelay> {
        self.call_standby
            .as_ref()
            .filter(|s| !avoid.contains(&s.relay.family.as_str()))
            .map(|s| s.relay.clone())
    }

    /// Maximum privacy, in front, no call: keep a standby tunnel open;
    /// otherwise none.
    async fn standby_upkeep(&mut self) {
        let wanted = self.visible
            && self.call.is_none()
            && self.group_call.is_none()
            && self
                .client
                .as_ref()
                .is_some_and(enclave_core::Client::maximum);
        if !wanted {
            // Dropping it stops the padding (a call took it already, or
            // Maximum privacy is off, or the app left the front).
            if self.call.is_none() && self.group_call.is_none() {
                self.call_standby = None;
            }
            return;
        }
        if self.call_standby.is_some() || self.standby_opening {
            return;
        }
        let Some(c) = self.client.as_ref() else {
            return;
        };
        let home = self.family_of(&c.home_server());
        let relays = self.relays();
        let candidates = calls::candidates(&relays);
        let Some(relay) = route::caller_relay(&candidates, &home, "", calls::draw())
            .and_then(|p| {
                relays
                    .iter()
                    .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
            })
            .cloned()
        else {
            return;
        };
        self.standby_opening = true;
        self.open_leg(STANDBY, relay);
    }

    /// Show that the call ended and write its line.
    fn finish_call(&mut self, line: &str, note: &str) {
        let Some(call) = self.call.take() else {
            return;
        };
        if !line.is_empty()
            && let Some(c) = self.client.as_mut()
            && let Err(e) = c.add_call_line(&call.root, call.outgoing, line)
        {
            eprintln!("enclave-vault: call line: {e}");
        }
        let name = self
            .client
            .as_ref()
            .and_then(|c| c.contact(&call.root))
            .map(|c| c.name.clone())
            .unwrap_or_default();
        self.call_ended = Some((
            CallView {
                state: 5,
                conversation: hex_id(&call.root),
                name,
                video: call.video,
                error: if note.is_empty() {
                    line.into()
                } else {
                    note.into()
                },
                ..Default::default()
            },
            Instant::now(),
        ));
        // Dropping the sender ends the media task.
    }

    /// The line a call that connected leaves ("Call, 3:02").
    fn live_line(call: &Call, now: u64) -> String {
        let kind = if call.video { "Video call" } else { "Call" };
        format!(
            "{kind}, {}",
            duration_text(now.saturating_sub(call.connected_at))
        )
    }

    pub(super) async fn start_call(&mut self, conversation: &str, video: bool, direct: bool) {
        if self.call.is_some() || self.group_call.as_ref().is_some_and(|g| g.joined) {
            self.status = "You're already in a call.".into();
            return;
        }
        let Some(root) = self.root_of(conversation) else {
            return;
        };
        let Some(c) = self.client.as_ref() else {
            return;
        };
        let Some(contact) = c.contact(&root).cloned() else {
            return;
        };
        let (home, theirs) = (
            self.family_of(&c.home_server()),
            self.family_of(&contact.server),
        );
        let relays = self.relays();
        let candidates = calls::candidates(&relays);
        let picked = self.standby_relay(&[&home, &theirs]).or_else(|| {
            route::caller_relay(&candidates, &home, &theirs, calls::draw()).and_then(|p| {
                relays
                    .iter()
                    .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
                    .cloned()
            })
        });
        let now = self.transport.now();
        let mut rng = match HedgedRng::new() {
            Ok(r) => r,
            Err(_) => return,
        };
        let media = if video { Media::Video(0) } else { Media::Audio };
        let Some(relay) = picked else {
            self.call_ended = Some((
                CallView {
                    state: 5,
                    conversation: conversation.into(),
                    name: contact.name.clone(),
                    video,
                    error: NO_ROUTE.into(),
                    ..Default::default()
                },
                Instant::now(),
            ));
            return;
        };
        let rid = enclave_federation::relay_id(&relay.identity);
        let route = if direct { Route::Direct } else { Route::Relay };
        let Ok(pending) = signal::offer(media, route, rid.to_vec(), now, &mut rng) else {
            return;
        };
        let offer = pending.offer().clone();
        let id = offer.call_id;
        self.call = Some(Call {
            id,
            root,
            outgoing: true,
            video,
            phase: Phase::Calling,
            muted: false,
            camera: video,
            ringing_there: false,
            pending: Some(pending),
            offer: None,
            keys: None,
            words: String::new(),
            our_relay: Some(relay.clone()),
            leg: None,
            peer_relay: None,
            tx: None,
            created: Instant::now(),
            connected_at: 0,
            direct_wanted: direct,
            direct_side: None,
            direct_opening: false,
            direct_peer: None,
            direct_psk: None,
            on_direct: false,
            sharing: false,
        });
        self.leg_for(id, relay);
        if !self.signal(&root, &CallMessage::Offer(offer)).await {
            self.finish_call("", "Couldn't reach them to call. Try again.");
        }
    }

    pub(super) async fn answer_call(&mut self, direct: bool) {
        if self.call.is_none()
            && let Some(gid) = self
                .group_call
                .as_ref()
                .filter(|g| !g.joined)
                .and_then(|g| g.gid)
        {
            let conv = super::group_id_str(&gid);
            self.join_group_call(&conv).await;
            return;
        }
        let Some(call) = self.call.as_mut() else {
            return;
        };
        if call.phase != Phase::Ringing {
            return;
        }
        let (root, offer) = match call.offer.clone() {
            Some(o) => (call.root, o),
            None => return,
        };
        let Some(their_relay) = self.relay_by_id(&offer.relay) else {
            self.signal(&root, &CallMessage::End(offer.call_id)).await;
            self.finish_call("Missed call", NO_ROUTE);
            return;
        };
        let Some(c) = self.client.as_ref() else {
            return;
        };
        let home = self.family_of(&c.home_server());
        let conv = c.call_conversation(&root);
        let relays = self.relays();
        let candidates = calls::candidates(&relays);
        let picked = self
            .standby_relay(&[&home, &their_relay.family])
            .or_else(|| {
                route::callee_relay(&candidates, &home, &their_relay.family, calls::draw())
                    .and_then(|p| {
                        relays
                            .iter()
                            .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
                            .cloned()
                    })
            });
        let Some(relay) = picked else {
            self.signal(&root, &CallMessage::End(offer.call_id)).await;
            self.finish_call("Missed call", NO_ROUTE);
            return;
        };
        let Ok(peer) = their_relay.addr.parse::<std::net::SocketAddr>() else {
            self.finish_call("Missed call", NO_ROUTE);
            return;
        };
        let now = self.transport.now();
        let rid = enclave_federation::relay_id(&relay.identity);
        let Ok(mut rng) = HedgedRng::new() else {
            return;
        };
        let (answer, keys) = match signal::answer(&offer, rid.to_vec(), &conv, now, &mut rng) {
            Ok(a) => a,
            Err(_) => {
                self.finish_call("Missed call", "The call had already ended.");
                return;
            }
        };
        let id = offer.call_id;
        let direct = direct && offer.route == Route::Direct;
        if let Some(call) = self.call.as_mut() {
            call.words = keys.check_words().join(" ");
            call.direct_psk = Some(*keys.direct_psk());
            call.keys = Some(keys);
            call.peer_relay = Some(peer);
            call.our_relay = Some(relay.clone());
            call.phase = Phase::Connecting;
            call.direct_wanted = direct;
        }
        self.leg_for(id, relay.clone());
        if !self.signal(&root, &CallMessage::Answer(answer)).await {
            self.finish_call("Missed call", "Couldn't reach them to answer. Try again.");
            return;
        }
        // Answered directly: our addresses go first (the caller asked).
        if direct {
            self.open_direct(id, relay);
        }
    }

    /// Our side of a direct call, set up in the background.
    fn open_direct(&mut self, id: [u8; 16], relay: ListedRelay) {
        if let Some(c) = self.call.as_mut() {
            c.direct_opening = true;
        }
        let transport = std::sync::Arc::clone(&self.transport);
        let tx = self.call_tx.clone();
        tokio::spawn(async move {
            let side = calls::open_direct(&*transport, &relay).await;
            let _ = tx.send(CallEvent::Direct(id, side.map(Box::new)));
        });
    }

    /// Hand the running media both sides of the direct link, once there
    /// are both.
    fn try_direct(&mut self) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let (Some(tx), Some(psk)) = (call.tx.as_ref(), call.direct_psk) else {
            return;
        };
        if call.direct_side.is_none() || call.direct_peer.is_none() {
            return;
        }
        let (Some(side), Some(peer)) = (call.direct_side.take(), call.direct_peer.take()) else {
            return;
        };
        let path = DirectPath::new(side, &peer, psk, call.outgoing);
        let _ = tx.send(ToCall::Direct(Box::new(path)));
    }

    pub(super) async fn decline_call(&mut self) {
        let Some(call) = self.call.as_ref() else {
            self.decline_group_call();
            return;
        };
        if call.phase != Phase::Ringing {
            return;
        }
        let (root, id) = (call.root, call.id);
        self.signal(&root, &CallMessage::Decline(id)).await;
        self.finish_call("Declined call", "");
    }

    pub(super) async fn end_call(&mut self) {
        let Some(call) = self.call.as_ref() else {
            if self.leave_lobby() {
                return;
            }
            if self.group_call.as_ref().is_some_and(|g| g.joined) {
                self.leave_group_call("").await;
            } else {
                self.decline_group_call();
            }
            return;
        };
        let (root, id) = (call.root, call.id);
        let line = match call.phase {
            Phase::Live => Self::live_line(call, self.transport.now()),
            Phase::Ringing => "Declined call".into(),
            _ if call.outgoing => "Cancelled call".into(),
            _ => "Missed call".into(),
        };
        self.signal(&root, &CallMessage::End(id)).await;
        self.finish_call(&line, "");
    }

    pub(super) fn call_mute(&mut self, on: bool) {
        if let Some(g) = self.group_call.as_mut().filter(|g| g.joined) {
            g.muted = on;
            if let Some(tx) = &g.tx {
                let _ = tx.send(ToCall::Mute(on));
            }
        }
        if let Some(call) = self.call.as_mut() {
            call.muted = on;
            if let Some(tx) = &call.tx {
                let _ = tx.send(ToCall::Mute(on));
            }
        }
    }

    pub(super) fn call_camera(&mut self, on: bool) {
        if let Some(g) = self.group_call.as_mut().filter(|g| g.joined && g.video) {
            g.camera = on;
            if let Some(tx) = &g.tx {
                let _ = tx.send(ToCall::Camera(on));
            }
        }
        if let Some(call) = self.call.as_mut().filter(|c| c.video) {
            call.camera = on;
            if let Some(tx) = &call.tx {
                let _ = tx.send(ToCall::Camera(on));
            }
        }
    }

    /// Share the screen instead of the camera (a video call), or stop.
    pub(super) fn call_screen(&mut self, on: bool) {
        if let Some(g) = self.group_call.as_mut().filter(|g| g.joined && g.video) {
            g.sharing = on;
            if let Some(tx) = &g.tx {
                let _ = tx.send(ToCall::Screen(on));
            }
        }
        if let Some(call) = self.call.as_mut().filter(|c| c.video) {
            call.sharing = on;
            if let Some(tx) = &call.tx {
                let _ = tx.send(ToCall::Screen(on));
            }
        }
    }

    /// A camera frame, at the call's video size, or a shared screen's, at
    /// the screen's.
    pub(super) fn call_frame(&mut self, width: u32, height: u32, rgba: Vec<u8>) {
        let sharing = self.call.as_ref().is_some_and(|c| c.sharing)
            || self.group_call.as_ref().is_some_and(|g| g.sharing);
        let t = if sharing {
            enclave_media::callvideo::screen(0)
        } else {
            enclave_media::callvideo::tier(0)
        };
        if (width, height) != (t.width, t.height) {
            return;
        }
        let group = self
            .group_call
            .as_ref()
            .filter(|g| g.camera || g.sharing)
            .and_then(|g| g.tx.as_ref());
        if let Some(tx) = self
            .call
            .as_ref()
            .filter(|c| c.camera || c.sharing)
            .and_then(|c| c.tx.as_ref())
            .or(group)
        {
            let _ = tx.send(ToCall::Frame(rgba));
        }
    }

    pub(super) fn call_mic(&mut self, pcm: Vec<i16>) {
        let group = self.group_call.as_ref().and_then(|g| g.tx.as_ref());
        if let Some(tx) = self.call.as_ref().and_then(|c| c.tx.as_ref()).or(group) {
            let _ = tx.send(ToCall::Mic(pcm));
        }
    }

    /// Call signalling that a sync brought.
    pub(super) async fn on_call_message(&mut self, from: [u8; 64], bytes: &[u8]) {
        let Ok(m) = CallMessage::decode(bytes) else {
            return;
        };
        let now = self.transport.now();
        let ours = self
            .call
            .as_ref()
            .is_some_and(|c| c.id == m.call_id() && c.root == from);
        match m {
            CallMessage::Offer(o) => {
                if now > o.created_at + OFFER_TTL {
                    if let Some(c) = self.client.as_mut() {
                        let _ = c.add_call_line(&from, false, "Missed call");
                    }
                    return;
                }
                if self.call.is_some() || self.group_call.as_ref().is_some_and(|g| g.joined) {
                    self.signal(&from, &CallMessage::Busy(o.call_id)).await;
                    if let Some(c) = self.client.as_mut() {
                        let _ = c.add_call_line(&from, false, "Missed call (you were in a call)");
                    }
                    return;
                }
                let video = matches!(o.media, Media::Video(_));
                let id = o.call_id;
                // A group call that only rang gives way.
                self.group_call = None;
                self.call = Some(Call {
                    id,
                    root: from,
                    outgoing: false,
                    video,
                    phase: Phase::Ringing,
                    muted: false,
                    camera: video,
                    ringing_there: false,
                    pending: None,
                    offer: Some(o),
                    keys: None,
                    words: String::new(),
                    our_relay: None,
                    leg: None,
                    peer_relay: None,
                    tx: None,
                    created: Instant::now(),
                    connected_at: 0,
                    direct_wanted: false,
                    direct_side: None,
                    direct_opening: false,
                    direct_peer: None,
                    direct_psk: None,
                    on_direct: false,
                    sharing: false,
                });
                self.signal(&from, &CallMessage::Ringing(id)).await;
                let named = self.client.as_ref().is_some_and(|c| c.previews());
                let name = self
                    .client
                    .as_ref()
                    .and_then(|c| c.contact(&from))
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
                let _ = self.out.send(Out::Notify(enclave_ipc::Notice {
                    conversation: hex_id(&from),
                    title: if video {
                        enclave_ipc::VIDEO_CALL_NOTICE
                    } else {
                        enclave_ipc::CALL_NOTICE
                    }
                    .into(),
                    body: if named { name } else { String::new() },
                }));
            }
            CallMessage::Ringing(_) if ours => {
                if let Some(c) = self.call.as_mut() {
                    c.ringing_there = true;
                }
            }
            CallMessage::Answer(a) if ours => {
                let Some(call) = self.call.as_mut() else {
                    return;
                };
                let Some(pending) = call.pending.take() else {
                    return;
                };
                let conv = match self.client.as_ref() {
                    Some(c) => c.call_conversation(&from),
                    None => return,
                };
                let keys = match pending.finish(&a, &conv, now) {
                    Ok(k) => k,
                    Err(_) => {
                        self.signal(&from, &CallMessage::End(a.call_id)).await;
                        self.finish_call("Missed call", "The call couldn't be set up.");
                        return;
                    }
                };
                let peer = self
                    .relay_by_id(&a.relay)
                    .and_then(|r| r.addr.parse::<std::net::SocketAddr>().ok());
                let Some(call) = self.call.as_mut() else {
                    return;
                };
                call.words = keys.check_words().join(" ");
                call.direct_psk = Some(*keys.direct_psk());
                call.keys = Some(keys);
                call.peer_relay = peer;
                call.phase = Phase::Connecting;
                if peer.is_none() {
                    self.signal(&from, &CallMessage::End(a.call_id)).await;
                    self.finish_call("Cancelled call", NO_ROUTE);
                    return;
                }
                self.start_media().await;
            }
            CallMessage::Decline(_) if ours => self.finish_call("Call declined", ""),
            CallMessage::Busy(_) if ours => {
                self.finish_call("No answer", "They're in another call.")
            }
            CallMessage::End(_) if ours => {
                let line = match self.call.as_ref() {
                    Some(c) if c.phase == Phase::Live => Self::live_line(c, now),
                    Some(c) if c.outgoing => "No answer".into(),
                    _ => "Missed call".into(),
                };
                self.finish_call(&line, "");
            }
            CallMessage::Candidates(_, bytes) if ours => {
                let Ok(theirs) = Candidates::decode(&bytes) else {
                    return;
                };
                let Some(call) = self.call.as_mut() else {
                    return;
                };
                // Only a direct call we asked for (or agreed to) takes them.
                if !call.direct_wanted || call.direct_peer.is_some() {
                    return;
                }
                call.direct_peer = Some(theirs);
                // The callee named its addresses: now ours (the caller's).
                if call.outgoing && call.direct_side.is_none() && !call.direct_opening {
                    let id = call.id;
                    if let Some(relay) = call.our_relay.clone() {
                        self.open_direct(id, relay);
                    }
                }
                self.try_direct();
            }
            // Messages about other calls.
            _ => {}
        }
    }

    /// Start the media once there are keys, our leg and their relay.
    async fn start_media(&mut self) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        if call.tx.is_some() || call.keys.is_none() || call.leg.is_none() {
            return;
        }
        let Some(peer_relay) = call.peer_relay else {
            return;
        };
        let codec = match self.media.open_call().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("enclave-vault: call audio: {e}");
                let (root, id) = (call.root, call.id);
                self.signal(&root, &CallMessage::End(id)).await;
                self.finish_call("", "Couldn't start the call's audio.");
                return;
            }
        };
        // Video: tier 0 to start with (it only ever steps down).
        let video = if self.call.as_ref().is_some_and(|c| c.video) {
            match self.media.open_video(0).await {
                Ok(v) => Some((v, 0usize)),
                Err(e) => {
                    eprintln!("enclave-vault: call video: {e}");
                    None
                }
            }
        } else {
            None
        };
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let (Some(keys), Some(leg)) = (call.keys.take(), call.leg.take()) else {
            return;
        };
        let (tx, rx) = mpsc::unbounded_channel();
        if call.muted {
            let _ = tx.send(ToCall::Mute(true));
        }
        if call.video && !call.camera {
            let _ = tx.send(ToCall::Camera(false));
        }
        if call.sharing {
            let _ = tx.send(ToCall::Screen(true));
        }
        call.tx = Some(tx);
        let plan = calls::Plan {
            id: call.id,
            keys,
            caller: call.outgoing,
            peer_relay,
            codec,
            video,
        };
        tokio::spawn(calls::run(
            leg,
            plan,
            rx,
            self.out.clone(),
            self.call_tx.clone(),
        ));
        self.try_direct();
    }

    /// What a leg or a running call reported.
    pub(super) async fn on_call_event(&mut self, ev: CallEvent) {
        if self.is_lobby_event(&ev) {
            self.on_lobby_event(ev).await;
            return;
        }
        if self.is_group_event(&ev) {
            self.on_group_call_event(ev).await;
            return;
        }
        let current = |e: &Self, id: &[u8; 16]| e.call.as_ref().is_some_and(|c| &c.id == id);
        match ev {
            CallEvent::Leg(id, Ok(leg)) if id == STANDBY => {
                self.standby_opening = false;
                if self.call.is_none() {
                    self.call_standby = Some(calls::Standby::start(*leg, self.call_tx.clone()));
                }
            }
            CallEvent::Leg(id, Err(e)) if id == STANDBY => {
                self.standby_opening = false;
                eprintln!("enclave-vault: standby call tunnel: {e}");
            }
            CallEvent::StandbyEnded => self.call_standby = None,
            CallEvent::Leg(id, Ok(leg)) if current(self, &id) => {
                if let Some(c) = self.call.as_mut() {
                    c.leg = Some(*leg);
                }
                self.start_media().await;
            }
            CallEvent::Leg(id, Err(e)) if current(self, &id) => {
                eprintln!("enclave-vault: call relay: {e}");
                let (root, outgoing) = match self.call.as_ref() {
                    Some(c) => (c.root, c.outgoing),
                    None => return,
                };
                self.signal(&root, &CallMessage::End(id)).await;
                let line = if outgoing {
                    "Cancelled call"
                } else {
                    "Missed call"
                };
                self.finish_call(line, NO_ROUTE);
            }
            CallEvent::Media(id, FromCall::Connected) if current(self, &id) => {
                let now = self.transport.now();
                if let Some(c) = self.call.as_mut() {
                    c.phase = Phase::Live;
                    c.connected_at = now;
                }
            }
            CallEvent::Media(id, FromCall::Dropped(why)) if current(self, &id) => {
                let now = self.transport.now();
                let (root, line) = match self.call.as_ref() {
                    Some(c) if c.phase == Phase::Live => (c.root, Self::live_line(c, now)),
                    Some(c) if c.outgoing => (c.root, "Cancelled call".to_string()),
                    Some(c) => (c.root, "Missed call".to_string()),
                    None => return,
                };
                self.signal(&root, &CallMessage::End(id)).await;
                self.finish_call(&line, &why);
            }
            CallEvent::Media(id, FromCall::Direct(on)) if current(self, &id) => {
                if let Some(c) = self.call.as_mut() {
                    c.on_direct = on;
                }
            }
            CallEvent::Direct(id, Ok(side)) if current(self, &id) => {
                let ours = side.ours.encode();
                let root = match self.call.as_mut() {
                    Some(c) => {
                        c.direct_opening = false;
                        c.direct_side = Some(*side);
                        c.root
                    }
                    None => return,
                };
                self.signal(&root, &CallMessage::Candidates(id, ours)).await;
                self.try_direct();
            }
            CallEvent::Direct(id, Err(e)) if current(self, &id) => {
                // The relays carry the call.
                eprintln!("enclave-vault: direct call: {e}");
                if let Some(c) = self.call.as_mut() {
                    c.direct_opening = false;
                }
            }
            // About a call that already ended.
            _ => {}
        }
    }

    /// Every tick: unanswered calls time out; the ended notice goes.
    pub(super) async fn call_upkeep(&mut self) {
        self.standby_upkeep().await;
        self.group_call_upkeep().await;
        self.call_link_upkeep();
        if self
            .call_ended
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > ENDED_SHOWN)
        {
            self.call_ended = None;
        }
        let Some(call) = self.call.as_ref() else {
            return;
        };
        let unanswered = matches!(call.phase, Phase::Calling | Phase::Ringing)
            && call.created.elapsed() > Duration::from_secs(OFFER_TTL);
        if unanswered {
            let (root, id, outgoing) = (call.root, call.id, call.outgoing);
            if outgoing {
                self.signal(&root, &CallMessage::End(id)).await;
                self.finish_call("No answer", "");
            } else {
                self.finish_call("Missed call", "");
            }
        }
    }

    /// The call as the window shows it.
    pub(super) fn call_view(&self) -> CallView {
        let mut v = self.one_call_view();
        v.live_groups = self.live_groups();
        v
    }

    fn one_call_view(&self) -> CallView {
        let Some(call) = self.call.as_ref() else {
            if let Some(g) = self.group_call.as_ref() {
                return self.group_call_view(g);
            }
            if let Some(v) = self.waiting_view() {
                return v;
            }
            return self
                .call_ended
                .as_ref()
                .map(|(v, _)| v.clone())
                .unwrap_or_default();
        };
        let name = self
            .client
            .as_ref()
            .and_then(|c| c.contact(&call.root))
            .map(|c| c.name.clone())
            .unwrap_or_default();
        CallView {
            state: match call.phase {
                Phase::Calling => 1,
                Phase::Ringing => 2,
                Phase::Connecting => 3,
                Phase::Live => 4,
            },
            conversation: hex_id(&call.root),
            name,
            video: call.video,
            muted: call.muted,
            camera: call.video && call.camera,
            video_width: if call.video {
                enclave_media::callvideo::tier(0).width
            } else {
                0
            },
            video_height: if call.video {
                enclave_media::callvideo::tier(0).height
            } else {
                0
            },
            connected_at: call.connected_at,
            words: call.words.clone(),
            error: if call.phase == Phase::Calling && call.ringing_there {
                "Ringing…".into()
            } else {
                String::new()
            },
            direct_asked: call.phase == Phase::Ringing
                && call
                    .offer
                    .as_ref()
                    .is_some_and(|o| o.route == Route::Direct),
            direct: call.on_direct,
            screen: call.sharing,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_minutes_and_seconds() {
        assert_eq!(duration_text(0), "0:00");
        assert_eq!(duration_text(182), "3:02");
        assert_eq!(duration_text(3_725), "62:05");
    }
}
