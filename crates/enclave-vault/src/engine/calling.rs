//! The engine's calls: signalling with the contact, the two legs, and what
//! the window shows (`docs/11-calls.md`; `crate::calls` runs the media).
//!
//! ```text
//! caller:  StartCall → Offer ─────────────→ (ringing) ← Ringing
//!                      leg to our relay      Answer → keys → media
//! callee:  Offer → Ringing ──→ AnswerCall → Answer, leg to our relay → media
//! either:  End / Decline / Busy, or 60 s without an answer
//! ```

use super::{Engine, hex_id};
use crate::calls::{self, CallEvent, FromCall, Leg, ToCall};
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
}

/// "3:02" from seconds.
fn duration_text(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

impl Engine {
    /// Relays in the server list (the profile's, else the build's).
    fn relays(&self) -> Vec<ListedRelay> {
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
    fn family_of(&self, server: &[u8; 16]) -> String {
        self.servers()
            .iter()
            .find(|s| &s.id() == server)
            .map(|s| s.family.clone())
            .unwrap_or_default()
    }

    fn relay_by_id(&self, id: &[u8]) -> Option<ListedRelay> {
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
    fn open_leg(&self, id: [u8; 16], relay: ListedRelay) {
        let transport = std::sync::Arc::clone(&self.transport);
        let tx = self.call_tx.clone();
        tokio::spawn(async move {
            let leg = calls::open_leg(&*transport, &relay).await;
            let _ = tx.send(CallEvent::Leg(id, leg.map(Box::new)));
        });
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

    pub(super) async fn start_call(&mut self, conversation: &str, video: bool) {
        if self.call.is_some() {
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
        let picked = route::caller_relay(&candidates, &home, &theirs, calls::draw())
            .and_then(|p| {
                relays
                    .iter()
                    .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
            })
            .cloned();
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
        let Ok(pending) = signal::offer(media, Route::Relay, rid.to_vec(), now, &mut rng) else {
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
        });
        self.open_leg(id, relay);
        if !self.signal(&root, &CallMessage::Offer(offer)).await {
            self.finish_call("", "Couldn't reach them to call. Try again.");
        }
    }

    pub(super) async fn answer_call(&mut self) {
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
        let picked = route::callee_relay(&candidates, &home, &their_relay.family, calls::draw())
            .and_then(|p| {
                relays
                    .iter()
                    .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
            })
            .cloned();
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
        if let Some(call) = self.call.as_mut() {
            call.words = keys.check_words().join(" ");
            call.keys = Some(keys);
            call.peer_relay = Some(peer);
            call.our_relay = Some(relay.clone());
            call.phase = Phase::Connecting;
        }
        self.open_leg(id, relay);
        if !self.signal(&root, &CallMessage::Answer(answer)).await {
            self.finish_call("Missed call", "Couldn't reach them to answer. Try again.");
        }
    }

    pub(super) async fn decline_call(&mut self) {
        let Some(call) = self.call.as_ref() else {
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
        if let Some(call) = self.call.as_mut() {
            call.muted = on;
            if let Some(tx) = &call.tx {
                let _ = tx.send(ToCall::Mute(on));
            }
        }
    }

    pub(super) fn call_mic(&mut self, pcm: Vec<i16>) {
        if let Some(tx) = self.call.as_ref().and_then(|c| c.tx.as_ref()) {
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
                if self.call.is_some() {
                    self.signal(&from, &CallMessage::Busy(o.call_id)).await;
                    if let Some(c) = self.client.as_mut() {
                        let _ = c.add_call_line(&from, false, "Missed call (you were in a call)");
                    }
                    return;
                }
                let video = matches!(o.media, Media::Video(_));
                let id = o.call_id;
                self.call = Some(Call {
                    id,
                    root: from,
                    outgoing: false,
                    video,
                    phase: Phase::Ringing,
                    muted: false,
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
                        "Incoming video call"
                    } else {
                        "Incoming call"
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
            // Direct mode's candidates, and messages about other calls.
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
        call.tx = Some(tx);
        let plan = calls::Plan {
            id: call.id,
            keys,
            caller: call.outgoing,
            peer_relay,
            codec,
        };
        tokio::spawn(calls::run(
            leg,
            plan,
            rx,
            self.out.clone(),
            self.call_tx.clone(),
        ));
    }

    /// What a leg or a running call reported.
    pub(super) async fn on_call_event(&mut self, ev: CallEvent) {
        let current = |e: &Self, id: &[u8; 16]| e.call.as_ref().is_some_and(|c| &c.id == id);
        match ev {
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
            // About a call that already ended.
            _ => {}
        }
    }

    /// Every tick: unanswered calls time out; the ended notice goes.
    pub(super) async fn call_upkeep(&mut self) {
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
        let Some(call) = self.call.as_ref() else {
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
            connected_at: call.connected_at,
            words: call.words.clone(),
            error: if call.phase == Phase::Calling && call.ringing_there {
                "Ringing…".into()
            } else {
                String::new()
            },
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
