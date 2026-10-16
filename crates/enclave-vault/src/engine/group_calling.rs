//! The engine's group calls (`docs/11-calls.md` §8; `crate::calls::run_group`
//! runs the media).
//!
//! ```text
//! starter:  StartGroupCall → Start (in the group) → leg to its relay = SFU
//! member:   Start → rings 60 s → JoinGroupCall → Joined → leg to its relay,
//!           which forwards to the SFU
//! anyone:   leaving sends Left; the last one in sends End too
//! ```

use super::{Engine, group_id_str};
use crate::calls::{self, CallEvent, FromCall, GroupPlan, Leg, ToCall};
use enclave_calls::group::{GroupCallMessage, MAX_PARTICIPANTS};
use enclave_calls::route;
use enclave_calls::signal::{CallKeys, OFFER_TTL};
use enclave_crypto::rng::HedgedRng;
use enclave_federation::ListedRelay;
use enclave_ipc::{CallPeer, CallView, Out};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// How long a reaction shows on someone's tile.
const REACTION_SHOWN: Duration = Duration::from_secs(5);
/// A call no one said anything about for this long is taken as over.
const KNOWN_FOR: Duration = Duration::from_secs(6 * 3600);
/// What the window says when no private route exists.
const NO_ROUTE: &str = "Couldn't find a private route right now. Try again later.";
/// What a call joined from a link is called.
pub(super) const LINK_CALL: &str = "Call";

/// A group call someone started, as far as we know.
pub(super) struct Known {
    pub(super) id: [u8; 16],
    secret: Zeroizing<[u8; 64]>,
    sfu: [u8; 16],
    pub(super) video: bool,
    started_ms: u64,
    /// Who said they are in it.
    in_call: HashSet<[u8; 64]>,
    since: Instant,
}

/// Someone heard in the call.
#[derive(Default)]
struct Heard {
    hand: bool,
    reaction: Option<(String, Instant)>,
}

/// The group call we ring for or are in.
pub(super) struct GroupCall {
    pub(super) id: [u8; 16],
    /// The group (none: we joined from a call link).
    pub(super) gid: Option<[u8; 32]>,
    pub(super) video: bool,
    /// We joined (else it rings).
    pub(super) joined: bool,
    /// Media flows.
    pub(super) live: bool,
    pub(super) muted: bool,
    pub(super) camera: bool,
    pub(super) hand: bool,
    /// Our camera waits for a free place.
    cameras_full: bool,
    pub(super) keys: CallKeys,
    pub(super) secret: Zeroizing<[u8; 64]>,
    pub(super) me: u32,
    pub(super) sfu: Option<std::net::SocketAddr>,
    /// The SFU relay's id.
    pub(super) sfu_id: [u8; 16],
    pub(super) started_ms: u64,
    /// The call link we made for it, and its lobby.
    pub(super) link: Option<super::call_links::HostedLink>,
    /// Names people announced (shown for anyone not in the group).
    names: HashMap<u32, String>,
    leg: Option<Leg>,
    pub(super) tx: Option<mpsc::UnboundedSender<ToCall>>,
    heard: BTreeMap<u32, Heard>,
    created: Instant,
    connected_at: u64,
}

impl GroupCall {
    /// A call joined from a link (no group): joined at once.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn guest(
        id: [u8; 16],
        me: u32,
        keys: CallKeys,
        secret: Zeroizing<[u8; 64]>,
        video: bool,
        sfu: std::net::SocketAddr,
        sfu_id: [u8; 16],
        started_ms: u64,
    ) -> Self {
        Self {
            id,
            gid: None,
            video,
            joined: true,
            live: false,
            muted: false,
            camera: video,
            hand: false,
            cameras_full: false,
            keys,
            secret,
            me,
            sfu: Some(sfu),
            sfu_id,
            started_ms,
            link: None,
            names: HashMap::new(),
            leg: None,
            tx: None,
            heard: BTreeMap::new(),
            created: Instant::now(),
            connected_at: 0,
        }
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Engine {
    fn group_name(&self, gid: &[u8; 32]) -> String {
        self.client
            .as_ref()
            .and_then(|c| c.groups().into_iter().find(|g| &g.id == gid))
            .map(|g| g.name)
            .unwrap_or_default()
    }

    /// Our relay for a group call: one outside our home's operator family.
    pub(super) fn group_relay(&self) -> Option<ListedRelay> {
        let c = self.client.as_ref()?;
        let home = self.family_of(&c.home_server());
        let relays = self.relays();
        let candidates = calls::candidates(&relays);
        let p = route::caller_relay(&candidates, &home, "", calls::draw())?;
        relays
            .iter()
            .find(|r| enclave_federation::relay_id(&r.identity) == p.id)
            .cloned()
    }

    async fn group_signal(&mut self, gid: &[u8; 32], m: &GroupCallMessage) -> bool {
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        match c.send_group_call(gid, &m.encode()).await {
            Ok(()) => true,
            Err(e) => {
                eprintln!("enclave-vault: group call signalling: {e}");
                false
            }
        }
    }

    fn group_line(&mut self, gid: &[u8; 32], text: &str) {
        if let Some(c) = self.client.as_mut()
            && let Err(e) = c.add_group_call_line(gid, text)
        {
            eprintln!("enclave-vault: group call line: {e}");
        }
    }

    fn ended(&mut self, conversation: String, name: String, video: bool, note: &str) {
        self.call_ended = Some((
            CallView {
                state: 5,
                conversation,
                name,
                video,
                group: true,
                error: note.into(),
                ..Default::default()
            },
            Instant::now(),
        ));
    }

    /// Start a call in a group.
    pub(super) async fn start_group_call(&mut self, conversation: &str, video: bool) {
        if self.call.is_some() || self.group_call.is_some() {
            self.status = "You're already in a call.".into();
            return;
        }
        let Some(gid) = self.group_of(conversation) else {
            return;
        };
        let name = self.group_name(&gid);
        let Some(relay) = self.group_relay() else {
            self.ended(conversation.into(), name, video, NO_ROUTE);
            return;
        };
        let Ok(mut rng) = HedgedRng::new() else {
            return;
        };
        let (Ok(id), Ok(secret)) = (
            rng.array::<16>("calls/call-id"),
            rng.array::<64>("calls/group-secret"),
        ) else {
            return;
        };
        let secret = Zeroizing::new(secret);
        let sfu = enclave_federation::relay_id(&relay.identity);
        let started_ms = unix_ms();
        let Some(me) = self.client.as_ref().map(enclave_core::Client::root) else {
            return;
        };
        let msg = GroupCallMessage::Start {
            call_id: id,
            secret: secret.clone(),
            sfu,
            video,
            started_ms,
        };
        let keys = CallKeys::group(id, &secret);
        let secret_copy = secret.clone();
        self.group_calls.insert(
            gid,
            Known {
                id,
                secret,
                sfu,
                video,
                started_ms,
                in_call: HashSet::from([me]),
                since: Instant::now(),
            },
        );
        self.group_call = Some(GroupCall {
            id,
            gid: Some(gid),
            video,
            joined: true,
            live: false,
            muted: false,
            camera: video,
            hand: false,
            cameras_full: false,
            me: keys.participant(&me),
            keys,
            secret: Zeroizing::new(*secret_copy),
            sfu: relay.addr.parse().ok(),
            sfu_id: sfu,
            started_ms,
            link: None,
            names: HashMap::new(),
            leg: None,
            tx: None,
            heard: BTreeMap::new(),
            created: Instant::now(),
            connected_at: 0,
        });
        self.leg_for(id, relay);
        if !self.group_signal(&gid, &msg).await {
            self.group_call = None;
            self.group_calls.remove(&gid);
            self.ended(
                conversation.into(),
                name,
                video,
                "Couldn't reach the group to call. Try again.",
            );
            return;
        }
        let kind = if video {
            "You started a video call"
        } else {
            "You started a call"
        };
        self.group_line(&gid, kind);
    }

    /// Join the call going on in a group (it rings, or the group shows it).
    pub(super) async fn join_group_call(&mut self, conversation: &str) {
        let Some(gid) = self.group_of(conversation) else {
            return;
        };
        if self.call.is_some() || self.group_call.as_ref().is_some_and(|g| g.joined) {
            self.status = "You're already in a call.".into();
            return;
        }
        let Some(k) = self.group_calls.get(&gid) else {
            self.status = "That call has ended.".into();
            return;
        };
        if k.in_call.len() >= MAX_PARTICIPANTS {
            self.status = "That call is full.".into();
            return;
        }
        let (id, video, started_ms, sfu_id) = (k.id, k.video, k.started_ms, k.sfu);
        let keys = CallKeys::group(id, &k.secret);
        let secret = k.secret.clone();
        let sfu = self
            .relay_by_id(&k.sfu)
            .and_then(|r| r.addr.parse::<std::net::SocketAddr>().ok());
        let name = self.group_name(&gid);
        let (Some(sfu), Some(relay)) = (sfu, self.group_relay()) else {
            self.group_call = None;
            self.ended(conversation.into(), name, video, NO_ROUTE);
            return;
        };
        let Some(me) = self.client.as_ref().map(enclave_core::Client::root) else {
            return;
        };
        if let Some(k) = self.group_calls.get_mut(&gid) {
            k.in_call.insert(me);
        }
        self.group_call = Some(GroupCall {
            id,
            gid: Some(gid),
            video,
            joined: true,
            live: false,
            muted: false,
            camera: video,
            hand: false,
            cameras_full: false,
            me: keys.participant(&me),
            keys,
            secret,
            sfu: Some(sfu),
            sfu_id,
            started_ms,
            link: None,
            names: HashMap::new(),
            leg: None,
            tx: None,
            heard: BTreeMap::new(),
            created: Instant::now(),
            connected_at: 0,
        });
        self.leg_for(id, relay);
        self.group_signal(&gid, &GroupCallMessage::Joined(id)).await;
    }

    /// Leave the group call (or stop it ringing).
    pub(super) async fn leave_group_call(&mut self, note: &str) {
        let Some(g) = self.group_call.take() else {
            return;
        };
        if !g.joined {
            return;
        }
        let me = self.client.as_ref().map(enclave_core::Client::root);
        if let Some(gid) = g.gid {
            let last = match (self.group_calls.get_mut(&gid), me) {
                (Some(k), Some(me)) if k.id == g.id => {
                    k.in_call.remove(&me);
                    k.in_call.is_empty()
                }
                _ => true,
            };
            self.group_signal(&gid, &GroupCallMessage::Left(g.id)).await;
            if last {
                self.group_signal(&gid, &GroupCallMessage::End(g.id)).await;
                self.group_calls.remove(&gid);
            }
        }
        let line = if g.live {
            let secs = self.transport.now().saturating_sub(g.connected_at);
            let kind = if g.video {
                "Group video call"
            } else {
                "Group call"
            };
            format!("{kind}, {}:{:02}", secs / 60, secs % 60)
        } else {
            String::new()
        };
        if !line.is_empty()
            && let Some(gid) = g.gid
        {
            self.group_line(&gid, &line);
        }
        let (conversation, name) = match g.gid {
            Some(gid) => (group_id_str(&gid), self.group_name(&gid)),
            None => (String::new(), LINK_CALL.into()),
        };
        self.ended(
            conversation,
            name,
            g.video,
            if note.is_empty() { &line } else { note },
        );
        // Dropping the sender ends the media task.
    }

    /// Turn down a group call that rings (it goes on without us).
    pub(super) fn decline_group_call(&mut self) {
        if self.group_call.as_ref().is_some_and(|g| !g.joined) {
            self.group_call = None;
        }
    }

    /// Group call signalling that a sync brought.
    pub(super) async fn on_group_call_message(
        &mut self,
        gid: [u8; 32],
        from: [u8; 64],
        bytes: &[u8],
    ) {
        let Ok(m) = GroupCallMessage::decode(bytes) else {
            return;
        };
        let me = self.client.as_ref().map(enclave_core::Client::root);
        let ours = me == Some(from);
        match m {
            GroupCallMessage::Start {
                call_id,
                secret,
                sfu,
                video,
                started_ms,
            } => {
                if self.group_calls.get(&gid).is_some_and(|k| k.id == call_id) {
                    return;
                }
                let stale = unix_ms().saturating_sub(started_ms) > OFFER_TTL * 1000;
                self.group_calls.insert(
                    gid,
                    Known {
                        id: call_id,
                        secret: secret.clone(),
                        sfu,
                        video,
                        started_ms,
                        in_call: HashSet::from([from]),
                        since: Instant::now(),
                    },
                );
                // Another of our devices started it, or it's old news (a
                // sync after a long time away): the group shows it, nothing
                // rings.
                if ours || stale {
                    return;
                }
                let starter = self
                    .client
                    .as_ref()
                    .and_then(|c| c.groups().into_iter().find(|g| g.id == gid))
                    .and_then(|g| g.members.into_iter().find(|(r, _)| *r == from))
                    .map(|(_, n)| n)
                    .unwrap_or_default();
                let line = if video {
                    format!("{starter} started a video call")
                } else {
                    format!("{starter} started a call")
                };
                self.group_line(&gid, &line);
                if self.call.is_some() || self.group_call.is_some() {
                    return;
                }
                let keys = CallKeys::group(call_id, &secret);
                self.group_call = Some(GroupCall {
                    id: call_id,
                    gid: Some(gid),
                    video,
                    joined: false,
                    live: false,
                    muted: false,
                    camera: video,
                    hand: false,
                    cameras_full: false,
                    me: 0,
                    keys,
                    secret,
                    sfu: None,
                    sfu_id: sfu,
                    started_ms,
                    link: None,
                    names: HashMap::new(),
                    leg: None,
                    tx: None,
                    heard: BTreeMap::new(),
                    created: Instant::now(),
                    connected_at: 0,
                });
                let named = self.client.as_ref().is_some_and(|c| c.previews());
                let name = self.group_name(&gid);
                let _ = self.out.send(Out::Notify(enclave_ipc::Notice {
                    conversation: group_id_str(&gid),
                    title: if video {
                        enclave_ipc::VIDEO_CALL_NOTICE
                    } else {
                        enclave_ipc::CALL_NOTICE
                    }
                    .into(),
                    body: if named { name } else { String::new() },
                }));
            }
            GroupCallMessage::Joined(id) => {
                if let Some(k) = self.group_calls.get_mut(&gid).filter(|k| k.id == id) {
                    k.in_call.insert(from);
                    k.since = Instant::now();
                }
            }
            GroupCallMessage::Left(id) => {
                let empty = match self.group_calls.get_mut(&gid).filter(|k| k.id == id) {
                    Some(k) => {
                        k.in_call.remove(&from);
                        k.since = Instant::now();
                        k.in_call.is_empty()
                    }
                    None => false,
                };
                if empty {
                    self.group_calls.remove(&gid);
                    self.decline_group_call();
                }
            }
            GroupCallMessage::End(id) => {
                if self.group_calls.get(&gid).is_some_and(|k| k.id == id) {
                    self.group_calls.remove(&gid);
                }
                match self.group_call.as_ref() {
                    Some(g) if g.id == id && !g.joined => self.group_call = None,
                    // Others may still be in it: the media tells.
                    _ => {}
                }
            }
        }
    }

    /// Start the media once our leg is up.
    async fn start_group_media(&mut self) {
        let Some(g) = self.group_call.as_ref() else {
            return;
        };
        if g.tx.is_some() || g.leg.is_none() {
            return;
        }
        let video = g.video;
        let codec = match self.media.open_call().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("enclave-vault: group call audio: {e}");
                self.leave_group_call("Couldn't start the call's audio.")
                    .await;
                return;
            }
        };
        let video = if video {
            match self.media.open_video(0).await {
                Ok(v) => Some((v, 0usize)),
                Err(e) => {
                    eprintln!("enclave-vault: group call video: {e}");
                    None
                }
            }
        } else {
            None
        };
        let name = self
            .client
            .as_ref()
            .map(|c| c.card().name)
            .unwrap_or_default();
        let Some(g) = self.group_call.as_mut() else {
            return;
        };
        let (Some(leg), Some(sfu)) = (g.leg.take(), g.sfu) else {
            return;
        };
        let (tx, rx) = mpsc::unbounded_channel();
        if g.muted {
            let _ = tx.send(ToCall::Mute(true));
        }
        if g.video && !g.camera {
            let _ = tx.send(ToCall::Camera(false));
        }
        g.tx = Some(tx);
        let plan = GroupPlan {
            id: g.id,
            keys: CallKeys::group(g.id, &g.secret),
            me: g.me,
            sfu,
            started_ms: g.started_ms,
            codec,
            video,
            name,
        };
        tokio::spawn(calls::run_group(
            leg,
            plan,
            rx,
            self.out.clone(),
            self.call_tx.clone(),
        ));
    }

    /// Whether an event is about the group call.
    pub(super) fn is_group_event(&self, ev: &CallEvent) -> bool {
        let id = match ev {
            CallEvent::Leg(id, _) | CallEvent::Media(id, _) | CallEvent::Direct(id, _) => id,
            _ => return false,
        };
        self.group_call.as_ref().is_some_and(|g| &g.id == id)
    }

    /// What the group call's leg or media reported.
    pub(super) async fn on_group_call_event(&mut self, ev: CallEvent) {
        match ev {
            CallEvent::Leg(_, Ok(leg)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.leg = Some(*leg);
                }
                self.start_group_media().await;
            }
            CallEvent::Leg(_, Err(e)) => {
                eprintln!("enclave-vault: group call relay: {e}");
                self.leave_group_call(NO_ROUTE).await;
            }
            CallEvent::Media(_, FromCall::Connected) => {
                let now = self.transport.now();
                if let Some(g) = self.group_call.as_mut() {
                    g.live = true;
                    g.connected_at = now;
                }
            }
            CallEvent::Media(_, FromCall::Dropped(why)) => self.leave_group_call(&why).await,
            CallEvent::Media(_, FromCall::Heard(who)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.heard.entry(who).or_default();
                }
            }
            CallEvent::Media(_, FromCall::Hand(who, up)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.heard.entry(who).or_default().hand = up;
                }
            }
            CallEvent::Media(_, FromCall::Name(who, n)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.names.insert(who, n);
                }
            }
            CallEvent::Media(_, FromCall::CamerasFull(full)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.cameras_full = full;
                }
            }
            CallEvent::Media(_, FromCall::React(who, r)) => {
                if let Some(g) = self.group_call.as_mut() {
                    g.heard.entry(who).or_default().reaction = Some((r, Instant::now()));
                }
            }
            _ => {}
        }
    }

    /// Raise or lower our hand.
    pub(super) fn call_hand(&mut self, up: bool) {
        if let Some(g) = self.group_call.as_mut().filter(|g| g.joined) {
            g.hand = up;
            if let Some(tx) = &g.tx {
                let _ = tx.send(ToCall::Hand(up));
            }
        }
    }

    /// A reaction everyone in the call sees for a moment.
    pub(super) fn call_react(&mut self, emoji: String) {
        if emoji.is_empty() || emoji.len() > calls::MAX_REACTION {
            return;
        }
        if let Some(tx) = self
            .group_call
            .as_ref()
            .filter(|g| g.joined)
            .and_then(|g| g.tx.as_ref())
        {
            let _ = tx.send(ToCall::React(emoji));
        }
    }

    /// Every tick: a call that rang unanswered stops; reactions fade; calls
    /// no one spoke of in hours are forgotten.
    pub(super) async fn group_call_upkeep(&mut self) {
        if let Some(g) = self.group_call.as_mut() {
            for h in g.heard.values_mut() {
                if h.reaction
                    .as_ref()
                    .is_some_and(|(_, at)| at.elapsed() > REACTION_SHOWN)
                {
                    h.reaction = None;
                }
            }
            if !g.joined && g.created.elapsed() > Duration::from_secs(OFFER_TTL) {
                self.group_call = None;
            }
        }
        let current = self.group_call.as_ref().and_then(|g| g.gid);
        self.group_calls
            .retain(|gid, k| Some(*gid) == current || k.since.elapsed() < KNOWN_FOR);
    }

    /// Groups with a call going on that we aren't in (they show a Join
    /// button).
    pub(super) fn live_groups(&self) -> Vec<String> {
        let current = self
            .group_call
            .as_ref()
            .filter(|g| g.joined)
            .and_then(|g| g.gid);
        self.group_calls
            .keys()
            .filter(|gid| Some(**gid) != current)
            .map(group_id_str)
            .collect()
    }

    /// The group call as the window shows it.
    pub(super) fn group_call_view(&self, g: &GroupCall) -> CallView {
        let (name, members) = self
            .client
            .as_ref()
            .and_then(|c| c.groups().into_iter().find(|i| Some(i.id) == g.gid))
            .map(|i| (i.name, i.members))
            .unwrap_or_else(|| (LINK_CALL.into(), Vec::new()));
        let names: HashMap<u32, String> = members
            .into_iter()
            .map(|(root, n)| (g.keys.participant(&root), n))
            .collect();
        let tier = enclave_media::callvideo::tier(0);
        CallView {
            state: match (g.joined, g.live) {
                (false, _) => 2,
                (true, false) => 3,
                (true, true) => 4,
            },
            conversation: g.gid.as_ref().map(group_id_str).unwrap_or_default(),
            name,
            video: g.video,
            muted: g.muted,
            camera: g.video && g.camera,
            video_width: if g.video { tier.width } else { 0 },
            video_height: if g.video { tier.height } else { 0 },
            connected_at: g.connected_at,
            group: true,
            hand: g.hand,
            cameras_full: g.cameras_full,
            link: g.link.as_ref().map(|l| l.text.clone()).unwrap_or_default(),
            knocks: g
                .link
                .as_ref()
                .map(super::call_links::HostedLink::knocks)
                .unwrap_or_default(),
            peers: g
                .heard
                .iter()
                .map(|(id, h)| CallPeer {
                    id: *id,
                    // Someone not in the group (a guest from a call link):
                    // the name they gave, marked as theirs.
                    name: names
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| match g.names.get(id) {
                            Some(n) => format!("{n} (guest)"),
                            None => "Someone".into(),
                        }),
                    hand: h.hand,
                    reaction: h
                        .reaction
                        .as_ref()
                        .map(|(r, _)| r.clone())
                        .unwrap_or_default(),
                })
                .collect(),
            ..Default::default()
        }
    }
}
