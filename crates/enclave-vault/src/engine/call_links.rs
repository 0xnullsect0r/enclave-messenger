//! The engine's call links (`docs/11-calls.md` §8.2): making one for the
//! group call we're in, its lobby, and joining a call from a link.
//!
//! ```text
//! host:    CreateCallLink → link (open, or with a lobby at the SFU)
//!          lobby: Knock → shown → AdmitToCall (the call's secret, sealed
//!          to the knocker) or RefuseFromCall
//! guest:   the link in Add → open: join; lobby: knock every 5 s → Admit →
//!          join the call; Refuse or 10 min → "The host didn't let you in."
//! ```

use super::Engine;
use super::group_calling::{GroupCall, LINK_CALL};
use crate::calls::{self, CallEvent, FromCall, LobbyPlan};
use enclave_calls::link::{self, CallLink, CallSecret, Knocker, LobbyMessage};
use enclave_calls::signal::CallKeys;
use enclave_crypto::rng::HedgedRng;
use enclave_ipc::{CallPeer, CallView};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A knock is repeated this often until the host answers.
const KNOCK_EVERY: Duration = Duration::from_secs(5);
/// How long someone waits in a lobby.
const WAIT_LIMIT: Duration = Duration::from_secs(600);
/// Most people waiting at once.
const MAX_KNOCKS: usize = 16;

/// The call link we made, and its lobby.
pub(super) struct HostedLink {
    link: CallLink,
    pub(super) text: String,
    lobby_id: [u8; 16],
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// Waiting: name and knock.
    knocks: BTreeMap<u32, (String, LobbyMessage)>,
    /// Answered (repeated if they knock again: they didn't hear it).
    answered: HashMap<u32, LobbyMessage>,
}

impl HostedLink {
    /// Who waits, for the window.
    pub(super) fn knocks(&self) -> Vec<CallPeer> {
        self.knocks
            .iter()
            .map(|(id, (name, _))| CallPeer {
                id: *id,
                name: name.clone(),
                ..Default::default()
            })
            .collect()
    }
}

/// Waiting in a call link's lobby.
pub(super) struct Waiting {
    link: CallLink,
    knocker: Knocker,
    lobby_id: [u8; 16],
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    knocked: Option<Instant>,
    since: Instant,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn lobby_id(link: &CallLink) -> [u8; 16] {
    let cap = link.cap();
    let mut id = [0u8; 16];
    id.copy_from_slice(&cap[..16]);
    id
}

impl Engine {
    fn my_name(&self) -> String {
        self.client
            .as_ref()
            .map(|c| c.card().name)
            .unwrap_or_default()
    }

    /// Make a link to the group call we're in.
    pub(super) fn create_call_link(&mut self, lobby: bool) {
        let domain = self
            .client
            .as_ref()
            .map(|c| c.card().server_domain)
            .unwrap_or_default();
        let relay = self.group_relay();
        let Some(g) = self.group_call.as_mut().filter(|g| g.joined) else {
            return;
        };
        if g.link.is_some() {
            return;
        }
        let Ok(mut rng) = HedgedRng::new() else {
            return;
        };
        let call = CallSecret {
            call_id: g.id,
            secret: g.secret.clone(),
            started_ms: g.started_ms,
        };
        let Ok(link) = CallLink::new(&call, g.sfu_id, g.video, lobby, unix_ms(), &mut rng) else {
            return;
        };
        let text = enclave_core::card::call_link_text(&link.encode(), &domain);
        let id = lobby_id(&link);
        g.link = Some(HostedLink {
            link,
            text,
            lobby_id: id,
            tx: None,
            knocks: BTreeMap::new(),
            answered: HashMap::new(),
        });
        if lobby {
            match relay {
                Some(r) => self.open_leg(id, r),
                None => self.status = "Couldn't open the link's waiting room right now.".into(),
            }
        }
    }

    /// A call link from the Add screen.
    pub(super) fn join_call_link(&mut self, payload: &[u8]) {
        if self.call.is_some() || self.group_call.as_ref().is_some_and(|g| g.joined) {
            self.status = "You're already in a call.".into();
            return;
        }
        let Ok(link) = CallLink::decode(payload) else {
            self.add_error = "That call link isn't complete. Ask for it again.".into();
            return;
        };
        if let Some(call) = link.open.clone() {
            self.join_as_guest(&link, call);
            return;
        }
        let (Ok(mut rng), Some(relay)) = (HedgedRng::new(), self.group_relay()) else {
            self.ended_link("Couldn't find a private route right now. Try again later.");
            return;
        };
        let Ok(knocker) = Knocker::new(&mut rng) else {
            return;
        };
        let id = lobby_id(&link);
        self.call_waiting = Some(Waiting {
            link,
            knocker,
            lobby_id: id,
            tx: None,
            knocked: None,
            since: Instant::now(),
        });
        self.open_leg(id, relay);
    }

    fn ended_link(&mut self, note: &str) {
        self.call_ended = Some((
            CallView {
                state: 5,
                name: LINK_CALL.into(),
                group: true,
                error: note.into(),
                ..Default::default()
            },
            Instant::now(),
        ));
    }

    /// Into the call itself, as a guest.
    fn join_as_guest(&mut self, link: &CallLink, call: CallSecret) {
        let sfu = self
            .relay_by_id(&link.sfu)
            .and_then(|r| r.addr.parse::<std::net::SocketAddr>().ok());
        let (Some(sfu), Some(relay), Some(me)) = (
            sfu,
            self.group_relay(),
            self.client.as_ref().map(enclave_core::Client::root),
        ) else {
            self.ended_link("Couldn't find a private route right now. Try again later.");
            return;
        };
        let keys = CallKeys::group(call.call_id, &call.secret);
        self.group_call = Some(GroupCall::guest(
            call.call_id,
            keys.participant(&me),
            keys,
            call.secret,
            link.video,
            sfu,
            link.sfu,
            call.started_ms,
        ));
        self.leg_for(call.call_id, relay);
    }

    /// Whether an event is about a call link's lobby.
    pub(super) fn is_lobby_event(&self, ev: &CallEvent) -> bool {
        let id = match ev {
            CallEvent::Leg(id, _) | CallEvent::Media(id, _) => id,
            _ => return false,
        };
        self.call_waiting
            .as_ref()
            .is_some_and(|w| &w.lobby_id == id)
            || self
                .group_call
                .as_ref()
                .and_then(|g| g.link.as_ref())
                .is_some_and(|l| &l.lobby_id == id)
    }

    /// What a lobby's leg or session reported.
    pub(super) async fn on_lobby_event(&mut self, ev: CallEvent) {
        let waiting = matches!(&ev, CallEvent::Leg(id, _) | CallEvent::Media(id, _)
            if self.call_waiting.as_ref().is_some_and(|w| &w.lobby_id == id));
        let me_root = self.client.as_ref().map(enclave_core::Client::root);
        match ev {
            CallEvent::Leg(id, Ok(leg)) => {
                let (keys, me, sfu_id, started) = if waiting {
                    let Some(w) = self.call_waiting.as_ref() else {
                        return;
                    };
                    (
                        w.link.lobby_keys(),
                        w.knocker.id(&w.link),
                        w.link.sfu,
                        w.link.created_ms,
                    )
                } else {
                    let Some(l) = self.group_call.as_ref().and_then(|g| g.link.as_ref()) else {
                        return;
                    };
                    let keys = l.link.lobby_keys();
                    let me = me_root.map(|r| keys.participant(&r)).unwrap_or_default();
                    (keys, me, l.link.sfu, l.link.created_ms)
                };
                let Some(sfu) = self
                    .relay_by_id(&sfu_id)
                    .and_then(|r| r.addr.parse::<std::net::SocketAddr>().ok())
                else {
                    return;
                };
                let (tx, rx) = mpsc::unbounded_channel();
                tokio::spawn(calls::run_lobby(
                    *leg,
                    LobbyPlan {
                        id,
                        keys,
                        me,
                        sfu,
                        started_ms: started,
                    },
                    rx,
                    self.call_tx.clone(),
                ));
                if waiting {
                    if let Some(w) = self.call_waiting.as_mut() {
                        w.tx = Some(tx);
                    }
                    self.knock();
                } else if let Some(l) = self.group_call.as_mut().and_then(|g| g.link.as_mut()) {
                    l.tx = Some(tx);
                }
            }
            CallEvent::Leg(_, Err(e)) | CallEvent::Media(_, FromCall::Dropped(e)) => {
                if waiting {
                    self.call_waiting = None;
                    self.ended_link(if e.is_empty() {
                        "Couldn't reach the call's waiting room."
                    } else {
                        &e
                    });
                } else if let Some(l) = self.group_call.as_mut().and_then(|g| g.link.as_mut()) {
                    eprintln!("enclave-vault: call link waiting room: {e}");
                    l.tx = None;
                }
            }
            CallEvent::Media(_, FromCall::Lobby(from, bytes)) => {
                let Ok(m) = LobbyMessage::decode(&bytes) else {
                    return;
                };
                if waiting {
                    self.on_lobby_answer(&m);
                } else {
                    self.on_knock(from, m);
                }
            }
            _ => {}
        }
    }

    /// Host: someone knocked.
    fn on_knock(&mut self, from: u32, m: LobbyMessage) {
        let Some(l) = self.group_call.as_mut().and_then(|g| g.link.as_mut()) else {
            return;
        };
        let LobbyMessage::Knock { name, .. } = &m else {
            return;
        };
        // The id is the knocker's key's: a knock under someone else's id
        // is someone else's to send.
        if link::knocker_id(&l.link, &m) != Some(from) {
            return;
        }
        if let Some(a) = l.answered.get(&from) {
            if let Some(tx) = &l.tx {
                let _ = tx.send(a.encode());
            }
            return;
        }
        if l.knocks.len() >= MAX_KNOCKS && !l.knocks.contains_key(&from) {
            return;
        }
        let name = if name.trim().is_empty() {
            "Someone".to_string()
        } else {
            name.clone()
        };
        l.knocks.insert(from, (name, m));
    }

    /// Let someone in.
    pub(super) fn admit_to_call(&mut self, who: u32) {
        let Some(g) = self.group_call.as_mut() else {
            return;
        };
        let call = CallSecret {
            call_id: g.id,
            secret: g.secret.clone(),
            started_ms: g.started_ms,
        };
        let Some(l) = g.link.as_mut() else {
            return;
        };
        let Some((_, knock)) = l.knocks.remove(&who) else {
            return;
        };
        let Ok(mut rng) = HedgedRng::new() else {
            return;
        };
        if let Ok((to, m)) = link::admit(&l.link, &knock, &call, &mut rng) {
            if let Some(tx) = &l.tx {
                let _ = tx.send(m.encode());
            }
            l.answered.insert(to, m);
        }
    }

    /// Turn someone away.
    pub(super) fn refuse_from_call(&mut self, who: u32) {
        let Some(l) = self.group_call.as_mut().and_then(|g| g.link.as_mut()) else {
            return;
        };
        if l.knocks.remove(&who).is_some() {
            let m = LobbyMessage::Refuse { to: who };
            if let Some(tx) = &l.tx {
                let _ = tx.send(m.encode());
            }
            l.answered.insert(who, m);
        }
    }

    /// Guest: the host's answer.
    fn on_lobby_answer(&mut self, m: &LobbyMessage) {
        let Some(w) = self.call_waiting.as_ref() else {
            return;
        };
        let me = w.knocker.id(&w.link);
        match m {
            LobbyMessage::Admit { to, .. } if *to == me => {
                let Ok(call) = w.knocker.open(&w.link, m) else {
                    return;
                };
                let Some(w) = self.call_waiting.take() else {
                    return;
                };
                // Dropping the waiting room's sender ends its session.
                self.join_as_guest(&w.link, call);
            }
            LobbyMessage::Refuse { to } if *to == me => {
                self.call_waiting = None;
                self.ended_link("The host didn't let you in.");
            }
            _ => {}
        }
    }

    fn knock(&mut self) {
        let name = self.my_name();
        let Some(w) = self.call_waiting.as_mut() else {
            return;
        };
        if let Some(tx) = &w.tx {
            let _ = tx.send(w.knocker.knock(&name).encode());
            w.knocked = Some(Instant::now());
        }
    }

    /// Every tick: knock again while no answer comes; give up after a
    /// while.
    pub(super) fn call_link_upkeep(&mut self) {
        let Some(w) = self.call_waiting.as_ref() else {
            return;
        };
        if w.since.elapsed() > WAIT_LIMIT {
            self.call_waiting = None;
            self.ended_link("The host didn't let you in.");
            return;
        }
        if w.tx.is_some() && w.knocked.is_none_or(|k| k.elapsed() > KNOCK_EVERY) {
            self.knock();
        }
    }

    /// Stop waiting.
    pub(super) fn leave_lobby(&mut self) -> bool {
        self.call_waiting.take().is_some()
    }

    /// Waiting in a lobby, as the window shows it.
    pub(super) fn waiting_view(&self) -> Option<CallView> {
        let w = self.call_waiting.as_ref()?;
        Some(CallView {
            state: 1,
            name: LINK_CALL.into(),
            group: true,
            video: w.link.video,
            error: if w.tx.is_some() {
                "Waiting for the host to let you in…".into()
            } else {
                String::new()
            },
            ..Default::default()
        })
    }
}
