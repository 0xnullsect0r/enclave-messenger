//! The engine: owns the `Client`, runs the foreground tick and turns UI
//! commands into protocol actions. Its only outputs are display snapshots and
//! UI resets ([`Out`]); nothing secret crosses to the UI.

use enclave_core::{
    Client, ContactCard, ContactState, CoreError, Event, LinkError, Options, Place, TicketWallet,
};
use enclave_crypto::pwhash::PwParams;
use enclave_ipc::{Cmd, Device, Effect, Msg, Out, Pick, Row, Snapshot, tint_for};
use enclave_net::schedule::Profile;
use enclave_net::shaped::{ShapedTransport, Shaping};
use enclave_net::transport::{Route, ServerId, TcpTransport, Transport};
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, MemoryKeystore};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Foreground tick (docs/09-transport.md §9.4).
const TICK: Duration = Duration::from_secs(3);
/// Sync rounds between looks at the mixnet tickets (about 5 minutes).
const TICKET_UPKEEP_ROUNDS: u64 = 100;
/// After a failed start of the mixnet client, wait this long to try again.
const MIXNET_RETRY: u64 = 60;
/// Failed sync rounds in a row (about a minute) before the backup route
/// is offered.
const OFFER_BACKUP_AFTER: u32 = 20;

/// Where the account lives.
#[derive(Clone, Debug, PartialEq, Eq)]
// Made once at start; its size doesn't matter (paths are larger on Windows).
#[allow(clippy::large_enum_variant)]
pub enum Mode {
    /// Everything in memory with a local server and a demo contact.
    Demo,
    /// A profile on disk, its servers reached over the mixnet (or, in
    /// development, TCP).
    Server {
        /// Profile directory.
        profile: PathBuf,
        /// The home server's id: its key bundle must be signed by the
        /// identity this id is derived from.
        server: ServerId,
        /// How the home server is reached.
        route: Route,
        /// Other servers this build reaches directly (more `--server`
        /// flags: development routes).
        others: Vec<(ServerId, Route)>,
        /// The mixnet client takes its network from `NYM_*` variables (a
        /// local mixnet, the sandbox) instead of mainnet (`--nym-env`).
        nym_env: bool,
        /// Key-transparency pins for usernames (written by the dev server).
        kt_pins: Option<PathBuf>,
        /// The foundation's public key, when not built in.
        foundation: Option<PathBuf>,
        /// A signed server list to offer at start, when not built in.
        server_list: Option<PathBuf>,
        /// Shape traffic on the scheduler's clock (`--no-shaping` turns it
        /// off, for development).
        shaping: bool,
    },
}

impl Mode {
    /// Parse `--server HEXID=ROUTE --profile DIR [--kt-pins FILE]`, a
    /// route being `nym:ADDRESS` or (development) `HOST:PORT`
    /// (`enclave-server show-id` prints the id); without `--server` it is
    /// the demo. A `--server` that doesn't parse, or one without
    /// `--profile`, is an error rather than a quiet fall back to the demo.
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let arg = |k: &str| {
            args.iter()
                .position(|a| a == k)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        let mut servers = Vec::new();
        for pair in args.windows(2).filter(|p| p[0] == "--server") {
            servers.push(
                enclave_net::transport::parse_route(&pair[1]).ok_or_else(|| {
                    format!(
                        "--server {}: expected SERVER_ID=nym:ADDRESS or SERVER_ID=HOST:PORT",
                        pair[1]
                    )
                })?,
            );
        }
        if servers.is_empty() {
            return Ok(Mode::Demo);
        }
        let (server, route) = servers.remove(0);
        let profile = arg("--profile").ok_or("--server needs --profile DIR")?;
        Ok(Mode::Server {
            profile: profile.into(),
            server,
            route,
            others: servers,
            nym_env: args.iter().any(|a| a == "--nym-env"),
            kt_pins: arg("--kt-pins").map(Into::into),
            foundation: arg("--foundation").map(Into::into),
            server_list: arg("--server-list").map(Into::into),
            shaping: !args.iter().any(|a| a == "--no-shaping"),
        })
    }

    /// Inverse of [`Mode::from_args`].
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Mode::Demo => vec!["--demo".into()],
            Mode::Server {
                profile,
                server,
                route,
                others,
                nym_env,
                kt_pins,
                foundation,
                server_list,
                shaping,
            } => {
                let hex =
                    |id: &ServerId| -> String { id.iter().map(|b| format!("{b:02x}")).collect() };
                let mut v = vec![
                    "--server".into(),
                    format!("{}={route}", hex(server)),
                    "--profile".into(),
                    profile.display().to_string(),
                ];
                for (id, a) in others {
                    v.push("--server".into());
                    v.push(format!("{}={a}", hex(id)));
                }
                for (flag, path) in [
                    ("--kt-pins", kt_pins),
                    ("--foundation", foundation),
                    ("--server-list", server_list),
                ] {
                    if let Some(p) = path {
                        v.push(flag.into());
                        v.push(p.display().to_string());
                    }
                }
                if !shaping {
                    v.push("--no-shaping".into());
                }
                if *nym_env {
                    v.push("--nym-env".into());
                }
                v
            }
        }
    }
}

/// The foundation key and list for `mode`: the files it names, else what
/// the build has built in. The demo uses neither.
fn federation(
    mode: &Mode,
) -> (
    Option<enclave_federation::FoundationPublic>,
    Option<Vec<u8>>,
) {
    let Mode::Server {
        foundation,
        server_list,
        ..
    } = mode
    else {
        return (None, None);
    };
    let read = |p: &Option<PathBuf>, built: Option<&[u8]>| match p {
        Some(p) => match std::fs::read(p) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("enclave-vault: {}: {e}", p.display());
                None
            }
        },
        None => built.map(<[u8]>::to_vec),
    };
    let key = read(foundation, crate::built::FOUNDATION_PUB).and_then(|b| {
        enclave_federation::FoundationPublic::decode(&b)
            .map_err(|e| eprintln!("enclave-vault: foundation key: {e}"))
            .ok()
    });
    (key, read(server_list, crate::built::SERVER_LIST))
}

const DEMO_SERVER: ServerId = [0x5e; 16];

const SAM_HELLO: &str = "Hi, I'm Sam. I'm a demo contact running on this computer, so you can try Enclave before inviting anyone. Accept to start talking.";
const SAM_REPLIES: [&str; 5] = [
    "Every message travels as a sealed unit of exactly the same size, so a server can't tell a short hello from a long letter.",
    "Try the \"Check code\" button above. With a real person you'd compare those numbers face to face or on a call.",
    "In demo mode nothing you type leaves this computer.",
    "When you're ready, share your invite link with someone you trust.",
    "People can also find you by username, if you choose one in Settings. Mine is @sam@demo.enclave.",
];

const DEMO_DOMAIN: &str = "demo.enclave";

struct Demo {
    sam: Client,
    replies: usize,
}

/// Processes the vault hands work to (`docs/15-client.md` §1.1a).
#[derive(Default)]
pub struct Helpers {
    /// netd, for the network in server mode.
    pub net: Option<Arc<dyn Transport>>,
    /// mediad, for pictures (in-process decoding when absent).
    pub media: Option<crate::media::Media>,
}

/// Longest side of a preview sent to the UI.
const PREVIEW_SIDE: u16 = 560;
/// Largest attachment downloaded on its own for a preview.
const PREVIEW_MAX_BYTES: u64 = 16 << 20;

struct Engine {
    mode: Mode,
    media: crate::media::Media,
    /// Previews already sent to the UI (conversation, message position).
    previews: std::collections::HashSet<(String, u64)>,
    /// Voice notes' duration and waveform, by (conversation, position),
    /// read by mediad.
    voice: HashMap<(String, u64), (u32, Vec<u8>)>,
    transport: Arc<dyn Transport>,
    /// The traffic shaper, in server mode (`enclave_net::shaped`).
    shaper: Option<Arc<ShapedTransport>>,
    /// Rounds of shaped syncing so far.
    round: u64,
    server: ServerId,
    client: Option<Client>,
    demo: Option<Demo>,
    selected: Option<[u8; 64]>,
    selected_group: Option<[u8; 32]>,
    /// Note to self is open.
    selected_notes: bool,
    picked: BTreeSet<[u8; 64]>,
    link_offer: Option<enclave_core::LinkOffer>,
    link_status: String,
    status: String,
    add_error: String,
    username_error: String,
    kt: Option<enclave_core::KtPolicy>,
    /// The foundation's key (built in, or `--foundation`).
    foundation: Option<enclave_federation::FoundationPublic>,
    /// A server list to offer the account at start (built in, or
    /// `--server-list`).
    list: Option<Vec<u8>>,
    /// The day the server list was last refreshed from the home server.
    list_day: u64,
    /// This device, while it is being linked to an existing account.
    joining: Option<enclave_core::LinkingDevice>,
    join_code: String,
    join_words: String,
    busy: bool,
    /// The recovery sheet is open: only then do the words leave the vault.
    reveal_words: bool,
    /// The profile on disk needs its passphrase to open.
    locked: bool,
    unlock_error: String,
    /// The open profile has a passphrase (so "Lock now" makes sense).
    passphrase_set: bool,
    search: String,
    username_problem: String,
    meet_code: String,
    meet_words: String,
    meet_name: String,
    meet_error: String,
    meet_done: String,
    restore_error: String,
    /// Contacts typing, until when (an indicator lasts
    /// `TYPING_SHOW_SECS` unless renewed: a "stopped" may never arrive).
    typing_until: HashMap<[u8; 64], std::time::Instant>,
    /// When we last told each contact we were typing.
    typing_sent: HashMap<[u8; 64], std::time::Instant>,
    /// Clips' lengths (ms), by (conversation, message position), read from
    /// their headers by mediad.
    clips: HashMap<(String, u64), u32>,
    /// Conversation ids of contacts who changed their recovery words, old
    /// to new, so a window still showing the old id keeps working.
    renamed: HashMap<String, String>,
    /// The contact whose recovery share is on screen (only while shown).
    reveal_share: Option<[u8; 64]>,
    /// The mixnet client has been given its tickets (or told there are
    /// none to wait for).
    mixnet_up: bool,
    /// When to try starting it again after a failure.
    mixnet_retry_at: u64,
    /// Tickets bought before there was a profile to keep them in.
    prewallet: Option<TicketWallet>,
    /// Sync rounds that failed on the network, in a row.
    net_failures: u32,
    /// On the backup route (the user chose it).
    backup_route: bool,
    /// The user said "Keep waiting": not offered again until the mixnet
    /// has worked once more.
    backup_declined: bool,
    /// Tor didn't come up (netd says so).
    tor_blocked: bool,
    /// The bridges netd started with, and what is set now.
    bridges_at_start: String,
    bridges: String,
    bridges_error: String,
    out: mpsc::UnboundedSender<Out>,
}

/// Run the engine on a thread of this process (where a separate vault
/// process is not available). Returns the command sender and output receiver.
pub fn spawn(mode: Mode) -> (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Out>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("enclave-engine".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(run(mode, rx, out_tx));
        })
        .ok();
    (tx, out_rx)
}

fn hex_id(root: &[u8; 64]) -> String {
    root[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn group_id_str(gid: &[u8; 32]) -> String {
    let h: String = gid[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("g{h}")
}

fn clock(at: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(at as i64, 0)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_default()
}

/// Media type from a file name (what the sender says; receivers never open
/// files by it).
fn mime_for(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Edits are allowed for 24 hours (`docs/16-features.md`).
const EDIT_WINDOW: u64 = 24 * 3600;

/// MIME type of a voice note (`enclave_media::voice`).
const VOICE_MIME: &str = "audio/x-enclave-voice";
/// File name of a voice note.
const VOICE_NAME: &str = "voice-note.evn";

fn is_voice(a: &enclave_core::files::Attachment) -> bool {
    a.mime == VOICE_MIME && a.size <= PREVIEW_MAX_BYTES
}

/// Sticker pictures are re-encoded to at most this many pixels a side.
const STICKER_SIDE: u16 = 512;
/// Sticker thumbnails in the picker.
const PICKER_SIDE: u16 = 160;

/// A short opaque id for a 32-byte key (the UI never sees the key).
fn hex_short(k: &[u8; 32]) -> String {
    k[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// The id the UI uses for the note-to-self conversation.
const NOTES_ID: &str = "notes";

/// How a group message reads in the conversation.
fn group_text(m: &enclave_core::GroupMessage) -> String {
    if m.deleted {
        return "This message was deleted.".into();
    }
    let mut text = match &m.attachment {
        // The UI shows the picture (or its name until it arrives).
        Some(a) if is_picture(a) => m.text.clone(),
        Some(a) if m.text.is_empty() => format!("File: {}", a.name),
        Some(a) => format!("File: {}\n{}", a.name, m.text),
        None => m.text.clone(),
    };
    if m.edited {
        text.push_str(" (edited)");
    }
    for r in &m.reactions {
        text.push_str(&format!("  {}", r.emoji));
    }
    text
}

/// The list flags of a conversation.
fn prefs_row(p: enclave_core::ConvPrefs) -> Row {
    Row {
        pinned: p.pinned,
        muted: p.muted,
        archived: p.archived,
        ..Default::default()
    }
}

/// Longest pinned-message line, in characters.
const PIN_CHARS: usize = 80;

/// One line for the pinned-message bar: the first line of the text, cut to
/// [`PIN_CHARS`] (a file without a caption reads "File").
fn pin_text(text: &str, file: bool) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return if file { "File".into() } else { String::new() };
    }
    let mut out: String = line.chars().take(PIN_CHARS).collect();
    if line.chars().count() > PIN_CHARS {
        out.push('…');
    }
    out
}

/// How a stored message reads in the conversation.
fn display(m: &enclave_core::Message, now: u64) -> Msg {
    let mut text = if m.deleted {
        "This message was deleted.".to_string()
    } else if m.attachment.as_ref().is_some_and(is_picture) {
        // The UI shows the picture (or its name until it arrives).
        m.text.clone()
    } else if let Some(a) = &m.attachment {
        let kind = if a.mime.starts_with("image/") {
            "Photo"
        } else {
            "File"
        };
        if m.text.is_empty() {
            format!("{kind}: {}", a.name)
        } else {
            format!("{kind}: {}\n{}", a.name, m.text)
        }
    } else {
        m.text.clone()
    };
    if m.edited && !m.deleted {
        text.push_str(" (edited)");
    }
    for r in &m.reactions {
        text.push_str(&format!("  {}", r.emoji));
    }
    // 0 sending privately, 1 on its way, 2 delivered (their receipt),
    // 3 read, 4 not delivered yet (no receipt after every re-send).
    let status = if !m.outgoing || m.read {
        3
    } else if m.delivered {
        2
    } else if m.stalled {
        4
    } else if m.sent {
        1
    } else {
        0
    };
    let mut time = clock(m.at);
    if m.expires_secs > 0 {
        time.push_str(" · disappears");
    }
    Msg {
        text,
        outgoing: m.outgoing,
        time,
        status,
        sender: String::new(),
        seq: m.seq,
        can_edit: m.outgoing
            && !m.deleted
            && m.attachment.is_none()
            && now.saturating_sub(m.at) < EDIT_WINDOW,
        deleted: m.deleted,
        file: m
            .attachment
            .as_ref()
            .filter(|_| !m.deleted)
            .map(|a| a.name.clone())
            .unwrap_or_default(),
        image: m
            .attachment
            .as_ref()
            .is_some_and(|a| !m.deleted && is_picture(a)),
        ..Default::default()
    }
}

/// An attachment we'd preview: a JPEG or PNG (by its stated type; the bytes
/// are checked again before decoding) of a size worth fetching on its own.
fn is_picture(a: &enclave_core::files::Attachment) -> bool {
    (matches!(a.mime.as_str(), "image/jpeg" | "image/png") || is_clip(a))
        && a.size <= PREVIEW_MAX_BYTES
}

/// An animated picture (a short AV1 clip): previewed by its poster.
fn is_clip(a: &enclave_core::files::Attachment) -> bool {
    a.mime == enclave_media::video::CLIP_MIME && a.size <= PREVIEW_MAX_BYTES
}

/// Longest side of a clip's frames in the player.
const PLAYER_SIDE: u16 = 360;

/// Decode a picture's preview, or a clip's poster (and note its
/// length), and send it to the window.
async fn send_preview(
    media: &crate::media::Media,
    clips: &mut HashMap<(String, u64), u32>,
    out: &mpsc::UnboundedSender<Out>,
    id: &str,
    seq: u64,
    bytes: Vec<u8>,
) {
    let t = if enclave_media::video::is_clip(&bytes) {
        match media.clip_poster(bytes, PREVIEW_SIDE).await {
            Ok((t, ms)) => {
                clips.insert((id.to_string(), seq), ms);
                t
            }
            Err(_) => return,
        }
    } else if enclave_media::detect(&bytes).is_some() {
        match media.thumbnail(bytes, PREVIEW_SIDE).await {
            Ok(t) => t,
            Err(_) => return,
        }
    } else {
        return;
    };
    let _ = out.send(Out::Preview(enclave_ipc::Preview {
        conversation: id.to_string(),
        seq,
        width: t.width,
        height: t.height,
        pixels: t.pixels,
    }));
}

/// `name` with its extension replaced by `ext`.
fn with_extension(name: &str, ext: &str) -> String {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let stem = if stem.is_empty() { "picture" } else { stem };
    format!("{stem}.{ext}")
}

fn link_error(e: &CoreError) -> String {
    use enclave_core::UsernameError as U;
    match e {
        CoreError::Username(U::Unavailable) => "Usernames aren't available on that server. Ask them for their invite link instead.".into(),
        CoreError::Username(U::NotAllowed) => "That isn't a valid username. Usernames are 3 to 32 letters, numbers or _, and start with a letter.".into(),
        CoreError::Username(U::NotFound | U::Taken) => "Nobody has that username. Check the spelling, or ask them for their invite link.".into(),
        CoreError::Username(U::Unverified) => "Enclave couldn't confirm that this username is genuine, so it didn't add anyone. Ask them for their invite link instead.".into(),
        CoreError::Link(LinkError::DeviceLinkCode) => "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into(),
        CoreError::Link(LinkError::MeetCode) => "That's an in-person code. It only works in Meet in person, with them next to you.".into(),
        CoreError::Link(LinkError::NotEnclave) => "That isn't an Enclave invite link.".into(),
        CoreError::Link(LinkError::Malformed) => "This link is damaged. Ask them to send it again.".into(),
        CoreError::Link(LinkError::OwnCode) => "That's your own invite link.".into(),
        CoreError::Link(LinkError::AlreadyContact) => "You already talk to the person who sent this group link. Ask them to add you to the group.".into(),
        CoreError::Link(LinkError::InviteUsed) => "This invite link was already used, has expired or was cancelled. Ask them for a new one.".into(),
        CoreError::Net(_) => "Couldn't reach their server. Check your connection and try again.".into(),
        _ => "Couldn't add them with this link. Ask them to send a new one.".into(),
    }
}

fn username_error(e: &CoreError) -> String {
    use enclave_core::UsernameError as U;
    match e {
        CoreError::Username(U::Unavailable) => {
            "Usernames aren't available on your server yet.".into()
        }
        CoreError::Username(U::NotAllowed) => {
            "Use 3 to 32 letters, numbers or _, starting with a letter.".into()
        }
        CoreError::Username(U::Taken) => {
            "That name is taken, or looks too much like one that is. Try another.".into()
        }
        CoreError::Net(_) => {
            "Couldn't reach your server. Check your connection and try again.".into()
        }
        _ => "Couldn't claim that name. Try again in a moment.".into(),
    }
}

/// Run the engine until the command channel closes.
pub async fn run(mode: Mode, rx: mpsc::UnboundedReceiver<Cmd>, out: mpsc::UnboundedSender<Out>) {
    run_with(mode, Helpers::default(), rx, out).await;
}

/// [`run`], reaching the server in server mode through `net` (netd) instead
/// of opening connections from this process.
pub async fn run_with(
    mode: Mode,
    helpers: Helpers,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    out: mpsc::UnboundedSender<Out>,
) {
    let mut shaper: Option<Arc<ShapedTransport>> = None;
    let (transport, server, kt): (Arc<dyn Transport>, ServerId, _) = match &mode {
        Mode::Demo => {
            let t = LocalTransport::new();
            let _ = t.add_server(enclave_server::Config {
                id: DEMO_SERVER,
                effort_request: 4,
                effort_claim: 1,
                effort_blob: 1,
                effort_username: 4,
                effort_inbox: 1,
                ..Default::default()
            });
            let kt = t.enable_usernames(&DEMO_SERVER, DEMO_DOMAIN);
            (Arc::new(t), DEMO_SERVER, kt)
        }
        Mode::Server {
            server,
            route,
            others,
            kt_pins,
            shaping,
            ..
        } => {
            let id = *server;
            let kt = kt_pins
                .as_ref()
                .and_then(|p| std::fs::read(p).ok())
                .and_then(|b| enclave_core::KtPolicy::decode(&b).ok());
            let t: Arc<dyn Transport> = match helpers.net {
                Some(t) => t,
                None => {
                    // Without netd only the development TCP routes work:
                    // the mixnet client is netd's.
                    let mut routes = HashMap::new();
                    for (s, r) in
                        std::iter::once((id, route)).chain(others.iter().map(|(s, r)| (*s, r)))
                    {
                        match r {
                            Route::Tcp(a) => {
                                routes.insert(s, *a);
                            }
                            Route::Nym(_) | Route::Onion(_) => {
                                eprintln!(
                                    "enclave-vault: no netd, so no mixnet or Tor route to a server"
                                );
                            }
                        }
                    }
                    Arc::new(TcpTransport::new(routes))
                }
            };
            // Shaped on the scheduler's clock: the Standard profile until
            // the profile's own setting is read.
            let t: Arc<dyn Transport> = if *shaping {
                let s = ShapedTransport::start(t, Shaping::On(Profile::Foreground), vec![id]);
                shaper = Some(Arc::clone(&s));
                s
            } else {
                t
            };
            (t, id, kt)
        }
    };
    let (foundation, list) = federation(&mode);
    let mut e = Engine {
        mode,
        media: helpers
            .media
            .unwrap_or_else(crate::media::Media::in_process),
        previews: std::collections::HashSet::new(),
        voice: HashMap::new(),
        shaper,
        round: 0,
        transport,
        server,
        client: None,
        demo: None,
        selected: None,
        selected_group: None,
        selected_notes: false,
        picked: BTreeSet::new(),
        link_offer: None,
        link_status: String::new(),
        status: String::new(),
        add_error: String::new(),
        username_error: String::new(),
        kt,
        foundation,
        list,
        list_day: 0,
        joining: None,
        join_code: String::new(),
        join_words: String::new(),
        busy: false,
        reveal_words: false,
        locked: false,
        unlock_error: String::new(),
        passphrase_set: false,
        search: String::new(),
        username_problem: String::new(),
        meet_code: String::new(),
        meet_words: String::new(),
        meet_name: String::new(),
        meet_error: String::new(),
        meet_done: String::new(),
        restore_error: String::new(),
        typing_until: HashMap::new(),
        typing_sent: HashMap::new(),
        renamed: HashMap::new(),
        clips: HashMap::new(),
        reveal_share: None,
        mixnet_up: false,
        mixnet_retry_at: 0,
        prewallet: None,
        net_failures: 0,
        backup_route: false,
        backup_declined: false,
        tor_blocked: false,
        bridges_at_start: String::new(),
        bridges: String::new(),
        bridges_error: String::new(),
        out,
    };
    // Reopen an existing profile.
    if let Mode::Server { profile, .. } = &e.mode
        && profile.join("profile.redb").exists()
    {
        match Client::open(e.options(None), Arc::clone(&e.transport)) {
            Ok(mut c) => {
                e.configure(&mut c);
                e.client = Some(c);
            }
            // Protected by a passphrase: ask for it.
            Err(CoreError::Store(enclave_store::StoreError::Crypto)) => e.locked = true,
            Err(err) => e.status = format!("Couldn't open your profile: {err}"),
        }
        e.apply_privacy();
        e.push();
    }
    if let Mode::Server { profile, .. } = &e.mode {
        let b = std::fs::read_to_string(profile.join(crate::netd::BRIDGES_FILE))
            .unwrap_or_default()
            .trim()
            .to_string();
        e.bridges_at_start = b.clone();
        e.bridges = b;
    }
    e.check_tor().await;
    e.ensure_mixnet().await;
    let mut tick = tokio::time::interval(TICK);
    let mut ticks: u64 = 0;
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                // Keystrokes change nothing the window shows.
                let quiet = matches!(cmd, Cmd::Typing(..));
                e.handle(cmd).await;
                if !quiet {
                    e.push();
                    e.load_media().await;
                }
            }
            _ = tick.tick() => {
                ticks += 1;
                // Now and then: is Tor up (or blocked, so bridges may help)?
                if ticks.is_multiple_of(20) {
                    e.check_tor().await;
                    e.push();
                }
                e.ensure_mixnet().await;
                if e.client.is_some() {
                    e.sync().await;
                    e.push();
                    e.load_media().await;
                } else if e.joining.is_some() {
                    e.poll_join().await;
                    e.push();
                }
            }
        }
    }
}

impl Engine {
    /// Storage options; `passphrase` applies to profiles on disk (the demo
    /// lives in memory).
    fn options(&self, passphrase: Option<&str>) -> Options {
        let passphrase = passphrase
            .filter(|p| !p.is_empty())
            .map(|p| zeroize::Zeroizing::new(p.as_bytes().to_vec()));
        match &self.mode {
            Mode::Demo => Options {
                path: None,
                keystore: Arc::new(MemoryKeystore::default()),
                passphrase: None,
                pw_params: PwParams::FLOOR,
            },
            Mode::Server { profile, .. } => {
                let _ = std::fs::create_dir_all(profile);
                let keystore: Arc<dyn enclave_store::Keystore> =
                    match FileKeystore::new(profile.join("keys")) {
                        Ok(k) => Arc::new(k),
                        Err(_) => Arc::new(MemoryKeystore::default()),
                    };
                Options {
                    path: Some(profile.join("profile.redb")),
                    keystore,
                    passphrase,
                    // Argon2id, 1 GiB and 4 passes: seconds to unlock, slow
                    // to guess.
                    pw_params: PwParams::DESKTOP_DEFAULT,
                }
            }
        }
    }

    fn group_of(&self, id: &str) -> Option<[u8; 32]> {
        self.client
            .as_ref()?
            .groups()
            .into_iter()
            .map(|g| g.id)
            .find(|g| group_id_str(g) == id)
    }

    fn root_of(&self, id: &str) -> Option<[u8; 64]> {
        let mut id = id;
        for _ in 0..8 {
            match self.renamed.get(id) {
                Some(n) => id = n,
                None => break,
            }
        }
        self.client
            .as_ref()?
            .contacts()
            .into_iter()
            .map(|c| c.root)
            .find(|r| hex_id(r) == id)
    }

    /// Send the UI previews of pictures in the open conversation: fetched
    /// (people we accepted only, never message requests), decoded by
    /// mediad, a few per pass.
    /// Read the duration and waveform of voice notes in the open
    /// conversation (fetched, checked and read by mediad), a few per pass.
    /// Returns whether anything new is known.
    async fn load_voice(&mut self) -> bool {
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        let (conv, notes): (String, Vec<(u64, enclave_core::files::Attachment)>) =
            if let Some(gid) = self.selected_group {
                (
                    group_id_str(&gid),
                    c.group_messages(&gid)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|m| !m.deleted)
                        .filter_map(|m| m.attachment.filter(is_voice).map(|a| (m.seq, a)))
                        .collect(),
                )
            } else if let Some(root) = self.selected {
                if c.contact(&root).map(|ct| ct.state) != Some(ContactState::Accepted) {
                    return false;
                }
                (
                    hex_id(&root),
                    c.messages(&root)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|m| !m.deleted)
                        .filter_map(|m| m.attachment.filter(is_voice).map(|a| (m.seq, a)))
                        .collect(),
                )
            } else {
                return false;
            };
        let mut changed = false;
        let todo: Vec<(u64, enclave_core::files::Attachment)> = notes
            .into_iter()
            .rev()
            .filter(|(s, _)| !self.voice.contains_key(&(conv.clone(), *s)))
            .take(4)
            .collect();
        for (seq, att) in todo {
            let Ok(bytes) = c.fetch_file(&att).await else {
                continue;
            };
            // A note mediad can't read shows as a plain file from now on.
            let info = self
                .media
                .voice_info(bytes)
                .await
                .unwrap_or((0, Vec::new()));
            self.voice.insert((conv.clone(), seq), info);
            changed = true;
        }
        changed
    }

    /// Previews and voice-note details for the open conversation: their
    /// downloads are a bulk transfer.
    async fn load_media(&mut self) {
        self.bulk(true);
        self.load_previews().await;
        let voice = self.load_voice().await;
        self.bulk(false);
        if voice {
            self.push();
        }
    }

    /// What saving a file writes: a voice note becomes a WAV file anyone
    /// can play (decoded by mediad); anything else is saved as it is.
    async fn exportable(&self, name: String, bytes: Vec<u8>) -> (String, Vec<u8>) {
        if name.ends_with(".evn")
            && let Ok(wav) = self.media.voice_wav(bytes.clone()).await
        {
            return (with_extension(&name, "wav"), wav);
        }
        (name, bytes)
    }

    async fn load_previews(&mut self) {
        if let Some(gid) = self.selected_group {
            return self.load_group_previews(gid).await;
        }
        let (Some(root), Some(c)) = (self.selected, self.client.as_mut()) else {
            return;
        };
        if c.contact(&root).map(|ct| ct.state) != Some(enclave_core::ContactState::Accepted) {
            return;
        }
        let id = hex_id(&root);
        let Ok(msgs) = c.messages(&root) else {
            return;
        };
        let want: Vec<(u64, Option<(enclave_core::files::Attachment, u8)>)> = msgs
            .iter()
            .rev()
            .filter(|m| {
                !m.deleted && (m.sticker.is_some() || m.attachment.as_ref().is_some_and(is_picture))
            })
            .map(|m| {
                (
                    m.seq,
                    m.sticker.zip(m.attachment.clone()).map(|(i, a)| (a, i)),
                )
            })
            .filter(|(s, _)| !self.previews.contains(&(id.clone(), *s)))
            .take(4)
            .collect();
        for (seq, sticker) in want {
            // A download that fails is tried again next time; a picture
            // that doesn't decode is not.
            let fetched = match sticker {
                Some((att, i)) => c.sticker_picture(&att, i).await,
                None => c.fetch_attachment(&root, seq).await,
            };
            let Ok(bytes) = fetched else {
                continue;
            };
            self.previews.insert((id.clone(), seq));
            send_preview(&self.media, &mut self.clips, &self.out, &id, seq, bytes).await;
        }
    }

    /// Previews in the open group: its members' pictures (a group we are
    /// in, so never strangers' requests), the same way as for a contact.
    async fn load_group_previews(&mut self, gid: [u8; 32]) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        let id = group_id_str(&gid);
        let Ok(msgs) = c.group_messages(&gid) else {
            return;
        };
        let want: Vec<(u64, Option<(enclave_core::files::Attachment, u8)>)> = msgs
            .iter()
            .rev()
            .filter(|m| {
                !m.deleted && (m.sticker.is_some() || m.attachment.as_ref().is_some_and(is_picture))
            })
            .map(|m| {
                (
                    m.seq,
                    m.sticker.zip(m.attachment.clone()).map(|(i, a)| (a, i)),
                )
            })
            .filter(|(s, _)| !self.previews.contains(&(id.clone(), *s)))
            .take(4)
            .collect();
        for (seq, sticker) in want {
            let fetched = match sticker {
                Some((att, i)) => c.sticker_picture(&att, i).await,
                None => c.fetch_group_attachment(&gid, seq).await,
            };
            let Ok(bytes) = fetched else {
                continue;
            };
            self.previews.insert((id.clone(), seq));
            send_preview(&self.media, &mut self.clips, &self.out, &id, seq, bytes).await;
        }
    }

    async fn handle(&mut self, cmd: Cmd) {
        // Setting up, restoring and linking need the mixnet.
        if matches!(cmd, Cmd::Create(..) | Cmd::Restore(..)) || self.client.is_some() {
            self.ensure_mixnet().await;
        }
        // Transfers the spec counts as bulk (account setup, files, history,
        // joins, restore): disclosed bursts, except in Maximum.
        let bulk = matches!(
            cmd,
            Cmd::Create(..)
                | Cmd::Restore(..)
                | Cmd::SendFile(..)
                | Cmd::SaveFile(..)
                | Cmd::CreatePack(..)
                | Cmd::AddPack(..)
                | Cmd::LoadStickers
                | Cmd::SendHistory(..)
                | Cmd::StartJoin
                | Cmd::LinkScan(..)
                | Cmd::LinkPick(..)
                | Cmd::Add(..)
                | Cmd::ChangeWords
                | Cmd::PlayClip(..)
        );
        if bulk {
            self.bulk(true);
        }
        self.handle_cmd(cmd).await;
        if bulk {
            self.bulk(false);
        }
        self.apply_privacy();
    }

    async fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Create(name, passphrase) => {
                let name = name.trim().to_string();
                let protect = !passphrase.is_empty() && matches!(self.mode, Mode::Server { .. });
                match Client::create(
                    self.options(Some(&passphrase)),
                    Arc::clone(&self.transport),
                    self.server,
                    &name,
                )
                .await
                {
                    Ok((mut c, _words)) => {
                        self.configure(&mut c);
                        self.client = Some(c);
                        self.passphrase_set = protect;
                        if matches!(self.mode, Mode::Demo) {
                            self.start_demo().await;
                        }
                    }
                    Err(err) => self.status = format!("Couldn't set up your address: {err}"),
                }
            }
            Cmd::SaveBackup => {
                if let Some(c) = self.client.as_mut() {
                    match c.export_backup() {
                        Ok(b) if b.len() <= 15 * 1024 * 1024 => {
                            let day = chrono::Local::now().format("%Y-%m-%d");
                            let _ = self
                                .out
                                .send(Out::File(format!("Enclave backup {day}.enclave"), b));
                        }
                        Ok(_) => {
                            self.status = "Your backup is too large to save from here yet.".into()
                        }
                        Err(_) => self.status = "Couldn't make a backup.".into(),
                    }
                }
            }
            Cmd::Restore(secrets, archive) if self.client.is_none() => {
                self.restore_error.clear();
                self.busy = true;
                self.push();
                let secrets: Vec<&str> = secrets
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                let words = if secrets.len() == 1 {
                    Ok(secrets[0].to_string())
                } else {
                    enclave_core::words_from_shares(&secrets)
                };
                let restored = match words {
                    Ok(w) => {
                        Client::restore(
                            &w,
                            &archive,
                            self.options(None),
                            Arc::clone(&self.transport),
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match restored {
                    Ok(mut c) => {
                        self.configure(&mut c);
                        self.client = Some(c);
                        self.status = "Your account is back on this device. Contacts will accept it after 72 hours unless one of your other devices stops it.".into();
                    }
                    Err(_) => {
                        self.restore_error = if secrets.len() > 1 {
                            "Those shares don't fit together, or there aren't enough of them. Check each one, or ask one more friend.".into()
                        } else {
                            "The recovery words or the backup file don't match. Check the words, and that the file is your Enclave backup.".into()
                        };
                    }
                }
                self.busy = false;
            }
            Cmd::Restore(..) => {}
            Cmd::GiveShares(ids, threshold) => {
                self.busy = true;
                self.push();
                let roots: Vec<[u8; 64]> = ids.iter().filter_map(|i| self.root_of(i)).collect();
                if let Some(c) = self.client.as_mut() {
                    let t = u8::try_from(threshold).unwrap_or(u8::MAX);
                    match c.give_recovery_shares(&roots, t).await {
                        Ok(()) => {
                            self.picked.clear();
                            self.status = format!(
                                "Your recovery is shared. Any {t} of these {} people can help you get your account back.",
                                roots.len()
                            );
                        }
                        Err(_) => {
                            self.status = "Couldn't share your recovery. Choose at least two people you talk to, and check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::RevealShare(id) => {
                self.reveal_share = if id.is_empty() {
                    None
                } else {
                    self.root_of(&id)
                };
            }
            Cmd::Select(id) => {
                self.selected = self.root_of(&id);
                self.selected_group = self.group_of(&id);
                self.selected_notes = id == NOTES_ID;
                if let (Some(c), Some(r)) = (self.client.as_mut(), self.selected) {
                    let _ = c.mark_read(&r).await;
                }
                if let (Some(c), Some(g)) = (self.client.as_mut(), self.selected_group) {
                    let _ = c.mark_group_read(&g);
                }
            }
            Cmd::Send(id, text) if id == NOTES_ID => {
                if let Some(c) = self.client.as_mut()
                    && c.send_note(&text).await.is_err()
                {
                    self.status = "Couldn't save that note.".into();
                }
            }
            Cmd::Delete(id, seq) if id == NOTES_ID => {
                if let Some(c) = self.client.as_mut()
                    && c.delete_note(seq).await.is_err()
                {
                    self.status = "Couldn't delete that note.".into();
                }
            }
            Cmd::Send(id, text) if id.starts_with('g') => {
                let Some(gid) = self.group_of(&id) else {
                    return;
                };
                self.push();
                if let Some(c) = self.client.as_mut()
                    && c.send_group_text(&gid, &text).await.is_err()
                {
                    self.status = "Couldn't send to the group yet. We'll keep trying.".into();
                }
            }
            Cmd::Send(id, text) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                // The message itself ends their "typing…".
                self.typing_sent.remove(&root);
                // Show it as "sending privately" right away.
                self.push();
                if let Some(c) = self.client.as_mut()
                    && let Err(err) = c.send_text(&root, &text).await
                {
                    self.status = match err {
                        CoreError::OutOfTokens => {
                            "Waiting for them to come online before sending more.".into()
                        }
                        _ => "Couldn't send yet. We'll try again when you're back online.".into(),
                    };
                }
            }
            Cmd::Accept(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    // A join request: accepting lets them into the group.
                    let r = if c.join_request(&root).is_some() {
                        c.approve_join(&root).await
                    } else {
                        c.accept(&root).await
                    };
                    if r.is_err() {
                        self.status = "Couldn't accept yet. Check your connection.".into();
                    }
                }
            }
            Cmd::Decline(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let _ = if c.join_request(&root).is_some() {
                        c.decline_join(&root)
                    } else {
                        c.remove_contact(&root)
                    };
                    self.selected = None;
                }
            }
            Cmd::CreatePoll(id, question, options) => {
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    match c.create_poll(&gid, question.trim(), &options).await {
                        Ok(_) => self.effect(Effect::PollCreated),
                        Err(CoreError::TooLong) => {
                            self.status =
                                "A poll needs a question and at least two options.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't send the poll. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::Vote(id, seq, choice) => {
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut())
                    && let Some(poll) = c
                        .group_messages(&gid)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.poll)
                    && c.vote(&gid, &poll, u8::try_from(choice).unwrap_or(u8::MAX))
                        .await
                        .is_err()
                {
                    self.status = "Couldn't send your vote. The poll may be closed.".into();
                }
            }
            Cmd::ClosePoll(id, seq) => {
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut())
                    && let Some(poll) = c
                        .group_messages(&gid)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.poll)
                    && c.close_poll(&gid, &poll).await.is_err()
                {
                    self.status = "Couldn't close the poll. Check your connection.".into();
                }
            }
            Cmd::NewGroupInvite(id) => {
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    match c.create_group_invite(&gid, 1, true).await {
                        Ok(link) => {
                            let _ = self.out.send(Out::Invite(link));
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't make an invite link. Check your connection and try again."
                                    .into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::Add(link, _) if link.trim().starts_with(enclave_core::client::JOIN_PREFIX) => {
                self.add_error.clear();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.join_group(link.trim()).await {
                        Ok(name) => {
                            self.status = format!(
                                "You asked to join {name}. You'll be in once an admin lets you in."
                            );
                            self.effect(Effect::ContactAdded);
                        }
                        Err(err) => self.add_error = link_error(&err),
                    }
                }
                self.busy = false;
            }
            Cmd::Add(link, text) => {
                self.add_error.clear();
                let link = link.trim();
                self.busy = true;
                self.push();
                // An invite link, or a username to look up.
                let card = if link.starts_with("enclave:") || link.contains('#') {
                    ContactCard::from_link(link).map_err(CoreError::Link)
                } else if let Some(c) = self.client.as_mut() {
                    c.find_username(link).await
                } else {
                    Err(CoreError::NotFound)
                };
                let card = match card {
                    Ok(card) => card,
                    Err(err) => {
                        self.add_error = link_error(&err);
                        self.busy = false;
                        return;
                    }
                };
                if let Some(c) = self.client.as_mut() {
                    match c.add_contact(&card, text.trim()).await {
                        Ok(()) => {
                            self.selected = Some(card.root);
                            self.effect(Effect::ContactAdded);
                        }
                        Err(err) => self.add_error = link_error(&err),
                    }
                }
                self.busy = false;
            }
            Cmd::ClaimUsername(name) => {
                self.username_error.clear();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.claim_username(name.trim()).await {
                        Ok(_) => {
                            // A new name replaces one that stopped leading to us.
                            self.username_problem.clear();
                            self.effect(Effect::UsernameClaimed);
                        }
                        Err(err) => self.username_error = username_error(&err),
                    }
                }
                self.busy = false;
            }
            Cmd::ShareContact(id, who) => {
                let (Some(to), Some(who)) = (self.root_of(&id), self.root_of(&who)) else {
                    return;
                };
                if let Some(c) = self.client.as_mut()
                    && c.share_contact(&to, &who).await.is_err()
                {
                    self.status = "Couldn't share that contact. They need to have shared their code with you first.".into();
                }
            }
            Cmd::CreatePack(title, pictures) => {
                self.busy = true;
                self.push();
                let mut stickers = Vec::new();
                for p in pictures
                    .into_iter()
                    .take(enclave_core::client::MAX_STICKERS)
                {
                    // Re-encoded like any picture, and small.
                    match self.media.shrink(p, STICKER_SIDE).await {
                        Ok(s) => stickers.push(s.bytes),
                        Err(_) => {
                            self.status = "One of those files isn't a picture Enclave can read, so no pack was made.".into();
                            self.busy = false;
                            return;
                        }
                    }
                }
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.create_sticker_pack(&title, stickers).await {
                        Ok(p) => format!("Made the pack {} with {} stickers.", p.title, p.count),
                        Err(CoreError::TooLong) => {
                            "A pack needs 1 to 40 pictures and a short name.".into()
                        }
                        Err(_) => "Couldn't upload the pack. Check your connection.".into(),
                    };
                }
                self.busy = false;
            }
            Cmd::SendSticker(id, pack, index) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let Some(key) = c
                    .sticker_packs()
                    .into_iter()
                    .find(|p| hex_short(&p.key) == pack)
                    .map(|p| p.key)
                else {
                    return;
                };
                let index = u8::try_from(index).unwrap_or(u8::MAX);
                let r = match (root, gid) {
                    (Some(root), _) => c.send_sticker(&root, &key, index).await.map(|_| ()),
                    (None, Some(gid)) => c.send_group_sticker(&gid, &key, index).await.map(|_| ()),
                    (None, None) => Ok(()),
                };
                if r.is_err() {
                    self.status = "Couldn't send the sticker. Check your connection.".into();
                }
            }
            Cmd::AddPack(id, seq) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let att = match (root, gid) {
                    (Some(root), _) => c
                        .messages(&root)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.attachment),
                    (None, Some(gid)) => c
                        .group_messages(&gid)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.attachment),
                    (None, None) => None,
                };
                if let Some(att) = att {
                    self.status = match c.add_sticker_pack(&att).await {
                        Ok(p) => format!("Added the pack {}.", p.title),
                        Err(_) => "Couldn't add that pack. Check your connection.".into(),
                    };
                }
            }
            Cmd::LoadStickers => {
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                for p in c.sticker_packs() {
                    let conv = format!("stickers/{}", hex_short(&p.key));
                    for i in 0..p.count {
                        if self.previews.contains(&(conv.clone(), u64::from(i))) {
                            continue;
                        }
                        let Ok(bytes) = c.sticker_picture(&p.file, i).await else {
                            continue;
                        };
                        self.previews.insert((conv.clone(), u64::from(i)));
                        if let Ok(t) = self.media.thumbnail(bytes, PICKER_SIDE).await {
                            let _ = self.out.send(Out::Preview(enclave_ipc::Preview {
                                conversation: conv.clone(),
                                seq: u64::from(i),
                                width: t.width,
                                height: t.height,
                                pixels: t.pixels,
                            }));
                        }
                    }
                }
            }
            Cmd::Report(id, reason, quote, block, costlier) => {
                use enclave_rpc::api::ReportReason;
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                let reason = match reason {
                    1 => ReportReason::Spam,
                    2 => ReportReason::Abuse,
                    _ => ReportReason::Other,
                };
                self.busy = true;
                self.push();
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let sent = c
                    .report(&root, reason, if quote { 10 } else { 0 })
                    .await
                    .is_ok();
                let blocked = block && c.block(&root).await.is_ok();
                let raised = costlier
                    && reason == ReportReason::Spam
                    && c.raise_request_effort().await.is_ok();
                let mut status = match (sent, blocked) {
                    (true, true) => "Reported and blocked. Their server's operator can close their account's request inbox.",
                    (true, false) => "Reported. Their server's operator can close their account's request inbox.",
                    (false, true) => "Blocked, but the report didn't go through. Check your connection.",
                    (false, false) => "Couldn't send the report. Check your connection.",
                }
                .to_string();
                if raised {
                    status.push_str(" Message requests to you cost more for the next month.");
                }
                self.status = status;
                if blocked && self.selected == Some(root) {
                    let request = self
                        .client
                        .as_ref()
                        .and_then(|c| c.contact(&root))
                        .is_some_and(|ct| ct.state == ContactState::Request);
                    if request {
                        self.selected = None;
                    }
                }
                self.busy = false;
            }
            Cmd::ShareLocation(id, lat, lon, label) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                let parse = |s: &str| s.trim().replace(',', ".").parse::<f64>().ok();
                let Some(loc) = parse(&lat)
                    .zip(parse(&lon))
                    .and_then(|(la, lo)| enclave_core::Location::from_degrees(la, lo, &label))
                else {
                    self.status = "Check the coordinates: latitude from -90 to 90, longitude from -180 to 180.".into();
                    return;
                };
                if let Some(c) = self.client.as_mut()
                    && c.share_location(&root, &loc).await.is_err()
                {
                    self.status = "Couldn't send the location. Check your connection.".into();
                }
            }
            Cmd::AddShared(id, seq) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let card = c
                    .messages(&root)
                    .ok()
                    .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                    .and_then(|m| c.shared_contacts(&root).remove(&m.id));
                let Some(card) = card else {
                    return;
                };
                self.busy = true;
                self.push();
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                match c.add_contact(&card, "").await {
                    Ok(()) => {
                        self.selected = Some(card.root);
                        self.status = format!(
                            "Request sent to {}. Check their security code when you meet.",
                            card.name
                        );
                    }
                    Err(err) => self.status = link_error(&err),
                }
                self.busy = false;
            }
            Cmd::Block(id, on) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let r = if on {
                    c.block(&root).await
                } else {
                    c.unblock(&root).await
                };
                if r.is_err() {
                    self.status = if on {
                        "Blocked on this device, but couldn't reach your server to stop their messages. We'll drop anything they send."
                    } else {
                        "Unblocked, but couldn't send them a way to write to you yet. Check your connection."
                    }
                    .into();
                }
                if on && self.selected == Some(root) {
                    // A request we blocked goes away.
                    let request = c
                        .contact(&root)
                        .is_some_and(|ct| ct.state == ContactState::Request);
                    if request {
                        self.selected = None;
                    }
                }
            }
            Cmd::ConvPrefs(id, archived, pinned, muted) => {
                let place = match (self.root_of(&id), self.group_of(&id)) {
                    (Some(r), _) => Place::Contact(r),
                    (None, Some(g)) => Place::Group(g),
                    (None, None) => match self.client.as_ref() {
                        Some(c) if id == NOTES_ID => Place::Contact(c.root()),
                        _ => return,
                    },
                };
                let prefs = enclave_core::ConvPrefs {
                    archived,
                    // An archived conversation isn't pinned to the top.
                    pinned: pinned && !archived,
                    muted,
                };
                if let Some(c) = self.client.as_mut()
                    && c.set_conv_prefs(&place, prefs).is_err()
                {
                    self.status = format!(
                        "You can pin {} conversations. Unpin one first.",
                        enclave_core::MAX_PINNED_CONVERSATIONS
                    );
                }
            }
            Cmd::Pin(id, seq, on) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let r = match (root, gid) {
                    (Some(root), _) => c.pin_message(&root, seq, on).await,
                    (None, Some(gid)) => c.pin_group_message(&gid, seq, on).await,
                    (None, None) => Ok(()),
                };
                if r.is_err() {
                    self.status = if on {
                        "Couldn't pin that message. Check your connection."
                    } else {
                        "Couldn't unpin that message. Check your connection."
                    }
                    .into();
                }
            }
            Cmd::React(id, seq, emoji) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let r = match (root, gid) {
                    (Some(root), _) => c.react(&root, seq, &emoji).await,
                    (None, Some(gid)) => c.react_group(&gid, seq, &emoji).await,
                    (None, None) => Ok(()),
                };
                if r.is_err() {
                    self.status = "Couldn't send the reaction. Check your connection.".into();
                }
            }
            Cmd::Edit(id, seq, text) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let r = match (root, gid) {
                    (Some(root), _) => c.edit_message(&root, seq, text.trim()).await,
                    (None, Some(gid)) => c.edit_group_message(&gid, seq, text.trim()).await,
                    (None, None) => Ok(()),
                };
                if r.is_err() {
                    self.status = "Couldn't edit that message. Edits work for 24 hours.".into();
                }
            }
            Cmd::Delete(id, seq) => {
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let Some(c) = self.client.as_mut() else {
                    return;
                };
                let r = match (root, gid) {
                    (Some(root), _) => c.delete_for_everyone(&root, seq).await,
                    (None, Some(gid)) => c.delete_group_message(&gid, seq).await,
                    (None, None) => Ok(()),
                };
                if r.is_err() {
                    self.status = "Couldn't delete that message. Check your connection.".into();
                }
            }
            Cmd::Timer(id, secs) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.set_timer(&root, secs).await.is_err()
                {
                    self.status = "Couldn't change the timer. Check your connection.".into();
                }
            }
            Cmd::SendFile(id, name, bytes, caption) => {
                self.busy = true;
                self.push();
                // Pictures are re-encoded first: what leaves is new pixels
                // only, never the original file's metadata (GPS, camera).
                let (name, mime, bytes) = if enclave_media::voice::is_wav(&bytes) {
                    // A recording: re-encoded as a voice note, nothing of
                    // the original file but its sound.
                    match self.media.voice_note(bytes).await {
                        Ok((note, _, _)) => (VOICE_NAME.to_string(), VOICE_MIME, note),
                        Err(_) => {
                            self.status = "Enclave couldn't read that recording, so it wasn't sent. Use a 16-bit WAV file.".into();
                            self.busy = false;
                            return;
                        }
                    }
                } else if enclave_media::video::is_gif(&bytes) {
                    // An animated picture: sent as a short AV1 clip, so
                    // nobody's app ever decodes a GIF from someone else.
                    match self.media.clip(bytes).await {
                        Ok((clip, ..)) => (
                            with_extension(&name, "clip"),
                            enclave_media::video::CLIP_MIME,
                            clip,
                        ),
                        Err(_) => {
                            self.status = "Enclave couldn't read that GIF, so it wasn't sent. Try another file.".into();
                            self.busy = false;
                            return;
                        }
                    }
                } else if enclave_media::detect(&bytes).is_some() {
                    match self.media.sanitize(bytes).await {
                        Ok(s) => (
                            with_extension(&name, s.format.extension()),
                            s.format.mime(),
                            s.bytes,
                        ),
                        Err(_) => {
                            self.status = "Enclave couldn't read that picture, so it wasn't sent. Try another file.".into();
                            self.busy = false;
                            return;
                        }
                    }
                } else {
                    // Not a JPEG or PNG, whatever its name says.
                    let mime = match mime_for(&name) {
                        "image/jpeg" | "image/png" => "application/octet-stream",
                        m => m,
                    };
                    (name, mime, bytes)
                };
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                if let Some(c) = self.client.as_mut() {
                    let r = match (root, gid) {
                        (Some(root), _) => c
                            .send_attachment(&root, &name, mime, &bytes, caption.trim())
                            .await
                            .map(|_| ()),
                        (None, Some(gid)) => c
                            .send_group_file(&gid, &name, mime, &bytes, caption.trim())
                            .await
                            .map(|_| ()),
                        (None, None) => Err(CoreError::NotFound),
                    };
                    match r {
                        Ok(_) => self.effect(Effect::FileSent),
                        Err(CoreError::TooLong) => {
                            self.status = "That file is too large to send.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't send the file. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::SaveFile(id, seq) if id.starts_with('g') => {
                let Some(gid) = self.group_of(&id) else {
                    return;
                };
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let name = c
                        .group_messages(&gid)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.attachment)
                        .map(|a| a.name)
                        .unwrap_or_else(|| "file".into());
                    match c.fetch_group_attachment(&gid, seq).await {
                        Ok(bytes) if bytes.len() <= 15 * 1024 * 1024 => {
                            let (name, bytes) = self.exportable(name, bytes).await;
                            let _ = self.out.send(Out::File(name, bytes));
                        }
                        Ok(_) => {
                            self.status = "That file is too large to save from here yet.".into()
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't download the file. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::SaveFile(id, seq) => {
                self.busy = true;
                self.push();
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let name = c
                        .messages(&root)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.attachment)
                        .map(|a| a.name)
                        .unwrap_or_else(|| "file".into());
                    match c.fetch_attachment(&root, seq).await {
                        Ok(bytes) if bytes.len() <= 15 * 1024 * 1024 => {
                            let (name, bytes) = self.exportable(name, bytes).await;
                            let _ = self.out.send(Out::File(name, bytes));
                        }
                        Ok(_) => {
                            self.status = "That file is too large to save from here yet.".into()
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't download the file. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::StopRecovery | Cmd::ApproveRecovery => {
                let stop = cmd == Cmd::StopRecovery;
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let r = if stop {
                        c.stop_recovery().await
                    } else {
                        c.approve_recovery().await
                    };
                    self.status = match (r, stop) {
                        (Ok(()), true) => "Stopped. Your contacts won't accept that device. Choose new recovery words soon: whoever used them still has them.".into(),
                        (Ok(()), false) => "Approved. Your contacts will accept your new device now.".into(),
                        (Err(CoreError::Net(_)), _) => "Couldn't reach your server. Try again now — this matters.".into(),
                        (Err(_), _) => "Couldn't do that. Try again.".into(),
                    };
                }
                self.busy = false;
            }
            Cmd::SendHistory(hex) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let id =
                        c.devices().into_iter().map(|d| d.id).find(|d| {
                            d.iter().map(|b| format!("{b:02x}")).collect::<String>() == hex
                        });
                    if let Some(id) = id {
                        self.link_status = match c.send_history_now(&id).await {
                            Ok(()) => "Message history sent. It appears on the other device when it next connects.".into(),
                            Err(CoreError::Net(_)) => "Couldn't reach your server. Try again in a moment.".into(),
                            Err(_) => "Couldn't send message history.".into(),
                        };
                    }
                }
                self.busy = false;
            }
            Cmd::RemoveDevice(hex) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let id =
                        c.devices().into_iter().map(|d| d.id).find(|d| {
                            d.iter().map(|b| format!("{b:02x}")).collect::<String>() == hex
                        });
                    self.link_status = match id {
                        Some(id) => match c.remove_device(&id).await {
                            Ok(()) => "Removed. Your contacts will stop sending to it.".into(),
                            Err(CoreError::Net(_)) => {
                                "Couldn't reach your server. Try again in a moment.".into()
                            }
                            Err(_) => "Couldn't remove that device.".into(),
                        },
                        None => String::new(),
                    };
                }
                self.effect(Effect::RemovalDone);
                self.busy = false;
            }
            Cmd::StartJoin => {
                self.status.clear();
                match enclave_core::LinkingDevice::start(
                    self.options(None),
                    Arc::clone(&self.transport),
                    self.server,
                )
                .await
                {
                    Ok(l) => {
                        self.join_code = l.code();
                        self.joining = Some(l);
                        self.status = "Waiting for your other device…".into();
                    }
                    Err(CoreError::Net(_)) => {
                        self.status =
                            "Couldn't reach the server. Check your connection and try again."
                                .into();
                    }
                    Err(_) => self.status = "Couldn't start linking. Try again.".into(),
                }
            }
            Cmd::RevealWords(on) => self.reveal_words = on,
            Cmd::Unlock(passphrase) => {
                self.unlock_error.clear();
                self.busy = true;
                self.push();
                match Client::open(self.options(Some(&passphrase)), Arc::clone(&self.transport)) {
                    Ok(mut c) => {
                        self.configure(&mut c);
                        self.client = Some(c);
                        self.locked = false;
                        self.passphrase_set = true;
                    }
                    Err(CoreError::Store(enclave_store::StoreError::Crypto)) => {
                        self.unlock_error = "That passphrase doesn't open this profile.".into();
                    }
                    Err(err) => self.unlock_error = format!("Couldn't open your profile: {err}"),
                }
                self.busy = false;
            }
            Cmd::Lock if self.passphrase_set => {
                // Dropping the client drops its keys and the open database.
                self.client = None;
                self.locked = true;
                self.selected = None;
                self.selected_group = None;
                self.selected_notes = false;
                self.reveal_words = false;
                self.search.clear();
            }
            Cmd::Lock => {}
            Cmd::SetPassphrase(p) if matches!(self.mode, Mode::Server { .. }) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let new = (!p.is_empty()).then_some(p.as_bytes());
                    match c.change_passphrase(new, PwParams::DESKTOP_DEFAULT) {
                        Ok(()) => {
                            self.passphrase_set = new.is_some();
                            self.status = if new.is_some() {
                                "Passphrase set. You'll type it each time Enclave starts.".into()
                            } else {
                                "Passphrase removed. Anyone using this computer account can open Enclave.".into()
                            };
                            self.effect(Effect::PassphraseChanged);
                        }
                        Err(err) => self.status = format!("Couldn't change the passphrase: {err}"),
                    }
                }
                self.busy = false;
            }
            Cmd::SetPassphrase(_) => {}
            Cmd::NewInvite(uses) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.create_invite(uses).await {
                        Ok(link) => {
                            let _ = self.out.send(Out::Invite(link));
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't make an invite link. Check your connection and try again."
                                    .into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::CancelInvites => {
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.cancel_invites().await {
                        Ok(()) => "Your unused invite links no longer work.".into(),
                        Err(_) => "Couldn't cancel your invite links. Check your connection and try again.".into(),
                    };
                }
            }
            Cmd::Search(q) => self.search = q,
            Cmd::AddMembers(id) => {
                let members: Vec<[u8; 64]> = self.picked.iter().copied().collect();
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    match c.add_group_members(&gid, &members).await {
                        Ok(()) => self.picked.clear(),
                        Err(_) => {
                            self.status = "Couldn't add them. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::RemoveMember(id, member) => {
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    let root = c
                        .groups()
                        .into_iter()
                        .find(|g| g.id == gid)
                        .and_then(|g| g.members.into_iter().find(|(r, _)| hex_id(r) == member))
                        .map(|(r, _)| r);
                    if let Some(root) = root
                        && c.remove_group_member(&gid, &root).await.is_err()
                    {
                        self.status = "Couldn't remove them. Check your connection.".into();
                    }
                }
                self.busy = false;
            }
            Cmd::LeaveGroup(id) => {
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    if c.leave_group(&gid).await.is_ok() {
                        self.selected_group = None;
                        self.effect(Effect::LeftGroup);
                    } else {
                        self.status = "Couldn't leave the group. Check your connection.".into();
                    }
                }
            }
            Cmd::Meet(open) => {
                self.meet_words.clear();
                self.meet_name.clear();
                self.meet_error.clear();
                self.meet_done.clear();
                self.meet_code.clear();
                if let Some(c) = self.client.as_mut() {
                    c.meet_cancel();
                    if open && let Ok(code) = c.meet_code() {
                        self.meet_code = code;
                    }
                }
            }
            Cmd::MeetScan(code) => {
                self.meet_error.clear();
                if let Some(c) = self.client.as_mut() {
                    match c.meet_scan(&code) {
                        Ok(m) => {
                            self.meet_words = m.words.join(" ");
                            self.meet_name = m.name;
                        }
                        Err(CoreError::Link(LinkError::OwnCode)) => {
                            self.meet_error =
                                "That's your own code. Scan the other person's.".into();
                        }
                        Err(_) => {
                            self.meet_error = "That isn't an in-person code. Ask them to open Meet in person and show theirs.".into();
                        }
                    }
                }
            }
            Cmd::MeetConfirm => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.meet_confirm().await {
                        Ok(root) => {
                            self.meet_done = std::mem::take(&mut self.meet_name);
                            self.meet_words.clear();
                            self.meet_code.clear();
                            self.selected = Some(root);
                            self.selected_group = None;
                        }
                        Err(CoreError::Net(_)) => {
                            self.meet_error = "Checked, but couldn't reach the server to update your conversation. It will finish when you're back online.".into();
                        }
                        Err(_) => {
                            self.meet_error =
                                "Something went wrong. Scan each other's codes again.".into()
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::CancelJoin => {
                self.joining = None;
                self.join_code.clear();
                self.join_words.clear();
                self.status.clear();
            }
            Cmd::Check(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let _ = c.set_verified(&root, true);
                }
            }
            Cmd::PlayClip(id, seq) => {
                self.busy = true;
                self.push();
                let (root, gid) = (self.root_of(&id), self.group_of(&id));
                let mut bytes = None;
                if let Some(c) = self.client.as_mut() {
                    let att = match (root, gid) {
                        (Some(r), _) => c
                            .messages(&r)
                            .ok()
                            .and_then(|v| v.into_iter().find(|m| m.seq == seq))
                            .and_then(|m| m.attachment),
                        (None, Some(g)) => c
                            .group_messages(&g)
                            .ok()
                            .and_then(|v| v.into_iter().find(|m| m.seq == seq))
                            .and_then(|m| m.attachment),
                        _ => None,
                    };
                    if let Some(a) = att.filter(is_clip) {
                        bytes = c.fetch_file(&a).await.ok();
                    }
                }
                let played = match bytes {
                    Some(b) => self.media.clip_frames(b, PLAYER_SIDE).await.ok(),
                    None => None,
                };
                let clip = match played {
                    Some((frames, ms)) if !frames.is_empty() => enclave_ipc::ClipFrames {
                        width: frames[0].width,
                        height: frames[0].height,
                        interval_ms: ms / frames.len() as u32,
                        frames: frames.into_iter().map(|f| f.pixels).collect(),
                    },
                    // The player then says it couldn't play it.
                    _ => enclave_ipc::ClipFrames {
                        width: 0,
                        height: 0,
                        interval_ms: 0,
                        frames: Vec::new(),
                    },
                };
                let _ = self.out.send(Out::Clip(clip));
                self.busy = false;
            }
            Cmd::ChangeWords => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.change_recovery_words().await {
                        Ok(_) => {
                            self.reveal_words = true;
                            self.status.clear();
                        }
                        Err(_) => {
                            self.status = "Couldn't change your recovery words. Your old words still work. Check your connection and try again.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::TypingSetting(on) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_typing_enabled(on);
                }
                self.typing_until.clear();
                self.typing_sent.clear();
            }
            Cmd::Typing(id, on) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                let now = std::time::Instant::now();
                let send = if on {
                    // Renew well within the receiver's display time.
                    self.typing_sent.get(&root).is_none_or(|t| {
                        now.duration_since(*t).as_secs() >= enclave_core::TYPING_SHOW_SECS / 2
                    })
                } else {
                    self.typing_sent.contains_key(&root)
                };
                if !send {
                    return;
                }
                if on {
                    self.typing_sent.insert(root, now);
                } else {
                    self.typing_sent.remove(&root);
                }
                if let Some(c) = self.client.as_mut()
                    && let Ok(Some(sending)) = c.send_typing(&root, on).await
                {
                    // Waits for a cover slot, or is dropped: never hold up
                    // anything else for it.
                    tokio::spawn(async move {
                        let _ = sending.await;
                    });
                }
            }
            Cmd::SetBridges(text) => {
                self.bridges_error.clear();
                if let Mode::Server { profile, .. } = &self.mode {
                    match crate::netd::normalize_bridges(&text) {
                        Ok(b) => {
                            let file = profile.join(crate::netd::BRIDGES_FILE);
                            let saved = if b.is_empty() {
                                std::fs::remove_file(&file).or_else(|e| {
                                    if e.kind() == std::io::ErrorKind::NotFound {
                                        Ok(())
                                    } else {
                                        Err(e)
                                    }
                                })
                            } else {
                                std::fs::write(&file, &b)
                            };
                            match saved {
                                Ok(()) => self.bridges = b,
                                Err(e) => self.bridges_error = format!("Couldn't save them: {e}"),
                            }
                        }
                        Err(why) => self.bridges_error = why,
                    }
                }
            }
            Cmd::BackupRoute(on) => {
                let maximum = self
                    .client
                    .as_ref()
                    .is_some_and(|c| matches!(c.setting("privacy"), Ok(Some(v)) if v == [1]));
                self.backup_route = on && !maximum;
                if !on {
                    self.backup_declined = true;
                }
                self.net_failures = 0;
                self.transport.use_fallback(self.backup_route);
            }
            Cmd::Privacy(p) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_setting("privacy", &[p as u8]);
                    // Maximum has no push: the server forgets any token.
                    if p == 1 {
                        let _ = c.unregister_push().await;
                    }
                }
                self.apply_privacy();
            }
            Cmd::WordsSaved => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_setting("recovery-saved", &[1]);
                }
            }
            Cmd::TogglePick(id) => {
                if let Some(r) = self.root_of(&id)
                    && !self.picked.remove(&r)
                {
                    self.picked.insert(r);
                }
            }
            Cmd::CreateGroup(name) => {
                let members: Vec<[u8; 64]> = self.picked.iter().copied().collect();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.create_group(name.trim(), &members).await {
                        Ok(gid) => {
                            self.picked.clear();
                            self.selected = None;
                            self.selected_group = Some(gid);
                            self.effect(Effect::GroupCreated);
                        }
                        Err(_) => {
                            self.status = "Couldn't create the group. Check your connection.".into()
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::LinkScan(code) => {
                self.link_status.clear();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.link_prepare(code.trim()).await {
                        Ok(offer) => self.link_offer = Some(offer),
                        Err(CoreError::TooLong) => {
                            self.link_status =
                                "You can link up to 4 devices. Remove one first.".into()
                        }
                        Err(_) => self.link_status =
                            "That code didn't work. Check that the new device is still showing it."
                                .into(),
                    }
                }
                self.busy = false;
            }
            Cmd::LinkPick(i) => {
                if let (Some(offer), Some(c)) = (self.link_offer.take(), self.client.as_mut()) {
                    self.busy = true;
                    self.link_status = match c.link_confirm(offer, i.max(0) as usize).await {
                        Ok(()) => "Linked. Your new device will finish setting up in a moment.".into(),
                        Err(CoreError::Crypto) => {
                            "Those words don't match, so nothing was linked. If you didn't start this, someone may be trying to get into your account.".into()
                        }
                        Err(_) => "Linking didn't finish. Try again from the new device.".into(),
                    };
                    self.busy = false;
                }
            }
        }
    }

    /// Advance linking this device: words to show, then the account.
    async fn poll_join(&mut self) {
        let Some(l) = self.joining.as_mut() else {
            return;
        };
        match l.poll().await {
            Ok(enclave_core::LinkProgress::Waiting) => {}
            Ok(enclave_core::LinkProgress::Words(w)) => {
                self.join_words = w.join(" ");
                self.status = "Waiting for you to pick them there…".into();
            }
            Ok(enclave_core::LinkProgress::Ready) => {
                let Some(l) = self.joining.take() else {
                    return;
                };
                self.status = "Bringing over your contacts…".into();
                match l.finish().await {
                    Ok(mut c) => {
                        self.configure(&mut c);
                        self.client = Some(c);
                        self.join_code.clear();
                        self.join_words.clear();
                        self.status.clear();
                    }
                    Err(_) => {
                        self.join_code.clear();
                        self.join_words.clear();
                        self.status = "Linking didn't finish. Start again on both devices.".into();
                    }
                }
            }
            Err(CoreError::Net(_)) => {
                self.status = "Couldn't reach the server. Still trying…".into();
            }
            Err(_) => {}
        }
    }

    async fn start_demo(&mut self) {
        let Some(me) = self.client.as_ref() else {
            return;
        };
        let card = me.card();
        let opts = Options {
            path: None,
            keystore: Arc::new(MemoryKeystore::default()),
            passphrase: None,
            pw_params: PwParams::FLOOR,
        };
        if let Ok((mut sam, _)) =
            Client::create(opts, Arc::clone(&self.transport), self.server, "Sam (demo)").await
            && sam.add_contact(&card, SAM_HELLO).await.is_ok()
        {
            if let Some(p) = self.kt.clone() {
                sam.set_kt_policy(p);
                let _ = sam.claim_username("sam").await;
            }
            self.demo = Some(Demo { sam, replies: 0 });
        }
    }

    /// Follow the profile's privacy setting (`docs/09-transport.md` §6.6):
    /// Standard is the Foreground profile; Maximum is the Maximum profile,
    /// the private route only (no TCP route or fallback, nothing without
    /// Tor), no push, and nothing a person writes sent before all three
    /// KEMs protect the session.
    fn apply_privacy(&mut self) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        let maximum = matches!(c.setting("privacy"), Ok(Some(v)) if v == [1]);
        c.set_maximum(maximum);
        self.transport.require_private(maximum);
        // Maximum never uses the backup route.
        if maximum && self.backup_route {
            self.backup_route = false;
            self.transport.use_fallback(false);
        }
        if let Some(s) = &self.shaper {
            s.set_shaping(Shaping::On(if maximum {
                Profile::Maximum
            } else {
                Profile::Foreground
            }));
        }
    }

    /// Give a client what this build knows about the federation: the
    /// foundation key, a server list to offer, and extra pins.
    fn configure(&self, c: &mut Client) {
        if let Some(k) = &self.foundation {
            if let Err(e) = c.set_foundation(k.clone()) {
                eprintln!("enclave-vault: foundation key: {e}");
            }
            if let Some(b) = &self.list
                && let Err(e) = c.offer_server_list(b)
            {
                eprintln!("enclave-vault: server list: {e}");
            }
        }
        if let Some(p) = self.kt.clone() {
            c.set_kt_policy(p);
        }
    }

    /// Ask netd whether Tor came up (censorship mode,
    /// `docs/09-transport.md` §7).
    async fn check_tor(&mut self) {
        if matches!(self.mode, Mode::Server { .. }) {
            self.tor_blocked = matches!(self.transport.tor_status().await, Ok(2));
        }
    }

    /// Give the mixnet client its zk-nym tickets (`docs/09-transport.md`
    /// §7): netd starts it waiting for them. With a profile open, from the
    /// profile's wallet (buying a book first if it has none worth using);
    /// before there is one (a new device setting up, restoring or linking),
    /// from a wallet held here and handed to the profile once it exists. A
    /// locked profile waits for its passphrase. Without a credential gate
    /// in the server list it connects without tickets.
    async fn ensure_mixnet(&mut self) {
        if !matches!(self.mode, Mode::Server { .. }) {
            return;
        }
        if let (Some(c), Some(w)) = (self.client.as_mut(), self.prewallet.take())
            && let Err(e) = c.adopt_tickets(w)
        {
            eprintln!("enclave-vault: mixnet tickets: {e}");
        }
        let now = self.transport.now();
        if self.mixnet_up || self.locked || now < self.mixnet_retry_at {
            return;
        }
        let result = match self.client.as_mut() {
            Some(c) => c.start_mixnet().await,
            None => {
                let gate = self
                    .foundation
                    .as_ref()
                    .zip(self.list.as_ref())
                    .and_then(|(k, b)| enclave_federation::ServerList::verify(b, k, now, 0).ok())
                    .and_then(|l| l.credgates.first().cloned());
                let mut w = self.prewallet.take().unwrap_or_default();
                let r = match enclave_crypto::rng::HedgedRng::new() {
                    Ok(mut rng) => {
                        w.start(self.transport.as_ref(), gate.as_ref(), now, &mut rng)
                            .await
                    }
                    Err(_) => Err(CoreError::Crypto),
                };
                self.prewallet = Some(w);
                r
            }
        };
        match result {
            Ok(()) => self.mixnet_up = true,
            Err(e) => {
                eprintln!("enclave-vault: mixnet: {e}");
                self.status =
                    "Couldn't connect to the private network yet. Trying again in a minute.".into();
                self.mixnet_retry_at = now + MIXNET_RETRY;
            }
        }
    }

    /// Start or end a bulk transfer (files, account setup, previews): the
    /// shaper may then skip its clock, except in Maximum.
    fn bulk(&self, on: bool) {
        self.transport.set_bulk(on);
    }

    async fn sync(&mut self) {
        // Once a day: a newer server list from the home server, if any.
        let day = self.transport.now() / 86_400;
        if self.foundation.is_some()
            && day != self.list_day
            && let Some(c) = self.client.as_mut()
        {
            self.list_day = day;
            match c.refresh_server_list().await {
                Ok(_) | Err(CoreError::Server(enclave_rpc::api::Status::NotFound)) => {}
                Err(e) => eprintln!("enclave-vault: server list: {e}"),
            }
        }
        // Groups get one round in this many (fewer in Background).
        let period = match self.shaper.as_ref().map(|s| s.shaping()) {
            Some(Shaping::On(p)) => enclave_net::schedule::Scheduler::other_mailbox_period(p),
            _ => 2,
        } as u64;
        let shaped = self.shaper.is_some();
        let round = self.round;
        self.round = self.round.wrapping_add(1);
        // Now and then: what the mixnet client spent, and the next book
        // before the last runs out.
        if self.mixnet_up
            && round % TICKET_UPKEEP_ROUNDS == TICKET_UPKEEP_ROUNDS - 1
            && let Some(c) = self.client.as_mut()
            && let Err(e) = c.upkeep_tickets().await
        {
            eprintln!("enclave-vault: mixnet tickets: {e}");
        }
        if let Some(c) = self.client.as_mut() {
            let result = if shaped {
                c.sync_round_every(round, period).await
            } else {
                c.sync().await
            };
            // Whether the network carried this round (for the backup
            // route's offer).
            let result_kind = match &result {
                Ok(_) => Some(true),
                Err(CoreError::Net(_)) => Some(false),
                Err(_) => None,
            };
            match result {
                Ok(events) => {
                    if !events.is_empty() {
                        self.status.clear();
                    }
                    if let Some(Event::UsernameProblem { address }) = events
                        .iter()
                        .find(|e| matches!(e, Event::UsernameProblem { .. }))
                    {
                        self.username_problem = format!("@{address}");
                    }
                    let now = std::time::Instant::now();
                    for e in &events {
                        match e {
                            Event::Typing { root, on: true } => {
                                self.typing_until.insert(
                                    *root,
                                    now + Duration::from_secs(enclave_core::TYPING_SHOW_SECS),
                                );
                            }
                            Event::Typing { root, on: false } | Event::Message { root, .. } => {
                                self.typing_until.remove(root);
                            }
                            Event::ContactMoved { old, root, .. } => {
                                if self.selected == Some(*old) {
                                    self.selected = Some(*root);
                                }
                                self.typing_until.remove(old);
                                self.typing_sent.remove(old);
                                self.renamed.insert(hex_id(old), hex_id(root));
                            }
                            _ => {}
                        }
                    }
                    if events.contains(&Event::RemovedFromAccount) {
                        self.status = "This device was removed from your account on another device. It can't get new messages.".into();
                    }
                    if let Some(sel) = self.selected
                        && events
                            .iter()
                            .any(|e| matches!(e, Event::Message { root, .. } if *root == sel))
                    {
                        let _ = c.mark_read(&sel).await;
                    }
                    if let Some(g) = self.selected_group
                        && events.iter().any(
                            |e| matches!(e, Event::GroupMessage { group_id, .. } if *group_id == g),
                        )
                    {
                        let _ = c.mark_group_read(&g);
                    }
                }
                Err(_) => self.status = "Offline. Messages will send when you're back.".into(),
            }
            match result_kind {
                Some(true) => {
                    self.net_failures = 0;
                    self.backup_declined = false;
                }
                Some(false) => self.net_failures = self.net_failures.saturating_add(1),
                None => {}
            }
        }
        if let Some(d) = self.demo.as_mut()
            && let Ok(events) = d.sam.sync().await
        {
            for ev in events {
                let (Event::Message { root, .. } | Event::Accepted { root }) = ev else {
                    continue;
                };
                let reply = SAM_REPLIES[d.replies % SAM_REPLIES.len()];
                d.replies += 1;
                let _ = d.sam.send_text(&root, reply).await;
            }
        }
    }

    fn push(&self) {
        let _ = self.out.send(Out::Snapshot(Box::new(self.snapshot())));
    }

    fn effect(&self, e: Effect) {
        let _ = self.out.send(Out::Effect(e));
    }

    fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            locked: self.locked,
            unlock_error: self.unlock_error.clone(),
            can_lock: self.passphrase_set && self.client.is_some(),
            status: self.status.clone(),
            add_error: self.add_error.clone(),
            username_error: self.username_error.clone(),
            username_problem: self.username_problem.clone(),
            usernames: self.kt.is_some() || self.foundation.is_some(),
            can_join: matches!(self.mode, Mode::Server { .. }),
            join_code: self.join_code.clone(),
            join_words: self.join_words.clone(),
            meet_code: self.meet_code.clone(),
            meet_words: self.meet_words.clone(),
            meet_name: self.meet_name.clone(),
            meet_error: self.meet_error.clone(),
            meet_done: self.meet_done.clone(),
            restore_error: self.restore_error.clone(),
            busy: self.busy,
            tor_blocked: self.tor_blocked,
            bridges: self.bridges.clone(),
            bridges_error: self.bridges_error.clone(),
            bridges_restart: self.bridges != self.bridges_at_start,
            ..Default::default()
        };
        let Some(c) = self.client.as_ref() else {
            return s;
        };
        let now = c.now();
        s.my_name = c.name().to_string();
        if !self.search.trim().is_empty() {
            s.search = c
                .search(&self.search, 50)
                .unwrap_or_default()
                .into_iter()
                .map(|h| {
                    let (id, kind, tint) = match h.place {
                        enclave_core::Place::Contact(r) => (hex_id(&r), 0, tint_for(&r)),
                        enclave_core::Place::Group(g) => (group_id_str(&g), 1, tint_for(&g)),
                    };
                    Row {
                        id,
                        name: h.name,
                        preview: if h.outgoing {
                            format!("You: {}", h.snippet)
                        } else {
                            h.snippet
                        },
                        time: clock(h.at),
                        state: 2,
                        tint,
                        kind,
                        ..Default::default()
                    }
                })
                .collect();
        }
        s.my_link = c.card().to_link();
        s.sticker_packs = c
            .sticker_packs()
            .into_iter()
            .map(|p| enclave_ipc::StickerPackRow {
                id: hex_short(&p.key),
                title: p.title,
                count: u32::from(p.count),
            })
            .collect();
        s.invites = c.invites().map(|v| v.len() as u32).unwrap_or(0);
        s.typing_setting = c.typing_enabled();
        s.can_change_words = c.holds_recovery_words();
        s.words_pending = c.migration_pending();
        s.moved = self
            .selected
            .and_then(|r| c.moved(&r))
            .map_or(0, |m| if m.cross_signed { 1 } else { 2 });
        s.typing = self.selected.is_some_and(|r| {
            self.typing_until
                .get(&r)
                .is_some_and(|t| *t > std::time::Instant::now())
        });
        s.my_username = c.username().map(|u| format!("@{u}")).unwrap_or_default();
        s.joining = c.joining().into_iter().map(|(_, n)| n).collect();
        s.friends = c
            .contacts()
            .into_iter()
            .filter(|ct| ct.state == ContactState::Accepted)
            .map(|ct| Pick {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                tint: tint_for(&ct.root),
                selected: self.picked.contains(&ct.root),
            })
            .collect();
        if let Some((t, holders)) = c.recovery_holders() {
            s.share_threshold = u32::from(t);
            s.share_holders = holders
                .iter()
                .map(|r| {
                    c.contact(r)
                        .map(|ct| ct.name.clone())
                        .unwrap_or_else(|| "Someone".into())
                })
                .collect();
        }
        if let Some(sel) = self.selected {
            s.holds_share = c.holds_recovery_share(&sel);
            if self.reveal_share == Some(sel)
                && let Some(share) = c.recovery_share_for(&sel)
            {
                s.shown_share = share.to_string();
            }
        }
        s.clock_skew = c
            .clock_skew()
            .ok()
            .flatten()
            .map(describe_skew)
            .unwrap_or_default();
        s.kt_split = c
            .kt_alert()
            .map(|a| {
                c.kt_domain(&a.server)
                    .unwrap_or_else(|| "Your server".into())
            })
            .unwrap_or_default();
        s.recovery_alert = c
            .recovery_alert()
            .map(|a| {
                use chrono::TimeZone;
                chrono::Local
                    .timestamp_opt(a.until as i64, 0)
                    .single()
                    .map(|t| t.format("%-d %b %H:%M").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if self.reveal_words {
            s.recovery_words = c.recovery_words().unwrap_or_default();
        }
        s.recovery_saved = matches!(c.setting("recovery-saved"), Ok(Some(v)) if v == [1]);
        s.privacy = i32::from(matches!(c.setting("privacy"), Ok(Some(v)) if v == [1]));
        // The backup route: offered after a minute without the mixnet, when
        // the home server has an onion service and Maximum is off.
        s.route = if self.backup_route {
            2
        } else if self.net_failures >= OFFER_BACKUP_AFTER
            && !self.backup_declined
            && s.privacy != 1
            && c.server_descriptor(&self.server)
                .ok()
                .flatten()
                .is_some_and(|d| !d.onion.is_empty())
        {
            1
        } else {
            0
        };
        let mut rows: Vec<(u64, Row)> = Vec::new();
        for ct in c.contacts() {
            let blocked = c.is_blocked(&ct.root);
            if blocked && ct.state == ContactState::Request {
                continue; // a blocked request just goes away
            }
            let msgs = c.messages(&ct.root).unwrap_or_default();
            let last = msgs.last();
            let join = (ct.state == ContactState::Request)
                .then(|| c.join_request(&ct.root))
                .flatten()
                .and_then(|g| c.groups().into_iter().find(|x| x.id == g))
                .map(|g| format!("Asks to join {}", g.name));
            let row = Row {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                preview: join.unwrap_or_else(|| {
                    last.map(|m| {
                        let mut t = display(m, now).text;
                        if t.is_empty() {
                            t = if m.location.is_some() {
                                "Location".into()
                            } else {
                                "Shared a contact".into()
                            };
                        }
                        if m.outgoing { format!("You: {t}") } else { t }
                    })
                    .unwrap_or_default()
                }),
                time: last.map(|m| clock(m.at)).unwrap_or_default(),
                unread: ct.unread as i32,
                state: match ct.state {
                    ContactState::Pending => 0,
                    ContactState::Request => 1,
                    ContactState::Accepted => 2,
                },
                verified: ct.verified,
                met: c.met_in_person(&ct.root),
                tint: tint_for(&ct.root),
                kind: 0,
                members: 0,
                blocked,
                ..prefs_row(c.conv_prefs(&Place::Contact(ct.root)))
            };
            if self.selected == Some(ct.root) {
                s.current = Some(row.clone());
                s.finishing = c.protection_finishing(&ct.root);
                s.timer = ct.timer;
                let pinned = c.pinned_ids(&Place::Contact(ct.root));
                let shared = c.shared_contacts(&ct.root);
                let me = c.root();
                s.messages = msgs
                    .iter()
                    .map(|m| {
                        let card = shared.get(&m.id).filter(|_| !m.deleted);
                        if let Some(att) = m.attachment.as_ref().filter(|a| is_voice(a))
                            && !m.deleted
                        {
                            let (ms, wave) = self
                                .voice
                                .get(&(hex_id(&ct.root), m.seq))
                                .cloned()
                                .unwrap_or_default();
                            return Msg {
                                text: m.text.clone(),
                                file: att.name.clone(),
                                can_edit: false,
                                voice: true,
                                voice_ms: ms,
                                waveform: wave,
                                pinned: pinned.contains(&m.id),
                                ..display(m, now)
                            };
                        }
                        if let (Some(_), Some(att)) = (m.sticker, &m.attachment)
                            && !m.deleted
                        {
                            return Msg {
                                text: String::new(),
                                file: String::new(),
                                image: false,
                                can_edit: false,
                                sticker: true,
                                pack_added: c.has_sticker_pack(att),
                                pinned: pinned.contains(&m.id),
                                ..display(m, now)
                            };
                        }
                        Msg {
                            pinned: !m.deleted && pinned.contains(&m.id),
                            contact_name: card.map(|k| k.name.clone()).unwrap_or_default(),
                            contact_known: card
                                .is_some_and(|k| k.root == me || c.contact(&k.root).is_some()),
                            location: m
                                .location
                                .as_ref()
                                .map(|l| l.coordinates())
                                .unwrap_or_default(),
                            location_label: m
                                .location
                                .as_ref()
                                .map(|l| l.label.clone())
                                .unwrap_or_default(),
                            ..display(m, now)
                        }
                    })
                    .collect();
                s.pins = pinned
                    .iter()
                    .filter_map(|id| msgs.iter().find(|m| m.id == *id && !m.deleted))
                    .map(|m| pin_text(&m.text, m.attachment.is_some()))
                    .collect();
                let digits: String = c
                    .security_code(&ct.root)
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect();
                s.code_groups = digits
                    .as_bytes()
                    .chunks(5)
                    .map(|g| String::from_utf8_lossy(g).into_owned())
                    .collect();
            }
            rows.push((last.map(|m| m.at).unwrap_or(ct.added_at), row));
        }
        for g in c.groups().into_iter().filter(|g| !g.left) {
            let msgs = c.group_messages(&g.id).unwrap_or_default();
            let last = msgs.last();
            let row = Row {
                id: group_id_str(&g.id),
                name: g.name.clone(),
                preview: last
                    .map(|m| {
                        if m.from.is_none() {
                            format!("You: {}", group_text(m))
                        } else {
                            format!("{}: {}", m.from_name, group_text(m))
                        }
                    })
                    .unwrap_or_else(|| "New group".into()),
                time: last.map(|m| clock(m.at)).unwrap_or_default(),
                unread: g.unread as i32,
                state: 2,
                verified: false,
                met: false,
                tint: tint_for(&g.id),
                kind: 1,
                members: g.members.len() as i32 + 1,
                ..prefs_row(c.conv_prefs(&Place::Group(g.id)))
            };
            if self.selected_group == Some(g.id) {
                s.current = Some(row.clone());
                s.group_admin = g.admin;
                s.members = g
                    .members
                    .iter()
                    .map(|(r, name)| Row {
                        id: hex_id(r),
                        name: name.clone(),
                        state: 2,
                        verified: c.contact(r).is_some_and(|ct| ct.verified),
                        met: c.met_in_person(r),
                        tint: tint_for(r),
                        ..Default::default()
                    })
                    .collect();
                if g.admin {
                    s.addable = c
                        .contacts()
                        .into_iter()
                        .filter(|ct| {
                            ct.state == ContactState::Accepted
                                && !g.members.iter().any(|(r, _)| *r == ct.root)
                        })
                        .map(|ct| Pick {
                            id: hex_id(&ct.root),
                            name: ct.name.clone(),
                            tint: tint_for(&ct.root),
                            selected: self.picked.contains(&ct.root),
                        })
                        .collect();
                }
                let pinned = c.pinned_ids(&Place::Group(g.id));
                s.pins = pinned
                    .iter()
                    .filter_map(|id| msgs.iter().find(|m| m.id == *id && !m.deleted))
                    .map(|m| {
                        let text = pin_text(&m.text, false);
                        if m.from.is_none() {
                            text
                        } else {
                            format!("{}: {text}", m.from_name)
                        }
                    })
                    .collect();
                s.messages = msgs
                    .iter()
                    .map(|m| {
                        let mut msg = Msg {
                            text: group_text(m),
                            outgoing: m.from.is_none(),
                            time: clock(m.at),
                            status: if m.delivered { 1 } else { 0 },
                            sender: m.from_name.clone(),
                            seq: m.seq,
                            pinned: !m.deleted && pinned.contains(&m.id),
                            deleted: m.deleted,
                            can_edit: m.from.is_none()
                                && !m.deleted
                                && m.poll.is_none()
                                && m.attachment.is_none()
                                && now.saturating_sub(m.at) <= EDIT_WINDOW,
                            file: m
                                .attachment
                                .as_ref()
                                .filter(|_| !m.deleted)
                                .map(|a| a.name.clone())
                                .unwrap_or_default(),
                            image: m
                                .attachment
                                .as_ref()
                                .is_some_and(|a| !m.deleted && is_picture(a)),
                            ..Default::default()
                        };
                        if let Some(att) = m.attachment.as_ref().filter(|a| is_voice(a))
                            && !m.deleted
                        {
                            let (ms, wave) = self
                                .voice
                                .get(&(group_id_str(&g.id), m.seq))
                                .cloned()
                                .unwrap_or_default();
                            msg.text = m.text.clone();
                            msg.file = att.name.clone();
                            msg.voice = true;
                            msg.voice_ms = ms;
                            msg.waveform = wave;
                        }
                        if let (Some(_), Some(att)) = (m.sticker, &m.attachment)
                            && !m.deleted
                        {
                            msg.text.clear();
                            msg.file.clear();
                            msg.image = false;
                            msg.can_edit = false;
                            msg.sticker = true;
                            msg.pack_added = c.has_sticker_pack(att);
                        }
                        if let Some(p) = m.poll.and_then(|id| c.poll(&g.id, &id)) {
                            msg.poll_options = p.options.iter().map(|o| o.0.clone()).collect();
                            msg.poll_counts = p.options.iter().map(|o| o.1).collect();
                            msg.poll_mine = p.mine.map_or(0, |i| i32::from(i) + 1);
                            msg.poll_state = match p.tally_agrees {
                                None => 1,
                                Some(true) => 2,
                                Some(false) => 3,
                            };
                            msg.poll_ours = p.ours;
                        }
                        msg
                    })
                    .collect();
            }
            rows.push((last.map(|m| m.at).unwrap_or(0), row));
        }
        // Note to self: always listed, so it can be found.
        let notes = c.notes().unwrap_or_default();
        let last = notes.iter().rev().find(|m| !m.deleted);
        let row = Row {
            id: NOTES_ID.into(),
            name: "Note to self".into(),
            preview: last
                .map(|m| m.text.clone())
                .unwrap_or_else(|| "Write things down for yourself".into()),
            time: last.map(|m| clock(m.at)).unwrap_or_default(),
            state: 2,
            tint: 0,
            kind: 2,
            ..prefs_row(c.conv_prefs(&Place::Contact(c.root())))
        };
        if self.selected_notes {
            s.current = Some(row.clone());
            s.messages = notes
                .iter()
                .map(|m| Msg {
                    can_edit: false,
                    status: -1, // nothing is delivered anywhere
                    ..display(m, now)
                })
                .collect();
        }
        rows.push((last.map(|m| m.at).unwrap_or(0), row));
        // Pinned first, then newest first.
        rows.sort_by(|a, b| b.1.pinned.cmp(&a.1.pinned).then(b.0.cmp(&a.0)));
        for (_, r) in rows {
            if r.state == 1 {
                s.requests.push(r)
            } else if r.archived {
                s.archived.push(r)
            } else {
                s.contacts.push(r)
            }
        }
        s.pick = c
            .contacts()
            .into_iter()
            .filter(|ct| ct.state == ContactState::Accepted)
            .map(|ct| Pick {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                tint: tint_for(&ct.root),
                selected: self.picked.contains(&ct.root),
            })
            .collect();
        let can_link = c.can_link();
        s.devices = c
            .devices()
            .into_iter()
            .map(|d| {
                let label = if d.this_device {
                    "This device"
                } else if d.primary {
                    "First device"
                } else {
                    "Linked device"
                };
                let day = chrono::DateTime::from_timestamp(d.added_at as i64, 0)
                    .map(|t| t.format("%-d %b %Y").to_string())
                    .unwrap_or_default();
                let history_pending = can_link && !d.this_device && !c.history_sent(&d.id);
                Device {
                    id: d.id.iter().map(|b| format!("{b:02x}")).collect(),
                    label: label.to_string(),
                    detail: if history_pending {
                        format!("Added {day} · Message history follows 24 hours after linking")
                    } else {
                        format!("Added {day}")
                    },
                    removable: can_link && !d.this_device,
                    history_pending,
                }
            })
            .collect();
        s.link_choices = self
            .link_offer
            .as_ref()
            .map(|o| o.choices.iter().map(|c| c.join(" ")).collect())
            .unwrap_or_default();
        s.link_status = self.link_status.clone();
        s.can_link = c.can_link();
        let conv = self
            .selected
            .map(|r| hex_id(&r))
            .or(self.selected_group.map(|g| group_id_str(&g)));
        if let Some(conv) = conv {
            for m in &mut s.messages {
                if let Some(ms) = self.clips.get(&(conv.clone(), m.seq)) {
                    m.clip_ms = *ms;
                }
            }
        }
        s
    }
}

/// "3 hours behind", "2 days ahead": a clock skew in words.
fn describe_skew(skew: i64) -> String {
    let secs = skew.unsigned_abs();
    let (n, unit) = if secs < 2 * 3600 {
        (secs.div_ceil(60), "minute")
    } else if secs < 2 * 86_400 {
        (secs / 3600, "hour")
    } else {
        (secs / 86_400, "day")
    };
    let way = if skew < 0 { "behind" } else { "ahead" };
    format!("{n} {unit}{} {way}", if n == 1 { "" } else { "s" })
}
