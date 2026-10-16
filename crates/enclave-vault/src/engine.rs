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
use enclave_store::MemoryKeystore;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

mod call_links;
mod calling;
mod group_calling;
mod transcribing;
use std::time::Duration;
use tokio::sync::mpsc;

/// `NS_SETTINGS` key: `[0]` lets other programs capture the window
/// (screen security is on otherwise; `docs/14-storage.md` §5).
const SCREEN_SECURITY: &str = "screen-security";

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
    /// Everything in memory with a local server and a demo contact (a
    /// build with the `demo` feature).
    Demo,
    /// A profile on disk, its servers reached over the mixnet (or, in
    /// development, TCP).
    Server {
        /// Profile directory.
        profile: PathBuf,
        /// The home server and how it is reached, when named (`--server`;
        /// its key bundle must be signed by the identity its id is derived
        /// from). Otherwise it is the profile's, or (setting up) the one
        /// picked from the server list, reached as the list says.
        home: Option<(ServerId, Route)>,
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

/// Where profiles live when `--profile` isn't given: the platform's local
/// (not roaming) data directory (`~/.local/share/enclave` on Linux,
/// `~/Library/Application Support/com.aricummings.Enclave` on macOS,
/// `%LOCALAPPDATA%\aricummings\Enclave\data` on Windows; a Flatpak's own).
pub fn default_profile() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "aricummings", "Enclave")
        .map(|d| d.data_local_dir().to_path_buf())
}

impl Mode {
    /// Parse `[--profile DIR] [--server HEXID=ROUTE]… [--route HEXID=ROUTE]…
    /// [--kt-pins FILE] [--foundation FILE] [--server-list FILE] [--nym-env]
    /// [--no-shaping]`, or `--demo`. A route is `nym:ADDRESS` or (development) `HOST:PORT`
    /// (`enclave-server show-id` prints the id); the first `--server` is
    /// home, `--route` gives a route to a server that isn't (development).
    /// Without `--profile` the platform's data directory is used
    /// ([`default_profile`]); without `--server` the home server is the
    /// profile's, or one picked from the server list when setting up. A
    /// `--server` that doesn't parse is an error rather than a quiet
    /// fall back.
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let arg = |k: &str| {
            args.iter()
                .position(|a| a == k)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        if args.iter().any(|a| a == "--demo") {
            return if cfg!(feature = "demo") {
                Ok(Mode::Demo)
            } else {
                Err("this build has no demo".into())
            };
        }
        let routes = |flag: &str| -> Result<Vec<(ServerId, Route)>, String> {
            args.windows(2)
                .filter(|p| p[0] == flag)
                .map(|p| {
                    enclave_net::transport::parse_route(&p[1]).ok_or_else(|| {
                        format!(
                            "{flag} {}: expected SERVER_ID=nym:ADDRESS or SERVER_ID=HOST:PORT",
                            p[1]
                        )
                    })
                })
                .collect()
        };
        let mut servers = routes("--server")?;
        let home = (!servers.is_empty()).then(|| servers.remove(0));
        servers.extend(routes("--route")?);
        let profile = match arg("--profile") {
            Some(p) => p.into(),
            None => default_profile().ok_or("no place for the profile: use --profile DIR")?,
        };
        Ok(Mode::Server {
            profile,
            home,
            others: servers,
            nym_env: args.iter().any(|a| a == "--nym-env"),
            kt_pins: arg("--kt-pins").map(Into::into),
            foundation: arg("--foundation").map(Into::into),
            server_list: arg("--server-list").map(Into::into),
            shaping: !args.iter().any(|a| a == "--no-shaping"),
        })
    }

    /// This build offers a server list (built in, or `--server-list`).
    pub fn has_server_list(&self) -> bool {
        match self {
            Mode::Demo => false,
            Mode::Server { server_list, .. } => {
                server_list.is_some() || crate::built::SERVER_LIST.is_some()
            }
        }
    }

    /// Inverse of [`Mode::from_args`].
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Mode::Demo => vec!["--demo".into()],
            Mode::Server {
                profile,
                home,
                others,
                nym_env,
                kt_pins,
                foundation,
                server_list,
                shaping,
            } => {
                let hex =
                    |id: &ServerId| -> String { id.iter().map(|b| format!("{b:02x}")).collect() };
                let mut v = vec!["--profile".into(), profile.display().to_string()];
                // `--server` for home (the first), `--route` for the rest.
                for (i, (id, a)) in home.iter().chain(others).enumerate() {
                    v.push(
                        if i == 0 && home.is_some() {
                            "--server"
                        } else {
                            "--route"
                        }
                        .into(),
                    );
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

#[cfg(feature = "demo")]
const DEMO_SERVER: ServerId = [0x5e; 16];

const SAM_HELLO: &str = "Hi, I'm Sam. I'm a demo contact running on this computer, so you can try Enclave before inviting anyone. Accept to start talking.";
const SAM_REPLIES: [&str; 5] = [
    "Every message travels as a sealed unit of exactly the same size, so a server can't tell a short hello from a long letter.",
    "Try the \"Check code\" button above. With a real person you'd compare those numbers face to face or on a call.",
    "In demo mode nothing you type leaves this computer.",
    "When you're ready, share your invite link with someone you trust.",
    "People can also find you by username, if you choose one in Settings. Mine is @sam@demo.enclave.",
];

#[cfg(feature = "demo")]
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
    /// iOS: the notification key table last shared with the extension.
    #[cfg(target_os = "ios")]
    shared_table: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// Voice notes' duration and waveform, by (conversation, position),
    /// read by mediad.
    voice: HashMap<(String, u64), (u32, Vec<u8>)>,
    /// Voice-note transcription: the model's download, the model.
    transcription: transcribing::Transcription,
    transport: Arc<dyn Transport>,
    /// The traffic shaper, in server mode (`enclave_net::shaped`).
    shaper: Option<Arc<ShapedTransport>>,
    /// Rounds of shaped syncing so far.
    round: u64,
    /// The home server: the profile's, or (setting up) the one picked.
    /// Zero when there is none to offer (a build without a server list,
    /// started without `--server`).
    server: ServerId,
    /// The servers in the foundation's list, checked (for the picker).
    listed: Vec<enclave_federation::ListedServer>,
    /// The profile's secrets are in files, not a platform keystore.
    file_keys: bool,
    /// Touch ID or Windows Hello, when this computer has it set up.
    biometric_name: Option<&'static str>,
    /// History being fetched by the window on the local network, by token
    /// (hex): the offer and the chunks so far.
    lan_in: HashMap<String, (enclave_core::LanHistory, Vec<Vec<u8>>)>,

    client: Option<Client>,
    demo: Option<Demo>,
    selected: Option<[u8; 64]>,
    selected_group: Option<[u8; 32]>,
    /// Note to self is open.
    selected_notes: bool,
    /// The chat folder the list shows (empty: all).
    folder: String,
    /// A link opened from outside the app, waiting for the profile to be
    /// open and unlocked ([`Cmd::OpenLink`]).
    opened_link: Option<String>,
    /// A large file or backup the window is handing over in parts
    /// ([`Cmd::Stage`]).
    staged: Vec<u8>,
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
    /// The day release updates were last checked (0: check at the next
    /// sync).
    update_day: u64,
    /// What the last check found.
    update: Option<enclave_core::UpdateStatus>,
    /// What "Verify this build" found.
    build_check: String,
    /// This device, while it is being linked to an existing account.
    joining: Option<enclave_core::LinkingDevice>,
    join_code: String,
    join_words: String,
    busy: bool,
    /// The recovery sheet is open: only then do the words leave the vault.
    reveal_words: bool,
    /// Security-code words in English (`Cmd::CodeWordsEnglish`).
    code_words_english: bool,
    /// The profile on disk needs its passphrase to open.
    locked: bool,
    unlock_error: String,
    /// The open profile has a passphrase (so "Lock now" makes sense).
    passphrase_set: bool,
    /// The app PIN, the emergency PIN and the idle time (`lock.rs`).
    lock: Option<crate::lock::LockFile>,
    /// The window is locked by the app PIN (the profile stays open).
    pin_locked: bool,
    /// What the last "Check my backup" found.
    backup_check: String,
    /// The last command from the window.
    last_use: std::time::Instant,
    /// Wrong PINs or passphrases in a row, and the earliest next try.
    lock_tries: u32,
    lock_wait: Option<std::time::Instant>,
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
    /// Group members typing (group, member), with their name, until when.
    group_typing_until: HashMap<([u8; 32], [u8; 64]), (String, std::time::Instant)>,
    /// When we last told each group we were typing.
    group_typing_sent: HashMap<[u8; 32], std::time::Instant>,
    /// Clips' lengths (ms), by (conversation, message position), read from
    /// their headers by mediad.
    clips: HashMap<(String, u64), u32>,
    /// Conversation ids of contacts who changed their recovery words, old
    /// to new, so a window still showing the old id keeps working.
    renamed: HashMap<String, String>,
    /// The contact whose recovery share is being released (only while the
    /// sheet is open).
    reveal_share: Option<[u8; 64]>,
    /// Their share, sealed to the code on their new device.
    share_release: Option<([u8; 64], enclave_core::ShareRelease)>,
    /// Before there is an account: our request for friends' shares.
    share_request: Option<enclave_core::ShareRequest>,
    /// The mixnet client has been given its tickets (or told there are
    /// none to wait for).
    mixnet_up: bool,
    /// This device was removed from the account.
    removed: bool,
    /// Why the PIN wasn't taken.
    pin_error: String,
    /// When to try starting it again after a failure.
    mixnet_retry_at: u64,
    /// Tickets bought before there was a profile to keep them in.
    prewallet: Option<TicketWallet>,
    /// Sync rounds that failed on the network, in a row.
    net_failures: u32,
    /// On the backup route (the user chose it).
    backup_route: bool,
    /// The window is in front (the Foreground profile; Background when
    /// not, unless Maximum).
    visible: bool,
    /// The user said "Keep waiting": not offered again until the mixnet
    /// has worked once more.
    backup_declined: bool,
    /// Tor didn't come up (netd says so).
    tor_blocked: bool,
    /// The bridges netd started with, and what is set now.
    bridges_at_start: String,
    bridges: String,
    bridges_error: String,
    /// The call in progress, and how the last one ended (shown briefly).
    call: Option<calling::Call>,
    call_ended: Option<(enclave_ipc::CallView, std::time::Instant)>,
    /// Where call legs and running calls report.
    call_tx: mpsc::UnboundedSender<crate::calls::CallEvent>,
    /// The call relays in the build's server list.
    listed_relays: Vec<enclave_federation::ListedRelay>,
    /// Maximum privacy's standby call tunnel, and whether one is opening.
    call_standby: Option<crate::calls::Standby>,
    standby_opening: bool,
    /// The group call we ring for or are in, and the calls going on in
    /// our groups.
    group_call: Option<group_calling::GroupCall>,
    group_calls: HashMap<[u8; 32], group_calling::Known>,
    /// Waiting in a call link's lobby.
    call_waiting: Option<call_links::Waiting>,
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
            rt.block_on(async move {
                // The helpers too where they run as threads of this process
                // (Android, iOS): the network is theirs.
                let helpers = if enclave_platform::process::registered("enclave-netd") {
                    if matches!(mode, Mode::Server { .. }) {
                        crate::keystore::prepare();
                    }
                    crate::helpers::start(&mode)
                } else {
                    Helpers::default()
                };
                run_with(mode, helpers, rx, out_tx).await;
            });
        })
        .ok();
    (tx, out_rx)
}

/// "enclave-vault" from "enclave-vault@x86_64-unknown-linux-gnu".
fn program_name(target: &str) -> &str {
    target.split('@').next().unwrap_or(target)
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

/// A day, as "9 Oct 2026".
fn day_label(at: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(at as i64, 0)
        .single()
        .map(|t| t.format("%-d %b %Y").to_string())
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
fn server_row(v: &enclave_federation::ListedServer) -> enclave_ipc::ServerRow {
    enclave_ipc::ServerRow {
        id: hex_server(&v.id()),
        domain: v.domain.clone(),
        operator: v.operator.clone(),
        family: v.family.clone(),
    }
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bytes from hex (any even length).
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if s.len() != 32 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex_server(id: &ServerId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_short(k: &[u8; 32]) -> String {
    k[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// The id the UI uses for the note-to-self conversation.
const NOTES_ID: &str = "notes";

/// How a group message reads in the conversation.
/// A contact's art for the UI (`enclave_core::art`): cells and tint packed.
fn art_of(root: &[u8; 64]) -> u32 {
    let a = enclave_core::art::contact_art(root);
    a.cells | (u32::from(a.tint) << 25)
}

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
/// A poll's options, counts and state, on its message's row.
fn fill_poll(msg: &mut Msg, p: &enclave_core::client::PollView) {
    msg.poll_options = p.options.iter().map(|o| o.0.clone()).collect();
    msg.poll_counts = p.options.iter().map(|o| o.1).collect();
    msg.poll_mine = p.mine.map_or(0, |i| i32::from(i) + 1);
    msg.poll_state = match (p.closed, p.tally_agrees) {
        (false, _) => 1,
        (true, Some(false)) => 3,
        (true, _) => 2,
    };
    msg.poll_ours = p.ours;
    msg.poll_anonymous = p.anonymous;
    msg.poll_voters = p.voters;
}

/// A row that answers another message: the quoted one's position, author
/// and the start of its text (or a line saying it's gone).
fn quote(mut row: Msg, q: Option<(u64, String, String)>) -> Msg {
    match q {
        Some((seq, who, text)) => {
            row.quote_seq = seq;
            row.quote_who = who;
            row.quote_text = text;
        }
        None => {
            row.quote_seq = u64::MAX;
            row.quote_text = "A message that isn't here any more".into();
        }
    }
    row
}

/// The start of a quoted message, one line.
fn quoted_text(text: &str, attachment: bool, deleted: bool) -> String {
    if deleted {
        return "This message was deleted.".into();
    }
    let t = text.lines().next().unwrap_or("").trim();
    let t = if t.is_empty() && attachment {
        "A file"
    } else {
        t
    };
    match t.char_indices().nth(80) {
        Some((i, _)) => format!("{}…", &t[..i]),
        None => t.to_string(),
    }
}

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
    if m.late {
        time.push_str(" · delivered late");
    }
    if !m.outgoing && m.signed == Some(false) {
        time.push_str(" · not signed");
    }
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
/// Longest side of a picture in the full-size viewer (its RGBA crosses to
/// the window in one message: 1,600² × 4 B, under the 15 MiB limit).
const VIEWER_SIDE: u16 = 1600;

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

/// Most notifications from one sync; more become one "N new messages".
const MAX_NOTICES: usize = 3;
/// Longest text a notification shows.
const NOTICE_TEXT: usize = 160;

/// Desktop notifications for what a sync brought (`docs/14-storage.md`
/// §5): new messages in conversations that aren't muted, and message
/// requests. Only with "Show previews" on do they name who wrote and show
/// the text; otherwise "New message", as on a lock screen.
fn notices(c: &Client, events: &[Event]) -> Vec<enclave_ipc::Notice> {
    let previews = c.previews();
    let shown = |text: &str, file: bool| -> String {
        let t = if text.trim().is_empty() && file {
            "Sent a file".to_string()
        } else {
            text.trim().to_string()
        };
        match t.char_indices().nth(NOTICE_TEXT) {
            Some((i, _)) => format!("{}…", &t[..i]),
            None => t,
        }
    };
    let mut out = Vec::new();
    for e in events {
        let (conversation, title, body) = match e {
            Event::Message { root, message } if !message.outgoing => {
                if c.conv_prefs(&Place::Contact(*root)).muted {
                    continue;
                }
                let name = c
                    .contact(root)
                    .map(|ct| ct.name.clone())
                    .unwrap_or_default();
                (
                    hex_id(root),
                    name,
                    shown(&message.text, message.attachment.is_some()),
                )
            }
            Event::GroupMessage { group_id, message } if message.from.is_some() => {
                // A mention gets through a muted group.
                if c.conv_prefs(&Place::Group(*group_id)).muted && !message.mentions_me {
                    continue;
                }
                let group = c
                    .groups()
                    .into_iter()
                    .find(|g| g.id == *group_id)
                    .map(|g| g.name)
                    .unwrap_or_default();
                (
                    hex_short(group_id),
                    group,
                    format!(
                        "{}: {}",
                        message.from_name,
                        shown(&message.text, message.attachment.is_some())
                    ),
                )
            }
            Event::Request { root, name, text } => (
                hex_id(root),
                format!("Message request from {name}"),
                shown(text, false),
            ),
            _ => continue,
        };
        out.push(if previews {
            enclave_ipc::Notice {
                conversation,
                title,
                body,
            }
        } else {
            enclave_ipc::Notice {
                conversation,
                title: "Enclave".into(),
                body: "New message".into(),
            }
        });
    }
    if out.len() > MAX_NOTICES {
        let n = out.len();
        out = vec![enclave_ipc::Notice {
            conversation: String::new(),
            title: "Enclave".into(),
            body: format!("{n} new messages"),
        }];
    }
    out
}

/// `name` with its extension replaced by `ext`.
fn with_extension(name: &str, ext: &str) -> String {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let stem = if stem.is_empty() { "picture" } else { stem };
    format!("{stem}.{ext}")
}

/// The traffic-shaping profile (`docs/09-transport.md` §6.5, RT-12). It
/// depends on the window's visibility and the Maximum privacy setting and
/// on nothing else, so it changes only at a foreground/background
/// transition or when the person toggles Maximum privacy, never with what
/// the device is doing (messages, syncs, bulk transfers).
fn shaping_profile(maximum: bool, visible: bool) -> Profile {
    if maximum {
        Profile::Maximum
    } else if visible {
        Profile::Foreground
    } else {
        Profile::Background
    }
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
        CoreError::Link(LinkError::RecoveryCode) => "That code is for getting an account back. It only works there, with the friend next to you.".into(),
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
    let (transport, server, kt): (Arc<dyn Transport>, Option<ServerId>, _) = match &mode {
        #[cfg(feature = "demo")]
        Mode::Demo => {
            // Release builds must not contain this (CI checks with `strings`).
            std::hint::black_box("ENCLAVE-DEV-DEMO-ENABLED");
            let t = enclave_sim::LocalTransport::new();
            let _ = t.add_server(enclave_server::Config {
                id: DEMO_SERVER,
                effort_request: 4,
                effort_claim: 1,
                blob_tokens_per_day: 64,
                effort_username: 4,
                effort_inbox: 1,
                ..Default::default()
            });
            let kt = t.enable_usernames(&DEMO_SERVER, DEMO_DOMAIN);
            (Arc::new(t), Some(DEMO_SERVER), kt)
        }
        #[cfg(not(feature = "demo"))]
        Mode::Demo => {
            eprintln!("enclave-vault: this build has no demo");
            return;
        }
        Mode::Server {
            home,
            others,
            kt_pins,
            shaping,
            ..
        } => {
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
                    for (s, r) in home.iter().chain(others) {
                        match r {
                            Route::Tcp(a) => {
                                routes.insert(*s, *a);
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
            // the profile's own setting is read. Cover goes to the servers
            // used (the home server from its first request).
            let t: Arc<dyn Transport> = if *shaping {
                let s = ShapedTransport::start(
                    t,
                    Shaping::On(Profile::Foreground),
                    home.iter().map(|h| h.0).collect(),
                );
                shaper = Some(Arc::clone(&s));
                s
            } else {
                t
            };
            (t, home.as_ref().map(|h| h.0), kt)
        }
    };
    let (foundation, list) = federation(&mode);
    let file_keys = match &mode {
        Mode::Server { profile, .. } => crate::keystore::uses_files(profile),
        Mode::Demo => false,
    };
    let (call_tx, mut call_rx) = mpsc::unbounded_channel();
    let mut e = Engine {
        mode,
        media: helpers
            .media
            .unwrap_or_else(crate::media::Media::in_process),
        previews: std::collections::HashSet::new(),
        #[cfg(target_os = "ios")]
        shared_table: None,
        voice: HashMap::new(),
        transcription: Default::default(),
        shaper,
        round: 0,
        transport,
        server: server.unwrap_or_default(),
        listed: Vec::new(),
        file_keys,
        lan_in: HashMap::new(),
        biometric_name: enclave_platform::biometric::available()
            .then(enclave_platform::biometric::name)
            .flatten(),
        client: None,
        demo: None,
        selected: None,
        selected_group: None,
        selected_notes: false,
        folder: String::new(),
        opened_link: None,
        staged: Vec::new(),
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
        update_day: 0,
        update: None,
        build_check: String::new(),
        joining: None,
        join_code: String::new(),
        join_words: String::new(),
        busy: false,
        reveal_words: false,
        code_words_english: false,
        locked: false,
        unlock_error: String::new(),
        passphrase_set: false,
        lock: None,
        pin_locked: false,
        backup_check: String::new(),
        last_use: std::time::Instant::now(),
        lock_tries: 0,
        lock_wait: None,
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
        group_typing_until: HashMap::new(),
        group_typing_sent: HashMap::new(),
        renamed: HashMap::new(),
        clips: HashMap::new(),
        reveal_share: None,
        share_release: None,
        share_request: None,
        mixnet_up: false,
        removed: false,
        pin_error: String::new(),
        mixnet_retry_at: 0,
        prewallet: None,
        net_failures: 0,
        backup_route: false,
        visible: true,
        backup_declined: false,
        tor_blocked: false,
        bridges_at_start: String::new(),
        bridges: String::new(),
        bridges_error: String::new(),
        call: None,
        call_ended: None,
        call_tx,
        listed_relays: Vec::new(),
        call_standby: None,
        standby_opening: false,
        group_call: None,
        group_calls: HashMap::new(),
        call_waiting: None,
        out,
    };
    e.load_list();
    // Reopen an existing profile.
    if let Mode::Server { profile, .. } = &e.mode
        && profile.join("profile.redb").exists()
    {
        match Client::open(e.options(None), Arc::clone(&e.transport)) {
            Ok(mut c) => {
                e.configure(&mut c);
                e.server = c.home_server();
                e.client = Some(c);
            }
            // Protected by a passphrase: ask for it.
            Err(CoreError::Store(enclave_store::StoreError::Crypto)) => {
                e.locked = true;
                e.passphrase_set = true;
            }
            Err(err) => e.status = format!("Couldn't open your profile: {err}"),
        }
        e.load_lock();
        // With an app PIN the window starts locked.
        if e.client.is_some() && e.lock.as_ref().is_some_and(|l| l.app_set) {
            e.lock_now();
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
            ev = call_rx.recv() => {
                if let Some(ev) = ev {
                    e.on_call_event(ev).await;
                    e.push();
                }
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                // Keystrokes and the microphone change nothing the window
                // shows.
                let quiet = matches!(cmd, Cmd::Typing(..) | Cmd::CallMic(_) | Cmd::CallFrame(..));
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
                if e.idle_lock_due() {
                    e.lock_now();
                    e.push();
                }
                e.call_upkeep().await;
                if e.client.is_some() {
                    e.sync().await;
                    e.lan_upkeep();
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
                // Useless without this device's keystore, and outliving
                // shredding if copied: left out of OS backups.
                let _ = enclave_platform::backup::exclude(profile);
                // The platform keystore where there is one
                // (`crate::keystore`).
                let keystore = crate::keystore::open(profile);
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
        let now = c.now();
        let (conv, notes): (String, Vec<(u64, enclave_core::files::Attachment)>) =
            if let Some(gid) = self.selected_group {
                (
                    group_id_str(&gid),
                    c.group_messages(&gid)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|m| !m.deleted)
                        .filter(|m| m.from.is_none() || enclave_core::fetch_due(&m.id, m.at, now))
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
                        .filter(|m| m.outgoing || enclave_core::fetch_due(&m.id, m.at, now))
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

    /// A conversation's attachment (1:1 or group), from the local copy or
    /// the server.
    async fn attachment_bytes(&mut self, id: &str, seq: u64) -> Option<Vec<u8>> {
        if id.starts_with('g') {
            let gid = self.group_of(id)?;
            return self
                .client
                .as_mut()?
                .fetch_group_attachment(&gid, seq)
                .await
                .ok();
        }
        let root = self.root_of(id)?;
        self.client
            .as_mut()?
            .fetch_attachment(&root, seq)
            .await
            .ok()
    }

    /// Play a voice note: its sound to the window, ten seconds at a time.
    async fn play_voice(&mut self, id: &str, seq: u64) {
        let Some(note) = self.attachment_bytes(id, seq).await else {
            self.status = "Couldn't download the voice note. Check your connection.".into();
            return;
        };
        let key = format!("{id}:{seq}");
        let mut start = 0u32;
        loop {
            match self.media.voice_piece(note.clone(), start).await {
                Ok(pcm) if !pcm.is_empty() => {
                    let _ = self.out.send(Out::VoiceAudio(key.clone(), start == 0, pcm));
                }
                Ok(_) => return,
                Err(_) => {
                    if start == 0 {
                        self.status = "That voice note couldn't be played.".into();
                    }
                    return;
                }
            }
            start += enclave_media::voice::CHUNK_FRAMES;
        }
    }

    /// What saving a file writes: a voice note becomes an Ogg Opus file
    /// anyone can play (its own Opus packets, put in pages by mediad);
    /// anything else is saved as it is.
    async fn exportable(&self, name: String, bytes: Vec<u8>) -> (String, Vec<u8>) {
        if name.ends_with(".evn")
            && let Ok(ogg) = self.media.voice_ogg(bytes.clone()).await
        {
            return (with_extension(&name, "opus"), ogg);
        }
        // A picture is decoded and encoded again in the media sandbox
        // before it leaves the app, so whatever else the sender's file
        // carried (metadata, a payload for another program's decoder)
        // stays behind (`15-client.md` §5). One that won't decode is saved
        // as it came, like any file.
        let jpeg = bytes.starts_with(&[0xFF, 0xD8, 0xFF]);
        let png = bytes.starts_with(b"\x89PNG\r\n\x1a\n");
        if (jpeg || png)
            && let Ok(clean) = self.media.sanitize(bytes.clone()).await
        {
            let ext = match clean.format {
                enclave_media::Format::Png => "png",
                _ => "jpg",
            };
            return (with_extension(&name, ext), clean.bytes);
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
        let now = c.now();
        let Ok(msgs) = c.messages(&root) else {
            return;
        };
        let want: Vec<(u64, Option<(enclave_core::files::Attachment, u8)>)> = msgs
            .iter()
            .rev()
            .filter(|m| {
                !m.deleted && (m.sticker.is_some() || m.attachment.as_ref().is_some_and(is_picture))
            })
            // Not the moment it arrives: a fetch that follows an upload at
            // once would tie them together (RT-17).
            .filter(|m| m.outgoing || enclave_core::fetch_due(&m.id, m.at, now))
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
        let now = c.now();
        let Ok(msgs) = c.group_messages(&gid) else {
            return;
        };
        let want: Vec<(u64, Option<(enclave_core::files::Attachment, u8)>)> = msgs
            .iter()
            .rev()
            .filter(|m| {
                !m.deleted && (m.sticker.is_some() || m.attachment.as_ref().is_some_and(is_picture))
            })
            .filter(|m| m.from.is_none() || enclave_core::fetch_due(&m.id, m.at, now))
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
        // A large file comes in parts; the command after takes them.
        let cmd = match cmd {
            Cmd::Stage(b) => {
                if self.staged.len() + b.len() > enclave_ipc::MAX_STAGED {
                    self.staged = Vec::new();
                    self.status = "That file is too large.".into();
                    self.push();
                } else {
                    self.staged.extend_from_slice(&b);
                }
                return;
            }
            Cmd::SendStaged(c, n, cap) => {
                Cmd::SendFile(c, n, std::mem::take(&mut self.staged), cap)
            }
            Cmd::OpenFile(c, seq) => {
                let _ = self.out.send(Out::OpenNext);
                Cmd::SaveFile(c, seq)
            }
            Cmd::Restore(s, b) if b.is_empty() && !self.staged.is_empty() => {
                Cmd::Restore(s, std::mem::take(&mut self.staged))
            }
            Cmd::CheckBackup(w, b) if b.is_empty() && !self.staged.is_empty() => {
                Cmd::CheckBackup(w, std::mem::take(&mut self.staged))
            }
            other => other,
        };
        // Locked by the app PIN, the profile is open but the window gets
        // nothing until the PIN (or the emergency PIN) comes. What the
        // phone says on its own (in front or not, push, a new window,
        // which gets the locked state) still counts.
        let phone = matches!(
            cmd,
            Cmd::Visible(_) | Cmd::PushToken(..) | Cmd::Wake | Cmd::Reattach
        );
        if phone {
            self.handle_cmd(cmd).await;
            self.apply_privacy();
            self.deliver_link();
            return;
        }
        if let Cmd::OpenLink(link) = cmd {
            // Only what the Add screen takes; it waits for the profile and
            // the PIN, and the person still taps Add.
            let link = link.trim().to_string();
            if enclave_core::open_deep_link(&link).is_ok() {
                self.opened_link = Some(link);
            } else if !self.pin_locked {
                self.status =
                    "That link isn't an Enclave invite, or it only works on its own screen.".into();
                self.push();
            }
            self.deliver_link();
            return;
        }
        self.last_use = std::time::Instant::now();
        if self.pin_locked && !matches!(cmd, Cmd::Unlock(_) | Cmd::UnlockBiometric(_)) {
            return;
        }
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
        self.lan_upkeep();
        if bulk {
            self.bulk(false);
        }
        self.apply_privacy();
        self.deliver_link();
    }

    /// Hand a waiting opened link to the window once there's an unlocked
    /// profile to add it to.
    fn deliver_link(&mut self) {
        if self.client.is_some()
            && !self.pin_locked
            && let Some(l) = self.opened_link.take()
        {
            let _ = self.out.send(Out::OpenLink(l));
        }
    }

    async fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Create(name, passphrase) => {
                if !self.has_server() {
                    return;
                }
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
            Cmd::SaveBackup(media) => {
                if let Some(c) = self.client.as_mut() {
                    match c.export_backup_with(media) {
                        Ok(b) if b.len() <= enclave_ipc::MAX_STAGED => {
                            let day = chrono::Local::now().format("%Y-%m-%d");
                            self.send_out_file(format!("Enclave backup {day}.enclave"), b);
                        }
                        Ok(_) => {
                            self.status = if media {
                                "With photos and files your backup is too large to save from here. Save it without them, or keep one on your server.".into()
                            } else {
                                "Your backup is too large to save from here. Keep one on your server instead.".into()
                            }
                        }
                        Err(CoreError::PinRequired) => {
                            self.status = "Enter your PIN on the recovery words sheet first.".into()
                        }
                        Err(_) => self.status = "Couldn't make a backup.".into(),
                    }
                }
            }
            Cmd::ServerBackup(on) => {
                if self.client.is_some() {
                    self.busy = true;
                    self.push();
                }
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.set_server_backup(on).await {
                        Ok(()) if on => {
                            "A backup is on your server now, and is renewed every week.".into()
                        }
                        Ok(()) => "The backup on your server is deleted.".into(),
                        Err(CoreError::PinRequired) => {
                            "Enter your PIN on the recovery words sheet first.".into()
                        }
                        Err(CoreError::NotAccepted) => {
                            "Backups are made on the device that holds your recovery words.".into()
                        }
                        Err(_) => "Couldn't reach your server. Try again in a moment.".into(),
                    };
                    self.busy = false;
                }
            }
            Cmd::CheckBackup(words, archive) => {
                if self.client.is_some() {
                    self.busy = true;
                    self.push();
                }
                if let Some(c) = self.client.as_ref() {
                    let archive = if archive.is_empty() {
                        Client::fetch_server_backup(
                            &words,
                            self.server,
                            Arc::clone(&self.transport),
                        )
                        .await
                        .map_err(|_| {
                            "There's no backup on your server for these words.".to_string()
                        })
                    } else {
                        Ok(archive)
                    };
                    self.backup_check = match archive.map(|a| c.check_backup(&words, &a)) {
                        Ok(Ok(r)) if r.ours => {
                            let when = r.header.map(|h| format!(", made {}", day_label(h.created_at))).unwrap_or_default();
                            format!("Your words open this backup{when}: {} contacts and {} messages and notes. It would bring your account back.", r.contacts, r.messages)
                        }
                        Ok(Ok(_)) => "These words open the backup, but it's another account's.".into(),
                        Ok(Err(_)) => "These words don't open this backup. Check them, and that it is your Enclave backup.".into(),
                        Err(why) => why,
                    };
                    self.busy = false;
                }
            }
            Cmd::Restore(secrets, archive) if self.client.is_none() => {
                self.restore_from(secrets, Some(archive)).await;
            }
            Cmd::RestoreFromServer(secrets) if self.client.is_none() => {
                if self.has_server() {
                    self.restore_from(secrets, None).await;
                }
            }
            Cmd::PickServer(id) => {
                if self.client.is_none()
                    && let Some(s) = self.listed_server(&id)
                {
                    self.server = s;
                }
            }
            Cmd::MoveHome(id) => {
                let Some(to) = self.listed_server(&id) else {
                    return;
                };
                if self.client.is_some() {
                    self.busy = true;
                    self.push();
                }
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.move_home(to).await {
                        Ok(()) => "Moving your account. Contacts and groups are told as they come online, so keep Enclave running for a while.".into(),
                        Err(CoreError::NotAccepted) => "Only the device that holds your recovery words can move your account, and not while another move is still finishing.".into(),
                        Err(CoreError::PinRequired) => "Enter your PIN on the recovery words sheet first.".into(),
                        Err(CoreError::Net(_)) => "Couldn't reach that server. Try again in a moment.".into(),
                        Err(_) => "Couldn't move your account.".into(),
                    };
                    self.busy = false;
                }
            }
            Cmd::VoteGroupHost(id) => {
                let (Some(to), Some(gid)) = (self.listed_server(&id), self.selected_group) else {
                    return;
                };
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.vote_group_host(&gid, to).await {
                        Ok(()) => match c.group_host_votes(&gid) {
                            Some(v) if v.next == Some(to) => "The group moves to that server tomorrow.".into(),
                            _ => "Your vote is in. The group moves once more than half of its admins vote for the same server.".into(),
                        },
                        Err(CoreError::NotAccepted) => "Only admins can vote to move a group.".into(),
                        Err(CoreError::Net(_)) => "Couldn't reach the group's server. Try again in a moment.".into(),
                        Err(_) => "Couldn't send your vote.".into(),
                    };
                }
            }
            Cmd::RestoreFromServer(..) => {}
            Cmd::Restore(..) => {}
            Cmd::GiveShares(ids, threshold) => {
                self.busy = true;
                self.push();
                let roots: Vec<[u8; 64]> = ids.iter().filter_map(|i| self.root_of(i)).collect();
                if let Some(c) = self.client.as_mut() {
                    let t = u8::try_from(threshold).unwrap_or(u8::MAX);
                    match c.reshare_recovery(&roots, t).await {
                        Ok(None) => {
                            self.picked.clear();
                            self.status = format!(
                                "Your recovery is shared. Any {t} of these {} people can help you get your account back.",
                                roots.len()
                            );
                        }
                        // Someone no longer holds a share: new words.
                        Ok(Some(_)) => {
                            self.picked.clear();
                            self.reveal_words = true;
                            self.status = "Your recovery words changed, so the share you took back stops working. Write the new words down.".into();
                        }
                        Err(CoreError::PinRequired) => {
                            self.status = "Enter your PIN to share your recovery.".into();
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
                self.share_release = None;
            }
            Cmd::ReleaseShare(code) => {
                if let (Some(root), Some(c)) = (self.reveal_share, self.client.as_mut()) {
                    match c.release_recovery_share(&root, &code) {
                        Ok(r) => self.share_release = Some((root, r)),
                        Err(CoreError::Link(LinkError::NotEnclave | LinkError::Malformed)) => {
                            self.status = "That isn't the code on their new device. On their device, it's under Bring your account back → Ask a friend in person.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't seal your part for them. Ask them to show their code again.".into();
                        }
                    }
                }
            }
            Cmd::DeleteAccount => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.delete_account().await {
                        Ok(()) => {
                            self.erase_local();
                            self.status = "Your account is deleted, and everything on this device was erased.".into();
                        }
                        Err(CoreError::NotAccepted) => {
                            self.status = "Only the device that holds your recovery words can delete your account.".into();
                        }
                        Err(CoreError::PinRequired) => {
                            self.status = "Enter your PIN to delete your account.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't finish deleting your account. Check your connection and try again: what's done stays done.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::SetRootPin(pin) => {
                let params = self.options(None).pw_params;
                if let Some(c) = self.client.as_mut() {
                    self.pin_error = match c.set_root_pin(&pin, params) {
                        Ok(()) => {
                            self.status = "Your PIN is set. Enclave asks for it before anything that acts for your whole account.".into();
                            String::new()
                        }
                        Err(CoreError::TooLong) => format!(
                            "Use at least {} digits or letters.",
                            enclave_core::client::MIN_PIN_LEN
                        ),
                        Err(CoreError::PinRequired) => "Enter your current PIN first.".into(),
                        Err(_) => "Couldn't set your PIN. Try again.".into(),
                    };
                }
            }
            Cmd::UnlockRoot(pin) => {
                if let Some(c) = self.client.as_mut() {
                    self.pin_error = match c.unlock_root(&pin) {
                        Ok(()) => String::new(),
                        Err(CoreError::PinWait(until)) => {
                            use chrono::TimeZone;
                            let at = chrono::Local
                                .timestamp_opt(until as i64, 0)
                                .single()
                                .map(|t| t.format("%H:%M:%S").to_string())
                                .unwrap_or_default();
                            format!("Too many wrong PINs. Try again at {at}.")
                        }
                        Err(_) => "That PIN isn't right.".into(),
                    };
                }
            }
            Cmd::Visible(on) => {
                self.visible = on;
                self.apply_privacy();
            }
            Cmd::PushToken(platform, token) => {
                if let Some(c) = self.client.as_mut() {
                    // APNs tokens come as hex; the relay takes their bytes.
                    let bytes = match platform {
                        2 | 4 => unhex(&token).unwrap_or_default(),
                        _ => token.as_bytes().to_vec(),
                    };
                    let result = if platform == 4 {
                        // A PushKit VoIP token: call wakes only.
                        c.register_call_push(enclave_core::PushPlatform::ApnsVoip, &bytes)
                            .await
                    } else if token.is_empty() {
                        c.unregister_push().await
                    } else {
                        let platform = match platform {
                            1 => enclave_core::PushPlatform::UnifiedPush,
                            2 => enclave_core::PushPlatform::Apns,
                            _ => enclave_core::PushPlatform::Fcm,
                        };
                        // FCM wakes carry nothing, so Poisson dummy wakes
                        // hide when real ones come (`docs/10-push.md` §5).
                        let dummies = platform == enclave_core::PushPlatform::Fcm;
                        c.register_push_listed(platform, &bytes, dummies).await
                    };
                    if let Err(e) = result {
                        eprintln!("enclave-vault: push registration: {e}");
                    }
                }
            }
            Cmd::Reattach => {
                // A new window has none of the pictures and starts from
                // the whole state.
                self.previews.clear();
                self.push();
            }
            Cmd::Wake => {
                if self.client.is_some() {
                    self.ensure_mixnet().await;
                    self.sync().await;
                }
            }
            Cmd::SetPreviews(on) => {
                if let Some(c) = self.client.as_mut()
                    && let Err(CoreError::Net(_)) = c.set_previews(on).await
                {
                    self.status =
                        "Couldn't tell everyone yet. It goes on when you're back online.".into();
                }
            }
            Cmd::SecureAccount => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.secure_account().await {
                        Ok(()) | Err(CoreError::Net(_)) => "Securing your account: new keys and inboxes are on their way to your contacts, groups and other devices. This finishes on its own.".into(),
                        Err(CoreError::PinRequired) => "Enter your PIN to secure your account.".into(),
                        Err(_) => "Only the device that holds your recovery words can secure your account, once a change already under way is done.".into(),
                    };
                }
                self.busy = false;
            }
            Cmd::EraseDevice => {
                if self.client.is_some() {
                    self.erase_local();
                    self.status = "Everything on this device was erased.".into();
                }
            }
            Cmd::AskShares => {
                if self.client.is_none() && self.share_request.is_none() {
                    match enclave_core::ShareRequest::new() {
                        Ok(r) => self.share_request = Some(r),
                        Err(_) => {
                            self.restore_error =
                                "Couldn't make a code for your friends. Try again.".into()
                        }
                    }
                }
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
            Cmd::Send(id, text) => {
                self.send_with(&id, &text, enclave_core::TextOptions::default())
                    .await;
            }
            Cmd::SendReply(id, text, seq) => {
                let reply = self.message_id_at(&id, seq);
                let opts = enclave_core::TextOptions {
                    reply,
                    forwarded: false,
                };
                self.send_with(&id, &text, opts).await;
            }
            Cmd::Forward(from, seq, to) => self.forward(&from, seq, &to).await,
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
            Cmd::CreatePoll(id, question, options, anonymous) => {
                self.busy = true;
                self.push();
                if let (Some(place), Some(c)) = (self.place_of(&id), self.client.as_mut()) {
                    match c
                        .create_poll_in(&place, question.trim(), &options, anonymous)
                        .await
                    {
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
                if let Some((place, poll)) = self.poll_at(&id, seq)
                    && let Some(c) = self.client.as_mut()
                    && c.vote_in(&place, &poll, u8::try_from(choice).unwrap_or(u8::MAX))
                        .await
                        .is_err()
                {
                    self.status = "Couldn't send your vote. The poll may be closed.".into();
                }
            }
            Cmd::ClosePoll(id, seq) => {
                if let Some((place, poll)) = self.poll_at(&id, seq)
                    && let Some(c) = self.client.as_mut()
                    && c.close_poll_in(&place, &poll).await.is_err()
                {
                    self.status = "Couldn't close the poll. Check your connection.".into();
                }
            }
            Cmd::NewGroupInvite(id, uses, approve) => {
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    match c.create_group_invite(&gid, uses, approve).await {
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
            Cmd::Add(link, _) if enclave_core::card::call_link_payload(&link).is_some() => {
                self.add_error.clear();
                if let Some(p) = enclave_core::card::call_link_payload(&link) {
                    self.join_call_link(&p);
                }
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
                        Ok(bytes) => {
                            let (name, bytes) = self.exportable(name, bytes).await;
                            self.send_out_file(name, bytes);
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
                        Ok(bytes) => {
                            let (name, bytes) = self.exportable(name, bytes).await;
                            self.send_out_file(name, bytes);
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
                        let this = c.devices().iter().any(|d| d.this_device && d.id == id);
                        self.link_status = if this {
                            match c.ask_history_now().await {
                                Ok(()) => "Asked for your message history. Confirm on the device you linked from to send it now.".into(),
                                Err(CoreError::Net(_)) => "Couldn't reach your server. Try again in a moment.".into(),
                                Err(_) => "Couldn't ask for message history.".into(),
                            }
                        } else {
                            match c.send_history_now(&id).await {
                                Ok(()) => "Message history sent. It appears on the other device when it next connects.".into(),
                                Err(CoreError::Net(_)) => "Couldn't reach your server. Try again in a moment.".into(),
                                Err(_) => "Couldn't send message history.".into(),
                            }
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
                            Ok(()) => "Removed. Your contacts will stop sending to it. If it may be in someone else's hands, secure your account next.".into(),
                            Err(CoreError::PinRequired) => "Enter your PIN to remove a device.".into(),
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
                if !self.has_server() {
                    return;
                }
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
            Cmd::CodeWordsEnglish(on) => self.code_words_english = on,
            Cmd::WordsLanguage(code) => {
                if let Some(c) = self.client.as_mut()
                    && c.recovery_words_in(&code).is_ok()
                {
                    let _ = c.set_setting("words-language", code.as_bytes());
                }
            }
            Cmd::Unlock(passphrase) => {
                self.unlock_error.clear();
                if let Some(until) = self.lock_wait
                    && std::time::Instant::now() < until
                {
                    let secs = until
                        .saturating_duration_since(std::time::Instant::now())
                        .as_secs()
                        + 1;
                    self.unlock_error = format!("Too many tries. Try again in {secs} seconds.");
                    return;
                }
                if let Some(lf) = &self.lock {
                    match lf.entered(&passphrase) {
                        crate::lock::Entered::Emergency => {
                            self.emergency_erase();
                            return;
                        }
                        crate::lock::Entered::App if self.pin_locked => {
                            self.pin_locked = false;
                            self.locked = false;
                            self.lock_tries = 0;
                            self.lock_wait = None;
                            return;
                        }
                        _ => {}
                    }
                }
                if self.pin_locked {
                    self.wrong_unlock("That PIN isn't right.");
                    return;
                }
                self.busy = true;
                self.push();
                match Client::open(self.options(Some(&passphrase)), Arc::clone(&self.transport)) {
                    Ok(mut c) => {
                        self.configure(&mut c);
                        self.client = Some(c);
                        self.locked = false;
                        self.passphrase_set = true;
                        self.lock_tries = 0;
                        self.lock_wait = None;
                    }
                    Err(CoreError::Store(enclave_store::StoreError::Crypto)) => {
                        self.wrong_unlock("That passphrase doesn't open this profile.");
                    }
                    Err(err) => self.unlock_error = format!("Couldn't open your profile: {err}"),
                }
                self.busy = false;
            }
            Cmd::Lock => self.lock_now(),
            Cmd::SetAppLock(pin) => self.set_app_lock(&pin),
            Cmd::SetLockTimeout(t) => {
                if self.client.is_some()
                    && let Some(lf) = self.lock_mut()
                {
                    lf.timeout = t;
                    if !self.save_lock() {
                        self.status = "Couldn't save the lock settings.".into();
                    }
                }
            }
            Cmd::SetEmergencyPin(pin) => self.set_emergency_pin(&pin),
            // With the keys in files (no keyring here), the passphrase is
            // what protects them: it can be changed, not removed (PC-45).
            Cmd::SetPassphrase(p) if p.is_empty() && self.file_keys => {
                self.status = "This computer keeps Enclave's keys in files, so the passphrase can't be removed.".into();
            }
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
            Cmd::SetGroupAdmin(id, member, on) => {
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    let root = c
                        .groups()
                        .into_iter()
                        .find(|g| g.id == gid)
                        .and_then(|g| g.members.into_iter().find(|(r, _)| hex_id(r) == member))
                        .map(|(r, _)| r);
                    if let Some(root) = root
                        && c.set_group_admin(&gid, &root, on).await.is_err()
                    {
                        self.status =
                            "Couldn't change who is an admin. Check your connection.".into();
                    }
                }
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
                    if let Some(a) = att.filter(is_picture) {
                        let clip = is_clip(&a);
                        bytes = c.fetch_file(&a).await.ok().map(|b| (b, clip));
                    }
                }
                // A clip plays; a still picture shows full size, as one
                // frame (decoded in the sandbox like its preview).
                let played = match bytes {
                    Some((b, true)) => self.media.clip_frames(b, PLAYER_SIDE).await.ok(),
                    Some((b, false)) => self
                        .media
                        .thumbnail(b, VIEWER_SIDE)
                        .await
                        .ok()
                        .map(|f| (vec![f], 0)),
                    None => None,
                };
                let clip = match played {
                    Some((frames, ms)) if !frames.is_empty() => enclave_ipc::ClipFrames {
                        width: frames[0].width,
                        height: frames[0].height,
                        interval_ms: ms / frames.len().max(1) as u32,
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
                    // A device without the words makes new ones for an
                    // account whose words and first device are lost.
                    let r = if c.holds_recovery_words() {
                        c.change_recovery_words().await
                    } else {
                        c.replace_lost_root().await
                    };
                    match r {
                        Ok(_) => {
                            self.reveal_words = true;
                            self.status.clear();
                        }
                        Err(CoreError::PinRequired) => {
                            self.status = "Enter your PIN to change your recovery words.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't change your recovery words. Your old words still work. Check your connection and try again.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::UnlockBiometric(window) => {
                self.unlock_error.clear();
                if !self.pin_locked
                    || self.biometric_name.is_none()
                    || !self.lock.as_ref().is_some_and(|l| l.biometric)
                {
                    return;
                }
                let ok = tokio::task::spawn_blocking(move || {
                    enclave_platform::biometric::verify(window, "Unlock Enclave")
                })
                .await
                .unwrap_or(false);
                if ok {
                    self.pin_locked = false;
                    self.locked = false;
                    self.lock_tries = 0;
                    self.lock_wait = None;
                } else {
                    self.unlock_error = "Not unlocked. Type your PIN instead.".into();
                }
            }
            Cmd::SetBiometric(on) => {
                if on && self.biometric_name.is_none() {
                    self.status = "This computer has no Touch ID or Windows Hello set up.".into();
                } else if self.client.is_some()
                    && self.lock.as_ref().is_some_and(|l| l.app_set || !on)
                    && let Some(lf) = self.lock_mut()
                {
                    lf.biometric = on;
                    if !self.save_lock() {
                        self.status = "Couldn't save the lock settings.".into();
                    }
                }
            }
            Cmd::LanServing(token, addrs) => {
                if let (Some(c), Some(t)) = (self.client.as_mut(), unhex16(&token)) {
                    let _ = c.history_lan_ready(&t, addrs);
                }
            }
            Cmd::LanChunks(token, chunks, last) => {
                let Some((offer, got)) = self.lan_in.get_mut(&token) else {
                    return;
                };
                got.extend(chunks);
                if got.len() > offer.chunks() as usize {
                    if let (Some((offer, _)), Some(c)) =
                        (self.lan_in.remove(&token), self.client.as_mut())
                    {
                        let _ = c.history_lan_failed(&offer.attachment);
                    }
                    return;
                }
                if last
                    && let Some((offer, got)) = self.lan_in.remove(&token)
                    && let Some(c) = self.client.as_mut()
                    && c.import_history_chunks(&offer.attachment, &got).is_ok()
                {
                    self.status = "Your messages from your other device are here.".into();
                }
            }
            Cmd::LanFailed(token) => {
                if let (Some((offer, _)), Some(c)) =
                    (self.lan_in.remove(&token), self.client.as_mut())
                {
                    let _ = c.history_lan_failed(&offer.attachment);
                }
            }
            Cmd::StartCall(conversation, video, direct) => {
                self.start_call(&conversation, video, direct).await
            }
            Cmd::AnswerCall => self.answer_call(false).await,
            Cmd::AnswerCallDirect => self.answer_call(true).await,
            Cmd::DeclineCall => self.decline_call().await,
            Cmd::EndCall => self.end_call().await,
            Cmd::CallMute(on) => self.call_mute(on),
            Cmd::CallMic(pcm) => self.call_mic(pcm),
            Cmd::CallCamera(on) => self.call_camera(on),
            Cmd::CallFrame(width, height, rgba) => self.call_frame(width, height, rgba),
            Cmd::StartGroupCall(conversation, video) => {
                self.start_group_call(&conversation, video).await
            }
            Cmd::JoinGroupCall(conversation) => self.join_group_call(&conversation).await,
            Cmd::CallHand(up) => self.call_hand(up),
            Cmd::CallReact(emoji) => self.call_react(emoji),
            Cmd::CreateCallLink(lobby) => self.create_call_link(lobby),
            Cmd::CallScreen(on) => self.call_screen(on),
            Cmd::PlayVoice(id, seq) => self.play_voice(&id, seq).await,
            Cmd::TranscriptionModel(on) => self.transcription_model(on),
            Cmd::Transcribe(id, seq) => self.transcribe(&id, seq).await,
            Cmd::AdmitToCall(who) => self.admit_to_call(who),
            Cmd::RefuseFromCall(who) => self.refuse_from_call(who),
            Cmd::CheckUpdates => {
                self.update_day = 0;
                if self.client.is_some() {
                    self.sync().await;
                }
            }
            Cmd::VerifyBuild(files) => {
                self.build_check = self.verify_build(&files);
            }
            Cmd::SetScreenSecurity(on) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_setting(SCREEN_SECURITY, if on { &[] } else { &[0] });
                }
            }
            Cmd::ReceiptsSetting(on) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_receipts_enabled(on);
                }
            }
            Cmd::TypingSetting(on) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_typing_enabled(on);
                }
                self.typing_until.clear();
                self.typing_sent.clear();
                self.group_typing_until.clear();
                self.group_typing_sent.clear();
            }
            Cmd::Typing(id, on) if id.starts_with('g') => {
                let Some(gid) = self.group_of(&id) else {
                    return;
                };
                let now = std::time::Instant::now();
                let send = if on {
                    self.group_typing_sent.get(&gid).is_none_or(|t| {
                        now.duration_since(*t).as_secs() >= enclave_core::TYPING_SHOW_SECS / 2
                    })
                } else {
                    self.group_typing_sent.contains_key(&gid)
                };
                if !send {
                    return;
                }
                if on {
                    self.group_typing_sent.insert(gid, now);
                } else {
                    self.group_typing_sent.remove(&gid);
                }
                if let Some(c) = self.client.as_mut()
                    && let Ok(Some(sending)) = c.send_group_typing(&gid, on).await
                {
                    tokio::spawn(async move {
                        let _ = sending.await;
                    });
                }
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
            Cmd::NewFolder(name) => {
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.new_folder(&name) {
                        Ok(()) => String::new(),
                        Err(CoreError::NotAccepted) => {
                            "There's already a folder with that name.".into()
                        }
                        Err(CoreError::TooLong) => format!(
                            "A folder name is 1 to {} characters, and you can have {} folders.",
                            enclave_core::MAX_FOLDER_NAME,
                            enclave_core::MAX_FOLDERS
                        ),
                        Err(_) => "Couldn't make the folder.".into(),
                    };
                }
            }
            Cmd::DeleteFolder(name) => {
                if let Some(c) = self.client.as_mut()
                    && c.delete_folder(&name).is_ok()
                    && self.folder == name
                {
                    self.folder.clear();
                }
            }
            Cmd::InFolder(name, on) => {
                let place = match (self.selected, self.selected_group) {
                    (Some(r), _) => Some(Place::Contact(r)),
                    (None, Some(g)) => Some(Place::Group(g)),
                    _ => None,
                };
                if let (Some(p), Some(c)) = (place, self.client.as_mut())
                    && c.set_in_folder(&name, &p, on).is_err()
                {
                    self.status = "Couldn't change the folder.".into();
                }
            }
            Cmd::ShowFolder(name) => self.folder = name,
            // Taken in `handle`.
            Cmd::OpenLink(_) => {}
            Cmd::SetAnnouncementOnly(on) => {
                if let (Some(g), Some(c)) = (self.selected_group, self.client.as_mut())
                    && c.set_group_announcement_only(&g, on).await.is_err()
                {
                    self.status = "Couldn't change who can post. Check your connection.".into();
                }
            }
            Cmd::SetOnRecord(on) => {
                let done = match (self.selected, self.selected_group, self.client.as_mut()) {
                    (Some(root), _, Some(c)) => c.set_on_the_record(&root, on).await.is_ok(),
                    (None, Some(g), Some(c)) => c.set_group_on_the_record(&g, on).await.is_ok(),
                    _ => true,
                };
                if !done {
                    self.status = "Couldn't change the mode. Check your connection.".into();
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
            // Turned into other commands before they get here (`handle`).
            Cmd::Stage(_) | Cmd::SendStaged(..) | Cmd::OpenFile(..) => {}
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
            s.set_shaping(Shaping::On(shaping_profile(maximum, self.visible)));
        }
    }

    /// Hand the window what history it is to serve, stop serving or fetch
    /// on the local network (`enclave_core` history): only sealed chunks
    /// and where to find them cross to it.
    fn lan_upkeep(&mut self) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        for s in c.take_history_serve() {
            let token = hex16(&s.token);
            let batches: Vec<&[Vec<u8>]> = s.chunks.chunks(enclave_ipc::LAN_BATCH).collect();
            if batches.is_empty() {
                let _ = self
                    .out
                    .send(Out::LanChunks(token.clone(), Vec::new(), true));
            }
            for (i, b) in batches.iter().enumerate() {
                let last = i + 1 == batches.len();
                let _ = self
                    .out
                    .send(Out::LanChunks(token.clone(), b.to_vec(), last));
            }
        }
        for t in c.take_history_lan_stop() {
            let _ = self.out.send(Out::LanStop(hex16(&t)));
        }
        for h in c.take_lan_history() {
            let token = hex16(&h.token);
            let _ = self
                .out
                .send(Out::LanFetch(token.clone(), h.addrs.clone(), h.chunks()));
            self.lan_in.insert(token, (h, Vec::new()));
        }
    }

    /// Check the server list this build offers and route to its servers,
    /// so a new account can be set up on any of them; without a home
    /// server named, pick one (weighted by the list), which the person can
    /// change before setting up.
    fn load_list(&mut self) {
        let Some(list) = self
            .foundation
            .as_ref()
            .zip(self.list.as_ref())
            .and_then(|(k, b)| {
                enclave_federation::ServerList::verify(b, k, self.transport.now(), 0)
                    .map_err(|e| eprintln!("enclave-vault: server list: {e}"))
                    .ok()
            })
        else {
            return;
        };
        for s in &list.servers {
            if !s.nym_address.is_empty() {
                self.transport
                    .set_route(s.id(), Route::Nym(s.nym_address.clone()));
            }
        }
        if self.server == ServerId::default() {
            let draw = enclave_crypto::rng::HedgedRng::new()
                .and_then(|mut r| r.array::<8>("app/server-pick"))
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            if let Some(s) = list.pick(draw) {
                self.server = s.id();
            }
        }
        self.listed = list.servers;
        self.listed_relays = list.relays;
    }

    /// The servers to pick from: the profile's list (perhaps newer than the
    /// build's), else the build's.
    fn servers(&self) -> Vec<enclave_federation::ListedServer> {
        match self.client.as_ref().and_then(Client::server_list) {
            Some(l) => l.servers.clone(),
            None => self.listed.clone(),
        }
    }

    /// The listed server taking new accounts with this id (hex).
    fn listed_server(&self, id: &str) -> Option<ServerId> {
        self.servers()
            .iter()
            .filter(|l| l.weight > 0)
            .map(enclave_federation::ListedServer::id)
            .find(|s| hex_server(s) == id)
    }

    /// Setting up needs a home server: say so when there is none.
    fn has_server(&mut self) -> bool {
        if self.server == ServerId::default() {
            self.status = "This build has no server to set up on. Start it with --server, or with a server list.".into();
            return false;
        }
        true
    }

    /// Give a client what this build knows about the federation: the
    /// foundation key, a server list to offer, and extra pins.
    fn configure(&self, c: &mut Client) {
        // History to and from our other devices goes window to window on
        // the local network where it can (`enclave_core` history).
        c.set_history_lan(matches!(self.mode, Mode::Server { .. }));
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

    /// "Verify this build" (`docs/19-ops.md` §1.3): the running programs'
    /// hashes against the newest release checked, and each one's Sigsum
    /// proof.
    fn verify_build(&self, files: &[enclave_ipc::FileHash]) -> String {
        let Some(root) = crate::built::UPDATE_ROOT else {
            return "This build has no release keys to check against (a development build).".into();
        };
        let Some(c) = self.client.as_ref() else {
            return String::new();
        };
        let Ok(Some((bundle, mut checker))) = c.update_bundle(root) else {
            return "No release information yet. It comes from your server once a day; check again later.".into();
        };
        let release = match bundle.apply(&mut checker, self.transport.now()) {
            Ok(r) => r,
            Err(e) => return format!("The release information couldn't be checked: {e}."),
        };
        if files.is_empty() {
            return "No programs to check.".into();
        }
        for f in files {
            let (Ok(sha256), Ok(sha3_512)) = (
                <[u8; 32]>::try_from(f.sha256.as_slice()),
                <[u8; 64]>::try_from(f.sha3_512.as_slice()),
            ) else {
                return "No programs to check.".into();
            };
            let got = enclave_update::Target {
                name: f.name.clone(),
                length: f.length,
                sha256,
                sha3_512,
            };
            let Some(proof) = bundle.proof(&f.name) else {
                return format!(
                    "{} isn't part of Enclave {}, the newest release. If you haven't updated yet, update and check again.",
                    program_name(&f.name),
                    release.release
                );
            };
            if let Err(e) = checker.check_target(&release, &got, proof) {
                return format!(
                    "{} doesn't match Enclave {}: {e}. Reinstall Enclave from its official download.",
                    program_name(&f.name),
                    release.release
                );
            }
        }
        format!(
            "This build is Enclave {}: all {} programs match the release its maintainers signed, and each is in the public Sigsum log.",
            release.release,
            files.len()
        )
    }

    /// Start or end a bulk transfer (files, account setup, previews): the
    /// shaper may then skip its clock, except in Maximum.
    fn bulk(&self, on: bool) {
        self.transport.set_bulk(on);
    }

    async fn sync(&mut self) {
        // A move (or a restore, or linking) may have changed it.
        if let Some(c) = self.client.as_ref() {
            self.server = c.home_server();
        }
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
        // Once a day: release updates the home server relays, checked
        // against the root built in (docs/19-ops.md §1.3).
        if let Some(root) = crate::built::UPDATE_ROOT
            && day != self.update_day
            && let Some(c) = self.client.as_mut()
        {
            self.update_day = day;
            match c.check_updates(root, env!("CARGO_PKG_VERSION")).await {
                Ok(Some(u)) => self.update = Some(u),
                Ok(None) => {}
                Err(e) => eprintln!("enclave-vault: updates: {e}"),
            }
            // The newest bundle checked (this time or before), for the
            // window's updater.
            if let Ok(Some((b, _))) = c.update_bundle(root) {
                let _ = self.out.send(Out::UpdateBundle(b.encode()));
            }
        }
        // 30 days below a release's minimum version: no more receiving
        // until Enclave is updated (docs/19-ops.md §4).
        if let Some(c) = self.client.as_ref()
            && c.receiving_stopped().unwrap_or(false)
        {
            self.status = "Update Enclave to keep receiving messages.".into();
            return;
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
        let mut call_messages: Vec<([u8; 64], Vec<u8>)> = Vec::new();
        let mut group_call_messages: Vec<([u8; 32], [u8; 64], Vec<u8>)> = Vec::new();
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
                    call_messages.extend(events.iter().filter_map(|e| match e {
                        Event::Call { from, message } => Some((*from, message.clone())),
                        _ => None,
                    }));
                    group_call_messages.extend(events.iter().filter_map(|e| match e {
                        Event::GroupCall {
                            group_id,
                            from,
                            message,
                        } => Some((*group_id, *from, message.clone())),
                        _ => None,
                    }));
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
                            Event::GroupTyping {
                                group_id,
                                root,
                                name,
                                on: true,
                            } => {
                                self.group_typing_until.insert(
                                    (*group_id, *root),
                                    (
                                        name.clone(),
                                        now + Duration::from_secs(enclave_core::TYPING_SHOW_SECS),
                                    ),
                                );
                            }
                            Event::GroupTyping {
                                group_id,
                                root,
                                on: false,
                                ..
                            } => {
                                self.group_typing_until.remove(&(*group_id, *root));
                            }
                            // Their message ends their "typing…".
                            Event::GroupMessage { group_id, message } => {
                                if let Some(root) = message.from {
                                    self.group_typing_until.remove(&(*group_id, root));
                                }
                            }
                            Event::ModeChanged {
                                root,
                                on_record,
                                by_us,
                            } => {
                                let who = if *by_us {
                                    "You".to_string()
                                } else {
                                    c.contact(root)
                                        .map(|ct| ct.name.clone())
                                        .unwrap_or_default()
                                };
                                self.status = if *on_record {
                                    format!(
                                        "{who} put the conversation on the record: messages now carry a signature."
                                    )
                                } else {
                                    format!("{who} took the conversation off the record.")
                                };
                            }
                            Event::GroupModeChanged {
                                group_id,
                                on_record,
                                by,
                            } => {
                                let who =
                                    c.contact(by).map(|ct| ct.name.clone()).unwrap_or_default();
                                let group = c
                                    .groups()
                                    .into_iter()
                                    .find(|g| g.id == *group_id)
                                    .map(|g| g.name)
                                    .unwrap_or_default();
                                self.status = if *on_record {
                                    format!(
                                        "{who} put {group} on the record: messages there now carry a signature."
                                    )
                                } else {
                                    format!("{who} took {group} off the record.")
                                };
                            }
                            Event::GroupDiverged { group_id } => {
                                let group = c
                                    .groups()
                                    .into_iter()
                                    .find(|g| g.id == *group_id)
                                    .map(|g| g.name)
                                    .unwrap_or_default();
                                self.status = format!(
                                    "Some people in {group} may be seeing different messages."
                                );
                            }
                            Event::ContactClosed { root } => {
                                let name = c
                                    .contact(root)
                                    .map(|ct| ct.name.clone())
                                    .unwrap_or_default();
                                self.status = format!("{name} closed their account.");
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
                    if events.contains(&Event::RecoveryStopped) {
                        self.status = "One of your other devices stopped this change. Your contacts won't accept this device.".into();
                    }
                    if events.contains(&Event::RemovedFromAccount) {
                        self.removed = true;
                        self.status = "This device was removed from your account on another device. It can't get new messages.".into();
                    }
                    if events.contains(&Event::AccountDeleted) {
                        self.erase_local();
                        self.status = "Your account was deleted from another of your devices, so everything on this device was erased too.".into();
                        return;
                    }
                    for n in notices(c, &events) {
                        let _ = self.out.send(Out::Notify(n));
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
        for (from, message) in call_messages {
            self.on_call_message(from, &message).await;
        }
        for (gid, from, message) in group_call_messages {
            self.on_group_call_message(gid, from, &message).await;
        }
        #[cfg(target_os = "ios")]
        self.share_notify_table();
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

    /// Send a text to conversation `id` (a contact or a group).
    async fn send_with(&mut self, id: &str, text: &str, opts: enclave_core::TextOptions) {
        if id == NOTES_ID {
            if let Some(c) = self.client.as_mut()
                && c.send_note(text).await.is_err()
            {
                self.status = "Couldn't save that note.".into();
            }
            return;
        }
        if let Some(gid) = self.group_of(id) {
            self.push();
            if let Some(c) = self.client.as_mut()
                && let Err(e) = c.send_group_text_with(&gid, text, opts).await
            {
                self.status = if matches!(e, CoreError::RecoveryHeld) {
                    HELD_TEXT.into()
                } else {
                    "Couldn't send to the group yet. We'll keep trying.".into()
                };
            }
            return;
        }
        let Some(root) = self.root_of(id) else {
            return;
        };
        // The message itself ends their "typing…".
        self.typing_sent.remove(&root);
        // Show it as "sending privately" right away.
        self.push();
        if let Some(c) = self.client.as_mut()
            && let Err(err) = c.send_text_with(&root, text, opts).await
        {
            self.status = match err {
                CoreError::OutOfTokens => {
                    "Waiting for them to come online before sending more.".into()
                }
                CoreError::RecoveryHeld => HELD_TEXT.into(),
                _ => "Couldn't send yet. We'll try again when you're back online.".into(),
            };
        }
    }

    /// A file for the window to save: in one message, or in parts.
    fn send_out_file(&self, name: String, bytes: Vec<u8>) {
        if bytes.len() <= enclave_ipc::FILE_PART {
            let _ = self.out.send(Out::File(name, bytes));
            return;
        }
        let n = bytes.chunks(enclave_ipc::FILE_PART).count();
        for (i, part) in bytes.chunks(enclave_ipc::FILE_PART).enumerate() {
            let _ = self
                .out
                .send(Out::FilePart(name.clone(), part.to_vec(), i + 1 == n));
        }
    }

    /// Conversation `id` as a place (a group or a contact).
    fn place_of(&self, id: &str) -> Option<Place> {
        self.group_of(id)
            .map(Place::Group)
            .or_else(|| self.root_of(id).map(Place::Contact))
    }

    /// The poll asked by the message at `seq` in conversation `id`.
    fn poll_at(&self, id: &str, seq: u64) -> Option<(Place, [u8; 16])> {
        let c = self.client.as_ref()?;
        let place = self.place_of(id)?;
        let poll = match place {
            Place::Group(g) => {
                c.group_messages(&g)
                    .ok()?
                    .into_iter()
                    .find(|m| m.seq == seq)?
                    .poll?
            }
            Place::Contact(r) => {
                c.messages(&r)
                    .ok()?
                    .into_iter()
                    .find(|m| m.seq == seq)?
                    .poll?
            }
        };
        Some((place, poll))
    }

    /// The id of the message at `seq` in conversation `id`.
    fn message_id_at(&self, id: &str, seq: u64) -> Option<[u8; 16]> {
        let c = self.client.as_ref()?;
        if let Some(gid) = self.group_of(id) {
            return c
                .group_messages(&gid)
                .ok()?
                .into_iter()
                .find(|m| m.seq == seq)
                .map(|m| m.id);
        }
        let root = self.root_of(id)?;
        c.messages(&root)
            .ok()?
            .into_iter()
            .find(|m| m.seq == seq)
            .map(|m| m.id)
    }

    /// Forward the message at `seq` in `from` to conversation `to`: a text
    /// goes as "Forwarded"; a file is fetched and sent again (sealed anew,
    /// so nothing links the two copies).
    async fn forward(&mut self, from: &str, seq: u64, to: &str) {
        let (from_g, from_r) = (self.group_of(from), self.root_of(from));
        let (to_g, to_r) = (self.group_of(to), self.root_of(to));
        let Some(c) = self.client.as_mut() else {
            return;
        };
        // What it is: its text, and its file if it has one.
        let found = if let Some(gid) = from_g {
            c.group_messages(&gid)
                .ok()
                .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                .filter(|m| !m.deleted && !m.notice && m.poll.is_none() && m.sticker.is_none())
                .map(|m| (m.text, m.attachment))
        } else if let Some(root) = from_r {
            c.messages(&root)
                .ok()
                .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                .filter(|m| !m.deleted && !m.notice && m.sticker.is_none() && m.location.is_none())
                .map(|m| (m.text, m.attachment))
        } else {
            None
        };
        let Some((text, attachment)) = found else {
            self.status = "That message can't be forwarded.".into();
            return;
        };
        let Some(a) = attachment else {
            let opts = enclave_core::TextOptions {
                reply: None,
                forwarded: true,
            };
            self.send_with(to, &text, opts).await;
            return;
        };
        let bytes = if let Some(gid) = from_g {
            c.fetch_group_attachment(&gid, seq).await
        } else if let Some(root) = from_r {
            c.fetch_attachment(&root, seq).await
        } else {
            return;
        };
        let Ok(bytes) = bytes else {
            self.status = "Couldn't fetch the file to forward it. Check your connection.".into();
            return;
        };
        let sent = if let Some(gid) = to_g {
            c.send_group_file(&gid, &a.name, &a.mime, &bytes, &text)
                .await
                .is_ok()
        } else if let Some(root) = to_r {
            c.send_attachment(&root, &a.name, &a.mime, &bytes, &text)
                .await
                .is_ok()
        } else {
            false
        };
        if !sent {
            self.status = "Couldn't forward the file yet. Check your connection.".into();
        }
    }

    fn push(&self) {
        let _ = self.out.send(Out::Snapshot(Box::new(self.snapshot())));
    }

    /// The recovery words from what was typed: the words themselves, or
    /// friends' shares (sealed codes open with our share request's keys).
    fn words_from(&self, secrets: &[String]) -> std::result::Result<String, String> {
        let mut opened = Vec::new();
        for s in secrets.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if s.starts_with(enclave_core::client::SHARE_PREFIX) {
                match self.share_request.as_ref().map(|r| r.open(s)) {
                    Some(Ok(w)) => opened.push(w.to_string()),
                    _ => return Err("One of your friends' codes doesn't open on this device. Ask them to scan the code on this screen again.".into()),
                }
            } else {
                opened.push(s.to_string());
            }
        }
        let refs: Vec<&str> = opened.iter().map(String::as_str).collect();
        if refs.len() == 1 {
            Ok(refs[0].to_string())
        } else {
            enclave_core::words_from_shares(&refs).map_err(|_| {
                "Those shares don't fit together, or there aren't enough of them. Check each one, or ask one more friend.".into()
            })
        }
    }

    /// Restore from `archive`, or (`None`) from the backup on the server.
    async fn restore_from(&mut self, secrets: Vec<String>, archive: Option<Vec<u8>>) {
        self.restore_error.clear();
        self.busy = true;
        self.push();
        let words = match self.words_from(&secrets) {
            Ok(w) => w,
            Err(why) => {
                self.restore_error = why;
                self.busy = false;
                return;
            }
        };
        let restored = match &archive {
            Some(a) => {
                Client::restore(&words, a, self.options(None), Arc::clone(&self.transport)).await
            }
            None => {
                Client::restore_from_server(
                    &words,
                    self.server,
                    self.options(None),
                    Arc::clone(&self.transport),
                )
                .await
            }
        };
        match restored {
            Ok(mut c) => {
                self.configure(&mut c);
                self.client = Some(c);
                self.share_request = None;
                self.status = "Your account is back on this device. Contacts will accept it after 72 hours unless one of your other devices stops it.".into();
            }
            Err(CoreError::Server(_)) if archive.is_none() => {
                self.restore_error = "Your server has no backup for these words. Check the words, or restore from a backup file.".into();
            }
            Err(CoreError::Net(_)) => {
                self.restore_error = "Couldn't reach your server. Try again in a moment.".into();
            }
            Err(_) => {
                self.restore_error = if secrets.iter().filter(|s| !s.trim().is_empty()).count() > 1
                {
                    "Those shares don't fit together, or there aren't enough of them. Check each one, or ask one more friend.".into()
                } else {
                    "The recovery words or the backup don't match. Check the words, and that the file is your Enclave backup.".into()
                };
            }
        }
        self.busy = false;
    }

    /// Where the lock settings live (beside the profile; the demo keeps
    /// them in memory).
    fn lock_path(&self) -> Option<PathBuf> {
        match &self.mode {
            Mode::Server { profile, .. } => Some(profile.join("lock.bin")),
            Mode::Demo => None,
        }
    }

    fn load_lock(&mut self) {
        if let Some(p) = self.lock_path()
            && let Ok(b) = std::fs::read(p)
        {
            self.lock = crate::lock::LockFile::decode(&b);
        }
    }

    fn save_lock(&mut self) -> bool {
        let (Some(p), Some(l)) = (self.lock_path(), &self.lock) else {
            return self.lock_path().is_none();
        };
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, l.encode()).is_ok() && std::fs::rename(&tmp, &p).is_ok()
    }

    /// The lock settings, made if there are none yet.
    fn lock_mut(&mut self) -> Option<&mut crate::lock::LockFile> {
        if self.lock.is_none() {
            let params = match self.mode {
                Mode::Demo => PwParams::FLOOR,
                Mode::Server { .. } => PwParams::DESKTOP_DEFAULT,
            };
            let mut rng = enclave_crypto::rng::HedgedRng::new().ok()?;
            self.lock = crate::lock::LockFile::new(params, &mut rng);
        }
        self.lock.as_mut()
    }

    /// Lock now: with a passphrase the profile closes (its keys leave
    /// memory); with an app PIN the window locks and the profile keeps
    /// receiving. Neither: nothing to lock with.
    fn lock_now(&mut self) {
        if self.client.is_none() {
            return;
        }
        if self.passphrase_set {
            // Dropping the client drops its keys and the open database.
            self.client = None;
        } else if self.lock.as_ref().is_some_and(|l| l.app_set) {
            self.pin_locked = true;
        } else {
            return;
        }
        self.locked = true;
        self.selected = None;
        self.selected_group = None;
        self.selected_notes = false;
        self.reveal_words = false;
        self.search.clear();
    }

    /// Time to lock: unused for longer than the timeout, with something to
    /// lock with.
    fn idle_lock_due(&self) -> bool {
        let timeout = self
            .lock
            .as_ref()
            .map_or(crate::lock::DEFAULT_TIMEOUT, |l| l.timeout);
        !self.locked
            && self.client.is_some()
            && timeout > 0
            && (self.passphrase_set || self.lock.as_ref().is_some_and(|l| l.app_set))
            && self.last_use.elapsed() >= Duration::from_secs(u64::from(timeout))
    }

    /// A wrong PIN or passphrase: after five, tries are spaced out (30 s,
    /// doubling up to an hour).
    fn wrong_unlock(&mut self, why: &str) {
        self.unlock_error = why.into();
        self.lock_tries += 1;
        if self.lock_tries >= 5 {
            let secs = (30u64 << (self.lock_tries - 5).min(7)).min(3600);
            self.lock_wait = Some(std::time::Instant::now() + Duration::from_secs(secs));
        }
    }

    fn set_app_lock(&mut self, pin: &str) {
        if self.client.is_none() {
            return;
        }
        let pin = pin.trim();
        if !pin.is_empty() && pin.chars().count() < crate::lock::MIN_PIN {
            self.status = format!("A PIN needs at least {} digits.", crate::lock::MIN_PIN);
            return;
        }
        let Some(lf) = self.lock_mut() else {
            return;
        };
        if !pin.is_empty() && lf.entered(pin) == crate::lock::Entered::Emergency {
            self.status = "That's your emergency PIN. Choose another.".into();
            return;
        }
        let Ok(mut rng) = enclave_crypto::rng::HedgedRng::new() else {
            return;
        };
        if lf
            .set_app((!pin.is_empty()).then_some(pin), &mut rng)
            .is_none()
        {
            return;
        }
        let on = lf.app_set;
        // Biometrics open the app lock only while there is one.
        if !on {
            lf.biometric = false;
        }
        self.status = if !self.save_lock() {
            "Couldn't save the lock settings.".into()
        } else if on {
            "App PIN set.".into()
        } else {
            "Lock settings saved.".into()
        };
    }

    fn set_emergency_pin(&mut self, pin: &str) {
        let pin = pin.trim();
        let Some(c) = self.client.as_ref() else {
            return;
        };
        if !pin.is_empty() && pin.chars().count() < crate::lock::MIN_PIN {
            self.status = format!("A PIN needs at least {} digits.", crate::lock::MIN_PIN);
            return;
        }
        // Entering it must never be taken for unlocking.
        if !pin.is_empty() && c.is_passphrase(pin) {
            self.status = "That's your passphrase. Choose another emergency PIN.".into();
            return;
        }
        let Some(lf) = self.lock_mut() else {
            return;
        };
        if !pin.is_empty() && lf.entered(pin) == crate::lock::Entered::App {
            self.status = "That's your app PIN. Choose another emergency PIN.".into();
            return;
        }
        let Ok(mut rng) = enclave_crypto::rng::HedgedRng::new() else {
            return;
        };
        if lf
            .set_emergency((!pin.is_empty()).then_some(pin), &mut rng)
            .is_none()
        {
            return;
        }
        self.status = if !self.save_lock() {
            "Couldn't save the lock settings.".into()
        } else if pin.is_empty() {
            "Emergency PIN removed.".into()
        } else {
            "Emergency PIN set. Entering it where Enclave asks for your PIN or passphrase erases this device.".into()
        };
    }

    /// The emergency PIN: erase everything here and show the welcome
    /// screen, as on a new install.
    fn emergency_erase(&mut self) {
        self.erase_local();
        if let Some(p) = self.lock_path() {
            let _ = std::fs::remove_file(p);
        }
        self.lock = None;
        self.locked = false;
        self.pin_locked = false;
        self.passphrase_set = false;
        self.lock_tries = 0;
        self.lock_wait = None;
        self.unlock_error.clear();
        self.status.clear();
    }

    /// Crypto-erase the profile (its key goes, then its files) and go back
    /// to the welcome screen.
    fn erase_local(&mut self) {
        if let Some(c) = self.client.take() {
            let _ = c.erase();
        }
        #[cfg(target_os = "ios")]
        {
            enclave_platform::keystore::shared::delete(
                enclave_platform::keystore::shared::NOTIFY_TABLE,
            );
            self.shared_table = None;
        }
        if let Mode::Server { profile, .. } = &self.mode {
            // Every keystore secret left (all of them, if the profile was
            // closed by its passphrase) overwritten, then the files.
            let _ = crate::lock::erase_profile(profile);
        }
        self.selected = None;
        self.selected_group = None;
        self.removed = false;
        self.reveal_words = false;
        self.reveal_share = None;
        self.share_release = None;
        self.effect(Effect::Erased);
    }

    /// iOS: the notification extension's key table (each contact's and
    /// group's keys for today and yesterday, nothing else), in the Keychain
    /// item it shares with the app, whenever it changed
    /// (`docs/10-push.md` §5.1).
    #[cfg(target_os = "ios")]
    fn share_notify_table(&mut self) {
        use enclave_platform::keystore::shared;
        let Some(c) = self.client.as_ref() else {
            return;
        };
        let table = zeroize::Zeroizing::new(c.notify_table(self.transport.now()).encode());
        if self
            .shared_table
            .as_ref()
            .is_some_and(|t| t[..] == table[..])
        {
            return;
        }
        match shared::set(shared::NOTIFY_TABLE, &table) {
            Ok(()) => self.shared_table = Some(table),
            Err(e) => eprintln!("enclave-vault: notification keys: {e}"),
        }
    }

    fn effect(&self, e: Effect) {
        let _ = self.out.send(Out::Effect(e));
    }

    fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            locked: self.locked,
            unlock_error: self.unlock_error.clone(),
            can_lock: self.passphrase_set && self.client.is_some(),
            pin_lock: self.pin_locked,
            app_lock: self.lock.as_ref().is_some_and(|l| l.app_set),
            lock_timeout: self
                .lock
                .as_ref()
                .map_or(crate::lock::DEFAULT_TIMEOUT, |l| l.timeout),
            backup_check: self.backup_check.clone(),
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
            // Those taking new accounts (weight above 0), and home.
            servers: self
                .servers()
                .iter()
                .filter(|v| v.weight > 0 || v.id() == self.server)
                .map(server_row)
                .collect(),
            file_keys: self.file_keys,
            biometric: self.biometric_name.unwrap_or_default().into(),
            biometric_on: self.biometric_name.is_some()
                && self.lock.as_ref().is_some_and(|l| l.app_set && l.biometric),
            // On until turned off, and while no profile is open.
            screen_security: self
                .client
                .as_ref()
                .is_none_or(|c| !matches!(c.setting(SCREEN_SECURITY), Ok(Some(v)) if v == [0])),
            home: if self.server == ServerId::default() {
                String::new()
            } else {
                hex_server(&self.server)
            },
            ..Default::default()
        };
        (
            s.transcription,
            s.transcription_percent,
            s.transcription_error,
        ) = self.transcription_state();
        s.sandbox_weak = crate::harden::filesystem_weak();
        if let Some(r) = &self.share_request {
            s.share_request = r.code();
            s.share_request_words = r.words().join(" ");
        }
        // Locked by the app PIN: nothing from the profile.
        if self.pin_locked {
            return s;
        }
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
                    let (id, kind, tint, art) = match h.place {
                        enclave_core::Place::Contact(r) if r == c.root() => {
                            (NOTES_ID.to_string(), 2, 0, 0)
                        }
                        enclave_core::Place::Contact(r) => {
                            (hex_id(&r), 0, tint_for(&r), art_of(&r))
                        }
                        enclave_core::Place::Group(g) => (group_id_str(&g), 1, tint_for(&g), 0),
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
                        art,
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
        s.receipts_setting = c.receipts_enabled();
        s.can_change_words = c.holds_recovery_words();
        let (on, at) = c.server_backup();
        s.server_backup = on;
        s.server_backup_at = if at > 0 { day_label(at) } else { String::new() };
        s.moving = c.move_pending();
        s.can_move = c.holds_recovery_words() && !matches!(self.mode, Mode::Demo);
        s.removed = self.removed;
        s.has_root_pin = c.has_root_pin();
        s.securing = c.securing();
        s.previews = c.previews();
        s.pin_error = self.pin_error.clone();
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
        if let Some(g) = self.selected_group {
            let mut who: Vec<&str> = self
                .group_typing_until
                .iter()
                .filter(|((gid, _), (_, t))| *gid == g && *t > std::time::Instant::now())
                .map(|(_, (n, _))| n.as_str())
                .collect();
            who.sort_unstable();
            s.typing = !who.is_empty();
            s.typing_who = who.join(", ");
        }
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
                && let Some((root, r)) = &self.share_release
                && *root == sel
            {
                s.share_release = r.code.clone();
                s.share_release_words = r.words.join(" ");
            }
        }
        s.update_release = self
            .update
            .as_ref()
            .filter(|u| u.newer)
            .map(|u| u.release.clone())
            .unwrap_or_default();
        s.update_required = match c.update_required_since() {
            Ok(Some(_)) if c.receiving_stopped().unwrap_or(false) => 2,
            Ok(Some(_)) => 1,
            _ => 0,
        };
        s.build_check = self.build_check.clone();
        s.call = self.call_view();
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
        let when = |until: u64| {
            use chrono::TimeZone;
            chrono::Local
                .timestamp_opt(until as i64, 0)
                .single()
                .map(|t| t.format("%-d %b %H:%M").to_string())
                .unwrap_or_default()
        };
        s.recovery_alert = c
            .recovery_alert()
            .map(|a| when(a.until))
            .unwrap_or_default();
        let hold = c.recovery_hold();
        s.recovery_hold = hold.map(|h| when(h.until)).unwrap_or_default();
        s.recovery_stopped = hold.is_some_and(|h| h.stopped);
        if self.reveal_words {
            let lang = c
                .setting("words-language")
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "en".into());
            s.recovery_words = c.recovery_words_in(&lang).unwrap_or_default();
            s.words_language = lang;
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
                art: art_of(&ct.root),
                kind: 0,
                members: 0,
                blocked,
                ..prefs_row(c.conv_prefs(&Place::Contact(ct.root)))
            };
            if self.selected == Some(ct.root) {
                s.current = Some(row.clone());
                s.finishing = c.protection_finishing(&ct.root);
                s.gap = c.gap(&ct.root);
                s.on_record = c.on_the_record(&ct.root);
                s.closed = c.is_closed(&ct.root);
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
                                transcript: m.transcript.clone(),
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
                for (row, m) in s.messages.iter_mut().zip(msgs.iter()) {
                    row.forwarded = m.forwarded && !m.deleted;
                    row.my_reaction = m
                        .reactions
                        .iter()
                        .find(|r| r.from_us)
                        .map(|r| r.emoji.clone())
                        .unwrap_or_default();
                    if let Some(p) = m
                        .poll
                        .filter(|_| !m.deleted)
                        .and_then(|id| c.poll_in(&Place::Contact(ct.root), &id))
                    {
                        row.can_edit = false;
                        fill_poll(row, &p);
                    }
                    if let Some(id) = m.reply_to.filter(|_| !m.deleted) {
                        let q = msgs.iter().find(|x| x.id == id);
                        let who = match q {
                            Some(q) if q.outgoing => "You".to_string(),
                            _ => ct.name.clone(),
                        };
                        *row = Msg {
                            quoted: true,
                            ..quote(
                                std::mem::take(row),
                                q.map(|q| {
                                    (
                                        q.seq,
                                        who,
                                        quoted_text(&q.text, q.attachment.is_some(), q.deleted),
                                    )
                                }),
                            )
                        };
                    }
                }
                let pinned_msgs: Vec<_> = pinned
                    .iter()
                    .filter_map(|id| msgs.iter().find(|m| m.id == *id && !m.deleted))
                    .collect();
                s.pins = pinned_msgs
                    .iter()
                    .map(|m| pin_text(&m.text, m.attachment.is_some()))
                    .collect();
                s.pin_seqs = pinned_msgs.iter().map(|m| m.seq.to_string()).collect();
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
                // Read aloud in the recovery words' list, or English when
                // the two people's languages differ (18-a11y-i18n.md).
                let lang = if self.code_words_english {
                    "en".to_string()
                } else {
                    c.setting("words-language")
                        .ok()
                        .flatten()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_else(|| "en".into())
                };
                s.code_words = c.security_words(&ct.root, &lang).unwrap_or_default();
                s.code_words_english = self.code_words_english;
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
                        if m.notice {
                            m.text.clone()
                        } else if m.from.is_none() {
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
                s.on_record = g.on_record;
                s.announcement_only = c.group_announcement_only(&g.id);
                if let Some(v) = c.group_host_votes(&g.id) {
                    s.group_host = hex_server(&v.host);
                    s.group_next = v.next.as_ref().map(hex_server).unwrap_or_default();
                    for h in std::iter::once(v.host).chain(v.next) {
                        if let Some(l) = self.servers().iter().find(|l| l.id() == h)
                            && !s.servers.iter().any(|r| r.id == hex_server(&h))
                        {
                            s.servers.push(server_row(l));
                        }
                    }
                    s.group_votes = v
                        .votes
                        .iter()
                        .map(|(h, n)| format!("{}:{n}", hex_server(h)))
                        .collect();
                    s.group_admins = v.admins as u32;
                    s.group_vote = v.mine.as_ref().map(hex_server).unwrap_or_default();
                }
                s.held_moves = g
                    .held_moves
                    .iter()
                    .filter_map(|old| g.members.iter().find(|(r, _)| r == old))
                    .map(|(_, name)| name.clone())
                    .collect();
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
                        art: art_of(r),
                        admin: g.admins.contains(r),
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
                let pinned_msgs: Vec<_> = pinned
                    .iter()
                    .filter_map(|id| msgs.iter().find(|m| m.id == *id && !m.deleted))
                    .collect();
                s.pin_seqs = pinned_msgs.iter().map(|m| m.seq.to_string()).collect();
                s.pins = pinned_msgs
                    .iter()
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
                        // A membership line (`GroupMessage::notice`) is
                        // the group's, not its author's: no sender, no
                        // actions.
                        let mut msg = Msg {
                            text: group_text(m),
                            outgoing: m.from.is_none() && !m.notice,
                            time: if m.from.is_some() && m.signed == Some(false) {
                                format!("{} · not signed", clock(m.at))
                            } else {
                                clock(m.at)
                            },
                            status: if m.delivered { 1 } else { 0 },
                            sender: if m.notice {
                                String::new()
                            } else {
                                m.from_name.clone()
                            },
                            seq: m.seq,
                            pinned: !m.deleted && pinned.contains(&m.id),
                            deleted: m.deleted,
                            can_edit: m.from.is_none()
                                && !m.notice
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
                            msg.transcript = m.transcript.clone();
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
                            fill_poll(&mut msg, &p);
                        }
                        msg
                    })
                    .collect();
                for (row, m) in s.messages.iter_mut().zip(msgs.iter()) {
                    row.forwarded = m.forwarded && !m.deleted;
                    row.mentions_me = m.mentions_me && !m.deleted;
                    row.my_reaction = m
                        .reactions
                        .iter()
                        .find(|r| r.from.is_none())
                        .map(|r| r.emoji.clone())
                        .unwrap_or_default();
                    if let Some(id) = m.reply_to.filter(|_| !m.deleted) {
                        let q = msgs.iter().find(|x| x.id == id).map(|q| {
                            let who = if q.from.is_none() {
                                "You".to_string()
                            } else {
                                q.from_name.clone()
                            };
                            (
                                q.seq,
                                who,
                                quoted_text(&q.text, q.attachment.is_some(), q.deleted),
                            )
                        });
                        *row = Msg {
                            quoted: true,
                            ..quote(std::mem::take(row), q)
                        };
                    }
                }
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
        // Chat folders: their names, the one shown (the main list keeps only
        // its conversations), and those the open one is in.
        let folders = c.folders();
        s.folders = folders.iter().map(|f| f.name.clone()).collect();
        let shown = folders.iter().find(|f| f.name == self.folder).map(|f| {
            f.places
                .iter()
                .map(|p| match p {
                    Place::Contact(r) => hex_id(r),
                    Place::Group(g) => group_id_str(g),
                })
                .collect::<std::collections::HashSet<_>>()
        });
        s.folder = if shown.is_some() {
            self.folder.clone()
        } else {
            String::new()
        };
        let open = match (self.selected, self.selected_group) {
            (Some(r), _) => Some(Place::Contact(r)),
            (None, Some(g)) => Some(Place::Group(g)),
            _ => None,
        };
        s.current_folders = open.map(|p| c.folders_of(&p)).unwrap_or_default();
        for (_, r) in rows {
            if r.state != 1 && !r.archived && shown.as_ref().is_some_and(|ids| !ids.contains(&r.id))
            {
                continue;
            }
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
        let own = c.own_devices();
        s.new_device = c
            .new_device_notice()
            .map(|d| {
                let who = if d.this_device {
                    "this device"
                } else {
                    "a new device"
                };
                let at = chrono::DateTime::from_timestamp(d.added_at as i64, 0)
                    .map(|t| t.format("%-d %b %H:%M").to_string())
                    .unwrap_or_default();
                format!("{who}, {at}")
            })
            .unwrap_or_default();
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
                // History goes early only when both devices confirm: the new
                // one asks, then the one holding the root sends.
                let history_pending = can_link && !d.this_device && !c.history_sent(&d.id);
                let history_action = if history_pending && c.history_asked(&d.id) {
                    "Send history now"
                } else if !can_link && d.this_device && !c.history_received() {
                    if c.history_asked(&d.id) { "" } else { "Ask for history now" }
                } else {
                    ""
                };
                // When we last heard from another device of ours, and
                // whether it's about to be taken off for being unused.
                let used = own
                    .iter()
                    .find(|o| o.id == d.id)
                    .map(|o| {
                        if o.inactive {
                            " · Unused for 30 days: it will be removed".to_string()
                        } else {
                            chrono::DateTime::from_timestamp(o.last_seen as i64, 0)
                                .map(|t| format!(" · Last used {}", t.format("%-d %b")))
                                .unwrap_or_default()
                        }
                    })
                    .unwrap_or_default();
                Device {
                    id: d.id.iter().map(|b| format!("{b:02x}")).collect(),
                    label: label.to_string(),
                    detail: if history_pending {
                        format!(
                            "Added {day}{used} · Message history follows 24 hours after linking, sooner if both devices confirm"
                        )
                    } else {
                        format!("Added {day}{used}")
                    },
                    removable: can_link && !d.this_device,
                    history_action: history_action.to_string(),
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
/// Why a send was refused while contacts hold this device's restore.
const HELD_TEXT: &str =
    "You can send once your contacts accept this device. Until then they wouldn't get it.";

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

#[cfg(test)]
mod tests {
    use super::*;

    /// RT-12: the profile changes only at a foreground/background transition
    /// (or a Maximum privacy toggle). Activity in between (messages, syncs,
    /// bulk transfers, a window shown again while already shown) never
    /// changes it.
    #[test]
    fn rt12_profile_change_only_on_visibility_transition() {
        enum Step {
            Visible(bool),
            Maximum(bool),
            /// Anything else the engine does: it re-applies the setting.
            Activity,
        }
        use Step::*;
        let steps = [
            Activity,
            Activity,
            Visible(false),
            Activity,
            Visible(false),
            Activity,
            Visible(true),
            Visible(true),
            Activity,
            Maximum(true),
            Visible(false),
            Activity,
            Visible(true),
            Maximum(false),
            Activity,
        ];
        let (mut visible, mut maximum) = (true, false);
        let mut profile = shaping_profile(maximum, visible);
        assert_eq!(profile, Profile::Foreground, "the window starts shown");
        let mut changes = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let transition = match step {
                Visible(on) => std::mem::replace(&mut visible, *on) != *on,
                Maximum(on) => std::mem::replace(&mut maximum, *on) != *on,
                Activity => false,
            };
            let next = shaping_profile(maximum, visible);
            if next != profile {
                assert!(transition, "step {i} changed the profile");
                changes.push((i, next));
            }
            profile = next;
        }
        assert_eq!(
            changes,
            [
                (2, Profile::Background),
                (6, Profile::Foreground),
                (9, Profile::Maximum),
                // Maximum stays Maximum in the background and back.
                (13, Profile::Foreground),
            ]
        );
        assert_eq!(shaping_profile(false, false), Profile::Background);
        assert_eq!(shaping_profile(true, false), Profile::Maximum);
    }
}
