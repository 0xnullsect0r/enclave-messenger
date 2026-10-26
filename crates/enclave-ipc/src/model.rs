//! The messages and their encodings.

use crate::codec::{Reader, Writer};
use crate::{IpcError, Result};

/// Number of contact-art tints the UI has.
pub const TINT_COUNT: usize = 6;

/// Tint index derived from key bytes (the same key always gets the same art).
pub fn tint_for(key: &[u8]) -> usize {
    key.first().map(|b| *b as usize % TINT_COUNT).unwrap_or(0)
}

/// A conversation in the list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// Opaque id (a root or group id prefix).
    pub id: String,
    /// Name.
    pub name: String,
    /// Last message.
    pub preview: String,
    /// Time of the last message.
    pub time: String,
    /// Unread count.
    pub unread: i32,
    /// 0 waiting, 1 request, 2 talking.
    pub state: i32,
    /// Checked.
    pub verified: bool,
    /// Checked in person (bonded).
    pub met: bool,
    /// Tint index (below [`TINT_COUNT`]).
    pub tint: usize,
    /// 0 person, 1 group.
    pub kind: i32,
    /// Members (groups).
    pub members: i32,
    /// Pinned to the top of the list.
    pub pinned: bool,
    /// Muted.
    pub muted: bool,
    /// Archived.
    pub archived: bool,
    /// Blocked.
    pub blocked: bool,
    /// A group member who is an admin (members sheet).
    pub admin: bool,
    /// Contact art (`enclave_core::art`): filled cells in bits 0–24, the
    /// tint (0–7) in bits 25–27; 0 for none (groups, notes).
    pub art: u32,
    /// A contact's "about", from their profile.
    pub about: String,
    /// A contact's profile photo: it comes as [`Out::Preview`] for
    /// conversation `avatar/<id>`, its `seq` naming the photo.
    pub has_photo: bool,
}

/// A sticker pack added on this device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StickerPackRow {
    /// Opaque id.
    pub id: String,
    /// Its name.
    pub title: String,
    /// How many stickers.
    pub count: u32,
}

/// A server from the foundation's list, to pick as home (setting up,
/// moving) or to vote a group onto.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerRow {
    /// Its id (hex).
    pub id: String,
    /// Its domain.
    pub domain: String,
    /// Who runs it.
    pub operator: String,
    /// The operator family (servers in one family are run together).
    pub family: String,
}

/// A contact that can be picked for a new group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pick {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Tint.
    pub tint: usize,
    /// Picked.
    pub selected: bool,
}

/// A story showing now (`enclave_core::Story`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoryRow {
    /// Its key for [`Cmd::OpenStory`] and [`Cmd::DeleteStory`]; its
    /// picture comes as an [`Out::Preview`] for conversation
    /// `story/<key>`.
    pub key: String,
    /// Whose: a contact's id (as in [`Snapshot::contacts`]), or empty for
    /// ours.
    pub who: String,
    /// Their name.
    pub name: String,
    /// Its words.
    pub text: String,
    /// How long ago it was posted ("3 h").
    pub ago: String,
    /// It has a picture.
    pub picture: bool,
    /// We opened it.
    pub viewed: bool,
    /// Ours: how many it reached, and how many it still goes to.
    pub reached: u32,
    /// Ours: still to go.
    pub waiting: u32,
}

/// A device of the account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    /// Hex id.
    pub id: String,
    /// "This device", "First device", "Linked device".
    pub label: String,
    /// When it was added.
    pub detail: String,
    /// This device may remove it.
    pub removable: bool,
    /// What this device can do about message history for that device:
    /// "Send history now", "Ask for history now", or empty for nothing.
    pub history_action: String,
}

/// A message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Msg {
    /// Text.
    pub text: String,
    /// Ours.
    pub outgoing: bool,
    /// "14:02".
    pub time: String,
    /// 0 sending, 1 on its way, 2 delivered, 3 read (and every incoming
    /// message), 4 not delivered yet; negative: no mark (notes to self).
    pub status: i32,
    /// Sender name (incoming group messages).
    pub sender: String,
    /// Position in the conversation (for actions on it).
    pub seq: u64,
    /// Ours, text, not deleted, and less than 24 hours old.
    pub can_edit: bool,
    /// Deleted by its author.
    pub deleted: bool,
    /// Attached file name, or empty.
    pub file: String,
    /// The attachment is a picture the vault will send a preview of.
    pub image: bool,
    /// A poll's options (empty when the message isn't a poll).
    pub poll_options: Vec<String>,
    /// Votes per option.
    pub poll_counts: Vec<u32>,
    /// Our vote: 0 none, else the option's index plus one.
    pub poll_mine: i32,
    /// 0 not a poll, 1 open, 2 closed (tallies agree), 3 closed (the
    /// creator's tally differs from ours).
    pub poll_state: i32,
    /// We created the poll (and may close it).
    pub poll_ours: bool,
    /// Pinned in this conversation.
    pub pinned: bool,
    /// A shared contact: their name (empty when the message isn't one).
    pub contact_name: String,
    /// The shared contact is already someone we talk to (or us).
    pub contact_known: bool,
    /// A shared place: its coordinates (empty when the message isn't one).
    pub location: String,
    /// The place's label.
    pub location_label: String,
    /// A sticker (its picture comes as a preview).
    pub sticker: bool,
    /// The sticker's pack is added here.
    pub pack_added: bool,
    /// A voice note.
    pub voice: bool,
    /// Its length in milliseconds (0 until read).
    pub voice_ms: u32,
    /// Its waveform: up to 64 peak levels, 0 to 255.
    pub waveform: Vec<u8>,
    /// A clip (an animated picture): its length in milliseconds once its
    /// poster arrived, else 0.
    pub clip_ms: u32,
    /// A voice note's transcript, made on this device, or empty.
    pub transcript: String,
    /// It answers another message, quoted above it.
    pub quoted: bool,
    /// The quoted message's position (`u64::MAX`: not in this
    /// conversation any more).
    pub quote_seq: u64,
    /// Who wrote the quoted message ("You" for ours).
    pub quote_who: String,
    /// The start of its text.
    pub quote_text: String,
    /// Forwarded from another conversation.
    pub forwarded: bool,
    /// A group message that mentions us.
    pub mentions_me: bool,
    /// An anonymous poll: votes sealed to its creator.
    pub poll_anonymous: bool,
    /// How many have voted in the poll.
    pub poll_voters: u32,
    /// Our reaction to it (empty: none).
    pub my_reaction: String,
    /// A view-once picture or clip.
    pub view_once: bool,
    /// ...that this device can still open ([`Cmd::OpenViewOnce`]).
    pub view_once_ready: bool,
    /// A video too large to preview: shown with a Play button only.
    pub video: bool,
    /// The sender's link preview: the page's title (empty: none), its
    /// description and site, and whether it has a picture (which comes as
    /// an [`Out::Preview`] for this message, like a picture's).
    pub link_title: String,
    /// The page's description.
    pub link_description: String,
    /// The page's site ("example.org").
    pub link_site: String,
    /// The preview has a picture.
    pub link_image: bool,
}

/// A call as the window shows it (`docs/11-calls.md`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallView {
    /// 0 none, 1 calling (ours, not answered yet), 2 ringing (theirs), 3
    /// connecting, 4 in the call, 5 just ended (with `error` or the line).
    pub state: u8,
    /// The conversation.
    pub conversation: String,
    /// Who.
    pub name: String,
    /// With video.
    pub video: bool,
    /// Our microphone is off.
    pub muted: bool,
    /// Our camera is on (a video call).
    pub camera: bool,
    /// The size camera frames are sent at (the call's video tier; 0 for
    /// an audio call).
    pub video_width: u32,
    /// As above.
    pub video_height: u32,
    /// When it connected (Unix seconds; 0 before).
    pub connected_at: u64,
    /// The two-word call check, once both have keys.
    pub words: String,
    /// Why it failed, or how it ended.
    pub error: String,
    /// The caller asked for a direct call (shown while it rings: answering
    /// directly shows our address to them).
    pub direct_asked: bool,
    /// The media goes directly now, not through the relays.
    pub direct: bool,
    /// A group call (`conversation` is the group; `name` its name).
    pub group: bool,
    /// Our hand is raised (a group call).
    pub hand: bool,
    /// Our camera waits: eight others are on (a group call).
    pub cameras_full: bool,
    /// We share our screen instead of the camera: frames go at
    /// [`SCREEN_WIDTH`] × [`SCREEN_HEIGHT`].
    pub screen: bool,
    /// The others heard in a group call.
    pub peers: Vec<CallPeer>,
    /// Groups with a call going on that we aren't in (they show Join).
    pub live_groups: Vec<String>,
    /// The call link we made for this call (to copy and share).
    pub link: String,
    /// The link asks us first: who is waiting in its lobby.
    pub knocks: Vec<CallPeer>,
}

/// Someone in a group call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallPeer {
    /// Their id in the call ([`Out::CallTile`] names it).
    pub id: u32,
    /// Their name.
    pub name: String,
    /// Their hand is raised.
    pub hand: bool,
    /// Their reaction, while it shows.
    pub reaction: String,
}

/// Everything the window shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Our name.
    pub my_name: String,
    /// Our profile's "about".
    pub my_about: String,
    /// We have a profile photo (it comes as [`Out::Preview`] for
    /// conversation `avatar/me`).
    pub my_photo: bool,
    /// Invite link.
    pub my_link: String,
    /// Conversations.
    pub contacts: Vec<Row>,
    /// Message requests.
    pub requests: Vec<Row>,
    /// Archived conversations.
    pub archived: Vec<Row>,
    /// Selected conversation.
    pub current: Option<Row>,
    /// Its messages.
    pub messages: Vec<Msg>,
    /// Security code in groups of five digits.
    pub code_groups: Vec<String>,
    /// The same code as 10 words to read aloud.
    pub code_words: Vec<String>,
    /// The words are shown in English (else in the recovery words' list).
    pub code_words_english: bool,
    /// Status line.
    pub status: String,
    /// Recovery words: empty unless the UI asked with `RevealWords(true)`.
    pub recovery_words: Vec<String>,
    /// Recovery words saved.
    pub recovery_saved: bool,
    /// The language the recovery words are shown in (a BIP-39 list code).
    pub words_language: String,
    /// Privacy: 0 Standard, 1 Maximum (the saved setting).
    pub privacy: i32,
    /// Maximum privacy is holding what was written in the current
    /// conversation until all three KEMs protect it ("Extra protection:
    /// finishing…").
    pub finishing: bool,
    /// Setting up the account: the step under way, 1 to
    /// [`SETUP_STEPS`] (0 when not setting up).
    pub setup_step: u8,
    /// Of a setup step sent in parts (the vault key: about a hundred),
    /// the parts done (0 for other steps).
    pub setup_part: u32,
    /// How many parts that step has (0 for other steps).
    pub setup_parts: u32,
    /// About how many seconds the parts still take, at the pace so far
    /// (0 when not known yet).
    pub setup_left: u32,
    /// A message in the current conversation may not have arrived: later
    /// ones did, over a minute ago (RT-24).
    pub gap: bool,
    /// The current conversation is on the record (messages signed).
    pub on_record: bool,
    /// The current contact closed their account (read-only).
    pub closed: bool,
    /// Error for the add sheet.
    pub add_error: String,
    /// A request is in flight.
    pub busy: bool,
    /// Contacts to pick for a new group.
    pub pick: Vec<Pick>,
    /// Devices.
    pub devices: Vec<Device>,
    /// Link word choices (when a link code was scanned).
    pub link_choices: Vec<String>,
    /// Link status line.
    pub link_status: String,
    /// This device can link others.
    pub can_link: bool,
    /// Our username as `@name@domain`, or empty.
    pub my_username: String,
    /// Usernames work on this server.
    pub usernames: bool,
    /// Error for the username field.
    pub username_error: String,
    /// This device can be linked to an existing account.
    pub can_join: bool,
    /// Link code this device shows while it is being linked.
    pub join_code: String,
    /// Words to pick on the other device.
    pub join_words: String,
    /// When someone else's change to this account takes effect unless it is
    /// stopped ("3 Oct 14:02"), or empty.
    pub recovery_alert: String,
    /// This device restored the account and contacts hold it until this
    /// time ("3 Oct 14:02"), or empty. It can't send meanwhile.
    pub recovery_hold: String,
    /// Another device of the account stopped this device's restore.
    pub recovery_stopped: bool,
    /// Our in-person code while the meet sheet is open.
    pub meet_code: String,
    /// Seal words after scanning their code.
    pub meet_words: String,
    /// Who we scanned.
    pub meet_name: String,
    /// Why their code didn't work.
    pub meet_error: String,
    /// Name of the person we just met (confirmed), or empty.
    pub meet_done: String,
    /// Disappearing timer of the open conversation, seconds (0 off).
    pub timer: u32,
    /// Search results (conversation rows with a snippet as the preview),
    /// newest first; empty when not searching.
    pub search: Vec<Row>,
    /// Our username (`@name@domain`) if the server's log no longer leads to
    /// us, or empty.
    pub username_problem: String,
    /// The domain of a username server proven to show people different
    /// versions of its log (RT-04), or empty.
    pub kt_split: String,
    /// How wrong the device clock is against trusted time ("3 hours
    /// behind"), or empty when it is right (RT-23).
    pub clock_skew: String,
    /// A newer release the vault checked (`v1.2.3`), or empty.
    pub update_release: String,
    /// Below a release's minimum version: 0 no, 1 sending stopped, 2
    /// receiving stopped too (`docs/19-ops.md` §4).
    pub update_required: u8,
    /// What "Verify this build" found, or empty.
    pub build_check: String,
    /// The call, if there is one.
    pub call: CallView,
    /// Voice-note transcription's model: 0 not downloaded, 1 downloading,
    /// 2 ready (`docs/18-a11y-i18n.md` §4).
    pub transcription: u8,
    /// How much of the model has come, in percent, while downloading.
    pub transcription_percent: u8,
    /// Why the last download failed, or empty.
    pub transcription_error: String,
    /// A device linked to the account in the last 7 days ("Linked device,
    /// 30 Sep 14:02"), pointed out on every device, or empty.
    pub new_device: String,
    /// Names of groups we asked to join that haven't let us in yet.
    pub joining: Vec<String>,
    /// Why restoring failed.
    pub restore_error: String,
    /// Accepted contacts who could hold a share of our recovery.
    pub friends: Vec<Pick>,
    /// Stories showing now, newest first: ours and our contacts'.
    pub stories: Vec<StoryRow>,
    /// Who our stories go to: accepted contacts, `selected` unless hidden.
    pub story_audience: Vec<Pick>,
    /// Who holds a share of our recovery, and how many are needed.
    pub share_holders: Vec<String>,
    /// Shares needed to rebuild our recovery (0: none given).
    pub share_threshold: u32,
    /// We hold part of the open contact's recovery.
    pub holds_share: bool,
    /// The share we hold for the open contact, sealed to the code on
    /// their new device (`enclave:share#…`): only while shown.
    pub share_release: String,
    /// The three words their screen shows too.
    pub share_release_words: String,
    /// Before there is an account: our request for friends' shares
    /// (`enclave:release#…`), once asked for.
    pub share_request: String,
    /// The three words each friend's screen should show.
    pub share_request_words: String,
    /// The open conversation's pinned messages (text, most recently
    /// pinned first).
    pub pins: Vec<String>,
    /// Their messages' positions (`seq`), in the same order, to jump to.
    pub pin_seqs: Vec<String>,
    /// Sticker packs added here.
    pub sticker_packs: Vec<StickerPackRow>,
    /// Members of the open group (other than us).
    pub members: Vec<Row>,
    /// We are an admin of the open group.
    pub group_admin: bool,
    /// Contacts that could be added to the open group.
    pub addable: Vec<Pick>,
    /// The profile needs its passphrase.
    pub locked: bool,
    /// Why unlocking failed.
    pub unlock_error: String,
    /// The profile has a passphrase, so it can be locked.
    pub can_lock: bool,
    /// Invite links that still work.
    pub invites: u32,
    /// Typing indicators are on (Settings).
    pub typing_setting: bool,
    /// Read receipts are on (Settings; on unless turned off).
    pub receipts_setting: bool,
    /// Link previews are on (off by default).
    pub link_previews: bool,
    /// GIF search is on (off by default).
    pub gif_search: bool,
    /// The open conversation's contact is typing.
    pub typing: bool,
    /// In a group: who is typing ("Ana, Ben"), when someone is.
    pub typing_who: String,
    /// The open group is announcement-only: only admins post.
    pub announcement_only: bool,
    /// Chat folders' names, in order.
    pub folders: Vec<String>,
    /// The folder the list shows (empty: all).
    pub folder: String,
    /// The folders the open conversation is in.
    pub current_folders: Vec<String>,
    /// Linux without (full) Landlock: the vault couldn't confine its files
    /// (PC-46).
    pub sandbox_weak: bool,
    /// This device can change the recovery words (it holds them).
    pub can_change_words: bool,
    /// Our change of recovery words is still reaching contacts and groups.
    pub words_pending: bool,
    /// This device was removed from the account: it can't get new
    /// messages, and may be erased.
    pub removed: bool,
    /// Root actions need the PIN.
    pub has_root_pin: bool,
    /// "Secure my account" is still reaching contacts and groups.
    pub securing: bool,
    /// Notifications show who wrote and a preview.
    pub previews: bool,
    /// Why the PIN wasn't taken, or empty.
    pub pin_error: String,
    /// The open conversation's contact changed their recovery words:
    /// 0 no, 1 confirmed by their old key, 2 not confirmed.
    pub moved: u8,
    /// Members of the open group whose change of recovery words is on
    /// hold here: we never got it from them (names).
    pub held_moves: Vec<String>,
    /// The route to the home server (`docs/09-transport.md` §7): 0 the
    /// mixnet, 1 the mixnet is unreachable and the backup route (Tor to the
    /// server's onion service) can be offered, 2 on the backup route.
    pub route: u8,
    /// Tor didn't come up: the network may be blocking it.
    pub tor_blocked: bool,
    /// Tor bridges set here: empty, `builtin`, `snowflake`, or bridge lines.
    pub bridges: String,
    /// Why the bridges given weren't taken.
    pub bridges_error: String,
    /// The bridges changed since Enclave started: they apply after a
    /// restart.
    pub bridges_restart: bool,
    /// The window is locked by the app PIN (not the passphrase).
    pub pin_lock: bool,
    /// An app PIN is set (`docs/14-storage.md` §5).
    pub app_lock: bool,
    /// Seconds without use before the app locks (0: never).
    pub lock_timeout: u32,
    /// A backup is kept on the home server.
    pub server_backup: bool,
    /// When it last went up (a date), or empty.
    pub server_backup_at: String,
    /// What checking a backup found, or empty.
    pub backup_check: String,
    /// The servers in the foundation's list.
    pub servers: Vec<ServerRow>,
    /// The home server's id (hex): the profile's, or (setting up) the one
    /// picked. Empty when this build has no server to offer.
    pub home: String,
    /// Our move to another server is still reaching contacts and groups.
    pub moving: bool,
    /// This device can move the account (it holds the recovery words).
    pub can_move: bool,
    /// The open group's server (id, hex).
    pub group_host: String,
    /// The server the open group moves to tomorrow (id, hex), or empty.
    pub group_next: String,
    /// Votes to move the open group: "id:votes", the server ids in hex.
    pub group_votes: Vec<String>,
    /// How many admins the open group has.
    pub group_admins: u32,
    /// The server we voted to move the open group to, or empty.
    pub group_vote: String,
    /// Keys are kept in files in the profile, not a platform keystore (a
    /// passphrase is recommended).
    pub file_keys: bool,
    /// The window is kept out of screen capture (on unless turned off).
    pub screen_security: bool,
    /// What this computer's biometric unlock is called ("Touch ID",
    /// "Windows Hello"), when it has one set up; else empty.
    pub biometric: String,
    /// It opens the app lock.
    pub biometric_on: bool,
}

/// UI → vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Create the account: name, passphrase (empty for none).
    Create(String, String),
    /// Open a conversation (empty id closes it).
    Select(String),
    /// Send text to a conversation.
    Send(String, String),
    /// Accept a message request.
    Accept(String),
    /// Delete a request or contact.
    Decline(String),
    /// Add from an invite link or username, with an optional first message.
    Add(String, String),
    /// "They match".
    Check(String),
    /// Privacy profile: 0 standard, 1 maximum.
    Privacy(i32),
    /// Recovery words written down.
    WordsSaved,
    /// Toggle a contact in the new-group picker.
    TogglePick(String),
    /// Create a group from the picked contacts.
    CreateGroup(String),
    /// A link code was pasted on the devices screen.
    LinkScan(String),
    /// The person picked link words (index).
    LinkPick(i32),
    /// Claim a username.
    ClaimUsername(String),
    /// Remove a linked device (hex id).
    RemoveDevice(String),
    /// Link this device to an existing account.
    StartJoin,
    /// Stop linking this device.
    CancelJoin,
    /// Send message history to a linked device now (hex id).
    SendHistory(String),
    /// "This wasn't me": veto the pending change to this account.
    StopRecovery,
    /// "It's me": approve the pending change to this account.
    ApproveRecovery,
    /// The meet sheet opened (make a code) or closed (forget it).
    Meet(bool),
    /// Their in-person code.
    MeetScan(String),
    /// The Seal words match.
    MeetConfirm,
    /// Include the recovery words in snapshots (only while the recovery
    /// sheet is open), or stop.
    RevealWords(bool),
    /// React to a message: conversation, seq, emoji (empty removes).
    React(String, u64, String),
    /// Edit one of our messages: conversation, seq, new text.
    Edit(String, u64, String),
    /// Delete one of our messages for everyone: conversation, seq.
    Delete(String, u64),
    /// Disappearing timer for a conversation, seconds (0 off).
    Timer(String, u32),
    /// Send a file: conversation, name, bytes, caption.
    SendFile(String, String, Vec<u8>, String),
    /// Download an attachment to hand to the UI: conversation, seq.
    SaveFile(String, u64),
    /// Search messages (empty stops searching).
    Search(String),
    /// Add the picked contacts to a group.
    AddMembers(String),
    /// Remove a member from a group: group, member.
    RemoveMember(String, String),
    /// Make a group member an admin, or no longer one: group id, member
    /// id, admin.
    SetGroupAdmin(String, String, bool),
    /// Leave a group.
    LeaveGroup(String),
    /// Open a locked profile with its passphrase.
    Unlock(String),
    /// Lock now: drop the open profile from memory.
    Lock,
    /// Set or change the passphrase (empty removes it).
    SetPassphrase(String),
    /// Make an invite link for this many people; it comes back as
    /// [`Out::Invite`].
    NewInvite(u8),
    /// Cancel every invite link.
    CancelInvites,
    /// Make a group invite link (admins): group, how many people, whether
    /// each join waits for approval. It comes back as [`Out::Invite`].
    NewGroupInvite(String, u8, bool),
    /// Ask a question: conversation (a group or 1:1), question, options,
    /// anonymous (groups only: votes sealed to us, counts at the close).
    CreatePoll(String, String, Vec<String>, bool),
    /// Vote in the poll at a message: conversation, position, option index.
    Vote(String, u64, u32),
    /// Close our poll at a group message: group, position.
    ClosePoll(String, u64),
    /// Export an encrypted backup (with photos and files if `true`); it
    /// comes back as [`Out::File`].
    SaveBackup(bool),
    /// Restore on this new device: the recovery words (one item) or
    /// friends' shares (one per item), and the backup file.
    Restore(Vec<String>, Vec<u8>),
    /// Split our recovery among these contacts; this many are needed.
    GiveShares(Vec<String>, u32),
    /// Show the recovery share we hold for this contact (empty id: hide it).
    RevealShare(String),
    /// Pin (true) or unpin a message: conversation, position.
    Pin(String, u64, bool),
    /// How to list a conversation: id, archived, pinned to the top, muted.
    ConvPrefs(String, bool, bool, bool),
    /// Block (true) or unblock a contact.
    Block(String, bool),
    /// Share a contact into a conversation: conversation, contact.
    ShareContact(String, String),
    /// Add the contact shared at a message: conversation, position.
    AddShared(String, u64),
    /// Share a place: conversation, latitude, longitude (degrees, as
    /// typed), label.
    ShareLocation(String, String, String, String),
    /// Report a contact to their server's operator: id, reason (1 spam,
    /// 2 abuse, 3 other), quote their latest messages, also block them,
    /// make message requests to us cost more for a month (spam only).
    Report(String, u8, bool, bool, bool),
    /// Make a sticker pack: title, pictures (as read from files).
    CreatePack(String, Vec<Vec<u8>>),
    /// Send a sticker: conversation, pack id, index.
    SendSticker(String, String, u32),
    /// Add the pack of the sticker at a message: conversation, position.
    AddPack(String, u64),
    /// Send the UI previews of every added pack's stickers.
    LoadStickers,
    /// Turn typing indicators on or off.
    TypingSetting(bool),
    /// Read receipts on or off, both ways.
    ReceiptsSetting(bool),
    /// The draft in a conversation changed: non-empty (typing) or not.
    Typing(String, bool),
    /// Replace the recovery words (a new root; 03 §8.2).
    ChangeWords,
    /// Play the clip at a message: conversation, position.
    PlayClip(String, u64),
    /// Use the backup route (true), or the mixnet again (false: "Keep
    /// waiting", "Back to the private route").
    BackupRoute(bool),
    /// Tor bridges: empty (none), `builtin`, `snowflake`, or bridge lines.
    SetBridges(String),
    /// Put the current conversation on the record (or off it).
    SetOnRecord(bool),
    /// The open group announcement-only (only admins post), or open again.
    SetAnnouncementOnly(bool),
    /// A new chat folder, by name.
    NewFolder(String),
    /// Delete a chat folder.
    DeleteFolder(String),
    /// Put the open conversation in a folder (true) or take it out.
    InFolder(String, bool),
    /// Show only a folder's conversations in the list (empty: all).
    ShowFolder(String),
    /// A link opened from outside the app (a tapped `enclave:` link, an
    /// `https://<host>/i#…` page's button): shown in the Add screen once
    /// the profile is open ([`Out::OpenLink`]).
    OpenLink(String),
    /// Send a text that answers a message: conversation, text, the
    /// answered message's position.
    SendReply(String, String, u64),
    /// Forward a message: from conversation, its position, to
    /// conversation.
    Forward(String, u64, String),
    /// The next part (at most [`FILE_PART`]) of a large file or backup
    /// the window reads; the command after uses what was staged.
    Stage(Vec<u8>),
    /// Send what was staged as a file: conversation, name, caption.
    SendStaged(String, String, String),
    /// "Open with…" the file at a message (after the window's warning): it
    /// comes back like a save, after [`Out::OpenNext`].
    OpenFile(String, u64),
    /// Send what was staged as a picture or clip to be viewed once:
    /// conversation, name, caption.
    SendViewOnce(String, String, String),
    /// Open a view-once picture or clip, once: it comes back as a viewer
    /// clip ([`Out::Clip`]) and is gone from here and our other devices.
    OpenViewOnce(String, u64),
    /// List every file in every conversation ([`Out::Gallery`]).
    AllFiles,
    /// Remove an added sticker pack (its id).
    RemovePack(String),
    /// Our display name.
    SetName(String),
    /// Our profile's "about".
    SetAbout(String),
    /// Our profile photo: a picture (re-encoded first), or empty for none.
    SetPhoto(Vec<u8>),
    /// Show the pack a sticker message carries before adding it: its
    /// title and count ([`Out::PackPreview`]), then each picture as a
    /// [`Out::Preview`] for conversation [`PACK_PREVIEW`].
    PreviewPack(String, u64),
    /// Link previews on or off.
    LinkPreviewsSetting(bool),
    /// GIF search on or off.
    GifSearchSetting(bool),
    /// Search for GIFs through Tor: the results come as [`Out::Gifs`],
    /// then each one's first frame as an [`Out::Preview`] for conversation
    /// [`GIF_RESULTS`] (its position as `seq`).
    GifSearch(String),
    /// Send a GIF from the last search: conversation, its position.
    SendGif(String, u32),
    /// Post a story: its words, and a picture's file name and bytes (empty
    /// for none; re-encoded first).
    PostStory(String, String, Vec<u8>),
    /// Delete one of our stories (its key).
    DeleteStory(String),
    /// Open a story (its key): marked viewed, and its picture sent.
    OpenStory(String),
    /// Hide our stories from a contact (true) or not.
    StoryHidden(String, bool),
    /// Start a video for a conversation (its name, and the size from
    /// `enclave_media::movie::video_size`): frames and sound follow, from
    /// the camera or a video file.
    RecordStart(String, String, u32, u32),
    /// The video's next frame: RGBA at its size, 30 a second.
    RecordFrame(Vec<u8>),
    /// More of its sound: 48 kHz mono, 16-bit little-endian.
    RecordSound(Vec<u8>),
    /// Finish it and send it, with this caption.
    RecordEnd(String),
    /// Throw it away.
    RecordCancel,
    /// Ask for the next piece of the video playing ([`Out::VideoPiece`]).
    VideoMore(String),
    /// Stop the video playing.
    StopVideo,
    /// Show the recovery words in this BIP-39 language (its code).
    WordsLanguage(String),
    /// Show the security code's words in English (else in the recovery
    /// words' language).
    CodeWordsEnglish(bool),
    /// Seal the share we hold for the open contact to the code on their
    /// new device (scanned or pasted), after they confirmed they're with
    /// them.
    ReleaseShare(String),
    /// Before there is an account: show a request for friends' shares.
    AskShares,
    /// Delete the account everywhere, then erase this device
    /// (`docs/03-identity.md` §8.5). Only on the device holding the words.
    DeleteAccount,
    /// Erase this device's copy of the account (it was removed, or the
    /// person wants it gone from here).
    EraseDevice,
    /// Set (or, after `UnlockRoot` with the old one, change) the PIN for
    /// root actions.
    SetRootPin(String),
    /// Enter the PIN before a root action (sent just before it).
    UnlockRoot(String),
    /// Replace the account's keys, inboxes and prekeys
    /// (`docs/03-identity.md` §5.2).
    SecureAccount,
    /// Ask contacts for previews in notification capsules (or stop).
    SetPreviews(bool),
    /// Set the app PIN (empty: none) (`docs/14-storage.md` §5).
    SetAppLock(String),
    /// The time without use before the app locks, in seconds (0: never).
    SetLockTimeout(u32),
    /// Keep a backup on the home server, renewed weekly (or stop, and
    /// delete it) (`docs/14-storage.md` §4).
    ServerBackup(bool),
    /// Check a backup with the recovery words: the archive given, or (if
    /// empty) the one on the home server.
    CheckBackup(String, Vec<u8>),
    /// Restore from the backup on the home server: the words, or friends'
    /// shares, as for [`Cmd::Restore`].
    RestoreFromServer(Vec<String>),
    /// Set the emergency PIN (empty: none): entered where a PIN or the
    /// passphrase is asked for, it erases this device.
    SetEmergencyPin(String),
    /// Setting up: use this server (id, hex) as home.
    PickServer(String),
    /// Move the account to this server (id, hex) (`docs/12-servers.md` §4).
    MoveHome(String),
    /// Vote to move the open group to this server (id, hex) (admins;
    /// `docs/07-groups.md` §4).
    VoteGroupHost(String),
    /// Keep the window out of screenshots and screen sharing (or stop).
    SetScreenSecurity(bool),
    /// Open the app lock with Touch ID or Windows Hello; the window that
    /// asks (Windows: its HWND, to attach the prompt to), or 0.
    UnlockBiometric(u64),
    /// Let Touch ID or Windows Hello open the app lock (or stop).
    SetBiometric(bool),
    /// The window serves the history for this token at these addresses
    /// (empty: it can't).
    LanServing(String, Vec<String>),
    /// History chunks fetched for this token, in order, in batches;
    /// `true` on the last.
    LanChunks(String, Vec<Vec<u8>>, bool),
    /// The history for this token couldn't be fetched.
    LanFailed(String),
    /// The window is in front (true) or not: Foreground or Background
    /// traffic profile (`docs/09-transport.md` §6), unless Maximum.
    Visible(bool),
    /// The phone's push token for this app (platform: 1 UnifiedPush
    /// endpoint, 2 APNs device token in hex, 3 FCM token, 4 PushKit VoIP
    /// token in hex for calls), to register
    /// with the home server sealed to the push relay; an empty token
    /// removes it (`docs/10-push.md` §2).
    PushToken(u8, String),
    /// A push woke the app: sync now rather than at the next tick.
    Wake,
    /// A new window joined a vault that kept running (a phone's activity
    /// made again): send it everything, pictures included.
    Reattach,
    /// "Verify this build": the running programs' hashes, to check against
    /// the newest release the vault has checked (`docs/19-ops.md` §1.3).
    VerifyBuild(Vec<FileHash>),
    /// Ask the home server for release updates now.
    CheckUpdates,
    /// Call a contact (conversation id), with video or not, directly or
    /// not (direct shows each side's internet address to the other).
    StartCall(String, bool, bool),
    /// Take the call that is ringing (through the relays).
    AnswerCall,
    /// Take the call that is ringing directly, as the caller asked (shows
    /// our internet address to them).
    AnswerCallDirect,
    /// Turn down the call that is ringing.
    DeclineCall,
    /// Hang up (or stop calling).
    EndCall,
    /// Turn our microphone off or on.
    CallMute(bool),
    /// The microphone's next 20 ms: 960 samples, 48 kHz mono.
    CallMic(Vec<i16>),
    /// Turn our camera off or on (a video call).
    CallCamera(bool),
    /// A camera frame: width, height (the call's video size), RGBA.
    CallFrame(u32, u32, Vec<u8>),
    /// Start a call in a group (conversation id), with video or not.
    StartGroupCall(String, bool),
    /// Join the call going on in a group.
    JoinGroupCall(String),
    /// Raise (true) or lower our hand in a group call.
    CallHand(bool),
    /// A reaction in a group call (an emoji).
    CallReact(String),
    /// Make a link to the group call we're in: true asks us before letting
    /// each person in (a lobby), false lets anyone with it in.
    CreateCallLink(bool),
    /// Let someone waiting in the call link's lobby in.
    AdmitToCall(u32),
    /// Turn someone waiting in the lobby away.
    RefuseFromCall(u32),
    /// Share the screen instead of the camera in a video call (true), or
    /// stop.
    CallScreen(bool),
    /// Play a voice note (conversation, message): its sound comes back in
    /// pieces ([`Out::VoiceAudio`]).
    PlayVoice(String, u64),
    /// Turn voice-note transcription on (download its model through Tor)
    /// or off (delete the model).
    TranscriptionModel(bool),
    /// Transcribe a voice note (conversation, message) on this device.
    Transcribe(String, u64),
}

/// Most samples in one [`Out::VoiceAudio`] (10 s at 48 kHz).
pub const VOICE_PIECE: usize = 480_000;

/// Most bytes of a file in one message between the window and the vault:
/// larger files go in parts ([`Cmd::Stage`], [`Out::FilePart`]), well
/// under the frame limit.
pub const FILE_PART: usize = 8 << 20;
/// Most bytes the vault holds staged from the window (a file of up to
/// 100 MiB, a backup with its media).
pub const MAX_STAGED: usize = 512 << 20;

/// The size a shared screen's frames go at ([`Cmd::CallFrame`]).
pub const SCREEN_WIDTH: u32 = 960;
/// As above.
pub const SCREEN_HEIGHT: u32 = 540;

/// Most people a group call shows.
pub const MAX_CALL_PEERS: usize = 64;

/// Most samples in one [`Cmd::CallMic`] or [`Out::CallAudio`] (20 ms).
pub const CALL_FRAME: usize = 960;

/// A file's name (as release targets name it) and hashes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileHash {
    /// `program@target-triple`, or a release file's name.
    pub name: String,
    /// Length in bytes.
    pub length: u64,
    /// SHA-256.
    pub sha256: Vec<u8>,
    /// SHA3-512.
    pub sha3_512: Vec<u8>,
}

/// One-off UI resets after a request succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Close the open sheet and clear the add fields.
    ContactAdded,
    /// Close the open sheet and clear the group name.
    GroupCreated,
    /// Clear the username field.
    UsernameClaimed,
    /// Close the attach sheet and clear it.
    FileSent,
    /// Close the members sheet and the conversation.
    LeftGroup,
    /// Clear the passphrase fields.
    PassphraseChanged,
    /// Close the device-removal confirmation.
    RemovalDone,
    /// Close the poll sheet and clear it.
    PollCreated,
    /// The account or this device was erased: back to the welcome screen.
    Erased,
}

/// How many steps setting up an account takes ([`Snapshot::setup_step`]).
pub const SETUP_STEPS: u8 = 8;

/// Vault → UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// New display state.
    Snapshot(Box<Snapshot>),
    /// A one-off reset.
    Effect(Effect),
    /// A downloaded attachment for the UI to save: name, bytes.
    File(String, Vec<u8>),
    /// A new invite link, for the UI to copy.
    Invite(String),
    /// A picture's preview: conversation, message position, RGBA pixels.
    Preview(Preview),
    /// A clip's frames to play.
    Clip(ClipFrames),
    /// Something to tell the person about while the window isn't in front:
    /// a desktop notification (what it says is the vault's choice: names
    /// and text only with previews on, `docs/14-storage.md` §5).
    Notify(Notice),
    /// History for our other device, to serve on the local network
    /// (`docs/03-identity.md` §4.3): sealed chunks, in order, for the
    /// token (hex), in batches; `true` on the last, after which the window
    /// serves them and answers [`Cmd::LanServing`].
    LanChunks(String, Vec<Vec<u8>>, bool),
    /// Stop serving the history for this token.
    LanStop(String),
    /// Fetch history offered on the local network: token, the other
    /// window's addresses, how many chunks. The chunks come back as
    /// [`Cmd::LanChunks`] (or [`Cmd::LanFailed`]).
    LanFetch(String, Vec<String>, u32),
    /// The update bundle the vault checked (`enclave_update::Bundle`), for
    /// the window's updater to check a download against before installing
    /// it (`docs/19-ops.md` §1.5).
    UpdateBundle(Vec<u8>),
    /// The call's next 20 ms to play: 960 samples, 48 kHz mono.
    CallAudio(Vec<i16>),
    /// The other person's newest picture: width, height, RGBA.
    CallVideo(u32, u32, Vec<u8>),
    /// A group call: one participant's newest picture (participant id,
    /// width, height, RGBA).
    CallTile(u32, u32, u32, Vec<u8>),
    /// A voice note to play ([`Cmd::PlayVoice`]): which (`conversation:seq`),
    /// whether this is its first piece, and up to [`VOICE_PIECE`] samples
    /// of 48 kHz mono.
    VoiceAudio(String, bool, Vec<i16>),
    /// Open the Add screen with this link in it (from [`Cmd::OpenLink`]):
    /// the person still taps Add, so a link can't act on its own.
    OpenLink(String),
    /// A part of a large file for the window to save: name, bytes, the
    /// last one (then it is saved like [`Out::File`]).
    FilePart(String, Vec<u8>, bool),
    /// The next file ([`Out::File`] or parts) is to open in another app,
    /// not to save.
    OpenNext,
    /// Every file in every conversation, newest first ([`Cmd::AllFiles`]).
    Gallery(Vec<GalleryRow>),
    /// A sticker pack before adding it ([`Cmd::PreviewPack`]): its title
    /// and how many stickers.
    PackPreview(String, u32),
    /// A GIF search's results ([`Cmd::GifSearch`]): each one's name, in
    /// order (empty: none found).
    Gifs(Vec<String>),
    /// A piece of the video playing (after [`Cmd::PlayClip`] on a video,
    /// then [`Cmd::VideoMore`]).
    VideoPiece(VideoPiece),
    /// Frames of the video being made encoded so far (so a file is read
    /// no faster than that).
    RecordProgress(u32),
    /// Something slow under way (over Tor most things take seconds; a key
    /// a hundred chunks): what ("Sending your request…", empty when it is
    /// done), the part being fetched or sent ("Their keys"), and how far
    /// (done of total; 0 of 0 when not known). The window shows it as a
    /// bar until an empty one comes.
    Activity(Activity),
}

/// What [`Out::Activity`] says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Activity {
    /// What is being done, in English for the window to translate; empty
    /// when nothing is.
    pub doing: String,
    /// The part under way, or empty.
    pub part: String,
    /// Chunks done.
    pub done: u32,
    /// Chunks in all (0: not known).
    pub total: u32,
}

/// A piece of a video playing: about half a second of frames and sound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VideoPiece {
    /// Which video (`conversation:seq`), to ask for more.
    pub key: String,
    /// Frames a second.
    pub fps: u32,
    /// Its whole length (ms).
    pub duration_ms: u32,
    /// Width of the frames.
    pub width: u32,
    /// Height of the frames.
    pub height: u32,
    /// The frames, RGBA.
    pub frames: Vec<Vec<u8>>,
    /// The sound for them: 48 kHz mono.
    pub pcm: Vec<i16>,
    /// The first piece (start playing).
    pub first: bool,
    /// The last piece.
    pub done: bool,
}

/// Most frames in a [`VideoPiece`].
pub const MAX_PIECE_FRAMES: usize = 30;

/// The conversation name a pack preview's pictures come under.
pub const PACK_PREVIEW: &str = "pack-preview";
/// The conversation name GIF search results' pictures come under.
pub const GIF_RESULTS: &str = "gif-results";
/// Most GIF search results.
pub const MAX_GIFS: usize = 12;

/// A file in the gallery across all conversations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GalleryRow {
    /// Its conversation's id (as in [`Snapshot::contacts`]).
    pub conversation: String,
    /// The conversation's name.
    pub name: String,
    /// The message's position.
    pub seq: u64,
    /// The file's name.
    pub file: String,
    /// A picture or animation (the viewer shows it).
    pub picture: bool,
    /// We sent it.
    pub outgoing: bool,
    /// When.
    pub time: String,
}

/// The most rows [`Out::Gallery`] carries.
pub const MAX_GALLERY: usize = 2000;

/// PCM as 16-bit little-endian bytes.
fn pcm_bytes(pcm: &[i16]) -> Vec<u8> {
    pcm.iter()
        .take(CALL_FRAME)
        .flat_map(|s| s.to_le_bytes())
        .collect()
}

fn bytes_pcm(b: &[u8]) -> Result<Vec<i16>> {
    if !b.len().is_multiple_of(2) || b.len() > CALL_FRAME * 2 {
        return Err(IpcError::Malformed);
    }
    Ok(b.chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// Most history chunks in one [`Out::LanChunks`] or [`Cmd::LanChunks`]
/// (about 7 MB, well inside a frame).
pub const LAN_BATCH: usize = 512;

/// The titles of a ringing call's notice (phones show the system's call
/// screen instead).
pub const CALL_NOTICE: &str = "Incoming call";
/// As above, for a video call.
pub const VIDEO_CALL_NOTICE: &str = "Incoming video call";

/// A desktop notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The conversation it is about (empty: several).
    pub conversation: String,
    /// Its title.
    pub title: String,
    /// Its text.
    pub body: String,
}

/// A clip decoded for playing (by `mediad`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipFrames {
    /// Width of every frame.
    pub width: u32,
    /// Height of every frame.
    pub height: u32,
    /// Time each frame shows.
    pub interval_ms: u32,
    /// `width × height × 4` bytes of RGBA each.
    pub frames: Vec<Vec<u8>>,
}

/// A picture's preview, decoded by `mediad`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    /// Conversation id.
    pub conversation: String,
    /// Message position.
    pub seq: u64,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// `width × height × 4` bytes of RGBA.
    pub pixels: Vec<u8>,
}

fn put_row(w: &mut Writer, r: &Row) {
    w.str(&r.id)
        .str(&r.name)
        .str(&r.preview)
        .str(&r.time)
        .i32(r.unread)
        .i32(r.state)
        .bool(r.verified)
        .bool(r.met)
        .u8((r.tint % TINT_COUNT) as u8)
        .i32(r.kind)
        .i32(r.members)
        .bool(r.pinned)
        .bool(r.muted)
        .bool(r.archived)
        .bool(r.blocked)
        .bool(r.admin)
        .u32(r.art)
        .str(&r.about)
        .bool(r.has_photo);
}

fn get_row(r: &mut Reader<'_>) -> Result<Row> {
    Ok(Row {
        id: r.str()?,
        name: r.str()?,
        preview: r.str()?,
        time: r.str()?,
        unread: r.i32()?,
        state: r.i32()?,
        verified: r.bool()?,
        met: r.bool()?,
        tint: tint(r.u8()?)?,
        kind: r.i32()?,
        members: r.i32()?,
        pinned: r.bool()?,
        muted: r.bool()?,
        archived: r.bool()?,
        blocked: r.bool()?,
        admin: r.bool()?,
        art: r.u32()? & 0x0fff_ffff,
        about: r.str()?,
        has_photo: r.bool()?,
    })
}

fn tint(v: u8) -> Result<usize> {
    let v = v as usize;
    if v < TINT_COUNT {
        Ok(v)
    } else {
        Err(IpcError::Malformed)
    }
}

fn put_rows(w: &mut Writer, rows: &[Row]) {
    w.len(rows.len());
    for r in rows {
        put_row(w, r);
    }
}

fn get_rows(r: &mut Reader<'_>) -> Result<Vec<Row>> {
    let n = r.len()?;
    (0..n).map(|_| get_row(r)).collect()
}

impl Snapshot {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.str(&self.my_name)
            .str(&self.my_about)
            .bool(self.my_photo)
            .str(&self.my_link);
        put_rows(&mut w, &self.contacts);
        put_rows(&mut w, &self.requests);
        put_rows(&mut w, &self.archived);
        match &self.current {
            Some(c) => {
                w.u8(1);
                put_row(&mut w, c);
            }
            None => {
                w.u8(0);
            }
        }
        w.len(self.messages.len());
        for m in &self.messages {
            w.str(&m.text)
                .bool(m.outgoing)
                .str(&m.time)
                .i32(m.status)
                .str(&m.sender)
                .u64(m.seq)
                .bool(m.can_edit)
                .bool(m.deleted)
                .str(&m.file)
                .bool(m.image)
                .strs(&m.poll_options)
                .len(m.poll_counts.len());
            for c in &m.poll_counts {
                w.u32(*c);
            }
            w.i32(m.poll_mine)
                .i32(m.poll_state)
                .bool(m.poll_ours)
                .bool(m.pinned)
                .str(&m.contact_name)
                .bool(m.contact_known)
                .str(&m.location)
                .str(&m.location_label)
                .bool(m.sticker)
                .bool(m.pack_added)
                .bool(m.voice)
                .u32(m.voice_ms)
                .bytes(&m.waveform[..m.waveform.len().min(64)])
                .u32(m.clip_ms)
                .str(&m.transcript)
                .bool(m.quoted)
                .u64(m.quote_seq)
                .str(&m.quote_who)
                .str(&m.quote_text)
                .bool(m.forwarded)
                .bool(m.mentions_me)
                .bool(m.poll_anonymous)
                .u32(m.poll_voters)
                .str(&m.my_reaction)
                .bool(m.view_once)
                .bool(m.view_once_ready)
                .bool(m.video)
                .str(&m.link_title)
                .str(&m.link_description)
                .str(&m.link_site)
                .bool(m.link_image);
        }
        w.strs(&self.code_groups)
            .strs(&self.code_words)
            .bool(self.code_words_english)
            .str(&self.status)
            .strs(&self.recovery_words)
            .bool(self.recovery_saved)
            .str(&self.words_language)
            .u8(u8::from(self.privacy == 1))
            .bool(self.finishing)
            .u8(self.setup_step)
            .u32(self.setup_part)
            .u32(self.setup_parts)
            .u32(self.setup_left)
            .bool(self.gap)
            .bool(self.on_record)
            .bool(self.closed)
            .str(&self.add_error)
            .bool(self.busy);
        w.len(self.pick.len());
        for p in &self.pick {
            w.str(&p.id)
                .str(&p.name)
                .u8((p.tint % TINT_COUNT) as u8)
                .bool(p.selected);
        }
        w.len(self.devices.len());
        for d in &self.devices {
            w.str(&d.id)
                .str(&d.label)
                .str(&d.detail)
                .bool(d.removable)
                .str(&d.history_action);
        }
        w.strs(&self.link_choices)
            .str(&self.link_status)
            .bool(self.can_link)
            .str(&self.my_username)
            .bool(self.usernames)
            .str(&self.username_error)
            .bool(self.can_join)
            .str(&self.join_code)
            .str(&self.join_words)
            .str(&self.recovery_alert)
            .str(&self.recovery_hold)
            .bool(self.recovery_stopped)
            .str(&self.meet_code)
            .str(&self.meet_words)
            .str(&self.meet_name)
            .str(&self.meet_error)
            .str(&self.meet_done)
            .u32(self.timer);
        put_rows(&mut w, &self.search);
        w.str(&self.username_problem)
            .str(&self.kt_split)
            .str(&self.clock_skew)
            .str(&self.new_device)
            .strs(&self.joining)
            .str(&self.restore_error);
        w.len(self.friends.len());
        for p in self.friends.iter().take(crate::codec::MAX_ITEMS) {
            w.str(&p.id)
                .str(&p.name)
                .u8((p.tint % TINT_COUNT) as u8)
                .bool(p.selected);
        }
        w.strs(&self.share_holders)
            .u32(self.share_threshold)
            .bool(self.holds_share)
            .str(&self.share_release)
            .str(&self.share_release_words)
            .str(&self.share_request)
            .str(&self.share_request_words)
            .strs(&self.pins)
            .strs(&self.pin_seqs)
            .len(self.sticker_packs.len());
        for p in &self.sticker_packs {
            w.str(&p.id).str(&p.title).u32(p.count);
        }
        put_rows(&mut w, &self.members);
        w.bool(self.group_admin);
        w.len(self.addable.len());
        for p in &self.addable {
            w.str(&p.id)
                .str(&p.name)
                .u8((p.tint % TINT_COUNT) as u8)
                .bool(p.selected);
        }
        w.bool(self.locked)
            .str(&self.unlock_error)
            .bool(self.can_lock)
            .u32(self.invites)
            .bool(self.typing_setting)
            .bool(self.receipts_setting)
            .bool(self.link_previews)
            .bool(self.gif_search)
            .bool(self.typing)
            .str(&self.typing_who)
            .bool(self.announcement_only)
            .strs(&self.folders)
            .str(&self.folder)
            .strs(&self.current_folders)
            .bool(self.sandbox_weak)
            .bool(self.can_change_words)
            .bool(self.words_pending)
            .bool(self.removed)
            .bool(self.has_root_pin)
            .bool(self.securing)
            .bool(self.previews)
            .str(&self.pin_error)
            .u8(self.moved)
            .strs(&self.held_moves)
            .u8(self.route)
            .bool(self.tor_blocked)
            .str(&self.bridges)
            .str(&self.bridges_error)
            .bool(self.bridges_restart)
            .bool(self.pin_lock)
            .bool(self.app_lock)
            .u32(self.lock_timeout)
            .bool(self.server_backup)
            .str(&self.server_backup_at)
            .str(&self.backup_check);
        w.len(self.servers.len());
        for v in &self.servers {
            w.str(&v.id).str(&v.domain).str(&v.operator).str(&v.family);
        }
        w.str(&self.home)
            .bool(self.moving)
            .bool(self.can_move)
            .str(&self.group_host)
            .str(&self.group_next)
            .strs(&self.group_votes)
            .u32(self.group_admins)
            .str(&self.group_vote)
            .bool(self.file_keys)
            .bool(self.screen_security)
            .str(&self.biometric)
            .bool(self.biometric_on)
            .str(&self.update_release)
            .u8(self.update_required)
            .str(&self.build_check)
            .u8(self.call.state)
            .str(&self.call.conversation)
            .str(&self.call.name)
            .bool(self.call.video)
            .bool(self.call.muted)
            .bool(self.call.camera)
            .u32(self.call.video_width)
            .u32(self.call.video_height)
            .u64(self.call.connected_at)
            .str(&self.call.words)
            .str(&self.call.error)
            .bool(self.call.direct_asked)
            .bool(self.call.direct)
            .bool(self.call.group)
            .bool(self.call.hand)
            .bool(self.call.cameras_full)
            .bool(self.call.screen)
            .u32(self.call.peers.len() as u32);
        for p in &self.call.peers {
            w.u32(p.id).str(&p.name).bool(p.hand).str(&p.reaction);
        }
        w.strs(&self.call.live_groups).str(&self.call.link);
        w.u32(self.call.knocks.len() as u32);
        for p in &self.call.knocks {
            w.u32(p.id).str(&p.name);
        }
        w.u8(self.transcription)
            .u8(self.transcription_percent)
            .str(&self.transcription_error);
        w.len(self.stories.len());
        for s in self.stories.iter().take(crate::codec::MAX_ITEMS) {
            w.str(&s.key)
                .str(&s.who)
                .str(&s.name)
                .str(&s.text)
                .str(&s.ago)
                .bool(s.picture)
                .bool(s.viewed)
                .u32(s.reached)
                .u32(s.waiting);
        }
        w.len(self.story_audience.len());
        for p in self.story_audience.iter().take(crate::codec::MAX_ITEMS) {
            w.str(&p.id)
                .str(&p.name)
                .u8((p.tint % TINT_COUNT) as u8)
                .bool(p.selected);
        }
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let my_name = r.str()?;
        let (my_about, my_photo) = (r.str()?, r.bool()?);
        let my_link = r.str()?;
        let contacts = get_rows(&mut r)?;
        let requests = get_rows(&mut r)?;
        let archived = get_rows(&mut r)?;
        let current = match r.u8()? {
            0 => None,
            1 => Some(get_row(&mut r)?),
            _ => return Err(IpcError::Malformed),
        };
        let n = r.len()?;
        let messages = (0..n)
            .map(|_| {
                Ok(Msg {
                    text: r.str()?,
                    outgoing: r.bool()?,
                    time: r.str()?,
                    status: r.i32()?,
                    sender: r.str()?,
                    seq: r.u64()?,
                    can_edit: r.bool()?,
                    deleted: r.bool()?,
                    file: r.str()?,
                    image: r.bool()?,
                    poll_options: r.strs()?,
                    poll_counts: {
                        let n = r.len()?;
                        (0..n).map(|_| r.u32()).collect::<Result<_>>()?
                    },
                    poll_mine: r.i32()?,
                    poll_state: r.i32()?,
                    poll_ours: r.bool()?,
                    pinned: r.bool()?,
                    contact_name: r.str()?,
                    contact_known: r.bool()?,
                    location: r.str()?,
                    location_label: r.str()?,
                    sticker: r.bool()?,
                    pack_added: r.bool()?,
                    voice: r.bool()?,
                    voice_ms: r.u32()?,
                    waveform: {
                        let w = r.bytes()?;
                        if w.len() > 64 {
                            return Err(IpcError::Malformed);
                        }
                        w
                    },
                    clip_ms: r.u32()?,
                    transcript: r.str()?,
                    quoted: r.bool()?,
                    quote_seq: r.u64()?,
                    quote_who: r.str()?,
                    quote_text: r.str()?,
                    forwarded: r.bool()?,
                    mentions_me: r.bool()?,
                    poll_anonymous: r.bool()?,
                    poll_voters: r.u32()?,
                    my_reaction: r.str()?,
                    view_once: r.bool()?,
                    view_once_ready: r.bool()?,
                    video: r.bool()?,
                    link_title: r.str()?,
                    link_description: r.str()?,
                    link_site: r.str()?,
                    link_image: r.bool()?,
                })
            })
            .collect::<Result<_>>()?;
        let code_groups = r.strs()?;
        let code_words = r.strs()?;
        let code_words_english = r.bool()?;
        let status = r.str()?;
        let recovery_words = r.strs()?;
        let recovery_saved = r.bool()?;
        let words_language = r.str()?;
        let privacy = match r.u8()? {
            0 => 0,
            1 => 1,
            _ => return Err(IpcError::Malformed),
        };
        let finishing = r.bool()?;
        let setup_step = r.u8()?;
        let setup_part = r.u32()?;
        let setup_parts = r.u32()?;
        let setup_left = r.u32()?;
        let gap = r.bool()?;
        let on_record = r.bool()?;
        let closed = r.bool()?;
        let add_error = r.str()?;
        let busy = r.bool()?;
        let n = r.len()?;
        let pick = (0..n)
            .map(|_| {
                Ok(Pick {
                    id: r.str()?,
                    name: r.str()?,
                    tint: tint(r.u8()?)?,
                    selected: r.bool()?,
                })
            })
            .collect::<Result<_>>()?;
        let n = r.len()?;
        let devices = (0..n)
            .map(|_| {
                Ok(Device {
                    id: r.str()?,
                    label: r.str()?,
                    detail: r.str()?,
                    removable: r.bool()?,
                    history_action: r.str()?,
                })
            })
            .collect::<Result<_>>()?;
        let s = Self {
            my_name,
            my_about,
            my_photo,
            my_link,
            contacts,
            requests,
            archived,
            current,
            messages,
            code_groups,
            code_words,
            code_words_english,
            status,
            recovery_words,
            recovery_saved,
            words_language,
            privacy,
            finishing,
            setup_step,
            setup_part,
            setup_parts,
            setup_left,
            gap,
            on_record,
            closed,
            add_error,
            busy,
            pick,
            devices,
            link_choices: r.strs()?,
            link_status: r.str()?,
            can_link: r.bool()?,
            my_username: r.str()?,
            usernames: r.bool()?,
            username_error: r.str()?,
            can_join: r.bool()?,
            join_code: r.str()?,
            join_words: r.str()?,
            recovery_alert: r.str()?,
            recovery_hold: r.str()?,
            recovery_stopped: r.bool()?,
            meet_code: r.str()?,
            meet_words: r.str()?,
            meet_name: r.str()?,
            meet_error: r.str()?,
            meet_done: r.str()?,
            timer: r.u32()?,
            search: get_rows(&mut r)?,
            username_problem: r.str()?,
            kt_split: r.str()?,
            clock_skew: r.str()?,
            new_device: r.str()?,
            joining: r.strs()?,
            restore_error: r.str()?,
            friends: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(Pick {
                            id: r.str()?,
                            name: r.str()?,
                            tint: usize::from(r.u8()?) % TINT_COUNT,
                            selected: r.bool()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            share_holders: r.strs()?,
            share_threshold: r.u32()?,
            holds_share: r.bool()?,
            share_release: r.str()?,
            share_release_words: r.str()?,
            share_request: r.str()?,
            share_request_words: r.str()?,
            pins: r.strs()?,
            pin_seqs: r.strs()?,
            sticker_packs: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(StickerPackRow {
                            id: r.str()?,
                            title: r.str()?,
                            count: r.u32()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            members: get_rows(&mut r)?,
            group_admin: r.bool()?,
            addable: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(Pick {
                            id: r.str()?,
                            name: r.str()?,
                            tint: tint(r.u8()?)?,
                            selected: r.bool()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            locked: r.bool()?,
            unlock_error: r.str()?,
            can_lock: r.bool()?,
            invites: r.u32()?,
            typing_setting: r.bool()?,
            receipts_setting: r.bool()?,
            link_previews: r.bool()?,
            gif_search: r.bool()?,
            typing: r.bool()?,
            typing_who: r.str()?,
            announcement_only: r.bool()?,
            folders: r.strs()?,
            folder: r.str()?,
            current_folders: r.strs()?,
            sandbox_weak: r.bool()?,
            can_change_words: r.bool()?,
            words_pending: r.bool()?,
            removed: r.bool()?,
            has_root_pin: r.bool()?,
            securing: r.bool()?,
            previews: r.bool()?,
            pin_error: r.str()?,
            moved: r.u8()?,
            held_moves: r.strs()?,
            route: r.u8()?,
            tor_blocked: r.bool()?,
            bridges: r.str()?,
            bridges_error: r.str()?,
            bridges_restart: r.bool()?,
            pin_lock: r.bool()?,
            app_lock: r.bool()?,
            lock_timeout: r.u32()?,
            server_backup: r.bool()?,
            server_backup_at: r.str()?,
            backup_check: r.str()?,
            servers: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(ServerRow {
                            id: r.str()?,
                            domain: r.str()?,
                            operator: r.str()?,
                            family: r.str()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            home: r.str()?,
            moving: r.bool()?,
            can_move: r.bool()?,
            group_host: r.str()?,
            group_next: r.str()?,
            group_votes: r.strs()?,
            group_admins: r.u32()?,
            group_vote: r.str()?,
            file_keys: r.bool()?,
            screen_security: r.bool()?,
            biometric: r.str()?,
            biometric_on: r.bool()?,
            update_release: r.str()?,
            update_required: r.u8()?,
            build_check: r.str()?,
            call: CallView {
                state: r.u8()?,
                conversation: r.str()?,
                name: r.str()?,
                video: r.bool()?,
                muted: r.bool()?,
                camera: r.bool()?,
                video_width: r.u32()?,
                video_height: r.u32()?,
                connected_at: r.u64()?,
                words: r.str()?,
                error: r.str()?,
                direct_asked: r.bool()?,
                direct: r.bool()?,
                group: r.bool()?,
                hand: r.bool()?,
                cameras_full: r.bool()?,
                screen: r.bool()?,
                peers: {
                    let n = r.u32()? as usize;
                    if n > MAX_CALL_PEERS {
                        return Err(IpcError::Malformed);
                    }
                    (0..n)
                        .map(|_| {
                            Ok(CallPeer {
                                id: r.u32()?,
                                name: r.str()?,
                                hand: r.bool()?,
                                reaction: r.str()?,
                            })
                        })
                        .collect::<Result<_>>()?
                },
                live_groups: r.strs()?,
                link: r.str()?,
                knocks: {
                    let n = r.u32()? as usize;
                    if n > MAX_CALL_PEERS {
                        return Err(IpcError::Malformed);
                    }
                    (0..n)
                        .map(|_| {
                            Ok(CallPeer {
                                id: r.u32()?,
                                name: r.str()?,
                                ..Default::default()
                            })
                        })
                        .collect::<Result<_>>()?
                },
            },
            transcription: r.u8()?,
            transcription_percent: r.u8()?,
            transcription_error: r.str()?,
            stories: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(StoryRow {
                            key: r.str()?,
                            who: r.str()?,
                            name: r.str()?,
                            text: r.str()?,
                            ago: r.str()?,
                            picture: r.bool()?,
                            viewed: r.bool()?,
                            reached: r.u32()?,
                            waiting: r.u32()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            story_audience: {
                let n = r.len()?;
                (0..n)
                    .map(|_| {
                        Ok(Pick {
                            id: r.str()?,
                            name: r.str()?,
                            tint: usize::from(r.u8()?) % TINT_COUNT,
                            selected: r.bool()?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
        };
        r.end()?;
        Ok(s)
    }
}

impl Cmd {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Cmd::Create(s, p) => w.u8(1).str(s).str(p),
            Cmd::Select(s) => w.u8(2).str(s),
            Cmd::Send(a, b) => w.u8(3).str(a).str(b),
            Cmd::Accept(s) => w.u8(4).str(s),
            Cmd::Decline(s) => w.u8(5).str(s),
            Cmd::Add(a, b) => w.u8(6).str(a).str(b),
            Cmd::Check(s) => w.u8(7).str(s),
            Cmd::Privacy(i) => w.u8(8).i32(*i),
            Cmd::WordsSaved => w.u8(9),
            Cmd::TogglePick(s) => w.u8(10).str(s),
            Cmd::CreateGroup(s) => w.u8(11).str(s),
            Cmd::LinkScan(s) => w.u8(12).str(s),
            Cmd::LinkPick(i) => w.u8(13).i32(*i),
            Cmd::ClaimUsername(s) => w.u8(14).str(s),
            Cmd::RemoveDevice(s) => w.u8(15).str(s),
            Cmd::StartJoin => w.u8(16),
            Cmd::CancelJoin => w.u8(17),
            Cmd::RevealWords(b) => w.u8(18).bool(*b),
            Cmd::SendHistory(s) => w.u8(19).str(s),
            Cmd::StopRecovery => w.u8(20),
            Cmd::ApproveRecovery => w.u8(21),
            Cmd::Meet(b) => w.u8(22).bool(*b),
            Cmd::MeetScan(s) => w.u8(23).str(s),
            Cmd::MeetConfirm => w.u8(24),
            Cmd::React(c, s, e) => w.u8(25).str(c).u64(*s).str(e),
            Cmd::Edit(c, s, t) => w.u8(26).str(c).u64(*s).str(t),
            Cmd::Delete(c, s) => w.u8(27).str(c).u64(*s),
            Cmd::Timer(c, t) => w.u8(28).str(c).u32(*t),
            Cmd::SendFile(c, n, b, cap) => w.u8(29).str(c).str(n).bytes(b).str(cap),
            Cmd::SaveFile(c, s) => w.u8(30).str(c).u64(*s),
            Cmd::Search(q) => w.u8(31).str(q),
            Cmd::AddMembers(g) => w.u8(32).str(g),
            Cmd::RemoveMember(g, m) => w.u8(33).str(g).str(m),
            Cmd::SetGroupAdmin(g, m, on) => w.u8(66).str(g).str(m).bool(*on),
            Cmd::LeaveGroup(g) => w.u8(34).str(g),
            Cmd::Unlock(p) => w.u8(35).str(p),
            Cmd::Lock => w.u8(36),
            Cmd::SetPassphrase(p) => w.u8(37).str(p),
            Cmd::NewInvite(n) => w.u8(38).u8(*n),
            Cmd::CancelInvites => w.u8(39),
            Cmd::NewGroupInvite(g, uses, approve) => w.u8(40).str(g).u8(*uses).bool(*approve),
            Cmd::CreatePoll(g, q, o, a) => w.u8(41).str(g).str(q).strs(o).bool(*a),
            Cmd::Vote(g, s, c) => w.u8(42).str(g).u64(*s).u32(*c),
            Cmd::ClosePoll(g, s) => w.u8(43).str(g).u64(*s),
            Cmd::SaveBackup(media) => w.u8(44).bool(*media),
            Cmd::Restore(s, b) => w.u8(45).strs(s).bytes(b),
            Cmd::GiveShares(ids, t) => w.u8(46).strs(ids).u32(*t),
            Cmd::RevealShare(id) => w.u8(47).str(id),
            Cmd::Pin(c, s, on) => w.u8(48).str(c).u64(*s).bool(*on),
            Cmd::ConvPrefs(c, a, p, m) => w.u8(49).str(c).bool(*a).bool(*p).bool(*m),
            Cmd::Block(c, on) => w.u8(50).str(c).bool(*on),
            Cmd::ShareContact(c, who) => w.u8(51).str(c).str(who),
            Cmd::AddShared(c, s) => w.u8(52).str(c).u64(*s),
            Cmd::ShareLocation(c, la, lo, l) => w.u8(53).str(c).str(la).str(lo).str(l),
            Cmd::Report(c, r, q, b, e) => w.u8(54).str(c).u8(*r).bool(*q).bool(*b).bool(*e),
            Cmd::CreatePack(t, pics) => {
                w.u8(55).str(t).len(pics.len());
                for p in pics {
                    w.bytes(p);
                }
                &mut w
            }
            Cmd::SendSticker(c, p, i) => w.u8(56).str(c).str(p).u32(*i),
            Cmd::AddPack(c, s) => w.u8(57).str(c).u64(*s),
            Cmd::LoadStickers => w.u8(58),
            Cmd::TypingSetting(on) => w.u8(59).bool(*on),
            Cmd::ReceiptsSetting(on) => w.u8(118).bool(*on),
            Cmd::Typing(c, on) => w.u8(60).str(c).bool(*on),
            Cmd::ChangeWords => w.u8(61),
            Cmd::PlayClip(c, s) => w.u8(62).str(c).u64(*s),
            Cmd::BackupRoute(on) => w.u8(63).bool(*on),
            Cmd::SetBridges(b) => w.u8(64).str(b),
            Cmd::SetOnRecord(on) => w.u8(65).bool(*on),
            Cmd::SetAnnouncementOnly(on) => w.u8(119).bool(*on),
            Cmd::NewFolder(n) => w.u8(120).str(n),
            Cmd::DeleteFolder(n) => w.u8(121).str(n),
            Cmd::InFolder(n, on) => w.u8(122).str(n).bool(*on),
            Cmd::ShowFolder(n) => w.u8(123).str(n),
            Cmd::OpenLink(l) => w.u8(124).str(l),
            Cmd::SendReply(c, t, seq) => w.u8(125).str(c).str(t).u64(*seq),
            Cmd::Forward(from, seq, to) => w.u8(126).str(from).u64(*seq).str(to),
            Cmd::Stage(b) => w.u8(127).bytes(b),
            Cmd::SendStaged(c, n, cap) => w.u8(128).str(c).str(n).str(cap),
            Cmd::OpenFile(c, seq) => w.u8(129).str(c).u64(*seq),
            Cmd::SendViewOnce(c, n, cap) => w.u8(130).str(c).str(n).str(cap),
            Cmd::OpenViewOnce(c, seq) => w.u8(131).str(c).u64(*seq),
            Cmd::AllFiles => w.u8(132),
            Cmd::RemovePack(p) => w.u8(133).str(p),
            Cmd::SetName(n) => w.u8(135).str(n),
            Cmd::SetAbout(a) => w.u8(136).str(a),
            Cmd::SetPhoto(b) => w.u8(137).bytes(b),
            Cmd::PreviewPack(c, seq) => w.u8(134).str(c).u64(*seq),
            Cmd::LinkPreviewsSetting(on) => w.u8(138).bool(*on),
            Cmd::GifSearchSetting(on) => w.u8(139).bool(*on),
            Cmd::GifSearch(q) => w.u8(140).str(q),
            Cmd::SendGif(c, i) => w.u8(141).str(c).u32(*i),
            Cmd::PostStory(t, n, b) => w.u8(142).str(t).str(n).bytes(b),
            Cmd::DeleteStory(k) => w.u8(143).str(k),
            Cmd::OpenStory(k) => w.u8(144).str(k),
            Cmd::StoryHidden(c, on) => w.u8(145).str(c).bool(*on),
            Cmd::RecordStart(c, n, width, height) => {
                w.u8(146).str(c).str(n).u32(*width).u32(*height)
            }
            Cmd::RecordFrame(b) => w.u8(147).bytes(b),
            Cmd::RecordSound(b) => w.u8(148).bytes(b),
            Cmd::RecordEnd(cap) => w.u8(149).str(cap),
            Cmd::RecordCancel => w.u8(150),
            Cmd::VideoMore(k) => w.u8(151).str(k),
            Cmd::StopVideo => w.u8(152),
            Cmd::WordsLanguage(l) => w.u8(67).str(l),
            Cmd::CodeWordsEnglish(on) => w.u8(68).bool(*on),
            Cmd::ReleaseShare(code) => w.u8(69).str(code),
            Cmd::AskShares => w.u8(70),
            Cmd::DeleteAccount => w.u8(71),
            Cmd::EraseDevice => w.u8(72),
            Cmd::SetRootPin(p) => w.u8(73).str(p),
            Cmd::UnlockRoot(p) => w.u8(74).str(p),
            Cmd::SecureAccount => w.u8(75),
            Cmd::SetPreviews(on) => w.u8(76).bool(*on),
            Cmd::SetAppLock(p) => w.u8(77).str(p),
            Cmd::SetLockTimeout(t) => w.u8(79).u32(*t),
            Cmd::ServerBackup(on) => w.u8(80).bool(*on),
            Cmd::CheckBackup(words, a) => w.u8(81).str(words).bytes(a),
            Cmd::RestoreFromServer(s) => w.u8(82).strs(s),
            Cmd::PickServer(s) => w.u8(83).str(s),
            Cmd::MoveHome(s) => w.u8(84).str(s),
            Cmd::VoteGroupHost(s) => w.u8(85).str(s),
            Cmd::SetScreenSecurity(on) => w.u8(86).bool(*on),
            Cmd::UnlockBiometric(window) => w.u8(87).u64(*window),
            Cmd::SetBiometric(on) => w.u8(88).bool(*on),
            Cmd::LanServing(t, a) => w.u8(89).str(t).strs(a),
            Cmd::LanChunks(t, chunks, last) => {
                w.u8(90).str(t).u32(chunks.len() as u32);
                for c in chunks {
                    w.bytes(c);
                }
                w.bool(*last)
            }
            Cmd::LanFailed(t) => w.u8(91).str(t),
            Cmd::Visible(on) => w.u8(92).bool(*on),
            Cmd::PushToken(p, t) => w.u8(93).u8(*p).str(t),
            Cmd::Wake => w.u8(94),
            Cmd::Reattach => w.u8(95),
            Cmd::VerifyBuild(files) => {
                w.u8(96).u32(files.len() as u32);
                for f in files {
                    w.str(&f.name)
                        .u64(f.length)
                        .bytes(&f.sha256)
                        .bytes(&f.sha3_512);
                }
                &mut w
            }
            Cmd::CheckUpdates => w.u8(97),
            Cmd::StartCall(c, video, direct) => w.u8(98).str(c).bool(*video).bool(*direct),
            Cmd::AnswerCallDirect => w.u8(106),
            Cmd::AnswerCall => w.u8(99),
            Cmd::DeclineCall => w.u8(100),
            Cmd::EndCall => w.u8(101),
            Cmd::CallMute(on) => w.u8(102).bool(*on),
            Cmd::CallMic(pcm) => w.u8(103).bytes(&pcm_bytes(pcm)),
            Cmd::CallCamera(on) => w.u8(104).bool(*on),
            Cmd::CallFrame(width, height, rgba) => w.u8(105).u32(*width).u32(*height).bytes(rgba),
            Cmd::StartGroupCall(c, video) => w.u8(107).str(c).bool(*video),
            Cmd::JoinGroupCall(c) => w.u8(108).str(c),
            Cmd::CallHand(up) => w.u8(109).bool(*up),
            Cmd::CallReact(e) => w.u8(110).str(e),
            Cmd::CreateCallLink(lobby) => w.u8(111).bool(*lobby),
            Cmd::AdmitToCall(id) => w.u8(112).u32(*id),
            Cmd::RefuseFromCall(id) => w.u8(113).u32(*id),
            Cmd::CallScreen(on) => w.u8(114).bool(*on),
            Cmd::PlayVoice(c, seq) => w.u8(115).str(c).u64(*seq),
            Cmd::TranscriptionModel(on) => w.u8(116).bool(*on),
            Cmd::Transcribe(c, seq) => w.u8(117).str(c).u64(*seq),
            Cmd::SetEmergencyPin(p) => w.u8(78).str(p),
        };
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let c = match r.u8()? {
            1 => Cmd::Create(r.str()?, r.str()?),
            2 => Cmd::Select(r.str()?),
            3 => Cmd::Send(r.str()?, r.str()?),
            4 => Cmd::Accept(r.str()?),
            5 => Cmd::Decline(r.str()?),
            6 => Cmd::Add(r.str()?, r.str()?),
            7 => Cmd::Check(r.str()?),
            8 => Cmd::Privacy(r.i32()?),
            9 => Cmd::WordsSaved,
            10 => Cmd::TogglePick(r.str()?),
            11 => Cmd::CreateGroup(r.str()?),
            12 => Cmd::LinkScan(r.str()?),
            13 => Cmd::LinkPick(r.i32()?),
            14 => Cmd::ClaimUsername(r.str()?),
            15 => Cmd::RemoveDevice(r.str()?),
            16 => Cmd::StartJoin,
            17 => Cmd::CancelJoin,
            18 => Cmd::RevealWords(r.bool()?),
            19 => Cmd::SendHistory(r.str()?),
            20 => Cmd::StopRecovery,
            21 => Cmd::ApproveRecovery,
            22 => Cmd::Meet(r.bool()?),
            23 => Cmd::MeetScan(r.str()?),
            24 => Cmd::MeetConfirm,
            25 => Cmd::React(r.str()?, r.u64()?, r.str()?),
            26 => Cmd::Edit(r.str()?, r.u64()?, r.str()?),
            27 => Cmd::Delete(r.str()?, r.u64()?),
            28 => Cmd::Timer(r.str()?, r.u32()?),
            29 => Cmd::SendFile(r.str()?, r.str()?, r.bytes()?, r.str()?),
            30 => Cmd::SaveFile(r.str()?, r.u64()?),
            31 => Cmd::Search(r.str()?),
            32 => Cmd::AddMembers(r.str()?),
            33 => Cmd::RemoveMember(r.str()?, r.str()?),
            66 => Cmd::SetGroupAdmin(r.str()?, r.str()?, r.bool()?),
            34 => Cmd::LeaveGroup(r.str()?),
            35 => Cmd::Unlock(r.str()?),
            36 => Cmd::Lock,
            37 => Cmd::SetPassphrase(r.str()?),
            38 => Cmd::NewInvite(r.u8()?),
            39 => Cmd::CancelInvites,
            40 => Cmd::NewGroupInvite(r.str()?, r.u8()?, r.bool()?),
            41 => Cmd::CreatePoll(r.str()?, r.str()?, r.strs()?, r.bool()?),
            42 => Cmd::Vote(r.str()?, r.u64()?, r.u32()?),
            43 => Cmd::ClosePoll(r.str()?, r.u64()?),
            44 => Cmd::SaveBackup(r.bool()?),
            45 => Cmd::Restore(r.strs()?, r.bytes()?),
            46 => Cmd::GiveShares(r.strs()?, r.u32()?),
            47 => Cmd::RevealShare(r.str()?),
            48 => Cmd::Pin(r.str()?, r.u64()?, r.bool()?),
            49 => Cmd::ConvPrefs(r.str()?, r.bool()?, r.bool()?, r.bool()?),
            50 => Cmd::Block(r.str()?, r.bool()?),
            51 => Cmd::ShareContact(r.str()?, r.str()?),
            52 => Cmd::AddShared(r.str()?, r.u64()?),
            53 => Cmd::ShareLocation(r.str()?, r.str()?, r.str()?, r.str()?),
            54 => Cmd::Report(r.str()?, r.u8()?, r.bool()?, r.bool()?, r.bool()?),
            55 => {
                let t = r.str()?;
                let n = r.len()?;
                Cmd::CreatePack(t, (0..n).map(|_| r.bytes()).collect::<Result<_>>()?)
            }
            56 => Cmd::SendSticker(r.str()?, r.str()?, r.u32()?),
            57 => Cmd::AddPack(r.str()?, r.u64()?),
            58 => Cmd::LoadStickers,
            59 => Cmd::TypingSetting(r.bool()?),
            118 => Cmd::ReceiptsSetting(r.bool()?),
            60 => Cmd::Typing(r.str()?, r.bool()?),
            61 => Cmd::ChangeWords,
            62 => Cmd::PlayClip(r.str()?, r.u64()?),
            63 => Cmd::BackupRoute(r.bool()?),
            64 => Cmd::SetBridges(r.str()?),
            65 => Cmd::SetOnRecord(r.bool()?),
            119 => Cmd::SetAnnouncementOnly(r.bool()?),
            120 => Cmd::NewFolder(r.str()?),
            121 => Cmd::DeleteFolder(r.str()?),
            122 => Cmd::InFolder(r.str()?, r.bool()?),
            123 => Cmd::ShowFolder(r.str()?),
            124 => Cmd::OpenLink(r.str()?),
            125 => Cmd::SendReply(r.str()?, r.str()?, r.u64()?),
            126 => Cmd::Forward(r.str()?, r.u64()?, r.str()?),
            127 => Cmd::Stage(r.bytes()?),
            128 => Cmd::SendStaged(r.str()?, r.str()?, r.str()?),
            129 => Cmd::OpenFile(r.str()?, r.u64()?),
            130 => Cmd::SendViewOnce(r.str()?, r.str()?, r.str()?),
            131 => Cmd::OpenViewOnce(r.str()?, r.u64()?),
            132 => Cmd::AllFiles,
            133 => Cmd::RemovePack(r.str()?),
            135 => Cmd::SetName(r.str()?),
            136 => Cmd::SetAbout(r.str()?),
            137 => Cmd::SetPhoto(r.bytes()?),
            134 => Cmd::PreviewPack(r.str()?, r.u64()?),
            138 => Cmd::LinkPreviewsSetting(r.bool()?),
            139 => Cmd::GifSearchSetting(r.bool()?),
            140 => Cmd::GifSearch(r.str()?),
            141 => Cmd::SendGif(r.str()?, r.u32()?),
            142 => Cmd::PostStory(r.str()?, r.str()?, r.bytes()?),
            143 => Cmd::DeleteStory(r.str()?),
            144 => Cmd::OpenStory(r.str()?),
            145 => Cmd::StoryHidden(r.str()?, r.bool()?),
            146 => Cmd::RecordStart(r.str()?, r.str()?, r.u32()?, r.u32()?),
            147 => Cmd::RecordFrame(r.bytes()?),
            148 => Cmd::RecordSound(r.bytes()?),
            149 => Cmd::RecordEnd(r.str()?),
            150 => Cmd::RecordCancel,
            151 => Cmd::VideoMore(r.str()?),
            152 => Cmd::StopVideo,
            67 => Cmd::WordsLanguage(r.str()?),
            68 => Cmd::CodeWordsEnglish(r.bool()?),
            69 => Cmd::ReleaseShare(r.str()?),
            70 => Cmd::AskShares,
            71 => Cmd::DeleteAccount,
            72 => Cmd::EraseDevice,
            73 => Cmd::SetRootPin(r.str()?),
            74 => Cmd::UnlockRoot(r.str()?),
            75 => Cmd::SecureAccount,
            76 => Cmd::SetPreviews(r.bool()?),
            77 => Cmd::SetAppLock(r.str()?),
            79 => Cmd::SetLockTimeout(r.u32()?),
            80 => Cmd::ServerBackup(r.bool()?),
            81 => Cmd::CheckBackup(r.str()?, r.bytes()?),
            82 => Cmd::RestoreFromServer(r.strs()?),
            83 => Cmd::PickServer(r.str()?),
            84 => Cmd::MoveHome(r.str()?),
            85 => Cmd::VoteGroupHost(r.str()?),
            86 => Cmd::SetScreenSecurity(r.bool()?),
            87 => Cmd::UnlockBiometric(r.u64()?),
            88 => Cmd::SetBiometric(r.bool()?),
            89 => Cmd::LanServing(r.str()?, r.strs()?),
            90 => {
                let t = r.str()?;
                let n = r.u32()? as usize;
                if n > LAN_BATCH {
                    return Err(IpcError::Malformed);
                }
                let chunks = (0..n).map(|_| r.bytes()).collect::<Result<Vec<_>>>()?;
                Cmd::LanChunks(t, chunks, r.bool()?)
            }
            91 => Cmd::LanFailed(r.str()?),
            92 => Cmd::Visible(r.bool()?),
            93 => Cmd::PushToken(r.u8()?, r.str()?),
            94 => Cmd::Wake,
            95 => Cmd::Reattach,
            96 => {
                let n = r.u32()? as usize;
                if n > 64 {
                    return Err(IpcError::Malformed);
                }
                let files = (0..n)
                    .map(|_| {
                        Ok(FileHash {
                            name: r.str()?,
                            length: r.u64()?,
                            sha256: r.bytes()?,
                            sha3_512: r.bytes()?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Cmd::VerifyBuild(files)
            }
            97 => Cmd::CheckUpdates,
            98 => Cmd::StartCall(r.str()?, r.bool()?, r.bool()?),
            106 => Cmd::AnswerCallDirect,
            99 => Cmd::AnswerCall,
            100 => Cmd::DeclineCall,
            101 => Cmd::EndCall,
            102 => Cmd::CallMute(r.bool()?),
            103 => Cmd::CallMic(bytes_pcm(&r.bytes()?)?),
            104 => Cmd::CallCamera(r.bool()?),
            105 => {
                let (width, height) = (r.u32()?, r.u32()?);
                let rgba = r.bytes()?;
                if crate::rgba_len(width, height) != Some(rgba.len()) {
                    return Err(IpcError::Malformed);
                }
                Cmd::CallFrame(width, height, rgba)
            }
            107 => Cmd::StartGroupCall(r.str()?, r.bool()?),
            108 => Cmd::JoinGroupCall(r.str()?),
            109 => Cmd::CallHand(r.bool()?),
            110 => Cmd::CallReact(r.str()?),
            111 => Cmd::CreateCallLink(r.bool()?),
            112 => Cmd::AdmitToCall(r.u32()?),
            113 => Cmd::RefuseFromCall(r.u32()?),
            114 => Cmd::CallScreen(r.bool()?),
            115 => Cmd::PlayVoice(r.str()?, r.u64()?),
            116 => Cmd::TranscriptionModel(r.bool()?),
            117 => Cmd::Transcribe(r.str()?, r.u64()?),
            78 => Cmd::SetEmergencyPin(r.str()?),
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(c)
    }
}

impl Out {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Out::Snapshot(s) => [&[1u8][..], &s.encode()].concat(),
            Out::File(name, bytes) => {
                let mut w = Writer::default();
                w.u8(3).str(name).bytes(bytes);
                w.0
            }
            Out::Invite(link) => {
                let mut w = Writer::default();
                w.u8(4).str(link);
                w.0
            }
            Out::Preview(p) => {
                let mut w = Writer::default();
                w.u8(5)
                    .str(&p.conversation)
                    .u64(p.seq)
                    .u32(p.width)
                    .u32(p.height)
                    .bytes(&p.pixels);
                w.0
            }
            Out::Clip(c) => {
                let mut w = Writer::default();
                w.u8(6)
                    .u32(c.width)
                    .u32(c.height)
                    .u32(c.interval_ms)
                    .u32(c.frames.len() as u32);
                for f in &c.frames {
                    w.bytes(f);
                }
                w.0
            }
            Out::Notify(n) => {
                let mut w = Writer::default();
                w.u8(7).str(&n.conversation).str(&n.title).str(&n.body);
                w.0
            }
            Out::LanChunks(token, chunks, last) => {
                let mut w = Writer::default();
                w.u8(8).str(token).u32(chunks.len() as u32);
                for c in chunks {
                    w.bytes(c);
                }
                w.bool(*last);
                w.0
            }
            Out::LanStop(token) => {
                let mut w = Writer::default();
                w.u8(9).str(token);
                w.0
            }
            Out::LanFetch(token, addrs, n) => {
                let mut w = Writer::default();
                w.u8(10).str(token).strs(addrs).u32(*n);
                w.0
            }
            Out::UpdateBundle(b) => {
                let mut w = Writer::default();
                w.u8(11).bytes(b);
                w.0
            }
            Out::CallAudio(pcm) => {
                let mut w = Writer::default();
                w.u8(12).bytes(&pcm_bytes(pcm));
                w.0
            }
            Out::CallVideo(width, height, rgba) => {
                let mut w = Writer::default();
                w.u8(13).u32(*width).u32(*height).bytes(rgba);
                w.0
            }
            Out::CallTile(who, width, height, rgba) => {
                let mut w = Writer::default();
                w.u8(14).u32(*who).u32(*width).u32(*height).bytes(rgba);
                w.0
            }
            Out::VoiceAudio(key, first, pcm) => {
                let mut w = Writer::default();
                let bytes: Vec<u8> = pcm
                    .iter()
                    .take(VOICE_PIECE)
                    .flat_map(|s| s.to_le_bytes())
                    .collect();
                w.u8(15).str(key).bool(*first).bytes(&bytes);
                w.0
            }
            Out::OpenLink(link) => {
                let mut w = Writer::default();
                w.u8(16).str(link);
                w.0
            }
            Out::FilePart(name, bytes, last) => {
                let mut w = Writer::default();
                w.u8(17).str(name).bytes(bytes).bool(*last);
                w.0
            }
            Out::OpenNext => vec![18],
            Out::PackPreview(title, n) => {
                let mut w = Writer::default();
                w.u8(20).str(title).u32(*n);
                w.0
            }
            Out::Gifs(names) => {
                let mut w = Writer::default();
                w.u8(21).strs(&names[..names.len().min(MAX_GIFS)]);
                w.0
            }
            Out::RecordProgress(n) => {
                let mut w = Writer::default();
                w.u8(23).u32(*n);
                w.0
            }
            Out::Activity(a) => {
                let mut w = Writer::default();
                w.u8(24).str(&a.doing).str(&a.part).u32(a.done).u32(a.total);
                w.0
            }
            Out::VideoPiece(p) => {
                let mut w = Writer::default();
                let frames = &p.frames[..p.frames.len().min(MAX_PIECE_FRAMES)];
                w.u8(22)
                    .str(&p.key)
                    .u32(p.fps)
                    .u32(p.duration_ms)
                    .u32(p.width)
                    .u32(p.height)
                    .u32(frames.len() as u32);
                for f in frames {
                    w.bytes(f);
                }
                let pcm: Vec<u8> = p.pcm.iter().flat_map(|s| s.to_le_bytes()).collect();
                w.bytes(&pcm).bool(p.first).bool(p.done);
                w.0
            }
            Out::Gallery(rows) => {
                let mut w = Writer::default();
                let rows = &rows[..rows.len().min(MAX_GALLERY)];
                w.u8(19).u32(rows.len() as u32);
                for g in rows {
                    w.str(&g.conversation)
                        .str(&g.name)
                        .u64(g.seq)
                        .str(&g.file)
                        .bool(g.picture)
                        .bool(g.outgoing)
                        .str(&g.time);
                }
                w.0
            }
            Out::Effect(e) => vec![
                2,
                match e {
                    Effect::ContactAdded => 1,
                    Effect::GroupCreated => 2,
                    Effect::UsernameClaimed => 3,
                    Effect::RemovalDone => 4,
                    Effect::FileSent => 5,
                    Effect::LeftGroup => 6,
                    Effect::PassphraseChanged => 7,
                    Effect::PollCreated => 8,
                    Effect::Erased => 9,
                },
            ],
        }
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        match b {
            [1, rest @ ..] => Ok(Out::Snapshot(Box::new(Snapshot::decode(rest)?))),
            [2, e] => Ok(Out::Effect(match e {
                1 => Effect::ContactAdded,
                2 => Effect::GroupCreated,
                3 => Effect::UsernameClaimed,
                4 => Effect::RemovalDone,
                5 => Effect::FileSent,
                6 => Effect::LeftGroup,
                7 => Effect::PassphraseChanged,
                8 => Effect::PollCreated,
                9 => Effect::Erased,
                _ => return Err(IpcError::Malformed),
            })),
            [3, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::File(r.str()?, r.bytes()?);
                r.end()?;
                Ok(o)
            }
            [8, ..] => {
                let mut r = Reader(&b[1..]);
                let token = r.str()?;
                let n = r.u32()? as usize;
                if n > LAN_BATCH {
                    return Err(IpcError::Malformed);
                }
                let chunks = (0..n).map(|_| r.bytes()).collect::<Result<Vec<_>>>()?;
                let o = Out::LanChunks(token, chunks, r.bool()?);
                r.end()?;
                Ok(o)
            }
            [9, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::LanStop(r.str()?);
                r.end()?;
                Ok(o)
            }
            [10, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::LanFetch(r.str()?, r.strs()?, r.u32()?);
                r.end()?;
                Ok(o)
            }
            [11, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::UpdateBundle(r.bytes()?);
                r.end()?;
                Ok(o)
            }
            [12, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::CallAudio(bytes_pcm(&r.bytes()?)?);
                r.end()?;
                Ok(o)
            }
            [13, ..] => {
                let mut r = Reader(&b[1..]);
                let (width, height) = (r.u32()?, r.u32()?);
                let rgba = r.bytes()?;
                if crate::rgba_len(width, height) != Some(rgba.len()) {
                    return Err(IpcError::Malformed);
                }
                r.end()?;
                Ok(Out::CallVideo(width, height, rgba))
            }
            [14, ..] => {
                let mut r = Reader(&b[1..]);
                let (who, width, height) = (r.u32()?, r.u32()?, r.u32()?);
                let rgba = r.bytes()?;
                if crate::rgba_len(width, height) != Some(rgba.len()) {
                    return Err(IpcError::Malformed);
                }
                r.end()?;
                Ok(Out::CallTile(who, width, height, rgba))
            }
            [15, ..] => {
                let mut r = Reader(&b[1..]);
                let (key, first, bytes) = (r.str()?, r.bool()?, r.bytes()?);
                r.end()?;
                if bytes.len() % 2 != 0 || bytes.len() > VOICE_PIECE * 2 {
                    return Err(IpcError::Malformed);
                }
                let pcm = bytes
                    .chunks_exact(2)
                    .map(|c| i16::from_le_bytes([c[0], c[1]]))
                    .collect();
                Ok(Out::VoiceAudio(key, first, pcm))
            }
            [16, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::OpenLink(r.str()?);
                r.end()?;
                Ok(o)
            }
            [18] => Ok(Out::OpenNext),
            [20, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::PackPreview(r.str()?, r.u32()?);
                r.end()?;
                Ok(o)
            }
            [23, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::RecordProgress(r.u32()?);
                r.end()?;
                Ok(o)
            }
            [24, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::Activity(Activity {
                    doing: r.str()?,
                    part: r.str()?,
                    done: r.u32()?,
                    total: r.u32()?,
                });
                r.end()?;
                Ok(o)
            }
            [22, ..] => {
                let mut r = Reader(&b[1..]);
                let key = r.str()?;
                let (fps, duration_ms, width, height) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                let n = r.u32()? as usize;
                if n > MAX_PIECE_FRAMES {
                    return Err(IpcError::Malformed);
                }
                let mut frames = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.bytes()?;
                    if crate::rgba_len(width, height) != Some(f.len()) {
                        return Err(IpcError::Malformed);
                    }
                    frames.push(f);
                }
                let pcm = r.bytes()?;
                if pcm.len() % 2 != 0 {
                    return Err(IpcError::Malformed);
                }
                let o = Out::VideoPiece(VideoPiece {
                    key,
                    fps,
                    duration_ms,
                    width,
                    height,
                    frames,
                    pcm: pcm
                        .chunks_exact(2)
                        .map(|c| i16::from_le_bytes([c[0], c[1]]))
                        .collect(),
                    first: r.bool()?,
                    done: r.bool()?,
                });
                r.end()?;
                Ok(o)
            }
            [21, ..] => {
                let mut r = Reader(&b[1..]);
                let names = r.strs()?;
                r.end()?;
                if names.len() > MAX_GIFS {
                    return Err(IpcError::Malformed);
                }
                Ok(Out::Gifs(names))
            }
            [19, ..] => {
                let mut r = Reader(&b[1..]);
                let n = r.u32()? as usize;
                if n > MAX_GALLERY {
                    return Err(IpcError::Malformed);
                }
                let mut rows = Vec::with_capacity(n);
                for _ in 0..n {
                    rows.push(GalleryRow {
                        conversation: r.str()?,
                        name: r.str()?,
                        seq: r.u64()?,
                        file: r.str()?,
                        picture: r.bool()?,
                        outgoing: r.bool()?,
                        time: r.str()?,
                    });
                }
                r.end()?;
                Ok(Out::Gallery(rows))
            }
            [17, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::FilePart(r.str()?, r.bytes()?, r.bool()?);
                r.end()?;
                Ok(o)
            }
            [7, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::Notify(Notice {
                    conversation: r.str()?,
                    title: r.str()?,
                    body: r.str()?,
                });
                r.end()?;
                Ok(o)
            }
            [4, ..] => {
                let mut r = Reader(&b[1..]);
                let o = Out::Invite(r.str()?);
                r.end()?;
                Ok(o)
            }
            [5, ..] => {
                let mut r = Reader(&b[1..]);
                let p = Preview {
                    conversation: r.str()?,
                    seq: r.u64()?,
                    width: r.u32()?,
                    height: r.u32()?,
                    pixels: r.bytes()?,
                };
                r.end()?;
                if crate::rgba_len(p.width, p.height) != Some(p.pixels.len()) {
                    return Err(IpcError::Malformed);
                }
                Ok(Out::Preview(p))
            }
            [6, ..] => {
                let mut r = Reader(&b[1..]);
                let (width, height, interval_ms) = (r.u32()?, r.u32()?, r.u32()?);
                let n = r.u32()? as usize;
                if n > crate::media::MAX_CLIP_FRAMES {
                    return Err(IpcError::Malformed);
                }
                let mut frames = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.bytes()?;
                    if crate::rgba_len(width, height) != Some(f.len()) {
                        return Err(IpcError::Malformed);
                    }
                    frames.push(f);
                }
                r.end()?;
                Ok(Out::Clip(ClipFrames {
                    width,
                    height,
                    interval_ms,
                    frames,
                }))
            }
            _ => Err(IpcError::Malformed),
        }
    }
}
