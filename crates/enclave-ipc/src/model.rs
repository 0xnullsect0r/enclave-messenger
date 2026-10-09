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
}

/// Everything the window shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Our name.
    pub my_name: String,
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
    /// A device linked to the account in the last 7 days ("Linked device,
    /// 30 Sep 14:02"), pointed out on every device, or empty.
    pub new_device: String,
    /// Names of groups we asked to join that haven't let us in yet.
    pub joining: Vec<String>,
    /// Why restoring failed.
    pub restore_error: String,
    /// Accepted contacts who could hold a share of our recovery.
    pub friends: Vec<Pick>,
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
    /// The open conversation's contact is typing.
    pub typing: bool,
    /// This device can change the recovery words (it holds them).
    pub can_change_words: bool,
    /// Our change of recovery words is still reaching contacts and groups.
    pub words_pending: bool,
    /// This device was removed from the account: it can't get new
    /// messages, and may be erased.
    pub removed: bool,
    /// Root actions need the PIN.
    pub has_root_pin: bool,
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
    /// Tor bridges set here: empty, `builtin`, or bridge lines.
    pub bridges: String,
    /// Why the bridges given weren't taken.
    pub bridges_error: String,
    /// The bridges changed since Enclave started: they apply after a
    /// restart.
    pub bridges_restart: bool,
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
    /// Make a group invite link (admins; joins wait for approval); it comes
    /// back as [`Out::Invite`].
    NewGroupInvite(String),
    /// Ask a group a question: group, question, options.
    CreatePoll(String, String, Vec<String>),
    /// Vote in the poll at a group message: group, position, option index.
    Vote(String, u64, u32),
    /// Close our poll at a group message: group, position.
    ClosePoll(String, u64),
    /// Export an encrypted backup; it comes back as [`Out::File`].
    SaveBackup,
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
    /// The draft in a conversation changed: non-empty (typing) or not.
    Typing(String, bool),
    /// Replace the recovery words (a new root; 03 §8.2).
    ChangeWords,
    /// Play the clip at a message: conversation, position.
    PlayClip(String, u64),
    /// Use the backup route (true), or the mixnet again (false: "Keep
    /// waiting", "Back to the private route").
    BackupRoute(bool),
    /// Tor bridges: empty (none), `builtin`, or bridge lines.
    SetBridges(String),
    /// Put the current conversation on the record (or off it).
    SetOnRecord(bool),
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
        .u32(r.art);
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
        w.str(&self.my_name).str(&self.my_link);
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
                .u32(m.clip_ms);
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
            .bool(self.typing)
            .bool(self.can_change_words)
            .bool(self.words_pending)
            .bool(self.removed)
            .bool(self.has_root_pin)
            .str(&self.pin_error)
            .u8(self.moved)
            .strs(&self.held_moves)
            .u8(self.route)
            .bool(self.tor_blocked)
            .str(&self.bridges)
            .str(&self.bridges_error)
            .bool(self.bridges_restart);
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let my_name = r.str()?;
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
            typing: r.bool()?,
            can_change_words: r.bool()?,
            words_pending: r.bool()?,
            removed: r.bool()?,
            has_root_pin: r.bool()?,
            pin_error: r.str()?,
            moved: r.u8()?,
            held_moves: r.strs()?,
            route: r.u8()?,
            tor_blocked: r.bool()?,
            bridges: r.str()?,
            bridges_error: r.str()?,
            bridges_restart: r.bool()?,
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
            Cmd::NewGroupInvite(g) => w.u8(40).str(g),
            Cmd::CreatePoll(g, q, o) => w.u8(41).str(g).str(q).strs(o),
            Cmd::Vote(g, s, c) => w.u8(42).str(g).u64(*s).u32(*c),
            Cmd::ClosePoll(g, s) => w.u8(43).str(g).u64(*s),
            Cmd::SaveBackup => w.u8(44),
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
            Cmd::Typing(c, on) => w.u8(60).str(c).bool(*on),
            Cmd::ChangeWords => w.u8(61),
            Cmd::PlayClip(c, s) => w.u8(62).str(c).u64(*s),
            Cmd::BackupRoute(on) => w.u8(63).bool(*on),
            Cmd::SetBridges(b) => w.u8(64).str(b),
            Cmd::SetOnRecord(on) => w.u8(65).bool(*on),
            Cmd::WordsLanguage(l) => w.u8(67).str(l),
            Cmd::CodeWordsEnglish(on) => w.u8(68).bool(*on),
            Cmd::ReleaseShare(code) => w.u8(69).str(code),
            Cmd::AskShares => w.u8(70),
            Cmd::DeleteAccount => w.u8(71),
            Cmd::EraseDevice => w.u8(72),
            Cmd::SetRootPin(p) => w.u8(73).str(p),
            Cmd::UnlockRoot(p) => w.u8(74).str(p),
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
            40 => Cmd::NewGroupInvite(r.str()?),
            41 => Cmd::CreatePoll(r.str()?, r.str()?, r.strs()?),
            42 => Cmd::Vote(r.str()?, r.u64()?, r.u32()?),
            43 => Cmd::ClosePoll(r.str()?, r.u64()?),
            44 => Cmd::SaveBackup,
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
            60 => Cmd::Typing(r.str()?, r.bool()?),
            61 => Cmd::ChangeWords,
            62 => Cmd::PlayClip(r.str()?, r.u64()?),
            63 => Cmd::BackupRoute(r.bool()?),
            64 => Cmd::SetBridges(r.str()?),
            65 => Cmd::SetOnRecord(r.bool()?),
            67 => Cmd::WordsLanguage(r.str()?),
            68 => Cmd::CodeWordsEnglish(r.bool()?),
            69 => Cmd::ReleaseShare(r.str()?),
            70 => Cmd::AskShares,
            71 => Cmd::DeleteAccount,
            72 => Cmd::EraseDevice,
            73 => Cmd::SetRootPin(r.str()?),
            74 => Cmd::UnlockRoot(r.str()?),
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
