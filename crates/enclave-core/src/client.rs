//! The client state machine.

use crate::card::{ContactCard, LinkError, MAX_NAME};
use crate::content::{Content, MAX_TEXT, Token};
use crate::persist::{
    self, NS_CONTACTS, NS_ISSUERS, NS_PROFILE, NS_REPLAY, NS_SECRETS, NS_SESSIONS, NS_SETTINGS,
    Profile,
};
use crate::rpc::Rpc;
use crate::{CoreError, Result};
use enclave_crypto::hash::{security_code, sha3_512};
use enclave_crypto::kem::McEliecePublic;
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::SealKey;
use enclave_crypto::sig::RootPublic;
use enclave_net::transport::{ServerId, Transport};
use enclave_proto::bundle::{Bundle, PrekeyStore};
use enclave_proto::envelope;
use enclave_proto::eqxdh::{self, InitiatorIdentity, Local, ManifestResolver, Mode, Peer};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_proto::ratchet::Session;
use enclave_proto::recovery::RecoverySecret;
use enclave_proto::{ProtoError, manifest::MAX_DEVICES};
use enclave_rpc::api::{
    self, DirAction, DirKind, FLAG_CREATE, FLAG_REQUEST_INBOX, device_key, manifest_key,
};
use enclave_store::{Keystore, Store};
use enclave_wire::{Op, RequestHeader};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Tokens handed to a contact in each hello.
const HELLO_TOKENS: usize = 16;
/// Refill once the contact has used this many tokens.
const REFILL_AFTER: u32 = 8;
/// Rounds of [`Client::sync_round`] between housekeeping passes.
pub const UPKEEP_EVERY: u64 = 10;
/// Most tokens kept for one contact's inbox.
const MAX_HELD_TOKENS: usize = 64;
/// Keep expired prekeys this long for late initial messages.
const PREKEY_GRACE: u64 = 7 * 86_400;
/// Republish prekeys when fewer one-time prekeys than this remain.
const OPK_LOW_WATER: usize = 20;

/// Where a contact stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactState {
    /// We sent a request; they have not answered.
    Pending,
    /// They sent us a request; we have not accepted it.
    Request,
    /// Both sides can write.
    Accepted,
}

/// A contact as the UI sees it.
#[derive(Clone)]
pub struct Contact {
    /// Root public key.
    pub root: [u8; 64],
    /// Display name (theirs, or the one on their card).
    pub name: String,
    /// State.
    pub state: ContactState,
    /// Checked in person or by comparing security codes.
    pub verified: bool,
    /// Home server.
    pub server: [u8; 16],
    /// Request inbox.
    pub request_inbox: [u8; 32],
    pub(crate) inbox: Option<[u8; 32]>,
    pub(crate) tokens: Vec<Token>,
    pub(crate) manifest: Manifest,
    pub(crate) next_seq: u64,
    pub(crate) received_since_refill: u32,
    /// Unread incoming messages.
    pub unread: u32,
    /// When the contact was added.
    pub added_at: u64,
    /// Their card, if they shared it (needed to introduce them into groups).
    pub(crate) card: Option<ContactCard>,
    /// Known only through a group: not shown in the conversation list.
    pub group_only: bool,
    /// Disappearing timer for new messages (seconds, 0 = off).
    pub timer: u32,
}

impl Contact {
    /// The version of their manifest this device has taken.
    pub fn manifest_version(&self) -> u64 {
        self.manifest.version
    }

    /// Number of linked devices the contact has.
    pub fn device_count(&self) -> usize {
        self.manifest.devices.len()
    }
}

mod backup;
mod blobs;
mod blocks;
mod braid;
pub mod clock;
mod closing;
mod closing_own;
mod devices;
mod gaps;
mod gossip;
mod group_devices;
mod group_edits;
mod group_files;
mod group_hosts;
mod group_pq;
mod group_record;
mod groups;
mod guard;
mod history;
mod inbox;
mod invites;
mod link;
mod location;
#[cfg(test)]
mod maximum_tests;
mod meet;
mod messages;
mod migrate;
mod moves;
mod notes;
mod notify;
pub mod outbox;
mod own_sync;
mod parts;
mod pin;
mod pins;
mod polls;
mod prefs;
mod push;
mod record;
mod reports;
mod root_wrap;
mod search;
mod secure;
mod servers;
mod sharing;
mod social;
mod stickers;
mod tokens;
mod typing;
mod usernames;
mod wallet;

pub use crate::rpc::Sending;
pub use blobs::fetch_due;
pub use braid::BRAID_DEADLINE_SECS;
pub use gossip::{GossipItem, KtAlert};
pub use group_hosts::HOST_VOTE_SECS;
pub use groups::{GroupInfo, GroupMessage, GroupReaction};
pub use guard::{RecoveryAlert, RecoveryHold};
pub use invites::{InviteInfo, JOIN_PREFIX, JoinLink};
pub use link::{DeviceInfo, LinkCode, LinkOffer, LinkProgress, LinkingDevice};
pub use location::{Location, MAX_LOCATION_LABEL};
pub use meet::{MEET_PREFIX, MeetMatch};
pub use messages::{EDIT_WINDOW, Message, Reaction};
pub use migrate::{HELD_MOVE_NOTICE_SECS, Moved};
use own_sync::NS_CARD_OWED;
pub use own_sync::{INACTIVE_SECS, NEW_DEVICE_SECS, OwnDeviceState};
pub use pin::{FREE_TRIES, MIN_PIN_LEN, UNLOCK_SECS};
pub use pins::MAX_PINS;
pub use polls::{MAX_OPTIONS, PollView};
pub use prefs::{ConvPrefs, MAX_PINNED_CONVERSATIONS};
pub use record::Evidence;
pub use reports::{CALM_PER_DAY, FLOOD_PER_DAY, RAISED_EFFORT_SECS};
pub use search::{Hit, Place};
pub use servers::ListUpdate;
pub use social::{
    MAX_HOLDERS, RELEASE_PREFIX, SHARE_PREFIX, ShareRelease, ShareRequest, words_from_shares,
};
pub use stickers::{InstalledPack, MAX_STICKERS, PACK_MIME, StickerPack};
pub use typing::{TYPING_RESERVE, TYPING_SHOW_SECS};
pub use usernames::AUDIT_EVERY_SECS;
pub use wallet::{BOOK_LIFETIME, REFILL_BELOW, TOKENS_PER_PROOF, TicketWallet};

/// Something the UI should show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A stranger sent a message request.
    Request {
        /// Their root.
        root: [u8; 64],
        /// The name they gave.
        name: String,
        /// Their first message.
        text: String,
    },
    /// Someone accepted our request.
    Accepted {
        /// Their root.
        root: [u8; 64],
    },
    /// A new message.
    Message {
        /// From whom.
        root: [u8; 64],
        /// The message.
        message: Message,
    },
    /// A reaction, edit, delete or read receipt changed a message.
    MessageChanged {
        /// Conversation.
        root: [u8; 64],
        /// Message position.
        seq: u64,
    },
    /// The contact changed the disappearing timer.
    TimerChanged {
        /// Conversation.
        root: [u8; 64],
        /// New timer in seconds (0 = off).
        secs: u32,
    },
    /// A contact changed their recovery words (`03-identity.md` §8.2):
    /// they are now `root`, and no longer checked ([`Client::moved`]).
    ContactMoved {
        /// The root they had.
        old: [u8; 64],
        /// Their root now.
        root: [u8; 64],
        /// Their old root signed the change too.
        cross_signed: bool,
    },
    /// The contact started or stopped typing (only with typing indicators
    /// on, [`Client::typing_enabled`]). Show it for a few seconds at most:
    /// a "stopped" may never arrive.
    Typing {
        /// Conversation.
        root: [u8; 64],
        /// Typing (else stopped).
        on: bool,
    },
    /// A device was linked to (or is now talking with) this account.
    DevicesChanged,
    /// Message history from our other device was added.
    HistoryImported,
    /// A contact gave us part of their recovery to keep.
    RecoveryShareReceived {
        /// Whose.
        root: [u8; 64],
    },
    /// A vote arrived or a poll closed.
    PollChanged {
        /// The group.
        group_id: [u8; 32],
        /// The poll.
        poll: [u8; 16],
    },
    /// Someone asked to join a group through our group invite link; they
    /// wait for approval ([`Client::approve_join`]).
    JoinRequest {
        /// Who.
        root: [u8; 64],
        /// The group.
        group: [u8; 32],
        /// The name they gave (unverified).
        name: String,
    },
    /// Gossip with a contact proved that a key-transparency server signed
    /// two different versions of its log for the same epoch (RT-04): it
    /// shows different people different keys.
    KtSplitView {
        /// The log's server.
        server: [u8; 16],
        /// The epoch.
        epoch: u64,
    },
    /// The device clock is wrong against trusted time (the witnesses'
    /// median timestamp; RT-23), or right again (`skew` is `None`). The app
    /// shows a notice while it is wrong: times shown and expiry checks would
    /// be off.
    ClockSkew {
        /// Device time minus trusted time, in seconds.
        skew: Option<i64>,
    },
    /// Our username no longer leads to this account in the server's log.
    UsernameProblem {
        /// The address (`name@domain`).
        address: String,
    },
    /// Someone changed this account's devices without any of our devices
    /// (for example, restoring it from the recovery words elsewhere). Contacts
    /// accept the change at `until` unless a device stops it.
    RecoveryPending {
        /// Unix time when contacts would accept it.
        until: u64,
    },
    /// This device was removed from the account by another device. It can
    /// no longer read new messages; the app should say so and offer to erase.
    RemovedFromAccount,
    /// Our account was deleted from another of our devices: its tombstone
    /// is on our server. The app erases this device.
    AccountDeleted,
    /// A member of the group changed their recovery words: the group was
    /// told, but we never got the change from them, so their new key is
    /// on hold here (an hour on; `Client::held_moves`).
    GroupMoveHeld {
        /// The group.
        group_id: [u8; 32],
        /// Their old root.
        root: [u8; 64],
    },
    /// This device restored the account, and one of the account's other
    /// devices stopped the change: contacts will never accept it ("One of
    /// your other devices stopped this change").
    RecoveryStopped,
    /// This device's restore of the account was co-signed by another
    /// device or waited out its 72 hours: contacts accept it, and it can
    /// send.
    RecoveryDone,
    /// We were added to a group.
    GroupJoined {
        /// Group.
        group_id: [u8; 32],
        /// Its name.
        name: String,
    },
    /// A new group message.
    GroupMessage {
        /// Group.
        group_id: [u8; 32],
        /// The message.
        message: GroupMessage,
    },
    /// Group membership or settings changed.
    GroupChanged {
        /// Group.
        group_id: [u8; 32],
    },
    /// Another of our devices wrote or deleted a note to self.
    NotesChanged,
    /// A reaction, edit or delete changed a group message.
    GroupMessageChanged {
        /// Group.
        group_id: [u8; 32],
        /// Message position.
        seq: u64,
    },
    /// Someone pinned or unpinned a message ([`Client::pinned`]).
    PinsChanged {
        /// The conversation.
        place: Place,
    },
    /// The conversation with `root` went on the record or off it
    /// (`client/record.rs`).
    ModeChanged {
        /// The contact.
        root: [u8; 64],
        /// On the record now.
        on_record: bool,
        /// We changed it (on another device of ours).
        by_us: bool,
    },
    /// An admin put group `group_id` on the record or took it off.
    GroupModeChanged {
        /// The group.
        group_id: [u8; 32],
        /// On the record now.
        on_record: bool,
        /// The admin who changed it.
        by: [u8; 64],
    },
    /// `root` closed their account: the conversation is read-only.
    ContactClosed {
        /// The contact.
        root: [u8; 64],
    },
    /// A message from `root` may not have arrived: later ones did, over a
    /// minute ago ([`Client::gap`]).
    Gap {
        /// The contact.
        root: [u8; 64],
    },
    /// Another device of ours changed something here: a conversation read,
    /// archived, pinned or muted, a setting, a contact added or blocked
    /// (`own_sync.rs`).
    Synced,
}

/// Where and how to keep the profile.
pub struct Options {
    /// Database file; `None` keeps everything in memory (tests).
    pub path: Option<PathBuf>,
    /// Platform keystore holding the device secret.
    pub keystore: Arc<dyn Keystore>,
    /// Optional app passphrase.
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    /// Argon2id parameters for the passphrase.
    pub pw_params: PwParams,
}

/// The client engine for one profile on one device.
pub struct Client {
    store: Store,
    rng: HedgedRng,
    rpc: Rpc,
    account: AccountKeys,
    device: DeviceKeys,
    prekeys: PrekeyStore,
    manifest: Manifest,
    profile: Profile,
    sessions: HashMap<([u8; 64], [u8; 16]), Session>,
    contacts: BTreeMap<[u8; 64], Contact>,
    /// Registered write tokens not handed out yet (`tokens.rs`).
    token_pool: Vec<Token>,
    groups: BTreeMap<[u8; 32], groups::GroupEntry>,
    /// Pinned key-transparency logs and witnesses (from the app's server list).
    kt: Option<enclave_kt::KtPolicy>,
    /// Pins the app adds (development servers), merged with the list's.
    extra_pins: Option<enclave_kt::KtPolicy>,
    /// The foundation's key, from the app's build.
    foundation: Option<enclave_federation::FoundationPublic>,
    /// The newest server list verified under it.
    servers: Option<enclave_federation::ServerList>,
    /// Accounts whose device list changed (root → announced manifest
    /// version), refreshed at the end of `sync`.
    stale_manifests: BTreeMap<[u8; 64], u64>,
    /// History files from our own devices, fetched at the end of `sync`.
    pending_history: Vec<crate::files::Attachment>,
    /// Signed heads to send contacts whose gossip disagreed with ours.
    pending_kt_proofs: Vec<([u8; 64], [u8; 16], u64)>,
    /// Signed heads contacts sent us, to fetch and check.
    pending_kt_heads: Vec<([u8; 64], crate::files::Attachment)>,
    /// A change to our manifest that none of our devices made.
    recovery_alert: Option<guard::RecoveryAlert>,
    /// Our in-person code while it is on screen: (secret, payload).
    meet: Option<(zeroize::Zeroizing<[u8; 32]>, Vec<u8>)>,
    /// Scanned their code; waiting for the person to compare Seal words.
    pending_bond: Option<(ContactCard, zeroize::Zeroizing<[u8; 32]>)>,
    /// Messages received and not yet acknowledged with a delivery receipt
    /// (`outbox.rs`), sent at the end of the sync that brought them.
    pending_receipts: BTreeMap<[u8; 64], (u64, Vec<crate::content::MsgId>)>,
    /// Maximum privacy (`docs/09-transport.md` §6.6): no push, and nothing
    /// sent to a contact until all three KEMs protect the session.
    maximum: bool,
    /// Inbox rounds so far (the previous week's address is read in some).
    inbox_rounds: u64,
    /// A re-send writes to the week before's address (`outbox.rs`).
    fallback_week: bool,
    /// When each session last carried an envelope's PQ slot (a counter),
    /// for the carrier choice (`docs/06-multidevice.md` §3).
    pq_carried: HashMap<SessionKey, u64>,
    /// The envelope being handled arrived late (`Message::late`).
    late_unit: bool,
    /// The network is metered: braids wait (`braid.rs`).
    metered: bool,
    /// Root actions are unlocked until then (`pin.rs`).
    root_unlocked: u64,
    /// While unlocked with a PIN: the key that unwraps the recovery
    /// secret (`root_wrap.rs`).
    root_kek: Option<enclave_crypto::seal::SealKey>,
    /// The envelope being handled was personal content in a conversation
    /// on the record, or signed: its verified signature, if any
    /// (`Message::signed`).
    unit_signature: Option<Option<record::Evidence>>,
    /// The group message being handled: its signature's state on the
    /// record (`GroupMessage::signed`).
    group_unit_signed: Option<bool>,
    /// When each group was last read and how busy it has been, for the
    /// group rounds of [`Client::sync_round`].
    group_polls: HashMap<[u8; 32], GroupPoll>,
    /// Tests: start sessions without the McEliece vault key (2 KEMs, then
    /// the braid), as a client that doesn't have it would.
    #[cfg(test)]
    pub(crate) two_kem_for_tests: bool,
}

/// A group's place in the group rounds (`docs/09-transport.md` §5).
#[derive(Clone, Copy, Default)]
struct GroupPoll {
    /// When it was last read (0: not yet).
    last: u64,
    /// Smooth weighted round-robin credit.
    credit: i64,
    /// What its recent reads brought, halved at each read.
    activity: u32,
}

/// A message missing for this long, while later ones arrived, is pointed
/// out ("may not have arrived"), and one that then arrives is marked late
/// (`docs/05-ratchet.md` §11, RT-24).
pub const GAP_SECS: u64 = 60;

/// A group not read for this long goes first in the next group round.
pub const GROUP_FLOOR_SECS: u64 = 60;

/// Which of `refs` (sessions `keys`) carries the envelope's PQ slot
/// (`docs/06-multidevice.md` §3): of those with something to send in it,
/// the one whose pair last carried one longest ago.
pub(crate) fn pq_carrier(
    carried: &mut HashMap<SessionKey, u64>,
    keys: &[SessionKey],
    refs: &[&mut Session],
) -> Option<usize> {
    let i = refs
        .iter()
        .enumerate()
        .filter(|(_, s)| s.wants_pq_slot())
        .min_by_key(|(i, _)| carried.get(&keys[*i]).copied().unwrap_or(0))
        .map(|(i, _)| i)?;
    let tick = carried.values().max().copied().unwrap_or(0) + 1;
    carried.insert(keys[i], tick);
    Some(i)
}

/// A session is identified by the peer root and the peer device.
type SessionKey = ([u8; 64], [u8; 16]);

fn session_key(root: &[u8; 64], dev: &[u8; 16]) -> Vec<u8> {
    [&root[..], &dev[..]].concat()
}

/// Resolves the initiator's manifest from contacts or a freshly fetched copy,
/// recording what was asked for when it has neither.
struct Resolver<'a> {
    contacts: &'a BTreeMap<[u8; 64], Contact>,
    fetched: Option<Manifest>,
    wanted: Option<([u8; 64], u64, Vec<u8>)>,
}

impl ManifestResolver for Resolver<'_> {
    fn resolve(&mut self, id: &InitiatorIdentity) -> enclave_proto::Result<Manifest> {
        if let Some(m) = &self.fetched
            && m.root.0 == id.root
            && m.version == id.manifest_version
        {
            return Ok(m.clone());
        }
        if let Some(c) = self.contacts.get(&id.root)
            && c.manifest.version == id.manifest_version
        {
            return Ok(c.manifest.clone());
        }
        self.wanted = Some((id.root, id.manifest_version, id.locator.clone()));
        Err(ProtoError::Missing)
    }
}

impl Client {
    /// Set, change or remove the passphrase that protects this profile on
    /// this device. Records are not re-encrypted: the store's master key is
    /// rewrapped.
    pub fn change_passphrase(
        &mut self,
        new: Option<&[u8]>,
        params: enclave_crypto::pwhash::PwParams,
    ) -> Result<()> {
        Ok(self
            .store
            .change_passphrase(new.map(|p| (p, params)), &mut self.rng)?)
    }

    /// Current time, Unix seconds (from the transport, so simulations can
    /// move it).
    pub fn now(&self) -> u64 {
        self.rpc.now()
    }

    // ------------------------------------------------------------------
    // Profile lifecycle
    // ------------------------------------------------------------------

    /// Create a new account on `server` and publish it. Returns the client and
    /// the 24 recovery words (show them later, per the onboarding design).
    ///
    /// Slow: generates a Classic McEliece key and signs with SLH-DSA. Run it
    /// off the UI thread while the person types their name.
    pub async fn create(
        opts: Options,
        transport: Arc<dyn Transport>,
        server: ServerId,
        name: &str,
    ) -> Result<(Self, Vec<String>)> {
        if name.len() > MAX_NAME {
            return Err(CoreError::TooLong);
        }
        let mut rng = enclave_store::device_rng(opts.keystore.as_ref())?;
        let now = transport.now();
        let recovery = RecoverySecret::generate(&mut rng)?;
        let words = recovery.to_words()?;
        let account = AccountKeys::create(&recovery, &mut rng)?;
        let device = DeviceKeys::generate(&mut rng)?;
        let mut prekeys = PrekeyStore::default();
        let publication = prekeys.publish(&device, now, &mut rng)?;
        let mut profile = Profile {
            server,
            inbox_seed: rng.array("core/inbox-seed")?,
            request_inbox: rng.array("core/request-inbox")?,
            request_owner: rng.array("core/request-owner")?,
            vault_locator: rng.array("core/vault-locator")?,
            vault_key: rng.array("core/vault-key")?,
            name: name.to_string(),
            weeks: Vec::new(),
            request_cursor: 0,
            created_at: now,
        };
        let manifest = Manifest::genesis(&account, &device, now, profile.request_inbox.to_vec());
        let signed = manifest.sign(&account, &mut rng)?;

        let mut rpc = Rpc::new(transport);
        rpc.create_inbox(
            &server,
            profile.request_inbox,
            profile.request_owner,
            FLAG_CREATE | FLAG_REQUEST_INBOX,
            &[],
            now,
            &mut rng,
        )
        .await?;
        // This week's and next week's account-inbox addresses.
        let week = api::week_of(now);
        for w in [week, week + 1] {
            let days = inbox::read_days(&profile, w, now);
            rpc.create_inbox(
                &server,
                profile.addr(w),
                profile.owner(w),
                FLAG_CREATE,
                &days,
                now,
                &mut rng,
            )
            .await?;
            profile.add_week(w);
        }
        let mk = manifest_key(&account.root_public.0);
        rpc.dir_put(
            &server,
            DirKind::Manifest,
            mk,
            [0; 32],
            &signed.to_bytes(),
            now,
            &mut rng,
        )
        .await?;
        rpc.dir_put(
            &server,
            DirKind::Bundle,
            device_key(&device.id),
            [0; 32],
            &publication.encode(),
            now,
            &mut rng,
        )
        .await?;
        let vault_owner = enclave_rpc::api::vault_owner(&profile.vault_key);
        let blob = persist::seal_large(
            &SealKey::from_bytes(profile.vault_key),
            &account.vault_public.0[..],
            &mut rng,
        )?;
        rpc.dir_put(
            &server,
            DirKind::Vault,
            profile.vault_locator,
            vault_owner,
            &blob,
            now,
            &mut rng,
        )
        .await?;

        let pw = opts
            .passphrase
            .as_ref()
            .map(|p| (p.as_slice(), opts.pw_params));
        let store = Store::create(opts.path.as_deref(), opts.keystore, pw, &mut rng)?;
        let wrapped = root_wrap::initial(&store, &recovery, &mut rng)?;
        store.put(NS_SECRETS, root_wrap::KEY_ROOT_WRAP, &wrapped, &mut rng)?;
        store.put(NS_SECRETS, b"account", &account.export_shared(), &mut rng)?;
        store.put(NS_SECRETS, b"device", &device.export(), &mut rng)?;
        store.put(NS_SECRETS, b"prekeys", &prekeys.export(), &mut rng)?;
        store.put(NS_PROFILE, b"profile", &profile.encode(), &mut rng)?;
        store.put(NS_PROFILE, b"manifest", &manifest.encode()?, &mut rng)?;
        store.put(NS_PROFILE, b"signed-manifest", &signed.to_bytes(), &mut rng)?;

        let client = Self {
            store,
            rng,
            rpc,
            account,
            device,
            prekeys,
            manifest,
            profile,
            sessions: HashMap::new(),
            contacts: BTreeMap::new(),
            token_pool: Vec::new(),
            groups: BTreeMap::new(),
            kt: None,
            extra_pins: None,
            foundation: None,
            servers: None,
            stale_manifests: BTreeMap::new(),
            pending_history: Vec::new(),
            pending_kt_proofs: Vec::new(),
            pending_kt_heads: Vec::new(),
            recovery_alert: None,
            meet: None,
            pending_bond: None,
            pending_receipts: BTreeMap::new(),
            maximum: false,
            inbox_rounds: 0,
            fallback_week: false,
            pq_carried: std::collections::HashMap::new(),
            late_unit: false,
            metered: false,
            root_unlocked: 0,
            root_kek: None,
            unit_signature: None,
            group_unit_signed: None,
            group_polls: HashMap::new(),
            #[cfg(test)]
            two_kem_for_tests: false,
        };
        Ok((client, words))
    }

    /// Open an existing profile.
    pub fn open(opts: Options, transport: Arc<dyn Transport>) -> Result<Self> {
        let path = opts.path.as_deref().ok_or(CoreError::NotFound)?;
        let store = Store::open(
            path,
            opts.keystore,
            opts.passphrase.as_ref().map(|p| p.as_slice()),
        )?;
        let mut rng = enclave_store::device_rng(store.keystore().as_ref())?;
        // A change of recovery words interrupted after its commit point.
        migrate::finish_staged(&store, &mut rng)?;
        root_wrap::upgrade(&store, &mut rng)?;
        let get = |ns: &str, k: &[u8]| -> Result<Vec<u8>> {
            store.get(ns, k)?.ok_or(CoreError::NotFound)
        };
        // Linked devices have no recovery secret and so no root; behind a
        // PIN it waits for `unlock_root`.
        let recovery = root_wrap::without_pin(&store)?;
        let account = AccountKeys::import_shared(
            &Zeroizing::new(get(NS_SECRETS, b"account")?),
            recovery.as_ref(),
        )?;
        let device = DeviceKeys::import(&Zeroizing::new(get(NS_SECRETS, b"device")?))?;
        let prekeys = PrekeyStore::import(&Zeroizing::new(get(NS_SECRETS, b"prekeys")?))?;
        let profile = Profile::decode(&get(NS_PROFILE, b"profile")?)?;
        let manifest = Manifest::decode(&get(NS_PROFILE, b"manifest")?)?;
        let mut sessions = HashMap::new();
        for (k, v) in store.scan(NS_SESSIONS)? {
            if k.len() != 80 {
                continue;
            }
            let mut root = [0u8; 64];
            let mut dev = [0u8; 16];
            root.copy_from_slice(&k[..64]);
            dev.copy_from_slice(&k[64..]);
            sessions.insert((root, dev), Session::import(&Zeroizing::new(v))?);
        }
        let mut contacts = BTreeMap::new();
        for (_, v) in store.scan(NS_CONTACTS)? {
            let c = persist::decode_contact(&v)?;
            contacts.insert(c.root, c);
        }
        let token_pool = tokens::load_pool(&store)?;
        let groups = groups::load(&store)?;
        let mut client = Self {
            store,
            rng,
            rpc: Rpc::new(transport),
            account,
            device,
            prekeys,
            manifest,
            profile,
            sessions,
            contacts,
            token_pool,
            groups,
            kt: None,
            extra_pins: None,
            foundation: None,
            servers: None,
            stale_manifests: BTreeMap::new(),
            pending_history: Vec::new(),
            pending_kt_proofs: Vec::new(),
            pending_kt_heads: Vec::new(),
            recovery_alert: None,
            meet: None,
            pending_bond: None,
            pending_receipts: BTreeMap::new(),
            maximum: false,
            inbox_rounds: 0,
            fallback_week: false,
            pq_carried: std::collections::HashMap::new(),
            late_unit: false,
            metered: false,
            root_unlocked: 0,
            root_kek: None,
            unit_signature: None,
            group_unit_signed: None,
            group_polls: HashMap::new(),
            #[cfg(test)]
            two_kem_for_tests: false,
        };
        client.resume_rename()?;
        Ok(client)
    }

    /// Crypto-erase this profile (emergency PIN, panic wipe, account deletion).
    pub fn erase(self) -> Result<()> {
        Ok(self.store.crypto_erase()?)
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Our display name.
    pub fn name(&self) -> &str {
        &self.profile.name
    }

    /// Our root public key.
    pub fn root(&self) -> [u8; 64] {
        self.account.root_public.0
    }

    /// Our account identity key (in the manifest; "Secure my account"
    /// replaces it).
    pub fn identity_public(&self) -> [u8; 56] {
        self.account.identity_public.0
    }

    /// Our contact card (for the QR code and invite link).
    pub fn card(&self) -> ContactCard {
        ContactCard {
            root: self.account.root_public.0,
            server: self.profile.server,
            request_inbox: self.profile.request_inbox,
            vault_locator: self.profile.vault_locator,
            vault_key: self.profile.vault_key,
            name: self.profile.name.clone(),
            server_domain: self.server_domain(&self.profile.server).unwrap_or_default(),
            invite: None,
        }
    }

    /// The 24 recovery words (for the deferred "save your recovery words" card).
    pub fn recovery_words(&self) -> Result<Vec<String>> {
        Ok(self.recovery_secret()?.to_words()?)
    }

    /// The spoken security code with `root`: 10 words in the BIP-39 list
    /// `language` (`03-identity.md` §6.2).
    pub fn security_words(&self, root: &[u8; 64], language: &str) -> Result<Vec<String>> {
        let lang = enclave_proto::recovery::language(language).ok_or(CoreError::NotFound)?;
        Ok(enclave_proto::recovery::security_words(
            &self.account.root_public.0,
            root,
            lang,
        ))
    }

    /// The recovery words in another BIP-39 language (`recovery::language`
    /// codes). They stand for the same secret.
    pub fn recovery_words_in(&self, language: &str) -> Result<Vec<String>> {
        let lang = enclave_proto::recovery::language(language).ok_or(CoreError::NotFound)?;
        Ok(self.recovery_secret()?.to_words_in(lang)?)
    }

    /// All contacts.
    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts
            .values()
            .filter(|c| !c.group_only)
            .cloned()
            .collect()
    }

    /// One contact.
    pub fn contact(&self, root: &[u8; 64]) -> Option<&Contact> {
        self.contacts.get(root)
    }

    /// The 60-digit security code shared with `root`.
    pub fn security_code(&self, root: &[u8; 64]) -> String {
        security_code(&self.account.root_public.0, root)
    }

    /// Turn Maximum privacy on or off (the engine follows the setting).
    pub fn set_maximum(&mut self, on: bool) {
        self.maximum = on;
    }

    /// Whether Maximum privacy is on.
    pub fn maximum(&self) -> bool {
        self.maximum
    }

    /// In Maximum privacy, whether sends to `root` are waiting for all
    /// three KEMs ("Extra protection: finishing…").
    pub fn protection_finishing(&self, root: &[u8; 64]) -> bool {
        self.maximum
            && !self
                .sessions
                .iter()
                .any(|((r, _), s)| r == root && s.can_send() && s.three_kem())
    }

    /// Whether every session with `root` has completed the post-quantum
    /// authentication round trip and uses all three KEMs.
    pub fn fully_protected(&self, root: &[u8; 64]) -> bool {
        let mut any = false;
        for ((r, _), s) in &self.sessions {
            if r == root {
                any = true;
                if !(s.three_kem() && s.pq_authenticated()) {
                    return false;
                }
            }
        }
        any
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Store an app setting (sealed like everything else).
    pub fn set_setting(&mut self, key: &str, value: &[u8]) -> Result<()> {
        // The ones every device of the account shares go to the others.
        if own_sync::SYNCED_SETTINGS.contains(&key) && self.setting(key)?.as_deref() != Some(value)
        {
            self.queue_own(own_sync::SyncItem::Setting {
                key: key.to_string(),
                value: value.to_vec(),
            })?;
        }
        Ok(self
            .store
            .put(NS_SETTINGS, key.as_bytes(), value, &mut self.rng)?)
    }

    /// Read an app setting.
    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(NS_SETTINGS, key.as_bytes())?)
    }

    /// Mark a contact as checked (or not).
    pub fn set_verified(&mut self, root: &[u8; 64], verified: bool) -> Result<()> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.verified = verified;
        if verified {
            self.sync_contact_to_own(root, false)?;
        }
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        let c = c.clone();
        self.save_contact(&c)?;
        if verified {
            self.clear_moved(root)?;
        }
        Ok(())
    }

    /// Add someone from their card and send a first message. Fetches and
    /// verifies their manifest, McEliece vault key and a bundle per device.
    pub async fn add_contact(&mut self, card: &ContactCard, text: &str) -> Result<()> {
        self.add_contact_with(card, text, None, None).await
    }

    /// Add a contact, optionally as an introduction through a group.
    pub(crate) async fn add_contact_with(
        &mut self,
        card: &ContactCard,
        text: &str,
        group: Option<[u8; 32]>,
        psk: Option<&[u8; 32]>,
    ) -> Result<()> {
        if card.root == self.account.root_public.0 {
            return Err(LinkError::OwnCode.into());
        }
        if text.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        if self.contacts.contains_key(&card.root) {
            return Ok(());
        }
        // An old card (or invite link): the account may have moved since.
        let card = &self.follow_moves(card).await?;
        let now = self.now();
        let server = card.server;
        let peer_manifest = self.fetch_manifest(card, now).await?;
        // Someone met through a group starts on two KEMs: their 1.36 MB
        // vault key is fetched later (`braid.rs`, `04-eqxdh.md` §7), unless
        // Maximum privacy needs all three before anything is sent.
        let vault = if group.is_some() && !self.maximum {
            None
        } else {
            Some(self.fetch_vault(card, &peer_manifest, now).await?)
        };
        // An invite link's secret is a one-way PSK (weaker than meeting in
        // person, so it doesn't mark them checked).
        let invite_psk = card.invite.as_ref().map(|i| eqxdh::invite_psk(&i.secret));
        let session_psk = psk.or(invite_psk.as_deref());

        let tokens = self.issue_tokens(&card.root, HELLO_TOKENS, now).await?;
        let hello_id: crate::content::MsgId = self.rng.array("core/msg-id")?;
        let hello = Content::Hello {
            server: self.profile.server,
            inbox: self.profile.addr_seed(),
            tokens,
            name: self.profile.name.clone(),
            text: text.to_string(),
            card: self.card().encode(),
            group,
            id: hello_id,
        }
        .encode()?;

        let contact = Contact {
            root: card.root,
            name: card.name.clone(),
            state: ContactState::Pending,
            verified: psk.is_some(),
            server,
            request_inbox: card.request_inbox,
            inbox: None,
            tokens: Vec::new(),
            manifest: peer_manifest.clone(),
            next_seq: 0,
            received_since_refill: 0,
            unread: 0,
            added_at: now,
            // The invite is spent on this greeting; never keep it.
            card: Some(ContactCard {
                invite: None,
                ..card.clone()
            }),
            group_only: group.is_some(),
            timer: 0,
        };
        self.contacts.insert(card.root, contact.clone());
        self.save_contact(&contact)?;
        if !text.is_empty() {
            self.new_message(&card.root, hello_id, true, text, 0, now)?;
        }

        let r = self
            .initiate_to(
                card,
                &peer_manifest,
                vault.as_ref(),
                &hello,
                None,
                now,
                session_psk,
            )
            .await;
        if let Err(CoreError::Link(LinkError::InviteUsed)) = r {
            // Nothing reached them: forget the half-added contact.
            self.remove_contact(&card.root)?;
        }
        let _ = server;
        r
    }

    /// Fetch and verify a contact's manifest and McEliece vault key.
    pub(crate) async fn fetch_peer(
        &mut self,
        card: &ContactCard,
        now: u64,
    ) -> Result<(Manifest, McEliecePublic)> {
        let peer_manifest = self.fetch_manifest(card, now).await?;
        let vault = self.fetch_vault(card, &peer_manifest, now).await?;
        Ok((peer_manifest, vault))
    }

    /// `card`'s account manifest, checked against its root.
    pub(crate) async fn fetch_manifest(
        &mut self,
        card: &ContactCard,
        now: u64,
    ) -> Result<Manifest> {
        let server = card.server;
        let mb = self
            .rpc
            .dir_get(
                &server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&card.root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        Ok(SignedManifest::from_bytes(&mb)?.verify(&RootPublic(card.root), now)?)
    }

    /// `card`'s McEliece vault key (1.36 MB), checked against the hash in
    /// its manifest.
    pub(crate) async fn fetch_vault(
        &mut self,
        card: &ContactCard,
        peer_manifest: &Manifest,
        now: u64,
    ) -> Result<McEliecePublic> {
        let server = card.server;
        let vb = self
            .rpc
            .dir_get(
                &server,
                DirKind::Vault,
                DirAction::Get,
                card.vault_locator,
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        let vault = McEliecePublic::from_slice(&persist::open_large(
            &SealKey::from_bytes(card.vault_key),
            &vb,
        )?)?;
        if sha3_512(&vault.0[..]) != peer_manifest.vault_hash {
            return Err(ProtoError::BadSignature.into());
        }
        Ok(vault)
    }

    /// Start a session with every device of `card`'s account (except `skip`)
    /// and send `hello` as the first message of each.
    pub(crate) async fn initiate_to(
        &mut self,
        card: &ContactCard,
        peer_manifest: &Manifest,
        vault: Option<&McEliecePublic>,
        hello: &[u8],
        skip: Option<[u8; 16]>,
        now: u64,
        psk: Option<&[u8; 32]>,
    ) -> Result<()> {
        let server = card.server;
        // Invite links carry request-inbox capabilities in place of a proof
        // of work: one per device of the person joining, per use.
        let caps: Vec<[u8; 32]> = card
            .invite
            .as_ref()
            .map(|i| {
                (0..u32::from(i.uses) * invites::CAPS_PER_USE)
                    .map(|n| eqxdh::invite_cap(&i.secret, n))
                    .collect()
            })
            .unwrap_or_default();
        let mut next_cap = 0;
        for dev in peer_manifest.devices.iter().take(MAX_DEVICES) {
            if Some(dev.id) == skip || self.sessions.contains_key(&(card.root, dev.id)) {
                continue;
            }
            let bb = self
                .rpc
                .claim_bundle(&server, device_key(&dev.id), now, &mut self.rng)
                .await?;
            let bundle = Bundle::decode(&bb)?;
            bundle.verify(&dev.signing, now)?;
            let (session, env) = {
                let local = Local {
                    account: &self.account,
                    device: &self.device,
                    manifest: &self.manifest,
                    locator: &self.profile.server,
                };
                #[cfg(test)]
                let with_vault = !self.two_kem_for_tests;
                #[cfg(not(test))]
                let with_vault = true;
                let peer = Peer {
                    manifest: peer_manifest,
                    device: dev,
                    bundle: &bundle,
                    vault: vault.filter(|_| with_vault),
                };
                let init = eqxdh::initiate(&local, &peer, Mode::OffTheRecord, psk, &mut self.rng)?;
                let mut session = init.session;
                // Started on two KEMs: the next PQ step braids in the third
                // (`docs/04-eqxdh.md` §7), now if we hold the vault key,
                // else once `braid.rs` has fetched it.
                if !session.three_kem() {
                    match vault {
                        Some(v) => session.schedule_braid(v.clone()),
                        None => self.braid_due(&card.root, now)?,
                    }
                }
                let env =
                    envelope::seal_request(&init.message, &mut session, hello, &mut self.rng)?;
                (session, env)
            };
            // Persist before the envelope leaves.
            self.save_session(&card.root, &dev.id, &session)?;
            self.sessions.insert((card.root, dev.id), session);
            if caps.is_empty() {
                self.rpc
                    .write_request(&server, card.request_inbox, &env, now, &mut self.rng)
                    .await?;
            } else {
                self.rpc
                    .write_invited(
                        &server,
                        card.request_inbox,
                        &env,
                        &caps,
                        &mut next_cap,
                        now,
                        &mut self.rng,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Accept a message request: give them our inbox and write tokens.
    pub async fn accept(&mut self, root: &[u8; 64]) -> Result<()> {
        self.accept_with(root, None).await
    }

    async fn accept_with(&mut self, root: &[u8; 64], group: Option<[u8; 32]>) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Request {
            return Ok(());
        }
        let now = self.now();
        let tokens = self.issue_tokens(root, HELLO_TOKENS, now).await?;
        let hello = Content::Hello {
            server: self.profile.server,
            inbox: self.profile.addr_seed(),
            tokens,
            name: self.profile.name.clone(),
            text: String::new(),
            card: self.card().encode(),
            group,
            id: self.rng.array("core/msg-id")?,
        };
        self.send_content(root, &hello, now).await?;
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.state = ContactState::Accepted;
        let c = c.clone();
        self.save_contact(&c)?;
        self.sync_contact_to_own(root, true)
    }

    /// Delete a contact (declining a request, blocking). Their sessions and
    /// history are removed; they get no new tokens.
    pub fn remove_contact(&mut self, root: &[u8; 64]) -> Result<()> {
        self.contacts.remove(root);
        self.store.delete(NS_CONTACTS, root)?;
        self.store.delete(NS_ISSUERS, root)?;
        let devs: Vec<[u8; 16]> = self
            .sessions
            .keys()
            .filter(|(r, _)| r == root)
            .map(|(_, d)| *d)
            .collect();
        for d in devs {
            self.sessions.remove(&(*root, d));
            self.store.delete(NS_SESSIONS, &session_key(root, &d))?;
        }
        let ns = persist::msg_ns(root);
        for (k, _) in self.store.scan(&ns)? {
            self.store.delete(&ns, &k)?;
        }
        self.forget_record(root)?;
        self.forget_closed(root)?;
        self.forget_shared_contacts(root)
    }

    /// Send a text message.
    pub async fn send_text(&mut self, root: &[u8; 64], text: &str) -> Result<Message> {
        if text.len() > crate::content::MAX_LONG_TEXT {
            return Err(CoreError::TooLong);
        }
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        let tokens = if c.received_since_refill >= REFILL_AFTER {
            let n = refill_size(c.received_since_refill);
            self.issue_tokens(root, n, now).await?
        } else {
            Vec::new()
        };
        let refilled = !tokens.is_empty();
        let mut msg = self.store_message(root, true, text, now)?;
        let sent = self
            .send_tracked(
                root,
                msg.id,
                &Content::Text {
                    tokens,
                    text: text.to_string(),
                    id: msg.id,
                    expires: msg.expires_secs,
                },
                now,
            )
            .await?;
        let copy = Content::Text {
            tokens: Vec::new(),
            text: text.to_string(),
            id: msg.id,
            expires: msg.expires_secs,
        };
        self.send_self_copy(root, &copy, now).await?;
        if refilled && let Some(c) = self.contacts.get_mut(root) {
            c.received_since_refill = 0;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        msg.sent = sent;
        self.put_message(root, &msg)?;
        Ok(msg)
    }

    /// Fetch and process everything waiting in our inboxes, refill tokens and
    /// maintain prekeys. Returns what the UI should show.
    pub async fn sync(&mut self) -> Result<Vec<Event>> {
        let now = self.now();
        if self.account_deleted() {
            return Ok(Vec::new());
        }
        let mut events = match self.sync_inboxes(now, true).await {
            Ok(e) => e,
            Err(e) => return self.deleted_or(e, now).await,
        };
        events.append(&mut self.sync_upkeep(now).await?);
        let mut group_events = self.sync_groups(now).await?;
        events.append(&mut group_events);
        self.finish_pre_steps(now).await?;

        self.maintain_prekeys(now).await?;
        Ok(events)
    }

    /// One round of syncing, for a client whose traffic is shaped
    /// (`docs/09-transport.md` §9.4): even rounds read the account's
    /// inboxes, odd rounds one group's mailboxes in turn, and every
    /// [`UPKEEP_EVERY`] rounds the housekeeping that [`Client::sync`] does
    /// each time (manifests, token refills, expiry, prekeys…). Each round
    /// makes only a few requests, so at one poll per tick the app stays
    /// responsive between rounds.
    pub async fn sync_round(&mut self, round: u64) -> Result<Vec<Event>> {
        self.sync_round_every(round, 2).await
    }

    /// Like [`Client::sync_round`], with groups read in one round of every
    /// `period` (at least 2) and the account's inboxes in the others: the
    /// scheduler's `other_mailbox_period` for the profile (4 in
    /// Background).
    pub async fn sync_round_every(&mut self, round: u64, period: u64) -> Result<Vec<Event>> {
        let period = period.max(2);
        let now = self.now();
        let groups: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(k, _)| *k)
            .collect();
        if self.account_deleted() {
            return Ok(Vec::new());
        }
        let mut events = if round % period != period - 1 || groups.is_empty() {
            match self.sync_inboxes(now, false).await {
                Ok(e) => e,
                Err(e) => return self.deleted_or(e, now).await,
            }
        } else {
            let gid = self.next_group(&groups, now);
            let got = self.sync_group_with(&gid, now, true).await?;
            let p = self.group_polls.entry(gid).or_default();
            p.last = now;
            p.activity = p.activity / 2 + got.len() as u32;
            got
        };
        if round % UPKEEP_EVERY == 1 {
            events.append(&mut self.sync_upkeep(now).await?);
            self.finish_pre_steps(now).await?;
            self.maintain_prekeys(now).await?;
        }
        Ok(events)
    }

    /// The group a group round reads: one not read for
    /// [`GROUP_FLOOR_SECS`] (the longest waiting first), else by smooth
    /// weighted round robin, a group's weight growing with what its recent
    /// reads brought.
    fn next_group(&mut self, groups: &[[u8; 32]], now: u64) -> [u8; 32] {
        self.group_polls.retain(|g, _| groups.contains(g));
        let overdue = groups
            .iter()
            .map(|g| (*g, self.group_polls.get(g).map_or(0, |p| p.last)))
            .filter(|(_, last)| last.saturating_add(GROUP_FLOOR_SECS) <= now)
            .min_by_key(|(_, last)| *last);
        if let Some((g, _)) = overdue {
            return g;
        }
        let weight = |p: &GroupPoll| 1 + i64::from(p.activity.min(7));
        let total: i64 = groups
            .iter()
            .map(|g| weight(&self.group_polls.get(g).copied().unwrap_or_default()))
            .sum();
        let mut best = groups[0];
        let mut best_credit = i64::MIN;
        for g in groups {
            let p = self.group_polls.entry(*g).or_default();
            p.credit += weight(p);
            if p.credit > best_credit {
                best_credit = p.credit;
                best = *g;
            }
        }
        if let Some(p) = self.group_polls.get_mut(&best) {
            p.credit -= total;
        }
        best
    }

    /// Read the request inbox and the account inbox's addresses (`all`:
    /// the previous week's too, whatever the round).
    async fn sync_inboxes(&mut self, now: u64, all: bool) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let server = self.profile.server;
        let reqs = self
            .rpc
            .poll(
                &server,
                self.profile.request_inbox,
                enclave_rpc::api::read_credential(&self.profile.request_owner),
                self.profile.request_cursor,
                now,
                &mut self.rng,
            )
            .await?;
        // A flood of requests makes new ones cost more (`reports.rs`).
        if let Err(e) = self.note_requests(reqs.len() as u32, now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        for polled in reqs {
            match self.handle_request(&polled.envelope, now).await {
                Ok(Some(e)) => {
                    if let Event::Accepted { root } = &e {
                        self.sync_contact_to_own(root, true)?;
                    }
                    events.push(e);
                }
                Ok(None) => {}
                // Network trouble: stop here and retry this envelope next time.
                Err(e @ CoreError::Net(_)) => {
                    self.save_profile()?;
                    return Err(e);
                }
                // Anything else is a bad or foreign envelope: skip it.
                Err(_) => {}
            }
            self.profile.request_cursor = polled.cursor;
            self.save_profile()?;
        }

        // A new week whose address isn't there yet (we were away). If it
        // can't be made now, the addresses we have are still read.
        if !self.profile.has_week(api::week_of(self.inbox_now(now)))
            && let Err(e) = self.ensure_weeks(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        for week in self.weeks_to_read(now, all) {
            let mut p = Profile::decode(&self.profile.encode())?;
            let read = self
                .read_week(&mut p, week, now, |c, p| {
                    c.profile.weeks = p.weeks.clone();
                    c.save_profile()
                })
                .await;
            events.append(&mut read?);
        }
        // Envelopes held for want of a session, which this sync may have brought.
        events.append(&mut self.retry_held(now)?);
        events.append(&mut self.process_migrations(now).await?);
        events.append(&mut self.home_upkeep(now).await?);
        // What arrived is acknowledged before the next round.
        if let Err(e) = self.flush_receipts(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        Ok(events)
    }

    /// Everything but reading mailboxes: manifests, history, refills,
    /// expiry, invites.
    async fn sync_upkeep(&mut self, now: u64) -> Result<Vec<Event>> {
        // A PIN unlock that has lapsed takes the unwrapped root with it.
        self.relock_root_if_due();
        let mut events = Vec::new();
        match self.check_clock(now).await {
            Ok(mut e) => events.append(&mut e),
            Err(CoreError::Net(e)) => return Err(CoreError::Net(e)),
            Err(_) => {}
        }
        // Next week's address, made ahead (`inbox.rs`), by the clock just
        // checked.
        if let Err(e) = self.ensure_weeks(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        // Until it has switched, our own manifest check would look at the
        // home we are leaving.
        if let Err(e) = self.push_home_move(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        events.append(&mut self.refresh_manifests(now).await?);
        events.append(&mut self.resend_outbox(now).await?);
        events.append(&mut self.release_held(now).await?);
        events.append(&mut self.check_own_manifest(now).await?);
        events.append(&mut self.check_recovering(now).await?);
        events.append(&mut self.notice_held_moves(now)?);
        if let Err(e) = self.secure_upkeep(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        if let Err(e) = self.notify_upkeep(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        if let Err(e) = self.push_groups(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        // The third KEM for someone met through a group (`braid.rs`).
        if let Err(e) = self.upgrade_braids(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        if let Err(e) = self.push_migration(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        events.append(&mut self.audit_username(now).await?);
        if let Err(e) = self.relax_request_effort(now).await
            && matches!(e, CoreError::Net(_))
        {
            return Err(e);
        }
        events.extend(self.process_kt(now).await?);
        if self.import_pending_history(now).await? > 0 {
            events.push(Event::HistoryImported);
        }
        self.send_due_history(now).await?;
        events.append(&mut self.own_upkeep(now).await?);

        // Token refills for contacts who have been writing without replies.
        let due: Vec<([u8; 64], usize)> = self
            .contacts
            .values()
            .filter(|c| {
                c.state == ContactState::Accepted && c.received_since_refill >= REFILL_AFTER + 4
            })
            .filter(|c| !self.is_blocked(&c.root))
            .map(|c| (c.root, refill_size(c.received_since_refill)))
            .collect();
        for (root, n) in due {
            let tokens = self.issue_tokens(&root, n, now).await?;
            self.send_content(&root, &Content::Tokens(tokens), now)
                .await?;
            if let Some(c) = self.contacts.get_mut(&root) {
                c.received_since_refill = 0;
                let c = c.clone();
                self.save_contact(&c)?;
            }
        }

        // Parts of content that never completed.
        self.expire_parts(now)?;

        // Forget message keys for messages that never arrived.
        let mut expired = Vec::new();
        for (k, s) in self.sessions.iter_mut() {
            if s.expire_skipped(now, enclave_proto::ratchet::SKIPPED_MAX_AGE) > 0 {
                expired.push((*k, s.clone()));
            }
        }
        for ((root, dev), s) in expired {
            self.save_session(&root, &dev, &s)?;
        }
        // Messages that seem missing (keys skipped, now stamped).
        events.append(&mut self.check_gaps()?);

        self.purge_expired(now)?;
        self.expire_invites(now).await?;
        Ok(events)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    async fn handle_request(&mut self, env: &[u8], now: u64) -> Result<Option<Event>> {
        let msg = envelope::request_initial(env)?;
        if !self.prekeys.signed.contains_key(&msg.spk_id) {
            return Ok(None);
        }
        let rid = msg.replay_id();
        if self.store.get(NS_REPLAY, &rid)?.is_some() {
            return Ok(None);
        }
        let mut fetched: Option<Manifest> = None;
        // To answer with our previous manifest if this one doesn't open.
        let prekeys_before = self.prekeys.export();
        // A greeting from someone we met in person carries the bond PSK,
        // and one through an invite link carries that link's PSK; we don't
        // know who it is before opening it, so try each.
        #[derive(Clone, Copy)]
        enum Via {
            Plain,
            Bond,
            Invite([u8; 32]),
        }
        let candidates: Vec<(Via, Option<zeroize::Zeroizing<[u8; 32]>>)> = if msg.psk {
            let bonds = self.bonds()?.into_iter().map(|p| (Via::Bond, Some(p)));
            let invites = self
                .invite_psks()?
                .into_iter()
                .map(|(k, p)| (Via::Invite(k), Some(p)));
            bonds.chain(invites).collect()
        } else {
            vec![(Via::Plain, None)]
        };
        if candidates.is_empty() {
            return Err(ProtoError::Crypto.into());
        }
        let mut candidate = 0;
        let resp = loop {
            let psk = candidates[candidate].1.clone();
            let (result, wanted) = {
                let local = Local {
                    account: &self.account,
                    device: &self.device,
                    manifest: &self.manifest,
                    locator: &self.profile.server,
                };
                let mut resolver = Resolver {
                    contacts: &self.contacts,
                    fetched: fetched.clone(),
                    wanted: None,
                };
                let r = eqxdh::respond(
                    &local,
                    &mut self.prekeys,
                    &msg,
                    psk.as_deref(),
                    &mut resolver,
                    &mut self.rng,
                );
                (r, resolver.wanted)
            };
            match (result, wanted) {
                (Ok(r), _) => break r,
                (Err(ProtoError::Missing), Some((root, version, locator))) if fetched.is_none() => {
                    let server: ServerId = locator
                        .as_slice()
                        .try_into()
                        .map_err(|_| ProtoError::Decode)?;
                    let mb = self
                        .rpc
                        .dir_get(
                            &server,
                            DirKind::Manifest,
                            DirAction::Get,
                            manifest_key(&root),
                            [0; 32],
                            now,
                            &mut self.rng,
                        )
                        .await?;
                    let sm = SignedManifest::from_bytes(&mb)?;
                    let m = sm.verify(&RootPublic(root), now)?;
                    // Older than the greeting names: the server is behind or
                    // rolling back. Newer: they changed it (a device linked)
                    // after writing; the greeting then counts only if the
                    // current one still lists its device (checked when it
                    // is opened), and its transcript has the version it named.
                    if m.version < version {
                        return Err(ProtoError::Rollback.into());
                    }
                    if let Some(c) = self.contacts.get(&root)
                        && c.manifest.version > m.version
                    {
                        return Err(ProtoError::Rollback.into());
                    }
                    // A newer manifest of an account we know (a contact, or
                    // our own) takes effect only if a device co-signed it,
                    // or after the 72-hour guard.
                    let known = if root == self.account.root_public.0 {
                        Some(self.manifest.clone())
                    } else {
                        self.contacts.get(&root).map(|c| c.manifest.clone())
                    };
                    if let Some(old) = known
                        && m.version > old.version
                    {
                        match self.judge(&root, &server, &old, &sm, &m, now).await? {
                            guard::Judgement::Accept => {}
                            guard::Judgement::Wait(until) => {
                                self.hold_request(&rid, env, until, now)?;
                                return Ok(None);
                            }
                            guard::Judgement::Vetoed => {
                                return Err(ProtoError::BadSignature.into());
                            }
                            // Held until the server's log has it.
                            guard::Judgement::Unlogged => {
                                self.hold_request(&rid, env, now + 600, now)?;
                                return Ok(None);
                            }
                        }
                    }
                    let mut named = m;
                    named.version = version;
                    fetched = Some(named);
                }
                (Err(_), _) if candidate + 1 < candidates.len() => candidate += 1,
                (Err(e), _) => return Err(e.into()),
            }
        };
        let via = candidates[candidate].0;
        let bonded = matches!(via, Via::Bond);
        let mut resp = resp;
        let content = match envelope::open_request(&mut resp.session, env, &mut self.rng) {
            Ok(c) => c,
            // They wrote with our manifest from before our last change (we
            // linked a device in between): the transcript has that version.
            Err(e) => {
                let Some(prev) = self.previous_manifest()? else {
                    return Err(e.into());
                };
                self.prekeys = PrekeyStore::import(&prekeys_before)?;
                let psk = candidates[candidate].1.clone();
                let retry = {
                    let local = Local {
                        account: &self.account,
                        device: &self.device,
                        manifest: &prev,
                        locator: &self.profile.server,
                    };
                    let mut resolver = Resolver {
                        contacts: &self.contacts,
                        fetched: fetched.clone(),
                        wanted: None,
                    };
                    eqxdh::respond(
                        &local,
                        &mut self.prekeys,
                        &msg,
                        psk.as_deref(),
                        &mut resolver,
                        &mut self.rng,
                    )
                };
                let Ok(r) = retry else {
                    self.prekeys = PrekeyStore::import(&prekeys_before)?;
                    return Err(e.into());
                };
                resp = r;
                match envelope::open_request(&mut resp.session, env, &mut self.rng) {
                    Ok(c) => c,
                    Err(_) => {
                        self.prekeys = PrekeyStore::import(&prekeys_before)?;
                        return Err(e.into());
                    }
                }
            }
        };
        let session = resp.session;
        let content = Content::decode(&content)?;
        let root = resp.identity.root;
        if let Via::Invite(key) = via
            && root != self.account.root_public.0
            && !self.use_invite(&key, &root).await?
        {
            // The link already brought everyone it could.
            self.store
                .put(NS_REPLAY, &rid, &now.to_be_bytes(), &mut self.rng)?;
            return Ok(None);
        }
        // Through a group invite link: a join request.
        let join = match via {
            Via::Invite(key) if root != self.account.root_public.0 => self.invite_group(&key),
            _ => None,
        };
        if root == self.account.root_public.0 {
            // Another device of ours (it is in our root-signed manifest, or
            // `respond` would have failed): keep the session for self-copies.
            self.store
                .put(NS_REPLAY, &rid, &now.to_be_bytes(), &mut self.rng)?;
            self.save_prekeys()?;
            self.save_session(&root, &resp.identity.device, &session)?;
            self.sessions.insert((root, resp.identity.device), session);
            if resp.manifest.version > self.manifest.version {
                self.manifest = resp.manifest.clone();
                self.store.put(
                    NS_PROFILE,
                    b"manifest",
                    &self.manifest.encode()?,
                    &mut self.rng,
                )?;
            }
            return Ok(Some(Event::DevicesChanged));
        }
        let Content::Hello {
            server,
            inbox,
            tokens,
            name,
            text,
            card,
            group,
            id: hello_id,
        } = content
        else {
            return Err(ProtoError::Decode.into());
        };
        let root = resp.identity.root;
        if self.is_blocked(&root) {
            // Spend the prekey and remember the message, but keep nothing.
            self.store
                .put(NS_REPLAY, &rid, &now.to_be_bytes(), &mut self.rng)?;
            self.save_prekeys()?;
            return Ok(None);
        }
        let card = ContactCard::decode(&card).ok().filter(|c| c.root == root);
        // A group introduction is accepted automatically, but only from a
        // current member of a group we are in.
        let introduced_by = group.filter(|g| self.is_group_member(g, &root));
        // Commit: replay marker, consumed prekey, session. If both sides
        // started a session with each other at once, both keep the one the
        // lower root initiated, so they end up with the same pair.
        self.store
            .put(NS_REPLAY, &rid, &now.to_be_bytes(), &mut self.rng)?;
        self.save_prekeys()?;
        let sk = (root, resp.identity.device);
        let keep_ours = self.account.root_public.0 < root
            && self
                .sessions
                .get(&sk)
                .is_some_and(|s| s.role() == enclave_proto::ratchet::Role::Initiator);
        if !keep_ours {
            self.save_session(&root, &resp.identity.device, &session)?;
            self.sessions.insert(sk, session);
        }

        let name = sanitize_name(&name);
        // A known contact talking from a new device (linked or restored): it
        // may hold spent tokens, so send it fresh ones once it is set up.
        let grant_tokens = self
            .contacts
            .get(&root)
            .is_some_and(|c| c.state == ContactState::Accepted);
        let (event, contact) = match self.contacts.get(&root).cloned() {
            Some(mut c) => {
                // A known contact: a new device of theirs, or both sides added
                // each other at once.
                if resp.manifest.version > c.manifest.version {
                    c.manifest = resp.manifest.clone();
                }
                c.server = server;
                c.inbox = Some(inbox);
                if card.is_some() {
                    c.card = card.clone();
                }
                add_tokens(&mut c.tokens, self.my_share(tokens));
                let ev = if c.state == ContactState::Pending {
                    c.state = ContactState::Accepted;
                    Some(Event::Accepted { root })
                } else {
                    None
                };
                (ev, c)
            }
            None => {
                let c = Contact {
                    root,
                    name: name.clone(),
                    state: ContactState::Request,
                    verified: false,
                    server,
                    request_inbox: request_inbox_of(&resp.manifest),
                    inbox: Some(inbox),
                    tokens: tokens.into_iter().take(MAX_HELD_TOKENS).collect(),
                    manifest: resp.manifest.clone(),
                    next_seq: 0,
                    received_since_refill: 0,
                    unread: 0,
                    added_at: now,
                    card: card.clone(),
                    group_only: introduced_by.is_some(),
                    timer: 0,
                };
                let ev = if introduced_by.is_some() || bonded {
                    None
                } else if let Some((group, _)) = join {
                    Some(Event::JoinRequest { root, group, name })
                } else {
                    Some(Event::Request {
                        root,
                        name,
                        text: text.clone(),
                    })
                };
                (ev, c)
            }
        };
        let mut contact = contact;
        if !text.is_empty() {
            contact.unread = contact.unread.saturating_add(1);
        }
        if contact.card.is_none() {
            contact.card = card.clone();
        }
        if bonded {
            // We met in person and both confirmed the Seal words.
            contact.verified = true;
        }
        let auto_accept =
            contact.state == ContactState::Request && (introduced_by.is_some() || bonded);
        self.contacts.insert(root, contact.clone());
        self.save_contact(&contact)?;
        if auto_accept {
            self.accept_with(&root, introduced_by).await?;
            return Ok(None);
        }
        if let Some((gid, approve)) = join
            && contact.state == ContactState::Request
        {
            self.note_join_request(&root, &gid)?;
            if !approve {
                self.approve_join(&root).await?;
                return Ok(None);
            }
        }
        if grant_tokens {
            let tokens = self.issue_tokens(&root, HELLO_TOKENS, now).await?;
            self.send_content(&root, &Content::Tokens(tokens), now)
                .await?;
        }
        if !text.is_empty() {
            let m = self.new_message(&root, hello_id, false, &text, 0, now)?;
            if event.is_none() {
                return Ok(Some(Event::Message { root, message: m }));
            }
        }
        Ok(event)
    }

    /// An envelope from an inbox; `from` is who its session hint says
    /// wrote it, whose sessions are tried first.
    fn handle_direct_from(
        &mut self,
        env: &[u8],
        from: Option<[u8; 64]>,
        now: u64,
    ) -> Result<Vec<Event>> {
        let (key, content, skipped_at) = {
            let mut all: Vec<(SessionKey, &mut Session)> =
                self.sessions.iter_mut().map(|(k, s)| (*k, s)).collect();
            if let Some(r) = from {
                all.sort_by_key(|(k, _)| k.0 != r);
            }
            let (keys, mut refs): (Vec<SessionKey>, Vec<&mut Session>) = all.into_iter().unzip();
            let opened =
                envelope::open_direct(&mut refs, env, Some(&self.account.vault), &mut self.rng)?;
            (
                keys[opened.session_index],
                opened.content,
                opened.skipped_at,
            )
        };
        let (root, dev) = key;
        if let Some(s) = self.sessions.get(&key) {
            let s = s.clone();
            self.save_session(&root, &dev, &s)?;
        }
        // Its key was skipped over a minute ago: messages sent after it
        // came first ("Delivered late", RT-24).
        self.late_unit = skipped_at.is_some_and(|at| at > 0 && now.saturating_sub(at) > GAP_SECS);
        let r = self.handle_opened(root, dev, content, now);
        self.late_unit = false;
        r
    }

    fn handle_opened(
        &mut self,
        root: [u8; 64],
        dev: [u8; 16],
        content: Vec<u8>,
        now: u64,
    ) -> Result<Vec<Event>> {
        if self.is_blocked(&root) {
            return Ok(Vec::new()); // dropped without a trace
        }
        // Delivery receipts may ride along (`outbox.rs`).
        let (content, receipts) = outbox::unwrap_receipts(&content)?;
        let (content, gossip) = gossip::unwrap(&content)?;
        let mut acked = if root != self.account.root_public.0 && !receipts.is_empty() {
            self.on_message_content(&root, Content::Delivered(receipts), now)?
        } else {
            Vec::new()
        };
        let rest = (|| -> Result<Vec<Event>> {
            if root != self.account.root_public.0 {
                self.on_gossip(&root, &gossip)?;
            }
            // A continuation unit: kept until its content is whole
            // (`parts.rs`), which is then handled as if it came at once.
            let content = match Content::decode(&content) {
                Ok(Content::Part {
                    id,
                    index,
                    total,
                    data,
                }) => match self.take_part(&root, id, index, total, &data, now)? {
                    Some(whole) => whole,
                    None => return Ok(Vec::new()),
                },
                _ => content,
            };
            // On the record: signed content opens to what was signed, and
            // personal content without a good signature is marked
            // (`record.rs`).
            let content = if root == self.account.root_public.0 {
                content
            } else {
                match Content::decode(&content) {
                    Ok(Content::Signed {
                        counter,
                        sig,
                        content,
                        tokens,
                    }) => {
                        let (inner, evidence) =
                            self.open_signed(&root, &dev, counter, sig, content, tokens)?;
                        self.unit_signature = Some(evidence);
                        inner.encode()?
                    }
                    Ok(c) if c.is_personal() && self.on_the_record(&root) => {
                        self.unit_signature = Some(None);
                        content
                    }
                    _ => content,
                }
            };
            if root == self.account.root_public.0 {
                // From another device of ours: it's in use.
                self.seen_own(&dev, now)?;
                // Self-copies, device changes, keeping in step.
                return match Content::decode(&content)? {
                    Content::SelfCopy { to, content } => self.on_self_copy(&to, &content, now),
                    Content::OwnSync(b) => self.on_own_sync(&dev, &b),
                    Content::Devices(v) => {
                        self.stale_manifests.insert(root, v);
                        Ok(Vec::new())
                    }
                    Content::History(b) => {
                        if let Some(att) = history::history_ref(&b) {
                            self.pending_history.push(att);
                        }
                        Ok(Vec::new())
                    }
                    Content::Veto(b) => {
                        self.on_veto(&root, &b)?;
                        Ok(Vec::new())
                    }
                    Content::Migration(b) => {
                        self.queue_migration(&root, &dev, &b)?;
                        Ok(Vec::new())
                    }
                    Content::HomeMoved { .. } => {
                        self.queue_home_moved(&content)?;
                        Ok(Vec::new())
                    }
                    _ => Ok(Vec::new()),
                };
            }
            let mut c = self
                .contacts
                .get(&root)
                .cloned()
                .ok_or(CoreError::NotFound)?;
            let mut events = Vec::new();
            let mut rest = None;
            let mut got_card = false;
            match Content::decode(&content)? {
                Content::Hello {
                    server,
                    inbox,
                    tokens,
                    name,
                    text,
                    card,
                    group: _,
                    id,
                } => {
                    c.server = server;
                    c.inbox = Some(inbox);
                    c.name = sanitize_name(&name);
                    if let Ok(card) = ContactCard::decode(&card)
                        && card.root == root
                    {
                        c.card = Some(card);
                    }
                    add_tokens(&mut c.tokens, self.my_share(tokens));
                    if c.state == ContactState::Pending {
                        c.state = ContactState::Accepted;
                        events.push(Event::Accepted { root });
                    }
                    if !text.is_empty() {
                        rest = Some(Content::Text {
                            tokens: Vec::new(),
                            text,
                            id,
                            expires: 0,
                        });
                    }
                }
                Content::Tokens(tokens) => {
                    add_tokens(&mut c.tokens, self.my_share(tokens));
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                }
                Content::Devices(v) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    if v > c.manifest.version {
                        self.stale_manifests.insert(root, v);
                    }
                }
                Content::Veto(b) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.on_veto(&root, &b)?;
                }
                Content::KtHead(b) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.on_kt_head(&root, &b);
                }
                Content::Migration(b) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.queue_migration(&root, &dev, &b)?;
                }
                Content::ServerMoved {
                    server,
                    inbox,
                    request_inbox,
                    vault_locator,
                    tokens,
                } => {
                    self.on_server_moved(
                        &mut c,
                        (&server, &inbox, &request_inbox, &vault_locator),
                        tokens,
                    );
                }
                Content::RecoveryShare(share) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.keep_recovery_share(&root, &share)?;
                    if !share.is_empty() {
                        events.push(Event::RecoveryShareReceived { root });
                    }
                }
                Content::GroupWelcome(welcome) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    if let Some(ev) = self.on_group_welcome(&root, &welcome, now)? {
                        events.push(ev);
                    }
                }
                Content::GroupCards { group_id, cards } => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.on_group_cards(&root, &group_id, &cards)?;
                }
                Content::CardAsk => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    self.store.put(NS_CARD_OWED, &root, &[], &mut self.rng)?;
                }
                Content::Card(b) => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    if let Ok(card) = ContactCard::decode(&b)
                        && card.root == root
                        && c.card.is_none()
                    {
                        c.card = Some(card);
                        got_card = true;
                    }
                }
                Content::Text {
                    tokens,
                    text,
                    id,
                    expires,
                } => {
                    add_tokens(&mut c.tokens, self.my_share(tokens));
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    rest = Some(Content::Text {
                        tokens: Vec::new(),
                        text,
                        id,
                        expires,
                    });
                }
                Content::ModeChange { on_record, seq } => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    events.extend(self.on_mode_change(&root, on_record, seq, false)?);
                }
                Content::Closed => {
                    events.extend(self.on_closed(&root)?);
                }
                Content::NotifyKey { key, day, previews } => {
                    self.on_notify_key(&root, key, day, previews)?;
                }
                other => {
                    c.received_since_refill = c.received_since_refill.saturating_add(1);
                    rest = Some(other);
                }
            }
            self.contacts.insert(root, c.clone());
            self.save_contact(&c)?;
            // With a card at last, they can be handed to our other devices.
            if got_card {
                self.sync_contact_to_own(&root, true)?;
            }
            if let Some(content) = rest {
                events.extend(self.on_message_content(&root, content, now)?);
            }
            Ok(events)
        })();
        self.unit_signature = None;
        acked.extend(rest?);
        Ok(acked)
    }

    async fn send_content(&mut self, root: &[u8; 64], content: &Content, now: u64) -> Result<()> {
        if content.is_personal() {
            self.require_not_held()?;
        }
        // On the record, what a person writes is signed (`record.rs`).
        let content = &self.sign_for(root, content)?;
        // Too large for one envelope: continuation units (`parts.rs`).
        let bytes = content.encode()?;
        let id = self.rng.array("core/part-id")?;
        let units = match parts::split(&bytes, self.unit_room(root), id) {
            Some(p) => p,
            None => vec![content.clone()],
        };
        for c in &units {
            let (server, h, env) = self.seal_content(root, c, false)?;
            self.rpc.write(&server, h, &env, now, &mut self.rng).await?;
        }
        Ok(())
    }

    /// Encoded content that fits one envelope to `root`, with room for
    /// receipts and gossip.
    fn unit_room(&self, _root: &[u8; 64]) -> usize {
        enclave_wire::direct::BODY_LEN
            - enclave_crypto::seal::OVERHEAD
            - enclave_wire::CONTENT_FRAMING
            - 360
    }

    /// Seal `content` for `root`'s devices, spending a write token. A
    /// `droppable` envelope carries no PQ step: it may never be sent.
    pub(crate) fn seal_content(
        &mut self,
        root: &[u8; 64],
        content: &Content,
        droppable: bool,
    ) -> Result<(ServerId, RequestHeader, Vec<u8>)> {
        if self.is_blocked(root) || self.is_closed(root) {
            return Err(CoreError::NotAccepted);
        }
        let bytes = content.encode()?;
        // Key-transparency gossip rides in space the envelope pads anyway.
        let items = self.gossip_items();
        let capacity = enclave_wire::direct::BODY_LEN
            - enclave_crypto::seal::OVERHEAD
            - enclave_wire::CONTENT_FRAMING;
        let bytes = if bytes.len() + gossip::overhead(items.len()) <= capacity {
            gossip::wrap(&bytes, &items)?
        } else {
            bytes
        };
        // So do delivery receipts owed to this contact, except on a unit
        // that may be dropped.
        let bytes = if droppable {
            bytes
        } else {
            let room = capacity.saturating_sub(bytes.len());
            let ids = self.take_receipts(root, room);
            outbox::wrap_receipts(&bytes, &ids)
        };
        // Maximum privacy sends what a person wrote only over sessions all
        // three KEMs protect; until one does, it waits (and no token is
        // spent). Protocol messages go, so the session can get there.
        let maximum = self.maximum && content.waits_for_three_kems();
        if maximum
            && self.protection_finishing(root)
            && self
                .sessions
                .iter()
                .any(|((r, _), s)| r == root && s.can_send())
        {
            return Err(CoreError::Finishing);
        }
        // Their inbox's address this week (the week before's for a re-send
        // that falls back: they may not have been online to make this one).
        let week =
            api::week_of(self.inbox_now(self.now())).saturating_sub(u32::from(self.fallback_week));
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        let inbox = api::inbox_addr(&c.inbox.ok_or(CoreError::NotAccepted)?, week);
        let server = c.server;
        let token = c.tokens.pop().ok_or(CoreError::OutOfTokens)?;
        let c = c.clone();
        // The token is spent whatever happens next.
        self.save_contact(&c)?;
        let capsule = self.capsule_for(root, content, self.now())?;

        let env = {
            let (keys, mut refs): (Vec<SessionKey>, Vec<&mut Session>) = self
                .sessions
                .iter_mut()
                .filter(|((r, _), s)| r == root && s.can_send() && (!maximum || s.three_kem()))
                .take(MAX_DEVICES)
                .map(|(k, s)| (*k, s))
                .unzip();
            if refs.is_empty() {
                return Err(CoreError::NotAccepted);
            }
            // A dropped unit must not take a PQ step with it.
            let carrier = if droppable {
                None
            } else {
                pq_carrier(&mut self.pq_carried, &keys, &refs)
            };
            let env = envelope::seal_direct_with(
                &mut refs,
                &bytes,
                carrier,
                capsule.as_ref(),
                &mut self.rng,
            )?;
            drop(refs);
            for k in keys {
                if let Some(s) = self.sessions.get(&k) {
                    let s = s.clone();
                    self.save_session(&k.0, &k.1, &s)?;
                }
            }
            env
        };
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: inbox,
            token,
        };
        Ok((server, h, env))
    }

    async fn maintain_prekeys(&mut self, now: u64) -> Result<()> {
        self.prekeys.expire(now, PREKEY_GRACE);
        let latest = self
            .prekeys
            .signed
            .values()
            .map(|(_, exp)| *exp)
            .max()
            .unwrap_or(0);
        // The last-resort key lives 7 days, the signed prekey 14: republish
        // before either lapses, or nobody new can reach us.
        let last_resort = self
            .prekeys
            .last_resort
            .values()
            .map(|(_, exp)| *exp)
            .max()
            .unwrap_or(0);
        if self.prekeys.one_time.len() >= OPK_LOW_WATER
            && latest > now + 2 * 86_400
            && last_resort > now + 2 * 86_400
        {
            return Ok(());
        }
        let publication = self.prekeys.publish(&self.device, now, &mut self.rng)?;
        self.save_prekeys()?;
        let server = self.profile.server;
        self.rpc
            .dir_put(
                &server,
                DirKind::Bundle,
                device_key(&self.device.id),
                [0; 32],
                &publication.encode(),
                now,
                &mut self.rng,
            )
            .await
    }

    /// Tokens arriving in the shared account inbox reach every device of
    /// ours, but each can be spent once: every device keeps a disjoint share,
    /// chosen from the token itself and our position in the manifest.
    fn my_share(&self, tokens: Vec<Token>) -> Vec<Token> {
        let n = self.manifest.devices.len();
        let Some(i) = self
            .manifest
            .devices
            .iter()
            .position(|d| d.id == self.device.id)
        else {
            return tokens;
        };
        if n <= 1 {
            return tokens;
        }
        tokens
            .into_iter()
            .filter(|t| usize::from(t[0]) % n == i)
            .collect()
    }

    fn save_contact(&mut self, c: &Contact) -> Result<()> {
        Ok(self.store.put(
            NS_CONTACTS,
            &c.root,
            &persist::encode_contact(c)?,
            &mut self.rng,
        )?)
    }

    fn save_session(&mut self, root: &[u8; 64], dev: &[u8; 16], s: &Session) -> Result<()> {
        Ok(self.store.put(
            NS_SESSIONS,
            &session_key(root, dev),
            &s.export(),
            &mut self.rng,
        )?)
    }

    fn save_prekeys(&mut self) -> Result<()> {
        Ok(self.store.put(
            NS_SECRETS,
            b"prekeys",
            &self.prekeys.export(),
            &mut self.rng,
        )?)
    }

    fn save_profile(&mut self) -> Result<()> {
        Ok(self.store.put(
            NS_PROFILE,
            b"profile",
            &self.profile.encode(),
            &mut self.rng,
        )?)
    }
}

pub(crate) fn add_tokens(held: &mut Vec<Token>, new: Vec<Token>) {
    held.extend(new);
    if held.len() > MAX_HELD_TOKENS {
        let excess = held.len() - MAX_HELD_TOKENS;
        held.drain(..excess);
    }
}

/// A refill replaces every token the contact used since the last one.
fn refill_size(used: u32) -> usize {
    (used as usize).clamp(1, crate::content::MAX_TOKENS)
}

fn request_inbox_of(m: &Manifest) -> [u8; 32] {
    let mut out = [0u8; 32];
    if m.request_inbox.len() == 32 {
        out.copy_from_slice(&m.request_inbox);
    }
    out
}

/// Names from other people: strip control and bidi-override characters and
/// cap combining marks, so a name cannot spoof layout (`docs/15-client.md`).
pub(crate) fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    let mut combining = 0;
    for ch in name.chars() {
        let c = ch as u32;
        let bidi = matches!(c, 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x061C);
        if ch.is_control() || bidi {
            continue;
        }
        let is_combining = matches!(c, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F);
        if is_combining {
            combining += 1;
            if combining > 8 {
                continue;
            }
        } else {
            combining = 0;
        }
        out.push(ch);
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "Unnamed".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("Sam\u{202E}evil"), "Samevil");
        assert_eq!(sanitize_name("  \u{0007} "), "Unnamed");
        let zalgo: String = std::iter::once('a')
            .chain(std::iter::repeat_n('\u{0301}', 30))
            .collect();
        assert_eq!(sanitize_name(&zalgo).chars().count(), 9);
    }

    #[test]
    fn held_tokens_are_capped() {
        let mut held = vec![[1u8; 32]; MAX_HELD_TOKENS];
        add_tokens(&mut held, vec![[2u8; 32]; 3]);
        assert_eq!(held.len(), MAX_HELD_TOKENS);
        assert_eq!(held.pop().map(|t| t[0]), Some(2));
    }
}
