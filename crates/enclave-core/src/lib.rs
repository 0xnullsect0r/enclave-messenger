//! The Enclave client engine (`docs/15-client.md`).
//!
//! `enclave-core` runs in the vault process. It owns every long-term secret,
//! drives the protocol crates against servers through a [`Transport`], and
//! keeps all state in the sealed [`enclave_store::Store`]. The UI talks to it
//! through the command methods on [`Client`] and the [`Event`]s that
//! [`Client::sync`] returns; it never sees key material.
//!
//! Invariants:
//! * Ratchet state is persisted **before** the envelope it produced leaves the
//!   device, and after every envelope that changed it, so a crash can lose a
//!   message but never reuse a key.
//! * Prekeys consumed by a handshake are persisted before the session is used.
//! * Nothing from a stranger is shown until it has authenticated, and it lands
//!   in message requests until the user accepts it.
//!
//! [`Transport`]: enclave_net::transport::Transport
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod art;
pub mod card;
pub mod client;
pub mod content;
mod content_pb;
pub mod files;
mod persist;
mod rpc;

pub use card::{ContactCard, DeepLink, Invite, LinkError, open_deep_link};
pub use client::{BackupCheck, SERVER_BACKUP_EVERY, check_archive};
pub use client::{
    Client, Contact, ContactState, DeviceInfo, Event, GroupInfo, GroupMessage, GroupReaction,
    LinkCode, LinkOffer, LinkProgress, LinkingDevice, Message, Options, Reaction,
};
pub use client::{
    ConvPrefs, Folder, GalleryItem, Hit, Location, MAX_FOLDER_NAME, MAX_FOLDERS,
    MAX_PINNED_CONVERSATIONS, MAX_PINS, MeetMatch, Photo, Place, ProfileInfo, RecoveryAlert,
    RecoveryHold, ShareRelease, ShareRequest, words_from_shares,
};
pub use client::{
    HistoryServe, HostVotes, LanHistory, ListUpdate, Sending, TYPING_RESERVE, TYPING_SHOW_SECS,
    TicketWallet, fetch_due,
};
pub use client::{RECEIVE_GRACE, TextOptions, UpdateStatus};
pub use enclave_kt::KtPolicy;
pub use enclave_push_relay::Platform as PushPlatform;

use enclave_rpc::api::Status;

/// Errors from the client engine.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Local storage failed.
    #[error("storage: {0}")]
    Store(#[from] enclave_store::StoreError),
    /// Protocol failure (bad signature, decryption failure, ...).
    #[error("protocol: {0}")]
    Proto(#[from] enclave_proto::ProtoError),
    /// Network failure.
    #[error("network: {0}")]
    Net(#[from] enclave_net::NetError),
    /// A server refused a request.
    #[error("server replied {0:?}")]
    Server(Status),
    /// A cryptographic operation failed.
    #[error("cryptographic failure")]
    Crypto,
    /// Unknown contact or object.
    #[error("not found")]
    NotFound,
    /// A federation object (server list, descriptor) was refused.
    #[error("federation: {0}")]
    Federation(enclave_federation::FedError),
    /// The contact has not accepted yet, or we have not accepted them.
    #[error("contact has not accepted the conversation yet")]
    NotAccepted,
    /// No write tokens left for the contact's inbox.
    #[error("no write tokens left for this contact")]
    OutOfTokens,
    /// Input too long.
    #[error("too long")]
    TooLong,
    /// A link or QR code could not be used.
    #[error("link: {0}")]
    Link(#[from] LinkError),
    /// The backup was taken before the account moved to another server:
    /// it holds the old inboxes only. Restore a newer one.
    #[error("this backup is from before the account moved to another server")]
    BackupBeforeMove,
    /// A username could not be claimed or found.
    #[error("username: {0}")]
    Username(#[from] UsernameError),
    /// Maximum privacy waits for all three KEMs before sending to this
    /// contact ("Extra protection: finishing…", `docs/04-eqxdh.md` §7).
    #[error("extra protection is still finishing for this contact")]
    Finishing,
    /// This device restored the account, and contacts hold the change for
    /// up to 72 hours (`03-identity.md` §8.1): what it sent would be lost.
    #[error("your account is still being set up on this device")]
    RecoveryHeld,
    /// A root action needs the PIN first (`Client::unlock_root`).
    #[error("enter your PIN first")]
    PinRequired,
    /// The PIN was wrong.
    #[error("that PIN isn't right")]
    PinWrong,
    /// Too many wrong PINs: the next try is allowed at this time.
    #[error("too many wrong PINs; try again later")]
    PinWait(u64),
    /// Not allowed in Maximum privacy (push, `docs/10-push.md`).
    #[error("not available in Maximum privacy")]
    MaximumPrivacy,
    /// zk-nym tickets for the mixnet couldn't be bought
    /// (`docs/09-transport.md` §7).
    #[error("mixnet tickets: {0}")]
    Tickets(String),
    /// Release metadata was refused (`docs/19-ops.md` §1.5).
    #[error("update: {0}")]
    Update(String),
    /// A release made this version's minimum newer than it
    /// (`docs/19-ops.md` §4): update to keep sending.
    #[error("Update Enclave to keep sending messages.")]
    UpdateRequired,
}

/// Why a username operation failed, in terms the UI can explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    /// Usernames aren't set up for this server (no pinned log).
    #[error("usernames aren't available on this server")]
    Unavailable,
    /// The name breaks the rules (length, characters, reserved words).
    #[error("that name isn't allowed")]
    NotAllowed,
    /// Someone else has the name, or one that looks like it.
    #[error("that name is taken")]
    Taken,
    /// Nobody has that name.
    #[error("nobody has that name")]
    NotFound,
    /// The name was withdrawn: its account was deleted, or the operator
    /// withdrew it. Nobody can have it again.
    #[error("that name was withdrawn")]
    Withdrawn,
    /// The server's answer didn't check out against the pinned log and
    /// witnesses. Never shown as "not found": it may be an attack.
    #[error("the server's answer could not be checked")]
    Unverified,
}

impl From<enclave_crypto::Error> for CoreError {
    fn from(_: enclave_crypto::Error) -> Self {
        CoreError::Crypto
    }
}

impl From<enclave_rpc::RpcError> for CoreError {
    fn from(_: enclave_rpc::RpcError) -> Self {
        CoreError::Crypto
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, CoreError>;

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
