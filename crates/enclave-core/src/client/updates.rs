//! Release updates (`docs/19-ops.md` §1, §4).
//!
//! Once a day the vault asks the home server for the update bundle it
//! relays (`DirKind::Update`, over the mixnet like everything else) and
//! checks it here against the release root built into the app: TUF's
//! chain, 2 of 3 maintainers on the targets, versions that never go back.
//! What is learned is kept in the profile: the newest root (roots rotate
//! one version at a time), the versions seen, and the bundle itself, so
//! "Verify this build" and the desktop updater can check files against its
//! Sigsum proofs later without asking again.
//!
//! A release can name a minimum version (a critical fix). An app older
//! than it stops sending at once ("Update Enclave to keep sending
//! messages.") and stops receiving 30 days later; updating lifts both.

use super::Client;
use crate::{CoreError, Result};
use enclave_rpc::api::{DirAction, DirKind};
use enclave_update::{Bundle, UpdateError};

const ROOT: &str = "update-root";
const SEEN: &str = "update-seen";
const BUNDLE: &str = "update-bundle";
const BLOCKED: &str = "update-blocked-since";
/// How long an app below the minimum version keeps receiving.
pub const RECEIVE_GRACE: u64 = 30 * 86_400;

/// What a checked release says about this app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    /// The newest release (`v1.2.3`).
    pub release: String,
    /// It is newer than this app.
    pub newer: bool,
    /// This app is older than the release's minimum: it may not send.
    pub required: bool,
    /// Every file of the release, by name, with its hashes.
    pub targets: Vec<enclave_update::Target>,
}

impl Client {
    /// Fetch the update bundle from the home server and check it with the
    /// root built into the app (`builtin_root`), for an app at version
    /// `running`. `Ok(None)` when the server has none to relay.
    pub async fn check_updates(
        &mut self,
        builtin_root: &[u8],
        running: &str,
    ) -> Result<Option<UpdateStatus>> {
        let now = self.now();
        let server = self.profile.server;
        let bytes = match self
            .rpc
            .dir_get(
                &server,
                DirKind::Update,
                DirAction::Get,
                [0; 32],
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(b) => b,
            Err(CoreError::Server(enclave_rpc::api::Status::NotFound)) => return Ok(None),
            Err(e) => return Err(e),
        };
        self.accept_update_bundle(&bytes, builtin_root, running, now)
            .map(Some)
    }

    /// Check a bundle (however it came) and keep what it says.
    pub fn accept_update_bundle(
        &mut self,
        bytes: &[u8],
        builtin_root: &[u8],
        running: &str,
        now: u64,
    ) -> Result<UpdateStatus> {
        let bundle = Bundle::decode(bytes).map_err(update_error)?;
        let mut client = self.update_client(builtin_root)?;
        let release = bundle.apply(&mut client, now).map_err(update_error)?;
        // The newest root the bundle carried, to start from next time.
        if let Some(root) = bundle
            .roots
            .iter()
            .rev()
            .find(|r| root_version(r) == Some(client.root().version))
        {
            self.set_setting(ROOT, root)?;
        }
        let seen = client.seen();
        let mut s = Vec::with_capacity(12);
        for v in seen {
            s.extend_from_slice(&v.to_be_bytes());
        }
        self.set_setting(SEEN, &s)?;
        self.set_setting(BUNDLE, bytes)?;
        let required =
            !release.minimum.is_empty() && enclave_update::older(running, &release.minimum);
        match (required, self.setting(BLOCKED)?) {
            (true, None) => self.set_setting(BLOCKED, &now.to_be_bytes())?,
            (false, Some(_)) => self.store.delete(super::NS_SETTINGS, BLOCKED.as_bytes())?,
            _ => {}
        }
        Ok(UpdateStatus {
            newer: enclave_update::older(running, &release.release),
            release: release.release,
            required,
            targets: release.targets,
        })
    }

    /// The update client: the newest root kept, else the built-in one,
    /// with the versions seen.
    fn update_client(&self, builtin_root: &[u8]) -> Result<enclave_update::Client> {
        let seen = self.setting(SEEN)?.unwrap_or_default();
        let seen = if seen.len() == 12 {
            let v = |i: usize| u32::from_be_bytes([seen[i], seen[i + 1], seen[i + 2], seen[i + 3]]);
            [v(0), v(4), v(8)]
        } else {
            [0; 3]
        };
        let builtin = enclave_update::Client::new(builtin_root, seen).map_err(update_error)?;
        // A kept root counts only if it is newer than the built-in one
        // (an app update may carry a newer root itself).
        if let Some(kept) = self.setting(ROOT)?
            && root_version(&kept).is_some_and(|v| v > builtin.root().version)
            && let Ok(c) = enclave_update::Client::new(&kept, seen)
        {
            return Ok(c);
        }
        Ok(builtin)
    }

    /// The last bundle checked, to check a file against (the desktop
    /// updater, "Verify this build"): the release and the client that
    /// checked it.
    pub fn update_bundle(
        &self,
        builtin_root: &[u8],
    ) -> Result<Option<(Bundle, enclave_update::Client)>> {
        let Some(b) = self.setting(BUNDLE)? else {
            return Ok(None);
        };
        let bundle = Bundle::decode(&b).map_err(update_error)?;
        Ok(Some((bundle, self.update_client(builtin_root)?)))
    }

    /// Since when this app has been below a release's minimum version, if
    /// it is.
    pub fn update_required_since(&self) -> Result<Option<u64>> {
        Ok(self
            .setting(BLOCKED)?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes))
    }

    /// Refuse to send while below the minimum version.
    pub(crate) fn require_current(&self) -> Result<()> {
        match self.update_required_since()? {
            Some(_) => Err(CoreError::UpdateRequired),
            None => Ok(()),
        }
    }

    /// Whether receiving has stopped too (30 days below the minimum).
    pub fn receiving_stopped(&self) -> Result<bool> {
        Ok(self
            .update_required_since()?
            .is_some_and(|t| self.now() >= t + RECEIVE_GRACE))
    }
}

fn root_version(signed: &[u8]) -> Option<u32> {
    let s = enclave_update::Signed::decode(signed).ok()?;
    enclave_update::Root::decode(&s.body)
        .ok()
        .map(|r| r.version)
}

fn update_error(e: UpdateError) -> CoreError {
    CoreError::Update(e.to_string())
}
