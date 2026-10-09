//! Backups kept on the home server (`docs/14-storage.md` §4).
//!
//! With them on, the device that holds the recovery words uploads an
//! archive (`export_backup`, without photos and files) as an ordinary
//! blob every [`SERVER_BACKUP_EVERY`] seconds, so it never reaches the
//! blobs' 30-day expiry, and points to it from a slot only the words can
//! find:
//!
//! ```text
//! s       = KMAC256(recovery, "", 256, "enclave/v1/store/backup-blob-id")
//! locator = KMAC256(s, "locator", 256, "enclave/v1/store/backup-blob-id")
//! owner   = KMAC256(s, "owner",   256, "enclave/v1/store/backup-blob-id")
//! pointer = Seal(KMAC256(s, "pointer", …), "enclave-backup-pointer", blob reference)
//! ```
//!
//! kept as a `DirKind::Vault` object (which doesn't expire) at `locator`,
//! replaceable and deletable with `owner`. The server sees an opaque blob
//! and an opaque small object, re-written weekly; a new device that has
//! only the words and the server's name finds the archive and restores
//! ([`Client::restore_from_server`]). The keys are kept by the device
//! (`backup-keys`), so uploads need neither the words nor the PIN.

use super::backup::L_BACKUP_BLOB;
use super::{Client, Options};
use crate::files::{self, Attachment};
use crate::rpc::Rpc;
use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_net::transport::{ServerId, Transport};
use enclave_proto::recovery::RecoverySecret;
use enclave_rpc::api::{self, DirAction, DirKind};
use std::sync::Arc;
use zeroize::Zeroizing;

/// `NS_SETTINGS` key: server backups are on (`[1]`).
const KEY_ON: &str = "server-backup";
/// `NS_SETTINGS` key: when the last one was uploaded (`u64`).
const KEY_AT: &str = "server-backup-at";
/// How often a new archive is uploaded (well inside the blobs' expiry).
pub const SERVER_BACKUP_EVERY: u64 = 7 * 86_400;
const POINTER_AD: &[u8] = b"enclave-backup-pointer";

struct Slot {
    locator: [u8; 32],
    owner: [u8; 32],
    key: SealKey,
}

fn slot(secret: &[u8; 32]) -> Slot {
    let k =
        |what: &[u8]| -> [u8; 32] { enclave_crypto::kmac::kmac256(secret, what, L_BACKUP_BLOB) };
    Slot {
        locator: k(b"locator"),
        owner: k(b"owner"),
        key: SealKey::from_bytes(k(b"pointer")),
    }
}

fn slot_from_words(words: &str) -> Result<Slot> {
    let rs = RecoverySecret::from_words(words)?;
    let keys = super::backup::backup_keys_from(&rs);
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(&keys[32..]);
    Ok(slot(&s))
}

impl Client {
    fn backup_slot(&mut self) -> Result<Slot> {
        let keys = self.backup_keys()?;
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&keys[32..]);
        Ok(slot(&s))
    }

    /// Server backups are on, and when the last one went up (0: never).
    pub fn server_backup(&self) -> (bool, u64) {
        let on = matches!(self.setting(KEY_ON), Ok(Some(v)) if v == [1]);
        let at = self
            .setting(KEY_AT)
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_be_bytes);
        (on, at)
    }

    /// Turn server backups on (an archive goes up now) or off (the one
    /// there is deleted). On the device that holds the words.
    pub async fn set_server_backup(&mut self, on: bool) -> Result<()> {
        if !self.holds_recovery_words() {
            return Err(CoreError::NotAccepted);
        }
        if on {
            self.backup_slot()?;
            self.set_setting(KEY_ON, &[1])?;
            return self.upload_backup().await;
        }
        let s = self.backup_slot()?;
        let now = self.now();
        let server = self.profile.server;
        let r = self
            .rpc
            .dir_put(
                &server,
                DirKind::Vault,
                s.locator,
                s.owner,
                api::VAULT_DELETE,
                now,
                &mut self.rng,
            )
            .await;
        if let Err(e @ CoreError::Net(_)) = r {
            return Err(e);
        }
        self.set_setting(KEY_ON, &[])?;
        self.set_setting(KEY_AT, &[])?;
        Ok(())
    }

    /// Upload a fresh archive to the home server and point the slot at it.
    pub async fn upload_backup(&mut self) -> Result<()> {
        let s = self.backup_slot()?;
        let archive = Zeroizing::new(self.export_backup_with(false)?);
        let now = self.now();
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(
            &archive,
            "backup",
            "application/octet-stream",
            host,
            &mut self.rng,
        )?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        let pointer = seal::seal(&s.key, POINTER_AD, &att.encode(), &mut self.rng)?;
        self.rpc
            .dir_put(
                &host,
                DirKind::Vault,
                s.locator,
                s.owner,
                &pointer,
                now,
                &mut self.rng,
            )
            .await?;
        self.set_setting(KEY_AT, &now.to_be_bytes())?;
        Ok(())
    }

    /// Upload again when the last one is a week old (sync calls this).
    pub(crate) async fn server_backup_upkeep(&mut self, now: u64) -> Result<()> {
        let (on, at) = self.server_backup();
        if !on || now < at + SERVER_BACKUP_EVERY || !self.holds_recovery_words() {
            return Ok(());
        }
        match self.upload_backup().await {
            Err(e @ CoreError::Net(_)) => Err(e),
            // Not now (say, keys behind a PIN not yet kept): next time.
            _ => Ok(()),
        }
    }

    /// The archive kept on `server` for the account these `words` are
    /// for: found and opened with the words alone.
    pub async fn fetch_server_backup(
        words: &str,
        server: ServerId,
        transport: Arc<dyn Transport>,
    ) -> Result<Vec<u8>> {
        let s = slot_from_words(words)?;
        let mut rpc = Rpc::new(Arc::clone(&transport));
        let mut rng = HedgedRng::new()?;
        let now = transport.now();
        let pointer = rpc
            .dir_get(
                &server,
                DirKind::Vault,
                DirAction::Get,
                s.locator,
                [0; 32],
                now,
                &mut rng,
            )
            .await?;
        let att = Attachment::decode(&seal::open(&s.key, POINTER_AD, &pointer)?)?;
        let mut parts = Vec::with_capacity(att.chunks as usize);
        for i in 0..att.chunks {
            let chunk = rpc
                .blob_get(&att.host, att.chunk_id(i), now, &mut rng)
                .await?;
            parts.push(files::open_chunk(&att, i, &chunk)?);
        }
        Ok(files::finish(&att, &parts)?)
    }

    /// Restore from the archive kept on `server` (`fetch_server_backup`),
    /// with the words alone.
    pub async fn restore_from_server(
        words: &str,
        server: ServerId,
        opts: Options,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        let archive =
            Zeroizing::new(Self::fetch_server_backup(words, server, Arc::clone(&transport)).await?);
        Self::restore(words, &archive, opts, transport).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn slots_follow_the_words() {
        let a = super::slot(&[1; 32]);
        let b = super::slot(&[2; 32]);
        assert_ne!(a.locator, b.locator);
        assert_ne!(a.locator, a.owner);
    }
}
