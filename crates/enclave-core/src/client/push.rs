//! Push registration (`docs/10-push.md` §2).
//!
//! The device seals its platform token (a UnifiedPush endpoint, or an APNs
//! or FCM token) to the push relay's key and hands the sealed token to its
//! own server for the account inbox. The server can't open it; the relay
//! can't tell which inbox or server it belongs to. A fresh sealing on every
//! registration keeps two registrations unlinkable.

use super::Client;
use crate::{CoreError, Result};
use enclave_push_relay::{Platform, RelayPublic, seal_token};
use enclave_rpc::api;
use enclave_wire::{Op, RequestHeader};

impl Client {
    /// Ask for wakes when messages reach our inbox.
    pub async fn register_push(
        &mut self,
        relay: &RelayPublic,
        platform: Platform,
        token: &[u8],
    ) -> Result<()> {
        // Maximum privacy has no push at all (`docs/10-push.md`).
        if self.maximum() {
            return Err(CoreError::MaximumPrivacy);
        }
        let sealed =
            seal_token(relay, platform, token, 0, &mut self.rng).map_err(|_| CoreError::TooLong)?;
        self.send_push_registration(&sealed).await
    }

    /// Stop wakes: the server forgets the sealed token.
    pub async fn unregister_push(&mut self) -> Result<()> {
        self.send_push_registration(&[]).await
    }

    async fn send_push_registration(&mut self, sealed: &[u8]) -> Result<()> {
        let now = self.now();
        let payload = api::frame(sealed, &mut self.rng)?;
        let h = RequestHeader {
            op: Op::PushRegister,
            flags: 0,
            mailbox: self.profile.inbox,
            token: self.profile.inbox_owner,
        };
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &payload, now, &mut self.rng)
            .await?;
        Ok(())
    }
}
