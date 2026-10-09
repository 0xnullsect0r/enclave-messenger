//! An operator's own zk-nym tickets (`docs/09-transport.md` §7): a stack's
//! ingress (and push egress) on Nym's networks buys ticketbooks from its
//! operator's Nyx account, whose mnemonic is a Docker secret, at start and
//! whenever fewer than [`Funding::keep`] tickets are left. Devices don't do
//! this: they buy through the credential gate ([`crate::credentials`]).

use crate::client_error;
use enclave_nym::Result;
use nym_credential_storage::storage::Storage;
use nym_credentials_interface::TicketType;
use zeroize::Zeroizing;

/// Where an operator's tickets come from.
#[derive(Clone)]
pub struct Funding {
    /// The Nyx account's mnemonic.
    pub mnemonic: Zeroizing<String>,
    /// Buy another ticketbook when fewer tickets than this are left.
    pub keep: u64,
}

impl std::fmt::Debug for Funding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Funding")
            .field("mnemonic", &"…")
            .field("keep", &self.keep)
            .finish()
    }
}

/// Tickets left in the unexpired mixnet-entry books of `store`.
pub async fn tickets_left<St: Storage>(store: &St) -> Result<u64> {
    let today = nym_ecash_time::ecash_today_date();
    let kind = TicketType::V1MixnetEntry.to_string();
    Ok(store
        .get_ticketbooks_info()
        .await
        .map_err(client_error)?
        .into_iter()
        .filter(|b| b.expiration_date >= today && b.ticketbook_type == kind)
        .map(|b| u64::from(b.total_tickets.saturating_sub(b.used_tickets)))
        .sum())
}

/// Keeps a running client's ticket store topped up.
#[async_trait::async_trait]
pub trait TopUp: Send + Sync {
    /// Buy a ticketbook if fewer than [`Funding::keep`] tickets are left;
    /// the tickets left after.
    async fn top_up(&self) -> Result<u64>;
}

pub(crate) struct Funded<St: Storage> {
    pub(crate) store: St,
    pub(crate) buyer: nym_sdk::bandwidth::BandwidthAcquireClient<St>,
    pub(crate) keep: u64,
}

#[async_trait::async_trait]
impl<St> TopUp for Funded<St>
where
    St: Storage + Clone + Send + Sync + 'static,
    nym_sdk::bandwidth::BandwidthAcquireClient<St>: Send + Sync,
{
    async fn top_up(&self) -> Result<u64> {
        let left = tickets_left(&self.store).await?;
        if left >= self.keep {
            return Ok(left);
        }
        self.buyer.acquire().await.map_err(client_error)?;
        tickets_left(&self.store).await
    }
}
