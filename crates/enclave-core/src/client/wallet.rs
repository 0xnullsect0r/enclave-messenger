//! zk-nym tickets for the mixnet (`docs/09-transport.md` §7).
//!
//! Nym's gateways take a device's traffic only against zk-nym tickets. A
//! device buys them from a credential gate listed in the server list: it
//! does some work (proof of work) for a few Privacy Pass tokens blinded to the
//! gate's listed issuer key, then spends one token per ticketbook. The
//! ticketbook comes back through netd's mixnet process, which made the
//! ecash keys and withdrawal request and aggregated the signers' shares
//! itself; this wallet keeps the result, sealed in the profile, with how
//! many of its tickets are spent:
//!
//! - [`Client::start_mixnet`] buys a book when there is none worth using,
//!   then connects the mixnet client with every book that has tickets left
//!   (netd waits for this when started with `--await-tickets`);
//! - [`Client::upkeep_tickets`] (now and then) reads how many tickets the
//!   mixnet client has spent since it connected, marks them spent here, and
//!   buys the next book before the last one runs out, so the running client
//!   always has one to go on to.
//!
//! The wallet is never in a backup: a restored device buys its own. Tokens
//! left over from a proof of work are kept for the next book while their
//! issuer key is still accepted (this epoch and the one before).
//!
//! ```text
//! wallet = u8(1) ‖ u64 seen ‖ u32(n) ‖ n × (u64 bought ‖ u32 len ‖ Held)
//!        ‖ u32(n) ‖ n × (u32 epoch ‖ bytes(gate) ‖ Token (146))
//! ```

use super::Client;
use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_federation::CredGateEntry;
use enclave_net::transport::Transport;
use enclave_nym::Held;
use enclave_tokens::gate;
use enclave_tokens::privpass::{IssuerPublic, TOKEN_LEN, Token};
use std::sync::Arc;

const NS_WALLET: &str = "wallet";
const WALLET_KEY: &[u8] = b"wallet";
const VERSION: u8 = 1;

/// A ticketbook is good for 7 days from the day it was issued (Nym's
/// `TICKETBOOK_VALIDITY_DAYS`); it is let go a day early.
pub const BOOK_LIFETIME: u64 = 6 * 86_400;
/// Buy the next book when fewer tickets than this are left (a ticket is
/// 200 MB of mixnet traffic, about 2.5 h in the Foreground profile).
pub const REFILL_BELOW: u64 = 10;
/// Tokens asked for per proof of work: one for now, the rest for later.
pub const TOKENS_PER_PROOF: usize = 4;
/// Most books kept.
const MAX_BOOKS: usize = 16;
/// Most tokens kept.
const MAX_TOKENS: usize = 32;

/// Ticketbooks and spare tokens. A [`Client`] keeps its own in the
/// profile; before there is a profile (a new device), the caller holds one
/// and hands it over with [`Client::adopt_tickets`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TicketWallet {
    /// The mixnet client's spent counter when last read.
    seen: u64,
    /// `(bought, book)`, in the order the mixnet client spends them.
    books: Vec<(u64, Held)>,
    /// `(epoch, gate, token)`.
    tokens: Vec<(u32, String, Token)>,
}

impl TicketWallet {
    /// Encode (sealed by the caller: it holds ticket secrets).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.seen.to_be_bytes());
        out.extend_from_slice(&(self.books.len() as u32).to_be_bytes());
        for (bought, h) in &self.books {
            let b = h.encode();
            out.extend_from_slice(&bought.to_be_bytes());
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(&b);
        }
        out.extend_from_slice(&(self.tokens.len() as u32).to_be_bytes());
        for (epoch, gate, t) in &self.tokens {
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(&(gate.len() as u32).to_be_bytes());
            out.extend_from_slice(gate.as_bytes());
            out.extend_from_slice(&t.encode());
        }
        out
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = b;
        let mut take = |n: usize| -> Option<&[u8]> {
            if r.len() < n {
                return None;
            }
            let (a, rest) = r.split_at(n);
            r = rest;
            Some(a)
        };
        if take(1)? != [VERSION] {
            return None;
        }
        let u32_of = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap_or([0; 4]));
        let u64_of = |b: &[u8]| u64::from_be_bytes(b.try_into().unwrap_or([0; 8]));
        let seen = u64_of(take(8)?);
        let n = u32_of(take(4)?) as usize;
        if n > MAX_BOOKS {
            return None;
        }
        let mut books = Vec::with_capacity(n);
        for _ in 0..n {
            let bought = u64_of(take(8)?);
            let len = u32_of(take(4)?) as usize;
            books.push((bought, Held::decode(take(len)?).ok()?));
        }
        let n = u32_of(take(4)?) as usize;
        if n > MAX_TOKENS {
            return None;
        }
        let mut tokens = Vec::with_capacity(n);
        for _ in 0..n {
            let epoch = u32_of(take(4)?);
            let len = u32_of(take(4)?) as usize;
            let gate = String::from_utf8(take(len)?.to_vec()).ok()?;
            tokens.push((epoch, gate, Token::decode(take(TOKEN_LEN)?).ok()?));
        }
        r.is_empty().then_some(Self {
            seen,
            books,
            tokens,
        })
    }

    /// Drop books that are used up or about to expire, and tokens whose
    /// issuer key the gate no longer takes.
    fn prune(&mut self, now: u64) {
        self.books
            .retain(|(bought, h)| h.left() > 0 && now < bought.saturating_add(BOOK_LIFETIME));
        let epoch = gate::epoch_of(now);
        self.tokens.retain(|(e, _, _)| e + 1 >= epoch);
    }

    fn left(&self) -> u64 {
        self.books.iter().map(|(_, h)| u64::from(h.left())).sum()
    }

    /// The mixnet client's counter reads `spent`: mark what is new as
    /// spent, in the order it spends. A lower reading is a new mixnet
    /// client, counting from zero.
    fn note_spent(&mut self, spent: u64) {
        let new = if spent < self.seen {
            spent
        } else {
            spent - self.seen
        };
        self.seen = spent;
        if new == 0 {
            return;
        }
        let held: Vec<Held> = self.books.iter().map(|(_, h)| h.clone()).collect();
        for ((_, h), a) in self.books.iter_mut().zip(enclave_nym::advance(&held, new)) {
            *h = a;
        }
    }
}

impl TicketWallet {
    /// Read a wallet ([`TicketWallet::encode`]).
    pub fn decode_from(b: &[u8]) -> Option<Self> {
        Self::decode(b)
    }

    /// Tickets left in usable books at `now`.
    pub fn tickets_left(&self, now: u64) -> u64 {
        let mut w = self.clone();
        w.prune(now);
        w.left()
    }

    /// Connect the mixnet client with every book that has tickets left,
    /// buying one first from `gate` if there is none worth using.
    pub async fn start(
        &mut self,
        t: &dyn Transport,
        gate: Option<&CredGateEntry>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        self.prune(now);
        if let Some(g) = gate
            && self.left() < REFILL_BELOW
        {
            self.buy_book(t, g, now, rng).await?;
        }
        // A new client counts its spending from zero.
        self.seen = 0;
        let books = self.books.iter().map(|(_, h)| h.encode()).collect();
        t.connect_mixnet(books).await?;
        Ok(())
    }

    /// Follow what the mixnet client has spent, and buy the next book from
    /// `gate` when few tickets are left. True if it bought one.
    pub async fn upkeep(
        &mut self,
        t: &dyn Transport,
        gate: Option<&CredGateEntry>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<bool> {
        self.note_spent(t.tickets_spent().await?);
        self.prune(now);
        match gate {
            Some(g) if self.left() < REFILL_BELOW => {
                self.buy_book(t, g, now, rng).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Buy one ticketbook with a token (doing the work for more tokens if
    /// none is left).
    async fn buy_book(
        &mut self,
        t: &dyn Transport,
        g: &CredGateEntry,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let token = match self.tokens.iter().position(|(_, url, _)| *url == g.url) {
            // Taken out first: a token is good once, whatever happens to
            // the purchase.
            Some(i) => self.tokens.remove(i).2,
            None => {
                let mut fresh = fetch_tokens(t, g, now, rng).await?;
                let token = fresh.remove(0);
                let epoch = gate::epoch_of(now);
                for x in fresh {
                    if self.tokens.len() < MAX_TOKENS {
                        self.tokens.push((epoch, g.url.clone(), x));
                    }
                }
                token
            }
        };
        let book = t.buy_tickets(&g.url, &token.encode()).await?;
        let held = Held::decode(&book)
            .map_err(|_| CoreError::Tickets("the ticketbook didn't decode".into()))?;
        if self.books.len() >= MAX_BOOKS {
            self.books.remove(0);
        }
        self.books.push((now, held));
        Ok(())
    }
}

/// Solve the gate's puzzle for [`TOKENS_PER_PROOF`] tokens, blinded to the
/// issuer key the server list gives for this epoch.
async fn fetch_tokens(
    t: &dyn Transport,
    g: &CredGateEntry,
    now: u64,
    rng: &mut HedgedRng,
) -> Result<Vec<Token>> {
    let key = g
        .key(gate::epoch_of(now))
        .ok_or_else(|| CoreError::Tickets("the server list has no key for this month".into()))?;
    let base = g.url.trim_end_matches('/');
    let (status, challenge) = t
        .fetch("POST", &format!("{base}/credgate/v1/challenge"), Vec::new())
        .await?;
    if status != 200 {
        return Err(CoreError::Tickets(format!("challenge: {status}")));
    }
    let (body, pending) = gate::tokens_request(
        &challenge,
        IssuerPublic(*key),
        &g.issuer_name,
        TOKENS_PER_PROOF,
        rng,
    )
    .ok_or_else(|| CoreError::Tickets("the gate's challenge can't be met".into()))?;
    let (status, answer) = t
        .fetch("POST", &format!("{base}/credgate/v1/tokens"), body)
        .await?;
    if status != 200 {
        return Err(CoreError::Tickets(format!("tokens: {status}")));
    }
    // The DLEQ proofs tie every token to the listed key.
    gate::tokens_finish(pending, &answer)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| CoreError::Tickets("the gate's tokens didn't verify".into()))
}

impl Client {
    fn load_wallet(&self) -> Result<TicketWallet> {
        Ok(self
            .store
            .get(NS_WALLET, WALLET_KEY)?
            .and_then(|b| TicketWallet::decode(&b))
            .unwrap_or_default())
    }

    fn save_wallet(&mut self, w: &TicketWallet) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(w.encode());
        self.store
            .put(NS_WALLET, WALLET_KEY, &bytes, &mut self.rng)?;
        Ok(())
    }

    /// zk-nym tickets left in the wallet's usable books.
    pub fn tickets_left(&self) -> Result<u64> {
        Ok(self.load_wallet()?.tickets_left(self.now()))
    }

    /// The credential gate to buy from: the first the server list names.
    pub fn credgate(&self) -> Option<CredGateEntry> {
        self.server_list()?.credgates.first().cloned()
    }

    /// Take over a wallet filled before this profile existed (a new
    /// device buys its first book to reach its server at all).
    pub fn adopt_tickets(&mut self, w: TicketWallet) -> Result<()> {
        let mut mine = self.load_wallet()?;
        mine.seen = w.seen;
        mine.books.extend(w.books);
        mine.tokens.extend(w.tokens);
        mine.books.truncate(MAX_BOOKS);
        mine.tokens.truncate(MAX_TOKENS);
        self.save_wallet(&mine)
    }

    /// Connect the mixnet client (netd `--await-tickets`) with every book
    /// that has tickets left, buying one first if there is none. Without a
    /// credential gate in the server list it connects without tickets (a
    /// local mixnet, or gateways that don't ask).
    pub async fn start_mixnet(&mut self) -> Result<()> {
        let mut w = self.load_wallet()?;
        let (t, gate, now) = (
            Arc::clone(self.rpc.transport()),
            self.credgate(),
            self.now(),
        );
        let r = w.start(t.as_ref(), gate.as_ref(), now, &mut self.rng).await;
        self.save_wallet(&w)?;
        r
    }

    /// Bring the wallet up to date with what the mixnet client has spent,
    /// and buy the next book when few tickets are left. True if it bought
    /// one.
    pub async fn upkeep_tickets(&mut self) -> Result<bool> {
        let mut w = self.load_wallet()?;
        let (t, gate, now) = (
            Arc::clone(self.rpc.transport()),
            self.credgate(),
            self.now(),
        );
        let r = w
            .upkeep(t.as_ref(), gate.as_ref(), now, &mut self.rng)
            .await;
        self.save_wallet(&w)?;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(total: u32, spent: u32) -> Held {
        Held {
            total,
            spent,
            book: vec![7; 3],
        }
    }

    #[test]
    fn wallet_round_trips_and_tracks_spending() {
        let mut w = TicketWallet {
            seen: 0,
            books: vec![(100, held(50, 45)), (200, held(50, 0))],
            tokens: Vec::new(),
        };
        assert_eq!(TicketWallet::decode(&w.encode()), Some(w.clone()));
        // 7 spent: 5 finish the first book, 2 go to the second.
        w.note_spent(7);
        assert_eq!((w.books[0].1.spent, w.books[1].1.spent), (50, 2));
        // The same reading again changes nothing.
        w.note_spent(7);
        assert_eq!(w.books[1].1.spent, 2);
        // A new client counts from zero.
        w.note_spent(3);
        assert_eq!(w.books[1].1.spent, 5);
        // The used-up book goes; so does one past its lifetime.
        w.prune(150);
        assert_eq!(w.books.len(), 1);
        assert_eq!(w.left(), 45);
        w.prune(200 + BOOK_LIFETIME);
        assert!(w.books.is_empty());
        assert!(TicketWallet::decode(&w.encode()[..5]).is_none());
    }
}
