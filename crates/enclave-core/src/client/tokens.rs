//! Write tokens from a shared pool (`docs/09-transport.md` §3.2).
//!
//! The owner registers token hashes at its server ahead of time, in
//! batches of [`POOL_BATCH`] fresh tokens shuffled with [`POOL_DUMMIES`]
//! random values, and hands each contact tokens from that pool when they
//! need them. A batch therefore mixes tokens that end up with different
//! contacts, so the server can't group writes by sender from which batch
//! their tokens came in. (Registering one contact's tokens as their own
//! batch, as before, would let it: every token in a batch that is ever
//! burned would be the same person's.)
//!
//! The tokens each contact was given are kept (the last [`MAX_ISSUED`],
//! less the ones whose writes have arrived), so a block can revoke the
//! ones still outstanding and a new weekly address can register them.
//! The pool is per device and never in a backup: a restored device starts
//! with an empty one, so no token is handed out twice.

use super::Client;
use crate::persist::NS_ISSUERS;
use crate::{CoreError, Result};
use enclave_tokens::Token;

pub(crate) const NS_TOKEN_POOL: &str = "token-pool";
const POOL_KEY: &[u8] = b"pool";
/// Fresh tokens per registration batch.
pub const POOL_BATCH: usize = 64;
/// Random values shuffled into each batch.
pub const POOL_DUMMIES: usize = 16;
/// Tokens kept per contact for revocation and re-registration.
pub const MAX_ISSUED: usize = 128;

pub(crate) fn load_pool(store: &enclave_store::Store) -> Result<Vec<Token>> {
    Ok(store
        .get(NS_TOKEN_POOL, POOL_KEY)?
        .map(|b| {
            b.chunks_exact(32)
                .filter_map(|c| c.try_into().ok())
                .collect()
        })
        .unwrap_or_default())
}

impl Client {
    fn save_pool(&mut self) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(self.token_pool.concat());
        self.store
            .put(NS_TOKEN_POOL, POOL_KEY, &bytes, &mut self.rng)?;
        Ok(())
    }

    /// Register a batch of fresh tokens at every address writers may use
    /// now, and add them to the pool.
    async fn refill_pool(&mut self, at_least: usize, now: u64) -> Result<()> {
        let n = at_least.max(POOL_BATCH);
        let fresh: Vec<Token> = (0..n)
            .map(|_| self.rng.array("core/write-token"))
            .collect::<std::result::Result<_, _>>()?;
        // Just moved, or back after weeks away: make the addresses first.
        let inow = self.inbox_now(now);
        if self.profile.live_weeks(inow).is_empty() {
            self.ensure_weeks(now).await?;
        }
        let weeks = self.profile.live_weeks(inow);
        if weeks.is_empty() {
            return Err(CoreError::NotFound);
        }
        for week in weeks {
            self.register_at(week, &fresh, POOL_DUMMIES, 0, now).await?;
        }
        // Hand out the oldest first; new ones go to the back.
        self.token_pool.extend(fresh);
        self.save_pool()
    }

    /// `n` tokens for `root`, from the pool (registered first if it runs
    /// short).
    pub(crate) async fn issue_tokens(
        &mut self,
        root: &[u8; 64],
        n: usize,
        now: u64,
    ) -> Result<Vec<Token>> {
        if self.token_pool.len() < n {
            let missing = n - self.token_pool.len();
            self.refill_pool(missing, now).await?;
        }
        if self.token_pool.len() < n {
            return Err(CoreError::OutOfTokens);
        }
        let toks: Vec<Token> = self.token_pool.drain(..n).collect();
        self.save_pool()?;
        let mut issued = self.issued(root);
        issued.extend(toks.iter().copied());
        let drop = issued.len().saturating_sub(MAX_ISSUED);
        issued.drain(..drop);
        self.save_issued(root, &issued)?;
        Ok(toks)
    }

    fn save_issued(&mut self, root: &[u8; 64], issued: &[Token]) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(issued.concat());
        self.store.put(NS_ISSUERS, root, &bytes, &mut self.rng)?;
        Ok(())
    }

    /// The tokens `root` was given and hasn't used, as far as we know (the
    /// last [`MAX_ISSUED`]).
    pub(crate) fn issued(&self, root: &[u8; 64]) -> Vec<Token> {
        self.store
            .get(NS_ISSUERS, root)
            .ok()
            .flatten()
            .map(|b| {
                b.chunks_exact(32)
                    .filter_map(|c| c.try_into().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many of the tokens `root` was given haven't been used, as far
    /// as we know (diagnostics, tests).
    pub fn tokens_outstanding(&self, root: &[u8; 64]) -> usize {
        self.issued(root).len()
    }

    /// Every contact's outstanding tokens.
    pub(crate) fn all_issued(&self) -> Result<Vec<([u8; 64], Vec<Token>)>> {
        Ok(self
            .store
            .scan(NS_ISSUERS)?
            .into_iter()
            .filter_map(|(k, v)| {
                let root: [u8; 64] = k.as_slice().try_into().ok()?;
                let toks = v
                    .chunks_exact(32)
                    .filter_map(|c| c.try_into().ok())
                    .collect();
                Some((root, toks))
            })
            .collect())
    }

    /// A write that burned `token` arrived (its hint said whose): it's
    /// used, so it isn't registered at new addresses any more.
    pub(crate) fn burned(&mut self, root: &[u8; 64], token: &Token) -> Result<()> {
        let mut issued = self.issued(root);
        let before = issued.len();
        issued.retain(|t| t != token);
        if issued.len() != before {
            self.save_issued(root, &issued)?;
        }
        Ok(())
    }

    /// Forget the pool and what was handed out (a restored device must not
    /// reuse the old pool; a moved account's tokens were for the old home).
    pub(crate) fn clear_pool(&mut self) -> Result<()> {
        self.token_pool.clear();
        self.store.delete(NS_TOKEN_POOL, POOL_KEY)?;
        Ok(())
    }
}
