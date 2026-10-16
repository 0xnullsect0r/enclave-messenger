//! Spent ticket requests (`docs/11-calls.md` §3.3, RFC 0006).
//!
//! A ticket costs proof of work bound to its request, and a request buys
//! one ticket. The relay records each request's burn id; one seen before
//! is refused. [`RedbSpent`]
//! keeps the record on disk, so a restarted relay doesn't accept a token a
//! second time. Tokens are kept for [`RETENTION_SECS`], longer than an
//! issuer key lives, after which a replayed token fails issuer verification
//! anyway.

use enclave_calls::CallError;
use redb::{ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;

/// How long a spent token is remembered: two 31-day issuer-key periods.
pub const RETENTION_SECS: u64 = 62 * 86_400;

/// A record of spent tokens.
pub trait Spent {
    /// Record `token` as spent at `now`. `Ok(false)` if it was spent
    /// before.
    fn spend(&mut self, token: &[u8; 32], now: u64) -> Result<bool, CallError>;
    /// Forget tokens spent more than [`RETENTION_SECS`] before `now`.
    fn prune(&mut self, now: u64) -> Result<(), CallError>;
}

/// In memory (tests, development).
#[derive(Default)]
pub struct MemorySpent(HashMap<[u8; 32], u64>);

impl Spent for MemorySpent {
    fn spend(&mut self, token: &[u8; 32], now: u64) -> Result<bool, CallError> {
        if self.0.contains_key(token) {
            return Ok(false);
        }
        self.0.insert(*token, now);
        Ok(true)
    }

    fn prune(&mut self, now: u64) -> Result<(), CallError> {
        self.0.retain(|_, t| *t + RETENTION_SECS > now);
        Ok(())
    }
}

const SPENT: TableDefinition<'static, &'static [u8], u64> = TableDefinition::new("spent");

/// On disk, in redb. Each token is committed before the ticket is issued.
pub struct RedbSpent(redb::Database);

fn unavailable(e: impl core::fmt::Display) -> CallError {
    eprintln!("enclave-relay: ledger: {e}");
    CallError::Unavailable
}

impl RedbSpent {
    /// Open (or create) the ledger at `path`.
    pub fn open(path: &Path) -> Result<Self, CallError> {
        let db = redb::Database::create(path).map_err(unavailable)?;
        let w = db.begin_write().map_err(unavailable)?;
        w.open_table(SPENT).map_err(unavailable)?;
        w.commit().map_err(unavailable)?;
        Ok(Self(db))
    }
}

impl Spent for RedbSpent {
    fn spend(&mut self, token: &[u8; 32], now: u64) -> Result<bool, CallError> {
        let w = self.0.begin_write().map_err(unavailable)?;
        let fresh = {
            let mut t = w.open_table(SPENT).map_err(unavailable)?;
            if t.get(&token[..]).map_err(unavailable)?.is_some() {
                false
            } else {
                t.insert(&token[..], now).map_err(unavailable)?;
                true
            }
        };
        w.commit().map_err(unavailable)?;
        Ok(fresh)
    }

    fn prune(&mut self, now: u64) -> Result<(), CallError> {
        let w = self.0.begin_write().map_err(unavailable)?;
        w.open_table(SPENT)
            .map_err(unavailable)?
            .retain(|_, t| t + RETENTION_SECS > now)
            .map_err(unavailable)?;
        w.commit().map_err(unavailable)
    }
}
