//! Durable server state (`docs/12-servers.md` §1.3, §6): redb, or
//! PostgreSQL.
//!
//! Every table maps bytes to bytes; the server encodes values itself. A
//! request that changes state does so in one write transaction, committed
//! (fsync'd) before the reply is sealed, so a token burned or an envelope
//! stored survives a crash, and a replayed request after a restart finds
//! the token gone. Tests and the simulator use redb's in-memory backend:
//! the same code, no files.
//!
//! **Backends.** A redb file (`Db::open`) is the default. An operator who
//! wants the state in PostgreSQL gives a URL (`Db::connect`): every table
//! is rows of one relation `enclave_kv (tbl text, k bytea, v bytea)`,
//! primary key `(tbl, k)`, in the same transactions. `bytea` compares
//! bytewise, so prefix scans and key order are the same as redb's. Backups
//! are always redb files (`Db::snapshot`), and `Db::copy_from` loads one
//! into either backend.

use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, TableError,
    TableHandle, WriteTransaction,
};
use std::cell::RefCell;
use std::path::Path;

type Bytes = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// Inbox metadata: owner and read credential hashes, flags, next sequence.
pub const INBOXES: Bytes = TableDefinition::new("inboxes");
/// Daily read credentials of a rotating inbox: `mailbox ‖ u32 day` →
/// credential hash.
pub const READ_CREDS: Bytes = TableDefinition::new("read-creds");
/// Session hints: `mailbox ‖ u64 seq` → `u64 time ‖` the first 24 bytes of
/// the token hash the envelope's write burned.
pub const HINTS: Bytes = TableDefinition::new("hints");
/// Blob tokens issued: `mailbox ‖ u32 day` → `u32` count.
pub const BLOB_ISSUED: Bytes = TableDefinition::new("blob-issued");
/// Blob tokens redeemed: SHA3-512 of the token's nonce (first 32 bytes) →
/// `u32` issuer epoch.
pub const BLOB_SPENT: Bytes = TableDefinition::new("blob-spent");
/// Blob allocations: hash of the allocation secret → `u64 expires ‖ u32
/// uploads left`.
pub const ALLOCS: Bytes = TableDefinition::new("allocs");
/// Registered write tokens: `mailbox ‖ token hash` → empty.
pub const TOKENS: Bytes = TableDefinition::new("tokens");
/// Stored envelopes: `mailbox ‖ seq` → `time ‖ envelope`.
pub const ENVELOPES: Bytes = TableDefinition::new("envelopes");
/// Account manifests: key → `version ‖ signed manifest`.
pub const MANIFESTS: Bytes = TableDefinition::new("manifests");
/// Devices any manifest of an account listed: key → encoded list.
pub const DEVICES_SEEN: Bytes = TableDefinition::new("devices-seen");
/// Device attestations: key → encoded list (newest last).
pub const ATTESTATIONS: Bytes = TableDefinition::new("attestations");
/// Changes of recovery words: old root's key → migration record.
pub const MIGRATIONS: Bytes = TableDefinition::new("migrations");
/// Old root → new root.
pub const MOVED: Bytes = TableDefinition::new("moved");
/// Accounts that moved to another server: manifest key → `ServerMove`.
pub const SERVER_MOVES: Bytes = TableDefinition::new("server-moves");
/// Deleted accounts: manifest key → root-signed `Tombstone`.
pub const TOMBSTONES: Bytes = TableDefinition::new("tombstones");
/// Requests already opened: `u32 key_id ‖ replay id` → empty, until the
/// day's key is deleted.
pub const REPLAYS: Bytes = TableDefinition::new("replays");
/// Proofs of work already accepted: `u32 day ‖ proof` → empty, kept while
/// the day can still be proven for (today and yesterday).
pub const POW_SPENT: Bytes = TableDefinition::new("pow-spent");
/// Proofs that a key-transparency log equivocated: server id (padded to
/// 32 B) → `Equivocation`.
pub const EQUIVOCATIONS: Bytes = TableDefinition::new("equivocations");
/// Device id → the manifest key of the account that lists it.
pub const DEVICE_OWNER: Bytes = TableDefinition::new("device-owner");
/// Prekey publications: device → `next opk ‖ publication`.
pub const BUNDLES: Bytes = TableDefinition::new("bundles");
/// Encrypted vault keys: locator → `owner hash ‖ bytes`.
pub const VAULTS: Bytes = TableDefinition::new("vaults");
/// Blob chunks: id → `time ‖ bytes`.
pub const BLOBS: Bytes = TableDefinition::new("blobs");
/// Sealed push tokens: mailbox → sealed token.
pub const PUSH: Bytes = TableDefinition::new("push");
/// Usernames: name → `root ‖ last claim time`.
pub const USERNAMES: Bytes = TableDefinition::new("usernames");
/// Root → its current name.
pub const NAMES_BY_ROOT: Bytes = TableDefinition::new("names-by-root");
/// Reports for the operator: sequence → encoded report.
pub const REPORTS: Bytes = TableDefinition::new("reports");
/// Server metadata (schema version, counters).
pub const META: Bytes = TableDefinition::new("meta");

/// The schema this code writes. Older files are migrated on open.
pub const SCHEMA_VERSION: u32 = 8;

/// Storage failure. The server answers `Status::Internal` and logs it.
#[derive(Debug, thiserror::Error)]
#[error("storage: {0}")]
pub struct DbError(String);

impl DbError {
    /// A storage error with this message.
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for DbError {
            fn from(e: $t) -> Self {
                DbError(e.to_string())
            }
        }
    )*};
}
from_redb!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    postgres::Error
);

/// Result of a storage operation.
pub type Result<T> = core::result::Result<T, DbError>;

/// The server database.
pub struct Db {
    backend: Backend,
}

enum Backend {
    Redb(Database),
    Pg(Box<crate::pg::Pg>),
}

impl Db {
    /// Open (or create) the redb database file at `path`, migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Self {
            backend: Backend::Redb(Database::create(path)?),
        };
        db.migrate()?;
        Ok(db)
    }

    /// A database that lives in memory (tests, simulator, dev demo).
    pub fn memory() -> Result<Self> {
        let db = Self {
            backend: Backend::Redb(
                Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
            ),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Connect to PostgreSQL at `url` (`postgres://user:password@host/db`),
    /// creating the table and migrating.
    pub fn connect(url: &str) -> Result<Self> {
        let db = Self {
            backend: Backend::Pg(Box::new(crate::pg::Pg::connect(url)?)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Which backend: `"redb"` or `"postgres"`.
    pub fn backend(&self) -> &'static str {
        match self.backend {
            Backend::Redb(_) => "redb",
            Backend::Pg(_) => "postgres",
        }
    }

    fn migrate(&self) -> Result<()> {
        self.write(|t| {
            let current = t
                .get(META, b"schema")?
                .and_then(|v| v.try_into().ok().map(u32::from_be_bytes))
                .unwrap_or(0);
            if current > SCHEMA_VERSION {
                return Err(DbError(format!(
                    "database schema {current} is newer than this server ({SCHEMA_VERSION})"
                )));
            }
            // Every table is created at each start: 0 → 1 made them all,
            // 1 → 2 added `server-moves`, 2 → 3 `tombstones`, 3 → 4
            // `replays`, 4 → 5 `pow-spent`, 5 → 6 `equivocations`, 6 → 7
            // `read-creds` and `hints`, 7 → 8 `blob-issued`, `blob-spent`
            // and `allocs`.
            t.create_tables()?;
            t.put(META, b"schema", &SCHEMA_VERSION.to_be_bytes())
        })
    }

    /// Run `f` in one write transaction and commit it durably (synced to
    /// disk before this returns).
    pub fn write<R>(&self, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        self.write_with(true, f)
    }

    /// Like [`Db::write`], but the commit isn't synced on its own: it
    /// becomes durable with the next durable commit, and a crash before
    /// that loses it. For bookkeeping that a request's own durable write
    /// carries along (the replay cache, spent proofs of work), so a request
    /// costs one sync, not two.
    pub fn write_lazy<R>(&self, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        self.write_with(false, f)
    }

    fn write_with<R>(&self, durable: bool, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        match &self.backend {
            Backend::Redb(db) => {
                let mut w = db.begin_write()?;
                if !durable {
                    w.set_durability(redb::Durability::None)
                        .map_err(|e| DbError(e.to_string()))?;
                }
                let r = f(&mut Tx {
                    inner: TxInner::Redb(&w),
                })?;
                w.commit()?;
                Ok(r)
            }
            Backend::Pg(pg) => pg.transaction(durable, |t| {
                f(&mut Tx {
                    inner: TxInner::Pg(RefCell::new(t)),
                })
            }),
        }
    }

    /// Run `f` in a read transaction.
    pub fn read<R>(&self, f: impl FnOnce(&Rx<'_>) -> Result<R>) -> Result<R> {
        match &self.backend {
            Backend::Redb(db) => {
                let r = db.begin_read()?;
                f(&Rx {
                    inner: RxInner::Redb(r),
                })
            }
            Backend::Pg(pg) => pg.transaction(true, |t| {
                f(&Rx {
                    inner: RxInner::Pg(RefCell::new(t)),
                })
            }),
        }
    }

    /// Every `(table, key, value)`, in one read transaction.
    fn dump(&self) -> Result<Vec<(Bytes, Rows)>> {
        self.read(|r| ALL.iter().map(|t| Ok((*t, r.scan(*t, b"")?))).collect())
    }

    /// Copy every table into a fresh redb file at `path` (a consistent
    /// snapshot for backups: one read transaction), whatever the backend.
    pub fn snapshot(&self, path: &Path) -> Result<()> {
        let rows = self.dump()?;
        let out = Database::create(path)?;
        let w = out.begin_write()?;
        for (t, kvs) in rows {
            let mut dst = w.open_table(t)?;
            for (k, v) in kvs {
                dst.insert(k.as_slice(), v.as_slice())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Replace everything here with the contents of `src` (restoring a
    /// snapshot into either backend), in one transaction.
    pub fn copy_from(&self, src: &Db) -> Result<()> {
        let rows = src.dump()?;
        self.write(|t| {
            for (table, kvs) in &rows {
                t.remove_where(*table, b"", |_, _| true)?;
                for (k, v) in kvs {
                    t.put(*table, k, v)?;
                }
            }
            Ok(())
        })
    }
}

/// `(key, value)` pairs in key order.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Every table, for snapshots.
const ALL: [Bytes; 27] = [
    INBOXES,
    READ_CREDS,
    HINTS,
    BLOB_ISSUED,
    BLOB_SPENT,
    ALLOCS,
    TOKENS,
    ENVELOPES,
    MANIFESTS,
    DEVICES_SEEN,
    ATTESTATIONS,
    MIGRATIONS,
    MOVED,
    SERVER_MOVES,
    TOMBSTONES,
    REPLAYS,
    POW_SPENT,
    EQUIVOCATIONS,
    DEVICE_OWNER,
    BUNDLES,
    VAULTS,
    BLOBS,
    PUSH,
    USERNAMES,
    NAMES_BY_ROOT,
    REPORTS,
    META,
];

/// A write transaction.
pub struct Tx<'a> {
    inner: TxInner<'a>,
}

enum TxInner<'a> {
    Redb(&'a WriteTransaction),
    Pg(RefCell<&'a mut dyn crate::pg::Kv>),
}

/// A read transaction.
pub struct Rx<'a> {
    inner: RxInner<'a>,
}

enum RxInner<'a> {
    Redb(ReadTransaction),
    Pg(RefCell<&'a mut dyn crate::pg::Kv>),
}

/// The keys starting with `prefix`, as a half-open range `[prefix, end)`;
/// `None` for no upper bound (an empty prefix, or all 0xff).
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

impl Tx<'_> {
    fn create_tables(&mut self) -> Result<()> {
        if let TxInner::Redb(w) = &self.inner {
            for t in ALL {
                w.open_table(t)?;
            }
        }
        Ok(())
    }

    /// Value at `key`.
    pub fn get(&self, t: Bytes, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match &self.inner {
            TxInner::Redb(w) => {
                let table = w.open_table(t)?;
                Ok(table.get(key)?.map(|v| v.value().to_vec()))
            }
            TxInner::Pg(c) => c.borrow_mut().get(t.name(), key),
        }
    }

    /// Whether `key` exists.
    pub fn has(&self, t: Bytes, key: &[u8]) -> Result<bool> {
        Ok(self.get(t, key)?.is_some())
    }

    /// Set `key`.
    pub fn put(&mut self, t: Bytes, key: &[u8], value: &[u8]) -> Result<()> {
        match &self.inner {
            TxInner::Redb(w) => {
                let mut table = w.open_table(t)?;
                table.insert(key, value)?;
                Ok(())
            }
            TxInner::Pg(c) => c.borrow_mut().put(t.name(), key, value),
        }
    }

    /// Remove `key`; returns whether it existed.
    pub fn del(&mut self, t: Bytes, key: &[u8]) -> Result<bool> {
        match &self.inner {
            TxInner::Redb(w) => {
                let mut table = w.open_table(t)?;
                Ok(table.remove(key)?.is_some())
            }
            TxInner::Pg(c) => c.borrow_mut().del(t.name(), key),
        }
    }

    /// Every `(key, value)` whose key starts with `prefix`, in key order.
    pub fn scan(&self, t: Bytes, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range(t, prefix, prefix, usize::MAX)
    }

    /// Up to `limit` `(key, value)` pairs with `from ≤ key` under `prefix`.
    fn range(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        match &self.inner {
            TxInner::Redb(w) => {
                let table = w.open_table(t)?;
                range_table(&table, prefix, from, limit)
            }
            TxInner::Pg(c) => {
                c.borrow_mut()
                    .range(t.name(), from, prefix_end(prefix).as_deref(), limit)
            }
        }
    }

    /// Number of keys starting with `prefix`.
    pub fn count(&self, t: Bytes, prefix: &[u8]) -> Result<usize> {
        match &self.inner {
            TxInner::Redb(w) => {
                let table = w.open_table(t)?;
                let mut n = 0;
                for item in table.range(prefix..)? {
                    let (k, _) = item?;
                    if !k.value().starts_with(prefix) {
                        break;
                    }
                    n += 1;
                }
                Ok(n)
            }
            TxInner::Pg(c) => c
                .borrow_mut()
                .count(t.name(), prefix, prefix_end(prefix).as_deref()),
        }
    }

    /// The first `(key, value)` with `from ≤ key` that starts with `prefix`.
    pub fn first_from(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self.range(t, prefix, from, 1)?.pop())
    }

    /// Remove every key starting with `prefix` for which `drop` is true;
    /// returns how many were removed.
    pub fn remove_where(
        &mut self,
        t: Bytes,
        prefix: &[u8],
        mut drop: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<usize> {
        let doomed: Vec<Vec<u8>> = self
            .scan(t, prefix)?
            .into_iter()
            .filter(|(k, v)| drop(k, v))
            .map(|(k, _)| k)
            .collect();
        for k in &doomed {
            self.del(t, k)?;
        }
        Ok(doomed.len())
    }
}

impl Rx<'_> {
    /// Value at `key`.
    pub fn get(&self, t: Bytes, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match &self.inner {
            RxInner::Redb(r) => {
                let table = match r.open_table(t) {
                    Ok(t) => t,
                    Err(TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(e.into()),
                };
                Ok(table.get(key)?.map(|v| v.value().to_vec()))
            }
            RxInner::Pg(c) => c.borrow_mut().get(t.name(), key),
        }
    }

    /// Every `(key, value)` whose key starts with `prefix`.
    pub fn scan(&self, t: Bytes, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range(t, prefix, prefix, usize::MAX)
    }

    /// The first two `(key, value)` pairs with `from ≤ key` under `prefix`
    /// (a poll needs the next envelope and whether another follows).
    pub fn next_two(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range(t, prefix, from, 2)
    }

    fn range(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        match &self.inner {
            RxInner::Redb(r) => {
                let table = match r.open_table(t) {
                    Ok(t) => t,
                    Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                    Err(e) => return Err(e.into()),
                };
                range_table(&table, prefix, from, limit)
            }
            RxInner::Pg(c) => {
                c.borrow_mut()
                    .range(t.name(), from, prefix_end(prefix).as_deref(), limit)
            }
        }
    }
}

/// Up to `limit` pairs from `from` on, while keys start with `prefix`.
fn range_table(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
    from: &[u8],
    limit: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    for item in table.range(from..)? {
        let (k, v) = item?;
        if !k.value().starts_with(prefix) || out.len() == limit {
            break;
        }
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn put_scan_snapshot() {
        let db = Db::memory().unwrap();
        db.write(|t| {
            t.put(ENVELOPES, b"aa\x00\x01", b"x")?;
            t.put(ENVELOPES, b"aa\x00\x02", b"y")?;
            t.put(ENVELOPES, b"ab\x00\x01", b"z")
        })
        .unwrap();
        let s = db.read(|r| r.scan(ENVELOPES, b"aa")).unwrap();
        assert_eq!(s.len(), 2);
        let two = db
            .read(|r| r.next_two(ENVELOPES, b"aa", b"aa\x00\x02"))
            .unwrap();
        assert_eq!(two.len(), 1, "stops at the prefix");
        let n = db
            .write(|t| t.remove_where(ENVELOPES, b"aa", |k, _| k[3] <= 1))
            .unwrap();
        assert_eq!(n, 1);
        let dir = std::env::temp_dir().join(format!("enclave-db-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        db.snapshot(&dir).unwrap();
        let copy = Db::open(&dir).unwrap();
        assert_eq!(
            copy.read(|r| r.get(ENVELOPES, b"ab\x00\x01"))
                .unwrap()
                .unwrap(),
            b"z"
        );
        let _ = std::fs::remove_file(&dir);
    }
}
