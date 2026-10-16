//! The update bundle: everything a client needs to check a release, in one
//! file that servers relay over the mixnet (`docs/19-ops.md` §1.3).
//!
//! ```text
//! "ENCLUPD1"
//! u16 n ‖ n × bytes(signed root)        roots after version 1, in order
//! bytes(timestamp) ‖ bytes(snapshot) ‖ bytes(targets)
//! u16 m ‖ m × (bytes(file name) ‖ bytes(Sigsum proof))
//! ```
//!
//! A server only relays it: everything in it is signed, so a server can
//! hold it back (the timestamp then expires and the client says so) but
//! can't change it. [`Bundle::apply`] moves a client through any new roots
//! and checks the chain.

use crate::metadata::{Client, R, Release, Result, Signed, UpdateError, W};

/// The bundle's first bytes.
pub const MAGIC: &[u8; 8] = b"ENCLUPD1";
/// The largest bundle read.
pub const MAX_BUNDLE: usize = 4 << 20;
const MAX_DOC: usize = 1 << 20;
const MAX_ROOTS: usize = 64;
const MAX_PROOFS: usize = 1024;
const MAX_PROOF: usize = 16 << 10;

/// A release's metadata and its files' Sigsum proofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bundle {
    /// Signed roots newer than the first, oldest first; a client applies
    /// those above the one it has.
    pub roots: Vec<Vec<u8>>,
    /// The signed timestamp.
    pub timestamp: Vec<u8>,
    /// The signed snapshot.
    pub snapshot: Vec<u8>,
    /// The signed targets.
    pub targets: Vec<u8>,
    /// Each file's Sigsum proof, by file name.
    pub proofs: Vec<(String, String)>,
}

impl Bundle {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(MAGIC.to_vec());
        w.u16(self.roots.len() as u16);
        for r in &self.roots {
            w.bytes(r);
        }
        w.bytes(&self.timestamp)
            .bytes(&self.snapshot)
            .bytes(&self.targets);
        w.u16(self.proofs.len() as u16);
        for (name, proof) in &self.proofs {
            w.bytes(name.as_bytes()).bytes(proof.as_bytes());
        }
        w.0
    }

    /// Decode (nothing in it is trusted until [`Bundle::apply`]).
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_BUNDLE || !b.starts_with(MAGIC) {
            return Err(UpdateError::Malformed);
        }
        let mut r = R(&b[MAGIC.len()..]);
        let n = r.u16()? as usize;
        if n > MAX_ROOTS {
            return Err(UpdateError::Malformed);
        }
        let mut roots = Vec::with_capacity(n);
        for _ in 0..n {
            roots.push(r.bytes(MAX_DOC)?.to_vec());
        }
        let timestamp = r.bytes(MAX_DOC)?.to_vec();
        let snapshot = r.bytes(MAX_DOC)?.to_vec();
        let targets = r.bytes(MAX_DOC)?.to_vec();
        let m = r.u16()? as usize;
        if m > MAX_PROOFS {
            return Err(UpdateError::Malformed);
        }
        let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| UpdateError::Malformed);
        let mut proofs = Vec::with_capacity(m);
        for _ in 0..m {
            let name = text(r.bytes(255)?)?;
            let proof = text(r.bytes(MAX_PROOF)?)?;
            proofs.push((name, proof));
        }
        r.end()?;
        Ok(Self {
            roots,
            timestamp,
            snapshot,
            targets,
            proofs,
        })
    }

    /// Move `client` through the roots it doesn't have yet, then check the
    /// chain at `now`: the release it describes. On an error the client is
    /// left as it was.
    pub fn apply(&self, client: &mut Client, now: u64) -> Result<Release> {
        let mut next = client.clone();
        for r in &self.roots {
            let version = crate::metadata::Root::decode(&Signed::decode(r)?.body)?.version;
            if version > next.root().version {
                next.update_root(r)?;
            }
        }
        let release = next.refresh(&self.timestamp, &self.snapshot, &self.targets, now)?;
        *client = next;
        Ok(release)
    }

    /// A file's Sigsum proof.
    pub fn proof(&self, name: &str) -> Option<&str> {
        self.proofs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.as_str())
    }

    /// The timestamp document's version, without checking it (a relay
    /// keeps the newest bundle it is given).
    pub fn timestamp_version(&self) -> Option<u32> {
        let s = Signed::decode(&self.timestamp).ok()?;
        crate::metadata::Timestamp::decode(&s.body)
            .ok()
            .map(|t| t.version)
    }
}

/// Whether version `a` (`1.2.3`, an optional leading `v`, an optional
/// `-pre` part) is older than `b`. A pre-release is older than its
/// release. Unreadable versions are never older.
pub fn older(a: &str, b: &str) -> bool {
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// `(major, minor, patch, is_release, pre)` so tuples compare in order.
fn parse(v: &str) -> Option<(u64, u64, u64, bool, String)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>());
    let (a, b, c) = (it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?);
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c, pre.is_none(), pre.unwrap_or_default().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert!(older("0.1.0", "v0.2.0"));
        assert!(older("v1.2.3-rc.1", "1.2.3"));
        assert!(older("1.2.3-rc.1", "1.2.3-rc.2"));
        assert!(!older("1.10.0", "1.9.9"));
        assert!(!older("1.2.3", "1.2.3"));
        assert!(!older("junk", "1.0.0"));
    }

    #[test]
    fn bundles_round_trip_and_reject_junk() {
        let b = Bundle {
            roots: vec![vec![1, 2], vec![3]],
            timestamp: vec![4],
            snapshot: vec![5, 6],
            targets: vec![7],
            proofs: vec![("enclave.tar.gz".into(), "version=2\n".into())],
        };
        let e = b.encode();
        assert_eq!(Bundle::decode(&e), Ok(b.clone()));
        assert_eq!(b.proof("enclave.tar.gz"), Some("version=2\n"));
        assert!(Bundle::decode(&e[..e.len() - 1]).is_err());
        assert!(Bundle::decode(b"ENCLUPD0").is_err());
        let mut long = e.clone();
        long.push(0);
        assert!(Bundle::decode(&long).is_err());
    }
}
