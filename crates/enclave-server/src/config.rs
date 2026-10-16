//! Operator configuration (`server.toml`, `docs/12-servers.md` §1.1).
//!
//! Every key can be overridden from the environment as
//! `ENCLAVE_<SECTION>__<KEY>` (for example `ENCLAVE_SERVER__DOMAIN`), which
//! is how the compose file sets per-deployment values
//! (`enclave_service::config`). Unknown keys are refused, so a typo doesn't
//! silently fall back to a default.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The whole file.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    /// Where the server lives and what it is called.
    pub server: ServerSection,
    /// Abuse-control policy.
    pub policy: PolicySection,
    /// Key transparency.
    pub kt: KtSection,
    /// Push wakes.
    pub push: PushSection,
    /// Backups.
    pub backup: BackupSection,
    /// Where state is kept (redb by default, or PostgreSQL).
    pub database: DatabaseSection,
}

/// `[database]`: a redb file in `server.data_dir` unless a PostgreSQL URL
/// is given (`docs/12-servers.md` §6).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DatabaseSection {
    /// `postgres://user:password@host/db`; empty for redb.
    pub url: String,
    /// A file holding the URL (a Docker secret), used when `url` is empty.
    pub url_file: Option<PathBuf>,
}

impl DatabaseSection {
    /// The PostgreSQL URL, if one is configured.
    pub fn postgres_url(&self) -> Result<Option<String>, ConfigError> {
        if !self.url.is_empty() {
            return Ok(Some(self.url.clone()));
        }
        match &self.url_file {
            Some(p) => std::fs::read_to_string(p)
                .map(|s| Some(s.trim().to_string()))
                .map_err(|e| ConfigError(format!("{}: {e}", p.display()))),
            None => Ok(None),
        }
    }
}

/// `[server]`
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// The server's public domain (descriptor, usernames).
    pub domain: String,
    /// Operator name shown to users.
    pub operator: String,
    /// Operator family: servers and relays of one family never count as
    /// independent of each other.
    pub family: String,
    /// Database directory.
    pub data_dir: PathBuf,
    /// Key directory (mode 0700; `enclave-server init` fills it).
    pub keys_dir: PathBuf,
    /// Where the ingress (or, in development, clients) reach the server.
    pub listen: SocketAddr,
    /// Where public files (descriptor, KT pins) are written for the front.
    pub public_dir: PathBuf,
    /// The Nym address of this server's ingress, published in the
    /// descriptor (empty until it has one).
    pub nym_address: String,
    /// A copy of the foundation's signed server list to serve to clients
    /// (`DirKind::ServerList`); re-read when it changes.
    pub server_list: Option<PathBuf>,
    /// The release update bundle the front fetches (`front.update_dir`),
    /// relayed to clients as `DirKind::Update`; re-read when it changes.
    pub update_bundle: Option<PathBuf>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            domain: "localhost".into(),
            operator: String::new(),
            family: String::new(),
            data_dir: PathBuf::from("/var/lib/enclave/server"),
            keys_dir: PathBuf::from("/var/lib/enclave/keys"),
            listen: SocketAddr::from(([127, 0, 0, 1], 7443)),
            public_dir: PathBuf::from("/var/lib/enclave/public"),
            nym_address: String::new(),
            server_list: None,
            update_bundle: None,
        }
    }
}

/// `[policy]`: the abuse controls of `crate::Config`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicySection {
    /// Proof-of-work effort for request-inbox writes.
    pub effort_request: u32,
    /// Proof-of-work effort for claiming a bundle.
    pub effort_claim: u32,
    /// Blob-upload tokens one inbox may be issued a day.
    pub blob_tokens_per_day: u32,
    /// Proof-of-work effort for claiming a username.
    pub effort_username: u32,
    /// Proof-of-work effort for creating an inbox.
    pub effort_inbox: u32,
    /// Maximum stored envelopes per inbox.
    pub inbox_quota: usize,
    /// Maximum pending requests per request inbox.
    pub request_quota: usize,
    /// Maximum registered unspent tokens per inbox.
    pub token_quota: usize,
    /// Days envelopes and blobs are kept.
    pub ttl_days: u64,
}

impl Default for PolicySection {
    fn default() -> Self {
        let c = crate::Config::default();
        Self {
            effort_request: c.effort_request,
            effort_claim: c.effort_claim,
            blob_tokens_per_day: c.blob_tokens_per_day,
            effort_username: c.effort_username,
            effort_inbox: c.effort_inbox,
            inbox_quota: c.inbox_quota,
            request_quota: c.request_quota,
            token_quota: c.token_quota,
            ttl_days: c.ttl_secs / 86_400,
        }
    }
}

/// `[kt]`
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KtSection {
    /// Run a key-transparency log (usernames).
    pub enabled: bool,
    /// Witnesses to ask for cosignatures (base URLs, other operators'
    /// `enclave-witness` services).
    pub witnesses: Vec<String>,
    /// Extra roots (PEM) to trust for witnesses' certificates.
    pub witness_ca: Option<PathBuf>,
    /// Usernames the operator withdrew for breaking its policy
    /// (`13-operators.md` §1): tombstoned at start, for good.
    pub withdrawn: Vec<String>,
    /// Seconds over which claims are gathered into one epoch
    /// (`12-servers.md` §3.4), so names claimed around the same time
    /// can't be told apart by epoch. Each claim waits up to this long.
    pub batch_secs: u64,
}

impl Default for KtSection {
    fn default() -> Self {
        Self {
            enabled: true,
            witnesses: Vec::new(),
            witness_ca: None,
            withdrawn: Vec::new(),
            batch_secs: 2,
        }
    }
}

/// `[push]`
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PushSection {
    /// Where due wakes are forwarded (the push egress, which carries them
    /// to the push relay over the mixnet). Empty: no push.
    /// `HOST:PORT` (a name on the stack's network, or an address).
    pub forward: Option<String>,
}

/// `[backup]`
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BackupSection {
    /// Directory for snapshots; empty disables them.
    pub dir: Option<PathBuf>,
    /// Hours between snapshots.
    pub interval_hours: u64,
    /// Snapshots kept.
    pub keep: usize,
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            dir: None,
            interval_hours: 24,
            keep: 7,
        }
    }
}

pub use enclave_service::config::ConfigError;

impl FileConfig {
    /// Read `path` (if given) and apply `ENCLAVE_*` overrides from `env`.
    pub fn load(
        path: Option<&Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let cfg: FileConfig = enclave_service::config::load(path, env)?;
        cfg.check()?;
        Ok(cfg)
    }

    fn check(&self) -> Result<(), ConfigError> {
        let d = &self.server.domain;
        if d.is_empty()
            || d.len() > 253
            || !d
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(ConfigError(format!(
                "server.domain {d:?} is not a domain name"
            )));
        }
        if self.policy.ttl_days == 0 || self.policy.inbox_quota == 0 {
            return Err(ConfigError(
                "policy.ttl_days and inbox_quota must be positive".into(),
            ));
        }
        Ok(())
    }

    /// The policy as published in the descriptor.
    pub fn published_policy(&self) -> enclave_federation::Policy {
        let p = &self.policy;
        let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
        enclave_federation::Policy {
            effort_request: p.effort_request,
            effort_claim: p.effort_claim,
            blob_tokens_per_day: p.blob_tokens_per_day,
            effort_username: p.effort_username,
            effort_inbox: p.effort_inbox,
            inbox_quota: n(p.inbox_quota),
            request_quota: n(p.request_quota),
            token_quota: n(p.token_quota),
            ttl_days: u32::try_from(p.ttl_days).unwrap_or(u32::MAX),
        }
    }

    /// The server policy.
    pub fn policy(&self, id: [u8; 16]) -> crate::Config {
        let p = &self.policy;
        crate::Config {
            id,
            effort_request: p.effort_request,
            effort_claim: p.effort_claim,
            blob_tokens_per_day: p.blob_tokens_per_day,
            effort_username: p.effort_username,
            effort_inbox: p.effort_inbox,
            inbox_quota: p.inbox_quota,
            request_quota: p.request_quota,
            token_quota: p.token_quota,
            ttl_secs: p.ttl_days * 86_400,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn defaults_file_and_env() {
        let c = FileConfig::load(None, []).unwrap();
        assert_eq!(c.server.domain, "localhost");
        let dir = std::env::temp_dir().join(format!("enclave-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("server.toml");
        std::fs::write(
            &p,
            "[server]\ndomain = \"a.example\"\n[policy]\ninbox_quota = 10\n",
        )
        .unwrap();
        let c = FileConfig::load(
            Some(&p),
            [
                ("ENCLAVE_SERVER__OPERATOR".into(), "Ada's Servers".into()),
                ("ENCLAVE_POLICY__TOKEN_QUOTA".into(), "77".into()),
                ("ENCLAVE_KT__ENABLED".into(), "false".into()),
                ("UNRELATED".into(), "x".into()),
            ],
        )
        .unwrap();
        assert_eq!(c.server.domain, "a.example");
        assert_eq!(c.server.operator, "Ada's Servers");
        assert_eq!(c.policy.inbox_quota, 10);
        assert_eq!(c.policy.token_quota, 77);
        assert!(!c.kt.enabled);
        std::fs::write(&p, "[server]\ndomian = \"typo\"\n").unwrap();
        assert!(
            FileConfig::load(Some(&p), []).is_err(),
            "unknown keys refused"
        );
        assert!(
            FileConfig::load(
                None,
                [("ENCLAVE_SERVER__DOMAIN".into(), "bad domain!".into())]
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
