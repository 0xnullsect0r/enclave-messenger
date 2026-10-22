//! An in-process [`Transport`]: real sealed requests to real servers, with
//! the network replaced by a function call. Used by `enclave-core` tests and
//! the desktop app's offline demo mode.

use enclave_net::NetError;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use enclave_server::Server;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Servers shared by every client in one process.
#[derive(Clone, Default)]
pub struct LocalTransport {
    servers: Arc<Mutex<HashMap<ServerId, Server>>>,
    /// Identity keys of servers started with [`Self::add_federated_server`]
    /// (descriptors are signed with them).
    identities: Arc<Mutex<HashMap<ServerId, (String, enclave_crypto::sig::CompositeSigningKey)>>>,
    /// Seconds added to the system clock (to simulate time passing).
    offset: Arc<Mutex<u64>>,
}

impl LocalTransport {
    /// No servers yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a server with `config` (its `id` is the address).
    pub fn add_server(
        &self,
        config: enclave_server::Config,
    ) -> Result<(), enclave_server::ServerError> {
        let day = (self.now() / 86_400) as u32;
        let id = config.id;
        let server = Server::new(config, day)?;
        if let Ok(mut m) = self.servers.lock() {
            m.insert(id, server);
        }
        Ok(())
    }

    /// Start a server with its own identity (so its id is derived from it,
    /// as in production) and a key-transparency log under `domain` with
    /// three in-process witnesses. Returns its entry for a server list and
    /// the witnesses for one.
    pub fn add_federated_server(
        &self,
        domain: &str,
        weight: u32,
    ) -> Result<
        (
            enclave_federation::ListedServer,
            Vec<enclave_federation::ListedWitness>,
        ),
        enclave_server::ServerError,
    > {
        let mut rng = enclave_crypto::rng::HedgedRng::new()?;
        let identity = enclave_crypto::sig::CompositeSigningKey::generate(&mut rng)?;
        let id = enclave_federation::server_id(identity.public());
        self.add_server(enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            effort_username: 1,
            effort_inbox: 1,
            ..Default::default()
        })?;
        let policy =
            self.enable_usernames(&id, domain)
                .ok_or(enclave_server::ServerError::Crypto(
                    enclave_crypto::Error::Rng,
                ))?;
        let info = policy
            .by_server(&id)
            .cloned()
            .ok_or(enclave_server::ServerError::Crypto(
                enclave_crypto::Error::Rng,
            ))?;
        let listed = enclave_federation::ListedServer {
            identity: identity.public().clone(),
            domain: domain.into(),
            operator: info.operator.clone(),
            family: format!("family-{domain}"),
            nym_address: String::new(),
            onion: String::new(),
            weight,
            kt: Some(enclave_federation::KtKeys {
                head_key: info.head_key,
                vrf_public: info.vrf_public,
            }),
        };
        let witnesses = policy
            .witnesses
            .witnesses
            .into_iter()
            .map(|(_, key, operator)| enclave_federation::ListedWitness {
                key,
                operator: format!("{operator}@{domain}"),
                family: format!("witness-family-{domain}"),
                url: String::new(),
            })
            .collect();
        if let Ok(mut m) = self.identities.lock() {
            m.insert(id, (domain.to_string(), identity));
        }
        self.publish_descriptor(&id, "", true)
            .ok_or(enclave_server::ServerError::Crypto(
                enclave_crypto::Error::Rng,
            ))?;
        Ok((listed, witnesses))
    }

    /// Have federated server `id` sign a descriptor (valid two days, its
    /// current request key, `nym_address`) and serve it, committing its
    /// digest to its key-transparency log if `commit` (as a real server
    /// always does; `false` simulates a server showing a descriptor its log
    /// doesn't carry).
    pub fn publish_descriptor(
        &self,
        id: &ServerId,
        nym_address: &str,
        commit: bool,
    ) -> Option<enclave_federation::ServerDescriptor> {
        let now = self.now();
        let ids = self.identities.lock().ok()?;
        let (domain, identity) = ids.get(id)?;
        let mut rng = enclave_crypto::rng::HedgedRng::new().ok()?;
        self.with_server(id, |s| {
            let kt = s.kt_info().map(|i| enclave_federation::KtKeys {
                head_key: i.head_key,
                vrf_public: i.vrf_public,
            });
            let d = enclave_federation::ServerDescriptor::sign(
                identity,
                domain,
                &format!("operator-{domain}"),
                &format!("family-{domain}"),
                nym_address,
                "",
                enclave_federation::Policy::default(),
                kt,
                &[s.public_key()?],
                &s.blob_issuers(now),
                now,
                now + 2 * 86_400,
                &mut rng,
            )
            .ok()?;
            s.set_descriptor(d.encode());
            if commit {
                s.commit_descriptor(d.digest(), now)?.ok()?;
            }
            Some(d)
        })?
    }

    /// Turn on usernames for server `id` under `domain`, with a development
    /// key-transparency log and in-process witnesses. Returns what clients pin.
    pub fn enable_usernames(&self, id: &ServerId, domain: &str) -> Option<enclave_kt::KtPolicy> {
        let (svc, policy) = enclave_kt::KtService::start_dev(*id, domain).ok()?;
        self.with_server(id, |s| s.enable_kt(svc))?;
        Some(policy)
    }

    /// Move simulated time forward (clients and servers see it).
    pub fn advance(&self, secs: u64) {
        if let Ok(mut o) = self.offset.lock() {
            *o += secs;
        }
    }

    /// Current simulated time.
    pub fn now(&self) -> u64 {
        let sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        sys + self.offset.lock().map(|o| *o).unwrap_or(0)
    }

    /// Run `f` with a server (for inspecting what it stores).
    pub fn with_server<R>(&self, id: &ServerId, f: impl FnOnce(&mut Server) -> R) -> Option<R> {
        let mut m = self.servers.lock().ok()?;
        m.get_mut(id).map(f)
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        let now = self.now();
        let mut m = self
            .servers
            .lock()
            .map_err(|_| NetError::Unavailable("poisoned"))?;
        let s = m
            .get_mut(server)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        Ok(s.handle(&request, now))
    }

    fn now(&self) -> u64 {
        LocalTransport::now(self)
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<ServerKey> {
        let m = self
            .servers
            .lock()
            .map_err(|_| NetError::Unavailable("poisoned"))?;
        m.get(server)
            .and_then(Server::public_key)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))
    }
}
