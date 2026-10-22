//! The foundation's server list on the client (`docs/12-servers.md` §4.1).
//!
//! The app supplies the foundation's public key at every start (it is
//! built into the app). The client then holds the newest list it has
//! verified, kept in the store across restarts: from the app's build, from
//! a file during development, or fetched from the home server
//! (`DirKind::ServerList`). A list is taken only if both foundation
//! signatures verify and its sequence number is higher than the one held,
//! so a server can't roll a client back to an older list. The
//! key-transparency pins come from the list, merged with any the app adds
//! (development servers).
//!
//! A server's descriptor (§4.3) is fetched from the server itself and
//! taken only if it is self-signed by the identity the server id names
//! (and the list, if it lists the server), and, for a server with a pinned
//! log, if its digest is the one that log commits to under the witness
//! quorum. So a server can't show one client a descriptor it doesn't
//! show everyone.

use super::Client;
use crate::{CoreError, Result};
use enclave_federation::{FedError, FoundationPublic, ServerDescriptor, ServerList};
use enclave_kt::{KtPolicy, LookupReply, verify_descriptor_lookup};
use enclave_net::transport::Route;
use enclave_rpc::api::{self, DirAction, DirKind};

/// Store namespace (not in backups: the list is public and comes back on
/// its own).
pub(crate) const NS_SERVERS: &str = "servers";
const KEY_LIST: &[u8] = b"list";
/// `desc` ‖ server id: the last descriptor checked for that server.
const KEY_DESCRIPTOR: &[u8] = b"desc";

/// What became of a list offered to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListUpdate {
    /// Taken: the new sequence number.
    Updated(u64),
    /// Not newer than the list held (or the same one).
    Unchanged,
}

impl Client {
    /// The foundation's public key, from the app's build. Loads the list
    /// held in the store, if any, and re-derives the pins.
    pub fn set_foundation(&mut self, key: FoundationPublic) -> Result<()> {
        self.foundation = Some(key);
        if let Some(b) = self.store.get(NS_SERVERS, KEY_LIST)? {
            // Already accepted once: check the signatures again, not the
            // expiry (an old list beats none until a newer one arrives).
            if let Some(k) = &self.foundation
                && let Ok(list) = ServerList::verify(&b, k, 0, 0)
            {
                self.servers = Some(list);
            }
        }
        self.apply_pins();
        self.apply_routes();
        Ok(())
    }

    /// Offer a signed list (built into the app, read from a file, or
    /// fetched). Refused if it doesn't verify under the foundation key or
    /// has expired; ignored if it isn't newer than the one held.
    pub fn offer_server_list(&mut self, bytes: &[u8]) -> Result<ListUpdate> {
        let key = self.foundation.clone().ok_or(CoreError::NotFound)?;
        let held = self.servers.as_ref().map_or(0, |l| l.seq);
        let list = match ServerList::verify(bytes, &key, self.now(), held) {
            Ok(l) => l,
            Err(enclave_federation::FedError::Stale) => return Ok(ListUpdate::Unchanged),
            Err(e) => return Err(CoreError::Federation(e)),
        };
        self.store.put(NS_SERVERS, KEY_LIST, bytes, &mut self.rng)?;
        let seq = list.seq;
        self.servers = Some(list);
        self.apply_pins();
        self.apply_routes();
        Ok(ListUpdate::Updated(seq))
    }

    /// Fetch the list the home server mirrors and offer it.
    pub async fn refresh_server_list(&mut self) -> Result<ListUpdate> {
        let now = self.now();
        let server = self.profile.server;
        let bytes = self
            .rpc
            .dir_get(
                &server,
                DirKind::ServerList,
                DirAction::Get,
                [0; 32],
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        self.offer_server_list(&bytes)
    }

    /// Fetch server `id`'s descriptor and check it (see the module notes).
    /// Kept in the store; [`Self::server_descriptor`] returns it later.
    pub async fn fetch_descriptor(&mut self, id: &[u8; 16]) -> Result<ServerDescriptor> {
        // The server signs a new descriptor at each daily rotation and
        // then commits it: one retry covers a fetch between the two.
        let mut result = Err(CoreError::Federation(FedError::NotLogged));
        for _ in 0..2 {
            result = self.fetch_descriptor_once(id).await;
            if !matches!(result, Err(CoreError::Federation(FedError::NotLogged))) {
                break;
            }
        }
        let d = result?;
        // The descriptor names the server's ingress as it is now.
        if !d.nym_address.is_empty() {
            self.rpc.set_route(*id, Route::Nym(d.nym_address.clone()));
        }
        // Its onion service: the route to it (RFC 0010), or, beside a Nym
        // route, the fallback used only if the user chooses it
        // (`docs/09-transport.md` §7).
        if let Some(r) = Route::parse(&format!("onion:{}", d.onion)) {
            self.rpc.set_route(*id, r);
        }
        let key = [KEY_DESCRIPTOR, id.as_slice()].concat();
        self.store
            .put(NS_SERVERS, &key, &d.encode(), &mut self.rng)?;
        Ok(d)
    }

    async fn fetch_descriptor_once(&mut self, id: &[u8; 16]) -> Result<ServerDescriptor> {
        let now = self.now();
        let bytes = self
            .rpc
            .dir_get(
                id,
                DirKind::Descriptor,
                DirAction::Get,
                [0; 32],
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        let d = ServerDescriptor::decode(&bytes).map_err(CoreError::Federation)?;
        d.verify(now).map_err(CoreError::Federation)?;
        if d.id() != *id {
            return Err(CoreError::Federation(FedError::WrongId));
        }
        if let Some(listed) = self.servers.as_ref().and_then(|l| l.server(id))
            && listed.identity != d.identity
        {
            return Err(CoreError::Federation(FedError::WrongId));
        }
        let Some(info) = self.kt.as_ref().and_then(|p| p.by_server(id)).cloned() else {
            // No pinned log (a development server): the self-certifying id
            // is all there is to check.
            return Ok(d);
        };
        let witnesses = self
            .kt
            .as_ref()
            .map(|p| p.witnesses.clone())
            .ok_or(CoreError::NotFound)?;
        if d.kt.as_ref().is_some_and(|k| k.head_key != info.head_key) {
            return Err(CoreError::Federation(FedError::NotLogged));
        }
        let reply = self
            .rpc
            .dir_get(
                id,
                DirKind::Username,
                DirAction::Get,
                api::DESCRIPTOR_LOOKUP_KEY,
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
            .map_err(|e| match e {
                CoreError::Server(_) => CoreError::Federation(FedError::NotLogged),
                e => e,
            })?;
        let reply =
            LookupReply::decode(&reply).map_err(|_| CoreError::Federation(FedError::NotLogged))?;
        let (digest, trusted) = verify_descriptor_lookup(
            &witnesses,
            &info.head_key,
            &info.operator,
            &info.vrf_public,
            &reply.head,
            reply.proof,
            now,
        )
        .map_err(|_| CoreError::Federation(FedError::NotLogged))?;
        self.record_head(&reply.head)?;
        self.observe_trusted_time(trusted, now)?;
        if digest != enclave_crypto::hash::sha3_512(&bytes) {
            return Err(CoreError::Federation(FedError::NotLogged));
        }
        Ok(d)
    }

    /// The last descriptor [`Self::fetch_descriptor`] accepted for `id`
    /// (it may have expired since).
    pub fn server_descriptor(&self, id: &[u8; 16]) -> Result<Option<ServerDescriptor>> {
        let key = [KEY_DESCRIPTOR, id.as_slice()].concat();
        Ok(self
            .store
            .get(NS_SERVERS, &key)?
            .and_then(|b| ServerDescriptor::decode(&b).ok()))
    }

    /// The list held, if any.
    pub fn server_list(&self) -> Option<&ServerList> {
        self.servers.as_ref()
    }

    /// The domain of server `id`, from the list or the pins.
    pub fn server_domain(&self, id: &[u8; 16]) -> Option<String> {
        self.servers
            .as_ref()
            .and_then(|l| l.server(id))
            .map(|s| s.domain.clone())
            .or_else(|| {
                self.kt
                    .as_ref()
                    .and_then(|p| p.by_server(id))
                    .map(|i| i.domain.clone())
            })
    }

    /// Reach every listed server at its onion service through Tor (RFC
    /// 0010) and at its ingress's Nym address (a transport without the
    /// mixnet ignores that), the descriptor's onion service when one is
    /// held (it may be newer than the list's).
    fn apply_routes(&self) {
        for s in self.servers.iter().flat_map(|l| &l.servers) {
            let id = enclave_federation::server_id(&s.identity);
            if !s.nym_address.is_empty() {
                self.rpc.set_route(id, Route::Nym(s.nym_address.clone()));
            }
            if let Some(r) = Route::parse(&format!("onion:{}", s.onion)) {
                self.rpc.set_route(id, r);
            }
            if let Ok(Some(d)) = self.server_descriptor(&id)
                && let Some(r) = Route::parse(&format!("onion:{}", d.onion))
            {
                self.rpc.set_route(id, r);
            }
        }
    }

    /// Pins from the list, merged with the ones the app added.
    pub(crate) fn apply_pins(&mut self) {
        let mut pins = self.extra_pins.clone();
        if let Some(l) = &self.servers {
            let from_list = KtPolicy::from_server_list(l);
            pins = Some(match pins {
                Some(mut p) => {
                    p.merge(from_list);
                    p
                }
                None => from_list,
            });
        }
        self.kt = pins;
    }
}
