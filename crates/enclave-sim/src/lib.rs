//! In-process network simulator and a minimal client harness.
//!
//! The harness drives real protocol code (`enclave-proto`) against real server
//! code (`enclave-server`) through real sealed requests (`enclave-rpc`); only
//! the transport is a function call. It is the reference for how
//! `enclave-core` uses the lower layers.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod local;
pub use local::LocalTransport;

use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::McEliecePublic;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::bundle::{Bundle, PrekeyStore};
use enclave_proto::envelope;
use enclave_proto::eqxdh::{self, InitiatorIdentity, Local, ManifestResolver, Mode, Peer};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{DeviceEntry, Manifest, Role, SignedManifest};
use enclave_proto::ratchet::Session;
use enclave_proto::recovery::RecoverySecret;
use enclave_rpc::ServerKey;
use enclave_rpc::api::{
    self, DirAction, DirKind, DirReply, DirRequest, FLAG_CREATE, FLAG_FOUND, FLAG_REQUEST_INBOX,
    Status,
};
use enclave_server::{Server, device_key, manifest_key};
use enclave_tokens::TokenIssuer;
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::collections::HashMap;

/// Simulated clock.
pub const T0: u64 = 1_790_000_000;

/// Proof-of-work effort the simulated servers ask to create an inbox.
pub const INBOX_EFFORT: u32 = 1;

/// A set of servers addressed by id.
pub struct Network {
    /// Servers.
    pub servers: HashMap<[u8; 16], Server>,
    /// Current time.
    pub now: u64,
    /// Request-inbox proof-of-work effort per server (published in descriptors).
    pub efforts: HashMap<[u8; 16], u32>,
}

impl Network {
    /// Empty network.
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
            now: T0,
            efforts: HashMap::new(),
        }
    }

    /// Add a server.
    pub fn add_server(&mut self, id: [u8; 16], effort_request: u32) {
        let cfg = enclave_server::Config {
            id,
            effort_request,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            effort_inbox: INBOX_EFFORT,
            ..Default::default()
        };
        self.servers
            .insert(id, Server::new(cfg, (self.now / 86_400) as u32).unwrap());
        self.efforts.insert(id, effort_request);
    }

    /// Public request key of a server.
    pub fn key(&self, id: &[u8; 16]) -> ServerKey {
        self.servers[id].public_key().unwrap()
    }

    /// Send a request and return `(status, flags, reply header, reply envelope)`.
    pub fn call(
        &mut self,
        server: &[u8; 16],
        h: RequestHeader,
        env: &[u8],
        rng: &mut HedgedRng,
    ) -> (Status, u8, RequestHeader, Vec<u8>) {
        let key = self.key(server);
        let now = self.now;
        let (bytes, ex) = if h.op == Op::Poll || h.op == Op::Ack {
            enclave_rpc::seal_poll(&key, &h, rng).unwrap()
        } else {
            enclave_rpc::seal_request(&key, &h, env, rng).unwrap()
        };
        let reply = self.servers.get_mut(server).unwrap().handle(&bytes, now);
        let (rh, renv) = ex.open_reply(&reply).unwrap();
        (Status::from_u8(rh.flags), rh.flags, rh, renv)
    }

    fn dir(
        &mut self,
        server: &[u8; 16],
        req: DirRequest,
        rng: &mut HedgedRng,
    ) -> (Status, Option<DirReply>) {
        let env = api::frame(&req.encode(), rng).unwrap();
        let h = RequestHeader {
            op: Op::Directory,
            flags: 0,
            mailbox: [0; 32],
            token: [0; 32],
        };
        let (s, _, _, renv) = self.call(server, h, &env, rng);
        let reply = api::unframe(&renv)
            .ok()
            .filter(|p| !p.is_empty())
            .and_then(|p| DirReply::decode(p).ok());
        (s, reply)
    }

    /// Upload an object to a server's directory in chunks.
    pub fn dir_put(
        &mut self,
        server: &[u8; 16],
        kind: DirKind,
        key: [u8; 32],
        proof: [u8; 32],
        data: &[u8],
        rng: &mut HedgedRng,
    ) -> Status {
        let chunks = api::chunks(data);
        let total = chunks.len() as u32;
        let mut last = Status::Ok;
        for (i, c) in chunks.iter().enumerate() {
            let req = DirRequest {
                kind,
                action: DirAction::Put,
                key,
                index: i as u32,
                total,
                proof,
                data: c.to_vec(),
            };
            last = self.dir(server, req, rng).0;
        }
        last
    }

    /// Download an object (following chunk totals).
    pub fn dir_get(
        &mut self,
        server: &[u8; 16],
        kind: DirKind,
        action: DirAction,
        key: [u8; 32],
        proof: [u8; 32],
        rng: &mut HedgedRng,
    ) -> Option<Vec<u8>> {
        let first = DirRequest {
            kind,
            action,
            key,
            index: 0,
            total: 0,
            proof,
            data: vec![],
        };
        let (s, r) = self.dir(server, first, rng);
        let r = r.filter(|_| s == Status::Ok)?;
        let mut out = r.data;
        let (key, action) = if action == DirAction::Claim {
            (r.claim, DirAction::Get)
        } else {
            (key, action)
        };
        for i in 1..r.total {
            let req = DirRequest {
                kind,
                action,
                key,
                index: i,
                total: 0,
                proof,
                data: vec![],
            };
            let (_, rr) = self.dir(server, req, rng);
            out.extend_from_slice(&rr?.data);
        }
        Some(out)
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

/// Seal a large object as a sequence of EnclaveSeal segments.
pub fn seal_large(key: &SealKey, data: &[u8], rng: &mut HedgedRng) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, seg) in data.chunks(60_000).enumerate() {
        let s = seal::seal(key, &(i as u64).to_be_bytes(), seg, rng).unwrap();
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(&s);
    }
    out
}

/// Inverse of [`seal_large`].
pub fn open_large(key: &SealKey, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0;
    let mut i = 0u64;
    while off < data.len() {
        let n = u32::from_be_bytes(data.get(off..off + 4)?.try_into().ok()?) as usize;
        off += 4;
        let seg = seal::open(key, &i.to_be_bytes(), data.get(off..off + n)?).ok()?;
        out.extend_from_slice(&seg);
        off += n;
        i += 1;
    }
    Some(out)
}

/// Tokens a contact gave us, with their server and inbox address.
pub type PeerInbox = (Vec<[u8; 32]>, [u8; 16], [u8; 32]);

/// What a QR code or invite link carries.
#[derive(Clone)]
pub struct ContactCard {
    /// Root public key.
    pub root: [u8; 64],
    /// Home server.
    pub server: [u8; 16],
    /// Request inbox address.
    pub request_inbox: [u8; 32],
    /// Where the encrypted McEliece vault key lives.
    pub vault_locator: [u8; 32],
    /// Key that decrypts it.
    pub vault_key: [u8; 32],
}

/// One device of a simulated user.
pub struct SimDevice {
    /// Keys.
    pub keys: DeviceKeys,
    /// Prekey secrets.
    pub prekeys: PrekeyStore,
    /// Sessions by (peer root, peer device).
    pub sessions: HashMap<([u8; 64], [u8; 16]), Session>,
    /// Inbox cursor.
    pub cursor: u64,
    /// Request-inbox cursor.
    pub request_cursor: u64,
}

/// A simulated user with one account and several devices.
pub struct SimUser {
    /// Account keys.
    pub account: AccountKeys,
    /// Devices.
    pub devices: Vec<SimDevice>,
    /// Current manifest.
    pub manifest: Manifest,
    /// Signed manifest.
    pub signed: SignedManifest,
    /// Home server.
    pub server: [u8; 16],
    /// Account inbox address.
    pub inbox: [u8; 32],
    /// Request inbox address.
    pub request_inbox: [u8; 32],
    /// Owner secret of the account inbox.
    pub inbox_owner: [u8; 32],
    /// Owner secret of the request inbox.
    pub request_owner: [u8; 32],
    /// Vault locator and key.
    pub vault: ([u8; 32], [u8; 32]),
    /// Tokens we issued to each contact (by root).
    pub issuers: HashMap<[u8; 64], TokenIssuer>,
    /// Tokens contacts gave us for their inboxes, by root.
    pub tokens_for: HashMap<[u8; 64], PeerInbox>,
    /// Verified manifests of contacts.
    pub contacts: HashMap<[u8; 64], Manifest>,
}

/// Content of a first message or reply: our inbox address and write tokens.
pub fn encode_hello(
    server: &[u8; 16],
    inbox: &[u8; 32],
    tokens: &[[u8; 32]],
    text: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(server);
    v.extend_from_slice(inbox);
    v.push(tokens.len() as u8);
    for t in tokens {
        v.extend_from_slice(t);
    }
    v.extend_from_slice(text);
    v
}

/// Parse [`encode_hello`].
pub fn decode_hello(b: &[u8]) -> ([u8; 16], [u8; 32], Vec<[u8; 32]>, Vec<u8>) {
    let server: [u8; 16] = b[..16].try_into().unwrap();
    let inbox: [u8; 32] = b[16..48].try_into().unwrap();
    let n = b[48] as usize;
    let tokens = (0..n)
        .map(|i| b[49 + 32 * i..81 + 32 * i].try_into().unwrap())
        .collect();
    (server, inbox, tokens, b[49 + 32 * n..].to_vec())
}

struct Resolver<'a>(&'a HashMap<[u8; 64], Manifest>);

impl ManifestResolver for Resolver<'_> {
    fn resolve(&mut self, id: &InitiatorIdentity) -> enclave_proto::Result<Manifest> {
        self.0
            .get(&id.root)
            .cloned()
            .ok_or(enclave_proto::ProtoError::Missing)
    }
}

impl SimUser {
    /// Create a user, publish everything to its home server.
    pub fn create(
        net: &mut Network,
        server: [u8; 16],
        n_devices: usize,
        rng: &mut HedgedRng,
    ) -> Self {
        let rs = RecoverySecret::generate(rng).unwrap();
        let account = AccountKeys::create(&rs, rng).unwrap();
        let mut devices = Vec::new();
        for _ in 0..n_devices {
            devices.push(SimDevice {
                keys: DeviceKeys::generate(rng).unwrap(),
                prekeys: PrekeyStore::default(),
                sessions: HashMap::new(),
                cursor: 0,
                request_cursor: 0,
            });
        }
        let request_inbox: [u8; 32] = rng.array("sim").unwrap();
        let inbox: [u8; 32] = rng.array("sim").unwrap();
        let inbox_owner: [u8; 32] = rng.array("sim").unwrap();
        let request_owner: [u8; 32] = rng.array("sim").unwrap();
        let mut manifest =
            Manifest::genesis(&account, &devices[0].keys, net.now, request_inbox.to_vec());
        for d in &devices[1..] {
            manifest
                .devices
                .push(DeviceEntry::for_device(&d.keys, Role::Linked, net.now));
        }
        let signed = manifest.sign(&account, rng).unwrap();

        // Inboxes.
        for (addr, owner, flags) in [
            (inbox, inbox_owner, FLAG_CREATE),
            (
                request_inbox,
                request_owner,
                FLAG_CREATE | FLAG_REQUEST_INBOX,
            ),
        ] {
            let h = RequestHeader {
                op: Op::RegisterTokens,
                flags,
                mailbox: addr,
                token: owner,
            };
            let ctx = api::pow_context_inbox(&addr, net.now / 86_400);
            let proof = enclave_tokens::solve(&ctx, INBOX_EFFORT, rng).unwrap();
            let (s, ..) = net.call(&server, h, &api::frame(&proof.0, rng).unwrap(), rng);
            assert_eq!(s, Status::Ok);
        }
        // Manifest, prekeys, vault.
        let mk = manifest_key(&account.root_public.0);
        assert_eq!(
            net.dir_put(
                &server,
                DirKind::Manifest,
                mk,
                [0; 32],
                &signed.to_bytes(),
                rng
            ),
            Status::Ok
        );
        for d in devices.iter_mut() {
            let publication = d.prekeys.publish(&d.keys, net.now, rng).unwrap();
            let s = net.dir_put(
                &server,
                DirKind::Bundle,
                device_key(&d.keys.id),
                [0; 32],
                &publication.encode(),
                rng,
            );
            assert_eq!(s, Status::Ok);
        }
        let vault_locator: [u8; 32] = rng.array("sim").unwrap();
        let vault_key: [u8; 32] = rng.array("sim").unwrap();
        let vault_owner: [u8; 32] = rng.array("sim").unwrap();
        let blob = seal_large(
            &SealKey::from_bytes(vault_key),
            &account.vault_public.0[..],
            rng,
        );
        assert_eq!(
            net.dir_put(
                &server,
                DirKind::Vault,
                vault_locator,
                vault_owner,
                &blob,
                rng
            ),
            Status::Ok
        );

        Self {
            account,
            devices,
            manifest,
            signed,
            server,
            inbox,
            request_inbox,
            inbox_owner,
            request_owner,
            vault: (vault_locator, vault_key),
            issuers: HashMap::new(),
            tokens_for: HashMap::new(),
            contacts: HashMap::new(),
        }
    }

    /// Our contact card (what the QR code shows).
    pub fn card(&self) -> ContactCard {
        ContactCard {
            root: self.account.root_public.0,
            server: self.server,
            request_inbox: self.request_inbox,
            vault_locator: self.vault.0,
            vault_key: self.vault.1,
        }
    }

    /// Issue `n` write tokens for `contact` and register their hashes.
    pub fn issue_tokens(
        &mut self,
        net: &mut Network,
        contact: [u8; 64],
        n: usize,
        rng: &mut HedgedRng,
    ) -> Vec<[u8; 32]> {
        let issuer = self
            .issuers
            .entry(contact)
            .or_insert_with(|| TokenIssuer::new(rng).unwrap());
        let (toks, hashes) = issuer.issue(n, &self.inbox);
        let batch = enclave_tokens::registration_batch(&hashes, 8, rng).unwrap();
        let payload: Vec<u8> = batch.concat();
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: 0,
            mailbox: self.inbox,
            token: self.inbox_owner,
        };
        let (s, ..) = net.call(&self.server, h, &api::frame(&payload, rng).unwrap(), rng);
        assert_eq!(s, Status::Ok);
        toks
    }

    /// Add a contact from their card: fetch and verify manifest, vault and
    /// bundles, then send a first message to each of their devices.
    pub fn add_contact(
        &mut self,
        net: &mut Network,
        card: &ContactCard,
        text: &[u8],
        rng: &mut HedgedRng,
    ) {
        let server = card.server;
        let root = enclave_crypto::sig::RootPublic(card.root);
        let mb = net
            .dir_get(
                &server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&card.root),
                [0; 32],
                rng,
            )
            .unwrap();
        let peer_manifest = SignedManifest::from_bytes(&mb)
            .unwrap()
            .verify(&root, net.now)
            .unwrap();
        let vb = net
            .dir_get(
                &server,
                DirKind::Vault,
                DirAction::Get,
                card.vault_locator,
                [0; 32],
                rng,
            )
            .unwrap();
        let vault_bytes = open_large(&SealKey::from_bytes(card.vault_key), &vb).unwrap();
        let vault = McEliecePublic::from_slice(&vault_bytes).unwrap();
        assert_eq!(
            sha3_512(&vault.0[..]),
            peer_manifest.vault_hash,
            "vault matches the manifest commitment"
        );

        let tokens = self.issue_tokens(net, card.root, 16, rng);
        let hello = encode_hello(&self.server, &self.inbox, &tokens, text);
        for dev in &peer_manifest.devices {
            let key = device_key(&dev.id);
            let day = net.now / 86_400;
            let proof = enclave_tokens::solve(&api::pow_context_claim(&key, day), 1, rng).unwrap();
            let bb = net
                .dir_get(
                    &server,
                    DirKind::Bundle,
                    DirAction::Claim,
                    key,
                    proof.0,
                    rng,
                )
                .unwrap();
            let bundle = Bundle::decode(&bb).unwrap();
            bundle.verify(&dev.signing, net.now).unwrap();
            // Our device 0 initiates to each of their devices.
            let me = &self.devices[0];
            let local = Local {
                account: &self.account,
                device: &me.keys,
                manifest: &self.manifest,
                locator: b"sim",
            };
            let peer = Peer {
                manifest: &peer_manifest,
                device: dev,
                bundle: &bundle,
                vault: Some(&vault),
            };
            let init = eqxdh::initiate(&local, &peer, Mode::OffTheRecord, None, rng).unwrap();
            let mut session = init.session;
            let env = envelope::seal_request(&init.message, &mut session, &hello, rng).unwrap();
            let ctx =
                api::pow_context_request(&card.request_inbox, net.now / 86_400, &sha3_512(&env));
            let effort = net.efforts.get(&server).copied().unwrap_or(1);
            let proof = enclave_tokens::solve(&ctx, effort, rng).unwrap();
            let h = RequestHeader {
                op: Op::WriteRequest,
                flags: 0,
                mailbox: card.request_inbox,
                token: proof.0,
            };
            let (s, ..) = net.call(&server, h, &env, rng);
            assert_eq!(s, Status::Ok, "request write accepted");
            self.devices[0]
                .sessions
                .insert((card.root, dev.id), session);
        }
        self.contacts.insert(card.root, peer_manifest);
    }

    /// Poll one mailbox from `cursor`, returning envelopes and the new cursor.
    fn poll(
        net: &mut Network,
        server: &[u8; 16],
        mailbox: [u8; 32],
        owner: &[u8; 32],
        mut cursor: u64,
        rng: &mut HedgedRng,
    ) -> (Vec<Vec<u8>>, u64) {
        let cred = api::read_credential(owner);
        let mut out = Vec::new();
        loop {
            let mut token = [0u8; 32];
            token[..24].copy_from_slice(&cred);
            token[24..].copy_from_slice(&cursor.to_be_bytes());
            let h = RequestHeader {
                op: Op::Poll,
                flags: 0,
                mailbox,
                token,
            };
            let (s, flags, rh, env) = net.call(server, h, &[], rng);
            assert_eq!(s, Status::Ok);
            if flags & FLAG_FOUND == 0 {
                break;
            }
            cursor = u64::from_be_bytes(rh.token[24..].try_into().unwrap());
            out.push(env);
        }
        (out, cursor)
    }

    /// Device `d` processes its request inbox. Returns texts received.
    pub fn process_requests(
        &mut self,
        net: &mut Network,
        d: usize,
        rng: &mut HedgedRng,
    ) -> Vec<Vec<u8>> {
        let (envs, cursor) = Self::poll(
            net,
            &self.server,
            self.request_inbox,
            &self.request_owner,
            self.devices[d].request_cursor,
            rng,
        );
        self.devices[d].request_cursor = cursor;
        let mut texts = Vec::new();
        for env in envs {
            let Ok(msg) = envelope::request_initial(&env) else {
                continue;
            };
            // Is it addressed to this device? (its signed prekey id)
            if !self.devices[d].prekeys.signed.contains_key(&msg.spk_id) {
                continue;
            }
            let dev = &mut self.devices[d];
            let local = Local {
                account: &self.account,
                device: &dev.keys,
                manifest: &self.manifest,
                locator: b"sim",
            };
            // In the sim, the initiator's manifest is fetched out of band into
            // `contacts` by the test before processing.
            let mut resolver = Resolver(&self.contacts);
            let Ok(resp) = eqxdh::respond(&local, &mut dev.prekeys, &msg, None, &mut resolver, rng)
            else {
                continue;
            };
            let mut session = resp.session;
            let content = envelope::open_request(&mut session, &env, rng).unwrap();
            let (srv, inbox, tokens, text) = decode_hello(&content);
            self.tokens_for
                .entry(resp.identity.root)
                .or_insert((Vec::new(), srv, inbox))
                .0
                .extend(tokens);
            dev.sessions
                .insert((resp.identity.root, resp.identity.device), session);
            texts.push(text);
        }
        texts
    }

    /// Send `text` to every device of `peer` with one envelope via their inbox.
    pub fn send(
        &mut self,
        net: &mut Network,
        d: usize,
        peer: [u8; 64],
        text: &[u8],
        rng: &mut HedgedRng,
    ) -> Status {
        let (tokens, server, inbox) = self.tokens_for.get_mut(&peer).expect("no tokens for peer");
        let token = tokens.pop().expect("out of tokens");
        let (server, inbox) = (*server, *inbox);
        let dev = &mut self.devices[d];
        let mut sessions: Vec<&mut Session> = dev
            .sessions
            .iter_mut()
            .filter(|((r, _), _)| *r == peer)
            .map(|(_, s)| s)
            .collect();
        let carrier = sessions.iter().position(|s| s.wants_pq_slot());
        let env = envelope::seal_direct(&mut sessions, text, carrier, rng).unwrap();
        assert_eq!(env.len(), ENVELOPE_LEN);
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: inbox,
            token,
        };
        net.call(&server, h, &env, rng).0
    }

    /// Device `d` reads its account inbox. Returns texts.
    pub fn receive(&mut self, net: &mut Network, d: usize, rng: &mut HedgedRng) -> Vec<Vec<u8>> {
        let (envs, cursor) = Self::poll(
            net,
            &self.server,
            self.inbox,
            &self.inbox_owner,
            self.devices[d].cursor,
            rng,
        );
        self.devices[d].cursor = cursor;
        let vault = &self.account.vault;
        let dev = &mut self.devices[d];
        let mut out = Vec::new();
        for env in envs {
            let mut sessions: Vec<&mut Session> = dev.sessions.values_mut().collect();
            if let Ok(o) = envelope::open_direct(&mut sessions, &env, Some(vault), rng) {
                out.push(o.content);
            }
        }
        out
    }

    /// Record tokens a contact sent us in a reply.
    pub fn accept_hello(&mut self, peer: [u8; 64], content: &[u8]) -> Vec<u8> {
        let (srv, inbox, tokens, text) = decode_hello(content);
        self.tokens_for
            .entry(peer)
            .or_insert((Vec::new(), srv, inbox))
            .0
            .extend(tokens);
        text
    }
}
