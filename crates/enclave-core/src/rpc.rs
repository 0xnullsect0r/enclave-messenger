//! Sealed request/reply helpers over a [`Transport`].

use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use enclave_rpc::api::{
    self, DirAction, DirKind, DirReply, DirRequest, FLAG_DEFER, FLAG_FOUND, Status,
};
use enclave_wire::{Op, RequestHeader};
use std::collections::HashMap;
use std::sync::Arc;

/// Reply to one call.
pub(crate) struct Reply {
    pub status: Status,
    pub flags: u8,
    pub header: RequestHeader,
    pub envelope: Vec<u8>,
}

/// Proof-of-work efforts tried in order when a server asks for more.
pub(crate) const EFFORT_LADDER: [u32; 7] = [8, 16, 64, 256, 1024, 4096, 16_384];

/// A sealed request on its way: resolves once it was sent and answered,
/// or dropped.
pub type Sending = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// Status polls for one answer before giving up (`Rpc::fetch_answer`).
/// Each is a round trip through the mixnet (and, shaped, waits for its
/// poll slot), so they pace themselves: a minute or more in all.
const STATUS_TRIES: u32 = 120;

pub(crate) struct Rpc {
    transport: Arc<dyn Transport>,
    keys: HashMap<ServerId, ServerKey>,
}

impl Rpc {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            keys: HashMap::new(),
        }
    }

    /// Reach `server` by `route` from now on ([`Transport::set_route`]).
    pub fn set_route(&self, server: ServerId, route: enclave_net::transport::Route) {
        self.transport.set_route(server, route);
    }

    /// The transport, for what isn't a server request (the credential
    /// gate, the mixnet client's tickets).
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Current time, from the transport (simulations move it).
    pub fn now(&self) -> u64 {
        self.transport.now()
    }

    /// Start or end a bulk transfer ([`Transport::set_bulk`]).
    pub fn bulk(&self, on: bool) {
        self.transport.set_bulk(on);
    }

    async fn key(&mut self, server: &ServerId, now: u64) -> Result<ServerKey> {
        let today = (now / 86_400) as u32;
        if let Some(k) = self.keys.get(server)
            && k.key_id == today
        {
            return Ok(k.clone());
        }
        let k = self.transport.server_key(server).await?;
        self.keys.insert(*server, k.clone());
        Ok(k)
    }

    pub async fn call(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Reply> {
        let key = self.key(server, now).await?;
        let (rh, renv) = if matches!(h.op, Op::Poll | Op::Ack | Op::BlobGet | Op::Status) {
            let (bytes, ex) = enclave_rpc::seal_poll(&key, &h, rng)?;
            let reply = self.transport.exchange(server, bytes).await?;
            ex.open_reply(&reply)?
        } else {
            // Every unit goes one way over the mixnet; the server keeps the
            // answer for a status poll, which comes back in the poll slot
            // like any poll reply (`docs/09-transport.md` §6.1).
            let mut h = h;
            h.flags |= FLAG_DEFER;
            let (bytes, ex) = enclave_rpc::seal_request(&key, &h, env, rng)?;
            match self.transport.exchange_deferred(server, bytes).await? {
                Some(reply) => ex.open_reply(&reply)?,
                None => self.fetch_answer(server, ex.status_id(), now, rng).await?,
            }
        };
        Ok(Reply {
            status: Status::from_u8(rh.flags),
            flags: rh.flags,
            header: rh,
            envelope: renv,
        })
    }

    /// The answer to a request sent one way: status polls until the server
    /// has it (the request may still be on its way).
    async fn fetch_answer(
        &mut self,
        server: &ServerId,
        id: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<(RequestHeader, Vec<u8>)> {
        for _ in 0..STATUS_TRIES {
            let key = self.key(server, now).await?;
            let h = RequestHeader {
                op: Op::Status,
                flags: 0,
                mailbox: id,
                token: rng.array("rpc/status-token")?,
            };
            let (bytes, ex) = enclave_rpc::seal_poll(&key, &h, rng)?;
            let reply = self.transport.exchange(server, bytes).await?;
            let (rh, env) = ex.open_reply(&reply)?;
            let waiting = rh.op == Op::Status && Status::from_u8(rh.flags) == Status::NotFound;
            if !waiting {
                return Ok((rh, env));
            }
        }
        Err(CoreError::Net(enclave_net::NetError::Unreachable(
            "no answer from the server".into(),
        )))
    }

    /// A call that must succeed.
    pub async fn call_ok(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Reply> {
        let r = self.call(server, h, env, now, rng).await?;
        if r.status != Status::Ok {
            return Err(CoreError::Server(r.status));
        }
        Ok(r)
    }

    /// A write whose answer isn't needed (a message, a self-copy, a group
    /// post): one way over the mixnet ([`Transport::exchange_oneway`]),
    /// where whether it arrived is learned from a delivery receipt. When a
    /// transport does bring the reply back, its status is checked as
    /// [`Rpc::call_ok`] would.
    pub async fn write(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let key = self.key(server, now).await?;
        let (bytes, ex) = enclave_rpc::seal_request(&key, &h, env, rng)?;
        match self.transport.exchange_oneway(server, bytes).await? {
            None => Ok(()),
            Some(reply) => {
                let (rh, _) = ex.open_reply(&reply)?;
                match Status::from_u8(rh.flags) {
                    Status::Ok => Ok(()),
                    s => Err(CoreError::Server(s)),
                }
            }
        }
    }

    /// Seal a write that may be dropped rather than add traffic
    /// ([`Transport::exchange_droppable`]), and return the sending as a
    /// future that borrows nothing, so the caller needn't wait for a slot.
    pub async fn prepare_droppable(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Sending> {
        let key = self.key(server, now).await?;
        let (bytes, ex) = enclave_rpc::seal_request(&key, &h, env, rng)?;
        let transport = Arc::clone(&self.transport);
        let server = *server;
        Ok(Box::pin(async move {
            let Some(reply) = transport.exchange_droppable_oneway(&server, bytes).await? else {
                return Ok(());
            };
            let (rh, _) = ex.open_reply(&reply)?;
            match Status::from_u8(rh.flags) {
                Status::Ok => Ok(()),
                s => Err(CoreError::Server(s)),
            }
        }))
    }

    async fn dir(
        &mut self,
        server: &ServerId,
        req: DirRequest,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<(Status, Option<DirReply>)> {
        let env = api::frame(&req.encode(), rng)?;
        let h = RequestHeader {
            op: Op::Directory,
            flags: 0,
            mailbox: [0; 32],
            token: [0; 32],
        };
        let r = self.call(server, h, &env, now, rng).await?;
        let reply = api::unframe(&r.envelope)
            .ok()
            .filter(|p| !p.is_empty())
            .and_then(|p| DirReply::decode(p).ok());
        Ok((r.status, reply))
    }

    /// Upload an object in chunks.
    pub async fn dir_put(
        &mut self,
        server: &ServerId,
        kind: DirKind,
        key: [u8; 32],
        proof: [u8; 32],
        data: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let chunks = api::chunks(data);
        let total = chunks.len() as u32;
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
            let (s, _) = self.dir(server, req, now, rng).await?;
            if s != Status::Ok {
                return Err(CoreError::Server(s));
            }
        }
        Ok(())
    }

    /// Download an object, following chunk totals.
    pub async fn dir_get(
        &mut self,
        server: &ServerId,
        kind: DirKind,
        action: DirAction,
        key: [u8; 32],
        proof: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let first = DirRequest {
            kind,
            action,
            key,
            index: 0,
            total: 0,
            proof,
            data: vec![],
        };
        let (s, r) = self.dir(server, first, now, rng).await?;
        if s != Status::Ok {
            return Err(CoreError::Server(s));
        }
        let r = r.ok_or(CoreError::Server(Status::Malformed))?;
        if r.total > 4096 {
            return Err(CoreError::TooLong);
        }
        let mut out = r.data;
        let (key, action) = if action == DirAction::Claim {
            (r.claim, DirAction::Get)
        } else if kind == DirKind::Username {
            // Later chunks of a lookup are fetched by the reply id.
            (r.claim, action)
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
            let (s, rr) = self.dir(server, req, now, rng).await?;
            if s != Status::Ok {
                return Err(CoreError::Server(s));
            }
            out.extend_from_slice(&rr.ok_or(CoreError::Server(Status::Malformed))?.data);
        }
        Ok(out)
    }

    /// Claim a device bundle, escalating proof of work as the server asks.
    pub async fn claim_bundle(
        &mut self,
        server: &ServerId,
        key: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let ctx = api::pow_context_claim(&key, now / 86_400);
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            match self
                .dir_get(
                    server,
                    DirKind::Bundle,
                    DirAction::Claim,
                    key,
                    proof.0,
                    now,
                    rng,
                )
                .await
            {
                Err(CoreError::Server(Status::Pow)) => continue,
                other => return other,
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Create an inbox (`flags` is `FLAG_CREATE`, with `FLAG_REQUEST_INBOX`
    /// for a request inbox) owned by `owner`, escalating proof of work as
    /// the server asks.
    pub async fn create_inbox(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        owner: [u8; 32],
        flags: u8,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let ctx = api::pow_context_inbox(&mailbox, now / 86_400);
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            let h = RequestHeader {
                op: Op::RegisterTokens,
                flags,
                mailbox,
                token: owner,
            };
            let env = api::frame(&proof.0, rng)?;
            match self.call(server, h, &env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Pow => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Write to a request inbox, escalating proof of work as the server asks.
    pub async fn write_request(
        &mut self,
        server: &ServerId,
        inbox: [u8; 32],
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let ctx =
            api::pow_context_request(&inbox, now / 86_400, &enclave_crypto::hash::sha3_512(env));
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            let h = RequestHeader {
                op: Op::WriteRequest,
                flags: 0,
                mailbox: inbox,
                token: proof.0,
            };
            match self.call(server, h, env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Pow => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Report the account whose request inbox is `inbox` to `server`'s
    /// operator, escalating proof of work as the server asks.
    pub async fn report(
        &mut self,
        server: &ServerId,
        inbox: [u8; 32],
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let ctx =
            api::pow_context_report(&inbox, now / 86_400, &enclave_crypto::hash::sha3_512(env));
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            let h = RequestHeader {
                op: Op::Report,
                flags: 0,
                mailbox: inbox,
                token: proof.0,
            };
            match self.call(server, h, env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Pow => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Write to a request inbox with invite capabilities instead of a proof
    /// of work: try `caps[*next..]` in order (other people may have used
    /// some), leaving `*next` after the one that worked.
    pub async fn write_invited(
        &mut self,
        server: &ServerId,
        inbox: [u8; 32],
        env: &[u8],
        caps: &[[u8; 32]],
        next: &mut usize,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        while let Some(cap) = caps.get(*next) {
            *next += 1;
            let h = RequestHeader {
                op: Op::WriteRequest,
                flags: api::FLAG_INVITE,
                mailbox: inbox,
                token: *cap,
            };
            match self.call(server, h, env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Denied => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(crate::LinkError::InviteUsed.into())
    }

    /// Fetch everything in `mailbox` after `cursor`. Returns the envelopes with
    /// the cursor after each one.
    pub async fn poll(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        owner: &[u8; 32],
        cursor: u64,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        let cred = api::read_credential(owner);
        let mut out = Vec::new();
        // Catching up on a backlog is a bulk transfer (a shaping transport
        // may then skip its clock, where the profile allows).
        let mut bulk = false;
        let r = self
            .poll_loop(server, mailbox, cred, cursor, now, rng, &mut out, &mut bulk)
            .await;
        if bulk {
            self.bulk(false);
        }
        r.map(|()| out)
    }

    #[allow(clippy::too_many_arguments)]
    async fn poll_loop(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        cred: [u8; 24],
        mut cursor: u64,
        now: u64,
        rng: &mut HedgedRng,
        out: &mut Vec<(Vec<u8>, u64)>,
        bulk: &mut bool,
    ) -> Result<()> {
        // Bounded so a hostile server cannot keep us polling forever.
        for _ in 0..1024 {
            let mut token = [0u8; 32];
            token[..24].copy_from_slice(&cred);
            token[24..].copy_from_slice(&cursor.to_be_bytes());
            let h = RequestHeader {
                op: Op::Poll,
                flags: 0,
                mailbox,
                token,
            };
            let r = self.call_ok(server, h, &[], now, rng).await?;
            if r.flags & FLAG_FOUND == 0 {
                break;
            }
            let mut c = [0u8; 8];
            c.copy_from_slice(&r.header.token[24..]);
            let next = u64::from_be_bytes(c);
            if next <= cursor {
                return Err(CoreError::Server(Status::Malformed));
            }
            cursor = next;
            out.push((r.envelope, cursor));
            if r.flags & api::FLAG_MORE != 0 && !*bulk {
                *bulk = true;
                self.bulk(true);
            }
        }
        Ok(())
    }
}
