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
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Reply to one call.
pub(crate) struct Reply {
    pub status: Status,
    pub flags: u8,
    pub header: RequestHeader,
    pub envelope: Vec<u8>,
}

/// One envelope read from a mailbox.
pub(crate) struct Polled {
    pub envelope: Vec<u8>,
    /// Its sequence number: the cursor after it.
    pub cursor: u64,
    /// The first 24 bytes of the token hash its write burned (zeros when
    /// none): which contact wrote it (`docs/09-transport.md` §3.3).
    pub hint: [u8; 24],
}

/// Proof-of-work efforts tried in order when a server asks for more.
pub(crate) const EFFORT_LADDER: [u32; 7] = [8, 16, 64, 256, 1024, 4096, 16_384];

/// A sealed request on its way: resolves once it was sent and answered,
/// or dropped.
pub type Sending = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// A chunk of an upload on its way, to the server's status for it.
type Sent = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Status>> + Send>>;
/// A chunk of a download on its way: its index, the server's status and
/// reply.
type Got = std::pin::Pin<
    Box<dyn std::future::Future<Output = (u32, Result<(Status, Option<DirReply>)>)> + Send>,
>;

/// Status polls for one answer before giving up (`Rpc::fetch_answer`).
/// Each is a round trip through the mixnet (and, shaped, waits for its
/// poll slot), so they pace themselves: a minute or more in all.
const STATUS_TRIES: u32 = 120;

/// Tries for each chunk of an upload in several.
const CHUNK_TRIES: u32 = 4;

/// Told how a transfer in several chunks goes ([`Rpc::set_progress`]):
/// which part ("Their keys"), chunks done, chunks in all.
pub type ProgressFn = Arc<dyn Fn(&'static str, u32, u32) + Send + Sync>;

/// What a directory object is, as the person reads it in a progress bar:
/// ours going up, or someone's coming down.
fn part_of(kind: DirKind, up: bool) -> &'static str {
    match (kind, up) {
        (DirKind::Vault, true) => "Your keys",
        (DirKind::Vault, false) => "Their keys",
        (DirKind::Bundle, _) => "Device keys",
        (DirKind::Manifest, _) => "Account",
        (_, true) => "Sending",
        (_, false) => "Receiving",
    }
}

pub(crate) struct Rpc {
    transport: Arc<dyn Transport>,
    progress: Option<ProgressFn>,
    keys: HashMap<ServerId, ServerKey>,
    /// The disappearing-timer clock's last reading, and when it was taken
    /// (`Rpc::timer_now`).
    timer: Mutex<Option<(u64, Instant)>>,
}

/// Envelopes read in a row from one mailbox before the rest is read as a
/// bulk transfer (`docs/09-transport.md` §6.4).
pub const BACKLOG_BULK: usize = 8;
impl Rpc {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            progress: None,
            keys: HashMap::new(),
            timer: Mutex::new(None),
        }
    }

    /// Tell `f` how each transfer in several chunks goes, from now on.
    pub fn set_progress(&mut self, f: ProgressFn) {
        self.progress = Some(f);
    }

    /// Say how a transfer of `kind` goes, `up` or down (only one in
    /// several chunks).
    fn tell_progress(&self, kind: DirKind, up: bool, done: u32, total: u32) {
        if total > 1
            && let Some(f) = &self.progress
        {
            f(part_of(kind, up), done, total);
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

    /// The time disappearing timers run on (RT-23, `docs/12-servers.md`
    /// §3.5): the device clock while it moves forward, but never behind
    /// its last reading plus the local monotonic time since. Setting the
    /// clock back doesn't stop a timer that has started, or bring back a
    /// message that has gone; the timer keeps running at the monotonic
    /// rate until the clock catches up. (A restart starts again from the
    /// device clock: the matrix's residual of a tampered offline device.)
    pub fn timer_now(&self) -> u64 {
        let wall = self.now();
        let Ok(mut last) = self.timer.lock() else {
            return wall;
        };
        let at = Instant::now();
        let (t, mark) = match *last {
            Some((t0, at0)) => {
                let secs = at.duration_since(at0).as_secs();
                let run = t0.saturating_add(secs);
                if wall > run {
                    (wall, at)
                } else {
                    // Whole seconds only, so no fraction of one is lost.
                    let mark = at0
                        .checked_add(std::time::Duration::from_secs(secs))
                        .unwrap_or(at);
                    (run, mark)
                }
            }
            None => (wall, at),
        };
        *last = Some((t, mark));
        t
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
        let key = self.key(server, now).await?;
        answer(&*self.transport, &key, server, id, rng).await
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
    #[allow(clippy::too_many_arguments)]
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
        self.dir_put_with_progress(server, kind, key, proof, data, now, rng, &|_, _| {})
            .await
    }

    /// [`Rpc::dir_put`], saying `progress(chunks answered, chunks)` as they
    /// are. The chunks go together, so the shaper's bulk bursts carry
    /// them and their answers come back in the same ticks: one at a time,
    /// each waiting for its slot and then its answer's, a vault key (about
    /// a hundred chunks) took ten minutes over Tor.
    #[allow(clippy::too_many_arguments)]
    pub async fn dir_put_with_progress(
        &mut self,
        server: &ServerId,
        kind: DirKind,
        key: [u8; 32],
        proof: [u8; 32],
        data: &[u8],
        now: u64,
        rng: &mut HedgedRng,
        progress: &(dyn Fn(u32, u32) + Send + Sync),
    ) -> Result<()> {
        let chunks = api::chunks(data);
        let total = chunks.len() as u32;
        let server_key = self.key(server, now).await?;
        let mut sending: Vec<Sent> = Vec::with_capacity(chunks.len());
        // A chunk whose answer didn't come (a Tor stream that stalled) is
        // sent again: the server keeps chunks by index, so one that did
        // arrive is only replaced.
        let tries = if chunks.len() > 1 { CHUNK_TRIES } else { 1 };
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
            let env = api::frame(&req.encode(), rng)?;
            // Each chunk seals its tries and polls from its own generator.
            let mut own = HedgedRng::with_hedge(rng.array("rpc/chunk-hedge")?);
            let transport = Arc::clone(&self.transport);
            let server_key = server_key.clone();
            let server = *server;
            sending.push(Box::pin(async move {
                chunk_tried(&*transport, &server_key, &server, &env, &mut own, tries)
                    .await
                    .map(|(s, _)| s)
            }));
        }
        let mut done = 0;
        while !sending.is_empty() {
            // Whichever chunk is answered first.
            let status = next_done(&mut sending).await?;
            // The last chunk the server takes answers for the whole object.
            if status != Status::Ok {
                return Err(CoreError::Server(status));
            }
            done += 1;
            progress(done, total);
            self.tell_progress(kind, true, done, total);
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
        // The rest together (a vault key is about a hundred chunks: one at
        // a time over Tor, each waiting for its slot and its answer's, that
        // was minutes), each sent again if its answer didn't come.
        let server_key = self.key(server, now).await?;
        let mut getting: Vec<Got> = Vec::new();
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
            let env = api::frame(&req.encode(), rng)?;
            let mut own = HedgedRng::with_hedge(rng.array("rpc/chunk-hedge")?);
            let transport = Arc::clone(&self.transport);
            let server_key = server_key.clone();
            let server = *server;
            getting.push(Box::pin(async move {
                let r = chunk_tried(
                    &*transport,
                    &server_key,
                    &server,
                    &env,
                    &mut own,
                    CHUNK_TRIES,
                )
                .await;
                (i, r)
            }));
        }
        let mut parts: Vec<Option<Vec<u8>>> = vec![None; r.total as usize];
        let mut done = 1;
        self.tell_progress(kind, false, done, r.total);
        while !getting.is_empty() {
            let (i, got) = next_done(&mut getting).await;
            let (s, rr) = got?;
            if s != Status::Ok {
                return Err(CoreError::Server(s));
            }
            parts[i as usize] = Some(rr.ok_or(CoreError::Server(Status::Malformed))?.data);
            done += 1;
            self.tell_progress(kind, false, done, r.total);
        }
        for p in parts.into_iter().skip(1) {
            out.extend_from_slice(&p.ok_or(CoreError::Server(Status::Malformed))?);
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
    /// for a request inbox) owned by `owner`, read with the daily
    /// credentials whose hashes are `days` (none: the static credential),
    /// escalating proof of work as the server asks.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_inbox(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        owner: [u8; 32],
        flags: u8,
        days: &[(u32, [u8; 32])],
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
            let env = api::frame(&api::create_payload(&proof.0, days), rng)?;
            match self.call(server, h, &env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Pow => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Delete an inbox we own (the account is closing).
    pub async fn delete_inbox(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        owner: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: api::FLAG_DELETE,
            mailbox,
            token: owner,
        };
        let env = api::frame(&[], rng)?;
        match self.call(server, h, &env, now, rng).await?.status {
            Status::Ok => Ok(()),
            s => Err(CoreError::Server(s)),
        }
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

    /// Fetch everything in `mailbox` after `cursor`, reading with `cred`.
    /// A few envelopes waiting are read in ordinary poll slots; a backlog
    /// of [`BACKLOG_BULK`] or more opens a bulk window.
    pub async fn poll(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        cred: [u8; 24],
        cursor: u64,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<Polled>> {
        let mut out = Vec::new();
        // Catching up on a real backlog is a bulk transfer (a shaping
        // transport may then skip its clock, where the profile allows).
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
        out: &mut Vec<Polled>,
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
            let mut hint = [0u8; 24];
            hint.copy_from_slice(&r.header.token[..24]);
            out.push(Polled {
                envelope: r.envelope,
                cursor,
                hint,
            });
            // `MORE` steers the next poll to this mailbox; without it the
            // mailbox is read to the end (`docs/09-transport.md` §5).
            if r.flags & api::FLAG_MORE == 0 {
                break;
            }
            // Our own cover self-copies and a few receipts are no backlog:
            // they wait for ordinary slots, or every busy tick would skip
            // the clock (the CI shape check found it).
            if !*bulk && out.len() >= BACKLOG_BULK {
                *bulk = true;
                self.bulk(true);
            }
        }
        Ok(())
    }
}

/// One directory request (a chunk of an upload or a download), as
/// `Rpc::call` sends it (one way, the answer polled for): the server's
/// status and its reply.
async fn chunk(
    transport: &dyn Transport,
    key: &ServerKey,
    server: &ServerId,
    env: &[u8],
    rng: &mut HedgedRng,
) -> Result<(Status, Option<DirReply>)> {
    let h = RequestHeader {
        op: Op::Directory,
        flags: FLAG_DEFER,
        mailbox: [0; 32],
        token: [0; 32],
    };
    let (bytes, ex) = enclave_rpc::seal_request(key, &h, env, rng)?;
    let (rh, renv) = match transport.exchange_deferred(server, bytes).await? {
        Some(reply) => ex.open_reply(&reply)?,
        None => answer(transport, key, server, ex.status_id(), rng).await?,
    };
    let reply = api::unframe(&renv)
        .ok()
        .filter(|p| !p.is_empty())
        .and_then(|p| DirReply::decode(p).ok());
    Ok((Status::from_u8(rh.flags), reply))
}

/// [`chunk`], sent again (up to [`CHUNK_TRIES`]) when its answer didn't
/// come: a stalled stream over Tor. Chunks are kept and served by index,
/// so a repeat changes nothing.
async fn chunk_tried(
    transport: &dyn Transport,
    key: &ServerKey,
    server: &ServerId,
    env: &[u8],
    rng: &mut HedgedRng,
    tries: u32,
) -> Result<(Status, Option<DirReply>)> {
    let mut tried = 0;
    loop {
        tried += 1;
        match chunk(transport, key, server, env, rng).await {
            Err(CoreError::Net(_)) if tried < tries => continue,
            r => return r,
        }
    }
}

/// Futures polled together until each is done (no runtime to spawn on
/// here), their outputs in the order they finish.
async fn next_done<T>(
    pending: &mut Vec<std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>>,
) -> T {
    std::future::poll_fn(|cx| {
        for i in 0..pending.len() {
            if let std::task::Poll::Ready(r) = pending[i].as_mut().poll(cx) {
                drop(pending.swap_remove(i));
                return std::task::Poll::Ready(r);
            }
        }
        std::task::Poll::Pending
    })
    .await
}

/// The answer to a request sent one way: status polls until the server
/// has it (the request may still be on its way).
async fn answer(
    transport: &dyn Transport,
    key: &ServerKey,
    server: &ServerId,
    id: [u8; 32],
    rng: &mut HedgedRng,
) -> Result<(RequestHeader, Vec<u8>)> {
    for _ in 0..STATUS_TRIES {
        let h = RequestHeader {
            op: Op::Status,
            flags: 0,
            mailbox: id,
            token: rng.array("rpc/status-token")?,
        };
        let (bytes, ex) = enclave_rpc::seal_poll(key, &h, rng)?;
        let reply = transport.exchange(server, bytes).await?;
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
