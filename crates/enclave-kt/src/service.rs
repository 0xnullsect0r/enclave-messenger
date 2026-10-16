//! A key-transparency log on its own thread.
//!
//! akd is async and spawns tokio tasks, while the server's request handler is
//! a plain function from one sealed request to one sealed reply. The service
//! owns the log (and, in development, the witnesses the server contacts after
//! each epoch) on a dedicated thread with its own runtime; callers block on a
//! reply channel. That works from sync code and from inside any async runtime,
//! since the caller's runtime is never used to drive akd.
//!
//! In production the witnesses are separate services run by other operators
//! and reached over TLS; here they are passed in so tests and the dev server
//! can run the whole cosigning flow in one process.

use crate::head::WitnessPolicy;
use crate::log::{KtLog, Witness, WitnessClient};
use crate::store::KtStore;
use crate::wire::{KtInfo, KtPolicy, LookupReply, NameAnswer};
use crate::{KtError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use std::sync::mpsc;

/// Heads older than this get a heartbeat epoch before a lookup is answered.
pub const HEARTBEAT_SECS: u64 = 3600;

enum Job {
    /// Names bound together (one epoch whatever the window).
    Publish {
        names: Vec<(String, Vec<u8>)>,
        now: u64,
        reply: mpsc::Sender<Result<u64>>,
    },
    /// How long to gather changes into one epoch.
    Window(std::time::Duration),
    /// A name, or a raw label (`Err`: the descriptor digest, an account
    /// record).
    Lookup {
        name: std::result::Result<String, Vec<u8>>,
        /// Answer with a [`NameAnswer`] (absence proved) rather than a bare
        /// [`LookupReply`].
        answer: bool,
        now: u64,
        reply: mpsc::Sender<Result<Vec<u8>>>,
    },
    Commit {
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        now: u64,
        reply: mpsc::Sender<Result<u64>>,
    },
}

/// Handle to a running log.
pub struct KtService {
    tx: mpsc::Sender<Job>,
    info: KtInfo,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for KtService {
    /// Stop the log's thread and wait for it, so its store is closed (and
    /// can be opened again) when this returns.
    fn drop(&mut self) {
        let (dead, _) = mpsc::channel();
        drop(std::mem::replace(&mut self.tx, dead));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl KtService {
    /// Start a log for `server` in memory. `vrf_secret` must stay fixed for
    /// the life of the log.
    pub fn start(
        server: [u8; 16],
        domain: &str,
        operator: &str,
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
        witnesses: Vec<Witness>,
    ) -> Result<Self> {
        let witnesses = witnesses
            .into_iter()
            .map(|w| Box::new(w) as Box<dyn WitnessClient>)
            .collect();
        Self::open(
            KtStore::memory()?,
            server,
            domain,
            operator,
            signing,
            vrf_secret,
            witnesses,
            0,
        )
    }

    /// Run the log kept in `store` (see [`KtLog::open`]): the same server,
    /// head key and VRF secret every time, so clients' pins survive a
    /// restart.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        store: KtStore,
        server: [u8; 16],
        domain: &str,
        operator: &str,
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
        witnesses: Vec<Box<dyn WitnessClient>>,
        now: u64,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        let (init_tx, init_rx) = mpsc::channel();
        let head_key = signing.public().clone();
        let thread = std::thread::Builder::new()
            .name("enclave-kt".into())
            .spawn(move || {
                run(
                    store, server, signing, vrf_secret, witnesses, now, rx, init_tx,
                )
            })
            .map_err(|e| KtError::Directory(e.to_string()))?;
        let vrf_public = init_rx.recv().map_err(|_| KtError::Stopped)??;
        Ok(Self {
            tx,
            thread: Some(thread),
            info: KtInfo {
                server,
                domain: domain.to_string(),
                operator: operator.to_string(),
                head_key,
                vrf_public,
            },
        })
    }

    /// **Development only**: a log with fresh keys and three in-process
    /// witnesses under distinct operator names, plus the policy clients pin
    /// for it. Real witnesses are other operators' services.
    pub fn start_dev(server: [u8; 16], domain: &str) -> Result<(Self, KtPolicy)> {
        let mut rng = HedgedRng::new().map_err(|_| KtError::Directory("rng".into()))?;
        let key = |rng: &mut HedgedRng| {
            CompositeSigningKey::generate(rng).map_err(|_| KtError::Directory("keygen".into()))
        };
        let mut witnesses = Vec::new();
        for i in 0..3u8 {
            let k = key(&mut rng)?;
            witnesses.push(Witness::new(
                enclave_federation::witness_id(k.public()),
                &format!("dev-witness-{i}"),
                k,
            ));
        }
        let pins = witnesses
            .iter()
            .map(|w| (w.id, w.public_key().clone(), w.operator.clone()))
            .collect();
        let vrf = rng
            .array::<32>("kt/dev-vrf")
            .map_err(|_| KtError::Directory("rng".into()))?;
        let svc = Self::start(server, domain, "dev-server", key(&mut rng)?, vrf, witnesses)?;
        let policy = KtPolicy {
            servers: vec![svc.info().clone()],
            witnesses: WitnessPolicy {
                witnesses: pins,
                threshold: 3,
            },
        };
        Ok((svc, policy))
    }

    /// **Testing only**: two independent logs under the *same* server key,
    /// VRF key and witness keys, as a server whose witnesses collude would
    /// run to show different people different views (RT-04). Both logs'
    /// heads verify under the one policy returned; only comparing heads
    /// between clients (gossip) can tell them apart.
    pub fn start_dev_twins(server: [u8; 16], domain: &str) -> Result<(Self, Self, KtPolicy)> {
        use enclave_crypto::sig::COMPOSITE_SEED_LEN;
        let mut rng = HedgedRng::new().map_err(|_| KtError::Directory("rng".into()))?;
        let err = |_| KtError::Directory("keygen".into());
        // Keys are made from seeds so each twin gets its own copy.
        let mut seed = || {
            rng.array::<COMPOSITE_SEED_LEN>("kt/dev-twin-seed")
                .map_err(err)
        };
        let key = |s: &[u8; COMPOSITE_SEED_LEN]| CompositeSigningKey::from_seed(s).map_err(err);
        let mut wseeds = Vec::new();
        for i in 0..3u8 {
            let s = seed()?;
            let id = enclave_federation::witness_id(key(&s)?.public());
            wseeds.push((id, format!("dev-witness-{i}"), s));
        }
        let server_seed = seed()?;
        let vrf = rng
            .array::<32>("kt/dev-vrf")
            .map_err(|_| KtError::Directory("rng".into()))?;
        let witnesses = || -> Result<Vec<Witness>> {
            wseeds
                .iter()
                .map(|(id, op, s)| Ok(Witness::new(*id, op, key(s)?)))
                .collect()
        };
        let pins = witnesses()?
            .iter()
            .map(|w| (w.id, w.public_key().clone(), w.operator.clone()))
            .collect();
        let a = Self::start(
            server,
            domain,
            "dev-server",
            key(&server_seed)?,
            vrf,
            witnesses()?,
        )?;
        let b = Self::start(
            server,
            domain,
            "dev-server",
            key(&server_seed)?,
            vrf,
            witnesses()?,
        )?;
        let policy = KtPolicy {
            servers: vec![a.info().clone()],
            witnesses: WitnessPolicy {
                witnesses: pins,
                threshold: 3,
            },
        };
        Ok((a, b, policy))
    }

    /// Parameters clients pin for this log.
    pub fn info(&self) -> &KtInfo {
        &self.info
    }

    /// Bind `name` to `value` in a new epoch and collect witness cosignatures.
    /// Returns the epoch.
    pub fn publish(&self, name: &str, value: Vec<u8>, now: u64) -> Result<u64> {
        self.publish_many(vec![(name.to_string(), value)], now)
    }

    /// Bind several names in one epoch (a rename: the old name released
    /// and the new one taken together). Returns the epoch.
    pub fn publish_many(&self, names: Vec<(String, Vec<u8>)>, now: u64) -> Result<u64> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(Job::Publish { names, now, reply })
            .map_err(|_| KtError::Stopped)?;
        rx.recv().map_err(|_| KtError::Stopped)?
    }

    /// Gather the changes that arrive within `window` of the first into
    /// one epoch (`12-servers.md` §3.4), so names claimed around the same
    /// time can't be told apart by epoch. Zero (the default) still puts
    /// whatever is already waiting into one epoch.
    pub fn set_batch_window(&self, window: std::time::Duration) {
        let _ = self.tx.send(Job::Window(window));
    }

    /// Commit a descriptor digest in a new epoch (and collect witness
    /// cosignatures). Returns the epoch.
    pub fn commit_descriptor(&self, digest: [u8; 64], now: u64) -> Result<u64> {
        self.commit(
            vec![(crate::log::DESCRIPTOR_LABEL.to_vec(), digest.to_vec())],
            now,
        )
    }

    /// Commit account records (`03-identity.md` §8.1) in one new epoch:
    /// `(last 31 bytes of the manifest directory key, record)` pairs.
    pub fn commit_accounts(&self, records: Vec<([u8; 31], Vec<u8>)>, now: u64) -> Result<u64> {
        self.commit(
            records
                .into_iter()
                .map(|(t, r)| (crate::log::account_label(&t), r))
                .collect(),
            now,
        )
    }

    fn commit(&self, entries: Vec<(Vec<u8>, Vec<u8>)>, now: u64) -> Result<u64> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(Job::Commit {
                entries,
                now,
                reply,
            })
            .map_err(|_| KtError::Stopped)?;
        rx.recv().map_err(|_| KtError::Stopped)?
    }

    /// An encoded [`LookupReply`] for `name` against a fresh, cosigned head.
    pub fn lookup(&self, name: &str, now: u64) -> Result<Vec<u8>> {
        self.lookup_label(Ok(name.to_string()), false, now)
    }

    /// An encoded [`NameAnswer`] for `name` against a fresh, cosigned head:
    /// its entry, or proof that it was never registered.
    pub fn lookup_name(&self, name: &str, now: u64) -> Result<Vec<u8>> {
        self.lookup_label(Ok(name.to_string()), true, now)
    }

    /// An encoded [`LookupReply`] for the server's committed descriptor
    /// digest (checked with [`crate::log::verify_descriptor_lookup`]).
    pub fn lookup_descriptor(&self, now: u64) -> Result<Vec<u8>> {
        self.lookup_label(Err(crate::log::DESCRIPTOR_LABEL.to_vec()), false, now)
    }

    /// An encoded [`LookupReply`] for the record of the account whose
    /// manifest directory key ends in `tail` (checked with
    /// [`crate::log::verify_label_lookup`]).
    pub fn lookup_account(&self, tail: &[u8; 31], now: u64) -> Result<Vec<u8>> {
        self.lookup_label(Err(crate::log::account_label(tail)), false, now)
    }

    fn lookup_label(
        &self,
        name: std::result::Result<String, Vec<u8>>,
        answer: bool,
        now: u64,
    ) -> Result<Vec<u8>> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(Job::Lookup {
                name,
                answer,
                now,
                reply,
            })
            .map_err(|_| KtError::Stopped)?;
        rx.recv().map_err(|_| KtError::Stopped)?
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    store: KtStore,
    server: [u8; 16],
    signing: CompositeSigningKey,
    vrf_secret: [u8; 32],
    mut witnesses: Vec<Box<dyn WitnessClient>>,
    now: u64,
    rx: mpsc::Receiver<Job>,
    init: mpsc::Sender<Result<Vec<u8>>>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("enclave-kt-akd")
        // Timers and sockets: remote witnesses are reached over HTTPS.
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = init.send(Err(KtError::Directory(e.to_string())));
            return;
        }
    };
    let mut rng = match HedgedRng::new() {
        Ok(r) => r,
        Err(_) => {
            let _ = init.send(Err(KtError::Directory("rng".into())));
            return;
        }
    };
    let mut log = match rt.block_on(KtLog::open(
        store, server, signing, vrf_secret, now, &mut rng,
    )) {
        Ok(l) => l,
        Err(e) => {
            let _ = init.send(Err(e));
            return;
        }
    };
    if init.send(Ok(log.vrf_public().to_vec())).is_err() {
        return;
    }
    // Last epoch each witness cosigned (remembered across restarts by
    // witnesses with a store).
    let mut last: Vec<Option<u64>> = Vec::with_capacity(witnesses.len());
    for w in witnesses.iter_mut() {
        last.push(rt.block_on(w.last_epoch(&server)));
    }
    // Heads signed while a witness was unreachable (or before a restart)
    // get their cosignatures now.
    rt.block_on(cosign_all(
        &mut log,
        &mut witnesses,
        &mut last,
        now,
        &mut rng,
    ));
    let mut window = std::time::Duration::ZERO;
    // Jobs taken off the channel while a batch gathered, to run after it.
    let mut held: std::collections::VecDeque<Job> = Default::default();
    loop {
        let job = match held.pop_front() {
            Some(j) => j,
            None => match rx.recv() {
                Ok(j) => j,
                Err(_) => break,
            },
        };
        match job {
            Job::Window(w) => window = w,
            first @ (Job::Publish { .. } | Job::Commit { .. }) => {
                let mut batch = vec![first];
                let deadline = std::time::Instant::now() + window;
                loop {
                    let next = match deadline.checked_duration_since(std::time::Instant::now()) {
                        Some(left) if !left.is_zero() => rx.recv_timeout(left).ok(),
                        _ => rx.try_recv().ok(),
                    };
                    match next {
                        Some(j @ (Job::Publish { .. } | Job::Commit { .. })) => batch.push(j),
                        Some(other) => held.push_back(other),
                        None => break,
                    }
                }
                let left = rt.block_on(commit_batch(
                    &mut log,
                    &mut witnesses,
                    &mut last,
                    batch,
                    &mut rng,
                ));
                // Changes to a label already in the batch go next.
                for j in left.into_iter().rev() {
                    held.push_front(j);
                }
            }
            Job::Lookup {
                name,
                answer,
                now,
                reply,
            } => {
                let r = rt.block_on(async {
                    let fresh = log
                        .latest()
                        .is_some_and(|h| h.head.time + HEARTBEAT_SECS > now);
                    if !fresh {
                        log.heartbeat(now, &mut rng).await?;
                        cosign_all(&mut log, &mut witnesses, &mut last, now, &mut rng).await;
                    }
                    let found = match &name {
                        Ok(n) => log.lookup(n).await,
                        Err(label) => log.lookup_raw(label).await,
                    };
                    match (found, &name, answer) {
                        (Ok((proof, head)), _, false) => LookupReply { head, proof }.encode(),
                        (Ok((proof, head)), _, true) => {
                            NameAnswer::Found(LookupReply { head, proof }).encode()
                        }
                        (Err(_), Ok(n), true) => {
                            let (proof, head) = log.lookup_absent(n).await?;
                            NameAnswer::Absent { head, proof }.encode()
                        }
                        (Err(e), _, _) => Err(e),
                    }
                });
                let _ = reply.send(r);
            }
        }
    }
}

/// Commit a batch of `Publish` and `Commit` jobs in one epoch and answer
/// each with it (or with its own error). Returns the jobs that touch a
/// label already in this epoch (akd takes each label once an epoch), to
/// run in the next.
async fn commit_batch(
    log: &mut KtLog,
    witnesses: &mut [Box<dyn WitnessClient>],
    last: &mut [Option<u64>],
    batch: Vec<Job>,
    rng: &mut HedgedRng,
) -> Vec<Job> {
    let mut labels: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut skeletons: std::collections::HashMap<String, String> = Default::default();
    let mut names = Vec::new();
    let mut raw = Vec::new();
    let mut replies = Vec::new();
    let mut later = Vec::new();
    let mut now = 0;
    for job in batch {
        match job {
            Job::Publish {
                names: ns,
                now: t,
                reply,
            } => {
                let checked: Result<Vec<(String, String, Vec<u8>)>> = ns
                    .into_iter()
                    .map(|(n, v)| log.check_name(&n).map(|(n, sk)| (n, sk, v)))
                    .collect();
                let checked = match checked {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        continue;
                    }
                };
                // Two names with one skeleton in the same batch: the first
                // claim wins, as it would one epoch apart.
                if checked
                    .iter()
                    .any(|(n, sk, _)| skeletons.get(sk).is_some_and(|other| other != n))
                {
                    let _ = reply.send(Err(KtError::Username));
                    continue;
                }
                if checked
                    .iter()
                    .any(|(n, _, _)| labels.contains(n.as_bytes()))
                {
                    later.push(Job::Publish {
                        names: checked.into_iter().map(|(n, _, v)| (n, v)).collect(),
                        now: t,
                        reply,
                    });
                    continue;
                }
                for (n, sk, v) in checked {
                    labels.insert(n.as_bytes().to_vec());
                    skeletons.insert(sk.clone(), n.clone());
                    names.push((n, sk, v));
                }
                now = now.max(t);
                replies.push(reply);
            }
            Job::Commit {
                entries,
                now: t,
                reply,
            } => {
                if entries.iter().any(|(l, _)| labels.contains(l)) {
                    later.push(Job::Commit {
                        entries,
                        now: t,
                        reply,
                    });
                    continue;
                }
                for (l, v) in entries {
                    labels.insert(l.clone());
                    raw.push((l, v));
                }
                now = now.max(t);
                replies.push(reply);
            }
            other => later.push(other),
        }
    }
    if replies.is_empty() {
        return later;
    }
    let r = match log.publish_entries(names, raw, now, rng).await {
        Ok(sh) => {
            cosign_all(log, witnesses, last, now, rng).await;
            Ok(sh.head.epoch)
        }
        Err(e) => Err(e),
    };
    for reply in replies {
        let _ = reply.send(r.clone());
    }
    later
}

/// Ask every witness to cosign the latest head. A witness that refuses leaves
/// the head without its cosignature; clients then decide by their quorum.
///
/// A witness that refuses (it was restarted from an older state, or was
/// down while heads passed) is asked where it stands, and the next round
/// sends the heads and proof from there.
async fn cosign_all(
    log: &mut KtLog,
    witnesses: &mut [Box<dyn WitnessClient>],
    last: &mut [Option<u64>],
    now: u64,
    _rng: &mut HedgedRng,
) {
    let Some(epoch) = log.latest().map(|h| h.head.epoch) else {
        return;
    };
    let server = log.server();
    let server_key = log.public_key().clone();
    for (w, seen) in witnesses.iter_mut().zip(last.iter_mut()) {
        let (heads, proof) = match *seen {
            Some(l) if l >= epoch => continue,
            Some(l) => match log.audit(l, epoch).await {
                Ok(p) => (log.heads_after(l, epoch), Some(p)),
                Err(_) => continue,
            },
            None => (log.heads_after(epoch.saturating_sub(1), epoch), None),
        };
        match w.cosign(&server_key, &heads, proof, now).await {
            Ok(c) => {
                *seen = Some(epoch);
                if let Err(e) = log.add_cosignature(epoch, c) {
                    eprintln!("enclave-kt: couldn't store a cosignature: {e}");
                }
            }
            Err(_) => *seen = w.last_epoch(&server).await,
        }
    }
}
