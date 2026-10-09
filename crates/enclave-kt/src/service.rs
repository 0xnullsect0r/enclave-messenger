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
    Publish {
        name: String,
        value: Vec<u8>,
        now: u64,
        reply: mpsc::Sender<Result<u64>>,
    },
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
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(Job::Publish {
                name: name.to_string(),
                value,
                now,
                reply,
            })
            .map_err(|_| KtError::Stopped)?;
        rx.recv().map_err(|_| KtError::Stopped)?
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
    while let Ok(job) = rx.recv() {
        match job {
            Job::Publish {
                name,
                value,
                now,
                reply,
            } => {
                let r = rt.block_on(async {
                    let sh = log.publish(&name, value, now, &mut rng).await?;
                    cosign_all(&mut log, &mut witnesses, &mut last, now, &mut rng).await;
                    Ok(sh.head.epoch)
                });
                let _ = reply.send(r);
            }
            Job::Commit {
                entries,
                now,
                reply,
            } => {
                let r = rt.block_on(async {
                    let sh = log.commit_labels(entries, now, &mut rng).await?;
                    cosign_all(&mut log, &mut witnesses, &mut last, now, &mut rng).await;
                    Ok(sh.head.epoch)
                });
                let _ = reply.send(r);
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
