//! End-to-end driver: headless Enclave clients against real server stacks
//! run separately (CI job `federation-e2e-tcp`, `ci/federation/`).
//!
//! ```text
//! enclave-e2e setup         --state DIR --servers A_ID=ROUTE,B_ID=ROUTE,C_ID=ROUTE
//!                           --foundation FILE --server-list FILE [--nymd PATH [--tord PATH]]
//!                           [--push-relay-keys FILE --push-listen ADDR --push-endpoint URL]
//! enclave-e2e after-restart --state DIR --servers … --foundation FILE --server-list FILE
//! enclave-e2e shape         --state DIR --servers … --foundation FILE --server-list FILE
//!                           --nymd PATH [--tord PATH] --marks FILE [--seconds N] [--warmup N]
//!                           [--profile foreground|maximum]
//! ```
//!
//! A route is `HOST:PORT` (the development TCP transport, CI job
//! `federation-e2e-tcp`) or `nym:ADDRESS` (the stack's ingress, over the
//! mixnet: CI job `federation-e2e-localnet`). Nym routes go through
//! `enclave-nymd` at `--nymd PATH`, started with `--env` (so a local
//! mixnet's `ENCLAVE_NYM_TOPOLOGY` and `ENCLAVE_NYM_API` reach it), as
//! netd drives it on a device. With `--tord PATH` (a `dev-direct` build of
//! `enclave-tord`), nymd reaches its gateway and nym-api through tord's
//! SOCKS5 port, the way a device reaches them through Tor.
//!
//! Three people, one per stack (Ada on A, Ben on B, Cyrus on C). `setup`:
//!
//! 1. each claims a username on their home server; the others find them
//!    by `@name@domain`, verified under pins from the foundation's list
//!    with cosignatures from the other stacks' witnesses;
//! 2. they add each other and talk across servers;
//! 3. a group of three, hosted on A;
//! 4. a file from Ada to Ben (blobs on A, fetched by Ben);
//! 5. push (when a push relay is given): Ben registers a UnifiedPush
//!    endpoint this program serves, and Ada's message to him wakes it;
//! 6. Ada leaves a message for Ben on B, unread.
//!
//! Then the CI script restarts stack B, and `after-restart`:
//!
//! 7. Ben reads the message B held across the restart and answers; usernames
//!    on B still verify; the group still works;
//! 8. at no point did anyone see a split view of a log.
//!
//! Profiles are kept in `--state` between the runs. Any failure exits
//! non-zero with what went wrong.
//!
//! `shape`, after those two, is the traffic-shape check
//! (`ci/federation/pcap-check.py`, `docs/09-transport.md` §6.7): Ada's
//! client runs shaped in the Foreground (or Maximum) profile, as the vault
//! runs it,
//! over this process's mixnet client. After `--warmup` seconds she is idle
//! for `--seconds`, then busy for as long (a message every 6 s, to Ben and
//! Cyrus in turn: an idle contact refills write tokens only as it reads, so
//! one alone would run out),
//! syncing on the vault's 3 s clock throughout. The phases' wall-clock
//! bounds go to `--marks` (`idle_start idle_end busy_start busy_end`, Unix
//! ms) for the checker, which compares a packet capture of the link to the
//! gateway in both. Ben and Cyrus, idle meanwhile, then check every message
//! arrived.

use enclave_core::{Client, ContactCard, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_federation::{FoundationPublic, ServerList};
use enclave_net::transport::{NymTransport, Route, TcpTransport, Transport, parse_route};
use enclave_service::config::flag;
use enclave_store::FileKeystore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

const NAMES: [&str; 3] = ["ada", "ben", "cyrus"];
/// How long to wait for something to arrive.
const PATIENCE: Duration = Duration::from_secs(180);

struct World {
    state: PathBuf,
    transport: Arc<dyn Transport>,
    // Kept so nymd (and tord) live as long as the transport.
    _nymd: Option<tokio::process::Child>,
    _tord: Option<enclave_tord::launch::Running>,
    servers: Vec<[u8; 16]>,
    foundation: FoundationPublic,
    list: Vec<u8>,
    domains: Vec<String>,
}

type R<T> = Result<T, String>;

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("enclave-e2e: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = rt.block_on(async {
        let w = world(&args).await?;
        match args.first().map(String::as_str) {
            Some("setup") => setup(&w, &args).await,
            Some("after-restart") => after_restart(&w).await,
            Some("shape") => shape(&w, &args).await,
            _ => Err("usage: enclave-e2e setup|after-restart|shape (see the module docs)".into()),
        }?;
        // What went one way (the message B is to keep across its restart)
        // must leave before this process and its mixnet client exit.
        match w.transport.flush(PATIENCE).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!("sends still unacknowledged after {PATIENCE:?}")),
            Err(x) => Err(format!("flush: {x}")),
        }
    });
    match result {
        Ok(()) => {
            eprintln!("enclave-e2e: all passed");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("enclave-e2e: FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The mixnet client, driven over its stdin and stdout.
async fn start_nymd(
    bin: &str,
    tor: Option<&enclave_tord::launch::Running>,
) -> R<(enclave_nym::pipe::PipeDriver, tokio::process::Child)> {
    let mut cmd = tokio::process::Command::new(bin);
    if let Some(t) = tor {
        cmd.envs(t.nymd_env());
        for v in enclave_tord::launch::Running::NYMD_ENV_REMOVE {
            cmd.env_remove(v);
        }
    }
    let mut child = cmd
        .arg("--env")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("{bin}: {err}"))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("no pipes to enclave-nymd".into());
    };
    // Connecting to the mixnet can take a while.
    let driver = tokio::time::timeout(PATIENCE, enclave_nym::pipe::PipeDriver::new(stdout, stdin))
        .await
        .map_err(|_| "enclave-nymd didn't connect".to_string())?
        .map_err(e)?;
    Ok((driver, child))
}

async fn world(args: &[String]) -> R<World> {
    let need = |n: &str| flag(args, n).ok_or_else(|| format!("missing {n}"));
    let state = PathBuf::from(need("--state")?);
    std::fs::create_dir_all(&state).map_err(e)?;
    let mut tcp = HashMap::new();
    let mut nym = HashMap::new();
    let mut servers = Vec::new();
    for s in need("--servers")?.split(',') {
        match parse_route(s).ok_or_else(|| format!("--servers: {s}"))? {
            (id, Route::Tcp(a)) => {
                tcp.insert(id, a);
                servers.push(id);
            }
            (id, Route::Nym(a)) => {
                nym.insert(id, a);
                servers.push(id);
            }
        }
    }
    if !tcp.is_empty() && !nym.is_empty() {
        return Err("--servers: all TCP or all Nym".into());
    }
    if servers.len() != 3 {
        return Err("--servers: three stacks expected".into());
    }
    let foundation =
        FoundationPublic::decode(&std::fs::read(need("--foundation")?).map_err(e)?).map_err(e)?;
    let list = std::fs::read(need("--server-list")?).map_err(e)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(e)?
        .as_secs();
    let parsed = ServerList::verify(&list, &foundation, now, 0).map_err(e)?;
    let domains = servers
        .iter()
        .map(|id| {
            parsed
                .server(id)
                .map(|s| s.domain.clone())
                .ok_or_else(|| "a server isn't in the list".to_string())
        })
        .collect::<R<Vec<_>>>()?;
    // `--tord PATH` (a dev-direct build): nymd reaches its gateway and
    // nym-api through enclave-tord's SOCKS5 port, as on a device (Tor),
    // dialling directly behind it.
    let tord = match flag(args, "--tord") {
        Some(bin) if !nym.is_empty() => {
            let secret: String = enclave_crypto::rng::HedgedRng::new()
                .and_then(|mut r| r.array::<32>("e2e/tor-secret"))
                .map_err(e)?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let t = enclave_tord::launch::start(
                std::path::Path::new(&bin),
                &state.join("tor"),
                secret,
                true,
                true,
                Duration::from_secs(30),
            )
            .await?;
            eprintln!("enclave-e2e: through enclave-tord on port {}", t.port);
            Some(t)
        }
        _ => None,
    };
    let (transport, nymd): (Arc<dyn Transport>, _) = if nym.is_empty() {
        (Arc::new(TcpTransport::new(tcp)), None)
    } else {
        let (driver, child) = start_nymd(&need("--nymd")?, tord.as_ref()).await?;
        eprintln!("enclave-e2e: on the mixnet as {}", {
            use enclave_nym::MixnetDriver;
            driver.address()
        });
        (
            Arc::new(NymTransport::new(
                Arc::new(driver),
                nym,
                NymTransport::TIMEOUT,
            )),
            Some(child),
        )
    };
    Ok(World {
        state,
        transport,
        _nymd: nymd,
        _tord: tord,
        servers,
        foundation,
        list,
        domains,
    })
}

fn options(dir: &Path) -> R<Options> {
    std::fs::create_dir_all(dir).map_err(e)?;
    Ok(Options {
        path: Some(dir.join("profile.redb")),
        keystore: Arc::new(FileKeystore::new(dir.join("keys")).map_err(e)?),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    })
}

impl World {
    async fn create(&self, i: usize) -> R<Client> {
        let (mut c, _) = Client::create(
            options(&self.state.join(NAMES[i]))?,
            Arc::clone(&self.transport),
            self.servers[i],
            NAMES[i],
        )
        .await
        .map_err(|x| format!("{}: create: {x}", NAMES[i]))?;
        c.set_foundation(self.foundation.clone()).map_err(e)?;
        c.offer_server_list(&self.list).map_err(e)?;
        Ok(c)
    }

    fn open(&self, i: usize) -> R<Client> {
        let mut c = Client::open(
            options(&self.state.join(NAMES[i]))?,
            Arc::clone(&self.transport),
        )
        .map_err(|x| format!("{}: open: {x}", NAMES[i]))?;
        c.set_foundation(self.foundation.clone()).map_err(e)?;
        Ok(c)
    }
}

/// Every event any client saw, checked at the end for split views.
#[derive(Default)]
struct Seen(Vec<Event>);

impl Seen {
    async fn sync(&mut self, c: &mut Client, who: &str) -> R<Vec<Event>> {
        let ev = c.sync().await.map_err(|x| format!("{who}: sync: {x}"))?;
        self.0.extend(ev.iter().cloned());
        Ok(ev)
    }

    /// Sync `c` until `want` matches an event, or give up.
    async fn until(
        &mut self,
        c: &mut Client,
        who: &str,
        what: &str,
        want: impl Fn(&Event) -> bool,
    ) -> R<Event> {
        let start = Instant::now();
        loop {
            for ev in self.sync(c, who).await? {
                if want(&ev) {
                    eprintln!("  {who}: {what}");
                    return Ok(ev);
                }
            }
            if start.elapsed() > PATIENCE {
                return Err(format!("{who}: no {what} after {PATIENCE:?}"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    fn no_split_views(&self) -> R<()> {
        match self
            .0
            .iter()
            .find(|e| matches!(e, Event::KtSplitView { .. } | Event::UsernameProblem { .. }))
        {
            Some(ev) => Err(format!("a log looked forked: {ev:?}")),
            None => Ok(()),
        }
    }
}

fn text_from(root: [u8; 64], text: &'static str) -> impl Fn(&Event) -> bool {
    move |ev| matches!(ev, Event::Message { root: r, message } if *r == root && message.text == text)
}

fn group_text(text: &'static str) -> impl Fn(&Event) -> bool {
    move |ev| matches!(ev, Event::GroupMessage { message, .. } if message.text == text)
}

async fn setup(w: &World, args: &[String]) -> R<()> {
    // A fresh start: profiles from an earlier run belong to other servers.
    for n in NAMES {
        let _ = std::fs::remove_dir_all(w.state.join(n));
    }
    let mut seen = Seen::default();
    eprintln!("creating Ada on A, Ben on B, Cyrus on C");
    let mut ada = w.create(0).await?;
    let mut ben = w.create(1).await?;
    let mut cy = w.create(2).await?;

    // 1. Usernames on three servers, found across them.
    eprintln!("1. usernames");
    for (c, i) in [(&mut ada, 0), (&mut ben, 1), (&mut cy, 2)] {
        let got = c
            .claim_username(NAMES[i])
            .await
            .map_err(|x| format!("{}: claim: {x}", NAMES[i]))?;
        if got != format!("{}@{}", NAMES[i], w.domains[i]) {
            return Err(format!("{}: claimed {got}", NAMES[i]));
        }
    }
    let ben_card = ada
        .find_username(&format!("@ben@{}", w.domains[1]))
        .await
        .map_err(|x| format!("ada: find ben: {x}"))?;
    let ada_card = cy
        .find_username(&format!("@ada@{}", w.domains[0]))
        .await
        .map_err(|x| format!("cyrus: find ada: {x}"))?;
    if ben_card.root != ben.root() || ada_card.root != ada.root() {
        return Err("a username led to the wrong account".into());
    }

    // 2. Contacts across servers.
    eprintln!("2. one-to-one across servers");
    connect(&mut seen, &mut ada, "ada", &ben_card, &mut ben, "ben").await?;
    connect(&mut seen, &mut cy, "cyrus", &ada_card, &mut ada, "ada").await?;
    let cy_card = cy.card();
    connect(&mut seen, &mut ben, "ben", &cy_card, &mut cy, "cyrus").await?;
    ada.send_text(&ben.root(), "hello from A")
        .await
        .map_err(e)?;
    seen.until(
        &mut ben,
        "ben",
        "Ada's message",
        text_from(ada.root(), "hello from A"),
    )
    .await?;
    ben.send_text(&ada.root(), "hello from B")
        .await
        .map_err(e)?;
    seen.until(
        &mut ada,
        "ada",
        "Ben's answer",
        text_from(ben.root(), "hello from B"),
    )
    .await?;

    // 3. A group hosted on A.
    eprintln!("3. a group of three");
    let gid = ada
        .create_group("e2e", &[ben.root(), cy.root()])
        .await
        .map_err(|x| format!("ada: create group: {x}"))?;
    for (c, who) in [(&mut ben, "ben"), (&mut cy, "cyrus")] {
        seen.until(c, who, "the group", |ev| {
            matches!(ev, Event::GroupJoined { .. })
        })
        .await?;
    }
    ada.send_group_text(&gid, "group hello").await.map_err(e)?;
    for (c, who) in [(&mut ben, "ben"), (&mut cy, "cyrus")] {
        seen.until(c, who, "the group message", group_text("group hello"))
            .await?;
    }
    cy.send_group_text(&gid, "from C to the group")
        .await
        .map_err(e)?;
    seen.until(
        &mut ada,
        "ada",
        "Cyrus's group message",
        group_text("from C to the group"),
    )
    .await?;

    // 4. A file: blobs on A, fetched by Ben.
    eprintln!("4. a file");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
    ada.send_attachment(
        &ben.root(),
        "e2e.bin",
        "application/octet-stream",
        &data,
        "a file",
    )
    .await
    .map_err(|x| format!("ada: send file: {x}"))?;
    let ev = seen
        .until(
            &mut ben,
            "ben",
            "the file message",
            text_from(ada.root(), "a file"),
        )
        .await?;
    let Event::Message { message, .. } = ev else {
        return Err("unexpected event".into());
    };
    let got = ben
        .fetch_attachment(&ada.root(), message.seq)
        .await
        .map_err(|x| format!("ben: fetch file: {x}"))?;
    if got != data {
        return Err("the file arrived changed".into());
    }

    // 5. Push.
    if let Some(keys) = flag(args, "--push-relay-keys") {
        eprintln!("5. push");
        push(&mut seen, &mut ada, &mut ben, &keys, args).await?;
    } else {
        eprintln!("5. push: skipped (no --push-relay-keys)");
    }

    // 6. Left on B for after the restart.
    ada.send_text(&ben.root(), "kept across the restart")
        .await
        .map_err(e)?;
    seen.no_split_views()?;
    std::fs::write(w.state.join("group"), gid).map_err(e)?;
    Ok(())
}

/// `a` adds `b` from `card` and `b` accepts.
async fn connect(
    seen: &mut Seen,
    a: &mut Client,
    a_name: &str,
    card: &ContactCard,
    b: &mut Client,
    b_name: &str,
) -> R<()> {
    a.add_contact(card, &format!("hi from {a_name}"))
        .await
        .map_err(|x| format!("{a_name}: add {b_name}: {x}"))?;
    let root = a.root();
    seen.until(
        b,
        b_name,
        "the request",
        |ev| matches!(ev, Event::Request { root: r, .. } if *r == root),
    )
    .await?;
    b.accept(&root)
        .await
        .map_err(|x| format!("{b_name}: accept: {x}"))?;
    let broot = b.root();
    seen.until(
        a,
        a_name,
        "the acceptance",
        |ev| matches!(ev, Event::Accepted { root: r } if *r == broot),
    )
    .await?;
    Ok(())
}

async fn push(
    seen: &mut Seen,
    ada: &mut Client,
    ben: &mut Client,
    keys: &str,
    args: &[String],
) -> R<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let need = |n: &str| flag(args, n).ok_or_else(|| format!("missing {n}"));
    let bytes = std::fs::read(keys).map_err(|x| format!("{keys}: {x}"))?;
    let one = 4 + 56 + 1568;
    let relay = enclave_push_relay::RelayPublic::decode(bytes.get(..one).ok_or("short key file")?)
        .map_err(e)?;
    let listener = tokio::net::TcpListener::bind(need("--push-listen")?)
        .await
        .map_err(e)?;
    let endpoint = need("--push-endpoint")?;
    ben.register_push(
        &relay,
        enclave_push_relay::Platform::UnifiedPush,
        endpoint.as_bytes(),
    )
    .await
    .map_err(|x| format!("ben: register push: {x}"))?;
    ada.send_text(&ben.root(), "wake up").await.map_err(e)?;
    // Wakes leave the relay in 60-second windows.
    let (mut s, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .map_err(|_| "no wake reached the push endpoint".to_string())?
        .map_err(e)?;
    let mut buf = vec![0u8; 1024];
    let n = s.read(&mut buf).await.map_err(e)?;
    if !buf[..n].starts_with(b"POST ") {
        return Err("the push endpoint got something other than a wake".into());
    }
    s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
        .await
        .map_err(e)?;
    eprintln!("  ben: woken by push");
    seen.until(
        ben,
        "ben",
        "the message that woke him",
        text_from(ada.root(), "wake up"),
    )
    .await?;
    Ok(())
}

async fn after_restart(w: &World) -> R<()> {
    let mut seen = Seen::default();
    let mut ada = w.open(0)?;
    let mut ben = w.open(1)?;
    let mut cy = w.open(2)?;
    let gid: [u8; 32] = std::fs::read(w.state.join("group"))
        .map_err(e)?
        .try_into()
        .map_err(|_| "bad group file".to_string())?;

    eprintln!("7. after B restarted");
    seen.until(
        &mut ben,
        "ben",
        "the message B kept across the restart",
        text_from(ada.root(), "kept across the restart"),
    )
    .await?;
    ben.send_text(&ada.root(), "B is back").await.map_err(e)?;
    seen.until(
        &mut ada,
        "ada",
        "Ben's answer",
        text_from(ben.root(), "B is back"),
    )
    .await?;
    let card = cy
        .find_username(&format!("@ben@{}", w.domains[1]))
        .await
        .map_err(|x| format!("cyrus: find ben after the restart: {x}"))?;
    if card.root != ben.root() {
        return Err("Ben's username moved".into());
    }
    ben.send_group_text(&gid, "group after restart")
        .await
        .map_err(e)?;
    for (c, who) in [(&mut ada, "ada"), (&mut cy, "cyrus")] {
        seen.until(
            c,
            who,
            "the group message",
            group_text("group after restart"),
        )
        .await?;
    }
    eprintln!("8. no split views");
    seen.no_split_views()
}

/// Unix time in milliseconds.
fn unix_ms() -> R<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(e)?
        .as_millis() as u64)
}

async fn shape(w: &World, args: &[String]) -> R<()> {
    use enclave_net::schedule::Profile;
    use enclave_net::shaped::{ShapedTransport, Shaping};
    let secs = |n: &str, default: u64| -> R<Duration> {
        flag(args, n)
            .map(|v| v.parse::<u64>().map_err(|x| format!("{n}: {x}")))
            .transpose()
            .map(|v| Duration::from_secs(v.unwrap_or(default)))
    };
    let phase = secs("--seconds", 90)?;
    let warmup = secs("--warmup", 30)?;
    let marks = flag(args, "--marks").ok_or("missing --marks")?;
    // Background's ticks are minutes apart at random: its shape needs hours
    // of capture, which `enclave-e2e bench` (N4) measures instead.
    let profile = match flag(args, "--profile").as_deref() {
        None | Some("foreground") => Profile::Foreground,
        Some("maximum") => Profile::Maximum,
        Some(p) => return Err(format!("--profile: {p} (foreground or maximum)")),
    };
    // Ben and Cyrus only read, afterwards, over the unshaped transport.
    let mut readers = [w.open(1)?, w.open(2)?];
    let roots = [readers[0].root(), readers[1].root()];
    let shaped = ShapedTransport::start(
        Arc::clone(&w.transport),
        Shaping::On(profile),
        vec![w.servers[0]],
    );
    let mut ada = Client::open(
        options(&w.state.join(NAMES[0]))?,
        Arc::clone(&shaped) as Arc<dyn Transport>,
    )
    .map_err(|x| format!("ada: open: {x}"))?;
    ada.set_foundation(w.foundation.clone()).map_err(e)?;
    // Like the vault: a sync round started at most every 3 s, groups one
    // round in `other_mailbox_period`, upkeep every `UPKEEP_EVERY` rounds.
    let period = enclave_net::schedule::Scheduler::other_mailbox_period(profile) as u64;
    let start = Instant::now();
    let idle_at = start + warmup;
    let busy_at = idle_at + phase;
    let end = busy_at + phase;
    let base_ms = unix_ms()?;
    let ms = |t: Instant| base_ms + t.duration_since(start).as_millis() as u64;
    eprintln!(
        "shape: Ada shaped ({profile:?}); warm-up {warmup:?}, idle {phase:?}, busy {phase:?}"
    );
    let mut round = 0u64;
    let mut next = start;
    let mut last_send: Option<Instant> = None;
    let mut sent: Vec<(usize, String)> = Vec::new();
    while Instant::now() < end {
        tokio::time::sleep_until(next.into()).await;
        let now = Instant::now();
        next = now + Duration::from_secs(3);
        if now >= busy_at
            && last_send.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(6))
        {
            let to = sent.len() % 2;
            let text = format!("shape {}", sent.len());
            ada.send_text(&roots[to], &text)
                .await
                .map_err(|x| format!("ada: send to {}: {x}", NAMES[to + 1]))?;
            sent.push((to, text));
            last_send = Some(now);
        }
        ada.sync_round_every(round, period)
            .await
            .map_err(|x| format!("ada: sync: {x}"))?;
        round += 1;
    }
    std::fs::write(
        &marks,
        format!(
            "{} {} {} {}\n",
            ms(idle_at),
            ms(busy_at),
            ms(busy_at),
            ms(end)
        ),
    )
    .map_err(|x| format!("{marks}: {x}"))?;
    eprintln!(
        "shape: {} rounds, {} messages sent in the busy phase; marks in {marks}",
        round,
        sent.len()
    );
    if sent.is_empty() {
        return Err("no message went out in the busy phase".into());
    }
    // Every message sent in the busy phase arrived.
    let mut seen = Seen::default();
    let ada_root = ada.root();
    for (i, reader) in readers.iter_mut().enumerate() {
        let who = NAMES[i + 1];
        let mut missing: std::collections::HashSet<&str> = sent
            .iter()
            .filter(|(to, _)| *to == i)
            .map(|(_, text)| text.as_str())
            .collect();
        let t = Instant::now();
        while !missing.is_empty() {
            for ev in seen.sync(reader, who).await? {
                if let Event::Message { root, message } = &ev
                    && *root == ada_root
                {
                    missing.remove(message.text.as_str());
                }
            }
            if t.elapsed() > PATIENCE {
                return Err(format!(
                    "{who}: {} of the busy phase's messages missing",
                    missing.len()
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        eprintln!("  {who}: every busy-phase message arrived");
    }
    seen.no_split_views()
}
