//! The Enclave server binary (`docs/12-servers.md` §1, `ops/compose`).
//!
//! ```text
//! enclave-server init        [--config FILE]   create keys; print the server id
//! enclave-server run         [--config FILE]   serve (state in redb, keys from disk)
//! enclave-server show-id     [--config FILE]   print the server id
//! enclave-server backup DIR  [--config FILE]   write a consistent snapshot now
//! enclave-server restore SNAPSHOT [--config FILE]   put a snapshot back (server stopped)
//! enclave-server descriptor  [--config FILE]   verify and describe the published descriptor
//! enclave-server descriptor OUT [--config FILE]  sign a descriptor now (for the foundation's list)
//! enclave-server healthcheck [--config FILE]   exit 0 if the server answers
//! enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]
//! ```
//!
//! `run` listens on `server.listen` with the length-prefixed frame
//! transport (`u32 BE length ‖ bytes`; a zero-length frame asks for the
//! signed key bundle, `enclave_federation::KeyBundle`). In production that port is reachable only from
//! the Nym ingress on the stack's internal network, never from outside.
//!
//! `dev` is the old all-in-memory development server: random keys every
//! start (it prints its server id), nothing persisted. It is what a bare `enclave-server [ADDR]`
//! runs, for local development and the test suites.

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{KeyBundle, server_id};
use enclave_kt::{KtService, KtStore};
use enclave_server::config::FileConfig;
use enclave_server::db::Db;
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use enclave_service::config::{flag, hex};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn today() -> u32 {
    (now() / 86_400) as u32
}

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    FileConfig::load(path.as_deref(), std::env::vars()).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("dev");
    let result = match cmd {
        "init" => init(&args),
        "run" => runtime().and_then(|rt| rt.block_on(run(&args))),
        "show-id" => show_id(&args),
        "backup" => backup_now(&args),
        "restore" => restore(&args),
        "descriptor" => match args.get(1).filter(|a| !a.starts_with("--")) {
            Some(out) => write_descriptor(&args, out),
            None => show_descriptor(&args),
        },
        "healthcheck" => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        "dev" => runtime().and_then(|rt| rt.block_on(dev(&args[1.min(args.len())..]))),
        "--help" | "-h" | "help" => {
            eprintln!(
                "usage: enclave-server init|run|show-id|descriptor|healthcheck [--config FILE]\n       enclave-server backup DIR | restore SNAPSHOT [--config FILE]\n       enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]"
            );
            Ok(())
        }
        // `enclave-server [ADDR] [--flags]`: the development server.
        _ => runtime().and_then(|rt| rt.block_on(dev(&args))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn init(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = ServerKeys::init(&cfg.server.keys_dir, today()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.server.data_dir).map_err(|e| e.to_string())?;
    println!("{}", hex(&keys.id()));
    eprintln!(
        "keys created in {}; back this directory up somewhere safe and offline",
        cfg.server.keys_dir.display()
    );
    Ok(())
}

fn show_id(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = ServerKeys::load(&cfg.server.keys_dir).map_err(|e| e.to_string())?;
    println!("{}", hex(&keys.id()));
    Ok(())
}

fn db_path(cfg: &FileConfig) -> PathBuf {
    cfg.server.data_dir.join("server.redb")
}

/// The server's database: PostgreSQL if `[database]` names one, otherwise
/// the redb file in `data_dir`.
fn open_db(cfg: &FileConfig) -> Result<Db, String> {
    match cfg.database.postgres_url().map_err(|e| e.to_string())? {
        Some(url) => Db::connect(&url).map_err(|e| format!("postgres: {e}")),
        None => Db::open(&db_path(cfg)).map_err(|e| e.to_string()),
    }
}

fn kt_path(cfg: &FileConfig) -> PathBuf {
    cfg.server.data_dir.join("kt.redb")
}

/// Write `server-<unix time>.redb` (and `kt-<unix time>.redb`) into `dir`
/// and keep the newest `keep` of each.
fn snapshot(db: &Db, kt: Option<&KtStore>, dir: &Path, keep: usize) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let t = now();
    let path = dir.join(format!("server-{t}.redb"));
    db.snapshot(&path).map_err(|e| e.to_string())?;
    if let Some(kt) = kt {
        kt.snapshot(&dir.join(format!("kt-{t}.redb")))
            .map_err(|e| e.to_string())?;
    }
    for prefix in ["server-", "kt-"] {
        let mut old: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".redb"))
            })
            .collect();
        old.sort();
        while old.len() > keep.max(1) {
            let p = old.remove(0);
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(path)
}

fn backup_now(args: &[String]) -> Result<(), String> {
    let dir = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: enclave-server backup DIR")?;
    let cfg = load_config(args)?;
    // redb allows one process per file: this works only while `run` is
    // stopped; a running server takes its own snapshots (`[backup]`).
    // PostgreSQL is snapshotted in one transaction while it runs.
    let db = open_db(&cfg)?;
    let kt = if kt_path(&cfg).exists() {
        Some(KtStore::open(&kt_path(&cfg)).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let p = snapshot(&db, kt.as_ref(), Path::new(dir), usize::MAX)?;
    println!("{}", p.display());
    Ok(())
}

/// Put a snapshot written by `backup` (or by `run`'s `[backup]`) back:
/// `server-<t>.redb`, and `kt-<t>.redb` next to it if there is one. The
/// server must be stopped; the files it replaces are kept as `*.old`. The
/// key directory is restored separately (it isn't in snapshots).
fn restore(args: &[String]) -> Result<(), String> {
    let snap = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .ok_or("usage: enclave-server restore SNAPSHOT")?;
    let name = snap
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.starts_with("server-") && n.ends_with(".redb"))
        .ok_or("expected a server-<time>.redb snapshot")?;
    let cfg = load_config(args)?;
    // Opening it checks it is a database this server can read.
    let snap_db = Db::open(&snap).map_err(|e| format!("{}: {e}", snap.display()))?;
    let kt_snap = snap.with_file_name(name.replacen("server-", "kt-", 1));
    let mut pairs = Vec::new();
    if let Some(url) = cfg.database.postgres_url().map_err(|e| e.to_string())? {
        // Into PostgreSQL: everything replaced in one transaction.
        let db = Db::connect(&url).map_err(|e| format!("postgres: {e}"))?;
        db.copy_from(&snap_db).map_err(|e| e.to_string())?;
        println!("{} -> postgres", snap.display());
    } else {
        // redb takes a lock: if `run` holds the database, this fails here.
        drop(Db::open(&db_path(&cfg)).map_err(|e| format!("is the server running? {e}"))?);
        pairs.push((snap.clone(), db_path(&cfg)));
    }
    drop(snap_db);
    if kt_snap.exists() {
        pairs.push((kt_snap, kt_path(&cfg)));
    }
    for (from, to) in pairs {
        if to.exists() {
            std::fs::rename(&to, to.with_extension("redb.old")).map_err(|e| e.to_string())?;
        }
        std::fs::copy(&from, &to).map_err(|e| format!("{}: {e}", from.display()))?;
        println!("{} -> {}", from.display(), to.display());
    }
    Ok(())
}

/// Verify `public_dir/descriptor.bin` and print what it says.
fn show_descriptor(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let path = cfg.server.public_dir.join("descriptor.bin");
    let b = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let d = enclave_federation::ServerDescriptor::decode(&b).map_err(|e| e.to_string())?;
    d.verify(now()).map_err(|e| format!("descriptor: {e}"))?;
    println!("id        {}", hex(&d.id()));
    println!("domain    {}", d.domain);
    println!("operator  {} (family {})", d.operator, d.family);
    println!(
        "nym       {}",
        if d.nym_address.is_empty() {
            "-"
        } else {
            &d.nym_address
        }
    );
    println!("kt        {}", if d.kt.is_some() { "yes" } else { "no" });
    for c in &d.certs {
        println!(
            "key       day {} (valid {}..{})",
            c.key.key_id, c.not_before, c.not_after
        );
    }
    println!("expires   {}", d.expires);
    Ok(())
}

async fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(cfg.server.listen),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e.to_string())?;
    s.write_all(&0u32.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > enclave_wire::UNIT_LEN {
        return Err("no key bundle".into());
    }
    let mut b = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut b))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    // The bundle must be well formed and current for the identity it names.
    let bundle = KeyBundle::decode(&b).map_err(|e| format!("key bundle: {e}"))?;
    bundle
        .verify(&server_id(&bundle.identity), now())
        .map_err(|e| format!("key bundle: {e}"))?;
    Ok(())
}

/// Request keys certified by the identity key.
fn key_bundle(
    identity: &CompositeSigningKey,
    keys: &[enclave_rpc::ServerKey],
) -> Result<Vec<u8>, String> {
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    KeyBundle::sign(identity, keys, &mut rng)
        .map(|b| b.encode())
        .map_err(|e| e.to_string())
}

/// The bundle for the chain's current state: today's key and tomorrow's.
fn chain_bundle(keys: &ServerKeys) -> Result<Vec<u8>, String> {
    let today = keys.chain.keys()[0].public().clone();
    let next = keys.chain.next_key().public().clone();
    key_bundle(&keys.identity, &[today, next])
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = ServerKeys::load(&cfg.server.keys_dir).map_err(|e| e.to_string())?;
    keys.chain.advance_to(today()).map_err(|e| e.to_string())?;
    let id = keys.id();
    std::fs::create_dir_all(&cfg.server.data_dir).map_err(|e| e.to_string())?;
    let db = open_db(&cfg)?;
    eprintln!("state: {}", db.backend());
    let mut server =
        Server::open(cfg.policy(id), db, keys.chain.keys()).map_err(|e| e.to_string())?;
    server.set_key_bundle(chain_bundle(&keys)?);
    server.set_blob_seed(keys.blob_seed());
    // The username log: its own file, the same head key and VRF secret
    // every run, so what clients pin stays valid. Witnesses are other
    // operators' services (`docs/12-servers.md` §3.3); until they are
    // configured, heads carry no cosignatures and clients refuse lookups.
    let kt_store = if cfg.kt.enabled {
        // Clients never count a witness run by the log's own operator, so
        // the log has to say who runs it.
        if cfg.server.operator.is_empty() {
            return Err("set server.operator (key transparency names the operator)".into());
        }
        let store = KtStore::open(&kt_path(&cfg)).map_err(|e| e.to_string())?;
        // Witnesses are connected when first needed and again after a
        // failure, so the server starts whether or not they are up; heads
        // get their cosignatures once enough answer.
        let mut witnesses: Vec<Box<dyn enclave_kt::WitnessClient>> = Vec::new();
        let mut pinned = Vec::new();
        for url in &cfg.kt.witnesses {
            let mut w = enclave_witness::LazyWitness::new(url, cfg.kt.witness_ca.as_deref());
            // Try now; reachable witnesses also go into the development
            // pins file.
            let _ = enclave_kt::WitnessClient::last_epoch(&mut w, &id).await;
            match w.descriptor() {
                Some(d) => pinned.push((d.id(), d.key.clone(), d.operator.clone())),
                None => eprintln!("witness {url}: not reachable yet; will retry"),
            }
            witnesses.push(Box::new(w));
        }
        let kt = KtService::open(
            store.clone(),
            id,
            &cfg.server.domain,
            &cfg.server.operator,
            keys.kt_head_copy().map_err(|e| e.to_string())?,
            *keys.kt_vrf,
            witnesses,
            now(),
        )
        .map_err(|e| format!("key transparency: {e}"))?;
        let policy = enclave_kt::KtPolicy {
            servers: vec![kt.info().clone()],
            // For development clients; real clients pin the server list.
            witnesses: enclave_kt::WitnessPolicy {
                threshold: pinned.len().max(1),
                witnesses: pinned,
            },
        };
        kt.set_batch_window(std::time::Duration::from_secs(cfg.kt.batch_secs));
        server.enable_kt(kt);
        for name in &cfg.kt.withdrawn {
            match server.withdraw_username(name, now()) {
                Ok(true) => eprintln!("username {name}: withdrawn"),
                Ok(false) => {}
                Err(e) => eprintln!("username {name}: can't withdraw: {e}"),
            }
        }
        std::fs::create_dir_all(&cfg.server.public_dir).map_err(|e| e.to_string())?;
        let pins = cfg.server.public_dir.join("kt-pins.bin");
        std::fs::write(&pins, policy.encode()).map_err(|e| format!("{}: {e}", pins.display()))?;
        Some(store)
    } else {
        None
    };
    publish_descriptor(&cfg, &keys, &mut server)?;
    let mut list_seen = (None, None);
    refresh_server_list(&cfg, &mut server, &mut list_seen);
    eprintln!(
        "enclave-server {} ({}) listening on {}",
        hex(&id),
        cfg.server.domain,
        cfg.server.listen
    );
    let server = Arc::new(Mutex::new(server));
    let keys = Arc::new(Mutex::new(keys));

    // Once a minute: step the request-key chain at midnight UTC (yesterday's
    // seed is kept a day, older ones are erased) and expire old objects.
    {
        let server = Arc::clone(&server);
        let keys = Arc::clone(&keys);
        let cfg = cfg.clone();
        let mut published = (ingress_address(&cfg), onion_address(&cfg));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let mut k = keys.lock().await;
                match k.chain.advance_to(today()) {
                    Ok(true) => {
                        let bundle = chain_bundle(&k);
                        let mut s = server.lock().await;
                        for key in k.chain.keys().into_iter().rev() {
                            s.install_key(key);
                        }
                        match bundle {
                            Ok(b) => s.set_key_bundle(b),
                            Err(e) => eprintln!("key bundle failed: {e}"),
                        }
                        // A new day's keys: a new descriptor.
                        if let Err(e) = publish_descriptor(&cfg, &k, &mut s) {
                            eprintln!("descriptor failed: {e}");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("request-key rotation failed: {e}"),
                }
                // The ingress connected (or moved), or the onion service
                // came up: a descriptor naming them.
                let now_at = (ingress_address(&cfg), onion_address(&cfg));
                if now_at != published {
                    let mut s = server.lock().await;
                    match publish_descriptor(&cfg, &k, &mut s) {
                        Ok(()) => published = now_at,
                        Err(e) => eprintln!("descriptor failed: {e}"),
                    }
                }
                drop(k);
                let mut s = server.lock().await;
                s.expire(now());
                refresh_server_list(&cfg, &mut s, &mut list_seen);
                // Proofs that a log equivocated go to every witness we know.
                let proofs = s.take_equivocations();
                if !proofs.is_empty() {
                    let mut urls = cfg.kt.witnesses.clone();
                    urls.extend(s.listed_witnesses().iter().cloned());
                    urls.sort();
                    urls.dedup();
                    let ca = cfg.kt.witness_ca.clone();
                    tokio::spawn(forward_equivocations(urls, ca, proofs));
                }
            }
        });
    }
    if let Some(dir) = cfg.backup.dir.clone() {
        let server = Arc::clone(&server);
        let every = Duration::from_secs(cfg.backup.interval_hours.max(1) * 3600);
        let keep = cfg.backup.keep;
        let kt = kt_store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let s = server.lock().await;
                match snapshot(s.db(), kt.as_ref(), &dir, keep) {
                    Ok(p) => eprintln!("backup written: {}", p.display()),
                    Err(e) => eprintln!("backup failed: {e}"),
                }
            }
        });
    }
    if let Some(fwd) = cfg.push.forward.clone() {
        spawn_push_forwarder(Arc::clone(&server), fwd);
    }
    #[cfg(unix)]
    spawn_admin_socket(
        Arc::clone(&server),
        cfg.server.data_dir.join(enclave_server::admin::SOCKET),
    )?;
    let listener = TcpListener::bind(cfg.server.listen)
        .await
        .map_err(|e| e.to_string())?;
    let accept = serve(listener, Arc::clone(&server));
    tokio::select! {
        r = accept => r,
        _ = shutdown_signal() => {
            // Every request commits before its reply, so taking the lock
            // waits for the one in flight; then the process can stop.
            let _ = server.lock().await;
            eprintln!("enclave-server: stopped");
            Ok(())
        }
    }
}

/// Sign today's descriptor, serve it (`DirKind::Descriptor`), write it to
/// `public_dir/descriptor.bin` for the front, and commit its digest to the
/// key-transparency log.
fn publish_descriptor(
    cfg: &FileConfig,
    keys: &ServerKeys,
    server: &mut Server,
) -> Result<(), String> {
    let t = now();
    let kt = server.kt_info().map(|i| enclave_federation::KtKeys {
        head_key: i.head_key,
        vrf_public: i.vrf_public,
    });
    let d = sign_descriptor(cfg, keys, kt, t)?;
    let bytes = d.encode();
    std::fs::create_dir_all(&cfg.server.public_dir).map_err(|e| e.to_string())?;
    let path = cfg.server.public_dir.join("descriptor.bin");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    server.set_descriptor(bytes);
    if let Some(Err(e)) = server.commit_descriptor(d.digest(), t) {
        eprintln!("committing the descriptor to the log failed: {e}");
    }
    Ok(())
}

/// The Nym address clients reach this server at: `[server] nym_address`,
/// or what the stack's ingress wrote to `public_dir/ingress.addr` once it
/// connected; empty before either.
fn ingress_address(cfg: &FileConfig) -> String {
    if !cfg.server.nym_address.is_empty() {
        return cfg.server.nym_address.clone();
    }
    std::fs::read_to_string(cfg.server.public_dir.join("ingress.addr"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The onion address of the stack's fallback route (`enclave-onion`, which
/// writes `public_dir/onion.addr`); empty without one.
fn onion_address(cfg: &FileConfig) -> String {
    std::fs::read_to_string(cfg.server.public_dir.join("onion.addr"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Today's descriptor: valid two days, today's and tomorrow's request keys.
fn sign_descriptor(
    cfg: &FileConfig,
    keys: &ServerKeys,
    kt: Option<enclave_federation::KtKeys>,
    t: u64,
) -> Result<enclave_federation::ServerDescriptor, String> {
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    enclave_federation::ServerDescriptor::sign(
        &keys.identity,
        &cfg.server.domain,
        &cfg.server.operator,
        &cfg.server.family,
        &ingress_address(cfg),
        &onion_address(cfg),
        cfg.published_policy(),
        kt,
        &[
            keys.chain.keys()[0].public().clone(),
            keys.chain.next_key().public().clone(),
        ],
        &enclave_server::blob_issuers(&keys.blob_seed(), t),
        t,
        t + 2 * 86_400,
        &mut rng,
    )
    .map_err(|e| format!("descriptor: {e}"))
}

/// `descriptor OUT`: sign a descriptor without running the server (for
/// the foundation's list, before the first start). The key-transparency
/// keys are the ones `run` uses: the head key, and the VRF public key
/// derived from the VRF secret.
fn write_descriptor(args: &[String], out: &str) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = ServerKeys::load(&cfg.server.keys_dir).map_err(|e| e.to_string())?;
    keys.chain.advance_to(today()).map_err(|e| e.to_string())?;
    let kt = if cfg.kt.enabled {
        let head = keys.kt_head_copy().map_err(|e| e.to_string())?;
        let head_key = head.public().clone();
        let vrf = *keys.kt_vrf;
        let id = keys.id();
        let vrf_public = runtime()?.block_on(async {
            enclave_kt::KtLog::new(id, head, vrf)
                .await
                .map(|l| l.vrf_public().to_vec())
                .map_err(|e| e.to_string())
        })?;
        Some(enclave_federation::KtKeys {
            head_key,
            vrf_public,
        })
    } else {
        None
    };
    let d = sign_descriptor(&cfg, &keys, kt, now())?;
    std::fs::write(out, d.encode()).map_err(|e| format!("{out}: {e}"))?;
    println!("{}", hex(&d.id()));
    Ok(())
}

/// The largest update bundle relayed (`enclave_update::bundle::MAX_BUNDLE`).
const MAX_UPDATE_BUNDLE: usize = 4 << 20;

/// Serve the foundation's list from `server.server_list`, and the update
/// bundle from `server.update_bundle`, re-reading each file when its
/// modification time changes.
fn refresh_server_list(
    cfg: &FileConfig,
    server: &mut Server,
    seen: &mut (Option<std::time::SystemTime>, Option<std::time::SystemTime>),
) {
    if let Some(path) = &cfg.server.update_bundle
        && let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified())
        && seen.1 != Some(modified)
    {
        match std::fs::read(path) {
            Ok(b) if b.len() <= MAX_UPDATE_BUNDLE => {
                server.set_update_bundle(b);
                seen.1 = Some(modified);
            }
            Ok(_) => eprintln!("{}: too large", path.display()),
            Err(e) => eprintln!("{}: {e}", path.display()),
        }
    }
    let seen = &mut seen.0;
    let Some(path) = &cfg.server.server_list else {
        return;
    };
    let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
        return;
    };
    if *seen == Some(modified) {
        return;
    }
    match std::fs::read(path) {
        Ok(b) => {
            server.set_server_list(b);
            *seen = Some(modified);
        }
        Err(e) => eprintln!("{}: {e}", path.display()),
    }
}

/// Hand equivocation proofs to witnesses (`docs/12-servers.md` §3.8).
async fn forward_equivocations(
    urls: Vec<String>,
    ca: Option<std::path::PathBuf>,
    proofs: Vec<enclave_kt::Equivocation>,
) {
    for url in urls {
        let w = match enclave_witness::HttpWitness::connect(&url, ca.as_deref(), now()).await {
            Ok(w) => w,
            Err(e) => {
                eprintln!("equivocation: witness {url}: {e}");
                continue;
            }
        };
        for p in &proofs {
            match w.publish_equivocation(p).await {
                Ok(_) => eprintln!(
                    "equivocation of log {} (epoch {}) handed to {url}",
                    hex(&p.server()),
                    p.epoch()
                ),
                Err(e) => eprintln!("equivocation: {e}"),
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The operator's console (`enclave_server::admin`): one command per
/// connection on a Unix socket only the server's user can open.
#[cfg(unix)]
fn spawn_admin_socket(server: Arc<Mutex<Server>>, path: PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let _ = std::fs::remove_file(&path);
    let listener =
        tokio::net::UnixListener::bind(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (rd, mut wr) = sock.into_split();
                let mut line = String::new();
                let mut rd = BufReader::new(rd.take(4096));
                if rd.read_line(&mut line).await.is_err() {
                    return;
                }
                let answer =
                    enclave_server::admin::command(&mut *server.lock().await, line.trim(), now());
                let _ = wr.write_all(answer.as_bytes()).await;
            });
        }
    });
    Ok(())
}

fn spawn_push_forwarder(server: Arc<Mutex<Server>>, to: String) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let due = server.lock().await.due_wakes(now());
            if due.is_empty() {
                continue;
            }
            match tokio::net::TcpStream::connect(&to).await {
                Ok(mut s) => {
                    for sealed in due {
                        let _ = s.write_all(&(sealed.len() as u32).to_be_bytes()).await;
                        let _ = s.write_all(&sealed).await;
                    }
                }
                Err(e) => eprintln!("push forwarder unreachable: {e}"),
            }
        }
    });
}

async fn serve(listener: TcpListener, server: Arc<Mutex<Server>>) -> Result<(), String> {
    loop {
        let (mut sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
        // Each reply goes out whole at once: many requests share a stream
        // (an onion service's, the ingress's), and Nagle would hold every
        // answer back for the client's delayed acknowledgement.
        let _ = sock.set_nodelay(true);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len);
                // No reply wanted (a write, a cover unit): an empty frame.
                let oneway = len & enclave_wire::STREAM_ONEWAY != 0;
                let n = (len & !enclave_wire::STREAM_ONEWAY) as usize;
                if n > enclave_wire::UNIT_LEN {
                    return;
                }
                let mut buf = vec![0u8; n];
                if sock.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let reply = {
                    let mut s = server.lock().await;
                    if n == 0 {
                        s.key_bundle().to_vec()
                    } else {
                        s.handle(&buf, now())
                    }
                };
                let reply = if oneway { Vec::new() } else { reply };
                let frame = [&(reply.len() as u32).to_be_bytes()[..], &reply].concat();
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// The in-memory development server (`enclave-server [ADDR] …`).
async fn dev(args: &[String]) -> Result<(), String> {
    let addr = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7443".to_string());
    let day = today();
    // A fresh identity every start: nothing is kept, so neither is the id.
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let identity = CompositeSigningKey::generate(&mut rng).map_err(|e| e.to_string())?;
    let id = server_id(identity.public());
    let cfg = Config {
        id,
        ..Config::default()
    };
    let mut server = Server::new(cfg, day).map_err(|e| e.to_string())?;
    let key = server.public_key().ok_or("no request key")?;
    server.set_key_bundle(key_bundle(&identity, &[key])?);
    println!("{}", hex(&id));
    let domain = flag(args, "--domain").unwrap_or_else(|| "localhost".to_string());
    match enclave_kt::KtService::start_dev(id, &domain) {
        Ok((kt, policy)) => {
            server.enable_kt(kt);
            if let Some(path) = flag(args, "--kt-pins") {
                std::fs::write(&path, policy.encode()).map_err(|e| e.to_string())?;
                eprintln!("usernames on @{domain}; clients pin {path}");
            }
        }
        Err(e) => eprintln!("usernames disabled: {e}"),
    }
    let server = Arc::new(Mutex::new(server));
    {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            let mut current = day;
            loop {
                tick.tick().await;
                let today = today();
                let mut s = server.lock().await;
                if today != current {
                    if let Err(e) = s.rotate(today) {
                        eprintln!("key rotation failed: {e}");
                    } else {
                        current = today;
                        match s.public_key().map(|k| key_bundle(&identity, &[k])) {
                            Some(Ok(b)) => s.set_key_bundle(b),
                            _ => eprintln!("key bundle failed"),
                        }
                    }
                }
                s.expire(now());
            }
        });
    }
    if let Some(relay) = flag(args, "--push-relay") {
        spawn_push_forwarder(Arc::clone(&server), relay);
    }
    let listener = TcpListener::bind(&addr).await.map_err(|e| e.to_string())?;
    eprintln!(
        "enclave-server {} (dev transport, in memory) listening on {addr}",
        hex(&id)
    );
    serve(listener, server).await
}
