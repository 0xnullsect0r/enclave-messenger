//! `enclave-admin`: tools for the foundation and for operators
//! (`docs/12-servers.md` §4, `docs/13-operators.md`).
//!
//! ```text
//! enclave-admin foundation-keygen SECRET_OUT PUBLIC_OUT
//! enclave-admin server-list build SPEC.toml --out FILE [--key SECRET] [--now UNIX]
//! enclave-admin server-list sign UNSIGNED --key SECRET --out LIST [--now UNIX]
//! enclave-admin server-list verify LIST --foundation PUBLIC [--held-seq N] [--now UNIX]
//! enclave-admin kt-pins LIST --foundation PUBLIC --out PINS [--now UNIX]
//! enclave-admin descriptor verify server|witness|relay FILE [--id HEX] [--now UNIX]
//! enclave-admin descriptor fetch DOMAIN --out FILE [--id HEX] [--ca PEM] [--now UNIX]
//! enclave-admin reports [show N | dismiss N | close-request-inbox HEX] [--socket PATH]
//! enclave-admin console COMMAND… [--socket PATH]
//! enclave-admin release keygen | root | targets | sign | online | verify   (`release.rs`)
//! ```
//!
//! `reports` and `console` talk to a running server through its console
//! socket (`enclave_server::admin`, default
//! `/var/lib/enclave/server/admin.sock`): run them in the server's
//! container, `docker compose exec server enclave-admin reports`.
//!
//! `build` without `--key` writes the list unsigned: the foundation key
//! can then stay on an offline machine, where `sign` shows what it is about
//! to sign, signs, and checks the result. `descriptor fetch` gets a
//! server's descriptor from `https://DOMAIN/.well-known/enclave` over the
//! Enclave TLS profile (`--ca` adds a root, for a test or private CA) and
//! verifies it before writing it.
//!
//! The list is built from the signed descriptors operators submit: each is
//! verified (signature, validity, and for servers every key certificate)
//! before its long-lived facts go into the list. The spec names the
//! descriptor files, relative to the spec:
//!
//! ```toml
//! seq = 12
//! valid_days = 30
//! witness_threshold = 2
//!
//! [[server]]
//! descriptor = "ops/a/descriptor.bin"
//! weight = 3
//!
//! [[witness]]
//! descriptor = "ops/w1/witness.bin"
//!
//! [[relay]]
//! descriptor = "ops/r1/relay.bin"
//!
//! [[push]]
//! nym_address = "…"
//! keys = "push/push-relay-keys.bin"
//!
//! [[credgate]]
//! url = "https://enclave.example"
//! issuer_name = "enclave.example"
//! keys = "credgate/keys.txt"   # `enclave-credgate show-key --epochs 4`
//! ```
//!
//! A gate's key file holds one `EPOCH HEX` line per epoch; list the
//! epochs the list will be valid for (and the one after, for clients that
//! keep a list until a newer one arrives).
#![forbid(unsafe_code)]

mod release;

use enclave_crypto::rng::HedgedRng;
use enclave_federation::{
    CredGateEntry, FoundationKey, FoundationPublic, ListedRelay, ListedServer, ListedWitness,
    PushRelayEntry, RelayDescriptor, ServerDescriptor, ServerList, WitnessDescriptor,
};
use enclave_service::config::{flag, hex, unhex};
use enclave_service::keyfile;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Bytes of one push-relay key: `u32 epoch ‖ X448 ‖ ML-KEM-1024`.
const PUSH_KEY_LEN: usize = 4 + 56 + 1568;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    seq: u64,
    valid_days: u64,
    witness_threshold: u8,
    #[serde(default)]
    server: Vec<ServerSpec>,
    #[serde(default)]
    witness: Vec<FileSpec>,
    #[serde(default)]
    relay: Vec<FileSpec>,
    #[serde(default)]
    push: Vec<PushSpec>,
    #[serde(default)]
    credgate: Vec<GateSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateSpec {
    url: String,
    issuer_name: String,
    keys: PathBuf,
}

/// A gate's key file: `EPOCH HEX` per line (`enclave-credgate show-key`).
fn gate_keys(text: &str) -> Result<Vec<(u32, [u8; 49])>, String> {
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (e, k) = line
            .split_once(' ')
            .ok_or_else(|| format!("{line:?}: expected EPOCH HEX"))?;
        let e: u32 = e.parse().map_err(|_| format!("{e:?}: not an epoch"))?;
        let k: [u8; 49] = unhex(k.trim())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("epoch {e}: not a 49-byte key"))?;
        keys.push((e, k));
    }
    Ok(keys)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSpec {
    descriptor: PathBuf,
    weight: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    descriptor: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushSpec {
    nym_address: String,
    keys: PathBuf,
}

fn now_or(args: &[String]) -> Result<u64, String> {
    match flag(args, "--now") {
        Some(t) => t.parse().map_err(|_| format!("--now {t}: not a number")),
        None => Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn positional(args: &[String], i: usize, what: &str) -> Result<String, String> {
    args.get(i)
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("missing {what}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().take(2).map(String::as_str).collect();
    let result = match words.as_slice() {
        ["foundation-keygen", ..] => foundation_keygen(&args),
        ["server-list", "build", ..] => build(&args),
        ["server-list", "sign", ..] => sign(&args),
        ["server-list", "verify", ..] => verify(&args),
        ["kt-pins", ..] => kt_pins(&args),
        ["descriptor", "verify", ..] => verify_descriptor(&args),
        ["descriptor", "fetch", ..] => fetch_descriptor(&args),
        ["reports", ..] => reports(&args),
        ["console", ..] => console(&args),
        ["release", ..] => release::run(&args),
        _ => Err("usage: enclave-admin foundation-keygen | server-list build|sign|verify | kt-pins | descriptor verify|fetch | reports | console | release (see the module docs)".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-admin: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Default console socket of a server in the compose stack.
#[cfg(unix)]
const CONSOLE: &str = "/var/lib/enclave/server/admin.sock";

/// Send one command to a running server's console; print its answer.
#[cfg(unix)]
fn ask(args: &[String], line: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    let path = flag(args, "--socket").unwrap_or_else(|| CONSOLE.to_string());
    let mut s = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| format!("{path}: {e} (is the server running, and is this its container?)"))?;
    s.write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut answer = String::new();
    s.read_to_string(&mut answer).map_err(|e| e.to_string())?;
    print!("{answer}");
    if answer.starts_with("ok") {
        Ok(())
    } else {
        Err("the server refused".into())
    }
}

#[cfg(not(unix))]
fn ask(_: &[String], _: &str) -> Result<(), String> {
    Err("the server console is a Unix socket".into())
}

/// The words of `args` from `from` on, up to the first `--flag`.
fn words_from(args: &[String], from: usize) -> Vec<&str> {
    args.iter()
        .skip(from)
        .take_while(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect()
}

fn reports(args: &[String]) -> Result<(), String> {
    let line = match words_from(args, 1).as_slice() {
        [] => "reports".to_string(),
        ["show", n] => format!("report {n}"),
        ["dismiss", n] => format!("dismiss {n}"),
        ["close-request-inbox", h] => format!("close-request-inbox {h}"),
        _ => {
            return Err(
                "usage: enclave-admin reports [show N | dismiss N | close-request-inbox HEX]"
                    .into(),
            );
        }
    };
    ask(args, &line)
}

fn console(args: &[String]) -> Result<(), String> {
    let words = words_from(args, 1);
    if words.is_empty() {
        return Err("usage: enclave-admin console COMMAND…".into());
    }
    ask(args, &words.join(" "))
}

fn foundation_keygen(args: &[String]) -> Result<(), String> {
    let secret = PathBuf::from(positional(args, 1, "SECRET_OUT")?);
    let public = PathBuf::from(positional(args, 2, "PUBLIC_OUT")?);
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let key = FoundationKey::generate(&mut rng).map_err(|e| e.to_string())?;
    keyfile::create_secret(&secret, &key.to_bytes()).map_err(|e| e.to_string())?;
    if public.exists() {
        return Err(format!("{} exists", public.display()));
    }
    std::fs::write(&public, key.public().encode())
        .map_err(|e| format!("{}: {e}", public.display()))?;
    eprintln!(
        "foundation key written to {}; keep it offline. Its public key ({}) is built into every client.",
        secret.display(),
        public.display()
    );
    Ok(())
}

fn foundation(args: &[String]) -> Result<FoundationPublic, String> {
    FoundationPublic::decode(&read(Path::new(&need(args, "--foundation")?))?)
        .map_err(|e| format!("foundation public key: {e}"))
}

fn build(args: &[String]) -> Result<(), String> {
    let spec_path = PathBuf::from(positional(args, 2, "SPEC.toml")?);
    let base = spec_path.parent().unwrap_or(Path::new("."));
    let text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let spec: Spec = toml::from_str(&text).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let now = now_or(args)?;
    let key = flag(args, "--key")
        .map(|k| load_key(Path::new(&k)))
        .transpose()?;
    if spec.valid_days == 0 || spec.valid_days > 90 {
        return Err("valid_days must be 1 to 90".into());
    }
    let mut servers = Vec::new();
    for s in &spec.server {
        let p = base.join(&s.descriptor);
        let d =
            ServerDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        if servers
            .iter()
            .any(|x: &ListedServer| x.id() == d.id() || x.domain.eq_ignore_ascii_case(&d.domain))
        {
            return Err(format!("{}: server or domain listed twice", p.display()));
        }
        servers.push(ListedServer {
            identity: d.identity.clone(),
            domain: d.domain.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            nym_address: d.nym_address.clone(),
            weight: s.weight,
            kt: d.kt.clone(),
        });
    }
    let mut witnesses = Vec::new();
    for w in &spec.witness {
        let p = base.join(&w.descriptor);
        let d =
            WitnessDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        witnesses.push(ListedWitness {
            key: d.key.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            url: d.url.clone(),
        });
    }
    if usize::from(spec.witness_threshold) > witnesses.len() {
        return Err(format!(
            "witness_threshold {} but only {} witnesses",
            spec.witness_threshold,
            witnesses.len()
        ));
    }
    let mut relays = Vec::new();
    for r in &spec.relay {
        let p = base.join(&r.descriptor);
        let d = RelayDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        relays.push(ListedRelay {
            identity: d.identity.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            addr: d.addr.clone(),
            link_key: d.link_key,
        });
    }
    let mut push = Vec::new();
    for x in &spec.push {
        let p = base.join(&x.keys);
        let b = read(&p)?;
        if b.is_empty() || b.len() % PUSH_KEY_LEN != 0 {
            return Err(format!("{}: not a push-relay key file", p.display()));
        }
        push.push(PushRelayEntry {
            nym_address: x.nym_address.clone(),
            keys: b.chunks(PUSH_KEY_LEN).map(<[u8]>::to_vec).collect(),
        });
    }
    let mut credgates = Vec::new();
    for g in &spec.credgate {
        let p = base.join(&g.keys);
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let keys = gate_keys(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        let epoch = (now / (30 * 86_400)) as u32;
        if !keys.iter().any(|(e, _)| *e == epoch) {
            return Err(format!("{}: no key for this epoch ({epoch})", p.display()));
        }
        credgates.push(CredGateEntry {
            url: g.url.clone(),
            issuer_name: g.issuer_name.clone(),
            keys,
        });
    }
    let list = ServerList {
        seq: spec.seq,
        issued: now,
        expires: now + spec.valid_days * 86_400,
        witness_threshold: spec.witness_threshold,
        servers,
        witnesses,
        relays,
        push,
        credgates,
    };
    let out = need(args, "--out")?;
    match key {
        Some(key) => write_signed(&list, &key, now, &out),
        None => {
            let b = list.encode_unsigned().map_err(|e| e.to_string())?;
            std::fs::write(&out, b).map_err(|e| format!("{out}: {e}"))?;
            eprintln!(
                "unsigned server list seq {} → {out}; sign it with `server-list sign` where the foundation key is",
                list.seq
            );
            Ok(())
        }
    }
}

fn load_key(path: &Path) -> Result<FoundationKey, String> {
    FoundationKey::from_bytes(&keyfile::read_secret(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("foundation key: {e}"))
}

/// Sign, check that what is written verifies, write.
fn write_signed(list: &ServerList, key: &FoundationKey, now: u64, out: &str) -> Result<(), String> {
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let signed = list.sign(key, &mut rng).map_err(|e| e.to_string())?;
    ServerList::verify(&signed, &key.public(), now, 0).map_err(|e| e.to_string())?;
    std::fs::write(out, &signed).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "server list seq {} with {} servers, {} witnesses, {} relays, {} push relays → {out}",
        list.seq,
        list.servers.len(),
        list.witnesses.len(),
        list.relays.len(),
        list.push.len()
    );
    Ok(())
}

/// Sign a list built elsewhere, after showing what it holds.
fn sign(args: &[String]) -> Result<(), String> {
    let path = positional(args, 2, "UNSIGNED")?;
    let list = ServerList::decode_unsigned(&read(Path::new(&path))?)
        .map_err(|e| format!("{path}: {e}"))?;
    let now = now_or(args)?;
    if list.expires <= now {
        return Err(format!("{path}: already expired"));
    }
    print_list(&list);
    let key = load_key(Path::new(&need(args, "--key")?))?;
    write_signed(&list, &key, now, &need(args, "--out")?)
}

/// Fetch a server's descriptor from its front and check it.
fn fetch_descriptor(args: &[String]) -> Result<(), String> {
    let domain = positional(args, 2, "DOMAIN")?;
    let base = if domain.starts_with("https://") {
        domain.trim_end_matches('/').to_string()
    } else {
        format!("https://{domain}")
    };
    let ca = flag(args, "--ca").map(PathBuf::from);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let bytes = rt.block_on(get_https(
        &format!("{base}/.well-known/enclave"),
        ca.as_deref(),
    ))?;
    let d = ServerDescriptor::decode(&bytes).map_err(|e| format!("{base}: {e}"))?;
    d.verify(now_or(args)?)
        .map_err(|e| format!("{base}: {e}"))?;
    if let Some(want) = flag(args, "--id")
        && unhex(&want).as_deref() != Some(&d.id()[..])
    {
        return Err(format!("{base} serves {}, not {want}", hex(&d.id())));
    }
    let out = need(args, "--out")?;
    std::fs::write(&out, &bytes).map_err(|e| format!("{out}: {e}"))?;
    println!(
        "server {} {} ({}, {}) → {out}",
        hex(&d.id()),
        d.domain,
        d.operator,
        d.family
    );
    Ok(())
}

/// GET `url` over the Enclave TLS profile (the public web's roots, plus
/// `ca`).
async fn get_https(url: &str, ca: Option<&Path>) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(p) = ca {
        for c in CertificateDer::pem_slice_iter(&read(p)?) {
            roots
                .add(c.map_err(|e| format!("{}: {e}", p.display()))?)
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
    tls.alpn_protocols.clear();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    let res = tokio::time::timeout(std::time::Duration::from_secs(30), client.get(uri))
        .await
        .map_err(|_| format!("{url}: timeout"))?
        .map_err(|e| format!("{url}: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("{url}: HTTP {}", res.status()));
    }
    let body = http_body_util::Limited::new(res.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    Ok(body.to_bytes().to_vec())
}

fn load_list(args: &[String]) -> Result<ServerList, String> {
    let path = positional(args, if args[0] == "kt-pins" { 1 } else { 2 }, "LIST")?;
    let held = match flag(args, "--held-seq") {
        Some(n) => n
            .parse()
            .map_err(|_| format!("--held-seq {n}: not a number"))?,
        None => 0,
    };
    ServerList::verify(
        &read(Path::new(&path))?,
        &foundation(args)?,
        now_or(args)?,
        held,
    )
    .map_err(|e| format!("{path}: {e}"))
}

fn verify(args: &[String]) -> Result<(), String> {
    print_list(&load_list(args)?);
    Ok(())
}

fn print_list(l: &ServerList) {
    println!(
        "seq {}  issued {}  expires {}  witness threshold {}",
        l.seq, l.issued, l.expires, l.witness_threshold
    );
    for s in &l.servers {
        println!(
            "server  {}  {}  {} ({})  weight {}{}",
            hex(&s.id()),
            s.domain,
            s.operator,
            s.family,
            s.weight,
            if s.kt.is_some() { "  kt" } else { "" }
        );
    }
    for w in &l.witnesses {
        println!(
            "witness {}  {} ({})  {}",
            hex(&w.id()),
            w.operator,
            w.family,
            w.url
        );
    }
    for r in &l.relays {
        println!(
            "relay   {}  {} ({})  {}",
            hex(&enclave_federation::relay_id(&r.identity)),
            r.operator,
            r.family,
            r.addr
        );
    }
    for p in &l.push {
        println!("push    {}  {} keys", p.nym_address, p.keys.len());
    }
    for g in &l.credgates {
        let epochs: Vec<String> = g.keys.iter().map(|(e, _)| e.to_string()).collect();
        println!(
            "gate    {}  {}  epochs {}",
            g.url,
            g.issuer_name,
            epochs.join(",")
        );
    }
}

fn kt_pins(args: &[String]) -> Result<(), String> {
    let l = load_list(args)?;
    let pins = enclave_kt::KtPolicy::from_server_list(&l);
    let out = need(args, "--out")?;
    std::fs::write(&out, pins.encode()).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "pins for {} logs and {} witnesses (threshold {}) → {out}",
        pins.servers.len(),
        pins.witnesses.witnesses.len(),
        pins.witnesses.threshold
    );
    Ok(())
}

fn verify_descriptor(args: &[String]) -> Result<(), String> {
    let kind = positional(args, 2, "server|witness|relay")?;
    let path = positional(args, 3, "FILE")?;
    let b = read(Path::new(&path))?;
    let now = now_or(args)?;
    let id = match kind.as_str() {
        "server" => {
            let d = ServerDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "server {} {} ({}, {})",
                hex(&d.id()),
                d.domain,
                d.operator,
                d.family
            );
            d.id()
        }
        "witness" => {
            let d = WitnessDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "witness {} {} ({}) {}",
                hex(&d.id()),
                d.operator,
                d.family,
                d.url
            );
            d.id()
        }
        "relay" => {
            let d = RelayDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "relay {} {} ({}) {}",
                hex(&d.id()),
                d.operator,
                d.family,
                d.addr
            );
            d.id()
        }
        other => return Err(format!("{other}: expected server, witness or relay")),
    };
    if let Some(want) = flag(args, "--id")
        && unhex(&want).as_deref() != Some(&id[..])
    {
        return Err(format!("{path} is {}, not {want}", hex(&id)));
    }
    Ok(())
}
