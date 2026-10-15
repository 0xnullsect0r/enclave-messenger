//! `enclave-admin release …`: the maintainers' tools for the update
//! channel (`docs/19-ops.md` §1, ADR 0005). Signing keys stay offline:
//! every document is built unsigned, shown, and signed by each maintainer
//! in turn on their own machine.
//!
//! ```text
//! enclave-admin release keygen SECRET_OUT PUBLIC_OUT
//! enclave-admin release root ROOT.toml --out UNSIGNED
//! enclave-admin release targets DIR --tag vX.Y.Z --version N [--valid-days 90] --out UNSIGNED [--now UNIX]
//! enclave-admin release sign DOC --key SECRET --index N --out DOC
//! enclave-admin release online TARGETS --key ONLINE_SECRET --index N --out-dir DIR [--valid-days 7] [--now UNIX]
//! enclave-admin release verify --root ROOT --dir DIR [--file F --proof P] [--now UNIX]
//! ```
//!
//! `ROOT.toml`:
//!
//! ```toml
//! version = 1
//! valid_days = 365
//! keys = ["m1.pub", "m2.pub", "m3.pub", "online.pub"]   # maintainers, then the online key
//! root = [0, 1, 2]
//! root_threshold = 2
//! targets = [0, 1, 2]
//! targets_threshold = 2
//! online = [3]                                            # snapshot and timestamp
//! [sigsum]
//! log = "hex Ed25519 key"
//! submitters = ["hex"]
//! witnesses = ["hex", "hex", "hex"]
//! quorum = 2
//! ```
//!
//! `online` writes `snapshot.bin` and `timestamp.bin` for a signed
//! `targets.bin` (the release workflow holds that key); `verify` checks
//! `timestamp.bin`, `snapshot.bin` and `targets.bin` in DIR against a root
//! as a client would, and a file with its Sigsum proof.

use crate::{need, now_or, positional, read};
use enclave_crypto::rng::HedgedRng;
use enclave_service::config::{flag, unhex};
use enclave_service::keyfile;
use enclave_update::sigsum::Policy;
use enclave_update::{
    Client, MaintainerKey, MaintainerPublic, Role, RoleKeys, Root, Signed, Snapshot, Target,
    Targets, Timestamp,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DAY: u64 = 86_400;

#[derive(Deserialize)]
struct RootSpec {
    version: u32,
    valid_days: u64,
    keys: Vec<String>,
    root: Vec<u8>,
    root_threshold: u8,
    targets: Vec<u8>,
    targets_threshold: u8,
    online: Vec<u8>,
    sigsum: SigsumSpec,
}

#[derive(Deserialize)]
struct SigsumSpec {
    log: String,
    submitters: Vec<String>,
    witnesses: Vec<String>,
    quorum: usize,
}

fn key32(s: &str) -> Result<[u8; 32], String> {
    unhex(s)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("not a 32-byte hex key: {s}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).into()
}

/// What a document says, for the person about to sign it.
fn describe(s: &Signed) -> Result<String, String> {
    let e = |e: enclave_update::UpdateError| e.to_string();
    Ok(match s.role {
        Role::Root => {
            let r = Root::decode(&s.body).map_err(e)?;
            format!(
                "root version {}, {} keys, root {}/{}, targets {}/{}, online {}/{}, Sigsum quorum {} of {} witnesses, expires {}",
                r.version,
                r.keys.len(),
                r.roles[0].threshold,
                r.roles[0].keys.len(),
                r.roles[1].threshold,
                r.roles[1].keys.len(),
                r.roles[3].threshold,
                r.roles[3].keys.len(),
                r.sigsum.quorum,
                r.sigsum.witnesses.len(),
                r.expires
            )
        }
        Role::Targets => {
            let t = Targets::decode(&s.body).map_err(e)?;
            let mut out = format!(
                "targets version {} for {}, expires {}:",
                t.version, t.release, t.expires
            );
            for f in &t.targets {
                out.push_str(&format!(
                    "\n  {} ({} B) sha256 {}",
                    f.name,
                    f.length,
                    enclave_service::config::hex(&f.sha256)
                ));
            }
            out
        }
        Role::Snapshot => format!(
            "snapshot version {}",
            Snapshot::decode(&s.body).map_err(e)?.version
        ),
        Role::Timestamp => format!(
            "timestamp version {}",
            Timestamp::decode(&s.body).map_err(e)?.version
        ),
    })
}

fn keygen(args: &[String]) -> Result<(), String> {
    let secret = PathBuf::from(positional(args, 2, "SECRET_OUT")?);
    let public = PathBuf::from(positional(args, 3, "PUBLIC_OUT")?);
    if public.exists() {
        return Err(format!("{} exists", public.display()));
    }
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let key = MaintainerKey::generate(&mut rng).map_err(|e| e.to_string())?;
    keyfile::create_secret(&secret, &key.to_bytes()).map_err(|e| e.to_string())?;
    write_new(&public, &key.public().to_bytes())?;
    eprintln!(
        "release key written to {}; keep it offline. Public key: {}",
        secret.display(),
        public.display()
    );
    Ok(())
}

fn root(args: &[String]) -> Result<(), String> {
    let spec_path = PathBuf::from(positional(args, 2, "ROOT.toml")?);
    let base = spec_path.parent().unwrap_or(Path::new("."));
    let text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let spec: RootSpec =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let now = now_or(args)?;
    let keys = spec
        .keys
        .iter()
        .map(|k| {
            MaintainerPublic::from_slice(&read(&base.join(k))?).map_err(|e| format!("{k}: {e}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let r = Root {
        version: spec.version,
        expires: now + spec.valid_days * DAY,
        keys,
        roles: [
            RoleKeys {
                keys: spec.root,
                threshold: spec.root_threshold,
            },
            RoleKeys {
                keys: spec.targets,
                threshold: spec.targets_threshold,
            },
            RoleKeys {
                keys: spec.online.clone(),
                threshold: 1,
            },
            RoleKeys {
                keys: spec.online,
                threshold: 1,
            },
        ],
        sigsum: Policy {
            log: key32(&spec.sigsum.log)?,
            submitters: spec
                .sigsum
                .submitters
                .iter()
                .map(|k| key32(k))
                .collect::<Result<_, _>>()?,
            witnesses: spec
                .sigsum
                .witnesses
                .iter()
                .map(|k| key32(k))
                .collect::<Result<_, _>>()?,
            quorum: spec.sigsum.quorum,
        },
    };
    let doc = Signed::root(&r);
    // The checks a client makes on reading it.
    Root::decode(&doc.body).map_err(|e| format!("root: {e}"))?;
    let out = PathBuf::from(need(args, "--out")?);
    write_new(&out, &doc.encode())?;
    eprintln!("{}\nwritten unsigned to {}", describe(&doc)?, out.display());
    Ok(())
}

fn targets(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(positional(args, 2, "DIR")?);
    let now = now_or(args)?;
    let days: u64 = flag(args, "--valid-days")
        .map_or(Ok(90), |d| d.parse())
        .map_err(|_| "--valid-days")?;
    let version: u32 = need(args, "--version")?.parse().map_err(|_| "--version")?;
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.') && !n.ends_with(".sigsum"))
        .collect();
    names.sort();
    let files = names
        .iter()
        .map(|n| Ok(Target::of(n, &read(&dir.join(n))?)))
        .collect::<Result<Vec<_>, String>>()?;
    let t = Targets {
        version,
        expires: now + days * DAY,
        release: need(args, "--tag")?,
        targets: files,
    };
    let doc = Signed::targets(&t);
    let out = PathBuf::from(need(args, "--out")?);
    write_new(&out, &doc.encode())?;
    eprintln!("{}\nwritten unsigned to {}", describe(&doc)?, out.display());
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(positional(args, 2, "DOC")?);
    let mut doc = Signed::decode(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = MaintainerKey::from_bytes(
        &keyfile::read_secret(Path::new(&need(args, "--key")?)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let index: u8 = need(args, "--index")?.parse().map_err(|_| "--index")?;
    eprintln!("signing as key {index}:\n{}", describe(&doc)?);
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    doc.sign(index, &key, &mut rng).map_err(|e| e.to_string())?;
    let out = PathBuf::from(need(args, "--out")?);
    write_new(&out, &doc.encode())?;
    eprintln!(
        "{} signature(s) now; written to {}",
        doc.signatures.len(),
        out.display()
    );
    Ok(())
}

fn online(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(positional(args, 2, "TARGETS")?);
    let targets = read(&path)?;
    let tdoc = Signed::decode(&targets).map_err(|e| format!("{}: {e}", path.display()))?;
    let t = Targets::decode(&tdoc.body).map_err(|e| e.to_string())?;
    let key = MaintainerKey::from_bytes(
        &keyfile::read_secret(Path::new(&need(args, "--key")?)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let index: u8 = need(args, "--index")?.parse().map_err(|_| "--index")?;
    let now = now_or(args)?;
    let days: u64 = flag(args, "--valid-days")
        .map_or(Ok(7), |d| d.parse())
        .map_err(|_| "--valid-days")?;
    // Snapshot and timestamp take the targets' version: one of each per
    // release, and a fresh timestamp (`--valid-days`) re-signed as needed.
    let version = flag(args, "--timestamp-version")
        .map_or(Ok(t.version), |v| v.parse())
        .map_err(|_| "--timestamp-version")?;
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let mut s = Signed::snapshot(&Snapshot {
        version: t.version,
        expires: t.expires,
        targets_version: t.version,
        targets_hash: sha256(&targets),
    });
    s.sign(index, &key, &mut rng).map_err(|e| e.to_string())?;
    let snapshot = s.encode();
    let mut ts = Signed::timestamp(&Timestamp {
        version,
        expires: now + days * DAY,
        snapshot_version: t.version,
        snapshot_hash: sha256(&snapshot),
    });
    ts.sign(index, &key, &mut rng).map_err(|e| e.to_string())?;
    let dir = PathBuf::from(need(args, "--out-dir")?);
    write_new(&dir.join("snapshot.bin"), &snapshot)?;
    write_new(&dir.join("timestamp.bin"), &ts.encode())?;
    eprintln!(
        "snapshot.bin and timestamp.bin written to {}",
        dir.display()
    );
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    let root = read(Path::new(&need(args, "--root")?))?;
    let dir = PathBuf::from(need(args, "--dir")?);
    let now = now_or(args)?;
    let mut c = Client::new(&root, [0; 3]).map_err(|e| format!("root: {e}"))?;
    let release = c
        .refresh(
            &read(&dir.join("timestamp.bin"))?,
            &read(&dir.join("snapshot.bin"))?,
            &read(&dir.join("targets.bin"))?,
            now,
        )
        .map_err(|e| e.to_string())?;
    println!(
        "release {} (targets version {}): {} files",
        release.release,
        release.version,
        release.targets.len()
    );
    if let Some(file) = flag(args, "--file") {
        let path = PathBuf::from(&file);
        let name = path.file_name().and_then(|n| n.to_str()).ok_or("--file")?;
        let proof = std::fs::read_to_string(need(args, "--proof")?).map_err(|e| e.to_string())?;
        c.check(&release, name, &read(&path)?, &proof)
            .map_err(|e| e.to_string())?;
        println!("{name}: in the release, and logged in Sigsum");
    }
    Ok(())
}

/// `enclave-admin release …`.
pub fn run(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(args),
        Some("root") => root(args),
        Some("targets") => targets(args),
        Some("sign") => sign(args),
        Some("online") => online(args),
        Some("verify") => verify(args),
        _ => Err("usage: enclave-admin release keygen | root | targets | sign | online | verify (see the module docs)".into()),
    }
}
