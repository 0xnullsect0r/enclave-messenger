//! `cargo xtask licenses [--check]`: the notices for everything the
//! desktop app ships (`crates/enclave-app/licenses.txt`, shown under
//! Settings → About → Open-source licences), or a check that the
//! committed file is current.
//!
//! From `cargo metadata` of the main workspace (the app, vault, netd,
//! mediad and tord) and of `nym/` (nymd): every package their normal
//! dependencies reach on any platform (not build or dev dependencies, which
//! don't ship), with its licence expression, and each licence file it
//! carries (`LICENSE*`, `LICENCE*`, `COPYING*`, `NOTICE*`, `UNLICENSE`).
//! Identical texts are printed once, after the packages that share them.
//! Then the notices in `LICENSES/` (fonts, the JPEG encoder's DCT).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::ExitCode;

const ROOTS: [&str; 6] = [
    "enclave-app",
    "enclave-vault",
    "enclave-netd",
    "enclave-mediad",
    "enclave-tord",
    "enclave-nymd",
];

struct Pkg {
    name: String,
    version: String,
    license: String,
    texts: Vec<String>,
}

fn metadata(manifest: &Path) -> Result<serde_json::Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())
}

/// The packages reachable from the roots over normal dependencies.
fn shipped(meta: &serde_json::Value) -> Vec<Pkg> {
    let empty = Vec::new();
    let packages = meta["packages"].as_array().unwrap_or(&empty);
    let by_id: BTreeMap<&str, &serde_json::Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: BTreeMap<&str, &serde_json::Value> = meta["resolve"]["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let mut todo: Vec<&str> = packages
        .iter()
        .filter(|p| ROOTS.contains(&p["name"].as_str().unwrap_or_default()))
        .filter_map(|p| p["id"].as_str())
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        for d in nodes
            .get(id)
            .and_then(|n| n["deps"].as_array())
            .unwrap_or(&empty)
        {
            let normal = d["dep_kinds"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .any(|k| k["kind"].is_null());
            if normal && let Some(pkg) = d["pkg"].as_str() {
                todo.push(pkg);
            }
        }
    }
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut out = Vec::new();
    for id in seen {
        let Some(p) = by_id.get(id) else { continue };
        // Our own crates are under the licence at the top of the file (the
        // patched crates in third_party/ are not ours, and are listed).
        if members.contains(id) {
            continue;
        }
        let dir = Path::new(p["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|f| {
                let n = f
                    .file_name()
                    .map(|n| n.to_string_lossy().to_uppercase())
                    .unwrap_or_default();
                f.is_file()
                    && ["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"]
                        .iter()
                        .any(|k| n.starts_with(k))
            })
            .collect();
        files.sort();
        out.push(Pkg {
            name: p["name"].as_str().unwrap_or_default().into(),
            version: p["version"].as_str().unwrap_or_default().into(),
            license: p["license"].as_str().unwrap_or("see its repository").into(),
            texts: files
                .iter()
                .filter_map(|f| std::fs::read_to_string(f).ok())
                .map(|t| t.replace("\r\n", "\n").trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
        });
    }
    out
}

/// The notices file.
fn notices(root: &Path) -> Result<String, String> {
    let mut pkgs = shipped(&metadata(&root.join("Cargo.toml"))?);
    pkgs.extend(shipped(&metadata(&root.join("nym/Cargo.toml"))?));
    pkgs.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    pkgs.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    // Each distinct text, with the packages that carry it; packages with
    // no licence file under their expression alone.
    let mut by_text: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bare: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in &pkgs {
        let label = format!("{} {}", p.name, p.version);
        if p.texts.is_empty() {
            bare.entry(p.license.clone())
                .or_default()
                .push(label.clone());
        }
        for t in &p.texts {
            by_text
                .entry(t.clone())
                .or_default()
                .push(format!("{label} ({})", p.license));
        }
    }
    let mut out = String::from(
        "Enclave is free software under the GNU General Public License, version 3 only, with the additional permissions in legal/ADDITIONAL-PERMISSIONS.md. It is built with the software below, under the licences that follow each list.\n",
    );
    let mut entries: Vec<(String, String)> = by_text
        .into_iter()
        .map(|(text, users)| (users.join(", "), text))
        .collect();
    entries.sort();
    for (users, text) in entries {
        out.push_str(&format!("\n=== {users}\n{text}\n"));
    }
    for (license, users) in bare {
        out.push_str(&format!(
            "\n=== {}\nUnder {license}. These packages carry no licence file of their own; the full text of each licence named is in this file (the GNU GPL's is Enclave's own licence).\n",
            users.join(", ")
        ));
    }
    let mut extra: Vec<_> = std::fs::read_dir(root.join("LICENSES"))
        .map_err(|e| format!("LICENSES: {e}"))?
        .flatten()
        .map(|e| e.path())
        .collect();
    extra.sort();
    for f in extra {
        let name = f
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        out.push_str(&format!(
            "\n=== {name}\n{}\n",
            text.replace("\r\n", "\n").trim()
        ));
    }
    Ok(out)
}

pub fn licenses(check: bool) -> ExitCode {
    let root = super::root();
    let path = root.join("crates/enclave-app/licenses.txt");
    let text = match notices(&root) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("licenses: {e}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            eprintln!(
                "licenses: crates/enclave-app/licenses.txt is out of date; run `cargo xtask licenses` and commit it"
            );
            return ExitCode::FAILURE;
        }
        println!("licenses ok: {} bytes", text.len());
        return ExitCode::SUCCESS;
    }
    if let Err(e) = std::fs::write(&path, &text) {
        eprintln!("licenses: {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("licenses written: {} bytes", text.len());
    ExitCode::SUCCESS
}
