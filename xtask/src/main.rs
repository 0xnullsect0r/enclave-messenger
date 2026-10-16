//! `cargo xtask <task>`: repository checks that are not unit tests.
//!
//! * `labels`: every `enclave/v1/...` string literal in `crates/` is listed in
//!   `docs/label-registry.md`, and no label is defined twice in code.
//! * `repro [package] [bin]`: build a release binary twice, from scratch, in
//!   two target directories, and check the two are byte-identical
//!   (`docs/19-ops.md`, reproducible builds). Default: `enclave-relay`.
//! * `dudect`: run the constant-time timing tests (slow; not in `cargo test`).
//! * `ctgrind`: run the secret-poisoning tests under Valgrind's Memcheck
//!   (`crates/enclave-crypto/tests/ctgrind.rs`).
//! * `shape`: the traffic-shape scenarios (`shape.rs`).
//! * `proverif`: run every model in `formal/proverif/` and check each
//!   query's result against the `(* expect: true|false|unproved *)` note
//!   before it.
//!   The binary is `$PROVERIF`, or `proverif` on the path.
//! * `tamarin`: prove every model in `formal/tamarin/` and check each
//!   lemma against the `/* expect: verified|falsified */` note before it
//!   (`tamarin.rs`). The binary is `$TAMARIN`, or `tamarin-prover`.
//! * `cryptoverif`: prove every model in `formal/cryptoverif/`
//!   (`cryptoverif.rs`). The binary is `$CRYPTOVERIF`, or `cryptoverif`.
//! * `done [--report]`: the 1.0 completion gate (`done.rs`).
//! * `icons [--check]`: the app icons for every platform (`icons.rs`).
//! * `licenses [--check]`: the notices the app shows (`licenses.rs`).
//! * `dist`, `packager`, `bundle-macos`, `checksums`, `version`: release
//!   builds, archives and installers (`dist.rs`).

mod cryptoverif;
mod dist;
mod done;
mod i18n;
mod icons;
mod licenses;
mod shape;
mod supply;
mod tamarin;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "labels" => labels(),
        "repro" => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            let pkg = args.first().map_or("enclave-relay", String::as_str);
            let bin = args.get(1).map_or(pkg, String::as_str);
            repro(pkg, bin)
        }
        "dudect" => dudect(),
        "ctgrind" => ctgrind(),
        "shape" => shape::run(),
        "proverif" => proverif(),
        "tamarin" => tamarin::tamarin(),
        "cryptoverif" => cryptoverif::cryptoverif(),
        "done" => done::done(std::env::args().any(|a| a == "--report")),
        "icons" => icons::icons(std::env::args().any(|a| a == "--check")),
        "i18n" => match i18n::i18n(std::env::args().any(|a| a == "--check")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        "licenses" => licenses::licenses(std::env::args().any(|a| a == "--check")),
        "dist" | "packager" | "bundle-macos" | "checksums" | "version" | "msix" => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            match task.as_str() {
                "dist" => dist::dist(&args),
                "packager" => dist::packager(&args),
                "bundle-macos" => dist::bundle_macos(&args),
                "checksums" => dist::checksums(&args),
                "msix" => dist::msix(&args),
                _ => dist::version_task(&args),
            }
        }
        _ => {
            eprintln!(
                "usage: cargo xtask labels | repro [package] [bin] | dudect | ctgrind | shape | proverif | tamarin | cryptoverif | done [--report] | icons [--check] | i18n [--check] | licenses [--check] | dist [--target T] [--no-build] | packager --target T --formats F | bundle-macos [--target T] | checksums DIR | version [TAG] | msix --target T"
            );
            ExitCode::FAILURE
        }
    }
}

/// Build `bin` of `pkg` twice in separate target directories and compare.
fn repro(pkg: &str, bin: &str) -> ExitCode {
    if reproducible(&[pkg], &[bin]) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Build `bins` of `pkgs` (release, locked) twice, from scratch, in two
/// target directories, and whether every binary came out byte-identical.
pub(crate) fn reproducible(pkgs: &[&str], bins: &[&str]) -> bool {
    let root = root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        std::env::var("HOME")
            .map(|h| format!("{h}/.cargo"))
            .unwrap_or_default()
    });
    let mut hashes: Vec<Vec<[u8; 64]>> = Vec::new();
    for side in ["a", "b"] {
        let dir = root.join("target").join(format!("repro-{side}"));
        let _ = fs::remove_dir_all(&dir);
        // Every path the compiler might embed maps to the same name on both
        // sides. rustc applies the *last* matching mapping, and the target
        // directory lies under the source root, so it goes last (otherwise
        // build-script output such as akd_core's generated protobuf code
        // keeps `repro-a` or `repro-b` in its path).
        let flags = format!(
            "--remap-path-prefix={}=/cargo --remap-path-prefix={}=/src --remap-path-prefix={}=/target",
            cargo_home,
            root.display(),
            dir.display()
        );
        eprintln!("repro: building {} in {}", bins.join(", "), dir.display());
        let mut c = std::process::Command::new(&cargo);
        c.current_dir(&root)
            .args(["build", "--release", "--locked"]);
        for p in pkgs {
            c.args(["-p", p]);
        }
        for b in bins {
            c.args(["--bin", b]);
        }
        let status = c
            .env("CARGO_TARGET_DIR", &dir)
            .env("RUSTFLAGS", &flags)
            .env("CARGO_INCREMENTAL", "0")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .status();
        if !status.is_ok_and(|s| s.success()) {
            eprintln!("repro: build failed");
            return false;
        }
        let mut side_hashes = Vec::new();
        for bin in bins {
            let exe = dir
                .join("release")
                .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
            let Ok(bytes) = fs::read(&exe) else {
                eprintln!("repro: {} missing", exe.display());
                return false;
            };
            let h = enclave_crypto::hash::sha3_512(&bytes);
            let hex: String = h[..16].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "repro: {side}: {bin}: {} bytes, sha3-512 {hex}…",
                bytes.len()
            );
            side_hashes.push(h);
        }
        hashes.push(side_hashes);
    }
    let mut ok = true;
    for (i, bin) in bins.iter().enumerate() {
        if hashes[0][i] == hashes[1][i] {
            eprintln!("repro ok: {bin} is byte-identical across two clean builds");
        } else {
            eprintln!("repro FAILED: the two builds of {bin} differ");
            ok = false;
        }
    }
    ok
}

/// The secret-poisoning tests, optimised, each run under Memcheck.
fn ctgrind() -> ExitCode {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let runner = "valgrind --tool=memcheck --error-exitcode=0 --track-origins=yes";
    let var = format!(
        "CARGO_TARGET_{}_RUNNER",
        target_triple().to_uppercase().replace('-', "_")
    );
    let status = std::process::Command::new(cargo)
        .current_dir(root())
        .env(var, runner)
        // Debug info for Memcheck's reports; the code is still optimised.
        .env("CARGO_PROFILE_RELEASE_DEBUG", "1")
        .args([
            "test",
            "--release",
            "-p",
            "enclave-crypto",
            "--test",
            "ctgrind",
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .status();
    // Token verification (the issuer's key is private to its module).
    let tokens =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(root())
            .env(
                format!(
                    "CARGO_TARGET_{}_RUNNER",
                    target_triple().to_uppercase().replace('-', "_")
                ),
                runner,
            )
            .env("CARGO_PROFILE_RELEASE_DEBUG", "1")
            .args([
                "test",
                "--release",
                "-p",
                "enclave-tokens",
                "--lib",
                "--",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "ctgrind::",
            ])
            .status();
    if status.is_ok_and(|s| s.success()) && tokens.is_ok_and(|s| s.success()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The host's target triple (what `rustc -vV` calls `host`).
fn target_triple() -> String {
    let out = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    out.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .unwrap_or("x86_64-unknown-linux-gnu")
        .to_string()
}

/// Expected results, in order, from `(* expect: true|false|unproved *)`
/// notes.
fn expectations(model: &str) -> Vec<Verdict> {
    model
        .match_indices("(* expect: ")
        .filter_map(|(i, _)| {
            let rest = &model[i + "(* expect: ".len()..];
            if rest.starts_with("true") {
                Some(Verdict::True)
            } else if rest.starts_with("false") {
                Some(Verdict::False)
            } else if rest.starts_with("unproved") {
                Some(Verdict::Unproved)
            } else {
                None
            }
        })
        .collect()
}

/// A ProVerif result. An equivalence that doesn't hold usually comes back
/// "cannot be proved" rather than "false": a sanity model expects that
/// with `(* expect: unproved *)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    True,
    False,
    Unproved,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Verdict::True => "true",
            Verdict::False => "false",
            Verdict::Unproved => "unproved",
        })
    }
}

/// Results, in order, from ProVerif's `RESULT … is true.` lines.
fn results(output: &str) -> Vec<Option<Verdict>> {
    output
        .lines()
        .filter(|l| l.starts_with("RESULT "))
        .map(|l| {
            if l.ends_with(" is true.") {
                Some(Verdict::True)
            } else if l.ends_with(" is false.") {
                Some(Verdict::False)
            } else if l.ends_with(" cannot be proved.") {
                Some(Verdict::Unproved)
            } else {
                None
            }
        })
        .collect()
}

fn proverif() -> ExitCode {
    let bin = std::env::var("PROVERIF").unwrap_or_else(|_| "proverif".into());
    let dir = root().join("formal/proverif");
    let mut models: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "pv"))
                .collect()
        })
        .unwrap_or_default();
    models.sort();
    if models.is_empty() {
        eprintln!("no models in {}", dir.display());
        return ExitCode::FAILURE;
    }
    let mut ok = true;
    for m in &models {
        let name = m
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let want = expectations(&fs::read_to_string(m).unwrap_or_default());
        let out = match std::process::Command::new(&bin).arg(m).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(e) => {
                eprintln!("can't run {bin}: {e} (set PROVERIF to its path)");
                return ExitCode::FAILURE;
            }
        };
        let got = results(&out);
        if want.is_empty() || got.len() != want.len() {
            eprintln!("{name}: {} expectations, {} results", want.len(), got.len());
            ok = false;
            continue;
        }
        let mut all = true;
        for (i, (w, g)) in want.iter().zip(&got).enumerate() {
            if Some(*w) != *g {
                eprintln!("{name}: query {} expected {w}, got {g:?}", i + 1);
                all = false;
            }
        }
        if all {
            println!("{name}: {} queries as expected", got.len());
        }
        ok &= all;
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The timing tests live in `enclave-crypto/tests/dudect.rs` (ignored by
/// default: they take minutes and need a quiet machine).
fn dudect() -> ExitCode {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = std::process::Command::new(cargo)
        .current_dir(root())
        .args([
            "test",
            "--release",
            "-p",
            "enclave-crypto",
            "--test",
            "dudect",
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .status();
    if status.is_ok_and(|s| s.success()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Extract `"enclave/v1/..."` literals from source text.
fn labels_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let needle = "\"enclave/v1/";
    let mut rest = text;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i + 1..];
        if let Some(end) = after.find('"') {
            let lit = &after[..end];
            if lit
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
            {
                found.push(lit.to_string());
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    found
}

fn labels() -> ExitCode {
    let root = root();
    let registry = fs::read_to_string(root.join("docs/label-registry.md")).unwrap_or_default();
    let registered: BTreeSet<String> = registry
        .split(|c: char| c == '`' || c.is_whitespace() || c == '|')
        .filter(|s| s.starts_with("enclave/v1/"))
        .map(str::to_string)
        .collect();

    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    // label -> files that define it as a `pub const`
    let mut defs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for f in &files {
        let Ok(text) = fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines() {
            let is_def = line.trim_start().starts_with("pub const")
                || line.trim_start().starts_with("const");
            for l in labels_in(line) {
                used.insert(l.clone());
                if is_def {
                    defs.entry(l).or_default().push(f.display().to_string());
                }
            }
        }
    }

    let mut ok = true;
    for (label, where_) in &defs {
        if where_.len() > 1 {
            eprintln!("label {label} defined more than once: {where_:?}");
            ok = false;
        }
    }
    if registered.is_empty() {
        eprintln!("docs/label-registry.md is missing or lists no labels");
        return ExitCode::FAILURE;
    }
    for l in &used {
        if !registered.contains(l) {
            eprintln!("label {l} is used in code but missing from docs/label-registry.md");
            ok = false;
        }
    }
    if ok {
        println!(
            "labels ok: {} used, {} registered",
            used.len(),
            registered.len()
        );
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod repro_tests {
    /// RT-13: the client programs a release ships build byte for byte the
    /// same twice, so anyone can check a download against the source (the
    /// release's `repro-check` job also rebuilds the whole Linux tarball).
    #[test]
    #[ignore = "two clean release builds; the CI job `repro` runs it"]
    fn rt13_reproducible_build_diff_empty() {
        assert!(super::reproducible(
            &crate::dist::PACKAGES,
            &[
                "enclave",
                "enclave-vault",
                "enclave-netd",
                "enclave-mediad",
                "enclave-tord",
            ],
        ));
    }

    /// RT-28: the server programs an operator runs build byte for byte the
    /// same twice, so what an operator runs can be checked against the
    /// source.
    #[test]
    #[ignore = "two clean release builds; the CI job `repro` runs it"]
    fn rt28_server_build_reproducible() {
        assert!(super::reproducible(
            &[
                "enclave-server",
                "enclave-relay",
                "enclave-front",
                "enclave-witness",
                "enclave-push-relay",
                "enclave-credgate",
                "enclave-admin",
            ],
            &[
                "enclave-server",
                "enclave-relay",
                "enclave-front",
                "enclave-witness",
                "enclave-push-relay",
                "enclave-credgate",
                "enclave-admin",
            ],
        ));
    }
}
