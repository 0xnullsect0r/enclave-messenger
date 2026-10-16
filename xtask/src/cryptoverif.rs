//! `cargo xtask cryptoverif`: run every CryptoVerif model in
//! `formal/cryptoverif/` (`*.ocv`) and check that CryptoVerif proves all
//! of its queries, as each model's `EXPECTED` block says. A model named
//! `<prefix>_….ocv` reads the library `<prefix>_common.ocvl` beside it.
//!
//! The binary is `$CRYPTOVERIF`, or `cryptoverif` on the path; its
//! standard library (`default.cvl`) is the one next to the binary, or
//! `$CRYPTOVERIF_LIB` (the path without `.cvl`).

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::root;

pub fn cryptoverif() -> ExitCode {
    let bin = std::env::var("CRYPTOVERIF").unwrap_or_else(|_| "cryptoverif".into());
    let default = std::env::var("CRYPTOVERIF_LIB").ok().or_else(|| {
        let p = PathBuf::from(&bin);
        let dir = if p.is_absolute() {
            p.parent().map(PathBuf::from)
        } else {
            which(&bin)
        }?;
        Some(dir.join("default").to_string_lossy().into_owned())
    });
    let dir = root().join("formal/cryptoverif");
    let mut models: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "ocv"))
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
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = fs::read_to_string(m).unwrap_or_default();
        if !text.contains("(* EXPECTED\nAll queries proved.") {
            eprintln!("{name}: no EXPECTED block saying all queries are proved");
            ok = false;
            continue;
        }
        let mut c = std::process::Command::new(&bin);
        c.current_dir(&dir);
        if let Some(d) = &default {
            c.args(["-lib", d]);
        }
        let prefix = name.split('_').next().unwrap_or_default();
        let common = format!("{prefix}_common");
        if dir.join(format!("{common}.ocvl")).exists() {
            c.args(["-lib", &common]);
        }
        let out = match c.arg(m).output() {
            Ok(o) => {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            }
            Err(e) => {
                eprintln!("can't run {bin}: {e} (set CRYPTOVERIF to its path)");
                return ExitCode::FAILURE;
            }
        };
        let proved: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("RESULT Proved"))
            .collect();
        if out.lines().any(|l| l.trim() == "All queries proved.") && !proved.is_empty() {
            for p in proved {
                println!("{name}: {}", p.trim_start_matches("RESULT "));
            }
        } else {
            let why: Vec<&str> = out
                .lines()
                .filter(|l| l.starts_with("RESULT Could not") || l.contains("rror"))
                .collect();
            eprintln!("{name}: not proved: {why:?}");
            ok = false;
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The directory on the path that holds `bin`.
fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).find(|d| d.join(bin).is_file()))
}
