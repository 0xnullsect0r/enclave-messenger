//! `cargo xtask tamarin`: prove every Tamarin model in `formal/tamarin/`
//! and check each lemma against the result written before it, as
//! `/* expect: verified */` or `/* expect: falsified */`.
//!
//! A model fails if any lemma differs, has no expectation, or isn't
//! decided, and if Tamarin's wellformedness checks warn (its results
//! "might be wrong"). Set `TAMARIN` to the binary; Maude must be on the
//! path.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::root;

/// Lemma names with the result each must give, in file order.
fn expectations(model: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut rest = model;
    while let Some(i) = rest.find("/* expect: ") {
        let after = &rest[i + "/* expect: ".len()..];
        let want = if after.starts_with("verified") {
            Some(true)
        } else if after.starts_with("falsified") {
            Some(false)
        } else {
            None
        };
        let Some(l) = after.find("lemma ") else {
            break;
        };
        let name: String = after[l + "lemma ".len()..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if let Some(w) = want {
            out.push((name, w));
        }
        rest = &after[l..];
    }
    out
}

/// Results from Tamarin's summary: `name (all-traces): verified (8 steps)`
/// or `name (exists-trace): falsified - …`; anything else (analysis
/// incomplete) is undecided.
fn results(output: &str) -> Vec<(String, Option<bool>)> {
    let Some(start) = output.find("summary of summaries:") else {
        return Vec::new();
    };
    output[start..]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let (name, rest) = l.split_once(" (")?;
            let (_, verdict) = rest.split_once("): ")?;
            if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return None;
            }
            let r = if verdict.starts_with("verified") {
                Some(true)
            } else if verdict.starts_with("falsified") {
                Some(false)
            } else {
                None
            };
            Some((name.to_string(), r))
        })
        .collect()
}

pub fn tamarin() -> ExitCode {
    let bin = std::env::var("TAMARIN").unwrap_or_else(|_| "tamarin-prover".into());
    let dir = root().join("formal/tamarin");
    let mut models: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "spthy"))
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
        let out = match std::process::Command::new(&bin)
            .arg("--prove")
            .arg(m)
            // Tamarin prints Unicode; without a UTF-8 locale it stops.
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .output()
        {
            Ok(o) => {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            }
            Err(e) => {
                eprintln!("can't run {bin}: {e} (set TAMARIN to its path)");
                return ExitCode::FAILURE;
            }
        };
        if out.contains("wellformedness check") && out.contains("failed") {
            eprintln!("{name}: Tamarin's wellformedness checks failed");
            ok = false;
            continue;
        }
        let got = results(&out);
        if want.is_empty() || got.len() != want.len() {
            eprintln!("{name}: {} expectations, {} results", want.len(), got.len());
            ok = false;
            continue;
        }
        let mut all = true;
        for (lemma, w) in &want {
            let g = got.iter().find(|(n, _)| n == lemma).and_then(|(_, r)| *r);
            if g != Some(*w) {
                let say = |b: bool| if b { "verified" } else { "falsified" };
                eprintln!(
                    "{name}: {lemma} expected {}, got {}",
                    say(*w),
                    g.map_or("no result", say)
                );
                all = false;
            }
        }
        if all {
            println!("{name}: {} lemmas as expected", got.len());
        }
        ok &= all;
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_expectations_and_results() {
        let model = "/* expect: verified */\nlemma a_b:\n  \"…\"\n/* note */\n/* expect: falsified */\nlemma c:\n";
        assert_eq!(
            expectations(model),
            vec![("a_b".to_string(), true), ("c".to_string(), false)]
        );
        let out = "summary of summaries:\n\n  a_b (all-traces): verified (8 steps)\n  c (exists-trace): falsified - no trace found (2 steps)\n  d (all-traces): analysis incomplete (1 steps)\n";
        assert_eq!(
            results(out),
            vec![
                ("a_b".to_string(), Some(true)),
                ("c".to_string(), Some(false)),
                ("d".to_string(), None)
            ]
        );
    }
}
