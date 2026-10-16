//! `cargo xtask done`: the 1.0 completion gate (`docs/completion-plan.md`,
//! "Definition of Done").
//!
//! Every check below counts unfinished work found in the repository itself,
//! so "nothing left undone" is a number that has to reach zero, not a claim:
//!
//! * **D1** unfinished markers in `docs/` ("not implemented", "Not done", …);
//! * **D2** labels still in the registry's "Reserved" table, and reserved
//!   labels already used in code (the registry is stale);
//! * **D3** red-team tests named in `docs/redteam-matrix.md` that don't exist;
//! * **D4** feature-matrix rows not marked done;
//! * **D5** open questions not resolved;
//! * **D6** platform constraints without a handled status;
//! * **D7** `TODO`, `FIXME`, `todo!`, `unimplemented!` in code and CI.
//!
//! Items that only people outside the code can finish (audits, store review,
//! translations…) are listed in `docs/completion.md` § External gates; a
//! marker that names one of them as "prepared" doesn't count.
//!
//! `--report` prints everything and exits 0 (CI before 1.0); without it the
//! task fails while anything is left.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Docs that are history or the plan itself, not specifications.
const SKIP_DOCS: &[&str] = &["PLAN.md", "completion-plan.md", "completion.md"];

/// Phrases that mark unfinished work in a specification.
const MARKERS: &[&str] = &[
    "not implemented",
    "not yet implemented",
    "not done",
    "not built",
    "not yet done",
    "not yet built",
    "todo",
    "tbd",
];

struct Finding {
    check: &'static str,
    place: String,
    what: String,
}

pub fn done(report: bool) -> ExitCode {
    let root = super::root();
    let mut f = Vec::new();
    markers(&root, &mut f);
    reserved_labels(&root, &mut f);
    redteam_tests(&root, &mut f);
    feature_matrix(&root, &mut f);
    open_questions(&root, &mut f);
    platform_constraints(&root, &mut f);
    code_todos(&root, &mut f);

    let mut by: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for x in &f {
        by.entry(x.check).or_default().push(x);
    }
    for (check, items) in &by {
        println!("{check}: {} left", items.len());
        for x in items {
            println!("  {}: {}", x.place, x.what);
        }
    }
    println!("done-gate: {} item(s) left", f.len());
    if f.is_empty() || report {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn docs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["docs", "docs/spikes", "docs/math", "docs/rfcs"] {
        if let Ok(rd) = fs::read_dir(root.join(dir)) {
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.extension().is_some_and(|x| x == "md") && !SKIP_DOCS.contains(&name) {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).display().to_string()
}

/// External gates marked "prepared" in `docs/completion.md`: a marker line
/// naming one (`G1`…) is not counted.
fn prepared_gates(root: &Path) -> Vec<String> {
    let text = fs::read_to_string(root.join("docs/completion.md")).unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with("| G") && l.to_lowercase().contains("| prepared"))
        .filter_map(|l| l.split('|').nth(1).map(|s| s.trim().to_string()))
        .collect()
}

fn markers(root: &Path, f: &mut Vec<Finding>) {
    let gates = prepared_gates(root);
    for p in docs(root) {
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let low = line.to_lowercase();
            // "Not planned" rows are decisions, not unfinished work.
            if low.contains("not planned") {
                continue;
            }
            let hit = MARKERS.iter().find(|m| {
                low.match_indices(*m).any(|(at, _)| {
                    // Whole words only ("todo" in "todos", "tbd" in an id).
                    let before = low[..at].chars().next_back();
                    let after = low[at + m.len()..].chars().next();
                    !before.is_some_and(|c| c.is_alphanumeric())
                        && !after.is_some_and(|c| c.is_alphanumeric())
                })
            });
            let Some(m) = hit else {
                continue;
            };
            if gates.iter().any(|g| line.contains(&format!("({g})"))) {
                continue;
            }
            f.push(Finding {
                check: "D1 doc markers",
                place: format!("{}:{}", rel(root, &p), i + 1),
                what: format!("\"{m}\": {}", excerpt(line)),
            });
        }
    }
}

fn excerpt(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() > 140 {
        format!("{}…", t.chars().take(140).collect::<String>())
    } else {
        t.to_string()
    }
}

fn code_text(root: &Path) -> String {
    let mut files = Vec::new();
    for d in ["crates", "xtask", "apps", "fuzz"] {
        super::rust_files(&root.join(d), &mut files);
    }
    files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

fn reserved_labels(root: &Path, f: &mut Vec<Finding>) {
    let reg = fs::read_to_string(root.join("docs/label-registry.md")).unwrap_or_default();
    let Some(start) = reg.find("## 3. Reserved labels") else {
        return;
    };
    let section = &reg[start..];
    let section = &section[..section[3..].find("\n## ").map_or(section.len(), |e| e + 3)];
    let code = code_text(root);
    for line in section.lines().filter(|l| l.starts_with("| `enclave/v1/")) {
        let Some(label) = line.split('`').nth(1) else {
            continue;
        };
        let used = code.contains(&format!("\"{label}\""));
        f.push(Finding {
            check: "D2 reserved labels",
            place: "docs/label-registry.md §3".into(),
            what: if used {
                format!("{label}: used in code, move it to §2")
            } else {
                format!("{label}: build the feature or retire the label")
            },
        });
    }
}

fn redteam_tests(root: &Path, f: &mut Vec<Finding>) {
    let matrix = fs::read_to_string(root.join("docs/redteam-matrix.md")).unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    for w in matrix.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        let b = w.as_bytes();
        if b.len() > 5
            && w.starts_with("rt")
            && b[2].is_ascii_digit()
            && b[3].is_ascii_digit()
            && b[4] == b'_'
            && !names.iter().any(|n| n == w)
        {
            names.push(w.to_string());
        }
    }
    let code = code_text(root);
    let checklist = fs::read_to_string(root.join("docs/release-checklist.md")).unwrap_or_default();
    let shape = fs::read_to_string(root.join("xtask/src/shape.rs")).unwrap_or_default();
    for n in names {
        let found = code.contains(&format!("fn {n}("))
            || shape.contains(&format!("\"{n}\""))
            || checklist.contains(&format!("`{n}`"));
        if !found {
            f.push(Finding {
                check: "D3 red-team tests",
                place: "docs/redteam-matrix.md".into(),
                what: format!("{n} doesn't exist"),
            });
        }
    }
}

/// Columns of a markdown table header line.
fn columns(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect()
}

/// Every row of the first table under `heading` must have `want` (case-
/// insensitive prefix) in column `col`, or "N/A".
fn table_status(
    root: &Path,
    doc: &str,
    heading_prefix: &str,
    col: &str,
    check: &'static str,
    f: &mut Vec<Finding>,
) {
    let text = fs::read_to_string(root.join(doc)).unwrap_or_default();
    let mut header: Option<usize> = None;
    let mut seen_table = false;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with('|') {
            if seen_table && header.is_some() {
                header = None;
            }
            continue;
        }
        let cols = columns(line);
        if cols.first().is_some_and(|c| c.starts_with("---")) {
            continue;
        }
        if cols.first().is_some_and(|c| c == "ID" || c == "Feature") {
            seen_table = true;
            header = cols.iter().position(|c| c.eq_ignore_ascii_case(col));
            if header.is_none() {
                f.push(Finding {
                    check,
                    place: format!("{doc}:{}", i + 1),
                    what: format!("table has no \"{col}\" column"),
                });
                // Count every row of this table as open.
                header = Some(usize::MAX);
            }
            continue;
        }
        let Some(h) = header else {
            continue;
        };
        if !cols
            .first()
            .is_some_and(|c| c.starts_with(heading_prefix) || heading_prefix.is_empty())
        {
            continue;
        }
        let status = cols.get(h).map(String::as_str).unwrap_or("");
        let low = status.to_lowercase();
        let ok = low.starts_with("done")
            || low.starts_with("n/a")
            || cols.iter().any(|c| c.eq_ignore_ascii_case("not planned"));
        if !ok {
            f.push(Finding {
                check,
                place: format!("{doc}:{}", i + 1),
                what: excerpt(cols.first().map(String::as_str).unwrap_or("")),
            });
        }
    }
}

fn feature_matrix(root: &Path, f: &mut Vec<Finding>) {
    table_status(
        root,
        "docs/16-features.md",
        "",
        "Status",
        "D4 feature matrix",
        f,
    );
}

fn platform_constraints(root: &Path, f: &mut Vec<Finding>) {
    table_status(
        root,
        "docs/15b-platform-constraints.md",
        "PC-",
        "Handled",
        "D6 platform constraints",
        f,
    );
}

fn open_questions(root: &Path, f: &mut Vec<Finding>) {
    for p in docs(root) {
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        let mut inside = false;
        for (i, line) in text.lines().enumerate() {
            if line.starts_with("## ") {
                inside = line.trim() == "## Open questions";
                continue;
            }
            if !inside {
                continue;
            }
            let t = line.trim_start();
            let item = t.starts_with("- ")
                || t.split_once(". ")
                    .is_some_and(|(n, _)| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty());
            // Continuation lines belong to the item above them.
            if !item || line.starts_with("  ") {
                continue;
            }
            if t.contains("**Resolved") || t.contains("**Closed") {
                continue;
            }
            f.push(Finding {
                check: "D5 open questions",
                place: format!("{}:{}", rel(root, &p), i + 1),
                what: excerpt(t),
            });
        }
    }
}

fn code_todos(root: &Path, f: &mut Vec<Finding>) {
    let mut files = Vec::new();
    for d in ["crates", "xtask", "apps", "fuzz"] {
        super::rust_files(&root.join(d), &mut files);
    }
    if let Ok(rd) = fs::read_dir(root.join(".github/workflows")) {
        files.extend(rd.flatten().map(|e| e.path()));
    }
    // This file names the markers it looks for.
    let me = root.join("xtask/src/done.rs");
    for p in files.iter().filter(|p| **p != me) {
        let Ok(text) = fs::read_to_string(p) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            for m in ["TODO", "FIXME", "XXX", "todo!(", "unimplemented!("] {
                if marked(line, m) {
                    f.push(Finding {
                        check: "D7 code markers",
                        place: format!("{}:{}", rel(root, p), i + 1),
                        what: excerpt(line),
                    });
                    break;
                }
            }
        }
    }
}

/// Whether `line` carries the marker `m` as a word of its own (so
/// "XXXL" in a constant's name and "XXXX" in a pattern aren't markers).
fn marked(line: &str, m: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(m).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + m.len()..].chars().next();
        let ends_open = m.ends_with('(');
        !before.is_some_and(word) && (ends_open || !after.is_some_and(word))
    })
}
