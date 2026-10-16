//! `cargo xtask i18n [--check]` (`docs/18-a11y-i18n.md` §2).
//!
//! - Extracts every translatable string into
//!   `crates/enclave-app/ui/lang/enclave-app.pot`: the window's `@tr("…")`
//!   (the first argument of each), and the sentences the vault and the app
//!   write in Rust (string literals that start with a capital letter and
//!   have a space, outside logging, panics and tests; `format!` arguments
//!   become `{}`).
//! - Merges it into each language's catalog
//!   (`ui/lang/<lang>/LC_MESSAGES/enclave-app.po`): new strings untranslated,
//!   translations kept, gone ones dropped. Translations come from people
//!   (Weblate, External Gate G10), never from a machine.
//! - Writes two pseudo-locales from it: `en-XA` (accented and 40% longer,
//!   for truncation) and `ar-XB` (right-to-left), shown in CI screenshots.
//! - Fails (`--check`) when a file it writes would change, or when a
//!   string the window shows isn't `@tr(…)`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The tier-1 languages (18 §2): catalogs exist for each, empty until a
/// person translates them.
const LANGUAGES: &[&str] = &[
    "ar", "de", "es", "fa", "fr", "hi", "id", "ja", "pt-BR", "ru", "tr", "uk", "zh-Hans", "zh-Hant",
];
const PSEUDO: &[&str] = &["en-XA", "ar-XB"];
const DOMAIN: &str = "enclave-app";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Unescape a Slint or Rust string literal's body (no raw strings).
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    // \u{XXXX}
                    let hex: String = it.by_ref().skip(1).take_while(|&c| c != '}').collect();
                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// String literals in `text` with their line numbers and the byte offset
/// where each starts.
fn literals(text: &str) -> Vec<(usize, usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    while i < b.len() {
        match b[i] {
            b'\n' => line += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'"' => {
                let start = i;
                i += 1;
                let body_start = i;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
                out.push((line, start, text[body_start..i.min(text.len())].to_string()));
            }
            // Rust char literals with a quote: '"'
            b'\'' if b.get(i + 1) == Some(&b'"') && b.get(i + 2) == Some(&b'\'') => i += 2,
            _ => {}
        }
        i += 1;
    }
    out
}

/// Whether a Slint literal is text a person reads (the rules of the
/// one-off migration that wrapped them).
fn shown(body: &str, line: &str) -> bool {
    // Source text is English; names in their own script (the languages
    // of the recovery words) stay as they are.
    let has_letter = body.chars().any(|c| c.is_ascii_alphabetic());
    let ident = body
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c));
    let path = body.trim_start().starts_with(['M', 'm'])
        && body
            .chars()
            .all(|c| "MLHVCSQTAZmlhvcsqtaz0123456789 .,-".contains(c));
    let skip_line = [
        "font-family",
        "@image-url",
        "commands:",
        "import ",
        "==",
        "!=",
    ]
    .iter()
    .any(|k| line.contains(k));
    has_letter && !ident && !path && !skip_line
}

fn slint_strings(
    found: &mut BTreeMap<String, Vec<String>>,
    lint: &mut Vec<String>,
) -> Result<(), String> {
    let ui = root().join("crates/enclave-app/ui");
    for f in ["app.slint", "controls.slint"] {
        let path = ui.join(f);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let lines: Vec<&str> = text.lines().collect();
        for (line, start, body) in literals(&text) {
            let first_arg = text[..start].ends_with("@tr(");
            let in_tr_args = {
                // An argument of @tr, after the first: inside the same
                // parentheses as a preceding `@tr(`.
                let before = &text[..start];
                before.rfind("@tr(").is_some_and(|at| {
                    let mut depth = 0i32;
                    for c in before[at + 3..].chars() {
                        match c {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                    }
                    depth > 0
                })
            };
            if first_arg {
                found
                    .entry(unescape(&body))
                    .or_default()
                    .push(format!("ui/{f}:{line}"));
            } else if !in_tr_args && shown(&body, lines.get(line - 1).unwrap_or(&"")) {
                lint.push(format!(
                    "ui/{f}:{line}: \"{body}\" is shown but not @tr(\"…\")"
                ));
            }
        }
    }
    Ok(())
}

/// `format!` placeholders as `{}`; `{{` and `}}` kept.
fn placeholders(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '{' if it.peek() == Some(&'{') => {
                it.next();
                out.push_str("{{");
            }
            '{' => {
                for d in it.by_ref() {
                    if d == '}' {
                        break;
                    }
                }
                out.push_str("{}");
            }
            '}' if it.peek() == Some(&'}') => {
                it.next();
                out.push_str("}}");
            }
            o => out.push(o),
        }
    }
    out
}

fn rust_strings(found: &mut BTreeMap<String, Vec<String>>) -> Result<(), String> {
    let mut files = Vec::new();
    for dir in ["crates/enclave-vault/src", "crates/enclave-app/src"] {
        collect_rs(&root().join(dir), &mut files)?;
    }
    for path in files {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // Tests are not shown to anyone.
        let end = text.find("#[cfg(test)]").unwrap_or(text.len());
        let text = &text[..end];
        let lines: Vec<&str> = text.lines().collect();
        let rel = path
            .strip_prefix(root().join("crates"))
            .unwrap_or(&path)
            .display()
            .to_string();
        for (line, _, body) in literals(text) {
            let l = lines.get(line - 1).copied().unwrap_or("").trim_start();
            if l.starts_with("//")
                || [
                    "eprintln!",
                    "println!",
                    "panic!",
                    "expect(",
                    "assert",
                    "unreachable!",
                    "log::",
                    "write!",
                    "writeln!",
                ]
                .iter()
                .any(|k| l.contains(k))
            {
                continue;
            }
            let s = unescape(&body);
            let starts_upper = s.chars().next().is_some_and(char::is_uppercase);
            if !starts_upper || !s.contains(' ') || s.starts_with("Enclave/") {
                continue;
            }
            found
                .entry(placeholders(&s))
                .or_default()
                .push(format!("{rel}:{line}"));
        }
    }
    Ok(())
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "bin") {
                collect_rs(&p, out)?;
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    Ok(())
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            o => out.push(o),
        }
    }
    out.push('"');
    out
}

fn header(lang: &str) -> String {
    let plural = match lang {
        "ja" | "zh-Hans" | "zh-Hant" | "id" | "tr" => "nplurals=1; plural=0;",
        "ar" | "ar-XB" => {
            "nplurals=6; plural=(n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 ? 4 : 5);"
        }
        "ru" | "uk" => {
            "nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);"
        }
        "fr" | "pt-BR" | "hi" | "fa" => "nplurals=2; plural=(n > 1);",
        _ => "nplurals=2; plural=(n != 1);",
    };
    format!(
        "msgid \"\"\nmsgstr \"\"\n\"Project-Id-Version: enclave-app\\n\"\n\"Language: {lang}\\n\"\n\"Content-Type: text/plain; charset=UTF-8\\n\"\n\"Plural-Forms: {plural}\\n\"\n"
    )
}

/// The `msgid → msgstr` pairs of an existing catalog.
fn read_po(path: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let (mut id, mut msg, mut field) = (None::<String>, String::new(), 0);
    let unq = |s: &str| unescape(s.trim().trim_start_matches('"').trim_end_matches('"'));
    for line in text.lines().chain(std::iter::once("")) {
        let l = line.trim();
        if let Some(r) = l.strip_prefix("msgid ") {
            if let Some(i) = id.take() {
                out.insert(i, std::mem::take(&mut msg));
            }
            id = Some(unq(r));
            field = 1;
        } else if let Some(r) = l.strip_prefix("msgstr ") {
            msg = unq(r);
            field = 2;
        } else if l.starts_with('"') {
            match (field, id.as_mut()) {
                (1, Some(i)) => i.push_str(&unq(l)),
                (2, _) => msg.push_str(&unq(l)),
                _ => {}
            }
        } else if l.is_empty() {
            if let Some(i) = id.take() {
                out.insert(i, std::mem::take(&mut msg));
            }
            field = 0;
        }
    }
    out.remove("");
    out
}

fn po(
    lang: Option<&str>,
    strings: &BTreeMap<String, Vec<String>>,
    translate: impl Fn(&str) -> String,
) -> String {
    let mut out = match lang {
        Some(l) => header(l),
        None => "msgid \"\"\nmsgstr \"\"\n\"Project-Id-Version: enclave-app\\n\"\n\"Content-Type: text/plain; charset=UTF-8\\n\"\n".to_string(),
    };
    for (id, refs) in strings {
        out.push('\n');
        // Where it is (files, not lines, so catalogs change only when the
        // strings do).
        let mut files: Vec<&str> = refs
            .iter()
            .map(|r| r.rsplit_once(':').map_or(r.as_str(), |(f, _)| f))
            .collect();
        files.sort();
        files.dedup();
        out.push_str(&format!("#: {}\n", files.join(" ")));
        out.push_str(&format!(
            "msgid {}\nmsgstr {}\n",
            quote(id),
            quote(&translate(id))
        ));
    }
    out
}

/// `f` applied to the text of `s` between its placeholders.
fn around_placeholders(s: &str, f: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    let mut text = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '{' || c == '}' {
            out.push_str(&f(&std::mem::take(&mut text)));
            out.push(c);
            if c == '{' {
                while let Some(&d) = it.peek() {
                    out.push(d);
                    it.next();
                    if d == '}' {
                        break;
                    }
                }
            }
        } else if c == '\n' {
            out.push_str(&f(&std::mem::take(&mut text)));
            out.push('\n');
        } else {
            text.push(c);
        }
    }
    out.push_str(&f(&text));
    out
}

fn accent(s: &str) -> String {
    let map = |c: char| match c {
        'a' => 'á',
        'e' => 'é',
        'i' => 'í',
        'o' => 'ó',
        'u' => 'ú',
        'c' => 'ç',
        'n' => 'ñ',
        'y' => 'ý',
        'A' => 'Á',
        'E' => 'É',
        'I' => 'Í',
        'O' => 'Ó',
        'U' => 'Ú',
        'C' => 'Ç',
        'N' => 'Ñ',
        'Y' => 'Ý',
        o => o,
    };
    let body: String = s.chars().map(map).collect();
    let pad = s.chars().count() * 2 / 5;
    format!("{body}{}", "·".repeat(pad))
}

/// `en-XA`: `[Áççéñtéd·····]`, 40% longer.
fn pseudo_long(s: &str) -> String {
    format!("[{}]", around_placeholders(s, accent))
}

/// `ar-XB`: right-to-left text, each run in RLE … PDF.
fn pseudo_rtl(s: &str) -> String {
    around_placeholders(s, |t| {
        if t.is_empty() {
            String::new()
        } else {
            format!("\u{202B}{t}\u{202C}")
        }
    })
}

fn write_or_check(
    path: &Path,
    text: &str,
    check: bool,
    stale: &mut Vec<String>,
) -> Result<(), String> {
    let old = std::fs::read_to_string(path).unwrap_or_default();
    if old == text {
        return Ok(());
    }
    if check {
        stale.push(path.display().to_string());
        return Ok(());
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The task.
pub fn i18n(check: bool) -> Result<(), String> {
    let mut strings = BTreeMap::new();
    let mut lint = Vec::new();
    slint_strings(&mut strings, &mut lint)?;
    rust_strings(&mut strings)?;
    let lang_dir = root().join("crates/enclave-app/ui/lang");
    let mut stale = Vec::new();
    write_or_check(
        &lang_dir.join(format!("{DOMAIN}.pot")),
        &po(None, &strings, |_| String::new()),
        check,
        &mut stale,
    )?;
    for lang in LANGUAGES {
        let path = lang_dir
            .join(lang)
            .join("LC_MESSAGES")
            .join(format!("{DOMAIN}.po"));
        let old = read_po(&path);
        let text = po(Some(lang), &strings, |id| {
            old.get(id).cloned().unwrap_or_default()
        });
        write_or_check(&path, &text, check, &mut stale)?;
    }
    for (lang, f) in PSEUDO
        .iter()
        .zip([pseudo_long as fn(&str) -> String, pseudo_rtl])
    {
        let path = lang_dir
            .join(lang)
            .join("LC_MESSAGES")
            .join(format!("{DOMAIN}.po"));
        write_or_check(&path, &po(Some(lang), &strings, f), check, &mut stale)?;
    }
    let mut problems = lint;
    problems.extend(
        stale
            .iter()
            .map(|s| format!("{s} is out of date; run `cargo xtask i18n` and commit it")),
    );
    if problems.is_empty() {
        println!(
            "i18n ok: {} strings, {} languages and 2 pseudo-locales",
            strings.len(),
            LANGUAGES.len()
        );
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_and_pseudo_locales() {
        assert_eq!(
            placeholders("Saved as {place} ({n:02})"),
            "Saved as {} ({})"
        );
        assert_eq!(placeholders("{{x}}"), "{{x}}");
        assert_eq!(pseudo_long("Hi {} you"), "[Hí ·{} ýóú·]");
        assert!(pseudo_rtl("Hi {}").contains("{}"));
        assert!(shown("Send", "text: \"Send\";"));
        assert!(!shown("qr", "icon: \"qr\";"));
        assert!(!shown("M 1 2 L 3 4", "commands: \"M 1 2\";"));
    }
}
