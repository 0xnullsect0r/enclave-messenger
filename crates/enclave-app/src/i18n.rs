//! Translations (`docs/18-a11y-i18n.md` §2). The window's own text is
//! `@tr(…)` in the Slint files, translated by Slint from the catalogs in
//! `ui/lang` built into the program; what the vault writes (status lines,
//! errors, notices) is in English and is translated here, from the same
//! catalogs, as it is shown. A catalog entry may have `{}` (or `{0}`,
//! `{1}`…) where the vault puts a name, a number or a date: `tr` matches
//! the vault's text against it and moves those parts into the translation.

use std::sync::RwLock;

include!(concat!(env!("OUT_DIR"), "/catalogs.rs"));

static LANG: RwLock<Option<usize>> = RwLock::new(None);

/// The languages there are catalogs for (besides English).
pub fn languages() -> Vec<&'static str> {
    CATALOGS.iter().map(|(l, _)| *l).collect()
}

/// The catalog for `lang` (`de`, `pt-BR`, or a locale such as `de_DE.UTF-8`),
/// matching the whole tag first, then the language alone.
fn find(lang: &str) -> Option<usize> {
    let tag = lang.split('.').next().unwrap_or("").replace('_', "-");
    if tag.is_empty() || tag == "C" || tag == "POSIX" {
        return None;
    }
    CATALOGS
        .iter()
        .position(|(l, _)| l.eq_ignore_ascii_case(&tag))
        .or_else(|| {
            let base = tag.split('-').next().unwrap_or("");
            CATALOGS
                .iter()
                .position(|(l, _)| l.eq_ignore_ascii_case(base))
        })
}

/// Use `lang` (English when there is no catalog for it, or for `en`).
/// Returns the catalog's language, for the window (`slint::select_bundled_translation`).
pub fn set_language(lang: &str) -> Option<&'static str> {
    let idx = find(lang);
    if let Ok(mut l) = LANG.write() {
        *l = idx;
    }
    idx.map(|i| CATALOGS[i].0)
}

/// The person's language: `ENCLAVE_LANG`, else the system's (`LC_ALL`,
/// `LC_MESSAGES`, `LANG`, or the platform's setting).
pub fn system_language() -> String {
    for v in ["ENCLAVE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(l) = std::env::var(v)
            && !l.is_empty()
        {
            return l;
        }
    }
    sys_locale::get_locale().unwrap_or_default()
}

/// The parts of `text` where `msgid`'s placeholders are, if it matches.
fn matches(msgid: &str, text: &str) -> Option<Vec<String>> {
    let pieces = split(msgid);
    let (first, rest) = pieces.split_first()?;
    let mut t = text.strip_prefix(first.as_str())?;
    let mut args = Vec::new();
    for (i, p) in rest.iter().enumerate() {
        // The last piece must end the text; others are the next match.
        let at = if i + 1 == rest.len() {
            if !t.ends_with(p.as_str()) {
                return None;
            }
            t.len() - p.len()
        } else if p.is_empty() {
            return None;
        } else {
            t.find(p.as_str())?
        };
        args.push(t[..at].to_string());
        t = &t[at + p.len()..];
    }
    t.is_empty().then_some(args)
}

/// `s` split at its placeholders (`{}` or `{N}`).
fn split(s: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '{' {
            let mut inner = String::new();
            while let Some(&d) = it.peek() {
                if d.is_ascii_digit() {
                    inner.push(d);
                    it.next();
                } else {
                    break;
                }
            }
            if it.peek() == Some(&'}') {
                it.next();
                out.push(String::new());
                continue;
            }
            if let Some(l) = out.last_mut() {
                l.push('{');
                l.push_str(&inner);
            }
        } else if let Some(l) = out.last_mut() {
            l.push(c);
        }
    }
    out
}

/// `msgstr` with `args` in its placeholders: `{}` in order, `{N}` by number.
fn fill(msgstr: &str, args: &[String]) -> String {
    let mut out = String::new();
    let mut next = 0;
    let mut it = msgstr.chars().peekable();
    while let Some(c) = it.next() {
        if c == '{' {
            let mut num = String::new();
            while let Some(&d) = it.peek() {
                if d.is_ascii_digit() {
                    num.push(d);
                    it.next();
                } else {
                    break;
                }
            }
            if it.peek() == Some(&'}') {
                it.next();
                let i = if num.is_empty() {
                    next += 1;
                    next - 1
                } else {
                    num.parse().unwrap_or(usize::MAX)
                };
                out.push_str(args.get(i).map_or("", String::as_str));
                continue;
            }
            out.push('{');
            out.push_str(&num);
        } else {
            out.push(c);
        }
    }
    out
}

/// `text` in the person's language, or as it is when there is no
/// translation.
pub fn tr(text: &str) -> String {
    let Some(idx) = LANG.read().ok().and_then(|l| *l) else {
        return text.to_string();
    };
    let entries = CATALOGS[idx].1;
    if let Ok(i) = entries.binary_search_by(|(id, _)| (*id).cmp(text)) {
        return entries[i].1.to_string();
    }
    for (id, s) in entries {
        if id.contains('{')
            && let Some(args) = matches(id, text)
        {
            return fill(s, &args);
        }
    }
    text.to_string()
}

/// A notice in the person's language. The generic ones (titled "Enclave":
/// "New message", "3 new messages") are translated; one that shows who
/// wrote and what they wrote stays as it is.
pub fn notice(mut n: enclave_ipc::Notice) -> enclave_ipc::Notice {
    if n.title == "Enclave" {
        n.body = tr(&n.body);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_match_and_fill() {
        assert_eq!(
            matches("Saved as {}", "Saved as /tmp/x.png"),
            Some(vec!["/tmp/x.png".into()])
        );
        assert_eq!(
            matches("{} of {} admins", "2 of 5 admins"),
            Some(vec!["2".into(), "5".into()])
        );
        assert_eq!(matches("Saved as {}", "Not saved"), None);
        assert_eq!(matches("Plain", "Plain"), Some(vec![]));
        assert_eq!(fill("Gespeichert: {}", &["a".into()]), "Gespeichert: a");
        assert_eq!(fill("{1} von {0}", &["5".into(), "2".into()]), "2 von 5");
        assert_eq!(fill("{{literal}", &[]), "{{literal}");
    }

    #[test]
    fn languages_fall_back_to_english() {
        assert_eq!(set_language("C"), None);
        assert_eq!(tr("Anything"), "Anything");
        assert_eq!(set_language("en_US.UTF-8"), None);
    }
}
