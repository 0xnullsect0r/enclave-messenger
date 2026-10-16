//! Message formatting (`docs/16-features.md`: bold, italic, strike, mono,
//! spoiler), written the way people type it and shown as Slint styled
//! text:
//!
//! ```text
//! *bold*   _italic_   ~strike~   `mono`   ||spoiler||
//! ```
//!
//! A marker opens only before a non-space and after the start, a space or
//! punctuation, and closes only after a non-space and before the end, a
//! space or punctuation, so `2*3*4` and `snake_case_name` stay as they are.
//! Inside `mono` nothing else is read. A spoiler shows as blocks until the
//! message is selected. Everything else is escaped before it reaches the
//! markdown reader, so a message can't make links, headings, lists or
//! anything but these five.

/// One run of text and the styles on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    /// The text.
    pub text: String,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Struck through.
    pub strike: bool,
    /// Monospace.
    pub mono: bool,
    /// A spoiler.
    pub spoiler: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Bold,
    Italic,
    Strike,
    Mono,
    Spoiler,
}

impl Mark {
    fn at(s: &[char], i: usize) -> Option<(Mark, usize)> {
        match s[i] {
            '*' => Some((Mark::Bold, 1)),
            '_' => Some((Mark::Italic, 1)),
            '~' => Some((Mark::Strike, 1)),
            '`' => Some((Mark::Mono, 1)),
            '|' if s.get(i + 1) == Some(&'|') => Some((Mark::Spoiler, 2)),
            _ => None,
        }
    }
}

fn boundary(c: Option<&char>) -> bool {
    c.is_none_or(|c| c.is_whitespace() || (c.is_ascii_punctuation() && !"*_~`|".contains(*c)))
}

/// Where the marker at `i` closes, if it opens there.
fn closing(s: &[char], i: usize, mark: Mark, len: usize) -> Option<usize> {
    let open_ok =
        (i == 0 || boundary(s.get(i - 1))) && s.get(i + len).is_some_and(|c| !c.is_whitespace());
    if !open_ok {
        return None;
    }
    let mut j = i + len + 1;
    while j < s.len() {
        if let Some((m, l)) = Mark::at(s, j)
            && m == mark
            && !s[j - 1].is_whitespace()
            && boundary(s.get(j + l))
        {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// The runs of `text`.
pub fn parse(text: &str) -> Vec<Run> {
    let s: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    walk(&s, Run::default(), &mut out);
    // Join neighbours with the same style.
    let mut joined: Vec<Run> = Vec::new();
    for r in out.into_iter().filter(|r| !r.text.is_empty()) {
        match joined.last_mut() {
            Some(l)
                if Run {
                    text: String::new(),
                    ..l.clone()
                } == Run {
                    text: String::new(),
                    ..r.clone()
                } =>
            {
                l.text.push_str(&r.text)
            }
            _ => joined.push(r),
        }
    }
    joined
}

fn walk(s: &[char], style: Run, out: &mut Vec<Run>) {
    let mut plain = String::new();
    let mut i = 0;
    while i < s.len() {
        if !style.mono
            && let Some((mark, len)) = Mark::at(s, i)
            && let Some(end) = closing(s, i, mark, len)
        {
            out.push(Run {
                text: std::mem::take(&mut plain),
                ..style.clone()
            });
            let mut inner = Run {
                text: String::new(),
                ..style.clone()
            };
            match mark {
                Mark::Bold => inner.bold = true,
                Mark::Italic => inner.italic = true,
                Mark::Strike => inner.strike = true,
                Mark::Mono => inner.mono = true,
                Mark::Spoiler => inner.spoiler = true,
            }
            if mark == Mark::Mono {
                out.push(Run {
                    text: s[i + len..end].iter().collect(),
                    ..inner
                });
            } else {
                walk(&s[i + len..end], inner, out);
            }
            i = end + len;
            continue;
        }
        plain.push(s[i]);
        i += 1;
    }
    out.push(Run {
        text: plain,
        ..style
    });
}

/// The text without its markers, spoilers kept (copying, search, the
/// screen reader when the message is selected).
pub fn plain(text: &str) -> String {
    parse(text).into_iter().map(|r| r.text).collect()
}

/// For a screen reader: spoilers said to be hidden until the message is
/// selected.
pub fn spoken(text: &str, reveal: bool) -> String {
    parse(text)
        .into_iter()
        .map(|r| {
            if r.spoiler && !reveal {
                crate::i18n::tr("Hidden text")
            } else {
                r.text
            }
        })
        .collect()
}

/// For a one-line preview or a notification: no markers, spoilers as
/// blocks (a preview is never "selected", so it never reveals one).
pub fn preview(text: &str) -> String {
    parse(text)
        .into_iter()
        .map(|r| if r.spoiler { blocks(&r.text) } else { r.text })
        .collect()
}

fn blocks(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_whitespace() { c } else { '█' })
        .collect()
}

/// Whether `text` has a spoiler.
pub fn has_spoiler(text: &str) -> bool {
    parse(text).iter().any(|r| r.spoiler)
}

/// Escape for the markdown reader: every ASCII punctuation mark escaped,
/// line starts that would indent a code block kept as no-break spaces,
/// and line breaks as paragraph breaks.
fn escape(text: &str, line_start: &mut bool) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '\n' => {
                out.push_str("\\\n");
                *line_start = true;
                continue;
            }
            ' ' | '\t' if *line_start => out.push('\u{a0}'),
            c if c.is_ascii_punctuation() => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
        *line_start = false;
    }
    out
}

/// Markdown for `text`'s runs: what [`styled`] gives Slint. Spoilers are
/// blocks of the same length unless `reveal`.
pub fn markdown(text: &str, reveal: bool) -> String {
    let mut out = String::new();
    let mut at = true;
    for r in parse(text) {
        let body = if r.spoiler && !reveal {
            blocks(&r.text)
        } else {
            r.text.clone()
        };
        if body.trim().is_empty()
            || body.contains('\n') && (r.bold || r.italic || r.strike || r.mono)
        {
            // Markers don't span paragraphs; nor do they wrap spaces alone.
            out.push_str(&escape(&body, &mut at));
            continue;
        }
        let (lead, core, trail) = split_space(&body);
        out.push_str(&escape(lead, &mut at));
        at = false;
        if r.mono {
            // A code span takes text as it is: only its backticks need care.
            let ticks = if core.contains('`') { "`` " } else { "`" };
            let close = if core.contains('`') { " ``" } else { "`" };
            out.push_str(ticks);
            out.push_str(core);
            out.push_str(close);
        } else {
            let mut s = escape(core, &mut at);
            if r.strike {
                s = format!("~~{s}~~");
            }
            if r.italic {
                s = format!("*{s}*");
            }
            if r.bold {
                s = format!("**{s}**");
            }
            out.push_str(&s);
        }
        out.push_str(&escape(trail, &mut at));
    }
    out
}

/// `s` as leading spaces, the rest, and trailing spaces (emphasis can't
/// start or end with a space).
fn split_space(s: &str) -> (&str, &str, &str) {
    let t = s.trim_start();
    let lead = &s[..s.len() - t.len()];
    let core = t.trim_end();
    (lead, core, &t[core.len()..])
}

/// `text` as Slint styled text (plain when the markdown can't be read,
/// which escaping should make impossible).
pub fn styled(text: &str, reveal: bool) -> slint::StyledText {
    slint::StyledText::from_markdown(&markdown(text, reveal))
        .unwrap_or_else(|_| slint::StyledText::from_plain_text(&plain(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(text: &str) -> Run {
        Run {
            text: text.into(),
            ..Run::default()
        }
    }

    #[test]
    fn markers_need_boundaries() {
        assert_eq!(parse("2*3*4"), vec![r("2*3*4")]);
        assert_eq!(parse("snake_case_name"), vec![r("snake_case_name")]);
        assert_eq!(parse("* not bold *"), vec![r("* not bold *")]);
        assert_eq!(
            parse("a *b* c"),
            vec![
                r("a "),
                Run {
                    text: "b".into(),
                    bold: true,
                    ..Run::default()
                },
                r(" c")
            ]
        );
        assert_eq!(
            parse("(_it_)"),
            vec![
                r("("),
                Run {
                    text: "it".into(),
                    italic: true,
                    ..Run::default()
                },
                r(")")
            ]
        );
        assert_eq!(
            parse("*bold _both_*"),
            vec![
                Run {
                    text: "bold ".into(),
                    bold: true,
                    ..Run::default()
                },
                Run {
                    text: "both".into(),
                    bold: true,
                    italic: true,
                    ..Run::default()
                },
            ]
        );
        assert_eq!(
            parse("`*x*`"),
            vec![Run {
                text: "*x*".into(),
                mono: true,
                ..Run::default()
            }]
        );
        assert_eq!(parse("||s||").first().map(|r| r.spoiler), Some(true));
        assert_eq!(plain("hi *there* ||you||"), "hi there you");
        assert_eq!(
            preview("Sam: hi *there* ||you two||"),
            "Sam: hi there ███ ███"
        );
    }

    #[test]
    fn markdown_is_escaped_and_reads() {
        for text in [
            "plain",
            "# not a heading",
            "    not code",
            "- not a list\n1. nor this",
            "<b>no html</b> &amp; [no](link) ![img](x)",
            "*bold* _it_ ~gone~ `a*b` ||secret||",
            "line\nbreak\n\n\nmany",
            "`tick ` inside`",
            "*spaced bold * no",
            "trailing \\",
        ] {
            let md = markdown(text, true);
            assert!(
                slint::StyledText::from_markdown(&md).is_ok(),
                "{text:?} → {md:?}"
            );
            let hidden = markdown(text, false);
            assert!(
                slint::StyledText::from_markdown(&hidden).is_ok(),
                "{text:?} → {hidden:?}"
            );
        }
        assert_eq!(markdown("a *b*", true), "a **b**");
        assert_eq!(markdown("||ab cd||", false), "██ ██");
        assert_eq!(markdown("x.", true), "x\\.");
    }
}
