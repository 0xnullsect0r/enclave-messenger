//! The operator's console on a running server (`docs/13-operators.md` §2):
//! one text command per connection on a Unix socket in the data directory
//! (`admin.sock`, mode 0600, reachable only inside the server's container),
//! answered in text. `enclave-admin reports` is the client.
//!
//! ```text
//! reports                     waiting reports, one line each
//! report N                    one report, with its quotes
//! dismiss N                   forget report N
//! close-request-inbox HEX     close a reported account's request inbox
//! withdraw-username NAME      tombstone a name for breaking the policy
//! stats                       aggregate counters
//! ```
//!
//! Answers start with `ok` or `error`, then the details on later lines.

use crate::Server;
use enclave_rpc::api::ReportReason;

/// Socket file name in the server's data directory.
pub const SOCKET: &str = "admin.sock";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn reason(r: ReportReason) -> &'static str {
    match r {
        ReportReason::Spam => "spam",
        ReportReason::Abuse => "harassment or threats",
        ReportReason::Other => "other",
    }
}

/// Run one console command against `server`.
pub fn command(server: &mut Server, line: &str, now: u64) -> String {
    let mut words = line.split_whitespace();
    let cmd = words.next().unwrap_or_default();
    let arg = words.next();
    match (cmd, arg) {
        ("reports", None) => {
            let all = server.reports_by_id();
            let mut out = format!("ok {} waiting\n", all.len());
            for (id, r) in all {
                out.push_str(&format!(
                    "#{id} day {} {} quotes {} {} request inbox {}\n",
                    r.day,
                    reason(r.body.reason),
                    r.body.quotes.len(),
                    if r.body.on_record {
                        "on the record (signed quotes)"
                    } else {
                        "off the record (unverifiable)"
                    },
                    hex(&r.request_inbox)
                ));
            }
            out
        }
        ("report", Some(n)) => {
            let Ok(id) = n.parse::<u64>() else {
                return "error: report N\n".into();
            };
            let Some((_, r)) = server.reports_by_id().into_iter().find(|(i, _)| *i == id) else {
                return format!("error: no report #{id}\n");
            };
            let mut out = format!(
                "ok\nreport #{id}\nday {}\nreason {}\nrequest inbox {}\n{}\n",
                r.day,
                reason(r.body.reason),
                hex(&r.request_inbox),
                if r.body.on_record {
                    "on the record: signed quotes are checked against the account's manifest; other quotes are unverified"
                } else {
                    "off the record: nobody can confirm who wrote the quotes"
                }
            );
            for (i, q) in r.body.quotes.iter().enumerate() {
                // One line per quote; line breaks inside shown as ⏎.
                out.push_str(&format!(
                    "quote {}: {}\n",
                    i + 1,
                    q.replace('\n', " \u{23ce} ")
                ));
            }
            for (i, v) in server.verify_quotes(&r).into_iter().enumerate() {
                let s = &r.body.signed[i];
                out.push_str(&match v {
                    Ok(text) => format!(
                        "signed {}: verified, device {}: {}\n",
                        i + 1,
                        hex(&s.device),
                        text.replace('\n', " \u{23ce} ")
                    ),
                    Err(why) => format!("signed {}: not verified: {why}\n", i + 1),
                });
            }
            out
        }
        ("dismiss", Some(n)) => match n.parse::<u64>() {
            Ok(id) if server.dismiss_report(id) => format!("ok dismissed #{id}\n"),
            Ok(id) => format!("error: no report #{id}\n"),
            Err(_) => "error: dismiss N\n".into(),
        },
        ("close-request-inbox", Some(h)) => {
            let Some(mb) = unhex32(h) else {
                return "error: close-request-inbox HEX (64 hex digits)\n".into();
            };
            if server.disable_request_inbox(&mb) {
                format!("ok closed request inbox {h}\n")
            } else {
                format!("error: no request inbox {h}\n")
            }
        }
        ("withdraw-username", Some(name)) => match server.withdraw_username(name, now) {
            Ok(true) => format!("ok withdrew {name}\n"),
            Ok(false) => format!("ok {name} was already withdrawn\n"),
            Err(e) => format!("error: {e}\n"),
        },
        ("stats", None) => {
            let s = server.stats();
            format!(
                "ok\nrequests {}\ncover {}\nstored {}\ntokens burned {}\ndenied {}\nreplays {}\n",
                s.requests, s.cover, s.stored, s.tokens_burned, s.denied, s.replays
            )
        }
        _ => "error: commands are reports, report N, dismiss N, close-request-inbox HEX, \
              withdraw-username NAME, stats\n"
            .into(),
    }
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}
