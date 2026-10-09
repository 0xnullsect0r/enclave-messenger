//! Reporting an account to its server's operator
//! (`docs/13-operators.md` §2, RT-25).
//!
//! A report goes to the reported person's home server, sealed to that
//! server like every request (so only its operator reads it), with a proof
//! of work. It names their request inbox, the only handle an operator can
//! act on, and the reason. Quoting their recent messages is the reporter's
//! choice. Conversations here are off the record, so quotes are an
//! unverifiable claim and the operator is told so. The report carries
//! nothing about the reporter; the request comes through the mixnet like
//! any other.
//!
//! After reporting spam, the reporter can make message requests to them
//! cost more for a month ([`Client::raise_request_effort`]): their server
//! asks every writer to their request inbox for that proof of work.

use super::{Client, ContactState};
use crate::{CoreError, Result};
use enclave_rpc::api::{
    self, FLAG_EFFORT, MAX_INBOX_EFFORT, MAX_REPORT_MESSAGES, ReportBody, ReportReason,
};
use enclave_wire::{Op, RequestHeader};

const EFFORT: &str = "request-effort";
/// Requests seen per day: `u32 day ‖ u32 today ‖ u32 yesterday ‖ u8 auto`.
const LOAD: &str = "request-load";
/// Requests in one day that make new ones cost more (a flood).
pub const FLOOD_PER_DAY: u32 = 20;
/// A raise the flood caused ends after a day with fewer than this.
pub const CALM_PER_DAY: u32 = 5;
/// How long a raised request effort lasts.
pub const RAISED_EFFORT_SECS: u64 = 30 * 86_400;
/// The first raise (above the server's default of 64).
const FIRST_RAISE: u32 = 256;

impl Client {
    /// Report `root` to their server's operator, quoting up to
    /// `quote` of their latest messages (0 for none).
    pub async fn report(
        &mut self,
        root: &[u8; 64],
        reason: ReportReason,
        quote: usize,
    ) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state == ContactState::Pending {
            return Err(CoreError::NotAccepted); // nothing of theirs to report
        }
        let (server, inbox) = (c.server, c.request_inbox);
        let mut quotes: Vec<String> = self
            .messages(root)?
            .into_iter()
            .filter(|m| !m.outgoing && !m.deleted && !m.text.is_empty())
            .map(|m| m.text)
            .collect();
        let keep = quote.min(MAX_REPORT_MESSAGES);
        quotes.drain(..quotes.len().saturating_sub(keep));
        let body = ReportBody {
            reason,
            on_record: false,
            quotes,
        };
        let env = api::frame(&body.encode(), &mut self.rng)?;
        let now = self.now();
        self.rpc
            .report(&server, inbox, &env, now, &mut self.rng)
            .await
    }

    /// Make message requests to us cost more for [`RAISED_EFFORT_SECS`]:
    /// four times the last raise (256 the first time), up to
    /// [`MAX_INBOX_EFFORT`]. Returns the new effort.
    pub async fn raise_request_effort(&mut self) -> Result<u32> {
        let (now_effort, _) = self.request_effort()?;
        let effort = (now_effort.saturating_mul(4)).clamp(FIRST_RAISE, MAX_INBOX_EFFORT);
        let now = self.now();
        self.set_request_effort(effort, now).await?;
        Ok(effort)
    }

    /// The effort we asked for our request inbox and since when (0: the
    /// server's own).
    pub fn request_effort(&self) -> Result<(u32, u64)> {
        Ok(self
            .setting(EFFORT)?
            .filter(|b| b.len() == 12)
            .map_or((0, 0), |b| {
                (
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                    u64::from_be_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]),
                )
            }))
    }

    async fn set_request_effort(&mut self, effort: u32, now: u64) -> Result<()> {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: FLAG_EFFORT,
            mailbox: self.profile.request_inbox,
            token: self.profile.request_owner,
        };
        let env = api::frame(&effort.to_be_bytes(), &mut self.rng)?;
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &env, now, &mut self.rng)
            .await?;
        let rec = [&effort.to_be_bytes()[..], &now.to_be_bytes()].concat();
        self.set_setting(EFFORT, &rec)
    }

    /// A month after the last raise, requests cost what the server asks
    /// again; a raise a flood caused ends after a calm day (from `sync`).
    pub(crate) async fn relax_request_effort(&mut self, now: u64) -> Result<()> {
        let (effort, since) = self.request_effort()?;
        let load = self.request_load(now)?;
        let calm = load.3 && load.2 < CALM_PER_DAY && load.1 < CALM_PER_DAY;
        if effort > 0 && (now >= since + RAISED_EFFORT_SECS || calm) {
            self.set_request_effort(0, now).await?;
            self.set_request_load(&(load.0, load.1, load.2, false))?;
        }
        Ok(())
    }

    /// `n` more envelopes came to the request inbox (`docs/09-transport.md`
    /// §4, adaptive effort): past [`FLOOD_PER_DAY`] in a day, and at each
    /// multiple of it, new requests cost four times more, up to
    /// [`MAX_INBOX_EFFORT`].
    pub(crate) async fn note_requests(&mut self, n: u32, now: u64) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        let (day, today, yesterday, auto) = self.request_load(now)?;
        let after = today.saturating_add(n);
        let flood = after / FLOOD_PER_DAY > today / FLOOD_PER_DAY;
        let (effort, _) = self.request_effort()?;
        let auto = if flood && effort < MAX_INBOX_EFFORT {
            let next = effort
                .saturating_mul(4)
                .clamp(FIRST_RAISE, MAX_INBOX_EFFORT);
            self.set_request_effort(next, now).await?;
            // A raise the person asked for stays its month.
            auto || effort == 0
        } else {
            auto
        };
        self.set_request_load(&(day, after, yesterday, auto))
    }

    /// Today's day, requests today and yesterday, and whether the current
    /// raise came from a flood (moved on to `now`'s day).
    fn request_load(&self, now: u64) -> Result<(u32, u32, u32, bool)> {
        let day = api::day_of(now);
        let (d, today, yesterday, auto) =
            self.setting(LOAD)?
                .filter(|b| b.len() == 13)
                .map_or((day, 0, 0, false), |b| {
                    let at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                    (at(0), at(4), at(8), b[12] == 1)
                });
        Ok(match day.saturating_sub(d) {
            0 => (day, today, yesterday, auto),
            1 => (day, 0, today, auto),
            _ => (day, 0, 0, auto),
        })
    }

    fn set_request_load(&mut self, l: &(u32, u32, u32, bool)) -> Result<()> {
        let b = [
            &l.0.to_be_bytes()[..],
            &l.1.to_be_bytes(),
            &l.2.to_be_bytes(),
            &[u8::from(l.3)],
        ]
        .concat();
        self.set_setting(LOAD, &b)
    }
}
