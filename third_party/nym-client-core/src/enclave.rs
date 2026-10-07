// ENCLAVE PATCH (third_party/PATCHES.md): what this process has handed to
// its mixnet client that hasn't reached the far gateway yet, so it can wait
// for that before exiting (a one-way send is otherwise lost with the
// process). Process-wide: an Enclave process runs one mixnet client.
//
// A message counts 1 from submission (`note_submitted`, by whoever calls
// the client's sender) until the client has prepared it, and each of its
// fragments counts 1 from then until its acknowledgement comes back (or it
// is given up after its retransmissions).

use std::sync::atomic::{AtomicIsize, Ordering};

static OUTSTANDING: AtomicIsize = AtomicIsize::new(0);

/// Messages submitted but not yet prepared, plus fragments sent but not
/// yet acknowledged.
pub fn outstanding() -> usize {
    usize::try_from(OUTSTANDING.load(Ordering::SeqCst)).unwrap_or(0)
}

/// Call before handing a message to the client's sender.
pub fn note_submitted() {
    OUTSTANDING.fetch_add(1, Ordering::SeqCst);
}

/// Call if handing it over failed.
pub fn note_unsubmitted() {
    settle(1);
}

static FRAGMENTS_SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Fragments (Sphinx packets of real messages) prepared so far, for
/// measuring how many packets a message takes.
pub fn fragments_sent() -> u64 {
    FRAGMENTS_SENT.load(Ordering::SeqCst)
}

pub(crate) fn add(n: usize) {
    OUTSTANDING.fetch_add(isize::try_from(n).unwrap_or(isize::MAX), Ordering::SeqCst);
    FRAGMENTS_SENT.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::SeqCst);
}

pub(crate) fn settle(n: usize) {
    OUTSTANDING.fetch_sub(isize::try_from(n).unwrap_or(isize::MAX), Ordering::SeqCst);
}

// Pacing (`docs/09-transport.md` §6.3): the gap between real packets, so a
// tick's packets leave at even intervals instead of in a burst, and the
// mean delay of loop cover, both set by whoever runs the client and read
// afresh for every packet. 0 means unset: no gap, and the configured loop
// cover delay.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

static PACKET_GAP_NS: AtomicU64 = AtomicU64::new(0);
static LOOP_COVER_NS: AtomicU64 = AtomicU64::new(0);

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Leave at least `gap` between two real packets (zero: none).
pub fn set_packet_gap(gap: Duration) {
    PACKET_GAP_NS.store(nanos(gap), Ordering::SeqCst);
}

/// The gap between real packets.
pub fn packet_gap() -> Duration {
    Duration::from_nanos(PACKET_GAP_NS.load(Ordering::SeqCst))
}

/// Send loop cover with this mean delay (zero: the configured one).
pub fn set_loop_cover_delay(mean: Duration) {
    LOOP_COVER_NS.store(nanos(mean), Ordering::SeqCst);
}

/// The loop cover mean delay, if one was set.
pub fn loop_cover_delay() -> Option<Duration> {
    match LOOP_COVER_NS.load(Ordering::SeqCst) {
        0 => None,
        n => Some(Duration::from_nanos(n)),
    }
}
