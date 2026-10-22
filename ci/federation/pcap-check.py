#!/usr/bin/env python3
"""The traffic-shape check (docs/09-transport.md §6.7): from a packet
capture of a device's link to its Nym gateway (or, with --stream, to its
servers' onion services), is the traffic the same whether the device is
idle or busy, and what the model says?

    pcap-check.py CAPTURE MARKS [--port 9000] [--src HOST] [--dst HOST]
                  [--window 15] [--tick 3] [--per-tick 16] [--self-rate 0.1]
    pcap-check.py CAPTURE MARKS --stream --port 7441 --port 7442 …
                  [--per-tick 2] [--self-rate 0]

CAPTURE is a pcap file (tcpdump -w; Ethernet, Linux cooked v1/v2, raw IP or
BSD loopback). MARKS holds `idle_start idle_end busy_start busy_end` in Unix
milliseconds (`enclave-e2e shape --marks`). The link is WebSocket over TCP
(`ws://`, the local mixnet): this reassembles the device's stream to the
gateway, finds the WebSocket frames in it, and counts the binary frames of
the size a Sphinx packet takes (the commonest size; one packet per frame).

With --stream the link is Enclave's own stream framing (RFC 0010: what the
onion carrier sends a server, here dialled directly as the CI stacks are):
`u32 len ‖ request` up, the top bit of the length marking a one-way
request, and `u32 len ‖ reply` down, an empty frame acknowledging a
one-way one. Each request counts as a packet (a tick is one unit and one
poll: --per-tick 2), each non-empty reply as one down; acknowledgements
count as other frames.

It passes when, over windows of WINDOW seconds inside each phase:

* the busy phase's mean packet count is within 15% of the idle phase's;
* no window has more than 1.5 times the median of its phase (no bursts);
* each phase's mean per tick is within ±20% of the model: PER_TICK packets
  a tick (a one-way unit and a poll with its reply blocks) plus
  SELF_RATE a second addressed to the device itself (Nym loop cover and
  Enclave's self-loop probes; math/cover-traffic.md).

It prints a table either way and exits 1 on a failure. Standard library
only.
"""

import argparse
import bisect
import collections
import ipaddress
import statistics
import struct
import sys


def packets(path):
    """(timestamp, link-layer type, bytes) for each record of a pcap file."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise SystemExit(f"{path}: not a pcap file")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise SystemExit(f"{path}: not a pcap file (pcapng? write with tcpdump -w)")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(end + "I", data[20:24])[0] & 0x0FFFFFFF
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(end + "IIII", data[off : off + 16])
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[off : off + incl]
        off += incl


def ip_payload(linktype, frame):
    """The IP packet inside a link-layer frame, or None."""
    if linktype == 1:  # Ethernet
        off, ethertype = 14, frame[12:14]
        while ethertype == b"\x81\x00":  # VLAN tags
            ethertype, off = frame[off + 2 : off + 4], off + 4
        return frame[off:] if ethertype in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == 113:  # Linux cooked v1
        return frame[16:] if frame[14:16] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == 276:  # Linux cooked v2
        return frame[20:] if frame[0:2] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == 0:  # BSD loopback
        return frame[4:]
    if linktype in (101, 228, 229):  # raw IP
        return frame
    return None


def tcp_segment(ip):
    """(src, sport, dst, dport, seq, flags, payload) of a TCP packet, or None."""
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4:
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        if ip[9] != 6:
            return None
        src, dst = ipaddress.ip_address(ip[12:16]), ipaddress.ip_address(ip[16:20])
        tcp = ip[ihl:total]
    elif version == 6:
        if ip[6] != 6:  # no extension headers on this link
            return None
        plen = struct.unpack("!H", ip[4:6])[0]
        src, dst = ipaddress.ip_address(ip[8:24]), ipaddress.ip_address(ip[24:40])
        tcp = ip[40 : 40 + plen]
    else:
        return None
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    doff = (tcp[12] >> 4) * 4
    return str(src), sport, str(dst), dport, seq, tcp[13], tcp[doff:]


class Stream:
    """One direction of a TCP connection, put back in order."""

    def __init__(self):
        self.isn = None
        self.synced = False
        self.segments = []  # (relative seq, timestamp, payload)

    def add(self, ts, seq, flags, payload):
        if flags & 0x02:  # SYN: data starts at the next sequence number
            self.isn = (seq + 1) & 0xFFFFFFFF
            self.synced = True
            return
        if not payload:
            return
        if self.isn is None:
            self.isn = seq
        rel = (seq - self.isn) & 0xFFFFFFFF
        if rel > 0x80000000:  # before the first segment seen
            return
        self.segments.append((rel, ts, payload))

    @property
    def start(self):
        """Where the first data captured is in the stream (0: from the
        connection's start), or None without the SYN."""
        if not self.synced or not self.segments:
            return None
        return min(rel for rel, _, _ in self.segments)

    def runs(self):
        """Contiguous runs of the stream: (bytes, [(offset, timestamp)])."""
        buf, marks, pos = bytearray(), [], None
        for rel, ts, data in sorted(self.segments, key=lambda s: (s[0], s[1])):
            if pos is None:
                pos = rel
            if rel > pos:  # a gap in the capture
                yield bytes(buf), marks
                buf, marks, pos = bytearray(), [], rel
            if rel + len(data) <= pos:  # a retransmission
                continue
            marks.append((len(buf), ts))
            buf += data[pos - rel :]
            pos = rel + len(data)
        if buf:
            yield bytes(buf), marks


def ws_frame(buf, i, masked=True):
    """(opcode, payload length, next offset) of a WebSocket frame at `i`
    (masked: from the client; unmasked: from the server), or None if there
    is no plausible one."""
    if i + 2 > len(buf):
        return None
    b0, b1 = buf[i], buf[i + 1]
    opcode = b0 & 0x0F
    if b0 & 0x70 or opcode not in (0, 1, 2, 8, 9, 10) or bool(b1 & 0x80) != masked:
        return None
    n, j = b1 & 0x7F, i + 2
    if n == 126:
        if j + 2 > len(buf):
            return None
        n, j = struct.unpack("!H", buf[j : j + 2])[0], j + 2
    elif n == 127:
        if j + 8 > len(buf):
            return None
        n, j = struct.unpack("!Q", buf[j : j + 8])[0], j + 8
    j += (4 if masked else 0) + n  # mask key, payload
    return (opcode, n, j) if j <= len(buf) else None


def frames(buf, marks, masked=True):
    """(timestamp, opcode, payload length) of each frame in a run."""
    offsets = [m[0] for m in marks]
    start = 0
    if buf.startswith(b"GET ") or buf.startswith(b"HTTP/"):  # the upgrade
        end = buf.find(b"\r\n\r\n")
        start = end + 4 if end >= 0 else len(buf)
    i = start
    while i < len(buf):
        # Find three frames in a row (the capture may begin mid-frame).
        f = ws_frame(buf, i, masked)
        ok = f is not None
        j = f[2] if f else i
        for _ in range(2):
            if not ok or j >= len(buf):
                break
            g = ws_frame(buf, j, masked)
            ok = g is not None
            j = g[2] if g else j
        if not ok:
            i += 1
            continue
        while f is not None:
            ts = marks[bisect.bisect_right(offsets, i) - 1][1]
            yield ts, f[0], f[1]
            i = f[2]
            f = ws_frame(buf, i, masked)
        # Lost sync (or the end): look again from here.
        if i < len(buf):
            i += 1


def stream_frames(buf, marks):
    """(timestamp, opcode, length) of each `u32 len ‖ bytes` frame in a run
    that starts at the beginning of a connection: opcode 2 for a frame with
    bytes, 0 for an empty one (an acknowledgement)."""
    offsets = [m[0] for m in marks]
    i = 0
    while i + 4 <= len(buf):
        n = struct.unpack("!I", buf[i : i + 4])[0] & 0x7FFFFFFF
        if i + 4 + n > len(buf):
            break
        ts = marks[bisect.bisect_right(offsets, i) - 1][1]
        yield ts, 2 if n else 0, n
        i += 4 + n


def window_counts(found, size, t0, t1, width):
    """Per window of `width` seconds in [t0, t1): (packets of `size` (any
    non-empty frame for None), other frames, payload bytes)."""
    out, k = [], 0
    while t0 + (k + 1) * width <= t1:
        w0, w1 = t0 + k * width, t0 + (k + 1) * width
        inside = [(op, n) for ts, op, n in found if w0 <= ts < w1]
        p = sum(1 for op, n in inside if op == 2 and (n == size if size is not None else n > 0))
        out.append((p, len(inside) - p, sum(n for _, n in inside)))
        k += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("marks")
    ap.add_argument("--port", type=int, action="append",
                    help="the gateway's WebSocket port (9000), or with --stream the servers' ports")
    ap.add_argument("--stream", action="store_true",
                    help="Enclave's stream framing (the onion route) instead of WebSocket")
    ap.add_argument("--dst", help="the gateway's address")
    ap.add_argument("--src", help="the device's address")
    ap.add_argument("--window", type=float, default=15.0)
    ap.add_argument("--tick", type=float, default=3.0)
    ap.add_argument("--per-tick", type=float, default=16.0)
    ap.add_argument("--self-rate", type=float, default=0.1)
    a = ap.parse_args()
    ports = set(a.port or [9000])

    marks = [int(x) / 1000 for x in open(a.marks).read().split()]
    if len(marks) != 4:
        raise SystemExit(f"{a.marks}: want idle_start idle_end busy_start busy_end")
    phases = {"idle": (marks[0], marks[1]), "busy": (marks[2], marks[3])}

    # Up: device to gateway (masked frames). Down: gateway to device.
    streams = {"up": collections.defaultdict(Stream), "down": collections.defaultdict(Stream)}
    for ts, linktype, frame in packets(a.capture):
        seg = tcp_segment(ip_payload(linktype, frame))
        if seg is None:
            continue
        src, sport, dst, dport, seq, flags, payload = seg
        if dport in ports and (not a.dst or dst == a.dst) and (not a.src or src == a.src):
            way = "up"
        elif sport in ports and (not a.dst or src == a.dst) and (not a.src or dst == a.src):
            way = "down"
        else:
            continue
        streams[way][(src, sport, dst, dport)].add(ts, seq, flags, payload)
    if not streams["up"]:
        print("pcap-check: no traffic to the gateway in the capture")
        return 1

    found = {"up": [], "down": []}
    for way, flows in streams.items():
        for key, st in flows.items():
            n = 0
            for k, (buf, m) in enumerate(st.runs()):
                if a.stream and (k > 0 or st.start != 0):
                    # Framing can't be found mid-stream: only what follows
                    # the connection's start counts.
                    break
                got = stream_frames(buf, m) if a.stream else frames(buf, m, masked=way == "up")
                for f in got:
                    found[way].append(f)
                    n += 1
            print(f"{way:<4} {key[0]}:{key[1]} → {key[2]}:{key[3]}: {n} frames")
    sizes = {}
    for way in ("up", "down") if not a.stream else ():
        binary = collections.Counter(n for _, op, n in found[way] if op == 2)
        if binary:
            sizes[way] = binary.most_common(1)[0][0]
            others = sum(binary.values()) - binary[sizes[way]]
            print(f"{way}: Sphinx packets are binary frames of {sizes[way]} B "
                  f"({binary[sizes[way]]}); {others} other binary frames")
    if a.stream:
        for way in ("up", "down"):
            lengths = collections.Counter(n for _, op, n in found[way] if op == 2)
            sizes[way] = None
            print(f"{way}: frames by length: "
                  + ", ".join(f"{n} B ×{c}" for n, c in lengths.most_common(4)))
        if not any(op == 2 for _, op, _ in found["up"]):
            print("pcap-check: no requests to the servers")
            return 1
    elif "up" not in sizes:
        print("pcap-check: no WebSocket binary frames to the gateway")
        return 1

    model = a.per_tick + a.self_rate * a.tick
    print(f"model, up: {a.per_tick:g} + {a.self_rate:g}/s × {a.tick:g} s = {model:.2f} packets a tick")
    print()
    print(f"{'phase':<6}{'window':>7}{'up':>6}{'a tick':>8}{'other':>7}{'bytes':>9}"
          f"{'down':>7}{'other':>7}{'bytes':>9}")
    stats, spacing, down, failures = {}, {}, {}, []
    per_hour = 3600 / a.window
    for name, (t0, t1) in phases.items():
        ups = window_counts(found["up"], sizes["up"], t0, t1, a.window)
        downs = window_counts(found["down"], sizes.get("down", -1), t0, t1, a.window)
        up_size = sizes["up"]
        for k, ((p, o, b), (dp, do, db)) in enumerate(zip(ups, downs)):
            print(f"{name:<6}{k:>7}{p:>6}{p * a.tick / a.window:>8.2f}{o:>7}{b:>9}"
                  f"{dp:>7}{do:>7}{db:>9}")
        counts = [p for p, _, _ in ups]
        if len(counts) < 2:
            failures.append(f"{name}: fewer than two {a.window:g} s windows")
            continue
        stats[name] = (statistics.mean(counts), statistics.median(counts), max(counts))
        down[name] = (
            statistics.mean(b for _, _, b in ups) * per_hour,
            statistics.mean(b for _, _, b in downs) * per_hour,
        )
        times = sorted(
            ts for ts, op, n in found["up"]
            if op == 2 and (n == up_size if up_size is not None else n > 0) and t0 <= ts < t1
        )
        gaps = sorted(y - x for x, y in zip(times, times[1:]))
        if gaps:
            spacing[name] = (statistics.median(gaps), gaps[len(gaps) // 20])
    print()
    for name, (mean, median, top) in stats.items():
        per_tick = mean * a.tick / a.window
        off = per_tick / model - 1
        print(
            f"{name}: up {per_tick:.2f} packets a tick ({off:+.1%} of the model), "
            f"largest window {top} (median {median:g})"
        )
        if name in spacing:
            med, low = spacing[name]
            print(f"{name}: packets {med * 1000:.0f} ms apart (median), 5% under {low * 1000:.0f} ms")
        up_h, down_h = down[name]
        print(f"{name}: {up_h / 1e6:.1f} MB/h up, {down_h / 1e6:.1f} MB/h down, "
              f"{(up_h + down_h) / 1e6:.1f} MB/h in all "
              f"({'frame' if a.stream else 'WebSocket'} payloads)")
        if abs(off) > 0.20:
            failures.append(f"{name}: {per_tick:.2f} packets a tick is {off:+.1%} of the model")
        if top > 1.5 * median:
            failures.append(f"{name}: a window of {top} packets against a median of {median:g}")
    if "idle" in stats and "busy" in stats:
        d = stats["busy"][0] / stats["idle"][0] - 1
        print(f"busy against idle: up {d:+.1%}", end="")
        if abs(d) > 0.15:
            failures.append(f"up, busy is {d:+.1%} of idle")
        if down["idle"][1] > 0:
            dd = down["busy"][1] / down["idle"][1] - 1
            print(f", down {dd:+.1%}", end="")
            if abs(dd) > 0.15:
                failures.append(f"down, busy is {dd:+.1%} of idle")
        print()
    if failures:
        for f in failures:
            print(f"pcap-check: FAILED: {f}")
        return 1
    print("pcap-check: the same traffic idle and busy, as the model says")
    return 0


if __name__ == "__main__":
    sys.exit(main())
