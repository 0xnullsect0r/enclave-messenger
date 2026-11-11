#!/usr/bin/env python3
"""The fast routes' numbers (RFC 0011; workflow live.yml): start
enclave-tord as the carrier netd runs, then through it `POST` sealed
requests to a stack's front (`https://DOMAIN/net`) and time them — over
Tor's exit (`exit:DOMAIN`), or with `--direct` dialed by tord with no Tor
in between (`direct:DOMAIN`). Run it beside carrier-bench.py for the onion
route's numbers on the same stack and compare.

    front-bench.py TORD STATE_DIR DOMAIN [--rounds 20] [--out bench.json]
                  [--direct] [--socks HOST:PORT] [--front-port N]

It prints, and writes as JSON: how long Tor took to come up (instant with
`--socks`, a system Tor's SocksPort), how long the first answer took, and
the median and 90th percentile of each kind of round trip after that. A
stack whose front didn't open its fast route (`[front] net` empty, HTTP
404) fails at once with the front's answer. Standard library only.

The carrier's front request (crates/enclave-tord/src/carrier.rs): kind 3,
`u32 id ‖ u8 flags ‖ u16 len ‖ DOMAIN ‖ request`, its answer like any
other's. `--direct` asks tord to dial the front itself with no Tor (the
consented direct fast route); without it the request leaves through Tor's
exit. `--socks` passes `--tor-socks` to tord, riding a system Tor instead
of the embedded arti. `--front-port` (443) is where the front's HTTPS
listener is, for a test stack that put it elsewhere.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import time

UNIT = 16384
POLL = 2048
ONEWAY = 1
DIRECT = 2


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            raise SystemExit("front-bench: enclave-tord closed its stdout")
        b += c
    return b


class Carrier:
    def __init__(self, tord, state, direct, socks=None):
        args = [tord, "--state", state, "--carrier"]
        if direct:
            args.append("--direct")
        if socks:
            args += ["--tor-socks", socks]
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.p.stdin.write(os.urandom(32).hex().encode() + b"\n")
        self.p.stdin.flush()
        t0 = time.monotonic()
        line = b""
        while not line.startswith(b"ready"):
            line = self.p.stdout.readline()
            if not line:
                raise SystemExit("front-bench: enclave-tord exited before ready")
        self.bootstrap = time.monotonic() - t0
        self.next = 1

    def front(self, domain, request, oneway, direct, port):
        i = self.next
        self.next += 1
        d = domain.encode()
        flags = (ONEWAY if oneway else 0) | (DIRECT if direct else 0)
        body = (
            bytes([3]) + struct.pack("!IB", i, flags)
            + struct.pack("!H", len(d)) + d + struct.pack("!H", port) + request
        )
        self.p.stdin.write(struct.pack("!I", len(body)) + body)
        self.p.stdin.flush()
        n = struct.unpack("!I", read_exact(self.p.stdout, 4))[0]
        reply = read_exact(self.p.stdout, n)
        kind, rid, err = reply[0], struct.unpack("!I", reply[1:5])[0], reply[5]
        if kind != 3 or rid != i:
            raise SystemExit(f"front-bench: answer {kind}/{rid} to {i}")
        if err:
            raise RuntimeError(reply[6:].decode(errors="replace"))
        return reply[6:]


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tord")
    ap.add_argument("state")
    ap.add_argument("domain")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out")
    ap.add_argument("--patience", type=float, default=600, help="seconds to wait for a first answer")
    ap.add_argument("--direct", action="store_true", help="tord dials the front itself, no Tor")
    ap.add_argument("--socks", help="a system Tor's SocksPort to ride (HOST:PORT)")
    ap.add_argument("--front-port", type=int, default=443)
    a = ap.parse_args()

    c = Carrier(a.tord, a.state, a.direct, a.socks)
    print(f"tord ready in {c.bootstrap:.1f} s")
    # The front may be behind a Tor still coming up: ask until it answers.
    t0 = time.monotonic()
    while True:
        try:
            bundle = c.front(a.domain, b"", False, a.direct, a.front_port)
            break
        except RuntimeError as e:
            if time.monotonic() - t0 > a.patience:
                raise SystemExit(f"front-bench: no answer from {a.domain}: {e}")
            print(f"not yet: {e}")
            time.sleep(10)
    first = time.monotonic() - t0
    if not bundle:
        raise SystemExit("front-bench: an empty key bundle")
    print(f"first answer after {first:.1f} s ({len(bundle)} B key bundle)")
    polls, units = [], []
    for _ in range(a.rounds):
        t = time.monotonic()
        c.front(a.domain, os.urandom(POLL), False, a.direct, a.front_port)
        polls.append(time.monotonic() - t)
        t = time.monotonic()
        ack = c.front(a.domain, os.urandom(UNIT), True, a.direct, a.front_port)
        units.append(time.monotonic() - t)
        if ack:
            raise SystemExit("front-bench: a one-way unit got a reply")
    route = "direct" if a.direct else ("exit" + (f" via {a.socks}" if a.socks else ""))
    out = {
        "route": route,
        "bootstrap_s": round(c.bootstrap, 2),
        "first_answer_s": round(first, 2),
        "rounds": a.rounds,
        "poll_ms": {"median": round(pct(polls, 0.5) * 1000), "p90": round(pct(polls, 0.9) * 1000)},
        "oneway_unit_ms": {"median": round(pct(units, 0.5) * 1000), "p90": round(pct(units, 0.9) * 1000)},
    }
    print(json.dumps(out, indent=2))
    if a.out:
        with open(a.out, "w") as f:
            json.dump(out, f, indent=2)
    c.p.stdin.close()
    try:
        c.p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        c.p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
