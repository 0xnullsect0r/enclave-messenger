#!/usr/bin/env python3
"""The onion route's numbers on the live Tor network (RFC 0010; workflow
live.yml, job onion-live): start enclave-tord as the carrier netd runs,
then through it ask a server's onion service for its key bundle (a round
trip with a reply, as a poll) and send it one-way units (16 KiB, answered
by an empty acknowledgement), and time them.

    carrier-bench.py TORD STATE_DIR HOST.onion [--rounds 20] [--out bench.json] [--direct]

It prints, and writes as JSON: how long Tor took to bootstrap, how long the
first answer took (circuits to the service built), and the median and 90th
percentile of each kind of round trip after that. Exits non-zero if no
answer came. Standard library only. `--direct` is for a `dev-direct` build
of enclave-tord (a local check without Tor: ENCLAVE_DEV_ONION_MAP names
where HOST.onion really is).

The carrier protocol (crates/enclave-tord/src/carrier.rs): the secret on
the first line of stdin, `ready PORT` on stdout, then `u32 len ‖ body`
frames both ways; an exchange is `1 ‖ u32 id ‖ u8 flags ‖ u16 len ‖ host ‖
u16 port ‖ request`, its answer `1 ‖ u32 id ‖ 0 ‖ reply` (or `1` and a
reason).
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import time

PORT = 7443
UNIT = 16384


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            raise SystemExit("carrier-bench: enclave-tord closed its stdout")
        b += c
    return b


class Carrier:
    def __init__(self, tord, state, direct=False):
        self.p = subprocess.Popen(
            [tord, "--state", state, "--carrier"] + (["--direct"] if direct else []),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.p.stdin.write(os.urandom(32).hex().encode() + b"\n")
        self.p.stdin.flush()
        t0 = time.monotonic()
        line = b""
        while not line.startswith(b"ready"):
            line = self.p.stdout.readline()
            if not line:
                raise SystemExit("carrier-bench: enclave-tord exited before ready")
        self.bootstrap = time.monotonic() - t0
        self.next = 1

    def exchange(self, host, request, oneway):
        i = self.next
        self.next += 1
        h = host.encode()
        body = (
            bytes([1]) + struct.pack("!IB", i, 1 if oneway else 0)
            + struct.pack("!H", len(h)) + h + struct.pack("!H", PORT) + request
        )
        self.p.stdin.write(struct.pack("!I", len(body)) + body)
        self.p.stdin.flush()
        n = struct.unpack("!I", read_exact(self.p.stdout, 4))[0]
        reply = read_exact(self.p.stdout, n)
        kind, rid, err = reply[0], struct.unpack("!I", reply[1:5])[0], reply[5]
        if kind != 1 or rid != i:
            raise SystemExit(f"carrier-bench: answer {kind}/{rid} to {i}")
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
    ap.add_argument("host")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out")
    ap.add_argument("--patience", type=float, default=600, help="seconds to wait for a first answer")
    ap.add_argument("--direct", action="store_true", help="a dev-direct enclave-tord (no Tor)")
    a = ap.parse_args()

    c = Carrier(a.tord, a.state, a.direct)
    print(f"bootstrapped Tor in {c.bootstrap:.1f} s")
    # A new onion service takes a while to be reachable: ask until it is.
    t0 = time.monotonic()
    while True:
        try:
            bundle = c.exchange(a.host, b"", False)
            break
        except RuntimeError as e:
            if time.monotonic() - t0 > a.patience:
                raise SystemExit(f"carrier-bench: no answer from {a.host}: {e}")
            print(f"not yet: {e}")
            time.sleep(10)
    first = time.monotonic() - t0
    if not bundle:
        raise SystemExit("carrier-bench: an empty key bundle")
    print(f"first answer after {first:.1f} s ({len(bundle)} B key bundle)")
    polls, units = [], []
    for _ in range(a.rounds):
        t = time.monotonic()
        c.exchange(a.host, b"", False)
        polls.append(time.monotonic() - t)
        t = time.monotonic()
        ack = c.exchange(a.host, os.urandom(UNIT), True)
        units.append(time.monotonic() - t)
        if ack:
            raise SystemExit("carrier-bench: a one-way unit got a reply")
    out = {
        "bootstrap_s": round(c.bootstrap, 2),
        "first_answer_s": round(first, 2),
        "rounds": a.rounds,
        "key_bundle_ms": {"median": round(pct(polls, 0.5) * 1000), "p90": round(pct(polls, 0.9) * 1000)},
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
