#!/usr/bin/env python3
"""Ask a server for its key bundle over the fallback route: SOCKS5 (user
`enclave`, password from argv) to HOST:PORT, then the server's framing
(`u32 len ‖ bytes` each way) with an empty request. Prints the bundle's
length; exits non-zero if there is none. Standard library only.

    keybundle.py SOCKS_PORT SECRET HOST PORT
"""
import socket
import struct
import sys


def read(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit("connection closed")
        b += c
    return b


def main():
    socks_port, secret, host, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    s = socket.create_connection(("127.0.0.1", int(socks_port)), timeout=300)
    s.sendall(b"\x05\x01\x02")
    if read(s, 2) != b"\x05\x02":
        raise SystemExit("socks: no user/password")
    user, pw = b"enclave", secret.encode()
    s.sendall(bytes([1, len(user)]) + user + bytes([len(pw)]) + pw)
    if read(s, 2) != b"\x01\x00":
        raise SystemExit("socks: refused the secret")
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    head = read(s, 4)
    if head[1] != 0:
        raise SystemExit(f"socks: connect failed ({head[1]})")
    skip = {1: 4, 4: 16}.get(head[3])
    if skip is None:
        skip = read(s, 1)[0]
    read(s, skip + 2)
    s.sendall(struct.pack(">I", 0))
    n = struct.unpack(">I", read(s, 4))[0]
    bundle = read(s, n)
    print(f"key bundle over {host}: {len(bundle)} bytes")
    if n == 0:
        raise SystemExit("empty bundle")


main()
