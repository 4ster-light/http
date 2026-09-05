#!/usr/bin/env python3
"""SEC-HTTP-001 demo: header bomb.

Sends a request whose headers exceed the 16 KiB head cap. A server without
this control would either buffer without bound or drop the connection
silently (finding F8); this server must answer `431 Request Header Fields
Too Large` and close the connection.

Usage: header_bomb.py [--addr 127.0.0.1:8000] [--size 20480]
"""

import argparse
import socket
import sys

OK, FAIL = "PASS", "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--addr", default="127.0.0.1:8000")
    parser.add_argument("--size", type=int, default=20480,
                        help="size of the oversized header value in bytes "
                             "(default 20 KiB > 16 KiB cap)")
    args = parser.parse_args()
    host, port = args.addr.rsplit(":", 1)

    print("== SEC-HTTP-001: header bomb ==")
    print(f"target={args.addr} header value={args.size} bytes (cap is 16 KiB)")

    bomb = b"A" * args.size
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: demo\r\n"
        b"X-Bomb: " + bomb + b"\r\n"
        b"\r\n"
    )

    try:
        with socket.create_connection((host, int(port)), timeout=5) as s:
            s.sendall(request)
            s.settimeout(3)
            data = s.recv(4096)
            status = data.split(b"\r\n", 1)[0].decode(errors="replace")
            print(f"OBSERVED: {status!r}")
            mitigated = status.startswith("HTTP/1.1 431")
    except (OSError, ValueError) as e:
        print(f"OBSERVED: connection failure: {e}")
        mitigated = False

    print()
    print("EXPECTED: HTTP/1.1 431 Request Header Fields Too Large + close "
          "(no silent drop, no unbounded buffering)")
    verdict = OK if mitigated else FAIL
    print(f"VERDICT : {verdict}")
    return 0 if verdict == OK else 1


if __name__ == "__main__":
    sys.exit(main())
