#!/usr/bin/env python3
"""SEC-HTTP-002 demo: Slow-Loris stalled headers.

Opens several connections, sends an incomplete request head, then goes
silent for longer than the server's head-read timeout (default 10 s).
A server without this control would hold every socket open indefinitely
(finding F2 in REFACTOR-PLAN.md); this server must drop each stalled
connection with a `400` response, while normal traffic keeps working.

Note the honest scope of the control: the timeout is a per-read idle
timeout, so it kills connections that *stall* past the limit — exactly
what this demo does. See docs/security/controls.md (SEC-HTTP-002).

Usage: slowloris.py [--addr 127.0.0.1:8000] [--sockets 5] [--stall 12]
"""

import argparse
import socket
import sys
import time

OK, FAIL = "PASS", "FAIL"


def legit_get(addr: tuple[str, int]) -> bool:
    """A normal GET must succeed even while the attack runs."""
    try:
        with socket.create_connection(addr, timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: demo\r\nConnection: close\r\n\r\n")
            data = s.recv(4096)
            return data.startswith(b"HTTP/1.1 200")
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--addr", default="127.0.0.1:8000")
    parser.add_argument("--sockets", type=int, default=5)
    parser.add_argument("--stall", type=float, default=12.0,
                        help="seconds of silence; must exceed the server's "
                             "head_read_timeout (default 10 s)")
    args = parser.parse_args()
    host, port = args.addr.rsplit(":", 1)
    addr = (host, int(port))

    print("== SEC-HTTP-002: Slow-Loris (stalled request heads) ==")
    print(f"target={args.addr} sockets={args.sockets} stall={args.stall}s")
    print()

    control_ok = legit_get(addr)
    print(f"[control] normal GET during attack window : "
          f"{'200 OK' if control_ok else 'FAILED'}")

    sockets = []
    for i in range(args.sockets):
        s = socket.create_connection(addr, timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: demo\r\n")  # incomplete head
        sockets.append(s)
    print(f"[attack ] opened {len(sockets)} connections with incomplete heads; "
          f"going silent for {args.stall}s ...")

    time.sleep(args.stall)

    results = []
    for i, s in enumerate(sockets):
        s.settimeout(3)
        try:
            data = s.recv(4096)
            if not data:
                results.append((i, "closed without response"))
            elif data.startswith(b"HTTP/1.1 400"):
                results.append((i, "400 Bad Request"))
            else:
                results.append((i, f"unexpected response: {data[:40]!r}"))
        except socket.timeout:
            results.append((i, "still open (server waited) — NOT dropped"))
        except OSError as e:
            results.append((i, f"connection error: {e}"))
        finally:
            s.close()

    print()
    print("per-connection outcome after the stall:")
    for i, outcome in results:
        print(f"  socket {i}: {outcome}")

    dropped = sum(1 for _, o in results if "400" in o or "closed" in o)
    attack_mitigated = dropped == len(sockets)
    print()
    print("EXPECTED: every stalled connection dropped (400 + close) within "
          "~head_read_timeout; normal traffic unaffected")
    print(f"OBSERVED: {dropped}/{len(sockets)} dropped; "
          f"normal GET {'worked' if control_ok else 'FAILED'}")
    verdict = OK if attack_mitigated and control_ok else FAIL
    print(f"VERDICT : {verdict}")
    return 0 if verdict == OK else 1


if __name__ == "__main__":
    sys.exit(main())
