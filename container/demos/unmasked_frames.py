#!/usr/bin/env python3
"""SEC-WS-001 demo: unmasked client frames.

Performs a real opening handshake (RFC 6455 §4.2.1, verifying the
`Sec-WebSocket-Accept` digest per §4.2.2), then sends two data frames:

1. a correctly *masked* text frame — must be echoed (positive control);
2. an *unmasked* text frame — a §5.3 violation (finding F6/forgery
   enabler: unmasked frames let malicious intermediaries forge traffic).
   The server must fail the connection with a `1002` close frame, not
   process the payload.

Usage: unmasked_frames.py [--addr 127.0.0.1:8000]
"""

import argparse
import base64
import hashlib
import os
import socket
import sys

OK, FAIL = "PASS", "FAIL"
MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def handshake(sock: socket.socket, host_header: str) -> None:
    """Client side of the opening handshake, with digest verification."""
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(request)

    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("closed during handshake")
        head += chunk
    text = head.decode(errors="replace")
    status = text.splitlines()[0]

    digest = base64.b64encode(hashlib.sha1(key.encode() + MAGIC).digest()).decode()
    accept = None
    for line in text.split("\r\n"):
        if line.lower().startswith("sec-websocket-accept:"):
            accept = line.split(":", 1)[1].strip()
    if not status.startswith("HTTP/1.1 101"):
        raise ConnectionError(f"expected 101, got {status!r}")
    if accept != digest:
        raise ConnectionError(
            f"Sec-WebSocket-Accept mismatch (RFC 6455 §4.2.2): {accept!r} != {digest!r}"
        )
    print(f"[control] handshake accepted; Sec-WebSocket-Accept verified "
          f"(RFC 6455 §4.2.2)")

    if len(head) > head.index(b"\r\n\r\n") + 4:
        raise ConnectionError("unexpected bytes after 101 head")


def read_frame(sock: socket.socket):
    """Reads one server-to-client frame: returns (fin, opcode, payload)."""
    def need(n: int, buf: bytearray) -> None:
        while len(buf) < n:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed while reading frame")
            buf.extend(chunk)

    buf = bytearray()
    need(2, buf)
    fin = bool(buf[0] & 0x80)
    opcode = buf[0] & 0x0F
    masked = bool(buf[1] & 0x80)
    if masked:  # RFC 6455 §5.1: server frames are never masked.
        raise ConnectionError("server sent a masked frame")
    length = buf[1] & 0x7F
    offset = 2
    if length == 126:
        need(4, buf)
        length = int.from_bytes(buf[2:4], "big")
        offset = 4
    elif length == 127:
        need(10, buf)
        length = int.from_bytes(buf[2:10], "big")
        offset = 10
    need(offset + length, buf)
    return fin, opcode, bytes(buf[offset:offset + length])


def text_frame(payload: bytes, mask: bytes | None) -> bytes:
    """Builds a text frame; mask=None produces an (illegal) unmasked frame."""
    mask_bit = 0x80 if mask is not None else 0x00
    header = bytearray([0x81, mask_bit | len(payload)])
    if mask is not None:
        header += mask
        header += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    else:
        header += payload
    return bytes(header)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--addr", default="127.0.0.1:8000")
    args = parser.parse_args()
    host, port = args.addr.rsplit(":", 1)
    host_header = args.addr if host else "localhost"

    print("== SEC-WS-001: unmasked client frames (RFC 6455 §5.3) ==")
    print(f"target={args.addr}")

    sock = socket.create_connection((host, int(port)), timeout=5)
    sock.settimeout(5)
    try:
        handshake(sock, host_header)

        # 1. Positive control: a masked frame must be echoed.
        sock.sendall(text_frame(b"Hello", mask=os.urandom(4)))
        fin, opcode, payload = read_frame(sock)
        echoed = opcode == 0x1 and payload == b"Echo: Hello"
        print(f"[control] masked frame echoed           : {payload!r}")

        # 2. The attack: an unmasked text frame.
        print("[attack ] sending UNMASKED text frame 'forged'")
        sock.sendall(text_frame(b"forged", mask=None))
        fin, opcode, payload = read_frame(sock)
        is_close = opcode == 0x8
        code = int.from_bytes(payload[:2], "big") if is_close and len(payload) >= 2 else None
        detail = f"close frame code={code}" if is_close else f"unexpected frame opcode={opcode} payload={payload!r}"
        print(f"OBSERVED: {detail}")
        mitigated = is_close and code == 1002
    finally:
        sock.close()

    print()
    print("EXPECTED: masked frames echoed; unmasked frame answered with "
          "close 1002 (protocol error), payload never processed")
    verdict = OK if echoed and mitigated else FAIL
    print(f"VERDICT : {verdict}")
    return 0 if verdict == OK else 1


if __name__ == "__main__":
    sys.exit(main())
