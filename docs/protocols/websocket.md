# WebSocket protocol notes

Deep-dive into the `websocket` crate. For the requirement-by-requirement
status see
[../rfc-compliance/websocket-rfc6455.md](../rfc-compliance/websocket-rfc6455.md).

## Handshake

`handshake::validate_upgrade` implements the RFC 6455 §4.2.1 checks and
returns one of three outcomes (SEC-WS-007, F11 fixed):

- `NotUpgrade`: no `Upgrade: websocket` header; the request is plain HTTP.
- `Valid(&key)`: method is GET, version is HTTP/1.1+, `Upgrade: websocket`
  and `Connection: Upgrade` are present, `Sec-WebSocket-Version` is 13, and
  the `Sec-WebSocket-Key` decodes as base64 of exactly 16 bytes.
- `Invalid(reason)`: an upgrade was attempted but failed validation. The
  server answers `400` with the reason.

`handshake::generate_accept` answers a valid upgrade with `101 Switching
Protocols` and `Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-…85B11"))`
(§4.2.2), verified against the RFC test vector in unit tests and end-to-end.

## Frame codec (`frame`)

The codec works on raw frames: `Frame { fin, opcode, payload }`.

`Frame::parse(&[u8], &Limits) -> Result<(Frame, consumed), ParseError>`:

- Expects **client-to-server** traffic: unmasked input is rejected
  (`UnmaskedClientFrame`, §5.3) and answered with close 1002 (SEC-WS-001).
- `to_bytes()` serializes server-to-client frames: unmasked, FIN set.
- 7/16/64-bit payload lengths supported; a 64-bit length with the MSB set is
  rejected (§5.2).
- RSV bits must be 0 (no extension is negotiated); reserved opcodes are
  rejected rather than silently mapped (SEC-WS-003, F6 fixed).
- Control frames over 125 bytes (`ControlFrameTooLarge`) and fragmented
  control frames are rejected (§5.5, SEC-WS-003/004).
- A data frame announcing more than `Limits::max_frame_payload` (1 MiB
  default) is rejected with `FrameTooLarge` on the announced length, before
  any payload is buffered (SEC-WS-002, F5 fixed).

## Connection lifecycle (`connection::handle_websocket`)

```txt
BytesMut buffer (persistent across reads; parsed before blocking on IO)
    ↓
Read → parse one frame
    ├─> Control frame → handle immediately (works mid-message)
    │     ├─ Close → reply close, stop
    │     ├─ Ping  → pong with same payload
    │     └─ Pong  → clear liveness flag
    ├─> Data frame (FIN=1) → validate + deliver
    ├─> Data frame (FIN=0) → start/continue reassembly
    │     └─ Continuation → append; on FIN validate + deliver
    └─> Violation → close frame with the mapped code (1002/1007/1009)
```

- Text is echoed back prefixed with `Echo:`; binary is echoed as-is. Text is
  UTF-8 validated on the whole reassembled message (§5.6, SEC-WS-005): a
  failure sends close 1007.
- Reassembly rules per §5.4 (SEC-WS-009, F4 fixed): a continuation without an
  open message and a new data frame while a message is open both fail with
  close 1002; the reassembled size is capped by
  `Limits::max_message_bytes` (close 1009).
- Every protocol failure produces a close frame with the mapped code (1002
  protocol error, 1007 invalid UTF-8, 1009 too big) before the connection
  ends, never a silent drop (F8 fixed).
- **Liveness:** the first ping goes out one full interval (30 s) after the
  handshake, not immediately (F10 fixed); a missed pong by the next tick
  sends close 1002 ("Ping timeout") (SEC-WS-008). The behavior is pinned by
  a paused-time test.
- The loop is generic over `AsyncRead + AsyncWrite`, so tests drive it with
  `tokio::io::duplex` and paused clocks without real sockets.
