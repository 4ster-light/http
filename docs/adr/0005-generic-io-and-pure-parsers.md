# 0005 - Generic IO, pure parsers, single-owner buffers

- **Status:** Accepted (implementation scheduled for the security phase,
  Phase 3)
- **Date:** 2026-07-31 (plan decisions D2/D3; root fix for finding F1)

## Context

Today the connection drivers read directly from `tokio::net::TcpStream`, and
every read site owns a throwaway buffer. Concretely: `handle_connection`
accumulates bytes until the header terminator, parses the head, and then
discards any bytes already read past that point; body reads go straight to the
socket. This is finding **F1 (P0)**: same-segment POST bodies stall and HTTP
pipelining is broken. It also makes the parsers untestable without real
sockets and unfuzzable, which blocks the security phase's test taxonomy and
fuzz harnesses (see [../security/fuzzing.md](../security/fuzzing.md)).

Alternatives considered: patching the discard at the current call site (the
structural problem stays, and every future read site is free to reintroduce
it), or redesigning IO ownership once.

## Decision

- **Parsers are pure functions over byte slices** (`&[u8]`), returning either a
  value plus bytes consumed or "incomplete". No sockets, no async, no runtime
  in the parsing layer.
- **One connection owns one buffer** (`bytes::BytesMut`) with consumed-byte
  tracking; all reads append to it and all parsing consumes from it. Nothing
  is ever silently dropped.
- **Connection drivers are generic over `AsyncRead + AsyncWrite`**, so tests
  drive them with `tokio::io::duplex` and the real server uses `TcpStream`.
- A typed **Limits** struct (header cap, body cap, frame cap, timeouts,
  keep-alive policy) rides along and becomes the single home for the Phase-3
  security controls.

## Consequences

- F1 is fixed by construction: buffered bytes feed the body and any pipelined
  next request.
- Deterministic tests: duplex IO plus `tokio::time::pause` give exact control
  of bytes and time (required by SEC-HTTP-002 and SEC-WS-008).
- Fuzz harnesses call the pure parsers directly.
- This is the largest structural change in Phase 3 and gates most of the
  security test catalog. It is decided now so Phase 3 is execution, not
  design.
