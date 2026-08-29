# 0003 - Error type per crate, no shared error crate

- **Status:** Accepted
- **Date:** 2026-07-31 (implemented in Phase 1; plan decision D5)

## Context

The pre-workspace code had one `Error` enum mixing HTTP, WebSocket, IO and
application variants. After the split, that single type would either live in
`http` (making `http` know about WebSocket, a dependency inversion) or in a
fourth "common" crate (explicitly forbidden by D1). A shared error crate also
couples every crate's evolution to the others.

## Decision

One error type per crate, derived with `thiserror`:

- `http::Error`: `Io(#[from] std::io::Error)`,
  `InvalidHttpRequest(&'static str)`.
- `websocket::Error`: `Io`, `Http(#[from] http::Error)`, handshake/frame
  variants. It may wrap `http::Error` because depending on `http` is its
  allowed direction. Frame decoding keeps a separate fine-grained
  `frame::ParseError` which the connection layer maps into `websocket::Error`.
- `server::ServerError`: aggregates `Http(#[from])`, `WebSocket(#[from])`,
  `Io`, and application variants (`FileNotFound`, `PortUnavailable`).

## Consequences

- No dependency cycles: errors flow in the same direction as the crate graph.
- Error provenance is obvious from the type; matching on application errors in
  `server` is exhaustive.
- There is a small boilerplate cost at boundaries
  (`map_err(ServerError::from)`), paid consciously.
- Turning parse errors into protocol-level responses (`400`/`431`/close codes)
  is a Phase-3 refinement layered on top of these types, not a change to them.
