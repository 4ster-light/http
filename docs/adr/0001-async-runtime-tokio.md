# 0001 — Async runtime: tokio

- **Status:** Accepted (retroactive)
- **Date:** 2026-07-31 (written retroactively; the decision predates the
  workspace era)

## Context

The project implements network protocols from scratch for learning purposes, and
must handle many concurrent connections without one OS thread per connection. At
project inception the realistic choices were: `std` threads + blocking IO
(simplest, scales poorly, teaches less about modern Rust), `async-std` (smaller
ecosystem), `smol` (minimal), or `tokio` (the de-facto standard, richest
ecosystem: timers, `select!`, `BytesMut` via `bytes`).

## Decision

Use **tokio**, with one task per accepted connection. As of the workspace split,
each crate declares only the tokio features it actually needs (`net`, `io-util`,
`time`, `fs`, `rt-multi-thread`, `macros`) instead of `features = ["full"]`.

## Consequences

- The concurrency model (task per connection, `tokio::select!` for the WS ping
  ticker) and the liveness ping/pong design build directly on tokio primitives.
- `bytes::BytesMut` is the natural buffering companion (see ADR-0005).
- Runtime coupling is accepted at the _connection driver_ level; ADR-0005 keeps
  the _parsers_ runtime-free so they stay testable without a reactor.
- Tests can use `tokio::io::duplex` and `tokio::time::pause` for deterministic
  IO and time control (used by SEC-WS-008 tests in Phase 3).
