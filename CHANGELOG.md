# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There are no versioned
releases yet; the workspace crates are at `0.1.0` and evolve per the
[refactor plan](REFACTOR-PLAN.md).

## [Unreleased]

### Added

- Cargo workspace: `http` and `websocket` libraries plus the `server` demo
  binary (Phase 1, ADR-0002). Dependency direction is strictly
  `websocket → http`.
- Per-crate error types: `http::Error`, `websocket::Error`,
  `server::ServerError` (ADR-0003).
- `http::body` module holding the chunked transfer-encoding reader.
- Full documentation system under `docs/` (Phase 2): architecture, development,
  testing and benchmarking docs, protocol deep-dives, RFC 9110/9112 and RFC 6455
  compliance matrices, threat model, security controls catalog, hardening and
  fuzzing guides, and ADRs 0001–0005.
- Doc-tested examples on both library crates; `cargo test --workspace` now runs
  19 tests.
- CI: fmt, clippy, tests, docs build, and a boot-and-curl smoke test of the
  server binary on every push and PR.

### Changed

- `Date` header formatting switched from `chrono` to `httpdate`; emitted format
  unchanged (ADR-0004).
- `Config::default().static_dir` resolves via `CARGO_MANIFEST_DIR`, so serving
  works regardless of the process working directory.
- Tracing `EnvFilter` default renamed `http=info` → `server=info` to match the
  binary crate name.
- Workspace lint policy: `unsafe_code` forbidden, `missing_docs` denied,
  `clippy::all` + `clippy::pedantic` denied.
- README rewritten: honest feature/compliance claims, workspace quickstart, docs
  index.

### Removed

- `REFINEMENTS.md` — its content was distributed: durable decisions → ADRs
  0001–0005, flow diagrams → `docs/protocols/`, change history → this changelog,
  migration notes → the entry below.
- Unused `bytes` dependency from the `http` crate; `chrono` from the tree.

## [Refinements] — 2025-10-11

The pre-workspace hardening round (commit `87e9be1`), migrated from
`REFINEMENTS.md`. File paths refer to the old single-crate layout.

### Added

- HTTP keep-alive: `handle_connection` loops per connection;
  `Connection:
  close` honored; responses advertise `Connection: keep-alive`
  and `Keep-Alive: timeout=5, max=100`.
- Standard response headers auto-added by `HttpResponse::to_bytes`: `Date`,
  `Server: http-rs/0.1.0`, status-dependent `Connection`.
- WebSocket server-initiated PING every 30 s; connection closed with code 1002
  when the client misses a PONG.
- Close frames with optional code/reason: `Close(Option<(u16, String)>)`.
- Structured logging with `tracing` + `tracing-subscriber`, filtered via
  `RUST_LOG`; all `println!`/`eprintln!` replaced.

### Changed

- **(Breaking)** `handle_connection(socket)` →
  `handle_connection(socket, config: &Config)`.
- **(Breaking)** `HttpRequest::from_buffer` became async
  (`from_buffer(buffer, socket)`); `from_buffer_sync(buffer)` added for
  header-only parsing in tests.
- **(Breaking)** `WebSocketFrame::parse` now returns
  `Result<(Self, usize), ParseError>` (was `Option<Self>`), tracking consumed
  bytes for buffer advancement.
- **(Breaking)** `WebSocketFrame::Close` variant gained `Option<(u16, String)>`.
- Header reading is now streaming (`BytesMut` until `\r\n\r\n`) instead of a
  fixed 1 KiB buffer, with a 16 KiB header cap.
- Request bodies read per `Content-Length` (10 MiB cap) or chunked
  transfer-encoding; WebSocket frames buffer across partial reads.
- Control frames enforce the 125-byte payload cap; client frames must be masked;
  close codes validated.
- `Config` is now `Clone`.

### Security

- Header-bomb protection (16 KiB cap), body-size limit (10 MiB), WebSocket
  masking/frame validation, path-traversal protection retained.

[Unreleased]: #
[Refinements]: #
