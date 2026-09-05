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
  fuzzing guides, and ADRs 0001–0008.
- Doc-tested examples on both library crates.
- CI: fmt, clippy, tests, docs build, a boot-and-curl smoke test of the server
  binary (including the POST-echo F1 regression probe), and 60-second fuzz
  smoke runs with crash-artifact archiving on every push and PR.
- Security hardening (Phase 3, G3):
  - Typed `Limits` per protocol crate (ADR-0006): head 16 KiB → `431`, body
    10 MiB → `413`, head read timeout 10 s, keep-alive idle 5 s / max 100
    requests, WS frame cap 1 MiB → close 1009, WS message cap, ping interval.
  - Generic-IO connection layers with one persistent buffer per connection
    (ADR-0005): same-segment POST bodies and pipelined requests work; F1 (P0)
    closed.
  - CL/TE conflict rejection (SEC-HTTP-003, F4), HTTP/1.0 close-by-default
    semantics (F7), comma-merged duplicate headers with fail-closed
    `Content-Length`.
  - Proper protocol-level error responses: 400/431/413 for HTTP (F8), close
    1002/1007/1009 for WebSocket, instead of silent drops.
  - Strict WebSocket frame validation: RSV bits, reserved opcodes, 64-bit
    length MSB, fragmented control frames, control-frame size (F5/F6 closed).
  - Full handshake validation: GET, HTTP/1.1+, base64-of-16-bytes key, with
    400 on failure (F11 closed, SEC-WS-007).
  - Complete RFC 6455 §5.4 fragmentation and reassembly with interleaved
    control-frame handling (SEC-WS-009): the last RFC 6455 compliance gap is
    closed.
  - Keep-alive enforcement matching the advertised header (F3 closed,
    ADR-0007) and read timeouts (Slow-Loris mitigation, F2 closed).
  - Path-traversal hardening: percent-decode, canonicalize, prefix check,
    canonical-path read (F10 closed).
  - Security test catalog: 43 SEC-\*-named tests with control IDs and RFC
    references, plus 14 end-to-end tests against the real binary over TCP.
  - Fuzz harnesses `request_head_parse` and `frame_parse` with seed corpora
    and protocol dictionaries under `fuzz/`.
  - ADRs 0006–0008; compliance matrices updated to the post-hardening state
    with per-row test links.
- Reproducible demos and benchmarks (Phase 4, G4, ADR-0009):
  - `container/Containerfile`: multi-stage build with digest-pinned
    `rust:1-bookworm` and `debian:bookworm-slim`, `--locked` release build,
    non-root runtime user, binary + static files only, with `tini` as PID 1
    so containers stop instantly on SIGTERM (the server itself has no signal
    handler; graceful shutdown stays future work).
  - `container/compose.yaml` with profiles: `server` (always on), `bench`
    (wrk HTTP benchmark, `ws_bench` WebSocket benchmark), and `attack`
    (`demo_slowloris`, `demo_header_bomb`, `demo_unmasked_frames` — stdlib
    Python scripts that print EXPECTED vs OBSERVED and exit non-zero when a
    mitigation does not hold).
  - `examples` workspace member with `ws_echo_client` (interactive client that
    verifies the §4.2.2 accept digest) and `ws_bench` (echo and handshake
    benchmarks with latency percentiles), plus a documented minimal client-side
    frame codec (masked send, reject masked server frames).
  - `justfile`: `test`, `lint`, `docs`, `fuzz`, `image`, `up`/`down`, `bench`,
    `bench-http`, `bench-ws`, `demo`, `demo-container`. The bench and demo
    recipes share `container/scripts/ensure-server`, which probes the target
    address and starts the containerized server when needed, so one-command
    runs work from a clean machine.
  - `docs/benchmarking.md` results: keep-alive ON ~23.7k vs OFF ~4.8k req/s
    (≈5× connection-reuse payoff), ~0.46 ms p50 at light concurrency, ~66k WS
    echo messages/s, ~5.6k handshakes/s — with environment disclosure and
    one-command repro steps.
  - ADR-0009 (containerized demos and benchmarks).
  - `websocket::handshake::accept_key` is public, so client implementations can
    verify `Sec-WebSocket-Accept` (RFC 6455 §4.2.2); server behavior unchanged.

### Changed

- `Date` header formatting switched from `chrono` to `httpdate`; emitted format
  unchanged (ADR-0004).
- `Config::default().static_dir` resolves via `CARGO_MANIFEST_DIR`, so serving
  works regardless of the process working directory; `STATIC_DIR` now overrides
  it for containers and deployments (ADR-0009).
- Tracing `EnvFilter` default renamed `http=info` → `server=info` to match the
  binary crate name.
- Workspace lint policy: `unsafe_code` forbidden, `missing_docs` denied,
  `clippy::all` + `clippy::pedantic` denied.
- README rewritten: honest feature/compliance claims, workspace quickstart, docs
  index.
- **(Breaking, Phase 3)** `HttpRequest::from_buffer`/`from_buffer_sync`
  replaced by the pure `HttpRequest::parse(buffer, &Limits)` returning
  `Ok(Some((request, consumed)))` or `Ok(None)`.
- **(Breaking, Phase 3)** The WebSocket codec is frame-level:
  `websocket::frame::Frame { fin, opcode, payload }` with
  `Frame::parse(data, &Limits)`; message semantics (echo, reassembly, close
  codes) live in the connection layer. `WebSocketFrame` is gone.
- **(Breaking, Phase 3)** `websocket::handshake::is_websocket_request` replaced
  by `validate_upgrade` returning `UpgradeCheck::{NotUpgrade, Valid, Invalid}`.
- **(Breaking, Phase 3)** `websocket::handle_websocket` is generic over
  `AsyncRead + AsyncWrite` and takes the key plus `&Limits`.
- **(Breaking, Phase 3)** `Config` gains an explicit `address` (default
  `127.0.0.1:8000`, overridable via `SERVER_ADDR`); the port-scan fallback is
  removed (ADR-0008).
- The WebSocket ping ticker no longer fires immediately after the handshake;
  the first ping goes out one full interval later (F10).

### Removed

- `REFINEMENTS.md` — its content was distributed: durable decisions → ADRs
  0001–0005, flow diagrams → `docs/protocols/`, change history → this changelog,
  migration notes → the entry below.
- Unused `bytes` dependency from the `http` crate; `chrono` from the tree.
- (Phase 3) The port-scan fallback in `Config::default()` and the
  `ServerError::PortUnavailable` variant.

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
