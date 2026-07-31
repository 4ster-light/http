# Refactor & Hardening Plan (Temporary Working Document)

> **Status:** Final — ratified 2026-07-30. All open questions resolved (§8).
> This file is a _temporary_ planning artifact. Once the phases below land, its
> durable content will live in `docs/` (architecture, ADRs, compliance matrices)
> and `CHANGELOG.md`, and this file should be deleted.
>
> **Scope:** Workspace split, documentation system, security-focused testing,
> reproducible containerized demos/benchmarks. No new protocol features (HTTP/2,
> TLS, compression) except where noted as future work.

---

## 1. Background & Goals

This repo is a from-scratch HTTP/1.1 + WebSocket implementation in Rust for
learning and portfolio purposes, with a networking + cybersecurity angle. Four
goals drive this refactor:

1. **G1 — Workspace architecture:** ✅ **COMPLETE (2026-07-31, see §7 Phase 1
   status).** Split the single crate into a Cargo workspace: `http` and
   `websocket` library crates (room for future crates like `tls`), plus a demo
   `server` binary crate.
2. **G2 — Documentation system:** Replace the changelog-style `REFINEMENTS.md`
   with a `docs/` tree a human wants to read: architecture docs, Architecture
   Decision Records (ADRs), RFC compliance matrices, and security docs.
3. **G3 — Security as a documented strength:** A security test catalog where
   every test cites the attack/RFC section it covers, cross-referenced from the
   threat model. Fuzzing for the parsers.
4. **G4 — Reproducible demonstrations:** Podman containers + compose so anyone
   can reproduce benchmarks and attack-mitigation demos with one command.

### Compliance target

The end state is **100% compliance within a declared scope**, verified by the
matrices (§4.2):

- **RFC 6455 (WebSocket):** every MUST/SHOULD ✅ — including message
  fragmentation/reassembly (§5.4), the last current gap.
- **RFC 7230–7235 (HTTP/1.1):** every in-scope MUST/SHOULD ✅. Areas the server
  does not claim (caching RFC 7234, conditional requests RFC 7232, range
  requests RFC 7233, auth RFC 7235, proxy/absolute-form) are marked **"out of
  scope" with a written rationale** in the matrix — never silently missing. A
  declared ❌-free, scope-explicit matrix is the deliverable.

### Non-goals

- HTTP/2, TLS, WebSocket extensions (permessage-deflate), compression. Recorded
  as future ADRs, not implemented here.
- crates.io publication (names `http`/`websocket` are kept as-is; revisit only
  if publication ever becomes a goal).
- A general-purpose web framework (routing/middleware beyond the demo).

---

## 2. Current State Audit

Verified by code review and live testing on 2026-07-30. ~1,460 LOC, 17 tests (6
unit + 11 integration), zero clippy warnings, edition 2024.

### 2.1 Verified findings (this is why Phase 3 exists)

Severity: **P0** correctness bug, **P1** security-relevant, **P2**
compliance/robustness, **P3** hygiene.

| ID  | Sev    | Finding                                                                                                                                                                                                                                                                                                                                                                                                  | Evidence                                                                                                                  |
| --- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| F1  | **P0** | **POST/PUT bodies deadlock.** `handle_connection` reads until `\r\n\r\n`, then discards every byte past the header terminator; the body is then read from the socket with `read_exact`. When headers+body arrive in one segment (normal for curl), the buffered body bytes are dropped and the server blocks forever. Same flaw breaks HTTP pipelining (leftover bytes of the next request are dropped). | Reproduced: `curl -X POST -d "Hello" http://127.0.0.1:8000/api/test` hangs until client timeout; server logs `early eof`. |
| F2  | **P1** | **No read timeouts anywhere** → trivial Slow Loris: trickle one byte/second, hold every connection/task forever.                                                                                                                                                                                                                                                                                         | F1 repro also proves this (server waited indefinitely).                                                                   |
| F3  | **P1** | **Advertised keep-alive limits are not enforced.** Responses claim `Keep-Alive: timeout=5, max=100` but there is no idle timeout and no request counter. Either enforce or stop advertising (enforcing is the point of this project).                                                                                                                                                                    | `protocol/response.rs` vs `protocol/mod.rs`.                                                                              |
| F4  | **P1** | **CL/TE request-smuggling vector.** When both `Content-Length` and `Transfer-Encoding` are present, RFC 7230 §3.3.3 requires TE to take precedence and recommends rejecting the message; the parser checks `Content-Length` first.                                                                                                                                                                       | `protocol/request.rs` body-parsing branch order.                                                                          |
| F5  | **P1** | **Unbounded WebSocket data-frame size.** A frame announcing a huge 64-bit payload returns `Incomplete` and the connection buffers data forever → memory exhaustion. Only control frames have a size cap (125 B).                                                                                                                                                                                         | `websocket/frame.rs::parse`.                                                                                              |
| F6  | **P2** | **WebSocket protocol validation gaps:** RSV1–3 bits ignored (must fail with 1002 when no extension negotiated); unknown opcodes silently map to `Close` instead of failing; FIN ignored on control frames (fragmented control frames must be rejected); `Continuation` returns `Incomplete` → infinite read loop on any fragmented message.                                                              | `websocket/frame.rs` (`let _fin = …`, `OpCode::from` catch-all, `Continuation => Err(Incomplete)`).                       |
| F7  | **P2** | **HTTP/1.0 semantics ignored.** Version is parsed as a string and never used; HTTP/1.0 requests get 1.1 keep-alive defaults (1.0 must default to close).                                                                                                                                                                                                                                                 | `protocol/mod.rs`, `request.rs`.                                                                                          |
| F8  | **P2** | **Errors close the socket without a response.** Header bomb (16 KB), bad request line, oversized body → connection dies silently. Should send `431`, `400`, `413` respectively per RFC 7231.                                                                                                                                                                                                             | `protocol/mod.rs` error paths.                                                                                            |
| F9  | **P3** | `find_header_end` rescans the whole buffer after every 1 KiB read (O(n·m) with trickled bytes); track a scan offset.                                                                                                                                                                                                                                                                                     | `protocol/mod.rs`.                                                                                                        |
| F10 | **P3** | Headers/request line parsed via `String::from_utf8_lossy` (silent mangling); duplicate header names collapse in the `HashMap`; static-file handler reads the non-canonical path after validating the canonical one (minor TOCTOU); ping interval's first tick fires immediately.                                                                                                                         | `request.rs`, `handler.rs`, `websocket/mod.rs`.                                                                           |
| F11 | **P3** | `Sec-WebSocket-Key` not validated as base64 of 16 bytes (RFC 6455 §4.2.1); handshake does not check method is GET or version ≥ 1.1.                                                                                                                                                                                                                                                                      | `websocket/handshake.rs`.                                                                                                 |

These findings are _good news_ for the portfolio: each becomes a documented
control + regression test (Phase 3) and an entry in the compliance matrices
(Phase 2).

### 2.2 What is already solid (keep / carry over)

- Clear module separation (protocol vs websocket vs config/error).
- Frame buffering with consumed-byte tracking; masking enforcement; close-code
  validation; server PING/PONG liveness.
- Header-bomb cap (16 KB), body cap (10 MB), path-traversal protection.
- Structured logging with `tracing`; builder API for responses.

---

## 3. Target Architecture (G1)

### 3.1 Workspace layout

```txt
├── Cargo.toml                  # workspace root: members, workspace deps, lints
├── crates/
│   ├── http/                   # HTTP/1.1 protocol library
│   │   ├── src/
│   │   │   ├── lib.rs          # public API, crate-level docs
│   │   │   ├── error.rs        # http::Error (thiserror)
│   │   │   ├── request.rs      # request-line + header parsing (pure, sync)
│   │   │   ├── response.rs     # response builder
│   │   │   ├── body.rs         # Content-Length / chunked readers
│   │   │   ├── limits.rs       # Limits struct (security controls, §5)
│   │   │   └── connection.rs   # keep-alive loop over generic IO
│   │   └── tests/              # protocol + security integration tests
│   ├── websocket/              # WebSocket protocol library (depends on http)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── error.rs        # websocket::Error, #[from] http::Error
│   │   │   ├── frame.rs        # frame codec (pure, sync)
│   │   │   ├── handshake.rs    # upgrade validation + accept key
│   │   │   └── connection.rs   # WS lifecycle, ping/pong, over generic IO
│   │   └── tests/
│   └── server/                 # demo application (binary)
│       ├── src/main.rs         # config, accept loop, handlers, static files
│       ├── static/index.html
│       └── tests/              # end-to-end tests against a live server
├── docs/                       # §4
├── fuzz/                       # cargo-fuzz targets (excluded from default-members)
├── container/
│   ├── Containerfile
│   ├── compose.yaml
│   └── demos/                  # attack/benchmark scripts
├── examples/                   # runnable client examples (ws echo client, bench)
├── CHANGELOG.md                # Keep a Changelog (absorbs REFINEMENTS.md)
├── justfile                    # task runner (build, test, fuzz, bench, demo)
└── REFACTOR-PLAN.md            # this file (temporary)
```

### 3.2 Design decisions (each becomes an ADR)

- **D1 — Dependency direction:** `websocket → http` (the handshake is an HTTP
  upgrade; `websocket::handshake` consumes `http::Request`).
  `server →
  {http, websocket}`. No cycles. No shared "common" crate until a
  third consumer exists (YAGNI).
- **D2 — Pure parsers + generic IO:** Parsing/serialization is synchronous and
  socket-free (`parse(&[u8])`, `to_bytes()`), operating on caller-managed
  buffers. Connection drivers are generic over
  `tokio::io::AsyncRead + AsyncWrite` instead of concrete `TcpStream`.
  Rationale: testability — the entire state machine can be driven
  deterministically with `tokio::io::duplex` in tests, no real sockets, no
  sleeps. This is the single highest-leverage refactor for G3.
- **D3 — Fix F1 structurally, not locally:** the connection layer owns one
  persistent `BytesMut` read buffer for the whole connection lifetime; parse
  consumes exactly the request's bytes; leftovers stay buffered for pipelined
  requests and body reads consume from the buffer first, socket second.
- **D4 — Typed `Limits` config:** all security knobs in one struct with
  documented defaults (§5), passed explicitly. Replaces magic constants
  (`16384`, `10MB`, `30s`) scattered in code.
- **D5 — Per-crate error types:** `http::Error`, `websocket::Error` (with
  `#[from] http::Error`), `server` maps them into responses/logging. The current
  single `ServerError` mixes protocol and application concerns.
- **D6 — Keep tokio, `tracing`, `thiserror`, `bytes`, `sha1`, `base64`; replace
  `chrono` with the tiny `httpdate` crate** (single-purpose, ~200 LOC, smaller
  supply chain — it only exists to format the `Date` header).
- **D7 — Handlers/routing live in `server`, not in `http`.** The protocol crates
  expose protocol primitives; static-file serving, the echo endpoint and CORS
  are application concerns. Keeps the libraries reusable and the threat model of
  each crate honest.
- **D8 — Explicit bind configuration.** `Config` takes an explicit address
  (default `127.0.0.1:8080`) and the server **fails fast if the port is taken**.
  The current silent port-scanning fallback is removed: convenience for dev, but
  surprising behavior and a race condition — explicitness is the correct
  security posture for a server.

### 3.3 Mechanical migration notes (Phase 1)

- Use `git mv` to preserve history: `src/protocol/* → crates/http/src/*`,
  `src/websocket/* → crates/websocket/src/*`,
  `src/main.rs + config.rs +
  handler.rs + static/ → crates/server/`.
- Workspace `Cargo.toml`: `[workspace] members = ["crates/*"]`,
  `workspace.dependencies` for shared versions, `[workspace.lints]` with clippy
  `pedantic`-ish allowlist + `#![warn(missing_docs)]` per lib crate.
- No behavior changes in Phase 1 except import-path rewiring; the existing 17
  tests must pass unmodified (they move with the code).

---

## 4. Documentation System (G2)

### 4.1 `docs/` tree

```txt
docs/
├── README.md                   # docs index / reading guide
├── architecture/
│   ├── overview.md             # crate graph, connection lifecycle, data flow
│   ├── http.md                 # request pipeline, keep-alive, chunked TE, limits
│   └── websocket.md            # frame codec, handshake, liveness, close semantics
├── adrs/
│   ├── 0000-template.md        # Nygard format: Status/Context/Decision/Consequences
│   ├── 0001-async-runtime-tokio.md          (retroactive)
│   ├── 0002-workspace-split.md              (this refactor)
│   ├── 0003-generic-io-and-pure-parsers.md  (D2/D3)
│   ├── 0004-security-limits-and-timeouts.md (Phase 3)
│   ├── 0005-error-type-per-crate.md         (D5)
│   ├── 0006-keep-alive-policy.md            (F3 resolution)
│   └── 0007-explicit-bind-port.md           (D8)
├── rfc-compliance/
│   ├── http-1.1.md             # RFC 7230–7235 requirement matrix
│   └── websocket-rfc6455.md    # RFC 6455 requirement matrix
├── security/
│   ├── threat-model.md         # assets, trust boundaries, attacker capabilities
│   ├── controls.md             # control catalog: SEC-HTTP-001… / SEC-WS-001…
│   └── fuzzing.md              # harnesses, corpus, how to run
└── benchmarking.md             # methodology, environment, results, repro steps
```

### 4.2 Rules that make this better than one big markdown file

- **ADRs are immutable:** once accepted, changes happen via a new ADR that
  supersedes the old one. Numbered, one decision each, ~1 page max. Retroactive
  ADRs (0001) extract the durable "why" currently buried in `REFINEMENTS.md`.
- **Compliance matrices are tables, not prose:** one row per RFC requirement:
  `Section | Requirement (MUST/SHOULD/MAY) | Status ✅/⚠️/❌ |
  Implementation (file:fn) | Test (test name)`.
  Status ❌ is allowed and honest — this is a learning project; the matrix _is_
  the roadmap.
- **Controls catalog mirrors the tests:** every security control has an ID
  (`SEC-HTTP-003`), a threat reference (threat-model.md), an implementation
  pointer, and a test pointer. Tests carry the same ID in a doc comment (§5.3).
- **`CHANGELOG.md`** (Keep a Changelog format) absorbs the "what changed" role
  of REFINEMENTS.md. **REFINEMENTS.md is deleted** after its content is
  distributed: decisions → ADRs, compliance claims → matrices, migration notes →
  CHANGELOG `### Changed` entries.
- **README.md rewrite:** remove the "Recently Enhanced" banner and changelog
  noise; crisp pitch, feature matrix (linking to the full matrices), quickstart
  (native + Podman), architecture diagram, docs index, test/fuzz/bench commands.
  One screen of substance.
- **rustdoc:** `#![warn(missing_docs)]` on both lib crates; every public item
  documented with RFC section references where applicable; `cargo doc` build
  enforced in CI.

---

## 5. Security Testing Strategy (G3)

### 5.1 Test taxonomy

| Layer                        | Where                          | Tools                                                   | Purpose                                                             |
| ---------------------------- | ------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------- |
| Unit                         | `src/**` `#[cfg(test)]`        | std test                                                | codec round-trips, close-code tables                                |
| Protocol conformance         | `crates/*/tests/`              | std test + `tokio::io::duplex`                          | RFC-derived cases, one per requirement                              |
| Security / attack simulation | `crates/*/tests/security_*.rs` | duplex + manual byte crafting                           | prove mitigations hold                                              |
| End-to-end                   | `crates/server/tests/`         | real server on ephemeral port + raw `TcpStream` clients | keep-alive, pipelining, static files, upgrade flow                  |
| Fuzz                         | `fuzz/`                        | `cargo-fuzz` (libFuzzer)                                | parser robustness: `http::parse_request`, `websocket::Frame::parse` |
| Adversarial demos            | `container/demos/`             | python/rust scripts in containers                       | human-visible attacks vs. hardened server                           |

### 5.2 Security controls to implement-then-test (from §2.1)

Each gets a `Limits` field, a control ID, tests, and a threat-model entry:

- `SEC-HTTP-001` Header-size cap → `431` response + close (fixes F8 too).
- `SEC-HTTP-002` Header read timeout (default 10 s) + per-read idle timeout →
  Slow-Loris mitigation (F2).
- `SEC-HTTP-003` Reject `Content-Length` + `Transfer-Encoding` together; TE
  precedence per RFC 7230 §3.3.3 (F4).
- `SEC-HTTP-004` Body-size cap → `413` (exists, now typed in `Limits` + response
  code fixed).
- `SEC-HTTP-005` Keep-alive: enforce idle timeout + max requests/connection,
  matching advertised `Keep-Alive` header (F3).
- `SEC-HTTP-006` Path traversal: canonicalize + prefix check (exists), plus
  regression tests for `..`, encoded variants, absolute paths, symlink escape;
  read via the canonical path (F10).
- `SEC-HTTP-007` Correct buffer ownership: no discarded bytes; pipelining
  regression test (F1 — the P0).
- `SEC-WS-001` Masking enforcement (exists) + test for unmasked → close 1002.
- `SEC-WS-002` Max data-frame payload (default e.g. 1 MiB, configurable) → close
  1009 (F5).
- `SEC-WS-003` RSV bits / unknown opcode / fragmented control frame → close 1002
  (F6).
- `SEC-WS-004` Control frame ≤125 B (exists) + tests at 125/126 boundary.
- `SEC-WS-005` Invalid UTF-8 in text frames → close 1007 (partially exists:
  currently a parse error; must become a proper close frame).
- `SEC-WS-006` Close-code validation (exists) + invalid code → 1002 test.
- `SEC-WS-007` Handshake validation: GET only, HTTP/1.1+, key is base64(16B)
  (F11).
- `SEC-WS-008` Ping/pong liveness timeout (exists) + deterministic test via
  duplex + paused time (`tokio::time::pause`).
- `SEC-WS-009` Fragmentation (RFC 6455 §5.4): continuation-frame reassembly for
  text/binary messages, control frames interleaved mid-message handled
  immediately, fragmented control frames rejected with 1002, continuation
  without an open message rejected.

### 5.3 Tests as documentation

- Naming: `sec_http_003_rejects_cl_te_conflict`,
  `rfc6455_s5_2_rejects_unmasked_frame`. IDs greppable from docs.
- Every security test carries a doc comment: control ID, RFC section, attack it
  simulates, expected server behavior. `docs/security/controls.md` links each
  control to its tests and vice versa.
- Fuzzing: two targets (`request_head_parse`, `frame_parse`), dictionary of
  HTTP/WS tokens, documented in `docs/security/fuzzing.md`. Runs on a pinned
  nightly toolchain (`cargo +nightly fuzz`); CI executes a 60 s smoke run per
  target on every PR and archives any crash artifacts.

---

## 6. Containers, Benchmarks & Demos (G4)

### 6.1 Artifacts

- **`container/Containerfile`** — multi-stage: pinned `rust:1-bookworm` builder
  → pinned `debian:bookworm-slim` runtime, non-root user, `EXPOSE
  8080`,
  binary only (+ static files). Reproducibility: base images pinned by digest,
  `Cargo.lock` committed (already true), `--locked` builds.
- **`container/compose.yaml`** (podman-compose / `podman compose`) with
  profiles:
  - `server` (always): the demo server.
  - profile `bench`: `bench-http` (wrk image: keep-alive on/off, N connections,
    fixed duration) and `bench-ws` (custom Rust bench binary from `examples/` —
    measures msg/s, latency percentiles, handshake rate).
  - profile `attack`: `demo-slowloris`, `demo-header-bomb`,
    `demo-unmasked-frames` — small Python scripts that attack `server` and print
    observed vs. expected mitigation. These are the cybersecurity showcase:
    adversary and defender in one compose file.
- **`examples/`** — `ws_echo_client.rs`, `ws_bench.rs` (also used by the bench
  container), `http_bench_notes.md` pointing to wrk. Examples double as
  documentation and as bench tooling (no heavy external WS tooling needed).
- **`justfile`** — `just test`, `just fuzz 60`, `just image`, `just bench`,
  `just demo slowloris`, `just docs` (cargo doc + open).
- **`docs/benchmarking.md`** — methodology (tool versions, flags, container
  limits, hardware notes), results table with dates, and exact repro commands.
  Results are stated as _indicative_, with environment recorded — honest
  benchmarking is itself a portfolio signal.

### 6.2 Why containers specifically

- One-command reproduction for reviewers (`podman compose up`), no local
  toolchain assumptions beyond Podman.
- Network isolation per scenario; attack demos can't escape to the host.
- Demonstrates container/supply-chain literacy alongside protocol literacy.

---

## 7. Phased Roadmap

Each phase is one PR. Phases are ordered so every PR is green and reviewable.

### Phase 0 — Safety net (≈0.5 day)

- Add a minimal e2e smoke test (spawn server on ephemeral port, GET `/`, POST
  echo — POST expected to _fail/hang-guarded_ until Phase 3, so assert current
  GET behavior only).
- GitHub Actions CI: fmt, `clippy -D warnings`, `cargo test`, `cargo doc`.
- **Exit:** CI green on `main`.

### Phase 1 — Workspace split (≈1 day)

> **Status: ✅ COMPLETE — 2026-07-31**
>
> Validated exit criteria:
>
> - `cargo build --workspace` / `cargo test --workspace` green: all 17 tests
>   (6 unit + 11 integration) pass unchanged; only import paths rewired.
> - `cargo clippy --workspace --all-targets` zero warnings; `cargo fmt --check`
>   clean; `cargo doc --workspace --no-deps` builds.
> - `cargo run -p server` verified live: static GET `/` 200 (from
>   `crates/server/static`), 404s, path-traversal rejection, keep-alive
>   across sequential requests, WebSocket upgrade (101 + RFC 6455 accept-key
>   vector), masked-frame echo, close handshake.
> - Dependency direction per D1 confirmed via `cargo tree`: `websocket → http`,
>   `server → {http, websocket}`, no cycles, no shared "common" crate.
> - History preserved via `git mv` (renames staged as `R`).
>
> Deviations/notes (all within Phase 1 scope):
>
> - `handle_connection` glue lives in `server` (per D7 it dispatches between
>   the HTTP handlers and the WS upgrade); `http::connection` arrives with the
>   Phase 3 D2/D3 generic-IO refactor, as does `limits.rs`.
> - `http::body` created with the chunked reader (moved out of `request.rs`).
> - D6/Q6 applied while rewiring the dependency graph: `chrono` → `httpdate`
>   (Date header byte-format unchanged, IMF-fixdate).
> - Per-crate error types per D5: `http::Error`, `websocket::Error`
>   (`#[from] http::Error`), `server::ServerError` aggregates both.
> - `[workspace.lints]` infrastructure in place (`unsafe_code = forbid`,
>   clippy `all = deny`); `missing_docs` + pedantic ratchet deferred to
>   Phases 2/5 as scheduled in §4.2/§7.
> - `Config::default().static_dir` now resolves via `CARGO_MANIFEST_DIR`
>   (required by the `static/` move; serving behavior unchanged, no longer
>   CWD-dependent). Tracing `EnvFilter` default renamed `http=info` →
>   `server=info` to match the new binary crate name.
> - Port-scan fallback (D8) intentionally untouched — removal lands in
>   Phase 3.2 as scheduled.

- Mechanical migration per §3.3 (`git mv`, workspace manifest, import rewiring).
  No behavior changes.
- Move existing tests with their crates; all 17 must pass unchanged.
- **Exit:** workspace builds; `cargo test --workspace` green; binary runs as
  before via `cargo run -p server`.

### Phase 2 — Documentation system (≈2–3 days)

- Create `docs/` tree per §4; write architecture docs with diagrams (keep the
  ASCII flow diagrams from REFINEMENTS — they're good).
- Retroactive ADRs 0001–0003; ADR template; forward ADRs as decisions land.
- Compliance matrices v1: audit both protocols row by row; mark F1–F11 statuses
  honestly (❌/⚠️).
- Convert REFINEMENTS.md → CHANGELOG.md entries + ADR content; delete
  REFINEMENTS.md; rewrite README.md; `missing_docs` warnings on.
- **Exit:** a stranger can navigate README → docs and answer "what does it
  implement, why is it built this way, how do I verify the claims?"

### Phase 3 — Security hardening + test catalog (≈4–5 days)

Order matters: harness first, then red tests, then fixes.

1. D2/D3 refactor: pure parsers + generic IO + connection-owned buffer (fixes
   F1, F9 structurally).
2. `Limits` struct + timeouts + keep-alive enforcement (F2, F3, F8 → proper 4xx
   responses). Config per D8: explicit bind, fail fast if the port is taken;
   remove the port-scan fallback.
3. Request hardening: CL/TE rejection, HTTP/1.0 semantics, header duplicate
   policy (F4, F7, F10).
4. WebSocket hardening: frame-size cap, RSV/opcode/FIN validation, UTF-8 → 1007,
   handshake validation (F5, F6, F11) — plus **full message fragmentation and
   reassembly per RFC 6455 §5.4** (SEC-WS-009): a reassembly state machine in
   the connection layer, continuation frames accepted only mid-message,
   interleaved control frames processed immediately, fragmented control frames
   rejected with 1002. This closes the last RFC 6455 gap; the infinite-read-loop
   failure mode (F6) disappears with it.
5. Security test catalog per §5.2–5.3; e2e suite; fuzz targets (pinned
   nightly) + CI smoke runs.
6. ADRs 0004–0007; update matrices (❌→✅ with test links); threat model v1.

- **Exit:** RFC 6455 matrix 100% ✅; HTTP matrix ✅ for every in-scope
  MUST/SHOULD with all else explicitly declared out of scope;
  `cargo test
  --workspace` green; fuzz smoke green; F1 repro from this
  document now returns 200 instantly.

### Phase 4 — Containers, benchmarks, demos (≈2–3 days)

- Containerfile + compose + profiles per §6; `ws_bench` example; attack demo
  scripts; `justfile`; `docs/benchmarking.md` with first measured results
  (keep-alive on/off comparison is the headline number — it validates the F3/F1
  work).
- **Exit:** on a clean machine: `podman compose up` serves; `just bench`
  reproduces the table within noise; each `just demo <attack>` prints the
  mitigation holding.

### Phase 5 — Polish (≈1 day)

- CI: container build job, fuzz smoke job, doc job; README badges.
- Final pass: clippy pedantic review, doc cross-links, delete this file.
- **Exit:** REFACTOR-PLAN.md deleted; repo tells its own story.

**Total estimate: ~9–13 days** of focused work.

---

## 8. Decisions Ratified (2026-07-30)

All questions resolved; no open items remain. Each decision is recorded where it
lands in the plan:

| #  | Decision                                                                                        | Where it lands                                   |
| -- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Q1 | Keep crate names `http` / `websocket`; rename only if ever publishing.                          | §1 Non-goals, §3.1                               |
| Q2 | Delete `REFINEMENTS.md` after distributing its content (CHANGELOG + ADRs + matrices).           | §4.2, Phase 2                                    |
| Q3 | Adopt generic IO (`AsyncRead + AsyncWrite`) + pure parsers — the backbone of the test strategy. | §3.2 D2, Phase 3.1                               |
| Q4 | **Implement full WebSocket fragmentation/reassembly** — target is 100% RFC 6455 compliance.     | §1 Compliance target, §5.2 SEC-WS-009, Phase 3.4 |
| Q5 | Adopt `cargo-fuzz` on pinned nightly, with 60 s CI smoke runs.                                  | §5.3, Phase 3.5                                  |
| Q6 | Replace `chrono` with `httpdate`.                                                               | §3.2 D6                                          |
| Q7 | Benchmarks: wrk (container) for HTTP + custom Rust `ws_bench` for WebSocket.                    | §6.1, Phase 4                                    |
| Q8 | CI on GitHub Actions.                                                                           | Phase 0, Phase 5                                 |
| Q9 | Explicit bind address; fail fast if the port is taken; remove port-scan fallback.               | §3.2 D8, Phase 3.2, ADR 0007                     |

## 9. Explicitly Out of Scope (future ADRs)

TLS (`rustls` vs `native-tls`), HTTP/2, permessage-deflate, response
compression, routing/middleware framework, rate limiting beyond connection
limits, graceful shutdown draining.
