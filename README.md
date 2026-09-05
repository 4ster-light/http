# HTTP & WebSockets in Rust

A from-scratch implementation of HTTP/1.1 and WebSocket (RFC 6455) protocols in
Rust, built on `tokio`. This is a learning and portfolio project with a
networking + cybersecurity angle: the goal is not just to make the protocols
work, but to understand them deeply enough to document compliance honestly and
to prove, with tests, that the server holds up under attack.

The code is organized as a Cargo workspace of small, single-purpose crates. The
security audit and hardening program in [REFACTOR-PLAN.md](REFACTOR-PLAN.md) is
complete: every finding now has a documented control with regression tests, and
the parsers are fuzzed in CI.

## Table of Contents

- [Features](#features)
  - [HTTP/1.1 (RFC 7230-7235)](#http11-rfc-7230-7235)
  - [WebSocket (RFC 6455)](#websocket-rfc-6455)
  - [Engineering practices](#engineering-practices)
- [Workspace layout](#workspace-layout)
- [Documentation](#documentation)
- [Usage](#usage)
  - [Running the server](#running-the-server)
  - [Tests, lints and docs](#tests-lints-and-docs)
  - [Containers and demos](#containers-and-demos)
  - [HTTP endpoints](#http-endpoints)
  - [WebSocket endpoint](#websocket-endpoint)
- [Trying it out](#trying-it-out)
- [Using the libraries](#using-the-libraries)
- [Dependencies](#dependencies)
- [Security](#security)
- [Roadmap](#roadmap)
- [License](#license)

## Features

### HTTP/1.1 (RFC 7230-7235)

- ✅ Request parsing for all common methods (GET, POST, PUT, DELETE, HEAD,
  OPTIONS, PATCH, TRACE, CONNECT)
- ✅ Persistent connections (keep-alive): idle timeout and request budget
  enforced to match the advertised `Keep-Alive` header
- ✅ Pipelining: a connection-owned buffer never discards bytes (F1 closed)
- ✅ Request bodies via `Content-Length` and chunked transfer-encoding
- ✅ CL/TE conflict rejection per RFC 9112 §6.3 (request-smuggling defense)
- ✅ Response builder with strongly-typed status codes (including `413`/`431`)
- ✅ Auto-generated standard headers (`Date`, `Server`, `Connection`,
  `Keep-Alive`)
- ✅ Malformed input answered with proper 4xx responses, never silent drops
- ✅ Read timeouts against Slow-Loris style attacks
- ✅ Static file serving with content-type detection, percent-decoding, and
  canonicalized traversal protection

Full requirement-by-requirement status:
[docs/rfc-compliance/http-1.1.md](docs/rfc-compliance/http-1.1.md)

### WebSocket (RFC 6455)

- ✅ Opening handshake with full §4.2.1 validation (GET, HTTP/1.1+, base64
  16-byte key) and `Sec-WebSocket-Accept` computation per §4.2
- ✅ Strict frame codec: masking (§5.3), RSV bits, opcodes, 64-bit length MSB,
  control-frame rules (§5.5)
- ✅ Message fragmentation and reassembly per §5.4, with interleaved control
  frames handled immediately
- ✅ Text and binary messages, echo behavior in the demo server
- ✅ Data-frame and message size caps (close 1009 before buffering)
- ✅ Protocol failures answered with the right close code (1002/1007/1009)
- ✅ Server-initiated ping/pong liveness checks with timeout
- ✅ Clean close handshake with status codes and reasons

Full requirement-by-requirement status:
[docs/rfc-compliance/websocket-rfc6455.md](docs/rfc-compliance/websocket-rfc6455.md)

### Engineering practices

- ✅ Cargo workspace: two protocol libraries + one demo binary (see below)
- ✅ Strong typing for methods, status codes, frames, limits and errors
  (`thiserror`)
- ✅ Per-crate error types: `http::Error`, `websocket::Error`
- ✅ Pure parsers over byte slices; connection drivers generic over
  `AsyncRead + AsyncWrite` (duplex-tested, fuzz-targeted)
- ✅ Async/await throughout, one `tokio` task per connection
- ✅ Structured logging with `tracing`
- ✅ 71 tests (13 unit + 27 integration + 43 security/conformance + 14
  end-to-end + 2 doctests), clippy-clean with `all`/`pedantic` warnings denied
  workspace-wide, `missing_docs` denied, `unsafe_code` forbidden

## Workspace layout

```txt
├── Cargo.toml              # workspace root: shared deps + lints
├── justfile                # task runner: test, lint, fuzz, image, bench, demo
├── container/              # pinned multi-stage image + compose (bench/attack profiles)
├── examples/               # client-side examples: ws_echo_client, ws_bench
├── fuzz/                   # cargo-fuzz harnesses (own workspace, nightly)
└── crates/
    ├── http/               # HTTP/1.1 protocol library
    │   ├── src/
    │   │   ├── request.rs  #   pure request parsing (head + body framing)
    │   │   ├── response.rs #   response builder
    │   │   ├── body.rs     #   chunked body decoding (pure)
    │   │   ├── connection.rs#  generic-IO request reader (persistent buffer)
    │   │   ├── limits.rs   #   typed security limits
    │   │   └── error.rs    #   http::Error with status mapping
    │   └── tests/          # protocol + security integration tests
    ├── websocket/          # WebSocket library (depends on http)
    │   ├── src/
    │   │   ├── frame.rs    #   strict frame codec (RFC 6455 §5)
    │   │   ├── handshake.rs#   upgrade validation + accept key
    │   │   ├── connection.rs#  lifecycle: echo, reassembly, ping/pong, close
    │   │   ├── limits.rs   #   typed security limits
    │   │   └── error.rs    #   websocket::Error
    │   └── tests/
    └── server/             # demo application (binary)
        ├── src/            #   config, connection dispatch, handlers
        ├── static/         #   files served by the demo
        └── tests/          # end-to-end tests over real TCP
```

Dependency direction is strictly `websocket → http` (the WebSocket handshake is
an HTTP upgrade) and `server → {http, websocket}`. No cycles, no shared "common"
crate; each protocol crate carries only what it needs, so they can be read and
reused independently.

## Documentation

The full documentation system lives in [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md): crates, concurrency and error models,
  request/connection lifecycles
- RFC compliance matrices: [HTTP/1.1](docs/rfc-compliance/http-1.1.md) and
  [WebSocket](docs/rfc-compliance/websocket-rfc6455.md), one row per RFC
  requirement, honest ❌ rows included
- Security: [threat model](docs/security/threat-model.md),
  [controls catalog](docs/security/controls.md),
  [hardening guide](docs/security/hardening.md),
  [fuzzing](docs/security/fuzzing.md)
- Protocol deep-dives: [HTTP](docs/protocols/http.md),
  [WebSocket](docs/protocols/websocket.md)
- [Testing](docs/testing.md) · [Development](docs/development.md) ·
  [Benchmarking](docs/benchmarking.md)
- [ADRs](docs/adr/0001-async-runtime-tokio.md): architecture decision records
  (tokio, workspace split, error model, httpdate, generic IO, security limits,
  keep-alive policy, explicit bind, containerized demos)

## Usage

### Running the server

```bash
cargo run -p server
```

The demo server starts on <http://127.0.0.1:8000>. The bind address is
explicit (ADR-0008): set `SERVER_ADDR` to change it, and a taken port fails
startup rather than drifting to another one.

Enable detailed logging with `RUST_LOG`:

```bash
RUST_LOG=server=debug cargo run -p server
```

### Tests, lints and docs

```bash
cargo test --workspace                    # all 71 tests (incl. doctests)
cargo test -p http                        # just one crate
cargo clippy --workspace --all-targets    # all + pedantic warnings denied
cargo doc --workspace --open              # API documentation
```

CI runs fmt, clippy, tests, a docs build, a boot-and-curl smoke test (including
the POST echo regression probe) and 60-second fuzz smokes on every push. See
[docs/development.md](docs/development.md).

### Containers and demos

Everything runs reproducibly with [Podman](https://podman.io) — defender and
adversary in one compose file (ADR-0009):

```bash
just image                 # pinned multi-stage build (digest-pinned bases, --locked)
just up                    # demo server on localhost:8080
just bench                 # wrk keep-alive ON/OFF + ws_bench, recorded in docs/benchmarking.md
just bench-http            # HTTP benchmark only (auto-starts the server)
just bench-ws              # WebSocket benchmark only (auto-starts the server)
just demo-container slowloris       # attack demos print EXPECTED vs OBSERVED
just demo-container header_bomb
just demo-container unmasked_frames
```

The attack scripts cite their control IDs (`SEC-HTTP-001/002`, `SEC-WS-001`)
and exit non-zero if a mitigation does not hold. Results and methodology:
[docs/benchmarking.md](docs/benchmarking.md).

### HTTP endpoints

- `GET /`: serves `crates/server/static/index.html`
- `GET /<file>`: serves files from the static directory
- `POST /<any path>`: echo endpoint, returns the body as JSON
- `OPTIONS /<any path>`: permissive CORS preflight response

### WebSocket endpoint

Any path with valid upgrade headers is accepted (e.g. `ws://127.0.0.1:8000`).
The server echoes text messages back prefixed with `Echo:`, echoes binary
messages as-is, answers pings with pongs, and performs a proper close handshake.

## Trying it out

```bash
# Fetch the index page
curl -i http://127.0.0.1:8000/

# Post some data to the echo endpoint
curl -X POST http://127.0.0.1:8000/api/test -d "Hello, Server!"
```

From a browser (already wired up in the served `index.html`, which connects
back to whatever host and port served the page):

```javascript
const wsScheme = location.protocol === "https:" ? "wss:" : "ws:";
const socket = new WebSocket(`${wsScheme}//${location.host}/`);
socket.onopen = () => socket.send("Hello, Rust!");
socket.onmessage = (e) => console.log("Received:", e.data);
socket.onclose = (e) => console.log("Closed:", e.code, e.reason);
```

## Using the libraries

Building an HTTP response with the `http` crate:

```rust
use http::response::{HttpResponse, HttpStatusCode};

// Simple text response
let response = HttpResponse::ok().with_text("Hello, World!");

// JSON with a custom status code
let response = HttpResponse::new(HttpStatusCode::Created)
    .with_json(r#"{"message": "Resource created"}"#);

// Custom headers; to_bytes() serializes the full response
let bytes = HttpResponse::ok()
    .with_header("cache-control", "no-cache")
    .with_html("<h1>Hello</h1>")
    .to_bytes();
```

Working with frames from the `websocket` crate:

```rust
use websocket::{frame::{Frame, OpCode}, limits::Limits};

// Build and serialize a frame (server-to-client frames are unmasked)
let bytes = Frame::text("Hello").to_bytes();

// Parsing expects client-to-server traffic: client frames must be
// masked (RFC 6455 §5.3), unmasked input is rejected as a protocol error.
match Frame::parse(&wire_bytes, &Limits::default()) {
    Ok((frame, consumed)) => {
        if frame.opcode == OpCode::Text {
            println!("got: {}", String::from_utf8_lossy(&frame.payload));
        }
    }
    Err(e) => eprintln!("frame error: {e:?}"),
}
```

## Dependencies

Kept deliberately small; versions are managed once in the workspace root.

| Dependency                       | Used by           | Purpose                                                         |
| -------------------------------- | ----------------- | --------------------------------------------------------------- |
| `tokio`                          | all crates        | Async runtime (each crate opts into only the features it needs) |
| `bytes`                          | websocket, server | Byte-buffer utilities for frame/request buffering               |
| `thiserror`                      | all crates        | Derive macros for the per-crate error types                     |
| `tracing` + `tracing-subscriber` | websocket, server | Structured, level-filtered logging                              |
| `base64`, `sha1`                 | websocket         | `Sec-WebSocket-Accept` handshake computation                    |
| `httpdate`                       | http              | IMF-fixdate formatting for the `Date` header                    |

## Security

Security is a stated goal of this project, and honesty about the current state
is part of it. The hardening phase (G3) is complete; in place today:

typed limits per protocol crate (head 16 KiB → `431`, body 10 MiB → `413`, WS
frame 1 MiB → close 1009), read timeouts against Slow-Loris, enforced
keep-alive (idle timeout, request budget, HTTP/1.0 semantics), CL/TE conflict
rejection, canonicalized path handling with canonical-path reads, strict
WebSocket frame validation with close codes 1002/1007/1009, full §4.2.1
handshake validation, and complete §5.4 fragmentation/reassembly.

Every control carries an ID (`SEC-HTTP-003`, `SEC-WS-009`) in
[docs/security/controls.md](docs/security/controls.md) with implementation and
test pointers; 43 security tests and 14 end-to-end socket tests pin the
behavior, and CI fuzzes both parsers for 60 seconds per push. The compliance
matrices mark the remaining declared gaps (`Host`/`Origin` validation) and the
out-of-scope features explicitly.

## Roadmap

Tracked in detail in [REFACTOR-PLAN.md](REFACTOR-PLAN.md):

- [x] **G1: Workspace split** into `http` / `websocket` / `server` crates
- [x] **G2: Documentation system**: architecture docs, ADRs, RFC compliance
      matrices, rustdoc with `missing_docs` denied, docs built in CI
- [x] **G3: Security hardening**: timeouts and limits, request-smuggling fixes,
      WebSocket message fragmentation/reassembly (RFC 6455 §5.4), security test
      catalog, fuzzing
- [x] **G4: Reproducible demos**: containers, benchmarks, attack-mitigation
      demos ([docs/benchmarking.md](docs/benchmarking.md),
      [ADR-0009](docs/adr/0009-containerized-demos-and-benchmarks.md))

Explicit non-goals for now: HTTP/2, TLS, WebSocket extensions
(permessage-deflate) and compression: recorded as future work, not silently
missing.

## License

This project is licensed under the MIT License: see the [LICENSE](LICENSE) file
for details.
