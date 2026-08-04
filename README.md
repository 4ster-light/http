# HTTP & WebSockets in Rust

A from-scratch implementation of HTTP/1.1 and WebSocket (RFC 6455) protocols in
Rust, built on `tokio`. This is a learning and portfolio project with a
networking + cybersecurity angle: the goal is not just to make the protocols
work, but to understand them deeply enough to document compliance honestly and
to prove — with tests — that the server holds up under attack.

The code is organized as a Cargo workspace of small, single-purpose crates. An
active refactor & hardening program is tracked in
[REFACTOR-PLAN.md](REFACTOR-PLAN.md), including a full security audit of the
current code and the roadmap to address every finding.

## Table of Contents

- [Features](#features)
  - [HTTP/1.1 (RFC 7230–7235)](#http11-rfc-72307235)
  - [WebSocket (RFC 6455)](#websocket-rfc-6455)
  - [Engineering practices](#engineering-practices)
- [Workspace layout](#workspace-layout)
- [Documentation](#documentation)
- [Usage](#usage)
  - [Running the server](#running-the-server)
  - [Tests, lints and docs](#tests-lints-and-docs)
  - [HTTP endpoints](#http-endpoints)
  - [WebSocket endpoint](#websocket-endpoint)
- [Trying it out](#trying-it-out)
- [Using the libraries](#using-the-libraries)
- [Dependencies](#dependencies)
- [Security](#security)
- [Roadmap](#roadmap)
- [License](#license)

## Features

### HTTP/1.1 (RFC 7230–7235)

- ✅ Request parsing for all common methods (GET, POST, PUT, DELETE, HEAD,
  OPTIONS, PATCH, TRACE, CONNECT)
- ✅ Persistent connections (keep-alive): multiple requests per TCP connection
- ✅ Request body reading via `Content-Length` and chunked transfer-encoding
- ✅ Response builder with strongly-typed status codes
- ✅ Auto-generated standard headers (`Date`, `Server`, `Connection`,
  `Keep-Alive`)
- ✅ Static file serving with content-type detection and directory-traversal
  protection
- ✅ Header-size cap (16 KB) against header-bomb attacks

Full requirement-by-requirement status:
[docs/rfc-compliance/http-1.1.md](docs/rfc-compliance/http-1.1.md)

### WebSocket (RFC 6455)

- ✅ Opening handshake (`Sec-WebSocket-Accept` computation per §4.2)
- ✅ Frame codec with buffering: incomplete frames are reassembled across reads
- ✅ Text and binary messages, echo behavior in the demo server
- ✅ Masking enforcement: unmasked client frames are rejected (§5.3)
- ✅ Control-frame validation (≤ 125 byte payload, close-code table)
- ✅ Server-initiated ping/pong liveness checks with timeout
- ✅ Clean close handshake with status codes and reasons

Full requirement-by-requirement status:
[docs/rfc-compliance/websocket-rfc6455.md](docs/rfc-compliance/websocket-rfc6455.md)

### Engineering practices

- ✅ Cargo workspace: two protocol libraries + one demo binary (see below)
- ✅ Strong typing for methods, status codes, frames and errors (`thiserror`)
- ✅ Per-crate error types: `http::Error`, `websocket::Error`
- ✅ Async/await throughout, one `tokio` task per connection
- ✅ Structured logging with `tracing`
- ✅ 19 tests (6 unit + 11 integration + 2 doctests), clippy-clean with
  `all`/`pedantic` warnings denied workspace-wide, `missing_docs` denied,
  `unsafe_code` forbidden

## Workspace layout

```txt
├── Cargo.toml              # workspace root: shared deps + lints
└── crates/
    ├── http/               # HTTP/1.1 protocol library
    │   ├── src/
    │   │   ├── request.rs  #   request-line + header parsing
    │   │   ├── response.rs #   response builder
    │   │   ├── body.rs     #   Content-Length / chunked body readers
    │   │   └── error.rs    #   http::Error
    │   └── tests/          # protocol integration tests
    ├── websocket/          # WebSocket library (depends on http)
    │   ├── src/
    │   │   ├── frame.rs    #   frame codec
    │   │   ├── handshake.rs#   upgrade validation + accept key
    │   │   ├── connection.rs#  lifecycle: echo, ping/pong, close
    │   │   └── error.rs    #   websocket::Error
    │   └── tests/
    └── server/             # demo application (binary)
        ├── src/            #   config, connection dispatch, handlers
        └── static/         #   files served by the demo
```

Dependency direction is strictly `websocket → http` (the WebSocket handshake is
an HTTP upgrade) and `server → {http, websocket}`. No cycles, no shared "common"
crate — each protocol crate carries only what it needs, so they can be read and
reused independently.

## Documentation

The full documentation system lives in [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md) — crates, concurrency and error models,
  request/connection lifecycles
- RFC compliance matrices — [HTTP/1.1](docs/rfc-compliance/http-1.1.md) and
  [WebSocket](docs/rfc-compliance/websocket-rfc6455.md), one row per RFC
  requirement, honest ❌ rows included
- Security — [threat model](docs/security/threat-model.md),
  [controls catalog](docs/security/controls.md),
  [hardening guide](docs/security/hardening.md)
- Protocol deep-dives — [HTTP](docs/protocols/http.md),
  [WebSocket](docs/protocols/websocket.md)
- [Testing](docs/testing.md) · [Development](docs/development.md) ·
  [Benchmarking](docs/benchmarking.md)
- [ADRs](docs/adr/0001-async-runtime-tokio.md) — architecture decision records
  (tokio, workspace split, error model, httpdate, generic IO)

## Usage

### Running the server

```bash
cargo run -p server
```

The demo server starts on <http://127.0.0.1:8000>. If that port is taken it
currently scans for a free one and logs a warning — a future milestone replaces
this with explicit, fail-fast configuration (see REFACTOR-PLAN.md, D8).

Enable detailed logging with `RUST_LOG`:

```bash
RUST_LOG=server=debug cargo run -p server
```

### Tests, lints and docs

```bash
cargo test --workspace                    # all 19 tests (incl. doctests)
cargo test -p http                        # just one crate
cargo clippy --workspace --all-targets    # all + pedantic warnings denied
cargo doc --workspace --open              # API documentation
```

CI runs fmt, clippy, tests, a docs build and a boot-and-curl smoke test on every
push — see [docs/development.md](docs/development.md).

### HTTP endpoints

- `GET /` — serves `crates/server/static/index.html`
- `GET /<file>` — serves files from the static directory
- `POST /<any path>` — echo endpoint, returns the body as JSON
- `OPTIONS /<any path>` — permissive CORS preflight response

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

From a browser (already wired up in the served `index.html`):

```javascript
const socket = new WebSocket("ws://127.0.0.1:8000");
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
use websocket::frame::WebSocketFrame;

// Build and serialize a frame (server-to-client frames are unmasked)
let bytes = WebSocketFrame::text("Hello").to_bytes();

// Parsing expects client-to-server traffic: client frames must be
// masked (RFC 6455 §5.3), unmasked input is rejected as a protocol error.
match WebSocketFrame::parse(&wire_bytes) {
    Ok((WebSocketFrame::Text(msg), consumed)) => println!("got: {msg}"),
    Ok((WebSocketFrame::Close(info), _)) => println!("closing: {info:?}"),
    Ok(_) => {}
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
is part of it. In place today: directory-traversal protection with path
canonicalization, a 16 KB header-size cap, a 10 MB body-size cap, WebSocket
masking enforcement, control-frame size limits and close-code validation.

A full audit of the codebase (REFACTOR-PLAN.md §2) additionally documents every
known weakness — including a request-body buffering bug (F1), missing read
timeouts (F2) and unbounded WebSocket data frames (F5) — each with a severity,
evidence, and a scheduled fix in the hardening phase. That phase turns every
finding into a documented control with regression tests, plus fuzzing for the
parsers. If you are evaluating this code, read the plan: it shows both the holes
and exactly how they get closed.

## Roadmap

Tracked in detail in [REFACTOR-PLAN.md](REFACTOR-PLAN.md):

- [x] **G1 — Workspace split** into `http` / `websocket` / `server` crates
- [x] **G2 — Documentation system**: architecture docs, ADRs, RFC compliance
      matrices, rustdoc with `missing_docs` denied, docs built in CI
- [ ] **G3 — Security hardening**: timeouts and limits, request-smuggling fixes,
      WebSocket message fragmentation/reassembly (RFC 6455 §5.4), security test
      catalog, fuzzing
- [ ] **G4 — Reproducible demos**: containers, benchmarks, attack-mitigation
      demos

Explicit non-goals for now: HTTP/2, TLS, WebSocket extensions
(permessage-deflate) and compression — recorded as future work, not silently
missing.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file
for details.
