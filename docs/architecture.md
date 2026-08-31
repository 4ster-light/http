# Architecture

## Workspace crates

```txt
┌──────────────────────────────────────────────────────────┐
│ server (binary)                                          │
│ config · connection dispatch · static/POST/OPTIONS       │
│ handlers · ServerError                                   │
└───────────────┬──────────────────────────┬───────────────┘
                │ uses                     │ uses
┌───────────────▼───────────┐   ┌──────────▼───────────────┐
│ http (library)            │   │ websocket (library)      │
│ request · response · body │◄──│ frame · handshake ·      │
│ · connection · limits     │   │ connection · limits      │
│ · error                   │   │ · error                  │
└───────────────────────────┘   └──────────────────────────┘
```

**Dependency rule (D1):** `websocket → http` (the WebSocket handshake is an
HTTP upgrade request) and `server → {http, websocket}`. Never the reverse.
There is deliberately no shared "common" crate: each protocol crate carries
only what it needs, so `http` and `websocket` can be read, tested and reused
independently.

### Crate responsibilities

| Crate       | Owns                                                                                     | Does not own                                  |
| ----------- | ---------------------------------------------------------------------------------------- | --------------------------------------------- |
| `http`      | Pure request parsing, body decoding, response building, typed limits, generic-IO request reader | Routing, static files, the WebSocket upgrade |
| `websocket` | Strict frame codec, handshake validation + accept key, connection loop (echo, reassembly, ping/pong, close), typed limits | HTTP parsing (imports it from `http`)        |
| `server`    | Accept loop, per-connection dispatch (HTTP vs WS upgrade), handlers, config, static directory, error responses | Protocol details (delegates to the libraries) |

## Concurrency model

One `tokio` task per accepted TCP connection (`tokio::spawn` in `server::main`).
Connections share no mutable state; the only shared data is the read-only
`Config` (static directory path, bind address, limits). The WebSocket loop
uses `tokio::select!` to race socket reads against the ping ticker.

## Parsers, buffers, and IO (ADR-0005)

Parsing is pure: `HttpRequest::parse` and `Frame::parse` take byte slices and
return either a value plus consumed bytes or "incomplete"/a typed error. No
sockets, no async, no runtime. The connection layers own the buffers:

- `http::connection::read_request` is generic over `AsyncRead`; the caller
  owns one `BytesMut` for the connection's lifetime, and consumed bytes are
  never discarded (SEC-HTTP-007, F1 fixed).
- The WebSocket loop is generic over `AsyncRead + AsyncWrite` with the same
  buffer discipline.
- Tests drive both with `tokio::io::duplex` and `tokio::time::pause`; fuzz
  harnesses call the parsers directly (no IO at all).

## Request lifecycle (HTTP)

1. `server::main` accepts a connection and spawns
   `connection::handle_connection`.
2. `http::connection::read_request` accumulates bytes into the connection
   buffer and parses complete requests out of it. Oversized heads give `431`
   (SEC-HTTP-001); partial requests must complete within the head timeout
   (SEC-HTTP-002); the idle keep-alive window closes quiet connections
   (SEC-HTTP-005).
3. The parse yields the request including its body (Content-Length or
   chunked), so same-segment POST bodies and pipelined requests work (F1
   fixed). Parse failures produce a mapped 4xx/5xx response before close
   (F8 fixed).
4. `websocket::handshake::validate_upgrade` classifies the request; an
   invalid upgrade attempt gets `400` (SEC-WS-007), a valid one hands the
   socket to `websocket::handle_websocket`.
5. Otherwise `handler::handle_http_request` dispatches by method (GET →
   static file with traversal protection, POST → echo, OPTIONS → CORS
   preflight) and writes the response, advertising keep-alive parameters
   from the same limits the loop enforces (F3 fixed).
6. The loop repeats unless the client asked for close, the version defaults
   to close (HTTP/1.0, F7 fixed), the request budget is exhausted, or an
   error occurred.

## WebSocket lifecycle

1. Handshake validated (SEC-WS-007) and the `101` response written by
   `handshake::generate_accept` with the RFC §4.2.2 accept digest.
2. Frame loop over a persistent buffer: frames are parsed with strict
   validation (RSV, opcodes, masking, length rules, size caps) and control
   frames are handled immediately, including mid-message.
3. Fragmented messages are reassembled by the state machine (SEC-WS-009);
   text messages are UTF-8 validated as a whole (SEC-WS-005). Violations
   answer with close 1002/1007/1009 before shutdown (F5/F6/F8 fixed).
4. Text is echoed with an `"Echo: "` prefix; binary is echoed as-is; ping
   gets a pong; close gets a close reply.
5. The first server ping goes out one interval (30 s) after the handshake;
   a missed pong by the next tick closes with 1002 (SEC-WS-008, F10 fixed).

## Error model (D5)

Each crate has exactly one error type; there is no shared error crate.

- `http::Error`: `Io(#[from] std::io::Error)`, `InvalidHttpRequest`,
  `HeadTooLarge`, `BodyTooLarge`, plus a `status()` mapping so the server can
  answer 400/431/413/500 correctly (F8 fixed).
- `websocket::Error`: `Io`, `Http(#[from] http::Error)`, handshake/frame
  variants. Frame decoding keeps a fine-grained `frame::ParseError`, which
  the connection layer translates into close codes.
- `server::ServerError`: aggregates `Io`, `Http(#[from])`,
  `WebSocket(#[from])`, plus the application variant `FileNotFound`.

Errors surface as protocol responses (HTTP status or WS close code) followed
by a connection close, with a log entry naming the reason.

## Where to verify all this

- Controls and their tests: [security/controls.md](security/controls.md).
- RFC requirement matrices with linked tests:
  [rfc-compliance/http-1.1.md](rfc-compliance/http-1.1.md),
  [rfc-compliance/websocket-rfc6455.md](rfc-compliance/websocket-rfc6455.md).
- Test taxonomy and determinism techniques: [testing.md](testing.md).
- Parser fuzzing: [security/fuzzing.md](security/fuzzing.md).
