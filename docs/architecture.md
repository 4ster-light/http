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
│ · error                   │   │ connection · error       │
└───────────────────────────┘   └──────────────────────────┘
```

**Dependency rule (D1):** `websocket → http` (the WebSocket handshake is an
HTTP upgrade request) and `server → {http, websocket}`. Never the reverse. There
is deliberately no shared "common" crate: each protocol crate carries only what
it needs, so `http` and `websocket` can be read, tested and reused
independently.

### Crate responsibilities

| Crate       | Owns                                                                                          | Does not own                                  |
| ----------- | --------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `http`      | Request-line/header parsing, body framing (Content-Length, chunked), response building        | Connection management, routing, static files  |
| `websocket` | Frame codec, handshake validation + accept key, connection loop (echo, ping/pong, close)      | HTTP parsing (imports it from `http`)         |
| `server`    | Accept loop, per-connection dispatch (HTTP vs WS upgrade), handlers, config, static directory | Protocol details (delegates to the libraries) |

## Concurrency model

One `tokio` task per accepted TCP connection (`tokio::spawn` in `server::main`).
Connections share no mutable state; the only shared data is the read-only
`Config` (static directory path, bind address). The WebSocket loop additionally
uses `tokio::select!` to race socket reads against a 30 s ping ticker.

## Request lifecycle (HTTP)

1. `server::main` accepts a connection and spawns
   `connection::handle_connection`.
2. Bytes are accumulated into a `BytesMut` until `\r\n\r\n` is found
   (`find_header_end`), with a 16 KiB header cap.
3. `http::request::HttpRequest::from_buffer` parses the request head. When
   `Content-Length` or chunked `Transfer-Encoding` is present, it reads the
   body from the socket (10 MiB body cap, 1 MiB per-chunk cap).
4. `websocket::handshake::is_websocket_request` checks for an upgrade. On a
   match the socket is handed to `websocket::handle_websocket` and never
   returns.
5. Otherwise `handler::handle_http_request` dispatches by method (GET → static
   file, POST → echo, OPTIONS → CORS preflight) and writes the serialized
   `HttpResponse`.
6. Unless the client sent `Connection: close`, the loop repeats for the next
   request (keep-alive).

**Known flaw in steps 2-3 (F1, P0):** parsing discards any bytes already read
past the header end, and body reads go straight to the socket instead of
consuming buffered bytes. This breaks pipelining and stalls same-segment POST
bodies. The fix is architectural, see
[ADR-0005](adr/0005-generic-io-and-pure-parsers.md), and is scheduled for the
security phase.

## WebSocket lifecycle

1. Handshake validated (headers checked) and `101` response written by
   `handshake::generate_accept`.
2. Frame loop: incoming bytes are appended to a `BytesMut`; complete frames are
   consumed via `frame::WebSocketFrame::parse` (masked frames only).
3. Text is echoed back with an `"Echo: "` prefix; binary is echoed as-is; ping
   gets a pong; pong clears the liveness flag; close gets a close reply before
   shutdown.
4. Every 30 s without an outstanding ping the server pings. One missed pong
   means a close frame with code 1002 and shutdown.

## Error model (D5)

Each crate has exactly one error type; there is no shared error crate.

- `http::Error`: `Io(#[from] std::io::Error)`,
  `InvalidHttpRequest(&'static str)`.
- `websocket::Error`: `Io`, `Http(#[from] http::Error)`, handshake/frame
  variants. Frame decoding additionally has a dedicated `frame::ParseError`,
  which the connection layer maps into `websocket::Error::WebSocketError`.
- `server::ServerError`: aggregates `Io`, `Http(#[from])`,
  `WebSocket(#[from])`, plus application variants (`FileNotFound`,
  `PortUnavailable`).

Errors currently surface by logging and dropping the connection. Turning parse
failures into proper protocol responses (`400`/`431`/`413`, WS close codes) is
part of the security controls catalog
([security/controls.md](security/controls.md)).

## IO seams: current and planned

Today the parsing layer takes `&[u8]` but the drivers are coupled to
`tokio::net::TcpStream`, and every read site owns (and discards) its own
buffer. ADR-0005 moves to pure parsers over byte slices, connection drivers
generic over `AsyncRead + AsyncWrite`, and a single connection-owned buffer
with consumed-byte tracking. That fixes F1 by construction and makes
`tokio::io::duplex`-based tests and byte-level fuzz harnesses possible without
sockets.
