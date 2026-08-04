# HTTP/1.1 protocol notes

Deep-dive into the `http` crate and how `server` drives it. For the
requirement-by-requirement status see
[../rfc-compliance/http-1.1.md](../rfc-compliance/http-1.1.md).

## Request pipeline

1. **Framing (server side).** Bytes accumulate in a `BytesMut` until `\r\n\r\n`
   (`find_header_end`). If the head exceeds **16 KiB** the connection is dropped
   (a `431` response is planned, SEC-HTTP-001).
2. **Head parsing (`HttpRequest::from_buffer`).** The request line must be
   exactly `METHOD SP target SP version`; the method is matched
   case-insensitively against 9 known methods. Header names are lower-cased into
   a `HashMap`, so `get_header` is case-insensitive per RFC 9110 §5.1.
3. **Body framing.** If `Content-Length` is present, exactly that many bytes are
   read (cap: **10 MiB**). Otherwise, if `Transfer-Encoding` contains `chunked`,
   the body is decoded chunk by chunk. Otherwise the request has no body.

### Known deviations in the pipeline

- **F1 (P0):** bytes already read past the header end are discarded instead of
  feeding the body/next request. Breaks pipelining and same-segment POST bodies.
  Fixed by the buffer-ownership refactor (ADR-0005).
- **F4:** when `Content-Length` _and_ `Transfer-Encoding` are both present, the
  `Content-Length` path wins — the opposite of RFC 9112 §6.3 precedence.
  Scheduled as SEC-HTTP-003.
- Malformed requests (bad request line, oversized head, oversized body)
  currently end the connection **without any response**; proper
  `400`/`431`/`413` replies are part of the controls catalog.

## Chunked transfer-encoding

```txt
Read chunk size line (hex) → Parse size
    ↓
Read size bytes of data → Append to body
    ↓
Read trailing \r\n
    ↓
If size = 0 → Done
Else → Loop back
```

`body::read_chunked_body` decodes `size CRLF data CRLF … 0 CRLF CRLF`:

- Chunk size parsed as hex; anything else → error.
- Per-chunk cap of **1 MiB** (defense against absurd size declarations).
- Any bytes after the terminating `0`-chunk (trailers) are rejected.
- Chunk extensions (`;foo=bar`) are not parsed — rejected as malformed.

## Response pipeline

`HttpResponse` is a consuming builder. `to_bytes()` fills in, when absent:

- `Date` — IMF-fixdate via `httpdate` (RFC 9110 §6.6.1).
- `Server` — `http-rs/0.1.0`.
- `Connection` / `Keep-Alive` — `keep-alive` with `timeout=5, max=100` is
  advertised **only for 2xx responses**; everything else gets `close`.

`with_body` sets `Content-Length` unless the caller already did.

### Known deviations

- **F3:** the advertised `timeout=5, max=100` is not enforced server-side —
  connections live as long as the client keeps them busy. Enforcement scheduled
  as SEC-HTTP-005.
- No chunked _responses_; every response body is length-delimited. That is legal
  HTTP/1.1, just inflexible for streaming.

## Keep-alive

```txt
Client connects → Server accepts
    ↓
┌─> Read headers until \r\n\r\n
│   ↓
│   Parse headers
│   ↓
│   Read body (if Content-Length or chunked)
│   ↓
│   Handle request
│   ↓
│   Send response with Connection: keep-alive
│   ↓
│   Check if Connection: close
│   ↓
└── Loop back if keep-alive
```

The connection loop in `server::connection::handle_connection` repeats until:
the client closes, the client sends `Connection: close`, or an error occurs.
There is no idle timeout and no max-requests counter yet (F3 above), and no read
timeout at all (F2 → SEC-HTTP-002).

## Static file serving (server handler)

- `/` maps to `index.html`.
- Paths are canonicalized and must stay under the canonical static directory
  (directory-traversal protection).
- **F10:** the file is then read via the *un*canonicalized path (TOCTOU symlink
  race) — fix scheduled as SEC-HTTP-006 together with regression tests for `..`,
  encoded variants and symlink escapes.
- Content types are a fixed extension table, defaulting to
  `application/octet-stream`.

## Method support

| Method    | Behavior                                           |
| --------- | -------------------------------------------------- |
| `GET`     | Static file serving                                |
| `POST`    | Echo endpoint (returns body as JSON) — ⚠️ see F1   |
| `OPTIONS` | Permissive CORS preflight                          |
| others    | `405 Method Not Allowed` (incl. `HEAD`, `CONNECT`) |
