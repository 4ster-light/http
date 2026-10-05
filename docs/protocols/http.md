# HTTP/1.1 protocol notes

Deep-dive into the `http` crate and how `server` drives it. For the
requirement-by-requirement status see
[../rfc-compliance/http-1.1.md](../rfc-compliance/http-1.1.md).

## Request pipeline

1. **Framing (pure).** `http::connection::read_request` owns a persistent
   `BytesMut` for the whole connection. `HttpRequest::parse` scans the buffer
   for the head terminator; a head past **16 KiB** fails with `HeadTooLarge`,
   which the server answers with `431` (SEC-HTTP-001). The buffer is never reset
   between requests, so pipelined bytes are preserved (SEC-HTTP-007, F1 fixed).
2. **Head parsing.** The request line must be exactly
   `METHOD SP target SP
   version` with an `HTTP/`DIGIT`.`DIGIT version token
   (RFC 9112 §2.3). The method is matched case-insensitively against 9 known
   methods. The target is classified by form (RFC 9112 §3.2.1): origin-form is
   routed, `*` is accepted only for `OPTIONS`, authority-form is accepted only
   for `CONNECT`, and absolute-form is rejected with `400` rather than misparsed
   as a path (SEC-HTTP-011). An HTTP/1.1 request must carry `Host`
   (SEC-HTTP-009); whitespace between a field name and the colon is rejected
   (RFC 9110 §5.6.3). Header names are lower-cased into a `HashMap`
   (case-insensitive lookup, RFC 9110 §5.1); duplicate field lines are
   comma-merged per RFC 9110 §5.2, which makes conflicting `Content-Length`
   values fail closed.
3. **Body framing.** Sending `Content-Length` and `Transfer-Encoding` together
   is rejected outright (SEC-HTTP-003, RFC 9112 §6.3). A `Content-Length` body
   is taken from the buffer (cap **10 MiB**, excess gives `413`); chunked bodies
   are decoded by the pure `body::decode_chunked_body` (extensions tolerated and
   ignored, trailers rejected). `parse` returns `Ok(None)` until the full
   request is buffered, so partial bodies simply wait for more bytes. A client
   that announced `Expect: 100-continue` is answered with an interim
   `100 Continue` once the head is complete and before the body is awaited
   (HTTP/1.1 only; SEC-HTTP-010, RFC 9110 §10.1.1).

## Read timeouts

`read_request` applies `Limits::head_read_timeout` (10 s) once a partial request
is in flight and the keep-alive idle timeout (5 s) when the buffer is empty
(SEC-HTTP-002, SEC-HTTP-005, ADR-0007). A timeout on an empty buffer is a clean
close; a timeout mid-request is an error the server reports before closing.

## Error responses (F8 fixed)

Every parse failure maps to a status through `http::Error::status()`:
`InvalidHttpRequest` → 400, `HeadTooLarge` → 431, `BodyTooLarge` → 413, IO →
500. `server::connection` writes that response (with `Connection: close`) before
tearing down, so abuse attempts are visible to clients and logs.

## Chunked transfer-encoding

```txt
Read chunk size line (hex) → Parse size
    ↓
Read size bytes of data → Append to body
    ↓
Read trailing \r\n
    ↓
If size = 0 → Done (empty terminator line required)
Else → Loop back
```

`body::decode_chunked_body` decodes `size [;ext] CRLF data CRLF … 0 CRLF
CRLF`
from a byte slice and returns the body plus the consumed length:

- Chunk size parsed as hex; anything else is an error.
- Chunk extensions are tolerated and ignored (RFC 9112 §7.1.1).
- The reassembled body is capped by `Limits::max_body_bytes` (`413`).
- Trailer fields after the terminating chunk are rejected to keep framing
  unambiguous.

## Response pipeline

`HttpResponse` is a consuming builder. `to_bytes()` fills in, when absent:

- `Date`: IMF-fixdate via `httpdate` (RFC 9110 §6.6.1).
- `Server`: `http-rs/0.1.0`.
- `Connection` / `Keep-Alive`: keep-alive is advertised only for 2xx responses;
  the handler derives the `Keep-Alive` parameters from the same `Limits` the
  server enforces (timeout=5, max=100 by default).

`with_body` sets `Content-Length` unless the caller already did. Response bodies
are always length-delimited (no chunked responses), which is legal HTTP/1.1.
`into_head` converts a built response into its `HEAD` form: the `Content-Length`
the equivalent GET would send is kept, the body is cleared, and no bytes follow
the head (RFC 9110 §9.3.2).

## Keep-alive

```txt
Client connects → Server accepts
    ↓
┌─> Read request from persistent buffer (timeouts per Limits)
│   ↓
│   Parse + handle request
│   ↓
│   Send response (Keep-Alive header from Limits)
│   ↓
│   Close if: client said close · HTTP/1.0 without opt-in ·
│            request budget (max=100) exhausted · error occurred
│
└── Loop back otherwise
```

The policy is defined in [ADR-0006](../adr/0006-security-limits.md) and
[ADR-0007](../adr/0007-keep-alive-policy.md): idle timeout 5 s, head timeout 10
s, 100 requests per connection, all matching what responses advertise.

## Static file serving (server handler)

- `/` maps to `index.html`.
- The request target is percent-decoded first; decoding failures are a 400.
- The path is canonicalized and must stay under the canonical static directory;
  the file is read via the canonical path, closing the F10 TOCTOU window
  (SEC-HTTP-006).
- Content types come from a fixed extension table, defaulting to
  `application/octet-stream`.

## Method support

| Method    | Behavior                                                  |
| --------- | --------------------------------------------------------- |
| `GET`     | Static file serving                                       |
| `HEAD`    | Same headers as GET (incl. `Content-Length`), no body     |
| `POST`    | Echo endpoint (returns body as JSON)                      |
| `OPTIONS` | CORS preflight and `Allow` (also server-wide `OPTIONS *`) |
| `CONNECT` | Parsed (authority-form) but not routed → `405` + `Allow`  |
| others    | `405 Method Not Allowed` + `Allow` (RFC 9110 §15.5.5)     |
