# 0010 - `Expect: 100-continue` in the connection reader

- **Status:** Accepted
- **Date:** 2026-10-05
- **Resolves:** the `Expect: 100-continue` gap in
  [rfc-compliance/http-1.1.md](../rfc-compliance/http-1.1.md) §6.1 (control
  SEC-HTTP-010).

## Context

RFC 9110 §10.1.1 lets a client send a request head with `Expect: 100-continue`
and wait for an interim `100 Continue` before transmitting the body. A server
that ignores it leaves the client waiting until its own timeout; the previous
parser could not do otherwise, because `HttpRequest::parse` only returned a
request once the _whole_ body was buffered. The head was not observable on its
own, so there was no point at which the server could decide to send the interim
response.

Two shapes were considered:

1. **Parse the head, write `100`, then keep reading the body** in the connection
   reader. This matches the wire sequence and keeps all framing in one place.
2. **Parse the head in the server, write `100` from the server, then parse the
   body.** This spreads framing across the `server` layer and would force the
   application to re-implement the body logic that already lives in `http`.

The alternative of _always_ writing `100` first (before parsing the head) is
wrong: it would send an interim response to HTTP/1.0 clients and to requests
that will be rejected from the head alone (for example a `Content-Length` over
the cap), wasting a round trip and, worse, telling a client to send a body the
server has already decided to refuse.

## Decision

**Split head parsing from body framing and let `http::connection::read_request`
send the interim response.**

- `HttpRequest::parse_head(buffer, limits)` parses request line + fields plus
  the terminator, returning the request with an empty body and the head length.
  It still enforces the head cap and the `Content-Length`/`Transfer-Encoding`
  conflict, so those failures are decided from the head.
- `HttpRequest::parse` is now `parse_head` plus body framing; its public
  contract is unchanged.
- `read_request` requires `AsyncRead + AsyncWrite` and, when the head is
  complete, the version is not HTTP/1.0, `Expect: 100-continue` is present, and
  a body is announced, writes `HTTP/1.1 100 Continue\r\n\r\n` exactly once
  before waiting for the body.
- If `parse` already returns `Some` (the body arrived eagerly) or an error (the
  body is over the cap, or the framing is invalid), no interim response is sent.

## Consequences

- `http` now writes one protocol byte sequence, the interim response. That is
  framing-adjacent, so it belongs in the connection reader rather than in
  application code, and it keeps ADR-0002's ownership table intact: `http` owns
  generic-IO request reading, the `server` still owns routing and final
  responses.
- The connection reader's bound is `AsyncRead + AsyncWrite` instead of read
  only. Every caller already had both (a `TcpStream` in production, a
  `tokio::io::duplex` half in tests), so no caller changed shape.
- The interim response is best-effort with respect to rejection: a request whose
  `Content-Length` exceeds the configured cap is refused with `413` and never
  receives a `100`, which RFC 9110 §10.1.1 permits (a final status may replace
  the interim).
- Tests cover the interactive path, the rejected-before-body path, and the
  HTTP/1.0 opt-out (`sec_http_010_*`, e2e `e2e_expect_continue_sends_100`).
