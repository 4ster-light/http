# 0007 - Keep-alive policy: enforce what is advertised

- **Status:** Accepted
- **Date:** 2026-08-31 (implemented in Phase 3; resolves finding F3)

## Context

Responses advertised `Keep-Alive: timeout=5, max=100` but nothing enforced
either value: connections stayed open indefinitely, a client could hoard
tasks forever, and the advertised policy was a lie (F3). The read side had no
timeouts at all, which also made Slow-Loris trivial (F2).

## Decision

The keep-alive loop in `server::connection` enforces exactly the advertised
policy, expressed through `http::limits::Limits` (ADR-0006):

- The idle window between requests is bounded by
  `keep_alive_idle_timeout` (5 s). A quiet client is disconnected after the
  window; this is treated as a clean close, not an error.
- A connection serves at most `max_requests_per_connection` (100) requests,
  then closes after the final response.
- A partially received request must complete within `head_read_timeout`
  (10 s), which is the Slow-Loris mitigation (SEC-HTTP-002).
- HTTP/1.0 semantics are honored: close by default, keep-alive only on
  explicit `Connection: keep-alive` (F7, RFC 9112 §9.3).
- The handler writes the `Keep-Alive` header from the same limits, so the
  advertisement always matches the enforcement.

## Consequences

- `sec_http_005_advertised_keep_alive_matches_limits_defaults` pins the
  advertisement/enforcement match.
- Idle clients are disconnected after 5 s; the e2e suite covers sequential
  keep-alive requests within the window.
- Slow clients that cannot finish a head within 10 s are dropped with a 408-
  style timeout error path (currently a close after the mapped status).
