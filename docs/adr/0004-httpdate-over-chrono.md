# 0004 — httpdate over chrono for the Date header

- **Status:** Accepted
- **Date:** 2026-07-31 (implemented in Phase 1; plan question Q6 / decision D6)

## Context

HTTP `Date` headers must be IMF-fixdate (RFC 9110 §6.6.1), a fixed,
locale-independent format. The pre-workspace code pulled in `chrono` for this
one call. `chrono` is a large date/time library whose surface we used at ~0%; it
has also historically dragged in the vulnerable `time 0.1` dependency
(RUSTSEC-2020-0071) unless carefully feature-gated. `httpdate` is a tiny,
single-purpose crate that does exactly HTTP date parsing/formatting.

## Decision

Use `httpdate::fmt_http_date(SystemTime::now())` in
`http::response::HttpResponse::to_bytes`; drop `chrono` entirely.

## Consequences

- Smaller dependency tree and compile times; no date-time advisory surface for a
  formatting-only need.
- The emitted format is unchanged (verified: `date: Fri, 31 Jul 2026 … GMT`), so
  this was a zero-behavior-change swap validated by the existing tests and the
  live smoke test.
- If the project ever needs real calendar math (cache expiry calculations,
  scheduling), the decision can be revisited with an actual requirement on the
  table.
