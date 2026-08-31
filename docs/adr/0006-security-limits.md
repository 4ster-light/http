# 0006 - Typed security limits for parsing and connections

- **Status:** Accepted
- **Date:** 2026-08-31 (implemented in Phase 3; plan §3.1 `limits.rs`, §5.2)

## Context

Before Phase 3, security thresholds were magic constants scattered through the
code: a 16 KiB head cap in `server::connection`, a 10 MiB body cap and a 1 MiB
chunk cap in the request parser, a 30 s ping interval in the WebSocket loop.
None of them were documented in one place, advertised values (`Keep-Alive:
timeout=5, max=100`) were not enforced anywhere, and tests could not exercise
small limits because the constants were not configurable.

## Decision

Each protocol crate gets a typed `Limits` struct passed explicitly by the
caller (plan decision D4):

- `http::limits::Limits`: `max_head_bytes` (16 KiB, 431 on excess,
  SEC-HTTP-001), `max_body_bytes` (10 MiB, 413, SEC-HTTP-004),
  `head_read_timeout` (10 s, SEC-HTTP-002), `keep_alive_idle_timeout` (5 s)
  and `max_requests_per_connection` (100) for SEC-HTTP-005.
- `websocket::limits::Limits`: `max_frame_payload` (1 MiB, close 1009,
  SEC-WS-002), `max_message_bytes` (1 MiB reassembly cap, SEC-WS-009),
  `ping_interval` (30 s, SEC-WS-008).

Defaults match what responses advertise, so the server never promises a
policy it does not enforce.

## Consequences

- Tests construct limits per scenario (e.g. a 16-byte body cap) instead of
  sending 10 MiB payloads; the SEC-\* test catalog relies on this.
- The demo server uses the defaults; deployments that need different values
  change one struct (the Phase 4 container work builds on this).
- Advertised and enforced keep-alive behavior cannot drift apart silently:
  the handler derives the `Keep-Alive` header from the same limits it
  enforces (covered by `sec_http_005_advertised_keep_alive_matches_limits_defaults`).
