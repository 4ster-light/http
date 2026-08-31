# Hardening guide

Practical guidance for running the demo server, reflecting the posture after
the Phase 3 hardening.

## Current posture

The Phase 3 security work is complete: request parsing has typed limits
(head 16 KiB, body 10 MiB, WS frame 1 MiB), read timeouts defend against
Slow-Loris, keep-alive is enforced as advertised, malformed input is answered
with proper 4xx responses and WebSocket close codes instead of silent drops,
and the parser invariants are fuzzed in CI (see
[controls.md](controls.md) for the control-by-control catalog with tests).

This remains a learning/demo server. It still has no TLS, no authentication,
and no rate limiting. Localhost and trusted lab networks remain the intended
environments; see the [threat model](threat-model.md) for the full picture.

## Running it

- **Bind:** `127.0.0.1:8000` by default; set `SERVER_ADDR` to change it. The
  address is explicit (ADR-0008): if the port is taken, startup fails rather
  than drifting to another port.
- **Limits:** the defaults live in `http::limits::Limits` and
  `websocket::limits::Limits` (ADR-0006). Review them for your deployment;
  the `Keep-Alive` advertisement always follows the configured values.
- **TLS:** the server speaks plain TCP only. For anything beyond localhost,
  front it with a TLS-terminating reverse proxy and keep the backend on
  loopback.
- **Static directory:** run with a dedicated, read-only static directory;
  never point `static/` at a directory containing sensitive files. Traversal
  protection is enforced (percent-decode, canonicalize, prefix check,
  canonical-path read), and defense in depth is cheap.
- **User privileges:** run as an unprivileged user; the server needs no
  capabilities beyond binding a high port.
- **Process limits:** belt and braces on top of the application limits:
  `systemd` units (`MemoryMax=`, `TasksMax=`) or `ulimit -v`.
- **Logging:** `RUST_LOG=server=info` is the default. At `debug` the server
  logs request paths and WS payloads, so treat logs as sensitive.

## Verification

- `cargo test --workspace` runs the full security catalog (SEC-HTTP-\* and
  SEC-WS-\* tests) plus end-to-end socket tests against the real binary.
- `cargo +nightly fuzz run request_head_parse -- -max_total_time=60` (and
  `frame_parse`) exercises the parsers; CI runs 60-second smokes on every PR.
- The compliance matrices list every RFC requirement with its implementing
  test; anything not claimed is marked out of scope rather than silently
  missing.

## Hardening checklist

- [ ] Bound to loopback (or behind a TLS proxy on loopback)
- [ ] Static directory dedicated and read-only
- [ ] Unprivileged user
- [ ] OS-level memory/task limits in place
- [ ] Log level reviewed
- [ ] `Limits` reviewed for the deployment
- [ ] `SERVER_ADDR` set explicitly (no implicit defaults)
