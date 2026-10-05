# 0011 - WebSocket Origin validation: declared accepted risk

- **Status:** Accepted
- **Date:** 2026-10-05
- **Resolves:** the `Origin` gap recorded in
  [rfc-compliance/websocket-rfc6455.md](../rfc-compliance/websocket-rfc6455.md)
  §10.2 and in the [threat model](../security/threat-model.md).

## Context

RFC 6455 §10.2 says a WebSocket server SHOULD validate the `Origin` header of
the opening handshake to prevent browsers on other sites from opening
connections to it (cross-site WebSocket hijacking). It is a SHOULD, not a MUST:
non-browser clients do not send `Origin` at all, and an origin check only means
anything when the server is reachable from a browser page it does not control.

This project's server is a demo: it serves a local static page and binds
`127.0.0.1` by default (ADR-0008), and the WebSocket endpoint echoes messages
back. The compliance matrix already lists Origin validation as a declared gap
rather than a hidden one. The remaining question is whether to implement it now
or to accept the risk explicitly.

The handshake layer already validates everything else in §4.2.1 (method,
version, `Upgrade`/`Connection`, `Sec-WebSocket-Version`, and a base64 16-byte
`Sec-WebSocket-Key`) and answers failures with `400` through the
`UpgradeCheck::Invalid` path (SEC-WS-007, F11). Adding an Origin check would be
a small, local change to `websocket::handshake::validate_upgrade` plus an
allow-list threaded through `server::Config`.

## Decision

**Accept the risk and keep Origin validation out of scope for the demo.**

The reasoning:

- The server is explicitly a localhost demo. Same-origin policy concerns apply
  to browser pages from other origins reaching the endpoint; the demo does not
  host third-party pages and binds loopback by default. Deployments that expose
  it are already told to front it with a reverse proxy
  ([hardening.md](../security/hardening.md)).
- The controls that _do_ matter against hostile peers are in place and tested:
  masking enforcement, strict frame validation, payload/message caps, liveness
  timeouts, and a full §4.2.1 handshake. Origin validation is not a
  memory-safety or resource-exhaustion control.
- An allow-list would need a configuration surface and an operational story
  (what origins, how reloaded); inventing that for a demo adds a knob that would
  then be wrong for every real deployment.
- The matrix's honest `❌` is preferable to a check that suggests protection it
  cannot provide: a non-browser attacker forges `Origin` trivially, so the
  control only defends against browsers, and only when configured strictly.

If the project grows a real deployment target, the implementation path is
recorded here: add an `allowed_origins: Vec<String>` (or `Option`) to
`server::Config`, thread it into `validate_upgrade`, return
`UpgradeCheck::Invalid("Origin not allowed")` for a present-and-unlisted
`Origin`, and allow a missing `Origin` for non-browser clients. That reuses the
existing 400 error path with no new error type.

## Consequences

- The WebSocket compliance matrix keeps the §10.2 row `❌` and links here; the
  threat model keeps listing it as a known, accepted gap. Nothing is hidden.
- `validate_upgrade` stays a pure function of the request alone, which keeps it
  trivially testable and free of configuration.
- A future Origin control is a contained change with an existing test seam; it
  does not require touching the frame codec or the connection loop.
