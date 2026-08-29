# Hardening guide

Practical guidance for running the demo server today, and for what changes
when the security phase lands.

## Today's posture (read this first)

The server is a learning project mid-hardening. The
[threat model](threat-model.md) lists known weaknesses; most importantly:

- **P0**: request-body and pipelining buffering bug (F1).
- **P1**: no read timeouts (F2), unbounded WS frame buffering (F5), handshake
  validation gaps (F11).

**Do not expose this server to untrusted networks in its current state.**
Localhost (the default bind) and trusted lab networks are the intended
environments until Phase 3 closes the P0/P1 findings.

## Running it sensibly today

- **Bind:** defaults to `127.0.0.1:8000`. Keep it there unless you know why you
  are changing it. The current fallback port scan is a convenience that Phase 3
  replaces with explicit, fail-fast configuration (D8).
- **TLS:** the server speaks plain TCP only. For anything beyond localhost,
  front it with a TLS-terminating reverse proxy and keep the backend on
  loopback.
- **Static directory:** run with a dedicated, read-only static directory; never
  point `static/` at a directory containing sensitive files. Traversal
  protection exists (canonicalize + prefix check), and defense in depth is
  cheap.
- **User privileges:** run as an unprivileged user; the server needs no
  capabilities beyond binding a high port.
- **Process limits:** until application-level limits land, wrap the process.
  `systemd` units (`MemoryMax=`, `TasksMax=`) or `ulimit -v` give a hard outer
  bound against the unbounded-buffer findings.
- **Logging:** `RUST_LOG=server=info` is the default. At `debug` the server
  logs request paths and WS payloads, so treat logs as sensitive.

## What Phase 3 changes for operators

- A typed `Limits` configuration (timeouts, header/body/frame caps, keep-alive
  policy) with safe defaults. These are the knobs the controls catalog
  references.
- Proper protocol-level rejections (`400`/`431`/`413`, WS close codes) instead
  of silent connection drops, which also makes abuse visible in logs.
- Explicit bind address/port; no implicit port scanning.

## Hardening checklist

- [ ] Bound to loopback (or behind a TLS proxy on loopback)
- [ ] Static directory dedicated and read-only
- [ ] Unprivileged user
- [ ] OS-level memory/task limits in place
- [ ] Log level reviewed
- [ ] (After Phase 3) `Limits` reviewed for the deployment
