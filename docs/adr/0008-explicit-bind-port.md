# 0008 - Explicit bind address, fail fast on conflict

- **Status:** Accepted
- **Date:** 2026-08-31 (implemented in Phase 3; plan decision D8, question Q9)

## Context

`Config::default()` port-scanned from 8000 upward and silently bound the
first free port. That was convenient for development but surprising: the
operator did not know which port the server took, a race existed between
reserving and using the port, and a security-sensitive server silently
changing its bind point is the wrong default posture.

## Decision

- `Config` carries an explicit `address` (`"127.0.0.1:8000"` by default,
  overridable with the `SERVER_ADDR` environment variable for tests and
  deployments).
- `main` binds exactly that address; a bind failure is a fatal startup
  error. No fallback scanning.
- The `PortUnavailable` error variant and the scanning code were removed.

## Consequences

- A second instance of the server on the same port exits loudly instead of
  drifting to another port.
- The e2e suite spawns the binary on ephemeral ports via `SERVER_ADDR`,
  which is also the documented way to change the bind point.
- Operators who relied on the automatic port drift must set `SERVER_ADDR`
  explicitly; this is intentional friction (security posture over
  convenience).
