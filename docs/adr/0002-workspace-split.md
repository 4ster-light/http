# 0002 - Workspace split into http / websocket / server

- **Status:** Accepted
- **Date:** 2026-07-31 (implemented in Phase 1)

## Context

The project began as a single crate mixing two protocols and an application
(`src/protocol`, `src/websocket`, `src/main.rs`). Crates should be readable,
testable and publishable independently, with room for future crates (`tls`,
etc.), and a shared "common" crate is forbidden because it blurs ownership.

## Decision

A Cargo workspace with three crates:

- `http`: HTTP/1.1 protocol library (parsing, responses, body readers).
- `websocket`: WebSocket library. It depends on `http` because the opening
  handshake is an HTTP upgrade (dependency direction is strictly
  `websocket → http`, never the reverse).
- `server`: the demo binary. It holds config, connection dispatch (the only
  place that knows both protocols, so the upgrade glue lives here), handlers,
  and static files.

Workspace-level `[workspace.dependencies]` and `[workspace.lints]` keep versions
and lint policy in one place. Git history was preserved with `git mv`; tests
moved alongside their crates.

## Consequences

- Each protocol crate is independently readable and reusable; the `http` crate
  has no knowledge of WebSocket.
- Cross-crate refactors require touching dependent crates explicitly. That is a
  feature (the API surface is deliberate), not a bug.
- The static directory moved into `crates/server/`, so `Config` resolves it via
  `CARGO_MANIFEST_DIR` instead of the process CWD.
- Publishing to crates.io is deferred; crates reference each other by path until
  APIs stabilize. The crate names (`http`, `websocket`) stay until then; a
  rename only becomes relevant at first publish.
