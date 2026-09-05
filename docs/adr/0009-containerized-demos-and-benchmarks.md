# ADR-0009: Containerized demos and benchmarks

- **Status:** Accepted
- **Date:** 2026-09-05 (decisions landed 2026-09-03 through 2026-09-05 during
  review)
- **Phase:** G4 (reproducible demos), REFACTOR-PLAN.md §6
- **Supersedes:** none
- **Superseded by:** none

## Context

The security-hardening phase produced controls whose value is easiest to see
against a real adversary: stalled Slow-Loris connections, header bombs,
unmasked WebSocket frames. Describing them in prose is weak evidence; a
reviewer should be able to run the attack and watch the mitigation hold. The
same applies to benchmarks: numbers without a reproducible setup are noise.

Requirements pulled from the refactor plan (§6):

1. One-command reproduction for reviewers: `podman compose up`, nothing but
   Podman installed.
2. Network isolation: attack demos run in containers and cannot escape to the
   host.
3. Pinned inputs: committed `Cargo.lock` (already true), `--locked` builds,
   base images pinned by digest.
4. No toolchain in the runtime: the served artifact is a binary plus static
   files, running as a non-root user.

## Decision

1. **Multi-stage `container/Containerfile`:** pinned
   `rust:1-bookworm` (digest) builder → pinned `debian:bookworm-slim`
   (digest) runtime; non-root user (UID 10001), no shell, `EXPOSE 8080`,
   `ENTRYPOINT ["/usr/bin/tini", "--", "/app/server"]`. Builds run
   `cargo build --release --locked`. The runtime includes `tini` as PID 1:
   a server without a signal handler ignores SIGTERM when it *is* PID 1
   (Linux only delivers signals to PID 1 if a handler is installed), which
   made every stop wait out podman's 10 s grace period and end in SIGKILL;
   tini forwards the signal so containers stop in milliseconds.
2. **One compose file, defender and adversary together**
   (`container/compose.yaml`) with profiles:
   - default: the `server` service;
   - `bench`: `bench-http` (wrk, pinned image) and `bench-ws` (the `ws_bench`
     example compiled by `container/Containerfile.bench-ws`, slim runtime);
   - `attack`: `demo_slowloris`, `demo_header_bomb`, `demo_unmasked_frames` —
     stdlib-only Python scripts bind-mounted read-only, each printing
     EXPECTED vs OBSERVED and exiting non-zero when a mitigation does not
     hold.
3. **Attack scripts are honest about scope.** Each cites its control ID
   (SEC-HTTP-001/002, SEC-WS-001) and states what the control actually
   covers. Example: the Slow-Loris demo stalls past the head-read timeout
   because the control is a per-read idle timeout; the script says so.
4. **Benchmarks:** wrk (containerized) for HTTP, the repo's own `ws_bench`
   example for WebSocket. Results are recorded in
   `docs/benchmarking.md` with full environment disclosure, three runs per
   scenario, median reported, and marked as indicative.
5. **Configuration for containers (code change):** the server's static
   directory defaults to the compile-time crate path but can be overridden
   with `STATIC_DIR`, matching the existing `SERVER_ADDR` pattern from
   ADR-0008. The container sets `SERVER_ADDR=0.0.0.0:8080` and
   `STATIC_DIR=/app/static`.
6. **A `justfile` wraps everything:** `just test`, `lint`, `docs`, `fuzz`,
   `image`, `up`/`down`, `bench` (server + wrk keep-alive ON/OFF + ws_bench),
   `bench-http`/`bench-ws` (single-scenario runs against any target),
   `demo <name>`, `demo-container <name>`. The bench and demo recipes share
   `container/scripts/ensure-server`, which probes the target address and
   starts the containerized server when the unreachable target is the
   compose default (localhost:8080), so one-command runs work from a clean
   machine.
7. **A small `examples` workspace member** provides the client side:
   `ws_echo_client` (interactive, verifies the §4.2.2 digest) and `ws_bench`.
   Because the `websocket` crate implements the server half only, the
   examples crate carries a ~120-line documented client-side codec (mask on
   send, reject masked server frames, verify the accept digest). This keeps
   the library's server-only security posture unchanged while making the
   examples real, protocol-correct clients. Clients must verify
   `Sec-WebSocket-Accept` (RFC 6455 §4.2.2), so the handshake crate now
   exposes `accept_key` for exactly that purpose.

## Consequences

- A reviewer needs Podman only: `just bench`, `just demo-container
  header_bomb`, and every claim in `docs/benchmarking.md` and the controls
  catalog becomes reproducible.
- Base-image digests and the wrk image digest age; refreshing them is a
  deliberate, greppable change (update digest + date comment), not silent
  drift.
- The compile-time static path stops being a deployment constraint; the
  default behavior for `cargo run -p server` is unchanged.
- The examples crate builds under the same workspace lint ratchet as the
  libraries, so its code stays teaching-grade.
- Attack demos are still only demos: they cover three representative
  controls, not the full catalog. The test suite (43 security tests) remains
  the complete verification layer.
