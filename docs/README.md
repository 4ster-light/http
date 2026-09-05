# Documentation index

Everything here is plain markdown with no build step. We chose plain markdown
over mdBook because these docs are read on GitHub, where markdown renders
natively. A zero-tooling docs tree cannot rot, and the layout stays compatible
with mdBook if that ever changes.

## Orientation

- [architecture.md](architecture.md): workspace crates, dependency rules,
  concurrency and error models, request/connection lifecycles.
- [development.md](development.md): toolchain, build/test/lint commands, lint
  policy, how to write an ADR, CI gates.
- [testing.md](testing.md): test taxonomy, current inventory, naming
  conventions, what is coming in the security phase.

## Protocol deep-dives

- [protocols/http.md](protocols/http.md): request pipeline, keep-alive, chunked
  transfer-encoding, current limits.
- [protocols/websocket.md](protocols/websocket.md): frame codec, handshake,
  liveness, close semantics.

## RFC compliance matrices

One row per RFC requirement. `❌` rows are allowed and honest; the matrix is
the roadmap.

- [rfc-compliance/http-1.1.md](rfc-compliance/http-1.1.md): RFC 9110/9112.
- [rfc-compliance/websocket-rfc6455.md](rfc-compliance/websocket-rfc6455.md):
  RFC 6455.

## Security

- [security/threat-model.md](security/threat-model.md): assets, trust
  boundaries, attacker capabilities, abuse cases.
- [security/controls.md](security/controls.md): the SEC-HTTP-\* and SEC-WS-\*
  control catalog with implementation and test pointers.
- [security/hardening.md](security/hardening.md): deployment hardening guide.
- [security/fuzzing.md](security/fuzzing.md): fuzz harnesses, corpora,
  dictionaries, and how to run them.

## Benchmarking and demos

- [benchmarking.md](benchmarking.md): methodology, environment disclosure,
  recorded results (HTTP keep-alive ON/OFF, WS echo/handshake), and one-command
  repro steps.
- `container/` (repo root): digest-pinned multi-stage Containerfile, compose
  file with `server`/`bench`/`attack` profiles, and the attack demo scripts
  (see ADR-0009).
- `justfile` (repo root): `just test`, `lint`, `docs`, `fuzz`, `image`, `up`,
  `bench`, `demo <name>`.

## Architecture Decision Records

Immutable, numbered, one decision each. See
[adr/0000-template.md](adr/0000-template.md) for the format.

| ADR                                             | Decision                                        | Status                                                     |
| ----------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| [0001](adr/0001-async-runtime-tokio.md)         | Async runtime: tokio                            | Accepted                                                   |
| [0002](adr/0002-workspace-split.md)             | Workspace split into http/websocket/server      | Accepted                                                   |
| [0003](adr/0003-error-type-per-crate.md)        | Per-crate error types, no shared error crate    | Accepted                                                   |
| [0004](adr/0004-httpdate-over-chrono.md)        | httpdate over chrono for the Date header        | Accepted                                                   |
| [0005](adr/0005-generic-io-and-pure-parsers.md) | Generic IO + pure parsers, single-owner buffers | Accepted (implemented in the security phase)               |
| [0006](adr/0006-security-limits.md)             | Typed security limits per protocol crate        | Accepted                                                   |
| [0007](adr/0007-keep-alive-policy.md)           | Keep-alive policy: enforce what is advertised   | Accepted                                                   |
| [0008](adr/0008-explicit-bind-port.md)          | Explicit bind address, fail fast on conflict    | Accepted                                                   |
| [0009](adr/0009-containerized-demos-and-benchmarks.md) | Containerized demos, benchmarks, and attack scripts | Accepted                                   |

Cross-references used throughout: `F1-F11` are audit findings,
`SEC-HTTP-00x`/`SEC-WS-00x` are security controls, `D1-D8` are architecture
decisions. All are defined in [REFACTOR-PLAN.md](../REFACTOR-PLAN.md).
