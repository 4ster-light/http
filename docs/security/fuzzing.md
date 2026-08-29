# Fuzzing

> **Status: planned. Harnesses land with the security phase (Phase 3).**
> Written now so the design is reviewable and the commands are ready.

## Why fuzz here

The two most attacker-exposed surfaces are the parsers at the trust boundary:
the HTTP request head parser and the WebSocket frame parser. This is exactly
the kind of code (length arithmetic, byte scanning, state transitions) where
fuzzing finds what unit tests do not.

## Targets

| Harness              | Function under test                       | What it should prove                                          |
| -------------------- | ----------------------------------------- | ------------------------------------------------------------- |
| `request_head_parse` | `http` request-line + header parsing      | No panic, no unbounded allocation, no hang on arbitrary bytes |
| `frame_parse`        | `websocket::frame::WebSocketFrame::parse` | No panic on arbitrary bytes; declared-length arithmetic sound |

Both become trivially fuzzable once parsers are pure functions over byte
slices, per [ADR-0005](../adr/0005-generic-io-and-pure-parsers.md). That is one
of the reasons the parser-purity refactor is a prerequisite for the security
phase.

## Tooling

- `cargo-fuzz` (libFuzzer) on a pinned nightly toolchain.
- A seed corpus built from the test suite's valid requests/frames plus the RFC
  examples, and a small dictionary of protocol tokens (`GET`, `HTTP/1.1`,
  `\r\n`, `upgrade`, `sec-websocket-key`, opcode bytes, and so on).

## How to run (once landed)

```bash
cargo +nightly fuzz run request_head_parse   # indefinite local run
cargo +nightly fuzz run frame_parse -- -max_total_time=300
```

## CI policy (once landed)

- A 60-second smoke run per target on every PR.
- Crash artifacts are archived as CI artifacts.
- A found crash becomes a regression test in the relevant crate's
  `tests/security_*.rs` with its control ID, before the fix lands.
