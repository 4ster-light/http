# Security controls catalog

Every control has an ID, a threat reference
([threat-model.md](threat-model.md)), an implementation pointer and a test
pointer. Status values:

- **In place** — implemented and enforced today.
- **Partial** — mechanism exists but deviates from the target behavior.
- **Scheduled** — planned for the security phase (Phase 3); the IDs below are
  stable and will appear in test names (`sec_http_003_…`, `sec_ws_002_…`).

## HTTP controls

| ID           | Control                                                               | Threat                   | Status    | Implementation today                                          | Target behavior / tests (Phase 3)                                                                                 |
| ------------ | --------------------------------------------------------------------- | ------------------------ | --------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| SEC-HTTP-001 | Header-size cap                                                       | Header bomb (F8)         | Partial   | 16 KiB cap in `server::connection`; connection drops silently | Respond `431` + close; boundary tests                                                                             |
| SEC-HTTP-002 | Header read timeout (10 s) + per-read idle timeout                    | Slow-Loris (F2)          | Scheduled | —                                                             | `tokio::time::timeout` around reads; drip-feed tests                                                              |
| SEC-HTTP-003 | Reject `Content-Length` + `Transfer-Encoding` together; TE precedence | Request smuggling (F4)   | Scheduled | CL path silently wins                                         | Reject/TE-wins per RFC 9112 §6.3; conflict tests                                                                  |
| SEC-HTTP-004 | Body-size cap                                                         | Memory exhaustion        | Partial   | 10 MiB cap; connection drops silently                         | Respond `413`; typed in `Limits`; tests                                                                           |
| SEC-HTTP-005 | Keep-alive idle timeout + max requests/connection                     | Connection hoarding (F3) | Scheduled | Advertised (`timeout=5, max=100`) but unenforced              | Enforce what we advertise; tests                                                                                  |
| SEC-HTTP-006 | Path traversal protection                                             | Arbitrary file read      | Partial   | Canonicalize + prefix check                                   | Read via canonical path (F10 TOCTOU); regression tests for `..`, encoded variants, absolute paths, symlink escape |
| SEC-HTTP-007 | Buffer ownership: no discarded bytes                                  | Framing desync (F1, P0)  | Scheduled | Bytes after header end discarded                              | Single connection-owned buffer (ADR-0005); pipelining regression test                                             |

## WebSocket controls

| ID         | Control                                                                                | Threat                       | Status    | Implementation today                            | Target behavior / tests (Phase 3)                     |
| ---------- | -------------------------------------------------------------------------------------- | ---------------------------- | --------- | ----------------------------------------------- | ----------------------------------------------------- |
| SEC-WS-001 | Masking enforcement                                                                    | Intermediary cache poisoning | Partial   | `ParseError::UnmaskedClientFrame` → TCP close   | Also send close 1002; test                            |
| SEC-WS-002 | Max data-frame payload (default 1 MiB, configurable)                                   | Memory exhaustion (F5)       | Scheduled | —                                               | Close 1009; boundary tests                            |
| SEC-WS-003 | Reject RSV≠0, unknown opcodes, fragmented control frames                               | Protocol confusion (F6)      | Scheduled | Unknown opcodes map to `Close` (no close frame) | Strict checks, close 1002; tests                      |
| SEC-WS-004 | Control frames ≤ 125 B                                                                 | Protocol violation           | In place  | `ParseError::ControlFrameTooLarge`              | Add 125/126 boundary tests                            |
| SEC-WS-005 | Invalid UTF-8 in text frames                                                           | Protocol violation           | Partial   | `ParseError::InvalidUtf8` → TCP close           | Send close 1007; test                                 |
| SEC-WS-006 | Close-code validation                                                                  | Protocol violation           | Partial   | `is_valid_close_code` → parse error             | Send close 1002; test                                 |
| SEC-WS-007 | Full handshake validation (GET only, HTTP ≥ 1.1, key = base64(16 B))                   | Malformed upgrade (F11)      | Scheduled | Header presence only                            | Reject with `400`; tests                              |
| SEC-WS-008 | Ping/pong liveness timeout                                                             | Silent-connection hoarding   | In place  | 30 s ticker, close 1002 on missed pong          | Deterministic tests via `tokio::time::pause` + duplex |
| SEC-WS-009 | Fragmentation: continuation reassembly, interleaved control, reject fragmented control | RFC 6455 §5.4 (F4)           | Scheduled | Continuations return `Incomplete` (hang)        | Reassembly state machine; conformance tests           |

## Notes

- "Partial" rows that end a connection _without_ a protocol response share one
  root cause: parse errors propagate as Rust errors instead of being translated
  into protocol-level replies. The security phase introduces that translation
  layer once, then each control uses it.
- Configurable limits land as a typed `Limits` struct (see
  [ADR-0005](../adr/0005-generic-io-and-pure-parsers.md) and the plan §3.1
  `limits.rs`).
