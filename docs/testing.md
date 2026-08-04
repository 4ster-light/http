# Testing

## Strategy

Tests are layered so that each layer proves something the layer below cannot:

| Layer       | Where                                 | Runs today | Proves                                               |
| ----------- | ------------------------------------- | ---------- | ---------------------------------------------------- |
| Unit        | `src/**` `#[cfg(test)]`               | ✅         | Codec round-trips, close-code table, handshake math  |
| Integration | `crates/*/tests/`                     | ✅         | Public API behavior against realistic byte input     |
| Doc tests   | rustdoc examples                      | ✅         | Documentation examples actually compile and behave   |
| Conformance | `crates/*/tests/` (RFC-derived cases) | Phase 3    | One test per RFC requirement row in the matrices     |
| Security    | `crates/*/tests/security_*.rs`        | Phase 3    | Each SEC-\* control holds under its abuse case       |
| End-to-end  | `crates/server/tests/`, real sockets  | Phase 3–4  | Keep-alive, upgrade flow, static files over real TCP |
| Fuzz        | `fuzz/` (`cargo-fuzz`)                | Phase 3–4  | Parser robustness on arbitrary bytes                 |

## Current inventory (19 tests)

`http` — integration (`crates/http/tests/http_tests.rs`):

| Test                             | Proves                                                          |
| -------------------------------- | --------------------------------------------------------------- |
| `test_http_request_parsing`      | Request line + headers parse; header lookup is case-insensitive |
| `test_websocket_request_parsing` | Upgrade headers survive parsing intact                          |
| `test_http_response_creation`    | Builder produces status line, headers, body                     |
| `test_http_method_parsing`       | All 9 methods round-trip through `FromStr`/`Display`            |
| `test_status_code_display`       | Codes render with correct reason phrases                        |

`websocket` — unit (`src/**`):

| Test                                                                    | Proves                                                |
| ----------------------------------------------------------------------- | ----------------------------------------------------- |
| `test_websocket_key_generation`                                         | Accept key matches the RFC 6455 §4.2.2 test vector    |
| `test_is_websocket_request_valid` / `test_is_websocket_request_invalid` | Handshake header validation accepts/rejects correctly |
| `test_frame_serialization`                                              | Text frame wire format (opcode byte, length, payload) |
| `test_close_frame` / `test_close_frame_with_code`                       | Close frame wire format                               |

`websocket` — integration (`crates/websocket/tests/websocket_tests.rs`):
`test_websocket_detection`, `test_websocket_frame_text_serialization`,
`test_websocket_frame_text_parsing`, `test_websocket_frame_close`,
`test_websocket_frame_close_with_code`, `test_websocket_frame_ping_pong` — frame
parse/serialize round-trips against the public API, including the
masked-client-frame requirement.

Doc tests: response building (`http`), RFC 6455 §5.7 masked-frame parsing
(`websocket`).

## Known gaps (honest list)

- The chunked body reader has **no test yet** (`body::read_chunked_body`).
- Header-cap rejection, keep-alive across requests, and the upgrade flow are
  only verified manually (see CI smoke step), not by automated tests.
- No security tests exist yet — they land with the controls in Phase 3.

## Naming conventions (Phase 3 onward)

- Security tests carry their control ID: `sec_http_003_rejects_cl_te_conflict`.
- RFC conformance tests carry the section:
  `rfc6455_s5_2_rejects_unmasked_frame`.
- Each security test gets a doc comment: control ID, RFC section, simulated
  attack, expected behavior. The IDs are greppable from
  [security/controls.md](security/controls.md) and back.

## Running

```bash
cargo test --workspace          # everything
cargo test -p websocket         # one crate
cargo test --doc                # doc tests only
```

Coverage expectations: the security phase targets line coverage of the parse
paths in `http` and `websocket` high enough that every compliance-matrix row has
at least one linked test; there is no global percentage gate.
