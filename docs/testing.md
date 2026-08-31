# Testing

## Strategy

Tests are layered so that each layer proves something the layer below cannot:

| Layer       | Where                                 | Runs today | Proves                                               |
| ----------- | ------------------------------------- | ---------- | ---------------------------------------------------- |
| Unit        | `src/**` `#[cfg(test)]`               | ✅         | Codec round-trips, close-code table, handshake math  |
| Integration | `crates/*/tests/`                     | ✅         | Public API behavior against realistic byte input     |
| Doc tests   | rustdoc examples                      | ✅         | Documentation examples compile and behave            |
| Conformance | `crates/*/tests/` (RFC-derived cases) | ✅         | One test per RFC requirement row in the matrices     |
| Security    | `crates/*/tests/security_*.rs`        | ✅         | Each SEC-\* control holds under its abuse case       |
| End-to-end  | `crates/server/tests/e2e.rs`          | ✅         | Real binary on real TCP: keep-alive, pipelining, upgrade, 4xx rejections |
| Fuzz        | `fuzz/` (`cargo-fuzz`)                | ✅         | Parser robustness on arbitrary bytes; 60 s CI smoke  |

## Current inventory (71 tests)

`http` integration (`crates/http/tests/http_tests.rs`, 5):
`test_http_request_parsing`, `test_websocket_request_parsing`,
`test_http_response_creation`, `test_http_method_parsing`,
`test_status_code_display`.

`http` security catalog (`crates/http/tests/security_http.rs`, 14):
`sec_http_001_head_bomb_rejected_with_431_status`,
`sec_http_001_head_at_limit_accepted`,
`sec_http_002_slowloris_head_read_times_out` (paused time),
`sec_http_003_rejects_cl_te_conflict`,
`sec_http_003_duplicate_content_length_rejected`,
`sec_http_004_oversized_body_rejected_with_413_status`,
`sec_http_004_chunked_body_over_cap_rejected`,
`sec_http_005_advertised_keep_alive_matches_limits_defaults`,
`sec_http_007_pipelined_requests_parse_in_sequence`,
`sec_http_007_post_body_consumed_from_buffer`,
`sec_http_007_post_body_over_duplex_completes`,
`sec_http_f7_http_1_0_defaults_to_close`, `sec_http_chunked_trailers_rejected`,
`sec_http_chunked_body_decodes`.

`websocket` unit tests (`src/**`, 7): `test_frame_serialization`,
`test_close_frame`, `test_close_frame_with_code`,
`test_websocket_key_generation`, `test_validate_upgrade_valid`,
`test_validate_upgrade_invalid_upgrade_header`,
`test_validate_upgrade_rejects_bad_key`.

`websocket` integration (`crates/websocket/tests/websocket_tests.rs`, 8):
frame codec round-trips (text, 16-bit extended length, close, ping/pong) plus
handshake detection on the public API.

`websocket` security catalog
(`crates/websocket/tests/security_websocket.rs`, 21):
`sec_ws_001_unmasked_frame_closes_1002`,
`sec_ws_002_oversized_announced_payload_rejected_before_buffering`,
`sec_ws_002_payload_at_limit_accepted`, `sec_ws_003_rsv_bits_rejected`,
`sec_ws_003_reserved_opcode_rejected`,
`sec_ws_003_fragmented_control_frame_rejected`,
`sec_ws_003_64bit_length_msb_rejected`,
`sec_ws_004_control_frame_boundary_125_126`,
`sec_ws_005_invalid_utf8_text_closes_1007`,
`sec_ws_005_invalid_utf8_fragmented_closes_1007`,
`sec_ws_006_invalid_close_codes_rejected`,
`sec_ws_007_handshake_requires_get`,
`sec_ws_007_handshake_requires_http_1_1`,
`sec_ws_007_handshake_requires_16_byte_base64_key`,
`sec_ws_007_handshake_requires_version_13`, `sec_ws_007_valid_handshake_passes`,
`sec_ws_008_ping_timeout_closes_1002` (paused time),
`sec_ws_009_fragmented_text_reassembled_and_echoed`,
`sec_ws_009_control_frame_interleaved_mid_message`,
`sec_ws_009_continuation_without_open_message_closes_1002`,
`sec_ws_009_new_data_frame_while_fragment_open_closes_1002`.

`server` end-to-end (`crates/server/tests/e2e.rs`, 14): spawns the real
binary on an ephemeral port (`SERVER_ADDR`) and speaks raw HTTP/1.1 and
WebSocket: static files, 404, POST echo (F1 over real sockets), sequential
keep-alive, pipelining, HTTP/1.0 close, traversal (plain and percent-encoded),
431 header bomb, 413 oversized body, 400 CL/TE conflict, 400 garbage request
line, upgrade with the RFC accept vector plus echo and close handshake, and
400 on a malformed key.

Doc tests: response building (`http`), RFC 6455 §5.7 masked-frame parsing
(`websocket`).

## Determinism techniques

- `tokio::io::duplex` drives the connection loops without real sockets
  (`sec_http_007_post_body_over_duplex_completes`, the SEC-WS-009 scenarios).
- `#[tokio::test(start_paused = true)]` makes timeouts exact: the Slow-Loris
  timeout and the WS liveness close run in milliseconds of wall time while
  the code sees full seconds (`sec_http_002_*`, `sec_ws_008_*`).
- The e2e suite allocates ports from one per-process counter so parallel
  tests never collide on a bind (the server fails fast on conflicts by
  design, ADR-0008).

## Naming conventions

- Security tests carry their control ID: `sec_http_003_rejects_cl_te_conflict`.
- RFC conformance tests carry the section:
  `rfc6455_s5_2_rejects_unmasked_frame` (the 003/005/009 security tests double
  as conformance tests; the matrices link to them).
- Each security test has a doc comment with control ID, RFC section, simulated
  attack, and expected behavior. IDs are greppable from
  [security/controls.md](security/controls.md) and back.

## Running

```bash
cargo test --workspace          # everything
cargo test -p websocket         # one crate
cargo test --doc                # doc tests only
cargo +nightly fuzz run request_head_parse -- -max_total_time=60   # fuzz smoke
```

Coverage expectations: every compliance-matrix row has at least one linked
test on the in-scope rows; the declared out-of-scope rows are documented
rather than tested. There is no global percentage gate.
