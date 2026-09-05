# Security controls catalog

Every control has an ID, a threat reference
([threat-model.md](threat-model.md)), an implementation pointer, and a test
pointer. Status values:

- **In place**: implemented and enforced.
- **Partial**: a mechanism exists but deviates from the target behavior.

Test names live in `crates/http/tests/security_http.rs`,
`crates/websocket/tests/security_websocket.rs`, and
`crates/server/tests/e2e.rs`; every name is greppable.

## HTTP controls

| ID           | Control                                                               | Threat                   | Status   | Implementation                                                                 | Tests                                                                       |
| ------------ | --------------------------------------------------------------------- | ------------------------ | -------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| SEC-HTTP-001 | Header-size cap, `431` + close                                        | Header bomb (F8)         | In place | `http::limits::Limits::max_head_bytes`, `http::request::HttpRequest::parse`    | `sec_http_001_head_bomb_rejected_with_431_status`, `sec_http_001_head_at_limit_accepted`, e2e `e2e_header_bomb_431` |
| SEC-HTTP-002 | Head read timeout (10 s) + keep-alive idle timeout                    | Slow-Loris (F2)          | In place | `http::connection::read_request` (tokio timeouts)                              | `sec_http_002_slowloris_head_read_times_out` (paused time)                   |
| SEC-HTTP-003 | Reject `Content-Length` + `Transfer-Encoding` together                | Request smuggling (F4)   | In place | `HttpRequest::parse` rejects the combination per RFC 9112 §6.3                 | `sec_http_003_rejects_cl_te_conflict`, `sec_http_003_duplicate_content_length_rejected`, e2e `e2e_cl_te_conflict_400` |
| SEC-HTTP-004 | Body-size cap, `413`                                                  | Memory exhaustion        | In place | `Limits::max_body_bytes` (Content-Length and chunked paths)                    | `sec_http_004_oversized_body_rejected_with_413_status`, `sec_http_004_chunked_body_over_cap_rejected`, e2e `e2e_oversized_body_413` |
| SEC-HTTP-005 | Keep-alive idle timeout + max requests, matching the advertisement    | Connection hoarding (F3) | In place | `server::connection` loop + `Limits` (ADR-0007); `Keep-Alive` header derived from the same limits | `sec_http_005_advertised_keep_alive_matches_limits_defaults`, e2e `e2e_keep_alive_sequential_requests` |
| SEC-HTTP-006 | Path traversal protection, canonical-path read                        | Arbitrary file read (F10)| In place | `server::handler` percent-decodes, canonicalizes, prefix-checks, and reads the canonical path | e2e `e2e_path_traversal_rejected`, `e2e_encoded_path_traversal_rejected`     |
| SEC-HTTP-007 | Buffer ownership: no discarded bytes, pipelining safe                 | Framing desync (F1, P0)  | In place | `http::connection::read_request` over one persistent `BytesMut` (ADR-0005)     | `sec_http_007_pipelined_requests_parse_in_sequence`, `sec_http_007_post_body_consumed_from_buffer`, `sec_http_007_post_body_over_duplex_completes`, e2e `e2e_post_echo_same_segment_body`, `e2e_pipelined_requests_answered_in_order` |
| SEC-HTTP-008 | Malformed requests answered with mapped 4xx/5xx responses             | Silent error paths (F8)  | In place | `http::Error::status()` maps errors to status codes; `server::connection` writes the response before closing | e2e `e2e_garbage_request_line_400`                                           |

## WebSocket controls

| ID         | Control                                                                                | Threat                       | Status   | Implementation                                                     | Tests                                                                                     |
| ---------- | -------------------------------------------------------------------------------------- | ---------------------------- | -------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| SEC-WS-001 | Masking enforcement with close 1002                                                    | Intermediary cache poisoning | In place | `frame::ParseError::UnmaskedClientFrame` answered with close 1002   | `sec_ws_001_unmasked_frame_closes_1002`                                                     |
| SEC-WS-002 | Max data-frame payload (1 MiB default, configurable)                                   | Memory exhaustion (F5)       | In place | `websocket::limits::Limits::max_frame_payload`, rejected on the announced length before buffering | `sec_ws_002_oversized_announced_payload_rejected_before_buffering`, `sec_ws_002_payload_at_limit_accepted` |
| SEC-WS-003 | Reject RSV≠0, reserved opcodes, fragmented control frames, 64-bit MSB length           | Protocol confusion (F6)      | In place | strict checks in `frame::Frame::parse`                              | `sec_ws_003_rsv_bits_rejected`, `sec_ws_003_reserved_opcode_rejected`, `sec_ws_003_fragmented_control_frame_rejected`, `sec_ws_003_64bit_length_msb_rejected` |
| SEC-WS-004 | Control frames ≤ 125 B                                                                 | Protocol violation           | In place | `ParseError::ControlFrameTooLarge`                                  | `sec_ws_004_control_frame_boundary_125_126`                                                 |
| SEC-WS-005 | Invalid UTF-8 in text messages answered with close 1007                                | Protocol violation           | In place | UTF-8 validated at message assembly (also after reassembly)         | `sec_ws_005_invalid_utf8_text_closes_1007`, `sec_ws_005_invalid_utf8_fragmented_closes_1007` |
| SEC-WS-006 | Close-code validation                                                                  | Protocol violation           | In place | `frame::decode_close_payload` rejects unregistered codes            | `sec_ws_006_invalid_close_codes_rejected`                                                   |
| SEC-WS-007 | Full handshake validation (GET, HTTP/1.1+, key = base64 of 16 bytes)                   | Malformed upgrade (F11)      | In place | `handshake::validate_upgrade` with `UpgradeCheck`; server answers `400` | `sec_ws_007_handshake_requires_get`, `sec_ws_007_handshake_requires_http_1_1`, `sec_ws_007_handshake_requires_16_byte_base64_key`, `sec_ws_007_handshake_requires_version_13`, e2e `e2e_websocket_invalid_key_400` |
| SEC-WS-008 | Ping/pong liveness timeout                                                             | Silent-connection hoarding   | In place | ping ticker (first tick deferred, F10) with close 1002 on missed pong | `sec_ws_008_ping_timeout_closes_1002` (paused time, deterministic)                          |
| SEC-WS-009 | Fragmentation: continuation reassembly, interleaved control frames, strict state rules | RFC 6455 §5.4 (F4)           | In place | reassembly state machine in `websocket::connection`                 | `sec_ws_009_fragmented_text_reassembled_and_echoed`, `sec_ws_009_control_frame_interleaved_mid_message`, `sec_ws_009_continuation_without_open_message_closes_1002`, `sec_ws_009_new_data_frame_while_fragment_open_closes_1002` |

## Notes

- Parse errors no longer drop connections silently: the connection layer
  translates them into the correct protocol response once (`4xx` for HTTP,
  1002/1007/1009 for WebSocket) and every control reuses that path.
- Configurable limits are the typed `Limits` structs of ADR-0006; defaults
  match what the server advertises.
- Fuzzing backs the parser invariants: see
  [fuzzing.md](fuzzing.md) for the harnesses that run in CI.

## Live demos (G4)

Three controls have runnable, human-visible demos under `container/demos/`
(ADR-0009): they print EXPECTED vs OBSERVED and exit non-zero if the
mitigation does not hold.

| Demo                   | Control      | Run                                                  |
| ---------------------- | ------------ | ---------------------------------------------------- |
| `slowloris.py`         | SEC-HTTP-002 | `just demo slowloris` / `just demo-container slowloris` |
| `header_bomb.py`       | SEC-HTTP-001 | `just demo header_bomb` / `just demo-container header_bomb` |
| `unmasked_frames.py`   | SEC-WS-001   | `just demo unmasked_frames` / `just demo-container unmasked_frames` |
