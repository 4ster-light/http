# WebSocket compliance matrix: RFC 6455

Status legend: ✅ implemented · ⚠️ partial / deviates · ❌ not implemented.
Requirement levels (MUST/SHOULD/MAY) come from the RFC. After the Phase 3
hardening the frame protocol is fully compliant; the remaining gaps are
handshake-adjacent (Host/Origin) and are declared, not hidden.

## Opening handshake (§4)

| §     | Requirement                                       | Level | Status | Implementation                    | Evidence / tests                                                                                   |
| ----- | ------------------------------------------------- | ----- | ------ | --------------------------------- | -------------------------------------------------------------------------------------------------- |
| 4.2.1 | Request must be `GET`                             | MUST  | ✅     | `handshake::validate_upgrade`     | `sec_ws_007_handshake_requires_get`                                                                 |
| 4.2.1 | HTTP version ≥ 1.1                                | MUST  | ✅     | `handshake::validate_upgrade`     | `sec_ws_007_handshake_requires_http_1_1`                                                             |
| 4.2.1 | `Host` header present                             | MUST  | ❌     |                                   | never inspected (future work; HTTP matrix shares the gap)                                            |
| 4.2.1 | `Upgrade: websocket`                              | MUST  | ✅     | `handshake::validate_upgrade`     | `test_websocket_detection`                                                                           |
| 4.2.1 | `Connection: Upgrade`                             | MUST  | ✅     | `handshake::validate_upgrade`     | case-insensitive substring match                                                                     |
| 4.2.1 | `Sec-WebSocket-Key`: base64 of 16 bytes           | MUST  | ✅     | decoded and length-checked        | `sec_ws_007_handshake_requires_16_byte_base64_key`                                                   |
| 4.2.1 | `Sec-WebSocket-Version: 13`                       | MUST  | ✅     | `handshake::validate_upgrade`     | `sec_ws_007_handshake_requires_version_13`                                                           |
| 4.2.1 | Failed handshake answered with an HTTP error      | MUST  | ✅     | server writes `400` for `UpgradeCheck::Invalid` | e2e `e2e_websocket_invalid_key_400`                                                     |
| 4.2.2 | `101` response with `Upgrade`/`Connection`        | MUST  | ✅     | `handshake::generate_accept`      | e2e `e2e_websocket_upgrade_echo_close`                                                               |
| 4.2.2 | `Sec-WebSocket-Accept = base64(SHA1(key + GUID))` | MUST  | ✅     | `handshake::generate_accept_key`  | `test_websocket_key_generation` (RFC vector); e2e accept-header check                                |
| 4.2.2 | `Sec-WebSocket-Protocol` only if supported        | MUST  | ✅     | header never sent                 | no subprotocol support (compliant by omission)                                                       |
| 4.2.2 | Unsupported extensions must not be accepted       | MUST  | ✅     | no extension is ever negotiated; RSV≠0 frames are rejected as protocol violations | `sec_ws_003_rsv_bits_rejected`                                                        |

## Frame protocol (§5)

| §           | Requirement                                                  | Level | Status | Implementation                         | Evidence / tests                                                              |
| ----------- | ------------------------------------------------------------ | ----- | ------ | -------------------------------------- | ---------------------------------------------------------------------------- |
| 5.2         | Frame format: FIN/RSV/opcode, mask bit, 7/16/64-bit lengths  | MUST  | ✅     | `frame::Frame::parse`/`to_bytes`       | `test_websocket_frame_text_parsing`, `test_extended_16_bit_length_round_trip`, doc test |
| 5.2         | RSV bits are 0 unless an extension negotiates otherwise      | MUST  | ✅     | RSV≠0 rejected                         | `sec_ws_003_rsv_bits_rejected`                                               |
| 5.2         | Unknown opcodes fail the connection                          | MUST  | ✅     | reserved opcodes rejected (close 1002) | `sec_ws_003_reserved_opcode_rejected`                                        |
| 5.2         | Most-significant bit of 64-bit length must be 0              | MUST  | ✅     | MSB check in `Frame::parse`            | `sec_ws_003_64bit_length_msb_rejected`                                       |
| 5.3         | Client frames MUST be masked; unmasked input fails           | MUST  | ✅     | `ParseError::UnmaskedClientFrame` → close 1002 | `sec_ws_001_unmasked_frame_closes_1002`                              |
| 5.4         | Fragmentation: reassemble continuation frames                | MUST  | ✅     | reassembly state machine in `websocket::connection` | `sec_ws_009_fragmented_text_reassembled_and_echoed`          |
| 5.4         | Control frames may arrive mid-message and are handled        | MUST  | ✅     | control frames processed immediately   | `sec_ws_009_control_frame_interleaved_mid_message`                           |
| 5.4         | Continuation without an open message fails                   | MUST  | ✅     | state machine rejects (close 1002)     | `sec_ws_009_continuation_without_open_message_closes_1002`                   |
| 5.4         | New data frame while a message is open fails                 | MUST  | ✅     | state machine rejects (close 1002)     | `sec_ws_009_new_data_frame_while_fragment_open_closes_1002`                  |
| 5.5         | Control frames: payload ≤ 125 bytes                          | MUST  | ✅     | `ParseError::ControlFrameTooLarge`     | `sec_ws_004_control_frame_boundary_125_126`                                  |
| 5.5         | Control frames MUST NOT be fragmented                        | MUST  | ✅     | FIN=0 on control frames rejected       | `sec_ws_003_fragmented_control_frame_rejected`                               |
| 5.5.1       | Close: reply close, then close the connection                | MUST  | ✅     | `websocket::connection` loop           | e2e `e2e_websocket_upgrade_echo_close`                                       |
| 5.5.2/5.5.3 | Ping gets a pong with identical payload                      | MUST  | ✅     | `handle_control`                       | e2e echo; `sec_ws_009_control_frame_interleaved_mid_message`                 |
| 5.6         | Text messages are valid UTF-8 (checked per message)          | MUST  | ✅     | UTF-8 validated after reassembly       | `sec_ws_005_invalid_utf8_fragmented_closes_1007`                             |

## Data-size and liveness controls (implementation hardening)

| Behavior                                                  | Status | Notes                                                                 |
| --------------------------------------------------------- | ------ | --------------------------------------------------------------------- |
| Max data-frame payload (close 1009 before buffering)      | ✅     | `Limits::max_frame_payload` (F5 fixed); `sec_ws_002_*`                |
| Max reassembled message size (close 1009)                 | ✅     | `Limits::max_message_bytes` (SEC-WS-009)                              |
| Frame buffering across partial reads                      | ✅     | `BytesMut` accumulate + consumed tracking                             |
| Server ping every 30 s, close 1002 on missed pong         | ✅     | first tick deferred one interval (F10); `sec_ws_008_ping_timeout_closes_1002` |
| Protocol failures answered with close frames (1002/1007/1009) | ✅ | `close_for_parse_error` mapping (F6/F8 fixed)                         |

## Security considerations (§10)

| §    | Requirement                                           | Level  | Status | Notes                                                                                |
| ---- | ----------------------------------------------------- | ------ | ------ | ------------------------------------------------------------------------------------ |
| 10.2 | Origin validation for browser clients                 | SHOULD | ❌     | accepted risk for the demo; see [../security/hardening.md](../security/hardening.md) |
| 10.3 | Masking makes traffic unpredictable to intermediaries | MUST   | ✅     | enforced (§5.3 above)                                                                |
| 10.x | Frame-size limits protect against resource exhaustion | MUST   | ✅     | SEC-WS-002/009 with `Limits` caps                                                    |

## Summary

Every in-scope MUST/SHOULD of the frame protocol (§5) and the message
semantics (§6) is implemented with a linked test; the close handshake and
liveness behavior are covered end-to-end. The declared gaps are handshake
`Host` checking and browser `Origin` validation (§10.2); both are future
work recorded here and in the threat model.
