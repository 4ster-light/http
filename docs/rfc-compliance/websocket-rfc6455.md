# WebSocket compliance matrix — RFC 6455

Status legend: ✅ implemented · ⚠️ partial / deviates · ❌ not implemented.
Requirement levels (MUST/SHOULD/MAY) are from the RFC.

## Opening handshake (§4)

| §     | Requirement                                       | Level | Status | Implementation                    | Evidence / notes                                                                                         |
| ----- | ------------------------------------------------- | ----- | ------ | --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| 4.2.1 | Request must be `GET`                             | MUST  | ❌     | —                                 | **F11**: method not checked (SEC-WS-007)                                                                 |
| 4.2.1 | HTTP version ≥ 1.1                                | MUST  | ❌     | —                                 | **F11**: version not checked                                                                             |
| 4.2.1 | `Host` present                                    | MUST  | ❌     | —                                 | never inspected (see HTTP matrix)                                                                        |
| 4.2.1 | `Upgrade: websocket`                              | MUST  | ✅     | `handshake::is_websocket_request` | `test_is_websocket_request_valid/invalid`                                                                |
| 4.2.1 | `Connection: Upgrade`                             | MUST  | ✅     | `handshake::is_websocket_request` | case-insensitive substring match                                                                         |
| 4.2.1 | `Sec-WebSocket-Key`: base64 of 16 bytes           | MUST  | ⚠️     | presence checked                  | **F11**: format not verified (SEC-WS-007)                                                                |
| 4.2.1 | `Sec-WebSocket-Version: 13`                       | MUST  | ✅     | `handshake::is_websocket_request` | rejects other versions by non-match                                                                      |
| 4.2.2 | `101` response with `Upgrade`/`Connection`        | MUST  | ✅     | `handshake::generate_accept`      | live smoke test                                                                                          |
| 4.2.2 | `Sec-WebSocket-Accept = base64(SHA1(key + GUID))` | MUST  | ✅     | `handshake::generate_accept_key`  | `test_websocket_key_generation` (RFC vector)                                                             |
| 4.2.2 | `Sec-WebSocket-Protocol` only if supported        | MUST  | ✅     | —                                 | no subprotocol support; header never sent (compliant by omission)                                        |
| 4.2.2 | Unsupported extensions must not be accepted       | MUST  | ⚠️     | —                                 | `Sec-WebSocket-Extensions` ignored — no extension is ever enabled, but the request isn't rejected either |

## Frame protocol (§5)

| §           | Requirement                                                  | Level | Status | Implementation                            | Evidence / notes                                                          |
| ----------- | ------------------------------------------------------------ | ----- | ------ | ----------------------------------------- | ------------------------------------------------------------------------- |
| 5.2         | Frame format: FIN/RSV/opcode, mask bit, 7/16/64-bit lengths  | MUST  | ✅     | `frame::WebSocketFrame::parse`/`to_bytes` | `test_websocket_frame_text_parsing`, doc test                             |
| 5.2         | RSV bits are 0 unless an extension negotiates otherwise      | MUST  | ❌     | —                                         | **F6**: RSV ignored (SEC-WS-003)                                          |
| 5.2         | Unknown opcodes → fail the connection                        | MUST  | ⚠️     | `OpCode::from` maps unknown → `Close`     | connection closes, but no 1002 close frame sent                           |
| 5.2         | Most-significant bit of 64-bit length must be 0              | MUST  | ❌     | —                                         | not checked                                                               |
| 5.3         | Client frames MUST be masked; unmasked → fail                | MUST  | ✅     | `ParseError::UnmaskedClientFrame`         | TCP close w/o 1002 frame today (SEC-WS-001 adds it)                       |
| 5.4         | Fragmentation: reassemble continuation frames                | MUST  | ❌     | —                                         | **F4**: FIN untracked, continuations → `Incomplete` (SEC-WS-009, Phase 3) |
| 5.4         | Control frames may arrive mid-message and must be handled    | MUST  | ❌     | —                                         | blocked by F4                                                             |
| 5.5         | Control frames: payload ≤ 125 bytes                          | MUST  | ✅     | `ParseError::ControlFrameTooLarge`        | boundary tests planned (SEC-WS-004)                                       |
| 5.5         | Control frames MUST NOT be fragmented                        | MUST  | ❌     | —                                         | FIN untracked (SEC-WS-003)                                                |
| 5.5.1       | Close: reply close, then close the connection                | MUST  | ✅     | `connection::handle_websocket`            | manual + smoke                                                            |
| 5.5.2/5.5.3 | Ping → pong with identical payload; pongs may be unsolicited | MUST  | ✅     | connection loop                           | `test_websocket_frame_ping_pong`                                          |
| 6.1         | Invalid UTF-8 in text frames → fail (1007)                   | MUST  | ⚠️     | `ParseError::InvalidUtf8`                 | fails the connection but sends no 1007 (SEC-WS-005)                       |
| 7.1.6       | Close codes restricted to registered ranges                  | MUST  | ✅     | `is_valid_close_code`                     | invalid → parse error; 1002 close frame planned (SEC-WS-006)              |

## Liveness & robustness (implementation, beyond RFC)

| Behavior                                     | Status | Notes                                                                              |
| -------------------------------------------- | ------ | ---------------------------------------------------------------------------------- |
| Server ping every 30 s, close on missed pong | ✅     | close code 1002 ("Ping timeout") — SEC-WS-008 adds deterministic paused-time tests |
| Frame buffering across partial reads         | ✅     | `BytesMut` accumulate + consumed tracking                                          |
| Max data-frame size                          | ❌     | **F5**: unbounded (SEC-WS-002, close 1009)                                         |

## Security considerations (§10)

| §    | Requirement                                           | Level  | Status | Notes                                                                                |
| ---- | ----------------------------------------------------- | ------ | ------ | ------------------------------------------------------------------------------------ |
| 10.2 | Origin validation for browser clients                 | SHOULD | ❌     | accepted risk for the demo; see [../security/hardening.md](../security/hardening.md) |
| 10.3 | Masking makes traffic unpredictable to intermediaries | MUST   | ✅     | enforced (5.3 above)                                                                 |

## Summary

Core wire format, masking, control-frame size and close-code rules are in place.
The meaningful gaps are **fragmentation (F4)**, **frame validation depth
(F5/F6)** and **handshake validation depth (F11)** — all scheduled with controls
and tests in [../security/controls.md](../security/controls.md).
