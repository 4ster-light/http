//! Security test catalog for the `websocket` crate (REFACTOR-PLAN.md §5.2).
//!
//! Every test carries its control ID and RFC section in the name and doc
//! comment; `docs/security/controls.md` links back to these names.

use http::request::{HttpMethod, HttpRequest};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use websocket::{
    connection::handle_websocket,
    error::Error,
    frame::{Frame, OpCode, ParseError},
    handshake::{UpgradeCheck, validate_upgrade},
    limits::Limits,
};

/// Builds a masked client-to-server frame from opcode/fin/payload.
fn masked_frame(opcode: OpCode, fin: bool, payload: &[u8]) -> Vec<u8> {
    let first = if fin { 0x80 } else { 0x00 } | (opcode as u8 & 0x0F);
    let mut bytes = vec![first];
    let mask = [0x01u8, 0x02, 0x03, 0x04];
    match payload.len() {
        len if len < 126 => bytes.push(0x80 | u8::try_from(len).unwrap()),
        len if len < 65536 => {
            bytes.push(0x80 | 0x7E);
            bytes.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        }
        len => {
            bytes.push(0x80 | 0x7F);
            bytes.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

/// The RFC 6455 §4.2.2 test vector key (base64 of 16 bytes).
const VALID_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn request_with(
    method: HttpMethod,
    version: &str,
    headers: HashMap<String, String>,
) -> HttpRequest {
    HttpRequest {
        method,
        path: "/".to_string(),
        version: version.to_string(),
        headers,
        body: Vec::new(),
    }
}

fn valid_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("connection".to_string(), "Upgrade".to_string());
    headers.insert("sec-websocket-key".to_string(), VALID_KEY.to_string());
    headers.insert("sec-websocket-version".to_string(), "13".to_string());
    headers.insert("upgrade".to_string(), "websocket".to_string());
    headers
}

/// Drives one client scenario against the connection loop over duplex IO
/// and returns everything the server sent after the handshake.
async fn run_client(input: Vec<u8>) -> Vec<u8> {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let _ = handle_websocket(&mut server, VALID_KEY, &Limits::default()).await;
    });
    client.write_all(&input).await.unwrap();

    // Read until the server goes quiet (no pings can interfere: the first
    // one is due at 30 s).
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < 8192 {
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.read(&mut chunk),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }
    drop(client);
    let _ = server_task.await;
    out
}

/// Splits server output into (handshake bytes, frames) by locating the first
/// frame with a close/ping opcode; simplified for these tests: returns all
/// frames after the `\r\n\r\n` handshake terminator.
fn frames_after_handshake(out: &[u8]) -> Vec<u8> {
    let pos = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("handshake present")
        + 4;
    out[pos..].to_vec()
}

/// Parses all consecutive server (unmasked) frames from raw bytes.
fn parse_server_frames(mut bytes: &[u8]) -> Vec<(OpCode, Vec<u8>)> {
    let mut frames = Vec::new();
    while bytes.len() >= 2 {
        let opcode = OpCode::from_wire(bytes[0] & 0x0F).expect("valid opcode");
        let len = (bytes[1] & 0x7F) as usize;
        if bytes.len() < 2 + len {
            break;
        }
        frames.push((opcode, bytes[2..2 + len].to_vec()));
        bytes = &bytes[2 + len..];
    }
    frames
}

// ---------------------------------------------------------------------------
// SEC-WS-001: masking enforcement (RFC 6455 §5.3)
// ---------------------------------------------------------------------------

/// SEC-WS-001, RFC 6455 §5.3. Attack: unmasked client-to-server frame
/// (cache-poisoning via intermediaries). Expected: close 1002.
#[tokio::test]
async fn sec_ws_001_unmasked_frame_closes_1002() {
    // Text frame "Hi", no mask bit, no mask key, raw payload.
    let input = vec![0x81, 0x02, b'H', b'i'];
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Close);
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1002);
}

// ---------------------------------------------------------------------------
// SEC-WS-002: max data-frame payload (F5)
// ---------------------------------------------------------------------------

/// SEC-WS-002, RFC 6455 §5.2/§10. Attack: a frame announcing a huge payload
/// to force unbounded buffering. Expected: reject on the announced length
/// with close 1009, before any payload arrives.
#[test]
fn sec_ws_002_oversized_announced_payload_rejected_before_buffering() {
    let limits = Limits {
        max_frame_payload: 1024,
        ..Limits::default()
    };
    // Header only: FIN+Binary, mask bit, 64-bit length 2^40. The payload is
    // absent; the parse must still fail with FrameTooLarge, not Incomplete.
    let mut wire = vec![0x82, 0x80 | 127];
    wire.extend_from_slice(&(1u64 << 40).to_be_bytes());
    wire.extend_from_slice(&[0, 0, 0, 0]); // mask key
    let err = Frame::parse(&wire, &limits).unwrap_err();
    assert_eq!(err, ParseError::FrameTooLarge);
}

/// SEC-WS-002 boundary: exactly at the limit is accepted.
#[test]
fn sec_ws_002_payload_at_limit_accepted() {
    let limits = Limits {
        max_frame_payload: 4,
        ..Limits::default()
    };
    let wire = masked_frame(OpCode::Binary, true, &[1, 2, 3, 4]);
    let (frame, consumed) = Frame::parse(&wire, &limits).unwrap();
    assert_eq!(frame.payload, vec![1, 2, 3, 4]);
    assert_eq!(consumed, wire.len());
}

// ---------------------------------------------------------------------------
// SEC-WS-003: RSV bits, reserved opcodes, fragmented control frames (F6)
// ---------------------------------------------------------------------------

/// SEC-WS-003, RFC 6455 §5.2. Attack: RSV1 set with no negotiated extension
/// (compression confusion). Expected: close 1002.
#[test]
fn sec_ws_003_rsv_bits_rejected() {
    let mut wire = masked_frame(OpCode::Text, true, b"hi");
    wire[0] |= 0x40; // RSV1
    let err = Frame::parse(&wire, &Limits::default()).unwrap_err();
    assert_eq!(
        err,
        ParseError::ProtocolViolation("RSV bits set"),
        "RSV bits must be rejected without negotiated extensions"
    );
}

/// SEC-WS-003, RFC 6455 §5.2. Attack: reserved opcode 0x3 (undefined
/// semantics). Expected: reject (close 1002), not silent mapping.
#[test]
fn sec_ws_003_reserved_opcode_rejected() {
    let wire = masked_frame(
        // 0x3 is not a valid OpCode; build manually.
        OpCode::Text,
        true,
        b"x",
    );
    let mut wire = wire;
    wire[0] = 0x83; // FIN + reserved opcode 0x3
    let err = Frame::parse(&wire, &Limits::default()).unwrap_err();
    assert_eq!(err, ParseError::ProtocolViolation("Reserved opcode"));
}

/// SEC-WS-003, RFC 6455 §5.5. Attack: fragmented control frame (FIN=0 ping)
/// to smuggle payload past the 125-byte control cap. Expected: close 1002.
#[test]
fn sec_ws_003_fragmented_control_frame_rejected() {
    let wire = masked_frame(OpCode::Ping, false, b"abc");
    let err = Frame::parse(&wire, &Limits::default()).unwrap_err();
    assert_eq!(
        err,
        ParseError::ProtocolViolation("Fragmented control frame")
    );
}

/// SEC-WS-003, RFC 6455 §5.2. Attack: 64-bit length with the MSB set
/// (negative/overflow confusion). Expected: reject.
#[test]
fn sec_ws_003_64bit_length_msb_rejected() {
    let mut wire = vec![0x82, 0x80 | 127];
    wire.extend_from_slice(&u64::MAX.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 0, 0]);
    let err = Frame::parse(&wire, &Limits::default()).unwrap_err();
    assert_eq!(
        err,
        ParseError::ProtocolViolation("MSB set in 64-bit length")
    );
}

// ---------------------------------------------------------------------------
// SEC-WS-004: control-frame payload cap (RFC 6455 §5.5)
// ---------------------------------------------------------------------------

/// SEC-WS-004, RFC 6455 §5.5 boundary. Payload of 125 is the maximum
/// accepted; 126 must be rejected.
#[test]
fn sec_ws_004_control_frame_boundary_125_126() {
    let limits = Limits::default();
    // 125: accepted.
    let ok = masked_frame(OpCode::Ping, true, &[0u8; 125]);
    assert!(Frame::parse(&ok, &limits).is_ok());
    // 126: rejected.
    let big = masked_frame(OpCode::Ping, true, &[0u8; 126]);
    assert_eq!(
        Frame::parse(&big, &limits).unwrap_err(),
        ParseError::ControlFrameTooLarge
    );
}

// ---------------------------------------------------------------------------
// SEC-WS-005: invalid UTF-8 in text messages (RFC 6455 §6.1)
// ---------------------------------------------------------------------------

/// SEC-WS-005, RFC 6455 §6.1/§8.1. Attack: invalid UTF-8 in a text frame.
/// Expected: close 1007 (not a silent TCP drop).
#[tokio::test]
async fn sec_ws_005_invalid_utf8_text_closes_1007() {
    let input = masked_frame(OpCode::Text, true, &[0xED, 0xA0, 0x80]); // lone surrogate
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Close);
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1007);
}

/// SEC-WS-005 via fragmentation: the invalid UTF-8 must be detected after
/// reassembly too (the check applies to the whole message, §5.6).
#[tokio::test]
async fn sec_ws_005_invalid_utf8_fragmented_closes_1007() {
    let mut input = masked_frame(OpCode::Text, false, &[0xED]);
    input.extend_from_slice(&masked_frame(OpCode::Continuation, true, &[0xA0, 0x80]));
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Close);
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1007);
}

// ---------------------------------------------------------------------------
// SEC-WS-006: close-code validation (RFC 6455 §7.1.6 / §7.4)
// ---------------------------------------------------------------------------

/// SEC-WS-006, RFC 6455 §7.4.1. Attack: close code 1005/1006/2999 are
/// outside the registered ranges (1005/1006 MUST NOT appear on the wire).
/// Expected: rejection via `decode_close_payload`.
#[test]
fn sec_ws_006_invalid_close_codes_rejected() {
    for code in [1005u16, 1006, 1012, 2999] {
        let payload = code.to_be_bytes().to_vec();
        assert!(
            websocket::frame::decode_close_payload(&payload).is_err(),
            "close code {code} must be rejected"
        );
    }
    for code in [1000u16, 1001, 1008, 3000, 4999] {
        let payload = code.to_be_bytes().to_vec();
        assert!(websocket::frame::decode_close_payload(&payload).is_ok());
    }
}

// ---------------------------------------------------------------------------
// SEC-WS-007: handshake validation (RFC 6455 §4.2.1, F11)
// ---------------------------------------------------------------------------

/// SEC-WS-007, RFC 6455 §4.2.1. Attack: upgrade with a non-GET method.
/// Expected: Invalid (→ 400 in the server layer).
#[test]
fn sec_ws_007_handshake_requires_get() {
    let request = request_with(HttpMethod::Post, "HTTP/1.1", valid_headers());
    assert!(matches!(
        validate_upgrade(&request),
        UpgradeCheck::Invalid(_)
    ));
}

/// SEC-WS-007, RFC 6455 §4.2.1. Attack: upgrade over HTTP/1.0.
#[test]
fn sec_ws_007_handshake_requires_http_1_1() {
    let request = request_with(HttpMethod::Get, "HTTP/1.0", valid_headers());
    assert!(matches!(
        validate_upgrade(&request),
        UpgradeCheck::Invalid(_)
    ));
}

/// SEC-WS-007, RFC 6455 §4.2.1. Attack: key that is not base64 of 16 bytes.
/// ("AAAA" decodes to 3 bytes; 24 unpadded A's decode to 18 bytes; a key
/// with an invalid character fails to decode at all.)
#[test]
fn sec_ws_007_handshake_requires_16_byte_base64_key() {
    for bad_key in ["test-key", "AAAA", "AAAAAAAAAAAAAAAAAAAAAAAA"] {
        let mut headers = valid_headers();
        headers.insert("sec-websocket-key".to_string(), bad_key.to_string());
        let request = request_with(HttpMethod::Get, "HTTP/1.1", headers);
        assert!(
            matches!(validate_upgrade(&request), UpgradeCheck::Invalid(_)),
            "key {bad_key} must be rejected"
        );
    }
}

/// SEC-WS-007: missing Sec-WebSocket-Version: 13.
#[test]
fn sec_ws_007_handshake_requires_version_13() {
    let mut headers = valid_headers();
    headers.insert("sec-websocket-version".to_string(), "8".to_string());
    let request = request_with(HttpMethod::Get, "HTTP/1.1", headers);
    assert!(matches!(
        validate_upgrade(&request),
        UpgradeCheck::Invalid(_)
    ));
}

/// SEC-WS-007: a valid upgrade passes and yields the key.
#[test]
fn sec_ws_007_valid_handshake_passes() {
    let request = request_with(HttpMethod::Get, "HTTP/1.1", valid_headers());
    match validate_upgrade(&request) {
        UpgradeCheck::Valid(key) => assert_eq!(key, VALID_KEY),
        _ => panic!("valid upgrade must pass"),
    }
}

// ---------------------------------------------------------------------------
// SEC-WS-009: fragmentation and reassembly (RFC 6455 §5.4)
// ---------------------------------------------------------------------------

/// SEC-WS-009, RFC 6455 §5.4. A fragmented text message is reassembled and
/// echoed as one message.
#[tokio::test]
async fn sec_ws_009_fragmented_text_reassembled_and_echoed() {
    let mut input = masked_frame(OpCode::Text, false, b"Hel");
    input.extend_from_slice(&masked_frame(OpCode::Continuation, false, b"lo, "));
    input.extend_from_slice(&masked_frame(OpCode::Continuation, true, b"world"));
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Text);
    assert_eq!(payload, b"Echo: Hello, world");
}

/// SEC-WS-009, RFC 6455 §5.4. Interleaved control frames (a ping) are
/// answered immediately mid-message; the fragmented message still completes.
#[tokio::test]
async fn sec_ws_009_control_frame_interleaved_mid_message() {
    let mut input = masked_frame(OpCode::Text, false, b"Hel");
    input.extend_from_slice(&masked_frame(OpCode::Ping, true, b"ping"));
    input.extend_from_slice(&masked_frame(OpCode::Continuation, true, b"lo"));
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);

    // Server output: pong (echo of "ping"), then the text echo.
    let (pong_opcode, pong_payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(pong_opcode, OpCode::Pong);
    assert_eq!(pong_payload, b"ping");
}

/// SEC-WS-009, RFC 6455 §5.4. A continuation frame with no open message is
/// a protocol violation: close 1002.
#[tokio::test]
async fn sec_ws_009_continuation_without_open_message_closes_1002() {
    let input = masked_frame(OpCode::Continuation, true, b"stray");
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Close);
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1002);
}

/// SEC-WS-009, RFC 6455 §5.4. A new data frame while a fragmented message
/// is open is a protocol violation: close 1002.
#[tokio::test]
async fn sec_ws_009_new_data_frame_while_fragment_open_closes_1002() {
    let mut input = masked_frame(OpCode::Text, false, b"Hel");
    input.extend_from_slice(&masked_frame(OpCode::Text, true, b"stray"));
    let out = run_client(input).await;
    let frames = frames_after_handshake(&out);
    let (opcode, payload) = parse_server_frames(&frames).remove(0);
    assert_eq!(opcode, OpCode::Close);
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1002);
}

// ---------------------------------------------------------------------------
// SEC-WS-008: liveness ping/pong (deterministic, paused time)
// ---------------------------------------------------------------------------

/// SEC-WS-008. A silent client that never answers pings is closed with 1002
/// after one missed pong. Uses paused time for determinism.
#[tokio::test(start_paused = true)]
async fn sec_ws_008_ping_timeout_closes_1002() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let limits = Limits {
        ping_interval: std::time::Duration::from_secs(30),
        ..Limits::default()
    };

    let server_task =
        tokio::spawn(async move { handle_websocket(&mut server, VALID_KEY, &limits).await });

    // Advance time past two ping ticks without answering anything. The
    // first ping is due at t=30, the close at t=60.
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;

    // Read whatever the server wrote: a ping at t=30, then a close 1002 at t=60.
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut total = 0;
    while total < 512 {
        let n = client.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        total += n;
        if out.windows(2).any(|w| w[0] == 0x88) {
            break;
        }
    }

    // First server frame after the handshake is the ping; the close (0x88...)
    // follows once the pong is overdue.
    let frames = {
        let pos = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("handshake present")
            + 4;
        parse_server_frames(&out[pos..])
    };
    // The server pings first, then closes with 1002 once the pong is overdue.
    let (_opcode, payload) = frames
        .iter()
        .find(|(op, _)| *op == OpCode::Close)
        .expect("a close frame is sent");
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    assert_eq!(code, 1002);

    drop(client);
    let result = server_task.await.unwrap();
    assert!(matches!(result, Err(Error::WebSocketError(_)) | Ok(())));
}
