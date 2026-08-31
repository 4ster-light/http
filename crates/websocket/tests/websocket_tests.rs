//! Integration tests for the `websocket` crate: handshake validation and
//! frame codec behavior on the public API.

use http::request::{HttpMethod, HttpRequest};
use std::collections::HashMap;
use websocket::{
    frame::{Frame, OpCode},
    handshake::{UpgradeCheck, validate_upgrade},
    limits::Limits,
};

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
    headers.insert(
        "sec-websocket-key".to_string(),
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
    );
    headers.insert("sec-websocket-version".to_string(), "13".to_string());
    headers.insert("upgrade".to_string(), "websocket".to_string());
    headers
}

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

#[test]
fn test_websocket_detection() {
    let request = request_with(HttpMethod::Get, "HTTP/1.1", valid_headers());
    assert!(matches!(validate_upgrade(&request), UpgradeCheck::Valid(_)));
}

#[test]
fn test_websocket_frame_text_serialization() {
    let frame = Frame::text("Hello, WebSocket!");
    let bytes = frame.to_bytes();

    // FIN + TEXT opcode in the first byte, no mask bit.
    assert_eq!(bytes[0], 0x81);
    assert_eq!(bytes[1] & 0x80, 0);
}

#[test]
fn test_websocket_frame_text_parsing() {
    // The masked "Hello" frame from RFC 6455 §5.7.
    let wire = [
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    let (frame, consumed) = Frame::parse(&wire, &Limits::default()).unwrap();
    assert_eq!(frame.opcode, OpCode::Text);
    assert!(frame.fin);
    assert_eq!(frame.payload, b"Hello");
    assert_eq!(consumed, wire.len());
}

#[test]
fn test_websocket_frame_close() {
    let frame = Frame::close();
    let bytes = frame.to_bytes();

    assert_eq!(bytes[0], 0x88);
    assert_eq!(bytes[1], 0);
}

#[test]
fn test_websocket_frame_close_with_code() {
    let frame = Frame::close_with_code(1000, "Normal");
    let bytes = frame.to_bytes();

    assert_eq!(bytes[0], 0x88);
    assert!(bytes.len() > 2);
}

#[test]
fn test_websocket_frame_ping_pong() {
    let ping_data = b"ping data".to_vec();
    let frame = Frame::ping(ping_data.clone());
    let bytes = frame.to_bytes();

    assert_eq!(bytes[0], 0x89);

    let wire = masked_frame(OpCode::Ping, true, &ping_data);
    let (parsed, _) = Frame::parse(&wire, &Limits::default()).unwrap();
    assert_eq!(parsed.opcode, OpCode::Ping);
    assert_eq!(parsed.payload, ping_data);
}

#[test]
fn test_extended_16_bit_length_round_trip() {
    let payload = vec![0xABu8; 300];
    let wire = masked_frame(OpCode::Binary, true, &payload);
    let (parsed, consumed) = Frame::parse(&wire, &Limits::default()).unwrap();
    assert_eq!(parsed.payload.len(), 300);
    assert_eq!(consumed, wire.len());
}

#[test]
fn test_invalid_upgrade_headers_rejected() {
    let mut headers = valid_headers();
    headers.insert("upgrade".to_string(), "http/1.1".to_string());
    let request = request_with(HttpMethod::Get, "HTTP/1.1", headers);
    // Wrong Upgrade value: not an upgrade request at all.
    assert!(matches!(
        validate_upgrade(&request),
        UpgradeCheck::NotUpgrade
    ));
}
