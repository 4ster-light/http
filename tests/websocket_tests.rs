use http::{
    protocol::request::{HttpMethod, HttpRequest},
    websocket::{frame::WebSocketFrame, handshake::is_websocket_request},
};
use std::collections::HashMap;

#[test]
fn test_websocket_detection() {
    let mut headers = HashMap::new();
    headers.insert("upgrade".to_string(), "websocket".to_string());
    headers.insert("connection".to_string(), "Upgrade".to_string());
    headers.insert("sec-websocket-key".to_string(), "test-key".to_string());
    headers.insert("sec-websocket-version".to_string(), "13".to_string());

    let request = HttpRequest {
        method: HttpMethod::Get,
        path: "/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers,
        body: Vec::new(),
    };

    assert!(is_websocket_request(&request).is_some());
}

#[test]
fn test_websocket_frame_text_serialization() {
    let text_frame = WebSocketFrame::Text("Hello, WebSocket!".to_string());
    let bytes = text_frame.to_bytes();

    // Should start with 0x81 (FIN + TEXT opcode)
    assert_eq!(bytes[0], 0x81);
    // Server frames are not masked
    assert_eq!(bytes[1] & 0x80, 0);
}

#[test]
fn test_websocket_frame_text_parsing() {
    // Create a masked client-to-server text frame manually
    let text = "Hello";
    let mut frame = vec![
        0x81,     // FIN + TEXT
        0x80 | 5, // MASK + length 5
        0x01,
        0x02,
        0x03,
        0x04, // Mask key
    ];

    // Mask the payload
    let mask = [0x01, 0x02, 0x03, 0x04];
    for (i, byte) in text.bytes().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }

    let (parsed_frame, consumed) = WebSocketFrame::parse(&frame).unwrap();
    assert_eq!(consumed, frame.len());

    if let WebSocketFrame::Text(parsed_text) = parsed_frame {
        assert_eq!(parsed_text, "Hello");
    } else {
        panic!("Expected text frame");
    }
}

#[test]
fn test_websocket_frame_close() {
    let close_frame = WebSocketFrame::close();
    let bytes = close_frame.to_bytes();

    // Should start with 0x88 (FIN + CLOSE opcode)
    assert_eq!(bytes[0], 0x88);
    // Length should be 0
    assert_eq!(bytes[1], 0);
}

#[test]
fn test_websocket_frame_close_with_code() {
    let close_frame = WebSocketFrame::close_with_code(1000, "Normal");
    let bytes = close_frame.to_bytes();

    // Should start with 0x88 (FIN + CLOSE opcode)
    assert_eq!(bytes[0], 0x88);
    // Should have payload
    assert!(bytes.len() > 2);
}

#[test]
fn test_websocket_frame_ping_pong() {
    let ping_data = b"ping data".to_vec();
    let ping_frame = WebSocketFrame::Ping(ping_data.clone());
    let bytes = ping_frame.to_bytes();

    // Should start with 0x89 (FIN + PING opcode)
    assert_eq!(bytes[0], 0x89);

    // Create a masked version for parsing
    let mut masked_frame = vec![
        0x89,     // FIN + PING
        0x80 | 9, // MASK + length 9
        0x01,
        0x02,
        0x03,
        0x04, // Mask key
    ];

    let mask = [0x01, 0x02, 0x03, 0x04];
    for (i, &byte) in ping_data.iter().enumerate() {
        masked_frame.push(byte ^ mask[i % 4]);
    }

    let (parsed_frame, _) = WebSocketFrame::parse(&masked_frame).unwrap();
    if let WebSocketFrame::Ping(parsed_data) = parsed_frame {
        assert_eq!(parsed_data, ping_data);
    } else {
        panic!("Expected ping frame");
    }
}
