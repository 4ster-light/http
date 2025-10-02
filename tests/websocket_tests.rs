use std::collections::HashMap;
use http::{
    protocol::request::{HttpRequest, HttpMethod},
    websocket::{
        frame::WebSocketFrame,
        handshake::is_websocket_request
    }
};

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

    assert!(is_websocket_request(&request));
}

#[test]
fn test_websocket_frame_text() {
    let text_frame = WebSocketFrame::Text("Hello, WebSocket!".to_string());
    let bytes = text_frame.to_bytes();
    
    // Should start with 0x81 (FIN + TEXT opcode)
    assert_eq!(bytes[0], 0x81);
    
    // Parse it back
    if let Some(WebSocketFrame::Text(parsed_text)) = WebSocketFrame::parse(&bytes) {
        assert_eq!(parsed_text, "Hello, WebSocket!");
    } else {
        panic!("Failed to parse text frame");
    }
}

#[test]
fn test_websocket_frame_close() {
    let close_frame = WebSocketFrame::Close;
    let bytes = close_frame.to_bytes();
    
    // Should start with 0x88 (FIN + CLOSE opcode)
    assert_eq!(bytes[0], 0x88);
    // Length should be 0
    assert_eq!(bytes[1], 0);
}

#[test]
fn test_websocket_frame_ping_pong() {
    let ping_data = b"ping data".to_vec();
    let ping_frame = WebSocketFrame::Ping(ping_data.clone());
    let bytes = ping_frame.to_bytes();
    
    // Should start with 0x89 (FIN + PING opcode)
    assert_eq!(bytes[0], 0x89);
    
    // Parse it back
    if let Some(WebSocketFrame::Ping(parsed_data)) = WebSocketFrame::parse(&bytes) {
        assert_eq!(parsed_data, ping_data);
    } else {
        panic!("Failed to parse ping frame");
    }
}
