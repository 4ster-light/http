use base64::{Engine as _, engine::general_purpose};
use sha1::{Sha1, Digest};
use crate::{
    protocol::{
        request::HttpRequest,
        response::HttpResponse,
    },
    error::{Result, ServerError}
};

const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn is_websocket_request(request: &HttpRequest) -> bool {
    request.get_header("upgrade")
        .map(|v| v.to_lowercase() == "websocket")
        .unwrap_or(false)
        && request.get_header("connection")
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
        && request.get_header("sec-websocket-key").is_some()
        && request.get_header("sec-websocket-version")
            .map(|v| v == "13")
            .unwrap_or(false)
}

pub fn generate_accept(request: &HttpRequest) -> Result<Vec<u8>> {
    let websocket_key = request
        .get_header("sec-websocket-key")
        .ok_or_else(|| ServerError::WebSocketHandshakeFailed("Missing Sec-WebSocket-Key header".to_string()))?;

    let accept_key = generate_accept_key(websocket_key);

    let response = HttpResponse::switching_protocols()
        .with_header("upgrade", "websocket")
        .with_header("connection", "Upgrade")
        .with_header("sec-websocket-accept", &accept_key);

    Ok(response.to_bytes())
}

fn generate_accept_key(websocket_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(websocket_key.as_bytes());
    hasher.update(WEBSOCKET_MAGIC_STRING.as_bytes());
    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::protocol::request::HttpMethod;

    #[test]
    fn test_websocket_key_generation() {
        // Test vector from RFC 6455
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(generate_accept_key(key), expected);
    }

    #[test]
    fn test_is_websocket_request() {
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
}
