use crate::{
    error::Result,
    protocol::{request::HttpRequest, response::HttpResponse},
};
use base64::{Engine as _, engine::general_purpose};
use sha1::{Digest, Sha1};

const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn is_websocket_request(request: &HttpRequest) -> Option<&String> {
    let is_upgrade = request
        .get_header("upgrade")
        .map(|v| v.to_lowercase() == "websocket")
        .unwrap_or(false);

    let is_connection_upgrade = request
        .get_header("connection")
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let is_version_13 = request
        .get_header("sec-websocket-version")
        .map(|v| v == "13")
        .unwrap_or(false);

    let websocket_key = request.get_header("sec-websocket-key");

    if is_upgrade && is_connection_upgrade && is_version_13 {
        websocket_key
    } else {
        None
    }
}

pub fn generate_accept(websocket_key: &str) -> Result<Vec<u8>> {
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
    use crate::protocol::request::{HttpMethod, HttpRequest};
    use std::collections::HashMap;

    #[test]
    fn test_websocket_key_generation() {
        // Test vector from RFC 6455
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(generate_accept_key(key), expected);
    }

    #[test]
    fn test_is_websocket_request_valid() {
        let mut headers = HashMap::new();
        headers.insert("upgrade".to_string(), "websocket".to_string());
        headers.insert("connection".to_string(), "Upgrade".to_string());

        let key = "test-key".to_string();
        headers.insert("sec-websocket-key".to_string(), key.clone());
        headers.insert("sec-websocket-version".to_string(), "13".to_string());

        let request = HttpRequest {
            method: HttpMethod::Get,
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
        };

        assert_eq!(is_websocket_request(&request), Some(&key));
    }

    #[test]
    fn test_is_websocket_request_invalid() {
        let mut headers = HashMap::new();
        headers.insert("upgrade".to_string(), "http/1.1".to_string()); // Invalid
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert("sec-websocket-key".to_string(), "test-key".to_string());
        headers.insert("sec-websocket-version".to_string(), "13".to_string());

        let request = HttpRequest {
            method: HttpMethod::Get,
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
        };

        assert_eq!(is_websocket_request(&request), None);
    }
}
