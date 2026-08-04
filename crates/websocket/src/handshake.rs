use crate::error::Result;
use base64::{Engine as _, engine::general_purpose};
use http::{request::HttpRequest, response::HttpResponse};
use sha1::{Digest, Sha1};

const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Checks whether an HTTP request is a valid WebSocket upgrade request
/// (RFC 6455 §4.2.1).
///
/// Requires `Upgrade: websocket`, a `Connection` header listing `Upgrade`,
/// and `Sec-WebSocket-Version: 13`. On success returns the value of
/// `Sec-WebSocket-Key`, ready for [`generate_accept`].
///
/// Note: the key's *format* (base64 of 16 bytes) is not verified yet — that
/// is known gap F11, scheduled for the hardening phase.
#[must_use]
pub fn is_websocket_request(request: &HttpRequest) -> Option<&String> {
    let is_upgrade = request
        .get_header("upgrade")
        .is_some_and(|v| v.to_lowercase() == "websocket");

    let is_connection_upgrade = request
        .get_header("connection")
        .is_some_and(|v| v.to_lowercase().contains("upgrade"));

    let is_version_13 = request
        .get_header("sec-websocket-version")
        .is_some_and(|v| v == "13");

    let websocket_key = request.get_header("sec-websocket-key");

    if is_upgrade && is_connection_upgrade && is_version_13 {
        websocket_key
    } else {
        None
    }
}

/// Builds the serialized `101 Switching Protocols` response for a validated
/// upgrade request, including the `Sec-WebSocket-Accept` digest.
///
/// The digest is `base64(sha1(key + magic))` per RFC 6455 §4.2.2.
///
/// # Errors
///
/// Currently infallible; returns [`Result`] so future validation (e.g. key
/// format checks, see F11) does not break the API.
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
    use http::request::HttpMethod;
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
