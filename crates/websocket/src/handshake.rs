use crate::error::Result;
use base64::{Engine as _, engine::general_purpose};
use http::{request::HttpRequest, response::HttpResponse};
use sha1::{Digest, Sha1};

const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The result of checking an HTTP request for a WebSocket upgrade
/// (RFC 6455 §4.2.1).
pub enum UpgradeCheck<'a> {
    /// The request is not a WebSocket upgrade at all (no `Upgrade:
    /// websocket`); route it as plain HTTP.
    NotUpgrade,
    /// The upgrade request passed full §4.2.1 validation; carries the
    /// `Sec-WebSocket-Key` ready for [`generate_accept`].
    Valid(&'a String),
    /// An upgrade was attempted but failed validation (method not GET,
    /// version below 1.1, missing/malformed key or headers). The server
    /// should answer `400` (SEC-WS-007, F11).
    Invalid(&'static str),
}

/// Checks an HTTP request for a WebSocket upgrade (RFC 6455 §4.2.1).
///
/// Validation (SEC-WS-007): the method must be GET, the HTTP version must be
/// 1.1 or later, `Upgrade: websocket` and `Connection: Upgrade` must be
/// present, `Sec-WebSocket-Version` must be 13, and the
/// `Sec-WebSocket-Key` must decode as base64 of exactly 16 bytes. Failing an
/// upgrade header when no upgrade was requested is not an `Invalid` result;
/// it is `NotUpgrade`.
#[must_use]
pub fn validate_upgrade(request: &HttpRequest) -> UpgradeCheck<'_> {
    let is_upgrade = request
        .get_header("upgrade")
        .is_some_and(|v| v.to_lowercase() == "websocket");
    if !is_upgrade {
        return UpgradeCheck::NotUpgrade;
    }

    if request.method != http::request::HttpMethod::Get {
        return UpgradeCheck::Invalid("Upgrade must use GET");
    }
    // RFC 9112 lexically-enough version check ("HTTP/1.1" and above).
    let version_ok = request
        .version
        .strip_prefix("HTTP/")
        .and_then(|rest| rest.parse::<f64>().ok())
        .is_some_and(|v| v >= 1.1);
    if !version_ok {
        return UpgradeCheck::Invalid("Upgrade requires HTTP/1.1 or newer");
    }
    if !request
        .get_header("connection")
        .is_some_and(|v| v.to_lowercase().contains("upgrade"))
    {
        return UpgradeCheck::Invalid("Missing Connection: Upgrade");
    }
    if request
        .get_header("sec-websocket-version")
        .is_none_or(|v| v != "13")
    {
        return UpgradeCheck::Invalid("Sec-WebSocket-Version must be 13");
    }
    let Some(key) = request.get_header("sec-websocket-key") else {
        return UpgradeCheck::Invalid("Missing Sec-WebSocket-Key");
    };
    let valid_key = general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|decoded| decoded.len() == 16);
    if !valid_key {
        return UpgradeCheck::Invalid("Sec-WebSocket-Key must be base64 of 16 bytes");
    }

    UpgradeCheck::Valid(key)
}

/// Builds the serialized `101 Switching Protocols` response for a validated
/// upgrade request, including the `Sec-WebSocket-Accept` digest.
///
/// The digest is `base64(sha1(key + magic))` per RFC 6455 §4.2.2.
///
/// # Errors
///
/// Currently infallible; returns [`Result`] to keep caller error handling
/// uniform.
pub fn generate_accept(websocket_key: &str) -> Result<Vec<u8>> {
    let accept_key = accept_key(websocket_key);

    let response = HttpResponse::switching_protocols()
        .with_header("upgrade", "websocket")
        .with_header("connection", "Upgrade")
        .with_header("sec-websocket-accept", &accept_key);

    Ok(response.to_bytes())
}

/// Computes the `Sec-WebSocket-Accept` digest for a handshake key:
/// `base64(sha1(key + magic))` per RFC 6455 §4.2.2.
///
/// Servers use this inside [`generate_accept`]; clients use it to verify the
/// `Sec-WebSocket-Accept` response header (RFC 6455 §4.2.2: a client MUST
/// fail the connection when the value does not match). See
/// `examples/src/lib.rs` for the client-side usage.
#[must_use]
pub fn accept_key(websocket_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(websocket_key.as_bytes());
    hasher.update(WEBSOCKET_MAGIC_STRING.as_bytes());
    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::request::{HttpMethod, HttpRequest};
    use std::collections::HashMap;

    fn request_with(headers: HashMap<String, String>) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
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

    #[test]
    fn test_websocket_key_generation() {
        // Test vector from RFC 6455
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(accept_key(key), expected);
    }

    #[test]
    fn test_generate_accept_builds_101_response() {
        let response = generate_accept("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 101"));
        assert!(text.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }

    #[test]
    fn test_validate_upgrade_valid() {
        let request = request_with(valid_headers());
        assert!(matches!(validate_upgrade(&request), UpgradeCheck::Valid(_)));
    }

    #[test]
    fn test_validate_upgrade_invalid_upgrade_header() {
        let mut headers = valid_headers();
        headers.insert("upgrade".to_string(), "http/1.1".to_string());
        let request = request_with(headers);
        assert!(matches!(
            validate_upgrade(&request),
            UpgradeCheck::NotUpgrade
        ));
    }

    #[test]
    fn test_validate_upgrade_rejects_bad_key() {
        let mut headers = valid_headers();
        headers.insert("sec-websocket-key".to_string(), "test-key".to_string());
        let request = request_with(headers);
        assert!(matches!(
            validate_upgrade(&request),
            UpgradeCheck::Invalid(_)
        ));
    }
}
