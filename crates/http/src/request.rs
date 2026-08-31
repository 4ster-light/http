//! Pure HTTP/1.1 request parsing (REFACTOR-PLAN.md §3.2 D2/D3).
//!
//! The parser operates on caller-managed buffers: it either returns the
//! complete request plus the number of bytes consumed, or reports that more
//! bytes are needed. No sockets, no async. This is what fixes F1 (discarded
//! bytes) structurally and makes the parser fuzzable.

use crate::{
    body::decode_chunked_body,
    error::{Error, Result},
    limits::Limits,
};
use std::{collections::HashMap, fmt};

/// HTTP request method (RFC 9110 §9).
///
/// Parsed case-insensitively via [`FromStr`](std::str::FromStr); unknown
/// methods are rejected rather than silently mapped.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    /// `GET`: retrieve a representation of the target resource.
    Get,
    /// `POST`: process the enclosed representation according to the
    /// resource's own semantics.
    Post,
    /// `PUT`: replace the target resource's state with the enclosed one.
    Put,
    /// `DELETE`: remove the target resource.
    Delete,
    /// `HEAD`: like `GET`, but the server must not send a message body.
    Head,
    /// `OPTIONS`: describe the communication options for the target resource.
    Options,
    /// `PATCH`: apply partial modifications to the target resource.
    Patch,
    /// `TRACE`: perform a message loop-back test along the request path.
    Trace,
    /// `CONNECT`: establish a tunnel to the server identified by the target.
    Connect,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Connect => write!(f, "CONNECT"),
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            "TRACE" => Ok(HttpMethod::Trace),
            "CONNECT" => Ok(HttpMethod::Connect),
            _ => Err(Error::InvalidHttpRequest("Unsupported HTTP method")),
        }
    }
}

/// A parsed HTTP/1.1 request: request line, headers, and (optionally) body.
///
/// Produced by [`HttpRequest::parse`], a pure function over a byte buffer.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The request method.
    pub method: HttpMethod,
    /// The raw request target (path and query), exactly as received.
    pub path: String,
    /// The HTTP version token from the request line (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Header fields with lower-cased names; lookups via
    /// [`HttpRequest::get_header`] are case-insensitive (RFC 9110 §5.1).
    /// Duplicate field lines are combined with `", "` (RFC 9110 §5.2).
    pub headers: HashMap<String, String>,
    /// The message body; empty when the request carries none.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Attempts to parse a complete request from the front of `buffer`.
    ///
    /// Returns `Ok(None)` when the buffer does not yet hold the full request
    /// (head or body incomplete). Returns `Ok(Some((request, consumed)))` on
    /// success; the caller advances its buffer by `consumed`, keeping any
    /// pipelined bytes (F1, SEC-HTTP-007).
    ///
    /// The head must end within [`Limits::max_head_bytes`] or the parse fails
    /// with [`Error::HeadTooLarge`] so the caller can answer `431` instead of
    /// buffering indefinitely (SEC-HTTP-001). Bodies larger than
    /// [`Limits::max_body_bytes`] fail with [`Error::BodyTooLarge`] (413,
    /// SEC-HTTP-004). Sending both `Content-Length` and `Transfer-Encoding` is
    /// rejected per RFC 9112 §6.3 (SEC-HTTP-003).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHttpRequest`] for a malformed request line,
    /// unsupported method, malformed header, or framing violation.
    /// [`Error::HeadTooLarge`] and [`Error::BodyTooLarge`] for limit
    /// violations as described above.
    pub fn parse(buffer: &[u8], limits: &Limits) -> Result<Option<(Self, usize)>> {
        let Some(head_len) = find_head_end(buffer) else {
            // No terminator yet: the head must still fit the limit, otherwise
            // an attacker could keep the buffer growing forever (F8/SEC-HTTP-001).
            if buffer.len() > limits.max_head_bytes {
                return Err(Error::HeadTooLarge);
            }
            return Ok(None);
        };
        if head_len > limits.max_head_bytes {
            return Err(Error::HeadTooLarge);
        }

        let (mut request, _) = parse_head(&buffer[..head_len])?;

        // SEC-HTTP-003: Content-Length + Transfer-Encoding together is a
        // request-smuggling vector; TE precedence per RFC 9112 §6.3 is to
        // reject the message entirely.
        let has_cl = request.headers.contains_key("content-length");
        let has_te = request.headers.contains_key("transfer-encoding");
        if has_cl && has_te {
            return Err(Error::InvalidHttpRequest(
                "Content-Length with Transfer-Encoding",
            ));
        }

        if let Some(content_length) = request.headers.get("content-length") {
            let length: usize = content_length
                .parse()
                .map_err(|_| Error::InvalidHttpRequest("Invalid Content-Length"))?;
            if length > limits.max_body_bytes {
                return Err(Error::BodyTooLarge);
            }
            let body_start = head_len;
            if buffer.len() - head_len < length {
                return Ok(None);
            }
            request.body = buffer[body_start..body_start + length].to_vec();
            return Ok(Some((request, head_len + length)));
        }

        if let Some(transfer_encoding) = request.headers.get("transfer-encoding") {
            if transfer_encoding.to_lowercase().contains("chunked") {
                let Some((body, body_len)) =
                    decode_chunked_body(&buffer[head_len..], limits.max_body_bytes)?
                else {
                    return Ok(None);
                };
                request.body = body;
                return Ok(Some((request, head_len + body_len)));
            }
            // Non-chunked TE is a `400` (RFC 9112 §6.3 final encoding rule).
            return Err(Error::InvalidHttpRequest("Unsupported Transfer-Encoding"));
        }

        // No body.
        Ok(Some((request, head_len)))
    }

    /// Parses a request head-only (no body) from a complete buffer; a
    /// convenience for tests and for the WebSocket handshake, which never
    /// has a body.
    ///
    /// # Errors
    ///
    /// Same as [`HttpRequest::parse`], minus body failures; returns the parse
    /// only if the input consumed exactly. This wrapper unwraps the
    /// `Ok(Some(..))` result and discards the consumed count.
    pub fn parse_head_only(buffer: &[u8]) -> Result<Self> {
        match Self::parse(buffer, &Limits::default())? {
            Some((request, _)) => Ok(request),
            None => Err(Error::InvalidHttpRequest("Incomplete request")),
        }
    }

    /// Returns the value of the named header field, matched
    /// case-insensitively (RFC 9110 §5.1).
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Whether the connection must close after this request (RFC 9112 §9.3).
    ///
    /// HTTP/1.1 defaults to keep-alive unless `Connection: close`; HTTP/1.0
    /// defaults to close unless `Connection: keep-alive` explicitly opts in
    /// (fixes F7).
    #[must_use]
    pub fn should_close(&self) -> bool {
        let connection = self.get_header("connection").map(|v| v.to_lowercase());
        if self.version == "HTTP/1.0" {
            !connection.is_some_and(|v| v.contains("keep-alive"))
        } else {
            connection.is_some_and(|v| v == "close")
        }
    }
}

/// Finds the position just past the first `\r\n\r\n` sequence. The caller's
/// buffer is rescanned linearly per call, which is acceptable given the
/// all-at-once buffer view and avoids stale offsets (see SEC-HTTP-001 cap).
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Parses the request line and header fields of a complete head.
fn parse_head(head: &[u8]) -> Result<(HttpRequest, usize)> {
    let head_text = std::str::from_utf8(head)
        .map_err(|_| Error::InvalidHttpRequest("Head is not valid UTF-8"))?;
    let mut lines = head_text.split("\r\n");

    let request_line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or(Error::InvalidHttpRequest("Empty request"))?;

    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidHttpRequest("Invalid request line"));
    }

    let method = parts[0].parse::<HttpMethod>()?;
    let path = parts[1].to_string();
    let version = parts[2].to_string();

    // RFC 9112 §3: the version token must look like `HTTP/digit.digit`.
    if !version.starts_with("HTTP/") {
        return Err(Error::InvalidHttpRequest("Invalid HTTP version"));
    }

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::InvalidHttpRequest("Malformed header line"));
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().to_string();
        if name.is_empty() {
            return Err(Error::InvalidHttpRequest("Empty header name"));
        }
        // RFC 9110 §5.2: a recipient MAY combine duplicate field lines into
        // one comma-separated value.
        headers
            .entry(name)
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&value);
            })
            .or_insert(value);
    }

    Ok((
        HttpRequest {
            method,
            path,
            version,
            headers,
            body: Vec::new(),
        },
        head.len(),
    ))
}
