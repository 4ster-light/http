use crate::{
    body::read_chunked_body,
    error::{Error, Result},
};
use std::{collections::HashMap, fmt};
use tokio::{io::AsyncReadExt, net::TcpStream};

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
/// Produced by [`HttpRequest::from_buffer`] (reads the body from the socket
/// when `Content-Length` or chunked `Transfer-Encoding` is present) or by
/// [`HttpRequest::from_buffer_sync`] for header-only parsing in tests.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The request method.
    pub method: HttpMethod,
    /// The raw request target (path and query), exactly as received.
    pub path: String,
    /// The HTTP version token from the request line (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Header fields with lower-cased names, so lookups via
    /// [`HttpRequest::get_header`] are case-insensitive (RFC 9110 §5.1).
    pub headers: HashMap<String, String>,
    /// The message body; empty when the request carries none or when parsed
    /// with [`HttpRequest::from_buffer_sync`].
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Parses the request line and headers from `buffer`, then reads the body
    /// from `socket` when the headers indicate one (`Content-Length` or
    /// chunked `Transfer-Encoding`).
    ///
    /// Bodies larger than 10 MiB are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHttpRequest`] for a malformed request line, an
    /// unsupported method, an invalid `Content-Length`, or an oversized body.
    /// Returns [`Error::Io`] if reading the body from the socket fails.
    pub async fn from_buffer(buffer: &[u8], socket: &mut TcpStream) -> Result<Self> {
        let request_str = String::from_utf8_lossy(buffer);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return Err(Error::InvalidHttpRequest("Empty request"));
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return Err(Error::InvalidHttpRequest("Invalid request line"));
        }

        let method = request_line_parts[0].parse::<HttpMethod>()?;
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Parse body based on Content-Length or Transfer-Encoding
        let body = if let Some(content_length) = headers.get("content-length") {
            // Read body based on Content-Length
            let length: usize = content_length
                .parse()
                .map_err(|_| Error::InvalidHttpRequest("Invalid Content-Length"))?;

            if length > 10 * 1024 * 1024 {
                return Err(Error::InvalidHttpRequest("Body too large"));
            }

            let mut body = vec![0u8; length];
            socket.read_exact(&mut body).await?;
            body
        } else if let Some(transfer_encoding) = headers.get("transfer-encoding") {
            if transfer_encoding.to_lowercase().contains("chunked") {
                // Decode chunked transfer encoding
                read_chunked_body(socket).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            method,
            path,
            version,
            headers,
            body,
        })
    }

    /// Parses the request line and headers without touching a socket.
    ///
    /// The body is always empty; intended for tests and for callers that read
    /// bodies separately.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHttpRequest`] for a malformed request line or
    /// an unsupported method.
    pub fn from_buffer_sync(buffer: &[u8]) -> Result<Self> {
        let request_str = String::from_utf8_lossy(buffer);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return Err(Error::InvalidHttpRequest("Empty request"));
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return Err(Error::InvalidHttpRequest("Invalid request line"));
        }

        let method = request_line_parts[0].parse::<HttpMethod>()?;
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        Ok(Self {
            method,
            path,
            version,
            headers,
            body: Vec::new(),
        })
    }

    /// Returns the value of the named header field, matched
    /// case-insensitively (RFC 9110 §5.1).
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }
}
