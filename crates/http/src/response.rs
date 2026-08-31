use std::{collections::HashMap, fmt, fmt::Write as _, time::SystemTime};

/// HTTP response status code (RFC 9110 §15), with the reason phrases defined
/// there.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum HttpStatusCode {
    // 1xx Informational
    /// `100 Continue`: the request's headers were received; send the body.
    Continue = 100,
    /// `101 Switching Protocols`: the server agrees to the requested protocol
    /// upgrade (e.g. to WebSocket).
    SwitchingProtocols = 101,

    // 2xx Success
    /// `200 OK`: the request succeeded.
    Ok = 200,
    /// `201 Created`: the request succeeded and a new resource was created.
    Created = 201,
    /// `202 Accepted`: the request was accepted for later processing.
    Accepted = 202,
    /// `204 No Content`: the request succeeded; there is no content to send.
    NoContent = 204,

    // 3xx Redirection
    /// `301 Moved Permanently`: the resource has a new permanent URI.
    MovedPermanently = 301,
    /// `302 Found`: the resource resides temporarily under a different URI.
    Found = 302,
    /// `304 Not Modified`: the cached representation is still valid.
    NotModified = 304,

    // 4xx Client Error
    /// `400 Bad Request`: the request could not be understood or was malformed.
    BadRequest = 400,
    /// `401 Unauthorized`: authentication is required or has failed.
    Unauthorized = 401,
    /// `403 Forbidden`: the server understood the request but refuses it.
    Forbidden = 403,
    /// `404 Not Found`: no representation exists for the target resource.
    NotFound = 404,
    /// `405 Method Not Allowed`: the method is not supported for this resource.
    MethodNotAllowed = 405,
    /// `413 Payload Too Large`: the request body exceeded a server limit
    /// (SEC-HTTP-004; RFC 9110 §15.5.14).
    PayloadTooLarge = 413,
    /// `431 Request Header Fields Too Large`: the request head exceeded a
    /// server limit (SEC-HTTP-001; RFC 6585 §5).
    RequestHeaderFieldsTooLarge = 431,

    // 5xx Server Error
    /// `500 Internal Server Error`: the server hit an unexpected condition.
    InternalServerError = 500,
    /// `501 Not Implemented`: the server does not support the functionality.
    NotImplemented = 501,
    /// `502 Bad Gateway`: an upstream server returned an invalid response.
    BadGateway = 502,
    /// `503 Service Unavailable`: the server is temporarily unable to serve.
    ServiceUnavailable = 503,
}

impl fmt::Display for HttpStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, text) = match self {
            HttpStatusCode::Continue => (100, "Continue"),
            HttpStatusCode::SwitchingProtocols => (101, "Switching Protocols"),
            HttpStatusCode::Ok => (200, "OK"),
            HttpStatusCode::Created => (201, "Created"),
            HttpStatusCode::Accepted => (202, "Accepted"),
            HttpStatusCode::NoContent => (204, "No Content"),
            HttpStatusCode::MovedPermanently => (301, "Moved Permanently"),
            HttpStatusCode::Found => (302, "Found"),
            HttpStatusCode::NotModified => (304, "Not Modified"),
            HttpStatusCode::BadRequest => (400, "Bad Request"),
            HttpStatusCode::Unauthorized => (401, "Unauthorized"),
            HttpStatusCode::Forbidden => (403, "Forbidden"),
            HttpStatusCode::NotFound => (404, "Not Found"),
            HttpStatusCode::MethodNotAllowed => (405, "Method Not Allowed"),
            HttpStatusCode::PayloadTooLarge => (413, "Payload Too Large"),
            HttpStatusCode::RequestHeaderFieldsTooLarge => (431, "Request Header Fields Too Large"),
            HttpStatusCode::InternalServerError => (500, "Internal Server Error"),
            HttpStatusCode::NotImplemented => (501, "Not Implemented"),
            HttpStatusCode::BadGateway => (502, "Bad Gateway"),
            HttpStatusCode::ServiceUnavailable => (503, "Service Unavailable"),
        };
        write!(f, "{code} {text}")
    }
}

impl HttpStatusCode {
    /// Returns the numeric status code (e.g. `404`).
    #[must_use]
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Returns the standard reason phrase (e.g. `"Not Found"`).
    #[must_use]
    pub fn reason_phrase(&self) -> &'static str {
        match self {
            HttpStatusCode::Continue => "Continue",
            HttpStatusCode::SwitchingProtocols => "Switching Protocols",
            HttpStatusCode::Ok => "OK",
            HttpStatusCode::Created => "Created",
            HttpStatusCode::Accepted => "Accepted",
            HttpStatusCode::NoContent => "No Content",
            HttpStatusCode::MovedPermanently => "Moved Permanently",
            HttpStatusCode::Found => "Found",
            HttpStatusCode::NotModified => "Not Modified",
            HttpStatusCode::BadRequest => "Bad Request",
            HttpStatusCode::Unauthorized => "Unauthorized",
            HttpStatusCode::Forbidden => "Forbidden",
            HttpStatusCode::NotFound => "Not Found",
            HttpStatusCode::MethodNotAllowed => "Method Not Allowed",
            HttpStatusCode::PayloadTooLarge => "Payload Too Large",
            HttpStatusCode::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            HttpStatusCode::InternalServerError => "Internal Server Error",
            HttpStatusCode::NotImplemented => "Not Implemented",
            HttpStatusCode::BadGateway => "Bad Gateway",
            HttpStatusCode::ServiceUnavailable => "Service Unavailable",
        }
    }

    /// Returns `true` for 2xx status codes.
    ///
    /// Drives the default `Connection` header in
    /// [`HttpResponse::to_bytes`]: keep-alive is only advertised on success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        let code = self.code();
        (200..300).contains(&code)
    }
}

/// An HTTP/1.1 response under construction.
///
/// Built with the consuming builder methods (`with_text`, `with_header`, …)
/// and serialized with [`HttpResponse::to_bytes`], which fills in the
/// standard `Date`, `Server` and `Connection` headers when absent.
#[derive(Debug)]
pub struct HttpResponse {
    /// The response status code.
    pub status: HttpStatusCode,
    /// Header fields to send; names are emitted exactly as inserted.
    pub headers: HashMap<String, String>,
    /// The message body bytes.
    pub body: Vec<u8>,
    /// Whether the connection should be kept alive after this response.
    pub keep_alive: bool,
}

impl HttpResponse {
    /// Creates an empty response with the given status; keep-alive defaults
    /// to enabled.
    #[must_use]
    pub fn new(status: HttpStatusCode) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
            keep_alive: true,
        }
    }

    /// Creates an empty `200 OK` response.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(HttpStatusCode::Ok)
    }

    /// Creates an empty `404 Not Found` response.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(HttpStatusCode::NotFound)
    }

    /// Creates an empty `500 Internal Server Error` response.
    #[must_use]
    pub fn internal_server_error() -> Self {
        Self::new(HttpStatusCode::InternalServerError)
    }

    /// Creates an empty `400 Bad Request` response.
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(HttpStatusCode::BadRequest)
    }

    /// Creates an empty `101 Switching Protocols` response.
    #[must_use]
    pub fn switching_protocols() -> Self {
        Self::new(HttpStatusCode::SwitchingProtocols)
    }

    /// Sets a header field, replacing any existing value with the same name.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Sets the message body, filling in `Content-Length` unless the caller
    /// already provided it.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        // Auto-set Content-Length if not already set
        if !self.headers.contains_key("content-length") {
            self.headers
                .insert("content-length".to_string(), body.len().to_string());
        }
        self.body = body;
        self
    }

    /// Sets a UTF-8 `text/plain` body and its `Content-Type`.
    #[must_use]
    pub fn with_text(self, text: &str) -> Self {
        self.with_header("content-type", "text/plain; charset=utf-8")
            .with_body(text.as_bytes().to_vec())
    }

    /// Sets a UTF-8 `text/html` body and its `Content-Type`.
    #[must_use]
    pub fn with_html(self, html: &str) -> Self {
        self.with_header("content-type", "text/html; charset=utf-8")
            .with_body(html.as_bytes().to_vec())
    }

    /// Sets a UTF-8 `application/json` body and its `Content-Type`.
    #[must_use]
    pub fn with_json(self, json: &str) -> Self {
        self.with_header("content-type", "application/json; charset=utf-8")
            .with_body(json.as_bytes().to_vec())
    }

    /// Marks the connection to be closed after this response is sent.
    #[must_use]
    pub fn close_connection(mut self) -> Self {
        self.keep_alive = false;
        self
    }

    /// Serializes the response head and body to wire bytes.
    ///
    /// Adds the standard `Date` (IMF-fixdate, RFC 9110 §6.6.1), `Server` and
    /// `Connection`/`Keep-Alive` headers when not already present. The
    /// connection is only kept alive for 2xx statuses.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {}\r\n", self.status);

        // Add standard headers if not already present
        let mut headers = self.headers.clone();

        // Add Date header (IMF-fixdate per RFC 7231 §7.1.1.1)
        if !headers.contains_key("date") {
            headers.insert(
                "date".to_string(),
                httpdate::fmt_http_date(SystemTime::now()),
            );
        }

        // Add Server header
        if !headers.contains_key("server") {
            headers.insert("server".to_string(), "http-rs/0.1.0".to_string());
        }

        // Add Connection header for keep-alive
        if !headers.contains_key("connection") {
            if self.keep_alive && self.status.is_success() {
                headers.insert("connection".to_string(), "keep-alive".to_string());
                if !headers.contains_key("keep-alive") {
                    headers.insert("keep-alive".to_string(), "timeout=5, max=100".to_string());
                }
            } else {
                headers.insert("connection".to_string(), "close".to_string());
            }
        }

        for (name, value) in &headers {
            // Writing to a String is infallible.
            let _ = write!(response, "{name}: {value}\r\n");
        }

        response.push_str("\r\n");

        let mut bytes = response.into_bytes();
        bytes.extend(&self.body);
        bytes
    }
}
