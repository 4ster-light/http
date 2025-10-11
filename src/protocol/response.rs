use chrono::Utc;
use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum HttpStatusCode {
    // 1xx Informational
    Continue = 100,
    SwitchingProtocols = 101,

    // 2xx Success
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,

    // 3xx Redirection
    MovedPermanently = 301,
    Found = 302,
    NotModified = 304,

    // 4xx Client Error
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,

    // 5xx Server Error
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
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
            HttpStatusCode::InternalServerError => (500, "Internal Server Error"),
            HttpStatusCode::NotImplemented => (501, "Not Implemented"),
            HttpStatusCode::BadGateway => (502, "Bad Gateway"),
            HttpStatusCode::ServiceUnavailable => (503, "Service Unavailable"),
        };
        write!(f, "{} {}", code, text)
    }
}

impl HttpStatusCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }

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
            HttpStatusCode::InternalServerError => "Internal Server Error",
            HttpStatusCode::NotImplemented => "Not Implemented",
            HttpStatusCode::BadGateway => "Bad Gateway",
            HttpStatusCode::ServiceUnavailable => "Service Unavailable",
        }
    }

    pub fn is_success(&self) -> bool {
        let code = self.code();
        (200..300).contains(&code)
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: HttpStatusCode,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl HttpResponse {
    pub fn new(status: HttpStatusCode) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
            keep_alive: true,
        }
    }

    pub fn ok() -> Self {
        Self::new(HttpStatusCode::Ok)
    }

    pub fn not_found() -> Self {
        Self::new(HttpStatusCode::NotFound)
    }

    pub fn internal_server_error() -> Self {
        Self::new(HttpStatusCode::InternalServerError)
    }

    pub fn bad_request() -> Self {
        Self::new(HttpStatusCode::BadRequest)
    }

    pub fn switching_protocols() -> Self {
        Self::new(HttpStatusCode::SwitchingProtocols)
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        // Auto-set Content-Length if not already set
        if !self.headers.contains_key("content-length") {
            self.headers
                .insert("content-length".to_string(), body.len().to_string());
        }
        self.body = body;
        self
    }

    pub fn with_text(self, text: &str) -> Self {
        self.with_header("content-type", "text/plain; charset=utf-8")
            .with_body(text.as_bytes().to_vec())
    }

    pub fn with_html(self, html: &str) -> Self {
        self.with_header("content-type", "text/html; charset=utf-8")
            .with_body(html.as_bytes().to_vec())
    }

    pub fn with_json(self, json: &str) -> Self {
        self.with_header("content-type", "application/json; charset=utf-8")
            .with_body(json.as_bytes().to_vec())
    }

    pub fn close_connection(mut self) -> Self {
        self.keep_alive = false;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {}\r\n", self.status);

        // Add standard headers if not already present
        let mut headers = self.headers.clone();

        // Add Date header
        if !headers.contains_key("date") {
            let now = Utc::now();
            headers.insert(
                "date".to_string(),
                now.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
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
            response.push_str(&format!("{}: {}\r\n", name, value));
        }

        response.push_str("\r\n");

        let mut bytes = response.into_bytes();
        bytes.extend(&self.body);
        bytes
    }
}
