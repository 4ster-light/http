//! Error type for the `http` crate (REFACTOR-PLAN.md §3.2 D5).

use crate::response::HttpStatusCode;
use thiserror::Error;

/// Errors produced by HTTP/1.1 parsing and I/O.
///
/// Parsing failures carry enough information
/// ([`Error::status`](crate::Error::status)) for the server layer to answer
/// with the correct 4xx response instead of dropping the connection (fixes
/// F8, SEC-HTTP-001/004).
#[derive(Error, Debug)]
pub enum Error {
    /// Underlying I/O failure while reading from or writing to the transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The request line, headers, or body framing violated HTTP/1.1 syntax.
    /// Maps to `400 Bad Request` (RFC 9112 §9.6 and RFC 9110 §15.5.1).
    #[error("Invalid HTTP request: {0}")]
    InvalidHttpRequest(&'static str),

    /// The request head exceeded the configured size limit. Maps to
    /// `431 Request Header Fields Too Large` (SEC-HTTP-001).
    #[error("Request head too large")]
    HeadTooLarge,

    /// The request body exceeded the configured size limit. Maps to
    /// `413 Payload Too Large` (SEC-HTTP-004).
    #[error("Request body too large")]
    BodyTooLarge,
}

impl Error {
    /// The HTTP status the server should answer with for this error (F8).
    /// `Io` maps to `500`; the parse variants map to their spec'd 4xx codes.
    #[must_use]
    pub fn status(&self) -> HttpStatusCode {
        match self {
            Self::Io(_) => HttpStatusCode::InternalServerError,
            Self::InvalidHttpRequest(_) => HttpStatusCode::BadRequest,
            Self::HeadTooLarge => HttpStatusCode::RequestHeaderFieldsTooLarge,
            Self::BodyTooLarge => HttpStatusCode::PayloadTooLarge,
        }
    }
}

/// Convenient alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;
