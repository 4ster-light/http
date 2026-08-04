//! HTTP/1.1 protocol primitives: request parsing, response building, and
//! body readers.
//!
//! This crate is transport-agnostic at the parsing layer; the connection
//! driver lives in the `server` crate until the planned generic-IO refactor
//! lands (see REFACTOR-PLAN.md §3.2 D2/D3).
//!
//! # Example
//!
//! ```
//! use http::response::HttpResponse;
//!
//! let bytes = HttpResponse::ok().with_text("Hello").to_bytes();
//! let head = String::from_utf8_lossy(&bytes);
//! assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
//! assert!(head.contains("content-length: 5\r\n"));
//! ```

/// HTTP message body readers (chunked transfer-encoding decoding).
pub mod body;
/// Error type for the HTTP protocol layer.
pub mod error;
/// HTTP request parsing: request line, headers, and body framing.
pub mod request;
/// HTTP response types and the response builder.
pub mod response;

pub use error::{Error, Result};
