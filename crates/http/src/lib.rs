//! HTTP/1.1 protocol primitives: pure request parsing, response building,
//! body decoding, limits, and a generic-IO connection reader.
//!
//! Parsers are pure functions over byte buffers (REFACTOR-PLAN.md §3.2 D2);
//! the only IO lives in [`connection`], which is generic over
//! [`AsyncRead`](tokio::io::AsyncRead) so tests can drive it with
//! `tokio::io::duplex`.
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

/// Message body decoding (chunked transfer-encoding).
pub mod body;
/// Generic-IO request reading with a persistent, caller-owned buffer.
pub mod connection;
/// Error type for the HTTP protocol layer, with 4xx status mapping.
pub mod error;
/// Typed security limits (head/body caps, timeouts, keep-alive policy).
pub mod limits;
/// Pure HTTP request parsing: request line, headers, and body framing.
pub mod request;
/// HTTP response types and the response builder.
pub mod response;

pub use error::{Error, Result};
