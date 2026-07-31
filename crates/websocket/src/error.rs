//! Error type for the `websocket` crate (REFACTOR-PLAN.md §3.2 D5).

use thiserror::Error;

/// Errors produced by the WebSocket handshake, frame codec, or connection.
#[derive(Error, Debug)]
pub enum Error {
    /// Underlying I/O failure while reading from or writing to the transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error from the HTTP layer (the WebSocket handshake is an HTTP upgrade).
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    /// The opening handshake failed validation (RFC 6455 §4.2).
    #[error("WebSocket handshake failed: {0}")]
    WebSocketHandshakeFailed(String),

    /// A received frame violated RFC 6455.
    #[error("WebSocket frame error: {0}")]
    WebSocketFrameError(&'static str),

    /// Any other WebSocket protocol error.
    #[error("WebSocket error: {0}")]
    WebSocketError(String),
}

/// Convenient alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;
