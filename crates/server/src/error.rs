//! Application-level error type: aggregates the protocol crate errors
//! (`http::Error`, `websocket::Error`) plus server-specific failures
//! (ADR-0003).

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] websocket::Error),

    #[error("Static file not found: {0}")]
    FileNotFound(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;
