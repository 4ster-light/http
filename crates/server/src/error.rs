//! Application-level error type: aggregates the protocol crate errors
//! (`http::Error`, `websocket::Error`) plus server-specific failures
//! (REFACTOR-PLAN.md §3.2 D5).

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

    #[error("No available port found starting from {0}")]
    PortUnavailable(u16),
}

pub type Result<T> = std::result::Result<T, ServerError>;
