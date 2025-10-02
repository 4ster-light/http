use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid HTTP request: {0}")]
    InvalidHttpRequest(&'static str),

    #[error("WebSocket handshake failed: {0}")]
    WebSocketHandshakeFailed(String),

    #[error("WebSocket frame error: {0}")]
    WebSocketFrameError(&'static str),

    #[error("Static file not found: {0}")]
    FileNotFound(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;
