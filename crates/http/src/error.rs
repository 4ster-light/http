//! Error type for the `http` crate (REFACTOR-PLAN.md §3.2 D5).

use thiserror::Error;

/// Errors produced by HTTP/1.1 parsing and I/O.
#[derive(Error, Debug)]
pub enum Error {
    /// Underlying I/O failure while reading from or writing to the transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The request head or body violated HTTP/1.1 syntax or configured limits.
    #[error("Invalid HTTP request: {0}")]
    InvalidHttpRequest(&'static str),
}

/// Convenient alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;
