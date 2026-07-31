//! HTTP/1.1 protocol primitives: request parsing, response building, and
//! body readers.
//!
//! This crate is transport-agnostic at the parsing layer; the connection
//! driver lives in the `server` crate until the planned generic-IO refactor
//! lands (see REFACTOR-PLAN.md §3.2 D2/D3).

pub mod body;
pub mod error;
pub mod request;
pub mod response;

pub use error::{Error, Result};
