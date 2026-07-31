//! WebSocket (RFC 6455) protocol implementation: frame codec, opening
//! handshake, and connection lifecycle with ping/pong liveness.
//!
//! Depends on the `http` crate for the upgrade handshake (REFACTOR-PLAN.md
//! §3.2 D1: dependency direction is `websocket → http`).

pub mod connection;
pub mod error;
pub mod frame;
pub mod handshake;

pub use connection::handle_websocket;
pub use error::{Error, Result};
