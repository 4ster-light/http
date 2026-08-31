//! WebSocket (RFC 6455) protocol implementation: strict frame codec, opening
//! handshake validation, and the connection lifecycle with fragmentation
//! reassembly and ping/pong liveness.
//!
//! Depends on the `http` crate for the upgrade handshake (REFACTOR-PLAN.md
//! §3.2 D1: dependency direction is `websocket → http`).
//!
//! # Example
//!
//! ```
//! use websocket::{
//!     frame::{Frame, OpCode},
//!     limits::Limits,
//! };
//!
//! // Serialize a server-to-client text frame (unmasked).
//! let bytes = Frame::text("Hello").to_bytes();
//! assert_eq!(bytes[0], 0x81);
//!
//! // Parse a client-to-server frame; the wire bytes below are the masked
//! // "Hello" example from RFC 6455 §5.7.
//! let wire = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
//! let (frame, consumed) = Frame::parse(&wire, &Limits::default()).unwrap();
//! assert_eq!(frame.opcode, OpCode::Text);
//! assert_eq!(frame.payload, b"Hello");
//! assert_eq!(consumed, wire.len());
//! ```

/// Connection lifecycle: echo behavior, liveness ping/pong, fragmentation
/// reassembly, and the close handshake over generic IO.
pub mod connection;
/// Error type for the WebSocket protocol layer.
pub mod error;
/// Raw frame codec (RFC 6455 §5): parsing and serialization with strict
/// validation.
pub mod frame;
/// Opening handshake: upgrade-request validation and accept-key computation.
pub mod handshake;
/// Typed security limits (frame/message caps, ping interval).
pub mod limits;

pub use connection::handle_websocket;
pub use error::{Error, Result};
