//! WebSocket (RFC 6455) protocol implementation: frame codec, opening
//! handshake, and connection lifecycle with ping/pong liveness.
//!
//! Depends on the `http` crate for the upgrade handshake (REFACTOR-PLAN.md
//! §3.2 D1: dependency direction is `websocket → http`).
//!
//! # Example
//!
//! ```
//! use websocket::frame::WebSocketFrame;
//!
//! // Serialize a server-to-client text frame (unmasked).
//! let bytes = WebSocketFrame::text("Hello").to_bytes();
//! assert_eq!(bytes[0], 0x81);
//!
//! // Parse a client-to-server frame; the wire bytes below are the masked
//! // "Hello" example from RFC 6455 §5.7.
//! let wire = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
//! let (frame, consumed) = WebSocketFrame::parse(&wire).unwrap();
//! let WebSocketFrame::Text(text) = frame else {
//!     panic!("expected a text frame");
//! };
//! assert_eq!(text, "Hello");
//! assert_eq!(consumed, wire.len());
//! ```

/// Connection lifecycle: the read/write loop with echo behavior, liveness
/// ping/pong, and the close handshake.
pub mod connection;
/// Error type for the WebSocket protocol layer.
pub mod error;
/// WebSocket frame codec (RFC 6455 §5): parsing and serialization.
pub mod frame;
/// Opening handshake: upgrade-request validation and accept-key computation.
pub mod handshake;

pub use connection::handle_websocket;
pub use error::{Error, Result};
