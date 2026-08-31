//! Typed security limits for the WebSocket layer (REFACTOR-PLAN.md §3.2 D4).

use std::time::Duration;

/// Security limits for frame decoding and connection liveness.
///
/// Defaults: 1 MiB data-frame cap (SEC-WS-002), 1 MiB aggregated message cap
/// for reassembly (SEC-WS-009), and a 30 s liveness ping interval
/// (SEC-WS-008).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum payload of a single data frame. A frame announcing more is
    /// rejected with close code 1009 before any buffering (SEC-WS-002, F5).
    pub max_frame_payload: u64,
    /// Maximum size of a reassembled fragmented message (SEC-WS-009).
    pub max_message_bytes: u64,
    /// Interval between server-initiated pings (SEC-WS-008).
    pub ping_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_payload: 1024 * 1024,
            max_message_bytes: 1024 * 1024,
            ping_interval: Duration::from_secs(30),
        }
    }
}
