//! Typed security limits for the HTTP layer (REFACTOR-PLAN.md §3.2 D4).
//!
//! One struct carrying every security knob, passed explicitly by the caller.
//! Defaults match what responses advertise in the `Keep-Alive` header.

use std::time::Duration;

/// Security limits for request parsing and connection handling.
///
/// The defaults are: 16 KiB head cap (SEC-HTTP-001), 10 MiB body cap
/// (SEC-HTTP-004), a 10 s header read timeout (SEC-HTTP-002), a 5 s keep-alive
/// idle timeout and 100 requests per connection (SEC-HTTP-005).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum size of the request head (request line plus headers). Excess
    /// yields a `431` response (SEC-HTTP-001).
    pub max_head_bytes: usize,
    /// Maximum size of a request body. Excess yields a `413` response
    /// (SEC-HTTP-004).
    pub max_body_bytes: usize,
    /// Time allowed for a partially received request head to complete; a form
    /// of Slow-Loris mitigation (SEC-HTTP-002).
    pub head_read_timeout: Duration,
    /// Idle keep-alive timeout between requests. `None` disables it; the
    /// default matches the advertised `Keep-Alive: timeout=5` (SEC-HTTP-005).
    pub keep_alive_idle_timeout: Option<Duration>,
    /// Maximum number of requests served on one connection. `None` disables
    /// the counter; the default matches the advertised `Keep-Alive: max=100`
    /// (SEC-HTTP-005).
    pub max_requests_per_connection: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 16 * 1024,
            max_body_bytes: 10 * 1024 * 1024,
            head_read_timeout: Duration::from_secs(10),
            keep_alive_idle_timeout: Some(Duration::from_secs(5)),
            max_requests_per_connection: Some(100),
        }
    }
}
