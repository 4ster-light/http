use http::limits::Limits;

/// Demo server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Explicit bind address (plan decision D8): no port scanning fallback,
    /// bind failure is fatal. `SERVER_ADDR` may override for tests and
    /// deployments.
    pub address: String,
    /// Static file directory, resolved against this crate at compile time.
    pub static_dir: String,
    /// Typed security limits for HTTP parsing and connection policy.
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        let address = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        Self {
            address,
            // Resolved relative to this crate (not the process CWD) so the
            // server serves static files identically regardless of where
            // `cargo run -p server` is invoked from.
            static_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/static").to_string(),
            limits: Limits::default(),
        }
    }
}
