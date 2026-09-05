use http::limits::Limits;

/// Demo server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Explicit bind address (plan decision D8): no port scanning fallback,
    /// bind failure is fatal. `SERVER_ADDR` may override for tests and
    /// deployments.
    pub address: String,
    /// Static file directory. Defaults to this crate's `static/` directory
    /// (resolved at compile time, not process CWD); `STATIC_DIR` overrides it
    /// for containers and deployments, where the compile-time path does not
    /// exist (ADR-0009).
    pub static_dir: String,
    /// Typed security limits for HTTP parsing and connection policy.
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        let address = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        Self {
            address,
            static_dir: std::env::var("STATIC_DIR")
                .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/static").to_string()),
            limits: Limits::default(),
        }
    }
}
