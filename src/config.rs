use crate::error::ServerError;

#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub static_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        let port = match find_available_port(8000) {
            Ok(port) => port,
            Err(err) => {
                tracing::warn!(%err, fallback_port = 8000, "Unable to reserve a port, falling back to default");
                8000
            }
        };

        Self {
            address: format!("127.0.0.1:{}", port),
            static_dir: "./static".to_string(),
        }
    }
}

fn try_bind(port: u16) -> std::result::Result<u16, std::io::Error> {
    use std::net::TcpListener;

    TcpListener::bind(("127.0.0.1", port)).map(|_| port)
}

fn find_available_port(default: u16) -> Result<u16, ServerError> {
    if let Ok(port) = try_bind(default) {
        return Ok(port);
    }

    (1024..=49151)
        .find_map(|port| try_bind(port).ok())
        .ok_or(ServerError::PortUnavailable(default))
}
