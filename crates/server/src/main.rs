mod config;
mod connection;
mod error;
mod handler;

use crate::{config::Config, connection::handle_connection, error::Result};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::default();
    let listener = TcpListener::bind(&config.address).await?;
    info!("Server running on http://{}", config.address);

    loop {
        let (socket, addr) = listener.accept().await?;
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, &config).await {
                error!(?addr, error = ?e, "Connection error");
            }
        });
    }
}
