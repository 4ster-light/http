use http::{config::Config, error::Result, protocol::handle_connection};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::default();
    let listener = TcpListener::bind(&config.address).await?;
    println!("Server running on http://{}", config.address);

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}
