use tokio::net::TcpListener;
use http::{
    error::Result,
    protocol::handle_connection,
    config::Config
};

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
