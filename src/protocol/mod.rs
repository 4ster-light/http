use crate::{error::ServerError, websocket};
use tokio::{io::AsyncReadExt, net::TcpStream};

pub mod handler;
pub mod request;
pub mod response;

/// Entry point for HTTP connections.
/// Detects WebSocket upgrades or delegates to HTTP handler.
pub async fn handle_connection(mut socket: TcpStream) -> Result<(), ServerError> {
    let mut buffer = [0; 1024];
    let n = socket.read(&mut buffer).await?;
    let request = request::HttpRequest::from_buffer(&buffer[..n])?;

    if let Some(websocket_key) = websocket::handshake::is_websocket_request(&request) {
        websocket::handle_websocket(socket, websocket_key).await?
    } else {
        handler::handle_http_request(&mut socket, request).await?
    }

    Ok(())
}
