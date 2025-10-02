use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream
};
use crate::{
    protocol::request::HttpRequest,
    error::ServerError,
    websocket::frame::WebSocketFrame
};

pub mod handshake;
pub mod frame;

/// Handles the WebSocket connection lifecycle.
pub async fn handle_websocket(mut socket: TcpStream, request: HttpRequest) -> Result<(), ServerError> {
    // Perform handshake
    let handshake_response = handshake::generate_accept(&request)?;
    socket.write_all(&handshake_response).await?;

    // Process WebSocket messages
    loop {
        let mut buffer = [0; 1024];
        let n = socket.read(&mut buffer).await?;
        
        if n == 0 {
            break; // Connection closed
        }
        
        if let Some(frame) = frame::WebSocketFrame::parse(&buffer[..n]) {
            match frame {
                WebSocketFrame::Text(text) => {
                    println!("Received: {}", text);
                    let response = WebSocketFrame::Text(format!("Echo: {}", text));
                    socket.write_all(&response.to_bytes()).await?;
                }
                WebSocketFrame::Ping(data) => {
                    // Respond to ping with pong
                    let pong = WebSocketFrame::Pong(data);
                    socket.write_all(&pong.to_bytes()).await?;
                }
                WebSocketFrame::Close => {
                    // Send close frame back and break
                    let close = WebSocketFrame::Close;
                    socket.write_all(&close.to_bytes()).await?;
                    break;
                }
                WebSocketFrame::Binary(data) => {
                    println!("Received binary data: {} bytes", data.len());
                    // Echo binary data back
                    let response = WebSocketFrame::Binary(data);
                    socket.write_all(&response.to_bytes()).await?;
                }
                WebSocketFrame::Pong(_) => {
                    // Just acknowledge pong, no response needed
                    println!("Received pong");
                }
            }
        }
    }
    Ok(())
}
