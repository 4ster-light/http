use crate::{config::Config, error::ServerError, websocket};
use bytes::BytesMut;
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::{error, info};

pub mod handler;
pub mod request;
pub mod response;

/// Entry point for HTTP connections.
/// Detects WebSocket upgrades or delegates to HTTP handler with keep-alive support.
pub async fn handle_connection(mut socket: TcpStream, config: &Config) -> Result<(), ServerError> {
    let peer_addr = socket.peer_addr().ok();
    info!(?peer_addr, "New connection");

    loop {
        // Read until we find the end of headers (\r\n\r\n)
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            let mut temp_buf = [0u8; 1024];
            match socket.read(&mut temp_buf).await {
                Ok(0) => {
                    if buffer.is_empty() {
                        info!(?peer_addr, "Connection closed by client");
                        return Ok(());
                    } else {
                        error!(?peer_addr, "Connection closed unexpectedly during request");
                        return Err(ServerError::InvalidHttpRequest("Incomplete request"));
                    }
                }
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);

                    // Look for \r\n\r\n in the accumulated buffer
                    if let Some(header_end) = find_header_end(&buffer) {
                        let request =
                            request::HttpRequest::from_buffer(&buffer[..header_end], &mut socket)
                                .await?;

                        // Check if this is a WebSocket upgrade
                        if let Some(websocket_key) =
                            websocket::handshake::is_websocket_request(&request)
                        {
                            info!(?peer_addr, "Upgrading to WebSocket");
                            return websocket::handle_websocket(socket, websocket_key).await;
                        }

                        // Handle HTTP request
                        let should_close = request
                            .get_header("connection")
                            .map(|v| v.to_lowercase() == "close")
                            .unwrap_or(false);

                        if let Err(e) =
                            handler::handle_http_request(&mut socket, request, config).await
                        {
                            error!(?peer_addr, error = ?e, "Error handling HTTP request");
                            return Err(e);
                        }

                        if should_close {
                            info!(?peer_addr, "Connection: close requested, closing");
                            return Ok(());
                        }

                        // Continue reading next request on the same connection
                        info!(?peer_addr, "Keeping connection alive for next request");
                        break;
                    }

                    // Prevent header bombs
                    if buffer.len() > 16384 {
                        error!(?peer_addr, "Request headers too large");
                        return Err(ServerError::InvalidHttpRequest("Headers too large"));
                    }
                }
                Err(e) => {
                    error!(?peer_addr, error = ?e, "Failed to read from socket");
                    return Err(e.into());
                }
            }
        }
    }
}

/// Find the position after \r\n\r\n in the buffer
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    for i in 0..buffer.len().saturating_sub(3) {
        if buffer[i] == b'\r'
            && buffer[i + 1] == b'\n'
            && buffer[i + 2] == b'\r'
            && buffer[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
}
