use crate::{error::Result, websocket::frame::WebSocketFrame};
use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, interval},
};
use tracing::{error, info, warn};

pub mod frame;
pub mod handshake;

/// Handles the WebSocket connection lifecycle with ping/pong support.
pub async fn handle_websocket(mut socket: TcpStream, websocket_key: &str) -> Result<()> {
    let handshake_response = handshake::generate_accept(websocket_key)?;
    socket.write_all(&handshake_response).await?;

    let peer_addr = socket.peer_addr().ok();
    info!(?peer_addr, "WebSocket connection established");

    // Frame buffering
    let mut buffer = BytesMut::with_capacity(4096);
    let mut ping_interval = interval(Duration::from_secs(30));
    let mut awaiting_pong = false;

    loop {
        tokio::select! {
            // Handle ping timer
            _ = ping_interval.tick() => {
                if awaiting_pong {
                    warn!(?peer_addr, "Client did not respond to PING, closing connection");
                    let _ = socket.write_all(&WebSocketFrame::close_with_code(1002, "Ping timeout").to_bytes()).await;
                    break;
                }

                info!(?peer_addr, "Sending PING");
                let ping = WebSocketFrame::Ping(Vec::new());
                if let Err(e) = socket.write_all(&ping.to_bytes()).await {
                    error!(?peer_addr, error = ?e, "Failed to send PING");
                    break;
                }

                awaiting_pong = true;
            }

            // Handle incoming data
            result = read_frame(&mut socket, &mut buffer) => {
                match result {
                    Ok(Some(frame)) => {
                        match frame {
                            WebSocketFrame::Text(text) => {
                                info!(?peer_addr, text = %text, "Received text frame");
                                let response = WebSocketFrame::Text(format!("Echo: {}", text));
                                if let Err(e) = socket.write_all(&response.to_bytes()).await {
                                    error!(?peer_addr, error = ?e, "Failed to send response");
                                    break;
                                }
                            }
                            WebSocketFrame::Binary(data) => {
                                info!(?peer_addr, len = data.len(), "Received binary frame");
                                let response = WebSocketFrame::Binary(data);
                                if let Err(e) = socket.write_all(&response.to_bytes()).await {
                                    error!(?peer_addr, error = ?e, "Failed to send response");
                                    break;
                                }
                            }
                            WebSocketFrame::Ping(data) => {
                                info!(?peer_addr, "Received PING, sending PONG");
                                let pong = WebSocketFrame::Pong(data);
                                if let Err(e) = socket.write_all(&pong.to_bytes()).await {
                                    error!(?peer_addr, error = ?e, "Failed to send PONG");
                                    break;
                                }
                            }
                            WebSocketFrame::Pong(_) => {
                                info!(?peer_addr, "Received PONG");
                                awaiting_pong = false;
                            }
                            WebSocketFrame::Close(code_reason) => {
                                if let Some((code, reason)) = code_reason {
                                    info!(?peer_addr, code = code, reason = %reason, "Received close frame");
                                } else {
                                    info!(?peer_addr, "Received close frame");
                                }
                                let close = WebSocketFrame::Close(None);
                                let _ = socket.write_all(&close.to_bytes()).await;
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        // Need more data, continue reading
                        continue;
                    }
                    Err(e) => {
                        error!(?peer_addr, error = ?e, "Error reading frame");
                        break;
                    }
                }
            }
        }
    }

    info!(?peer_addr, "WebSocket connection closed");
    Ok(())
}

/// Read and parse a WebSocket frame from the socket, buffering incomplete frames
async fn read_frame(
    socket: &mut TcpStream,
    buffer: &mut BytesMut,
) -> Result<Option<WebSocketFrame>> {
    let mut temp_buf = [0u8; 4096];

    match socket.read(&mut temp_buf).await {
        Ok(0) => {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        Ok(n) => {
            buffer.extend_from_slice(&temp_buf[..n]);
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    // Try to parse a frame from the buffer
    match WebSocketFrame::parse(buffer) {
        Ok((frame, consumed)) => {
            // Remove consumed bytes from buffer
            buffer.advance(consumed);
            Ok(Some(frame))
        }
        Err(frame::ParseError::Incomplete) => {
            // Need more data
            Ok(None)
        }
        Err(e) => Err(crate::error::ServerError::WebSocketError(format!(
            "Parse error: {:?}",
            e
        ))),
    }
}
