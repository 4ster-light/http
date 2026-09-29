//! Application-level connection glue: reads requests from a persistent buffer,
//! detects WebSocket upgrades, dispatches to the HTTP handlers, and turns
//! parse failures into proper protocol responses (SEC-HTTP-008, F8).

use crate::{config::Config, error::ServerError, handler};
use bytes::BytesMut;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tracing::{error, info};

/// Entry point for HTTP connections.
///
/// Owns the buffer for the whole connection lifetime (SEC-HTTP-007): request
/// bodies and pipelined requests are consumed in order, and nothing is
/// silently dropped. Keep-alive limits from [`Config::limits`] are enforced
/// (SEC-HTTP-005), matching what responses advertise.
pub async fn handle_connection(mut socket: TcpStream, config: &Config) -> Result<(), ServerError> {
    let peer_addr = socket.peer_addr().ok();
    info!(?peer_addr, "New connection");

    let limits = &config.limits;
    let mut buffer = BytesMut::with_capacity(8192);
    let mut served: u64 = 0;

    loop {
        match http::connection::read_request(&mut socket, &mut buffer, limits).await {
            // Clean close, or keep-alive idle timeout elapsed.
            Ok(None) => return Ok(()),
            Ok(Some(request)) => {
                match websocket::handshake::validate_upgrade(&request) {
                    websocket::handshake::UpgradeCheck::Valid(key) => {
                        info!(?peer_addr, "Upgrading to WebSocket");
                        websocket::handle_websocket(
                            &mut socket,
                            key,
                            &websocket::limits::Limits::default(),
                        )
                        .await
                        .map_err(ServerError::from)?;
                        return Ok(());
                    }
                    websocket::handshake::UpgradeCheck::Invalid(reason) => {
                        // F11/SEC-WS-007: reject malformed upgrades with 400
                        // instead of silently treating them as HTTP.
                        let response = http::response::HttpResponse::bad_request()
                            .with_text(reason)
                            .close_connection();
                        error!(?peer_addr, reason, "Rejected invalid WebSocket upgrade");
                        write_response_and_close(&mut socket, response.to_bytes()).await;
                        return Err(http::Error::InvalidHttpRequest(reason).into());
                    }
                    websocket::handshake::UpgradeCheck::NotUpgrade => {}
                }

                served += 1;
                let over_budget = limits
                    .max_requests_per_connection
                    .is_some_and(|max| served >= max);
                let close_after = request.should_close() || over_budget;

                if let Err(e) =
                    handler::handle_http_request(&mut socket, request, config, close_after).await
                {
                    error!(?peer_addr, error = ?e, "Error handling HTTP request");
                    return Err(e);
                }

                if close_after {
                    info!(?peer_addr, "Closing connection");
                    return Ok(());
                }
                info!(?peer_addr, "Keeping connection alive for next request");
            }
            Err(e) => {
                // F8: answer with the mapped status instead of dropping the
                // connection silently.
                let status = e.status();
                let body = format!("{}\n", status.reason_phrase());
                let response = http::response::HttpResponse::new(status)
                    .with_text(&body)
                    .close_connection();
                error!(?peer_addr, error = ?e, status = %status, "Rejected request");
                write_response_and_close(&mut socket, response.to_bytes()).await;
                return Err(e.into());
            }
        }
    }
}

/// Sends a final response and closes the connection gracefully.
///
/// Writing the response and immediately dropping the socket is not enough:
/// with request bytes still unread in the receive queue the close completes
/// as a TCP RST, and an RST that races the client's read of the response can
/// discard it entirely — the client sees an empty connection even though the
/// server answered (observed with 64 KiB header bombs: intermittent empty
/// response instead of the correct `431`). The sequence here is write,
/// `shutdown`s the write side so the client sees EOF after the response, then
/// drains the client's remaining bytes until EOF.
///
/// The drain is bounded (SEC-HTTP-002 posture): at most 1 MiB of discarded
/// attacker bytes and a hard 2 s budget, whichever runs out first, so this
/// never turns into an unbounded buffer or wait for a hostile client.
async fn write_response_and_close(socket: &mut TcpStream, response: Vec<u8>) {
    // At most 1 MiB of attacker bytes and a hard 2 s budget, whichever runs
    // out first, so the drain never becomes an unbounded buffer or wait.
    const MAX_DRAIN: usize = 1 << 20;
    const DRAIN_WAIT: Duration = Duration::from_secs(2);
    if let Err(e) = socket.write_all(&response).await {
        error!(error = ?e, "Could not send final response; closing");
        return;
    }
    if let Err(e) = socket.shutdown().await {
        error!(error = ?e, "Could not shut down write side; closing");
        return;
    }
    let deadline = Instant::now() + DRAIN_WAIT;
    let mut drained: usize = 0;
    let mut discard = [0u8; 8192];
    while drained < MAX_DRAIN {
        match timeout_at(deadline, socket.read(&mut discard)).await {
            // Client closed after reading the response; RST from the client;
            // or the bounded drain wait elapsed. Any of these ends the drain.
            Ok(Ok(0) | Err(_)) | Err(_) => return,
            // More request bytes to discard (header bombs, pipelined
            // requests after the error response, ...).
            Ok(Ok(n)) => drained += n,
        }
    }
}
