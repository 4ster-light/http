//! Application-level connection glue: reads requests from a persistent buffer,
//! detects WebSocket upgrades, dispatches to the HTTP handlers, and turns
//! parse failures into proper protocol responses (REFACTOR-PLAN.md §3.2 D7,
//! F8).

use crate::{config::Config, error::ServerError, handler};
use bytes::BytesMut;
use tokio::{io::AsyncWriteExt, net::TcpStream};
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
                        let _ = socket.write_all(&response.to_bytes()).await;
                        error!(?peer_addr, reason, "Rejected invalid WebSocket upgrade");
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
                let _ = socket.write_all(&response.to_bytes()).await;
                error!(?peer_addr, error = ?e, status = %status, "Rejected request");
                return Err(e.into());
            }
        }
    }
}
