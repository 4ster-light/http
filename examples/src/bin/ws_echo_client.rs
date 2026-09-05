//! Interactive WebSocket echo client (`ws_echo_client`).
//!
//! Walks the full RFC 6455 client flow against the demo server: opening
//! handshake with `Sec-WebSocket-Accept` verification (§4.2.2), masked text
//! frames (§5.3), ping→pong answers (§5.5.2), and a clean close handshake
//! (§7). Each step is printed so the example reads like a protocol trace.
//!
//! Usage: `cargo run -p examples --bin ws_echo_client -- [ADDR] [PATH]`
//! Defaults to `127.0.0.1:8000` (the demo server's native bind address).

use std::process::ExitCode;

use examples::{ClientError, connect_and_upgrade, read_until, send_close, send_text};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
};
use websocket::frame::OpCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args.first().map_or("127.0.0.1:8000", String::as_str);
    let path = args.get(1).map_or("/", String::as_str);

    match run(addr, path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives one interactive session.
async fn run(addr: &str, path: &str) -> Result<(), ClientError> {
    let mut socket = connect_and_upgrade(addr, path).await?;
    match session(&mut socket).await {
        Ok(()) => Ok(()),
        Err(error) => {
            // Best-effort close frame so the server sees an orderly
            // shutdown even when we exit on an error.
            let _ = send_close(&mut socket, 1011, "client error").await;
            Err(error)
        }
    }
}

/// The protocol flow, once the transport and handshake are up.
async fn session(socket: &mut TcpStream) -> Result<(), ClientError> {
    println!("handshake complete (RFC 6455 §4.2.2 accept digest verified)");

    // Echo loop: read a line, send it masked, print the echo.
    println!("type a message, or Ctrl-D to close:");
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    let mut buffer = Vec::new();
    loop {
        line.clear();
        let bytes = stdin.read_line(&mut line).await.map_err(ClientError::Io)?;
        if bytes == 0 {
            break; // EOF: fall through to the close handshake.
        }
        send_text(socket, line.trim_end()).await?;
        let echo = read_until(socket, &mut buffer, OpCode::Text).await?;
        println!("<- {}", String::from_utf8_lossy(&echo.payload));
    }

    // Close handshake (RFC 6455 §7): send 1000, await the reply.
    println!("-> close (1000)");
    send_close(socket, 1000, "bye").await?;
    match read_until(socket, &mut buffer, OpCode::Close).await {
        Ok(frame) => {
            let code = if frame.payload.len() >= 2 {
                u16::from_be_bytes([frame.payload[0], frame.payload[1]])
            } else {
                1005 // No status code present (RFC 6455 §7.1.5).
            };
            println!("<- close ({code}) — connection closed cleanly");
        }
        // The server may simply close the TCP stream after echoing our
        // close; both are acceptable §7.1.1 endings.
        Err(ClientError::ConnectionClosed) => println!("<- connection closed"),
        Err(e) => return Err(e),
    }
    Ok(())
}
