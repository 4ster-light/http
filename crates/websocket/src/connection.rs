//! WebSocket connection lifecycle: the frame loop over generic IO with
//! echo behavior, liveness ping/pong, fragmentation reassembly, and the
//! close handshake (REFACTOR-PLAN.md §3.2 D2, SEC-WS-009).

use crate::{
    error::{Error, Result},
    frame::{self, Frame, OpCode, ParseError},
    handshake,
    limits::Limits,
};
use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, interval_at},
};
use tracing::{info, warn};

/// A complete (possibly reassembled) data message delivered to the echo
/// logic.
enum Message {
    Text(String),
    Binary(Vec<u8>),
}

/// State of a fragmented message in progress (RFC 6455 §5.4).
struct Reassembly {
    opcode: OpCode,
    buffer: Vec<u8>,
}

/// The outcome of one read+parse step: a complete frame, or a protocol
/// violation that must be answered with a specific close code.
enum FrameRead {
    Frame(Frame),
    Violation(ParseError),
}

/// Handles the WebSocket connection lifecycle over any `AsyncRead +
/// AsyncWrite` transport (duplex streams in tests, `TcpStream` in the demo).
///
/// The loop reads frames off a persistent buffer, handles control frames on
/// arrival (including mid-message, per SEC-WS-009), reassembles fragmented
/// messages, and enforces [`Limits`]. Protocol violations are answered with
/// the appropriate close code (1002/1007/1009) instead of a silent drop
/// (F5/F6/F8).
///
/// # Errors
///
/// Returns on IO failure or an unrecoverable protocol failure; a best-effort
/// close frame is sent before returning.
pub async fn handle_websocket<IO>(io: &mut IO, websocket_key: &str, limits: &Limits) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let handshake_response = handshake::generate_accept(websocket_key)?;
    io.write_all(&handshake_response).await?;

    info!("WebSocket connection established");

    let mut buffer = BytesMut::with_capacity(4096);
    // The first tick of `interval` fires immediately; schedule the first
    // ping one full interval out instead (F10).
    let mut ping_interval =
        interval_at(Instant::now() + limits.ping_interval, limits.ping_interval);
    let mut awaiting_pong = false;
    let mut reassembly: Option<Reassembly> = None;

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                if awaiting_pong {
                    warn!("Client did not respond to PING, closing connection");
                    let _ = send_close(io, 1002, "Ping timeout").await;
                    break;
                }
                let ping = Frame::ping(Vec::new());
                if io.write_all(&ping.to_bytes()).await.is_err() {
                    break;
                }
                awaiting_pong = true;
            }
            result = read_frame(io, &mut buffer, limits) => {
                match result {
                    Ok(FrameRead::Frame(frame)) => {
                        if frame.is_control() {
                            match handle_control(io, &frame, &mut awaiting_pong).await {
                                ControlFlow::Continue => {}
                                ControlFlow::Break => break,
                            }
                            continue;
                        }
                        match handle_data(&frame, &mut reassembly, limits) {
                            Ok(Some(message)) => {
                                if send_echo(io, message).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                let (code, reason) = close_for_parse_error(&e);
                                let _ = send_close(io, code, reason).await;
                                return Err(Error::WebSocketError(format!(
                                    "Protocol violation: {reason} ({e:?})"
                                )));
                            }
                        }
                    }
                    Ok(FrameRead::Violation(e)) => {
                        let (code, reason) = close_for_parse_error(&e);
                        let _ = send_close(io, code, reason).await;
                        return Err(Error::WebSocketError(format!(
                            "Protocol violation: {reason} ({e:?})"
                        )));
                    }
                    Err(e) => {
                        let _ = io.write_all(&Frame::close().to_bytes()).await;
                        return Err(e);
                    }
                }
            }
        }
    }

    info!("WebSocket connection closed");
    Ok(())
}

/// Answered control frames; `Break` ends the loop.
enum ControlFlow {
    Continue,
    Break,
}

async fn handle_control<IO>(io: &mut IO, frame: &Frame, awaiting_pong: &mut bool) -> ControlFlow
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match frame.opcode {
        OpCode::Close => {
            match frame::decode_close_payload(&frame.payload) {
                Ok(Some((code, reason))) => {
                    info!(code, %reason, "Received close frame");
                }
                Ok(None) => info!("Received close frame"),
                Err(e) => {
                    warn!(error = ?e, "Invalid close frame");
                }
            }
            let _ = io.write_all(&Frame::close().to_bytes()).await;
            ControlFlow::Break
        }
        OpCode::Ping => {
            info!("Received PING, sending PONG");
            if io
                .write_all(&Frame::pong(frame.payload.clone()).to_bytes())
                .await
                .is_err()
            {
                ControlFlow::Break
            } else {
                ControlFlow::Continue
            }
        }
        OpCode::Pong => {
            info!("Received PONG");
            *awaiting_pong = false;
            ControlFlow::Continue
        }
        _ => ControlFlow::Continue,
    }
}

/// Feeds a data frame into the reassembly state machine per RFC 6455 §5.4.
/// Returns a complete message when this frame finalizes it.
///
/// # Errors
///
/// `ParseError::ProtocolViolation` for a continuation with no open message or
/// a new data frame while a message is open; `ParseError::FrameTooLarge` when
/// the reassembled size exceeds `limits.max_message_bytes`.
fn handle_data(
    frame: &Frame,
    reassembly: &mut Option<Reassembly>,
    limits: &Limits,
) -> std::result::Result<Option<Message>, ParseError> {
    match (frame.opcode, frame.fin) {
        (OpCode::Text | OpCode::Binary, true) => {
            if reassembly.is_some() {
                return Err(ParseError::ProtocolViolation(
                    "New message while a fragmented one is open",
                ));
            }
            finish_message(frame.opcode, frame.payload.clone()).map(Some)
        }
        (OpCode::Text | OpCode::Binary, false) => {
            if reassembly.is_some() {
                return Err(ParseError::ProtocolViolation(
                    "New message while a fragmented one is open",
                ));
            }
            *reassembly = Some(Reassembly {
                opcode: frame.opcode,
                buffer: frame.payload.clone(),
            });
            Ok(None)
        }
        (OpCode::Continuation, _) => {
            let Some(state) = reassembly else {
                return Err(ParseError::ProtocolViolation(
                    "Continuation without an open message",
                ));
            };
            let max_message = usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX);
            if state.buffer.len() + frame.payload.len() > max_message {
                return Err(ParseError::FrameTooLarge);
            }
            state.buffer.extend_from_slice(&frame.payload);
            if frame.fin {
                let opcode = state.opcode;
                let buffer = std::mem::take(&mut state.buffer);
                *reassembly = None;
                finish_message(opcode, buffer).map(Some)
            } else {
                Ok(None)
            }
        }
        _ => Err(ParseError::ProtocolViolation("Unexpected frame kind")),
    }
}

/// Validates and wraps a finished message (UTF-8 check for text, SEC-WS-005).
fn finish_message(opcode: OpCode, buffer: Vec<u8>) -> std::result::Result<Message, ParseError> {
    match opcode {
        OpCode::Text => {
            let text = String::from_utf8(buffer).map_err(|_| ParseError::InvalidUtf8)?;
            Ok(Message::Text(text))
        }
        OpCode::Binary => Ok(Message::Binary(buffer)),
        _ => Err(ParseError::ProtocolViolation("Control frame as data")),
    }
}

/// Sends the echo response for a completed message.
async fn send_echo<IO>(io: &mut IO, message: Message) -> std::io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    let frame = match message {
        Message::Text(text) => Frame::text(&format!("Echo: {text}")),
        Message::Binary(payload) => Frame::binary(payload),
    };
    io.write_all(&frame.to_bytes()).await
}

/// Close-code mapping from parse failures (protocol answers, not drops).
fn close_for_parse_error(e: &ParseError) -> (u16, &'static str) {
    match e {
        ParseError::InvalidUtf8 => (1007, "Invalid UTF-8 in text message"),
        ParseError::FrameTooLarge => (1009, "Message too big"),
        _ => (1002, "Protocol error"),
    }
}

/// Sends a close frame with a code and reason.
async fn send_close<IO>(io: &mut IO, code: u16, reason: &str) -> std::io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    io.write_all(&Frame::close_with_code(code, reason).to_bytes())
        .await
}

/// Reads bytes, appends them to the persistent buffer, and parses one frame.
/// The buffer is parsed first, so frames already received (e.g. a pipelined
/// continuation) are processed without waiting for new IO. Violations are
/// reported as data so the caller can answer with the right close code.
async fn read_frame<IO>(io: &mut IO, buffer: &mut BytesMut, limits: &Limits) -> Result<FrameRead>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match Frame::parse(buffer, limits) {
            Ok((frame, consumed)) => {
                let _ = buffer.split_to(consumed);
                return Ok(FrameRead::Frame(frame));
            }
            Err(ParseError::Incomplete) => {}
            Err(e) => return Ok(FrameRead::Violation(e)),
        }

        let mut chunk = [0u8; 4096];
        match io.read(&mut chunk).await {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::from(
                    std::io::ErrorKind::UnexpectedEof,
                )));
            }
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(Error::Io(e)),
        }
    }
}
