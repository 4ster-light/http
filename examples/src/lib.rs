//! Minimal client-side WebSocket helpers shared by the example binaries.
//!
//! The `websocket` crate implements the *server* side of RFC 6455: its
//! [`Frame::parse`](websocket::frame::Frame::parse) rejects unmasked frames
//! (server-to-client frames are always unmasked) and its `to_bytes` produces
//! unmasked output. A client needs exactly the opposite: mask everything it
//! sends (§5.3), reject any masked frame the server sends (§5.1), and verify
//! the `Sec-WebSocket-Accept` handshake digest (§4.2.2).
//!
//! This module fills that gap with ~120 lines of deliberately small, heavily
//! commented code. It is example material: it shows what a compliant client
//! must do on the wire, and doubles as a living reference for reading the
//! server's half of the same rules.
//!
//! Masking entropy note (RFC 6455 §5.3): the mask must be *unpredictable* to
//! intermediaries, not cryptographic. [`random_mask`] and [`random_key`] draw
//! from `std::collections::hash_map::RandomState`, which is seeded from the
//! OS entropy pool, so no random-number dependency is needed here. A
//! production client may still prefer a dedicated CSPRNG.

use std::io;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use websocket::frame::{Frame, OpCode};
use websocket::handshake::accept_key;

/// Largest server frame payload this example client will buffer (1 MiB,
/// mirroring the server's own `SEC-WS-002` default).
pub const MAX_SERVER_PAYLOAD: usize = 1024 * 1024;

/// Errors from the client-side codec and IO loop.
#[derive(Debug)]
pub enum ClientError {
    /// Underlying socket failure.
    Io(io::Error),
    /// The peer closed the transport (possibly without a close frame).
    ConnectionClosed,
    /// The buffer does not yet hold a complete frame; read more bytes.
    /// Internal to [`parse_server_frame`]/[`read_server_frame`].
    Incomplete,
    /// The server violated the protocol; the client MUST fail the
    /// connection (RFC 6455 §7.1.7 style failure).
    Protocol(&'static str),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io error: {e}"),
            ClientError::ConnectionClosed => write!(f, "connection closed by peer"),
            ClientError::Incomplete => write!(f, "need more bytes"),
            ClientError::Protocol(reason) => write!(f, "protocol violation: {reason}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Generates four fresh mask bytes (RFC 6455 §5.3).
///
/// Each call builds a new `RandomState`, whose keys come from the OS entropy
/// pool; hashing nothing yields 64 bits derived from those keys.
#[must_use]
pub fn random_mask() -> [u8; 4] {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u8(0);
    let full = hasher.finish().to_le_bytes();
    [full[0], full[1], full[2], full[3]]
}

/// Generates a random 16-byte `Sec-WebSocket-Key` as base64 (RFC 6455 §4.2.1).
///
/// The key is base64-of-16-bytes; the server's §4.2.1 validation (SEC-WS-007)
/// rejects anything else.
#[must_use]
pub fn random_key() -> String {
    use base64::Engine as _;
    use std::hash::{BuildHasher, Hasher};

    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u8(1);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes()[..chunk.len()]);
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Builds the opening-handshake request line and headers (RFC 6455 §4.2.1).
///
/// `host_header` is the value for the `Host` header (`host` or `host:port`).
/// The blank line terminating the head is included.
#[must_use]
pub fn build_upgrade_request(host_header: &str, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    )
}

/// Verifies the server's `101` handshake response head (RFC 6455 §4.2.2).
///
/// Checks the status line, the `Upgrade`/`Connection` headers, and — most
/// importantly — that `Sec-WebSocket-Accept` equals
/// [`accept_key`] applied to our key. RFC 6455 §4.2.2 requires the client to
/// *fail the WebSocket connection* when the digest does not match, so this
/// is not optional hardening: it is the handshake.
///
/// # Errors
///
/// Returns a human-readable reason string when the response is not a valid
/// accept for `key`.
pub fn verify_upgrade_response(head: &str, key: &str) -> Result<(), String> {
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101") {
        return Err(format!(
            "expected `101 Switching Protocols`, got `{status}`"
        ));
    }

    // Header names are case-insensitive (RFC 9110 §5.1); collect
    // lowercased-name → value.
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let get = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    if get("upgrade").is_none_or(|v| !v.eq_ignore_ascii_case("websocket")) {
        return Err("missing or wrong `Upgrade` header".to_string());
    }
    if get("connection").is_none_or(|v| !v.to_lowercase().contains("upgrade")) {
        return Err("missing or wrong `Connection` header".to_string());
    }
    let Some(received) = get("sec-websocket-accept") else {
        return Err("missing `Sec-WebSocket-Accept` header".to_string());
    };
    let expected = accept_key(key);
    if received != expected {
        return Err(format!(
            "`Sec-WebSocket-Accept` mismatch: got `{received}`, expected `{expected}`"
        ));
    }
    Ok(())
}

/// Serializes one client-to-server frame, masked per RFC 6455 §5.2/§5.3.
///
/// Everything a client sends must be masked; the examples always send
/// unfragmented frames (`fin = true`, no continuation), which is legal for
/// any message that fits one frame.
///
/// # Panics
///
/// Never in practice: the `expect`s guard length encodings that are proven
/// in range by the branch structure (< 126, < 65536), mirroring the server
/// codec in `websocket::frame::Frame::to_bytes`.
#[must_use]
pub fn encode_client_frame(fin: bool, opcode: OpCode, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 } else { 0x00 } | opcode as u8);

    // The mask bit (MSB of the second byte) is set for every client frame.
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | u8::try_from(len).expect("branch guarantees len < 126"));
    } else if len < 65_536 {
        out.push(0x80 | 0x7E);
        out.extend_from_slice(
            &u16::try_from(len)
                .expect("branch guarantees len < 65536")
                .to_be_bytes(),
        );
    } else {
        out.push(0x80 | 0x7F);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    // XOR every payload byte with mask[i % 4] (RFC 6455 §5.3).
    for (i, byte) in payload.iter().enumerate() {
        out.push(byte ^ mask[i % 4]);
    }
    out
}

/// Convenience wrapper: sends a complete text message as one masked frame.
///
/// # Errors
///
/// Propagates socket errors.
pub async fn send_text<IO>(io: &mut IO, text: &str) -> Result<(), ClientError>
where
    IO: AsyncWrite + Unpin,
{
    let frame = encode_client_frame(true, OpCode::Text, text.as_bytes(), random_mask());
    io.write_all(&frame).await.map_err(ClientError::Io)
}

/// Sends a masked close frame with a status code (RFC 6455 §7.1.6).
///
/// # Errors
///
/// Propagates socket errors.
pub async fn send_close<IO>(io: &mut IO, code: u16, reason: &str) -> Result<(), ClientError>
where
    IO: AsyncWrite + Unpin,
{
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    let frame = encode_client_frame(true, OpCode::Close, &payload, random_mask());
    io.write_all(&frame).await.map_err(ClientError::Io)
}

/// Parses one unmasked (server-to-client) frame from the front of `data`,
/// returning the frame and the number of bytes consumed.
///
/// Mirrors the server's codec rules from the client's side of §5.1: a masked
/// server frame is a protocol violation the client MUST fail on.
///
/// # Errors
///
/// Returns [`ClientError::Protocol`] for rule violations and
/// [`ClientError::ConnectionClosed`] is never produced here; use
/// [`read_server_frame`] for the buffered version that also handles IO.
pub fn parse_server_frame(data: &[u8]) -> Result<(Frame, usize), ClientError> {
    if data.len() < 2 {
        return Err(ClientError::Incomplete);
    }
    let first = data[0];
    let fin = first & 0x80 != 0;
    let opcode =
        OpCode::from_wire(first).ok_or(ClientError::Protocol("reserved opcode from server"))?;

    let masked = data[1] & 0x80 != 0;
    if masked {
        // RFC 6455 §5.1: "A client MUST close a connection if it detects a
        // masked frame."
        return Err(ClientError::Protocol("server sent a masked frame"));
    }
    let mut len = u64::from(data[1] & 0x7F);
    let mut offset = 2;
    if len == 126 {
        if data.len() < 4 {
            return Err(ClientError::Incomplete);
        }
        len = u64::from(u16::from_be_bytes([data[2], data[3]]));
        offset = 4;
    } else if len == 127 {
        if data.len() < 10 {
            return Err(ClientError::Incomplete);
        }
        let mut long_bytes = [0u8; 8];
        long_bytes.copy_from_slice(&data[2..10]);
        let long = u64::from_be_bytes(long_bytes);
        if long & (1 << 63) != 0 {
            return Err(ClientError::Protocol("MSB set in 64-bit length"));
        }
        len = long;
        offset = 10;
    }
    if opcode.is_control() && (len > 125 || !fin) {
        // RFC 6455 §5.5: control frames are never fragmented and ≤ 125 B.
        return Err(ClientError::Protocol("invalid control frame from server"));
    }
    if len > MAX_SERVER_PAYLOAD as u64 {
        return Err(ClientError::Protocol("server frame exceeds client cap"));
    }
    let payload_len = usize::try_from(len)
        .map_err(|_| ClientError::Protocol("frame length not representable"))?;
    let end = offset + payload_len;
    if data.len() < end {
        return Err(ClientError::Incomplete);
    }
    Ok((
        Frame {
            fin,
            opcode,
            payload: data[offset..end].to_vec(),
        },
        end,
    ))
}

/// Reads bytes from `io` into `buffer` until one complete server frame can
/// be parsed out of it. Consumed bytes are drained from `buffer`.
///
/// # Errors
///
/// [`ClientError::ConnectionClosed`] on EOF, IO errors verbatim, and
/// [`ClientError::Protocol`] for any server-side rule violation.
pub async fn read_server_frame<IO>(io: &mut IO, buffer: &mut Vec<u8>) -> Result<Frame, ClientError>
where
    IO: AsyncRead + Unpin,
{
    loop {
        match parse_server_frame(buffer) {
            Ok((frame, consumed)) => {
                buffer.drain(..consumed);
                return Ok(frame);
            }
            Err(ClientError::Incomplete) => {}
            Err(e) => return Err(e),
        }
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await.map_err(ClientError::Io)?;
        if n == 0 {
            return Err(ClientError::ConnectionClosed);
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

/// Reads bytes from `io` until the `\r\n\r\n` end of an HTTP response head
/// and returns the head as text. The WebSocket frame stream begins
/// immediately after the head; the demo server sends no body after `101`,
/// so nothing is left unread on the socket.
///
/// # Errors
///
/// [`ClientError::ConnectionClosed`] on EOF, IO errors verbatim, and
/// [`ClientError::Protocol`] for an oversized head (16 KiB cap, matching the
/// server's `SEC-HTTP-001` default).
pub async fn read_response_head<IO>(io: &mut IO) -> Result<String, ClientError>
where
    IO: AsyncRead + Unpin,
{
    let mut head: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = io.read(&mut chunk).await.map_err(ClientError::Io)?;
        if n == 0 {
            return Err(ClientError::ConnectionClosed);
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if head.len() > 16 * 1024 {
            return Err(ClientError::Protocol("handshake response head too large"));
        }
    }
}

/// Performs the complete opening handshake on a fresh connection: sends the
/// upgrade request, reads and verifies the `101` response (§4.2.2), and
/// returns the socket ready for frames.
///
/// # Errors
///
/// Any [`ClientError`] from the underlying steps; the socket is dropped on
/// error, which is an acceptable client failure mode (§7.1.7).
pub async fn connect_and_upgrade(addr: &str, path: &str) -> Result<TcpStream, ClientError> {
    let mut socket = TcpStream::connect(addr).await.map_err(ClientError::Io)?;
    let key = random_key();
    let request = build_upgrade_request(addr, path, &key);
    socket
        .write_all(request.as_bytes())
        .await
        .map_err(ClientError::Io)?;
    let head = read_response_head(&mut socket).await?;
    if let Err(reason) = verify_upgrade_response(&head, &key) {
        println!("handshake rejected: {reason}");
        return Err(ClientError::Protocol("handshake verification failed"));
    }
    Ok(socket)
}

/// Reads and discards frames until the message `opcode` frame arrives,
/// answering server pings along the way (clients MUST answer pings, §5.5.2).
/// Returns the payload of the first frame with the wanted opcode.
///
/// # Errors
///
/// Propagates [`ClientError`]; a server `Close` frame maps to
/// [`ClientError::ConnectionClosed`].
pub async fn read_until<IO>(
    io: &mut IO,
    buffer: &mut Vec<u8>,
    opcode: OpCode,
) -> Result<Frame, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let frame = read_server_frame(io, buffer).await?;
        match frame.opcode {
            OpCode::Ping => {
                let pong = encode_client_frame(true, OpCode::Pong, &frame.payload, random_mask());
                io.write_all(&pong).await.map_err(ClientError::Io)?;
            }
            OpCode::Close => return Err(ClientError::ConnectionClosed),
            hit if hit == opcode => return Ok(frame),
            _ => {}
        }
    }
}
