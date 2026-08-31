use crate::limits::Limits;
use bytes::{Buf, BufMut, BytesMut};

/// WebSocket frame opcode (RFC 6455 §5.2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCode {
    /// `0x0`: continuation of a fragmented message.
    Continuation = 0x0,
    /// `0x1`: a text data frame (payload is UTF-8).
    Text = 0x1,
    /// `0x2`: a binary data frame.
    Binary = 0x2,
    /// `0x8`: connection close control frame.
    Close = 0x8,
    /// `0x9`: ping control frame.
    Ping = 0x9,
    /// `0xa`: pong control frame.
    Pong = 0xa,
}

impl OpCode {
    /// Returns `true` for control opcodes (Close, Ping, Pong, RFC 6455 §5.5).
    #[must_use]
    pub fn is_control(self) -> bool {
        matches!(self, OpCode::Close | OpCode::Ping | OpCode::Pong)
    }

    /// Returns `true` for data opcodes (Text, Binary, Continuation).
    #[must_use]
    pub fn is_data(self) -> bool {
        matches!(self, OpCode::Text | OpCode::Binary | OpCode::Continuation)
    }

    /// Maps a wire opcode nibble to an opcode, if it is a registered one.
    /// Reserved opcodes are rejected (SEC-WS-003) instead of being silently
    /// mapped elsewhere.
    #[must_use]
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte & 0x0F {
            0x0 => Some(OpCode::Continuation),
            0x1 => Some(OpCode::Text),
            0x2 => Some(OpCode::Binary),
            0x8 => Some(OpCode::Close),
            0x9 => Some(OpCode::Ping),
            0xa => Some(OpCode::Pong),
            _ => None,
        }
    }
}

/// One decoded wire frame: FIN flag, opcode, and already-unmasked payload.
///
/// This is the raw frame layer the connection reassembly works on; the
/// message-level semantics live in the connection and in the constructors
/// below ([`Frame::text`], [`Frame::close`], ...).
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this frame carries the final fragment of its message.
    pub fin: bool,
    /// The frame opcode.
    pub opcode: OpCode,
    /// The unmasked payload bytes.
    pub payload: Vec<u8>,
}

/// Errors returned by [`Frame::parse`]. Each variant maps to a close code the
/// connection layer sends before shutdown (F8/F11-style protocol answers
/// instead of silent drops).
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The buffer does not yet hold a complete frame; read more bytes.
    Incomplete,
    /// A client-to-server frame arrived unmasked (RFC 6455 §5.3 violation,
    /// close 1002, SEC-WS-001).
    UnmaskedClientFrame,
    /// RSV bits set with no extension negotiated, a reserved opcode, a
    /// fragmented control frame, or a 64-bit length with the MSB set (close
    /// 1002, SEC-WS-003, F6).
    ProtocolViolation(&'static str),
    /// A control frame exceeded the 125-byte payload limit (RFC 6455 §5.5,
    /// close 1002, SEC-WS-004).
    ControlFrameTooLarge,
    /// A data frame announced more than the configured maximum (close 1009,
    /// SEC-WS-002, F5). Checked on the announced length before any payload
    /// buffering.
    FrameTooLarge,
    /// A text payload was not valid UTF-8 (close 1007, SEC-WS-005).
    InvalidUtf8,
    /// A close frame carried a status code outside the registered ranges
    /// (close 1002, SEC-WS-006).
    InvalidCloseCode,
}

impl Frame {
    /// Parses one frame from the front of `data`, returning the frame and the
    /// number of bytes consumed. Zero bytes are allocated before the
    /// announced payload size is validated against `limits` (SEC-WS-002).
    ///
    /// Expects client-to-server traffic: frames must be masked (SEC-WS-001).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Incomplete`] when more bytes are needed, or the
    /// specific protocol violation otherwise. RSV/`fin`/opcode/length rules
    /// per RFC 6455 §5.2 and §5.5 are enforced (SEC-WS-003/004).
    pub fn parse(data: &[u8], limits: &Limits) -> Result<(Self, usize), ParseError> {
        if data.len() < 2 {
            return Err(ParseError::Incomplete);
        }

        let mut buf = data;
        let start_len = buf.len();

        let first_byte = buf.get_u8();
        let fin = first_byte & 0x80 != 0;
        let rsv = first_byte & 0x70;
        if rsv != 0 {
            return Err(ParseError::ProtocolViolation("RSV bits set"));
        }
        let opcode = OpCode::from_wire(first_byte)
            .ok_or(ParseError::ProtocolViolation("Reserved opcode"))?;

        let second_byte = buf.get_u8();
        let masked = (second_byte & 0x80) != 0;
        let mut payload_length = u64::from(second_byte & 0x7F);

        if !masked {
            return Err(ParseError::UnmaskedClientFrame);
        }

        if payload_length == 126 {
            if buf.remaining() < 2 {
                return Err(ParseError::Incomplete);
            }
            payload_length = u64::from(buf.get_u16());
        } else if payload_length == 127 {
            if buf.remaining() < 8 {
                return Err(ParseError::Incomplete);
            }
            let long = buf.get_u64();
            // RFC 6455 §5.2: a 64-bit length with the MSB set is meaningless.
            if long & (1 << 63) != 0 {
                return Err(ParseError::ProtocolViolation("MSB set in 64-bit length"));
            }
            payload_length = long;
        }

        // Reject oversized data frames on the announced length, before any
        // payload is buffered (SEC-WS-002).
        if opcode.is_data() && payload_length > limits.max_frame_payload {
            return Err(ParseError::FrameTooLarge);
        }

        // Control-frame rules (RFC 6455 §5.5): never fragmented, ≤ 125 bytes.
        if opcode.is_control() {
            if payload_length > 125 {
                return Err(ParseError::ControlFrameTooLarge);
            }
            if !fin {
                return Err(ParseError::ProtocolViolation("Fragmented control frame"));
            }
        }

        let mut mask = [0u8; 4];
        if buf.remaining() < 4 {
            return Err(ParseError::Incomplete);
        }
        buf.copy_to_slice(&mut mask);

        // Data frames additionally respect the frame cap above; the
        // conversion is infallible after the u64 bound check.
        if (buf.remaining() as u64) < payload_length {
            return Err(ParseError::Incomplete);
        }
        let payload_length = usize::try_from(payload_length)
            .map_err(|_| ParseError::ProtocolViolation("Unrepresentable length"))?;
        let mut payload = vec![0u8; payload_length];
        buf.copy_to_slice(&mut payload);

        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }

        let consumed = start_len - buf.remaining();
        Ok((
            Self {
                fin,
                opcode,
                payload,
            },
            consumed,
        ))
    }

    /// Serializes a frame for server-to-client transmission (unmasked, FIN
    /// set; servers never fragment).
    ///
    /// # Panics
    ///
    /// Never in practice: the `expect`s guard length encodings that are
    /// proven in range by the branch structure (< 126, < 65536).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = BytesMut::new();
        frame.put_u8(0x80 | (self.opcode as u8));

        let payload_len = self.payload.len();
        if payload_len < 126 {
            frame.put_u8(u8::try_from(payload_len).expect("length < 126"));
        } else if payload_len < 65536 {
            frame.put_u8(126);
            frame.put_u16(u16::try_from(payload_len).expect("length < 65536"));
        } else {
            frame.put_u8(127);
            frame.put_u64(payload_len as u64);
        }

        frame.extend_from_slice(&self.payload);
        frame.to_vec()
    }

    /// Whether this frame is a control frame (Close/Ping/Pong).
    #[must_use]
    pub fn is_control(&self) -> bool {
        self.opcode.is_control()
    }

    /// Creates a text frame from a string slice.
    #[must_use]
    pub fn text(content: &str) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Text,
            payload: content.as_bytes().to_vec(),
        }
    }

    /// Creates a binary frame from raw payload bytes.
    #[must_use]
    pub fn binary(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Binary,
            payload: data,
        }
    }

    /// Creates a close frame without a status code.
    #[must_use]
    pub fn close() -> Self {
        Self {
            fin: true,
            opcode: OpCode::Close,
            payload: Vec::new(),
        }
    }

    /// Creates a close frame with a status code and reason (RFC 6455 §7.1.6).
    #[must_use]
    pub fn close_with_code(code: u16, reason: &str) -> Self {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        Self {
            fin: true,
            opcode: OpCode::Close,
            payload,
        }
    }

    /// Creates a ping frame with the given application data.
    #[must_use]
    pub fn ping(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Ping,
            payload: data,
        }
    }

    /// Creates a pong frame with the given application data.
    #[must_use]
    pub fn pong(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Pong,
            payload: data,
        }
    }
}

/// Decodes a close-frame payload into `(code, reason)`, validating the code
/// against the registered ranges (SEC-WS-006).
///
/// # Errors
///
/// Returns [`ParseError::InvalidCloseCode`] for unregistered codes and
/// [`ParseError::InvalidUtf8`] for a non-UTF-8 reason.
pub fn decode_close_payload(payload: &[u8]) -> Result<Option<(u16, String)>, ParseError> {
    if payload.len() < 2 {
        return Ok(None);
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !is_valid_close_code(code) {
        return Err(ParseError::InvalidCloseCode);
    }
    let reason = std::str::from_utf8(&payload[2..])
        .map_err(|_| ParseError::InvalidUtf8)?
        .to_string();
    Ok(Some((code, reason)))
}

/// Validates WebSocket close codes according to RFC 6455.
fn is_valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = Frame::text("Hello");
        let bytes = frame.to_bytes();

        assert_eq!(bytes[0], 0x81);
        assert_eq!(bytes[1], 5);
        assert_eq!(&bytes[2..], b"Hello");
    }

    #[test]
    fn test_close_frame() {
        let frame = Frame::close();
        let bytes = frame.to_bytes();

        assert_eq!(bytes[0], 0x88);
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_close_frame_with_code() {
        let frame = Frame::close_with_code(1000, "Normal closure");
        let bytes = frame.to_bytes();

        assert_eq!(bytes[0], 0x88);
        assert!(bytes.len() > 2);
    }
}
