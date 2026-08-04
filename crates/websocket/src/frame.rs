use bytes::{Buf, BufMut, BytesMut};

/// WebSocket frame opcode (RFC 6455 §5.2).
#[derive(Debug, Clone, PartialEq)]
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

impl From<u8> for OpCode {
    fn from(byte: u8) -> Self {
        match byte & 0x0F {
            0x0 => OpCode::Continuation,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xa => OpCode::Pong,
            // Not a duplicate of 0x8 by accident: reserved and unknown
            // opcodes are deliberately mapped to Close so the connection
            // layer terminates the connection (RFC 6455 §5.2).
            #[allow(clippy::match_same_arms)]
            _ => OpCode::Close,
        }
    }
}

impl OpCode {
    /// Returns `true` for control opcodes (Close, Ping, Pong — RFC 6455 §5.5).
    #[must_use]
    pub fn is_control(&self) -> bool {
        matches!(self, OpCode::Close | OpCode::Ping | OpCode::Pong)
    }
}

/// A single decoded WebSocket frame (RFC 6455 §5.2).
///
/// Fragmented messages are not reassembled yet — continuation frames are
/// reported as [`ParseError::Incomplete`] (known gap F4, tracked as
/// SEC-WS-009 in the refactor plan).
#[derive(Debug, Clone)]
pub enum WebSocketFrame {
    /// A text frame with its UTF-8 validated payload.
    Text(String),
    /// A binary frame with its raw payload.
    Binary(Vec<u8>),
    /// A close frame, optionally carrying a status code and reason.
    Close(Option<(u16, String)>),
    /// A ping control frame with its application data.
    Ping(Vec<u8>),
    /// A pong control frame with its application data.
    Pong(Vec<u8>),
}

/// Errors returned by [`WebSocketFrame::parse`].
#[derive(Debug)]
pub enum ParseError {
    /// The buffer does not yet hold a complete frame; read more bytes.
    Incomplete,
    /// A text frame's payload was not valid UTF-8.
    InvalidUtf8,
    /// A control frame exceeded the 125-byte payload limit (RFC 6455 §5.5).
    ControlFrameTooLarge,
    /// A client-to-server frame arrived unmasked (RFC 6455 §5.3 violation).
    UnmaskedClientFrame,
    /// A close frame carried a status code outside the registered ranges.
    InvalidCloseCode,
}

impl WebSocketFrame {
    /// Parses one frame from the front of `data`, returning the frame and the
    /// number of bytes consumed.
    ///
    /// Expects client-to-server traffic: frames must be masked, unmasked
    /// input is rejected (RFC 6455 §5.3). Server-to-client serialization is
    /// provided by [`WebSocketFrame::to_bytes`].
    ///
    /// # Errors
    ///
    /// - [`ParseError::Incomplete`]: not enough bytes yet — or a continuation
    ///   frame, which is not supported yet (F4).
    /// - [`ParseError::UnmaskedClientFrame`]: missing mask.
    /// - [`ParseError::ControlFrameTooLarge`]: control payload over 125 bytes.
    /// - [`ParseError::InvalidUtf8`]: text payload was not valid UTF-8.
    /// - [`ParseError::InvalidCloseCode`]: unregistered close status code.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        if data.len() < 2 {
            return Err(ParseError::Incomplete);
        }

        let mut buf = data;
        let start_len = buf.len();

        // First byte: FIN (1 bit) + RSV (3 bits) + OpCode (4 bits).
        // FIN is intentionally not tracked: fragmented messages are not
        // supported yet (F4), so every frame is treated as a full message.
        let first_byte = buf.get_u8();
        let opcode = OpCode::from(first_byte);

        // Second byte: MASK (1 bit) + Payload length (7 bits)
        let second_byte = buf.get_u8();
        let masked = (second_byte & 0x80) != 0;
        let mut payload_length = u64::from(second_byte & 0x7F);

        // Client-to-server frames MUST be masked
        if !masked {
            return Err(ParseError::UnmaskedClientFrame);
        }

        // Extended payload length
        if payload_length == 126 {
            if buf.remaining() < 2 {
                return Err(ParseError::Incomplete);
            }
            payload_length = u64::from(buf.get_u16());
        } else if payload_length == 127 {
            if buf.remaining() < 8 {
                return Err(ParseError::Incomplete);
            }
            payload_length = buf.get_u64();
        }

        // Control frames must have payload <= 125 bytes
        if opcode.is_control() && payload_length > 125 {
            return Err(ParseError::ControlFrameTooLarge);
        }

        // Masking key (if present)
        let mask = if masked {
            if buf.remaining() < 4 {
                return Err(ParseError::Incomplete);
            }
            let mut mask_bytes = [0u8; 4];
            buf.copy_to_slice(&mut mask_bytes);
            Some(mask_bytes)
        } else {
            None
        };

        // Payload. Lengths are compared in u64 so a huge declared length on
        // a 32-bit target cannot truncate into a false "complete" result.
        if (buf.remaining() as u64) < payload_length {
            return Err(ParseError::Incomplete);
        }

        // Cannot fail: the bounds check above proves the length fits usize.
        let payload_length = usize::try_from(payload_length).map_err(|_| ParseError::Incomplete)?;
        let mut payload = vec![0u8; payload_length];
        buf.copy_to_slice(&mut payload);

        // Unmask payload if needed
        if let Some(mask_key) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask_key[i % 4];
            }
        }

        let consumed = start_len - buf.remaining();

        // Create frame based on opcode
        let frame = match opcode {
            OpCode::Text => {
                let text = String::from_utf8(payload).map_err(|_| ParseError::InvalidUtf8)?;
                WebSocketFrame::Text(text)
            }
            OpCode::Binary => WebSocketFrame::Binary(payload),
            OpCode::Close => {
                let close_info = if payload.len() >= 2 {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);

                    // Validate close code
                    if !is_valid_close_code(code) {
                        return Err(ParseError::InvalidCloseCode);
                    }

                    let reason = if payload.len() > 2 {
                        String::from_utf8_lossy(&payload[2..]).to_string()
                    } else {
                        String::new()
                    };
                    Some((code, reason))
                } else {
                    None
                };
                WebSocketFrame::Close(close_info)
            }
            OpCode::Ping => WebSocketFrame::Ping(payload),
            OpCode::Pong => WebSocketFrame::Pong(payload),
            OpCode::Continuation => {
                // For now, treat continuation as incomplete
                // Full fragmentation support would require state management
                return Err(ParseError::Incomplete);
            }
        };

        Ok((frame, consumed))
    }

    /// Serializes the frame for server-to-client transmission (unmasked,
    /// FIN set, no fragmentation).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = BytesMut::new();

        match self {
            WebSocketFrame::Text(text) => {
                let payload = text.as_bytes();
                Self::write_frame(&mut frame, OpCode::Text, payload);
            }
            WebSocketFrame::Binary(data) => {
                Self::write_frame(&mut frame, OpCode::Binary, data);
            }
            WebSocketFrame::Close(code_reason) => {
                let mut payload = Vec::new();
                if let Some((code, reason)) = code_reason {
                    payload.extend_from_slice(&code.to_be_bytes());
                    payload.extend_from_slice(reason.as_bytes());
                }
                Self::write_frame(&mut frame, OpCode::Close, &payload);
            }
            WebSocketFrame::Ping(data) => {
                Self::write_frame(&mut frame, OpCode::Ping, data);
            }
            WebSocketFrame::Pong(data) => {
                Self::write_frame(&mut frame, OpCode::Pong, data);
            }
        }

        frame.to_vec()
    }

    fn write_frame(frame: &mut BytesMut, opcode: OpCode, payload: &[u8]) {
        // First byte: FIN (1) + RSV (000) + OpCode (4 bits)
        frame.put_u8(0x80 | (opcode as u8));

        // Second byte and payload length (no masking for server-to-client).
        // The expect()s cannot fail: each branch guards the value range.
        let payload_len = payload.len();
        if payload_len < 126 {
            frame.put_u8(u8::try_from(payload_len).expect("length < 126"));
        } else if payload_len < 65536 {
            frame.put_u8(126);
            frame.put_u16(u16::try_from(payload_len).expect("length < 65536"));
        } else {
            frame.put_u8(127);
            frame.put_u64(payload_len as u64);
        }

        // Payload (no masking for server-to-client frames)
        frame.extend_from_slice(payload);
    }

    /// Creates a text frame from a string slice.
    #[must_use]
    pub fn text(content: &str) -> Self {
        WebSocketFrame::Text(content.to_string())
    }

    /// Creates a binary frame from raw payload bytes.
    #[must_use]
    pub fn binary(data: Vec<u8>) -> Self {
        WebSocketFrame::Binary(data)
    }

    /// Creates a close frame without a status code.
    #[must_use]
    pub fn close() -> Self {
        WebSocketFrame::Close(None)
    }

    /// Creates a close frame with a status code and reason (RFC 6455 §7.1.6).
    #[must_use]
    pub fn close_with_code(code: u16, reason: &str) -> Self {
        WebSocketFrame::Close(Some((code, reason.to_string())))
    }

    /// Creates a ping frame with the given application data.
    #[must_use]
    pub fn ping(data: Vec<u8>) -> Self {
        WebSocketFrame::Ping(data)
    }

    /// Creates a pong frame with the given application data.
    #[must_use]
    pub fn pong(data: Vec<u8>) -> Self {
        WebSocketFrame::Pong(data)
    }
}

/// Validate WebSocket close codes according to RFC 6455
fn is_valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let text_frame = WebSocketFrame::text("Hello");
        let bytes = text_frame.to_bytes();

        // Should start with 0x81 (FIN + TEXT opcode)
        assert_eq!(bytes[0], 0x81);
        // Length should be 5
        assert_eq!(bytes[1], 5);
        // Payload should be "Hello"
        assert_eq!(&bytes[2..], b"Hello");
    }

    #[test]
    fn test_close_frame() {
        let close_frame = WebSocketFrame::close();
        let bytes = close_frame.to_bytes();

        // Should start with 0x88 (FIN + CLOSE opcode)
        assert_eq!(bytes[0], 0x88);
        // Length should be 0
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_close_frame_with_code() {
        let close_frame = WebSocketFrame::close_with_code(1000, "Normal closure");
        let bytes = close_frame.to_bytes();

        // Should start with 0x88 (FIN + CLOSE opcode)
        assert_eq!(bytes[0], 0x88);
        // Payload should contain code and reason
        assert!(bytes.len() > 2);
    }
}
