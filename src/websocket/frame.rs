use bytes::{Buf, BufMut, BytesMut};

#[derive(Debug, Clone, PartialEq)]
pub enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
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
            _ => OpCode::Close,
        }
    }
}

impl OpCode {
    pub fn is_control(&self) -> bool {
        matches!(self, OpCode::Close | OpCode::Ping | OpCode::Pong)
    }
}

#[derive(Debug, Clone)]
pub enum WebSocketFrame {
    Text(String),
    Binary(Vec<u8>),
    Close(Option<(u16, String)>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    InvalidUtf8,
    ControlFrameTooLarge,
    UnmaskedClientFrame,
    InvalidCloseCode,
}

impl WebSocketFrame {
    /// Parse a WebSocket frame, returning the frame and number of bytes consumed
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        if data.len() < 2 {
            return Err(ParseError::Incomplete);
        }

        let mut buf = data;
        let start_len = buf.len();

        // First byte: FIN (1 bit) + RSV (3 bits) + OpCode (4 bits)
        let first_byte = buf.get_u8();
        let _fin = (first_byte & 0x80) != 0;
        let opcode = OpCode::from(first_byte);

        // Second byte: MASK (1 bit) + Payload length (7 bits)
        let second_byte = buf.get_u8();
        let masked = (second_byte & 0x80) != 0;
        let mut payload_length = (second_byte & 0x7F) as u64;

        // Client-to-server frames MUST be masked
        if !masked {
            return Err(ParseError::UnmaskedClientFrame);
        }

        // Extended payload length
        if payload_length == 126 {
            if buf.remaining() < 2 {
                return Err(ParseError::Incomplete);
            }
            payload_length = buf.get_u16() as u64;
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

        // Payload
        if buf.remaining() < payload_length as usize {
            return Err(ParseError::Incomplete);
        }

        let mut payload = vec![0u8; payload_length as usize];
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

        // Second byte and payload length (no masking for server-to-client)
        let payload_len = payload.len();
        if payload_len < 126 {
            frame.put_u8(payload_len as u8);
        } else if payload_len < 65536 {
            frame.put_u8(126);
            frame.put_u16(payload_len as u16);
        } else {
            frame.put_u8(127);
            frame.put_u64(payload_len as u64);
        }

        // Payload (no masking for server-to-client frames)
        frame.extend_from_slice(payload);
    }

    pub fn text(content: &str) -> Self {
        WebSocketFrame::Text(content.to_string())
    }

    pub fn binary(data: Vec<u8>) -> Self {
        WebSocketFrame::Binary(data)
    }

    pub fn close() -> Self {
        WebSocketFrame::Close(None)
    }

    pub fn close_with_code(code: u16, reason: &str) -> Self {
        WebSocketFrame::Close(Some((code, reason.to_string())))
    }

    pub fn ping(data: Vec<u8>) -> Self {
        WebSocketFrame::Ping(data)
    }

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
