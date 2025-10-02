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
            _ => OpCode::Close, // Default to close for unknown opcodes
        }
    }
}

#[derive(Debug, Clone)]
pub enum WebSocketFrame {
    Text(String),
    Binary(Vec<u8>),
    Close,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

impl WebSocketFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let mut buf = data;
        
        // First byte: FIN (1 bit) + RSV (3 bits) + OpCode (4 bits)
        let first_byte = buf.get_u8();
        let _fin = (first_byte & 0x80) != 0;
        let opcode = OpCode::from(first_byte);

        // Second byte: MASK (1 bit) + Payload length (7 bits)
        let second_byte = buf.get_u8();
        let masked = (second_byte & 0x80) != 0;
        let mut payload_length = (second_byte & 0x7F) as u64;

        // Extended payload length
        if payload_length == 126 {
            if buf.remaining() < 2 {
                return None;
            }
            payload_length = buf.get_u16() as u64;
        } else if payload_length == 127 {
            if buf.remaining() < 8 {
                return None;
            }
            payload_length = buf.get_u64();
        }

        // Masking key (if present)
        let mask = if masked {
            if buf.remaining() < 4 {
                return None;
            }
            let mut mask_bytes = [0u8; 4];
            buf.copy_to_slice(&mut mask_bytes);
            Some(mask_bytes)
        } else {
            None
        };

        // Payload
        if buf.remaining() < payload_length as usize {
            return None;
        }

        let mut payload = vec![0u8; payload_length as usize];
        buf.copy_to_slice(&mut payload);

        // Unmask payload if needed
        if let Some(mask_key) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask_key[i % 4];
            }
        }

        // Create frame based on opcode
        match opcode {
            OpCode::Text => {
                if let Ok(text) = String::from_utf8(payload) {
                    Some(WebSocketFrame::Text(text))
                } else {
                    None
                }
            }
            OpCode::Binary => Some(WebSocketFrame::Binary(payload)),
            OpCode::Close => Some(WebSocketFrame::Close),
            OpCode::Ping => Some(WebSocketFrame::Ping(payload)),
            OpCode::Pong => Some(WebSocketFrame::Pong(payload)),
            OpCode::Continuation => None, // Not handling fragmented frames for now
        }
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
            WebSocketFrame::Close => {
                Self::write_frame(&mut frame, OpCode::Close, &[]);
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

        // Second byte and payload length
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
        WebSocketFrame::Close
    }

    pub fn ping(data: Vec<u8>) -> Self {
        WebSocketFrame::Ping(data)
    }

    pub fn pong(data: Vec<u8>) -> Self {
        WebSocketFrame::Pong(data)
    }
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
}
