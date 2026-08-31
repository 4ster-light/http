//! Body framings: the chunked transfer-encoding decoder is pure over byte
//! slices (REFACTOR-PLAN.md §3.2 D2), so it can be driven by buffered bytes
//! and fuzzed without a socket.

use crate::error::{Error, Result};

/// Attempts to decode one chunked transfer-encoded body (RFC 9112 §7.1) from
/// the front of `buffer`.
///
/// Returns `Ok(None)` when the buffer does not yet hold the complete body.
/// On success returns the reassembled body and the total wire bytes consumed
/// (including the terminating chunk), so the caller can advance its buffer.
///
/// Chunk extensions (`name=value` after the size) are tolerated and ignored
/// per RFC 9112 §7.1.1. A trailer section with actual trailer fields is
/// rejected to keep framing unambiguous; only the empty line that terminates
/// the message is accepted.
///
/// # Errors
///
/// Returns [`Error::InvalidHttpRequest`] for a malformed chunk-size line,
/// malformed chunk data, or a non-empty trailer. Returns
/// [`Error::BodyTooLarge`] when the reassembled body exceeds `max_body`
/// (SEC-HTTP-004).
pub(crate) fn decode_chunked_body(
    buffer: &[u8],
    max_body: usize,
) -> Result<Option<(Vec<u8>, usize)>> {
    let mut body = Vec::new();
    let mut rest: &[u8] = buffer;

    loop {
        // Chunk size line: hex digits, optional `;extension`, CRLF.
        let Some(line_len) = rest.iter().position(|&b| b == b'\r') else {
            return Ok(None);
        };
        if line_len + 1 >= rest.len() {
            return Ok(None);
        }
        let line = &rest[..line_len];
        if rest[line_len + 1] != b'\n' {
            return Err(Error::InvalidHttpRequest("Malformed chunk size line"));
        }
        if line.is_empty() || line.len() > 20 {
            return Err(Error::InvalidHttpRequest("Invalid chunk size line"));
        }
        // Tolerate and ignore chunk extensions (RFC 9112 §7.1.1).
        let size_hex = std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| Error::InvalidHttpRequest("Invalid chunk size"))?;
        rest = &rest[line_len + 2..];

        if chunk_size == 0 {
            // Terminating chunk: the remainder must be the empty line that
            // ends the message. A non-empty trailer field is rejected
            // (stricter than the RFC requires; keeps framing unambiguous).
            if rest.len() < 2 {
                return Ok(None);
            }
            if rest.starts_with(b"\r\n") {
                let consumed = buffer.len() - rest.len() + 2;
                return Ok(Some((body, consumed)));
            }
            return Err(Error::InvalidHttpRequest("Trailer fields unsupported"));
        }

        if body.len() + chunk_size > max_body {
            return Err(Error::BodyTooLarge);
        }

        if rest.len() < chunk_size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&rest[..chunk_size]);

        let crlf = &rest[chunk_size..chunk_size + 2];
        if crlf != b"\r\n" {
            return Err(Error::InvalidHttpRequest("Missing CRLF after chunk data"));
        }
        rest = &rest[chunk_size + 2..];
    }
}
