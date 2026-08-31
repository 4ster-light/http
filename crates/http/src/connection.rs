//! Connection-level request reading over generic IO (REFACTOR-PLAN.md §3.2
//! D2/D3).
//!
//! The caller owns one persistent buffer across requests (pipelining-safe,
//! SEC-HTTP-007); `read_request` appends to it and consumes exactly the
//! bytes of each complete request.

use crate::{
    error::{Error, Result},
    limits::Limits,
    request::HttpRequest,
};
use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

/// Reads one complete request from `io`, appending to and consuming from the
/// persistent `buffer`.
///
/// Returns `Ok(None)` on a clean close with an empty buffer (the peer had no
/// pending request). Any leftover pipelined bytes stay in `buffer` for the
/// next call (F1 fix).
///
/// The read is bounded by [`Limits::head_read_timeout`] once bytes start
/// arriving (SEC-HTTP-002). When `buffer` is empty (a keep-alive idle
/// window), [`Limits::keep_alive_idle_timeout`] applies instead
/// (SEC-HTTP-005) and its expiry is reported as `Ok(None)`.
///
/// # Errors
///
/// Propagates [`HttpRequest::parse`] errors (malformed request, limit
/// violations) and IO failures; a timeout expiry mid-request maps to
/// [`Error::InvalidHttpRequest`].
pub async fn read_request<R: AsyncRead + Unpin>(
    io: &mut R,
    buffer: &mut BytesMut,
    limits: &Limits,
) -> Result<Option<HttpRequest>> {
    loop {
        if let Some((request, consumed)) = HttpRequest::parse(buffer, limits)? {
            let _ = buffer.split_to(consumed);
            return Ok(Some(request));
        }
        // Either a fresh request window (idle timeout applies when
        // the buffer is empty) or a partial request (head timeout).
        let timeout_duration = if buffer.is_empty() {
            match limits.keep_alive_idle_timeout {
                Some(t) => t,
                None => limits.head_read_timeout,
            }
        } else {
            limits.head_read_timeout
        };
        let mut chunk = [0u8; 4096];
        let read = timeout(timeout_duration, io.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed mid-request",
                )));
            }
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => {
                if buffer.is_empty() {
                    // Keep-alive idle timeout elapsed: treat as a
                    // clean close rather than an error (SEC-HTTP-005).
                    return Ok(None);
                }
                return Err(Error::InvalidHttpRequest("Read timeout"));
            }
        }
    }
}
