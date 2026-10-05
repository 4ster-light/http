//! Connection-level request reading over generic IO (ADR-0005).
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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

/// Reads one complete request from `io`, appending to and consuming from the
/// persistent `buffer`.
///
/// Returns `Ok(None)` on a clean close with an empty buffer (the peer had no
/// pending request). Any leftover pipelined bytes stay in `buffer` for the
/// next call (F1 fix).
///
/// When the request head announces `Expect: 100-continue` and a body, this
/// writes a `100 Continue` interim response before waiting for the body
/// (RFC 9110 §10.1.1; HTTP/1.1 only). Clients that send the body eagerly do
/// not need it and it is omitted once the body is already present.
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
pub async fn read_request<R>(
    io: &mut R,
    buffer: &mut BytesMut,
    limits: &Limits,
) -> Result<Option<HttpRequest>>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut continue_sent = false;
    loop {
        match HttpRequest::parse(buffer, limits) {
            Ok(Some((request, consumed))) => {
                let _ = buffer.split_to(consumed);
                return Ok(Some(request));
            }
            Ok(None) => {
                // The head may be complete while the body is still on its way.
                // If the client is waiting for `100 Continue`, answer it now.
                if !continue_sent
                    && let Some((head, _)) = HttpRequest::parse_head(buffer, limits)?
                    && head.version != "HTTP/1.0"
                    && expects_continue(&head)
                    && request_has_body(&head)
                {
                    io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                    io.flush().await?;
                    continue_sent = true;
                }
            }
            Err(e) => return Err(e),
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

/// Whether the request carries `Expect: 100-continue` (RFC 9110 §10.1.1).
fn expects_continue(request: &HttpRequest) -> bool {
    request
        .get_header("expect")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"))
}

/// Whether the request announces a body, making a `100 Continue` meaningful.
fn request_has_body(request: &HttpRequest) -> bool {
    if let Some(content_length) = request.get_header("content-length") {
        return content_length.trim().parse::<u64>().map_or(true, |n| n > 0);
    }
    request
        .get_header("transfer-encoding")
        .is_some_and(|te| te.to_lowercase().contains("chunked"))
}
