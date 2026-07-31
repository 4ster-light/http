//! Body readers: Content-Length and chunked transfer-encoding.
//!
//! NOTE: these read directly from the socket for now. The Phase 3 refactor
//! (REFACTOR-PLAN.md §3.2 D3) will make them consume a connection-owned
//! buffer first, fixing the pipelining/buffer-discard flaw (F1).

use crate::error::{Error, Result};
use tokio::{io::AsyncReadExt, net::TcpStream};

/// Read a chunked transfer-encoded body (RFC 7230 §4.1).
pub(crate) async fn read_chunked_body(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = Vec::new();
        let mut byte_buf = [0u8; 1];

        loop {
            socket.read_exact(&mut byte_buf).await?;
            size_line.push(byte_buf[0]);

            if size_line.len() >= 2
                && size_line[size_line.len() - 2] == b'\r'
                && size_line[size_line.len() - 1] == b'\n'
            {
                break;
            }

            if size_line.len() > 20 {
                return Err(Error::InvalidHttpRequest("Invalid chunk size"));
            }
        }

        // Parse chunk size (ignore chunk extensions)
        let size_str = String::from_utf8_lossy(&size_line[..size_line.len() - 2]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| Error::InvalidHttpRequest("Invalid chunk size"))?;

        if chunk_size == 0 {
            // Read trailing CRLF after last chunk
            socket.read_exact(&mut [0u8; 2]).await?;
            break;
        }

        if body.len() + chunk_size > 10 * 1024 * 1024 {
            return Err(Error::InvalidHttpRequest("Chunked body too large"));
        }

        // Read chunk data
        let mut chunk = vec![0u8; chunk_size];
        socket.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        // Read trailing CRLF after chunk data
        socket.read_exact(&mut [0u8; 2]).await?;
    }

    Ok(body)
}
