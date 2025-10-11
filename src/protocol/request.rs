use crate::error::{Result, ServerError};
use std::{collections::HashMap, fmt};
use tokio::{io::AsyncReadExt, net::TcpStream};

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Connect => write!(f, "CONNECT"),
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = ServerError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            "TRACE" => Ok(HttpMethod::Trace),
            "CONNECT" => Ok(HttpMethod::Connect),
            _ => Err(ServerError::InvalidHttpRequest("Unsupported HTTP method")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub async fn from_buffer(buffer: &[u8], socket: &mut TcpStream) -> Result<Self> {
        let request_str = String::from_utf8_lossy(buffer);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return Err(ServerError::InvalidHttpRequest("Empty request"));
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return Err(ServerError::InvalidHttpRequest("Invalid request line"));
        }

        let method = request_line_parts[0].parse::<HttpMethod>()?;
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Parse body based on Content-Length or Transfer-Encoding
        let body = if let Some(content_length) = headers.get("content-length") {
            // Read body based on Content-Length
            let length: usize = content_length
                .parse()
                .map_err(|_| ServerError::InvalidHttpRequest("Invalid Content-Length"))?;

            if length > 10 * 1024 * 1024 {
                return Err(ServerError::InvalidHttpRequest("Body too large"));
            }

            let mut body = vec![0u8; length];
            socket.read_exact(&mut body).await?;
            body
        } else if let Some(transfer_encoding) = headers.get("transfer-encoding") {
            if transfer_encoding.to_lowercase().contains("chunked") {
                // Decode chunked transfer encoding
                read_chunked_body(socket).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            method,
            path,
            version,
            headers,
            body,
        })
    }

    /// Parse a complete HTTP request (headers only, no body) - for testing
    pub fn from_buffer_sync(buffer: &[u8]) -> Result<Self> {
        let request_str = String::from_utf8_lossy(buffer);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return Err(ServerError::InvalidHttpRequest("Empty request"));
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return Err(ServerError::InvalidHttpRequest("Invalid request line"));
        }

        let method = request_line_parts[0].parse::<HttpMethod>()?;
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        Ok(Self {
            method,
            path,
            version,
            headers,
            body: Vec::new(),
        })
    }

    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }
}

/// Read chunked transfer-encoded body
async fn read_chunked_body(socket: &mut TcpStream) -> Result<Vec<u8>> {
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
                return Err(ServerError::InvalidHttpRequest("Invalid chunk size"));
            }
        }

        // Parse chunk size (ignore chunk extensions)
        let size_str = String::from_utf8_lossy(&size_line[..size_line.len() - 2]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ServerError::InvalidHttpRequest("Invalid chunk size"))?;

        if chunk_size == 0 {
            // Read trailing CRLF after last chunk
            socket.read_exact(&mut [0u8; 2]).await?;
            break;
        }

        if body.len() + chunk_size > 10 * 1024 * 1024 {
            return Err(ServerError::InvalidHttpRequest("Chunked body too large"));
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
