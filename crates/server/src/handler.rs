use crate::{
    config::Config,
    error::{Result, ServerError},
};
use http::{
    request::{HttpMethod, HttpRequest},
    response::{HttpResponse, HttpStatusCode},
};
use std::path::Path;
use tokio::{fs, io::AsyncWriteExt, net::TcpStream};

/// Dispatches one parsed request to a handler and writes the response.
///
/// `close_after` forces `Connection: close` (client request or the
/// keep-alive request budget, SEC-HTTP-005); otherwise the limits-derived
/// `Keep-Alive` parameters are advertised on success responses.
pub async fn handle_http_request(
    socket: &mut TcpStream,
    request: HttpRequest,
    config: &Config,
    close_after: bool,
) -> Result<()> {
    let response = match request.method {
        HttpMethod::Get => handle_get_request(&request, config).await?,
        HttpMethod::Post => handle_post_request(&request),
        HttpMethod::Options => handle_options_request(&request),
        _ => HttpResponse::new(HttpStatusCode::MethodNotAllowed).with_text("Method not allowed"),
    };

    let mut response = if close_after || !response.keep_alive {
        response.close_connection()
    } else {
        response
    };
    if response.keep_alive
        && response.status.is_success()
        && let Some(timeout) = config.limits.keep_alive_idle_timeout
    {
        let advertised = match config.limits.max_requests_per_connection {
            Some(max) => format!("timeout={}, max={max}", timeout.as_secs()),
            None => format!("timeout={}", timeout.as_secs()),
        };
        response = response.with_header("keep-alive", &advertised);
    }

    socket.write_all(&response.to_bytes()).await?;
    Ok(())
}

async fn handle_get_request(request: &HttpRequest, config: &Config) -> Result<HttpResponse> {
    // Percent-decode the target first so encoded traversal attempts cannot
    // slip past the checks below (SEC-HTTP-006 regression coverage).
    let Some(decoded) = percent_decode(&request.path) else {
        return Ok(HttpResponse::bad_request().with_text("Invalid path encoding"));
    };

    let file_path = if decoded == "/" {
        format!("{}/index.html", config.static_dir)
    } else {
        format!("{}{}", config.static_dir, decoded)
    };

    let canonical_static_dir = std::fs::canonicalize(&config.static_dir)
        .map_err(|_| ServerError::FileNotFound(config.static_dir.clone()))?;

    let Ok(canonical_file_path) = std::fs::canonicalize(&file_path) else {
        return Ok(HttpResponse::not_found().with_text("File not found"));
    };

    if !canonical_file_path.starts_with(&canonical_static_dir) {
        return Ok(HttpResponse::bad_request().with_text("Invalid path"));
    }

    // Read via the canonical path validated above (fixes the F10 TOCTOU).
    match fs::read(&canonical_file_path).await {
        Ok(contents) => Ok(HttpResponse::ok()
            .with_header("content-type", &get_content_type(&file_path))
            .with_body(contents)),
        Err(_) => Ok(HttpResponse::not_found().with_text("File not found")),
    }
}

fn handle_post_request(request: &HttpRequest) -> HttpResponse {
    // Simple echo for POST requests
    let body_str = String::from_utf8_lossy(&request.body);
    let json_path = json_escape(&request.path);
    let json_body = json_escape(&body_str);
    HttpResponse::ok().with_json(&format!(
        r#"{{"received": "{json_body}", "path": "{json_path}"}}"#
    ))
}

fn handle_options_request(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::ok()
        .with_header("access-control-allow-origin", "*")
        .with_header(
            "access-control-allow-methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .with_header(
            "access-control-allow-headers",
            "Content-Type, Authorization",
        )
        .with_body(Vec::new())
}

/// Percent-decodes a request target. Returns `None` for malformed escapes or
/// non-UTF-8 results (rejected as a bad request).
fn percent_decode(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            let value = u8::from_str_radix(hex, 16).ok()?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Minimal JSON string escaper for the echo endpoint.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn get_content_type(file_path: &str) -> String {
    let path = Path::new(file_path);
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8".to_string(),
        Some("css") => "text/css; charset=utf-8".to_string(),
        Some("js") => "application/javascript; charset=utf-8".to_string(),
        Some("json") => "application/json".to_string(),
        Some("png") => "image/png".to_string(),
        Some("jpg" | "jpeg") => "image/jpeg".to_string(),
        Some("gif") => "image/gif".to_string(),
        Some("svg") => "image/svg+xml".to_string(),
        Some("ico") => "image/x-icon".to_string(),
        Some("txt") => "text/plain; charset=utf-8".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}
