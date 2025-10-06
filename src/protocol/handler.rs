use crate::{
    config::Config,
    error::{Result, ServerError},
    protocol::{
        request::{HttpMethod, HttpRequest},
        response::{HttpResponse, HttpStatusCode},
    },
};
use std::path::Path;
use tokio::{fs, io::AsyncWriteExt, net::TcpStream};

pub async fn handle_http_request(socket: &mut TcpStream, request: HttpRequest) -> Result<()> {
    let response = match request.method {
        HttpMethod::Get => handle_get_request(&request).await,
        HttpMethod::Post => handle_post_request(&request).await,
        HttpMethod::Options => handle_options_request(&request).await,
        _ => {
            Ok(HttpResponse::new(HttpStatusCode::MethodNotAllowed).with_text("Method not allowed"))
        }
    }?;

    socket.write_all(&response.to_bytes()).await?;
    Ok(())
}

async fn handle_get_request(request: &HttpRequest) -> Result<HttpResponse> {
    let config = Config::default();

    // Handle root path
    let file_path = if request.path == "/" {
        format!("{}/index.html", config.static_dir)
    } else {
        format!("{}{}", config.static_dir, request.path)
    };

    // Security: prevent directory traversal
    let canonical_static_dir = std::fs::canonicalize(&config.static_dir)
        .map_err(|_| ServerError::FileNotFound(config.static_dir.clone()))?;

    let canonical_file_path = match std::fs::canonicalize(&file_path) {
        Ok(path) => path,
        Err(_) => return Ok(HttpResponse::not_found().with_text("File not found")),
    };

    if !canonical_file_path.starts_with(&canonical_static_dir) {
        return Ok(HttpResponse::bad_request().with_text("Invalid path"));
    }

    // Serve file if it exists
    match fs::read(&file_path).await {
        Ok(contents) => Ok(HttpResponse::ok()
            .with_header("content-type", &get_content_type(&file_path))
            .with_body(contents)),
        Err(_) => Ok(HttpResponse::not_found().with_text("File not found")),
    }
}

async fn handle_post_request(request: &HttpRequest) -> Result<HttpResponse> {
    // Simple echo for POST requests
    let body_str = String::from_utf8_lossy(&request.body);
    Ok(HttpResponse::ok().with_json(&format!(
        r#"{{"received": "{}", "path": "{}"}}"#,
        body_str, request.path
    )))
}

async fn handle_options_request(_request: &HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::ok()
        .with_header("access-control-allow-origin", "*")
        .with_header(
            "access-control-allow-methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .with_header(
            "access-control-allow-headers",
            "Content-Type, Authorization",
        )
        .with_body(Vec::new()))
}

fn get_content_type(file_path: &str) -> String {
    let path = Path::new(file_path);
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8".to_string(),
        Some("css") => "text/css; charset=utf-8".to_string(),
        Some("js") => "application/javascript; charset=utf-8".to_string(),
        Some("json") => "application/json; charset=utf-8".to_string(),
        Some("png") => "image/png".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("gif") => "image/gif".to_string(),
        Some("svg") => "image/svg+xml".to_string(),
        Some("ico") => "image/x-icon".to_string(),
        Some("txt") => "text/plain; charset=utf-8".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}
