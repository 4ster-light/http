use http::protocol::{
    request::{HttpRequest, HttpMethod},
    response::{HttpResponse, HttpStatusCode}
};

#[test]
fn test_http_request_parsing() {
    let request_data = b"GET /index.html HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n";
    
    let request = HttpRequest::from_buffer(request_data).unwrap();
    
    assert_eq!(request.method, HttpMethod::Get);
    assert_eq!(request.path, "/index.html");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.get_header("host"), Some(&"localhost:8080".to_string()));
    assert_eq!(request.get_header("connection"), Some(&"keep-alive".to_string()));
}

#[test]
fn test_websocket_request_parsing() {
    let request_data = b"GET / HTTP/1.1\r\nHost: localhost:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    
    let request = HttpRequest::from_buffer(request_data).unwrap();
    
    assert_eq!(request.method, HttpMethod::Get);
    assert_eq!(request.get_header("upgrade"), Some(&"websocket".to_string()));
    assert_eq!(request.get_header("connection"), Some(&"Upgrade".to_string()));
    assert_eq!(request.get_header("sec-websocket-key"), Some(&"dGhlIHNhbXBsZSBub25jZQ==".to_string()));
}

#[test]
fn test_http_response_creation() {
    let response = HttpResponse::ok()
        .with_text("Hello, World!")
        .with_header("custom-header", "custom-value");
    
    let response_bytes = response.to_bytes();
    let response_str = String::from_utf8_lossy(&response_bytes);
    
    assert!(response_str.starts_with("HTTP/1.1 200 OK"));
    assert!(response_str.contains("content-type: text/plain"));
    assert!(response_str.contains("custom-header: custom-value"));
    assert!(response_str.contains("Hello, World!"));
}

#[test]
fn test_http_method_parsing() {
    assert_eq!("GET".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
    assert_eq!("POST".parse::<HttpMethod>().unwrap(), HttpMethod::Post);
    assert_eq!("put".parse::<HttpMethod>().unwrap(), HttpMethod::Put);
    
    assert!("INVALID".parse::<HttpMethod>().is_err());
}

#[test]
fn test_status_code_display() {
    assert_eq!(HttpStatusCode::Ok.to_string(), "200 OK");
    assert_eq!(HttpStatusCode::NotFound.to_string(), "404 Not Found");
    assert_eq!(HttpStatusCode::InternalServerError.to_string(), "500 Internal Server Error");
}
