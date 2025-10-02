# HTTP & WebSockets in Rust

A basic implementation of HTTP 1.1 and WebSocket protocols built from scratch in Rust using idiomatic Rust practices and the `tokio` async runtime.

## Features

### HTTP 1.1 Support
- ✅ HTTP request parsing (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT)
- ✅ HTTP response generation with proper status codes
- ✅ Static file serving with proper Content-Type detection
- ✅ Request header parsing and response header setting
- ✅ Directory traversal protection
- ✅ Support for multiple content types (HTML, CSS, JS, JSON, images, etc.)

### WebSocket Support (RFC 6455)
- ✅ WebSocket handshake (Sec-WebSocket-Key verification)
- ✅ WebSocket frame parsing and generation
- ✅ Text and binary message support
- ✅ Ping/Pong frame handling
- ✅ Connection close handling
- ✅ Echo server functionality for testing

### Type Safety & Developer Experience
- ✅ Strongly-typed HTTP methods (`HttpMethod` enum)
- ✅ Strongly-typed HTTP status codes (`HttpStatusCode` enum)
- ✅ Comprehensive error handling with `thiserror`
- ✅ Builder pattern for HTTP responses
- ✅ Extensive test coverage

## Architecture

```
src/
├── main.rs          # Server entry point
├── lib.rs           # Library exports
├── config.rs        # Configuration
├── error.rs         # Error types
├── protocol/        # HTTP implementation
│   ├── mod.rs       # HTTP connection handling
│   ├── request.rs   # HTTP request parsing
│   ├── response.rs  # HTTP response generation
│   └── handler.rs   # HTTP request handlers
└── websocket/       # WebSocket implementation
    ├── mod.rs       # WebSocket connection handling
    ├── handshake.rs # WebSocket handshake
    └── frame.rs     # WebSocket frame parsing/generation
```

## Usage

### Running the Server

```bash
cargo run
```

The server will start on `http://127.0.0.1:8080` by default.

### Testing

```bash
cargo test
```

### HTTP Endpoints

- `GET /` - Serves `static/index.html`
- `GET /path/to/file` - Serves static files from the `static/` directory
- `POST /any/path` - Echo endpoint that returns the request body as JSON

### WebSocket

Connect to `ws://127.0.0.1:8080` to establish a WebSocket connection. The server will:
- Echo back any text messages prefixed with "Echo: "
- Echo back binary messages as-is
- Respond to ping frames with pong frames
- Handle connection close properly

## Example Usage

### HTTP Client

```bash
# Get the index page
curl http://127.0.0.1:8080/

# Post some data
curl -X POST http://127.0.0.1:8080/api/test -d "Hello, Server!"
```

### WebSocket Client (Browser)

```javascript
const socket = new WebSocket("ws://127.0.0.1:8080");
socket.onopen = () => {
    console.log("Connected");
    socket.send("Hello, Rust!");
};
socket.onmessage = (e) => console.log("Received:", e.data);
socket.onerror = (e) => console.error("WebSocket error:", e);
socket.onclose = (e) => console.log("Connection closed:", e.code, e.reason);
```

## Code Examples

### Creating HTTP Responses

```rust
use http::http::{HttpResponse, HttpStatusCode};

// Simple text response
let response = HttpResponse::ok()
    .with_text("Hello, World!");

// JSON response
let response = HttpResponse::new(HttpStatusCode::Created)
    .with_json(r#"{"message": "Resource created"}"#);

// Custom headers
let response = HttpResponse::ok()
    .with_header("cache-control", "no-cache")
    .with_html("<h1>Hello</h1>");
```

### WebSocket Frame Handling

```rust
use http::websocket::WebSocketFrame;

// Create frames
let text_frame = WebSocketFrame::Text("Hello".to_string());
let ping_frame = WebSocketFrame::Ping(b"ping data".to_vec());
let close_frame = WebSocketFrame::Close;

// Serialize to bytes
let bytes = text_frame.to_bytes();

// Parse from bytes
if let Some(frame) = WebSocketFrame::parse(&bytes) {
    match frame {
        WebSocketFrame::Text(text) => println!("Received: {}", text),
        WebSocketFrame::Close => println!("Connection closing"),
        _ => {}
    }
}
```

## Dependencies
| Dependency  | Purpose                                 |
|:-----------:|-----------------------------------------|
|   `tokio`   | Async runtime with full features        |
|   `bytes`   | Byte manipulation utilities             |
|  `base64`   | Base64 encoding for WebSocket handshake |
|   `sha1`    | SHA1 hashing for WebSocket handshake    |
| `thiserror` | Error handling macros                   |

## Security Features

- Directory traversal protection (prevents access outside static directory)
- Proper path canonicalization
- Input validation for HTTP requests
- WebSocket handshake validation

## Performance Characteristics

- Asynchronous I/O using `tokio`
- Connection pooling through `tokio::spawn`
- Zero-copy buffer management where possible
- Efficient WebSocket frame parsing

## Testing

The project includes comprehensive tests:

- HTTP request/response parsing
- WebSocket handshake validation
- WebSocket frame serialization/deserialization
- HTTP method and status code handling
- Integration tests for both protocols

## Future Improvements

- [ ] HTTP/2 support
- [ ] TLS/SSL support
- [ ] WebSocket extensions (compression, etc.)
- [ ] Request routing and middleware
- [ ] Connection pooling and rate limiting
- [ ] Logging and metrics
- [ ] Configuration file support

## License

This project is for educational purposes demonstrating HTTP/1.1 and WebSocket protocol implementations in Rust.