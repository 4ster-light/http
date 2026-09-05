//! End-to-end tests against the real server binary over real TCP sockets.
//!
//! Each test spawns the `server` binary on an ephemeral port (`SERVER_ADDR`)
//! and speaks raw HTTP/1.1 and WebSocket to it. These tests prove the F1/F2/
//! F3/F7/F8 fixes hold over actual sockets, not just duplex streams.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU16, Ordering},
    thread::sleep,
    time::Duration,
};

/// A spawned server binary, killed on drop.
struct TestServer {
    child: Child,
    addr: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Base port for this test process; tests take sequential ports from here
/// so parallel tests never collide on a bind.
static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn spawn_server() -> TestServer {
    if NEXT_PORT.load(Ordering::SeqCst) == 0 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        NEXT_PORT.store(port, Ordering::SeqCst);
    }
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_server"))
        .env("SERVER_ADDR", &addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server binary spawns");

    // Wait for readiness (retry until the listener accepts). The deadline
    // is generous because parallel test threads and busy machines slow
    // process startup down; a server that exits early is reported at once
    // instead of burning the whole deadline.
    for _ in 0..500 {
        if TcpStream::connect(&addr).is_ok() {
            return TestServer { child, addr };
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("server on {addr} exited early with {status}");
        }
        sleep(Duration::from_millis(20));
    }
    panic!("server did not become ready on {addr}");
}

fn connect(server: &TestServer) -> TcpStream {
    let stream = TcpStream::connect(&server.addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

/// Reads WebSocket frames from `stream`: one generous wait for the first
/// data, then a short quiet window; returns raw bytes.
fn read_ws_frames(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    match stream.read(&mut chunk) {
        Ok(0) | Err(_) => return buf,
        Ok(n) => buf.extend_from_slice(&chunk[..n]),
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

/// Reads until EOF or the end of a complete HTTP response; returns the raw
/// bytes.
fn read_response(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // Stop after the head terminator when content-length is known.
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(header_end) = text.find("\r\n\r\n") {
                    let body_start = header_end + 4;
                    let declared = text
                        .to_lowercase()
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok());
                    if let Some(len) = declared
                        && buf.len() >= body_start + len
                    {
                        break;
                    }
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Reads raw bytes until a short quiet window; used for pipelined responses.
fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    match stream.read(&mut chunk) {
        Ok(0) | Err(_) => return buf,
        Ok(n) => buf.extend_from_slice(&chunk[..n]),
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// Basic HTTP behavior
// ---------------------------------------------------------------------------

/// E2E: GET / serves the static index page.
#[test]
fn e2e_get_index_serves_static_file() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
    assert!(response.contains("text/html"));
    assert!(response.contains("<!DOCTYPE html>"));
}

/// E2E: a missing file yields 404.
#[test]
fn e2e_get_missing_file_404() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET /nope.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 404"), "got: {response}");
}

/// E2E (F1 P0 regression over real sockets): a POST with the body in the
/// same segment returns instantly instead of deadlocking.
#[test]
fn e2e_post_echo_same_segment_body() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"POST /api/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nHello")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
    assert!(response.contains("Hello"), "got: {response}");
}

/// E2E: keep-alive serves multiple sequential requests on one connection.
#[test]
fn e2e_keep_alive_sequential_requests() {
    let server = spawn_server();
    let mut stream = connect(&server);
    for _ in 0..3 {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let response = read_response(&mut stream);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
        assert!(response.to_lowercase().contains("connection: keep-alive"));
    }
}

/// E2E (F1 regression): pipelined requests in one write get two responses,
/// in order, on the same connection.
#[test]
fn e2e_pipelined_requests_answered_in_order() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(
            b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n\
              GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap();
    let raw = read_all(&mut stream);
    let text = String::from_utf8_lossy(&raw);
    let first = text.find("HTTP/1.1 404").expect("first response present");
    let second = text[first + 13..]
        .find("HTTP/1.1 404")
        .expect("second response present");
    assert!(first < second + 13);
}

/// E2E (F7): HTTP/1.0 defaults to Connection: close.
#[test]
fn e2e_http_1_0_defaults_to_close() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
    assert!(response.to_lowercase().contains("connection: close"));
}

// ---------------------------------------------------------------------------
// Security behavior over real sockets (controls catalog, HTTP half)
// ---------------------------------------------------------------------------

/// E2E SEC-HTTP-006: path traversal with `..` is rejected.
#[test]
fn e2e_path_traversal_rejected() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    let status = response.lines().next().unwrap_or_default();
    assert!(
        status.contains("400") || status.contains("404"),
        "traversal must not serve files; got: {status}"
    );
    assert!(!response.contains("root:"), "passwd content must not leak");
}

/// E2E SEC-HTTP-006: percent-encoded traversal is rejected too.
#[test]
fn e2e_encoded_path_traversal_rejected() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(
        !response.contains("root:"),
        "encoded traversal must not leak files; got: {response}"
    );
}

/// E2E SEC-HTTP-001 (F8): a header bomb gets a 431 response, not a silent
/// drop.
#[test]
fn e2e_header_bomb_431() {
    let server = spawn_server();
    let mut stream = connect(&server);
    let mut bomb = b"GET / HTTP/1.1\r\nHost: x\r\nX-Bomb: ".to_vec();
    bomb.extend(std::iter::repeat_n(b'A', 64 * 1024));
    let _ = stream.write_all(&bomb);
    let response = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 431"),
        "header bomb must get 431; got: {response}"
    );
}

/// E2E SEC-HTTP-004 (F8): an oversized Content-Length gets 413.
#[test]
fn e2e_oversized_body_413() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n")
        .unwrap();
    let response = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "oversized body must get 413; got: {response}"
    );
}

/// E2E SEC-HTTP-003 (F4): CL+TE together gets 400 (smuggling vector).
#[test]
fn e2e_cl_te_conflict_400() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .unwrap();
    let response = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "CL/TE conflict must get 400; got: {response}"
    );
}

/// E2E (F8): a malformed request line gets 400.
#[test]
fn e2e_garbage_request_line_400() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream.write_all(b"NOT-A-REQUEST\r\n\r\n").unwrap();
    let response = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "garbage request must get 400; got: {response}"
    );
}

// ---------------------------------------------------------------------------
// WebSocket upgrade flow (SEC-WS-007)
// ---------------------------------------------------------------------------

/// E2E: a valid upgrade gets 101 with the RFC 6455 §4.2.2 accept vector, the
/// masked text frame is echoed, and the close handshake completes.
#[test]
fn e2e_websocket_upgrade_echo_close() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 101"), "got: {response}");
    assert!(
        response.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "accept vector mismatch; got: {response}"
    );

    // Masked "Hello" text frame (RFC 6455 §5.7 vector).
    let frame: [u8; 11] = [
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    stream.write_all(&frame).unwrap();
    let echoed = read_ws_frames(&mut stream);
    assert!(
        echoed.windows(2).any(|w| w == [0x81, 0x0b])
            && echoed.windows(11).any(|w| w == *b"Echo: Hello"),
        "expected echo frame; got: {echoed:?}"
    );

    // Close handshake: masked close frame, zero mask key, payload = code 1000.
    let close: [u8; 8] = [0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00];
    let _ = stream.write_all(&close);
    let closing = read_ws_frames(&mut stream);
    assert!(
        closing.first() == Some(&0x88),
        "expected close reply; got: {closing:?}"
    );
}

/// E2E SEC-WS-007: an upgrade with a malformed key gets 400, not 101.
#[test]
fn e2e_websocket_invalid_key_400() {
    let server = spawn_server();
    let mut stream = connect(&server);
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: not-a-real-key\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
    let response = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "bad key must get 400; got: {response}"
    );
}
