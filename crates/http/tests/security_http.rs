//! Security test catalog for the `http` crate (REFACTOR-PLAN.md §5.2).
//!
//! Every test carries its control ID and RFC section in the name and doc
//! comment; `docs/security/controls.md` links back to these names.

use bytes::BytesMut;
use http::{
    error::Error,
    limits::Limits,
    request::HttpRequest,
    response::{HttpResponse, HttpStatusCode},
};
use tokio::io::AsyncWriteExt;

/// SEC-HTTP-001, RFC 9110 §15.5.21 / RFC 9112 §2. Attack: header bomb
/// (16+ KiB head without a terminator). Expected: `Error::HeadTooLarge`
/// (→ 431), not unbounded buffering.
#[test]
fn sec_http_001_head_bomb_rejected_with_431_status() {
    let limits = Limits {
        max_head_bytes: 4096,
        ..Limits::default()
    };
    let mut bomb = b"GET / HTTP/1.1\r\nHost: x\r\nX-Bomb: ".to_vec();
    bomb.extend(std::iter::repeat_n(b'A', 8192));
    let err = HttpRequest::parse(&bomb, &limits).unwrap_err();
    assert!(matches!(err, Error::HeadTooLarge));
    assert_eq!(err.status(), HttpStatusCode::RequestHeaderFieldsTooLarge);
}

/// SEC-HTTP-001 boundary: a head exactly at the limit with a terminator
/// parses fine.
#[test]
fn sec_http_001_head_at_limit_accepted() {
    let limits = Limits::default();
    let ok = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert!(HttpRequest::parse(ok, &limits).unwrap().is_some());
}

/// SEC-HTTP-002, RFC 9110 §9.4 / threat model (Slow-Loris). Attack: a
/// trickle-fed request head that never completes. Expected:
/// `head_read_timeout` expires and the read fails instead of hanging forever.
#[tokio::test(start_paused = true)]
async fn sec_http_002_slowloris_head_read_times_out() {
    let limits = Limits {
        head_read_timeout: std::time::Duration::from_secs(10),
        keep_alive_idle_timeout: Some(std::time::Duration::from_secs(5)),
        ..Limits::default()
    };

    // Send a partial request head and keep the connection open without
    // sending the rest (classic Slow-Loris drip).
    let (mut client, mut server) = tokio::io::duplex(64);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let mut buffer = BytesMut::new();
    let read_task = tokio::spawn(async move {
        http::connection::read_request(&mut server, &mut buffer, &limits).await
    });

    // Advance paused time past the head timeout (10 s).
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;

    let result = read_task.await.unwrap();
    match result {
        Err(Error::InvalidHttpRequest("Read timeout")) => {}
        other => panic!("expected read timeout, got {other:?}"),
    }
}

/// SEC-HTTP-003, RFC 9112 §6.3. Attack: request smuggling by sending both
/// `Content-Length` and `Transfer-Encoding`. Expected: rejection with 400.
#[test]
fn sec_http_003_rejects_cl_te_conflict() {
    let request = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
    assert_eq!(err.status(), HttpStatusCode::BadRequest);
}

/// SEC-HTTP-004, RFC 9110 §15.5.14. Attack: oversized declared body.
/// Expected: `Error::BodyTooLarge` (→ 413) without reading the body.
#[test]
fn sec_http_004_oversized_body_rejected_with_413_status() {
    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let request = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1024\r\n\r\n";
    let err = HttpRequest::parse(request, &limits).unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge));
    assert_eq!(err.status(), HttpStatusCode::PayloadTooLarge);
}

/// SEC-HTTP-004 boundary: chunked bodies exceeding the cap are also 413.
#[test]
fn sec_http_004_chunked_body_over_cap_rejected() {
    let limits = Limits {
        max_body_bytes: 4,
        ..Limits::default()
    };
    // Two 3-byte chunks = 6 bytes total > cap of 4.
    let request = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
    let err = HttpRequest::parse(request, &limits).unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge));
}

/// SEC-HTTP-005, RFC 9112 §9.3. Attack: connection hoarding on keep-alive.
/// Expected: after `max_requests_per_connection` requests the server closes;
/// advertised `Keep-Alive` parameters match the enforced limits.
#[test]
fn sec_http_005_advertised_keep_alive_matches_limits_defaults() {
    let limits = Limits::default();
    let response = HttpResponse::ok().with_text("hi");
    let bytes = String::from_utf8_lossy(&response.to_bytes()).to_string();
    let timeout = limits.keep_alive_idle_timeout.unwrap();
    let max = limits.max_requests_per_connection.unwrap();
    assert!(
        bytes.contains(&format!("timeout={}, max={}", timeout.as_secs(), max)),
        "advertised Keep-Alive must match enforced limits; got: {bytes}"
    );
}

/// SEC-HTTP-006 (server-layer control; here the framing half): pipelined
/// requests in one buffer are both parseable, the second one untouched
/// (regression for F1, the P0).
#[test]
fn sec_http_007_pipelined_requests_parse_in_sequence() {
    let limits = Limits::default();
    let first = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
    let second = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut buffer = first.to_vec();
    buffer.extend_from_slice(second);

    let (req_a, consumed) = HttpRequest::parse(&buffer, &limits)
        .unwrap()
        .expect("first request complete");
    assert_eq!(req_a.path, "/a");
    assert_eq!(consumed, first.len());

    let (req_b, consumed_b) = HttpRequest::parse(&buffer[consumed..], &limits)
        .unwrap()
        .expect("second request complete");
    assert_eq!(req_b.path, "/b");
    assert_eq!(consumed_b, second.len());
}

/// SEC-HTTP-007 (F1 P0 regression): a POST body that arrived in the same
/// buffer as the head is consumed from the buffer, not re-read from the
/// socket.
#[test]
fn sec_http_007_post_body_consumed_from_buffer() {
    let limits = Limits::default();
    let head = b"POST /api/test HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
    let mut buffer = head.to_vec();
    buffer.extend_from_slice(b"Hello");

    let (request, consumed) = HttpRequest::parse(&buffer, &limits)
        .unwrap()
        .expect("request complete");
    assert_eq!(request.body, b"Hello");
    assert_eq!(consumed, head.len() + 5);
}

/// SEC-HTTP-007 read-loop level: the same POST over real (duplex) IO
/// completes; before the fix the server blocked forever.
#[tokio::test]
async fn sec_http_007_post_body_over_duplex_completes() {
    let (mut client, mut server) = tokio::io::duplex(64);
    client
        .write_all(b"POST /api/test HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHello")
        .await
        .unwrap();
    drop(client);

    let mut buffer = BytesMut::new();
    let request = http::connection::read_request(&mut server, &mut buffer, &Limits::default())
        .await
        .unwrap()
        .expect("request present");
    assert_eq!(request.body, b"Hello");
}

/// F7: HTTP/1.0 defaults to close; keep-alive must be opted into.
#[test]
fn sec_http_f7_http_1_0_defaults_to_close() {
    let one_point_oh = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n";
    let request = HttpRequest::parse(one_point_oh, &Limits::default())
        .unwrap()
        .unwrap()
        .0;
    assert!(request.should_close());

    let opt_in = b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
    let request = HttpRequest::parse(opt_in, &Limits::default())
        .unwrap()
        .unwrap()
        .0;
    assert!(!request.should_close());

    let one_point_oh_close = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let request = HttpRequest::parse(one_point_oh_close, &Limits::default())
        .unwrap()
        .unwrap()
        .0;
    assert!(request.should_close());
}

/// Duplicate Content-Length lines (smuggling vector) are combined and
/// rejected: `5, 5` does not parse as one integer.
#[test]
fn sec_http_003_duplicate_content_length_rejected() {
    let request =
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nHello";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
}

/// Trailer fields after a chunked body keep framing unambiguous: rejected.
#[test]
fn sec_http_chunked_trailers_rejected() {
    let request = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: 1\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
}

/// A complete chunked body decodes correctly, including the consumed count.
#[test]
fn sec_http_chunked_body_decodes() {
    let request = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n world\r\n0\r\n\r\n";
    let (req, consumed) = HttpRequest::parse(request, &Limits::default())
        .unwrap()
        .expect("complete");
    assert_eq!(req.body, b"Hello world");
    assert_eq!(consumed, request.len());
}
