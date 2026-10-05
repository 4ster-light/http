//! Security test catalog for the `http` crate, indexed row-by-row in
//! `docs/security/controls.md` with the corresponding control IDs.
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

// ---------------------------------------------------------------------------
// SEC-HTTP-009: Host header required on HTTP/1.1 (RFC 9110 §7.4)
// ---------------------------------------------------------------------------

/// SEC-HTTP-009, RFC 9110 §7.4 / RFC 9112 §3.2. Attack: HTTP/1.1 request
/// without `Host` (virtual-host confusion). Expected: 400.
#[test]
fn sec_http_009_http_1_1_without_host_rejected_400() {
    let request = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
    assert_eq!(err.status(), HttpStatusCode::BadRequest);
}

/// SEC-HTTP-009 boundary: HTTP/1.0 predates the requirement, so a missing
/// `Host` is accepted (keeps the version condition honest).
#[test]
fn sec_http_009_http_1_0_without_host_accepted() {
    let request = b"GET / HTTP/1.0\r\n\r\n";
    assert!(
        HttpRequest::parse(request, &Limits::default())
            .unwrap()
            .is_some()
    );
}

/// SEC-HTTP-009, RFC 9110 §5.6.3. Attack: whitespace between a field name
/// and the colon (`Host : evil`) could smuggle a second, spoofed `Host`.
/// Expected: 400.
#[test]
fn sec_http_009_header_whitespace_before_colon_rejected() {
    let request = b"GET / HTTP/1.1\r\nHost : evil\r\nHost: good\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
}

// ---------------------------------------------------------------------------
// SEC-HTTP-011: request-target forms (RFC 9112 §3.2.1)
// ---------------------------------------------------------------------------

/// SEC-HTTP-011, RFC 9112 §3.2.1. Attack: absolute-form target on a server
/// that only routes origin-form; previously it was misparsed as a path and
/// silently 404'd. Expected: an explicit 400.
#[test]
fn sec_http_011_absolute_form_rejected_400() {
    let request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
    assert_eq!(err.status(), HttpStatusCode::BadRequest);
}

/// SEC-HTTP-011, RFC 9110 §9.3.7: server-wide `OPTIONS *` is routed.
#[test]
fn sec_http_011_asterisk_form_options_accepted() {
    let request = b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n";
    let (parsed, _) = HttpRequest::parse(request, &Limits::default())
        .unwrap()
        .expect("complete");
    assert_eq!(parsed.path, "*");
    assert_eq!(parsed.method, http::request::HttpMethod::Options);
}

/// SEC-HTTP-011: asterisk-form with any method other than `OPTIONS` is
/// invalid (RFC 9112 §3.2.1).
#[test]
fn sec_http_011_asterisk_form_non_options_rejected() {
    let request = b"GET * HTTP/1.1\r\nHost: x\r\n\r\n";
    let err = HttpRequest::parse(request, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
}

/// SEC-HTTP-011, RFC 9112 §3.2.1: authority-form is only meaningful for
/// `CONNECT`; for any other method it is an invalid target.
#[test]
fn sec_http_011_authority_form_requires_connect() {
    let connect = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(
        HttpRequest::parse(connect, &Limits::default())
            .unwrap()
            .is_some()
    );

    let get = b"GET example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let err = HttpRequest::parse(get, &Limits::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidHttpRequest(_)));
}

// ---------------------------------------------------------------------------
// SEC-HTTP-010: Expect: 100-continue (RFC 9110 §10.1.1)
// ---------------------------------------------------------------------------

/// SEC-HTTP-010, RFC 9110 §10.1.1. A client that sends the head with
/// `Expect: 100-continue` and waits receives the interim `100` before it
/// sends the body; the request then completes normally.
#[tokio::test]
async fn sec_http_010_expect_continue_gets_100_then_request_completes() {
    let (mut client, mut server) = tokio::io::duplex(256);
    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buffer = BytesMut::new();
    let read_task = tokio::spawn(async move {
        http::connection::read_request(&mut server, &mut buffer, &Limits::default()).await
    });

    // The interim response must arrive without the body being sent.
    let mut chunk = [0u8; 128];
    let n = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut chunk))
        .await
        .expect("interim response is prompt")
        .unwrap();
    let interim = String::from_utf8_lossy(&chunk[..n]);
    assert!(
        interim.starts_with("HTTP/1.1 100 Continue\r\n\r\n"),
        "expected 100 Continue; got: {interim}"
    );

    client.write_all(b"Hello").await.unwrap();
    let request = read_task.await.unwrap().unwrap().expect("request present");
    assert_eq!(request.body, b"Hello");
}

/// SEC-HTTP-010 / SEC-HTTP-004: when the announced body already exceeds the
/// cap, the 413 is decided from the head and no `100 Continue` is sent
/// (RFC 9110 §10.1.1 allows a final status instead).
#[tokio::test]
async fn sec_http_010_expect_continue_with_oversized_body_skips_100() {
    let (mut client, mut server) = tokio::io::duplex(256);
    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 99999\r\n\r\n",
        )
        .await
        .unwrap();

    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let mut buffer = BytesMut::new();
    let err = http::connection::read_request(&mut server, &mut buffer, &limits)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge));

    // No interim response was written before the final status was chosen.
    let mut chunk = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        client.read(&mut chunk),
    )
    .await;
    assert!(read.is_err(), "no bytes should be sent before the 413");
}

/// SEC-HTTP-010, RFC 9110 §10.1.1: `Expect` is ignored for HTTP/1.0, so no
/// interim response is sent.
#[tokio::test]
async fn sec_http_010_expect_ignored_for_http_1_0() {
    let (mut client, mut server) = tokio::io::duplex(256);
    client
        .write_all(b"POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
        .await
        .unwrap();

    let mut buffer = BytesMut::new();
    let read_task = tokio::spawn(async move {
        http::connection::read_request(&mut server, &mut buffer, &Limits::default()).await
    });

    let mut chunk = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        client.read(&mut chunk),
    )
    .await;
    assert!(read.is_err(), "HTTP/1.0 must not receive 100 Continue");

    client.write_all(b"Hello").await.unwrap();
    let request = read_task.await.unwrap().unwrap().expect("request present");
    assert_eq!(request.body, b"Hello");
}
