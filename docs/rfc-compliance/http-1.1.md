# HTTP/1.1 compliance matrix — RFC 9110 / RFC 9112

Status legend: ✅ implemented · ⚠️ partial / deviates · ❌ not implemented. `❌`
is not a failure to hide — it is the roadmap. Requirement levels
(MUST/SHOULD/MAY) are from the RFCs. Older code comments cite RFC 7230–7235 (the
obsoleted predecessors); section numbers here use the current RFCs.

## Message framing & parsing (RFC 9112)

| §       | Requirement                                                      | Level  | Status | Implementation                                                             | Evidence / notes                                                                         |
| ------- | ---------------------------------------------------------------- | ------ | ------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| 2.1     | Parse request: request-line, headers, CRLFCRLF terminator        | MUST   | ✅     | `server::connection::find_header_end`, `request::HttpRequest::from_buffer` | `test_http_request_parsing`                                                              |
| 3       | Request line is exactly `method SP target SP HTTP-version`       | MUST   | ✅     | `request::HttpRequest::from_buffer_sync`                                   | 3-token split, rejects otherwise                                                         |
| 3.2     | Method token handling                                            | MUST   | ✅     | `request::HttpMethod` (9 methods, case-insensitive `FromStr`)              | `test_http_method_parsing`                                                               |
| 3.2     | Respond 400 to missing/invalid `Host` on HTTP/1.1                | MUST   | ❌     | —                                                                          | `Host` never inspected                                                                   |
| 4       | Request target forms                                             | MUST   | ⚠️     | origin-form only                                                           | absolute-form, asterisk-form, authority-form unsupported                                 |
| 5       | Field syntax `name: value`; names case-insensitive               | MUST   | ✅     | `HttpRequest` lower-cases names into a map                                 | `test_http_request_parsing`                                                              |
| 5.1/5.2 | Enforce request-size limits (431 on excess)                      | SHOULD | ⚠️     | 16 KiB head cap in `server::connection`                                    | Cap exists (F8), but connection drops **with no response**; `431` planned (SEC-HTTP-001) |
| 6.3     | `Content-Length` body framing                                    | MUST   | ✅     | `HttpRequest::from_buffer` (10 MiB cap)                                    | manual; overflow → connection drop, `413` planned (SEC-HTTP-004)                         |
| 6.3     | `Transfer-Encoding` overrides `Content-Length` when both present | MUST   | ❌     | —                                                                          | **F4**: CL path wins; smuggling risk (SEC-HTTP-003)                                      |
| 7.1     | Chunked decoding: sizes, CRLF framing, terminating chunk         | MUST   | ✅     | `body::read_chunked_body` (1 MiB chunk cap)                                | **no test yet** — listed in testing.md gaps                                              |
| 7.1.1   | Chunk extensions                                                 | MAY    | ❌     | —                                                                          | Rejected as malformed (stricter than required — OK)                                      |
| 7.1.2   | Trailers                                                         | MAY    | ⚠️     | —                                                                          | Rejected as malformed (stricter than required — OK)                                      |
| 9.3     | Persistence: keep-alive by default for HTTP/1.1                  | MUST   | ✅     | `server::connection::handle_connection` loop                               | manual smoke; honored `Connection: close`                                                |
| 9.3     | HTTP/1.0 semantics (`Connection: keep-alive` opt-in)             | SHOULD | ❌     | —                                                                          | **F7**: version token parsed, never consulted                                            |
| 9.3.2   | Pipelining                                                       | MUST   | ❌     | —                                                                          | **F1 (P0)**: buffered bytes after head are discarded                                     |
| 6.1     | `Expect: 100-continue`                                           | MUST   | ❌     | —                                                                          | Not implemented                                                                          |
| 9.6     | Tear down cleanly on errors                                      | MUST   | ⚠️     | errors propagate, connection closes                                        | closes without response/status (see controls)                                            |

## Semantics (RFC 9110)

| §      | Requirement                                            | Level  | Status | Implementation                             | Evidence / notes                    |
| ------ | ------------------------------------------------------ | ------ | ------ | ------------------------------------------ | ----------------------------------- |
| 9.3.1  | `HEAD`: like GET without body                          | SHOULD | ❌     | —                                          | `405` (parsed but not routed)       |
| 9.3.7  | `OPTIONS`                                              | MAY    | ✅     | `server::handler::handle_options_request`  | permissive CORS preflight           |
| 15     | Status codes with reason phrases                       | MUST   | ✅     | `response::HttpStatusCode`                 | `test_status_code_display`          |
| 15.6.1 | `Server` header                                        | MAY    | ✅     | auto-added by `HttpResponse::to_bytes`     | `http-rs/0.1.0`                     |
| 6.6.1  | `Date` header, IMF-fixdate                             | MUST   | ✅     | `httpdate::fmt_http_date` in `to_bytes`    | visible in any response             |
| 7.8    | `Content-Length` on responses                          | SHOULD | ✅     | `with_body` auto-sets when absent          | `test_http_response_creation`       |
| 15.5.5 | `405` for unsupported methods                          | SHOULD | ✅     | `handler::handle_http_request` default arm | manual                              |
| 8.2    | `Keep-Alive` header parameters honored once advertised | —      | ⚠️     | advertises `timeout=5, max=100` on 2xx     | **F3**: not enforced (SEC-HTTP-005) |
| 9.3.2  | `Range` requests                                       | MAY    | ❌     | —                                          | out of scope for now                |

## Summary

- Blocking correctness/security gaps: **F1** (pipelining/body buffering), **F4**
  (CL/TE precedence), missing `Host` validation.
- Stricter-than-spec choices (acceptable): chunk extensions and trailers
  rejected; `HEAD`/`CONNECT` refused with `405`.
- Every ❌/⚠️ row maps to a control in
  [../security/controls.md](../security/controls.md) with a scheduled phase.
