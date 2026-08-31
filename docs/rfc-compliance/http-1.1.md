# HTTP/1.1 compliance matrix: RFC 9110 / RFC 9112

Status legend: ✅ implemented · ⚠️ partial / deviates · ❌ not implemented. A
`❌` row is the roadmap, not a hidden failure. Requirement levels
(MUST/SHOULD/MAY) come from the RFCs. Older code comments cite RFC 7230-7235
(the obsoleted predecessors); section numbers here use the current RFCs.

## Message framing & parsing (RFC 9112)

| §       | Requirement                                                      | Level  | Status | Implementation                                                                | Evidence / notes                                                                                   |
| ------- | ---------------------------------------------------------------- | ------ | ------ | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| 2.1     | Parse request: request-line, headers, CRLFCRLF terminator        | MUST   | ✅     | `http::request::HttpRequest::parse`, `http::connection::read_request`         | `sec_http_007_post_body_over_duplex_completes`                                                      |
| 3       | Request line is exactly `method SP target SP HTTP-version`       | MUST   | ✅     | `parse_head` in `http::request`                                               | 3-token split with version token check; e2e `e2e_garbage_request_line_400`                          |
| 3.2     | Method token handling                                            | MUST   | ✅     | `request::HttpMethod` (9 methods, case-insensitive `FromStr`)                 | `test_http_method_parsing`                                                                          |
| 3.2     | Respond 400 to missing/invalid `Host` on HTTP/1.1                | MUST   | ❌     |                                                                               | `Host` never inspected (future work)                                                                 |
| 4       | Request target forms                                             | MUST   | ⚠️     | origin-form only                                                              | absolute-form, asterisk-form, authority-form unsupported                                             |
| 5       | Field syntax `name: value`; names case-insensitive               | MUST   | ✅     | `HttpRequest` lower-cases names into a map                                    | `test_http_request_parsing`                                                                          |
| 5.2     | Duplicate field lines combined                                   | MAY    | ✅     | comma-merged in `parse_head`                                                  | `sec_http_003_duplicate_content_length_rejected` (conflicting CL fails closed)                       |
| 5.1/5.2 | Enforce request-size limits (431 on excess)                      | SHOULD | ✅     | `Limits::max_head_bytes` → `Error::HeadTooLarge` → `431`                      | `sec_http_001_head_bomb_rejected_with_431_status`, e2e `e2e_header_bomb_431`                         |
| 6.1     | `Expect: 100-continue`                                           | MUST   | ❌     |                                                                               | Not implemented (future work)                                                                        |
| 6.3     | `Content-Length` body framing                                    | MUST   | ✅     | `HttpRequest::parse` (cap `Limits::max_body_bytes`)                           | `sec_http_007_post_body_consumed_from_buffer`; overflow → `413` (`sec_http_004_*`)                   |
| 6.3     | `Transfer-Encoding` overrides `Content-Length` when both present | MUST   | ✅     | the combination is rejected outright (RFC 9112 §6.3 recommends rejection)     | `sec_http_003_rejects_cl_te_conflict`, e2e `e2e_cl_te_conflict_400`                                  |
| 7.1     | Chunked decoding: sizes, CRLF framing, terminating chunk         | MUST   | ✅     | `http::body::decode_chunked_body` (1 MiB chunk-independent, body cap)         | `sec_http_chunked_body_decodes`                                                                      |
| 7.1.1   | Chunk extensions tolerated and ignored                           | MAY    | ✅     | extensions split off the size line and ignored                                | decoder accepts `;`-extensions per §7.1.1                                                            |
| 7.1.2   | Trailers                                                         | MAY    | ⚠️     | trailer fields rejected (stricter than required)                              | `sec_http_chunked_trailers_rejected`                                                                 |
| 9.3     | Persistence: keep-alive by default for HTTP/1.1                  | MUST   | ✅     | `server::connection` loop with `Limits` (ADR-0007)                            | e2e `e2e_keep_alive_sequential_requests`                                                             |
| 9.3     | HTTP/1.0 semantics (`Connection: keep-alive` opt-in)             | SHOULD | ✅     | `HttpRequest::should_close` (F7 fixed)                                        | `sec_http_f7_http_1_0_defaults_to_close`, e2e `e2e_http_1_0_defaults_to_close`                       |
| 9.3.2   | Pipelining                                                       | MUST   | ✅     | connection-owned buffer; consumed bytes never discarded (F1 fixed, ADR-0005)  | `sec_http_007_pipelined_requests_parse_in_sequence`, e2e `e2e_pipelined_requests_answered_in_order`  |
| 9.6     | Tear down cleanly on errors                                      | MUST   | ✅     | errors mapped to status codes via `Error::status()`, response sent, then close | `sec_http_001_*`, e2e `e2e_garbage_request_line_400`, `e2e_cl_te_conflict_400`                       |

## Semantics (RFC 9110)

| §      | Requirement                                            | Level  | Status | Implementation                             | Evidence / notes                          |
| ------ | ------------------------------------------------------ | ------ | ------ | ------------------------------------------ | ----------------------------------------- |
| 9.3.1  | `HEAD`: like GET without body                          | SHOULD | ❌     |                                            | `405` (parsed but not routed; future work) |
| 9.3.7  | `OPTIONS`                                              | MAY    | ✅     | `server::handler::handle_options_request`  | permissive CORS preflight                 |
| 15     | Status codes with reason phrases                       | MUST   | ✅     | `response::HttpStatusCode` (incl. 413/431) | `test_status_code_display`                |
| 15.5.5 | `405` for unsupported methods                          | SHOULD | ✅     | `handler::handle_http_request` default arm | manual                                    |
| 15.5.14| `413 Payload Too Large` for oversized bodies           | MUST   | ✅     | `Error::BodyTooLarge` → 413                | `sec_http_004_oversized_body_rejected_with_413_status` |
| 8.2    | `Keep-Alive` header parameters honored once advertised |        | ✅     | advertisement derived from enforced `Limits` (ADR-0007) | `sec_http_005_advertised_keep_alive_matches_limits_defaults` |
| 15.6.1 | `Server` header                                        | MAY    | ✅     | auto-added by `HttpResponse::to_bytes`     | `http-rs/0.1.0`                           |
| 6.6.1  | `Date` header, IMF-fixdate                             | MUST   | ✅     | `httpdate::fmt_http_date` in `to_bytes`    | visible in any response                   |
| 7.8    | `Content-Length` on responses                          | SHOULD | ✅     | `with_body` auto-sets when absent          | `test_http_response_creation`             |
| 9.3.2  | `Range` requests                                       | MAY    | ❌     |                                            | out of scope                              |

## Summary

- The framing layer is now fully in scope and green: parsing, body framing,
  CL/TE conflict rejection, pipelining, and clean error teardown all have
  linked tests. F1 (P0), F4, F7, and F8 are closed.
- Remaining honest gaps: `Host` validation (400), `Expect: 100-continue`,
  `HEAD` routing, and non-origin-form targets. Each is future work, listed
  here rather than hidden.

## Out of scope (declared, per the plan §1)

Caching (RFC 9111), conditional requests (RFC 9110 §13), range requests
(§14), authentication (RFC 9110 §11), proxy/absolute-form handling. The
server claims none of these; a request depending on them is answered with
the closest honest status (`405`/`400`), never a wrong 2xx.
