# Threat model

## Scope

The demo `server` as it exists today: an unauthenticated HTTP/1.1 static file
server plus echo endpoint plus WebSocket echo server, bound to `127.0.0.1` by
default. The model covers what happens when it faces a hostile network peer.
It does not cover the host OS, the supply chain, or physical access.

## Assets

| Asset                       | Why it matters                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------- |
| Host filesystem             | Static serving must not escape the static directory                                                     |
| Process memory              | Unbounded buffering means denial of service (or worse, if unsafe code existed; it is forbidden)         |
| CPU / task scheduler        | Slow or malformed input must not starve other connections                                               |
| Availability                | The server should survive abusive clients and keep serving                                              |
| Connection stream integrity | Framing confusion (smuggling/desync) must not let one client's bytes be read as a different request     |

## Trust boundaries

1. **TCP byte stream into parser.** The attacker controls every byte, the
   timing of every byte (drip-feeding), and can open many connections.
2. **Parser into filesystem.** The request path crosses into `fs::read`; only
   canonicalization plus a prefix check stands between it and arbitrary reads.
3. **HTTP layer into WebSocket layer.** The upgrade hands the socket to a
   different protocol implementation with its own framing rules.

## Attacker capabilities

- Send arbitrary bytes, arbitrary framing, arbitrary header sets.
- Send bytes arbitrarily slowly (Slow-Loris) or in one segment (pipelining
  tricks).
- Open many parallel connections and hold them indefinitely.
- Send maximally-declared lengths (headers, bodies, frames).
- Attempt path traversal with `..`, URL-encoded variants, absolute paths, and
  (if the filesystem allows) symlink escapes.

No authentication is assumed or required; everything above is available to a
completely anonymous peer.

## Abuse cases → findings → controls

All Phase-3 controls are implemented and tested; the table records the
abuse case, the finding it maps to, and the control + test that prove the
mitigation. Test names live in `crates/*/tests/` (see
[controls.md](controls.md) for the full list).

| Abuse case                                              | Finding | Control (status)                                                                       |
| ------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| Drip-feed headers to hold tasks open (Slow-Loris)       | F2      | SEC-HTTP-002, head read timeout (closed)                                                |
| Declare huge header block                               | F8      | SEC-HTTP-001, 16 KiB cap with a 431 response (closed)                                   |
| Send `Content-Length` and `Transfer-Encoding` together  | F4      | SEC-HTTP-003, reject the combination (closed)                                           |
| Pipeline requests or same-segment body to desync framing | F1     | SEC-HTTP-007, connection-owned buffer (closed)                                          |
| Hold keep-alive connections forever                     | F3      | SEC-HTTP-005, idle timeout + max requests (closed)                                      |
| Huge `Content-Length` body                              |         | SEC-HTTP-004, 10 MiB cap with a 413 response (closed)                                   |
| Path traversal (`..`, encoded, symlink)                 | F10     | SEC-HTTP-006, percent-decode + canonicalize + prefix check + canonical-path read (closed) |
| Declare giant WS frame to force buffering               | F5      | SEC-WS-002, 1 MiB frame cap, close 1009 before buffering (closed)                       |
| Unmasked client frames                                  |         | SEC-WS-001, close 1002 (closed)                                                          |
| Reserved opcode / RSV bits / fragmented control frame   | F6      | SEC-WS-003, strict validation with close 1002 (closed)                                  |
| Oversized control frame                                 |         | SEC-WS-004, close 1002 (closed)                                                          |
| Invalid UTF-8 text frames                               |         | SEC-WS-005, close 1007 (closed)                                                          |
| Bogus close codes                                       |         | SEC-WS-006, validation (closed)                                                          |
| Garbage handshake (wrong method, bad key)               | F11     | SEC-WS-007, full §4.2.1 validation with 400 (closed)                                    |
| Silent client that never responds to pings              |         | SEC-WS-008, liveness close 1002, paused-time test (closed)                              |
| Fragmented-message abuse / control-frame interleave     | F4 (WS) | SEC-WS-009, reassembly state machine with strict state rules (closed)                   |
| Connection churn (open/close storms)                    |         | Not addressed; rate limiting is future work (see roadmap)                               |

## Out of scope (for now)

- **TLS.** There is no TLS termination; anything beyond localhost should front
  the server with a TLS proxy (see [hardening.md](hardening.md)).
- **Application-level authn/authz.** The demo has no protected resources.
- **HTTP request smuggling across intermediaries.** The server is modeled as
  origin, not proxy. SEC-HTTP-003 removes the local CL/TE ambiguity.
- **Network-layer DoS** (SYN floods etc.). That sits below the application.
- **`Host`/`Origin` header validation.** Recorded in the compliance matrices
  as the remaining honest gap; not exploitable beyond request confusion in
  the current single-tenant demo.
