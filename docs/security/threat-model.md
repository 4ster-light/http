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

| Abuse case                                              | Finding | Countermeasure                                                                      |
| ------------------------------------------------------- | ------- | ----------------------------------------------------------------------------------- |
| Drip-feed headers to hold tasks open (Slow-Loris)       | F2      | SEC-HTTP-002 (read timeouts)                                                        |
| Declare huge header block                               | F8      | 16 KiB cap today; SEC-HTTP-001 adds a `431` response                                |
| Send `Content-Length` and `Transfer-Encoding` together  | F4      | SEC-HTTP-003 (TE precedence / reject)                                               |
| Pipeline requests or same-segment body to desync framing | F1     | SEC-HTTP-007 (buffer ownership, ADR-0005)                                           |
| Hold keep-alive connections forever                     | F3      | SEC-HTTP-005 (idle timeout + max requests)                                          |
| Huge `Content-Length` body                              |         | 10 MiB cap today; SEC-HTTP-004 adds a `413` response                                |
| Path traversal (`..`, encoded, symlink)                 | F10     | Canonicalize + prefix check today; SEC-HTTP-006 reads the canonical path, with tests |
| Declare giant WS frame to force buffering               | F5      | SEC-WS-002 (max payload, close 1009)                                                |
| Unmasked client frames                                  |         | Enforced today; SEC-WS-001 adds close 1002 + test                                   |
| Reserved opcode / RSV bits / fragmented control frame   | F6      | SEC-WS-003 (strict validation, close 1002)                                          |
| Oversized control frame                                 |         | Enforced today; SEC-WS-004 adds boundary tests                                      |
| Invalid UTF-8 text frames                               |         | Parse error today; SEC-WS-005 sends close 1007                                      |
| Bogus close codes                                       |         | Table today; SEC-WS-006 sends close 1002 + test                                     |
| Garbage handshake (wrong method, bad key)               | F11     | SEC-WS-007 (full §4.2.1 validation)                                                 |
| Silent client that never responds to pings              |         | Liveness close 1002 today; SEC-WS-008 adds paused-time tests                        |
| Fragmented-message abuse / control-frame interleave     | F4 (WS) | SEC-WS-009 (reassembly state machine)                                               |
| Connection churn (open/close storms)                    |         | Not addressed yet; rate limiting is future work (see roadmap)                        |

## Out of scope (for now)

- **TLS.** There is no TLS termination; anything beyond localhost should front
  the server with a TLS proxy (see [hardening.md](hardening.md)).
- **Application-level authn/authz.** The demo has no protected resources.
- **HTTP request smuggling across intermediaries.** The server is modeled as
  origin, not proxy. SEC-HTTP-003 still fixes the local CL/TE ambiguity.
- **Network-layer DoS** (SYN floods etc.). That sits below the application.
