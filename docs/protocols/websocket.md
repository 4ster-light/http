# WebSocket protocol notes

Deep-dive into the `websocket` crate. For the requirement-by-requirement status
see
[../rfc-compliance/websocket-rfc6455.md](../rfc-compliance/websocket-rfc6455.md).

## Handshake

`handshake::is_websocket_request` requires, per RFC 6455 §4.2.1:

- `Upgrade: websocket` (case-insensitive)
- `Connection` containing `Upgrade` (case-insensitive substring)
- `Sec-WebSocket-Version: 13`

It returns the `Sec-WebSocket-Key` value when all match.

`handshake::generate_accept` answers with `101 Switching Protocols` and
`Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-…85B11"))` (§4.2.2),
verified against the RFC test vector.

**Not yet validated (F11, scheduled as SEC-WS-007):** the method being `GET`,
the HTTP version being at least 1.1, and the key format (base64 of 16 bytes).
A request with a nonsense key currently gets a syntactically valid `101`.

## Frame codec (`frame`)

`WebSocketFrame::parse(&[u8]) -> Result<(frame, consumed), ParseError>`:

- Expects **client-to-server** traffic: unmasked input is rejected
  (`UnmaskedClientFrame`, §5.3). `to_bytes()` does the opposite direction, so
  server frames are unmasked with FIN set.
- 7/16/64-bit payload lengths supported. Length bookkeeping is done in `u64`
  and bounds-checked before any `usize` conversion, so a hostile 64-bit length
  cannot truncate into a false "frame complete" on 32-bit targets.
- Control frames with payloads over 125 bytes are rejected
  (`ControlFrameTooLarge`, §5.5).
- Text payloads are UTF-8 validated (`InvalidUtf8`).
- Close codes are validated against the registered ranges
  (`1000..=1003 | 1007..=1011 | 3000..=4999`); anything else gives
  `InvalidCloseCode`.
- Unknown/reserved opcodes are mapped to `Close`, so the connection layer
  terminates the connection instead of desynchronizing the stream.

### Known deviations

- **F4 / SEC-WS-009:** fragmentation is not implemented. The FIN bit is not
  tracked and continuation frames return `Incomplete`, so a fragmented message
  hangs the connection. Reassembly lands in the security phase.
- **F5 / SEC-WS-002:** no cap on data-frame payloads. A frame can declare an
  enormous length and force buffering. Max payload with close code 1009
  planned.
- **F6 / SEC-WS-003:** RSV bits are ignored (they must be 0 without
  extensions), and fragmented control frames are not detected (FIN ignored).
- Parse errors currently end the TCP connection **without a close frame**;
  sending 1002/1007 as appropriate is part of the controls catalog.

## Connection lifecycle (`connection::handle_websocket`)

```txt
BytesMut buffer (persistent across reads)
    ↓
Read data from socket → Append to buffer
    ↓
Try to parse frame
    ↓
    ├─> Success: Remove consumed bytes, process frame
    ├─> Incomplete: Continue reading more data
    └─> Error: Close connection
```

- Text is echoed back prefixed with `Echo:`; binary is echoed as-is.
- Client ping gets a pong with the same payload; pong clears the liveness flag.
- **Liveness:** a server ping every 30 s. If no pong arrives before the next
  tick, the server sends a close frame with code **1002** ("Ping timeout") and
  shuts down.
- Close gets a reply close and a clean shutdown.
- Incoming bytes buffer across reads; incomplete frames wait for more data.

Timeouts are relative to the ping ticker, not to frame activity, so a fully
silent client is dropped after at most about 60 s.
