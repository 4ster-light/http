# Fuzzing

The parsers at the trust boundary are fuzzed with `cargo-fuzz` (libFuzzer):
the HTTP request parser and the WebSocket frame parser. The harnesses run on
a pinned nightly and CI executes a 60-second smoke per target on every push
and PR, archiving crash artifacts.

## Targets

| Harness              | Function under test                    | What it proves                                                |
| -------------------- | -------------------------------------- | ------------------------------------------------------------- |
| `request_head_parse` | `http::request::HttpRequest::parse`    | No panic, no unbounded allocation, no hang on arbitrary bytes; consumed never exceeds input |
| `frame_parse`        | `websocket::frame::Frame::parse`       | No panic on arbitrary bytes; declared-length arithmetic sound (oversized frames rejected before buffering) |

Both call pure functions over byte slices (per
[ADR-0005](../adr/0005-generic-io-and-pure-parsers.md)), which is what makes
them directly fuzzable.

## Layout

```txt
fuzz/
├── Cargo.toml              # own workspace, excluded from the main graph
├── fuzz_targets/
│   ├── request_head_parse.rs
│   └── frame_parse.rs
├── corpus/                 # seeds: valid requests/frames + RFC examples
│   ├── request_head_parse/
│   └── frame_parse/
└── dictionaries/           # protocol token dictionaries
    ├── http.dict
    └── websocket.dict
```

The seed corpora contain valid requests (GET, POST with body, chunked, an
upgrade), the RFC 6455 §5.7 masked "Hello" frame, a close frame, and
truncated variants so the fuzzer starts from known-good and known-edge
inputs.

## How to run

```bash
cargo +nightly fuzz run request_head_parse -- -dict=fuzz/dictionaries/http.dict -max_total_time=300
cargo +nightly fuzz run frame_parse -- -dict=fuzz/dictionaries/websocket.dict -max_total_time=300
```

Omit `-max_total_time` for an indefinite local run. Crash inputs land in
`fuzz/artifacts/<target>/`.

## CI policy

- A 60-second smoke run per target on every push and PR
  (`.github/workflows/cqc.yml`, job `fuzz-smoke`), with
  `-rss_limit_mb=2560` as an allocation guard.
- Crash artifacts are archived as CI artifacts.
- A found crash becomes a regression test in the relevant crate's
  `tests/security_*.rs` with its control ID, before the fix lands.
