# HTTP benchmarking notes

HTTP load generation is done with [wrk](https://github.com/wg/wrk) running in
a container, so no local tooling is required (G4: reproducible benchmarks).

## Why wrk in a container?

- One command, no install: `just bench-http http://127.0.0.1:8000/` pulls the
  pinned wrk image and runs it with host networking.
- Same binary, same flags, same pinned digest on every machine that runs the
  demo — results are comparable across environments (modulo hardware, which
  `docs/benchmarking.md` discloses).

## Scenarios

| Scenario        | Command                                                                | What it shows                                              |
| --------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------- |
| Keep-alive ON   | `wrk -t4 -c100 -d10s --latency http://HOST:PORT/`                      | Connection reuse (default): the SEC-HTTP-005/F1/F3 payoff.  |
| Keep-alive OFF  | `wrk -t4 -c100 -d10s --latency -H "Connection: close" URL`             | Cost of a full TCP setup per request; the headline delta.   |
| Latency profile | same with `-c10`                                                       | p50/p99 under light concurrency.                            |

The keep-alive ON/OFF delta is the headline number: it validates that the
connection layer actually reuses connections (F1's buffer ownership + F3's
enforced keep-alive), instead of just claiming to.

## WebSocket benchmarking

Use the companion Rust client:

```bash
cargo run --release -p examples --bin ws_bench -- \
    --addr 127.0.0.1:8000 --mode echo --connections 100 --messages 1000
```

See `docs/benchmarking.md` for the full methodology and recorded results.
