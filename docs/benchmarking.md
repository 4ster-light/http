# Benchmarking

> **Status: methodology only.** Results land with Phase 4 (G4 — reproducible
> demos), together with the container setup that makes them reproducible. This
> file is written now so the methodology is reviewable before numbers exist.

## Goals

1. Show the server holds up under realistic load (throughput, latency).
2. Quantify the cost of each security control added in Phase 3 (timeouts,
   limits, fragmentation reassembly) — hardening should be measurable, not
   aspirational.
3. Provide repro steps anyone can run.

## Methodology

- **Build:** `cargo build --release -p server` (release profile, default codegen
  options; no `lto`/`codegen-units` tuning unless documented here).
- **Environment disclosure:** CPU, RAM, OS/kernel, Rust version, and whether run
  natively or in the container, recorded alongside every result table.
- **Warm-up:** ≥ 2 s of load before measurement starts.
- **Repeatability:** every reported number is the median of ≥ 3 runs.

## Scenarios

| Scenario   | Tool                                  | Measures                                  |
| ---------- | ------------------------------------- | ----------------------------------------- |
| Static GET | `ritchie`-style raw client or `wrk`   | Requests/s, latency p50/p99 on `GET /`    |
| Keep-alive | `wrk -t4 -c100 -d10s`                 | Connection reuse efficiency               |
| WS echo    | Custom broadcast/echo microbench      | Frames/s, round-trip latency distribution |
| Churn      | Short-lived connections at fixed rate | Accept/spawn overhead per connection      |

## Repro (once Phase 4 lands)

```bash
cargo build --release -p server
./target/release/server &          # listens on 127.0.0.1:8000
wrk -t4 -c100 -d10s http://127.0.0.1:8000/
```

## Results

_To be filled in Phase 4 — one table per scenario, with environment disclosure
and the exact commands used._
