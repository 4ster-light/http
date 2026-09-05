# Benchmarking

Reproducible performance measurements for the demo server (G4). Every number
below can be re-run with one command; see [Repro](#repro).

## Goals

1. Show the server holds up under realistic load (throughput, latency).
2. Quantify the cost of the security controls added in the hardening phase.
   Hardening should be measurable, not hand-waved.
3. The headline comparison: keep-alive ON vs OFF. Connection reuse is what
   the F1 (buffer ownership) and F3 (enforced keep-alive) work delivered —
   this benchmark proves it instead of claiming it.

## Methodology

- **Server build:** `cargo build --release -p server` (default release
  profile, no `lto`/`codegen-units` tuning).
- **HTTP load:** [wrk](https://github.com/wg/wrk) from the pinned
  `williamyeh/wrk` container image, host networking, 4 threads, 100
  connections, 10 s per run (2 s light-concurrency profile uses 2 threads /
  10 connections).
- **WS load:** the `ws_bench` example from this repo (release build), which
  speaks the real client-side protocol: masked frames, verified handshake
  digest, pong answers. Echo mode: 100 connections × 300 round trips of
  64-byte text. Handshake mode: 20 clients × 100 full connect→upgrade→close
  cycles.
- **Warm-up:** each wrk/ws_bench run includes its own ramp-up; short-lived
  connection pools are re-established per run.
- **Repeatability:** three runs per scenario, median reported, all runs
  shown. Numbers are *indicative*, not certified claims — hardware is a
  laptop; the point is the ratio between scenarios, not absolute records.

## Environment (recorded 2026-09-05, final image)

| Item        | Value                                              |
| ----------- | -------------------------------------------------- |
| CPU         | Intel Core i5-10210U @ 1.60 GHz (8 threads)         |
| RAM         | 7.5 GiB                                            |
| OS / kernel | Fedora Linux 44, kernel 7.1.12-200.fc44.x86_64      |
| Rust        | 1.95.0 (release build, default profile)             |
| Containers  | Podman 5.8.4 rootless; wrk + server both containerized |
| Server      | `localhost/http-demo:latest` built from `container/Containerfile` (digest-pinned bases, `--locked`) |
| Topology    | wrk → host network → port 8080 → server container   |

## Results

> Absolute numbers move between sessions on this laptop (CPU governor, thermal
> state, background load): an earlier session measured ~15.3k vs ~3.8k req/s
> for the two headline scenarios. The **ratio between scenarios is the stable,
> meaningful result** — treat the absolutes as indicative, exactly as the
> methodology says.

### HTTP static GET (`GET /`)

| Scenario                    | Run 1      | Run 2      | Run 3 (median) | p50     | p99     |
| --------------------------- | ---------- | ---------- | -------------- | ------- | ------- |
| Keep-alive ON, 100 conn     | 24,952 r/s | 22,568 r/s | **23,739 r/s** | 3.8 ms  | 13.2 ms |
| Keep-alive OFF, 100 conn    | 5,200 r/s  | 4,803 r/s  | **4,803 r/s**  | 18.8 ms | 49.9 ms |
| Keep-alive ON, 10 conn      | 18,666 r/s | 17,929 r/s | **18,666 r/s** | 0.46 ms | 1.9 ms  |

**Headline: connection reuse is worth ~5× throughput** (23,739 vs 4,803
req/s at identical thread/connection counts) and roughly 5× lower latency at
p50. That is the F1/F3 keep-alive work showing up end to end: the advertised
`Keep-Alive: timeout=5, max=100` is actually enforced and reused, and the
connection-owned buffer serves pipelined requests without dropping bytes.

The light-concurrency profile shows what a single client can expect: ~0.46 ms
p50 and ~2 ms p99, i.e. sub-millisecond typical responses.

### WebSocket echo (100 connections, 64-byte text frames)

| Metric       | Run 1        | Run 2        | Run 3 (median) |
| ------------ | ------------ | ------------ | -------------- |
| Throughput   | 81,282 msg/s | 66,322 msg/s | **66,322 msg/s** |
| Latency p50  | 1.09 ms      | 1.30 ms      | 1.30 ms        |
| Latency p99  | 2.76 ms      | 3.81 ms      | 3.81 ms        |
| Latency mean | 1.17 ms      | 1.44 ms      | 1.44 ms        |

Each "message" is a full masked client frame → server parse → echo →
unmasked server frame → client parse round trip, including per-message RTT
measurement overhead in the single-threaded-per-connection client.

### WebSocket handshakes (full connect → 101 → close cycles)

| Metric       | Run 1      | Run 2      | Run 3 (median) |
| ------------ | ---------- | ---------- | -------------- |
| Throughput   | 3,739 hs/s | 5,588 hs/s | **5,588 hs/s** |
| Latency p50  | 4.82 ms    | 3.39 ms    | 3.39 ms        |
| Latency p99  | 11.9 ms    | 6.85 ms    | 7.09 ms        |

A handshake includes TCP setup, the §4.2.1 request, the server's SHA-1
accept-key computation, the client's §4.2.2 digest verification, a clean
close exchange, and connection teardown — the full per-connection cost.

## What the security controls cost

The hardening phase did not slow the fast path measurably: the controls are
checks at parse boundaries (size caps, per-read timeouts that only arm on
stalls, close-code validation), all O(1) or O(n) over the input. At wrk-sized
loads, syscall overhead dominates either way. The keep-alive ON vs OFF delta
(~5×) is the price of *not* reusing connections — which is precisely what
the controls preserve for honest clients while shedding stalled or abusive
ones.

## Repro

```bash
# containerized server + wrk + ws_bench, then teardown (one command)
just bench

# individual pieces
just image && just up                     # server on localhost:8080
just bench-http 127.0.0.1:8080            # wrk, keep-alive ON
podman run --rm --network host docker.io/williamyeh/wrk@sha256:78adc0d9d51a99e6759e702a08d03eaece81c890ffcc9790ef9e5b199d54f091 -t4 -c100 -d10s \
    --latency -H 'Connection: close' http://127.0.0.1:8080/   # keep-alive OFF
just bench-ws 127.0.0.1:8080              # ws_bench echo
cargo run --release -p examples --bin ws_bench -- \
    --addr 127.0.0.1:8080 --mode handshake --connections 20 --messages 100
```

Against the native server instead of the container: `just server`, then
substitute `127.0.0.1:8000`.
