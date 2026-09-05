//! WebSocket benchmark (`ws_bench`).
//!
//! Measures, against a running demo server:
//!
//! - `echo` mode: concurrent WebSocket clients send masked text frames and
//!   wait for the server's echo; reports round-trip throughput and the
//!   latency distribution (p50/p90/p99/max/mean). This exercises the full
//!   frame codec path on both sides.
//! - `handshake` mode: rate of complete opening handshakes (connect →
//!   `101` + accept-key verification → clean close), i.e. connection
//!   setup cost including the RFC 6455 §4.2.2 digest check.
//!
//! Usage:
//! `cargo run --release -p examples --bin ws_bench -- \
//!     [--addr 127.0.0.1:8000] [--mode echo|handshake] \
//!     [--connections 100] [--messages 1000] [--size 64]`
//!
//! This binary is also used by the `bench-ws` compose service (G4), which
//! runs it against the containerized server.

use std::{
    process::ExitCode,
    time::{Duration, Instant},
};

use examples::{ClientError, connect_and_upgrade, read_until, send_close, send_text};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use websocket::frame::OpCode;

/// Per-operation ceiling: a stuck round trip or handshake fails instead of
/// hanging the benchmark.
const OP_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed command-line arguments.
struct Args {
    addr: String,
    mode: Mode,
    connections: usize,
    messages: usize,
    size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Echo,
    Handshake,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: "127.0.0.1:8000".to_string(),
        mode: Mode::Echo,
        connections: 100,
        messages: 1000,
        size: 64,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--addr" => args.addr = value(&flag)?,
            "--mode" => {
                args.mode = match value(&flag)?.as_str() {
                    "echo" => Mode::Echo,
                    "handshake" => Mode::Handshake,
                    other => return Err(format!("unknown mode `{other}` (echo|handshake)")),
                }
            }
            "--connections" => {
                args.connections = value(&flag)?.parse().map_err(|_| "bad --connections")?;
            }
            "--messages" => args.messages = value(&flag)?.parse().map_err(|_| "bad --messages")?,
            "--size" => args.size = value(&flag)?.parse().map_err(|_| "bad --size")?,
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", USAGE.trim());
            return ExitCode::FAILURE;
        }
    };
    if args.mode == Mode::Echo {
        println!(
            "ws_bench: mode=echo addr={} connections={} messages={} size={}",
            args.addr, args.connections, args.messages, args.size,
        );
    } else {
        println!(
            "ws_bench: mode=handshake addr={} connections={} handshakes={}",
            args.addr, args.connections, args.messages,
        );
    }

    let started = Instant::now();
    let mut handles = Vec::with_capacity(args.connections);
    for id in 0..args.connections {
        let addr = args.addr.clone();
        handles.push(tokio::spawn(worker(
            id,
            addr,
            args.mode,
            args.messages,
            args.size,
        )));
    }

    let mut latencies: Vec<Duration> = Vec::new();
    let mut failed_workers = 0_usize;
    for handle in handles {
        match handle.await {
            Ok(Ok(times)) => latencies.extend(times),
            Ok(Err(e)) => {
                failed_workers += 1;
                eprintln!("worker error: {e}");
            }
            Err(join_error) => {
                failed_workers += 1;
                eprintln!("worker panicked: {join_error}");
            }
        }
    }
    let wall = started.elapsed();

    if latencies.is_empty() {
        eprintln!("benchmark failed: no successful operations");
        return ExitCode::FAILURE;
    }

    report(&args, &latencies, wall, failed_workers);
    if failed_workers > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

const USAGE: &str = "usage: ws_bench [--addr HOST:PORT] [--mode echo|handshake] \
[--connections N] [--messages M] [--size BYTES]";

/// One client's workload; returns its per-operation latencies.
async fn worker(
    _id: usize,
    addr: String,
    mode: Mode,
    messages: usize,
    size: usize,
) -> Result<Vec<Duration>, ClientError> {
    match mode {
        Mode::Echo => echo_worker(&addr, messages, size).await,
        Mode::Handshake => handshake_worker(&addr, messages).await,
    }
}

/// Sends `messages` text frames of `size` bytes and times each round trip.
async fn echo_worker(
    addr: &str,
    messages: usize,
    size: usize,
) -> Result<Vec<Duration>, ClientError> {
    let mut socket = connect_and_upgrade(addr, "/").await?;
    let mut buffer = Vec::new();
    let payload = "x".repeat(size);
    let mut latencies = Vec::with_capacity(messages);

    for _ in 0..messages {
        let started = Instant::now();
        timeout(OP_TIMEOUT, async {
            send_text(&mut socket, &payload).await?;
            read_until(&mut socket, &mut buffer, OpCode::Text).await?;
            Ok::<(), ClientError>(())
        })
        .await
        .map_err(|_| ClientError::Protocol("echo round trip timed out"))??;
        latencies.push(started.elapsed());
    }

    close(&mut socket).await;
    Ok(latencies)
}

/// Performs `messages` full handshake → close cycles, timing each.
async fn handshake_worker(addr: &str, iterations: usize) -> Result<Vec<Duration>, ClientError> {
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        timeout(OP_TIMEOUT, async {
            let mut socket = connect_and_upgrade(addr, "/").await?;
            close(&mut socket).await;
            Ok::<(), ClientError>(())
        })
        .await
        .map_err(|_| ClientError::Protocol("handshake timed out"))??;
        latencies.push(started.elapsed());
    }
    Ok(latencies)
}

/// Clean close handshake; a missing reply is fine (server may just close).
async fn close(socket: &mut TcpStream) {
    let mut buffer = Vec::new();
    if send_close(socket, 1000, "bench").await.is_ok() {
        let _ = read_until(socket, &mut buffer, OpCode::Close).await;
    }
    let _ = socket.shutdown().await;
}

/// Prints the result table: throughput and latency percentiles.
fn report(args: &Args, latencies: &[Duration], wall: Duration, failed_workers: usize) {
    let mut sorted = latencies.to_vec();
    sorted.sort();
    let ops = sorted.len();
    let op_unit = if args.mode == Mode::Echo {
        "messages"
    } else {
        "handshakes"
    };
    let per_sec = f64::from(u32::try_from(ops).unwrap_or(u32::MAX)) / wall.as_secs_f64();

    println!();
    println!("results");
    println!(
        "  workers failed       {failed_workers}/{}",
        args.connections
    );
    println!("  total {op_unit:<10} {ops}");
    println!("  wall time            {wall:.2?}");
    println!("  throughput           {per_sec:.0} {op_unit}/s");
    println!("  latency p50          {:?}", percentile(&sorted, 0.50));
    println!("  latency p90          {:?}", percentile(&sorted, 0.90));
    println!("  latency p99          {:?}", percentile(&sorted, 0.99));
    println!("  latency max          {:?}", sorted[ops - 1]);
    let mean: Duration =
        sorted.iter().sum::<Duration>() / u32::try_from(ops.max(1)).unwrap_or(u32::MAX);
    println!("  latency mean         {mean:?}");
}

/// Nearest-rank percentile over a sorted slice.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    // The casts are safe here: the index is rounded, clamped to the valid
    // range, and precision loss beyond 2^52 samples is meaningless.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let idx = {
        let last = sorted.len() - 1;
        (p * last as f64).round().clamp(0.0, last as f64) as usize
    };
    sorted[idx]
}
