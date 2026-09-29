# Task runner for the http-rs workspace (G4: one-command reproducibility).
# Run `just --list` for an overview, `just --show <recipe>` for details.

# ── Settings ──────────────────────────────────────────────────────────────

# Tag for the containerized demo server
image_tag := "localhost/http-demo:latest"

# Compose file with the server/bench/attack profiles
compose := "container/compose.yaml"

# Pinned wrk image (matches container/compose.yaml)
wrk_image := "docker.io/williamyeh/wrk@sha256:78adc0d9d51a99e6759e702a08d03eaece81c890ffcc9790ef9e5b199d54f091"

# ── Workspace ─────────────────────────────────────────────────────────────

# List the available tasks
default:
    @just --list

# Run every workspace test (protocol, security, e2e, doctests)
test:
    cargo test --workspace

# Lint gate: rustfmt check + clippy with all and pedantic denied
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets

# Build the API docs (missing_docs denied) and open them
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --open

# Build the release server binary
build-release:
    cargo build --release -p server

# ── Server & containers ───────────────────────────────────────────────────

# Run the native demo server (binds 127.0.0.1:8000, SERVER_ADDR to override)
server:
    cargo run -p server

# Build the pinned multi-stage demo image (localhost/http-demo:latest)
image:
    podman build -f container/Containerfile -t {{image_tag}} .

# Force-remove stale demo containers and pods
clean:
    @# Prints the IDs of anything it had to force-remove; silent when clean.
    @podman compose -f {{compose}} down >/dev/null 2>&1 || true
    @podman ps -aq --filter "name=http-demo_" | xargs -r podman rm -f

# Start the containerized demo server on localhost:8080
up: (clean)
    @# Ctrl-C stops the stack; `just` then prints
    @# `error: recipe up failed ... exit code 1`, which is its way of
    @# reporting the interrupt — the containers are stopped.
    podman compose -f {{compose}} up server

# Stop and remove the demo stack
down:
    podman compose -f {{compose}} down

# ── Benchmarks ────────────────────────────────────────────────────────────

# Benchmark HTTP with wrk against ADDR
bench-http addr="127.0.0.1:8080" duration="10s":
    #!/usr/bin/env bash
    set -euo pipefail
    # ADDR may be given as host:port or a full URL; the containerized server
    # on localhost:8080 is auto-started when not running.
    addr="{{addr}}"
    addr="${addr#http://}"; addr="${addr#https://}"; addr="${addr%%/*}"
    if [ -z "$addr" ]; then
        echo "error: empty benchmark address" >&2
        exit 1
    fi
    container/scripts/ensure-server "$addr"
    podman run --rm --network host {{wrk_image}} -t4 -c100 -d{{duration}} --latency "http://$addr/"

# Benchmark WebSockets with ws_bench against ADDR
bench-ws addr="127.0.0.1:8080" connections="100" messages="1000":
    #!/usr/bin/env bash
    set -euo pipefail
    # Same address handling and server auto-start as bench-http.
    addr="{{addr}}"
    addr="${addr#http://}"; addr="${addr#https://}"; addr="${addr%%/*}"
    if [ -z "$addr" ]; then
        echo "error: empty benchmark address" >&2
        exit 1
    fi
    container/scripts/ensure-server "$addr"
    cargo run --release -p examples --bin ws_bench -- --addr "$addr" --connections {{connections}} --messages {{messages}}

# Run the full benchmark suite (starts and tears down the server)
bench: (image) (clean)
    #!/usr/bin/env bash
    set -euo pipefail
    echo "== starting containerized server =="
    podman compose -f {{compose}} up -d server
    trap 'podman compose -f {{compose}} down' EXIT
    for _ in $(seq 1 60); do
        curl -sf http://127.0.0.1:8080/ >/dev/null && break
        sleep 0.5
    done
    echo
    echo "== keep-alive ON (connection reuse) =="
    podman run --rm --network host {{wrk_image}} -t4 -c100 -d10s --latency http://127.0.0.1:8080/
    echo
    echo "== keep-alive OFF (Connection: close, one TCP setup per request) =="
    podman run --rm --network host {{wrk_image}} -t4 -c100 -d10s --latency -H 'Connection: close' http://127.0.0.1:8080/
    echo
    echo "== websocket echo (ws_bench) =="
    cargo run --release -p examples --bin ws_bench -- --addr 127.0.0.1:8080 --connections 100 --messages 500

# ── Security demos & fuzzing ──────────────────────────────────────────────

# Run one attack demo natively against ADDR
demo name addr="127.0.0.1:8000":
    @# name: slowloris, header_bomb, or unmasked_frames
    python3 container/demos/{{name}}.py --addr {{addr}}

# Run one attack demo in a container against the compose server
demo-container name:
    #!/usr/bin/env bash
    set -euo pipefail
    # name: slowloris, header_bomb, or unmasked_frames.
    # The server is started on localhost:8080 if not running; `just down`
    # afterwards stops it.
    container/scripts/ensure-server 127.0.0.1:8080
    podman compose -f {{compose}} --profile attack run --rm demo_{{name}}

# Fuzz both parsers with cargo-fuzz (needs nightly + cargo-fuzz)
fuzz duration="60":
    @# Targets: request_head_parse, frame_parse. See docs/security/fuzzing.md.
    cd fuzz && cargo +nightly fuzz run request_head_parse -- -max_total_time={{duration}}
    cd fuzz && cargo +nightly fuzz run frame_parse -- -max_total_time={{duration}}
