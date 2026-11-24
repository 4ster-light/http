# Dev container

A spec-standard dev container that mirrors the project toolchain and wraps
the whole `justfile` surface, including the Podman recipes, in one container.
The workflow documentation lives in
[docs/development.md](../docs/development.md).

## What's inside

| Tool | Version | Why |
|---|---|---|
| Rust | stable 1.95, default profile (fmt, clippy, docs) | docs/development.md toolchain |
| nightly + cargo-fuzz | nightly-2026-11-21, pinned via fuzz/rust-toolchain.toml | fuzz/ harnesses, mirrors the CI fuzz-smoke job |
| just | latest, `--locked` | every flow is a recipe (ADR-0009) |
| Podman | 4.9.3 with netavark/aardvark + iptables | the nested engine below |
| podman-compose | 1.2.0 from PyPI | noble's apt 1.0.6 cannot parse `--profile <name>` |
| python3, curl | distro | attack demos, ensure-server |

Python editing support is `astral-sh.ruff` from Open VSX: the `ms-python`
extension family leans on proprietary Pylance, which VSCodium cannot ship.
The attack scripts themselves are stdlib-only and run on the image's
python3.

## Opening it

- VSCodium: "reopen in container" via your devcontainer extension. The first
  build pulls the ~400 MB base image and compiles `just` + `cargo-fuzz`, so
  give it a few minutes.
- CLI alternative: point `DOCKER_HOST` at the podman socket and use the
  spec CLI.

  ```bash
  systemctl --user enable --now podman.socket
  export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
  devcontainer up --workspace-folder "$(pwd)"
  ```

## Why nested rootful Podman (`runArgs`)

`--privileged` with `remoteUser root` gives the dev container its own
working Podman *inside* its user namespace, so every recipe is
self-contained:

- `just image / up / down / bench* / demo-container` run containers inside
  the dev container; compose publishes 8080 into its own network namespace,
  so the health-check curls in `ensure-server` and `just bench` pass
  unchanged;
- under rootless podman on the host, container root *is* your host user:
  cargo and rust-analyzer write the mounted repo as you, and `target/` stays
  host-owned (a touch inside lands as uid 1000);
- ports 8000/8080 are forwarded to the host for manual poking;
- on a rootful docker host the same setup works, but repo writes land as
  host root, the trade of `remoteUser: root` without userns remapping.

Why not `--userns=keep-id` with a rootless inner podman: the setuid
`newuidmap` cannot elevate inside a non-init user namespace, so a nested
rootless podman cannot map its subuids and dies with `newuidmap: write to
uid_map failed: Operation not permitted`. Rootful-in-the-userns needs none
of that machinery and is the supported nesting mode.

### The Fedora/SELinux note

With SELinux enforcing (this host), MCS separation denies the container even
reads of the bind-mounted repo. `--security-opt label=disable` in `runArgs`
neutralizes it. On non-SELinux hosts the flag
is a harmless no-op, and docker accepts it too.

### Noble packaging traps (each verified, each fixed)

- netavark/aardvark debs install into `/usr/lib/podman` while noble's podman
  looks in `/usr/libexec/podman`, so both binaries are symlinked into place;
- netavark 1.4 selects the **iptables** firewall driver, so `iptables` is
  installed (`nftables` alone is not enough);
- apt's podman-compose 1.0.6 rejects the `--profile <name>` syntax the
  justfile uses, so podman-compose 1.2.0 comes from PyPI instead;
- cgroups are not delegated into containers and journald does not run here:
  `/etc/containers/containers.conf` pins `cgroups = "disabled"` and
  `events_logger = "file"`.

## Named volumes

| Volume | Mount | Purpose |
|---|---|---|
| `http-rs-podman-storage` | /var/lib/containers | nested images persist across image rebuilds (the pinned demo image builds once, not once per session) |
| `http-rs-cargo-registry` | /usr/local/cargo/registry | the cargo dependency cache persists across image rebuilds |

## Alternative: host Podman socket

If you ever prefer the containers on the host engine: enable `podman.socket`
on the host, add to devcontainer.json

```json
"mounts": ["source=${localEnv:XDG_RUNTIME_DIR}/podman/podman.sock,target=/run/podman/podman.sock,type=bind"],
"containerEnv": { "CONTAINER_HOST": "unix:///run/podman/podman.sock" }
```

and drop `--privileged`. Caveat: compose then publishes 8080 on the *host*,
which the in-container health checks in `just bench` cannot see, so the bench
flows only work fully with nested mode.

## Verified locally

Image build and toolchain; the fuzz pin is honored: inside `fuzz/`,
`rustup show active-toolchain` reports nightly-2026-11-21, overridden by
`rust-toolchain.toml` (note that `cargo --version` there prints cargo's own
build date, which can be older than the channel). The full dev loop on a
clean checkout (`just test`, the 90-test suite / `just lint` / `just fuzz
10` on the pinned nightly, both cargo-fuzz targets); nested `just image` of
the pinned Containerfile; `just demo header_bomb` natively against the
running server (python3 stdlib, VERDICT: PASS); `just demo-container
header_bomb` through the compose attack profile with service DNS (VERDICT:
PASS); the CI-style probes (200 / 404 / POST echo / WS 101); a 2 s `just
bench-http` (134k req/s); `just down`. Not yet exercised through the
VSCodium extension itself.
