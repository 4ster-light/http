# Dev container image for the http-rs workspace. Local-only (uncommitted).
#
# Mirrors the documented toolchain (docs/development.md):
#   - stable Rust 1.95, edition 2024 (default profile ships rustfmt, clippy
#     and rust-docs)
#   - the pinned nightly + cargo-fuzz for fuzz/ (fuzz/rust-toolchain.toml)
#   - just, the task runner wrapping every flow (ADR-0009)
#   - python3 + curl for the stdlib attack demos and the bench helper script
# plus a nested Podman *inside* the dev container, so the containerized
# recipes (just image / up / bench / demo-container) work self-contained,
# exactly as they do on the host. See .devcontainer/README.md for the design.
#
# The expensive Rust layer comes first so container-stack tweaks below never
# invalidate it in the build cache.

FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

USER root

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH}

# 1.95 is the documented stable (docs/development.md). The nightly matches
# the fuzz pin in fuzz/rust-toolchain.toml. The default
# rustup profile ships rustfmt, clippy and rust-docs. The shared
# /usr/local/{rustup,cargo} keeps one toolchain setup; the chown makes them
# writable for the vscode user.
RUN curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init \
    && sh /tmp/rustup-init -y --no-modify-path --profile default --default-toolchain 1.95 \
    && rm /tmp/rustup-init \
    && rustup toolchain install nightly-2026-11-21 \
    && cargo +nightly-2026-11-21 install --locked cargo-fuzz \
    && cargo install --locked just \
    && chown -R vscode:vscode /usr/local/rustup /usr/local/cargo

# Nested container engine (runs rootful inside the dev container's own user
# namespace; see README "Why nested Podman"):
#   podman                   : the runtime the repo itself targets
#   podman-compose (pip)     : the compose provider; noble's apt 1.0.6 build
#                             rejects the `--profile <name>` syntax the
#                             justfile's demo/bench recipes use, so a modern
#                             PyPI release is installed separately below
#   netavark, aardvark-dns   : the netavark/aardvark stack with compose service
#                             DNS. Noble's netavark deb installs the binaries
#                             into /usr/lib/podman while its podman looks in
#                             /usr/libexec/podman, so both are symlinked into
#                             place below.
#   nftables, iptables        : firewall rules for published ports (netavark
#                             1.4 selects the iptables driver, so both are
#                             installed; nft stays as the alternative backend)
#   catatonit                : the pod pause binary (pods; podman-compose)
#   uidmap, slirp4netns,
#   fuse-overlayfs          : rootless plumbing, kept for hosts that run the
#                             dev container rootful (rootless nesting there)
#   python3                : `just demo` scripts (stdlib only)
# Subuid/subgid ranges for the vscode user likewise only matter for that
# rootless path; the default nested mode is rootful.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        podman \
        netavark \
        aardvark-dns \
        nftables \
        iptables \
        catatonit \
        uidmap \
        slirp4netns \
        fuse-overlayfs \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/podman/netavark /usr/libexec/podman/netavark \
    && ln -s /usr/lib/podman/aardvark-dns /usr/libexec/podman/aardvark-dns \
    && usermod --add-subuids 100000-165535 --add-subgids 100000-165535 vscode

# Compose provider from PyPI: noble's apt 1.0.6 cannot parse the justfile's
# `--profile <name>` argument shape (see the toolchain comment above).
RUN python3 -m pip install --break-system-packages --no-cache-dir \
        podman-compose==1.2.0 \
    && podman-compose --version

# Podman-in-container defaults, layered over the distro defaults in
# /usr/share/containers/: cgroups are not delegated into this container
# (disable them per container), journald does not run here (write engine
# events to a file instead), and the network backend is pinned to
# netavark/aardvark so compose service DNS works.
RUN printf '%s\n' \
        '[containers]' \
        'cgroups = "disabled"' \
        'events_logger = "file"' \
        '[network]' \
        'network_backend = "netavark"' \
        > /etc/containers/containers.conf

USER vscode
