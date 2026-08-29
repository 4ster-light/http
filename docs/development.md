# Development

## Toolchain

- Stable Rust (developed on 1.95), edition 2024.
- No build scripts, no code generation, no nightly features.
- Fuzzing (when it lands) will use `cargo-fuzz` on a pinned nightly. See
  [security/fuzzing.md](security/fuzzing.md).

## Everyday commands

```bash
cargo build --workspace                  # build everything
cargo run -p server                      # run the demo server on 127.0.0.1:8000
cargo test --workspace                   # unit + integration + doc tests
cargo test -p http                       # one crate only
cargo clippy --workspace --all-targets   # lint (warnings are denied, see below)
cargo fmt --all                          # format (CI checks with --check)
cargo doc --workspace --open             # API docs
```

`RUST_LOG=server=debug cargo run -p server` enables verbose logging.

## Lint policy

Enforced workspace-wide via `[workspace.lints]` in the root `Cargo.toml` and
checked by CI:

| Lint               | Level    | Why                                                                    |
| ------------------ | -------- | ---------------------------------------------------------------------- |
| `unsafe_code`      | `forbid` | Memory safety is a stated project goal; no exceptions.                 |
| `missing_docs`     | `deny`   | Public API docs are part of the deliverable (this docs system).        |
| `clippy::all`      | `deny`   | Baseline correctness/style.                                            |
| `clippy::pedantic` | `deny`   | Ratcheted on during the docs phase; keeps the codebase teaching-grade. |

CI additionally compiles with `RUSTFLAGS="-D warnings"` and builds docs with
`RUSTDOCFLAGS="-D warnings"`.

### Exceptions

`#[allow]` is acceptable only with a justification comment explaining why the
instance is intentional, never to silence a category. Current example:
`OpCode::from` maps reserved opcodes to `Close` and carries
`#[allow(clippy::match_same_arms)]` with a comment, because the wildcard arm
duplicating the `0x8` arm is deliberate.

## Documentation conventions

- **rustdoc:** every public item is documented, with RFC section references
  where applicable, `# Errors` sections on `Result`-returning functions, and
  doc examples compiled and run as tests.
- **Markdown docs** (this tree): plain markdown, no build step. Relative links,
  always with the `.md` suffix so they work on GitHub.
- **Compliance matrices** are tables, not prose; `❌` rows are the roadmap.

## Architecture Decision Records

Live in [adr/](adr/). Format: [adr/0000-template.md](adr/0000-template.md)
(Nygard). Rules:

- One decision per ADR, at most a page.
- Immutable once **Accepted**. Changes happen through a new ADR that supersedes
  the old one (the old one's status becomes `Superseded by ADR-NNNN`).
- Decisions that are made but not yet implemented get
  `Accepted (implementation scheduled …)`.

## Git conventions

- Conventional-commit style subjects (`refactor:`, `docs:`, `feat:`, etc.).
- Each refactor phase is one commit/PR; all gates green before commit.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push to `main` and
every PR: `fmt --check`, `clippy --workspace --all-targets`, `test --workspace`,
`doc --workspace`, plus a boot-and-curl smoke test of the server binary. A full
containerized end-to-end harness arrives with the demo/benchmark phase.
