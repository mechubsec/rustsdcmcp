# Contributing to rustsdcmcp

Thanks for considering a contribution. `rustsdcmcp` is an async Rust Model
Context Protocol server for HPE Juniper Security Director Cloud (SDC) — part
of the [mechub](https://github.com/mechubsec) family of open-source,
self-hosted network-security automation tooling. See [README.md](README.md)
for what the server does and its current status.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach
  before writing code.
- This project follows one hard rule across the whole mechub fleet:
  **deterministic code decides, a model may explain, a human approves.**
  Nothing you contribute should let an LLM or other model output directly
  drive an SDC action (a policy deploy, a device sync, any write against the
  management plane). Models may draft, summarize, or explain; deterministic
  code — the prepare → approve → apply change-control path — decides.

## Workspace layout

This is a Cargo workspace (`Cargo.toml`) with two members:

- `crates/rustsdcmcp-core` — the SDC client and change-control core
- `crates/rustsdcmcp` — the MCP server binary (tool surface, transport, CLI)

MSRV is `1.89` (`workspace.package.rust-version`); the pinned build toolchain
is `1.99.0` (`rust-toolchain.toml`).

## Build and test

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

Lint and format, both required to pass in CI (`.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Docs must build without warnings:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

MSRV is checked separately in CI's `msrv` job:

```sh
cargo +1.89 check --workspace --all-targets --locked
```

Workspace lints (`Cargo.toml`) deny `unsafe_code`, `todo!()`, and `dbg!()`,
and warn on `missing_docs` and `.unwrap()` — expect clippy to flag any of
those in review.

### If you touch the vendored SDC OpenAPI spec or `scripts/spec-drift.py`

CI's `rust` job runs these before build/test, so run them locally too:

```sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/spec-drift.py self-check
```

### Docker and packaging

CI also builds the container image and the Debian package
(`docker-build` and `packaging` jobs in `.github/workflows/ci.yml`). You don't
need to run these locally for a normal code change; see those job
definitions if you're touching `Dockerfile`, `scripts/build-package.sh`, or
anything under `packaging/`.

### Dependency and license checks

Required to pass in CI (`.github/workflows/security.yml`):

```sh
cargo audit --deny warnings
cargo deny check licenses bans sources
```

CI also runs Gitleaks against full git history and a Trivy filesystem scan
(secrets, vulnerabilities, misconfiguration). You don't need to run these
locally, but see "Fixtures and test data" below — the easiest way to keep
Trivy and Gitleaks quiet is to never give them anything real to find.

## Commit and PR conventions

- Match the existing commit style: `type: summary (#issue)` (`fix:`, `docs:`,
  `chore:`, etc.) — see `git log` for examples.
- Keep PRs focused on one change.
- Fill out the PR template, including the exact commands you ran to verify
  the change.
- This project does not require a `Signed-off-by` / DCO trailer. By opening a
  pull request, you're agreeing your contribution is licensed under this
  repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an
independent test run, before anything merges. Only a maintainer merges —
contributors, including anyone with write access, should not merge their own
PR. CI (build, test, clippy, fmt, `cargo audit`, `cargo deny`, Gitleaks,
Trivy) must be green first. All contributions land as a pull request against
`main`; there is no direct-push path for change.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real SDC tenant IDs, API tokens, hostnames, device serials, or
real device/policy configuration — synthetic or sanitized fixtures only
(see the examples under `examples/`). If you find real data already
committed anywhere in this repo, don't add to it — report it privately
instead (see [SECURITY.md](SECURITY.md)).
