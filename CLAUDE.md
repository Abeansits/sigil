# CLAUDE.md - sigil

## What This Is

`sigil` is a security-first Rust workspace for managing AI agent sessions - typed authority protocol, policy evaluation, HMAC-chained audit logging, tmux and container runtimes, bridge integrations (Slack/Telegram), and a conductor for orchestration.

## Design Rules

1. `ActionRequest` / `Action` / `ActionOrigin` are the authority-bearing protocol. All privileged orchestration actions flow through this.
2. No raw `Shell(String)` authority type. Host execution uses `CommandTemplate` or `BreakGlass`.
3. Terminal parsing is observability-only. `ToolAdapter::parse_output()` produces `AgentSignal`, not `ActionRequest`.
4. Trust zones: `Ingress`, `ControlPlane`, `AgentRuntime`, `HostPrivileged`.
5. Domain identifiers use newtypes (`SessionId`, `RequestId`, `GroupId`), not bare strings.
6. Library crates use `thiserror`; the application crate (`sigil-cli`) uses `anyhow`.
7. The `container` feature gate controls Apple Container support - `ContainerRuntime`, `DomainProxy`, MCP socket server, and related deps.
8. The CLI `--runtime` flag (`tmux` | `container`, env `SIGIL_RUNTIME`) dispatches via `RuntimeBackend` enum.

## Style Guide

Read `docs/RUST-STYLE-GUIDE.md` before writing code. It covers formatting, lints, error handling, async patterns, testing, security, and CI.

## Testing

```bash
cargo +nightly fmt --all
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

UC9 and UC10 are `#[ignore]` - run with `cargo test -- --ignored`.

## Docs

- `docs/ARCHITECTURE.md` - workspace structure, runtime flow, container runtime
- `docs/RUST-STYLE-GUIDE.md` - Rust best practices for this workspace
- `docs/SECURITY-PLAN.md` - security controls and hardening roadmap
- `docs/USE-CASES.md` - CLI and library walkthroughs
- `docs/archived/` - pre-v0.2.0 proposals and reviews (historical context, not current state)
