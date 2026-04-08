# CLAUDE.md — sigil

## What This Is

`sigil` is a Rust workspace for managing AI agent sessions with:

- typed authority (`ActionRequest`, `Action`, `ActionOrigin`)
- policy evaluation and trust-zone checks
- HMAC-chained audit logging
- tmux-backed session runtime
- supporting bridge and conductor crates

`docs/ARCHITECTURE.md` is the current architecture reference.
`docs/REWRITE-PROPOSAL.md` and `docs/SECURITY-PLAN.md` are planning documents and should be read as roadmap material, not as a perfect description of the current implementation.

## Current Workspace

```text
sigil/
  Cargo.toml
  rustfmt.toml
  clippy.toml
  deny.toml
  crates/
    sigil-core/        # Domain types, action protocol, principals, trust model, trait ports
    sigil-audit/       # Append-only JSONL audit writer + verifier
    sigil-policy/      # Tier/zone evaluation, normalization, fatigue guard, grant model
    sigil-store/       # SQLite store for sessions and approval grants
    sigil-runtime/     # tmux runtime, tool adapters, worktree manager
    sigil-conductor/   # Heartbeat, reconciliation, bridge message handling
    sigil-bridge/      # Slack/Telegram parsing, identity resolution, routing, live loops
    sigil-cli/         # `sigil` binary, clap commands, audit wiring
```

There are 8 workspace crates. There is no `sigil-container` crate in the tree.

## Dependency Graph

Compile-time workspace edges:

```text
sigil-cli → sigil-audit, sigil-conductor, sigil-core, sigil-runtime, sigil-store
sigil-conductor → sigil-audit, sigil-core, sigil-policy, sigil-runtime, sigil-store
sigil-bridge → sigil-audit, sigil-core, sigil-policy
sigil-runtime → sigil-core, sigil-policy
sigil-store → sigil-core, sigil-policy
sigil-policy → sigil-audit, sigil-core
sigil-audit → sigil-core
sigil-core → (no internal deps)
```

Notes:

- `sigil-cli` has test-only dependencies on `sigil-bridge` and `sigil-policy`.
- `sigil-bridge` and `sigil-conductor` still do not depend on each other directly.
- `sigil-store` depends on `sigil-policy` because it implements the approval-grant store trait.

## Current Implementation Notes

- Runtime backend is tmux-only today. There is no container runtime implementation in this workspace.
- The CLI currently exposes four top-level commands: `status`, `session`, `worktree`, and `conductor`.
- Audit logging is wired into `sigil-cli`; session commands and the conductor append events to `audit.jsonl`.
- Approval grants are persisted in SQLite and cleaned up during conductor heartbeats, but `sigil-policy::Evaluator` does not yet consult the grant store when making decisions.
- The bridge crates contain real Telegram/Slack parsing, allowlisting, rate limiting, and loop implementations, but they are not yet exposed through a top-level CLI/service command.

## Design Rules That Still Hold

1. `ActionRequest` / `Action` / `ActionOrigin` are the authority-bearing protocol for privileged orchestration actions.
2. No raw `Shell(String)` or equivalent authority type exists. Host execution is represented by `CommandTemplate` or `BreakGlass`.
3. Terminal parsing is observability-only. `ToolAdapter::parse_output()` produces `AgentSignal`, not `ActionRequest`.
4. Trust zones are `Ingress`, `ControlPlane`, `AgentRuntime`, and `HostPrivileged`.
5. Domain identifiers use newtypes (`SessionId`, `RequestId`, `GroupId`) rather than bare strings.
6. Library crates use `thiserror`; the application crate (`sigil-cli`) uses `anyhow`.

## Toolchain And Lints

- Edition: 2024
- Minimum Rust: 1.85.0
- Resolver: 3

Workspace lint highlights:

- `unsafe_code = "forbid"`
- `unused_must_use = "deny"`
- `unwrap_used = "deny"`
- `panic = "deny"`
- `todo = "deny"`
- `unimplemented = "deny"`
- `dbg_macro = "deny"`

## Testing

- Unit tests live primarily in `#[cfg(test)]` modules inside each crate.
- Integration tests currently live in [`crates/sigil-cli/tests`](/Users/zebas/Developer/sigil/crates/sigil-cli/tests).
- The workspace currently registers 368 tests total: 268 unit tests and 100 integration tests.

Run these before shipping changes:

```bash
cargo fmt
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```
