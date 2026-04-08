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
    sigil-mcp/         # Host-side MCP server for policy-mediated agent actions
    sigil-cli/         # `sigil` binary, clap commands, audit wiring
```

There are 9 workspace crates.

## Dependency Graph

Compile-time workspace edges:

```text
sigil-cli → sigil-audit, sigil-bridge, sigil-conductor, sigil-core, sigil-runtime, sigil-store
sigil-conductor → sigil-audit, sigil-core, sigil-policy, sigil-runtime, sigil-store
sigil-bridge → sigil-audit, sigil-core, sigil-policy
sigil-mcp → sigil-core, sigil-policy
sigil-runtime → sigil-core, sigil-mcp [container], sigil-policy
sigil-store → sigil-core, sigil-policy
sigil-policy → sigil-audit, sigil-core
sigil-audit → sigil-core
sigil-core → (no internal deps)
```

Notes:

- `sigil-cli` depends on `sigil-bridge` directly (bridge CLI commands are wired in).
- `sigil-cli` has test-only dependencies on `sigil-policy`.
- `sigil-bridge` and `sigil-conductor` still do not depend on each other directly.
- `sigil-store` depends on `sigil-policy` because it implements the approval-grant store trait.
- `sigil-runtime` depends on `sigil-mcp` behind the `container` feature gate (MCP socket server for containers).

## Current Implementation Notes

- Runtime backend is tmux-only today. Container runtime research exists in `docs/CONTAINER-POC.md` but no container backend is implemented.
- The CLI exposes six top-level commands: `status`, `session`, `worktree`, `conductor`, `bridge`, and `audit`.
- `sigil bridge` subcommands: `telegram`, `slack`, `all`.
- `sigil audit verify` validates HMAC chain integrity from the CLI.
- Audit logging is wired into `sigil-cli`; session commands and the conductor append events to `audit.jsonl`.
- `sigil-policy::Evaluator` consults the `GrantStore` when making decisions; stored approval grants affect policy outcomes.
- `FatigueGuard` is wired into the approval flow.
- The conductor is generic over `SessionRuntime` (not hardcoded to `TmuxRuntime`).
- `strip_ansi` panics on malformed input rather than silently falling back.
- Grant prefix matching includes path boundary checks.
- `sigil-mcp` provides a host-side MCP server for policy-mediated agent actions (JSON-RPC over stdin/stdout).

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
- The workspace currently registers 411 tests.

Run these before shipping changes:

```bash
cargo fmt
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```
