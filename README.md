# sigil

A security-first Rust workspace for managing AI agent sessions. It replaces the older Go + Python split with one typed, testable workspace built around policy checks, audit logging, and tmux-backed orchestration.

## Workspace

```text
sigil-cli         `sigil` binary, clap commands, audit wiring
sigil-conductor   Heartbeat loop, reconciliation, bridge message handling
sigil-bridge      Telegram/Slack parsing, identity resolution, routing, live bridge loops
sigil-runtime     tmux runtime, tool adapters, git worktree manager
sigil-store       SQLite persistence for sessions and approval grants
sigil-policy      Trust-zone checks, tier evaluation, normalization, fatigue guard, grant model
sigil-audit       HMAC-chained JSONL audit writer and verifier
sigil-core        Action protocol, origins, principals, trust model, trait ports
```

The workspace is an 8-crate DAG with `sigil-core` at the bottom and no internal dependency cycles.

## Design

- `ActionRequest` is the typed authority protocol for orchestrated actions.
- Terminal parsing is observability-only; `ToolAdapter` emits `AgentSignal`, not authority.
- Trust zones are `Ingress`, `ControlPlane`, `AgentRuntime`, and `HostPrivileged`.
- Audit events are written as append-only HMAC-chained JSONL entries.
- Approval grants have a real domain model and SQLite storage, though evaluator-side grant lookups are still pending.

## Build And Verify

```bash
cargo build --release     # current macOS arm64 build: 5.7M
cargo test               # 318 tests (268 unit + 50 integration)
cargo clippy --workspace --all-targets -- -D warnings
```

Rust 1.85+ is required. The release profile uses thin LTO and `codegen-units = 1`.

## Status

The current workspace has working session lifecycle commands, status reporting, worktree management, tmux reconciliation, audit logging, policy evaluation, grant persistence, and bridge libraries for Slack and Telegram.

The main gaps between the current code and the longer-term design are:

- runtime is tmux-only today; no container backend is implemented
- the policy evaluator does not yet consult stored approval grants
- bridge loops exist as library code but are not yet wired into a top-level runtime command

## Docs

- [Architecture](docs/ARCHITECTURE.md) — current workspace structure, dependency graph, and runtime flow
- [Feature Audit](docs/FEATURE-AUDIT.md) — current status of the feature set carried over from agent-deck
- [Rewrite Proposal](docs/REWRITE-PROPOSAL.md) — proposal history plus what has and has not landed
- [Security Plan](docs/SECURITY-PLAN.md) — current security controls and remaining hardening work
- [Use Cases](docs/USE-CASES.md) — CLI-oriented walkthroughs aligned to the current command surface
- [Agent Traps Defense](docs/AGENT-TRAPS-DEFENSE.md) — threat-model notes for current and planned defenses
- [Stego Defense](docs/STEGO-DEFENSE.md) — steganography hardening notes and future work

## License

MIT
