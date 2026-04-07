# agent-ops

A security-first Rust binary for managing AI agent sessions. Replaces [agent-deck](https://github.com/Abeansits/agent-deck) (Go) + bridge.py (Python) with a single binary that has security baked in from day one.

## Why

Running multiple AI coding agents (Claude Code, Codex, etc.) in tmux sessions works — but it's held together with Go + Python + shell scripts, no permission model, no audit trail, and no sandboxing. Agent-ops fixes that.

## Architecture

```
ops-cli            CLI entry point (clap)
ops-conductor      Heartbeat, escalation, session coordination
ops-bridge         Telegram + Slack adapters, rate limiting, identity resolution
ops-runtime        tmux session backend, tool adapters, git worktrees
ops-store          SQLite persistence (sessions, grants, audit index)
ops-policy         Trust zones, tier evaluation, approval grants, input sanitization
ops-audit          HMAC-chained JSONL audit trail
ops-core           Action enum, trust model, traits, domain types
```

Dependency flow is strictly top-down — no cycles.

## Key Design Decisions

- **Action enum as sole authority protocol** — ~30 typed variants, no `Shell(String)`. Every agent request maps to a concrete action.
- **Trust zones** — Z0 (Ingress) → Z1 (ControlPlane) → Z2 (AgentRuntime) → Z3 (HostPrivileged). Z2→Z3 is always blocked.
- **Permission tiers** — T0 (Read) → T1 (Operate) → T2 (Modify Infra) → T3 (Privileged Host) → T3+ (Break Glass).
- **Terminal parsing is observability only** — status scraping never grants authority. All privileged requests flow through structured MCP tool calls.
- **HMAC-chained audit** — SHA-256 content hash + prev_hash chain + HMAC-SHA256. Tamper-evident by design.
- **Principal model** — ActionOrigin → Principal → permissions. Auth strength, platform binding, trust posture, tier ceiling.

## Build

```bash
cargo build --release    # 5.6 MB binary (thin LTO)
cargo test               # 314 tests (267 unit + 47 integration)
cargo clippy -- -D warnings
```

Requires Rust 1.85+ (edition 2024).

## Status

Steps 1–10 of the [build plan](docs/ARCHITECTURE.md) are complete. Shadow mode (step 11) and cutover (step 12) are next.

## Docs

- [Architecture](docs/ARCHITECTURE.md) — full system design, Action enum spec, trust zones, build order
- [Feature Audit](docs/FEATURE-AUDIT.md) — 120 features from agent-deck, triaged into tiers
- [Rewrite Proposal](docs/REWRITE-PROPOSAL.md) — Codex consultation + Ting review results
- [Security Plan](docs/SECURITY-PLAN.md) — 8-layer security architecture
- [Agent Traps Defense](docs/AGENT-TRAPS-DEFENSE.md) — adversarial prompt/steganography defenses
- [Stego Defense](docs/STEGO-DEFENSE.md) — steganographic attack analysis

## License

MIT
