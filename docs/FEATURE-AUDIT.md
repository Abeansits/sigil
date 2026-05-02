# Feature Audit

**Status:** current implementation audit  
**Date:** 2026-05-01

This file records the current feature surface of the `sigil` workspace and what is intentionally out of scope. It is status-oriented, not historical.

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Session lifecycle | Implemented | Create, launch, start, stop, restart, send, output, remove, list, show |
| Status tracking | Implemented | Session states, tmux reads, reconciliation, status CLI |
| Groups and parent links | Implemented | Stored on session records and managed via `session set-group` / `session set-parent`; surfaced in `session show --json` (PR #61) |
| Conductor loop | Partial | Heartbeat, reconciliation, bridge-style command handling exist; multi-conductor management and policy-driven auto-response are not exposed |
| Slack / Telegram bridges | Implemented | Parsing, identity resolution, routing, rate limiting, live loops, and CLI commands (`sigil bridge telegram/slack/all`); Telegram bot token is redacted from `reqwest` error logs (PR #65) |
| tmux integration | Implemented | Dedicated tmux server label, send, output capture, status checks; reliable input delivery and session-restart-race fix (PRs #48, #59) |
| Git worktrees | Implemented | Create, list, finish, optional merge, safe branch delete attempt; one-step `session launch --worktree BRANCH [-b]` (PR #60) |
| Approval grants | Implemented | Domain model, SQLite storage, evaluator integration, fatigue guard, path boundary checks |
| Audit trail | Implemented | CLI and conductor write HMAC-chained JSONL audit entries; `sigil audit verify` validates chain integrity. HMAC key resolves env > Keychain (`sigil/audit-hmac`) > opt-in dev fallback; key bytes zeroized on drop (PRs #40, #47) |
| Security normalization | Implemented | Bridge normalization, ANSI stripping, trust zones, tier ceilings |
| MCP server | Implemented | Host-side policy-mediated MCP server for agent actions (`sigil-mcp`) |
| Container sandboxing | Implemented | `ContainerRuntime` for Apple Containers behind `container` feature gate; domain-filtered networking (`DomainProxy`), MCP-mediated IPC; CLI `--runtime container` flag; known compile-time boundary issue with `--all-features` |
| External-content sanitization | Implemented | `sigil-content` Phase 1 pipeline — plain / HTML / markdown / JSON sanitization across the 7-stage path (size guard → declare/decode → format-specific strip → text-layer normalize → injection-pattern scan → nonce-delimited provenance wrap → keyed-HMAC fingerprint report). `SanitizeReport` flows through `ActionResult`; the conductor enforces `SanitizationRequirement` via `ActionService::dispatch_fetch_external_content` (PRs #43, #45, #50, #52–#58) |
| ActionService unified policy | Implemented | Worktree, identity, status, and bridge T0 reads route through a single policy pipeline (PRs #37, #41) |
| Tool support | Implemented | `claude`, `codex`, and `opencode` tool kinds with adapters (PR #66) |
| Operational memory | Partial | `sigil-memory` crate ships episode logging, mechanical consolidation, idle consolidation hooks, and CLI subcommands (PRs #27–#30, #35, #38). Profile-aware/long-term memory is out of scope |
| Profiles / TUI / Web / SSH / Remotes / Cost tracking | Not started | These areas are not present in the current Rust CLI |

## Implemented Command-Facing Features

### Sessions

Implemented in the CLI today:

- create a session with title, path, tool, and optional group
- launch a session in one step
- list sessions in text or JSON
- show session details in text or JSON
- start, stop, and restart sessions
- send messages with `--wait` (default), `--no-wait`, `--timeout`, and quiet output modes (PRs #62, #63)
- read session output
- remove sessions
- resolve sessions by title, full ID, or ID prefix
- `sigil run` for inline command execution against a session (PR #31)

Not implemented from the original inventory:

- interactive attach
- automatic “current tmux session” detection
- rename command
- fork/clone session command
- notes editing

### Status And Metadata

Implemented:

- session states: `Running`, `Waiting`, `Idle`, `Error`, `Stopped`
- status summary command with JSON output
- conductor reconciliation against live tmux state
- ANSI stripping on runtime reads

Implemented (post-2026-04-08):

- `session set-group <id> <group>` and `session set-parent <id> <parent-id>`; `parent_title` rendered in `session show --json` (PR #61)

Not implemented:

- per-session notes
- “last accessed” tracking

### Worktrees

Implemented:

- create a worktree for a session
- list active worktrees
- finish a worktree
- optional merge before removal
- safe branch cleanup with `git branch -d`

Not implemented:

- auto-create worktree on session creation
- custom placement strategies
- orphan cleanup worker
- multi-repo orchestration beyond the current single-session repo model

### Bridges

Implemented:

- Telegram parsing and long-poll loop
- Slack parsing and Socket Mode loop
- sender allowlist resolution
- per-user rate limiting
- routing through `MessageSink`
- CLI commands: `sigil bridge telegram`, `sigil bridge slack`, `sigil bridge all`

Not implemented:

- Discord bridge
- profile-aware bridge routing

### Security And Policy

Implemented:

- typed action protocol
- trust-zone evaluation
- principal resolution and tier ceilings
- bridge input normalization
- tmux output ANSI stripping
- approval grant persistence
- HMAC-chained audit trail with Keychain-backed key resolution (PR #40) and zeroized key bytes (PR #47)
- container sandbox (`ContainerRuntime` + `DomainProxy` + MCP-mediated IPC)
- external-content sanitization with nonce-delimited provenance tagging (Phase 1, PRs #43, #45, #50, #52–#58)
- `SanitizationRequirement` policy gate enforced by `ActionService` on post-dispatch results (PR #55)
- supply-chain audit via `cargo-deny` (PR #16)
- Telegram bot token redaction in `reqwest` error logs (PR #65)

Not implemented:

- network read/write policy split at runtime

## Explicitly Out Of Scope For The Current CLI

The following feature groups from the old inventory are still absent from the workspace and should be treated as backlog, not as hidden or partially wired features:

- profile CRUD
- TUI dialogs and tree UI
- web UI / WebSocket server / push notifications
- Docker sandbox
- SSH remote execution
- multi-machine instance management
- cost tracking and budget UI
- OpenClaw integration
- hook install / uninstall command set

## Source Of Truth

Use these files for current behavior:

- [`docs/ARCHITECTURE.md`](/Users/zebas/Developer/sigil/docs/ARCHITECTURE.md)
- [`docs/USE-CASES.md`](/Users/zebas/Developer/sigil/docs/USE-CASES.md)
- [`README.md`](/Users/zebas/Developer/sigil/README.md)
