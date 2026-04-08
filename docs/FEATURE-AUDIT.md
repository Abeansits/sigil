# Feature Audit

**Status:** current implementation audit  
**Date:** 2026-04-07

This file records how the original agent-deck feature inventory maps onto the current `sigil` workspace. It is intentionally status-oriented now; the earlier “keep / drop / modify” worksheet is no longer the best description of the code that actually exists.

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Session lifecycle | Implemented | Create, launch, start, stop, restart, send, output, remove, list, show |
| Status tracking | Implemented | Session states, tmux reads, reconciliation, status CLI |
| Groups and parent links | Partial | Group and parent fields exist in stored session records; management commands are not exposed yet |
| Conductor loop | Partial | Heartbeat, reconciliation, bridge-style command handling exist; multi-conductor management and policy-driven auto-response are not exposed |
| Slack / Telegram bridges | Partial | Parsing, identity resolution, routing, rate limiting, and live loops exist at crate level; no top-level bridge runtime command yet |
| tmux integration | Implemented | Dedicated tmux server label, send, output capture, status checks |
| Git worktrees | Implemented | Create, list, finish, optional merge, safe branch delete attempt |
| Approval grants | Partial | Domain model and SQLite storage exist; evaluator lookup is still pending |
| Audit trail | Implemented | CLI and conductor write HMAC-chained JSONL audit entries |
| Security normalization | Implemented | Bridge normalization, ANSI stripping, trust zones, tier ceilings |
| Container sandboxing | Not started | No container runtime exists in the current workspace |
| Profiles / TUI / Web / SSH / Remotes / Cost tracking | Not started | These areas are not present in the current Rust CLI |

## Implemented Command-Facing Features

### Sessions

Implemented in the CLI today:

- create a session with title, path, tool, and optional group
- launch a session in one step
- list sessions in text or JSON
- show session details in text or JSON
- start, stop, and restart sessions
- send messages with `--wait` and quiet output modes
- read session output
- remove sessions
- resolve sessions by title, full ID, or ID prefix

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

Partial:

- group and parent metadata are stored but not fully surfaced through dedicated management commands

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

Implemented at the crate level:

- Telegram parsing and long-poll loop
- Slack parsing and Socket Mode loop
- sender allowlist resolution
- per-user rate limiting
- routing through `MessageSink`

Not yet wired into the current CLI:

- dedicated bridge runtime command
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
- HMAC-chained audit trail

Partial:

- fatigue guard exists but is not wired into approval handling
- approval grants are stored but not consulted by the evaluator yet

Not implemented:

- container sandbox
- network read/write policy split at runtime
- content provenance tagging
- host-side MCP approval transport

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
