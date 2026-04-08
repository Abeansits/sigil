# Feature Audit

**Status:** current implementation audit  
**Date:** 2026-04-08

This file records how the original agent-deck feature inventory maps onto the current `sigil` workspace. It is intentionally status-oriented now; the earlier “keep / drop / modify” worksheet is no longer the best description of the code that actually exists.

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Session lifecycle | Implemented | Create, launch, start, stop, restart, send, output, remove, list, show |
| Status tracking | Implemented | Session states, tmux reads, reconciliation, status CLI |
| Groups and parent links | Partial | Group and parent fields exist in stored session records; management commands are not exposed yet |
| Conductor loop | Partial | Heartbeat, reconciliation, bridge-style command handling exist; multi-conductor management and policy-driven auto-response are not exposed |
| Slack / Telegram bridges | Implemented | Parsing, identity resolution, routing, rate limiting, live loops, and CLI commands (`sigil bridge telegram/slack/all`) |
| tmux integration | Implemented | Dedicated tmux server label, send, output capture, status checks |
| Git worktrees | Implemented | Create, list, finish, optional merge, safe branch delete attempt |
| Approval grants | Implemented | Domain model, SQLite storage, evaluator integration, fatigue guard, path boundary checks |
| Audit trail | Implemented | CLI and conductor write HMAC-chained JSONL audit entries; `sigil audit verify` validates chain integrity |
| Security normalization | Implemented | Bridge normalization, ANSI stripping, trust zones, tier ceilings |
| MCP server | Implemented | Host-side policy-mediated MCP server for agent actions (`sigil-mcp`) |
| Container sandboxing | Not started | Research in `docs/CONTAINER-POC.md`; no container runtime backend yet |
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
- HMAC-chained audit trail

Not implemented:

- container sandbox
- network read/write policy split at runtime
- content provenance tagging

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
