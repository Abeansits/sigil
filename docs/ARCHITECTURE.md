# sigil Architecture

**Status:** current workspace snapshot  
**Date:** 2026-04-07

This document describes what is actually implemented in the Rust workspace today. It replaces the earlier proposal-style architecture writeup as the primary reference for workspace structure, dependency flow, and command surface.

## Workspace Structure

```text
sigil/
  Cargo.toml
  crates/
    sigil-core/
    sigil-audit/
    sigil-policy/
    sigil-store/
    sigil-runtime/
    sigil-conductor/
    sigil-bridge/
    sigil-cli/
```

### Crates

| Crate | Current responsibility |
|------|------------------------|
| `sigil-core` | Action protocol, IDs, principals, trust zones, session types, trait ports |
| `sigil-audit` | HMAC-chained JSONL writer and read-only verifier |
| `sigil-policy` | Tier and zone evaluation, normalization, fatigue guard, grant domain model |
| `sigil-store` | SQLite migrations, session CRUD, approval grant persistence and cleanup |
| `sigil-runtime` | tmux-backed `SessionRuntime`, Claude Code adapter, worktree manager |
| `sigil-conductor` | Heartbeat scans, reconciliation, status formatting, bridge message handling |
| `sigil-bridge` | Telegram/Slack parsing, identity allowlisting, rate limiting, routing, live loops |
| `sigil-cli` | `sigil` binary, clap commands, audit initialization, conductor runner |

There is no `ops-container` crate in this workspace. Container-backed runtime work remains future work.

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

- `sigil-cli` also has test-only dependencies on `sigil-bridge` and `sigil-policy`.
- `sigil-bridge` and `sigil-conductor` remain decoupled at compile time; bridge code targets `MessageSink`.
- `sigil-store` depends on `sigil-policy` because it implements the `GrantStore` trait and stores approval grants.

## Core Runtime Model

### Authority Boundary

The implemented authority model is centered on:

- `ActionRequest`
- `Action`
- `ActionOrigin`
- `PolicyDecision`

The important rule that matches the code today:

- typed orchestration actions carry authority
- terminal parsing does not

`sigil-runtime::ToolAdapter` parses session output into `AgentSignal` for observability. It does not mint `ActionRequest`s.

### Trust Zones

The current trust-zone enum is:

- `Ingress`
- `ControlPlane`
- `AgentRuntime`
- `HostPrivileged`

The policy engine currently enforces:

- `Ingress -> ControlPlane` allowed
- `ControlPlane -> AgentRuntime` allowed
- `AgentRuntime -> ControlPlane` allowed
- `ControlPlane -> HostPrivileged` requires at least tier `T3`
- `AgentRuntime -> HostPrivileged` always denied

### Permission Tiers

The current tier model in `sigil-core` is:

- `T0` read-only operations
- `T1` session management and messaging
- `T2` infrastructure changes such as worktrees and conductor config
- `T3` privileged host observation or mutation
- `T3Plus` break-glass actions

Current principal defaults:

- local CLI resolves to `T3Plus`
- Telegram resolves to `T3`
- Slack resolves to `T1`
- agent-generated requests resolve to `T1`
- system heartbeat resolves to `T1`

## Current Data Flow

### CLI Path

```text
sigil command
  -> sigil-cli parses clap args
  -> opens SQLite store
  -> initializes AuditLogWriter
  -> dispatches to session/status/worktree/conductor handler
  -> logs session/conductor audit events
```

### Session Path

```text
sigil-cli session <subcommand>
  -> sigil-store resolves SessionRecord
  -> sigil-runtime::TmuxRuntime launches/sends/reads/stops
  -> session state persists in SQLite
  -> audit event appended to audit.jsonl
```

### Bridge Library Path

```text
Telegram/Slack payload
  -> sigil-bridge parsing + normalization
  -> sender allowlist resolution
  -> rate limiting in BridgeRouter
  -> BridgeMessage delivered to a MessageSink
  -> conductor handles /status, /sessions, /check, /send or forwards text
```

Bridge code is implemented at the crate level, but the top-level CLI does not yet expose a dedicated bridge runner.

## Current CLI Surface

Top-level commands:

```text
sigil status
sigil session <subcommand>
sigil worktree <subcommand>
sigil conductor
```

### `session`

Implemented subcommands:

- `list [--json]`
- `show <name> [--json]`
- `create <path> --title <title> [--tool claude|codex] [--group <group>]`
- `launch <path> --title <title> [--tool claude|codex] [--group <group>] [--message <msg>]`
- `start <name>`
- `stop <name>`
- `restart <name>`
- `send <name> <message> [--wait] [-q|--quiet]`
- `output <name> [-q|--quiet]`
- `remove <name>`

### `worktree`

Implemented subcommands:

- `create <name> --branch <branch>`
- `finish <name> [--merge]`
- `list`

`worktree finish` removes the worktree and then attempts a safe `git branch -d`. If the branch is unmerged, deletion is left as a warning instead of a hard failure.

### `conductor`

Implemented:

- `conductor --interval <seconds>`

The conductor performs:

- startup reconciliation
- heartbeat scans
- expired-grant cleanup
- status formatting
- bridge-style slash-command handling at the library level

## What Is Implemented Today

### Fully wired

- session CRUD in SQLite
- session lifecycle CLI
- tmux-backed runtime
- worktree create/list/finish
- HMAC-chained audit logging from CLI/conductor
- audit-chain verification library
- trust-zone and tier evaluation
- bridge input normalization and sender allowlisting
- bridge rate limiting
- conductor reconciliation and heartbeat scans

### Present but not fully integrated

- approval grants are stored in SQLite, but the evaluator does not yet consult them before returning `NeedsApproval`
- `FatigueGuard` exists in `sigil-policy`, but it is not yet wired into the approval flow
- bridge live loops exist in `sigil-bridge`, but there is no top-level `sigil bridge ...` runtime command yet

### Not implemented in this workspace

- container runtime backend
- host-side MCP approval server
- Keychain-backed audit key management
- workflow-bundle approvals
- WebFetch/content sanitization pipeline

## Verification Snapshot

The workspace currently registers 318 tests:

- 268 unit tests
- 50 integration tests in [`crates/sigil-cli/tests`](/Users/zebas/Developer/sigil/crates/sigil-cli/tests)

Recommended verification commands:

```bash
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

## Relationship To Other Docs

- [`docs/REWRITE-PROPOSAL.md`](/Users/zebas/Developer/sigil/docs/REWRITE-PROPOSAL.md) now tracks proposal items that have and have not landed.
- [`docs/SECURITY-PLAN.md`](/Users/zebas/Developer/sigil/docs/SECURITY-PLAN.md) tracks current defenses plus remaining hardening work.
- [`docs/USE-CASES.md`](/Users/zebas/Developer/sigil/docs/USE-CASES.md) mirrors the current CLI command surface.
