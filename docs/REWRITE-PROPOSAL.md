# Rewrite Proposal Status

**Status:** proposal history with current landing status  
**Date:** 2026-04-07

This file no longer tries to restate the whole architecture in speculative form. Instead, it records which parts of the original rewrite proposal have landed in the current workspace and which parts are still backlog.

For the current implementation, see [`docs/ARCHITECTURE.md`](/Users/zebas/Developer/sigil/docs/ARCHITECTURE.md).

## Landed From The Proposal

### Workspace Shape

The planned 8-crate split landed:

- `sigil-core`
- `sigil-audit`
- `sigil-policy`
- `sigil-store`
- `sigil-runtime`
- `sigil-conductor`
- `sigil-bridge`
- `sigil-cli`

### Core Security Model

These proposal items exist in code today:

- `ActionRequest`, `Action`, and `ActionOrigin`
- trust zones and zone-transition checks
- tier ceilings and principal resolution
- HMAC-chained audit writer and verifier
- input normalization for bridge text
- ANSI stripping for tmux output
- SQLite-backed session persistence
- SQLite-backed approval grant persistence

### Runtime And CLI

These proposal items also landed:

- tmux-backed `SessionRuntime`
- Claude Code adapter
- session lifecycle CLI
- worktree CLI
- conductor heartbeat and reconciliation loop
- Slack and Telegram bridge crates, including live loop implementations

## Partially Landed

### Approval Grants

What exists:

- grant domain model in `sigil-policy`
- `GrantStore` trait
- SQLite implementation in `sigil-store`
- conductor-side expired-grant cleanup

What is still missing:

- evaluator-side grant lookup before returning `NeedsApproval`

### Bridge Integration

What exists:

- Telegram and Slack parsing
- allowlisting
- rate limiting
- routing via `MessageSink`
- live polling / Socket Mode loops

What is still missing:

- top-level CLI or service wiring that runs the bridge as part of `sigil`

### Conductor Automation

What exists:

- heartbeat scans
- reconciliation
- bridge-style slash-command handling
- escalation helpers

What is still missing:

- proposal-level approval gateway notifications
- fatigue-guard integration
- richer auto-response policy wiring

## Not Landed Yet

These proposal items are still roadmap work:

- container runtime backend
- host-side MCP approval server
- feature-gated container support in `sigil-runtime`
- Keychain-backed audit key lifecycle
- workflow-bundle approvals
- content provenance tagging
- WebFetch / fetched-content sanitization pipeline
- unsandboxed-vs-sandboxed session flags

## Corrections To The Original Proposal

The original proposal draft drifted in a few concrete ways. The current workspace corrects those assumptions:

- there is no `ops-container` crate
- there is no `PolicyContext` type in current runtime traits
- `sigil-runtime` does not depend on `sigil-store`
- `sigil-bridge` does not depend on `sigil-store`
- `sigil-cli` runtime dependencies do not include `sigil-bridge` or `sigil-policy`
- container support is not feature-gated in `sigil-runtime` because it does not exist yet

## Recommended Reading Order

1. [`docs/ARCHITECTURE.md`](/Users/zebas/Developer/sigil/docs/ARCHITECTURE.md) for the current system
2. [`docs/SECURITY-PLAN.md`](/Users/zebas/Developer/sigil/docs/SECURITY-PLAN.md) for current controls and next hardening steps
3. this file for “proposal vs reality” deltas
