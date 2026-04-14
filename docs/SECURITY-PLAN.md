# Security Plan

**Status:** current controls plus remaining hardening work  
**Date:** 2026-04-08

This plan is now aligned to the Rust workspace that exists today. It no longer assumes `bridge.py`, a container runtime, or a separate pre-Rust system as the primary implementation surface.

## Threat Model

Primary risks that still matter for the current workspace:

- untrusted bridge input entering a conductor or session flow
- prompt injection through agent-visible content
- privileged host actions without clear approval boundaries
- tampering with audit logs or approval state
- compromised Slack or Telegram identities

## Controls Implemented Today

### Typed Authority Model

Implemented in `sigil-core` and `sigil-policy`:

- `ActionRequest`, `Action`, and `ActionOrigin`
- principal resolution
- tier ceilings
- trust-zone checks
- denial of `AgentRuntime -> HostPrivileged`

### Input Normalization

Implemented today:

- bridge text normalization for zero-width, tag, directional-override, variation-selector, and control characters
- mixed-script detection
- ANSI stripping for tmux output before higher-level parsing

Current limitation:

- fetched web content, media, and code from external repos are not sanitized by a dedicated content pipeline

### Sender Controls

Implemented in `sigil-bridge`:

- sender allowlisting
- per-user rate limiting
- origin tagging for Telegram and Slack messages

Bridge loops are exposed through `sigil bridge telegram/slack/all` CLI commands.

### Audit Trail

Implemented:

- append-only HMAC-chained JSONL writer
- recovery from existing logs
- verifier for tamper detection
- audit wiring in `sigil-cli` session commands and conductor flow

Current limitation:

- audit key management still relies on `SIGIL_AUDIT_KEY` or a development fallback key, not Keychain-backed storage

### Approval Model

Implemented:

- approval-grant domain model
- SQLite persistence for approval grants
- conductor cleanup of expired grants
- `NeedsApproval` decisions for T2/T3 actions
- evaluator consults stored grants before returning `NeedsApproval`
- `FatigueGuard` wired into the approval flow
- grant prefix matching with path boundary checks

## Current Security Posture

| Area | Current state |
|------|---------------|
| Bridge ingress | Allowlist + normalization + rate limiting implemented |
| Session runtime | tmux (default) + Apple Containers (feature-gated `container`) |
| Sandboxing | Container runtime with domain-filtered networking and MCP-mediated IPC |
| Audit logging | Implemented and wired into CLI/conductor |
| Grant persistence | Implemented |
| Grant enforcement | Implemented |
| Web content sanitization | Not implemented |
| Key management | Partial |

## Remaining Hardening Work

### Priority 1

- replace development audit-key fallback with real secret management

### Priority 2

- add richer audit correlation for bridge-originated requests
- document and enforce allowed host-path scopes for T3 file actions

### Priority 3

- add fetched-content sanitization for web and media inputs
- add content provenance tagging for external inputs

## What This Plan No Longer Assumes

The current workspace does **not** yet provide:

- cloud-execution substitution for bridge users
- automatic bridge-to-conductor approval notifications
- a separate Python bridge process

The workspace **does** now provide:

- Apple Container execution behind the `container` feature gate (`ContainerRuntime`), with domain-filtered networking and MCP-mediated IPC (note: CLI integration with `--all-features` has a known compile-time boundary issue)
- host-side MCP server for policy-mediated agent actions (`sigil-mcp`)

Those ideas are still reasonable roadmap items, but they are not current implementation details and should not be documented as if they already exist.

## Practical Next Step Order

1. Remove the development fallback for audit HMAC keys.
2. Revisit sandboxing after the authority and audit paths are fully closed.
3. Add fetched-content sanitization for web and media inputs.
4. Add content provenance tagging for external inputs.
