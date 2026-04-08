# Security Plan

**Status:** current controls plus remaining hardening work  
**Date:** 2026-04-07

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

Current limitation:

- bridge loops are library-level today; there is no top-level bridge runtime command in `sigil`

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

Current limitation:

- the evaluator does not yet consult stored grants before returning `NeedsApproval`
- fatigue-guard logic exists but is not yet wired into the approval path

## Current Security Posture

| Area | Current state |
|------|---------------|
| Bridge ingress | Allowlist + normalization + rate limiting implemented |
| Session runtime | tmux only |
| Sandboxing | Not implemented |
| Audit logging | Implemented and wired into CLI/conductor |
| Grant persistence | Implemented |
| Grant enforcement | Partial |
| Web content sanitization | Not implemented |
| Key management | Partial |

## Remaining Hardening Work

### Priority 1

- wire `GrantStore` into `sigil-policy::Evaluator`
- replace development audit-key fallback with real secret management
- expose a bridge runtime path so the bridge libraries are exercised in the deployed binary

### Priority 2

- integrate `FatigueGuard` into approval handling
- add richer audit correlation for bridge-originated requests
- document and enforce allowed host-path scopes for T3 file actions

### Priority 3

- add a real sandboxed runtime backend
- add fetched-content sanitization for web and media inputs
- add content provenance tagging for external inputs

## What This Plan No Longer Assumes

The current workspace does **not** yet provide:

- Apple Container execution
- cloud-execution substitution for bridge users
- host-side MCP approval transport
- automatic bridge-to-conductor approval notifications
- a separate Python bridge process

Those ideas are still reasonable roadmap items, but they are not current implementation details and should not be documented as if they already exist.

## Practical Next Step Order

1. Make stored approval grants actually affect evaluator decisions.
2. Remove the development fallback for audit HMAC keys.
3. Add a bridge runner or equivalent integration path to the main binary.
4. Wire fatigue mitigation into approval handling.
5. Revisit sandboxing after the authority and audit paths are fully closed.
