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
- `sigil-content` sanitization pipeline for external content — plain-text and HTML paths with format-specific structural strip, text-layer normalize (composed from `sigil-policy::normalize`), injection-pattern scan with stable rule IDs, nonce-delimited provenance wrap, and keyed-HMAC fingerprints. Markdown + JSON land with PR5; policy-layer `SanitizationRequirement` enforcement lands with PR6; conductor + MCP wiring lands with PR7 (pending PR6 merge).

Current limitation:

- bridge message attachments, image/audio/PDF content, and inter-agent message relay are not yet routed through the content pipeline (Phase 2 of the design)

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

Key management is now Keychain-backed on macOS, with `SIGIL_AUDIT_KEY` as an env-based fallback for CI / tests. See PR #40 for the strict-resolution rollout.

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
| Web content sanitization | Implemented (Phase 1 — plain-text + HTML in `sigil-content`; Markdown + JSON in PR5; conductor + MCP wiring in PR7 pending PR6) |
| Content provenance tagging | Implemented (nonce-delimited in-band wrap + keyed-HMAC fingerprints in audit log) |
| Key management | Keychain-backed on macOS (audit + sanitizer fingerprint HMAC key) |

## Remaining Hardening Work

### Priority 1

- _(completed)_ replace development audit-key fallback with Keychain-backed secret management — landed in PR #40.

### Priority 2

- add richer audit correlation for bridge-originated requests
- document and enforce allowed host-path scopes for T3 file actions
- extend the `sigil-content` pipeline to image, audio, and PDF inputs (Phase 2 of the content-sanitization design)
- route bridge message attachments, external file reads, and inter-agent relays through `sigil-content`

### Priority 3

- _(completed Phase 1)_ fetched-content sanitization for web inputs (`sigil-content`: plain-text + HTML; Markdown + JSON with PR5; conductor + MCP wiring with PR7)
- _(completed Phase 1)_ content provenance tagging for external inputs (nonce-delimited in-band wrap + keyed-HMAC fingerprints in the audit log)

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

1. _(done)_ Keychain-backed audit HMAC key with strict resolution (PR #40).
2. _(done — Phase 1)_ Fetched-content sanitization pipeline (`sigil-content`, PRs #43–#54; conductor + MCP wiring in PR7).
3. _(done — Phase 1)_ Content provenance tagging — nonce-delimited wrap + keyed-HMAC fingerprints attached to `SanitizeReport` and audit log.
4. Extend `sigil-content` to image / audio / PDF inputs (Phase 2 of the content-sanitization design).
5. Route bridge message attachments, external file reads, and inter-agent relays through the sanitizer.
6. Revisit sandboxing after the authority and audit paths are fully closed.

## Content Sanitization Pipeline (Phase 1 Summary)

The `sigil-content` crate is the ingest-edge filter for external bytes on their way to an agent's context. Its production flow:

1. Raw bytes enter as `RawFetchedContent` (private body; consumed by value).
2. `Sanitizer::sanitize_{plain,html,markdown,json}` runs the 7-stage pipeline described in [`docs/design/content-sanitization.md`](design/content-sanitization.md).
3. Callers (conductor, MCP, bridge — current + deferred) receive `SanitizedContent { text, report }`. The cleaned `text` is what the agent sees; the `report` is what policy evaluates and audit persists.

Key security properties:

- **No sniffing.** Content type is caller-declared. Polyglot / lying-server attacks are flagged (`FMT-001`, `High`), not silently corrected.
- **No silent failures.** Size and encoding violations are typed errors. Pattern hits are recorded as findings with stable `rule_id`s (`INJ-001`, `ENC-003`, `FMT-001`, …). Stripped-element counts are recorded; raw stripped bytes are dropped.
- **Keyed fingerprints.** `HMAC-SHA256` under a per-deployment key sourced from the same Keychain/env path as the audit HMAC key. No unkeyed-SHA fallback; construction fails hard if the key is unavailable.
- **Nonce-delimited wrap.** Each call generates a fresh random nonce for the `<|sigil_external_start:…|>` / `<|sigil_external_end:…|>` sentinels. A payload containing a sentinel-prefix collision re-rolls the nonce. Header fields reject CR/LF to block HTTP-response-splitting-style injection.
- **Policy boundary preserved.** The sanitizer never returns `NeedsApproval`. It emits findings; `sigil-policy` maps findings + `risk_score` to `Allow` / `Deny` / `NeedsApproval` per the `SanitizationRequirement` on the action.

For the full threat model, stage-by-stage behavior, the false-positive budget, and the Phase 1 / Phase 2 integration-point matrix, see [`docs/design/content-sanitization.md`](design/content-sanitization.md).
