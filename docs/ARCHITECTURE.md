# sigil Architecture

**Status:** current workspace snapshot  
**Date:** 2026-04-08

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
    sigil-memory/
    sigil-runtime/
    sigil-conductor/
    sigil-bridge/
    sigil-mcp/
    sigil-content/
    sigil-cli/
```

### Crates

| Crate | Current responsibility |
|------|------------------------|
| `sigil-core` | Action protocol, IDs, principals, trust zones, session types, trait ports |
| `sigil-audit` | HMAC-chained JSONL writer and read-only verifier |
| `sigil-policy` | Tier and zone evaluation, normalization, fatigue guard, grant domain model |
| `sigil-store` | SQLite migrations, session CRUD, approval grant persistence and cleanup |
| `sigil-runtime` | tmux + container `SessionRuntime` backends, domain proxy, MCP socket, Claude Code adapter, worktree manager |
| `sigil-conductor` | Heartbeat scans, reconciliation, status formatting, bridge message handling |
| `sigil-bridge` | Telegram/Slack parsing, identity allowlisting, rate limiting, routing, live loops |
| `sigil-memory` | Operational memory — episode logging, mechanical consolidation of learnings |
| `sigil-mcp` | Host-side MCP server for policy-mediated agent actions (JSON-RPC over stdin/stdout) |
| `sigil-content` | External-content sanitization pipeline — HTML/Markdown/JSON/plain-text format-aware strip, text-layer normalize (composed from `sigil-policy::normalize`), injection-pattern scan, nonce-delimited provenance wrap, keyed-HMAC fingerprints. Pure transform — no policy decisions, no I/O. |
| `sigil-cli` | `sigil` binary, clap commands, bridge runner, audit verification, conductor runner, `sigil content sanitize` debug harness |

`ContainerRuntime` (feature-gated behind `container`) runs sessions in Apple Container VMs. The domain-filtering proxy and MCP socket server live in the same crate. The agent container image is defined in `container/Dockerfile`.

## Dependency Graph

Compile-time workspace edges:

```text
sigil-cli → sigil-audit, sigil-bridge, sigil-conductor, sigil-content, sigil-core, sigil-runtime, sigil-store
sigil-conductor → sigil-audit, sigil-core, sigil-memory, sigil-policy, sigil-runtime, sigil-store
sigil-bridge → sigil-audit, sigil-core, sigil-policy
sigil-content → sigil-core, sigil-policy
sigil-mcp → sigil-core, sigil-policy
sigil-runtime → sigil-core, sigil-policy, sigil-audit [container], sigil-mcp [container]
sigil-memory → sigil-core
sigil-store → sigil-core, sigil-policy
sigil-policy → sigil-audit, sigil-core
sigil-audit → sigil-core
sigil-core → (no internal deps)
```

Notes:

- `sigil-cli` depends on `sigil-bridge` directly for bridge CLI commands.
- `sigil-cli` has test-only dependencies on `sigil-policy`.
- `sigil-bridge` and `sigil-conductor` remain decoupled at compile time; bridge code targets `MessageSink`.
- `sigil-store` depends on `sigil-policy` because it implements the `GrantStore` trait and stores approval grants.
- `sigil-runtime` depends on `sigil-mcp` and `sigil-audit` behind the `container` feature gate (MCP socket server + audit-logged proxy).
- `sigil-content` depends on `sigil-policy::normalize` for the text-layer Unicode/control strip. The sanitizer is a pure transform that composes the existing normalizer rather than duplicating it.

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

## Container Runtime

### ContainerRuntime

`ContainerRuntime` implements `SessionRuntime` using the Apple `container` CLI. Each session gets an isolated VM with:

- VirtioFS-mounted worktree at `/workspace`
- Injected environment variables (API keys, session ID)
- Optional Unix socket mounts for proxy and MCP IPC

Feature-gated behind `container` in `sigil-runtime`.

### Network Isolation

Three modes via `NetworkMode`:

- `Internal` — no internet (default). Container runs on `--internal` network.
- `Full` — unrestricted internet access.
- `Filtered { allowlist }` — internal network with a host-side domain-filtering proxy.

### Domain Proxy

`DomainProxy` runs on the host, listens on a Unix socket published into the container at `/tmp/proxy.sock`. The container's `HTTP_PROXY`/`HTTPS_PROXY` env vars point to this socket. The proxy:

- Supports HTTP CONNECT (HTTPS tunneling) and plain HTTP forwarding
- Checks each outbound connection against a `DomainAllowlist`
- Denies raw IP addresses to prevent allowlist bypass
- Logs every connection attempt as an auditable event
- Enforces concurrent connection limits (128)

### MCP Socket IPC

When `ContainerRuntime` is configured with `.with_mcp(grants)`, launching a session auto-starts an MCP server on a Unix socket at `/tmp/sigil-mcp-{title}.sock` (host side), published into the container at `/tmp/sigil-mcp.sock`.

```text
Agent in container
  → /tmp/sigil-mcp.sock (Unix socket)
  → host-side MCP server (tokio task)
  → sigil-mcp handle_stream (JSON-RPC → policy evaluator → response)
```

The `McpSpawner` trait type-erases the `GrantStore` generic so `ContainerRuntime` stays non-generic.

### Agent Image

The agent container image (`container/Dockerfile`) provides Node.js 22, Claude Code CLI, Codex CLI, git, curl, python3, and build-essential. No secrets are baked in — API keys are injected at runtime. Build with `scripts/build-agent-image.sh`, smoke-test with `scripts/test-agent-image.sh`.

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

### Session Path (tmux)

```text
sigil-cli session <subcommand>
  → sigil-store resolves SessionRecord
  → sigil-runtime::TmuxRuntime launches/sends/reads/stops
  → session state persists in SQLite
  → audit event appended to audit.jsonl
```

### Session Path (container)

```text
ContainerRuntime::launch()
  → start domain proxy (if Filtered) on Unix socket
  → start MCP server (if enabled) on Unix socket
  → `container run` with VirtioFS mount, socket publishes, env injection
  → agent connects to MCP socket for policy-mediated actions
  → agent routes HTTP through proxy socket for domain-filtered internet
  → stop: shuts down proxy + MCP, stops container, cleans up
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

Bridge code is exposed through the `sigil bridge` CLI commands (`telegram`, `slack`, `all`).

## Current CLI Surface

Top-level commands:

```text
sigil status
sigil session <subcommand>
sigil worktree <subcommand>
sigil conductor
sigil bridge <subcommand>
sigil audit <subcommand>
```

### `session`

Implemented subcommands:

- `list [--json]`
- `show <name> [--json]` (renders `parent_title` when set)
- `create <path> --title <title> [--tool claude|codex|opencode] [--group <group>]`
- `launch <path> --title <title> [--tool claude|codex|opencode] [--group <group>] [--message <msg>] [--worktree <branch> [-b]]`
- `start <name>`
- `stop <name>`
- `restart <name>`
- `send <name> <message> [--wait | --no-wait] [--timeout <secs>] [-q|--quiet]`
- `output <name> [-q|--quiet]`
- `set-group <name> <group>`
- `set-parent <name> <parent>`
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

The conductor is generic over `SessionRuntime` (not hardcoded to `TmuxRuntime`). It performs:

- startup reconciliation
- heartbeat scans
- expired-grant cleanup
- status formatting
- bridge-style slash-command handling at the library level

### `bridge`

Implemented subcommands:

- `telegram` — runs the Telegram long-poll bridge loop
- `slack` — runs the Slack Socket Mode bridge loop
- `all` — runs all bridge loops concurrently

### `audit`

Implemented subcommands:

- `verify` — validates HMAC chain integrity of the audit log

## Content Sanitization Pipeline

The `sigil-content` crate implements the ingest-edge sanitization pipeline described in [`docs/design/content-sanitization.md`](design/content-sanitization.md). It runs on external content — bytes fetched from the web, attached to a bridge message, or returned by an MCP tool — **before** the content reaches an agent's context window.

### Production flow

```text
Action::FetchExternalContent { url, content_type }
      │
      ▼
┌────────────────────────────────────────────┐
│ ActionService::execute                     │
│   1. policy.evaluate  → Allow              │
│   2. dispatch_fetch_external_content:      │
│        fetcher.fetch(url) → bytes          │
│                                            │
│        ┌────────────────────────────────┐  │
│        │ sigil-content::Sanitizer       │  │
│        │  Stage 1: size cap (pre-decode)│  │
│        │  Stage 2: declared-type decode │  │
│        │  Stage 3: format-specific strip│  │
│        │  Stage 4: text-layer normalize │  │
│        │  Stage 5: injection scan       │  │
│        │  Stage 6: nonce provenance wrap│  │
│        │  Stage 7: HMAC fingerprints    │  │
│        └────────────────────────────────┘  │
│        → SanitizedContent { text, report } │
│                                            │
│   3. policy.evaluate_result(req, result)   │
│      → SanitizationRequirement gate        │
│   4. audit { decision, sanitize_report }   │
└────────────────────────────────────────────┘
      │
      ▼                               ▼
agent prompt / tool_result      HMAC-chained audit log
(wrapped cleaned text + report) (SanitizeReport + fingerprints)
```

Raw fetched bytes never leave the `dispatch_fetch_external_content` boundary. The sanitizer consumes them by value (`RawFetchedContent` is not `Clone` and has no public byte accessor), so the compile-time type system prevents unsanitized bytes from flowing into any `ActionOutcome::Completed` payload.

### Call sites

Phase 1 integration surface:

- `sigil content sanitize --file <path> --type <html|md|json|text|log>` — the CLI debug/red-team harness. Loads a file, runs the pipeline, prints the cleaned text and a summary of the `SanitizeReport` (or the full JSON report with `--json`).
- **Conductor:** the `Action::FetchExternalContent { url, content_type }` variant routes through `ActionService::dispatch_fetch_external_content` — `ExternalContentFetcher::fetch` → `sanitize_{html,markdown,json,plain}` → `DispatchResult::ExternalContent { text, report }`. `ActionService::execute` then calls `PolicyEngine::evaluate_result` on the post-dispatch `ActionResult` (carrying the report) so the `SanitizationRequirement` gate is enforced. A second audit event captures the post-dispatch decision with the `SanitizeReport` attached.
- **MCP tool results:** the `fetch_url` tool (added in PR7) dispatches through the same sanitizer the conductor uses. `McpServer::with_sanitizer` / `.with_fetcher` install the pipeline; post-`Allow` the server calls the fetcher, runs the sanitizer, and gates the reply through `Evaluator::evaluate_result` before packaging `{ text, report }` into the `ToolResult` data field. Raw fetched bytes never cross the MCP boundary.
- **Fetcher abstraction:** `sigil-content::fetcher` ships the `ExternalContentFetcher` trait (`fn fetch(&self, url) -> FetchFuture`), a `FetchError` taxonomy, and a `DisabledFetcher` default. Production deployments will plug in an HTTP client behind the existing domain-filtering proxy; PR7 does not ship that client.

Deferred to Phase 2 (design accommodates them; no wiring yet):

- Bridge message attachments (Telegram photos/docs, Slack file shares).
- External-file reads tagged by policy as `Ingress`.
- Inter-agent message relay re-sanitization.

### Design invariants

- **Pure transform.** `sigil-content` emits `SanitizedContent + SanitizeReport` and never decides `Allow` / `Deny` / `NeedsApproval`. Those decisions live in `sigil-policy`, which consumes the `risk_score`, `findings`, and size/encoding rejection flags from the report.
- **No sniffing.** Callers always declare the content type. A mismatch between declared type and body markers is flagged (`FMT-001`, `Severity::High`), not silently corrected.
- **Keyed fingerprints.** `raw_fingerprint` and `sanitized_fingerprint` are `HMAC-SHA256` under a per-deployment key sourced from the same Keychain/env path as the audit HMAC key. No unkeyed-SHA fallback; the sanitizer hard-fails at construction if the key is unavailable.
- **Parser differential mitigation.** Whatever the sanitizer emits is what the agent sees and what the auditor sees. The conductor never forwards raw fetched bytes to the model alongside the cleaned form.

### Report shape

The `SanitizeReport` (defined in `sigil-core::content`) carries three independent version numbers (`schema_version`, `rule_set_version`, `scoring_version`) so a report is reproducible against the rule catalog and scoring weights that produced it. See the design doc §Stage 7 for the full field inventory.

## What Is Implemented Today

### Fully wired

- session CRUD in SQLite
- session lifecycle CLI
- tmux-backed runtime
- worktree create/list/finish
- HMAC-chained audit logging from CLI/conductor
- audit-chain verification library and `sigil audit verify` CLI
- trust-zone and tier evaluation
- approval grants stored in SQLite and consulted by the policy evaluator
- `FatigueGuard` wired into the approval flow
- bridge input normalization and sender allowlisting
- bridge rate limiting
- bridge CLI commands (`sigil bridge telegram/slack/all`)
- conductor reconciliation and heartbeat scans (generic over `SessionRuntime`)
- grant prefix matching with path boundary checks
- `strip_ansi` panics on malformed input (no silent fallback)
- host-side MCP server for policy-mediated agent actions (`sigil-mcp`)
- container runtime backend (`ContainerRuntime` for Apple Containers, behind `container` feature gate)
- domain-filtering forward proxy for container network isolation (`DomainProxy`)
- MCP Unix socket IPC wired into container lifecycle
- agent container image (`container/Dockerfile`) with Claude Code + Codex
- operational memory — episode logging and mechanical consolidation (`sigil-memory`)
- property-based tests with `proptest` across core, audit, and policy crates
- external-content sanitization pipeline (`sigil-content`) — plain-text, HTML, Markdown, and JSON paths with nonce-delimited provenance wrap, keyed-HMAC fingerprints, and a stable rule-ID pattern scanner
- `sigil content sanitize` CLI debug harness for the sanitization pipeline
- policy-layer `SanitizationRequirement` enforcement (`Evaluator::evaluate_result`) — actions that declare `Required(content_type)` are gated by a matching `SanitizeReport`
- `Action::FetchExternalContent` variant + conductor dispatch (`ActionService::dispatch_fetch_external_content`) with fetch + sanitize + post-dispatch policy gate + audit entry carrying the report
- MCP `fetch_url` tool with in-process sanitize + `evaluate_result` gate
- End-to-end integration test (`crates/sigil-conductor/tests/sanitize_e2e.rs`) covering HTML, Markdown, and JSON fixtures through the full pipeline into the audit log

### Not implemented in this workspace

- workflow-bundle approvals
- image / audio / PDF sanitization (Phase 2 of the content pipeline)
- bridge attachment handling through the content pipeline

## Verification Snapshot

The workspace currently registers 991 tests across unit and integration suites (verified 2026-05-01 via `cargo test --workspace`).

Recommended verification commands:

```bash
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

## Relationship To Other Docs

- [`docs/SECURITY-PLAN.md`](SECURITY-PLAN.md) tracks current defenses plus remaining hardening work.
- [`docs/USE-CASES.md`](USE-CASES.md) mirrors the current CLI command surface.
- [`docs/archived/`](archived/) holds pre-v0.2.0 proposals and architecture reviews for historical context.
