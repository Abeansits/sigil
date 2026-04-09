# Use Cases

**Status:** aligned to the current CLI  
**Date:** 2026-04-08

These scenarios are written against the command surface that exists today.

## UC1 — Session Lifecycle

```bash
# Create a session pointing at a real directory
sigil session create ~/Projects/test-project --title test-session

# List sessions
sigil session list
sigil session list --json

# Show details
sigil session show test-session
sigil session show test-session --json

# Start, send, inspect output
sigil session start test-session
sigil session send test-session "echo hello from sigil"
sigil session send test-session "status?" --wait
sigil session output test-session
sigil session output test-session --quiet

# Restart, stop, remove
sigil session restart test-session
sigil session stop test-session
sigil session remove test-session
```

**Verify:**

- the session is persisted in SQLite
- tmux session exists after `start`
- output is captured after `send`
- `restart` returns the session to a running state
- tmux session is gone after `stop`
- removal deletes the SQLite record
- audit entries are appended for session actions

## UC2 — Launch Flow

```bash
sigil session launch ~/Projects/test-project \
  --title launch-test \
  --tool codex \
  --message "Summarize the repo layout"
```

**Verify:**

- one command creates, starts, and sends the initial message
- tool selection is persisted as `Codex`
- the session shows up in `session list`

## UC3 — Status Overview

```bash
sigil status
sigil status --json
```

**Verify:**

- counts match actual stored session states
- JSON output parses cleanly

## UC4 — Worktree Flow

```bash
sigil session create ~/Developer/sigil --title worktree-test
sigil worktree create worktree-test --branch feature/wt-test
sigil worktree list
sigil worktree finish worktree-test
sigil worktree finish worktree-test --merge
sigil session remove worktree-test
```

**Verify:**

- worktree directory is created under `.worktrees/`
- `worktree list` shows the session/branch/path tuple
- `finish` removes the worktree
- `finish --merge` merges before removal
- branch cleanup is attempted with safe delete (`git branch -d`)

## UC5 — Conductor Heartbeat

```bash
sigil conductor --interval 10
```

**Verify:**

- startup reconciliation runs before the steady heartbeat loop
- heartbeat scans produce sensible counts
- expired grants are cleaned up during heartbeat
- Ctrl-C stops the loop cleanly
- conductor start and heartbeat changes are logged to the audit trail

## UC6 — Audit Trail Integrity

Run after UC1 or UC5.

```bash
cat ~/.sigil/audit.jsonl
```

**Verify:**

- the file exists
- each line is valid JSON
- entries include `content_hash`, `prev_hash`, and `hmac`
- the first entry uses the genesis `prev_hash`

Verify the chain from the CLI:

```bash
sigil audit verify
```

**Verify:**

- the command exits successfully if the chain is intact
- a tampered or truncated log produces a clear error

## UC7 — Bridge CLI

```bash
# Run the Telegram bridge loop
sigil bridge telegram

# Run the Slack bridge loop
sigil bridge slack

# Run all bridge loops concurrently
sigil bridge all
```

**Verify:**

- each command starts its respective bridge loop
- known senders resolve and route messages
- unknown senders are rejected
- zero-width and directional-override characters are stripped
- per-user rate limiting triggers at the configured threshold
- Slack-origin `T1` actions are allowed; `T2`/`T3` are denied
- human-approved origins elevate otherwise-blocked privileged actions

## UC8 — Audit Verify

```bash
# Verify HMAC chain integrity
sigil audit verify
```

**Verify:**

- exits successfully when the audit log chain is intact
- reports a clear error when the log has been tampered with or truncated

## UC9 — Container Session Lifecycle

Requires macOS 26.0+ with Apple Silicon and `container` CLI installed.

```bash
# Build the agent image (one-time)
scripts/build-agent-image.sh

# The ContainerRuntime is used programmatically via the library.
# Example: launch a container session with domain-filtered networking
# and MCP-based policy mediation.

use sigil_runtime::{ContainerRuntime, ContainerConfig, NetworkMode};

let config = ContainerConfig {
    image: "sigil-agent:latest".into(),
    network: NetworkMode::Filtered {
        allowlist: vec![".anthropic.com".into(), ".github.com".into()],
    },
    ..Default::default()
};

let runtime = ContainerRuntime::with_audit(config, audit.clone())
    .with_mcp(grants.clone());

// launch(), send(), output(), stop() work through SessionRuntime trait
```

**Verify:**

- container VM starts with VirtioFS-mounted worktree at `/workspace`
- domain proxy rejects connections to unlisted domains
- domain proxy denies raw IP addresses
- MCP socket is reachable inside the container at `/tmp/sigil-mcp.sock`
- agent tool calls go through the policy evaluator (T0 allowed, T3 denied for agents)
- `stop` shuts down proxy, MCP server, and container; cleans up sockets

## UC10 — MCP Policy-Mediated Agent Actions

Within a container session with MCP enabled:

```bash
# Inside the container, the agent connects to the MCP socket:
#   /tmp/sigil-mcp.sock

# JSON-RPC initialize handshake
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"session_id":"agent-01"}}

# List available tools
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

# Call an allowed tool (T0 — list_sessions)
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_sessions"}}

# Call a denied tool (T3 — ReadHostFile, agent ceiling is T1)
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_approval","arguments":{"action":"ReadHostFile","path":"/etc/shadow"}}}
```

**Verify:**

- `initialize` returns server capabilities and tool schemas
- `tools/list` returns `request_approval`, `list_sessions`, `get_session_status`, `send_message`, `read_session_output`
- `list_sessions` (T0) succeeds with `status: "Allowed"`
- `request_approval` for `ReadHostFile` (T3) is denied by agent ceiling
- calls without `initialize` return a JSON-RPC error

## Current Notes

- The CLI exposes `status`, `session`, `worktree`, `conductor`, `bridge`, and `audit`.
- Audit logging is wired into the CLI; `sigil audit verify` validates HMAC chain integrity.
- `worktree finish` attempts safe branch deletion after removing the worktree.
- Bridge loops are exposed through `sigil bridge telegram/slack/all`.
- The policy evaluator consults stored approval grants and the `FatigueGuard` is wired into the approval flow.
- The conductor is generic over `SessionRuntime`.
- `ContainerRuntime` implements `SessionRuntime` for Apple Containers (behind `container` feature gate).
- Container sessions support domain-filtered networking via `DomainProxy` and MCP-based policy mediation via Unix socket IPC.
