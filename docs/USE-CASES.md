# Use Cases

**Status:** aligned to the current CLI  
**Date:** 2026-04-07

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

Library-level verification uses `sigil-audit::verify_log`; there is not yet a dedicated CLI subcommand for verification.

## UC7 — Bridge And Policy Coverage

Bridge behavior is currently tested at the library level, not through a top-level `sigil bridge ...` command.

Examples covered by tests:

- known Telegram sender resolves and routes
- unknown sender is rejected
- zero-width and directional-override characters are stripped
- per-user rate limiting triggers at the configured threshold
- Slack-origin `T1` actions are allowed
- Slack-origin `T2` and `T3` actions are denied
- human-approved origins elevate otherwise-blocked privileged actions

## Current Notes

- The CLI currently exposes `status`, `session`, `worktree`, and `conductor` only.
- Audit logging is wired into the CLI now; the earlier “audit not wired” finding is obsolete.
- `worktree finish` now attempts safe branch deletion after removing the worktree, so the older “branch always left behind” finding is obsolete.
- Bridge loops exist in `sigil-bridge`, but they are not yet exposed through a top-level CLI command.
