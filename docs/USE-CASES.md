# Use Cases

Manual walkthrough scenarios. Each will become an integration test.

## UC1 — Session Lifecycle

The core loop: create, inspect, start, communicate, stop, remove.

```bash
# Create a session pointing at a real directory
agent-ops session create ~/Projects/test-project --title "test-session"

# List — should show 1 session in stopped state
agent-ops session list

# Show details
agent-ops session show test-session

# Start the tmux session
agent-ops session start test-session

# Send a message
agent-ops session send test-session "echo hello from agent-ops"

# Read output
agent-ops session output test-session

# Stop
agent-ops session stop test-session

# Remove
agent-ops session remove test-session

# List — should be empty
agent-ops session list
```

**Verify:**
- Session appears in SQLite after create
- tmux session exists after start (`tmux has-session`)
- Output is captured after send
- tmux session gone after stop
- Session removed from SQLite after remove
- Audit trail has entries for each action

## UC2 — Status Overview

```bash
agent-ops status
agent-ops status --json
```

**Verify:**
- Counts match actual session states
- JSON output parses cleanly

## UC3 — Worktree Flow

```bash
# Requires UC1 session to exist and have a git repo
agent-ops session create ~/Developer/agent-ops --title "worktree-test"
agent-ops worktree create worktree-test --branch feature/wt-test
agent-ops worktree list
agent-ops worktree finish worktree-test
agent-ops session remove worktree-test
```

**Verify:**
- Git worktree created on disk
- Branch exists
- Worktree cleaned up after finish
- No leftover branches or directories

## UC4 — Conductor Heartbeat

```bash
# Start conductor with short interval
agent-ops conductor --interval 10
# Let it run 2-3 cycles
# Ctrl-C — verify clean shutdown
```

**Verify:**
- Heartbeat scans running tmux sessions
- Startup reconciliation runs (compares DB state vs tmux reality)
- Clean shutdown on SIGINT (no orphaned state)
- Audit entries for heartbeat cycles

## UC5 — Audit Trail Integrity

Run after UC1. Verify the HMAC-chained audit log.

```bash
# Check that the audit log exists and has entries
cat ~/.agent-ops/audit.jsonl

# Each entry should have: content_hash, prev_hash, hmac
# First entry prev_hash should be 64 zeros (genesis)
# Chain should be unbroken
```

**Verify:**
- Entries exist for session create/start/send/stop/remove
- HMAC chain is valid (prev_hash of entry N = content_hash of entry N-1)
- Tampering with any entry breaks verification

## UC6 — Bridge Message Flow (mocked)

For CI: mock the Telegram/Slack webhook payloads, feed them through the bridge pipeline.

```
Input:  Telegram update JSON with known user → identity resolution → policy check → route to session
Input:  Slack event JSON with known user → identity resolution → policy check → route to session
Input:  Unknown sender → rejected at identity resolution
Input:  Rate-limited sender → rejected after threshold
```

**Verify:**
- Known users resolve to correct Principal with correct tier ceiling
- Unknown senders are rejected with `UnknownSender` error
- Rate limiter kicks in after 30 messages/minute
- Messages are normalized (invisible chars stripped, ANSI stripped)
- Audit trail records each bridge event

## UC7 — Policy Evaluation (mocked)

Exercise the policy engine with various action/origin combinations.

```
T0 action + T0 principal → Allow
T3 action + T1 principal → Deny (tier ceiling)
T3 action + T3 principal → Approve (needs grant)
Z2 → Z3 transition → Deny (always blocked)
Expired grant → Deny
Valid grant → Allow + consume
Fatigue guard → Cooldown after burst
```

**Verify:**
- Decisions match the tier/zone/capability matrix
- Grants are consumed on use
- Fatigue guard triggers at threshold

## Manual Walkthrough Results (2026-04-07)

### UC1 — Session Lifecycle: PASS
All 8 commands work end-to-end against real tmux.
- tmux sessions run on a separate server (`-L agent-ops`), isolated from agent-deck
- Output capture works with ANSI stripping
- SQLite CRUD works correctly

### UC2 — Status: PASS
- Plain and JSON output both correct
- Counts match actual session states

### UC3 — Worktree: PASS (with finding)
- Create/list/finish all work against a real git repo
- **Finding: `worktree finish` doesn't delete the branch.** It removes the worktree directory but leaves the git branch behind. Should either delete the branch or accept a `--delete-branch` flag.

### UC4 — Conductor Heartbeat: PASS
- Startup reconciliation correctly detected a stale Running session (tmux gone) and corrected to Error
- Heartbeat cycles ran on schedule
- Clean exit on SIGTERM (exit code 143)

### UC5 — Audit Trail: BLOCKED
- **Finding: ops-audit is not wired into the CLI.** The crate exists, tests pass, HMAC chaining works, but no CLI command creates an `AuditLogWriter` or logs events. No audit.jsonl file is produced.

### UC6/UC7 — Bridge & Policy: NOT TESTED (mocked tests exist)
- These are covered by unit tests (53 bridge tests, 59 policy tests)
- End-to-end integration tests with mocked inputs are the next step

## Findings Summary

| # | Severity | Description | Fix |
|---|----------|-------------|-----|
| F1 | **High** | Audit trail not wired into CLI — no events logged | Wire `AuditLogWriter` into CLI command layer |
| F2 | Low | `worktree finish` doesn't delete the branch | Add `--delete-branch` flag or delete by default |
| F3 | Info | tmux server uses `-L agent-ops` (separate namespace) | Correct by design, just document it |

## Notes

- UC1-UC4 require tmux (real session management)
- UC5 requires filesystem (audit log)
- UC6-UC7 can run fully mocked (no external deps, CI-friendly)
- All UCs should verify audit trail entries as a side effect (once F1 is fixed)
