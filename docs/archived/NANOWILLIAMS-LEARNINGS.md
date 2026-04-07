# NanoWilliams → Agent-Deck: Portable Learnings

**Source:** `/Users/zebas/Developer/NanoWilliams` (Feb 2026, abandoned but full of good ideas)
**Principle:** Don't modify agent-deck internals. Build on top of it — scripts, bridge logic, conductor rules, standalone tools.

---

## What to Port (agent-deck independent)

### 1. Security: Mount/Path Allowlisting
**NW source:** `crates/nw-core/src/security.rs`

The security model is excellent and entirely portable:
- **Blocked paths:** `.ssh`, `.gnupg`, `.aws`, `credentials.json`, `/etc/passwd`, `/etc/shadow`
- **Per-group allowlists:** different sessions/users get different path access
- **Symlink escape detection:** prevents container breakout via symlinks
- **Write restrictions:** non-main groups can only write to their own roots

**How to port:** This doesn't need to live in agent-deck. Build it as:
- A bridge.py middleware that validates any file path in conductor commands
- Or a standalone `path-guard` CLI tool (like `strip-invisible`) that other scripts call
- The blocklist and allowlist live in a JSON config file

### 2. Patch Approval Flow
**NW source:** `/approve <job_id>` + `job.approve_patch` protocol message

The flow: agent writes a patch.diff → human reviews → `/approve` applies it via `git apply --check` then `git apply`. No auto-commit.

**How to port:** Bridge-level approval gate:
- When Vs (Slack/Paul) triggers any file modification or shell command, bridge holds it in a pending queue
- Sebastian gets a Telegram notification: "Paul requested: [action]. Approve?"
- Only proceeds on explicit approval
- Doesn't touch agent-deck internals — it's bridge logic

### 3. Nightly Sleep Compute (autoDream predecessor)
**NW source:** `crates/nw-daemon/src/scheduler.rs` + `memory/` directory

NanoWilliams runs at 2am daily, catches up if daemon starts after 2am. Auto-commits `learnings.md` and `tomorrow-plan.md`.

**What broke:** No deduplication. The same 5-6 learnings repeated 20+ times across entries. The nightly job was appending without consolidating.

**Lesson for our autoDream:** The schedule/trigger mechanism was right (cron-style, catch-up on missed runs). The consolidation logic was wrong (append-only without merge/dedup). Our dreamer must:
1. Read ALL existing entries before writing
2. Deduplicate aggressively
3. Merge related entries
4. Delete superseded entries
5. Be idempotent (running twice = same result)

### 4. Memory Index (SQLite FTS)
**NW source:** `crates/nw-core/src/memory_index.rs`

A SQLite full-text-search index over memory entries. This is Layer 3 (transcript grep) done properly — structured search over unstructured content.

**How to port:** A standalone `memory-search` script that:
- Indexes MEMORY.md, topic files, learnings, and task-log.md into a SQLite FTS table
- Provides keyword search across all memory sources
- Returns ranked results with source file and context
- Runs locally, no agent-deck dependency

### 5. Personality Bootstrap (SOUL + USER + IDENTITY)
**NW source:** `crates/nw-core/src/personality.rs`

Three-file personality system:
- `SOUL.md` — who the agent is (we already have this)
- `USER.md` — who the user is (we put this in memory topic files)
- `IDENTITY.json` — structured metadata (name, role, preferences)

**Lesson:** The structured `IDENTITY.json` is interesting — machine-readable personality data that doesn't need LLM parsing. Could be useful for programmatic decisions (e.g., bridge logic checking user tier).

### 6. Container-First Execution
**NW source:** `crates/nw-core/src/container.rs`

Agents run inside Apple Containers with explicit mount points:
- Workspace: read-write
- Project repo: **read-only** (code jobs)
- Scratchpad: persistent per-session
- Host fallback only when container isn't available

**Lesson for cloud execution plan:** The mount model maps directly to our cloud Vs concept:
- Cloud agent gets read access to shared repo (git)
- Write access only to its own workspace
- No access to host filesystem, credentials, or other sessions

### 7. Daemon Protocol (NDJSON over Unix Socket)
**NW source:** `crates/nw-core/src/daemon_protocol.rs`

Structured message protocol between TUI client and daemon. Every message is typed, every response is typed. No freeform text at the protocol level.

**Lesson:** Our bridge uses freeform text parsing (looking for `NEED:` and `AUTO:` in conductor responses). A structured protocol would be more reliable and harder to inject into. Not urgent, but worth noting for bridge v2.

---

## What NOT to Port

- **The Rust daemon itself** — we're not replacing agent-deck's tmux architecture
- **The TUI** — agent-deck has its own
- **Codex-specific integration** — we're multi-model (Claude + Codex)
- **The broken nightly sleep dedup** — learn from the bug, don't copy it

---

## Immediate Actions

| # | What | Effort | Source |
|---|------|--------|--------|
| 1 | `path-guard` CLI tool based on security.rs blocklist | Small | security.rs |
| 2 | Bridge approval gate for Slack-sourced commands | Medium | approval flow concept |
| 3 | Fix autoDream plan with NW sleep compute lessons | Already done | scheduler.rs learnings |
| 4 | `memory-search` SQLite FTS tool | Medium | memory_index.rs |
| 5 | IDENTITY.json for programmatic user/tier config | Small | personality.rs |

---

## Meta-Learning

Sebastian built NanoWilliams in ~3 weeks (Feb 3 - Feb 25, 2026). It has a Rust daemon, TUI, container sandboxing, security module, memory system, sleep compute, and patch approval. Then agent-deck solved the immediate work need and NW was shelved.

The pattern: the ideas were right, the execution was solid, but the timing conflicted with a real-world deadline. The ideas didn't die — they migrated. Container sandboxing → cloud execution plan. Patch approval → confirmation gates. Sleep compute → autoDream. Security module → security plan.

Nothing was wasted. The NW codebase is a design document written in Rust.
