# Memory System — Design Document

**Date:** April 11, 2026
**Status:** Draft — awaiting Sebastian's review
**Problem:** The agent memory layer works (flat files are the right abstraction), but behavioral discipline is missing. Episodes aren't captured, learnings aren't consolidated, and nothing fires between identity reload and session end. The storage is fine. The lifecycle is broken.

## Guiding Principles

1. **Simple Made Easy.** A flat file + hook beats a vector DB nobody queries.
2. **Earn your complexity.** No embeddings, no vector DB, no fancy retrieval until grep/FTS fails at the actual corpus size.
3. **Fix behavior, not architecture.** The storage works. Add lifecycle triggers.
4. **Phase 1 has no LLM dependency.** Pure mechanical consolidation. The Dreamer comes later.

## Current State

### What Exists

The identity reload system (PRs #18-#23) solved compaction recovery:

- `IdentitySpec` and `LifecycleEvent` in `sigil-core` define which files constitute a session's identity and when to reload them.
- `LifecycleHooks` trait in `sigil-core`, implemented by `TmuxRuntime`, registers Claude Code hooks that fire `sigil identity reload <session-id>` on `PostCompact`.
- `sigil identity snapshot` captures state during `PreCompact`.
- `.sigil/config.toml` and `--identity` CLI flag configure identity files per session.

The flat-file memory model:

| File | Purpose | Mutability |
|------|---------|------------|
| `SOUL.md` | Durable identity / persona | Read-only (human-authored) |
| `OPS.md` | Operating rules / policy | Read-mostly (human-reviewed) |
| `state.json` | Current truth / structured state | Machine-writable, schema-checked |
| `LEARNINGS.md` | Distilled durable learnings | Machine-proposed, threshold-promoted |

### What's Missing

The identity reload system covers two points on the memory lifecycle:

1. Reload identity after compaction/restart
2. Snapshot state before compaction

Everything between those two points is unaddressed:

- **No episodic capture.** Actions, corrections, approvals, and tool outcomes are not recorded as episodes. The only record is the security audit log, which is HMAC-chained and serves a different purpose.
- **No consolidation.** Candidate learnings are never deduplicated, merged, expired, or promoted into `LEARNINGS.md`. Running consolidation is a manual process.
- **No lifecycle triggers between compaction events.** `PostAction`, `SessionEnd`, and `Idle` don't exist as trigger points yet.
- **No retrieval beyond file reads.** When the corpus grows past a handful of files, there's no search mechanism.

## Architecture

### New Crate: `sigil-memory`

Follows the same pattern as `sigil-audit`: a JSONL writer crate that depends only on `sigil-core`. Follows the [Rust Workspace Style Guide](../RUST-STYLE-GUIDE.md) for crate structure, error handling, lint configuration, and testing conventions.

```text
sigil-memory/
  src/
    lib.rs           # EpisodeWriter, MechanicalConsolidator, public API, crate-level docs
    writer.rs        # Append-only JSONL writer for episodes.jsonl
    consolidator.rs  # Recurrence counting, dedup, expiry, promotion
    reader.rs        # Episode log reading and filtering
    error.rs         # MemoryError enum (thiserror)
```

### Where Types Live

| Type | Crate | Rationale |
|------|-------|-----------|
| `EpisodeEvent` | `sigil-core` | Domain type. Other crates need to construct episodes. Same pattern as `AuditEvent`. |
| `MemoryConfig` | `sigil-core` | Configuration for memory behavior. Lives alongside `IdentitySpec` in session config. |
| `EpisodeWriter` | `sigil-memory` | Implementation detail. Writes `episodes.jsonl`. Parallel to `AuditLogWriter`. |
| `MechanicalConsolidator` | `sigil-memory` | Reads episodes, applies mechanical rules, outputs promotions/expirations. |
| New `LifecycleEvent` variants | `sigil-core` | `PostAction`, `SessionEnd`, `Idle` added to the existing enum. |

### Updated Dependency Graph

```text
sigil-cli → sigil-audit, sigil-bridge, sigil-conductor, sigil-core, sigil-memory, sigil-runtime, sigil-store
sigil-conductor → sigil-audit, sigil-core, sigil-memory, sigil-policy, sigil-runtime, sigil-store
sigil-memory → sigil-core
sigil-bridge → sigil-audit, sigil-core, sigil-policy
sigil-mcp → sigil-core, sigil-policy
sigil-runtime → sigil-core, sigil-policy, sigil-audit [container], sigil-mcp [container]
sigil-store → sigil-core, sigil-policy
sigil-policy → sigil-audit, sigil-core
sigil-audit → sigil-core
sigil-core → (no internal deps)
```

New edges: `sigil-conductor → sigil-memory`, `sigil-cli → sigil-memory`. No cycles. `sigil-memory` is a leaf that depends only on `sigil-core`, same as `sigil-audit`.

### Relationship to Existing Systems

```text
sigil-audit   = security boundary. HMAC-chained. Tamper detection. Never read by agents.
sigil-memory  = operational memory. Append-only JSONL. Read by agents and consolidator.
```

These are separate concerns with separate files, separate writers, and separate trust models. The audit log is a security artifact. The episode log is an operational artifact. They happen to both use JSONL, but that's a format choice, not shared infrastructure.

## Episode Event Schema

### JSONL Format

Each line in `episodes.jsonl` is one `EpisodeEvent` serialized as JSON:

```json
{
  "id": "01JRR3EXAMPLE000000000000",
  "timestamp": "2026-04-11T14:32:00Z",
  "session_id": "01JRR3SESSION000000000000",
  "kind": "ActionCompleted",
  "summary": "Created worktree feature/auth on branch feature/auth",
  "details": {
    "action": "WorktreeCreate",
    "path": "/Users/zebas/Developer/project",
    "branch": "feature/auth"
  },
  "tags": ["worktree", "infrastructure"],
  "source": "conductor"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `EpisodeId` (ULID) | Yes | Unique identifier for this episode. |
| `timestamp` | `OffsetDateTime` (RFC 3339) | Yes | When the episode occurred. |
| `session_id` | `SessionId` | Yes | Which session produced this episode. |
| `kind` | `EpisodeKind` enum | Yes | Category of event (see below). |
| `summary` | `String` | Yes | One-line human-readable summary. |
| `details` | `serde_json::Value` | No | Structured context, schema varies by kind. |
| `tags` | `Vec<String>` | No | Freeform tags for filtering. |
| `source` | `String` | Yes | Who wrote this: `"conductor"`, `"agent"`, `"cli"`. |

### Episode Kinds

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum EpisodeKind {
    /// An action completed (worktree create, session launch, etc.)
    ActionCompleted,
    /// A tool produced a notable outcome
    ToolOutcome,
    /// An approval was granted or denied
    ApprovalDecision,
    /// The user corrected the agent's behavior
    UserCorrection,
    /// The agent proposes a candidate learning
    CandidateLearning,
    /// Session ended — end-of-session summary
    SessionSummary,
    /// State checkpoint (PreCompact snapshot diff)
    StateCheckpoint,
}
```

The enum is `#[non_exhaustive]` so new kinds can be added without breaking downstream.

### Candidate Learning Event

The `CandidateLearning` kind is special — it's the raw material that consolidation promotes into `LEARNINGS.md`:

```json
{
  "id": "01JRR3CANDIDATE00000000000",
  "timestamp": "2026-04-11T15:00:00Z",
  "session_id": "01JRR3SESSION000000000000",
  "kind": "CandidateLearning",
  "summary": "Worktree branches should match the session title for traceability",
  "details": {
    "confidence": "medium",
    "context": "Noticed confusion when worktree branch name didn't match session"
  },
  "tags": ["worktree", "naming"],
  "source": "agent"
}
```

## Write Paths and Permissions

### Who Can Write What

| File | Writer | Permission |
|------|--------|------------|
| `SOUL.md` | Human only | Read-only to all machine processes. Edits require explicit human authorization. |
| `OPS.md` | Human only | Read-mostly. Machine edits require human review and approval. |
| `state.json` | Conductor, agent (via MCP) | Machine-writable. Updated at checkpoints. Schema-checked on write. |
| `LEARNINGS.md` | Consolidator only | Machine-proposed via promotion from episodes. Never directly written by agents during normal execution. |
| `episodes.jsonl` | `EpisodeWriter` | Append-only. Written by conductor, CLI, and agents (via MCP episode-write tool). Never edited, never truncated during normal operation. |

### Write Rules

1. **Agents never write directly to `LEARNINGS.md`.** They emit `CandidateLearning` episodes. The consolidator promotes them.
2. **Agents never write to `SOUL.md` or `OPS.md`.** Period.
3. **`state.json` writes go through the conductor or MCP.** Schema is validated on write. No raw file mutation.
4. **Episodes are append-only.** The consolidator reads episodes but writes to `LEARNINGS.md`. It never modifies `episodes.jsonl`.
5. **The consolidator is the only writer to `LEARNINGS.md`.** It reads existing learnings before writing to deduplicate.

### Trust Model

Memory writes are not in the security boundary (that's `sigil-audit`), but they do follow trust principles:

- `AgentRuntime` trust zone can write episodes and `state.json`.
- `ControlPlane` trust zone (conductor) can write episodes, `state.json`, and promote learnings.
- `HostPrivileged` trust zone (human via CLI) can edit any memory file.
- Sandboxed/low-trust sessions cannot write shared memory (matches existing Sigil policy model).

## Lifecycle Triggers

### Existing Events (from identity reload)

| Event | Currently Fires | Current Action |
|-------|----------------|----------------|
| `PreCompact` | Before compaction | `sigil identity snapshot` — captures state |
| `PostCompact` | After compaction | `sigil identity reload` — re-reads identity files |
| `Restart` | On session restart | Identity reload |
| `SessionStart` | On fresh session start | Identity reload |

### New Events

| Event | When It Fires | Memory Action |
|-------|--------------|---------------|
| `PostAction` | After a conductor-mediated action completes | Append `ActionCompleted` or `ApprovalDecision` episode |
| `SessionEnd` | When a session stops (clean shutdown) | Append `SessionSummary` episode. Flush any pending state to `state.json` |
| `Idle` | When all sessions are idle/waiting for sustained period (conductor heartbeat detects) | Run mechanical consolidation |

### Updated `LifecycleEvent` Enum

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    // Existing
    PostCompact,
    PreCompact,
    Restart,
    SessionStart,
    // New
    PostAction,
    SessionEnd,
    Idle,
}
```

### How Triggers Are Wired

**`PostAction`** — Wired in the conductor. After the conductor processes an `ActionRequest` through the policy engine and executes it, it appends an episode via `EpisodeWriter`. No hook registration needed; this is internal to the conductor loop.

**`SessionEnd`** — Two paths:
1. CLI path: `sigil session stop <name>` appends a `SessionSummary` episode before stopping.
2. Hook path: register a Claude Code `Stop` hook that calls `sigil memory episode session-end <session-id>`. New CLI subcommand.

**`Idle`** — Wired in the conductor's heartbeat loop. When a heartbeat scan returns all sessions in `Waiting` or `Idle` state for N consecutive cycles (configurable, default 3), run the mechanical consolidator. This is a conductor-internal trigger — no external hooks.

## Mechanical Consolidation (Phase 1)

### What It Is

A pure-Rust function that reads `episodes.jsonl` and `LEARNINGS.md`, applies mechanical rules, and outputs a new `LEARNINGS.md`. No LLM. No embeddings. Just counting, matching, and filtering.

### Rules

1. **Recurrence counting.** Track how many times a `CandidateLearning` with a similar summary appears across sessions. "Similar" means exact substring match after lowercasing and stripping punctuation. Not fuzzy — intentionally strict.

2. **Promotion threshold.** A candidate learning is promoted to `LEARNINGS.md` when it appears in 3+ distinct sessions. Configurable via `MemoryConfig.promotion_threshold` (default: 3).

3. **Deduplication.** Before promoting, check if a substantially similar learning already exists in `LEARNINGS.md`. If yes, increment its recurrence count metadata instead of adding a duplicate.

4. **Expiry.** Episodes older than `MemoryConfig.episode_retention_days` (default: 90) are eligible for archival. The consolidator moves them to `episodes.archive.jsonl`. This keeps the active episode log at a manageable size for grep/FTS.

5. **Staleness.** Learnings in `LEARNINGS.md` that haven't been reinforced (no matching candidate learning in the last `MemoryConfig.staleness_days`, default: 180) get a `[stale]` annotation. Not removed — annotated. Human decides whether to keep or prune.

6. **Idempotence.** Running consolidation twice with the same inputs produces the same outputs. No duplication, no accumulation.

### Consolidator Interface

```rust
pub struct MechanicalConsolidator {
    config: MemoryConfig,
}

impl MechanicalConsolidator {
    /// Run one consolidation pass.
    ///
    /// Reads episodes from the log, reads existing learnings,
    /// applies promotion/dedup/expiry/staleness rules,
    /// returns a ConsolidationResult describing what changed.
    pub fn consolidate(
        &self,
        episodes: &[EpisodeEvent],
        existing_learnings: &str,
    ) -> Result<ConsolidationResult, MemoryError>;
}

pub struct ConsolidationResult {
    /// New content for LEARNINGS.md (full replacement, not diff).
    pub learnings_content: String,
    /// Episodes that were archived (older than retention window).
    pub archived_episodes: Vec<EpisodeId>,
    /// Candidate learnings that were promoted.
    pub promoted: Vec<String>,
    /// Existing learnings marked stale.
    pub marked_stale: Vec<String>,
    /// Summary for logging.
    pub summary: String,
}
```

The consolidator is a pure function over its inputs. The conductor calls it and writes the outputs. The consolidator itself does not touch the filesystem.

### Where It Runs

In the conductor's heartbeat loop, triggered by the `Idle` lifecycle event:

```rust
// Inside Conductor::run_heartbeat_cycle(), after the heartbeat scan:
if self.is_idle_for_n_cycles(3) {
    let result = self.consolidator.consolidate(&episodes, &learnings)?;
    if !result.promoted.is_empty() || !result.marked_stale.is_empty() {
        self.write_learnings(&result.learnings_content)?;
        self.archive_episodes(&result.archived_episodes)?;
        info!(promoted = result.promoted.len(),
              stale = result.marked_stale.len(),
              archived = result.archived_episodes.len(),
              "consolidation complete");
    }
}
```

## LLM Consolidation — The Dreamer (Phase 3)

### Why Phase 3

Mechanical consolidation (Phase 1) handles the boring-but-essential work: counting, dedup, expiry. It works without an LLM and covers the majority of consolidation needs.

LLM consolidation adds semantic understanding: merging learnings that say the same thing differently, summarizing episode clusters into insights, and identifying patterns across sessions. This requires a running LLM session — which Sigil can manage as a Sigil-managed session.

UC10 (the meta-test) already proved that Sigil can orchestrate sessions that manage other sessions. The Dreamer is the same pattern applied to memory.

### How It Works (Deferred Design)

The Dreamer is a Sigil-managed session that:

1. Reads `episodes.jsonl` and `LEARNINGS.md`.
2. Uses an LLM to identify semantic clusters, merge similar learnings, summarize episode patterns.
3. Proposes changes to `LEARNINGS.md` as a diff.
4. The conductor reviews and applies the diff (or escalates to human for review).

This is explicitly **not designed yet**. The mechanical consolidator must prove itself first. Designing the Dreamer before we know what mechanical consolidation leaves on the table is premature.

### What Phase 3 Requires

- A working mechanical consolidator (Phase 1).
- A corpus of episodes large enough that mechanical rules are insufficient.
- The conductor's ability to launch and manage a Dreamer session.
- A policy decision: does the Dreamer's output go directly to `LEARNINGS.md`, or does it require human review?

## Retrieval Strategy

### The Ladder

Search in this order. Move to the next rung only when the previous one fails at the actual corpus size:

| Rung | Method | When It's Enough | Cost |
|------|--------|------------------|------|
| 1 | File reads | Identity files, `state.json`, recent episodes | Free |
| 2 | `grep` / substring search | Finding specific learnings, filtering episodes by tag/kind | Free |
| 3 | SQLite FTS | When episode log grows past ~10K lines and grep gets slow | Low — FTS index over episode summaries and learnings |
| 4 | Embeddings | When semantic recall is needed and FTS misses too much | High — requires embedding model, storage, and retrieval pipeline |

### Phase 1 Retrieval

Phase 1 implements rungs 1 and 2 only:

- `sigil memory episodes list [--session <id>] [--kind <kind>] [--tag <tag>] [--since <date>]` — filtered reads over `episodes.jsonl`.
- `sigil memory search <query>` — grep across `LEARNINGS.md` and `episodes.jsonl`.

### Phase 2 Retrieval (Future)

Add a SQLite FTS5 virtual table indexing episode summaries, learning text, and tags. Queried through the same CLI surface, transparently upgraded from grep.

### Phase 4 Retrieval (Future, If Ever)

Embeddings. Only if FTS + metadata filtering is not enough. Never as the sole retrieval mechanism. Always backed by exact search as a fallback.

## Memory Configuration

### `MemoryConfig` Type

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Minimum distinct sessions a candidate learning must appear in
    /// before promotion to LEARNINGS.md.
    pub promotion_threshold: u32,

    /// Days after which episodes are archived.
    pub episode_retention_days: u32,

    /// Days without reinforcement before a learning is marked stale.
    pub staleness_days: u32,

    /// Enable episodic capture (append episodes on lifecycle events).
    pub episodes_enabled: bool,

    /// Enable mechanical consolidation in conductor idle loop.
    pub consolidation_enabled: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            promotion_threshold: 3,
            episode_retention_days: 90,
            staleness_days: 180,
            episodes_enabled: true,
            consolidation_enabled: true,
        }
    }
}
```

### Configuration Source

Extends `.sigil/config.toml`:

```toml
[identity]
files = ["SOUL.md", "OPS.md", "state.json", "LEARNINGS.md"]
reload_on = ["PostCompact", "Restart"]

[memory]
promotion_threshold = 3
episode_retention_days = 90
staleness_days = 180
episodes_enabled = true
consolidation_enabled = true
```

The `[memory]` section is optional. All fields have defaults. Missing section = all defaults.

## CLI Surface

### New Subcommands

```
sigil memory episodes list [--session <id>] [--kind <kind>] [--tag <tag>] [--since <date>] [--json]
sigil memory episodes write <session-id> --kind <kind> --summary <text> [--tags <tags>]
sigil memory search <query> [--json]
sigil memory consolidate [--dry-run]
sigil memory stats [--json]
```

| Command | Purpose |
|---------|---------|
| `episodes list` | Read and filter the episode log. |
| `episodes write` | Manually append an episode (used by hooks). |
| `search` | Grep across learnings and episodes. |
| `consolidate` | Run mechanical consolidation manually. `--dry-run` shows what would change without writing. |
| `stats` | Show episode count, learning count, last consolidation time, stale learning count. |

## File Layout On Disk

```
project/
  SOUL.md                  # read-only identity
  OPS.md                   # read-mostly operating rules
  state.json               # mutable structured state
  LEARNINGS.md             # consolidated learnings (written by consolidator only)
  .sigil/
    config.toml            # project config (identity + memory sections)
    episodes.jsonl         # append-only episode log
    episodes.archive.jsonl # archived episodes (older than retention window)
    consolidation.json     # last consolidation metadata (timestamp, counts)
```

Episodes and consolidation state live in `.sigil/` to keep the project root clean. Identity files stay at the root where agents expect them.

## Implementation Plan

### Phase 1: Episodic Capture + Mechanical Consolidation

Six PRs, merged in order. Each is independently reviewable and leaves the workspace compiling and green.

```text
PR1  Core types (EpisodeEvent, MemoryConfig, new LifecycleEvent variants)
 ↓
PR2  sigil-memory crate (writer + reader + consolidator)
 ↓
PR3  Config parsing ────────────────────────┐
 ↓                                          ↓
PR4  Conductor wiring (episode capture)    PR5  CLI subcommands
 ↓                                          ↓
 └──────────────┬───────────────────────────┘
                ↓
              PR6  Integration test + consolidation in heartbeat loop
```

---

#### PR1: Core Types

**Crates:** `sigil-core`

**What changes:**

- Add `EpisodeEvent`, `EpisodeKind`, `EpisodeId` to `sigil-core` (new file `crates/sigil-core/src/episode.rs`).
- Add `MemoryConfig` to `sigil-core/src/config.rs` alongside `ProjectConfig`.
- Extend `LifecycleEvent` enum with `PostAction`, `SessionEnd`, `Idle` variants.
- Add `memory: Option<MemoryConfig>` to `SessionConfig`.
- Re-export new types from `sigil-core/src/lib.rs`.

**Tests:**

- `EpisodeEvent` serde round-trip.
- `EpisodeKind` equality.
- `MemoryConfig::default()` values.
- New `LifecycleEvent` variants parse correctly in config.

**Review checklist:**

- [ ] No new external dependencies (uses existing `serde`, `time`, ULID from `sigil-core`)
- [ ] `LifecycleEvent` enum extension is backwards-compatible (`#[non_exhaustive]`)
- [ ] New types have doc comments per [style guide](../RUST-STYLE-GUIDE.md) section 10
- [ ] `cargo test -p sigil-core`

---

#### PR2: `sigil-memory` Crate

**Crates:** New `sigil-memory`

**What changes:**

- Create `crates/sigil-memory/` with `Cargo.toml` depending on `sigil-core`.
- `writer.rs`: `EpisodeWriter` — append-only JSONL writer for `episodes.jsonl`. Mutex-guarded file handle (same pattern as `AuditLogWriter`, minus the HMAC chain).
- `reader.rs`: `EpisodeReader` — reads and filters episodes from `episodes.jsonl` by session, kind, tag, date range.
- `consolidator.rs`: `MechanicalConsolidator` — pure function. Takes episodes + existing learnings text, returns `ConsolidationResult`.
- `error.rs`: `MemoryError` enum (`thiserror`).
- `lib.rs`: public API.
- Add `sigil-memory` to workspace `Cargo.toml`.

**Tests:**

- Writer: append events, read them back, verify JSONL format.
- Writer: concurrent appends don't interleave.
- Reader: filter by kind, session, tag, date range.
- Consolidator: candidate appearing 3x in 3 sessions gets promoted.
- Consolidator: candidate appearing 2x does not get promoted.
- Consolidator: duplicate candidate doesn't create duplicate learning.
- Consolidator: stale learning gets annotated.
- Consolidator: idempotence — same input produces same output.
- Consolidator: episodes older than retention window are flagged for archival.

**Dependencies:**

- `sigil-core` (workspace)
- `serde`, `serde_json` (existing workspace deps)
- `time` (existing workspace dep)
- `thiserror` (existing workspace dep)
- `tracing` (existing workspace dep)

**Crate setup per [Rust Style Guide](../RUST-STYLE-GUIDE.md):**

- `Cargo.toml` uses `edition.workspace = true`, `rust-version.workspace = true`, `[lints] workspace = true`.
- All workspace dependencies referenced with `.workspace = true`.
- `proptest` in `[dev-dependencies]` for property-based testing of consolidator invariants.
- `MemoryError` uses `thiserror` (library crate pattern, per style guide section 5).
- All public types and functions have doc comments (style guide section 10).
- `EpisodeKind` uses `#[non_exhaustive]` (matches `exhaustive_enums = "warn"` lint).

**Review checklist:**

- [ ] No HMAC chain — this is operational memory, not a security boundary
- [ ] Writer is `Send + Sync`
- [ ] Consolidator is a pure function, does not touch filesystem
- [ ] No `unwrap()` in library code (workspace lint: `unwrap_used = "deny"`)
- [ ] `cargo fmt && cargo clippy -p sigil-memory -- -D warnings && cargo test -p sigil-memory`

---

#### PR3: Config Parsing Extension

**Crates:** `sigil-core`

**What changes:**

- Add `MemoryConfigSection` to `config.rs` and wire it into `ProjectConfig`.
- Add parsing for `[memory]` section in `.sigil/config.toml`.
- Add `into_memory_config()` validator (same pattern as `IdentityConfigSection::into_spec()`).

**Tests:**

- Parse valid `[memory]` section.
- Missing `[memory]` section returns defaults.
- Invalid values return `CoreError::InvalidConfig`.
- `--memory-episodes` / `--memory-consolidation` CLI flags (if needed, or defer to config-only).

---

#### PR4: Conductor Wiring — Episode Capture

**Crates:** `sigil-conductor` (depends on PR1, PR2)

**What changes:**

- Add `sigil-memory` dependency to `sigil-conductor/Cargo.toml`.
- `Conductor` struct gains an `Arc<EpisodeWriter>`.
- After `run_heartbeat_cycle()` processes actions, append `ActionCompleted` episodes.
- After `handle_message()` processes bridge commands that trigger actions, append episodes.
- Wire `Idle` detection: track consecutive idle heartbeat cycles, trigger consolidation after N cycles.

**Tests:**

- Heartbeat cycle with completed action produces an episode.
- Idle detection triggers after configured consecutive cycles.
- Episode is appended with correct session_id and kind.

---

#### PR5: CLI Subcommands

**Crates:** `sigil-cli` (depends on PR1, PR2)

**What changes:**

- Add `Memory(MemoryCommands)` variant to top-level `Commands` enum.
- Implement `sigil memory episodes list`, `episodes write`, `search`, `consolidate`, `stats`.
- Wire `EpisodeWriter` initialization in CLI startup (same pattern as `AuditLogWriter`).

**Tests:**

- CLI integration: `sigil memory episodes list` with empty log returns empty output.
- CLI integration: `sigil memory consolidate --dry-run` with no episodes reports nothing to do.
- CLI integration: `sigil memory stats` shows zeros for fresh project.

---

#### PR6: Integration Test + Consolidation in Heartbeat

**Crates:** `sigil-cli`, `sigil-conductor` (depends on PR4, PR5)

**What changes:**

- End-to-end integration test in `crates/sigil-cli/tests/uc_memory.rs`:
  1. Create a session with memory config enabled.
  2. Simulate actions that produce episodes.
  3. Write candidate learnings across 3+ sessions.
  4. Run `sigil memory consolidate`.
  5. Assert: candidate learning promoted to `LEARNINGS.md`.
  6. Run consolidation again — assert idempotent (no duplicates).
  7. Assert: old episodes flagged for archival.
- Wire consolidation into conductor heartbeat idle path.
- Update `docs/ARCHITECTURE.md` with new crate and CLI surface.

**Tests:**

- Full lifecycle: create session -> produce episodes -> consolidate -> verify learnings.
- Idempotence: double consolidation produces same result.
- Archival: old episodes moved to archive file.

---

### Phase 2: Better Retrieval (Future)

- SQLite FTS5 index over episode summaries and learnings.
- `sigil memory search` transparently upgrades from grep to FTS.
- Scoped queries by session, conductor, topic.

### Phase 3: The Dreamer (Future)

- Dreamer session management in conductor.
- LLM-powered semantic consolidation.
- Policy decision on Dreamer output review.

### Phase 4: Semantic Recall (Future, If Ever)

- Embedding-based retrieval.
- Only if FTS + metadata filtering proves insufficient.

## Style Guide Compliance

The `sigil-memory` crate follows the [Rust Workspace Style Guide](../RUST-STYLE-GUIDE.md). Key compliance points:

| Style Guide Section | How It Applies |
|---------------------|----------------|
| **5. Error Handling** | `MemoryError` uses `thiserror` with typed variants (`Write`, `Read`, `Serialize`, `Consolidation`). Keep variant count under 10. All use `#[source]` or `#[from]` to preserve error chains. Application code in `sigil-cli` wraps with `anyhow::Context`. |
| **7. Testing** | Unit tests in `#[cfg(test)]` modules per source file. Property-based tests with `proptest` for consolidator invariants (idempotence, promotion threshold). Test naming: `<function>_<condition>_<expected>`. No mocking frameworks — trait-based test doubles. |
| **3. Lint Configuration** | Inherits workspace lints via `[lints] workspace = true`. No crate-level overrides needed. `EpisodeKind` and `EpisodeEvent` use `#[non_exhaustive]` to satisfy `exhaustive_enums` lint. |
| **9. Architecture** | Trait-based boundary: `sigil-core` defines the `EpisodeEvent` type, `sigil-memory` provides the writer implementation. Same pattern as `AuditEvent`/`AuditLogWriter`. |
| **10. Documentation** | All public items get doc comments. `lib.rs` gets crate-level `//!` docs explaining the module's role and relationship to `sigil-audit`. `# Errors` sections on all public functions returning `Result`. |
| **8. Security** | Episode file paths validated against the session's working directory. No user-controlled paths passed directly to `std::fs`. Tags and summaries are treated as untrusted input with length limits. |

### Error Type Sketch

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("failed to write episode")]
    Write(#[source] std::io::Error),

    #[error("failed to read episode log")]
    Read(#[source] std::io::Error),

    #[error("episode serialization error")]
    Serialize(#[from] serde_json::Error),

    #[error("consolidation failed: {message}")]
    Consolidation { message: String },

    #[error("invalid memory config: {message}")]
    InvalidConfig { message: String },
}
```

Conversion to `CoreError` via `From<MemoryError>` in `sigil-core` or at the call site, following the cross-crate error conversion pattern (style guide section 9).

## Design Decisions (Resolved Apr 11, 2026)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Separate episodic log from audit.** `episodes.jsonl` is a new file, not a reuse of `sigil-audit`. | Audit is a security boundary (HMAC-chained, tamper-detected). Memory events are operational. Different concerns, different trust models, different files. Mixing them would either weaken audit integrity or over-constrain memory writes. |
| 2 | **Triggers live in `sigil-runtime`/`sigil-core`.** The `LifecycleEvent` enum grows with new variants. `sigil-memory` is a consumer, not the owner of trigger points. | Other crates may consume lifecycle events for non-memory purposes (monitoring, metrics, bridge notifications). Memory doesn't own the lifecycle. |
| 3 | **Dreamer is phased.** Phase 1 is mechanical consolidation (no LLM). Phase 3 is LLM-powered semantic consolidation. | Mechanical consolidation covers the 80% case (dedup, counting, expiry). Designing the Dreamer before we know what mechanical consolidation leaves on the table is speculative. UC10 proved the orchestration pattern works, so Phase 3 is feasible when needed. |
| 4 | **Episodes live in `.sigil/`, identity files stay at project root.** | Agents expect `SOUL.md` and `LEARNINGS.md` at the project root. Episodes and consolidation metadata are infrastructure — they belong in `.sigil/` alongside `config.toml`. |
| 5 | **Consolidator is a pure function.** It takes inputs and returns outputs. It does not touch the filesystem. | Testability. The conductor handles I/O. The consolidator handles logic. Same separation as `sigil-policy::Evaluator` being pure over its inputs. |

## Open Questions

| # | Question | Notes |
|---|----------|-------|
| 1 | **Should agents be able to write episodes directly?** The design allows it via `source: "agent"` and an MCP tool, but should we gate this behind policy? An agent writing misleading candidate learnings could pollute `LEARNINGS.md` after enough repetitions. | Leaning toward: yes, but candidates from `AgentRuntime` zone require higher promotion threshold (5 instead of 3). |
| 2 | **Episode log rotation vs archival.** The current design archives old episodes to `episodes.archive.jsonl`. Should we rotate by size instead of (or in addition to) age? | Leaning toward: age-based first, add size rotation if needed. |
| 3 | **Cross-session learnings.** The promotion threshold counts "distinct sessions." What about learnings that are project-wide vs session-specific? Should there be a scope field? | Leaning toward: defer. Start with project-wide learnings only. Add scoping if the flat model gets noisy. |
| 4 | **`LEARNINGS.md` format.** Currently freeform markdown. Should the consolidator impose a structured format (e.g., YAML frontmatter per learning with recurrence count, last-seen date, source sessions)? | Leaning toward: yes, light structure. Markdown body for human readability, with a metadata comment per learning for machine parsing. |
| 5 | **MCP episode-write tool.** Should `sigil-mcp` expose an `episode.write` tool so container-backed agents can emit episodes through the MCP socket? | Leaning toward: yes (Phase 2, when container memory support is needed). |

## Relationship to Other Design Docs

- **[identity-reload.md](./identity-reload.md):** Identity reload is Phase 1 of the memory lifecycle (reload after compaction). This design picks up where identity reload left off — it adds episodic capture, consolidation, and the remaining lifecycle triggers.
- **[identity-reload-plan.md](./identity-reload-plan.md):** Format reference for the PR sequence.
- **[memory-systems-2026.md](../research/memory-systems-2026.md):** Research that informed these decisions. The "Recommendations for Sigil" section maps directly to this design.
