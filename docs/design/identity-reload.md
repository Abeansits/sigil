# Identity Reload — Design Document

**Date:** April 9, 2026
**Status:** Draft — awaiting Sebastian's review
**Problem:** After context compaction, agents lose identity files (SOUL.md, OPS.md, state.json) from context. No automatic mechanism to reload. Relies on human reminders, which fail.

## Guiding Principle

Simple Made Easy. A flat file with a hook that fires on compaction beats a vector database nobody remembers to query. Fix the behavior, not the storage.

## Current State

### What Exists
- Identity files: `SOUL.md` (persona), `OPS.md` (operating rules), `state.json` (current truth), `LEARNINGS.md` (shared patterns)
- CLAUDE.md startup checklist says "read these files" — but that only fires on fresh session start, not after compaction
- Claude Code exposes `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd` hooks
- `agent-deck hook-handler` already fires on `PreCompact` (for session state preservation)
- Sigil's conductor is generic over `SessionRuntime`

### What's Broken
- After compaction, the agent has no reminder to reload identity files
- The startup checklist is in CLAUDE.md (which survives compaction), but the instruction to "read SOUL.md" doesn't force a re-read — the model has to notice and act on it
- Manual reminders work but scale poorly and fail when the human is asleep

## Design

### Layer 1: IdentitySpec (sigil-core)

A session declares which files constitute its identity and when to reload them.

```rust
/// Files that define an agent session's identity and operating context.
/// These are reloaded on lifecycle events (compaction, restart, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentitySpec {
    /// Paths relative to the session's working directory.
    /// Loaded in order — identity first, then state, then learnings.
    pub files: Vec<PathBuf>,

    /// Which lifecycle events trigger a reload.
    pub reload_on: Vec<LifecycleEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// After context compaction completes.
    PostCompact,
    /// On session restart (e.g., agent-deck restart, sigil session restart).
    Restart,
    /// On fresh session start.
    SessionStart,
}

impl Default for IdentitySpec {
    fn default() -> Self {
        Self {
            files: vec![],
            reload_on: vec![LifecycleEvent::PostCompact, LifecycleEvent::Restart],
        }
    }
}
```

### Layer 2: Hook Registration (sigil-runtime)

Each runtime backend registers hooks with its agent tool. This is an implementation detail — the conductor doesn't know or care how the hook works.

**For Claude Code (TmuxRuntime):**
- On session create, if `identity_spec.reload_on` includes `PostCompact`:
  - Write a hook entry to `.claude/settings.local.json` (or the project hooks file) in the session's working directory
  - Hook command: `sigil identity reload <session-id>`
  - Hook event: `PostCompact`

**For Apple Containers (ContainerRuntime):**
- Container sessions don't have Claude Code hooks
- Alternative: the conductor polls session state and detects compaction via output markers, or the MCP server signals it
- Deferred — container identity reload is Phase 2

```rust
/// Extension trait for runtimes that support lifecycle hook registration.
pub trait LifecycleHooks {
    /// Register hooks for the given identity spec.
    /// Called once during session creation.
    fn register_identity_hooks(
        &self,
        session: &SessionHandle,
        spec: &IdentitySpec,
    ) -> Result<(), CoreError>;
}
```

### Layer 3: Reload Action (sigil-cli)

New CLI subcommand:

```
sigil identity reload <session-id>
```

What it does:
1. Look up the session in the store
2. Read the session's `IdentitySpec`
3. Build a reload message: "Re-read your identity files in this order: SOUL.md, OPS.md, state.json. These files define who you are and how you operate. Read each one now."
4. Send the message to the session via the runtime (`session send`)

The message is explicit and imperative — not a hint. It tells the agent exactly what to do.

### Layer 4: Configuration

Where does the identity spec come from? Three sources, in priority order:

1. **CLI flag** (highest priority):
   ```
   sigil session create ~/project --identity SOUL.md,OPS.md,state.json
   ```

2. **Project config** (`.sigil/config.toml` in the project directory):
   ```toml
   [identity]
   files = ["SOUL.md", "OPS.md", "state.json"]
   reload_on = ["PostCompact", "Restart"]
   ```

3. **Default** (lowest priority): empty identity spec (no files, no hooks).

The CLI flag overrides the project config. The project config overrides the default.

## The Flow

```
Session create
  ├── identity_spec from config/flag/default
  ├── store identity_spec in session record
  └── runtime.register_identity_hooks(session, spec)
        └── [Claude Code] writes PostCompact hook to .claude/settings.local.json

... agent works ...

Context compaction happens
  └── Claude Code fires PostCompact hook
        └── runs: sigil identity reload <session-id>
              ├── reads IdentitySpec from store
              ├── builds reload message
              └── sends message to session via runtime
                    └── agent re-reads SOUL.md, OPS.md, state.json
```

## What This Does NOT Do

- Does not inject file contents into context directly (the agent reads them itself)
- Does not modify CLAUDE.md or any identity files
- Does not require a running conductor (the hook calls the sigil binary directly)
- Does not handle memory consolidation (that's the Dreamer, separate concern)
- Does not add embedding retrieval or vector search

## Design Decisions (Resolved Apr 9, 2026)

1. **Hook installation location:** Project-level (`.claude/settings.local.json`). Committable with the repo — the feature travels with the project. Investigate how agent-deck handles hooks for reference.

2. **Session identifier:** ULID from the sigil store. Stable in any normal scenario (SQLite persists on disk). Only lost if the database is manually deleted, which is an edge case. Hook is written at session creation time when the ULID is known. Multiple sessions per path is a valid pattern (research + build, review + implement), so path alone is not sufficient.

3. **Reload message format:** Hardcoded imperative message. Simple and easy. The agent just needs a clear instruction, not a custom prompt. Less to configure, less to break.

4. **PreCompact snapshot:** Yes, included in Phase 1. Capture current state to disk while the agent still has full context, then reload the fresh snapshot after compaction.

## Implementation Plan

### Phase 1: Core + Claude Code backend + PreCompact
- Add `IdentitySpec` and `LifecycleEvent` to `sigil-core`
- Add `identity` field to `SessionConfig` and `SessionRecord`
- Implement `LifecycleHooks` for `TmuxRuntime` (writes Claude Code hooks)
- Add `sigil identity reload` CLI subcommand (uses ULID)
- Add `sigil identity snapshot` CLI subcommand (PreCompact state capture)
- Register both PostCompact (reload) and PreCompact (snapshot) hooks
- Add `.sigil/config.toml` parsing
- Integration test: create session with identity spec, simulate PreCompact + PostCompact, verify snapshot written and reload message sent

### Phase 2: Container backend
- Implement identity reload for `ContainerRuntime`

### Phase 3: Evaluate
- Does the reload actually work reliably?
- Does the agent follow the instruction?
- Do we need to inject content directly instead of asking the agent to read?

## Relationship to Memory System

This is the "narrow reload at resume time" pattern from the memory research. It's Phase 1 of the memory lifecycle — the simplest, most impactful fix.

The full memory lifecycle (from the research) is:
1. **Reload identity after compaction** ← this design
2. **Write episodes after actions** ← future: episodic memory feed
3. **Snapshot state before compaction** ← Phase 2 of this design
4. **Consolidate during idle time** ← future: the Dreamer
5. **Search memory on demand** ← future: FTS, then maybe embeddings

Each phase is independent and delivers value on its own.
