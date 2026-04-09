# Identity Reload — Implementation Plan

**Date:** April 9, 2026
**Scope:** Phase 1 only (Core + Claude Code backend)
**Parent doc:** [identity-reload.md](./identity-reload.md)
**Research:** [memory-systems-2026.md](../research/memory-systems-2026.md)

## Overview

Five PRs, merged in order. Each is independently reviewable and leaves the workspace compiling and green. Total touch surface: `sigil-core`, `sigil-store`, `sigil-runtime`, `sigil-cli`.

```text
PR1  Core types
 ↓
PR2  Store migration ──────┐
 ↓                         ↓
PR3  Config + CLI flag    PR4  TmuxRuntime hooks
 ↓                         ↓
 └────────┬────────────────┘
          ↓
        PR5  CLI command + integration test
```

---

## PR1: Core Types — `IdentitySpec`, `LifecycleEvent`, `LifecycleHooks`

**Crates:** `sigil-core`

### What changes

**`crates/sigil-core/src/session.rs`**

Add `IdentitySpec` and `LifecycleEvent` types:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IdentitySpec {
    pub files: Vec<PathBuf>,
    pub reload_on: Vec<LifecycleEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleEvent {
    PostCompact,
    Restart,
    SessionStart,
}
```

Add `identity` field to both structs:

| Struct | Field | Type | Line ref |
|--------|-------|------|----------|
| `SessionConfig` | `identity` | `Option<IdentitySpec>` | `:33–44` |
| `SessionRecord` | `identity` | `Option<IdentitySpec>` | `:61–72` |
| `SessionHandle` | `identity` | `Option<IdentitySpec>` | `:47–58` |

`Option<IdentitySpec>` rather than `IdentitySpec` — sessions created before this feature have no identity spec, and the default is "no identity files, no hooks." This avoids a breaking migration for existing sessions.

**`crates/sigil-core/src/traits.rs`**

Add the `LifecycleHooks` extension trait alongside `SessionRuntime` (`:14`):

```rust
pub trait LifecycleHooks: Send + Sync {
    fn register_identity_hooks(
        &self,
        handle: &SessionHandle,
        spec: &IdentitySpec,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}
```

This is a separate trait, not added to `SessionRuntime`. Not every runtime backend supports hook registration (containers don't in Phase 1). Code that needs hooks does a trait bound `R: SessionRuntime + LifecycleHooks` or checks at the call site.

### Tests

- Unit tests for `IdentitySpec` serde round-trip (serialize → deserialize).
- `LifecycleEvent` equality / display.
- `IdentitySpec::default()` returns empty files and empty `reload_on`.

### Review checklist

- [ ] No new dependencies added
- [ ] All existing tests still pass (the new fields are `Option`, so existing construction sites compile)
- [ ] `cargo clippy --workspace`

---

## PR2: Store Migration — Persist `IdentitySpec`

**Crates:** `sigil-store` (depends on PR1)

### What changes

**`crates/sigil-store/src/migrate.rs`**

Add migration V002 (or next available version):

```sql
ALTER TABLE sessions ADD COLUMN identity_json TEXT;
```

Stored as a JSON string. `NULL` means no identity spec. This matches how other optional structured fields are stored.

**`crates/sigil-store/src/session.rs`**

| Function | Change |
|----------|--------|
| `create_session()` (`:23–52`) | Insert `identity_json` column — serialize `record.identity` to JSON if `Some`. |
| `row_to_session()` (`:176–220`) | Read `identity_json` column — deserialize to `Option<IdentitySpec>`. |
| `get_session()` (`:60–71`) | No change (uses `row_to_session`). |
| `list_sessions()` (`:98–104`) | No change (uses `row_to_session`). |
| New: `update_session_identity()` | `pub async fn update_session_identity(&self, id: &SessionId, spec: Option<IdentitySpec>) -> Result<(), StoreError>` |

The new `update_session_identity` function is needed so the CLI can write the resolved identity spec to the store after merging config sources.

### Tests

- Create a session with `identity: Some(spec)`, read it back, assert round-trip.
- Create a session with `identity: None`, read it back, assert `None`.
- `update_session_identity` on existing session.
- Migration applies cleanly on a fresh database and on a database with existing sessions (existing rows get `NULL`).

### Review checklist

- [ ] Migration is additive (ALTER TABLE ADD COLUMN), not destructive
- [ ] Existing sessions with `NULL` identity_json deserialize to `None`
- [ ] `cargo test -p sigil-store`

---

## PR3: Config Parsing + `--identity` CLI Flag

**Crates:** `sigil-cli`, `sigil-core` (depends on PR1)

### What changes

**New file: `crates/sigil-core/src/config.rs`**

Project-level config parser for `.sigil/config.toml`:

```rust
#[derive(Debug, Deserialize, Default)]
pub struct ProjectConfig {
    pub identity: Option<IdentityConfigSection>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityConfigSection {
    pub files: Vec<PathBuf>,
    pub reload_on: Option<Vec<String>>,
}

impl ProjectConfig {
    pub fn load(project_dir: &Path) -> Result<Option<Self>, CoreError> { ... }
}

impl IdentityConfigSection {
    pub fn into_spec(self) -> Result<IdentitySpec, CoreError> { ... }
}
```

Uses `toml` crate for parsing. Add `toml` as a dependency of `sigil-core`. The `into_spec` method validates `reload_on` strings → `LifecycleEvent` enum variants.

**`crates/sigil-core/src/lib.rs`**

Export `config` module.

**`crates/sigil-cli/src/lib.rs`**

Add `--identity` flag to `session create` and `session launch` subcommands (`:83–180`):

```rust
/// Comma-separated identity files (e.g., SOUL.md,OPS.md,state.json).
/// Overrides .sigil/config.toml [identity] section.
#[arg(long)]
identity: Option<String>,
```

**New function: `resolve_identity_spec()`**

In `crates/sigil-cli/src/commands/session.rs`, add a function that implements the priority chain:

```rust
fn resolve_identity_spec(
    cli_flag: Option<&str>,
    project_dir: &Path,
) -> Result<Option<IdentitySpec>> {
    // 1. CLI flag (highest priority)
    // 2. .sigil/config.toml [identity] section
    // 3. None (no identity spec)
}
```

Called during `session create` and `session launch`. The resolved spec is stored on the `SessionConfig`.

### Tests

- Parse a valid `.sigil/config.toml` with identity section.
- Parse a `.sigil/config.toml` without identity section → `None`.
- Missing `.sigil/config.toml` → `None` (not an error).
- CLI flag overrides config file.
- Invalid `reload_on` value → `CoreError::InvalidConfig`.
- Empty `--identity ""` → empty files list (explicit "no identity").

### New dependency

- `toml` crate added to `sigil-core/Cargo.toml` (lightweight, no async, well-maintained).

### Review checklist

- [ ] `toml` version pinned
- [ ] Config parsing does not panic on malformed TOML (returns error)
- [ ] CLI flag parsing handles edge cases (trailing commas, spaces)

---

## PR4: TmuxRuntime Hook Registration

**Crates:** `sigil-runtime` (depends on PR1)

### What changes

**`crates/sigil-runtime/src/tmux.rs`**

Implement `LifecycleHooks` for `TmuxRuntime`:

```rust
impl LifecycleHooks for TmuxRuntime {
    async fn register_identity_hooks(
        &self,
        handle: &SessionHandle,
        spec: &IdentitySpec,
    ) -> Result<(), CoreError> { ... }
}
```

The implementation:

1. Checks if `spec.reload_on` contains `PostCompact`.
2. If yes, reads or creates `.claude/settings.local.json` in `handle.path`.
3. Adds a hook entry:

```json
{
  "hooks": {
    "PostCompact": [
      {
        "type": "command",
        "command": "sigil identity reload SESSION_ID"
      }
    ]
  }
}
```

4. Writes the file back. Merges with existing hooks — does not clobber other hook entries.

**New helper: `write_claude_hook()`**

Private function in `tmux.rs` that handles the JSON read-merge-write for `.claude/settings.local.json`. This is the only fiddly part — needs to handle:

- File doesn't exist yet → create with just the hook.
- File exists but has no `hooks` key → add `hooks`.
- File exists with existing hooks → merge, don't duplicate.

Uses `serde_json` (already a dependency of `sigil-runtime`).

### Tests

- Register hooks on a temp directory, verify `.claude/settings.local.json` content.
- Register hooks when file already exists with other hooks — verify merge.
- Register hooks when `reload_on` is empty — verify no file written.
- Register hooks when `reload_on` contains only `Restart` (no `PostCompact`) — verify no Claude hook written.

### Design decision: `.claude/settings.local.json`

Project-level, not user-level. Scoped to the session's working directory. This means:

- Different sessions in different directories get independent hooks.
- The hook file lives alongside the project, not in `~/.claude/`.
- `.claude/settings.local.json` is already in `.gitignore` for most projects (Claude Code convention).

This resolves Open Question 1 from the design doc.

---

## PR5: `sigil identity reload` CLI Command + Integration Test

**Crates:** `sigil-cli` (depends on PR2, PR4)

### What changes

**`crates/sigil-cli/src/lib.rs`**

Add `Identity(IdentityCommands)` variant to the `Commands` enum (`:50–81`):

```rust
/// Identity file management.
#[command(subcommand)]
Identity(IdentityCommands),
```

New enum:

```rust
#[derive(Debug, Subcommand)]
pub enum IdentityCommands {
    /// Reload identity files into an active session.
    Reload {
        /// Session name or ID.
        name: String,
    },
}
```

**New file: `crates/sigil-cli/src/commands/identity.rs`**

Handler:

```rust
pub async fn reload<R: SessionRuntime>(
    name: &str,
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
) -> Result<()> {
    // 1. Resolve session by name/title
    let record = store.get_session_by_title(name).await?;
    // 2. Get identity spec (bail if None)
    let spec = record.identity
        .ok_or_else(|| anyhow!("session '{}' has no identity spec configured", name))?;
    // 3. Build reload message
    let message = build_reload_message(&spec);
    // 4. Send to session via runtime
    let handle = SessionHandle::from(&record);
    runtime.send(&handle, ConductorMessage::text(&message)).await?;
    // 5. Audit event
    audit.append(/* identity_reload event */)?;
    Ok(())
}
```

**`build_reload_message()` function:**

```rust
fn build_reload_message(spec: &IdentitySpec) -> String {
    let file_list = spec.files.iter()
        .map(|f| f.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Re-read your identity files in this order: {file_list}. \
         These files define who you are and how you operate. \
         Read each one now."
    )
}
```

Hardcoded message — resolves Open Question 3 from the design doc. Simple wins.

**Wire into session create/launch flow:**

In `crates/sigil-cli/src/commands/session.rs`, after session creation:

```rust
// After runtime.launch() succeeds:
if let Some(ref spec) = config.identity {
    if let Some(hooks_runtime) = runtime_as_lifecycle_hooks() {
        hooks_runtime.register_identity_hooks(&handle, spec).await?;
    }
}
```

The `session create` and `session launch` commands call `resolve_identity_spec()` (from PR3), store the result on `SessionConfig`, persist it via the store (PR2), and register hooks (PR4).

### Integration test

**`crates/sigil-cli/tests/uc_identity.rs`**

Test scenario:

1. Create a temp project directory with `.sigil/config.toml` containing an identity section.
2. Create identity files (`SOUL.md`, `OPS.md`, `state.json`) in the directory.
3. `sigil session create` with `--identity SOUL.md,OPS.md,state.json`.
4. Assert: session record in store has `identity` field populated.
5. Assert: `.claude/settings.local.json` exists with `PostCompact` hook pointing to `sigil identity reload <session-id>`.
6. `sigil identity reload <session-name>`.
7. Assert: session received a reload message (check via `session output`).
8. Assert: audit log contains an identity reload event.

This test requires tmux. Gate it like existing integration tests — skip if tmux is not available.

### Review checklist

- [ ] `sigil identity reload` with no identity spec returns a clear error, not a panic
- [ ] Reload message includes all files in declared order
- [ ] Audit event is recorded
- [ ] Hook wiring is conditional (only when `LifecycleHooks` is implemented)
- [ ] Integration test is self-contained (creates and cleans up its own temp dir)

---

## Dependency Map (Summary)

| PR | Crates touched | Depends on | Key types/functions |
|----|---------------|------------|---------------------|
| PR1 | `sigil-core` | — | `IdentitySpec`, `LifecycleEvent`, `LifecycleHooks` trait, fields on `SessionConfig`/`SessionRecord`/`SessionHandle` |
| PR2 | `sigil-store` | PR1 | Migration V002, `update_session_identity()`, `row_to_session()` changes |
| PR3 | `sigil-core`, `sigil-cli` | PR1 | `ProjectConfig`, `resolve_identity_spec()`, `--identity` flag, `toml` dep |
| PR4 | `sigil-runtime` | PR1 | `LifecycleHooks for TmuxRuntime`, `write_claude_hook()` |
| PR5 | `sigil-cli` | PR2, PR4 | `IdentityCommands::Reload`, `identity::reload()`, `build_reload_message()`, integration test |

PR2, PR3, and PR4 can be developed in parallel after PR1 merges. PR5 waits for PR2 and PR4.

---

## Open Questions Resolved

| # | Question | Decision |
|---|----------|----------|
| 1 | Hook file location | `.claude/settings.local.json` in the project directory (PR4). |
| 2 | Session ID stability | Use session title for the CLI command (`sigil identity reload <name>`), resolved to `SessionId` via store lookup. Titles are unique and human-friendly. |
| 3 | Reload message format | Hardcoded imperative message. Not configurable. |
| 4 | PreCompact snapshot | Deferred to Phase 2 per the design doc. |

---

## Files Created or Modified (Complete List)

```text
Created:
  crates/sigil-core/src/config.rs            (PR3)
  crates/sigil-cli/src/commands/identity.rs   (PR5)
  crates/sigil-cli/tests/uc_identity.rs       (PR5)

Modified:
  crates/sigil-core/src/session.rs            (PR1)
  crates/sigil-core/src/traits.rs             (PR1)
  crates/sigil-core/src/lib.rs                (PR1, PR3)
  crates/sigil-core/Cargo.toml                (PR3 — toml dep)
  crates/sigil-store/src/migrate.rs           (PR2)
  crates/sigil-store/src/session.rs           (PR2)
  crates/sigil-runtime/src/tmux.rs            (PR4)
  crates/sigil-cli/src/lib.rs                 (PR3, PR5)
  crates/sigil-cli/src/commands/mod.rs        (PR5)
  crates/sigil-cli/src/commands/session.rs    (PR3, PR5)
  docs/ARCHITECTURE.md                        (PR5 — add identity command to CLI surface)
```

---

## Risk Notes

- **Claude Code hook format stability:** The `.claude/settings.local.json` hook schema is based on current Claude Code docs. If Anthropic changes the format, PR4's `write_claude_hook()` breaks. Mitigation: the hook write is isolated in one function, easy to update.
- **tmux test dependency:** The integration test needs tmux. Existing tests already handle this (skip-if-unavailable pattern). Follow the same approach.
- **toml dependency in sigil-core:** Adding `toml` to the foundational crate. It's a small, zero-async crate with no transitive risk, but worth noting. Alternative: put config parsing in `sigil-cli` instead. Trade-off: other crates can't reuse the parser. Recommendation: keep it in `sigil-core` — config is a domain concept.
