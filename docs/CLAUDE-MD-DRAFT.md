# CLAUDE.md — agent-ops

## What This Is

A Rust workspace replacing agent-deck (Go) + bridge.py (Python). Single binary for managing AI agent sessions with security baked in.

**Proposal:** `~/.agent-deck/conductor/ops/drafts/rewrite-proposal.md` — read this for full architecture, Action enum, trust zones, and build order.

## Workspace

```
agent-ops/
  Cargo.toml          # Virtual manifest (workspace root)
  rustfmt.toml
  clippy.toml
  deny.toml
  crates/
    ops-core/          # Action enum, ActionOrigin, traits, domain models
    ops-policy/        # Trust zones, tier eval, grants, input sanitization
    ops-audit/         # JSONL + HMAC chain
    ops-store/         # SQLite + migrations
    ops-runtime/       # SessionRuntime trait, tmux backend, hooks
    ops-bridge/        # Telegram + Slack adapters
    ops-conductor/     # Heartbeat, escalation, child coordination
    ops-container/     # Apple Container lifecycle
    ops-cli/           # clap commands, JSON output
```

## Dependency Graph (no cycles)

```
ops-cli → ops-conductor, ops-bridge, ops-runtime, ops-store, ops-policy, ops-core
ops-conductor → ops-runtime, ops-store, ops-policy, ops-audit, ops-core
ops-bridge → ops-store, ops-policy, ops-audit, ops-core
ops-runtime → ops-store, ops-policy, ops-core
ops-container → ops-store, ops-policy, ops-core
ops-store → ops-core
ops-policy → ops-audit, ops-core
ops-audit → ops-core
ops-core → (no internal deps)
```

Bridge and conductor never depend on each other. Both use traits in `ops-core` (`MessageSink`, `MessageSource`, `ActionRouter`).

## Critical Design Rules

1. **The Action enum is the sole authority-bearing protocol.** No string commands cross module boundaries. Every operation is a typed Action variant with an ActionOrigin.

2. **Every function that does anything takes `&PolicyContext`.** This was set up in Step 2 intentionally. If you're writing a function that doesn't take a policy context, ask yourself why.

3. **`unsafe` is forbidden.** `#![forbid(unsafe_code)]` at workspace level. No exceptions without a dedicated unsafe crate with justification.

4. **No `Shell(String)` or equivalent.** Host actions are enumerated capabilities (`GitStatus`, `ReadFile`, `RunTest`), not arbitrary shell commands.

5. **Library crates use `thiserror`. Application crates (`ops-cli`) use `anyhow`.** Each crate defines its own error enum. No mega-error-enum.

6. **No `.unwrap()`.** Denied by clippy. Use `.expect("justification")` only when the invariant is provably true and documented.

## Rust Edition & Toolchain

- **Edition:** 2024
- **Minimum Rust:** 1.85.0
- **Resolver:** 3 (edition 2024 default)

### Edition 2024 Gotchas

- `unsafe_op_in_unsafe_fn` warns by default — use explicit `unsafe {}` blocks inside unsafe fns
- `gen` is a reserved keyword
- `std::env::set_var` / `remove_var` are unsafe — use config instead
- `Future` and `IntoFuture` are in the prelude

## Code Style

### Formatting

Run `cargo fmt` before every commit. Config at workspace root:

```toml
# rustfmt.toml
style_edition = "2024"
edition = "2024"
max_width = 100
comment_width = 90
wrap_comments = true
imports_granularity = "Module"
group_imports = "StdExternalCrate"
use_field_init_shorthand = true
use_try_shorthand = true
format_code_in_doc_comments = true
newline_style = "Unix"
trailing_comma = "Vertical"
```

### Import Order

```rust
// 1. std
use std::collections::HashMap;
use std::path::PathBuf;

// 2. External crates
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// 3. Workspace crates
use ops_core::{Action, ActionOrigin};
```

### Functions

- **< 50 lines.** If longer, extract.
- **< 7 parameters.** Use a config struct or builder if more.
- All public functions that can fail return `Result`.

### Type Design (from NanoWilliams)

- **Enums over booleans.** `SessionState::Running` not `is_running: bool`.
- **Newtype pattern** for domain IDs: `struct SessionId(Ulid)` not bare `Ulid`.
- **`#[non_exhaustive]`** on public enums to allow future variants.
- **Explicit match arms** — no wildcard `_ =>` on enums (clippy enforces this).

### Constructors

- `new()` for 0-2 required params.
- Builder pattern for 3+ params or many optionals. Builder's `build()` returns `Result`.
- No `typed-builder` crate — write builders by hand.

## Error Handling

```rust
// Library crate: typed errors
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("session not found: {id}")]
    NotFound { id: SessionId },

    #[error("database error")]
    Database(#[source] sqlx::Error),
}

// Application crate: anyhow with context on every ?
fn load_config(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)
        .context("failed to read config file")?;
    toml::from_str(&content)
        .context("failed to parse config")
}
```

## Async Patterns

- **Tokio multi-thread runtime.**
- **`CancellationToken`** from tokio-util for cooperative shutdown.
- **Never hold state across `.await` in a partially-modified condition.**
- **`spawn_blocking`** for CPU-bound work (never block the executor).
- **Timeouts on all external calls:** `tokio::time::timeout(Duration::from_secs(30), ...)`.
- **Bounded channels** for backpressure: `mpsc::channel::<T>(1024)`.

### select! Safety

```rust
// Pin non-cancel-safe futures and reuse across iterations
let mut work = pin!(do_work());
loop {
    tokio::select! {
        result = &mut work => { break; }
        _ = token.cancelled() => { break; }
    }
}
```

## Testing

### Organization

- Unit tests: `#[cfg(test)] mod tests` at bottom of each source file.
- Integration tests: `tests/` directory at workspace root for cross-crate tests.

### Naming

```
<function>_<condition>_<expected_outcome>
```

Examples: `validate_token_with_expired_token_returns_error`, `create_session_without_policy_is_denied`

### Async Tests

```rust
#[tokio::test]
async fn heartbeat_sends_status() -> anyhow::Result<()> {
    // ...
}

// For time-dependent tests:
#[tokio::test(start_paused = true)]
async fn grant_expires_after_ttl() { /* ... */ }
```

### Property-Based Testing

Use `proptest` for Action enum exhaustiveness and policy decision coverage:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn all_actions_have_tier_assignment(action in arb_action()) {
        let tier = action.required_tier();
        assert!(tier <= Tier::T3Plus);
    }
}
```

### Test Doubles

Use traits as test boundaries. No mocking frameworks.

```rust
// In library code
pub trait SessionRuntime: Send + Sync {
    async fn send(&self, handle: &SessionHandle, msg: ConductorMessage) -> Result<()>;
}

// In tests
struct FakeRuntime { sent: Arc<Mutex<Vec<ConductorMessage>>> }

impl SessionRuntime for FakeRuntime {
    async fn send(&self, _: &SessionHandle, msg: ConductorMessage) -> Result<()> {
        self.sent.lock().await.push(msg);
        Ok(())
    }
}
```

## Security Practices

- **`secrecy::SecretString`** for all tokens, keys, passwords. Prevents accidental logging.
- **`zeroize`** for sensitive values in memory.
- **Path traversal prevention:** Always canonicalize paths and verify they're within expected roots before operations.
- **SQLite injection:** Use sqlx parameterized queries exclusively. Never interpolate strings into SQL.
- **Input sanitization:** All external input (bridge messages, session output) passes through `ops-policy` sanitization before processing.
- **No `.unwrap()` on user-provided data.** Ever.

## Dependencies

Centralized in `[workspace.dependencies]`. Member crates use `tokio.workspace = true`.

### Approved

tokio, tokio-util, clap, serde, serde_json, toml, thiserror, anyhow, tracing, tracing-subscriber, time, ulid, sqlx, reqwest, tokio-tungstenite, hmac, sha2, secrecy, zeroize

### Dev-only

proptest, tokio-test, assert_matches, tempfile

### Adding New Dependencies

Ask before adding. Justify why an existing crate or std can't do the job. Check: is it well-maintained? How many transitive deps does it pull in? Any unsafe code? Run `cargo deny check` after adding.

## CI Checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check advisories licenses bans sources
cargo audit
```

## Commits

- Run `cargo fmt` and `cargo clippy` before committing.
- Run `cargo test` for the crate you changed.
- Commit messages: imperative mood, one line summary, body if needed.
- Don't commit generated files, target/, or .env.

## What Not to Do

- Don't add features we haven't planned. Check the proposal.
- Don't add `pub` to things that don't need to be public.
- Don't create utility/helper crates. Put shared types in `ops-core`.
- Don't use `Box<dyn Error>` — use thiserror or anyhow.
- Don't use `String` where a newtype is appropriate (session IDs, user IDs, etc.).
- Don't write doc comments on private functions unless the logic is non-obvious.
- Don't add backward-compatibility shims. Just change the code.
