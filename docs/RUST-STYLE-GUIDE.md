# Rust Workspace Style Guide

**Target:** Multi-crate workspace (8 crates, async/tokio, SQLite, CLI tool)
**Rust edition:** 2024 (stable since Rust 1.85.0, February 2025)
**Minimum Rust version:** 1.85.0
**Last updated:** 2026-04-03

This guide is the single source of truth for AI coding agents working on this project.
Follow it exactly. When in doubt, be explicit over clever.

---

## Table of Contents

1. [Workspace Configuration](#1-workspace-configuration)
2. [Formatting (rustfmt)](#2-formatting-rustfmt)
3. [Lint Configuration](#3-lint-configuration)
4. [Code Style](#4-code-style)
5. [Error Handling](#5-error-handling)
6. [Async Patterns](#6-async-patterns)
7. [Testing](#7-testing)
8. [Security Practices](#8-security-practices)
9. [Architecture Patterns](#9-architecture-patterns)
10. [Documentation](#10-documentation)
11. [CI Configuration](#11-ci-configuration)
12. [Supply Chain Security](#12-supply-chain-security)

---

## 1. Workspace Configuration

### Root Cargo.toml

```toml
[workspace]
resolver = "3"          # Edition 2024 default; be explicit
members = [
    "crates/*",
]

[workspace.package]
edition = "2024"
rust-version = "1.85.0"  # Minimum supported Rust version (MSRV)
license = "MIT OR Apache-2.0"
repository = "https://github.com/org/project"
authors = ["Team Name"]

[workspace.dependencies]
# Async runtime
tokio = { version = "1.43", features = ["full"] }
tokio-util = { version = "0.7", features = ["rt"] }

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "migrate"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
thiserror = "2"
anyhow = "1"

# Security
secrecy = { version = "0.10", features = ["serde"] }

# CLI
clap = { version = "4", features = ["derive", "env"] }

# Logging / tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Testing (dev)
proptest = "1"
tokio-test = "0.4"
assert_matches = "1.5"

[workspace.lints.rust]
unsafe_code = "forbid"
unused_must_use = "deny"
unused_imports = "deny"
dead_code = "warn"
missing_docs = "warn"

[workspace.lints.clippy]
# -- Correctness (already deny-by-default, but be explicit) --
correctness = { level = "deny", priority = -1 }

# -- Standard groups elevated --
suspicious = { level = "deny", priority = -1 }
perf = { level = "warn", priority = -1 }
complexity = { level = "warn", priority = -1 }
style = { level = "warn", priority = -1 }

# -- Pedantic: enable group, then allow noisy ones --
pedantic = { level = "warn", priority = -1 }
module_name_repetitions = "allow"  # Too noisy in multi-crate workspaces
must_use_candidate = "allow"       # Let authors decide

# -- Security-critical restriction lints (cherry-picked) --
unwrap_used = "deny"
expect_used = "warn"               # Prefer proper error handling; allow with justification
panic = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "warn"              # Use tracing instead; allow in CLI binary crate
print_stderr = "warn"              # Use tracing instead; allow in CLI binary crate
indexing_slicing = "warn"          # Prefer .get() to avoid panics
string_slice = "warn"              # Panics on non-char boundaries
arithmetic_side_effects = "warn"   # Overflow/underflow awareness
undocumented_unsafe_blocks = "deny"
exhaustive_enums = "warn"          # Encourage #[non_exhaustive] on public enums
wildcard_enum_match_arm = "warn"   # Force explicit match arms

# -- Documentation lints --
missing_errors_doc = "warn"
missing_panics_doc = "warn"
doc_markdown = "warn"

# -- Cargo lints --
cargo = { level = "warn", priority = -1 }
```

### Member Crate Cargo.toml Pattern

```toml
[package]
name = "project-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[dependencies]
tokio.workspace = true
serde.workspace = true
thiserror.workspace = true
tracing.workspace = true

[dev-dependencies]
proptest.workspace = true
tokio = { workspace = true, features = ["test-util"] }

[lints]
workspace = true
```

The CLI binary crate can override specific lints in its source:

```rust
// In crates/cli/src/main.rs — CLI output is expected
#![allow(clippy::print_stdout, clippy::print_stderr)]
```

### Workspace Layout

```
project/
  Cargo.toml              # Virtual manifest (workspace root, no [package])
  Cargo.lock
  rustfmt.toml
  clippy.toml
  deny.toml
  .cargo/config.toml
  crates/
    core/                  # Domain types, traits, core logic
    db/                    # SQLite via sqlx, migrations
    auth/                  # Authentication / authorization
    crypto/                # Cryptographic operations
    api/                   # HTTP/gRPC layer
    cli/                   # CLI binary (clap)
    config/                # Configuration loading, validation
    common/                # Shared utilities, error types
  tests/                   # Workspace-level integration tests (optional)
```

---

## 2. Formatting (rustfmt)

### rustfmt.toml

Place at workspace root. All agents must run `cargo +nightly fmt --all` before
committing.

Note: The workspace MSRV is stable Rust 1.85.0, but this rustfmt configuration
intentionally uses unstable formatting options such as `imports_granularity`,
`group_imports`, `wrap_comments`, `comment_width`, and
`format_code_in_doc_comments`. Use nightly rustfmt for formatting only; keep
builds, tests, and clippy on the stable/MSRV toolchains described below.

```toml
# Rust 2024 style edition — matches our edition
style_edition = "2024"
edition = "2024"

# Line width
max_width = 100
comment_width = 90
wrap_comments = true

# Imports
imports_granularity = "Module"      # Group by module: use std::io::{self, Read, Write};
group_imports = "StdExternalCrate"  # Order: std, external, crate-local

# Formatting preferences
use_field_init_shorthand = true     # Point { x, y } instead of Point { x: x, y: y }
use_try_shorthand = true            # ? instead of try!()
format_code_in_doc_comments = true  # Format ```rust blocks in doc comments
newline_style = "Unix"              # LF everywhere
trailing_comma = "Vertical"         # Trailing commas in multi-line constructs

# Keep these as defaults (documenting for clarity)
tab_spaces = 4
hard_tabs = false
reorder_imports = true
merge_derives = true
```

### Import Organization Convention

Imports follow this order (enforced by `group_imports = "StdExternalCrate"`):

```rust
// 1. Standard library
use std::collections::HashMap;
use std::sync::Arc;

// 2. External crates
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// 3. Crate-internal / workspace crates
use crate::config::AppConfig;
use project_core::DomainEvent;
```

Within each group, imports are sorted alphabetically by `cargo +nightly fmt`.

---

## 3. Lint Configuration

### clippy.toml (Workspace Root)

```toml
# Upper bounds for complexity lints
cognitive-complexity-threshold = 25
too-many-arguments-threshold = 7
type-complexity-threshold = 250

# Large future warning threshold (bytes)
large-futures-threshold = 16384

# Disallowed methods — forces safer alternatives
disallowed-methods = [
    { path = "std::env::set_var", reason = "Unsafe in edition 2024; use config crate" },
    { path = "std::env::remove_var", reason = "Unsafe in edition 2024; use config crate" },
]

# Disallowed types
disallowed-types = [
    { path = "std::collections::HashMap", reason = "Use `std::collections::BTreeMap` when deterministic ordering matters; use `rustc_hash::FxHashMap` only for performance-sensitive code with trusted keys (allow with justification)" },
]
```

Note: The `disallowed-types` for HashMap is a strong suggestion. If
deterministic ordering is not required, add a comment and `#[allow]`. Do not use
`FxHashMap` for adversarial or untrusted keys; prefer the standard `HashMap` or
another hash-DoS-aware map when untrusted input controls keys.

### CI Clippy Invocation

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

This promotes all warnings to errors in CI. Locally, warnings are fine during development.

---

## 4. Code Style

### Edition 2024 Key Changes to Remember

These changed in edition 2024 -- agents must be aware:

- **`unsafe_op_in_unsafe_fn`** warns by default: use explicit `unsafe {}` blocks inside `unsafe fn`
- **`gen` is reserved**: do not use `gen` as an identifier; use `r#gen` if interfacing with old code
- **RPIT lifetime capture**: `impl Trait` in return position now captures all in-scope generics by default; use `+ use<>` to opt out
- **`std::env::set_var` / `remove_var` are unsafe**: use configuration crates instead
- **`Future` and `IntoFuture` in prelude**: no need to import them manually
- **Static mut references denied**: references to `static mut` items generate a deny-by-default error

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Crates | `snake_case` (with hyphens in Cargo.toml) | `project-core` / `project_core` |
| Modules | `snake_case` | `auth_handler` |
| Types (struct, enum, trait) | `UpperCamelCase` | `UserSession`, `AuthError` |
| Functions / methods | `snake_case` | `validate_token` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_RETRY_COUNT` |
| Type parameters | Single uppercase or short `CamelCase` | `T`, `K`, `V`, `Conn` |
| Feature flags | `snake_case`, no `use-` or `with-` prefix | `sqlite`, `postgres`, `test_utils` |

### Constructor Conventions

```rust
// Default constructor for simple cases
impl Config {
    pub fn new(path: &Path) -> Result<Self> { /* ... */ }
}

// Builder pattern for 3+ optional fields
pub struct ServerBuilder {
    host: String,
    port: u16,
    max_connections: Option<usize>,
    tls_config: Option<TlsConfig>,
}

impl ServerBuilder {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            max_connections: None,
            tls_config: None,
        }
    }

    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = Some(n);
        self
    }

    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn build(self) -> Result<Server> {
        // Validate and construct
    }
}
```

**Rule of thumb:** Use `new()` for 0-2 required parameters. Use a builder for 3+ parameters or when many are optional. Builder's `build()` should return `Result` if validation can fail.

### Type Aliases

Prefer explicit types. Only use type aliases when they genuinely improve readability:

```rust
// Good: genuinely simplifies a complex type
pub type BoxedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

// Bad: hides information without adding clarity
type S = String;  // Don't do this
```

---

## 5. Error Handling

### The Split: Library Crates vs. Application Crates

| Crate type | Crate | Error style |
|-----------|-------|-------------|
| Library (core, db, auth, crypto, config, common) | `thiserror` | Typed, matchable enums |
| Application (cli, api) | `anyhow` | Context-rich, opaque errors |

### Library Error Pattern (thiserror)

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("record not found: {id}")]
    NotFound { id: String },

    #[error("database query failed")]
    Query(#[source] sqlx::Error),

    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
```

Guidelines:
- Keep variant count under 10. Group related errors or use `#[error(transparent)]` for pass-through.
- Always use `#[source]` or `#[from]` to preserve the error chain.
- Error messages are lowercase, no trailing period (matches Rust convention).
- Each crate defines its own error enum. Do not use one mega-enum across the workspace.

### Application Error Pattern (anyhow)

```rust
use anyhow::{Context, Result};

fn load_config(path: &Path) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path)
        .context("failed to read config file")?;

    let config: AppConfig = toml::from_str(&content)
        .context("failed to parse config")?;

    config.validate()
        .context("config validation failed")?;

    Ok(config)
}
```

Guidelines:
- Use `.context("description")` on every `?` in application code. Never bare `?` at the app level.
- Use `anyhow::bail!("message")` for early returns on error conditions.
- Use `anyhow::ensure!(condition, "message")` as a precondition check.

### When to Use Which `Result`

```rust
// Library crate public API — always typed
pub fn get_user(id: &str) -> Result<User, StorageError> { /* ... */ }

// Library crate internal/private — typed is preferred, anyhow acceptable
fn parse_row(row: &SqliteRow) -> Result<User, StorageError> { /* ... */ }

// Application crate (CLI main, API handler) — anyhow
async fn handle_request(req: Request) -> anyhow::Result<Response> { /* ... */ }

// Tests — anyhow for convenience
#[test]
fn test_parsing() -> anyhow::Result<()> { /* ... */ }
```

### Unwrap / Expect Policy

`unwrap()` is denied by clippy. `expect()` is warned. When you have a
provably-safe unwrap:

```rust
// Use expect with a justification that explains the invariant.
#[allow(
    clippy::expect_used,
    reason = "static string '8080' is a valid u16"
)]
let port: u16 = "8080"
    .parse()
    .expect("static string '8080' is a valid u16");
```

For option access where `None` is a programming error, prefer:

```rust
// In library code: return an error
let user = users.get(id).ok_or(StorageError::NotFound { id: id.into() })?;

// In tests: prefer propagating the error
let user = result?;
```

Tests run under `clippy --all-targets`, so the same lint policy applies to test
code when warnings are denied in CI. Prefer returning `anyhow::Result<()>` from
tests and using `?`. If a test needs `unwrap()` or `expect()` for a local
invariant, add a narrow `#[allow(clippy::unwrap_used, clippy::expect_used,
reason = "...")]` on the smallest item and explain the invariant in the reason.

---

## 6. Async Patterns

### Runtime Configuration

```rust
// In main.rs — explicit runtime configuration
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ...
}

// For fine-grained control:
fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(16)
        .enable_all()
        .build()?
        .block_on(async { run().await })
}
```

### Cancellation Safety

**Rule: Never hold state in a partially-modified condition across an `.await` point.**

```rust
// BAD: If cancelled between reserve and send, the permit leaks
let permit = tx.reserve().await?;
do_something_else().await;  // <-- cancel point
permit.send(value);

// GOOD: Minimize gap between reserve and send
let permit = tx.reserve().await?;
permit.send(value);  // Infallible, no await
```

**Use `CancellationToken` for cooperative cancellation:**

```rust
use tokio_util::sync::CancellationToken;

async fn worker(token: CancellationToken) {
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("worker shutting down");
                break;
            }
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    process(msg).await;
                }
            }
        }
    }
}
```

### `select!` Safety Rules

1. All branches in `tokio::select!` should be cancellation-safe or pinned.
2. If a future is NOT cancel-safe, pin it and reuse across iterations:

```rust
let mut work = pin!(do_work());
loop {
    tokio::select! {
        result = &mut work => {
            // work completed
            break;
        }
        _ = token.cancelled() => {
            // handle cancellation
            break;
        }
    }
}
```

### Blocking Work

Never run blocking code on async worker threads:

```rust
// BAD
async fn hash_password(pw: &str) -> String {
    argon2::hash(pw)  // CPU-bound, blocks the executor
}

// GOOD
async fn hash_password(pw: String) -> Result<String> {
    tokio::task::spawn_blocking(move || argon2::hash(&pw))
        .await
        .context("hash task panicked")?
}
```

### Timeouts and Backpressure

```rust
use tokio::time::{timeout, Duration};

// Always wrap external calls with timeouts
let response = timeout(Duration::from_secs(30), client.get(url).send())
    .await
    .context("request timed out")?
    .context("request failed")?;

// Use bounded channels for backpressure
let (tx, rx) = tokio::sync::mpsc::channel::<Event>(1024);
```

### Task Spawning Guidelines

- Prefer structured concurrency (futures in the same task) over spawning when possible.
- When you must spawn, use `tokio::spawn` and handle the `JoinHandle`.
- Do not spawn thousands of micro-tasks; batch work into larger tasks.
- All spawned tasks must have error handling; never ignore `JoinHandle` results.

```rust
// GOOD: spawn with error handling
let handle = tokio::spawn(async move {
    if let Err(e) = process_batch(items).await {
        tracing::error!(error = %e, "batch processing failed");
    }
});

// Join before shutdown
handle.await.context("task panicked")?;
```

---

## 7. Testing

### Unit Test Organization

Unit tests live in a `#[cfg(test)]` module at the bottom of each source file:

```rust
// src/auth/token.rs

pub fn validate_token(token: &str) -> Result<Claims, AuthError> {
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_token_returns_claims() -> anyhow::Result<()> {
        let token = create_test_token()?;
        let claims = validate_token(&token)?;
        assert_eq!(claims.sub, "user-123");
        Ok(())
    }

    #[test]
    fn expired_token_returns_error() -> anyhow::Result<()> {
        let token = create_expired_token();
        let Err(err) = validate_token(&token) else {
            anyhow::bail!("expired token unexpectedly validated");
        };
        assert!(matches!(err, AuthError::TokenExpired));
        Ok(())
    }
}
```

### Test Naming Convention

```
<function_or_behavior>_<condition>_<expected_outcome>
```

Examples:
- `validate_token_with_valid_token_returns_claims`
- `validate_token_with_expired_token_returns_error`
- `parse_config_with_missing_field_fails`
- `insert_user_with_duplicate_email_returns_conflict`

For short, obvious cases, drop the middle segment:
- `serialize_roundtrip`
- `empty_input_returns_none`

### Async Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Single-threaded (default, preferred for unit tests)
    #[tokio::test]
    async fn fetch_user_returns_data() -> anyhow::Result<()> {
        let db = setup_test_db().await?;
        let user = fetch_user(&db, "user-1").await?;
        assert_eq!(user.name, "Alice");
        Ok(())
    }

    // Multi-threaded (when testing concurrent behavior)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_writes_dont_deadlock() -> anyhow::Result<()> {
        // ...
        Ok(())
    }

    // Time-sensitive tests (start with paused clock)
    #[tokio::test(start_paused = true)]
    async fn retry_respects_backoff() {
        // tokio::time::advance() controls time
    }
}
```

### Integration Tests

Place in `crates/<crate>/tests/` for crate-level integration tests, or `tests/` at workspace root for cross-crate tests.

```rust
// crates/db/tests/user_repository.rs

use project_db::{Database, UserRepository};
use sqlx::sqlite::SqlitePoolOptions;

async fn setup() -> anyhow::Result<Database> {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;

    Ok(Database::new(pool))
}

#[tokio::test]
async fn create_and_retrieve_user() -> anyhow::Result<()> {
    let db = setup().await?;
    // ...
    Ok(())
}
```

### Property-Based Testing (proptest)

Use `proptest` (not quickcheck). It has better shrinking, composable strategies, and constraint support.

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_serialization(input in "\\PC{1,256}") {
            let encoded = encode(&input);
            let decoded = decode(&encoded)
                .map_err(|err| TestCaseError::fail(format!("decode failed: {err}")))?;
            prop_assert_eq!(input, decoded);
        }

        #[test]
        fn amount_never_negative(
            a in 0u64..u64::MAX / 2,
            b in 0u64..u64::MAX / 2,
        ) {
            let result = safe_add(a, b);
            assert!(result >= a);
            assert!(result >= b);
        }
    }
}
```

### Mocking / Faking with Trait Boundaries

Do not use mocking frameworks. Use trait-based test doubles:

```rust
// Define trait in library crate
#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn get_user(&self, id: &str) -> Result<User, StorageError>;
    async fn save_user(&self, user: &User) -> Result<(), StorageError>;
}

// Real implementation
pub struct SqliteUserStore { /* ... */ }

#[async_trait::async_trait]
impl UserStore for SqliteUserStore { /* ... */ }

// Test double
#[cfg(test)]
pub struct FakeUserStore {
    pub users: std::sync::Mutex<Vec<User>>,
}

impl FakeUserStore {
    #[allow(
        clippy::expect_used,
        reason = "test double mutex poisoning means the test already failed"
    )]
    fn users(&self) -> std::sync::MutexGuard<'_, Vec<User>> {
        self.users
            .lock()
            .expect("test double mutex poisoning means the test already failed")
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl UserStore for FakeUserStore {
    async fn get_user(&self, id: &str) -> Result<User, StorageError> {
        self.users()
            .iter()
            .find(|u| u.id == id)
            .cloned()
            .ok_or(StorageError::NotFound { id: id.into() })
    }

    async fn save_user(&self, user: &User) -> Result<(), StorageError> {
        self.users().push(user.clone());
        Ok(())
    }
}
```

If test doubles need to be shared across crates, put them in a `test_utils` feature-gated module in the defining crate, or create a dedicated `project-test-utils` crate (dev-dependency only).

---

## 8. Security Practices

### Unsafe Code Policy

`unsafe` is **forbidden** at the workspace level (`unsafe_code = "forbid"` in workspace lints).

If a crate absolutely requires unsafe (e.g., FFI, performance-critical inner loops):
1. Create a dedicated crate for the unsafe code (e.g., `crates/crypto-sys`).
2. Override the lint in that crate's `Cargo.toml` or with `#![allow(unsafe_code)]`.
3. Every `unsafe` block requires a `// SAFETY: ...` comment explaining the invariant.
4. The crate must have exhaustive tests, including property tests for invariants.

### Secret Handling (secrecy crate)

```rust
use secrecy::{ExposeSecret, SecretString};

pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub password: SecretString,  // Zeroed on drop, redacted in Debug
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> SecretString {
        // expose_secret() only in the narrowest scope possible
        let url = format!(
            "sqlite://{}:{}@{}:{}/db",
            self.user,
            self.password.expose_secret(),
            self.host,
            self.port
        );
        SecretString::from(url)
    }
}
```

Rules:
- All passwords, tokens, API keys, and connection strings are `SecretString`.
- Never log a `SecretString` — its `Debug` impl prints `[REDACTED]`.
- `expose_secret()` must only appear in the function that actually needs the plaintext.
- Never clone or copy a secret into a `String` that outlives the immediate scope.

### String Handling for Untrusted Input

```rust
// Limit input length before processing
fn validate_username(input: &str) -> Result<&str, ValidationError> {
    if input.len() > 256 {
        return Err(ValidationError::TooLong);
    }
    if !input.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::InvalidCharacters);
    }
    Ok(input)
}

// Never index strings by byte position on untrusted input
// BAD:  &input[0..n]    — panics on non-UTF-8 boundary
// GOOD: input.get(0..n) — returns Option
```

### Path Traversal Prevention

```rust
use std::path::{Path, PathBuf};

/// Resolve a user-supplied path safely within a base directory.
/// Returns an error if the resolved path escapes the base.
fn safe_resolve(base: &Path, user_path: &str) -> Result<PathBuf, SecurityError> {
    // Reject absolute paths and obvious traversal
    if user_path.starts_with('/') || user_path.contains("..") {
        return Err(SecurityError::PathTraversal);
    }

    let candidate = base.join(user_path);
    let resolved = candidate
        .canonicalize()
        .map_err(|_| SecurityError::PathNotFound)?;

    let base_resolved = base
        .canonicalize()
        .map_err(|_| SecurityError::PathNotFound)?;

    if !resolved.starts_with(&base_resolved) {
        return Err(SecurityError::PathTraversal);
    }

    Ok(resolved)
}
```

Rules:
- Never pass user input directly to `std::fs` functions.
- Always canonicalize and check prefix.
- Consider the `cap-std` crate for capability-based filesystem access in high-security contexts.

### SQL Injection Prevention with sqlx

sqlx uses compile-time checked queries with parameterized statements. SQL injection is prevented by construction when used correctly.

```rust
// GOOD: Parameterized query — safe
let user = sqlx::query_as::<_, User>(
    "SELECT id, name, email FROM users WHERE id = ?",
)
.bind(user_id)
.fetch_one(&pool)
.await?;

// GOOD: query! macro — compile-time verified
let user = sqlx::query_as!(
    User,
    "SELECT id, name, email FROM users WHERE id = ?",
    user_id
)
.fetch_one(&pool)
.await?;

// FORBIDDEN: String interpolation in SQL
// let q = format!("SELECT * FROM users WHERE id = '{user_id}'");
```

Rules:
- Always use `?` parameter placeholders. Never interpolate values into SQL strings.
- Prefer `sqlx::query!` / `sqlx::query_as!` macros for compile-time verification.
- Use `sqlx::migrate!` for schema migrations; never run raw DDL from user input.
- Enable WAL mode for SQLite concurrency:

```rust
let pool = SqlitePoolOptions::new()
    .after_connect(|conn, _| {
        Box::pin(async move {
            sqlx::query("PRAGMA journal_mode=WAL;")
                .execute(&mut *conn)
                .await?;
            sqlx::query("PRAGMA foreign_keys=ON;")
                .execute(&mut *conn)
                .await?;
            Ok(())
        })
    })
    .connect(&database_url)
    .await?;
```

---

## 9. Architecture Patterns

### Trait-Based Boundaries Between Crates

Define trait interfaces in `core` or the consuming crate. Implement in the provider crate:

```
core (defines traits)  <--  db (implements traits)
       ^                         ^
       |                         |
      cli (uses traits)    api (uses traits)
```

```rust
// In crates/core/src/repository.rs
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, StorageError>;
    async fn save(&self, user: &User) -> Result<(), StorageError>;
    async fn delete(&self, id: &UserId) -> Result<bool, StorageError>;
}

// In crates/db/src/sqlite_user_repo.rs
use project_core::UserRepository;

pub struct SqliteUserRepository {
    pool: SqlitePool,
}

#[async_trait::async_trait]
impl UserRepository for SqliteUserRepository {
    // ...
}
```

### Shared Types Location

| What | Where |
|------|-------|
| Domain entities (`User`, `Session`, `Event`) | `crates/core/src/models/` |
| Error types per crate | Each crate's `src/error.rs` |
| Cross-crate error conversions | Implement `From<CrateError>` in the consuming crate |
| Shared trait definitions | `crates/core/src/traits/` or `crates/core/src/ports/` |
| Configuration types | `crates/config/` |
| Common utilities (retry, timing, ID generation) | `crates/common/` |

### Re-export Patterns

Crates should re-export their public API from `lib.rs`:

```rust
// crates/core/src/lib.rs
pub mod models;
pub mod traits;
pub mod error;

// Re-export the most-used items at the crate root
pub use error::CoreError;
pub use models::{User, UserId, Session};
pub use traits::{UserRepository, SessionRepository};
```

Do not re-export third-party types (like `sqlx::Error`) from your public API.
Wrap them in your own error types so downstream crates do not depend on your transitive dependencies.

### Feature Flag Conventions

```toml
[features]
default = []
# Name features after what they enable, not "use-X" or "with-X"
sqlite = ["dep:sqlx"]
postgres = ["dep:sqlx"]
test_utils = []  # Exposes test doubles and helpers
```

Rules:
- Feature names are `snake_case`.
- No `use-` or `with-` prefixes; name the feature directly (e.g., `sqlite`, not `with-sqlite`).
- `test_utils` feature gates test helpers that other crates need as dev-dependencies.
- Keep features additive; enabling a feature should never break existing code.
- Document feature flags in the crate's `lib.rs` doc comment.

### When to Split Into a New Crate

Split when:
- The module has its own distinct set of dependencies that other crates don't need.
- Two teams/agents will work on it independently and compile-time isolation helps.
- The module represents a clear domain boundary (auth, crypto, storage).
- You want to enforce a dependency direction (crate A cannot depend on crate B).

Do NOT split when:
- The module is small and only used by one other crate.
- It would create circular dependencies.
- The "crate" would have only one or two small files.

---

## 10. Documentation

### What Gets Doc Comments

| Item | Required? | Notes |
|------|-----------|-------|
| Public functions/methods | Yes | One-line summary + Errors/Panics sections if applicable |
| Public structs/enums | Yes | Explain purpose and invariants |
| Public struct fields | Yes, if not obvious | Skip for `pub name: String` on a `User` struct |
| Public traits | Yes | Explain the contract and when to implement |
| Trait methods | Yes | Explain expected behavior |
| Modules (`//!` at top) | Yes, for public modules | One paragraph explaining the module's role |
| Crate root (`//!` in lib.rs) | Yes | Overview, main types, quick example |
| Private functions | No | Add only when logic is non-obvious |
| Test functions | No | The test name should be self-documenting |

### Doc Comment Style

```rust
/// Validates a JWT token and returns the decoded claims.
///
/// The token is verified against the configured signing key and checked
/// for expiration. Clock skew tolerance is 30 seconds.
///
/// # Errors
///
/// Returns [`AuthError::TokenExpired`] if the token has expired.
/// Returns [`AuthError::InvalidSignature`] if the signature does not match.
///
/// # Examples
///
/// ```
/// use project_auth::validate_token;
///
/// # fn main() -> anyhow::Result<()> {
/// let claims = validate_token("eyJ...")?;
/// assert_eq!(claims.sub, "user-123");
/// # Ok(())
/// # }
/// ```
pub fn validate_token(token: &str) -> Result<Claims, AuthError> {
    // ...
}
```

Rules:
- First line is a single-sentence summary in third person ("Validates..." not "Validate...").
- Use `# Errors` section for any function returning `Result`.
- Use `# Panics` section if the function can panic (should be rare given our lint policy).
- Use `# Safety` section (mandatory) for any `unsafe fn`.
- Examples use `?` not `unwrap()`.
- Link to related types with `[`backtick`]` syntax.

### Module-Level Docs

```rust
//! User authentication and session management.
//!
//! This module handles JWT token validation, session creation/renewal,
//! and integration with the configured identity provider.
//!
//! # Architecture
//!
//! Authentication flows through [`AuthService`], which depends on
//! [`TokenVerifier`] for JWT validation and [`SessionRepository`]
//! for persistence.
```

---

## 11. CI Configuration

### Essential CI Steps

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"
  RUST_BACKTRACE: 1

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rustfmt

      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: Check formatting
        run: cargo +nightly fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets --all-features -- -D warnings

      - name: Build
        run: cargo build --workspace --all-features

      - name: Test
        run: cargo test --workspace --all-features

      - name: Doc tests
        run: cargo test --workspace --doc

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install audit tools
        run: cargo install cargo-audit cargo-deny

      - name: Security audit
        run: cargo audit

      - name: Dependency check
        run: cargo deny check

  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: "1.85.0"  # MSRV

      - name: Check MSRV
        run: cargo check --workspace --all-features
```

### Cargo Clippy CI Flags

```bash
# Full strictness for CI (all warnings become errors)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# For local development (warnings stay as warnings)
cargo clippy --workspace --all-targets --all-features
```

### Cargo Test Configuration

```bash
# Run all tests with output on failure
cargo test --workspace --all-features -- --nocapture

# Using cargo-nextest for faster parallel execution (recommended)
cargo nextest run --workspace --all-features
```

Consider adding a `.cargo/config.toml`:

```toml
# .cargo/config.toml
[build]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]  # Faster linking (if lld available)

[alias]
ci-clippy = "clippy --workspace --all-targets --all-features -- -D warnings"
ci-test = "test --workspace --all-features"
ci-fmt = "fmt --all -- --check"
```

### MSRV Policy

- Set `rust-version = "1.85.0"` in `[workspace.package]` (edition 2024 minimum).
- CI runs a check against the MSRV toolchain.
- Bump MSRV deliberately and document in CHANGELOG.
- The edition 2024 resolver (`resolver = "3"`) is Rust-version-aware and will select dependency versions compatible with your MSRV.

---

## 12. Supply Chain Security

### deny.toml

```toml
# deny.toml — workspace root

[graph]
all-features = true

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"
ignore = [
    # List advisory IDs that have been reviewed and accepted
    # "RUSTSEC-2024-XXXX",
]

[licenses]
unlicensed = "deny"
confidence-threshold = 0.92
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "BSL-1.0",
    "OpenSSL",
]
copyleft = "deny"

[[licenses.exceptions]]
allow = ["MPL-2.0"]
crate = "webpki-roots"

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"
# deny = [
#     { crate = "openssl-sys", reason = "Use rustls instead" },
# ]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

### Audit Commands

```bash
# Check for known vulnerabilities
cargo audit

# Comprehensive check (advisories + licenses + bans + sources)
cargo deny check

# Check only advisories
cargo deny check advisories

# Check only licenses
cargo deny check licenses

# Generate a deny.toml template
cargo deny init
```

---

## Quick Reference: What Agents Must Do Before Committing

1. `cargo +nightly fmt --all` — formatting is non-negotiable
2. `cargo clippy --workspace --all-targets --all-features` — fix all warnings
3. `cargo test --workspace` — all tests pass
4. `cargo doc --workspace --no-deps` — docs build without warnings
5. No `unwrap()` without a narrow lint allowance and invariant comment
6. No string interpolation in SQL
7. No `unsafe` blocks (unless in a dedicated crate with safety comments)
8. All public items have doc comments
9. Error types use `thiserror` in libraries, `anyhow` in application crates
10. Secrets wrapped in `SecretString`, never logged

---

## Sources

This guide was compiled from the following references:

- [Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
- [Rust 1.85.0 Release Notes](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/)
- [Cargo Workspaces Reference](https://doc.rust-lang.org/cargo/reference/workspaces.html)
- [Clippy Lint Documentation](https://doc.rust-lang.org/clippy/lints.html)
- [Clippy Lint Index](https://rust-lang.github.io/rust-clippy/master/index.html)
- [Rustfmt Configuration](https://rust-lang.github.io/rustfmt/)
- [Rustfmt Style Edition (2024)](https://doc.rust-lang.org/edition-guide/rust-2024/rustfmt-style-edition.html)
- [Rust API Documentation Guidelines](https://rust-lang.github.io/api-guidelines/documentation.html)
- [Error Handling: thiserror and anyhow (2026)](https://oneuptime.com/blog/post/2026-01-25-error-types-thiserror-anyhow-rust/view)
- [Secrecy Crate Patterns](https://leapcell.io/blog/secure-configuration-and-secrets-management-in-rust-with-secrecy-and-environment-variables)
- [Cancelling Async Rust (RustConf 2025)](https://sunshowers.io/posts/cancelling-async-rust/)
- [Oxide RFD 400: Cancel Safety](https://rfd.shared.oxide.computer/rfd/400)
- [Tokio Runtime Mistakes (2026)](https://www.techbuddies.io/2026/03/21/top-5-tokio-runtime-mistakes-that-quietly-kill-your-async-rust/)
- [Evolution of Async Rust (2026)](https://blog.jetbrains.com/rust/2026/02/17/the-evolution-of-async-rust-from-tokio-to-high-level-applications/)
- [Proptest vs QuickCheck](https://proptest-rs.github.io/proptest/proptest/vs-quickcheck.html)
- [cargo-deny Documentation](https://embarkstudios.github.io/cargo-deny/checks/cfg.html)
- [Rust Supply Chain Security Tools (2026)](https://digitalthriveai.com/en-us/resources/ai-and-automation/comparing-rust-supply-chain-safety-tools/)
- [Rust Vulnerability Scanning: What cargo audit Misses (2026)](https://www.geekwala.com/blog/securing-rust-dependencies-2026)
- [Large Rust Workspaces (matklad)](https://matklad.github.io/2021/08/22/large-rust-workspaces.html)
- [Path Traversal Prevention in Rust](https://www.stackhawk.com/blog/rust-path-traversal-guide-example-and-prevention/)
- [Cargo Features Reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [Rust API Naming Guidelines](https://rust-lang.github.io/api-guidelines/naming.html)
