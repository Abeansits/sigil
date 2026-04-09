//! Embedded SQL migrations.
//!
//! Migrations are plain SQL strings run in order on startup. A
//! `schema_version` table tracks which migrations have been applied.

use sqlx::SqlitePool;

use crate::error::StoreError;

/// SQL-only migrations run in order. Each entry is `(version, description, sql)`.
///
/// Migrations that need conditional logic (e.g. idempotent ALTER TABLE)
/// are handled separately in [`run_migrations`].
const SQL_MIGRATIONS: &[(i64, &str, &str)] = &[(1, "initial schema", V001)];

const V001: &str = r"
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    path TEXT NOT NULL,
    tool TEXT NOT NULL,
    group_id TEXT,
    parent_id TEXT,
    execution_class TEXT NOT NULL DEFAULT 'OfflineWorker',
    sandboxed INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'Stopped',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_groups (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS approval_grants (
    id TEXT PRIMARY KEY NOT NULL,
    principal_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    resource_scope TEXT,
    expires_at TEXT NOT NULL,
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0,
    issued_by TEXT NOT NULL,
    issued_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_index (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    action_summary TEXT NOT NULL,
    session_id TEXT,
    decision TEXT NOT NULL,
    jsonl_offset INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
CREATE INDEX IF NOT EXISTS idx_sessions_group ON sessions(group_id);
CREATE INDEX IF NOT EXISTS idx_grants_principal ON approval_grants(principal_id);
CREATE INDEX IF NOT EXISTS idx_grants_expires ON approval_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_index(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_index(session_id);
";

/// Run all pending migrations against the given pool.
///
/// Creates the `schema_version` tracking table if it does not exist,
/// then applies every migration whose version has not yet been recorded.
///
/// # Errors
///
/// Returns [`StoreError::Database`] if any SQL statement fails.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), StoreError> {
    // Ensure the version-tracking table exists.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY NOT NULL,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    // Phase 1: plain SQL migrations.
    for &(version, description, sql) in SQL_MIGRATIONS {
        apply_sql_migration(pool, version, description, sql).await?;
    }

    // Phase 2: programmatic migrations that need conditional logic.
    apply_v002_identity_column(pool).await?;

    Ok(())
}

/// Apply a plain-SQL migration if not already recorded.
async fn apply_sql_migration(
    pool: &SqlitePool,
    version: i64,
    description: &str,
    sql: &str,
) -> Result<(), StoreError> {
    if migration_applied(pool, version).await? {
        tracing::debug!(version, description, "migration already applied, skipping");
        return Ok(());
    }

    tracing::info!(version, description, "applying migration");

    // Execute each statement in the migration SQL individually.
    // SQLite's `execute` only runs the first statement when given
    // multiple statements separated by semicolons, so we split.
    for statement in sql.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        sqlx::query(trimmed).execute(pool).await?;
    }

    record_migration(pool, version, description).await
}

/// V002: add `identity_json` column to sessions.
///
/// Uses `PRAGMA table_info` to check whether the column already exists
/// before running `ALTER TABLE`. This makes the migration idempotent —
/// safe to retry if a previous attempt crashed after the ALTER succeeded
/// but before the version was recorded.
async fn apply_v002_identity_column(pool: &SqlitePool) -> Result<(), StoreError> {
    const VERSION: i64 = 2;
    const DESCRIPTION: &str = "add identity_json to sessions";

    if migration_applied(pool, VERSION).await? {
        tracing::debug!(VERSION, DESCRIPTION, "migration already applied, skipping");
        return Ok(());
    }

    tracing::info!(VERSION, DESCRIPTION, "applying migration");

    let has_column = column_exists(pool, "sessions", "identity_json").await?;
    if !has_column {
        sqlx::query("ALTER TABLE sessions ADD COLUMN identity_json TEXT")
            .execute(pool)
            .await?;
    }

    record_migration(pool, VERSION, DESCRIPTION).await
}

/// Check whether a migration version has already been recorded.
async fn migration_applied(pool: &SqlitePool, version: i64) -> Result<bool, StoreError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT version FROM schema_version WHERE version = ?")
            .bind(version)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

/// Record a migration version in the `schema_version` table.
async fn record_migration(
    pool: &SqlitePool,
    version: i64,
    description: &str,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO schema_version (version, description) VALUES (?, ?)")
        .bind(version)
        .bind(description)
        .execute(pool)
        .await?;
    Ok(())
}

/// Check whether a column exists on a table via `PRAGMA table_info`.
async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool, StoreError> {
    // PRAGMA doesn't support parameter binding, but table/column names
    // are compile-time constants in our migration code, not user input.
    let sql = format!("PRAGMA table_info({table})");
    let rows: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as(&sql).fetch_all(pool).await?;
    Ok(rows.iter().any(|(_, name, _, _, _, _)| name == column))
}
