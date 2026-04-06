//! Embedded SQL migrations.
//!
//! Migrations are plain SQL strings run in order on startup. A
//! `schema_version` table tracks which migrations have been applied.

use sqlx::SqlitePool;

use crate::error::StoreError;

/// All migrations in order. Each entry is `(version, description, sql)`.
const MIGRATIONS: &[(i64, &str, &str)] = &[(1, "initial schema", V001)];

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

    for &(version, description, sql) in MIGRATIONS {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT version FROM schema_version WHERE version = ?")
                .bind(version)
                .fetch_optional(pool)
                .await?;

        if row.is_some() {
            tracing::debug!(version, description, "migration already applied, skipping");
            continue;
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

        sqlx::query("INSERT INTO schema_version (version, description) VALUES (?, ?)")
            .bind(version)
            .bind(description)
            .execute(pool)
            .await?;
    }

    Ok(())
}
