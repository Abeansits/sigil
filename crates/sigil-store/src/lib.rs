//! sigil-store -- `SQLite` persistence for sessions, grants, and audit index.
//!
//! Uses sqlx with WAL mode and forward-only embedded migrations.
//! All queries use runtime-checked SQL (no compile-time verification).

pub mod error;
pub mod grants;
pub mod migrate;
pub mod session;

use sqlx::ConnectOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

pub use error::StoreError;

/// `SQLite`-backed persistence layer.
#[derive(Clone, Debug)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Open (or create) a `SQLite` database at `path` and run migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the connection cannot be
    /// established, or [`StoreError::Database`] if migrations fail.
    pub async fn new(path: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .log_statements(tracing::log::LevelFilter::Debug);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::Executor::execute(&mut *conn, "PRAGMA journal_mode=WAL").await?;
                    sqlx::Executor::execute(&mut *conn, "PRAGMA foreign_keys=ON").await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;

        migrate::run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    /// Create an in-memory store for testing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the in-memory pool cannot be
    /// created, or [`StoreError::Database`] if migrations fail.
    pub async fn new_in_memory() -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(":memory:")
            .log_statements(tracing::log::LevelFilter::Debug);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::Executor::execute(&mut *conn, "PRAGMA foreign_keys=ON").await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;

        migrate::run_migrations(&pool).await?;

        Ok(Self { pool })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use std::path::PathBuf;

    use assert_matches::assert_matches;

    use sigil_core::id::{GroupId, SessionId};
    use sigil_core::session::{IdentitySpec, LifecycleEvent, SessionRecord, SessionState};
    use sigil_core::trust::{Capability, ExecutionClass};
    use sigil_policy::grants::{ApprovalGrant, GrantStore};

    use super::*;

    fn make_session(title: &str) -> SessionRecord {
        SessionRecord {
            id: SessionId::new(),
            title: title.into(),
            path: PathBuf::from("/tmp/test"),
            tool: sigil_core::ToolKind::ClaudeCode,
            group: Some(GroupId::new("test-group")),
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
            identity: None,
        }
    }

    fn make_grant(
        principal: &str,
        capability: Capability,
        ttl_secs: i64,
        max_uses: Option<u32>,
    ) -> ApprovalGrant {
        let now = time::OffsetDateTime::now_utc();
        ApprovalGrant {
            id: sigil_core::id::RequestId::new(),
            principal_id: principal.into(),
            capability,
            resource_scope: None,
            expires_at: now + time::Duration::seconds(ttl_secs),
            max_uses,
            uses: 0,
            issued_by: "test".into(),
            issued_at: now,
        }
    }

    // -- Migration tests --

    #[tokio::test]
    async fn store_initializes_without_error() {
        let store = Store::new_in_memory().await;
        assert!(store.is_ok());
    }

    #[tokio::test]
    async fn double_init_is_idempotent() {
        let store = Store::new_in_memory().await.expect("first init");
        // Running migrations again on the same pool should be fine.
        let result = migrate::run_migrations(&store.pool).await;
        assert!(result.is_ok());
    }

    /// Simulates a crash between ALTER TABLE and `schema_version` INSERT:
    /// the column exists but V002 is not recorded. Re-running migrations
    /// must succeed (idempotent ALTER).
    #[tokio::test]
    async fn v002_migration_is_idempotent_after_partial_apply() {
        let store = Store::new_in_memory().await.expect("init");

        // Simulate crash: delete the V002 version record so next startup
        // retries the migration while the column already exists.
        sqlx::query("DELETE FROM schema_version WHERE version = 2")
            .execute(&store.pool)
            .await
            .expect("delete v002 record");

        // Re-run migrations — should not fail on duplicate column.
        let result = migrate::run_migrations(&store.pool).await;
        assert!(result.is_ok());
    }

    // -- Session CRUD tests --

    #[tokio::test]
    async fn create_and_get_session_by_id() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("my-session");
        store.create_session(&record).await.expect("create");

        let fetched = store.get_session(&record.id).await.expect("get");
        assert_eq!(fetched.id, record.id);
        assert_eq!(fetched.title, "my-session");
        assert_eq!(fetched.state, SessionState::Stopped);
    }

    #[tokio::test]
    async fn get_session_by_title() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("unique-title");
        store.create_session(&record).await.expect("create");

        let fetched = store
            .get_session_by_title("unique-title")
            .await
            .expect("get by title");
        assert_eq!(fetched.id, record.id);
    }

    #[tokio::test]
    async fn list_sessions_returns_all() {
        let store = Store::new_in_memory().await.expect("init");
        store
            .create_session(&make_session("a"))
            .await
            .expect("create a");
        store
            .create_session(&make_session("b"))
            .await
            .expect("create b");

        let sessions = store.list_sessions().await.expect("list");
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn list_sessions_by_state_filters() {
        let store = Store::new_in_memory().await.expect("init");
        let a = make_session("stopped-one");
        let mut b = make_session("running-one");
        b.state = SessionState::Running;

        store.create_session(&a).await.expect("create a");
        store.create_session(&b).await.expect("create b");

        let stopped = store
            .list_sessions_by_state(SessionState::Stopped)
            .await
            .expect("list stopped");
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].title, "stopped-one");

        let running = store
            .list_sessions_by_state(SessionState::Running)
            .await
            .expect("list running");
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].title, "running-one");
    }

    #[tokio::test]
    async fn update_session_state_changes_state() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("to-update");
        store.create_session(&record).await.expect("create");

        store
            .update_session_state(&record.id, SessionState::Running)
            .await
            .expect("update");

        let fetched = store.get_session(&record.id).await.expect("get");
        assert_eq!(fetched.state, SessionState::Running);
    }

    #[tokio::test]
    async fn delete_session_removes_it() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("to-delete");
        store.create_session(&record).await.expect("create");

        store.delete_session(&record.id).await.expect("delete");

        let result = store.get_session(&record.id).await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn get_nonexistent_session_returns_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        let id = SessionId::new();
        let result = store.get_session(&id).await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn duplicate_title_rejected_with_clear_error() {
        let store = Store::new_in_memory().await.expect("init");
        let first = make_session("same-title");
        store.create_session(&first).await.expect("create first");

        let second = make_session("same-title");
        let result = store.create_session(&second).await;
        assert_matches!(result, Err(StoreError::DuplicateTitle { title }) if title == "same-title");
    }

    #[tokio::test]
    async fn duplicate_id_returns_database_error_not_duplicate_title() {
        let store = Store::new_in_memory().await.expect("init");
        let first = make_session("title-a");
        store.create_session(&first).await.expect("create first");

        // Same ID, different title — should be a Database error, not DuplicateTitle.
        let mut second = make_session("title-b");
        second.id = first.id;
        let result = store.create_session(&second).await;
        assert_matches!(result, Err(StoreError::Database(_)));
    }

    #[tokio::test]
    async fn v003_migration_is_idempotent() {
        let store = Store::new_in_memory().await.expect("init");

        // Delete the V003 record and re-run migrations.
        sqlx::query("DELETE FROM schema_version WHERE version = 3")
            .execute(&store.pool)
            .await
            .expect("delete v003 record");

        let result = migrate::run_migrations(&store.pool).await;
        assert!(result.is_ok());
    }

    /// Helper: drop the unique title index, insert sessions with the given
    /// titles in order (forcing deterministic `created_at`), then rerun
    /// migrations. Returns the inserted session IDs in input order.
    async fn seed_pre_v003_duplicates(store: &Store, titles: &[&str]) -> Vec<SessionId> {
        sqlx::query("DROP INDEX IF EXISTS idx_sessions_title")
            .execute(&store.pool)
            .await
            .expect("drop unique index");

        let mut ids = Vec::with_capacity(titles.len());
        for (i, title) in titles.iter().enumerate() {
            let record = make_session(title);
            store.create_session(&record).await.expect("create");
            // Force deterministic ordering by created_at.
            let ts = format!("2026-01-{:02} 00:00:00", i + 1);
            sqlx::query("UPDATE sessions SET created_at = ? WHERE id = ?")
                .bind(&ts)
                .bind(record.id.to_string())
                .execute(&store.pool)
                .await
                .expect("set created_at");
            ids.push(record.id);
        }

        sqlx::query("DELETE FROM schema_version WHERE version = 3")
            .execute(&store.pool)
            .await
            .expect("delete v003 record");

        migrate::run_migrations(&store.pool)
            .await
            .expect("rerun migrations");

        ids
    }

    #[tokio::test]
    async fn v003_migration_dedups_existing_duplicate_titles() {
        let store = Store::new_in_memory().await.expect("init");
        let ids = seed_pre_v003_duplicates(&store, &["dup", "dup", "dup"]).await;

        let s1 = store.get_session(&ids[0]).await.expect("get s1");
        let s2 = store.get_session(&ids[1]).await.expect("get s2");
        let s3 = store.get_session(&ids[2]).await.expect("get s3");
        assert_eq!(s1.title, "dup");
        assert_eq!(s2.title, "dup (2)");
        assert_eq!(s3.title, "dup (3)");
    }

    #[tokio::test]
    async fn v003_migration_dedup_skips_existing_suffix() {
        let store = Store::new_in_memory().await.expect("init");
        // The pre-existing "dup (2)" must not collide with the rename target.
        let ids = seed_pre_v003_duplicates(&store, &["dup", "dup", "dup (2)"]).await;

        let s1 = store.get_session(&ids[0]).await.expect("get s1");
        let s2 = store.get_session(&ids[1]).await.expect("get s2");
        let s3 = store.get_session(&ids[2]).await.expect("get s3");
        assert_eq!(s1.title, "dup");
        // s2 was renamed; (2) was taken so it became (3).
        assert_eq!(s2.title, "dup (3)");
        // s3 is the only one with that title — left untouched.
        assert_eq!(s3.title, "dup (2)");
    }

    #[tokio::test]
    async fn v003_migration_dedups_multiple_independent_groups() {
        let store = Store::new_in_memory().await.expect("init");
        let ids = seed_pre_v003_duplicates(&store, &["a", "a", "b", "b"]).await;

        let a1 = store.get_session(&ids[0]).await.expect("get a1");
        let a2 = store.get_session(&ids[1]).await.expect("get a2");
        let b1 = store.get_session(&ids[2]).await.expect("get b1");
        let b2 = store.get_session(&ids[3]).await.expect("get b2");
        assert_eq!(a1.title, "a");
        assert_eq!(a2.title, "a (2)");
        assert_eq!(b1.title, "b");
        assert_eq!(b2.title, "b (2)");

        let dup_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM (SELECT title FROM sessions GROUP BY title HAVING COUNT(*) > 1)",
        )
        .fetch_one(&store.pool)
        .await
        .expect("count dups");
        assert_eq!(
            dup_count.0, 0,
            "no duplicates should remain after migration"
        );
    }

    #[tokio::test]
    async fn v003_migration_jumps_past_dense_existing_suffixes() {
        let store = Store::new_in_memory().await.expect("init");
        // Pre-existing (2) and (3) — the renamed s2 must jump to (4).
        let ids = seed_pre_v003_duplicates(&store, &["dup", "dup", "dup (2)", "dup (3)"]).await;

        let s1 = store.get_session(&ids[0]).await.expect("get s1");
        let s2 = store.get_session(&ids[1]).await.expect("get s2");
        let s3 = store.get_session(&ids[2]).await.expect("get s3");
        let s4 = store.get_session(&ids[3]).await.expect("get s4");
        assert_eq!(s1.title, "dup");
        assert_eq!(s2.title, "dup (4)");
        assert_eq!(s3.title, "dup (2)");
        assert_eq!(s4.title, "dup (3)");
    }

    /// When duplicates share a `created_at`, the dedup must still produce a
    /// well-defined result (tie-broken by `id`). We don't assert which
    /// specific row keeps the original title — only that all titles end up
    /// distinct and form the expected multiset.
    #[tokio::test]
    async fn v003_migration_dedup_handles_identical_created_at() {
        let store = Store::new_in_memory().await.expect("init");

        sqlx::query("DROP INDEX IF EXISTS idx_sessions_title")
            .execute(&store.pool)
            .await
            .expect("drop index");

        let mut ids = Vec::new();
        for _ in 0..3 {
            let record = make_session("same");
            store.create_session(&record).await.expect("create");
            ids.push(record.id);
        }
        // Force every row to share the same created_at.
        sqlx::query("UPDATE sessions SET created_at = '2026-01-01 00:00:00'")
            .execute(&store.pool)
            .await
            .expect("clobber created_at");

        sqlx::query("DELETE FROM schema_version WHERE version = 3")
            .execute(&store.pool)
            .await
            .expect("delete v003 record");

        migrate::run_migrations(&store.pool)
            .await
            .expect("rerun migrations");

        let mut titles: Vec<String> = sqlx::query_as("SELECT title FROM sessions")
            .fetch_all(&store.pool)
            .await
            .expect("list titles")
            .into_iter()
            .map(|(t,): (String,)| t)
            .collect();
        titles.sort();
        assert_eq!(titles, vec!["same", "same (2)", "same (3)"]);
    }

    // -- Identity persistence tests --

    #[tokio::test]
    async fn create_session_with_identity_round_trips() {
        let store = Store::new_in_memory().await.expect("init");
        let mut record = make_session("with-identity");
        record.identity = Some(IdentitySpec {
            files: vec![
                PathBuf::from("SOUL.md"),
                PathBuf::from("OPS.md"),
                PathBuf::from("state.json"),
            ],
            reload_on: vec![LifecycleEvent::PostCompact, LifecycleEvent::Restart],
        });

        store.create_session(&record).await.expect("create");
        let fetched = store.get_session(&record.id).await.expect("get");

        let identity = fetched.identity.expect("identity should be Some");
        assert_eq!(identity.files.len(), 3);
        assert_eq!(identity.files[0], PathBuf::from("SOUL.md"));
        assert_eq!(identity.files[1], PathBuf::from("OPS.md"));
        assert_eq!(identity.files[2], PathBuf::from("state.json"));
        assert_eq!(identity.reload_on.len(), 2);
        assert_eq!(identity.reload_on[0], LifecycleEvent::PostCompact);
        assert_eq!(identity.reload_on[1], LifecycleEvent::Restart);
    }

    #[tokio::test]
    async fn create_session_with_none_identity_reads_back_as_none() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("no-identity");
        assert!(record.identity.is_none());

        store.create_session(&record).await.expect("create");
        let fetched = store.get_session(&record.id).await.expect("get");

        assert!(fetched.identity.is_none());
    }

    #[tokio::test]
    async fn update_session_identity_sets_spec() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("update-identity");
        store.create_session(&record).await.expect("create");

        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::SessionStart],
        };

        store
            .update_session_identity(&record.id, Some(&spec))
            .await
            .expect("update identity");

        let fetched = store.get_session(&record.id).await.expect("get");
        let identity = fetched.identity.expect("identity should be Some");
        assert_eq!(identity.files, vec![PathBuf::from("SOUL.md")]);
        assert_eq!(identity.reload_on, vec![LifecycleEvent::SessionStart]);
    }

    #[tokio::test]
    async fn update_session_identity_clears_spec() {
        let store = Store::new_in_memory().await.expect("init");
        let mut record = make_session("clear-identity");
        record.identity = Some(IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        });
        store.create_session(&record).await.expect("create");

        store
            .update_session_identity(&record.id, None)
            .await
            .expect("clear identity");

        let fetched = store.get_session(&record.id).await.expect("get");
        assert!(fetched.identity.is_none());
    }

    #[tokio::test]
    async fn update_session_identity_nonexistent_returns_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        let id = SessionId::new();
        let spec = IdentitySpec::default();

        let result = store.update_session_identity(&id, Some(&spec)).await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    // -- Group / parent update tests --

    #[tokio::test]
    async fn update_session_group_sets_new_group() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("regroup-me");
        store.create_session(&record).await.expect("create");

        let new_group = GroupId::new("moved-group");
        store
            .update_session_group(&record.id, Some(&new_group))
            .await
            .expect("update group");

        let fetched = store.get_session(&record.id).await.expect("get");
        assert_eq!(fetched.group, Some(new_group));
    }

    #[tokio::test]
    async fn update_session_group_clears_group() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("clear-group");
        store.create_session(&record).await.expect("create");
        assert!(record.group.is_some(), "seed should have a group");

        store
            .update_session_group(&record.id, None)
            .await
            .expect("clear group");

        let fetched = store.get_session(&record.id).await.expect("get");
        assert!(fetched.group.is_none());
    }

    #[tokio::test]
    async fn update_session_group_nonexistent_returns_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        let id = SessionId::new();
        let group = GroupId::new("ghost");
        let result = store.update_session_group(&id, Some(&group)).await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn update_session_parent_sets_new_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let parent = make_session("parent");
        let child = make_session("child");
        store.create_session(&parent).await.expect("create parent");
        store.create_session(&child).await.expect("create child");

        store
            .update_session_parent(&child.id, Some(&parent.id))
            .await
            .expect("set parent");

        let fetched = store.get_session(&child.id).await.expect("get child");
        assert_eq!(fetched.parent, Some(parent.id));
    }

    #[tokio::test]
    async fn update_session_parent_clears_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let parent = make_session("p");
        let mut child = make_session("c");
        child.parent = Some(parent.id);
        store.create_session(&parent).await.expect("create parent");
        store.create_session(&child).await.expect("create child");

        store
            .update_session_parent(&child.id, None)
            .await
            .expect("clear parent");

        let fetched = store.get_session(&child.id).await.expect("get child");
        assert!(fetched.parent.is_none());
    }

    #[tokio::test]
    async fn update_session_parent_nonexistent_returns_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        let id = SessionId::new();
        let parent_id = SessionId::new();
        let result = store.update_session_parent(&id, Some(&parent_id)).await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    // -- Atomic set_session_parent_checked tests --

    #[tokio::test]
    async fn set_session_parent_checked_sets_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let parent = make_session("atomic-parent");
        let child = make_session("atomic-child");
        store.create_session(&parent).await.expect("create parent");
        store.create_session(&child).await.expect("create child");

        store
            .set_session_parent_checked(&child.id, Some(&parent.id))
            .await
            .expect("atomic set");

        let fetched = store.get_session(&child.id).await.expect("get child");
        assert_eq!(fetched.parent, Some(parent.id));
    }

    #[tokio::test]
    async fn set_session_parent_checked_clears_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let parent = make_session("apc-p");
        let mut child = make_session("apc-c");
        child.parent = Some(parent.id);
        store.create_session(&parent).await.expect("create p");
        store.create_session(&child).await.expect("create c");

        store
            .set_session_parent_checked(&child.id, None)
            .await
            .expect("atomic clear");

        let fetched = store.get_session(&child.id).await.expect("get");
        assert!(fetched.parent.is_none());
    }

    #[tokio::test]
    async fn set_session_parent_checked_rejects_self_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("self-loop");
        store.create_session(&record).await.expect("create");

        let result = store
            .set_session_parent_checked(&record.id, Some(&record.id))
            .await;
        assert_matches!(result, Err(StoreError::ParentCycle { .. }));
    }

    #[tokio::test]
    async fn set_session_parent_checked_rejects_two_node_cycle() {
        // a -> b (via checked path), then b -> a should be rejected.
        let store = Store::new_in_memory().await.expect("init");
        let a = make_session("two-cycle-a");
        let b = make_session("two-cycle-b");
        store.create_session(&a).await.expect("create a");
        store.create_session(&b).await.expect("create b");

        store
            .set_session_parent_checked(&a.id, Some(&b.id))
            .await
            .expect("a -> b ok");

        let result = store.set_session_parent_checked(&b.id, Some(&a.id)).await;
        assert_matches!(result, Err(StoreError::ParentCycle { .. }));

        // b must still have no parent after the rejected attempt.
        let fetched = store.get_session(&b.id).await.expect("get b");
        assert!(fetched.parent.is_none());
    }

    #[tokio::test]
    async fn set_session_parent_checked_rejects_nonexistent_parent() {
        let store = Store::new_in_memory().await.expect("init");
        let record = make_session("orphan-parent-test");
        store.create_session(&record).await.expect("create");
        let ghost = SessionId::new();

        let result = store
            .set_session_parent_checked(&record.id, Some(&ghost))
            .await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn set_session_parent_checked_rejects_nonexistent_child() {
        let store = Store::new_in_memory().await.expect("init");
        let parent = make_session("lonely-parent");
        store.create_session(&parent).await.expect("create");
        let ghost = SessionId::new();

        let result = store
            .set_session_parent_checked(&ghost, Some(&parent.id))
            .await;
        assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn list_sessions_preserves_identity() {
        let store = Store::new_in_memory().await.expect("init");

        let mut with_id = make_session("has-identity");
        with_id.identity = Some(IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![],
        });
        let without_id = make_session("no-identity");

        store.create_session(&with_id).await.expect("create with");
        store
            .create_session(&without_id)
            .await
            .expect("create without");

        let sessions = store.list_sessions().await.expect("list");
        assert_eq!(sessions.len(), 2);

        let found_with = sessions
            .iter()
            .find(|s| s.title == "has-identity")
            .expect("find with");
        let found_without = sessions
            .iter()
            .find(|s| s.title == "no-identity")
            .expect("find without");

        assert!(found_with.identity.is_some());
        assert!(found_without.identity.is_none());
    }

    // -- Grant tests --

    #[tokio::test]
    async fn save_and_find_grant() {
        let store = Store::new_in_memory().await.expect("init");
        let grant = make_grant("paul", Capability::ReadHostFile, 300, Some(5));

        store.save_grant(&grant).await.expect("save");

        let found = store
            .find_grant("paul", Capability::ReadHostFile, None)
            .await
            .expect("find");
        assert!(found.is_some());
        let found = found.expect("grant present");
        assert_eq!(found.principal_id, "paul");
    }

    #[tokio::test]
    async fn expired_grant_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        // TTL of -1 second = already expired.
        let grant = make_grant("paul", Capability::ReadHostFile, -1, None);

        store.save_grant(&grant).await.expect("save");

        let found = store
            .find_grant("paul", Capability::ReadHostFile, None)
            .await
            .expect("find");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn exhausted_grant_not_found() {
        let store = Store::new_in_memory().await.expect("init");
        let mut grant = make_grant("paul", Capability::ReadHostFile, 300, Some(1));
        grant.uses = 1; // Already used up.

        store.save_grant(&grant).await.expect("save");

        let found = store
            .find_grant("paul", Capability::ReadHostFile, None)
            .await
            .expect("find");
        assert!(found.is_none());
    }

    // -- Grant cleanup tests --

    #[tokio::test]
    async fn cleanup_expired_grants_removes_expired() {
        let store = Store::new_in_memory().await.expect("init");
        // TTL of -1 second = already expired.
        let grant = make_grant("paul", Capability::ReadHostFile, -1, None);
        store.save_grant(&grant).await.expect("save");

        let removed = store.cleanup_expired_grants().await.expect("cleanup");
        assert_eq!(removed, 1);

        // Verify it's actually gone by trying a direct SQL count.
        let remaining = store
            .cleanup_expired_grants()
            .await
            .expect("second cleanup");
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn cleanup_expired_grants_removes_exhausted() {
        let store = Store::new_in_memory().await.expect("init");
        let mut grant = make_grant("paul", Capability::WriteHostFile, 300, Some(3));
        grant.uses = 3; // Fully used.
        store.save_grant(&grant).await.expect("save");

        let removed = store.cleanup_expired_grants().await.expect("cleanup");
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn cleanup_expired_grants_keeps_valid() {
        let store = Store::new_in_memory().await.expect("init");
        // Valid grant: 300s TTL, 5 max uses, 0 consumed.
        let grant = make_grant("paul", Capability::ReadHostFile, 300, Some(5));
        store.save_grant(&grant).await.expect("save");

        let removed = store.cleanup_expired_grants().await.expect("cleanup");
        assert_eq!(removed, 0);

        // Grant should still be findable.
        let found = store
            .find_grant("paul", Capability::ReadHostFile, None)
            .await
            .expect("find");
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn cleanup_expired_grants_mixed_keeps_valid_removes_expired() {
        let store = Store::new_in_memory().await.expect("init");

        // One valid, one expired.
        let valid = make_grant("paul", Capability::ReadHostFile, 300, Some(5));
        let expired = make_grant("paul", Capability::WriteHostFile, -1, None);

        store.save_grant(&valid).await.expect("save valid");
        store.save_grant(&expired).await.expect("save expired");

        let removed = store.cleanup_expired_grants().await.expect("cleanup");
        assert_eq!(removed, 1);

        // Valid grant should still be there.
        let found = store
            .find_grant("paul", Capability::ReadHostFile, None)
            .await
            .expect("find");
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn cleanup_expired_grants_empty_store_returns_zero() {
        let store = Store::new_in_memory().await.expect("init");
        let removed = store.cleanup_expired_grants().await.expect("cleanup");
        assert_eq!(removed, 0);
    }
}
