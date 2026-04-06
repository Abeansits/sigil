//! ops-store -- `SQLite` persistence for sessions, grants, and audit index.
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
                    sqlx::Executor::execute(&mut *conn, "PRAGMA journal_mode=WAL")
                        .await?;
                    sqlx::Executor::execute(&mut *conn, "PRAGMA foreign_keys=ON")
                        .await?;
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
                    sqlx::Executor::execute(&mut *conn, "PRAGMA foreign_keys=ON")
                        .await?;
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
    use std::path::PathBuf;

    use assert_matches::assert_matches;

    use ops_core::id::{GroupId, SessionId};
    use ops_core::session::{SessionRecord, SessionState};
    use ops_core::trust::{Capability, ExecutionClass};
    use ops_policy::grants::{ApprovalGrant, GrantStore};

    use super::*;

    fn make_session(title: &str) -> SessionRecord {
        SessionRecord {
            id: SessionId::new(),
            title: title.into(),
            path: PathBuf::from("/tmp/test"),
            tool: ops_core::ToolKind::ClaudeCode,
            group: Some(GroupId::new("test-group")),
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
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
            id: ops_core::id::RequestId::new(),
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
}
