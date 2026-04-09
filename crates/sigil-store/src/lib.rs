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
