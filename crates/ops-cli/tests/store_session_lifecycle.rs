//! Store + session lifecycle integration tests.
//!
//! Exercises the full CRUD cycle on an in-memory SQLite store,
//! verifying state transitions, listing, and deletion.

use std::path::PathBuf;

use assert_matches::assert_matches;

use ops_core::ToolKind;
use ops_core::id::{GroupId, SessionId};
use ops_core::session::{SessionRecord, SessionState};
use ops_core::trust::ExecutionClass;
use ops_store::{Store, StoreError};

fn make_session(title: &str) -> SessionRecord {
    SessionRecord {
        id: SessionId::new(),
        title: title.into(),
        path: PathBuf::from("/tmp/test-project"),
        tool: ToolKind::ClaudeCode,
        group: Some(GroupId::new("integration-test")),
        parent: None,
        execution_class: ExecutionClass::OfflineWorker,
        sandboxed: true,
        state: SessionState::Stopped,
    }
}

#[tokio::test]
async fn full_session_lifecycle() {
    // 1. Create in-memory store.
    let store = Store::new_in_memory()
        .await
        .expect("store initialization should succeed");

    // 2. Create session.
    let record = make_session("lifecycle-test");
    let session_id = record.id;
    store
        .create_session(&record)
        .await
        .expect("session creation should succeed");

    // 3. Verify it starts in Stopped state.
    let fetched = store
        .get_session(&session_id)
        .await
        .expect("get session should succeed");
    assert_eq!(fetched.state, SessionState::Stopped);
    assert_eq!(fetched.title, "lifecycle-test");

    // 4. Transition to Running.
    store
        .update_session_state(&session_id, SessionState::Running)
        .await
        .expect("update to Running should succeed");

    let fetched = store
        .get_session(&session_id)
        .await
        .expect("get session should succeed");
    assert_eq!(fetched.state, SessionState::Running);

    // 5. List sessions -- verify it appears.
    let sessions = store
        .list_sessions()
        .await
        .expect("list sessions should succeed");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, session_id);

    // 6. Transition to Waiting.
    store
        .update_session_state(&session_id, SessionState::Waiting)
        .await
        .expect("update to Waiting should succeed");

    let fetched = store
        .get_session(&session_id)
        .await
        .expect("get session should succeed");
    assert_eq!(fetched.state, SessionState::Waiting);

    // 7. Delete session.
    store
        .delete_session(&session_id)
        .await
        .expect("delete should succeed");

    // 8. Verify it's gone.
    let result = store.get_session(&session_id).await;
    assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
}

#[tokio::test]
async fn multiple_sessions_with_state_filtering() {
    let store = Store::new_in_memory()
        .await
        .expect("store initialization should succeed");

    // Create three sessions in different states.
    let running = make_session("runner");
    let waiting = make_session("waiter");
    let stopped = make_session("stopper");

    store.create_session(&running).await.expect("create runner");
    store.create_session(&waiting).await.expect("create waiter");
    store
        .create_session(&stopped)
        .await
        .expect("create stopper");

    store
        .update_session_state(&running.id, SessionState::Running)
        .await
        .expect("set runner to Running");
    store
        .update_session_state(&waiting.id, SessionState::Waiting)
        .await
        .expect("set waiter to Waiting");

    // Filter by state.
    let running_sessions = store
        .list_sessions_by_state(SessionState::Running)
        .await
        .expect("list running sessions");
    assert_eq!(running_sessions.len(), 1);
    assert_eq!(running_sessions[0].title, "runner");

    let waiting_sessions = store
        .list_sessions_by_state(SessionState::Waiting)
        .await
        .expect("list waiting sessions");
    assert_eq!(waiting_sessions.len(), 1);
    assert_eq!(waiting_sessions[0].title, "waiter");

    let stopped_sessions = store
        .list_sessions_by_state(SessionState::Stopped)
        .await
        .expect("list stopped sessions");
    assert_eq!(stopped_sessions.len(), 1);
    assert_eq!(stopped_sessions[0].title, "stopper");
}

#[tokio::test]
async fn title_lookup_after_state_change() {
    let store = Store::new_in_memory()
        .await
        .expect("store initialization should succeed");

    let record = make_session("my-conductor");
    store
        .create_session(&record)
        .await
        .expect("create should succeed");

    store
        .update_session_state(&record.id, SessionState::Running)
        .await
        .expect("update state should succeed");

    // Title lookup should still work and reflect new state.
    let fetched = store
        .get_session_by_title("my-conductor")
        .await
        .expect("title lookup should succeed");
    assert_eq!(fetched.id, record.id);
    assert_eq!(fetched.state, SessionState::Running);
}

#[tokio::test]
async fn delete_nonexistent_session_returns_not_found() {
    let store = Store::new_in_memory()
        .await
        .expect("store initialization should succeed");

    let result = store.delete_session(&SessionId::new()).await;
    assert_matches!(result, Err(StoreError::SessionNotFound { .. }));
}

#[tokio::test]
async fn session_preserves_all_fields() {
    let store = Store::new_in_memory()
        .await
        .expect("store initialization should succeed");

    let record = SessionRecord {
        id: SessionId::new(),
        title: "full-fields".into(),
        path: PathBuf::from("/home/zebas/projects/test"),
        tool: ToolKind::Codex,
        group: Some(GroupId::new("prod-group")),
        parent: Some(SessionId::new()),
        execution_class: ExecutionClass::Builder,
        sandboxed: false,
        state: SessionState::Stopped,
    };

    store
        .create_session(&record)
        .await
        .expect("create should succeed");

    let fetched = store
        .get_session(&record.id)
        .await
        .expect("get should succeed");

    assert_eq!(fetched.title, record.title);
    assert_eq!(fetched.path, record.path);
    assert_eq!(fetched.tool, record.tool);
    assert_eq!(fetched.group, record.group);
    assert_eq!(fetched.parent, record.parent);
    assert_eq!(fetched.execution_class, record.execution_class);
    assert_eq!(fetched.sandboxed, record.sandboxed);
    assert_eq!(fetched.state, record.state);
}
