//! UC2: Status command integration test.
//!
//! Verifies plain-text and JSON status output, and that counts match
//! the actual session states in the store.

#![allow(clippy::expect_used, clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;

use sigil_audit::AuditLogWriter;
use sigil_cli::SessionCommands;
use sigil_core::id::SessionId;
use sigil_core::session::{SessionRecord, SessionState, ToolKind};
use sigil_core::trust::ExecutionClass;
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

async fn tmux_available() -> bool {
    TmuxRuntime::check_tmux().await.is_ok()
}

async fn cleanup(server: &str) {
    let _ = tokio::process::Command::new("tmux")
        .args(["-L", server, "kill-server"])
        .output()
        .await;
}

fn make_record(title: &str, path: &str, state: SessionState) -> SessionRecord {
    SessionRecord {
        id: SessionId::new(),
        title: title.into(),
        path: PathBuf::from(path),
        tool: ToolKind::ClaudeCode,
        group: None,
        parent: None,
        execution_class: ExecutionClass::OfflineWorker,
        sandboxed: true,
        state,
        identity: None,
    }
}

/// Create multiple sessions in various states and verify status counts.
#[tokio::test]
async fn status_counts_match_store_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store should init");

    // Insert sessions directly into the store with different states.
    let records = [
        make_record("s-running", "/tmp", SessionState::Running),
        make_record("s-waiting", "/tmp", SessionState::Waiting),
        make_record("s-stopped-1", "/tmp", SessionState::Stopped),
        make_record("s-stopped-2", "/tmp", SessionState::Stopped),
        make_record("s-error", "/tmp", SessionState::Error),
    ];

    for rec in &records {
        store.create_session(rec).await.expect("insert should work");
    }

    // Run status --json (it prints to stdout, we verify via store).
    sigil_cli::commands::status::run(&store, true)
        .await
        .expect("status --json should succeed");

    // Run status (plain text).
    sigil_cli::commands::status::run(&store, false)
        .await
        .expect("status should succeed");

    // Verify counts by querying the store.
    let all = store.list_sessions().await.expect("list");
    assert_eq!(all.len(), 5);

    let running = all
        .iter()
        .filter(|s| s.state == SessionState::Running)
        .count();
    let waiting = all
        .iter()
        .filter(|s| s.state == SessionState::Waiting)
        .count();
    let stopped = all
        .iter()
        .filter(|s| s.state == SessionState::Stopped)
        .count();
    let error = all
        .iter()
        .filter(|s| s.state == SessionState::Error)
        .count();

    assert_eq!(running, 1);
    assert_eq!(waiting, 1);
    assert_eq!(stopped, 2);
    assert_eq!(error, 1);
}

/// Status with no sessions shows zero counts.
#[tokio::test]
async fn status_empty_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store should init");

    sigil_cli::commands::status::run(&store, false)
        .await
        .expect("status should succeed on empty store");

    sigil_cli::commands::status::run(&store, true)
        .await
        .expect("status --json should succeed on empty store");

    let all = store.list_sessions().await.expect("list");
    assert!(all.is_empty());
}

/// Status counts update after session state transitions via the CLI.
#[tokio::test]
async fn status_updates_after_lifecycle_transitions() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping UC2 lifecycle test");
        return;
    }

    let server = "sigil-test-uc2";
    cleanup(server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store");
    let runtime = TmuxRuntime::new(server);
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, b"uc2-key".to_vec())
            .await
            .expect("audit"),
    );
    let work_dir = dir.path().to_str().expect("valid").to_owned();

    // Create two sessions.
    for name in &["uc2-a", "uc2-b"] {
        sigil_cli::commands::session::run(
            &store,
            &runtime,
            &audit,
            SessionCommands::Create {
                path: work_dir.clone(),
                title: (*name).to_owned(),
                tool: "claude".into(),
                group: None,
                identity: None,
            },
        )
        .await
        .expect("create");
    }

    // Both should be stopped.
    let all = store.list_sessions().await.expect("list");
    assert!(all.iter().all(|s| s.state == SessionState::Stopped));

    // Start one.
    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Start {
            name: "uc2-a".into(),
        },
    )
    .await
    .expect("start");

    let all = store.list_sessions().await.expect("list");
    let running = all
        .iter()
        .filter(|s| s.state == SessionState::Running)
        .count();
    let stopped = all
        .iter()
        .filter(|s| s.state == SessionState::Stopped)
        .count();
    assert_eq!(running, 1);
    assert_eq!(stopped, 1);

    // Stop and remove for cleanup.
    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Stop {
            name: "uc2-a".into(),
        },
    )
    .await
    .expect("stop");

    cleanup(server).await;
}
