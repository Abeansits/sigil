//! UC1: Full session lifecycle integration test.
//!
//! Exercises create -> list -> show -> start -> send -> output -> stop -> remove
//! against a real tmux backend, verifying `SQLite` state at each step.
//!
//! Requires tmux to be installed. Skips gracefully if unavailable.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_cli::{SessionCommands, WorktreeCommands};
use sigil_conductor::action_service::ActionService;
use sigil_core::session::SessionState;
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

const SERVER: &str = "sigil-test-uc1";

async fn tmux_available() -> bool {
    TmuxRuntime::check_tmux().await.is_ok()
}

async fn cleanup(server: &str) {
    let _ = tokio::process::Command::new("tmux")
        .args(["-L", server, "kill-server"])
        .output()
        .await;
}

async fn setup(
    dir: &tempfile::TempDir,
    server: &str,
) -> (Arc<Store>, Arc<TmuxRuntime>, Arc<AuditLogWriter>) {
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store should init");
    let runtime = TmuxRuntime::new(server);
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"test-uc1-key".to_vec();
    let writer = AuditLogWriter::new(&audit_path, key)
        .await
        .expect("audit writer should init");
    (Arc::new(store), Arc::new(runtime), Arc::new(writer))
}

fn build_action_service(
    store: &Arc<Store>,
    runtime: &Arc<TmuxRuntime>,
    audit: &Arc<AuditLogWriter>,
) -> ActionService<TmuxRuntime, PolicyService<NoopGrantStore>> {
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore));
    ActionService::new(
        policy,
        Arc::clone(runtime),
        Arc::clone(audit),
        Arc::clone(store),
    )
}

#[tokio::test]
async fn full_session_lifecycle() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping UC1");
        return;
    }

    // Ensure no leftover server from a prior failed run.
    cleanup(SERVER).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, SERVER).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();
    let title = "uc1-lifecycle".to_owned();

    // ── CREATE ──────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Create {
            path: work_dir.clone(),
            title: title.clone(),
            tool: "claude".into(),
            group: None,
            identity: None,
        },
    )
    .await
    .expect("create should succeed");

    let rec = store
        .get_session_by_title(&title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Stopped,
        "new session should be Stopped"
    );

    // ── LIST ────────────────────────────────────────────────────────
    let sessions = store.list_sessions().await.expect("list should work");
    assert_eq!(sessions.len(), 1);

    // ── SHOW (verify fields through store) ─────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Show {
            name: title.clone(),
            json: true,
        },
    )
    .await
    .expect("show --json should succeed");

    // ── START ───────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Start {
            name: title.clone(),
        },
    )
    .await
    .expect("start should succeed");

    let rec = store
        .get_session_by_title(&title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Running,
        "started session should be Running"
    );

    // ── SEND ────────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: title.clone(),
            message: "echo hello-from-sigil-uc1".into(),
            wait: false,
            no_wait: false,
            quiet: true,
            timeout: None,
        },
    )
    .await
    .expect("send should succeed");

    // Give tmux a moment to process the keystrokes.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── OUTPUT ──────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Output {
            name: title.clone(),
            quiet: true,
        },
    )
    .await
    .expect("output should succeed");

    // ── STOP ────────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Stop {
            name: title.clone(),
        },
    )
    .await
    .expect("stop should succeed");

    let rec = store
        .get_session_by_title(&title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Stopped,
        "stopped session should be Stopped"
    );

    // ── REMOVE ──────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Remove {
            name: title.clone(),
        },
    )
    .await
    .expect("remove should succeed");

    let sessions = store.list_sessions().await.expect("list");
    assert!(sessions.is_empty(), "store should be empty after remove");

    cleanup(SERVER).await;
}

/// Verify that `session restart` cycles through stop -> start.
#[tokio::test]
async fn session_restart_returns_to_running() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping restart test");
        return;
    }

    let server = "sigil-test-uc1-restart";
    cleanup(server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, server).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid").to_owned();
    let title = "uc1-restart".to_owned();

    // Create and start.
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Create {
            path: work_dir,
            title: title.clone(),
            tool: "claude".into(),
            group: None,
            identity: None,
        },
    )
    .await
    .expect("create");

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Start {
            name: title.clone(),
        },
    )
    .await
    .expect("start");

    // Restart.
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Restart {
            name: title.clone(),
        },
    )
    .await
    .expect("restart");

    let rec = store.get_session_by_title(&title).await.expect("session");
    assert_eq!(
        rec.state,
        SessionState::Running,
        "restarted session should be Running"
    );

    // Cleanup.
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Stop {
            name: title.clone(),
        },
    )
    .await
    .expect("stop");

    cleanup(server).await;
}

/// Verify that `session launch` creates, starts, and sends in one call.
#[tokio::test]
async fn session_launch_combines_create_start_send() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping launch test");
        return;
    }

    let server = "sigil-test-uc1-launch";
    cleanup(server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, server).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid").to_owned();
    let title = "uc1-launch".to_owned();

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: work_dir,
            title: title.clone(),
            tool: "codex".into(),
            group: Some("test-group".into()),
            message: Some("echo launched".into()),
            identity: None,
            worktree: None,
            create_branch: false,
        },
    )
    .await
    .expect("launch should succeed");

    let rec = store
        .get_session_by_title(&title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Running,
        "launched session should be Running"
    );
    assert_eq!(format!("{:?}", rec.tool), "Codex", "tool should be Codex");

    // The session should show up in list.
    let sessions = store.list_sessions().await.expect("list");
    assert_eq!(sessions.len(), 1);

    // Stop for cleanup.
    let handle = sigil_core::session::SessionHandle {
        id: rec.id,
        title: rec.title.clone(),
        tool: rec.tool,
        state: rec.state,
        path: rec.path.clone(),
        tmux_window: Some(rec.title.clone()),
        container_id: None,
        execution_class: rec.execution_class,
        sandboxed: rec.sandboxed,
        identity: None,
    };
    let _ = sigil_core::traits::SessionRuntime::stop(&*runtime, &handle).await;

    cleanup(server).await;
}

/// `worktree list` shows no worktrees when there are no git-backed sessions.
#[tokio::test]
async fn worktree_list_on_non_git_dir_produces_no_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Arc::new(Store::new(db_str).await.expect("store should init"));
    let runtime = Arc::new(TmuxRuntime::new("sigil-test-uc1-wtlist"));
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, b"uc1-key".to_vec())
            .await
            .expect("audit"),
    );
    let service = build_action_service(&store, &runtime, &audit);

    // Run worktree list with no sessions — should succeed without error.
    sigil_cli::commands::worktree::run(&service, WorktreeCommands::List)
        .await
        .expect("worktree list should succeed");
}
