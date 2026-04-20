//! UC8: Container session lifecycle integration test.
//!
//! Exercises create -> start -> send -> output -> stop -> remove using
//! `ContainerRuntime` against a real Apple Containers backend.
//!
//! Requires the `container` feature and Apple Containers CLI (`container`
//! binary). Skips gracefully if either is unavailable.
//!
//! Run with: `cargo test --features container --test uc8_container_session_lifecycle`

#![cfg(feature = "container")]
#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_cli::SessionCommands;
use sigil_conductor::action_service::ActionService;
use sigil_core::session::SessionState;
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_runtime::{ContainerConfig, ContainerRuntime};
use sigil_store::Store;

const IMAGE: &str = "sigil-agent:latest";

async fn container_cli_available() -> bool {
    ContainerRuntime::check_container_cli().await.is_ok()
}

async fn setup(
    dir: &tempfile::TempDir,
) -> (Arc<Store>, Arc<ContainerRuntime>, Arc<AuditLogWriter>) {
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store should init");
    let config = ContainerConfig {
        image: IMAGE.to_owned(),
        ..ContainerConfig::default()
    };
    let runtime = ContainerRuntime::new(config);
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"test-uc8-key".to_vec();
    let writer = AuditLogWriter::new(&audit_path, key)
        .await
        .expect("audit writer should init");
    (Arc::new(store), Arc::new(runtime), Arc::new(writer))
}

fn build_action_service(
    store: &Arc<Store>,
    runtime: &Arc<ContainerRuntime>,
    audit: &Arc<AuditLogWriter>,
) -> ActionService<ContainerRuntime, PolicyService<NoopGrantStore>> {
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore));
    ActionService::new(
        policy,
        Arc::clone(runtime),
        Arc::clone(audit),
        Arc::clone(store),
    )
}

/// Best-effort cleanup: stop and remove the container.
async fn cleanup_container(name: &str) {
    let _ = tokio::process::Command::new("container")
        .args(["stop", name, "--time", "5"])
        .output()
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = tokio::process::Command::new("container")
        .args(["rm", name])
        .output()
        .await;
}

#[tokio::test]
async fn container_session_lifecycle() {
    if !container_cli_available().await {
        eprintln!("Apple Containers CLI not available -- skipping UC8");
        return;
    }

    let title = "uc8-lifecycle";

    // Ensure no leftover container from a prior failed run.
    cleanup_container(title).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();

    // ── CREATE ──────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Create {
            path: work_dir.clone(),
            title: title.to_owned(),
            tool: "claude".into(),
            group: None,
            identity: None,
        },
    )
    .await
    .expect("create should succeed");

    let rec = store
        .get_session_by_title(title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Stopped,
        "new session should be Stopped"
    );

    // ── START ───────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Start {
            name: title.to_owned(),
        },
    )
    .await
    .expect("start should succeed");

    let rec = store
        .get_session_by_title(title)
        .await
        .expect("session should exist");
    assert_eq!(
        rec.state,
        SessionState::Running,
        "started session should be Running"
    );

    // Give the container a moment to initialize.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── SEND ────────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: title.to_owned(),
            message: "echo hello-from-sigil-uc8".into(),
            wait: false,
            no_wait: false,
            quiet: true,
            timeout: Duration::from_secs(600),
        },
    )
    .await
    .expect("send should succeed");

    // Give the container time to process the command.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── OUTPUT ──────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Output {
            name: title.to_owned(),
            quiet: true,
        },
    )
    .await
    .expect("output should succeed");

    // ── STOP ────────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Stop {
            name: title.to_owned(),
        },
    )
    .await
    .expect("stop should succeed");

    let rec = store
        .get_session_by_title(title)
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
            name: title.to_owned(),
        },
    )
    .await
    .expect("remove should succeed");

    let sessions = store.list_sessions().await.expect("list");
    assert!(sessions.is_empty(), "store should be empty after remove");

    // Final cleanup (container already removed by stop, but just in case).
    cleanup_container(title).await;
}
