//! UC10: Meta-test — sigil managing a session that echoes back.
//!
//! Exercises the full session lifecycle through the CLI API:
//! create → start → send `echo <marker>` → read output → verify marker
//! → stop → remove.
//!
//! No API keys required — just tmux + a shell echo.
//!
//! Marked `#[ignore]` because it requires tmux and takes ~2 seconds.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_cli::SessionCommands;
use sigil_conductor::action_service::ActionService;
use sigil_core::session::SessionState;
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

const SERVER: &str = "sigil-test-uc10";

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
    let key = b"test-uc10-key".to_vec();
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
#[ignore = "requires tmux — run with `cargo test -- --ignored`"]
async fn meta_session_echo_roundtrip() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping UC10");
        return;
    }

    cleanup(SERVER).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, SERVER).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();
    let title = "uc10-meta".to_owned();
    let marker = format!("hello-from-sigil-uc10-{}", std::process::id());

    // ── CREATE + START ─────────────────────────────────────────────
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

    // ── SEND echo ───────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: title.clone(),
            message: format!("echo {marker}"),
            wait: false,
            quiet: true,
        },
    )
    .await
    .expect("send should succeed");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── READ OUTPUT and VERIFY ──────────────────────────────────────
    let handle = sigil_core::session::SessionHandle {
        id: rec.id,
        title: rec.title.clone(),
        tool: rec.tool,
        state: SessionState::Running,
        path: rec.path.clone(),
        tmux_window: Some(rec.title.clone()),
        container_id: None,
        execution_class: rec.execution_class,
        sandboxed: rec.sandboxed,
        identity: None,
    };
    let output = sigil_core::traits::SessionRuntime::read_output(runtime.as_ref(), &handle)
        .await
        .expect("read_output should succeed");
    println!("--- captured output ---\n{output}\n--- end ---");
    assert!(
        output.contains(&marker),
        "marker '{marker}' not in output:\n{output}"
    );

    // ── STOP + REMOVE ─────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Stop {
            name: title.clone(),
        },
    )
    .await
    .expect("stop should succeed");

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Remove {
            name: title.clone(),
        },
    )
    .await
    .expect("remove should succeed");

    cleanup(SERVER).await;
}
