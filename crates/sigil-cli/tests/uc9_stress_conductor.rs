//! UC9: Multi-session conductor stress test.
//!
//! Creates 10 tmux sessions, runs conductor heartbeat and reconciliation,
//! verifies all sessions are tracked, then kills 3 externally and verifies
//! the conductor detects the disappearances.
//!
//! Requires tmux. Marked `#[ignore]` because it takes ~15 seconds.

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
use sigil_conductor::Conductor;
use sigil_core::session::SessionState;
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

const SESSION_COUNT: usize = 10;
const KILL_COUNT: usize = 3;

async fn tmux_available() -> bool {
    TmuxRuntime::check_tmux().await.is_ok()
}

async fn cleanup(server: &str) {
    let _ = tokio::process::Command::new("tmux")
        .args(["-L", server, "kill-server"])
        .output()
        .await;
}

/// Create and start all sessions, returning their names.
async fn create_and_start_sessions(
    store: &Store,
    runtime: &TmuxRuntime,
    audit: &Arc<AuditLogWriter>,
    work_dir: &str,
) -> Vec<String> {
    let names: Vec<String> = (0..SESSION_COUNT)
        .map(|i| format!("uc9-sess-{i:02}"))
        .collect();

    for name in &names {
        sigil_cli::commands::session::run(
            store,
            runtime,
            audit,
            SessionCommands::Create {
                path: work_dir.to_owned(),
                title: name.clone(),
                tool: "claude".into(),
                group: None,
                identity: None,
            },
        )
        .await
        .expect("create session");

        sigil_cli::commands::session::run(
            store,
            runtime,
            audit,
            SessionCommands::Start { name: name.clone() },
        )
        .await
        .expect("start session");
    }

    // Verify all are in the store as Running.
    let sessions = store.list_sessions().await.expect("list");
    assert_eq!(
        sessions.len(),
        SESSION_COUNT,
        "should have {SESSION_COUNT} sessions"
    );
    for s in &sessions {
        assert_eq!(
            s.state,
            SessionState::Running,
            "session '{}' should be Running",
            s.title
        );
    }

    names
}

/// Kill the first `KILL_COUNT` sessions externally via tmux, then run a
/// heartbeat and verify the conductor detected the failures.
async fn kill_and_verify(
    conductor: &Conductor<TmuxRuntime>,
    store: &Store,
    server: &str,
    session_names: &[String],
) {
    let victims = &session_names[..KILL_COUNT];
    for name in victims {
        let output = tokio::process::Command::new("tmux")
            .args(["-L", server, "kill-session", "-t", name])
            .output()
            .await
            .expect("kill-session command");
        assert!(
            output.status.success(),
            "tmux kill-session -t {name} should succeed"
        );
    }

    // Brief pause so tmux state settles.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Heartbeat detects dead sessions.
    let hb = conductor
        .run_heartbeat_cycle()
        .await
        .expect("heartbeat post-kill");

    assert_eq!(
        hb.total, SESSION_COUNT,
        "total should still be {SESSION_COUNT}"
    );
    assert!(
        hb.error >= KILL_COUNT,
        "expected at least {KILL_COUNT} errors after killing sessions, got {}",
        hb.error
    );

    // Verify the store was updated: killed sessions should be Error.
    for name in victims {
        let record = store.get_session_by_title(name).await.expect("get session");
        assert_eq!(
            record.state,
            SessionState::Error,
            "killed session '{name}' should be Error in store"
        );
    }

    // Surviving sessions should not be Error.
    let survivors = &session_names[KILL_COUNT..];
    for name in survivors {
        let record = store
            .get_session_by_title(name.as_str())
            .await
            .expect("get session");
        assert_ne!(
            record.state,
            SessionState::Error,
            "surviving session '{name}' should not be Error"
        );
    }
}

#[tokio::test]
#[ignore = "spawns 10 tmux sessions; ~15s wall time"]
async fn stress_conductor_detects_killed_sessions() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping UC9");
        return;
    }

    let server = "sigil-test-uc9-stress";
    cleanup(server).await;

    // -- Setup: store, runtime, audit --
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Arc::new(Store::new(db_str).await.expect("store"));
    let runtime = Arc::new(TmuxRuntime::new(server));
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, b"uc9-key".to_vec())
            .await
            .expect("audit"),
    );
    let work_dir = dir.path().to_str().expect("valid").to_owned();

    // -- Phase 1: Create and start 10 sessions --
    let session_names = create_and_start_sessions(&store, &runtime, &audit, &work_dir).await;

    // -- Phase 2: Conductor startup reconciliation --
    let conductor = Conductor::new(
        Arc::clone(&store),
        Arc::clone(&runtime),
        Duration::from_secs(5),
    );

    let reconcile_result = conductor
        .startup_reconcile()
        .await
        .expect("startup reconciliation");

    assert_eq!(
        reconcile_result.sessions_checked, SESSION_COUNT,
        "reconciliation should check all sessions"
    );

    // -- Phase 3: Heartbeat — all sessions alive --
    let hb1 = conductor
        .run_heartbeat_cycle()
        .await
        .expect("heartbeat cycle 1");

    assert_eq!(
        hb1.total, SESSION_COUNT,
        "heartbeat should see all sessions"
    );
    assert_eq!(
        hb1.running + hb1.stopped + hb1.error + hb1.waiting + hb1.idle,
        SESSION_COUNT,
        "all sessions should be categorized"
    );

    // -- Phase 4 & 5: Kill 3 sessions, verify detection --
    kill_and_verify(&conductor, &store, server, &session_names).await;

    // -- Phase 6: Reconciliation post-kill --
    let reconcile2 = conductor
        .startup_reconcile()
        .await
        .expect("reconciliation post-kill");

    assert_eq!(reconcile2.sessions_checked, SESSION_COUNT);

    // -- Cleanup --
    for name in &session_names[KILL_COUNT..] {
        let _ = sigil_cli::commands::session::run(
            &store,
            &*runtime,
            &audit,
            SessionCommands::Stop { name: name.clone() },
        )
        .await;
    }

    cleanup(server).await;

    println!(
        "UC9 stress test passed: {SESSION_COUNT} sessions created, \
         {KILL_COUNT} killed, conductor detected all failures."
    );
}
