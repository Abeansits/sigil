//! Identity reload integration test.
//!
//! Full round-trip: create a session with `--identity`, verify the DB record,
//! verify `.claude/settings.local.json` hooks, run `sigil identity reload`,
//! and verify the reload message was sent.
//!
//! Requires tmux. Skips gracefully if unavailable.

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
use sigil_cli::{IdentityCommands, SessionCommands};
use sigil_conductor::action_service::ActionService;
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

const SERVER: &str = "sigil-test-identity";

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
    let key = b"test-identity-key".to_vec();
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

/// Full identity round-trip: create with --identity, verify DB + hooks,
/// launch, reload, verify message sent.
#[tokio::test]
#[ignore = "requires tmux — run with `cargo test -- --ignored`"]
async fn identity_reload_round_trip() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping identity test");
        return;
    }

    cleanup(SERVER).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, SERVER).await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();
    let title = "identity-test".to_owned();

    // Create identity files in the project directory.
    std::fs::write(
        dir.path().join("SOUL.md"),
        "# Soul\nYou are a test agent.\n",
    )
    .expect("write SOUL.md");
    std::fs::write(dir.path().join("OPS.md"), "# Ops\nBe concise.\n").expect("write OPS.md");
    std::fs::write(dir.path().join("state.json"), "{}").expect("write state.json");

    // ── CREATE with --identity ─────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Create {
            path: work_dir.clone(),
            title: title.clone(),
            tool: "claude".into(),
            group: None,
            identity: Some("SOUL.md,OPS.md,state.json".into()),
        },
    )
    .await
    .expect("create with identity should succeed");

    // ── Verify DB record has identity ──────────────────────────────
    let rec = store
        .get_session_by_title(&title)
        .await
        .expect("session should exist");
    let spec = rec.identity.as_ref().expect("identity should be Some");
    assert_eq!(spec.files.len(), 3, "should have 3 identity files");
    assert_eq!(
        spec.files[0].to_str(),
        Some("SOUL.md"),
        "first file should be SOUL.md"
    );
    assert_eq!(
        spec.files[1].to_str(),
        Some("OPS.md"),
        "second file should be OPS.md"
    );
    assert_eq!(
        spec.files[2].to_str(),
        Some("state.json"),
        "third file should be state.json"
    );

    // ── Verify .claude/settings.local.json was created ─────────────
    let settings_path = dir.path().join(".claude").join("settings.local.json");
    assert!(
        settings_path.exists(),
        "settings.local.json should exist after create with identity"
    );

    let settings_content =
        std::fs::read_to_string(&settings_path).expect("read settings.local.json");
    let settings: serde_json::Value =
        serde_json::from_str(&settings_content).expect("parse settings JSON");

    // Verify PostCompact hook.
    let post_compact_cmd = settings["hooks"]["PostCompact"][0]["hooks"][0]["command"]
        .as_str()
        .expect("PostCompact hook command");
    let expected_reload = format!("sigil identity reload {}", rec.id);
    assert_eq!(
        post_compact_cmd, expected_reload,
        "PostCompact hook should point to identity reload"
    );

    // Verify PreCompact hook.
    let pre_compact_cmd = settings["hooks"]["PreCompact"][0]["hooks"][0]["command"]
        .as_str()
        .expect("PreCompact hook command");
    let expected_snapshot = format!("sigil identity snapshot {}", rec.id);
    assert_eq!(
        pre_compact_cmd, expected_snapshot,
        "PreCompact hook should point to identity snapshot"
    );

    // ── START the session (creates tmux session) ───────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Start {
            name: title.clone(),
        },
    )
    .await
    .expect("start should succeed");

    // Starting a session now auto-launches the declared tool in the
    // pane (fixes F-011 in docs/migration-friction.md). If the `claude`
    // binary is actually on PATH, it may take a couple of seconds for
    // the TUI to reach a ready state; if it isn't, the pane stays at
    // the shell and the reload text lands there. Either way we just
    // need to let the pane settle before sending the reload message.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── RELOAD identity ────────────────────────────────────────────
    sigil_cli::commands::identity::run(
        &service,
        IdentityCommands::Reload {
            name: title.clone(),
        },
    )
    .await
    .expect("identity reload should succeed");

    // The identity-reload call succeeded above — that proves the
    // full pipeline (resolve session → build message → dispatch
    // SendMessage → runtime.send) executed without error. We used to
    // additionally assert the `[SIGIL]` bytes showed up in
    // `capture-pane` output, but that check relied on a bare zsh
    // prompt echoing the typed command. With the F-011 fix the pane
    // now hosts the actual tool TUI (Claude Code if installed), which
    // absorbs pasted bytes into its input model instead of echoing
    // them to the scrollback. Runtime-level submit behaviour is
    // covered by `send_delivers_message_literally_and_submits` in
    // `sigil-runtime` against a deterministic `/bin/sh`.

    // ── SNAPSHOT identity ──────────────────────────────────────────
    sigil_cli::commands::identity::run(
        &service,
        IdentityCommands::Snapshot {
            name: title.clone(),
        },
    )
    .await
    .expect("identity snapshot should succeed");

    // ── Cleanup ────────────────────────────────────────────────────
    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Stop {
            name: title.clone(),
        },
    )
    .await
    .expect("stop should succeed");

    cleanup(SERVER).await;
}

/// `identity reload` on a session with no identity spec returns a clear error.
#[tokio::test]
async fn identity_reload_no_spec_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, "sigil-test-identity-nospec").await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();
    let title = "no-identity-session".to_owned();

    // Create a session without identity.
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
    .expect("create should succeed");

    // Reload should fail with a clear error.
    let result = sigil_cli::commands::identity::run(
        &service,
        IdentityCommands::Reload {
            name: title.clone(),
        },
    )
    .await;

    assert!(result.is_err(), "reload without identity should fail");
    let err_msg = format!("{}", result.expect_err("should be error"));
    assert!(
        err_msg.contains("no identity spec"),
        "error should mention missing identity spec, got: {err_msg}"
    );
}

/// `session create` without `--identity` should not create settings.local.json.
#[tokio::test]
async fn create_without_identity_skips_hooks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, runtime, audit) = setup(&dir, "sigil-test-identity-nohooks").await;
    let service = build_action_service(&store, &runtime, &audit);
    let work_dir = dir.path().to_str().expect("valid path").to_owned();

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Create {
            path: work_dir,
            title: "no-hooks-session".into(),
            tool: "claude".into(),
            group: None,
            identity: None,
        },
    )
    .await
    .expect("create should succeed");

    let settings_path = dir.path().join(".claude").join("settings.local.json");
    assert!(
        !settings_path.exists(),
        "settings.local.json should not exist when no identity is configured"
    );
}
