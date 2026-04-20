//! `session launch --worktree` compound flow integration tests.
//!
//! Covers:
//! - create-branch path (`-b`): new branch + worktree + running session.
//! - attach path (no `-b`): existing branch becomes the worktree cwd.
//! - two branch/flag mismatch errors fail pre-create-session, leaving
//!   no stranded session record.
//! - launches without `--worktree` are unchanged (sanity check on the
//!   plain path, small smoke test).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::wildcard_enum_match_arm
)]

use std::sync::Arc;

use sigil_audit::AuditLogWriter;
use sigil_cli::{SessionCommands, WorktreeCommands};
use sigil_conductor::action_service::ActionService;
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_runtime::{TmuxRuntime, WorktreeManager};
use sigil_store::Store;

const SERVER: &str = "sigil-test-launch-wt";

async fn tmux_available() -> bool {
    TmuxRuntime::check_tmux().await.is_ok()
}

async fn kill_tmux_server(server: &str) {
    let _ = tokio::process::Command::new("tmux")
        .args(["-L", server, "kill-server"])
        .output()
        .await;
}

async fn build_service(
    dir: &std::path::Path,
    server: &str,
) -> (
    ActionService<TmuxRuntime, PolicyService<NoopGrantStore>>,
    Arc<Store>,
) {
    let db_path = dir.join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Arc::new(Store::new(db_str).await.expect("store"));
    let runtime = Arc::new(TmuxRuntime::new(server));
    let audit_path = dir.join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, b"launch-wt-key".to_vec())
            .await
            .expect("audit"),
    );
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore));
    let service = ActionService::new(
        policy,
        Arc::clone(&runtime),
        Arc::clone(&audit),
        Arc::clone(&store),
    );
    (service, store)
}

async fn init_git_repo(path: &std::path::Path) {
    for args in [
        &["init", "-b", "main"][..],
        &["config", "user.email", "test@sigil.dev"][..],
        &["config", "user.name", "Sigil Test"][..],
    ] {
        tokio::process::Command::new("git")
            .args(args)
            .current_dir(path)
            .output()
            .await
            .expect("git");
    }

    std::fs::write(path.join("README.md"), "# test\n").expect("README");

    for args in [&["add", "."][..], &["commit", "-m", "init"][..]] {
        tokio::process::Command::new("git")
            .args(args)
            .current_dir(path)
            .output()
            .await
            .expect("git");
    }
}

async fn create_branch(repo: &std::path::Path, branch: &str) {
    tokio::process::Command::new("git")
        .args(["branch", branch])
        .current_dir(repo)
        .output()
        .await
        .expect("git branch");
}

/// Drop the active session record and its tmux session so tests don't
/// leak state when run back-to-back.
async fn teardown(store: &Arc<Store>, title: &str) {
    if let Ok(rec) = store.get_session_by_title(title).await {
        let _ = store.delete_session(&rec.id).await;
    }
}

// ---------------------------------------------------------------------------
// Happy paths — require tmux
// ---------------------------------------------------------------------------

#[tokio::test]
async fn launch_with_worktree_creates_branch_and_session_in_worktree() {
    if !tmux_available().await {
        eprintln!("tmux missing — skipping launch_with_worktree happy-path test");
        return;
    }

    let server = format!("{SERVER}-create-b");
    kill_tmux_server(&server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let (service, store) = build_service(dir.path(), &server).await;
    let title = "launch-wt-create";
    let branch = "feature/launch-create";

    let result = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: title.to_owned(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some(branch.to_owned()),
            create_branch: true,
        },
    )
    .await;

    assert!(result.is_ok(), "launch should succeed: {result:?}");

    // Session record's path must be the worktree path, not the repo.
    let expected_wt = WorktreeManager::worktree_path(&repo_path, branch);
    let rec = store
        .get_session_by_title(title)
        .await
        .expect("session persisted");
    assert_eq!(
        rec.path, expected_wt,
        "session.path should be the worktree dir so tmux launches there",
    );
    assert!(
        expected_wt.exists(),
        "worktree dir should exist on disk at {}",
        expected_wt.display(),
    );

    // Cleanup.
    teardown(&store, title).await;
    let _ = WorktreeManager::finish(&repo_path, branch, &expected_wt, false).await;
    kill_tmux_server(&server).await;
}

#[tokio::test]
async fn launch_with_worktree_attaches_existing_branch() {
    if !tmux_available().await {
        eprintln!("tmux missing — skipping launch_with_worktree attach test");
        return;
    }

    let server = format!("{SERVER}-attach");
    kill_tmux_server(&server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let branch = "feature/preexisting";
    create_branch(&repo_path, branch).await;

    let (service, store) = build_service(dir.path(), &server).await;
    let title = "launch-wt-attach";

    let result = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: title.to_owned(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some(branch.to_owned()),
            create_branch: false,
        },
    )
    .await;

    assert!(result.is_ok(), "attach should succeed: {result:?}");

    let expected_wt = WorktreeManager::worktree_path(&repo_path, branch);
    assert!(expected_wt.exists(), "worktree dir should exist");

    teardown(&store, title).await;
    let _ = WorktreeManager::finish(&repo_path, branch, &expected_wt, false).await;
    kill_tmux_server(&server).await;
}

// ---------------------------------------------------------------------------
// Error paths — only need git, no tmux
// ---------------------------------------------------------------------------

#[tokio::test]
async fn launch_errors_when_create_branch_but_branch_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let branch = "feature/already-here";
    create_branch(&repo_path, branch).await;

    let server = format!("{SERVER}-err-exists");
    let (service, store) = build_service(dir.path(), &server).await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: "err-exists".into(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some(branch.to_owned()),
            create_branch: true,
        },
    )
    .await
    .expect_err("launch should reject -b on an existing branch");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("already exists"),
        "error should explain branch already exists: {msg}",
    );

    // No session should have been created.
    assert!(
        store.get_session_by_title("err-exists").await.is_err(),
        "no session should be persisted when pre-flight fails",
    );
}

#[tokio::test]
async fn launch_errors_when_branch_missing_without_create_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let server = format!("{SERVER}-err-missing");
    let (service, store) = build_service(dir.path(), &server).await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: "err-missing".into(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some("feature/never-created".into()),
            create_branch: false,
        },
    )
    .await
    .expect_err("launch should reject attach to a missing branch");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not exist"),
        "error should explain branch missing: {msg}",
    );

    assert!(
        store.get_session_by_title("err-missing").await.is_err(),
        "no session should be persisted when pre-flight fails",
    );
}

#[tokio::test]
async fn launch_rejects_worktree_combined_with_project_identity_config() {
    // `.sigil/config.toml` declares an identity — the launch must
    // refuse rather than silently strip the spec and start a session
    // without its hooks. This mirrors the explicit --identity rejection
    // but covers the config-file path.
    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let sigil_dir = repo_path.join(".sigil");
    std::fs::create_dir_all(&sigil_dir).expect("mkdir .sigil");
    std::fs::write(
        sigil_dir.join("config.toml"),
        r#"
[identity]
files = ["SOUL.md"]
reload_on = ["PostCompact"]
"#,
    )
    .expect("write config.toml");

    let server = format!("{SERVER}-identity-reject");
    let (service, store) = build_service(dir.path(), &server).await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: "identity-reject".into(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some("feature/anything".into()),
            create_branch: true,
        },
    )
    .await
    .expect_err("launch should refuse --worktree when project identity is set");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("identity"),
        "error should mention identity: {msg}",
    );

    // Nothing persisted — pre-flight rejection happens before
    // CreateSession.
    assert!(store.get_session_by_title("identity-reject").await.is_err());
}

#[tokio::test]
async fn worktree_finish_discovers_launched_via_worktree_session() {
    if !tmux_available().await {
        eprintln!("tmux missing — skipping worktree_finish_discovers test");
        return;
    }

    let server = format!("{SERVER}-finish-disc");
    kill_tmux_server(&server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    let (service, store) = build_service(dir.path(), &server).await;
    let title = "launch-wt-finish";
    let branch = "feature/finish-discovery";

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: title.to_owned(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some(branch.to_owned()),
            create_branch: true,
        },
    )
    .await
    .expect("launch with worktree");

    // Confirm the session was stored with the worktree path.
    let rec = store
        .get_session_by_title(title)
        .await
        .expect("session persisted");
    let expected_wt = WorktreeManager::worktree_path(&repo_path, branch);
    assert_eq!(rec.path, expected_wt);

    // `sigil worktree finish <session>` must still be able to locate
    // and remove the worktree even though session.path is the worktree
    // itself, not the repo root. Before the fix, repo_root_for_session
    // would treat `.worktrees/foo` as the repo and look for
    // `.worktrees/foo/.worktrees`, finding nothing.
    sigil_cli::commands::worktree::run(
        &service,
        WorktreeCommands::Finish {
            name: title.to_owned(),
            merge: false,
        },
    )
    .await
    .expect("worktree finish should locate and remove the launched worktree");

    assert!(
        !expected_wt.exists(),
        "worktree dir should be removed by finish",
    );

    teardown(&store, title).await;
    kill_tmux_server(&server).await;
}

// ---------------------------------------------------------------------------
// Rollback path: git worktree fails after preflight → session record and
// any partial filesystem state must be cleaned up.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn launch_rollback_when_git_worktree_fails_after_preflight() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("mkdir");
    init_git_repo(&repo_path).await;

    // Preflight: branch doesn't exist, -b is set — passes.
    let branch = "feature/rollback-test";

    // Sabotage the would-be worktree path by pre-creating a file at the
    // expected location so `git worktree add` fails *after* preflight.
    let wt_path = WorktreeManager::worktree_path(&repo_path, branch);
    std::fs::create_dir_all(
        wt_path
            .parent()
            .expect("worktree path has a parent (`.worktrees/`)"),
    )
    .expect("mkdir .worktrees");
    std::fs::write(&wt_path, "sabotage\n").expect("sabotage file");

    let server = format!("{SERVER}-rollback");
    let (service, store) = build_service(dir.path(), &server).await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Launch {
            path: repo_path.to_str().expect("utf8").to_owned(),
            title: "rollback-test".into(),
            tool: "claude".into(),
            group: None,
            message: None,
            identity: None,
            worktree: Some(branch.to_owned()),
            create_branch: true,
        },
    )
    .await
    .expect_err("launch should fail when git worktree add cannot run");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("worktree"),
        "error should mention worktree failure: {msg}",
    );

    // Session record must be cleaned up so a retry isn't blocked by
    // DuplicateTitle.
    assert!(
        store.get_session_by_title("rollback-test").await.is_err(),
        "session record should be rolled back when git worktree fails",
    );

    // Sabotage-file at the worktree path must be untouched — rollback
    // is existence-aware and only runs `git worktree remove` on dirs
    // actually created by git worktree add.
    assert!(
        wt_path.exists(),
        "pre-existing sabotage file must not be clobbered by rollback",
    );

    // Branch side-effect is intentionally NOT cleaned up on this path.
    // `git worktree add -b` creates the branch before binding the path,
    // so a failed add can leave a branch behind. The conservative
    // rollback policy (see LaunchProgress::new_branch_owned) skips
    // force-delete here to avoid destroying a branch created
    // concurrently by another actor in the TOCTOU window. The test
    // therefore asserts nothing about branch existence — either outcome
    // is acceptable; the contract is only "no data loss of unrelated
    // branches" + "session record rolled back".
}

// ---------------------------------------------------------------------------
// Clap-level guard: -b without --worktree is rejected at parse time.
// ---------------------------------------------------------------------------

#[test]
fn clap_rejects_create_branch_without_worktree() {
    use clap::Parser;

    let result = sigil_cli::Cli::try_parse_from([
        "sigil",
        "session",
        "launch",
        "/tmp/whatever",
        "-t",
        "no-worktree",
        "-b",
    ]);
    assert!(
        result.is_err(),
        "-b should require --worktree at the CLI layer",
    );
}

#[test]
fn clap_accepts_worktree_flags() {
    use clap::Parser;

    let cli = sigil_cli::Cli::try_parse_from([
        "sigil",
        "session",
        "launch",
        "/tmp/repo",
        "-t",
        "with-wt",
        "-w",
        "feature/new",
        "-b",
    ])
    .expect("launch + -w + -b should parse");

    match cli.command {
        sigil_cli::Commands::Session(SessionCommands::Launch {
            worktree,
            create_branch,
            ..
        }) => {
            assert_eq!(worktree.as_deref(), Some("feature/new"));
            assert!(create_branch);
        }
        other => panic!("expected Session Launch, got {other:?}"),
    }
}
