//! Tier 3: CLI black-box tests for the `sigil` binary.
//!
//! These tests exercise the actual compiled binary via `std::process::Command`,
//! asserting on exit codes and stdout/stderr. No test crate dependencies beyond
//! the standard library.
//!
//! Each test gets its own `tempdir` for `--db` and audit isolation.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

/// Cached binary path — built once, reused across all tests in the process.
static SIGIL_BIN: OnceLock<PathBuf> = OnceLock::new();

/// Build the sigil binary and return its path.
///
/// Uses `cargo build --message-format=json` to parse the actual executable
/// path from compiler artifacts, so it works with custom `CARGO_TARGET_DIR`,
/// cross-compilation `--target` triples, and platform suffixes (`.exe`).
fn sigil_bin() -> &'static Path {
    SIGIL_BIN.get_or_init(|| {
        let output = Command::new("cargo")
            .args(["build", "--bin", "sigil", "--message-format=json"])
            .output()
            .expect("failed to run cargo build");
        assert!(
            output.status.success(),
            "cargo build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|msg| msg["reason"] == "compiler-artifact")
            .filter_map(|msg| msg["executable"].as_str().map(PathBuf::from))
            .next_back()
            .expect("cargo build should produce an executable artifact")
    })
}

/// Run the sigil binary with the given args, pointing `--db` at the
/// provided temp directory for isolation. Returns the `Output`.
///
/// The db is placed inside `<tmp>/.sigil/sigil.db` so the audit log
/// lands at `<tmp>/.sigil/audit.jsonl`, matching the default verify path.
fn run_sigil(tmp: &Path, args: &[&str]) -> Output {
    let sigil_dir = tmp.join(".sigil");
    let db_path = sigil_dir.join("sigil.db");

    Command::new(sigil_bin())
        .arg("--db")
        .arg(&db_path)
        .args(args)
        .env("HOME", tmp)
        .env("SIGIL_AUDIT_KEY", "test-blackbox-key")
        .env("RUST_LOG", "off")
        .env_remove("SIGIL_RUNTIME")
        .env_remove("SIGIL_DB")
        .output()
        .expect("failed to execute sigil binary")
}

/// Run sigil without injecting `--db` (for flag-level tests like --version).
fn run_sigil_raw(args: &[&str]) -> Output {
    Command::new(sigil_bin())
        .args(args)
        .output()
        .expect("failed to execute sigil binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn version_flag_shows_version_string() {
    let out = run_sigil_raw(&["--version"]);
    assert!(out.status.success(), "exit code should be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sigil"),
        "stdout should contain 'sigil': {stdout}"
    );
}

#[test]
fn help_flag_shows_usage_and_subcommands() {
    let out = run_sigil_raw(&["--help"]);
    assert!(out.status.success(), "exit code should be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Usage"),
        "stdout should contain 'Usage': {stdout}"
    );
    assert!(
        stdout.contains("session"),
        "stdout should mention 'session' subcommand: {stdout}"
    );
}

#[test]
fn unknown_subcommand_returns_error() {
    let out = run_sigil_raw(&["definitely-not-a-command"]);
    assert!(
        !out.status.success(),
        "unknown subcommand should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error") || stderr.contains("unrecognized"),
        "stderr should indicate an error: {stderr}"
    );
}

#[test]
fn status_empty_store_shows_zero_sessions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["status"]);
    assert!(
        out.status.success(),
        "status should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 sessions"),
        "empty store should show '0 sessions': {stdout}"
    );
}

#[test]
fn status_json_empty_store_returns_zero_counts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["status", "--json"]);
    assert!(
        out.status.success(),
        "status --json should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Parse as JSON to verify structure.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["total"], 0, "total should be 0");
    assert_eq!(parsed["running"], 0, "running should be 0");
}

#[test]
fn session_list_empty_store_shows_no_sessions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["session", "list"]);
    assert!(
        out.status.success(),
        "session list should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No sessions"),
        "empty store should say 'No sessions': {stdout}"
    );
}

#[test]
fn session_list_json_empty_store_returns_empty_array() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["session", "list", "--json"]);
    assert!(
        out.status.success(),
        "session list --json should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert!(parsed.is_array(), "should be an array");
    assert_eq!(
        parsed.as_array().expect("array").len(),
        0,
        "array should be empty"
    );
}

#[test]
fn session_create_then_list_includes_new_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    // Create a session.
    let out = run_sigil(
        tmp.path(),
        &[
            "session",
            "create",
            work_dir,
            "-t",
            "bb-test-create",
            "-c",
            "claude",
        ],
    );
    assert!(
        out.status.success(),
        "session create should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Created session 'bb-test-create'"),
        "should confirm creation: {stdout}"
    );

    // List should now show the session.
    let out = run_sigil(tmp.path(), &["session", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bb-test-create"),
        "list should include the new session: {stdout}"
    );
}

#[test]
fn session_show_json_returns_correct_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    // Create.
    let out = run_sigil(
        tmp.path(),
        &[
            "session",
            "create",
            work_dir,
            "-t",
            "bb-show-json",
            "-c",
            "codex",
            "-g",
            "test-group",
        ],
    );
    assert!(out.status.success(), "create should succeed");

    // Show --json.
    let out = run_sigil(tmp.path(), &["session", "show", "bb-show-json", "--json"]);
    assert!(
        out.status.success(),
        "session show --json should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["title"], "bb-show-json");
    assert_eq!(parsed["state"], "Stopped");
    assert_eq!(parsed["tool"], "Codex");
}

#[test]
fn session_remove_then_list_returns_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    // Create.
    let out = run_sigil(
        tmp.path(),
        &["session", "create", work_dir, "-t", "bb-remove-me"],
    );
    assert!(out.status.success());

    // Remove.
    let out = run_sigil(tmp.path(), &["session", "remove", "bb-remove-me"]);
    assert!(
        out.status.success(),
        "session remove should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Removed session 'bb-remove-me'"),
        "should confirm removal: {stdout}"
    );

    // List should be empty again.
    let out = run_sigil(tmp.path(), &["session", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No sessions"),
        "list should be empty after remove: {stdout}"
    );
}

#[test]
fn session_show_nonexistent_returns_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["session", "show", "does-not-exist"]);
    assert!(
        !out.status.success(),
        "showing a nonexistent session should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should mention 'not found': {stderr}"
    );
}

#[test]
fn audit_verify_fresh_log_reports_valid_chain() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Run a command that writes audit events to create the log file.
    let work_dir = tmp.path().to_str().expect("valid path");
    let out = run_sigil(
        tmp.path(),
        &["session", "create", work_dir, "-t", "bb-audit-seed"],
    );
    assert!(
        out.status.success(),
        "create should succeed to seed audit log"
    );

    // The audit log lives alongside the db at <tmp>/.sigil/audit.jsonl.
    let audit_path = tmp.path().join(".sigil").join("audit.jsonl");
    let audit_str = audit_path.to_str().expect("valid path");

    let out = run_sigil(tmp.path(), &["audit", "verify", "--path", audit_str]);
    assert!(
        out.status.success(),
        "audit verify should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("valid"),
        "audit chain should be valid: {stdout}"
    );
}

#[test]
fn runtime_flag_accepts_tmux() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["--runtime", "tmux", "status"]);
    // This simply checks the flag is accepted and the command runs.
    // Status doesn't require tmux to be running — it only queries the DB.
    assert!(
        out.status.success(),
        "--runtime tmux status should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn runtime_flag_rejects_invalid_value() {
    let out = run_sigil_raw(&["--runtime", "docker", "status"]);
    assert!(
        !out.status.success(),
        "invalid --runtime should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value") || stderr.contains("docker"),
        "stderr should mention the invalid value: {stderr}"
    );
}

#[test]
fn session_create_with_identity_persists_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    let out = run_sigil(
        tmp.path(),
        &[
            "session",
            "create",
            work_dir,
            "-t",
            "bb-identity",
            "--identity",
            "SOUL.md,OPS.md",
        ],
    );
    assert!(
        out.status.success(),
        "session create --identity should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Created session 'bb-identity'"),
        "should confirm creation: {stdout}"
    );

    // Verify identity persisted via show --json.
    let out = run_sigil(tmp.path(), &["session", "show", "bb-identity", "--json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    // The identity field should be present and contain the files.
    let identity = &parsed["identity"];
    assert!(
        !identity.is_null(),
        "identity should be present in JSON: {stdout}"
    );
    let files = &identity["files"];
    assert!(files.is_array(), "identity.files should be an array");
    let file_strs: Vec<&str> = files
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    assert!(
        file_strs.contains(&"SOUL.md"),
        "files should contain SOUL.md: {file_strs:?}"
    );
    assert!(
        file_strs.contains(&"OPS.md"),
        "files should contain OPS.md: {file_strs:?}"
    );
}

#[test]
fn status_json_after_creates_reflects_correct_counts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    // Status before creating sessions.
    let out = run_sigil(tmp.path(), &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert_eq!(parsed["total"], 0);

    // Create two sessions.
    for title in &["bb-count-a", "bb-count-b"] {
        let out = run_sigil(tmp.path(), &["session", "create", work_dir, "-t", title]);
        assert!(out.status.success());
    }

    // Status should now show 2 total, both stopped.
    let out = run_sigil(tmp.path(), &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert_eq!(parsed["total"], 2, "total should be 2");
    assert_eq!(parsed["stopped"], 2, "both should be stopped");
}

/// Regression: `audit` subcommands must short-circuit before any
/// DB / data-dir setup so they remain usable even when `SIGIL_DB`
/// points at an unwritable parent. (PR #40 review feedback.)
#[test]
fn audit_subcommand_runs_with_unwritable_db_parent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Place a regular file where the data dir's parent should be a
    // directory; create_dir_all on a child path would fail loudly.
    let blocker = tmp.path().join("not-a-dir");
    std::fs::write(&blocker, b"i am a file").expect("write blocker file");
    let bogus_db = blocker.join("nested").join("sigil.db");

    let out = Command::new(sigil_bin())
        .arg("--db")
        .arg(&bogus_db)
        .args(["audit", "--help"])
        .env("HOME", tmp.path())
        .env("RUST_LOG", "off")
        .env_remove("SIGIL_RUNTIME")
        .env_remove("SIGIL_DB")
        .output()
        .expect("failed to execute sigil");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "audit --help should exit 0 even with broken --db; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("failed to create data directory"),
        "audit short-circuit must skip data_dir setup; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("failed to open database"),
        "audit short-circuit must skip Store::new; stderr: {stderr}"
    );
}
