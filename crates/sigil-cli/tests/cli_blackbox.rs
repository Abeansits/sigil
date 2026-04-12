//! Tier 3: CLI black-box tests for the `sigil` binary.
//!
//! These tests exercise the actual compiled binary via `std::process::Command`,
//! asserting on exit codes and stdout/stderr. No test crate dependencies beyond
//! the standard library.
//!
//! Each test gets its own `tempdir` for `--db` and audit isolation.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;

static BUILD_ONCE: Once = Once::new();

/// Build the sigil binary once per test run and return its path.
fn sigil_bin() -> PathBuf {
    BUILD_ONCE.call_once(|| {
        let status = Command::new("cargo")
            .args(["build", "--bin", "sigil"])
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "cargo build failed");
    });

    // Locate the binary in the target directory.
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // workspace root
    path.push("target");
    path.push("debug");
    path.push("sigil");
    assert!(
        path.exists(),
        "sigil binary not found at {}",
        path.display()
    );
    path
}

/// Run the sigil binary with the given args, pointing `--db` at the
/// provided temp directory for isolation. Returns the `Output`.
///
/// The db is placed inside `<tmp>/.sigil/sigil.db` so the audit log
/// lands at `<tmp>/.sigil/audit.jsonl`, matching the default verify path.
fn run_sigil(tmp: &Path, args: &[&str]) -> Output {
    let sigil_dir = tmp.join(".sigil");
    let db_path = sigil_dir.join("sigil.db");
    let bin = sigil_bin();

    Command::new(&bin)
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
    let bin = sigil_bin();

    Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute sigil binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn version_flag_exits_zero_and_shows_version() {
    let out = run_sigil_raw(&["--version"]);
    assert!(out.status.success(), "exit code should be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sigil"),
        "stdout should contain 'sigil': {stdout}"
    );
}

#[test]
fn help_flag_exits_zero_and_shows_usage() {
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
fn unknown_subcommand_exits_nonzero() {
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
fn status_plain_text_exits_zero() {
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
fn status_json_exits_zero_with_valid_json() {
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
fn session_list_empty_store() {
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
fn session_list_json_empty_store() {
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
fn session_create_and_list_shows_session() {
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
fn session_show_json_returns_session_details() {
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
fn session_create_and_remove_then_list_is_empty() {
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
fn session_show_nonexistent_exits_nonzero() {
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
fn audit_verify_on_fresh_log() {
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
fn runtime_flag_tmux_explicit() {
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
fn runtime_flag_invalid_value_exits_nonzero() {
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
fn session_create_with_identity_flag() {
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
fn status_counts_update_after_session_create() {
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
