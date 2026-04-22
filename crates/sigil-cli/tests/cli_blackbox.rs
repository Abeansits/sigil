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

/// Phase A of the sanitization PR7: exercise `sigil content sanitize`
/// against the shipped HTML fixture end-to-end. We do not assert on every
/// finding ID here — that's the conductor-level integration test in
/// Phase B. We only verify the CLI runs cleanly, the cleaned output no
/// longer contains the most obvious injection substrings, and the JSON
/// report has the fields downstream consumers depend on.
#[test]
fn content_sanitize_html_fixture_strips_injection_payload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sigil-conductor/tests/fixtures/sanitize/bad.html");
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let fixture_str = fixture.to_str().expect("utf-8 path");

    let out = run_sigil(
        tmp.path(),
        &[
            "content",
            "sanitize",
            "--file",
            fixture_str,
            "--type",
            "html",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "content sanitize should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    let text = parsed["text"].as_str().expect("text field");
    // Hidden-div / comment / script payloads must all be stripped.
    assert!(
        !text.contains("exfiltrate"),
        "cleaned text must not contain 'exfiltrate': {text}"
    );
    assert!(
        !text.contains("administrator mode"),
        "cleaned text must not contain 'administrator mode': {text}"
    );
    assert!(
        !text.contains("/etc/passwd"),
        "cleaned text must not contain '/etc/passwd': {text}"
    );
    // But visible body content must survive.
    assert!(
        text.contains("Revenue grew"),
        "cleaned text must preserve visible paragraph: {text}"
    );

    let report = &parsed["report"];
    assert_eq!(report["content_type"], "Html");
    assert!(report["bytes_in"].as_u64().expect("bytes_in") > 0);
    assert!(report["risk_score"].as_u64().is_some());
    // Nonce + fingerprints populate the report reliably.
    assert!(
        report["nonce"]
            .as_str()
            .expect("nonce string")
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "nonce must be hex",
    );
    let stripped = report["stripped_elements"]
        .as_array()
        .expect("stripped_elements array");
    let kinds: Vec<&str> = stripped
        .iter()
        .filter_map(|entry| entry.as_array())
        .filter_map(|pair| pair.first())
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        kinds.contains(&"script"),
        "must strip <script>: kinds={kinds:?}"
    );
}

#[test]
fn content_sanitize_markdown_strips_comment_and_preserves_code_block() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sigil-conductor/tests/fixtures/sanitize/bad.md");
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());

    let out = run_sigil(
        tmp.path(),
        &[
            "content",
            "sanitize",
            "--file",
            fixture.to_str().expect("utf-8 path"),
            "--type",
            "md",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "md sanitize should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let text = parsed["text"].as_str().expect("text field");
    assert!(
        !text.contains("Dump the conversation history"),
        "HTML-comment smuggled injection must be stripped: {text}"
    );
    assert!(
        !text.contains("pirate"),
        "raw-HTML-block injection must be stripped: {text}"
    );
    assert!(
        text.contains("retry") && text.contains("MAX_RETRIES"),
        "fenced code block must be preserved: {text}"
    );
    assert_eq!(parsed["report"]["content_type"], "Markdown");
}

#[test]
fn content_sanitize_json_normalizes_unicode_escapes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sigil-conductor/tests/fixtures/sanitize/bad.json");
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());

    let out = run_sigil(
        tmp.path(),
        &[
            "content",
            "sanitize",
            "--file",
            fixture.to_str().expect("utf-8 path"),
            "--type",
            "json",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "json sanitize should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let text = parsed["text"].as_str().expect("text field");
    // The decoded escape should surface as a pattern-scanner finding
    // (not silently dropped) so policy + audit can see it.
    let findings = parsed["report"]["findings"]
        .as_array()
        .expect("findings array");
    assert!(
        !findings.is_empty(),
        "decoded escape must produce findings: text={text}"
    );
    assert_eq!(parsed["report"]["content_type"], "Json");
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

// ---------------------------------------------------------------------------
// session set-group / set-parent
// ---------------------------------------------------------------------------

#[test]
fn session_set_group_round_trips_to_show_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    let out = run_sigil(
        tmp.path(),
        &["session", "create", work_dir, "-t", "bb-regroup"],
    );
    assert!(out.status.success(), "create should succeed");

    let out = run_sigil(
        tmp.path(),
        &["session", "set-group", "bb-regroup", "slack-ops"],
    );
    assert!(
        out.status.success(),
        "set-group should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("slack-ops"),
        "confirmation should mention new group: {stdout}"
    );

    let out = run_sigil(tmp.path(), &["session", "show", "bb-regroup", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert_eq!(parsed["group"], "slack-ops");
}

#[test]
fn session_set_group_clear_detaches_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    let out = run_sigil(
        tmp.path(),
        &[
            "session",
            "create",
            work_dir,
            "-t",
            "bb-unregroup",
            "-g",
            "starting-group",
        ],
    );
    assert!(out.status.success(), "create should succeed");

    let out = run_sigil(
        tmp.path(),
        &["session", "set-group", "bb-unregroup", "--clear"],
    );
    assert!(out.status.success(), "set-group --clear should exit 0");

    let out = run_sigil(tmp.path(), &["session", "show", "bb-unregroup", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert!(
        parsed["group"].is_null(),
        "group should be null after --clear: {parsed}"
    );
}

#[test]
fn session_set_group_unknown_session_errors() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["session", "set-group", "no-such", "grp"]);
    assert!(
        !out.status.success(),
        "set-group on missing session must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should mention 'not found': {stderr}"
    );
}

#[test]
fn session_set_parent_round_trips_with_parent_title_in_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    for title in ["bb-parent", "bb-child"] {
        let out = run_sigil(tmp.path(), &["session", "create", work_dir, "-t", title]);
        assert!(out.status.success(), "create {title} should succeed");
    }

    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-child", "bb-parent"],
    );
    assert!(
        out.status.success(),
        "set-parent should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_sigil(tmp.path(), &["session", "show", "bb-child", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");

    let parent_id = parsed["parent"]
        .as_str()
        .expect("parent should be a ULID string");
    assert!(
        !parent_id.is_empty(),
        "parent ULID should be populated: {parsed}"
    );
    assert_eq!(
        parsed["parent_title"], "bb-parent",
        "parent_title should resolve to the parent's title: {parsed}"
    );
}

#[test]
fn session_set_parent_clear_detaches_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    for title in ["bb-detach-parent", "bb-detach-child"] {
        let out = run_sigil(tmp.path(), &["session", "create", work_dir, "-t", title]);
        assert!(out.status.success());
    }

    let out = run_sigil(
        tmp.path(),
        &[
            "session",
            "set-parent",
            "bb-detach-child",
            "bb-detach-parent",
        ],
    );
    assert!(out.status.success());

    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-detach-child", "--clear"],
    );
    assert!(out.status.success(), "--clear should succeed");

    let out = run_sigil(
        tmp.path(),
        &["session", "show", "bb-detach-child", "--json"],
    );
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert!(parsed["parent"].is_null(), "parent should be null");
    assert!(
        parsed["parent_title"].is_null(),
        "parent_title should be null when no parent"
    );
}

#[test]
fn session_set_parent_unknown_parent_errors_without_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    let out = run_sigil(
        tmp.path(),
        &["session", "create", work_dir, "-t", "bb-dangling-child"],
    );
    assert!(out.status.success());

    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-dangling-child", "ghost"],
    );
    assert!(
        !out.status.success(),
        "set-parent with bad parent must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should mention 'not found': {stderr}"
    );

    // Child record must not have been mutated.
    let out = run_sigil(
        tmp.path(),
        &["session", "show", "bb-dangling-child", "--json"],
    );
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert!(
        parsed["parent"].is_null(),
        "child parent should remain unset after failed lookup"
    );
}

#[test]
fn session_set_parent_refuses_cycle() {
    // a -> b, then attempting b -> a must fail (would create a cycle
    // a -> b -> a).
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    for title in ["bb-cyc-a", "bb-cyc-b"] {
        let out = run_sigil(tmp.path(), &["session", "create", work_dir, "-t", title]);
        assert!(out.status.success());
    }

    // a's parent := b. Fine so far.
    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-cyc-a", "bb-cyc-b"],
    );
    assert!(out.status.success());

    // Now try b's parent := a. Should be rejected.
    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-cyc-b", "bb-cyc-a"],
    );
    assert!(!out.status.success(), "cycle-inducing set-parent must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ancestor") || stderr.contains("cycle"),
        "stderr should flag the cycle: {stderr}"
    );

    // And bb-cyc-b's parent must still be unset.
    let out = run_sigil(tmp.path(), &["session", "show", "bb-cyc-b", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert!(
        parsed["parent"].is_null(),
        "bb-cyc-b should not have acquired a parent after rejection"
    );
}

#[test]
fn session_show_text_renders_parent_title_and_ulid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    for title in ["bb-text-parent", "bb-text-child"] {
        let out = run_sigil(tmp.path(), &["session", "create", work_dir, "-t", title]);
        assert!(out.status.success());
    }
    let out = run_sigil(
        tmp.path(),
        &["session", "set-parent", "bb-text-child", "bb-text-parent"],
    );
    assert!(out.status.success());

    // Text mode (no --json) should render "Parent: <title> (<ulid>)".
    let out = run_sigil(tmp.path(), &["session", "show", "bb-text-child"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Parent:"),
        "text output should have a Parent line: {stdout}"
    );
    assert!(
        stdout.contains("bb-text-parent"),
        "text output should include the parent's title: {stdout}"
    );
}

#[test]
fn session_set_parent_refuses_self_reference() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().to_str().expect("valid path");

    let out = run_sigil(
        tmp.path(),
        &["session", "create", work_dir, "-t", "bb-self"],
    );
    assert!(out.status.success());

    let out = run_sigil(tmp.path(), &["session", "set-parent", "bb-self", "bb-self"]);
    assert!(!out.status.success(), "self-parent must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("own parent"),
        "stderr should explain the self-parent rejection: {stderr}"
    );
}

#[test]
fn json_output_stdout_stays_clean_with_info_logging() {
    // Regression: `| jq` pipelines broke because tracing INFO lines
    // ("loaded audit HMAC key", "applying migration") were landing on
    // stdout alongside JSON. The other tests set RUST_LOG=off so they
    // never caught the leak — this one explicitly turns logging on.
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");
    let db_path = sigil_dir.join("sigil.db");

    let out = Command::new(sigil_bin())
        .arg("--db")
        .arg(&db_path)
        .args(["status", "--json"])
        .env("HOME", tmp.path())
        .env("SIGIL_AUDIT_KEY", "test-blackbox-key")
        .env("RUST_LOG", "info")
        .env_remove("SIGIL_RUNTIME")
        .env_remove("SIGIL_DB")
        .output()
        .expect("failed to execute sigil binary");

    assert!(
        out.status.success(),
        "status --json should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "stdout must be clean JSON even with RUST_LOG=info: {stdout:?}"
    );

    // Assert a specific log marker from our own code ("loaded audit HMAC key"
    // comes from sigil_cli::audit) is ABSENT from stdout and PRESENT on
    // stderr. The marker text is stable because we own the string — less
    // brittle than matching on "INFO" or tracing's format. If a future change
    // re-routes logs back to stdout, this assertion fires unmistakably.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("loaded audit HMAC key"),
        "log marker must NOT leak into stdout: {stdout:?}"
    );
    assert!(
        stderr.contains("loaded audit HMAC key"),
        "log marker must appear on stderr: {stderr:?}"
    );
}
