//! UC5: Audit trail integrity integration test.
//!
//! Runs a session lifecycle, reads audit.jsonl, and verifies:
//! - Each line is valid JSON
//! - Entries include `content_hash`, `prev_hash`, and `hmac`
//! - The first entry uses the genesis `prev_hash`
//! - The full HMAC chain validates
//!
//! Requires tmux.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::Arc;

use sigil_audit::AuditLogWriter;
use sigil_audit::chain::ChainedEntry;
use sigil_cli::SessionCommands;
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

/// The genesis hash used for the first entry's `prev_hash`.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn tmux_available() -> bool {
    TmuxRuntime::check_tmux().await.is_ok()
}

async fn cleanup(server: &str) {
    let _ = tokio::process::Command::new("tmux")
        .args(["-L", server, "kill-server"])
        .output()
        .await;
}

#[tokio::test]
async fn audit_trail_valid_after_session_lifecycle() {
    if !tmux_available().await {
        eprintln!("tmux not installed -- skipping UC5");
        return;
    }

    let server = "sigil-test-uc5";
    cleanup(server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store");
    let runtime = TmuxRuntime::new(server);
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"uc5-audit-key".to_vec();
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, key.clone())
            .await
            .expect("audit writer"),
    );
    let work_dir = dir.path().to_str().expect("valid").to_owned();
    let title = "uc5-audit".to_owned();

    // Run a lifecycle: create -> start -> send -> stop -> remove.
    // Each operation appends an audit event.

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Create {
            path: work_dir.clone(),
            title: title.clone(),
            tool: "claude".into(),
            group: None,
        },
    )
    .await
    .expect("create");

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Start {
            name: title.clone(),
        },
    )
    .await
    .expect("start");

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Send {
            name: title.clone(),
            message: "echo audit test".into(),
            wait: false,
            quiet: true,
        },
    )
    .await
    .expect("send");

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Stop {
            name: title.clone(),
        },
    )
    .await
    .expect("stop");

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Remove {
            name: title.clone(),
        },
    )
    .await
    .expect("remove");

    // Give the async writer a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── READ AND VERIFY THE AUDIT LOG ───────────────────────────────
    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit file should be readable");

    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 5,
        "should have at least 5 audit entries (create, start, send, stop, remove), got {}",
        lines.len()
    );

    // Parse each line as a ChainedEntry.
    let entries: Vec<ChainedEntry> = lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {i} should be valid JSON: {e}"))
        })
        .collect();

    // Verify each entry has the required fields.
    for (i, entry) in entries.iter().enumerate() {
        assert!(
            !entry.content_hash.is_empty(),
            "entry {i} should have a content_hash"
        );
        assert!(
            !entry.prev_hash.is_empty(),
            "entry {i} should have a prev_hash"
        );
        assert!(!entry.hmac.is_empty(), "entry {i} should have an hmac");
    }

    // First entry must use the genesis prev_hash.
    assert_eq!(
        entries[0].prev_hash, GENESIS_HASH,
        "first entry should use genesis prev_hash"
    );

    // Each subsequent entry's prev_hash should be the previous entry's hmac.
    for i in 1..entries.len() {
        assert_eq!(
            entries[i].prev_hash,
            entries[i - 1].hmac,
            "entry {i} prev_hash should equal entry {} hmac",
            i - 1
        );
    }

    // Verify expected action summaries.
    let actions: Vec<&str> = entries
        .iter()
        .map(|e| e.event.action_summary.as_str())
        .collect();
    assert_eq!(actions[0], "session.create");
    assert_eq!(actions[1], "session.start");
    assert_eq!(actions[2], "session.send");
    assert_eq!(actions[3], "session.stop");
    assert_eq!(actions[4], "session.remove");

    // Full chain verification using the library verifier.
    sigil_audit::chain::verify_chain(&key, &entries).expect("HMAC chain should be valid");

    // Also verify via the file-level verifier.
    let verify_result = sigil_audit::verify_log(&audit_path, &key)
        .await
        .expect("verify_log should succeed");
    assert_eq!(verify_result.total_entries, entries.len());
    assert_eq!(verify_result.valid_entries, entries.len());
    assert!(
        verify_result.first_broken.is_none(),
        "chain should have no broken entries"
    );

    cleanup(server).await;
}

/// Audit entries are written even when the session operation doesn't
/// need tmux (e.g., create and remove).
#[tokio::test]
async fn audit_events_for_non_tmux_operations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sigil.db");
    let db_str = db_path.to_str().expect("valid UTF-8");
    let store = Store::new(db_str).await.expect("store");
    let runtime = TmuxRuntime::new("sigil-test-uc5-notmux");
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"uc5-notmux-key".to_vec();
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, key.clone())
            .await
            .expect("audit writer"),
    );

    // Create and remove (no tmux needed).
    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Create {
            path: "/tmp".into(),
            title: "uc5-notmux".into(),
            tool: "claude".into(),
            group: None,
        },
    )
    .await
    .expect("create");

    sigil_cli::commands::session::run(
        &store,
        &runtime,
        &audit,
        SessionCommands::Remove {
            name: "uc5-notmux".into(),
        },
    )
    .await
    .expect("remove");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("read audit");
    let entries: Vec<ChainedEntry> = contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON"))
        .collect();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].event.action_summary, "session.create");
    assert_eq!(entries[1].event.action_summary, "session.remove");

    // Chain is valid.
    sigil_audit::chain::verify_chain(&key, &entries).expect("chain valid");
}
