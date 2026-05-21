//! Audit integration tests — verify that audit events are written to
//! disk with valid HMAC-chained JSONL entries when CLI operations run.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use assert_matches::assert_matches;
use serde_json::{Map, Value};
use sigil_audit::AuditLogWriter;
use sigil_audit::chain::ChainedEntry;
use sigil_core::PolicyDecision;
use sigil_core::id::SessionId;

/// Create a writer against a temp directory and log a `session.create`
/// event, then read back the file and verify it contains a valid entry.
#[tokio::test]
async fn session_create_produces_valid_audit_entry() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"integration-test-key".to_vec();

    let writer = AuditLogWriter::new(&audit_path, key.clone())
        .await
        .expect("writer creation should succeed");

    // Simulate what the CLI does after a successful session create.
    let session_id = SessionId::new();
    sigil_cli::audit::log_event(
        &writer,
        "session.create",
        "cli",
        PolicyDecision::Allow,
        Some(session_id),
    )
    .await;

    // Read back the file and verify.
    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit file should be readable");

    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "should have exactly one audit entry");

    let entry: ChainedEntry =
        serde_json::from_str(lines[0]).expect("entry should be valid ChainedEntry JSON");

    assert_eq!(entry.event.action_summary, "session.create");
    assert_eq!(entry.event.origin_summary, "cli");
    assert_matches!(entry.event.decision, PolicyDecision::Allow);
    assert_eq!(entry.event.session_id, Some(session_id));

    // Verify the chain is valid.
    sigil_audit::chain::verify_chain(&key, &[entry]).expect("chain should be valid");
}

/// Multiple events produce a valid HMAC chain.
#[tokio::test]
async fn multiple_audit_events_form_valid_chain() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"chain-test-key".to_vec();

    let writer = AuditLogWriter::new(&audit_path, key.clone())
        .await
        .expect("writer creation should succeed");

    let actions = [
        "session.create",
        "session.start",
        "session.send",
        "session.stop",
    ];

    for action in &actions {
        sigil_cli::audit::log_event(
            &writer,
            action,
            "cli",
            PolicyDecision::Allow,
            Some(SessionId::new()),
        )
        .await;
    }

    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit file should be readable");

    let entries: Vec<ChainedEntry> = contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("each line should be valid JSON"))
        .collect();

    assert_eq!(entries.len(), 4, "should have four entries");

    // Verify the full chain.
    sigil_audit::chain::verify_chain(&key, &entries).expect("chain should be valid");

    // Verify action summaries match.
    for (entry, expected_action) in entries.iter().zip(actions.iter()) {
        assert_eq!(&entry.event.action_summary, expected_action);
    }
}

/// `init_audit_writer` creates the file in the expected location.
#[tokio::test]
async fn init_audit_writer_creates_file_in_data_dir() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");

    let writer =
        sigil_cli::audit::init_audit_writer_with_key(dir.path(), b"init-test-key".to_vec())
            .await
            .expect("init should succeed");

    // Write a test event to confirm it works end-to-end.
    sigil_cli::audit::log_event(&writer, "test.init", "test", PolicyDecision::Allow, None).await;

    let audit_path = dir.path().join("audit.jsonl");
    assert!(audit_path.exists(), "audit.jsonl should exist in data dir");

    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit file should be readable");
    assert!(
        !contents.is_empty(),
        "audit file should contain at least one entry",
    );
}

/// Structured sidecar fields remain queryable after a CLI-style write.
#[tokio::test]
async fn log_event_with_fields_persists_structured_fields() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let audit_path = dir.path().join("audit.jsonl");
    let key = b"fields-integration-test-key".to_vec();

    let writer = AuditLogWriter::new(&audit_path, key.clone())
        .await
        .expect("writer creation should succeed");

    let session_id = SessionId::new();
    let fields = Map::from_iter([
        ("text_len".to_owned(), Value::from(42_u64)),
        ("truncated".to_owned(), Value::from(true)),
        ("normalized_len".to_owned(), Value::from(84_u64)),
        (
            "target_origin".to_owned(),
            Value::from("BridgeTelegram { chat_id: 7 }"),
        ),
    ]);

    sigil_cli::audit::log_event_with_fields(
        &writer,
        "bridge.reply_sent",
        "BridgeTelegram { chat_id: 7 }",
        PolicyDecision::Allow,
        Some(session_id),
        fields,
    )
    .await;

    let contents = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit file should be readable");
    let line = contents.lines().next().expect("expected one entry");
    let entry: ChainedEntry =
        serde_json::from_str(line).expect("entry should be valid ChainedEntry JSON");

    assert_eq!(entry.event.action_summary, "bridge.reply_sent");
    assert_eq!(entry.event.session_id, Some(session_id));

    let fields = entry.fields.as_ref().expect("fields should be present");
    assert_eq!(fields.get("text_len"), Some(&Value::from(42_u64)));
    assert_eq!(fields.get("truncated"), Some(&Value::from(true)));
    assert_eq!(fields.get("normalized_len"), Some(&Value::from(84_u64)));
    assert_eq!(
        fields.get("target_origin"),
        Some(&Value::from("BridgeTelegram { chat_id: 7 }"))
    );

    sigil_audit::chain::verify_chain(&key, &[entry]).expect("chain should be valid");
}
