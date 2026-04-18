//! Audit chain integrity integration tests.
//!
//! Exercises the full write-then-verify cycle: create an audit log,
//! write events, verify chain integrity, tamper, re-verify.

#![allow(clippy::expect_used)]

use sigil_audit::chain::ChainedEntry;
use sigil_audit::writer::AuditLogWriter;
use sigil_audit::{AuditError, verify_log};
use sigil_core::action::PolicyDecision;
use sigil_core::id::RequestId;
use sigil_core::traits::AuditEvent;
use time::OffsetDateTime;

fn make_event(action_summary: &str, decision: PolicyDecision) -> AuditEvent {
    AuditEvent {
        request_id: RequestId::new(),
        timestamp: OffsetDateTime::now_utc(),
        action_summary: action_summary.to_owned(),
        origin_summary: "integration-test".to_owned(),
        decision,
        session_id: None,
        sanitize_report: None,
    }
}

#[tokio::test]
async fn audit_chain_integrity_across_multiple_events() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let path = dir.path().join("audit.jsonl");
    let key = b"integration-test-key".to_vec();

    // 1. Create writer and write 5 events with different decisions.
    let writer = AuditLogWriter::new(&path, key.clone())
        .await
        .expect("writer creation should succeed");

    let events = [
        make_event("list sessions", PolicyDecision::Allow),
        make_event(
            "read host file",
            PolicyDecision::Deny {
                reason: "tier ceiling exceeded".into(),
            },
        ),
        make_event(
            "break glass",
            PolicyDecision::NeedsApproval {
                description: "requires human approval".into(),
            },
        ),
        make_event("send message", PolicyDecision::Allow),
        make_event(
            "write host file",
            PolicyDecision::Deny {
                reason: "not authorized".into(),
            },
        ),
    ];

    for event in &events {
        writer.append(event).await.expect("append should succeed");
    }

    // 2. Verify the chain is intact.
    let result = verify_log(&path, &key)
        .await
        .expect("verification should succeed");

    assert_eq!(result.total_entries, 5);
    assert_eq!(result.valid_entries, 5);
    assert!(result.first_broken.is_none());
}

#[tokio::test]
async fn tampered_event_breaks_chain() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let path = dir.path().join("tamper-test.jsonl");
    let key = b"tamper-detection-key".to_vec();

    let writer = AuditLogWriter::new(&path, key.clone())
        .await
        .expect("writer creation should succeed");

    // Write 3 events.
    for i in 0..3 {
        writer
            .append(&make_event(&format!("action-{i}"), PolicyDecision::Allow))
            .await
            .expect("append should succeed");
    }

    // Tamper with the second line's action summary.
    let contents = tokio::fs::read_to_string(&path)
        .await
        .expect("read should succeed");
    let mut lines: Vec<String> = contents.lines().map(String::from).collect();

    if let Some(line) = lines.get_mut(1) {
        let mut entry: ChainedEntry = serde_json::from_str(line).expect("should parse entry");
        entry.event.action_summary = "TAMPERED".to_owned();
        *line = serde_json::to_string(&entry).expect("should serialize");
    }

    let tampered = lines.join("\n") + "\n";
    tokio::fs::write(&path, tampered)
        .await
        .expect("write should succeed");

    // Verify should detect the tampering.
    let result = verify_log(&path, &key)
        .await
        .expect("verification call should succeed");

    assert_eq!(result.total_entries, 3);
    assert!(result.first_broken.is_some());

    let broken = result.first_broken.expect("should have a broken entry");
    assert_eq!(broken.index, 1, "second entry should be the broken one");
}

#[tokio::test]
async fn chain_recovery_after_writer_restart() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let path = dir.path().join("recovery.jsonl");
    let key = b"recovery-key".to_vec();

    // Write 2 events with the first writer.
    {
        let writer = AuditLogWriter::new(&path, key.clone())
            .await
            .expect("first writer should succeed");
        writer
            .append(&make_event("first", PolicyDecision::Allow))
            .await
            .expect("append should succeed");
        writer
            .append(&make_event("second", PolicyDecision::Allow))
            .await
            .expect("append should succeed");
    }

    // Open a new writer (simulates process restart).
    let writer = AuditLogWriter::new(&path, key.clone())
        .await
        .expect("recovery writer should succeed");
    writer
        .append(&make_event("third", PolicyDecision::Allow))
        .await
        .expect("append after recovery should succeed");

    // Full chain should be valid.
    let result = verify_log(&path, &key)
        .await
        .expect("verification should succeed");

    assert_eq!(result.total_entries, 3);
    assert_eq!(result.valid_entries, 3);
    assert!(result.first_broken.is_none());
}

#[tokio::test]
async fn wrong_key_breaks_verification() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let path = dir.path().join("wrong-key.jsonl");
    let write_key = b"correct-key".to_vec();
    let wrong_key = b"wrong-key";

    let writer = AuditLogWriter::new(&path, write_key)
        .await
        .expect("writer should succeed");
    writer
        .append(&make_event("test", PolicyDecision::Allow))
        .await
        .expect("append should succeed");

    // Verify with wrong key -- chain HMAC won't match.
    let result = verify_log(&path, wrong_key)
        .await
        .expect("verification call should succeed");

    assert!(
        result.first_broken.is_some(),
        "wrong key should break verification"
    );
}

#[tokio::test]
async fn missing_file_returns_error() {
    let result = verify_log("/tmp/nonexistent-audit-test.jsonl", b"key").await;
    assert!(result.is_err());
    assert!(matches!(
        result.as_ref().expect_err("should be an error"),
        AuditError::FileNotFound { .. }
    ));
}
