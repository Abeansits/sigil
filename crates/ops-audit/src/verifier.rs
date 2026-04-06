//! Read-only verification of an HMAC-chained audit log.

use std::path::Path;

use crate::chain::{self, ChainedEntry};
use crate::error::AuditError;

/// The result of verifying an audit log file.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifyResult {
    /// Total number of entries in the file.
    pub total_entries: usize,
    /// Number of entries that passed HMAC verification.
    pub valid_entries: usize,
    /// The first entry where the chain broke, if any.
    pub first_broken: Option<BrokenEntry>,
}

/// Details about the first chain break.
#[derive(Debug, Clone)]
pub struct BrokenEntry {
    /// The index (0-based) of the broken entry.
    pub index: usize,
    /// The request ID of the broken entry's event.
    pub event_id: String,
    /// A human-readable description of the mismatch.
    pub reason: String,
}

/// Verify every entry in an audit log file.
///
/// Reads the file, deserializes each JSONL line, and checks the HMAC
/// chain from genesis through the last entry.
///
/// # Errors
///
/// - [`AuditError::FileNotFound`] if the file does not exist.
/// - [`AuditError::Write`] on other I/O failures.
/// - [`AuditError::Serialize`] if a line cannot be deserialized.
/// - [`AuditError::KeyNotAvailable`] if the HMAC key is rejected.
pub async fn verify_log(
    path: impl AsRef<Path>,
    key: &[u8],
) -> Result<VerifyResult, AuditError> {
    let path = path.as_ref();

    let contents = tokio::fs::read_to_string(path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AuditError::FileNotFound {
                path: path.display().to_string(),
            }
        } else {
            AuditError::Write(e)
        }
    })?;

    let entries = parse_entries(&contents)?;
    let total_entries = entries.len();

    match chain::verify_chain(key, &entries) {
        Ok(()) => Ok(VerifyResult {
            total_entries,
            valid_entries: total_entries,
            first_broken: None,
        }),
        Err(AuditError::ChainBroken {
            event_id,
            expected,
            actual,
        }) => {
            let index = entries
                .iter()
                .position(|e| e.event.request_id.to_string() == event_id)
                .unwrap_or(0);

            Ok(VerifyResult {
                total_entries,
                valid_entries: index,
                first_broken: Some(BrokenEntry {
                    index,
                    event_id,
                    reason: format!("expected {expected}, got {actual}"),
                }),
            })
        }
        Err(e) => Err(e),
    }
}

/// Parse all non-empty lines into [`ChainedEntry`] values.
fn parse_entries(contents: &str) -> Result<Vec<ChainedEntry>, AuditError> {
    contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(AuditError::Serialize)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ops_core::{AuditEvent, PolicyDecision, RequestId};
    use time::OffsetDateTime;

    use super::*;
    use crate::writer::AuditLogWriter;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            request_id: RequestId::new(),
            timestamp: OffsetDateTime::now_utc(),
            action_summary: "test action".to_owned(),
            origin_summary: "test origin".to_owned(),
            decision: PolicyDecision::Allow,
            session_id: None,
        }
    }

    #[tokio::test]
    async fn valid_chain_passes_verification() {
        let dir = tempfile::tempdir()
            .expect("tempdir creation should succeed");
        let path = dir.path().join("valid.jsonl");
        let key = b"verify-key".to_vec();

        let writer = AuditLogWriter::new(&path, key.clone())
            .await
            .expect("writer should succeed");

        for _ in 0..5 {
            writer
                .append(&sample_event())
                .await
                .expect("append should succeed");
        }

        let result = verify_log(&path, &key)
            .await
            .expect("verification should succeed");

        assert_eq!(result.total_entries, 5);
        assert_eq!(result.valid_entries, 5);
        assert!(result.first_broken.is_none());
    }

    #[tokio::test]
    async fn tampered_chain_fails_verification() {
        let dir = tempfile::tempdir()
            .expect("tempdir creation should succeed");
        let path = dir.path().join("tampered.jsonl");
        let key = b"tamper-key".to_vec();

        let writer = AuditLogWriter::new(&path, key.clone())
            .await
            .expect("writer should succeed");

        for _ in 0..3 {
            writer
                .append(&sample_event())
                .await
                .expect("append should succeed");
        }

        // Tamper: modify the second line's action summary.
        let contents = tokio::fs::read_to_string(&path)
            .await
            .expect("read should succeed");
        let mut lines: Vec<String> =
            contents.lines().map(String::from).collect();

        if let Some(line) = lines.get_mut(1) {
            let mut entry: ChainedEntry = serde_json::from_str(line)
                .expect("should parse");
            entry.event.action_summary = "TAMPERED".to_owned();
            *line = serde_json::to_string(&entry)
                .expect("should serialize");
        }

        let tampered = lines.join("\n") + "\n";
        tokio::fs::write(&path, tampered)
            .await
            .expect("write should succeed");

        let result = verify_log(&path, &key)
            .await
            .expect("verification call should succeed");

        assert_eq!(result.total_entries, 3);
        assert!(result.first_broken.is_some());

        let broken =
            result.first_broken.expect("should have a broken entry");
        assert_eq!(broken.index, 1);
    }

    #[tokio::test]
    async fn empty_file_passes_verification() {
        let dir = tempfile::tempdir()
            .expect("tempdir creation should succeed");
        let path = dir.path().join("empty.jsonl");
        tokio::fs::write(&path, "")
            .await
            .expect("write should succeed");

        let result = verify_log(&path, b"any-key")
            .await
            .expect("verification should succeed");

        assert_eq!(result.total_entries, 0);
        assert_eq!(result.valid_entries, 0);
        assert!(result.first_broken.is_none());
    }

    #[tokio::test]
    async fn missing_file_returns_error() {
        let result = verify_log(
            "/tmp/nonexistent-audit-file.jsonl",
            b"key",
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.as_ref().expect_err("should be an error"),
            AuditError::FileNotFound { .. }
        ));
    }
}
