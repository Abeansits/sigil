//! Append-only JSONL audit log writer with HMAC chaining.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::chain::{self, ChainedEntry, GENESIS_HASH, payload_bytes};
use crate::error::AuditError;

/// An append-only audit log writer that maintains an HMAC chain.
///
/// Each entry is serialized as a single JSONL line. The writer holds
/// a mutex over the file handle so concurrent appends are safe.
///
/// The HMAC key is held in a [`Zeroizing`] wrapper so the secret bytes
/// are scrubbed from memory when the writer is dropped.
pub struct AuditLogWriter {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    state: Mutex<WriterState>,
}

struct WriterState {
    file: tokio::fs::File,
    prev_hash: String,
}

impl AuditLogWriter {
    /// Open or create an audit log file.
    ///
    /// If the file already exists, the last entry is read to recover
    /// the chain's `prev_hash`. If the file is empty or missing, the
    /// chain starts from the genesis hash.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Write`] if the file cannot be opened or
    /// created, or [`AuditError::Serialize`] if the last entry cannot
    /// be deserialized during recovery.
    pub async fn new(
        path: impl AsRef<Path>,
        key: impl Into<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let prev_hash = recover_prev_hash(&path).await?;

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(AuditError::Write)?;

        Ok(Self {
            path,
            key: key.into(),
            state: Mutex::new(WriterState { file, prev_hash }),
        })
    }

    /// Append an audit event to the log.
    ///
    /// Computes the content hash and HMAC, writes a single JSONL line,
    /// and flushes. The internal `prev_hash` advances to the new
    /// entry's HMAC for the next append.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Serialize`] if the event cannot be
    /// serialized, [`AuditError::Write`] on I/O failure, or
    /// [`AuditError::KeyNotAvailable`] if the HMAC key is rejected.
    pub async fn append(&self, event: &sigil_core::AuditEvent) -> Result<(), AuditError> {
        self.append_inner(event, None).await
    }

    /// Append an audit event with structured, queryable sidecar fields.
    ///
    /// The sidecar fields are included in the content hash so the HMAC
    /// chain protects them from tampering just like the core event.
    ///
    /// # Errors
    ///
    /// Returns the same error variants as [`Self::append`].
    pub async fn append_with_fields(
        &self,
        event: &sigil_core::AuditEvent,
        fields: Map<String, Value>,
    ) -> Result<(), AuditError> {
        self.append_inner(event, Some(fields)).await
    }

    async fn append_inner(
        &self,
        event: &sigil_core::AuditEvent,
        fields: Option<Map<String, Value>>,
    ) -> Result<(), AuditError> {
        let json_bytes = payload_bytes(event, fields.as_ref())?;

        let content_hash = chain::content_hash(&json_bytes);

        let mut state = self.state.lock().await;

        let hmac_tag = chain::compute_entry_hmac(&self.key, &content_hash, &state.prev_hash)?;

        let entry = ChainedEntry {
            event: event.clone(),
            fields,
            content_hash,
            prev_hash: state.prev_hash.clone(),
            hmac: hmac_tag.clone(),
        };

        let mut line = serde_json::to_vec(&entry).map_err(AuditError::Serialize)?;
        line.push(b'\n');

        state
            .file
            .write_all(&line)
            .await
            .map_err(AuditError::Write)?;
        state.file.flush().await.map_err(AuditError::Write)?;

        state.prev_hash = hmac_tag;

        tracing::debug!(
            path = %self.path.display(),
            request_id = %event.request_id,
            "audit event appended"
        );

        Ok(())
    }
}

/// Read the last line of an existing audit log to recover the chain
/// tail. Returns the genesis hash if the file doesn't exist or is
/// empty.
async fn recover_prev_hash(path: &Path) -> Result<String, AuditError> {
    let contents = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GENESIS_HASH.to_owned());
        }
        Err(e) => return Err(AuditError::Write(e)),
    };

    let last_line = contents.lines().rev().find(|l| !l.is_empty());

    match last_line {
        Some(line) => {
            let entry: ChainedEntry = serde_json::from_str(line).map_err(AuditError::Serialize)?;
            Ok(entry.hmac)
        }
        None => Ok(GENESIS_HASH.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use sigil_core::{AuditEvent, PolicyDecision, RequestId};
    use time::OffsetDateTime;

    use super::*;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            request_id: RequestId::new(),
            timestamp: OffsetDateTime::now_utc(),
            action_summary: "list sessions".to_owned(),
            origin_summary: "cli".to_owned(),
            decision: PolicyDecision::Allow,
            session_id: None,
            sanitize_report: None,
        }
    }

    #[tokio::test]
    async fn append_creates_valid_jsonl() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let key = b"test-key".to_vec();

        let writer = AuditLogWriter::new(&path, key).await?;

        writer.append(&sample_event()).await?;
        writer.append(&sample_event()).await?;

        let contents = tokio::fs::read_to_string(&path).await?;
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "should have two JSONL lines");

        // Each line should parse as a ChainedEntry.
        for line in &lines {
            let _entry: ChainedEntry = serde_json::from_str(line)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn recovery_from_existing_file() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let key = b"recovery-key".to_vec();

        // Write two entries with the first writer.
        {
            let writer = AuditLogWriter::new(&path, key.clone()).await?;
            writer.append(&sample_event()).await?;
            writer.append(&sample_event()).await?;
        }

        // Open a new writer on the same file -- it should recover
        // prev_hash.
        let writer = AuditLogWriter::new(&path, key.clone()).await?;
        writer.append(&sample_event()).await?;

        // Verify the whole chain.
        let contents = tokio::fs::read_to_string(&path).await?;
        let entries: Vec<ChainedEntry> = contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;

        assert_eq!(entries.len(), 3);
        chain::verify_chain(&key, &entries)?;
        Ok(())
    }

    #[tokio::test]
    async fn new_file_starts_from_genesis() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fresh.jsonl");
        let key = b"fresh-key".to_vec();

        let writer = AuditLogWriter::new(&path, key.clone()).await?;
        writer.append(&sample_event()).await?;

        let contents = tokio::fs::read_to_string(&path).await?;
        let first_line = contents
            .lines()
            .next()
            .ok_or_else(|| std::io::Error::other("expected at least one JSONL line"))?;
        let entry: ChainedEntry = serde_json::from_str(first_line)?;

        assert_eq!(entry.prev_hash, GENESIS_HASH);
        Ok(())
    }

    #[tokio::test]
    async fn append_preserves_structured_fields_through_round_trip() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fields.jsonl");
        let key = b"fields-key".to_vec();

        let writer = AuditLogWriter::new(&path, key).await?;
        let event = sample_event();
        let fields = serde_json::Map::from_iter([
            ("text_len".to_owned(), serde_json::Value::from(12_u64)),
            ("truncated".to_owned(), serde_json::Value::from(false)),
            ("normalized_len".to_owned(), serde_json::Value::from(14_u64)),
            (
                "target_origin".to_owned(),
                serde_json::Value::from("BridgeSlack"),
            ),
        ]);

        writer.append_with_fields(&event, fields).await?;

        let contents = tokio::fs::read_to_string(&path).await?;
        let entry: ChainedEntry = serde_json::from_str(
            contents
                .lines()
                .next()
                .ok_or_else(|| std::io::Error::other("expected one entry"))?,
        )?;

        let fields = entry
            .fields
            .ok_or_else(|| std::io::Error::other("fields should be present"))?;
        assert_eq!(
            fields.get("text_len"),
            Some(&serde_json::Value::from(12_u64))
        );
        assert_eq!(
            fields.get("truncated"),
            Some(&serde_json::Value::from(false))
        );
        assert_eq!(
            fields.get("normalized_len"),
            Some(&serde_json::Value::from(14_u64))
        );
        assert_eq!(
            fields.get("target_origin"),
            Some(&serde_json::Value::from("BridgeSlack"))
        );
        Ok(())
    }
}
