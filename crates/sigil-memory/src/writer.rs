//! Append-only JSONL writer for the episode log.
//!
//! [`EpisodeWriter`] writes [`sigil_core::EpisodeEvent`]s as
//! newline-delimited JSON to `episodes.jsonl`. It uses a mutex-guarded
//! file handle so concurrent appends from the conductor and CLI are
//! serialized.
//!
//! This writer does **not** maintain an HMAC chain — episode logs are
//! operational memory, not a security boundary. See `sigil-audit` for
//! tamper-evident logging.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use sigil_core::EpisodeEvent;

use crate::error::MemoryError;

/// Append-only JSONL writer for the episode log.
///
/// Each call to [`append`](Self::append) serializes one
/// [`sigil_core::EpisodeEvent`] as a single JSON line, followed by a
/// newline and a flush. The internal mutex ensures concurrent appends
/// do not interleave.
pub struct EpisodeWriter {
    path: PathBuf,
    file: Mutex<tokio::fs::File>,
}

impl EpisodeWriter {
    /// Open or create the episode log file at `path`.
    ///
    /// The file is opened in append mode. If it does not exist, it is
    /// created along with any missing parent directories.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Write`] if the file cannot be opened or
    /// created.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, MemoryError> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(MemoryError::Write)?;
        }

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(MemoryError::Write)?;

        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Append an episode event to the log.
    ///
    /// Serializes `event` as a single JSON line, writes it, and flushes.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Serialize`] if the event cannot be
    /// serialized, or [`MemoryError::Write`] on I/O failure.
    pub async fn append(&self, event: &EpisodeEvent) -> Result<(), MemoryError> {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&line).await.map_err(MemoryError::Write)?;
        file.flush().await.map_err(MemoryError::Write)?;

        tracing::debug!(
            path = %self.path.display(),
            episode_id = %event.id,
            kind = ?event.kind,
            "episode appended"
        );

        Ok(())
    }

    /// The path to the episode log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::Arc;

    use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, SessionId};
    use time::OffsetDateTime;

    use super::*;

    fn sample_event(session_id: SessionId) -> EpisodeEvent {
        EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id,
            kind: EpisodeKind::ActionCompleted,
            summary: "test action completed".into(),
            details: None,
            tags: vec![],
            source: "test".into(),
        }
    }

    #[tokio::test]
    async fn append_and_readback_produces_valid_jsonl() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let session = SessionId::new();
        writer.append(&sample_event(session)).await?;
        writer.append(&sample_event(session)).await?;

        let contents = tokio::fs::read_to_string(&path).await?;
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "should have two JSONL lines");

        for line in &lines {
            let _event: EpisodeEvent = serde_json::from_str(line)?;
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_dont_interleave() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&path).await?);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let w = Arc::clone(&writer);
            let session = SessionId::new();
            handles.push(tokio::spawn(async move {
                w.append(&sample_event(session)).await
            }));
        }

        for handle in handles {
            handle.await??;
        }

        let contents = tokio::fs::read_to_string(&path).await?;
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 10, "all 10 concurrent appends should land");

        // Every line must parse as valid JSON.
        for line in &lines {
            let _event: EpisodeEvent = serde_json::from_str(line)?;
        }
        Ok(())
    }
}
