//! Episode log reading and filtering.
//!
//! [`EpisodeReader`] reads [`sigil_core::EpisodeEvent`]s from a JSONL
//! episode log and supports filtering by session, kind, tag, and date
//! range via [`EpisodeFilter`].

use std::path::{Path, PathBuf};

use sigil_core::{EpisodeEvent, EpisodeKind, SessionId};

use crate::error::MemoryError;

/// Filter criteria for reading episodes.
///
/// All fields are optional. An episode must match **all** specified
/// criteria to be included (logical AND). Use `EpisodeFilter::default()`
/// for an unfiltered read.
#[derive(Debug, Default, Clone)]
pub struct EpisodeFilter {
    /// Only include episodes from this session.
    pub session_id: Option<SessionId>,
    /// Only include episodes of this kind.
    pub kind: Option<EpisodeKind>,
    /// Only include episodes that carry this tag.
    pub tag: Option<String>,
    /// Only include episodes at or after this timestamp.
    pub since: Option<time::OffsetDateTime>,
    /// Only include episodes strictly before this timestamp.
    pub until: Option<time::OffsetDateTime>,
}

/// Reads and filters episodes from a JSONL log file.
pub struct EpisodeReader {
    path: PathBuf,
}

impl EpisodeReader {
    /// Create a reader for the episode log at `path`.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Read all episodes from the log.
    ///
    /// Returns an empty vec if the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Read`] on I/O failure or
    /// [`MemoryError::Serialize`] if any line cannot be deserialized.
    pub async fn read_all(&self) -> Result<Vec<EpisodeEvent>, MemoryError> {
        self.read_filtered(&EpisodeFilter::default()).await
    }

    /// Read episodes matching the given filter.
    ///
    /// Returns an empty vec if the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Read`] on I/O failure or
    /// [`MemoryError::Serialize`] if any line cannot be deserialized.
    pub async fn read_filtered(
        &self,
        filter: &EpisodeFilter,
    ) -> Result<Vec<EpisodeEvent>, MemoryError> {
        let contents = match tokio::fs::read_to_string(&self.path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(MemoryError::Read(e)),
        };

        let mut episodes = Vec::new();
        for line in contents.lines() {
            if line.is_empty() {
                continue;
            }
            let event: EpisodeEvent = serde_json::from_str(line)?;
            if matches_filter(&event, filter) {
                episodes.push(event);
            }
        }
        Ok(episodes)
    }

    /// The path to the episode log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Check whether an event passes all filter criteria.
fn matches_filter(event: &EpisodeEvent, filter: &EpisodeFilter) -> bool {
    if let Some(ref sid) = filter.session_id {
        if event.session_id != *sid {
            return false;
        }
    }
    if let Some(ref kind) = filter.kind {
        if event.kind != *kind {
            return false;
        }
    }
    if let Some(ref tag) = filter.tag {
        if !event.tags.contains(tag) {
            return false;
        }
    }
    if let Some(since) = filter.since {
        if event.timestamp < since {
            return false;
        }
    }
    if let Some(until) = filter.until {
        if event.timestamp >= until {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, SessionId};
    use time::OffsetDateTime;

    use super::*;
    use crate::writer::EpisodeWriter;

    fn make_event(session_id: SessionId, kind: EpisodeKind, tags: Vec<String>) -> EpisodeEvent {
        EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id,
            kind,
            summary: "test event".into(),
            details: None,
            tags,
            source: "test".into(),
        }
    }

    fn make_event_at(session_id: SessionId, kind: EpisodeKind, ts: OffsetDateTime) -> EpisodeEvent {
        EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: ts,
            session_id,
            kind,
            summary: "test event".into(),
            details: None,
            tags: vec![],
            source: "test".into(),
        }
    }

    #[tokio::test]
    async fn read_all_returns_all_events() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let s1 = SessionId::new();
        writer
            .append(&make_event(s1, EpisodeKind::ActionCompleted, vec![]))
            .await?;
        writer
            .append(&make_event(s1, EpisodeKind::ToolOutcome, vec![]))
            .await?;

        let reader = EpisodeReader::new(&path);
        let all = reader.read_all().await?;
        assert_eq!(all.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn read_missing_file_returns_empty() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("nonexistent.jsonl");

        let reader = EpisodeReader::new(&path);
        let all = reader.read_all().await?;
        assert!(all.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn filter_by_kind_returns_matching() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let s1 = SessionId::new();
        writer
            .append(&make_event(s1, EpisodeKind::ActionCompleted, vec![]))
            .await?;
        writer
            .append(&make_event(s1, EpisodeKind::ToolOutcome, vec![]))
            .await?;
        writer
            .append(&make_event(s1, EpisodeKind::ActionCompleted, vec![]))
            .await?;

        let reader = EpisodeReader::new(&path);
        let filtered = reader
            .read_filtered(&EpisodeFilter {
                kind: Some(EpisodeKind::ActionCompleted),
                ..EpisodeFilter::default()
            })
            .await?;
        assert_eq!(filtered.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn filter_by_session_returns_matching() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let s1 = SessionId::new();
        let s2 = SessionId::new();
        writer
            .append(&make_event(s1, EpisodeKind::ActionCompleted, vec![]))
            .await?;
        writer
            .append(&make_event(s2, EpisodeKind::ActionCompleted, vec![]))
            .await?;
        writer
            .append(&make_event(s1, EpisodeKind::ToolOutcome, vec![]))
            .await?;

        let reader = EpisodeReader::new(&path);
        let filtered = reader
            .read_filtered(&EpisodeFilter {
                session_id: Some(s1),
                ..EpisodeFilter::default()
            })
            .await?;
        assert_eq!(filtered.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn filter_by_tag_returns_matching() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let s1 = SessionId::new();
        writer
            .append(&make_event(
                s1,
                EpisodeKind::ActionCompleted,
                vec!["infra".into()],
            ))
            .await?;
        writer
            .append(&make_event(
                s1,
                EpisodeKind::ActionCompleted,
                vec!["auth".into()],
            ))
            .await?;
        writer
            .append(&make_event(
                s1,
                EpisodeKind::ToolOutcome,
                vec!["infra".into(), "debug".into()],
            ))
            .await?;

        let reader = EpisodeReader::new(&path);
        let filtered = reader
            .read_filtered(&EpisodeFilter {
                tag: Some("infra".into()),
                ..EpisodeFilter::default()
            })
            .await?;
        assert_eq!(filtered.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn filter_by_date_range_returns_matching() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("episodes.jsonl");
        let writer = EpisodeWriter::new(&path).await?;

        let s1 = SessionId::new();
        let early = make_time(2026, 1, 1);
        let mid = make_time(2026, 3, 15);
        let late = make_time(2026, 6, 1);

        writer
            .append(&make_event_at(s1, EpisodeKind::ActionCompleted, early))
            .await?;
        writer
            .append(&make_event_at(s1, EpisodeKind::ActionCompleted, mid))
            .await?;
        writer
            .append(&make_event_at(s1, EpisodeKind::ActionCompleted, late))
            .await?;

        let reader = EpisodeReader::new(&path);
        let filtered = reader
            .read_filtered(&EpisodeFilter {
                since: Some(make_time(2026, 2, 1)),
                until: Some(make_time(2026, 5, 1)),
                ..EpisodeFilter::default()
            })
            .await?;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].timestamp, mid);
        Ok(())
    }

    fn make_time(year: i32, month: u8, day: u8) -> OffsetDateTime {
        let month = time::Month::try_from(month).unwrap();
        time::Date::from_calendar_date(year, month, day)
            .unwrap()
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
    }
}
