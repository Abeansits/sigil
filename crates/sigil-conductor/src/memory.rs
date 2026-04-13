//! Episode capture and idle consolidation wiring for the conductor.
//!
//! [`MemoryHandle`] bundles the episode writer, configuration, and
//! idle-cycle tracking the conductor needs for episodic capture and
//! mechanical consolidation. Episode creation helpers translate
//! heartbeat state changes and bridge messages into
//! [`sigil_core::EpisodeEvent`]s.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use sigil_core::session::SessionState;
use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig, SessionId};
use sigil_memory::{EpisodeReader, EpisodeWriter, MechanicalConsolidator};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::error::ConductorError;
use crate::heartbeat::StateChange;

/// Default number of consecutive idle heartbeat cycles before triggering
/// consolidation.
pub const DEFAULT_IDLE_THRESHOLD: u32 = 3;

/// Memory subsystem handle for the conductor.
///
/// Bundles the episode writer, configuration, idle-cycle tracking, and
/// learnings path needed for episodic capture and mechanical
/// consolidation. Created via [`Conductor::with_memory`](super::Conductor::with_memory).
pub struct MemoryHandle {
    writer: Arc<EpisodeWriter>,
    config: MemoryConfig,
    learnings_path: PathBuf,
    consecutive_idle_cycles: AtomicU32,
    idle_threshold: u32,
}

impl MemoryHandle {
    /// Create a new memory handle.
    ///
    /// `learnings_path` is the path to `LEARNINGS.md` in the project
    /// directory. The handle uses [`DEFAULT_IDLE_THRESHOLD`] for idle
    /// detection.
    pub fn new(
        writer: Arc<EpisodeWriter>,
        config: MemoryConfig,
        learnings_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            writer,
            config,
            learnings_path: learnings_path.as_ref().to_path_buf(),
            consecutive_idle_cycles: AtomicU32::new(0),
            idle_threshold: DEFAULT_IDLE_THRESHOLD,
        }
    }

    /// Override the idle threshold (mainly for testing).
    #[must_use]
    pub fn with_idle_threshold(mut self, threshold: u32) -> Self {
        self.idle_threshold = threshold;
        self
    }

    /// Whether episodic capture is enabled.
    #[must_use]
    pub fn episodes_enabled(&self) -> bool {
        self.config.episodes_enabled
    }

    /// Whether consolidation is enabled.
    #[must_use]
    pub fn consolidation_enabled(&self) -> bool {
        self.config.consolidation_enabled
    }

    /// Reference to the shared episode writer.
    #[must_use]
    pub fn writer(&self) -> &Arc<EpisodeWriter> {
        &self.writer
    }

    /// The current consecutive idle cycle count.
    #[must_use]
    pub fn idle_cycles(&self) -> u32 {
        self.consecutive_idle_cycles.load(Ordering::Relaxed)
    }

    /// Record one idle cycle. Returns `true` when the idle threshold is
    /// reached (meaning consolidation should run).
    pub fn record_idle_cycle(&self) -> bool {
        let cycles = self.consecutive_idle_cycles.fetch_add(1, Ordering::Relaxed) + 1;
        cycles >= self.idle_threshold
    }

    /// Reset the consecutive idle cycle counter (called when a non-idle
    /// heartbeat is observed, or after consolidation runs).
    pub fn reset_idle_cycles(&self) {
        self.consecutive_idle_cycles.store(0, Ordering::Relaxed);
    }

    /// Append episodes for any actionable state changes detected during
    /// a heartbeat scan.
    ///
    /// Only records transitions that indicate an action completed
    /// (e.g. `Running` → `Waiting`/`Idle`).
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::Memory`] if episode serialization or
    /// I/O fails.
    pub async fn record_state_changes(
        &self,
        changes: &[StateChange],
    ) -> Result<(), ConductorError> {
        if !self.config.episodes_enabled {
            return Ok(());
        }
        for change in changes {
            if let Some(episode) = action_completed_episode(change) {
                self.writer.append(&episode).await?;
            }
        }
        Ok(())
    }

    /// Append an episode recording a bridge message sent to a session.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::Memory`] on write failure.
    pub async fn record_bridge_send(
        &self,
        session_id: SessionId,
        session_title: &str,
    ) -> Result<(), ConductorError> {
        if !self.config.episodes_enabled {
            return Ok(());
        }
        let episode = EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id,
            kind: EpisodeKind::ActionCompleted,
            summary: format!("Bridge: sent message to {session_title}"),
            details: Some(serde_json::json!({ "command": "send" })),
            tags: vec!["bridge".into()],
            source: "conductor".into(),
        };
        self.writer.append(&episode).await?;
        Ok(())
    }

    /// Run one mechanical consolidation pass.
    ///
    /// Reads all episodes from the log, reads existing `LEARNINGS.md`,
    /// applies promotion / dedup / staleness / archival rules, and
    /// writes the updated `LEARNINGS.md` if anything changed.
    ///
    /// Returns `Some(result)` when learnings were updated, `None` when
    /// nothing changed.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] on I/O or consolidation failure.
    pub async fn consolidate(
        &self,
    ) -> Result<Option<sigil_memory::ConsolidationResult>, ConductorError> {
        let reader = EpisodeReader::new(self.writer.path());
        let episodes = reader.read_all().await?;

        let existing_learnings = match tokio::fs::read_to_string(&self.learnings_path).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                warn!(
                    path = %self.learnings_path.display(),
                    error = %e,
                    "failed to read LEARNINGS.md, proceeding with empty"
                );
                String::new()
            }
        };

        let consolidator = MechanicalConsolidator::new(self.config.clone());
        let now = OffsetDateTime::now_utc();
        let result = consolidator.consolidate(&episodes, &existing_learnings, now)?;

        if !result.promoted.is_empty() || !result.marked_stale.is_empty() {
            if let Some(parent) = self.learnings_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| ConductorError::Internal {
                        message: format!("failed to create directory for LEARNINGS.md: {e}"),
                    })?;
            }

            tokio::fs::write(&self.learnings_path, &result.learnings_content)
                .await
                .map_err(|e| ConductorError::Internal {
                    message: format!("failed to write LEARNINGS.md: {e}"),
                })?;

            info!(
                promoted = result.promoted.len(),
                stale = result.marked_stale.len(),
                archived = result.archived_episodes.len(),
                "consolidation complete"
            );

            Ok(Some(result))
        } else {
            info!("consolidation: nothing to promote or mark stale");
            Ok(None)
        }
    }
}

/// Create an `ActionCompleted` episode from a heartbeat state change.
///
/// Only produces an episode when the transition indicates a task
/// completed: `Running` → `Waiting` or `Running` → `Idle`.
#[must_use]
pub fn action_completed_episode(change: &StateChange) -> Option<EpisodeEvent> {
    #[allow(clippy::wildcard_enum_match_arm)]
    match (change.old_state, change.new_state) {
        (SessionState::Running, SessionState::Waiting | SessionState::Idle) => Some(EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id: change.session_id,
            kind: EpisodeKind::ActionCompleted,
            summary: format!(
                "Session '{}' completed task (now {:?})",
                change.title, change.new_state,
            ),
            details: Some(serde_json::json!({
                "old_state": format!("{:?}", change.old_state),
                "new_state": format!("{:?}", change.new_state),
            })),
            tags: vec!["heartbeat".into()],
            source: "conductor".into(),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::Arc;

    use sigil_core::session::SessionState;
    use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig, SessionId};
    use sigil_memory::EpisodeWriter;
    use time::OffsetDateTime;

    use super::*;

    // -- action_completed_episode ---------------------------------------------

    #[test]
    fn running_to_waiting_produces_episode() {
        let id = SessionId::new();
        let change = StateChange {
            session_id: id,
            title: "auth-agent".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Waiting,
        };

        let episode = action_completed_episode(&change);
        assert!(episode.is_some());

        let ep = episode.unwrap();
        assert_eq!(ep.session_id, id);
        assert_eq!(ep.kind, EpisodeKind::ActionCompleted);
        assert_eq!(ep.source, "conductor");
        assert!(ep.summary.contains("auth-agent"));
        assert!(ep.summary.contains("completed task"));
    }

    #[test]
    fn running_to_idle_produces_episode() {
        let id = SessionId::new();
        let change = StateChange {
            session_id: id,
            title: "test-session".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Idle,
        };

        let episode = action_completed_episode(&change);
        assert!(episode.is_some());
        assert_eq!(episode.unwrap().kind, EpisodeKind::ActionCompleted);
    }

    #[test]
    fn waiting_to_running_produces_no_episode() {
        let change = StateChange {
            session_id: SessionId::new(),
            title: "test".into(),
            old_state: SessionState::Waiting,
            new_state: SessionState::Running,
        };
        assert!(action_completed_episode(&change).is_none());
    }

    #[test]
    fn running_to_error_produces_no_episode() {
        let change = StateChange {
            session_id: SessionId::new(),
            title: "test".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Error,
        };
        assert!(action_completed_episode(&change).is_none());
    }

    #[test]
    fn stopped_to_stopped_produces_no_episode() {
        let change = StateChange {
            session_id: SessionId::new(),
            title: "test".into(),
            old_state: SessionState::Stopped,
            new_state: SessionState::Stopped,
        };
        assert!(action_completed_episode(&change).is_none());
    }

    #[test]
    fn episode_has_correct_session_id_and_kind() {
        let id = SessionId::new();
        let change = StateChange {
            session_id: id,
            title: "my-session".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Waiting,
        };

        let ep = action_completed_episode(&change).unwrap();
        assert_eq!(ep.session_id, id);
        assert_eq!(ep.kind, EpisodeKind::ActionCompleted);
        assert!(!ep.tags.is_empty());
        assert_eq!(ep.tags[0], "heartbeat");
    }

    // -- MemoryHandle: idle detection -----------------------------------------

    #[tokio::test]
    async fn idle_detection_triggers_at_default_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(
            EpisodeWriter::new(dir.path().join("episodes.jsonl"))
                .await
                .unwrap(),
        );
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        // Cycles 1 and 2: not yet.
        assert!(!handle.record_idle_cycle());
        assert!(!handle.record_idle_cycle());
        // Cycle 3: threshold reached.
        assert!(handle.record_idle_cycle());
    }

    #[tokio::test]
    async fn idle_detection_triggers_at_custom_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(
            EpisodeWriter::new(dir.path().join("episodes.jsonl"))
                .await
                .unwrap(),
        );
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        )
        .with_idle_threshold(2);

        assert!(!handle.record_idle_cycle());
        assert!(handle.record_idle_cycle());
    }

    #[tokio::test]
    async fn idle_detection_resets() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(
            EpisodeWriter::new(dir.path().join("episodes.jsonl"))
                .await
                .unwrap(),
        );
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        assert!(!handle.record_idle_cycle());
        assert!(!handle.record_idle_cycle());
        handle.reset_idle_cycles();
        assert_eq!(handle.idle_cycles(), 0);

        // Need 3 more cycles after reset.
        assert!(!handle.record_idle_cycle());
        assert!(!handle.record_idle_cycle());
        assert!(handle.record_idle_cycle());
    }

    // -- MemoryHandle: state change recording ---------------------------------

    #[tokio::test]
    async fn heartbeat_with_completed_action_produces_episode() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        let session_id = SessionId::new();
        let changes = vec![StateChange {
            session_id,
            title: "build-agent".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Waiting,
        }];

        handle.record_state_changes(&changes).await.unwrap();

        // Read back the episode log.
        let reader = sigil_memory::EpisodeReader::new(&episodes_path);
        let episodes = reader.read_all().await.unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].session_id, session_id);
        assert_eq!(episodes[0].kind, EpisodeKind::ActionCompleted);
        assert!(episodes[0].summary.contains("build-agent"));
    }

    #[tokio::test]
    async fn non_actionable_state_change_produces_no_episode() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        let changes = vec![StateChange {
            session_id: SessionId::new(),
            title: "test".into(),
            old_state: SessionState::Waiting,
            new_state: SessionState::Running,
        }];

        handle.record_state_changes(&changes).await.unwrap();

        let reader = sigil_memory::EpisodeReader::new(&episodes_path);
        let episodes = reader.read_all().await.unwrap();
        assert!(episodes.is_empty());
    }

    #[tokio::test]
    async fn episodes_disabled_skips_recording() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let config = MemoryConfig {
            episodes_enabled: false,
            ..MemoryConfig::default()
        };
        let handle = MemoryHandle::new(writer, config, dir.path().join("LEARNINGS.md"));

        let changes = vec![StateChange {
            session_id: SessionId::new(),
            title: "test".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Waiting,
        }];

        handle.record_state_changes(&changes).await.unwrap();

        let reader = sigil_memory::EpisodeReader::new(&episodes_path);
        let episodes = reader.read_all().await.unwrap();
        assert!(episodes.is_empty());
    }

    // -- MemoryHandle: bridge send recording ----------------------------------

    #[tokio::test]
    async fn bridge_send_produces_episode() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        let session_id = SessionId::new();
        handle
            .record_bridge_send(session_id, "api-server")
            .await
            .unwrap();

        let reader = sigil_memory::EpisodeReader::new(&episodes_path);
        let episodes = reader.read_all().await.unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].session_id, session_id);
        assert_eq!(episodes[0].kind, EpisodeKind::ActionCompleted);
        assert!(episodes[0].summary.contains("api-server"));
        assert_eq!(episodes[0].tags, vec!["bridge"]);
    }

    // -- MemoryHandle: consolidation ------------------------------------------

    #[tokio::test]
    async fn consolidation_runs_on_idle_and_promotes_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let learnings_path = dir.path().join("LEARNINGS.md");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let handle = MemoryHandle::new(writer.clone(), MemoryConfig::default(), &learnings_path);

        // Write 3 candidate learnings from 3 distinct sessions.
        for _ in 0..3 {
            let episode = EpisodeEvent {
                id: EpisodeId::new(),
                timestamp: OffsetDateTime::now_utc(),
                session_id: SessionId::new(),
                kind: EpisodeKind::CandidateLearning,
                summary: "Always verify session state before sending".into(),
                details: None,
                tags: vec![],
                source: "test".into(),
            };
            writer.append(&episode).await.unwrap();
        }

        let result = handle.consolidate().await.unwrap();
        assert!(result.is_some(), "should have promoted a learning");

        let result = result.unwrap();
        assert_eq!(result.promoted.len(), 1);
        assert_eq!(
            result.promoted[0],
            "Always verify session state before sending"
        );

        // LEARNINGS.md should exist with the promoted learning.
        let content = tokio::fs::read_to_string(&learnings_path).await.unwrap();
        assert!(content.contains("Always verify session state before sending"));
    }

    #[tokio::test]
    async fn consolidation_with_no_candidates_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let episodes_path = dir.path().join("episodes.jsonl");
        let writer = Arc::new(EpisodeWriter::new(&episodes_path).await.unwrap());
        let handle = MemoryHandle::new(
            writer,
            MemoryConfig::default(),
            dir.path().join("LEARNINGS.md"),
        );

        let result = handle.consolidate().await.unwrap();
        assert!(result.is_none());
    }
}
