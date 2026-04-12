//! Episodic memory types for capturing session events.
//!
//! An [`EpisodeEvent`] represents a single notable occurrence during a session:
//! an action completing, a tool outcome, an approval decision, a user correction,
//! or a candidate learning proposed by the agent.
//!
//! These events are written to `episodes.jsonl` by `sigil-memory::EpisodeWriter`
//! and consumed by the mechanical consolidator. They are **not** part of the
//! security audit trail (`sigil-audit`); they serve an operational purpose.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::id::SessionId;

/// Unique identifier for an episode event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpisodeId(Ulid);

impl EpisodeId {
    /// Create a new random `EpisodeId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    /// Wrap an existing ULID.
    #[must_use]
    pub fn from_ulid(id: Ulid) -> Self {
        Self(id)
    }

    /// Access the inner ULID.
    #[must_use]
    pub fn as_ulid(&self) -> Ulid {
        self.0
    }
}

impl Default for EpisodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EpisodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for EpisodeId {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_str(s).map(Self)
    }
}

/// Category of an episode event.
///
/// The enum is `#[non_exhaustive]` so new kinds can be added in future
/// releases without breaking downstream consumers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EpisodeKind {
    /// An action completed (worktree create, session launch, etc.).
    ActionCompleted,
    /// A tool produced a notable outcome.
    ToolOutcome,
    /// An approval was granted or denied.
    ApprovalDecision,
    /// The user corrected the agent's behavior.
    UserCorrection,
    /// The agent proposes a candidate learning.
    CandidateLearning,
    /// Session ended — end-of-session summary.
    SessionSummary,
    /// State checkpoint (pre-compact snapshot diff).
    StateCheckpoint,
}

/// A single episode captured during a session.
///
/// Episodes are the raw material for memory consolidation. They are
/// serialized as one JSON object per line in `episodes.jsonl`.
///
/// # Serialization
///
/// Timestamps use RFC 3339 format. The `details` field is freeform JSON
/// whose schema varies by [`EpisodeKind`]. Missing `details` deserializes
/// as [`serde_json::Value::Null`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpisodeEvent {
    /// Unique identifier for this episode.
    pub id: EpisodeId,

    /// When the episode occurred.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: time::OffsetDateTime,

    /// Which session produced this episode.
    pub session_id: SessionId,

    /// Category of event.
    pub kind: EpisodeKind,

    /// One-line human-readable summary.
    pub summary: String,

    /// Structured context (schema varies by kind). `None` serializes as
    /// JSON `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Freeform tags for filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Who wrote this episode: `"conductor"`, `"agent"`, `"cli"`.
    pub source: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn episode_id_roundtrips_through_string() {
        let id = EpisodeId::new();
        let s = id.to_string();
        let parsed: EpisodeId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn episode_kind_equality() {
        assert_eq!(EpisodeKind::ActionCompleted, EpisodeKind::ActionCompleted);
        assert_eq!(EpisodeKind::ToolOutcome, EpisodeKind::ToolOutcome);
        assert_eq!(EpisodeKind::ApprovalDecision, EpisodeKind::ApprovalDecision);
        assert_eq!(EpisodeKind::UserCorrection, EpisodeKind::UserCorrection);
        assert_eq!(
            EpisodeKind::CandidateLearning,
            EpisodeKind::CandidateLearning
        );
        assert_eq!(EpisodeKind::SessionSummary, EpisodeKind::SessionSummary);
        assert_eq!(EpisodeKind::StateCheckpoint, EpisodeKind::StateCheckpoint);
        assert_ne!(EpisodeKind::ActionCompleted, EpisodeKind::ToolOutcome);
        assert_ne!(EpisodeKind::CandidateLearning, EpisodeKind::SessionSummary);
    }

    #[test]
    fn episode_event_serde_round_trip() {
        let event = EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            session_id: SessionId::new(),
            kind: EpisodeKind::ActionCompleted,
            summary: "Created worktree feature/auth".into(),
            details: Some(serde_json::json!({
                "action": "WorktreeCreate",
                "branch": "feature/auth"
            })),
            tags: vec!["worktree".into(), "infrastructure".into()],
            source: "conductor".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EpisodeEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, event.id);
        assert_eq!(deserialized.session_id, event.session_id);
        assert_eq!(deserialized.kind, EpisodeKind::ActionCompleted);
        assert_eq!(deserialized.summary, "Created worktree feature/auth");
        assert!(deserialized.details.is_some());
        assert_eq!(deserialized.tags, vec!["worktree", "infrastructure"]);
        assert_eq!(deserialized.source, "conductor");
    }

    #[test]
    fn episode_event_serde_round_trip_no_details_no_tags() {
        let event = EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            session_id: SessionId::new(),
            kind: EpisodeKind::SessionSummary,
            summary: "Session ended cleanly".into(),
            details: None,
            tags: vec![],
            source: "cli".into(),
        };

        let json = serde_json::to_string(&event).unwrap();

        // details and tags should be absent from the JSON
        assert!(!json.contains("details"));
        assert!(!json.contains("tags"));

        let deserialized: EpisodeEvent = serde_json::from_str(&json).unwrap();
        assert!(deserialized.details.is_none());
        assert!(deserialized.tags.is_empty());
    }

    #[test]
    fn episode_event_candidate_learning_round_trip() {
        let event = EpisodeEvent {
            id: EpisodeId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            session_id: SessionId::new(),
            kind: EpisodeKind::CandidateLearning,
            summary: "Worktree branches should match the session title".into(),
            details: Some(serde_json::json!({
                "confidence": "medium",
                "context": "Noticed confusion when branch name didn't match session"
            })),
            tags: vec!["worktree".into(), "naming".into()],
            source: "agent".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EpisodeEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.kind, EpisodeKind::CandidateLearning);
        let details = deserialized.details.unwrap();
        assert_eq!(details["confidence"], "medium");
    }
}
