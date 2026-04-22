use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::MemoryConfig;
use crate::id::{GroupId, SessionId};
use crate::trust::ExecutionClass;

/// Which AI tool runs inside a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToolKind {
    ClaudeCode,
    Codex,
    OpenCode,
}

/// Observable state of an agent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionState {
    /// Agent is actively processing.
    Running,
    /// Agent finished, awaiting input.
    Waiting,
    /// Waiting, but user acknowledged.
    Idle,
    /// Session crashed or unreachable.
    Error,
    /// Session is stopped (not running).
    Stopped,
}

/// Lifecycle events that trigger identity reloads, memory capture, or
/// consolidation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    /// After context compaction completes.
    PostCompact,
    /// Before context compaction (snapshot opportunity).
    PreCompact,
    /// On session restart.
    Restart,
    /// On fresh session start.
    SessionStart,
    /// After a conductor-mediated action completes.
    PostAction,
    /// When a session stops (clean shutdown).
    SessionEnd,
    /// When all sessions are idle for a sustained period.
    Idle,
}

/// Files that define an agent session's identity and operating context.
/// These are reloaded on lifecycle events (compaction, restart, etc.).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IdentitySpec {
    /// Paths relative to the session's working directory.
    /// Loaded in order — identity first, then state, then learnings.
    pub files: Vec<PathBuf>,

    /// Which lifecycle events trigger a reload.
    pub reload_on: Vec<LifecycleEvent>,
}

/// Configuration for creating a new session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    pub path: PathBuf,
    pub title: String,
    pub tool: ToolKind,
    pub group: Option<GroupId>,
    pub parent: Option<SessionId>,
    pub execution_class: ExecutionClass,
    pub sandboxed: bool,
    pub initial_message: Option<String>,
    pub worktree_branch: Option<String>,
    pub identity: Option<IdentitySpec>,
    /// Memory subsystem configuration for this session.
    pub memory: Option<MemoryConfig>,
}

/// Handle to a live session. Opaque reference used by `SessionRuntime`.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    pub id: SessionId,
    pub title: String,
    pub tool: ToolKind,
    pub state: SessionState,
    pub path: PathBuf,
    pub tmux_window: Option<String>,
    pub container_id: Option<String>,
    pub execution_class: ExecutionClass,
    pub sandboxed: bool,
    pub identity: Option<IdentitySpec>,
}

/// Persisted session metadata (stored in `SQLite`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub title: String,
    pub path: PathBuf,
    pub tool: ToolKind,
    pub group: Option<GroupId>,
    pub parent: Option<SessionId>,
    pub execution_class: ExecutionClass,
    pub sandboxed: bool,
    pub state: SessionState,
    pub identity: Option<IdentitySpec>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn identity_spec_default_is_empty() {
        let spec = IdentitySpec::default();
        assert!(spec.files.is_empty());
        assert!(spec.reload_on.is_empty());
    }

    #[test]
    fn lifecycle_event_equality() {
        assert_eq!(LifecycleEvent::PostCompact, LifecycleEvent::PostCompact);
        assert_eq!(LifecycleEvent::PreCompact, LifecycleEvent::PreCompact);
        assert_eq!(LifecycleEvent::Restart, LifecycleEvent::Restart);
        assert_eq!(LifecycleEvent::SessionStart, LifecycleEvent::SessionStart);
        assert_eq!(LifecycleEvent::PostAction, LifecycleEvent::PostAction);
        assert_eq!(LifecycleEvent::SessionEnd, LifecycleEvent::SessionEnd);
        assert_eq!(LifecycleEvent::Idle, LifecycleEvent::Idle);
        assert_ne!(LifecycleEvent::PostCompact, LifecycleEvent::PreCompact);
        assert_ne!(LifecycleEvent::Restart, LifecycleEvent::SessionStart);
        assert_ne!(LifecycleEvent::PostAction, LifecycleEvent::SessionEnd);
    }

    #[test]
    fn new_lifecycle_events_serde_round_trip() {
        let events = vec![
            LifecycleEvent::PostAction,
            LifecycleEvent::SessionEnd,
            LifecycleEvent::Idle,
        ];

        let json = serde_json::to_string(&events).unwrap();
        let deserialized: Vec<LifecycleEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, events);
    }

    #[test]
    fn identity_spec_serde_round_trip() {
        let spec = IdentitySpec {
            files: vec![
                PathBuf::from("SOUL.md"),
                PathBuf::from("OPS.md"),
                PathBuf::from("state.json"),
            ],
            reload_on: vec![
                LifecycleEvent::PostCompact,
                LifecycleEvent::PreCompact,
                LifecycleEvent::Restart,
                LifecycleEvent::SessionStart,
            ],
        };

        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: IdentitySpec = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.files.len(), 3);
        assert_eq!(deserialized.files[0], PathBuf::from("SOUL.md"));
        assert_eq!(deserialized.files[1], PathBuf::from("OPS.md"));
        assert_eq!(deserialized.files[2], PathBuf::from("state.json"));
        assert_eq!(deserialized.reload_on.len(), 4);
        assert_eq!(deserialized.reload_on[0], LifecycleEvent::PostCompact);
        assert_eq!(deserialized.reload_on[1], LifecycleEvent::PreCompact);
        assert_eq!(deserialized.reload_on[2], LifecycleEvent::Restart);
        assert_eq!(deserialized.reload_on[3], LifecycleEvent::SessionStart);
    }

    #[test]
    fn identity_spec_none_serde_round_trip() {
        let config = SessionConfig {
            path: PathBuf::from("/tmp/test"),
            title: "test".into(),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            initial_message: None,
            worktree_branch: None,
            identity: None,
            memory: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SessionConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.identity.is_none());
        assert!(deserialized.memory.is_none());
    }

    #[test]
    fn identity_spec_some_serde_round_trip() {
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        };
        let config = SessionConfig {
            path: PathBuf::from("/tmp/test"),
            title: "test".into(),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            initial_message: None,
            worktree_branch: None,
            identity: Some(spec),
            memory: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SessionConfig = serde_json::from_str(&json).unwrap();
        let id = deserialized.identity.unwrap();
        assert_eq!(id.files, vec![PathBuf::from("SOUL.md")]);
        assert_eq!(id.reload_on, vec![LifecycleEvent::PostCompact]);
    }
}

/// Configuration for a conductor instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConductorConfig {
    pub name: String,
    pub auto_response_enabled: bool,
    pub heartbeat_interval_secs: u64,
    pub escalation_channels: Vec<String>,
}
