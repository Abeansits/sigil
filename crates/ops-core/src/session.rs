use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::id::{GroupId, SessionId};
use crate::trust::ExecutionClass;

/// Which AI tool runs inside a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToolKind {
    ClaudeCode,
    Codex,
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
}

/// Configuration for a conductor instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConductorConfig {
    pub name: String,
    pub auto_response_enabled: bool,
    pub heartbeat_interval_secs: u64,
    pub escalation_channels: Vec<String>,
}
