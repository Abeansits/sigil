use sigil_core::CoreError;

/// Errors from the runtime layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("tmux command failed: {command} — {stderr}")]
    TmuxCommand { command: String, stderr: String },

    #[error("tmux not found or too old (need 3.3+)")]
    TmuxNotFound,

    #[error("session not running: {title}")]
    SessionNotRunning { title: String },

    #[error("git command failed: {command} — {stderr}")]
    GitCommand { command: String, stderr: String },

    #[error("failed to load config from {path}: {message}")]
    ConfigLoad {
        path: std::path::PathBuf,
        message: String,
    },

    #[error("failed to parse config: {message}")]
    ConfigParse { message: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout waiting for session")]
    Timeout,
}

impl From<RuntimeError> for CoreError {
    fn from(err: RuntimeError) -> Self {
        Self::Runtime {
            message: err.to_string(),
        }
    }
}
