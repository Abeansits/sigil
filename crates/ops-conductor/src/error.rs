//! Conductor-specific error types.

use ops_core::CoreError;

/// Errors from the conductor orchestration layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConductorError {
    #[error("store error: {0}")]
    Store(#[from] ops_store::StoreError),

    #[error("runtime error: {0}")]
    Runtime(#[from] ops_runtime::RuntimeError),

    #[error("policy error: {0}")]
    Policy(#[from] ops_policy::PolicyError),

    #[error("no sessions found")]
    NoSessions,

    #[error("conductor error: {message}")]
    Internal { message: String },
}

impl From<ConductorError> for CoreError {
    fn from(err: ConductorError) -> Self {
        match err {
            ConductorError::Store(e) => Self::from(e),
            ConductorError::Runtime(e) => Self::from(e),
            ConductorError::Policy(e) => Self::from(e),
            ConductorError::NoSessions => Self::Store {
                message: "no sessions found".into(),
            },
            ConductorError::Internal { message } => Self::Runtime { message },
        }
    }
}
