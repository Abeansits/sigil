//! Store-specific error types.

use sigil_core::CoreError;

/// Errors from the persistence layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("session not found: {id}")]
    SessionNotFound { id: String },

    #[error("duplicate session title: {title}")]
    DuplicateTitle { title: String },

    /// A `set_session_parent_checked` call was rejected because the
    /// proposed assignment would form a parent chain cycle.
    #[error("parent cycle: {reason}")]
    ParentCycle { reason: String },

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<StoreError> for CoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::SessionNotFound { id } => Self::Store {
                message: format!("session not found: {id}"),
            },
            StoreError::DuplicateTitle { title } => Self::Store {
                message: format!("duplicate session title: {title}"),
            },
            StoreError::ParentCycle { reason } => Self::Store {
                message: format!("parent cycle: {reason}"),
            },
            StoreError::Database(e) => Self::Store {
                message: format!("database error: {e}"),
            },
            StoreError::Migration(e) => Self::Store {
                message: format!("migration error: {e}"),
            },
            StoreError::Serialization(e) => Self::Store {
                message: format!("serialization error: {e}"),
            },
        }
    }
}

impl From<StoreError> for sigil_policy::PolicyError {
    fn from(err: StoreError) -> Self {
        Self::Denied {
            reason: format!("store error: {err}"),
        }
    }
}
