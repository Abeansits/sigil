//! Audit-specific error types.

/// Errors that can occur during audit operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    #[error("failed to write audit event: {0}")]
    Write(#[source] std::io::Error),

    #[error("failed to serialize audit event: {0}")]
    Serialize(#[source] serde_json::Error),

    #[error("HMAC chain broken at event {event_id}: expected {expected}, got {actual}")]
    ChainBroken {
        event_id: String,
        expected: String,
        actual: String,
    },

    #[error("audit log file not found: {path}")]
    FileNotFound { path: String },

    #[error("HMAC key not available")]
    KeyNotAvailable,
}

impl From<AuditError> for ops_core::CoreError {
    fn from(err: AuditError) -> Self {
        Self::Audit {
            message: err.to_string(),
        }
    }
}
