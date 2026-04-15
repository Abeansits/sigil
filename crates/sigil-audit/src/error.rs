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

    #[error(
        "audit HMAC key not available: set SIGIL_AUDIT_KEY, install one in the macOS Keychain \
         (`sigil audit key generate`), or opt into the dev fallback with SIGIL_DEV_AUDIT_KEY=1"
    )]
    KeyNotAvailable,

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("random source error: {0}")]
    Random(String),

    #[error("SIGIL_AUDIT_KEY is set but invalid: {reason}")]
    InvalidEnvKey { reason: String },
}

impl From<AuditError> for sigil_core::CoreError {
    fn from(err: AuditError) -> Self {
        Self::Audit {
            message: err.to_string(),
        }
    }
}
