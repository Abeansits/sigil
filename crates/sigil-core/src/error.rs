use crate::id::SessionId;

/// Errors from core operations.
///
/// Each higher-level crate defines its own error enum that wraps these
/// or adds domain-specific variants. Library crates use `thiserror`,
/// application crates (`sigil-cli`) use `anyhow`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    #[error("session not found: {id}")]
    SessionNotFound { id: SessionId },

    #[error("session already exists: {title}")]
    SessionAlreadyExists { title: String },

    #[error("action denied: {reason}")]
    ActionDenied { reason: String },

    #[error("approval required for {description}")]
    ApprovalRequired { description: String },

    #[error("approval timed out for request {request_id}")]
    ApprovalTimeout { request_id: crate::id::RequestId },

    #[error("invalid configuration: {message}")]
    InvalidConfig { message: String },

    #[error("runtime error: {message}")]
    Runtime { message: String },

    #[error("bridge error: {message}")]
    Bridge { message: String },

    #[error("audit error: {message}")]
    Audit { message: String },

    #[error("store error: {message}")]
    Store { message: String },
}
