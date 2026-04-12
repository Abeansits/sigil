//! Memory-specific error types.

/// Errors from memory operations (episodic capture and consolidation).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemoryError {
    /// Failed to write to the episode log.
    #[error("failed to write episode")]
    Write(#[source] std::io::Error),

    /// Failed to read the episode log.
    #[error("failed to read episode log")]
    Read(#[source] std::io::Error),

    /// Episode serialization or deserialization failure.
    #[error("episode serialization error")]
    Serialize(#[from] serde_json::Error),

    /// Consolidation rule violation or internal error.
    #[error("consolidation failed: {message}")]
    Consolidation {
        /// What went wrong during consolidation.
        message: String,
    },

    /// Invalid memory configuration.
    #[error("invalid memory config: {message}")]
    InvalidConfig {
        /// Description of the configuration error.
        message: String,
    },
}

impl From<MemoryError> for sigil_core::CoreError {
    fn from(err: MemoryError) -> Self {
        Self::Memory {
            message: err.to_string(),
        }
    }
}
