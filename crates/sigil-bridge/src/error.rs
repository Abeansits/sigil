use sigil_core::CoreError;

/// Errors from bridge operations.
///
/// Each variant captures enough context for diagnostics without
/// leaking sensitive data (user IDs are platform-scoped, not secrets).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("unknown sender: {platform} user {user_id}")]
    UnknownSender { platform: String, user_id: String },

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("rate limited: {user_id}")]
    RateLimited { user_id: String },

    #[error("platform error: {message}")]
    Platform { message: String },
}

impl From<BridgeError> for CoreError {
    fn from(err: BridgeError) -> Self {
        CoreError::Bridge {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_sender_displays_platform_and_id() {
        let err = BridgeError::UnknownSender {
            platform: "telegram".into(),
            user_id: "12345".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("telegram"));
        assert!(msg.contains("12345"));
    }

    #[test]
    fn bridge_error_converts_to_core_error() {
        let bridge_err = BridgeError::Platform {
            message: "connection lost".into(),
        };
        let core_err: CoreError = bridge_err.into();
        let msg = core_err.to_string();
        assert!(msg.contains("connection lost"));
    }
}
