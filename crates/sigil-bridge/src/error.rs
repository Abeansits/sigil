use sigil_core::CoreError;

/// Errors from bridge operations.
///
/// Each variant captures enough context for diagnostics without
/// leaking sensitive data (user IDs are platform-scoped, not secrets).
///
/// **Invariant for `Platform`:** the `message` is pre-formatted at the
/// call site and is expected to be scrubbed before construction.
/// Never build it by hand from a raw `reqwest::Error` — its `Display`
/// embeds the request URL, and Telegram puts the bot token in that
/// path. Use [`BridgeError::from_reqwest`] instead; it centralises
/// the `.without_url()` call so a future site cannot regress.
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

impl BridgeError {
    /// Build a [`BridgeError::Platform`] from a [`reqwest::Error`] with
    /// the request URL stripped.
    ///
    /// Telegram embeds the bot token in the URL path, and Slack's
    /// Socket Mode WSS URL contains an ephemeral ticket — so
    /// `reqwest::Error`'s default `Display` leaks the secret into
    /// anything that logs the error. `.without_url()` is the canonical
    /// primitive to strip it; this helper makes that the only way to
    /// construct a `Platform` error from a network error, so new call
    /// sites cannot forget it.
    #[must_use]
    pub fn from_reqwest(context: &str, err: reqwest::Error) -> Self {
        Self::Platform {
            message: format!("{context}: {}", err.without_url()),
        }
    }
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
    #![allow(clippy::expect_used)]

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

    /// Contract test for the central scrub primitive. Any
    /// `reqwest::Error` carrying a URL must have that URL stripped
    /// before the error string is formatted, so tokens in URL paths
    /// (Telegram) and tickets in query strings (Slack Socket Mode
    /// WSS URLs) cannot reach logs. Applies regardless of call site.
    #[tokio::test]
    async fn from_reqwest_strips_url_containing_secret() {
        let secret = "LEAKED_IF_YOU_SEE_THIS";
        let url = format!("http://127.0.0.1:1/path?token={secret}");

        // Build a real reqwest::Error by hitting a closed port.
        let req_err = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("client builds")
            .get(&url)
            .send()
            .await
            .expect_err("port 1 connection should fail");

        let bridge_err = BridgeError::from_reqwest("test context", req_err);
        let msg = bridge_err.to_string();

        assert!(
            msg.contains("test context"),
            "context prefix must be preserved: {msg}"
        );
        assert!(
            !msg.contains(secret),
            "URL-embedded secret must not survive: {msg}"
        );
        assert!(
            !msg.contains("127.0.0.1"),
            "URL host must not survive: {msg}"
        );
    }
}
