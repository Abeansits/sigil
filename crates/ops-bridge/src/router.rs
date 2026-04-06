//! Message routing from bridge adapters to the conductor.
//!
//! The [`BridgeRouter`] accepts normalized [`BridgeMessage`]s and
//! forwards them to a [`MessageSink`] (implemented by the conductor).
//! It also provides utilities for parsing target session references
//! from message text.

use std::sync::Arc;

use ops_core::protocol::BridgeMessage;
use ops_core::traits::MessageSink;

use crate::error::BridgeError;

/// Routes bridge messages to the conductor via a [`MessageSink`].
///
/// Generic over the sink implementation because `MessageSink` uses
/// `impl Future` in return position (not dyn-compatible). The `Arc`
/// allows sharing across async tasks.
pub struct BridgeRouter<S: MessageSink> {
    sink: Arc<S>,
}

impl<S: MessageSink> BridgeRouter<S> {
    /// Create a new router that forwards messages to the given sink.
    pub fn new(sink: Arc<S>) -> Self {
        Self { sink }
    }

    /// Forward a bridge message to the conductor.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` if the sink rejects the message.
    pub async fn route(&self, msg: BridgeMessage) -> Result<(), BridgeError> {
        self.sink
            .accept(msg)
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("sink rejected message: {e}"),
            })
    }
}

/// Parse a target session reference from message text.
///
/// Recognizes two patterns:
/// - `@session-name rest of message` -- returns `("session-name", "rest
///   of message")`
/// - `/send session-name rest of message` -- returns `("session-name",
///   "rest of message")`
///
/// Returns `None` if neither pattern matches.
#[must_use]
pub fn parse_target_session(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();

    // Pattern 1: @session-name message
    if let Some(rest) = trimmed.strip_prefix('@') {
        let mut parts = rest.splitn(2, ' ');
        if let Some(name) = parts.next() {
            if !name.is_empty() {
                let message = parts.next().unwrap_or_default().trim().to_string();
                return Some((name.to_string(), message));
            }
        }
    }

    // Pattern 2: /send session-name message
    if let Some(rest) = trimmed.strip_prefix("/send ") {
        let rest = rest.trim_start();
        let mut parts = rest.splitn(2, ' ');
        if let Some(name) = parts.next() {
            if !name.is_empty() {
                let message = parts.next().unwrap_or_default().trim().to_string();
                return Some((name.to_string(), message));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use ops_core::CoreError;

    use super::*;

    // A fake MessageSink for testing the router.
    struct FakeSink {
        should_fail: bool,
    }

    impl MessageSink for FakeSink {
        async fn accept(&self, _message: BridgeMessage) -> Result<(), CoreError> {
            if self.should_fail {
                return Err(CoreError::Bridge {
                    message: "test failure".into(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn parse_at_mention_extracts_session_and_message() {
        let result = parse_target_session("@frontend fix the login bug");
        assert_eq!(
            result,
            Some(("frontend".into(), "fix the login bug".into()))
        );
    }

    #[test]
    fn parse_at_mention_with_no_message() {
        let result = parse_target_session("@backend");
        assert_eq!(result, Some(("backend".into(), String::new())));
    }

    #[test]
    fn parse_send_command_extracts_session_and_message() {
        let result = parse_target_session("/send api-server restart the tests");
        assert_eq!(
            result,
            Some(("api-server".into(), "restart the tests".into()))
        );
    }

    #[test]
    fn parse_plain_text_returns_none() {
        let result = parse_target_session("just a regular message");
        assert!(result.is_none());
    }

    #[test]
    fn parse_slash_command_not_send_returns_none() {
        let result = parse_target_session("/status");
        assert!(result.is_none());
    }

    #[test]
    fn parse_empty_at_mention_returns_none() {
        let result = parse_target_session("@ ");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn route_forwards_to_sink() {
        let sink = Arc::new(FakeSink { should_fail: false });
        let router = BridgeRouter::new(sink);
        let msg = BridgeMessage {
            origin: ops_core::ActionOrigin::BridgeTelegram {
                user_id: "test".into(),
            },
            text: "hello".into(),
            target_session: None,
            is_command: false,
        };
        router.route(msg).await.expect("should succeed");
    }

    #[tokio::test]
    async fn route_returns_error_when_sink_fails() {
        let sink = Arc::new(FakeSink { should_fail: true });
        let router = BridgeRouter::new(sink);
        let msg = BridgeMessage {
            origin: ops_core::ActionOrigin::BridgeTelegram {
                user_id: "test".into(),
            },
            text: "hello".into(),
            target_session: None,
            is_command: false,
        };
        let err = router.route(msg).await.expect_err("should fail");
        assert!(matches!(err, BridgeError::Platform { .. }));
    }
}
