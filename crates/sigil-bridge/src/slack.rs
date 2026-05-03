//! Slack adapter types and event processing.
//!
//! Defines a simplified Slack event type (Socket Mode envelope) and the
//! processing pipeline: filter event type, verify sender, normalize
//! text, size-check, detect commands, and emit a [`BridgeMessage`].

use sigil_core::origin::ActionOrigin;
use sigil_core::protocol::{BridgeMessage, ReplyContext};

use crate::error::BridgeError;
use crate::identity::{IdentityConfig, resolve_identity};

/// Maximum message size in bytes (32 KB).
const MAX_MESSAGE_BYTES: usize = 32 * 1024;

/// A Slack event (simplified Socket Mode envelope).
#[derive(Clone, Debug, Default)]
pub struct SlackEvent {
    pub event_type: String,
    pub user: String,
    pub channel: String,
    pub text: String,
    pub ts: String,
    /// `bot_id` from the Slack event payload. When set, the message
    /// was authored by a bot and must be dropped to prevent self-loop
    /// (R3 in `docs/design/bridge-routing.md`).
    pub bot_id: Option<String>,
    /// `subtype` from the Slack event payload. Slack uses
    /// `"bot_message"` for messages posted by integrations even when
    /// `bot_id` is absent on the outer event.
    pub subtype: Option<String>,
}

/// Process a Slack event into a `BridgeMessage`.
///
/// Only `"message"` events are handled. Returns `Ok(None)` for all
/// other event types (e.g., `reaction_added`, `app_mention`) and for
/// any bot-authored message (`bot_id` set or `subtype == "bot_message"`).
///
/// The bot-event filter fires before allowlist resolution so a bot
/// impersonating an allowlisted user is dropped without burning quota.
///
/// # Errors
///
/// - `BridgeError::UnknownSender` if the user ID is not in the allowlist.
/// - `BridgeError::MessageTooLarge` if the normalized text exceeds 32 KB.
pub fn process_slack_event(
    event: &SlackEvent,
    config: &IdentityConfig,
) -> Result<Option<BridgeMessage>, BridgeError> {
    // Only handle "message" events.
    if event.event_type != "message" {
        return Ok(None);
    }

    // Drop bot-authored messages before allowlist resolution.
    if event.bot_id.is_some() || event.subtype.as_deref() == Some("bot_message") {
        tracing::debug!(
            bot_id = ?event.bot_id,
            subtype = ?event.subtype,
            "slack: dropping bot-authored event"
        );
        return Ok(None);
    }

    // Verify sender is in allowlist.
    let origin = ActionOrigin::BridgeSlack {
        user_id: event.user.clone(),
        channel_id: event.channel.clone(),
    };
    let _user = resolve_identity(config, &origin)?;

    // Normalize text (strip invisible chars).
    let normalized = sigil_policy::normalize::normalize_text(&event.text);
    let text = normalized.cleaned;

    if normalized.stripped_count > 0 {
        tracing::debug!(
            stripped = normalized.stripped_count,
            categories = ?normalized.categories,
            "slack: stripped invisible characters"
        );
    }

    // Size check.
    let size = text.len();
    if size > MAX_MESSAGE_BYTES {
        return Err(BridgeError::MessageTooLarge {
            size,
            max: MAX_MESSAGE_BYTES,
        });
    }

    // Detect commands (Slack slash commands start with /).
    let is_command = text.starts_with('/');

    Ok(Some(BridgeMessage {
        origin,
        text,
        target_session: None,
        is_command,
        reply_context: ReplyContext {
            chat_id: None,
            channel_id: Some(event.channel.clone()),
        },
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::identity::default_config;

    fn make_event(user: &str, text: &str, event_type: &str) -> SlackEvent {
        SlackEvent {
            event_type: event_type.into(),
            user: user.into(),
            channel: "C_GENERAL".into(),
            text: text.into(),
            ts: "1700000000.000100".into(),
            bot_id: None,
            subtype: None,
        }
    }

    #[test]
    fn valid_message_event_produces_bridge_message() {
        let config = default_config();
        let event = make_event("SEBASTIAN_SLACK_ID", "hello from slack", "message");
        let result = process_slack_event(&event, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert_eq!(result.text, "hello from slack");
        assert!(!result.is_command);
        assert!(matches!(result.origin, ActionOrigin::BridgeSlack { .. }));
    }

    #[test]
    fn non_message_event_returns_none() {
        let config = default_config();
        let event = make_event("SEBASTIAN_SLACK_ID", "thumbs up", "reaction_added");
        let result = process_slack_event(&event, &config).expect("should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn unknown_sender_rejected() {
        let config = default_config();
        let event = make_event("UNKNOWN_SLACK_USER", "hi", "message");
        let err = process_slack_event(&event, &config).expect_err("should fail");
        assert!(matches!(err, BridgeError::UnknownSender { .. }));
    }

    #[test]
    fn command_detection_works() {
        let config = default_config();
        let event = make_event("PAUL_SLACK_ID", "/status", "message");
        let result = process_slack_event(&event, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert!(result.is_command);
    }

    #[test]
    fn oversized_slack_message_is_rejected() {
        let config = default_config();
        let huge = "x".repeat(MAX_MESSAGE_BYTES + 1);
        let event = make_event("SEBASTIAN_SLACK_ID", &huge, "message");
        let err = process_slack_event(&event, &config).expect_err("should fail");
        assert!(matches!(err, BridgeError::MessageTooLarge { .. }));
    }

    #[test]
    fn input_normalization_strips_invisible_chars() {
        let config = default_config();
        let event = make_event("PAUL_SLACK_ID", "hel\u{200B}lo", "message");
        let result = process_slack_event(&event, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert_eq!(result.text, "hello");
    }

    #[test]
    fn bot_id_drops_event_before_allowlist() {
        let config = default_config();
        // Unknown sender + bot_id set: if the bot filter fires first
        // the event is dropped; if allowlist runs first we'd see
        // `UnknownSender`. `Ok(None)` proves ordering.
        let mut event = make_event("UNKNOWN_BOT_USER", "loop bait", "message");
        event.bot_id = Some("B0123456".into());
        let result = process_slack_event(&event, &config).expect("filter should swallow");
        assert!(result.is_none());
    }

    #[test]
    fn subtype_bot_message_drops_event_before_allowlist() {
        let config = default_config();
        let mut event = make_event("UNKNOWN_BOT_USER", "loop bait", "message");
        event.subtype = Some("bot_message".into());
        let result = process_slack_event(&event, &config).expect("filter should swallow");
        assert!(result.is_none());
    }

    #[test]
    fn other_subtypes_still_processed() {
        // Subtypes such as `me_message` are user-authored and must
        // continue to flow.
        let config = default_config();
        let mut event = make_event("PAUL_SLACK_ID", "hello", "message");
        event.subtype = Some("me_message".into());
        let result = process_slack_event(&event, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert_eq!(result.text, "hello");
    }
}
