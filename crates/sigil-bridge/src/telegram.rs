//! Telegram adapter types and message processing.
//!
//! Defines simplified Telegram update/message types and the processing
//! pipeline: extract message, verify sender, normalize text, size-check,
//! detect commands, and emit a [`BridgeMessage`].

use sigil_core::origin::ActionOrigin;
use sigil_core::protocol::{BridgeMessage, ReplyContext};

use crate::error::BridgeError;
use crate::identity::{IdentityConfig, resolve_identity};

/// Maximum message size in bytes (32 KB).
const MAX_MESSAGE_BYTES: usize = 32 * 1024;

/// A Telegram update (simplified — only the fields we need).
#[derive(Clone, Debug)]
pub struct TelegramUpdate {
    pub update_id: i64,
    pub message: Option<TelegramMessage>,
}

/// A Telegram message (simplified).
#[derive(Clone, Debug, Default)]
pub struct TelegramMessage {
    pub message_id: i64,
    pub from_user_id: String,
    pub chat_id: i64,
    pub text: String,
    pub date: i64,
    /// Mirrors `message.from.is_bot` from the Telegram Bot API
    /// (<https://core.telegram.org/bots/api#user>). Bot-authored
    /// messages are dropped at ingest to prevent self-loop (R3 in
    /// `docs/design/bridge-routing.md`).
    pub from_is_bot: bool,
}

/// Process a Telegram update into a `BridgeMessage`.
///
/// Returns `Ok(None)` if the update contains no message (e.g., an
/// `edited_message` or `callback_query` we don't handle yet).
///
/// # Errors
///
/// - `BridgeError::UnknownSender` if the user ID is not in the allowlist.
/// - `BridgeError::MessageTooLarge` if the normalized text exceeds 32 KB.
pub fn process_telegram_update(
    update: &TelegramUpdate,
    config: &IdentityConfig,
) -> Result<Option<BridgeMessage>, BridgeError> {
    let Some(msg) = &update.message else {
        return Ok(None);
    };

    // Drop bot-authored messages before allowlist resolution.
    if msg.from_is_bot {
        tracing::debug!(
            from_user_id = %msg.from_user_id,
            "telegram: dropping bot-authored message"
        );
        return Ok(None);
    }

    // Verify sender is in allowlist.
    let origin = ActionOrigin::BridgeTelegram {
        user_id: msg.from_user_id.clone(),
    };
    let _user = resolve_identity(config, &origin)?;

    // Normalize text (strip invisible chars).
    let normalized = sigil_policy::normalize::normalize_text(&msg.text);
    let text = normalized.cleaned;

    if normalized.stripped_count > 0 {
        tracing::debug!(
            stripped = normalized.stripped_count,
            categories = ?normalized.categories,
            "telegram: stripped invisible characters"
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

    // Detect commands (Telegram commands start with /).
    let is_command = text.starts_with('/');

    Ok(Some(BridgeMessage {
        origin,
        text,
        target_session: None,
        is_command,
        reply_context: ReplyContext {
            chat_id: Some(msg.chat_id),
            channel_id: None,
        },
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::identity::default_config;

    fn make_update(user_id: &str, text: &str) -> TelegramUpdate {
        TelegramUpdate {
            update_id: 1,
            message: Some(TelegramMessage {
                message_id: 100,
                from_user_id: user_id.into(),
                chat_id: 42,
                text: text.into(),
                date: 1_700_000_000,
                from_is_bot: false,
            }),
        }
    }

    #[test]
    fn valid_message_produces_bridge_message() {
        let config = default_config();
        let update = make_update("7279215778", "hello conductor");
        let result = process_telegram_update(&update, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert_eq!(result.text, "hello conductor");
        assert!(!result.is_command);
        assert!(matches!(result.origin, ActionOrigin::BridgeTelegram { .. }));
    }

    #[test]
    fn unknown_sender_is_rejected() {
        let config = default_config();
        let update = make_update("UNKNOWN_USER", "hi");
        let err = process_telegram_update(&update, &config).expect_err("should fail");
        assert!(matches!(err, BridgeError::UnknownSender { .. }));
    }

    #[test]
    fn empty_update_returns_none() {
        let config = default_config();
        let update = TelegramUpdate {
            update_id: 1,
            message: None,
        };
        let result = process_telegram_update(&update, &config).expect("should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn oversized_message_is_rejected() {
        let config = default_config();
        let huge_text = "x".repeat(MAX_MESSAGE_BYTES + 1);
        let update = make_update("7279215778", &huge_text);
        let err = process_telegram_update(&update, &config).expect_err("should fail");
        assert!(matches!(err, BridgeError::MessageTooLarge { .. }));
    }

    #[test]
    fn command_detection_works() {
        let config = default_config();
        let update = make_update("7279215778", "/status");
        let result = process_telegram_update(&update, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert!(result.is_command);
    }

    #[test]
    fn input_normalization_strips_invisible_chars() {
        let config = default_config();
        // Zero-width space injected into "hello"
        let update = make_update("7279215778", "hel\u{200B}lo");
        let result = process_telegram_update(&update, &config)
            .expect("should succeed")
            .expect("should have a message");
        assert_eq!(result.text, "hello");
    }

    #[test]
    fn from_is_bot_drops_message_before_allowlist() {
        let config = default_config();
        // Unknown sender + is_bot: filter must drop before
        // allowlist resolution would otherwise raise
        // `UnknownSender`.
        let mut update = make_update("UNKNOWN_BOT_USER", "loop bait");
        if let Some(m) = update.message.as_mut() {
            m.from_is_bot = true;
        }
        let result = process_telegram_update(&update, &config).expect("filter should swallow");
        assert!(result.is_none());
    }
}
