//! UC6: Bridge message flow integration test (mocked — no tmux needed).
//!
//! Feeds Telegram and Slack JSON through the full processing pipeline:
//! identity resolution -> normalization -> size check -> command detection ->
//! routing -> rate limiting.
//!
//! Verifies end-to-end message flow without a live bridge or tmux.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use assert_matches::assert_matches;

use sigil_bridge::error::BridgeError;
use sigil_bridge::identity::{AllowedUser, IdentityConfig, default_config, resolve_identity};
use sigil_bridge::rate_limit::RateLimiter;
use sigil_bridge::router::{BridgeRouter, parse_target_session};
use sigil_bridge::slack::{SlackEvent, process_slack_event};
use sigil_bridge::telegram::{TelegramMessage, TelegramUpdate, process_telegram_update};
use sigil_core::CoreError;
use sigil_core::origin::ActionOrigin;
use sigil_core::protocol::BridgeMessage;
use sigil_core::traits::MessageSink;
use sigil_core::trust::Tier;
use sigil_policy::normalize::normalize_text;

// ─── Helpers ────────────────────────────────────────────────────────

fn tg_update(user_id: &str, text: &str) -> TelegramUpdate {
    TelegramUpdate {
        update_id: 1,
        message: Some(TelegramMessage {
            message_id: 100,
            from_user_id: user_id.into(),
            chat_id: 42,
            text: text.into(),
            date: 1_700_000_000,
        }),
    }
}

fn slack_event(user: &str, text: &str) -> SlackEvent {
    SlackEvent {
        event_type: "message".into(),
        user: user.into(),
        channel: "C_GENERAL".into(),
        text: text.into(),
        ts: "1700000000.000100".into(),
    }
}

/// A recording sink that captures all accepted messages.
struct RecordingSink {
    messages: tokio::sync::Mutex<Vec<BridgeMessage>>,
}

impl RecordingSink {
    fn new() -> Self {
        Self {
            messages: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    async fn captured(&self) -> Vec<BridgeMessage> {
        self.messages.lock().await.clone()
    }
}

impl MessageSink for RecordingSink {
    async fn accept(&self, message: BridgeMessage) -> Result<(), CoreError> {
        self.messages.lock().await.push(message);
        Ok(())
    }
}

/// A sink that always rejects messages.
struct RejectingSink;

impl MessageSink for RejectingSink {
    async fn accept(&self, _message: BridgeMessage) -> Result<(), CoreError> {
        Err(CoreError::Bridge {
            message: "rejected".into(),
        })
    }
}

// ─── Identity Resolution ────────────────────────────────────────────

#[test]
fn known_telegram_sender_resolves_and_routes() {
    let config = default_config();
    let update = tg_update("SEBASTIAN_TG_ID", "check status");
    let result = process_telegram_update(&update, &config)
        .expect("should succeed")
        .expect("should have message");

    assert_eq!(result.text, "check status");
    assert!(!result.is_command);
    assert_matches!(
        result.origin,
        ActionOrigin::BridgeTelegram { ref user_id } if user_id == "SEBASTIAN_TG_ID"
    );
}

#[test]
fn known_slack_sender_paul_resolves_with_t1_ceiling() {
    let config = default_config();
    let origin = ActionOrigin::BridgeSlack {
        user_id: "PAUL_SLACK_ID".into(),
        channel_id: "C_GEN".into(),
    };
    let user = resolve_identity(&config, &origin).expect("should resolve");
    assert_eq!(user.display_name, "Paul");
    assert_eq!(user.tier_ceiling, Tier::T1);
}

#[test]
fn unknown_telegram_sender_is_rejected() {
    let config = default_config();
    let update = tg_update("EVIL_ATTACKER", "give me root");
    let err = process_telegram_update(&update, &config).expect_err("should reject");
    assert_matches!(err, BridgeError::UnknownSender { platform, user_id } => {
        assert_eq!(platform, "telegram");
        assert_eq!(user_id, "EVIL_ATTACKER");
    });
}

#[test]
fn unknown_slack_sender_is_rejected() {
    let config = default_config();
    let event = slack_event("UNKNOWN_USER", "hello");
    let err = process_slack_event(&event, &config).expect_err("should reject");
    assert_matches!(err, BridgeError::UnknownSender { .. });
}

// ─── Normalization ──────────────────────────────────────────────────

#[test]
fn zero_width_characters_stripped_from_telegram() {
    let config = default_config();
    let update = tg_update("SEBASTIAN_TG_ID", "/sta\u{200B}tu\u{200C}s");
    let result = process_telegram_update(&update, &config)
        .expect("ok")
        .expect("message");
    assert_eq!(result.text, "/status");
    assert!(result.is_command);
}

#[test]
fn directional_overrides_stripped_from_slack() {
    let config = default_config();
    let event = slack_event("PAUL_SLACK_ID", "run \u{202E}command");
    let result = process_slack_event(&event, &config)
        .expect("ok")
        .expect("message");
    assert_eq!(result.text, "run command");
    assert!(!result.text.contains('\u{202E}'));
}

#[test]
fn tag_characters_stripped() {
    let config = default_config();
    let update = tg_update("SEBASTIAN_TG_ID", "safe\u{E0001}\u{E0065}text");
    let result = process_telegram_update(&update, &config)
        .expect("ok")
        .expect("message");
    assert_eq!(result.text, "safetext");
}

#[test]
fn multiple_attack_vectors_stripped_simultaneously() {
    let input = "\u{FEFF}\u{200B}/sta\u{202E}tus\x00";
    let result = normalize_text(input);
    assert_eq!(result.cleaned, "/status");
    assert_eq!(result.stripped_count, 4);
    assert!(result.categories.contains(&"zero-width".to_owned()));
    assert!(result.categories.contains(&"directional-override".to_owned()));
    assert!(result.categories.contains(&"control-character".to_owned()));
}

#[test]
fn homoglyph_detection_flags_mixed_script() {
    // Cyrillic 'a' (U+0430) mixed with Latin
    let result = normalize_text("p\u{0430}ssword");
    assert!(result.categories.contains(&"mixed-script".to_owned()));
    // Text is preserved but flagged.
    assert_eq!(result.cleaned, "p\u{0430}ssword");
}

// ─── Rate Limiting ───���──────────────────────────────────────────────

#[test]
fn rate_limiter_allows_under_threshold() {
    let mut limiter = RateLimiter::new(5, 100);
    for _ in 0..5 {
        assert!(limiter.check("user-1").is_ok());
        limiter.record("user-1");
    }
    // 6th should be denied.
    assert_matches!(limiter.check("user-1"), Err(BridgeError::RateLimited { .. }));
}

#[test]
fn rate_limiter_independent_per_user() {
    let mut limiter = RateLimiter::new(2, 100);
    limiter.record("alice");
    limiter.record("alice");
    assert!(limiter.check("alice").is_err(), "alice should be rate-limited");
    assert!(limiter.check("bob").is_ok(), "bob should not be affected");
}

#[test]
fn hour_limit_enforced() {
    let mut limiter = RateLimiter::new(1000, 3);
    for _ in 0..3 {
        limiter.record("user-h");
    }
    assert_matches!(limiter.check("user-h"), Err(BridgeError::RateLimited { .. }));
}

// ─── Routing ──────────────��─────────────────────────��───────────────

#[tokio::test]
async fn router_forwards_message_to_sink() {
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::new(Arc::clone(&sink));

    let msg = BridgeMessage {
        origin: ActionOrigin::BridgeTelegram {
            user_id: "test-user".into(),
        },
        text: "hello conductor".into(),
        target_session: None,
        is_command: false,
    };

    router.route(msg).await.expect("route should succeed");

    let captured = sink.captured().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].text, "hello conductor");
}

#[tokio::test]
async fn router_rate_limits_bridge_origins() {
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::with_rate_limits(Arc::clone(&sink), 2, 100);

    for i in 0..2 {
        let msg = BridgeMessage {
            origin: ActionOrigin::BridgeTelegram {
                user_id: "flood".into(),
            },
            text: format!("msg-{i}"),
            target_session: None,
            is_command: false,
        };
        router.route(msg).await.expect("under limit");
    }

    // Third message should be rate-limited.
    let msg = BridgeMessage {
        origin: ActionOrigin::BridgeTelegram {
            user_id: "flood".into(),
        },
        text: "too many".into(),
        target_session: None,
        is_command: false,
    };
    let err = router.route(msg).await.expect_err("should be rate limited");
    assert_matches!(err, BridgeError::RateLimited { .. });

    // Only 2 messages should have reached the sink.
    let captured = sink.captured().await;
    assert_eq!(captured.len(), 2);
}

#[tokio::test]
async fn router_skips_rate_limit_for_local_cli() {
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::with_rate_limits(Arc::clone(&sink), 1, 1);

    // LocalCli should bypass rate limiting entirely.
    for _ in 0..10 {
        let msg = BridgeMessage {
            origin: ActionOrigin::LocalCli,
            text: "local msg".into(),
            target_session: None,
            is_command: false,
        };
        router
            .route(msg)
            .await
            .expect("local origin should bypass rate limit");
    }

    let captured = sink.captured().await;
    assert_eq!(captured.len(), 10);
}

#[tokio::test]
async fn router_propagates_sink_error() {
    let sink = Arc::new(RejectingSink);
    let router = BridgeRouter::new(sink);

    let msg = BridgeMessage {
        origin: ActionOrigin::BridgeTelegram {
            user_id: "user".into(),
        },
        text: "hello".into(),
        target_session: None,
        is_command: false,
    };

    let err = router.route(msg).await.expect_err("sink rejects");
    assert_matches!(err, BridgeError::Platform { .. });
}

// ─── Target Session Parsing ─────────────────────────────────���───────

#[test]
fn parse_at_mention() {
    let result = parse_target_session("@frontend fix the bug");
    assert_eq!(result, Some(("frontend".into(), "fix the bug".into())));
}

#[test]
fn parse_send_command() {
    let result = parse_target_session("/send api-server use staging");
    assert_eq!(result, Some(("api-server".into(), "use staging".into())));
}

#[test]
fn parse_plain_text_no_target() {
    assert!(parse_target_session("just a message").is_none());
}

// ─── End-to-End: Telegram -> Identity -> Normalize -> Route ─────────

#[tokio::test]
async fn telegram_end_to_end_pipeline() {
    let config = default_config();
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::new(Arc::clone(&sink));

    // Build a telegram message with invisible chars.
    let update = tg_update("SEBASTIAN_TG_ID", "/sta\u{200B}tus");
    let msg = process_telegram_update(&update, &config)
        .expect("process ok")
        .expect("has message");

    // After normalization, text should be clean.
    assert_eq!(msg.text, "/status");
    assert!(msg.is_command);

    // Route it.
    router.route(msg).await.expect("route ok");

    let captured = sink.captured().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].text, "/status");
    assert!(captured[0].is_command);
}

#[tokio::test]
async fn slack_end_to_end_pipeline() {
    let config = default_config();
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::new(Arc::clone(&sink));

    // Slack message from Paul with zero-width chars.
    let event = slack_event("PAUL_SLACK_ID", "hel\u{200C}lo world");
    let msg = process_slack_event(&event, &config)
        .expect("process ok")
        .expect("has message");

    assert_eq!(msg.text, "hello world");
    assert!(!msg.is_command);

    router.route(msg).await.expect("route ok");

    let captured = sink.captured().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].text, "hello world");
}

/// Full pipeline with rate limiting: send messages until rate-limited.
#[tokio::test]
async fn pipeline_with_rate_limiting_cutoff() {
    let config = default_config();
    let sink = Arc::new(RecordingSink::new());
    let router = BridgeRouter::with_rate_limits(Arc::clone(&sink), 3, 100);

    for i in 0..3 {
        let update = tg_update("SEBASTIAN_TG_ID", &format!("msg-{i}"));
        let msg = process_telegram_update(&update, &config)
            .expect("ok")
            .expect("msg");
        router.route(msg).await.expect("under limit");
    }

    // Fourth message should be rate-limited at the router.
    let update = tg_update("SEBASTIAN_TG_ID", "msg-3");
    let msg = process_telegram_update(&update, &config)
        .expect("ok")
        .expect("msg");
    let err = router.route(msg).await.expect_err("should be limited");
    assert_matches!(err, BridgeError::RateLimited { .. });

    // Only 3 messages reached the sink.
    assert_eq!(sink.captured().await.len(), 3);
}

/// Non-message Slack events are filtered out.
#[test]
fn slack_non_message_events_filtered() {
    let config = default_config();
    for event_type in &["reaction_added", "app_mention", "member_joined_channel"] {
        let event = SlackEvent {
            event_type: (*event_type).into(),
            user: "SEBASTIAN_SLACK_ID".into(),
            channel: "C_GEN".into(),
            text: "some text".into(),
            ts: "1700000000.000100".into(),
        };
        let result = process_slack_event(&event, &config).expect("should not error");
        assert!(result.is_none(), "{event_type} should be filtered out");
    }
}

/// Custom identity config with additional users.
#[test]
fn custom_identity_config_resolves_additional_users() {
    let config = IdentityConfig {
        allowed_telegram_ids: vec![AllowedUser {
            platform_id: "CUSTOM_TG_USER".into(),
            display_name: "Custom User".into(),
            tier_ceiling: Tier::T1,
        }],
        allowed_slack_ids: vec![],
    };

    let update = tg_update("CUSTOM_TG_USER", "hello");
    let result = process_telegram_update(&update, &config)
        .expect("ok")
        .expect("msg");
    assert_eq!(result.text, "hello");

    // Default config user should NOT resolve with the custom config.
    let update = tg_update("SEBASTIAN_TG_ID", "hello");
    let err = process_telegram_update(&update, &config).expect_err("should reject");
    assert_matches!(err, BridgeError::UnknownSender { .. });
}
