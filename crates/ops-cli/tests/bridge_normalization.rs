//! Bridge input normalization integration tests.
//!
//! Exercises the Telegram processing pipeline end-to-end: message
//! creation, identity resolution, invisible character stripping, and
//! ANSI escape removal from session output.

use assert_matches::assert_matches;

use ops_bridge::error::BridgeError;
use ops_bridge::identity::default_config;
use ops_bridge::telegram::{TelegramMessage, TelegramUpdate, process_telegram_update};
use ops_core::origin::ActionOrigin;
use ops_policy::normalize::{normalize_text, strip_ansi};

fn make_update(user_id: &str, text: &str) -> TelegramUpdate {
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

// ------------------------------------------------------------------
// Telegram pipeline integration
// ------------------------------------------------------------------

#[test]
fn telegram_message_with_zero_width_chars_is_normalized() {
    let config = default_config();
    // Zero-width spaces injected between characters.
    let update = make_update(
        "SEBASTIAN_TG_ID",
        "/sta\u{200B}tu\u{200C}s",
    );

    let result = process_telegram_update(&update, &config)
        .expect("processing should succeed")
        .expect("should have a message");

    assert_eq!(result.text, "/status");
    assert!(result.is_command);
    assert_matches!(result.origin, ActionOrigin::BridgeTelegram { .. });
}

#[test]
fn telegram_message_with_directional_overrides_is_cleaned() {
    let config = default_config();
    let update = make_update(
        "SEBASTIAN_TG_ID",
        "check \u{202E}sessions",
    );

    let result = process_telegram_update(&update, &config)
        .expect("processing should succeed")
        .expect("should have a message");

    assert_eq!(result.text, "check sessions");
    assert!(!result.text.contains('\u{202E}'));
}

#[test]
fn telegram_message_with_tag_characters_is_cleaned() {
    let config = default_config();
    let update = make_update(
        "SEBASTIAN_TG_ID",
        "hello\u{E0001}\u{E0065}\u{E006E} world",
    );

    let result = process_telegram_update(&update, &config)
        .expect("processing should succeed")
        .expect("should have a message");

    assert_eq!(result.text, "hello world");
}

#[test]
fn telegram_unknown_sender_is_rejected() {
    let config = default_config();
    let update = make_update("UNKNOWN_ATTACKER", "give me access");

    let err = process_telegram_update(&update, &config)
        .expect_err("unknown sender should be rejected");

    assert_matches!(err, BridgeError::UnknownSender { .. });
}

#[test]
fn telegram_empty_update_returns_none() {
    let config = default_config();
    let update = TelegramUpdate {
        update_id: 1,
        message: None,
    };

    let result = process_telegram_update(&update, &config)
        .expect("processing should succeed");

    assert!(result.is_none());
}

// ------------------------------------------------------------------
// ANSI stripping (session output pipeline)
// ------------------------------------------------------------------

#[test]
fn ansi_in_session_output_is_stripped() {
    let tmux_output = "\x1b[?2004h\x1b[1m$ claude\x1b[0m\n\x1b[32m✓\x1b[0m Ready";
    let clean = strip_ansi(tmux_output);

    assert!(!clean.contains('\x1b'), "should not contain escape bytes");
    assert!(clean.contains("Ready"), "should preserve 'Ready'");
    assert!(clean.contains("claude"), "should preserve 'claude'");
}

#[test]
fn ansi_complex_tmux_output_is_cleaned() {
    // Real-world tmux pane capture with multiple escape types.
    let raw = concat!(
        "\x1b]0;tmux session\x07",  // OSC title
        "\x1b[?1049h",               // alternate screen buffer
        "\x1b[1;32mRunning\x1b[0m ", // bold green "Running"
        "\x1b[36m3 sessions\x1b[0m", // cyan "3 sessions"
        "\n\x1b[?1049l",             // restore screen buffer
    );
    let clean = strip_ansi(raw);

    assert!(!clean.contains('\x1b'));
    assert!(clean.contains("Running"));
    assert!(clean.contains("3 sessions"));
}

// ------------------------------------------------------------------
// Normalization edge cases
// ------------------------------------------------------------------

#[test]
fn normalization_preserves_legitimate_unicode() {
    let input = "Deploy to staging? y/n";
    let result = normalize_text(input);

    assert_eq!(result.cleaned, input);
    assert_eq!(result.stripped_count, 0);
    assert!(result.categories.is_empty());
}

#[test]
fn normalization_strips_multiple_attack_vectors_at_once() {
    // Combine zero-width, BOM, directional override, and control char.
    let input = "\u{FEFF}\u{200B}/stat\u{202E}us\x00";
    let result = normalize_text(input);

    assert_eq!(result.cleaned, "/status");
    assert_eq!(result.stripped_count, 4);
    assert!(result.categories.contains(&"zero-width".to_owned()));
    assert!(result.categories.contains(&"directional-override".to_owned()));
    assert!(result.categories.contains(&"control-character".to_owned()));
}

#[test]
fn normalization_detects_homoglyph_attack() {
    // "password" with Cyrillic 'a' (U+0430) instead of Latin 'a'.
    let input = "p\u{0430}ssword";
    let result = normalize_text(input);

    // Text is preserved but flagged.
    assert_eq!(result.cleaned, input);
    assert!(result.categories.contains(&"mixed-script".to_owned()));
}
