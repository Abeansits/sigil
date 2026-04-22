//! Telegram Bot API long-polling client.
//!
//! Wraps `reqwest` to call `getUpdates` (long-poll) and `sendMessage`,
//! converting raw Telegram JSON into the public [`TelegramUpdate`] type.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::error::BridgeError;
use crate::telegram::{TelegramMessage, TelegramUpdate};

/// HTTP timeout for the reqwest client. Telegram long-poll uses
/// `timeout=30`, so the HTTP timeout must exceed that.
const HTTP_TIMEOUT: Duration = Duration::from_secs(90);

/// Seconds to pass as `timeout` to the Telegram `getUpdates` API.
const POLL_TIMEOUT_SECS: u64 = 30;

/// Telegram Bot API long-polling client.
pub struct TelegramClient {
    http: reqwest::Client,
    base_url: String,
    last_update_id: i64,
}

// ── Telegram API response types (private) ─────────────────────────

#[derive(Deserialize)]
struct TgResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct TgUpdate {
    update_id: i64,
    message: Option<TgMessage>,
}

#[derive(Deserialize)]
struct TgMessage {
    message_id: i64,
    from: Option<TgUser>,
    chat: TgChat,
    text: Option<String>,
    date: i64,
}

#[derive(Deserialize)]
struct TgUser {
    id: i64,
}

#[derive(Deserialize)]
struct TgChat {
    id: i64,
}

// ── Conversion ────────────────────────────────────────────────────

/// Convert a raw Telegram update into the public type.
fn tg_update_to_public(raw: TgUpdate) -> TelegramUpdate {
    let message = raw.message.map(|m| {
        let from_user_id = m.from.map(|u| u.id.to_string()).unwrap_or_default();

        TelegramMessage {
            message_id: m.message_id,
            from_user_id,
            chat_id: m.chat.id,
            text: m.text.unwrap_or_default(),
            date: m.date,
        }
    });

    TelegramUpdate {
        update_id: raw.update_id,
        message,
    }
}

// ── Client impl ───────────────────────────────────────────────────

impl TelegramClient {
    /// Create a new client from a bot token.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` if the HTTP client cannot be
    /// built (e.g., TLS back-end unavailable).
    pub fn new(token: &SecretString) -> Result<Self, BridgeError> {
        let base_url = format!("https://api.telegram.org/bot{}", token.expose_secret());

        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| BridgeError::Platform {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(Self {
            http,
            base_url,
            last_update_id: 0,
        })
    }

    /// Long-poll for new updates.
    ///
    /// Calls `getUpdates` with an offset one past the last seen
    /// update, blocking for up to [`POLL_TIMEOUT_SECS`] seconds on
    /// the server side.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` on network or API errors.
    pub async fn poll(&mut self) -> Result<Vec<TelegramUpdate>, BridgeError> {
        let url = format!(
            "{}/getUpdates?offset={}&timeout={POLL_TIMEOUT_SECS}",
            self.base_url,
            self.last_update_id + 1,
        );

        let resp: TgResponse<Vec<TgUpdate>> = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Platform {
                // `reqwest::Error`'s Display impl embeds the request URL —
                // and for Telegram, the URL path contains the bot token. Use
                // `.without_url()` to strip the URL before formatting so
                // transient network errors don't leak the secret into logs.
                message: format!("getUpdates request failed: {}", e.without_url()),
            })?
            .json()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("getUpdates parse failed: {}", e.without_url()),
            })?;

        if !resp.ok {
            let desc = resp.description.unwrap_or_default();
            return Err(BridgeError::Platform {
                message: format!("Telegram API error: {desc}"),
            });
        }

        let raw_updates = resp.result.unwrap_or_default();

        // Track the highest update_id we've seen.
        for u in &raw_updates {
            if u.update_id > self.last_update_id {
                self.last_update_id = u.update_id;
            }
        }

        Ok(raw_updates.into_iter().map(tg_update_to_public).collect())
    }

    /// Send a text message to a chat.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` on network or API errors.
    pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<(), BridgeError> {
        let url = format!("{}/sendMessage", self.base_url);

        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
        });

        let resp: TgResponse<serde_json::Value> = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("sendMessage request failed: {}", e.without_url()),
            })?
            .json()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("sendMessage parse failed: {}", e.without_url()),
            })?;

        if !resp.ok {
            let desc = resp.description.unwrap_or_default();
            return Err(BridgeError::Platform {
                message: format!("sendMessage API error: {desc}"),
            });
        }

        Ok(())
    }

    /// Return the current `last_update_id` (useful for testing).
    #[cfg(test)]
    fn last_update_id(&self) -> i64 {
        self.last_update_id
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn new_builds_correct_base_url() {
        let token = SecretString::from("123456:ABC-DEF");
        let client = TelegramClient::new(&token).expect("client should build");
        assert_eq!(
            client.base_url,
            "https://api.telegram.org/bot123456:ABC-DEF"
        );
    }

    #[test]
    fn initial_last_update_id_is_zero() {
        let token = SecretString::from("test-token");
        let client = TelegramClient::new(&token).expect("client should build");
        assert_eq!(client.last_update_id(), 0);
    }

    #[test]
    fn tg_update_conversion_preserves_fields() {
        let raw = TgUpdate {
            update_id: 42,
            message: Some(TgMessage {
                message_id: 100,
                from: Some(TgUser { id: 999 }),
                chat: TgChat { id: 555 },
                text: Some("hello".into()),
                date: 1_700_000_000,
            }),
        };

        let public = tg_update_to_public(raw);
        assert_eq!(public.update_id, 42);
        let msg = public.message.expect("should have message");
        assert_eq!(msg.message_id, 100);
        assert_eq!(msg.from_user_id, "999");
        assert_eq!(msg.chat_id, 555);
        assert_eq!(msg.text, "hello");
        assert_eq!(msg.date, 1_700_000_000);
    }

    #[test]
    fn tg_update_without_message_converts_to_none() {
        let raw = TgUpdate {
            update_id: 1,
            message: None,
        };
        let public = tg_update_to_public(raw);
        assert!(public.message.is_none());
    }

    #[test]
    fn tg_update_without_from_user_defaults_to_empty() {
        let raw = TgUpdate {
            update_id: 1,
            message: Some(TgMessage {
                message_id: 1,
                from: None,
                chat: TgChat { id: 1 },
                text: Some("anon".into()),
                date: 0,
            }),
        };

        let public = tg_update_to_public(raw);
        let msg = public.message.expect("should have message");
        assert_eq!(msg.from_user_id, "");
    }

    #[test]
    fn tg_update_without_text_defaults_to_empty() {
        let raw = TgUpdate {
            update_id: 1,
            message: Some(TgMessage {
                message_id: 1,
                from: Some(TgUser { id: 1 }),
                chat: TgChat { id: 1 },
                text: None,
                date: 0,
            }),
        };

        let public = tg_update_to_public(raw);
        let msg = public.message.expect("should have message");
        assert_eq!(msg.text, "");
    }

    /// Build a test client whose `base_url` embeds the given token and
    /// points at a closed localhost port, so any request fails fast with
    /// a connection error. Centralizing this keeps the redaction tests
    /// insulated from struct-field churn.
    fn client_with_leaky_base_url(token: &str) -> TelegramClient {
        TelegramClient {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .expect("http client builds"),
            // Port 1 on the loopback interface reliably refuses connections.
            base_url: format!("http://127.0.0.1:1/bot{token}"),
            last_update_id: 0,
        }
    }

    /// Regression: `reqwest::Error`'s Display embeds the request URL in
    /// its message, and Telegram puts the bot token in the URL path. Any
    /// transient network error would therefore leak the token into logs
    /// unless `.without_url()` is applied.
    #[tokio::test]
    async fn poll_error_redacts_bot_token() {
        let token = "555555:LEAKED_IF_YOU_SEE_THIS";
        let mut client = client_with_leaky_base_url(token);
        let err = client.poll().await.expect_err("port 1 connection should fail");
        let msg = format!("{err}");

        assert!(
            !msg.contains(token),
            "bot token must not appear in error message: {msg}"
        );
        assert!(
            !msg.contains("127.0.0.1"),
            "URL must be stripped from error message: {msg}"
        );
    }

    #[tokio::test]
    async fn send_message_error_redacts_bot_token() {
        let token = "555555:LEAKED_IF_YOU_SEE_THIS";
        let client = client_with_leaky_base_url(token);
        let err = client
            .send_message(12345, "hello")
            .await
            .expect_err("port 1 connection should fail");
        let msg = format!("{err}");

        assert!(
            !msg.contains(token),
            "bot token must not appear in error message: {msg}"
        );
    }
}
