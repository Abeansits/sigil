//! Slack API client for Socket Mode and messaging.
//!
//! Wraps `reqwest` to call `apps.connections.open` (obtain a WSS URL)
//! and `chat.postMessage` (send replies), using app-level and bot-level
//! tokens respectively.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::error::BridgeError;

/// HTTP timeout for Slack API calls.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Slack API client.
///
/// Holds two tokens:
/// - `bot_token` (`xoxb-`): used for `chat.postMessage` and other Bot
///   API methods.
/// - `app_token` (`xapp-`): used for `apps.connections.open` to obtain
///   a Socket Mode WebSocket URL.
pub struct SlackClient {
    http: reqwest::Client,
    bot_token: SecretString,
    app_token: SecretString,
}

// ── Slack API response types (private) ───────────────────────────

#[derive(Deserialize)]
struct SlackApiResponse {
    ok: bool,
    url: Option<String>,
    error: Option<String>,
}

// ── Client impl ──────────────────────────────────────────────────

impl SlackClient {
    /// Create a new Slack client from bot and app tokens.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` if the HTTP client cannot be
    /// built (e.g., TLS back-end unavailable).
    pub fn new(bot_token: &SecretString, app_token: &SecretString) -> Result<Self, BridgeError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| BridgeError::Platform {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(Self {
            http,
            bot_token: bot_token.clone(),
            app_token: app_token.clone(),
        })
    }

    /// Request a new Socket Mode WebSocket URL.
    ///
    /// Calls `apps.connections.open` with the app-level token and
    /// returns the `wss://` URL from the response.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` on network errors or if the
    /// Slack API response indicates failure.
    pub async fn open_connection(&self) -> Result<String, BridgeError> {
        let resp: SlackApiResponse = self
            .http
            .post("https://slack.com/api/apps.connections.open")
            .header(
                "Authorization",
                format!("Bearer {}", self.app_token.expose_secret()),
            )
            .send()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("apps.connections.open request failed: {e}"),
            })?
            .json()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("apps.connections.open parse failed: {e}"),
            })?;

        if !resp.ok {
            let detail = resp.error.unwrap_or_default();
            return Err(BridgeError::Platform {
                message: format!("apps.connections.open API error: {detail}"),
            });
        }

        resp.url.ok_or_else(|| BridgeError::Platform {
            message: "apps.connections.open returned ok but no url".into(),
        })
    }

    /// Send a text message to a Slack channel.
    ///
    /// Calls `chat.postMessage` with the bot token.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Platform` on network errors or if the
    /// Slack API response indicates failure.
    pub async fn send_message(&self, channel: &str, text: &str) -> Result<(), BridgeError> {
        let body = serde_json::json!({
            "channel": channel,
            "text": text,
        });

        let resp: SlackApiResponse = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .header(
                "Authorization",
                format!("Bearer {}", self.bot_token.expose_secret()),
            )
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("chat.postMessage request failed: {e}"),
            })?
            .json()
            .await
            .map_err(|e| BridgeError::Platform {
                message: format!("chat.postMessage parse failed: {e}"),
            })?;

        if !resp.ok {
            let detail = resp.error.unwrap_or_default();
            return Err(BridgeError::Platform {
                message: format!("chat.postMessage API error: {detail}"),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_constructs_without_error() {
        let bot = SecretString::from("xoxb-test-bot-token");
        let app = SecretString::from("xapp-test-app-token");
        let client = SlackClient::new(&bot, &app);
        assert!(client.is_ok());
    }
}
