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

/// Default base URL for the Slack Web API.
const DEFAULT_BASE_URL: &str = "https://slack.com/api";

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
    /// Base URL for Slack Web API. Always `DEFAULT_BASE_URL` in
    /// production; overridable in tests via struct-literal construction
    /// so regression tests can point at a closed port and assert the
    /// URL is stripped from formatted errors.
    base_url: String,
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
            base_url: DEFAULT_BASE_URL.into(),
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
            .post(format!("{}/apps.connections.open", self.base_url))
            .header(
                "Authorization",
                format!("Bearer {}", self.app_token.expose_secret()),
            )
            .send()
            .await
            .map_err(|e| BridgeError::from_reqwest("apps.connections.open request failed", e))?
            .json()
            .await
            .map_err(|e| BridgeError::from_reqwest("apps.connections.open parse failed", e))?;

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
            .post(format!("{}/chat.postMessage", self.base_url))
            .header(
                "Authorization",
                format!("Bearer {}", self.bot_token.expose_secret()),
            )
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::from_reqwest("chat.postMessage request failed", e))?
            .json()
            .await
            .map_err(|e| BridgeError::from_reqwest("chat.postMessage parse failed", e))?;

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
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn new_constructs_without_error() {
        let bot = SecretString::from("xoxb-test-bot-token");
        let app = SecretString::from("xapp-test-app-token");
        let client = SlackClient::new(&bot, &app);
        assert!(client.is_ok());
    }

    /// Build a test client whose `base_url` embeds a fake secret and
    /// points at a closed localhost port, so any request fails fast
    /// with a connection error. Mirrors the Telegram regression
    /// pattern from PR #65 so the two clients stay symmetric.
    fn client_with_leaky_base_url(secret_marker: &str) -> SlackClient {
        SlackClient {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .expect("http client builds"),
            bot_token: SecretString::from("xoxb-unused-in-this-test"),
            app_token: SecretString::from("xapp-unused-in-this-test"),
            // Port 1 on the loopback interface reliably refuses
            // connections. The query-string marker stands in for any
            // URL-embedded credential and must not survive to the
            // formatted error.
            base_url: format!("http://127.0.0.1:1/leak?token={secret_marker}"),
        }
    }

    /// Regression: `reqwest::Error`'s Display embeds the request URL.
    /// `apps.connections.open` must route through
    /// `BridgeError::from_reqwest` so a URL-embedded secret cannot
    /// leak into logs.
    #[tokio::test]
    async fn open_connection_error_redacts_url() {
        let secret = "LEAKED_IF_YOU_SEE_THIS";
        let client = client_with_leaky_base_url(secret);
        let err = client
            .open_connection()
            .await
            .expect_err("port 1 connection should fail");
        let msg = format!("{err}");

        assert!(
            !msg.contains(secret),
            "URL-embedded secret must not appear in error message: {msg}"
        );
        assert!(
            !msg.contains("127.0.0.1"),
            "URL must be stripped from error message: {msg}"
        );
    }

    #[tokio::test]
    async fn send_message_error_redacts_url() {
        let secret = "LEAKED_IF_YOU_SEE_THIS";
        let client = client_with_leaky_base_url(secret);
        let err = client
            .send_message("C12345", "hello")
            .await
            .expect_err("port 1 connection should fail");
        let msg = format!("{err}");

        assert!(
            !msg.contains(secret),
            "URL-embedded secret must not appear in error message: {msg}"
        );
        assert!(
            !msg.contains("127.0.0.1"),
            "URL must be stripped from error message: {msg}"
        );
    }
}
