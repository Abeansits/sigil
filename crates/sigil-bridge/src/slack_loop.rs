//! Slack Socket Mode bridge loop.
//!
//! [`SlackBridge`] connects to the Slack Socket Mode WebSocket,
//! receives event envelopes, acknowledges them, extracts message
//! events, and routes them through [`process_slack_event`] to a
//! [`MessageSink`].

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sigil_core::protocol::ReplyContext;
use sigil_core::traits::MessageSink;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::error::BridgeError;
use crate::identity::IdentityConfig;
use crate::slack::{SlackEvent, process_slack_event};
use crate::slack_client::SlackClient;

/// Delay before reconnecting after a WebSocket error or disconnect.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Sentinel used in place of a WSS URL in formatted error messages.
const WSS_URL_REDACTED: &str = "<wss-url-redacted>";

/// Scrub a WSS URL out of a formatted error string.
///
/// The Socket Mode WSS URL returned by `apps.connections.open`
/// carries an ephemeral, per-connection ticket in its query string,
/// which is a credential for this connection. Several
/// `tungstenite::Error` variants (`Url`, `Http`, some wrapped `Io`
/// messages) can surface that URL into Display, so any formatted
/// error message that originated from a connect attempt must have
/// the URL stripped before it reaches logs. Typical connect errors
/// (refused / TLS) don't currently embed it, but new tungstenite
/// versions could — this is defence-in-depth, symmetrical with the
/// `BridgeError::from_reqwest` primitive for reqwest errors.
fn redact_wss_url(err_msg: &str, wss_url: &str) -> String {
    err_msg.replace(wss_url, WSS_URL_REDACTED)
}

// ── Socket Mode envelope types (private) ─────────────────────────

#[derive(serde::Deserialize)]
struct SocketEnvelope {
    envelope_id: String,
    #[serde(rename = "type")]
    envelope_type: String,
    payload: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct EventPayload {
    #[serde(rename = "type")]
    event_type: Option<String>,
    user: Option<String>,
    channel: Option<String>,
    text: Option<String>,
    ts: Option<String>,
    bot_id: Option<String>,
    subtype: Option<String>,
}

// ── Bridge ───────────────────────────────────────────────────────

/// The main Slack Socket Mode bridge that connects via WebSocket and
/// routes processed messages to a sink.
pub struct SlackBridge {
    client: SlackClient,
    identity_config: IdentityConfig,
}

impl SlackBridge {
    /// Create a new bridge from a pre-built client and identity config.
    pub fn new(client: SlackClient, identity_config: IdentityConfig) -> Self {
        Self {
            client,
            identity_config,
        }
    }

    /// Run the connect-read-process loop until cancelled.
    ///
    /// Continuously:
    /// 1. Reads Slack Socket Mode events and routes them to the sink.
    /// 2. Receives conductor responses from `reply_rx` and sends them back to the
    ///    originating Slack channel.
    ///
    /// On WebSocket disconnect or error the bridge sleeps for
    /// [`RECONNECT_DELAY`], obtains a fresh WSS URL, and reconnects.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` when the cancellation token fires. Only
    /// returns `Err` for truly unrecoverable situations (none today).
    pub async fn run<S: MessageSink>(
        &mut self,
        sink: &S,
        cancel: CancellationToken,
        reply_rx: &mut mpsc::Receiver<(ReplyContext, String)>,
    ) -> Result<(), BridgeError> {
        loop {
            if cancel.is_cancelled() {
                tracing::info!("slack bridge: shutting down before connect");
                return Ok(());
            }

            // Obtain a fresh WSS URL.
            let wss_url = match self.client.open_connection().await {
                Ok(url) => url,
                Err(e) => {
                    tracing::warn!(error = %e, "slack bridge: failed to open connection, retrying");
                    tokio::select! {
                        () = tokio::time::sleep(RECONNECT_DELAY) => {}
                        () = cancel.cancelled() => {
                            tracing::info!("slack bridge: shutting down during reconnect delay");
                            return Ok(());
                        }
                    }
                    continue;
                }
            };

            tracing::info!("slack bridge: connecting to socket mode");

            // Connect to the WebSocket.
            let ws_stream = match tokio_tungstenite::connect_async(&wss_url).await {
                Ok((stream, _response)) => stream,
                Err(e) => {
                    let err_msg = redact_wss_url(&format!("{e}"), &wss_url);
                    tracing::warn!(error = %err_msg, "slack bridge: websocket connect failed, retrying");
                    tokio::select! {
                        () = tokio::time::sleep(RECONNECT_DELAY) => {}
                        () = cancel.cancelled() => {
                            tracing::info!("slack bridge: shutting down during reconnect delay");
                            return Ok(());
                        }
                    }
                    continue;
                }
            };

            tracing::info!("slack bridge: connected to socket mode");

            let (mut ws_write, mut ws_read) = ws_stream.split();

            // Read loop for this connection.
            loop {
                tokio::select! {
                    biased;

                    () = cancel.cancelled() => {
                        tracing::info!("slack bridge: shutting down");
                        // Attempt a clean close; ignore errors.
                        let _ = ws_write.send(Message::Close(None)).await;
                        return Ok(());
                    }

                    Some((ctx, text)) = reply_rx.recv() => {
                        if let Some(ref channel) = ctx.channel_id {
                            if let Err(e) = self.client.send_message(channel, &text).await {
                                tracing::warn!(
                                    error = %e,
                                    channel,
                                    "slack bridge: failed to send reply"
                                );
                            }
                        }
                    }

                    frame = ws_read.next() => {
                        match frame {
                            Some(Ok(Message::Text(text))) => {
                                self.handle_text_frame(
                                    &text,
                                    &mut ws_write,
                                    sink,
                                ).await;
                            }
                            Some(Ok(Message::Close(_))) => {
                                tracing::info!("slack bridge: server sent close frame, reconnecting");
                                break;
                            }
                            Some(Ok(Message::Ping(data))) => {
                                if let Err(e) = ws_write.send(Message::Pong(data)).await {
                                    tracing::warn!(error = %e, "slack bridge: failed to send pong");
                                    break;
                                }
                            }
                            Some(Ok(_)) => {
                                // Binary or Pong frames — ignore.
                            }
                            Some(Err(e)) => {
                                tracing::warn!(error = %e, "slack bridge: websocket read error, reconnecting");
                                break;
                            }
                            None => {
                                tracing::info!("slack bridge: websocket stream ended, reconnecting");
                                break;
                            }
                        }
                    }
                }
            }

            // Brief pause before reconnecting.
            tokio::select! {
                () = tokio::time::sleep(RECONNECT_DELAY) => {}
                () = cancel.cancelled() => {
                    tracing::info!("slack bridge: shutting down during reconnect delay");
                    return Ok(());
                }
            }
        }
    }

    /// Handle a single text frame from the WebSocket.
    ///
    /// Parses the envelope, sends an acknowledgement, and routes
    /// message events to the sink.
    async fn handle_text_frame<W, S>(&self, text: &str, ws_write: &mut W, sink: &S)
    where
        W: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
        S: MessageSink,
    {
        let envelope: SocketEnvelope = match serde_json::from_str(text) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "slack bridge: failed to parse envelope");
                return;
            }
        };

        // Always acknowledge the envelope.
        let ack = format!(r#"{{"envelope_id":"{}"}}"#, envelope.envelope_id);
        if let Err(e) = ws_write.send(Message::Text(ack)).await {
            tracing::warn!(error = %e, "slack bridge: failed to send ack");
            return;
        }

        // Only process events_api envelopes.
        if envelope.envelope_type != "events_api" {
            tracing::debug!(
                envelope_type = %envelope.envelope_type,
                "slack bridge: skipping non-events_api envelope"
            );
            return;
        }

        // Extract the event from the payload.
        let Some(payload) = envelope.payload else {
            tracing::debug!("slack bridge: events_api envelope has no payload");
            return;
        };

        let Some(event_value) = payload.get("event") else {
            tracing::debug!("slack bridge: payload has no event field");
            return;
        };

        let event_data: EventPayload = match serde_json::from_value(event_value.clone()) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "slack bridge: failed to parse event payload");
                return;
            }
        };

        let slack_event = SlackEvent {
            event_type: event_data.event_type.unwrap_or_default(),
            user: event_data.user.unwrap_or_default(),
            channel: event_data.channel.unwrap_or_default(),
            text: event_data.text.unwrap_or_default(),
            ts: event_data.ts.unwrap_or_default(),
            bot_id: event_data.bot_id,
            subtype: event_data.subtype,
        };

        match process_slack_event(&slack_event, &self.identity_config) {
            Ok(Some(bridge_msg)) => {
                if let Err(e) = sink.accept(bridge_msg).await {
                    tracing::warn!(
                        error = %e,
                        "slack bridge: sink rejected message"
                    );
                }
            }
            Ok(None) => {
                // Non-message event type — skip.
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "slack bridge: event processing failed"
                );
            }
        }
    }
}

/// Build an acknowledgement JSON string for a given envelope ID.
#[cfg(test)]
fn build_ack_json(envelope_id: &str) -> String {
    format!(r#"{{"envelope_id":"{envelope_id}"}}"#)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use secrecy::SecretString;
    use sigil_core::CoreError;
    use sigil_core::protocol::BridgeMessage;
    use sigil_core::traits::MessageSink;
    use tokio::sync::Mutex;

    use super::*;
    use crate::identity::default_config;

    /// A sink that records accepted messages.
    struct RecordingSink {
        messages: Arc<Mutex<Vec<BridgeMessage>>>,
    }

    impl RecordingSink {
        fn new() -> (Self, Arc<Mutex<Vec<BridgeMessage>>>) {
            let messages = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    messages: Arc::clone(&messages),
                },
                messages,
            )
        }
    }

    impl MessageSink for RecordingSink {
        async fn accept(&self, message: BridgeMessage) -> Result<(), CoreError> {
            self.messages.lock().await.push(message);
            Ok(())
        }
    }

    #[test]
    fn parse_valid_events_api_envelope_extracts_event() {
        let json = r#"{
            "envelope_id": "abc-123",
            "type": "events_api",
            "payload": {
                "event": {
                    "type": "message",
                    "user": "U12345",
                    "channel": "C67890",
                    "text": "hello world",
                    "ts": "1700000000.000100"
                }
            }
        }"#;

        let envelope: SocketEnvelope = serde_json::from_str(json).expect("should parse");
        assert_eq!(envelope.envelope_id, "abc-123");
        assert_eq!(envelope.envelope_type, "events_api");

        let payload = envelope.payload.expect("should have payload");
        let event_value = payload.get("event").expect("should have event");
        let event: EventPayload =
            serde_json::from_value(event_value.clone()).expect("should parse event");

        assert_eq!(event.event_type.as_deref(), Some("message"));
        assert_eq!(event.user.as_deref(), Some("U12345"));
        assert_eq!(event.channel.as_deref(), Some("C67890"));
        assert_eq!(event.text.as_deref(), Some("hello world"));
        assert_eq!(event.ts.as_deref(), Some("1700000000.000100"));
    }

    #[test]
    fn parse_non_events_api_envelope_has_correct_type() {
        let json = r#"{
            "envelope_id": "def-456",
            "type": "slash_commands",
            "payload": {}
        }"#;

        let envelope: SocketEnvelope = serde_json::from_str(json).expect("should parse");
        assert_eq!(envelope.envelope_type, "slash_commands");
        // Non-events_api envelopes are acknowledged but not processed
        // as message events.
    }

    /// Regression: if a `tungstenite::Error`'s Display includes the
    /// WSS URL, the Socket Mode ticket in the URL's query string
    /// would leak into logs via the connect-failure tracing site.
    /// `redact_wss_url` must strip the URL literal regardless of
    /// where in the error message it appears.
    #[test]
    fn redact_wss_url_scrubs_embedded_ticket() {
        let wss_url = "wss://wss-primary.slack.com/link/?ticket=LEAKED_TICKET&app_id=A123";
        // Simulated tungstenite error message shapes (Io and Url
        // variants are the most likely to embed the URL).
        let io_shape = format!("IO error: failed to connect to {wss_url}: refused");
        let url_shape = format!("URL error parsing {wss_url}: invalid port");

        for err_msg in [&io_shape, &url_shape] {
            let scrubbed = redact_wss_url(err_msg, wss_url);
            assert!(
                !scrubbed.contains("LEAKED_TICKET"),
                "ticket must be stripped: {scrubbed}"
            );
            assert!(
                !scrubbed.contains("wss-primary.slack.com"),
                "WSS host must be stripped: {scrubbed}"
            );
            assert!(
                scrubbed.contains(WSS_URL_REDACTED),
                "sentinel should be present: {scrubbed}"
            );
        }
    }

    #[test]
    fn ack_json_is_correctly_formed() {
        let ack = build_ack_json("env-789");
        assert_eq!(ack, r#"{"envelope_id":"env-789"}"#);
    }

    #[test]
    fn ack_json_with_special_chars() {
        let ack = build_ack_json("abc-123-def");
        let parsed: serde_json::Value = serde_json::from_str(&ack).expect("should be valid JSON");
        assert_eq!(
            parsed.get("envelope_id").and_then(|v| v.as_str()),
            Some("abc-123-def")
        );
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let bot = SecretString::from("xoxb-test");
        let app = SecretString::from("xapp-test");
        let client = SlackClient::new(&bot, &app).expect("client should build");
        let config = default_config();
        let mut bridge = SlackBridge::new(client, config);

        let (sink, _messages) = RecordingSink::new();
        let cancel = CancellationToken::new();
        let (_reply_tx, mut reply_rx) = mpsc::channel(8);

        // Cancel immediately so the loop exits before connecting.
        cancel.cancel();

        let result = bridge.run(&sink, cancel, &mut reply_rx).await;
        assert!(result.is_ok());
    }
}
