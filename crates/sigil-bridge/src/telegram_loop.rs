//! Telegram bridge loop — ties long-polling to message processing.
//!
//! [`TelegramBridge`] continuously polls for updates, processes each
//! one through [`process_telegram_update`], and routes valid messages
//! to a [`MessageSink`].

use std::time::Duration;

use sigil_core::protocol::ReplyContext;
use sigil_core::traits::MessageSink;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::BridgeError;
use crate::identity::IdentityConfig;
use crate::telegram::{TelegramUpdate, process_telegram_update};
use crate::telegram_client::TelegramClient;

/// Delay before retrying after a poll error.
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// The main Telegram bridge that polls for updates and routes
/// processed messages to a sink.
pub struct TelegramBridge {
    client: TelegramClient,
    identity_config: IdentityConfig,
}

impl TelegramBridge {
    /// Create a new bridge from a pre-built client and identity config.
    pub fn new(client: TelegramClient, identity_config: IdentityConfig) -> Self {
        Self {
            client,
            identity_config,
        }
    }

    /// Run the poll-process-route loop until cancelled.
    ///
    /// Continuously:
    /// 1. Polls Telegram for new updates and routes them to the sink.
    /// 2. Receives conductor responses from `reply_rx` and sends them
    ///    back to the originating Telegram chat.
    ///
    /// - On poll errors: logs a warning, sleeps [`RETRY_DELAY`], and
    ///   retries.
    /// - On processing errors (unknown sender, oversized message):
    ///   logs a warning and continues to the next update.
    /// - On sink errors: logs a warning and continues.
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
        // Use an enum so the select block only captures data, avoiding
        // mutable borrow conflicts between `self.client.poll()` and
        // `self.client.send_message()`.
        enum Action {
            Shutdown,
            Reply(ReplyContext, String),
            Poll(Result<Vec<TelegramUpdate>, BridgeError>),
        }

        loop {
            let action = tokio::select! {
                biased;

                () = cancel.cancelled() => Action::Shutdown,

                Some((ctx, text)) = reply_rx.recv() => Action::Reply(ctx, text),

                result = self.client.poll() => Action::Poll(result),
            };

            match action {
                Action::Shutdown => {
                    tracing::info!("telegram bridge: shutting down");
                    return Ok(());
                }
                Action::Reply(ctx, text) => {
                    if let Some(chat_id) = ctx.chat_id {
                        if let Err(e) = self.client.send_message(chat_id, &text).await {
                            tracing::warn!(
                                error = %e,
                                chat_id,
                                "telegram bridge: failed to send reply"
                            );
                        }
                    }
                }
                Action::Poll(Ok(updates)) => {
                    self.process_updates(sink, &updates).await;
                }
                Action::Poll(Err(e)) => {
                    tracing::warn!(error = %e, "telegram poll failed, retrying");
                    tokio::select! {
                        () = tokio::time::sleep(RETRY_DELAY) => {}
                        () = cancel.cancelled() => {
                            tracing::info!("telegram bridge: shutting down during retry");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// Process a batch of updates, routing valid messages to the sink.
    async fn process_updates<S: MessageSink>(&self, sink: &S, updates: &[TelegramUpdate]) {
        for update in updates {
            match process_telegram_update(update, &self.identity_config) {
                Ok(Some(bridge_msg)) => {
                    if let Err(e) = sink.accept(bridge_msg).await {
                        tracing::warn!(
                            error = %e,
                            update_id = update.update_id,
                            "sink rejected telegram message"
                        );
                    }
                }
                Ok(None) => {
                    // Non-message update (edited_message, etc.) — skip.
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        update_id = update.update_id,
                        "telegram update processing failed"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use std::sync::Arc;

    use sigil_core::CoreError;
    use sigil_core::protocol::BridgeMessage;
    use sigil_core::traits::MessageSink;
    use tokio::sync::Mutex;

    use crate::identity::default_config;
    use crate::telegram::TelegramMessage;

    use super::*;

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

    #[tokio::test]
    async fn process_updates_routes_valid_messages() {
        let config = default_config();
        // We can't easily build a TelegramClient without a real token
        // that would make HTTP calls, so we test process_updates
        // directly via a bridge with a dummy client.
        let token = secrecy::SecretString::from("fake-token");
        let client = TelegramClient::new(&token).expect("client should build");
        let bridge = TelegramBridge::new(client, config);

        let (sink, messages) = RecordingSink::new();

        let updates = vec![TelegramUpdate {
            update_id: 1,
            message: Some(TelegramMessage {
                message_id: 100,
                from_user_id: "7279215778".into(),
                chat_id: 42,
                text: "hello".into(),
                date: 1_700_000_000,
            }),
        }];

        bridge.process_updates(&sink, &updates).await;

        let recorded = messages.lock().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].text, "hello");
    }

    #[tokio::test]
    async fn process_updates_skips_unknown_sender_without_panic() {
        let config = default_config();
        let token = secrecy::SecretString::from("fake-token");
        let client = TelegramClient::new(&token).expect("client should build");
        let bridge = TelegramBridge::new(client, config);

        let (sink, messages) = RecordingSink::new();

        let updates = vec![TelegramUpdate {
            update_id: 1,
            message: Some(TelegramMessage {
                message_id: 100,
                from_user_id: "UNKNOWN_USER".into(),
                chat_id: 42,
                text: "sneaky".into(),
                date: 1_700_000_000,
            }),
        }];

        // Should not panic — just logs and continues.
        bridge.process_updates(&sink, &updates).await;

        let recorded = messages.lock().await;
        assert!(recorded.is_empty());
    }

    #[tokio::test]
    async fn process_updates_handles_empty_update_batch() {
        let config = default_config();
        let token = secrecy::SecretString::from("fake-token");
        let client = TelegramClient::new(&token).expect("client should build");
        let bridge = TelegramBridge::new(client, config);

        let (sink, messages) = RecordingSink::new();

        bridge.process_updates(&sink, &[]).await;

        let recorded = messages.lock().await;
        assert!(recorded.is_empty());
    }

    #[tokio::test]
    async fn process_updates_skips_non_message_updates() {
        let config = default_config();
        let token = secrecy::SecretString::from("fake-token");
        let client = TelegramClient::new(&token).expect("client should build");
        let bridge = TelegramBridge::new(client, config);

        let (sink, messages) = RecordingSink::new();

        let updates = vec![TelegramUpdate {
            update_id: 1,
            message: None,
        }];

        bridge.process_updates(&sink, &updates).await;

        let recorded = messages.lock().await;
        assert!(recorded.is_empty());
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let config = default_config();
        let token = secrecy::SecretString::from("fake-token");
        let client = TelegramClient::new(&token).expect("client should build");
        let mut bridge = TelegramBridge::new(client, config);

        let (sink, _messages) = RecordingSink::new();
        let cancel = CancellationToken::new();
        let (_reply_tx, mut reply_rx) = mpsc::channel(8);

        // Cancel immediately so the loop exits on first select.
        cancel.cancel();

        let result = bridge.run(&sink, cancel, &mut reply_rx).await;
        assert!(result.is_ok());
    }
}
