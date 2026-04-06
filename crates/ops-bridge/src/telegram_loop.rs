//! Telegram bridge loop — ties long-polling to message processing.
//!
//! [`TelegramBridge`] continuously polls for updates, processes each
//! one through [`process_telegram_update`], and routes valid messages
//! to a [`MessageSink`].

use std::time::Duration;

use ops_core::traits::MessageSink;
use tokio_util::sync::CancellationToken;

use crate::error::BridgeError;
use crate::identity::IdentityConfig;
use crate::telegram::process_telegram_update;
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
    ) -> Result<(), BridgeError> {
        loop {
            tokio::select! {
                biased;

                () = cancel.cancelled() => {
                    tracing::info!("telegram bridge: shutting down");
                    return Ok(());
                }

                result = self.client.poll() => {
                    match result {
                        Ok(updates) => {
                            self.process_updates(sink, &updates).await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "telegram poll failed, retrying");
                            // Use select so we can still honour cancellation
                            // during the retry delay.
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
        }
    }

    /// Process a batch of updates, routing valid messages to the sink.
    async fn process_updates<S: MessageSink>(
        &self,
        sink: &S,
        updates: &[crate::telegram::TelegramUpdate],
    ) {
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
    use std::sync::Arc;

    use ops_core::CoreError;
    use ops_core::protocol::BridgeMessage;
    use ops_core::traits::MessageSink;
    use tokio::sync::Mutex;

    use crate::identity::default_config;
    use crate::telegram::{TelegramMessage, TelegramUpdate};

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
                from_user_id: "SEBASTIAN_TG_ID".into(),
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

        // Cancel immediately so the loop exits on first select.
        cancel.cancel();

        let result = bridge.run(&sink, cancel).await;
        assert!(result.is_ok());
    }
}
