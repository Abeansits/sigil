//! ops-bridge -- Telegram and Slack bridge adapters.
//!
//! Receives messages from external platforms, resolves sender identity,
//! normalizes input, and routes to the conductor via [`MessageSink`].
//!
//! # Modules
//!
//! - [`error`] -- `BridgeError` enum.
//! - [`identity`] -- Sender allowlist and identity resolution.
//! - [`telegram`] -- Telegram update types and processing.
//! - [`telegram_client`] -- Telegram Bot API long-polling HTTP client.
//! - [`telegram_loop`] -- Telegram bridge loop (poll → process → route).
//! - [`slack`] -- Slack event types and processing.
//! - [`router`] -- Message routing to the conductor.

pub mod error;
pub mod identity;
pub mod router;
pub mod slack;
pub mod telegram;
pub mod telegram_client;
pub mod telegram_loop;

pub use error::BridgeError;
pub use identity::{AllowedUser, IdentityConfig, default_config, resolve_identity};
pub use router::{parse_target_session, BridgeRouter};
pub use slack::{SlackEvent, process_slack_event};
pub use telegram::{TelegramMessage, TelegramUpdate, process_telegram_update};
pub use telegram_client::TelegramClient;
pub use telegram_loop::TelegramBridge;
