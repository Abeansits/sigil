//! ops-bridge -- Telegram and Slack bridge adapters.
//!
//! Receives messages from external platforms, resolves sender identity,
//! normalizes input, and routes to the conductor via [`MessageSink`].
//!
//! This crate provides the types, identity resolution, and message
//! processing logic. Live WebSocket/HTTP connections are wired in a
//! later phase.
//!
//! # Modules
//!
//! - [`error`] -- `BridgeError` enum.
//! - [`identity`] -- Sender allowlist and identity resolution.
//! - [`telegram`] -- Telegram update types and processing.
//! - [`slack`] -- Slack event types and processing.
//! - [`router`] -- Message routing to the conductor.

pub mod error;
pub mod identity;
pub mod router;
pub mod slack;
pub mod telegram;

pub use error::BridgeError;
pub use identity::{AllowedUser, IdentityConfig, default_config, resolve_identity};
pub use router::{parse_target_session, BridgeRouter};
pub use slack::{SlackEvent, process_slack_event};
pub use telegram::{TelegramMessage, TelegramUpdate, process_telegram_update};
