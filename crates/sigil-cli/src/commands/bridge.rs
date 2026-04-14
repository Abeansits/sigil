//! The `bridge` command — run Telegram and/or Slack bridge loops.
//!
//! Messages from bridges are routed through a [`ConductorSink`] that
//! forwards them to [`Conductor::handle_message`] for command dispatch
//! and session forwarding.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;
use tracing::info;

use sigil_audit::AuditLogWriter;
use sigil_bridge::{
    IdentityConfig, SlackBridge, SlackClient, TelegramBridge, TelegramClient, build_config,
};
use sigil_conductor::Conductor;
use sigil_core::CoreError;
use sigil_core::PolicyDecision;
use sigil_core::protocol::{BridgeMessage, ReplyContext};
use sigil_core::traits::{MessageSink, SessionRuntime};
use tokio::sync::mpsc;

use crate::BridgeCommands;
use crate::audit::log_event;

/// Channel capacity for bridge response delivery.
const REPLY_CHANNEL_CAPACITY: usize = 64;

/// A [`MessageSink`] that routes bridge messages through the conductor.
///
/// On each accepted message the sink:
/// 1. Forwards to [`Conductor::handle_message`] for command routing and
///    session dispatch.
/// 2. Sends the conductor's response (with [`ReplyContext`]) back
///    through the reply channel so the bridge loop can deliver it.
/// 3. Records an audit event.
pub(crate) struct ConductorSink<R: SessionRuntime> {
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    reply_tx: mpsc::Sender<(ReplyContext, String)>,
}

impl<R: SessionRuntime> MessageSink for ConductorSink<R> {
    async fn accept(&self, message: BridgeMessage) -> Result<(), CoreError> {
        info!(
            origin = ?message.origin,
            text_len = message.text.len(),
            target = ?message.target_session,
            "bridge message received"
        );

        let reply_context = message.reply_context.clone();
        let response = self.conductor.handle_message(&message).await?;

        info!(response = %response, "conductor response");

        if let Err(e) = self.reply_tx.send((reply_context, response)).await {
            tracing::warn!(error = %e, "failed to enqueue bridge reply");
        }

        log_event(
            &self.audit,
            &format!("bridge.message_routed: {} chars", message.text.len()),
            &format!("{:?}", message.origin),
            PolicyDecision::Allow,
            message.target_session,
        )
        .await;

        Ok(())
    }
}

/// Run the bridge subcommand.
///
/// Builds a [`ConductorSink`] to route messages through the conductor,
/// then starts the requested bridge loop(s) with an internal
/// cancellation token (ctrl-c).
///
/// # Errors
///
/// Returns an error if required environment variables are missing or
/// if a client fails to initialize.
pub async fn run<R: SessionRuntime>(
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    cmd: BridgeCommands,
) -> Result<()> {
    let cancel = make_cancel_token();
    start_bridges(conductor, audit, cmd, cancel).await
}

/// Run bridge loop(s) with an externally provided cancellation token.
///
/// Used by `sigil run` for coordinated shutdown with the heartbeat
/// loop.
pub(crate) async fn start_bridges<R: SessionRuntime>(
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    cmd: BridgeCommands,
    cancel: CancellationToken,
) -> Result<()> {
    match cmd {
        BridgeCommands::Telegram => run_telegram(conductor, audit, cancel).await,
        BridgeCommands::Slack => run_slack(conductor, audit, cancel).await,
        BridgeCommands::All => run_all(conductor, audit, cancel).await,
    }
}

/// Build a `CancellationToken` that fires on ctrl-c.
pub(crate) fn make_cancel_token() -> CancellationToken {
    let cancel = CancellationToken::new();
    let child = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            child.cancel();
        }
    });
    cancel
}

/// Load the identity config from `.sigil/config.toml`, falling back to
/// env vars and then hardcoded defaults.
///
/// If the config file exists but is malformed, this returns an error
/// rather than silently falling back to defaults (fail closed).
pub(crate) fn load_identity_config() -> Result<IdentityConfig> {
    let bridge_section = match std::env::current_dir() {
        Ok(cwd) => sigil_core::config::ProjectConfig::load(&cwd)
            .context("failed to load .sigil/config.toml")?
            .and_then(|cfg| cfg.bridge),
        Err(_) => None,
    };

    Ok(build_config(bridge_section.as_ref()))
}

/// Build an [`EvaluatorConfig`] with per-user tier ceilings from the
/// bridge identity config. This converges bridge and core principal
/// resolution into a single path.
pub(crate) fn evaluator_config_from_identity(
    config: &IdentityConfig,
) -> sigil_policy::EvaluatorConfig {
    use sigil_core::PlatformIdentity;
    use std::collections::HashMap;

    let mut user_tier_ceilings = HashMap::new();

    for user in &config.allowed_telegram_ids {
        user_tier_ceilings.insert(
            PlatformIdentity::Telegram {
                user_id: user.platform_id.clone(),
            },
            user.tier_ceiling,
        );
    }

    for user in &config.allowed_slack_ids {
        user_tier_ceilings.insert(
            PlatformIdentity::Slack {
                user_id: user.platform_id.clone(),
            },
            user.tier_ceiling,
        );
    }

    sigil_policy::EvaluatorConfig { user_tier_ceilings }
}

// ── Telegram ────────────────────────────────────────────────────────

#[allow(clippy::print_stdout)]
async fn run_telegram<R: SessionRuntime>(
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    cancel: CancellationToken,
) -> Result<()> {
    let token = read_env_secret("SIGIL_TELEGRAM_TOKEN")?;
    let client = TelegramClient::new(&token).context("failed to build Telegram client")?;
    let identity = load_identity_config()?;
    let mut bridge = TelegramBridge::new(client, identity);

    let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);
    let sink = ConductorSink {
        conductor,
        audit: Arc::clone(&audit),
        reply_tx,
    };

    log_event(
        &audit,
        "bridge.telegram.start",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("telegram bridge starting");
    println!("Telegram bridge running. Press Ctrl-C to stop.");

    bridge
        .run(&sink, cancel, &mut reply_rx)
        .await
        .context("telegram bridge loop failed")?;

    log_event(
        &audit,
        "bridge.telegram.stop",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("telegram bridge stopped");
    println!("\nTelegram bridge stopped.");
    Ok(())
}

// ── Slack ────────────────────────────────────────────────────────────

#[allow(clippy::print_stdout)]
async fn run_slack<R: SessionRuntime>(
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    cancel: CancellationToken,
) -> Result<()> {
    let app_token = read_env_secret("SIGIL_SLACK_APP_TOKEN")?;
    let bot_token = read_env_secret("SIGIL_SLACK_BOT_TOKEN")?;
    let client =
        SlackClient::new(&bot_token, &app_token).context("failed to build Slack client")?;
    let identity = load_identity_config()?;
    let mut bridge = SlackBridge::new(client, identity);

    let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);
    let sink = ConductorSink {
        conductor,
        audit: Arc::clone(&audit),
        reply_tx,
    };

    log_event(
        &audit,
        "bridge.slack.start",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("slack bridge starting");
    println!("Slack bridge running. Press Ctrl-C to stop.");

    bridge
        .run(&sink, cancel, &mut reply_rx)
        .await
        .context("slack bridge loop failed")?;

    log_event(
        &audit,
        "bridge.slack.stop",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("slack bridge stopped");
    println!("\nSlack bridge stopped.");
    Ok(())
}

// ── Both ─────────────────────────────────────────────────────────────

#[allow(clippy::print_stdout)]
async fn run_all<R: SessionRuntime>(
    conductor: Arc<Conductor<R>>,
    audit: Arc<AuditLogWriter>,
    cancel: CancellationToken,
) -> Result<()> {
    let tg_token = read_env_secret("SIGIL_TELEGRAM_TOKEN")?;
    let slack_app = read_env_secret("SIGIL_SLACK_APP_TOKEN")?;
    let slack_bot = read_env_secret("SIGIL_SLACK_BOT_TOKEN")?;

    let tg_client = TelegramClient::new(&tg_token).context("failed to build Telegram client")?;
    let slack_client =
        SlackClient::new(&slack_bot, &slack_app).context("failed to build Slack client")?;

    let identity = load_identity_config()?;
    let mut tg_bridge = TelegramBridge::new(tg_client, identity.clone());
    let mut slack_bridge = SlackBridge::new(slack_client, identity);

    let (tg_reply_tx, mut tg_reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);
    let (slack_reply_tx, mut slack_reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);

    let tg_sink = ConductorSink {
        conductor: Arc::clone(&conductor),
        audit: Arc::clone(&audit),
        reply_tx: tg_reply_tx,
    };
    let slack_sink = ConductorSink {
        conductor,
        audit: Arc::clone(&audit),
        reply_tx: slack_reply_tx,
    };

    log_event(
        &audit,
        "bridge.all.start",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("starting telegram and slack bridges concurrently");
    println!("Telegram + Slack bridges running. Press Ctrl-C to stop.");

    let tg_cancel = cancel.clone();
    let slack_cancel = cancel;

    let (tg_result, slack_result) = tokio::join!(
        tg_bridge.run(&tg_sink, tg_cancel, &mut tg_reply_rx),
        slack_bridge.run(&slack_sink, slack_cancel, &mut slack_reply_rx),
    );

    if let Err(e) = &tg_result {
        tracing::error!(error = %e, "telegram bridge failed");
    }
    if let Err(e) = &slack_result {
        tracing::error!(error = %e, "slack bridge failed");
    }

    log_event(
        &audit,
        "bridge.all.stop",
        "bridge",
        PolicyDecision::Allow,
        None,
    )
    .await;
    info!("all bridges stopped");
    println!("\nBridges stopped.");

    tg_result.context("telegram bridge failed")?;
    slack_result.context("slack bridge failed")?;
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Read a required secret from an environment variable.
fn read_env_secret(name: &str) -> Result<SecretString> {
    let val =
        std::env::var(name).with_context(|| format!("{name} environment variable is required"))?;
    if val.is_empty() {
        bail!("{name} environment variable must not be empty");
    }
    Ok(SecretString::from(val))
}
