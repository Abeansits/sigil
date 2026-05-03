//! The `bridge` command — run Telegram and/or Slack bridge loops.
//!
//! Messages from bridges are routed through a [`ConductorSink`] that
//! forwards them to [`Conductor::handle_message`] for command dispatch
//! and session forwarding.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use secrecy::SecretString;
use sigil_audit::AuditLogWriter;
use sigil_bridge::{
    IdentityConfig, SlackBridge, SlackClient, TelegramBridge, TelegramClient, build_config,
};
use sigil_conductor::Conductor;
use sigil_core::protocol::{BridgeMessage, ReplyContext};
use sigil_core::traits::{MessageSink, SessionRuntime};
use sigil_core::{CoreError, PolicyDecision};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::BridgeCommands;
use crate::audit::log_event;

/// Channel capacity for bridge response delivery.
const REPLY_CHANNEL_CAPACITY: usize = 64;

/// Hard cap on egress reply size in bytes.
///
/// Matches Telegram's per-message limit (4096 chars). Slack tolerates
/// more, but long replies are a stego/exfil amplifier.
const REPLY_MAX_BYTES: usize = 4096;

/// Outcome of running the egress filter on a conductor response.
struct SanitizedReply {
    /// Reply ready to ship to the bridge — normalized and, when
    /// oversize, truncated with the `… [truncated, N bytes]` suffix.
    text: String,
    /// Byte count of the normalized reply *before* truncation. The
    /// audit event records this so an investigator sees the original
    /// size even when only the truncated prefix reached the user.
    normalized_len: usize,
}

impl SanitizedReply {
    fn truncated(&self) -> bool {
        self.normalized_len > REPLY_MAX_BYTES
    }
}

/// Strip invisible Unicode and cap a conductor response at
/// [`REPLY_MAX_BYTES`] before it leaves the control-plane.
fn sanitize_reply(response: &str) -> SanitizedReply {
    let mut normalized = sigil_policy::normalize::normalize_text(response).cleaned;
    let normalized_len = normalized.len();

    if normalized_len <= REPLY_MAX_BYTES {
        return SanitizedReply {
            text: normalized,
            normalized_len,
        };
    }

    let mut cutoff = REPLY_MAX_BYTES;
    while cutoff > 0 && !normalized.is_char_boundary(cutoff) {
        cutoff -= 1;
    }
    normalized.truncate(cutoff);
    let _ = write!(normalized, " … [truncated, {normalized_len} bytes]");

    SanitizedReply {
        text: normalized,
        normalized_len,
    }
}

/// A [`MessageSink`] that routes bridge messages through the conductor.
///
/// On each accepted message the sink:
/// 1. Forwards to [`Conductor::handle_message`] for command routing and session dispatch.
/// 2. Sends the conductor's response (with [`ReplyContext`]) back through the reply
///    channel so the bridge loop can deliver it.
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

        let reply = sanitize_reply(&response);
        let truncated = reply.truncated();
        let reply_len = reply.text.len();

        info!(len = reply_len, truncated, "conductor response sanitized");

        if let Err(e) = self.reply_tx.send((reply_context, reply.text)).await {
            tracing::warn!(error = %e, "failed to enqueue bridge reply");
        }

        let origin_summary = format!("{:?}", message.origin);
        let target_session = message.target_session;
        log_event(
            &self.audit,
            &format!("bridge.message_routed: {} chars", message.text.len()),
            &origin_summary,
            PolicyDecision::Allow,
            target_session,
        )
        .await;
        log_event(
            &self.audit,
            &format!(
                "bridge.reply_sent: {reply_len} bytes (truncated={truncated}, original={})",
                reply.normalized_len,
            ),
            &origin_summary,
            PolicyDecision::Allow,
            target_session,
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
    use std::collections::HashMap;

    use sigil_core::PlatformIdentity;

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

    sigil_policy::EvaluatorConfig {
        user_tier_ceilings,
        ..Default::default()
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use sigil_core::origin::ActionOrigin;
    use sigil_core::protocol::{ConductorMessage, ReplyContext};
    use sigil_core::session::{SessionConfig, SessionHandle, SessionState};
    use sigil_store::Store;

    use super::*;

    const TRUNCATION_PREFIX: &str = " … [truncated, ";

    // ── sanitize_reply ────────────────────────────────────────────────

    #[test]
    fn sanitize_reply_strips_zero_width_and_directional_overrides() {
        let input = "hel\u{200B}lo\u{202E}world";
        let out = sanitize_reply(input);
        assert_eq!(out.text, "helloworld");
        assert!(!out.truncated());
        assert_eq!(out.normalized_len, "helloworld".len());
    }

    #[test]
    fn sanitize_reply_under_cap_is_unchanged() {
        let input = "small reply";
        let out = sanitize_reply(input);
        assert_eq!(out.text, input);
        assert!(!out.truncated());
        assert_eq!(out.normalized_len, input.len());
    }

    #[test]
    fn sanitize_reply_truncates_oversize_with_suffix_and_byte_count() {
        let original = "x".repeat(REPLY_MAX_BYTES + 200);
        let out = sanitize_reply(&original);

        assert!(out.truncated());
        assert_eq!(out.normalized_len, original.len());
        let suffix = format!("{TRUNCATION_PREFIX}{} bytes]", original.len());
        assert!(
            out.text.ends_with(&suffix),
            "expected truncation suffix, got: {}",
            &out.text[out.text.len().saturating_sub(80)..]
        );
        let prefix_len = out.text.len() - suffix.len();
        assert!(prefix_len <= REPLY_MAX_BYTES);
    }

    #[test]
    fn sanitize_reply_truncates_at_char_boundary_for_multibyte() {
        // 3-byte chars (€ = U+20AC) straddle the cap regardless of the
        // cap's parity, so the boundary walk must back up at least 1
        // byte. Validates the resulting String is still valid UTF-8.
        let original = "€".repeat(REPLY_MAX_BYTES);
        let out = sanitize_reply(&original);
        assert!(out.truncated());
        assert!(std::str::from_utf8(out.text.as_bytes()).is_ok());
    }

    // ── ConductorSink::accept ────────────────────────────────────────

    /// Stands a `Conductor` up without tmux or container backends.
    #[derive(Default)]
    struct NoopRuntime;

    impl SessionRuntime for NoopRuntime {
        async fn launch(&self, _config: &SessionConfig) -> Result<SessionHandle, CoreError> {
            Err(CoreError::Runtime {
                message: "noop runtime: launch not supported".into(),
            })
        }
        async fn send(
            &self,
            _handle: &SessionHandle,
            _msg: ConductorMessage,
        ) -> Result<(), CoreError> {
            Ok(())
        }
        async fn read_output(&self, _handle: &SessionHandle) -> Result<String, CoreError> {
            Ok(String::new())
        }
        async fn status(&self, _handle: &SessionHandle) -> Result<SessionState, CoreError> {
            Ok(SessionState::Stopped)
        }
        async fn stop(&self, _handle: &SessionHandle) -> Result<(), CoreError> {
            Ok(())
        }
    }

    async fn read_audit_log(path: &std::path::Path) -> Vec<serde_json::Value> {
        let raw = tokio::fs::read_to_string(path).await.expect("read audit");
        raw.lines()
            .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
            .collect()
    }

    fn action_summary(entry: &serde_json::Value) -> &str {
        entry
            .get("event")
            .and_then(|e| e.get("action_summary"))
            .and_then(|v| v.as_str())
            .expect("action_summary present")
    }

    async fn build_sink(
        audit_path: &std::path::Path,
    ) -> (
        ConductorSink<NoopRuntime>,
        mpsc::Receiver<(ReplyContext, String)>,
    ) {
        let store = Arc::new(Store::new_in_memory().await.expect("store"));
        let runtime = Arc::new(NoopRuntime);
        let conductor = Arc::new(Conductor::new(store, runtime, Duration::from_secs(30)));
        let audit = Arc::new(
            AuditLogWriter::new(audit_path, b"bridge-pr-a-test".to_vec())
                .await
                .expect("audit writer"),
        );
        let (reply_tx, reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);
        (
            ConductorSink {
                conductor,
                audit,
                reply_tx,
            },
            reply_rx,
        )
    }

    fn slack_dm(text: &str) -> BridgeMessage {
        BridgeMessage {
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_TEST".into(),
                channel_id: "C_TEST".into(),
            },
            text: text.into(),
            target_session: None,
            is_command: text.starts_with('/'),
            reply_context: ReplyContext {
                chat_id: None,
                channel_id: Some("C_TEST".into()),
            },
        }
    }

    #[tokio::test]
    async fn accept_emits_reply_sent_event_with_truncated_false_for_short_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (sink, mut reply_rx) = build_sink(&audit_path).await;

        sink.accept(slack_dm("/help")).await.expect("accept ok");

        let (_ctx, reply) = reply_rx.recv().await.expect("reply enqueued");
        assert!(!reply.contains(TRUNCATION_PREFIX));

        let entries = read_audit_log(&audit_path).await;
        let summaries: Vec<&str> = entries.iter().map(action_summary).collect();
        assert!(
            summaries
                .iter()
                .any(|s| s.starts_with("bridge.message_routed:")),
            "expected message_routed in {summaries:?}"
        );
        let reply_summary = summaries
            .iter()
            .find(|s| s.starts_with("bridge.reply_sent:"))
            .expect("reply_sent present");
        assert!(reply_summary.contains("truncated=false"));
    }
}
