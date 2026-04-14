//! The `run` command — conductor heartbeat loop with optional bridges.
//!
//! This is the main production entry point: it starts the conductor
//! heartbeat, optionally starts bridge adapters, and runs everything
//! concurrently under a single cancellation token.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use sigil_audit::AuditLogWriter;
use sigil_conductor::Conductor;
use sigil_core::PolicyDecision;
use sigil_core::traits::SessionRuntime;
use sigil_store::Store;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::BridgeCommands;
use crate::audit::log_event;
use crate::commands::bridge;

/// Bridge mode for `sigil run --bridge <mode>`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum BridgeMode {
    /// Telegram bridge only.
    Telegram,
    /// Slack bridge only.
    Slack,
    /// Both Telegram and Slack.
    All,
}

impl BridgeMode {
    fn to_bridge_command(self) -> BridgeCommands {
        match self {
            Self::Telegram => BridgeCommands::Telegram,
            Self::Slack => BridgeCommands::Slack,
            Self::All => BridgeCommands::All,
        }
    }
}

/// Run the conductor with optional bridge adapters.
///
/// Creates a [`Conductor`], reconciles state, then runs the heartbeat
/// loop. If `bridge_mode` is specified, the bridge loop runs
/// concurrently using the same conductor for message routing.
///
/// # Errors
///
/// Returns an error if reconciliation or the heartbeat loop fails.
#[allow(clippy::print_stdout)]
pub async fn run<R: SessionRuntime>(
    store: Arc<Store>,
    runtime: Arc<R>,
    audit: Arc<AuditLogWriter>,
    interval: u64,
    bridge_mode: Option<BridgeMode>,
) -> Result<()> {
    println!("{}\n", crate::banner::BANNER);

    let mut conductor_builder = Conductor::new(
        Arc::clone(&store),
        Arc::clone(&runtime),
        Duration::from_secs(interval),
    )
    .with_audit(Arc::clone(&audit));

    // When running with bridges, apply per-user tier ceilings from the
    // same loaded IdentityConfig the bridge loops will consume, so policy
    // ceilings can never drift from the actual allowlist.
    if bridge_mode.is_some() {
        let identity_config = bridge::load_identity_config()?;
        let eval_config = bridge::evaluator_config_from_identity(&identity_config);
        conductor_builder = conductor_builder.with_evaluator_config(eval_config);
    }

    let conductor = Arc::new(conductor_builder);

    // Reconcile DB state with live runtime before entering the loop.
    do_reconcile(&conductor, &audit).await;

    let cancel = CancellationToken::new();
    let cancel_on_ctrlc = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_on_ctrlc.cancel();
        }
    });

    info!(interval_secs = interval, "sigil run starting");
    log_event(
        &audit,
        "run.start",
        "conductor",
        PolicyDecision::Allow,
        None,
    )
    .await;

    if let Some(mode) = bridge_mode {
        println!(
            "Conductor + {mode:?} bridge running (heartbeat every {interval}s). \
             Press Ctrl-C to stop.",
        );

        let bridge_conductor = Arc::clone(&conductor);
        let bridge_audit = Arc::clone(&audit);
        let bridge_cancel = cancel.clone();
        let cmd = mode.to_bridge_command();

        // Run the heartbeat loop and bridge loop concurrently.
        // When either exits (ctrl-c), the other is cancelled.
        tokio::select! {
            result = heartbeat_loop(&conductor, &audit, cancel.clone()) => {
                result?;
            }
            result = bridge::start_bridges(bridge_conductor, bridge_audit, cmd, bridge_cancel) => {
                result.context("bridge loop failed")?;
            }
        }
    } else {
        println!("Conductor running (heartbeat every {interval}s). Press Ctrl-C to stop.");
        heartbeat_loop(&conductor, &audit, cancel).await?;
    }

    log_event(&audit, "run.stop", "conductor", PolicyDecision::Allow, None).await;
    info!("sigil run stopped");
    println!("\nStopped.");
    Ok(())
}

/// Run startup reconciliation, logging results.
#[allow(clippy::print_stdout)]
async fn do_reconcile<R: SessionRuntime>(conductor: &Conductor<R>, audit: &AuditLogWriter) {
    match conductor.startup_reconcile().await {
        Ok(result) => {
            info!(
                checked = result.sessions_checked,
                corrections = result.state_corrections.len(),
                "startup reconciliation complete",
            );
            let detail = format!(
                "checked={}, corrections={}",
                result.sessions_checked,
                result.state_corrections.len(),
            );
            log_event(
                audit,
                &format!("conductor.reconcile: {detail}"),
                "conductor",
                PolicyDecision::Allow,
                None,
            )
            .await;
            if result.state_corrections.is_empty() {
                println!("Reconciliation: all sessions consistent.");
            } else {
                println!(
                    "Reconciliation: {} corrections applied.",
                    result.state_corrections.len(),
                );
            }
        }
        Err(e) => {
            // Reconciliation failure is non-fatal — log and continue.
            error!(error = %e, "startup reconciliation failed");
        }
    }
}

/// Run the heartbeat loop until the cancel token fires.
async fn heartbeat_loop<R: SessionRuntime>(
    conductor: &Conductor<R>,
    audit: &AuditLogWriter,
    cancel: CancellationToken,
) -> Result<()> {
    let mut prev_counts: Option<(usize, usize, usize, usize)> = None;

    loop {
        tokio::select! {
            () = tokio::time::sleep(conductor.heartbeat_interval()) => {
                match conductor.run_heartbeat_cycle().await {
                    Ok(result) => {
                        let counts = (result.total, result.running, result.waiting, result.error);

                        if prev_counts.as_ref() != Some(&counts) {
                            let detail = format!(
                                "total={} running={} waiting={} error={}",
                                counts.0, counts.1, counts.2, counts.3,
                            );
                            log_event(
                                audit,
                                &format!("conductor.heartbeat: {detail}"),
                                "conductor",
                                PolicyDecision::Allow,
                                None,
                            )
                            .await;
                            prev_counts = Some(counts);
                        }

                        info!(
                            total = result.total,
                            running = result.running,
                            waiting = result.waiting,
                            error = result.error,
                            "heartbeat complete"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "heartbeat cycle failed");
                    }
                }
            }
            () = cancel.cancelled() => {
                info!("received shutdown signal");
                return Ok(());
            }
        }
    }
}
