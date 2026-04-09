//! The `conductor` command — run the heartbeat loop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use sigil_audit::AuditLogWriter;
use sigil_conductor::Conductor;
use sigil_core::PolicyDecision;
use sigil_core::traits::SessionRuntime;
use sigil_store::Store;
use tracing::{error, info};

use crate::audit::log_event;

/// Run the conductor heartbeat loop.
///
/// Creates a `Conductor`, then loops `run_heartbeat_cycle()` every
/// `interval` seconds. Uses `tokio::select!` with a ctrl-c handler
/// for clean shutdown.
///
/// # Errors
///
/// Returns an error if the initial tmux check fails.
#[allow(clippy::print_stdout)]
pub async fn run<R: SessionRuntime>(
    store: Arc<Store>,
    runtime: Arc<R>,
    audit: Arc<AuditLogWriter>,
    interval: u64,
) -> Result<()> {
    let conductor = Conductor::new(
        Arc::clone(&store),
        Arc::clone(&runtime),
        Duration::from_secs(interval),
    );

    // Reconcile DB state against live tmux sessions before entering
    // the heartbeat loop. This catches stale state from crashes or
    // upgrades.
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
                &audit,
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

    info!(interval_secs = interval, "conductor starting");
    log_event(
        &audit,
        "conductor.start",
        "conductor",
        PolicyDecision::Allow,
        None,
    )
    .await;
    println!("Conductor running (heartbeat every {interval}s). Press Ctrl-C to stop.");

    let mut prev_counts: Option<(usize, usize, usize, usize)> = None;

    loop {
        tokio::select! {
            () = tokio::time::sleep(conductor.heartbeat_interval()) => {
                match conductor.run_heartbeat_cycle().await {
                    Ok(result) => {
                        let counts = (result.total, result.running, result.waiting, result.error);

                        // Only log an audit event when session counts change.
                        if prev_counts.as_ref() != Some(&counts) {
                            let detail = format!(
                                "total={} running={} waiting={} error={}",
                                counts.0, counts.1, counts.2, counts.3,
                            );
                            log_event(&audit, &format!("conductor.heartbeat: {detail}"), "conductor", PolicyDecision::Allow, None).await;
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
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => {
                        info!("received ctrl-c, shutting down conductor");
                        println!("\nConductor stopped.");
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e).context("failed to listen for ctrl-c signal");
                    }
                }
            }
        }
    }
}
