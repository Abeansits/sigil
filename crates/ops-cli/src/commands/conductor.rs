//! The `conductor` command — run the heartbeat loop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ops_conductor::Conductor;
use ops_runtime::TmuxRuntime;
use ops_store::Store;
use tracing::{error, info};

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
pub async fn run(store: Arc<Store>, runtime: Arc<TmuxRuntime>, interval: u64) -> Result<()> {
    TmuxRuntime::check_tmux()
        .await
        .context("tmux is required for the conductor")?;

    let conductor = Conductor::new(
        Arc::clone(&store),
        Arc::clone(&runtime),
        Duration::from_secs(interval),
    );

    info!(interval_secs = interval, "conductor starting");
    println!("Conductor running (heartbeat every {interval}s). Press Ctrl-C to stop.");

    loop {
        tokio::select! {
            () = tokio::time::sleep(conductor.heartbeat_interval()) => {
                match conductor.run_heartbeat_cycle().await {
                    Ok(result) => {
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
