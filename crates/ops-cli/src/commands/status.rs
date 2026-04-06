//! The `status` command — show a summary of session counts by state.

use anyhow::{Context, Result};

use ops_core::session::SessionState;
use ops_store::Store;

/// Run the status command: fetch all sessions, count by state, output
/// as JSON or formatted text.
///
/// # Errors
///
/// Returns an error if the session list cannot be fetched.
#[allow(clippy::print_stdout)]
pub async fn run(store: &Store, json: bool) -> Result<()> {
    let sessions = store
        .list_sessions()
        .await
        .context("failed to list sessions")?;

    let mut running = 0u32;
    let mut waiting = 0u32;
    let mut idle = 0u32;
    let mut error = 0u32;
    let mut stopped = 0u32;

    for s in &sessions {
        #[allow(clippy::wildcard_enum_match_arm)]
        match s.state {
            SessionState::Running => running += 1,
            SessionState::Waiting => waiting += 1,
            SessionState::Idle => idle += 1,
            SessionState::Error => error += 1,
            SessionState::Stopped => stopped += 1,
            _ => {}
        }
    }

    let total = sessions.len();

    if json {
        let output = serde_json::json!({
            "total": total,
            "running": running,
            "waiting": waiting,
            "idle": idle,
            "error": error,
            "stopped": stopped,
        });
        let formatted =
            serde_json::to_string_pretty(&output).context("failed to serialize status")?;
        println!("{formatted}");
    } else {
        println!(
            "{total} sessions: {running} running, {waiting} waiting, \
             {idle} idle, {error} error, {stopped} stopped"
        );
    }

    Ok(())
}
