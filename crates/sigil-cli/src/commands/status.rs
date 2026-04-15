//! The `status` command — show a summary of session counts by state.
//!
//! Routes through [`ActionService`] via `Action::ListSessions` so the read
//! is policy-evaluated like every other privileged operation, even though
//! T0 reads are expected to be allowed.

use anyhow::{Context, Result, bail};

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::origin::ActionOrigin;
use sigil_core::session::SessionState;
use sigil_core::traits::{LifecycleHooks, PolicyEngine, SessionRuntime};

/// Run the status command: fetch all sessions via `ActionService`, count
/// by state, output as JSON or formatted text.
///
/// # Errors
///
/// Returns an error if policy denies the read or the dispatch fails.
#[allow(clippy::print_stdout)]
pub async fn run<R, P>(service: &ActionService<R, P>, json: bool) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);
    let outcome = service.execute(request).await.context("list sessions")?;

    let sessions = match outcome {
        ActionOutcome::Completed(DispatchResult::SessionList(sessions)) => sessions,
        ActionOutcome::Completed(_) => bail!("unexpected dispatch result for ListSessions"),
        ActionOutcome::Denied { reason } => bail!("policy denied: {reason}"),
        ActionOutcome::NeedsApproval { description } => {
            bail!("approval required: {description}")
        }
    };

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
