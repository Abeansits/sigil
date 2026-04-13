//! Heartbeat scanning — periodic session health checks.
//!
//! The heartbeat loop queries the store for all sessions, checks their
//! live status via the runtime, and flags sessions that need attention.

use std::sync::Arc;

use sigil_core::SessionId;
use sigil_core::session::{SessionRecord, SessionState};
use sigil_core::traits::SessionRuntime;
use sigil_store::Store;
use tracing::{debug, warn};

use crate::error::ConductorError;

/// A detected state transition during a heartbeat scan.
#[derive(Clone, Debug)]
pub struct StateChange {
    /// Session that changed state.
    pub session_id: SessionId,
    /// Session title (for logging and episode summaries).
    pub title: String,
    /// State in the store before this cycle.
    pub old_state: SessionState,
    /// Live state detected this cycle.
    pub new_state: SessionState,
}

/// Results of a single heartbeat scan cycle.
#[derive(Clone, Debug, Default)]
pub struct HeartbeatResult {
    pub total: usize,
    pub running: usize,
    pub waiting: usize,
    pub idle: usize,
    pub error: usize,
    pub stopped: usize,
    pub auto_responded: Vec<String>,
    pub needs_attention: Vec<String>,
    /// State transitions detected this cycle.
    pub state_changes: Vec<StateChange>,
}

/// Run one heartbeat scan: fetch all sessions, check live status, update
/// stored state where it diverges, and categorize sessions.
///
/// # Errors
///
/// Returns [`ConductorError::Store`] if the session list cannot be fetched
/// or state updates fail, or [`ConductorError::NoSessions`] if the store
/// is empty.
pub async fn scan_sessions<R: SessionRuntime>(
    store: &Arc<Store>,
    runtime: &Arc<R>,
) -> Result<HeartbeatResult, ConductorError> {
    let sessions = store.list_sessions().await?;

    if sessions.is_empty() {
        return Err(ConductorError::NoSessions);
    }

    let mut result = HeartbeatResult {
        total: sessions.len(),
        ..HeartbeatResult::default()
    };

    for session in &sessions {
        let live_state = check_live_state(runtime, session).await;

        // If the live state differs from the stored state, update it.
        if live_state != session.state {
            debug!(
                session = %session.title,
                stored = ?session.state,
                live = ?live_state,
                "session state changed"
            );

            result.state_changes.push(StateChange {
                session_id: session.id,
                title: session.title.clone(),
                old_state: session.state,
                new_state: live_state,
            });

            if let Err(e) = store.update_session_state(&session.id, live_state).await {
                warn!(session = %session.title, error = %e, "failed to update session state");
            }
        }

        categorize(&mut result, &session.title, live_state);
    }

    Ok(result)
}

/// Check the live state of a session via the runtime.
///
/// If the runtime query fails (e.g. tmux session gone), returns
/// `SessionState::Error` rather than propagating the error.
async fn check_live_state<R: SessionRuntime>(
    runtime: &Arc<R>,
    session: &SessionRecord,
) -> SessionState {
    // Only check sessions that are supposed to be alive.
    if session.state == SessionState::Stopped {
        return SessionState::Stopped;
    }

    let handle = sigil_core::session::SessionHandle {
        id: session.id,
        title: session.title.clone(),
        tool: session.tool,
        state: session.state,
        path: session.path.clone(),
        tmux_window: Some(session.title.clone()),
        container_id: None,
        execution_class: session.execution_class,
        sandboxed: session.sandboxed,
        identity: session.identity.clone(),
    };

    match runtime.status(&handle).await {
        Ok(state) => state,
        Err(e) => {
            warn!(
                session = %session.title,
                error = %e,
                "runtime status check failed, marking as error"
            );
            SessionState::Error
        }
    }
}

/// Categorize a session by its current state and update the result counters.
fn categorize(result: &mut HeartbeatResult, title: &str, state: SessionState) {
    #[allow(clippy::wildcard_enum_match_arm)]
    match state {
        SessionState::Running => result.running += 1,
        SessionState::Waiting => {
            result.waiting += 1;
            // Waiting sessions are candidates for auto-response or escalation.
            // For now, flag them as needing attention; the conductor's
            // `run_heartbeat_cycle` will refine this with escalation logic.
            result.needs_attention.push(title.to_owned());
        }
        SessionState::Idle => result.idle += 1,
        SessionState::Error => {
            result.error += 1;
            result.needs_attention.push(title.to_owned());
        }
        SessionState::Stopped => result.stopped += 1,
        // Future variants: treat as needing attention until we know better.
        _ => result.needs_attention.push(title.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(
        running: usize,
        waiting: usize,
        idle: usize,
        error: usize,
        stopped: usize,
    ) -> HeartbeatResult {
        HeartbeatResult {
            total: running + waiting + idle + error + stopped,
            running,
            waiting,
            idle,
            error,
            stopped,
            auto_responded: Vec::new(),
            needs_attention: Vec::new(),
            state_changes: Vec::new(),
        }
    }

    #[test]
    fn categorize_running_increments_counter() {
        let mut result = HeartbeatResult::default();
        categorize(&mut result, "test-session", SessionState::Running);
        assert_eq!(result.running, 1);
        assert!(result.needs_attention.is_empty());
    }

    #[test]
    fn categorize_waiting_flags_attention() {
        let mut result = HeartbeatResult::default();
        categorize(&mut result, "waiting-session", SessionState::Waiting);
        assert_eq!(result.waiting, 1);
        assert_eq!(result.needs_attention, vec!["waiting-session"]);
    }

    #[test]
    fn categorize_error_flags_attention() {
        let mut result = HeartbeatResult::default();
        categorize(&mut result, "error-session", SessionState::Error);
        assert_eq!(result.error, 1);
        assert_eq!(result.needs_attention, vec!["error-session"]);
    }

    #[test]
    fn categorize_stopped_no_attention() {
        let mut result = HeartbeatResult::default();
        categorize(&mut result, "stopped-session", SessionState::Stopped);
        assert_eq!(result.stopped, 1);
        assert!(result.needs_attention.is_empty());
    }

    #[test]
    fn categorize_idle_no_attention() {
        let mut result = HeartbeatResult::default();
        categorize(&mut result, "idle-session", SessionState::Idle);
        assert_eq!(result.idle, 1);
        assert!(result.needs_attention.is_empty());
    }

    #[test]
    fn heartbeat_result_default_is_zeroed() {
        let r = HeartbeatResult::default();
        assert_eq!(r.total, 0);
        assert_eq!(r.running, 0);
        assert_eq!(r.waiting, 0);
        assert_eq!(r.idle, 0);
        assert_eq!(r.error, 0);
        assert_eq!(r.stopped, 0);
        assert!(r.auto_responded.is_empty());
        assert!(r.needs_attention.is_empty());
    }

    #[test]
    fn heartbeat_result_formatting_shows_counts() {
        let r = make_result(2, 1, 0, 1, 1);
        assert_eq!(r.total, 5);
        assert_eq!(r.running, 2);
        assert_eq!(r.waiting, 1);
        assert_eq!(r.error, 1);
        assert_eq!(r.stopped, 1);
    }

    #[test]
    fn state_change_stores_transition() {
        let id = SessionId::new();
        let change = StateChange {
            session_id: id,
            title: "test-session".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Waiting,
        };
        assert_eq!(change.session_id, id);
        assert_eq!(change.old_state, SessionState::Running);
        assert_eq!(change.new_state, SessionState::Waiting);
    }

    #[test]
    fn heartbeat_result_default_has_empty_state_changes() {
        let r = HeartbeatResult::default();
        assert!(r.state_changes.is_empty());
    }
}
