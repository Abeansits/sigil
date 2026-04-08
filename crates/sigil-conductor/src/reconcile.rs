//! Crash recovery — reconcile DB state against live runtime sessions.
//!
//! When the conductor restarts (crash, upgrade, etc.), the persisted
//! session states in `SQLite` may be stale. This module compares each
//! stored session against the runtime backend and corrects mismatches.

use std::fmt;
use std::sync::Arc;

use sigil_core::session::{SessionHandle, SessionState};
use sigil_core::traits::SessionRuntime;
use sigil_store::Store;
use tracing::{info, warn};

use crate::error::ConductorError;

/// Summary of a startup reconciliation pass.
#[derive(Clone, Debug, Default)]
pub struct ReconcileResult {
    pub sessions_checked: usize,
    /// DB said running but runtime says stopped (or vice versa).
    pub state_mismatches: usize,
    /// In runtime but not in DB (future use — not yet detected).
    pub orphaned_sessions: usize,
    /// In DB but runtime session is gone.
    pub missing_sessions: usize,
    pub state_corrections: Vec<StateCorrection>,
}

/// A single state correction applied during reconciliation.
#[derive(Clone, Debug)]
pub struct StateCorrection {
    pub session_title: String,
    pub old_state: SessionState,
    pub new_state: SessionState,
    pub reason: String,
}

impl fmt::Display for StateCorrection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?} -> {:?} ({})",
            self.session_title, self.old_state, self.new_state, self.reason,
        )
    }
}

/// Reconcile the store's session states against the live runtime backend.
///
/// For each session in the DB:
/// - If the DB says `Running`/`Waiting`/`Idle` but runtime has no such
///   session, update to `Error`.
/// - If the DB says `Running` but runtime reports `Stopped`, update to
///   `Stopped`.
/// - If the DB says `Stopped` but runtime shows the session alive, update
///   to `Running`.
///
/// Sessions already in `Error` state are left alone (they need manual
/// attention).
///
/// # Errors
///
/// Returns [`ConductorError::Store`] if the session list cannot be
/// fetched or a state update fails.
pub async fn reconcile<R: SessionRuntime>(
    store: &Arc<Store>,
    runtime: &Arc<R>,
) -> Result<ReconcileResult, ConductorError> {
    let sessions = store.list_sessions().await?;
    let mut result = ReconcileResult {
        sessions_checked: sessions.len(),
        ..ReconcileResult::default()
    };

    for session in &sessions {
        let handle = SessionHandle {
            id: session.id,
            title: session.title.clone(),
            tool: session.tool,
            state: session.state,
            path: session.path.clone(),
            tmux_window: Some(session.title.clone()),
            container_id: None,
            execution_class: session.execution_class,
            sandboxed: session.sandboxed,
        };

        let live_state = match runtime.status(&handle).await {
            Ok(state) => state,
            Err(_) => {
                // Runtime session doesn't exist or is unreachable.
                SessionState::Error
            }
        };

        if let Some(correction) = detect_mismatch(session.state, live_state, &session.title) {
            apply_correction(store, &session.id, &correction, &mut result).await;
        }
    }

    Ok(result)
}

/// Compare stored vs. live state and return a correction if they
/// disagree.
fn detect_mismatch(
    stored: SessionState,
    live: SessionState,
    title: &str,
) -> Option<StateCorrection> {
    match (stored, live) {
        // DB thinks it's alive, but runtime says it's gone.
        (
            SessionState::Running | SessionState::Waiting | SessionState::Idle,
            SessionState::Error,
        ) => Some(StateCorrection {
            session_title: title.to_owned(),
            old_state: stored,
            new_state: SessionState::Error,
            reason: "runtime session not found".into(),
        }),

        // DB thinks it's running, but runtime says stopped.
        (SessionState::Running, SessionState::Stopped) => Some(StateCorrection {
            session_title: title.to_owned(),
            old_state: stored,
            new_state: SessionState::Stopped,
            reason: "runtime reports session stopped".into(),
        }),

        // DB thinks it's stopped, but runtime shows it alive.
        (
            SessionState::Stopped,
            SessionState::Running | SessionState::Waiting | SessionState::Idle,
        ) => Some(StateCorrection {
            session_title: title.to_owned(),
            old_state: SessionState::Stopped,
            new_state: SessionState::Running,
            reason: "runtime session is alive but DB says stopped".into(),
        }),

        // Already in error or states agree — no correction needed.
        _ => None,
    }
}

/// Persist a correction to the store and update the result counters.
async fn apply_correction(
    store: &Arc<Store>,
    session_id: &sigil_core::id::SessionId,
    correction: &StateCorrection,
    result: &mut ReconcileResult,
) {
    info!(
        session = %correction.session_title,
        old = ?correction.old_state,
        new = ?correction.new_state,
        reason = %correction.reason,
        "reconcile: correcting session state",
    );

    if let Err(e) = store
        .update_session_state(session_id, correction.new_state)
        .await
    {
        warn!(
            session = %correction.session_title,
            error = %e,
            "reconcile: failed to update session state",
        );
        return;
    }

    // Categorize the correction.
    if correction.new_state == SessionState::Error {
        result.missing_sessions += 1;
    }
    result.state_mismatches += 1;
    result.state_corrections.push(correction.clone());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    // -- ReconcileResult default --

    #[test]
    fn reconcile_result_default_is_zeroed() {
        let r = ReconcileResult::default();
        assert_eq!(r.sessions_checked, 0);
        assert_eq!(r.state_mismatches, 0);
        assert_eq!(r.orphaned_sessions, 0);
        assert_eq!(r.missing_sessions, 0);
        assert!(r.state_corrections.is_empty());
    }

    // -- StateCorrection fields --

    #[test]
    fn state_correction_stores_fields_correctly() {
        let c = StateCorrection {
            session_title: "my-session".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Error,
            reason: "runtime session not found".into(),
        };
        assert_eq!(c.session_title, "my-session");
        assert_eq!(c.old_state, SessionState::Running);
        assert_eq!(c.new_state, SessionState::Error);
        assert_eq!(c.reason, "runtime session not found");
    }

    #[test]
    fn state_correction_display_is_readable() {
        let c = StateCorrection {
            session_title: "api-server".into(),
            old_state: SessionState::Running,
            new_state: SessionState::Stopped,
            reason: "runtime reports session stopped".into(),
        };
        let display = format!("{c}");
        assert!(display.contains("api-server"));
        assert!(display.contains("Running"));
        assert!(display.contains("Stopped"));
    }

    // -- detect_mismatch tests --

    #[test]
    fn detect_mismatch_running_vs_error_returns_correction() {
        let result = detect_mismatch(SessionState::Running, SessionState::Error, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.new_state, SessionState::Error);
    }

    #[test]
    fn detect_mismatch_waiting_vs_error_returns_correction() {
        let result = detect_mismatch(SessionState::Waiting, SessionState::Error, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.old_state, SessionState::Waiting);
        assert_eq!(c.new_state, SessionState::Error);
    }

    #[test]
    fn detect_mismatch_idle_vs_error_returns_correction() {
        let result = detect_mismatch(SessionState::Idle, SessionState::Error, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.old_state, SessionState::Idle);
        assert_eq!(c.new_state, SessionState::Error);
    }

    #[test]
    fn detect_mismatch_running_vs_stopped_returns_correction() {
        let result = detect_mismatch(SessionState::Running, SessionState::Stopped, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.new_state, SessionState::Stopped);
    }

    #[test]
    fn detect_mismatch_stopped_vs_running_returns_correction() {
        let result = detect_mismatch(SessionState::Stopped, SessionState::Running, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.old_state, SessionState::Stopped);
        assert_eq!(c.new_state, SessionState::Running);
    }

    #[test]
    fn detect_mismatch_stopped_vs_waiting_returns_correction() {
        let result = detect_mismatch(SessionState::Stopped, SessionState::Waiting, "test");
        assert!(result.is_some());
        let c = result.expect("correction");
        assert_eq!(c.new_state, SessionState::Running);
    }

    #[test]
    fn detect_mismatch_running_vs_running_returns_none() {
        let result = detect_mismatch(SessionState::Running, SessionState::Running, "test");
        assert!(result.is_none());
    }

    #[test]
    fn detect_mismatch_stopped_vs_stopped_returns_none() {
        let result = detect_mismatch(SessionState::Stopped, SessionState::Stopped, "test");
        assert!(result.is_none());
    }

    #[test]
    fn detect_mismatch_error_vs_anything_returns_none() {
        // Sessions already in error are not touched.
        let result = detect_mismatch(SessionState::Error, SessionState::Running, "test");
        assert!(result.is_none());
        let result = detect_mismatch(SessionState::Error, SessionState::Error, "test");
        assert!(result.is_none());
    }

    // -- ReconcileResult accumulation --

    #[test]
    fn reconcile_result_with_no_sessions_is_empty() {
        let r = ReconcileResult {
            sessions_checked: 0,
            ..ReconcileResult::default()
        };
        assert_eq!(r.sessions_checked, 0);
        assert_eq!(r.state_mismatches, 0);
        assert!(r.state_corrections.is_empty());
    }
}
