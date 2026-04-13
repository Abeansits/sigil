//! `ActionService` — the single policy gateway for all privileged actions.
//!
//! Every privileged orchestration path flows through
//! [`ActionService::execute()`]:
//!
//! 1. Build an [`ActionRequest`]
//! 2. Evaluate policy via [`PolicyEngine`]
//! 3. If allowed, dispatch to the runtime / store
//! 4. Log the real decision to the audit trail
//!
//! No more "call runtime then log allowed."

use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_core::action::{Action, ActionRequest, PolicyDecision};
use sigil_core::id::{GroupId, SessionId};
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{SessionConfig, SessionHandle, SessionRecord, SessionState, ToolKind};
use sigil_core::traits::{AuditEvent, LifecycleHooks, PolicyEngine, SessionRuntime};
use sigil_core::trust::ExecutionClass;
use sigil_store::Store;
use tracing::warn;

use crate::error::ConductorError;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The outcome of executing an action through the pipeline.
#[derive(Debug)]
pub enum ActionOutcome {
    /// Action was allowed and the dispatch completed.
    Completed(DispatchResult),
    /// Action was denied by the policy engine.
    Denied { reason: String },
    /// Action requires human approval (pending grant).
    NeedsApproval { description: String },
}

/// Data returned from a successfully dispatched action.
#[derive(Debug)]
#[non_exhaustive]
pub enum DispatchResult {
    /// A session record (create, show, start, stop, restart, remove).
    Session(SessionRecord),
    /// A list of sessions.
    SessionList(Vec<SessionRecord>),
    /// Text output (session output, status report, etc.).
    Text(String),
    /// Simple confirmation with no data payload.
    Done,
}

// ---------------------------------------------------------------------------
// ActionService
// ---------------------------------------------------------------------------

/// The single policy gateway for all privileged orchestration actions.
///
/// Generic over `R: SessionRuntime` and `P: PolicyEngine` so the runtime
/// and policy backends can be swapped (tmux/container, real/test evaluator).
pub struct ActionService<R, P> {
    policy: P,
    runtime: Arc<R>,
    audit: Arc<AuditLogWriter>,
    store: Arc<Store>,
}

impl<R, P> ActionService<R, P>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    /// Create a new action service with the given dependencies.
    pub fn new(policy: P, runtime: Arc<R>, audit: Arc<AuditLogWriter>, store: Arc<Store>) -> Self {
        Self {
            policy,
            runtime,
            audit,
            store,
        }
    }

    /// Execute an action through the full pipeline:
    /// policy evaluation → dispatch (if allowed) → audit.
    ///
    /// This is the **only** entry point for privileged operations.
    /// All callers (CLI, conductor, bridge) use this method.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if policy evaluation fails with an
    /// internal error, or if the dispatch itself fails. Policy denials
    /// and approval-needed results are returned as [`ActionOutcome`],
    /// not as errors.
    pub async fn execute(&self, request: ActionRequest) -> Result<ActionOutcome, ConductorError> {
        // 1. Evaluate policy.
        let decision =
            self.policy
                .evaluate(&request)
                .await
                .map_err(|e| ConductorError::Internal {
                    message: format!("policy evaluation failed: {e}"),
                })?;

        // 2. Dispatch if allowed, building the outcome.
        let outcome = match &decision {
            PolicyDecision::Allow => {
                let result = self.dispatch(&request).await?;
                ActionOutcome::Completed(result)
            }
            PolicyDecision::Deny { reason } => ActionOutcome::Denied {
                reason: reason.clone(),
            },
            PolicyDecision::NeedsApproval { description } => ActionOutcome::NeedsApproval {
                description: description.clone(),
            },
        };

        // 3. Audit — log the real decision (not hardcoded Allow).
        self.audit_decision(&request, &decision).await;

        Ok(outcome)
    }

    /// Expose the store for read-only operations that callers may need
    /// outside the action pipeline (e.g., session resolution by title
    /// before building an `ActionRequest`).
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Expose the runtime for internal control-loop operations
    /// (heartbeat status checks, etc.) that use `ActionOrigin::SystemHeartbeat`.
    #[must_use]
    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    // -----------------------------------------------------------------------
    // Dispatch — execute the action against runtime / store
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_lines)] // dispatch covers all Action variants
    async fn dispatch(&self, request: &ActionRequest) -> Result<DispatchResult, ConductorError> {
        match &request.action {
            // --- T0: Read ---
            Action::ListSessions => {
                let sessions = self.store.list_sessions().await?;
                Ok(DispatchResult::SessionList(sessions))
            }
            Action::GetSessionStatus { session_id } => {
                let session = self.store.get_session(session_id).await?;
                let handle = record_to_handle(&session);
                let state = self.runtime.status(&handle).await.map_err(runtime_err)?;
                Ok(DispatchResult::Text(format!(
                    "{} [{state:?}]",
                    session.title
                )))
            }
            Action::ReadSessionOutput { session_id } => {
                let session = self.store.get_session(session_id).await?;
                let handle = record_to_handle(&session);
                let output = self.runtime.read_output(&handle).await.map_err(runtime_err)?;
                Ok(DispatchResult::Text(output))
            }
            Action::ListGroups => {
                let sessions = self.store.list_sessions().await?;
                let mut groups: Vec<String> = sessions
                    .iter()
                    .filter_map(|s| s.group.as_ref().map(std::string::ToString::to_string))
                    .collect();
                groups.sort();
                groups.dedup();
                Ok(DispatchResult::Text(groups.join("\n")))
            }
            Action::GetSystemStatus => {
                let sessions = self.store.list_sessions().await?;
                let running = sessions
                    .iter()
                    .filter(|s| s.state == SessionState::Running)
                    .count();
                let total = sessions.len();
                Ok(DispatchResult::Text(format!(
                    "{running}/{total} sessions running"
                )))
            }

            // --- T1: Operate ---
            Action::CreateSession {
                path,
                title,
                group,
                tool,
                identity,
            } => {
                self.dispatch_create_session(
                    path.clone(),
                    title.clone(),
                    *tool,
                    group.clone(),
                    identity.clone(),
                )
                .await
            }
            Action::LaunchSession {
                path,
                title,
                tool,
                group,
                message,
                identity,
            } => {
                self.dispatch_launch_session(
                    path.clone(),
                    title.clone(),
                    *tool,
                    group.clone(),
                    message.clone(),
                    identity.clone(),
                )
                .await
            }
            Action::StartSession { session_id } => {
                self.dispatch_start_session(*session_id).await
            }
            Action::StopSession { session_id } => {
                self.dispatch_stop_session(*session_id).await
            }
            Action::RestartSession { session_id } => {
                self.dispatch_restart_session(*session_id).await
            }
            Action::SendMessage {
                session_id,
                message,
            } => {
                self.dispatch_send_message(*session_id, message.clone())
                    .await
            }
            Action::RemoveSession { session_id } => {
                self.dispatch_remove_session(*session_id).await
            }

            // --- T2+: Infrastructure / Privileged ---
            // These action variants are evaluated by policy but dispatched
            // by the caller (worktree commands, host operations, etc.).
            // The ActionService ensures they went through policy.
            Action::CreateWorktree { .. }
            | Action::FinishWorktree { .. }
            | Action::SetSessionParent { .. }
            | Action::RenameSession { .. }
            | Action::MoveSessionToGroup { .. }
            | Action::ConfigureConductor { .. }
            | Action::ReadHostFile { .. }
            | Action::WriteHostFile { .. }
            | Action::ModifyGitState { .. }
            | Action::ExecuteHostCommand { .. }
            | Action::RestartService { .. }
            | Action::ExternalNetworkWrite { .. }
            | Action::BreakGlass { .. }
            // Future variants: policy-approved but not dispatched here.
            | _ => Ok(DispatchResult::Done),
        }
    }

    // -----------------------------------------------------------------------
    // Session dispatch helpers
    // -----------------------------------------------------------------------

    async fn dispatch_create_session(
        &self,
        path: std::path::PathBuf,
        title: String,
        tool: ToolKind,
        group: Option<GroupId>,
        identity: Option<sigil_core::session::IdentitySpec>,
    ) -> Result<DispatchResult, ConductorError> {
        let record = SessionRecord {
            id: SessionId::new(),
            title,
            path,
            tool,
            group,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
            identity,
        };

        self.store.create_session(&record).await?;

        // Register identity hooks if configured.
        if let Some(ref spec) = record.identity {
            if !spec.reload_on.is_empty() {
                let handle = record_to_handle(&record);
                if let Err(e) = self.runtime.register_identity_hooks(&handle, spec).await {
                    warn!(error = %e, "failed to register identity hooks");
                }
            }
        }

        Ok(DispatchResult::Session(record))
    }

    async fn dispatch_launch_session(
        &self,
        path: std::path::PathBuf,
        title: String,
        tool: ToolKind,
        group: Option<GroupId>,
        message: Option<String>,
        identity: Option<sigil_core::session::IdentitySpec>,
    ) -> Result<DispatchResult, ConductorError> {
        let config = SessionConfig {
            path,
            title,
            tool,
            group: group.clone(),
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            initial_message: message,
            worktree_branch: None,
            identity,
            memory: None,
        };

        let handle = self.runtime.launch(&config).await.map_err(runtime_err)?;

        let record = SessionRecord {
            id: handle.id,
            title: handle.title.clone(),
            path: handle.path.clone(),
            tool: handle.tool,
            group,
            parent: None,
            execution_class: handle.execution_class,
            sandboxed: handle.sandboxed,
            state: handle.state,
            identity: handle.identity.clone(),
        };

        self.store.create_session(&record).await?;

        // Register identity hooks if configured.
        if let Some(ref spec) = record.identity {
            if !spec.reload_on.is_empty() {
                if let Err(e) = self.runtime.register_identity_hooks(&handle, spec).await {
                    warn!(error = %e, "failed to register identity hooks");
                }
            }
        }

        Ok(DispatchResult::Session(record))
    }

    async fn dispatch_start_session(
        &self,
        session_id: SessionId,
    ) -> Result<DispatchResult, ConductorError> {
        let session = self.store.get_session(&session_id).await?;

        if session.state != SessionState::Stopped {
            return Err(ConductorError::Internal {
                message: format!(
                    "session '{}' is {:?}, not Stopped — cannot start",
                    session.title, session.state
                ),
            });
        }

        let config = SessionConfig {
            path: session.path.clone(),
            title: session.title.clone(),
            tool: session.tool,
            group: session.group.clone(),
            parent: session.parent,
            execution_class: session.execution_class,
            sandboxed: session.sandboxed,
            initial_message: None,
            worktree_branch: None,
            identity: session.identity.clone(),
            memory: None,
        };

        self.runtime.launch(&config).await.map_err(runtime_err)?;

        self.store
            .update_session_state(&session.id, SessionState::Running)
            .await?;

        let updated = self.store.get_session(&session.id).await?;
        Ok(DispatchResult::Session(updated))
    }

    async fn dispatch_stop_session(
        &self,
        session_id: SessionId,
    ) -> Result<DispatchResult, ConductorError> {
        let session = self.store.get_session(&session_id).await?;
        let handle = record_to_handle(&session);

        self.runtime.stop(&handle).await.map_err(runtime_err)?;

        self.store
            .update_session_state(&session.id, SessionState::Stopped)
            .await?;

        let updated = self.store.get_session(&session.id).await?;
        Ok(DispatchResult::Session(updated))
    }

    async fn dispatch_restart_session(
        &self,
        session_id: SessionId,
    ) -> Result<DispatchResult, ConductorError> {
        let session = self.store.get_session(&session_id).await?;
        let handle = record_to_handle(&session);

        // Stop if currently alive.
        if session.state != SessionState::Stopped {
            let _ = self.runtime.stop(&handle).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        let config = SessionConfig {
            path: session.path.clone(),
            title: session.title.clone(),
            tool: session.tool,
            group: session.group.clone(),
            parent: session.parent,
            execution_class: session.execution_class,
            sandboxed: session.sandboxed,
            initial_message: None,
            worktree_branch: None,
            identity: session.identity.clone(),
            memory: None,
        };

        self.runtime.launch(&config).await.map_err(runtime_err)?;

        self.store
            .update_session_state(&session.id, SessionState::Running)
            .await?;

        let updated = self.store.get_session(&session.id).await?;
        Ok(DispatchResult::Session(updated))
    }

    async fn dispatch_send_message(
        &self,
        session_id: SessionId,
        message: String,
    ) -> Result<DispatchResult, ConductorError> {
        let session = self.store.get_session(&session_id).await?;
        let handle = record_to_handle(&session);

        let conductor_msg = ConductorMessage::TaskAssignment {
            instructions: message,
        };

        self.runtime
            .send(&handle, conductor_msg)
            .await
            .map_err(runtime_err)?;

        Ok(DispatchResult::Done)
    }

    async fn dispatch_remove_session(
        &self,
        session_id: SessionId,
    ) -> Result<DispatchResult, ConductorError> {
        let session = self.store.get_session(&session_id).await?;
        self.store.delete_session(&session.id).await?;
        Ok(DispatchResult::Session(session))
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    /// Log an audit event with the real policy decision and execution context.
    async fn audit_decision(&self, request: &ActionRequest, decision: &PolicyDecision) {
        let session_id = extract_session_id(&request.action);
        let event = AuditEvent {
            request_id: request.id,
            timestamp: request.timestamp,
            action_summary: format!("{:?}", request.action),
            origin_summary: format!("{:?}", request.origin),
            decision: decision.clone(),
            session_id,
        };

        if let Err(e) = self.audit.append(&event).await {
            warn!(
                error = %e,
                request_id = %request.id,
                "failed to write audit event"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `SessionRecord` to a `SessionHandle` for runtime calls.
pub fn record_to_handle(record: &SessionRecord) -> SessionHandle {
    SessionHandle {
        id: record.id,
        title: record.title.clone(),
        tool: record.tool,
        state: record.state,
        path: record.path.clone(),
        tmux_window: Some(record.title.clone()),
        container_id: None,
        execution_class: record.execution_class,
        sandboxed: record.sandboxed,
        identity: record.identity.clone(),
    }
}

/// Extract the session ID from an action, if applicable.
pub fn extract_session_id(action: &Action) -> Option<SessionId> {
    match action {
        Action::GetSessionStatus { session_id }
        | Action::ReadSessionOutput { session_id }
        | Action::StartSession { session_id }
        | Action::StopSession { session_id }
        | Action::RestartSession { session_id }
        | Action::SendMessage { session_id, .. }
        | Action::RemoveSession { session_id }
        | Action::CreateWorktree { session_id, .. }
        | Action::FinishWorktree { session_id, .. }
        | Action::SetSessionParent { session_id, .. }
        | Action::RenameSession { session_id, .. }
        | Action::MoveSessionToGroup { session_id, .. } => Some(*session_id),
        Action::ListSessions
        | Action::ListGroups
        | Action::GetSystemStatus
        | Action::CreateSession { .. }
        | Action::LaunchSession { .. }
        | Action::ConfigureConductor { .. }
        | Action::ReadHostFile { .. }
        | Action::WriteHostFile { .. }
        | Action::ModifyGitState { .. }
        | Action::ExecuteHostCommand { .. }
        | Action::RestartService { .. }
        | Action::ExternalNetworkWrite { .. }
        | Action::BreakGlass { .. }
        // Future variants without session IDs.
        | _ => None,
    }
}

/// Convert a `CoreError` from runtime calls into `ConductorError`.
#[allow(clippy::needless_pass_by_value)] // map_err requires FnOnce(E)
fn runtime_err(e: sigil_core::CoreError) -> ConductorError {
    ConductorError::Internal {
        message: format!("runtime: {e}"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;

    use sigil_core::session::ToolKind;

    use super::*;

    /// Verify `extract_session_id` returns the right ID for session actions.
    #[test]
    fn extract_session_id_from_session_actions() {
        let sid = SessionId::new();

        let actions_with_id = [
            Action::GetSessionStatus { session_id: sid },
            Action::ReadSessionOutput { session_id: sid },
            Action::StartSession { session_id: sid },
            Action::StopSession { session_id: sid },
            Action::RestartSession { session_id: sid },
            Action::SendMessage {
                session_id: sid,
                message: "test".into(),
            },
            Action::RemoveSession { session_id: sid },
        ];

        for action in &actions_with_id {
            assert_eq!(
                extract_session_id(action),
                Some(sid),
                "failed for {action:?}"
            );
        }
    }

    #[test]
    fn extract_session_id_returns_none_for_global_actions() {
        let global = [
            Action::ListSessions,
            Action::ListGroups,
            Action::GetSystemStatus,
        ];

        for action in &global {
            assert_eq!(
                extract_session_id(action),
                None,
                "should be None for {action:?}"
            );
        }
    }

    #[test]
    fn record_to_handle_preserves_fields() {
        let record = SessionRecord {
            id: SessionId::new(),
            title: "test-session".into(),
            path: PathBuf::from("/tmp/test"),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Running,
            identity: None,
        };

        let handle = record_to_handle(&record);
        assert_eq!(handle.id, record.id);
        assert_eq!(handle.title, record.title);
        assert_eq!(handle.tool, record.tool);
        assert_eq!(handle.state, record.state);
        assert_eq!(handle.path, record.path);
        assert_eq!(handle.tmux_window, Some(record.title.clone()));
    }

    /// Verify that `ActionOutcome` variants can be constructed.
    #[test]
    fn action_outcome_construction() {
        let completed = ActionOutcome::Completed(DispatchResult::Done);
        assert!(matches!(
            completed,
            ActionOutcome::Completed(DispatchResult::Done)
        ));

        let denied = ActionOutcome::Denied {
            reason: "test".into(),
        };
        assert!(matches!(denied, ActionOutcome::Denied { .. }));

        let needs = ActionOutcome::NeedsApproval {
            description: "test".into(),
        };
        assert!(matches!(needs, ActionOutcome::NeedsApproval { .. }));
    }
}
