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

use sigil_audit::AuditLogWriter;
use sigil_content::Sanitizer;
use sigil_core::action::{Action, ActionRequest, ActionResult, PolicyDecision};
use sigil_core::content::{SanitizationRequirement, SanitizeReport};
use sigil_core::id::{GroupId, SessionId};
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{SessionConfig, SessionHandle, SessionRecord, SessionState, ToolKind};
use sigil_core::traits::{AuditEvent, LifecycleHooks, PolicyEngine, SessionRuntime};
use sigil_core::trust::ExecutionClass;
use sigil_store::Store;
use tracing::warn;

use crate::error::ConductorError;
use crate::sanitize::{DisabledFetcher, ExternalContentFetcher, fetch_and_sanitize};

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
    /// Policy allowed the action, but `ActionService` does not own its
    /// execution. The caller is responsible for performing the side effect
    /// (e.g., worktree git operations). Used for T2+ infrastructure actions.
    AuthorizedNotDispatched,
    /// External content fetched, sanitized, and ready for the caller.
    /// The cleaned text is what the agent / caller sees; the report is
    /// what the policy evaluator and audit log consume.
    ExternalContent {
        /// Sanitized text — safe to echo into an agent's context.
        text: String,
        /// Full sanitizer report for policy + audit.
        report: SanitizeReport,
    },
}

// ---------------------------------------------------------------------------
// ActionService
// ---------------------------------------------------------------------------

/// The single policy gateway for all privileged orchestration actions.
///
/// Generic over `R: SessionRuntime` and `P: PolicyEngine` so the runtime
/// and policy backends can be swapped (tmux/container, real/test evaluator).
///
/// External-content wiring: when the service is built with
/// [`with_sanitizer`](Self::with_sanitizer) (and optionally
/// [`with_fetcher`](Self::with_fetcher)), the dispatch arm for
/// [`Action::FetchExternalContent`] runs the fetched bytes through the
/// `sigil-content` pipeline, attaches the resulting `SanitizeReport`
/// to an `ActionResult`, and runs the evaluator's post-dispatch
/// `evaluate_result` gate before returning to the caller. Services
/// built without a sanitizer deny every `FetchExternalContent`
/// dispatch cleanly (no runtime panic, no silent passthrough).
pub struct ActionService<R, P> {
    policy: P,
    runtime: Arc<R>,
    audit: Arc<AuditLogWriter>,
    store: Arc<Store>,
    sanitizer: Option<Arc<Sanitizer>>,
    fetcher: Arc<dyn ExternalContentFetcher>,
}

impl<R, P> ActionService<R, P>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    /// Create a new action service with the given dependencies.
    ///
    /// The sanitizer and fetcher default to "disabled" — attempts to
    /// dispatch [`Action::FetchExternalContent`] through this service
    /// will deny cleanly. Use [`with_sanitizer`](Self::with_sanitizer)
    /// and [`with_fetcher`](Self::with_fetcher) (chained) to enable
    /// the external-content path.
    pub fn new(policy: P, runtime: Arc<R>, audit: Arc<AuditLogWriter>, store: Arc<Store>) -> Self {
        Self {
            policy,
            runtime,
            audit,
            store,
            sanitizer: None,
            fetcher: Arc::new(DisabledFetcher),
        }
    }

    /// Install a sanitizer for external-content actions. Without one,
    /// `Action::FetchExternalContent` dispatches produce a
    /// policy-compatible denial.
    #[must_use]
    pub fn with_sanitizer(mut self, sanitizer: Arc<Sanitizer>) -> Self {
        self.sanitizer = Some(sanitizer);
        self
    }

    /// Install a fetcher. The default
    /// ([`DisabledFetcher`](crate::sanitize::DisabledFetcher))
    /// returns [`FetchError::NotConfigured`](crate::sanitize::FetchError::NotConfigured)
    /// for every URL; production and test wiring replace it with a
    /// network client or a fixture-backed stub.
    #[must_use]
    pub fn with_fetcher(mut self, fetcher: Arc<dyn ExternalContentFetcher>) -> Self {
        self.fetcher = fetcher;
        self
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

        // 2. Pre-dispatch audit. For actions that produce a
        //    SanitizeReport, the report is still `None` at this point
        //    (it only exists post-dispatch); a second audit event
        //    captures it below in `finalize_sanitize_outcome`. For
        //    every other action this is the only audit entry.
        self.audit_decision(&request, &decision, None).await;

        // 3. Dispatch if allowed, building the outcome.
        let outcome = match &decision {
            PolicyDecision::Allow => {
                let result = self.dispatch(&request).await?;
                if matches!(
                    request.action.sanitization_requirement(),
                    SanitizationRequirement::Required(_)
                ) {
                    // Post-dispatch gate: check `evaluate_result` and
                    // emit a follow-up audit entry with the report
                    // attached.
                    self.finalize_sanitize_outcome(&request, result).await?
                } else {
                    ActionOutcome::Completed(result)
                }
            }
            PolicyDecision::Deny { reason } => ActionOutcome::Denied {
                reason: reason.clone(),
            },
            PolicyDecision::NeedsApproval { description } => ActionOutcome::NeedsApproval {
                description: description.clone(),
            },
        };

        Ok(outcome)
    }

    /// Post-dispatch handling for actions declaring
    /// [`SanitizationRequirement::Required`]. Extracts the report
    /// from the [`DispatchResult`], runs the evaluator's
    /// `evaluate_result` gate, and emits a second audit entry with the
    /// report attached.
    ///
    /// If the post-dispatch gate denies (presence mismatch, content-type
    /// mismatch, or — post-PR7 — threshold violation), the outcome is
    /// downgraded to [`ActionOutcome::Denied`] with the evaluator's
    /// reason.
    async fn finalize_sanitize_outcome(
        &self,
        request: &ActionRequest,
        dispatch: DispatchResult,
    ) -> Result<ActionOutcome, ConductorError> {
        // Pull the report out of the dispatch result when it carries
        // one; otherwise build an empty `ActionResult` so the evaluator
        // can still deny for "missing report" per PR6 semantics.
        let report = match &dispatch {
            DispatchResult::ExternalContent { report, .. } => Some(report.clone()),
            // A well-behaved sanitize action produces ExternalContent.
            // Anything else — e.g. a variant added without a matching
            // dispatch arm — surfaces as "missing report" through the
            // evaluator's gate below. We deliberately do not short-
            // circuit here: the evaluator owns the deny shape.
            _ => None,
        };

        let action_result = match report.clone() {
            Some(r) => ActionResult::new().with_sanitize_report(r),
            None => ActionResult::new(),
        };

        let post = self
            .policy
            .evaluate_result(request, &action_result)
            .await
            .map_err(|e| ConductorError::Internal {
                message: format!("post-dispatch policy evaluation failed: {e}"),
            })?;

        // Second audit entry: the decision carries either the original
        // `Allow` (now with the report attached) or the evaluator's
        // post-dispatch `Deny`. Either way the audit log gets the
        // report and the final verdict together.
        self.audit_decision(request, &post, report).await;

        match post {
            PolicyDecision::Allow => Ok(ActionOutcome::Completed(dispatch)),
            PolicyDecision::Deny { reason } => Ok(ActionOutcome::Denied { reason }),
            // Post-dispatch should never produce NeedsApproval (that is
            // a pre-dispatch concept), but map defensively so future
            // variants can't be silently dropped.
            PolicyDecision::NeedsApproval { description } => Ok(ActionOutcome::NeedsApproval {
                description,
            }),
        }
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
                let output = self
                    .runtime
                    .read_output(&handle)
                    .await
                    .map_err(runtime_err)?;
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
            Action::StartSession { session_id } => self.dispatch_start_session(*session_id).await,
            Action::StopSession { session_id } => self.dispatch_stop_session(*session_id).await,
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
            Action::RemoveSession { session_id } => self.dispatch_remove_session(*session_id).await,

            // --- T1 with grant: External-content fetch + sanitize ---
            Action::FetchExternalContent { url, content_type } => {
                self.dispatch_fetch_external_content(url.clone(), *content_type)
                    .await
            }

            // --- T2+: Infrastructure / Privileged ---
            // These action variants are evaluated by policy but dispatched
            // by the caller (worktree commands, host operations, etc.).
            // The ActionService ensures they went through policy.
            //
            // This list is intentionally explicit and the match uses a
            // fail-closed catch-all below rather than a wildcard so that a
            // newly added `Action` variant cannot silently look like a
            // successful authorized-but-not-dispatched execution.
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
            | Action::BreakGlass { .. } => Ok(DispatchResult::AuthorizedNotDispatched),

            // Fail closed: an unknown variant (added to `Action` but not
            // wired into this match) must not be silently reported as a
            // successful authorized dispatch.
            unknown => Err(ConductorError::Internal {
                message: format!(
                    "ActionService::dispatch: unsupported action variant {unknown:?}; \
                     add an explicit arm in action_service::dispatch()"
                ),
            }),
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

        // Register identity hooks if configured. Fail closed: roll back the
        // persisted session so we never leave behind a half-configured record
        // that policy callers believe was fully provisioned.
        if let Some(ref spec) = record.identity {
            if !spec.reload_on.is_empty() {
                let handle = record_to_handle(&record);
                if let Err(e) = self.runtime.register_identity_hooks(&handle, spec).await {
                    if let Err(rollback_err) = self.store.delete_session(&record.id).await {
                        warn!(
                            error = %rollback_err,
                            session_id = %record.id,
                            "failed to roll back session after identity hook registration error"
                        );
                    }
                    return Err(runtime_err(e));
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

        // Register identity hooks if configured. Fail closed: stop the
        // launched runtime session and remove the persisted record so we
        // never leave behind a half-configured session.
        if let Some(ref spec) = record.identity {
            if !spec.reload_on.is_empty() {
                if let Err(e) = self.runtime.register_identity_hooks(&handle, spec).await {
                    if let Err(stop_err) = self.runtime.stop(&handle).await {
                        warn!(
                            error = %stop_err,
                            session_id = %record.id,
                            "failed to stop runtime session after identity hook registration error"
                        );
                    }
                    if let Err(rollback_err) = self.store.delete_session(&record.id).await {
                        warn!(
                            error = %rollback_err,
                            session_id = %record.id,
                            "failed to roll back session after identity hook registration error"
                        );
                    }
                    return Err(runtime_err(e));
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

        // Stop if currently alive. `SessionRuntime::stop` (for tmux)
        // blocks until the backend confirms teardown so the same
        // session name can be reused immediately. A stop failure is
        // non-fatal — the relaunch will surface "duplicate session" if
        // teardown didn't happen — but we log it so the cause isn't
        // lost.
        if session.state != SessionState::Stopped {
            if let Err(err) = self.runtime.stop(&handle).await {
                warn!(
                    session = %session.title,
                    error = %err,
                    "stop during restart failed; attempting relaunch anyway",
                );
            }
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

    /// Fetch an external URL and route the bytes through the
    /// `sigil-content` sanitizer. Returns a
    /// [`DispatchResult::ExternalContent`] carrying the cleaned text
    /// and the full [`SanitizeReport`]. The post-dispatch gate in
    /// [`execute`](Self::execute) consumes the report.
    ///
    /// Failure modes, all surfaced as `ConductorError::Internal` with a
    /// descriptive message:
    ///
    /// - The service was built without `with_sanitizer` — the pipeline
    ///   cannot run, so the dispatch fails cleanly rather than
    ///   pretending to have produced sanitized bytes.
    /// - The fetcher rejects the URL (network error, `NotConfigured`,
    ///   `NotFound`, …).
    /// - The sanitizer rejects the payload (oversize, invalid UTF-8,
    ///   unsupported content type).
    async fn dispatch_fetch_external_content(
        &self,
        url: String,
        content_type: sigil_core::content::ContentType,
    ) -> Result<DispatchResult, ConductorError> {
        let sanitizer = self.sanitizer.as_ref().ok_or_else(|| {
            ConductorError::Internal {
                message: "FetchExternalContent dispatch: no sanitizer configured; \
                         build ActionService with .with_sanitizer(...) to enable"
                    .to_owned(),
            }
        })?;

        let sanitized =
            fetch_and_sanitize(self.fetcher.as_ref(), sanitizer.as_ref(), &url, content_type)
                .await?;

        Ok(DispatchResult::ExternalContent {
            text: sanitized.text,
            report: sanitized.report,
        })
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    /// Log an audit event with the real policy decision and execution context.
    ///
    /// The `sanitize_report` argument is `None` today: no dispatched
    /// variant currently produces external content. PR7 wires the
    /// conductor / MCP fetch path and starts passing a populated
    /// report here so the audit chain records the sanitizer's output
    /// alongside the decision.
    async fn audit_decision(
        &self,
        request: &ActionRequest,
        decision: &PolicyDecision,
        sanitize_report: Option<sigil_core::content::SanitizeReport>,
    ) {
        let session_id = extract_session_id(&request.action);
        let event = AuditEvent {
            request_id: request.id,
            timestamp: request.timestamp,
            action_summary: format!("{:?}", request.action),
            origin_summary: format!("{:?}", request.origin),
            decision: decision.clone(),
            session_id,
            sanitize_report,
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
        | Action::FetchExternalContent { .. }
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
    #![allow(clippy::expect_used, clippy::panic, clippy::wildcard_enum_match_arm)]

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

    // -----------------------------------------------------------------------
    // Dispatch tests — verify T2+ actions return AuthorizedNotDispatched and
    // every `execute` call produces an audit entry (allow/deny).
    // -----------------------------------------------------------------------

    use sigil_audit::AuditLogWriter;
    use sigil_core::error::CoreError;
    use sigil_core::origin::ActionOrigin;
    use sigil_core::protocol::ConductorMessage;
    use sigil_core::session::{IdentitySpec, SessionConfig, SessionHandle};

    struct StubRuntime;

    impl SessionRuntime for StubRuntime {
        async fn launch(&self, _config: &SessionConfig) -> Result<SessionHandle, CoreError> {
            Err(CoreError::Runtime {
                message: "stub: launch unused".into(),
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

    impl LifecycleHooks for StubRuntime {
        async fn register_identity_hooks(
            &self,
            _handle: &SessionHandle,
            _spec: &IdentitySpec,
        ) -> Result<(), CoreError> {
            Ok(())
        }
    }

    struct AllowPolicy;

    impl PolicyEngine for AllowPolicy {
        async fn evaluate(&self, _request: &ActionRequest) -> Result<PolicyDecision, CoreError> {
            Ok(PolicyDecision::Allow)
        }
    }

    struct DenyPolicy;

    impl PolicyEngine for DenyPolicy {
        async fn evaluate(&self, _request: &ActionRequest) -> Result<PolicyDecision, CoreError> {
            Ok(PolicyDecision::Deny {
                reason: "denied-by-test".into(),
            })
        }
    }

    async fn build_test_service<P: PolicyEngine>(
        policy: P,
    ) -> (ActionService<StubRuntime, P>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = Arc::new(
            AuditLogWriter::new(&dir.path().join("audit.jsonl"), b"t".to_vec())
                .await
                .expect("audit"),
        );
        let store = Arc::new(Store::new_in_memory().await.expect("store"));
        let runtime = Arc::new(StubRuntime);
        (ActionService::new(policy, runtime, audit, store), dir)
    }

    #[tokio::test]
    async fn create_worktree_returns_authorized_not_dispatched() {
        let (service, _dir) = build_test_service(AllowPolicy).await;
        let sid = SessionId::new();
        let request = ActionRequest::new(
            Action::CreateWorktree {
                session_id: sid,
                branch: "feature/test".into(),
            },
            ActionOrigin::LocalCli,
        );

        let outcome = service.execute(request).await.expect("execute");
        assert!(matches!(
            outcome,
            ActionOutcome::Completed(DispatchResult::AuthorizedNotDispatched)
        ));
    }

    #[tokio::test]
    async fn finish_worktree_returns_authorized_not_dispatched() {
        let (service, _dir) = build_test_service(AllowPolicy).await;
        let sid = SessionId::new();
        let request = ActionRequest::new(
            Action::FinishWorktree {
                session_id: sid,
                merge: true,
            },
            ActionOrigin::LocalCli,
        );

        let outcome = service.execute(request).await.expect("execute");
        assert!(matches!(
            outcome,
            ActionOutcome::Completed(DispatchResult::AuthorizedNotDispatched)
        ));
    }

    #[tokio::test]
    async fn t2_action_under_deny_policy_returns_denied() {
        let (service, _dir) = build_test_service(DenyPolicy).await;
        let request = ActionRequest::new(
            Action::CreateWorktree {
                session_id: SessionId::new(),
                branch: "feature/blocked".into(),
            },
            ActionOrigin::LocalCli,
        );

        let outcome = service.execute(request).await.expect("execute");
        match outcome {
            ActionOutcome::Denied { reason } => assert_eq!(reason, "denied-by-test"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_sessions_flows_through_action_service() {
        let (service, _dir) = build_test_service(AllowPolicy).await;
        let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);

        let outcome = service.execute(request).await.expect("execute");
        match outcome {
            ActionOutcome::Completed(DispatchResult::SessionList(list)) => {
                assert!(list.is_empty());
            }
            other => panic!("expected SessionList, got {other:?}"),
        }
    }
}
