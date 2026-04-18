//! sigil-conductor — Orchestration brain for agent sessions.
//!
//! This crate implements the heartbeat loop, auto-response evaluation,
//! escalation logic, child session coordination, and bridge message
//! routing. It is the central decision-maker: it reads session state
//! from `sigil-store`, checks live status via `sigil-runtime`, evaluates
//! policy through `sigil-policy`, and logs events through `sigil-audit`.
//!
//! The `Conductor` struct provides the building blocks for the main
//! run loop (wired up in `sigil-cli`).

pub mod action_service;
pub mod error;
pub mod escalation;
pub mod heartbeat;
pub mod memory;
pub mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_core::MemoryConfig;
use sigil_core::action::{Action, ActionRequest, PolicyDecision};
use sigil_core::origin::ActionOrigin;
use sigil_core::protocol::BridgeMessage;
use sigil_core::traits::{AuditEvent, SessionRuntime};
use sigil_memory::EpisodeWriter;
use sigil_policy::{EvaluatorConfig, PolicyService};
use sigil_store::Store;
use tracing::{debug, info, warn};

use crate::action_service::record_to_handle;
use crate::error::ConductorError;
use crate::escalation::format_status_report;
use crate::heartbeat::{HeartbeatResult, scan_sessions};
use crate::memory::MemoryHandle;
use crate::reconcile::{ReconcileResult, reconcile};

/// The conductor — orchestrates agent sessions.
///
/// Generic over `R: SessionRuntime` so the runtime backend can be
/// swapped (tmux today, containers in the future) without changing
/// conductor logic.
///
/// Holds shared references to the store and runtime, plus configuration
/// for the heartbeat interval. The `sigil-cli` crate wires this into an
/// async run loop with `CancellationToken` for cooperative shutdown.
///
/// Bridge commands (`/send`, `/check`, message forwarding) go through
/// the policy pipeline: `ActionRequest` → evaluate → execute → audit.
///
/// When memory is configured via [`with_memory`](Self::with_memory),
/// the conductor captures episodes on heartbeat state transitions and
/// bridge sends, and triggers mechanical consolidation after sustained
/// idle periods.
pub struct Conductor<R: SessionRuntime> {
    store: Arc<Store>,
    runtime: Arc<R>,
    /// Policy service for evaluating bridge commands.
    policy: PolicyService<Store>,
    /// Audit writer for logging bridge command decisions.
    audit: Option<Arc<AuditLogWriter>>,
    heartbeat_interval: Duration,
    memory: Option<MemoryHandle>,
}

impl<R: SessionRuntime> Conductor<R> {
    /// Create a new conductor with the given dependencies.
    #[must_use]
    pub fn new(store: Arc<Store>, runtime: Arc<R>, heartbeat_interval: Duration) -> Self {
        let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
        Self {
            store,
            runtime,
            policy,
            audit: None,
            heartbeat_interval,
            memory: None,
        }
    }

    /// Configure the audit writer for policy decision logging.
    ///
    /// When set, bridge commands are audited through the same HMAC-chained
    /// audit trail as CLI commands.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<AuditLogWriter>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Configure per-user tier ceilings for bridge identity convergence.
    ///
    /// This feeds bridge identity config (e.g., `AllowedUser.tier_ceiling`)
    /// into the policy evaluator, converging bridge and core principal
    /// resolution into a single path.
    #[must_use]
    pub fn with_evaluator_config(mut self, config: EvaluatorConfig) -> Self {
        self.policy = PolicyService::new(config, Arc::clone(&self.store));
        self
    }

    /// Configure the memory subsystem for episode capture and consolidation.
    ///
    /// When set, the conductor will:
    /// - Append `ActionCompleted` episodes when heartbeat detects state
    ///   transitions (e.g. `Running` → `Waiting`).
    /// - Append episodes when bridge messages are sent to sessions.
    /// - Track consecutive idle heartbeat cycles and trigger mechanical
    ///   consolidation when the threshold is reached.
    #[must_use]
    pub fn with_memory(
        mut self,
        writer: Arc<EpisodeWriter>,
        config: MemoryConfig,
        learnings_path: PathBuf,
    ) -> Self {
        self.memory = Some(MemoryHandle::new(writer, config, learnings_path));
        self
    }

    /// Returns the configured heartbeat interval.
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Run on startup to reconcile DB state with actual runtime state.
    ///
    /// Compares every session in the store against the live runtime
    /// backend and corrects mismatches. Call this before entering
    /// the heartbeat loop.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if reconciliation fails.
    pub async fn startup_reconcile(&self) -> Result<ReconcileResult, ConductorError> {
        info!("running startup reconciliation");
        let result = reconcile(&self.store, &self.runtime).await?;

        info!(
            checked = result.sessions_checked,
            mismatches = result.state_mismatches,
            missing = result.missing_sessions,
            orphaned = result.orphaned_sessions,
            corrections = result.state_corrections.len(),
            "reconciliation complete",
        );

        for correction in &result.state_corrections {
            info!(correction = %correction, "applied state correction");
        }

        Ok(result)
    }

    /// Run one heartbeat scan cycle.
    ///
    /// Delegates to [`scan_sessions`] and logs the result. Also runs
    /// periodic maintenance (expired grant cleanup), records episodes
    /// for state transitions, and triggers consolidation on idle.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if the scan fails.
    pub async fn run_heartbeat_cycle(&self) -> Result<HeartbeatResult, ConductorError> {
        debug!("starting heartbeat cycle");
        let result = scan_sessions(&self.store, &self.runtime).await?;

        // Periodic maintenance: clean up expired grants.
        match self.store.cleanup_expired_grants().await {
            Ok(0) => {}
            Ok(n) => info!(removed = n, "cleaned up expired grants"),
            Err(e) => warn!(error = %e, "failed to clean up expired grants"),
        }

        // Memory: episode capture and idle consolidation.
        if let Some(ref memory) = self.memory {
            // Record episodes for actionable state transitions.
            if let Err(e) = memory.record_state_changes(&result.state_changes).await {
                warn!(error = %e, "failed to record state change episodes");
            }

            // Idle detection: no sessions running or errored.
            if result.running == 0 && result.error == 0 {
                if memory.consolidation_enabled() && memory.record_idle_cycle() {
                    if let Err(e) = memory.consolidate().await {
                        warn!(error = %e, "consolidation failed");
                    }
                    memory.reset_idle_cycles();
                }
            } else {
                memory.reset_idle_cycles();
            }
        }

        info!(
            total = result.total,
            running = result.running,
            waiting = result.waiting,
            error = result.error,
            "heartbeat scan complete"
        );

        Ok(result)
    }

    /// Handle an incoming bridge message.
    ///
    /// Routes commands (messages starting with `/`) to the appropriate
    /// handler, and forwards other messages to the target session if
    /// specified. All privileged operations go through
    /// `ActionRequest` → policy evaluation → audit.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if command processing fails.
    pub async fn handle_message(&self, msg: &BridgeMessage) -> Result<String, ConductorError> {
        let text = msg.text.trim();

        // Check if this is a command.
        if text.starts_with('/') {
            return self.handle_command(text, &msg.origin).await;
        }

        // Non-command message — forward to target session if specified.
        if let Some(ref session_id) = msg.target_session {
            let session = self.store.get_session(session_id).await?;

            // Route through policy: SendMessage action.
            let request = ActionRequest::new(
                Action::SendMessage {
                    session_id: *session_id,
                    message: text.to_owned(),
                },
                msg.origin.clone(),
            );

            let decision = self.evaluate_and_audit(&request).await?;

            match decision {
                PolicyDecision::Allow => {
                    let handle = record_to_handle(&session);
                    let conductor_msg = sigil_core::protocol::ConductorMessage::TaskAssignment {
                        instructions: text.to_owned(),
                    };
                    self.runtime
                        .send(&handle, conductor_msg)
                        .await
                        .map_err(|e| ConductorError::Internal {
                            message: format!("failed to send to session {}: {e}", session.title),
                        })?;

                    if let Some(ref memory) = self.memory {
                        if let Err(e) = memory.record_bridge_send(session.id, &session.title).await
                        {
                            warn!(error = %e, "failed to write bridge episode");
                        }
                    }

                    return Ok(format!("Message sent to {}.", session.title));
                }
                PolicyDecision::Deny { reason } => {
                    return Ok(format!("Denied: {reason}"));
                }
                PolicyDecision::NeedsApproval { description } => {
                    return Ok(format!("Needs approval: {description}"));
                }
            }
        }

        Ok("No target session. Use /send <name> <msg> or try /help.".into())
    }

    /// Format the current status for display.
    ///
    /// Runs a heartbeat scan and formats the result as a status report.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if the scan fails.
    pub async fn format_status(&self) -> Result<String, ConductorError> {
        let result = scan_sessions(&self.store, &self.runtime).await?;
        Ok(format_status_report(&result))
    }

    // -----------------------------------------------------------------------
    // Policy pipeline helpers
    // -----------------------------------------------------------------------

    /// Evaluate an `ActionRequest` through the policy engine and log the
    /// decision to the audit trail. Returns the decision for the caller
    /// to act on.
    async fn evaluate_and_audit(
        &self,
        request: &ActionRequest,
    ) -> Result<PolicyDecision, ConductorError> {
        let decision = self.evaluate_policy(request).await?;

        // Audit the decision if we have a writer.
        if let Some(ref audit) = self.audit {
            let event = AuditEvent {
                request_id: request.id,
                timestamp: request.timestamp,
                action_summary: format!("{:?}", request.action),
                origin_summary: format!("{:?}", request.origin),
                decision: decision.clone(),
                session_id: action_service::extract_session_id(&request.action),
                sanitize_report: None,
            };
            if let Err(e) = audit.append(&event).await {
                warn!(error = %e, "failed to write audit event");
            }
        }

        Ok(decision)
    }

    /// Evaluate a request through the policy engine without writing an
    /// audit entry. Used for T0 reads where the audit would be pure noise.
    async fn evaluate_policy(
        &self,
        request: &ActionRequest,
    ) -> Result<PolicyDecision, ConductorError> {
        use sigil_core::PolicyEngine;

        self.policy
            .evaluate(request)
            .await
            .map_err(|e| ConductorError::Internal {
                message: format!("policy evaluation failed: {e}"),
            })
    }

    /// Evaluate a request and audit it iff the decision is not `Allow`.
    /// Used for T0 reads so routine allowed traffic stays out of the audit
    /// log while denials and approval prompts are still recorded.
    async fn evaluate_with_non_allow_audit(
        &self,
        request: &ActionRequest,
    ) -> Result<PolicyDecision, ConductorError> {
        let decision = self.evaluate_policy(request).await?;

        if !matches!(decision, PolicyDecision::Allow) {
            if let Some(ref audit) = self.audit {
                let event = AuditEvent {
                    request_id: request.id,
                    timestamp: request.timestamp,
                    action_summary: format!("{:?}", request.action),
                    origin_summary: format!("{:?}", request.origin),
                    decision: decision.clone(),
                    session_id: action_service::extract_session_id(&request.action),
                    sanitize_report: None,
                };
                if let Err(e) = audit.append(&event).await {
                    warn!(error = %e, "failed to write audit event");
                }
            }
        }

        Ok(decision)
    }

    /// Handle a slash command routed from a bridge message.
    async fn handle_command(
        &self,
        text: &str,
        origin: &ActionOrigin,
    ) -> Result<String, ConductorError> {
        let parts: Vec<&str> = text.splitn(3, ' ').collect();
        let command = parts.first().copied().unwrap_or_default();

        match command {
            "/status" => self.cmd_status(origin).await,
            "/sessions" => self.cmd_sessions(origin).await,
            "/check" => {
                let name = parts.get(1).copied().unwrap_or_default().trim();
                self.cmd_check(name, origin).await
            }
            "/send" => {
                let name = parts.get(1).copied().unwrap_or_default().trim();
                let message = parts.get(2).copied().unwrap_or_default().trim();
                self.cmd_send(name, message, origin).await
            }
            "/help" => Ok("Commands:\n\
                 /status - Show session overview\n\
                 /sessions - List all sessions with state\n\
                 /check <name> - Read recent output from a session\n\
                 /send <name> <msg> - Send a message to a session\n\
                 /help - Show this help"
                .into()),
            _ => Ok(format!("Unknown command: {command}. Try /help.")),
        }
    }

    /// T0 read: list sessions. Evaluated through policy so bridge reads
    /// honor the same pipeline as mutating commands. To keep audit volume
    /// manageable we skip audit entries for allowed reads (the common case)
    /// but do record denials and approval prompts — those are the events
    /// worth investigating later.
    async fn cmd_sessions(&self, origin: &ActionOrigin) -> Result<String, ConductorError> {
        let request = ActionRequest::new(Action::ListSessions, origin.clone());
        let decision = self.evaluate_with_non_allow_audit(&request).await?;

        match decision {
            PolicyDecision::Allow => {
                let sessions = self.store.list_sessions().await?;
                if sessions.is_empty() {
                    return Ok("No sessions.".into());
                }
                let mut lines = Vec::with_capacity(sessions.len());
                for s in &sessions {
                    lines.push(format!(
                        "- {} [{:?}] ({})",
                        s.title,
                        s.state,
                        s.path.display()
                    ));
                }
                Ok(lines.join("\n"))
            }
            PolicyDecision::Deny { reason } => Ok(format!("Denied: {reason}")),
            PolicyDecision::NeedsApproval { description } => {
                Ok(format!("Needs approval: {description}"))
            }
        }
    }

    /// T0 read: overall status report. Same policy-evaluated / audit-on-
    /// denial treatment as [`cmd_sessions`].
    async fn cmd_status(&self, origin: &ActionOrigin) -> Result<String, ConductorError> {
        let request = ActionRequest::new(Action::GetSystemStatus, origin.clone());
        let decision = self.evaluate_with_non_allow_audit(&request).await?;

        match decision {
            PolicyDecision::Allow => self.format_status().await,
            PolicyDecision::Deny { reason } => Ok(format!("Denied: {reason}")),
            PolicyDecision::NeedsApproval { description } => {
                Ok(format!("Needs approval: {description}"))
            }
        }
    }

    async fn cmd_check(&self, name: &str, origin: &ActionOrigin) -> Result<String, ConductorError> {
        if name.is_empty() {
            return Ok("Usage: /check <session-name>".into());
        }
        let session = self.store.get_session_by_title(name).await?;

        let request = ActionRequest::new(
            Action::ReadSessionOutput {
                session_id: session.id,
            },
            origin.clone(),
        );
        let decision = self.evaluate_and_audit(&request).await?;

        match decision {
            PolicyDecision::Allow => {
                let handle = record_to_handle(&session);
                let output = self.runtime.read_output(&handle).await.map_err(|e| {
                    ConductorError::Internal {
                        message: format!("failed to read output from {name}: {e}"),
                    }
                })?;
                let last_lines: String = output
                    .lines()
                    .rev()
                    .take(10)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(format!("{name} [{:?}]:\n{last_lines}", session.state))
            }
            PolicyDecision::Deny { reason } => Ok(format!("Denied: {reason}")),
            PolicyDecision::NeedsApproval { description } => {
                Ok(format!("Needs approval: {description}"))
            }
        }
    }

    async fn cmd_send(
        &self,
        name: &str,
        message: &str,
        origin: &ActionOrigin,
    ) -> Result<String, ConductorError> {
        if name.is_empty() || message.is_empty() {
            return Ok("Usage: /send <session-name> <message>".into());
        }
        let session = self.store.get_session_by_title(name).await?;

        let request = ActionRequest::new(
            Action::SendMessage {
                session_id: session.id,
                message: message.to_owned(),
            },
            origin.clone(),
        );
        let decision = self.evaluate_and_audit(&request).await?;

        match decision {
            PolicyDecision::Allow => {
                let handle = record_to_handle(&session);
                let conductor_msg = sigil_core::protocol::ConductorMessage::TaskAssignment {
                    instructions: message.to_owned(),
                };
                self.runtime
                    .send(&handle, conductor_msg)
                    .await
                    .map_err(|e| ConductorError::Internal {
                        message: format!("failed to send to {name}: {e}"),
                    })?;

                if let Some(ref memory) = self.memory {
                    if let Err(e) = memory.record_bridge_send(session.id, name).await {
                        warn!(error = %e, "failed to write bridge episode");
                    }
                }

                Ok(format!("Sent to {name}."))
            }
            PolicyDecision::Deny { reason } => Ok(format!("Denied: {reason}")),
            PolicyDecision::NeedsApproval { description } => {
                Ok(format!("Needs approval: {description}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::wildcard_enum_match_arm,
        clippy::doc_markdown
    )]

    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use sigil_core::SessionId;
    use sigil_core::error::CoreError;
    use sigil_core::origin::ActionOrigin;
    use sigil_core::protocol::{BridgeMessage, ConductorMessage, ReplyContext};
    use sigil_core::session::{SessionConfig, SessionHandle, SessionRecord, SessionState};
    use sigil_core::traits::SessionRuntime;
    use sigil_core::trust::ExecutionClass;
    use sigil_store::Store;

    /// A mock runtime that returns fixed state and output for any session.
    struct MockRuntime {
        state: SessionState,
        output: String,
    }

    impl MockRuntime {
        fn new(state: SessionState, output: &str) -> Self {
            Self {
                state,
                output: output.into(),
            }
        }
    }

    impl SessionRuntime for MockRuntime {
        async fn launch(&self, _config: &SessionConfig) -> Result<SessionHandle, CoreError> {
            Err(CoreError::Runtime {
                message: "mock: launch not implemented".into(),
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
            Ok(self.output.clone())
        }

        async fn status(&self, _handle: &SessionHandle) -> Result<SessionState, CoreError> {
            Ok(self.state)
        }

        async fn stop(&self, _handle: &SessionHandle) -> Result<(), CoreError> {
            Ok(())
        }
    }

    /// Helper to create a bridge message for tests.
    fn command_msg(text: &str) -> BridgeMessage {
        BridgeMessage {
            origin: ActionOrigin::LocalCli,
            text: text.into(),
            target_session: None,
            is_command: text.starts_with('/'),
            reply_context: ReplyContext::default(),
        }
    }

    fn msg_with_target(text: &str, target: SessionId) -> BridgeMessage {
        BridgeMessage {
            origin: ActionOrigin::LocalCli,
            text: text.into(),
            target_session: Some(target),
            is_command: false,
            reply_context: ReplyContext::default(),
        }
    }

    fn make_session(title: &str, state: SessionState) -> SessionRecord {
        SessionRecord {
            id: SessionId::new(),
            title: title.into(),
            path: PathBuf::from("/tmp/test"),
            tool: sigil_core::ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state,
            identity: None,
        }
    }

    async fn setup_conductor(
        sessions: &[SessionRecord],
        runtime_state: SessionState,
        runtime_output: &str,
    ) -> (super::Conductor<MockRuntime>, Arc<Store>) {
        let store = Arc::new(Store::new_in_memory().await.expect("store init"));
        for s in sessions {
            store.create_session(s).await.expect("create session");
        }
        let runtime = Arc::new(MockRuntime::new(runtime_state, runtime_output));
        let conductor = super::Conductor::new(Arc::clone(&store), runtime, Duration::from_secs(30));
        (conductor, store)
    }

    // -- Command parsing tests --

    #[test]
    fn command_parsing_status() {
        let msg = command_msg("/status");
        assert!(msg.text.starts_with('/'));
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/status"));
    }

    #[test]
    fn command_parsing_sessions() {
        let msg = command_msg("/sessions");
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/sessions"));
    }

    #[test]
    fn command_parsing_check_with_name() {
        let msg = command_msg("/check frontend");
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/check"));
        assert_eq!(parts.get(1).copied(), Some("frontend"));
    }

    #[test]
    fn command_parsing_send_with_name_and_message() {
        let msg = command_msg("/send api-server use the staging database");
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/send"));
        assert_eq!(parts.get(1).copied(), Some("api-server"));
        assert_eq!(parts.get(2).copied(), Some("use the staging database"));
    }

    #[test]
    fn command_parsing_help() {
        let msg = command_msg("/help");
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/help"));
    }

    #[test]
    fn command_parsing_unknown() {
        let msg = command_msg("/foobar");
        assert!(msg.text.starts_with('/'));
        let parts: Vec<&str> = msg.text.splitn(3, ' ').collect();
        assert_eq!(parts.first().copied(), Some("/foobar"));
    }

    #[test]
    fn non_command_not_detected() {
        let msg = command_msg("just a regular message");
        assert!(!msg.text.starts_with('/'));
    }

    // -- Integration tests with mock runtime --

    #[tokio::test]
    async fn help_command_lists_all_commands() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/help");
        let response = conductor.handle_message(&msg).await.expect("/help");
        assert!(response.contains("/status"));
        assert!(response.contains("/sessions"));
        assert!(response.contains("/check"));
        assert!(response.contains("/send"));
        assert!(response.contains("/help"));
    }

    #[tokio::test]
    async fn sessions_command_empty_store() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/sessions");
        let response = conductor.handle_message(&msg).await.expect("/sessions");
        assert_eq!(response, "No sessions.");
    }

    #[tokio::test]
    async fn sessions_command_lists_all() {
        let s1 = make_session("frontend", SessionState::Running);
        let s2 = make_session("api-server", SessionState::Waiting);
        let (conductor, _) = setup_conductor(&[s1, s2], SessionState::Running, "").await;

        let msg = command_msg("/sessions");
        let response = conductor.handle_message(&msg).await.expect("/sessions");
        assert!(response.contains("frontend"));
        assert!(response.contains("api-server"));
        assert!(response.contains("Running"));
        assert!(response.contains("Waiting"));
    }

    #[tokio::test]
    async fn status_command_returns_formatted_report() {
        let s1 = make_session("frontend", SessionState::Running);
        let s2 = make_session("backend", SessionState::Running);
        let (conductor, _) = setup_conductor(&[s1, s2], SessionState::Running, "").await;

        let msg = command_msg("/status");
        let response = conductor.handle_message(&msg).await.expect("/status");
        assert!(response.contains("STATUS"));
        assert!(response.contains('2'));
    }

    #[tokio::test]
    async fn check_command_returns_session_output() {
        let s = make_session("frontend", SessionState::Running);
        let output = "line 1\nline 2\nline 3\nline 4\nline 5";
        let (conductor, _) = setup_conductor(&[s], SessionState::Running, output).await;

        let msg = command_msg("/check frontend");
        let response = conductor.handle_message(&msg).await.expect("/check");
        assert!(response.contains("frontend"));
        assert!(response.contains("Running"));
        assert!(response.contains("line 1"));
        assert!(response.contains("line 5"));
    }

    #[tokio::test]
    async fn check_command_missing_name_shows_usage() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/check");
        let response = conductor.handle_message(&msg).await.expect("/check usage");
        assert!(response.contains("Usage"));
    }

    #[tokio::test]
    async fn send_command_forwards_to_session() {
        let s = make_session("api-server", SessionState::Running);
        let (conductor, _) = setup_conductor(&[s], SessionState::Running, "").await;

        let msg = command_msg("/send api-server run the migration");
        let response = conductor.handle_message(&msg).await.expect("/send");
        assert!(response.contains("Sent to api-server"));
    }

    #[tokio::test]
    async fn send_command_missing_args_shows_usage() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/send");
        let response = conductor.handle_message(&msg).await.expect("/send usage");
        assert!(response.contains("Usage"));
    }

    #[tokio::test]
    async fn send_command_missing_message_shows_usage() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/send api-server");
        let response = conductor.handle_message(&msg).await.expect("/send usage");
        assert!(response.contains("Usage"));
    }

    /// `/sessions` from a bridge origin now flows through policy. Default
    /// `EvaluatorConfig` allows T0 reads, so the session list is returned
    /// — the important guarantee is that the response is shape-compatible
    /// with the prior direct-store path.
    #[tokio::test]
    async fn sessions_command_allows_bridge_origin_under_default_policy() {
        let s = make_session("frontend", SessionState::Running);
        let (conductor, _) = setup_conductor(&[s], SessionState::Running, "").await;

        let msg = BridgeMessage {
            origin: ActionOrigin::BridgeTelegram {
                user_id: "some-user".into(),
            },
            text: "/sessions".into(),
            target_session: None,
            is_command: true,
            reply_context: ReplyContext::default(),
        };
        let response = conductor.handle_message(&msg).await.expect("/sessions");
        assert!(response.contains("frontend"));
    }

    /// `/status` from a bridge origin also flows through policy and is
    /// allowed for T0 reads under the default config.
    #[tokio::test]
    async fn status_command_allows_bridge_origin_under_default_policy() {
        let s = make_session("frontend", SessionState::Running);
        let (conductor, _) = setup_conductor(&[s], SessionState::Running, "").await;

        let msg = BridgeMessage {
            origin: ActionOrigin::BridgeTelegram {
                user_id: "some-user".into(),
            },
            text: "/status".into(),
            target_session: None,
            is_command: true,
            reply_context: ReplyContext::default(),
        };
        let response = conductor.handle_message(&msg).await.expect("/status");
        assert!(response.contains("STATUS"));
    }

    #[tokio::test]
    async fn unknown_command_suggests_help() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("/foobar");
        let response = conductor.handle_message(&msg).await.expect("unknown cmd");
        assert!(response.contains("Unknown command"));
        assert!(response.contains("/help"));
    }

    #[tokio::test]
    async fn non_command_with_target_forwards_to_session() {
        let s = make_session("frontend", SessionState::Running);
        let session_id = s.id;
        let (conductor, _) = setup_conductor(&[s], SessionState::Running, "").await;

        let msg = msg_with_target("do the thing", session_id);
        let response = conductor.handle_message(&msg).await.expect("forward");
        assert!(response.contains("Message sent to frontend"));
    }

    #[tokio::test]
    async fn non_command_without_target_shows_help() {
        let (conductor, _) = setup_conductor(&[], SessionState::Running, "").await;
        let msg = command_msg("just a regular message");
        let response = conductor.handle_message(&msg).await.expect("no target");
        assert!(response.contains("/help") || response.contains("/send"));
    }

    // -- evaluate_with_non_allow_audit --
    //
    // These tests pin the noise-reduction contract added in PR #41:
    // allowed T0 bridge reads stay out of the audit log; denials and
    // approval prompts still land there with full context. We exercise
    // the helper directly (private, same-crate access) so the deny /
    // needs-approval branches are reachable without a policy engine
    // mock — the real evaluator naturally produces those decisions for
    // ceiling-busting requests like `BridgeSlack` + `ReadHostFile`.

    use sigil_audit::AuditLogWriter;
    use sigil_core::action::{Action, ActionRequest, PolicyDecision};

    async fn setup_conductor_with_audit(
        sessions: &[SessionRecord],
    ) -> (
        super::Conductor<MockRuntime>,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(
            AuditLogWriter::new(&audit_path, b"bridge-deny-test-key".to_vec())
                .await
                .expect("audit writer"),
        );
        let store = Arc::new(Store::new_in_memory().await.expect("store init"));
        for s in sessions {
            store.create_session(s).await.expect("create session");
        }
        let runtime = Arc::new(MockRuntime::new(SessionState::Running, ""));
        let conductor = super::Conductor::new(Arc::clone(&store), runtime, Duration::from_secs(30))
            .with_audit(audit);
        (conductor, audit_path, dir)
    }

    async fn audit_line_count(path: &std::path::Path) -> usize {
        tokio::fs::read_to_string(path)
            .await
            .map_or(0, |s| s.lines().filter(|l| !l.is_empty()).count())
    }

    /// Read the last chained entry's event payload as generic JSON. Returning
    /// `serde_json::Value` lets each test assert on just the fields it cares
    /// about without pulling a `ChainedEntry` type through the test boundary.
    async fn last_audit_event(path: &std::path::Path) -> serde_json::Value {
        let contents = tokio::fs::read_to_string(path).await.expect("read audit");
        let last = contents
            .lines()
            .rfind(|l| !l.is_empty())
            .expect("audit log should have at least one entry");
        let entry: serde_json::Value = serde_json::from_str(last).expect("entry is json");
        entry
            .get("event")
            .cloned()
            .expect("chained entry must have event field")
    }

    fn decision_from_event(event: &serde_json::Value) -> PolicyDecision {
        let decision = event
            .get("decision")
            .cloned()
            .expect("event.decision present");
        serde_json::from_value(decision).expect("decision deserializes")
    }

    /// T0 bridge read through `/sessions`: under default policy this is
    /// allowed, so the helper must NOT write to the audit log.
    #[tokio::test]
    async fn sessions_command_allowed_bridge_read_does_not_audit() {
        let s = make_session("frontend", SessionState::Running);
        let (conductor, audit_path, _dir) = setup_conductor_with_audit(&[s]).await;
        let msg = BridgeMessage {
            origin: ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            text: "/sessions".into(),
            target_session: None,
            is_command: true,
            reply_context: ReplyContext::default(),
        };
        let response = conductor.handle_message(&msg).await.expect("/sessions");
        assert!(response.contains("frontend"));
        assert_eq!(
            audit_line_count(&audit_path).await,
            0,
            "allowed T0 bridge read should not produce an audit entry",
        );
    }

    /// Same no-audit-on-Allow contract for `/status`.
    #[tokio::test]
    async fn status_command_allowed_bridge_read_does_not_audit() {
        let s = make_session("frontend", SessionState::Running);
        let (conductor, audit_path, _dir) = setup_conductor_with_audit(&[s]).await;
        let msg = BridgeMessage {
            origin: ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            text: "/status".into(),
            target_session: None,
            is_command: true,
            reply_context: ReplyContext::default(),
        };
        let _ = conductor.handle_message(&msg).await.expect("/status");
        assert_eq!(
            audit_line_count(&audit_path).await,
            0,
            "allowed T0 bridge read should not produce an audit entry",
        );
    }

    /// Deny branch: the helper must write the denial to the audit log with
    /// the real `Deny { reason }` preserved, plus matching request context
    /// (request_id / action_summary / origin_summary). Context assertions
    /// guard against a regression where the helper audits the right verdict
    /// but attaches it to a mismatched request.
    #[tokio::test]
    async fn evaluate_with_non_allow_audit_records_deny() {
        let (conductor, audit_path, _dir) = setup_conductor_with_audit(&[]).await;
        // BridgeSlack Paul → T1 ceiling, ReadHostFile is T3 → Deny.
        let req = ActionRequest::new(
            Action::ReadHostFile {
                path: PathBuf::from("/etc/passwd"),
            },
            ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
        );
        let expected_request_id = req.id;
        let decision = conductor
            .evaluate_with_non_allow_audit(&req)
            .await
            .expect("evaluate");
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "expected Deny, got {decision:?}",
        );
        assert_eq!(
            audit_line_count(&audit_path).await,
            1,
            "deny should produce exactly one audit entry",
        );

        let event = last_audit_event(&audit_path).await;
        match decision_from_event(&event) {
            PolicyDecision::Deny { reason } => {
                assert!(
                    reason.contains("ceiling"),
                    "deny reason should mention tier ceiling: {reason}",
                );
            }
            other => panic!("audit entry should carry Deny, got {other:?}"),
        }
        let request_id = event
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .expect("event.request_id is a string");
        assert_eq!(
            request_id,
            expected_request_id.to_string(),
            "audit entry must carry the originating request_id",
        );
        let action_summary = event
            .get("action_summary")
            .and_then(serde_json::Value::as_str)
            .expect("event.action_summary is a string");
        assert!(
            action_summary.contains("ReadHostFile"),
            "action_summary should reflect the action: {action_summary}",
        );
        let origin_summary = event
            .get("origin_summary")
            .and_then(serde_json::Value::as_str)
            .expect("event.origin_summary is a string");
        assert!(
            origin_summary.contains("BridgeSlack"),
            "origin_summary should reflect the origin: {origin_summary}",
        );
    }

    /// NeedsApproval branch: LocalCli + T3 read has ceiling but still
    /// requires explicit approval. The helper must audit these too, with
    /// the originating request's context preserved.
    #[tokio::test]
    async fn evaluate_with_non_allow_audit_records_needs_approval() {
        let (conductor, audit_path, _dir) = setup_conductor_with_audit(&[]).await;
        let req = ActionRequest::new(
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
            ActionOrigin::LocalCli,
        );
        let expected_request_id = req.id;
        let decision = conductor
            .evaluate_with_non_allow_audit(&req)
            .await
            .expect("evaluate");
        assert!(
            matches!(decision, PolicyDecision::NeedsApproval { .. }),
            "expected NeedsApproval, got {decision:?}",
        );
        assert_eq!(
            audit_line_count(&audit_path).await,
            1,
            "NeedsApproval should produce exactly one audit entry",
        );

        let event = last_audit_event(&audit_path).await;
        match decision_from_event(&event) {
            PolicyDecision::NeedsApproval { description } => {
                assert!(
                    description.contains("approval"),
                    "description should mention approval: {description}",
                );
            }
            other => panic!("audit entry should carry NeedsApproval, got {other:?}"),
        }
        let request_id = event
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .expect("event.request_id is a string");
        assert_eq!(request_id, expected_request_id.to_string());
        let origin_summary = event
            .get("origin_summary")
            .and_then(serde_json::Value::as_str)
            .expect("event.origin_summary is a string");
        assert!(
            origin_summary.contains("LocalCli"),
            "origin_summary should reflect the origin: {origin_summary}",
        );
    }

    /// Allow branch: direct invocation of the helper with an allowed
    /// request must leave the audit log untouched.
    #[tokio::test]
    async fn evaluate_with_non_allow_audit_skips_audit_on_allow() {
        let (conductor, audit_path, _dir) = setup_conductor_with_audit(&[]).await;
        let req = ActionRequest::new(
            Action::ListSessions,
            ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
        );
        let decision = conductor
            .evaluate_with_non_allow_audit(&req)
            .await
            .expect("evaluate");
        assert!(
            matches!(decision, PolicyDecision::Allow),
            "expected Allow, got {decision:?}",
        );
        assert_eq!(
            audit_line_count(&audit_path).await,
            0,
            "allowed request must not produce an audit entry",
        );
    }
}
