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

pub mod error;
pub mod escalation;
pub mod heartbeat;
pub mod memory;
pub mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sigil_core::MemoryConfig;
use sigil_core::protocol::BridgeMessage;
use sigil_core::traits::SessionRuntime;
use sigil_memory::EpisodeWriter;
use sigil_store::Store;
use tracing::{debug, info, warn};

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
/// When memory is configured via [`with_memory`](Self::with_memory),
/// the conductor captures episodes on heartbeat state transitions and
/// bridge sends, and triggers mechanical consolidation after sustained
/// idle periods.
pub struct Conductor<R: SessionRuntime> {
    store: Arc<Store>,
    runtime: Arc<R>,
    heartbeat_interval: Duration,
    memory: Option<MemoryHandle>,
}

impl<R: SessionRuntime> Conductor<R> {
    /// Create a new conductor with the given dependencies.
    #[must_use]
    pub fn new(store: Arc<Store>, runtime: Arc<R>, heartbeat_interval: Duration) -> Self {
        Self {
            store,
            runtime,
            heartbeat_interval,
            memory: None,
        }
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
    /// specified.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if command processing fails.
    pub async fn handle_message(&self, msg: &BridgeMessage) -> Result<String, ConductorError> {
        let text = msg.text.trim();

        // Check if this is a command.
        if text.starts_with('/') {
            return self.handle_command(text).await;
        }

        // Non-command message — forward to target session if specified.
        if let Some(ref session_id) = msg.target_session {
            let session = self.store.get_session(session_id).await?;
            let handle = session_to_handle(&session);
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
                if let Err(e) = memory.record_bridge_send(session.id, &session.title).await {
                    warn!(error = %e, "failed to write bridge episode");
                }
            }

            return Ok(format!("Message sent to {}.", session.title));
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

    /// Handle a slash command.
    async fn handle_command(&self, text: &str) -> Result<String, ConductorError> {
        let parts: Vec<&str> = text.splitn(3, ' ').collect();
        let command = parts.first().copied().unwrap_or_default();

        match command {
            "/status" => self.format_status().await,

            "/sessions" => {
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

            "/check" => {
                let name = parts.get(1).copied().unwrap_or_default().trim();
                if name.is_empty() {
                    return Ok("Usage: /check <session-name>".into());
                }
                let session = self.store.get_session_by_title(name).await?;
                let handle = session_to_handle(&session);
                let output = self.runtime.read_output(&handle).await.map_err(|e| {
                    ConductorError::Internal {
                        message: format!("failed to read output from {name}: {e}"),
                    }
                })?;
                // Return a brief summary: last few lines of output.
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

            "/send" => {
                let name = parts.get(1).copied().unwrap_or_default().trim();
                let message = parts.get(2).copied().unwrap_or_default().trim();
                if name.is_empty() || message.is_empty() {
                    return Ok("Usage: /send <session-name> <message>".into());
                }
                let session = self.store.get_session_by_title(name).await?;
                let handle = session_to_handle(&session);
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
}

/// Convert a `SessionRecord` to a `SessionHandle` for runtime calls.
fn session_to_handle(
    session: &sigil_core::session::SessionRecord,
) -> sigil_core::session::SessionHandle {
    sigil_core::session::SessionHandle {
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
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

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
}
