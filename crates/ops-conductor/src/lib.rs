//! ops-conductor — Orchestration brain for agent sessions.
//!
//! This crate implements the heartbeat loop, auto-response evaluation,
//! escalation logic, child session coordination, and bridge message
//! routing. It is the central decision-maker: it reads session state
//! from `ops-store`, checks live status via `ops-runtime`, evaluates
//! policy through `ops-policy`, and logs events through `ops-audit`.
//!
//! The `Conductor` struct provides the building blocks for the main
//! run loop (wired up in `ops-cli`).

pub mod error;
pub mod escalation;
pub mod heartbeat;

use std::sync::Arc;
use std::time::Duration;

use ops_core::protocol::BridgeMessage;
use ops_core::traits::SessionRuntime;
use ops_runtime::TmuxRuntime;
use ops_store::Store;
use tracing::{debug, info};

use crate::error::ConductorError;
use crate::escalation::format_status_report;
use crate::heartbeat::{HeartbeatResult, scan_sessions};

/// The conductor — orchestrates agent sessions.
///
/// Holds shared references to the store and runtime, plus configuration
/// for the heartbeat interval. The `ops-cli` crate wires this into an
/// async run loop with `CancellationToken` for cooperative shutdown.
pub struct Conductor {
    store: Arc<Store>,
    runtime: Arc<TmuxRuntime>,
    heartbeat_interval: Duration,
}

impl Conductor {
    /// Create a new conductor with the given dependencies.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        runtime: Arc<TmuxRuntime>,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            store,
            runtime,
            heartbeat_interval,
        }
    }

    /// Returns the configured heartbeat interval.
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Run one heartbeat scan cycle.
    ///
    /// Delegates to [`scan_sessions`] and logs the result.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError`] if the scan fails.
    pub async fn run_heartbeat_cycle(&self) -> Result<HeartbeatResult, ConductorError> {
        debug!("starting heartbeat cycle");
        let result = scan_sessions(&self.store, &self.runtime).await?;

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
    pub async fn handle_message(
        &self,
        msg: &BridgeMessage,
    ) -> Result<String, ConductorError> {
        let text = msg.text.trim();

        // Check if this is a command.
        if text.starts_with('/') {
            return self.handle_command(text).await;
        }

        // Non-command message — forward to target session if specified.
        if let Some(ref session_id) = msg.target_session {
            let session = self.store.get_session(session_id).await?;
            let handle = session_to_handle(&session);
            let conductor_msg = ops_core::protocol::ConductorMessage::TaskAssignment {
                instructions: text.to_owned(),
            };
            self.runtime.send(&handle, conductor_msg).await.map_err(|e| {
                ConductorError::Internal {
                    message: format!("failed to send to session {}: {e}", session.title),
                }
            })?;
            return Ok(format!("Message sent to {}.", session.title));
        }

        Ok("Message received.".into())
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
                    lines.push(format!("- {} [{:?}] ({})", s.title, s.state, s.path.display()));
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
                Ok(format!(
                    "{name} [{:?}]:\n{last_lines}",
                    session.state
                ))
            }

            "/send" => {
                let name = parts.get(1).copied().unwrap_or_default().trim();
                let message = parts.get(2).copied().unwrap_or_default().trim();
                if name.is_empty() || message.is_empty() {
                    return Ok("Usage: /send <session-name> <message>".into());
                }
                let session = self.store.get_session_by_title(name).await?;
                let handle = session_to_handle(&session);
                let conductor_msg = ops_core::protocol::ConductorMessage::TaskAssignment {
                    instructions: message.to_owned(),
                };
                self.runtime.send(&handle, conductor_msg).await.map_err(|e| {
                    ConductorError::Internal {
                        message: format!("failed to send to {name}: {e}"),
                    }
                })?;
                Ok(format!("Sent to {name}."))
            }

            "/help" => Ok(
                "Commands:\n\
                 /status - Show session overview\n\
                 /sessions - List all sessions with state\n\
                 /check <name> - Read recent output from a session\n\
                 /send <name> <msg> - Send a message to a session\n\
                 /help - Show this help"
                    .into(),
            ),

            _ => Ok(format!("Unknown command: {command}. Try /help.")),
        }
    }
}

/// Convert a `SessionRecord` to a `SessionHandle` for runtime calls.
fn session_to_handle(session: &ops_core::session::SessionRecord) -> ops_core::session::SessionHandle {
    ops_core::session::SessionHandle {
        id: session.id,
        title: session.title.clone(),
        tool: session.tool,
        state: session.state,
        path: session.path.clone(),
        tmux_window: Some(session.title.clone()),
        container_id: None,
        execution_class: session.execution_class,
        sandboxed: session.sandboxed,
    }
}

#[cfg(test)]
mod tests {
    use ops_core::origin::ActionOrigin;
    use ops_core::protocol::BridgeMessage;

    /// Helper to create a bridge message for command tests.
    fn command_msg(text: &str) -> BridgeMessage {
        BridgeMessage {
            origin: ActionOrigin::LocalCli,
            text: text.into(),
            target_session: None,
            is_command: text.starts_with('/'),
        }
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
        assert_eq!(
            parts.get(2).copied(),
            Some("use the staging database")
        );
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
}
