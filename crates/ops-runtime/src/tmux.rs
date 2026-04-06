use std::time::Duration;

use ops_core::error::CoreError;
use ops_core::protocol::ConductorMessage;
use ops_core::session::{SessionConfig, SessionHandle, SessionState, ToolKind};
use ops_core::traits::{SessionRuntime, ToolAdapter};
use tokio::process::Command;
use tracing::debug;

use crate::adapter;
use crate::error::RuntimeError;

/// Manages agent sessions via tmux.
///
/// Each session is a tmux window inside a server named `server_name`
/// (default `"agent-ops"`). All tmux interaction goes through the
/// `run_tmux` helper so that the server name is always passed via `-L`.
pub struct TmuxRuntime {
    server_name: String,
}

impl TmuxRuntime {
    /// Create a runtime using the given tmux server name.
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }

    /// Verify that tmux is installed and reachable.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError::TmuxNotFound` if the binary is missing or
    /// the version cannot be determined.
    pub async fn check_tmux() -> Result<(), RuntimeError> {
        let output = Command::new("tmux")
            .arg("-V")
            .output()
            .await
            .map_err(|_| RuntimeError::TmuxNotFound)?;

        if !output.status.success() {
            return Err(RuntimeError::TmuxNotFound);
        }
        Ok(())
    }

    /// Run an arbitrary tmux command against this server, returning stdout.
    async fn run_tmux(&self, args: &[&str]) -> Result<String, RuntimeError> {
        let output = Command::new("tmux")
            .arg("-L")
            .arg(&self.server_name)
            .args(args)
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let command = format!("tmux -L {} {}", self.server_name, args.join(" "));
            Err(RuntimeError::TmuxCommand { command, stderr })
        }
    }

    /// Return the appropriate `ToolAdapter` for the given tool kind.
    fn get_adapter(tool: ToolKind) -> Box<dyn ToolAdapter> {
        adapter::adapter_for(tool)
    }
}

impl SessionRuntime for TmuxRuntime {
    async fn launch(&self, config: &SessionConfig) -> Result<SessionHandle, CoreError> {
        let path_str = config
            .path
            .to_str()
            .ok_or_else(|| CoreError::InvalidConfig {
                message: "session path is not valid UTF-8".to_owned(),
            })?;

        // Create a new tmux session (detached) with the title as the
        // session name and the working directory set to `config.path`.
        self.run_tmux(&["new-session", "-d", "-s", &config.title, "-c", path_str])
            .await?;

        debug!(title = %config.title, path = %config.path.display(), "launched tmux session");

        // If there is an initial message, send it.
        if let Some(ref msg) = config.initial_message {
            let adapter = Self::get_adapter(config.tool);
            let translated = adapter.translate_send(&ConductorMessage::TaskAssignment {
                instructions: msg.clone(),
            });
            if !translated.is_empty() {
                self.run_tmux(&["send-keys", "-t", &config.title, &translated, "Enter"])
                    .await?;
            }
        }

        Ok(SessionHandle {
            id: ops_core::id::SessionId::new(),
            title: config.title.clone(),
            tool: config.tool,
            state: SessionState::Running,
            path: config.path.clone(),
            tmux_window: Some(config.title.clone()),
            container_id: None,
            execution_class: config.execution_class,
            sandboxed: config.sandboxed,
        })
    }

    async fn send(&self, handle: &SessionHandle, msg: ConductorMessage) -> Result<(), CoreError> {
        let adapter = Self::get_adapter(handle.tool);
        let translated = adapter.translate_send(&msg);

        // Pings translate to empty — nothing to send.
        if translated.is_empty() {
            return Ok(());
        }

        self.run_tmux(&["send-keys", "-t", &handle.title, &translated, "Enter"])
            .await?;

        debug!(title = %handle.title, "sent message to tmux session");
        Ok(())
    }

    async fn read_output(&self, handle: &SessionHandle) -> Result<String, CoreError> {
        let output = self
            .run_tmux(&["capture-pane", "-t", &handle.title, "-p", "-S", "-100"])
            .await?;
        Ok(output)
    }

    async fn status(&self, handle: &SessionHandle) -> Result<SessionState, CoreError> {
        // First check whether the tmux session exists at all.
        let list_result = self
            .run_tmux(&[
                "list-windows",
                "-t",
                &format!("{}:{}", self.server_name, handle.title),
                "-F",
                "#{window_activity}",
            ])
            .await;

        if list_result.is_err() {
            return Ok(SessionState::Error);
        }

        // Session exists — capture pane and let the adapter detect state.
        let output = self
            .run_tmux(&["capture-pane", "-t", &handle.title, "-p", "-S", "-100"])
            .await?;

        let adapter = Self::get_adapter(handle.tool);
        let signals = adapter.parse_output(&output);

        // Use the first status signal if any, otherwise default to Running.
        for signal in signals {
            if let ops_core::AgentSignal::StatusUpdate { state } = signal {
                return Ok(state);
            }
        }

        Ok(SessionState::Running)
    }

    async fn stop(&self, handle: &SessionHandle) -> Result<(), CoreError> {
        // Send Ctrl-C to interrupt the running process.
        let _ = self
            .run_tmux(&["send-keys", "-t", &handle.title, "C-c"])
            .await;

        // Brief delay to let the interrupt propagate.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Kill the window.
        self.run_tmux(&["kill-session", "-t", &handle.title])
            .await?;

        debug!(title = %handle.title, "stopped tmux session");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_tmux_succeeds_when_installed() {
        // This test only verifies the binary exists; it does not create
        // sessions. If tmux is not installed in the test environment,
        // the test is skipped rather than failing.
        match TmuxRuntime::check_tmux().await {
            Ok(()) => {} // tmux found
            Err(RuntimeError::TmuxNotFound) => {
                eprintln!("tmux not installed — skipping");
            }
            Err(e) => {
                // Unexpected error variant.
                std::result::Result::<(), _>::Err(e).expect("unexpected error from check_tmux");
            }
        }
    }

    #[tokio::test]
    async fn run_tmux_with_invalid_args_returns_error() {
        let rt = TmuxRuntime::new("ops-runtime-test-invalid");
        let result = rt.run_tmux(&["not-a-real-command"]).await;
        assert!(result.is_err(), "expected error for invalid tmux command");
    }
}
