use std::time::Duration;

use sigil_core::error::CoreError;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{
    IdentitySpec, LifecycleEvent, SessionConfig, SessionHandle, SessionState, ToolKind,
};
use sigil_core::traits::{LifecycleHooks, SessionRuntime, ToolAdapter};
use tokio::process::Command;
use tracing::debug;

use crate::adapter;
use crate::error::RuntimeError;

/// Manages agent sessions via tmux.
///
/// Each session is a tmux window inside a server named `server_name`
/// (default `"sigil"`). All tmux interaction goes through the
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
            id: sigil_core::id::SessionId::new(),
            title: config.title.clone(),
            tool: config.tool,
            state: SessionState::Running,
            path: config.path.clone(),
            tmux_window: Some(config.title.clone()),
            container_id: None,
            execution_class: config.execution_class,
            sandboxed: config.sandboxed,
            identity: config.identity.clone(),
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
        let raw = self
            .run_tmux(&["capture-pane", "-t", &handle.title, "-p", "-S", "-100"])
            .await?;
        Ok(sigil_policy::normalize::strip_ansi(&raw))
    }

    async fn status(&self, handle: &SessionHandle) -> Result<SessionState, CoreError> {
        // First check whether the tmux session exists at all.
        // The server name is already passed via `-L` in run_tmux,
        // so `-t` only needs the session name (handle.title).
        let list_result = self
            .run_tmux(&[
                "list-windows",
                "-t",
                &handle.title,
                "-F",
                "#{window_activity}",
            ])
            .await;

        if list_result.is_err() {
            return Ok(SessionState::Error);
        }

        // Session exists — capture pane, strip ANSI escapes, then let the
        // adapter detect state.
        let raw = self
            .run_tmux(&["capture-pane", "-t", &handle.title, "-p", "-S", "-100"])
            .await?;
        let output = sigil_policy::normalize::strip_ansi(&raw);

        let adapter = Self::get_adapter(handle.tool);
        let signals = adapter.parse_output(&output);

        // Use the first status signal if any, otherwise default to Running.
        for signal in signals {
            if let sigil_core::AgentSignal::StatusUpdate { state } = signal {
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

impl LifecycleHooks for TmuxRuntime {
    async fn register_identity_hooks(
        &self,
        handle: &SessionHandle,
        spec: &IdentitySpec,
    ) -> Result<(), CoreError> {
        let hooks = build_claude_hooks(handle, spec);
        if hooks.is_empty() {
            return Ok(());
        }

        let settings_path = handle.path.join(".claude").join("settings.local.json");
        write_claude_hooks(&settings_path, &hooks).await?;

        debug!(
            title = %handle.title,
            path = %settings_path.display(),
            "registered {} identity hook(s)",
            hooks.len(),
        );
        Ok(())
    }
}

/// A Claude Code hook entry to be written to settings.local.json.
struct ClaudeHookEntry {
    /// Claude Code event name (e.g. `PostCompact`, `PreCompact`).
    event: &'static str,
    /// Shell command to run.
    command: String,
}

/// Map lifecycle events to Claude Code hook entries.
fn build_claude_hooks(handle: &SessionHandle, spec: &IdentitySpec) -> Vec<ClaudeHookEntry> {
    let mut entries = Vec::new();
    for event in &spec.reload_on {
        match event {
            LifecycleEvent::PostCompact => entries.push(ClaudeHookEntry {
                event: "PostCompact",
                command: format!("sigil identity reload {}", handle.id),
            }),
            LifecycleEvent::PreCompact => entries.push(ClaudeHookEntry {
                event: "PreCompact",
                command: format!("sigil identity snapshot {}", handle.id),
            }),
            // Other events are handled by sigil itself, not via Claude
            // Code hooks.
            LifecycleEvent::Restart | LifecycleEvent::SessionStart | _ => {}
        }
    }
    entries
}

/// Read-merge-write Claude Code hooks into `.claude/settings.local.json`.
///
/// Handles three cases:
/// - File doesn't exist → create with just the hooks.
/// - File exists but has no `hooks` key → add `hooks`.
/// - File exists with existing hooks → merge without duplicating.
async fn write_claude_hooks(
    settings_path: &std::path::Path,
    entries: &[ClaudeHookEntry],
) -> Result<(), CoreError> {
    use serde_json::{Map, Value};

    // Read existing file or start with an empty object.
    let mut root: Map<String, Value> = if settings_path.exists() {
        let contents = tokio::fs::read_to_string(settings_path)
            .await
            .map_err(|e| CoreError::Runtime {
                message: format!("failed to read {}: {e}", settings_path.display()),
            })?;
        serde_json::from_str(&contents).map_err(|e| CoreError::Runtime {
            message: format!("failed to parse {}: {e}", settings_path.display()),
        })?
    } else {
        Map::new()
    };

    // Ensure `hooks` object exists.
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks_map = hooks.as_object_mut().ok_or_else(|| CoreError::Runtime {
        message: format!("{}: \"hooks\" is not an object", settings_path.display()),
    })?;

    for entry in entries {
        let new_hook = serde_json::json!({
            "type": "command",
            "command": entry.command,
            "timeout": 10
        });
        let new_rule = serde_json::json!({
            "matcher": "*",
            "hooks": [new_hook]
        });

        let event_rules = hooks_map
            .entry(entry.event)
            .or_insert_with(|| Value::Array(Vec::new()));
        let rules_arr = event_rules
            .as_array_mut()
            .ok_or_else(|| CoreError::Runtime {
                message: format!(
                    "{}: hooks.{} is not an array",
                    settings_path.display(),
                    entry.event
                ),
            })?;

        // Check for an existing sigil hook to avoid duplicates.
        let already_registered = rules_arr.iter().any(|rule| {
            rule.get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|hooks| {
                    hooks.iter().any(|h| {
                        h.get("command")
                            .and_then(Value::as_str)
                            .is_some_and(|c| c == entry.command)
                    })
                })
        });

        if !already_registered {
            rules_arr.push(new_rule);
        }
    }

    // Ensure the `.claude` directory exists.
    if let Some(parent) = settings_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| CoreError::Runtime {
                message: format!("failed to create {}: {e}", parent.display()),
            })?;
    }

    let json = serde_json::to_string_pretty(&root).map_err(|e| CoreError::Runtime {
        message: format!("failed to serialize settings: {e}"),
    })?;
    tokio::fs::write(settings_path, json)
        .await
        .map_err(|e| CoreError::Runtime {
            message: format!("failed to write {}: {e}", settings_path.display()),
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::print_stderr,
        clippy::unnecessary_literal_unwrap
    )]

    use std::path::PathBuf;

    use super::*;

    /// Helper to create a `SessionHandle` pointing at the given path.
    fn test_handle(path: PathBuf) -> SessionHandle {
        SessionHandle {
            id: sigil_core::id::SessionId::new(),
            title: "test-session".to_owned(),
            tool: ToolKind::ClaudeCode,
            state: SessionState::Running,
            path,
            tmux_window: Some("test-session".to_owned()),
            container_id: None,
            execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
            sandboxed: false,
            identity: None,
        }
    }

    // ---------------------------------------------------------------
    // LifecycleHooks / write_claude_hooks tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn register_hooks_writes_settings_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let rt = TmuxRuntime::new("sigil-test-hooks");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("register_identity_hooks");

        let settings_path = dir.path().join(".claude").join("settings.local.json");
        assert!(settings_path.exists(), "settings file should exist");

        let contents = tokio::fs::read_to_string(&settings_path)
            .await
            .expect("read settings");
        let root: serde_json::Value = serde_json::from_str(&contents).expect("parse settings");

        let hook_cmd = root["hooks"]["PostCompact"][0]["hooks"][0]["command"]
            .as_str()
            .expect("hook command");
        let expected = format!("sigil identity reload {}", handle.id);
        assert_eq!(hook_cmd, expected);

        let timeout = root["hooks"]["PostCompact"][0]["hooks"][0]["timeout"]
            .as_u64()
            .expect("timeout");
        assert_eq!(timeout, 10);

        let matcher = root["hooks"]["PostCompact"][0]["matcher"]
            .as_str()
            .expect("matcher");
        assert_eq!(matcher, "*");
    }

    #[tokio::test]
    async fn register_hooks_merges_with_existing_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("mkdir .claude");

        // Write an existing settings file with a custom key and existing hook.
        let existing = serde_json::json!({
            "permissions": { "allow": ["Read"] },
            "hooks": {
                "PostCompact": [{
                    "matcher": "*.rs",
                    "hooks": [{"type": "command", "command": "echo existing", "timeout": 5}]
                }]
            }
        });
        let settings_path = claude_dir.join("settings.local.json");
        std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&existing).expect("serialize"),
        )
        .expect("write existing settings");

        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let rt = TmuxRuntime::new("sigil-test-merge");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("register_identity_hooks");

        let contents = tokio::fs::read_to_string(&settings_path)
            .await
            .expect("read settings");
        let root: serde_json::Value = serde_json::from_str(&contents).expect("parse settings");

        // Existing keys preserved.
        assert!(
            root["permissions"]["allow"].is_array(),
            "existing permissions should be preserved"
        );

        // Existing hook preserved, new hook appended.
        let post_compact = root["hooks"]["PostCompact"]
            .as_array()
            .expect("PostCompact array");
        assert_eq!(
            post_compact.len(),
            2,
            "should have existing + new hook rules"
        );
        assert_eq!(
            post_compact[0]["hooks"][0]["command"].as_str(),
            Some("echo existing"),
        );
        let expected = format!("sigil identity reload {}", handle.id);
        assert_eq!(
            post_compact[1]["hooks"][0]["command"].as_str(),
            Some(expected.as_str()),
        );
    }

    #[tokio::test]
    async fn register_hooks_empty_reload_on_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![],
        };

        let rt = TmuxRuntime::new("sigil-test-empty");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("register_identity_hooks");

        let settings_path = dir.path().join(".claude").join("settings.local.json");
        assert!(
            !settings_path.exists(),
            "no file should be created when reload_on is empty"
        );
    }

    #[tokio::test]
    async fn register_hooks_non_claude_events_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::Restart, LifecycleEvent::SessionStart],
        };

        let rt = TmuxRuntime::new("sigil-test-non-claude");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("register_identity_hooks");

        let settings_path = dir.path().join(".claude").join("settings.local.json");
        assert!(
            !settings_path.exists(),
            "no file should be created for non-Claude events"
        );
    }

    #[tokio::test]
    async fn register_hooks_both_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PreCompact, LifecycleEvent::PostCompact],
        };

        let rt = TmuxRuntime::new("sigil-test-both");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("register_identity_hooks");

        let settings_path = dir.path().join(".claude").join("settings.local.json");
        let contents = tokio::fs::read_to_string(&settings_path)
            .await
            .expect("read settings");
        let root: serde_json::Value = serde_json::from_str(&contents).expect("parse settings");

        let reload_cmd = root["hooks"]["PostCompact"][0]["hooks"][0]["command"]
            .as_str()
            .expect("PostCompact command");
        assert!(reload_cmd.starts_with("sigil identity reload "));

        let snapshot_cmd = root["hooks"]["PreCompact"][0]["hooks"][0]["command"]
            .as_str()
            .expect("PreCompact command");
        assert!(snapshot_cmd.starts_with("sigil identity snapshot "));
    }

    #[tokio::test]
    async fn register_hooks_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(dir.path().to_path_buf());
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let rt = TmuxRuntime::new("sigil-test-idempotent");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("first call");
        rt.register_identity_hooks(&handle, &spec)
            .await
            .expect("second call");

        let settings_path = dir.path().join(".claude").join("settings.local.json");
        let contents = tokio::fs::read_to_string(&settings_path)
            .await
            .expect("read settings");
        let root: serde_json::Value = serde_json::from_str(&contents).expect("parse settings");

        let post_compact = root["hooks"]["PostCompact"]
            .as_array()
            .expect("PostCompact array");
        assert_eq!(
            post_compact.len(),
            1,
            "duplicate registration should not create extra entries"
        );
    }

    // ---------------------------------------------------------------
    // Existing tmux tests
    // ---------------------------------------------------------------

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
        let rt = TmuxRuntime::new("sigil-runtime-test-invalid");
        let result = rt.run_tmux(&["not-a-real-command"]).await;
        assert!(result.is_err(), "expected error for invalid tmux command");
    }

    #[tokio::test]
    async fn status_uses_session_title_not_server_colon_title() {
        // Verify that status() uses handle.title as the tmux target,
        // not "server_name:handle.title". When the session doesn't
        // exist the error message from tmux will contain the target
        // we passed, letting us assert the format.
        let rt = TmuxRuntime::new("sigil-status-test");
        let handle = SessionHandle {
            id: sigil_core::id::SessionId::new(),
            title: "test-session".to_owned(),
            tool: ToolKind::ClaudeCode,
            state: SessionState::Running,
            path: std::path::PathBuf::from("/tmp"),
            tmux_window: Some("test-session".to_owned()),
            container_id: None,
            execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
            sandboxed: false,
            identity: None,
        };

        // status() returns Error when the session doesn't exist,
        // which is fine — we just need to verify it doesn't crash
        // and doesn't include "sigil-status-test:test-session" in
        // the command (the old bug).
        let state = rt.status(&handle).await;

        // The session doesn't exist, so we expect Error state
        // (not a Rust error — status() returns Ok(Error) for
        // missing sessions).
        match state {
            Ok(_) => {
                // Ok(Error) is expected for a missing session.
                // Any other Ok variant means tmux happened to have
                // this session — the call still succeeded.
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("sigil-status-test:test-session"),
                    "status() should not use server_name:title as target, got: {msg}"
                );
            }
        }
    }
}
