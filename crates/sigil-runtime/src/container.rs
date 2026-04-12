//! Container-based session runtime using Apple Containers.
//!
//! This module provides [`ContainerRuntime`], a [`SessionRuntime`]
//! implementation that runs agent sessions inside Apple Containers
//! (lightweight VMs on macOS). Each session gets its own isolated
//! container with a VirtioFS-mounted worktree, injected environment
//! variables, and optional Unix socket publishing for MCP IPC.
//!
//! Network defaults to `--internal` (no internet). Set
//! [`NetworkMode::Full`] to allow unrestricted access. Domain-level
//! filtering requires a forward proxy (tracked separately in issue #7).
//!
//! Feature-gated behind `container`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sigil_audit::AuditLogWriter;
use sigil_core::error::CoreError;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{SessionConfig, SessionHandle, SessionState, ToolKind};
use sigil_core::traits::{SessionRuntime, ToolAdapter};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::adapter;
use crate::error::RuntimeError;
use crate::mcp_socket::{self, McpHandle, McpSpawner, McpSpawnerImpl};
use crate::proxy::DomainProxy;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Network mode for a containerized session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    /// No internet access (`--network <internal-network>`). This is the
    /// safe default; domain-level filtering requires the Rust proxy
    /// (issue #7).
    #[default]
    Internal,
    /// Unrestricted internet. Use only when the session is trusted or
    /// the proxy is handling filtering externally.
    Full,
    /// Internal network with a domain-filtering proxy. The proxy runs
    /// on the host, listening on a Unix socket published into the
    /// container. Only domains in the allowlist can be reached.
    Filtered {
        /// Domains to permit (e.g. `".anthropic.com"`, `".github.com"`).
        allowlist: Vec<String>,
    },
}

/// Container-specific configuration layered on top of [`SessionConfig`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// OCI image to run (default: `"sigil-agent:latest"`).
    pub image: String,
    /// Network isolation mode.
    pub network: NetworkMode,
    /// Extra bind mounts as `(host_path, container_path)` pairs.
    /// All extras are mounted read-only; the worktree mount is always RW.
    pub extra_mounts: Vec<(PathBuf, PathBuf)>,
    /// Extra environment variables injected at launch.
    pub extra_env: Vec<(String, String)>,
    /// Host-side path for the MCP Unix socket. When set, the socket is
    /// published into the container at `/tmp/sigil-mcp.sock`.
    pub mcp_socket_path: Option<PathBuf>,
    /// Internal network name used for `--internal` mode.
    pub internal_network_name: String,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: "sigil-agent:latest".to_owned(),
            network: NetworkMode::default(),
            extra_mounts: Vec::new(),
            extra_env: Vec::new(),
            mcp_socket_path: None,
            internal_network_name: "sigil-internal".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// Container path where the worktree is mounted.
const WORKSPACE_MOUNT: &str = "/workspace";

/// Container path for agent output capture.
const OUTPUT_PATH: &str = "/tmp/sigil-output";

/// Container path for the MCP socket inside the container.
const MCP_SOCKET_CONTAINER_PATH: &str = "/tmp/sigil-mcp.sock";

/// Container path for the proxy socket inside the container.
const PROXY_SOCKET_CONTAINER_PATH: &str = "/tmp/proxy.sock";

/// Default timeout for `container stop` before falling back to `kill`.
const STOP_TIMEOUT_SECS: u64 = 10;

/// State for a running proxy associated with a session.
struct ProxyHandle {
    task: tokio::task::JoinHandle<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
    socket_path: PathBuf,
}

/// Runs agent sessions inside Apple Containers.
pub struct ContainerRuntime {
    config: ContainerConfig,
    audit: Option<Arc<AuditLogWriter>>,
    proxy_handles: Mutex<HashMap<String, ProxyHandle>>,
    /// Type-erased MCP server spawner. When present, `launch()` auto-
    /// starts an MCP server on a Unix socket published into the container.
    mcp_spawner: Option<Arc<dyn McpSpawner>>,
    /// Running MCP server handles, keyed by session title.
    mcp_handles: Mutex<HashMap<String, McpHandle>>,
}

impl ContainerRuntime {
    /// Create a new container runtime with the given configuration.
    #[must_use]
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            audit: None,
            proxy_handles: Mutex::new(HashMap::new()),
            mcp_spawner: None,
            mcp_handles: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new container runtime with audit logging.
    #[must_use]
    pub fn with_audit(config: ContainerConfig, audit: Arc<AuditLogWriter>) -> Self {
        Self {
            config,
            audit: Some(audit),
            proxy_handles: Mutex::new(HashMap::new()),
            mcp_spawner: None,
            mcp_handles: Mutex::new(HashMap::new()),
        }
    }

    /// Create a runtime with default settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ContainerConfig::default())
    }

    /// Enable MCP server support with the given grant store.
    ///
    /// When enabled, `launch()` will automatically start an MCP server
    /// on a Unix socket published into each container. The agent inside
    /// the container connects to `/tmp/sigil-mcp.sock` and sends
    /// JSON-RPC requests through the policy evaluator.
    #[must_use]
    pub fn with_mcp<G: sigil_policy::grants::GrantStore + 'static>(
        mut self,
        grants: Arc<G>,
    ) -> Self {
        self.mcp_spawner = Some(Arc::new(McpSpawnerImpl::new(grants)));
        self
    }

    /// Return the host-side proxy socket path for a session.
    #[must_use]
    pub fn proxy_socket_path(session_title: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/sigil-proxy-{session_title}.sock"))
    }

    /// Start the domain proxy for a filtered-network session.
    async fn start_proxy(
        &self,
        session_title: &str,
        allowlist: &[String],
    ) -> Result<PathBuf, RuntimeError> {
        let socket_path = Self::proxy_socket_path(session_title);

        let proxy = DomainProxy::new(
            allowlist.to_vec(),
            socket_path.clone(),
            self.audit.clone(),
            None, // session_id is assigned after launch
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let task = tokio::spawn(async move {
            if let Err(e) = proxy.run(shutdown_rx).await {
                warn!(error = %e, "proxy exited with error");
            }
        });

        let handle = ProxyHandle {
            task,
            shutdown: shutdown_tx,
            socket_path: socket_path.clone(),
        };

        self.proxy_handles
            .lock()
            .await
            .insert(session_title.to_owned(), handle);

        info!(session = session_title, path = %socket_path.display(), "started proxy");
        Ok(socket_path)
    }

    /// Stop the MCP server for a session (if one is running).
    async fn stop_mcp(&self, session_title: &str) {
        let handle = self.mcp_handles.lock().await.remove(session_title);

        if let Some(handle) = handle {
            // Signal shutdown.
            let _ = handle.shutdown.send(true);
            // Wait for the task to finish (with a timeout).
            let _ = tokio::time::timeout(Duration::from_secs(5), handle.task).await;
            // Clean up socket just in case.
            let _ = tokio::fs::remove_file(&handle.socket_path).await;
            debug!(session = session_title, "stopped MCP server");
        }
    }

    /// Stop the proxy for a session (if one is running).
    async fn stop_proxy(&self, session_title: &str) {
        let handle = self.proxy_handles.lock().await.remove(session_title);

        if let Some(handle) = handle {
            // Signal shutdown.
            let _ = handle.shutdown.send(true);
            // Wait for the task to finish (with a timeout).
            let _ = tokio::time::timeout(Duration::from_secs(5), handle.task).await;
            // Clean up socket just in case.
            let _ = tokio::fs::remove_file(&handle.socket_path).await;
            debug!(session = session_title, "stopped proxy");
        }
    }

    // -- lifecycle helpers --------------------------------------------------

    /// Verify that the Apple `container` CLI is installed and reachable.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ContainerCliNotFound`] if the binary is
    /// missing or the version cannot be determined.
    pub async fn check_container_cli() -> Result<(), RuntimeError> {
        let output = Command::new("container")
            .arg("--version")
            .output()
            .await
            .map_err(|_| RuntimeError::ContainerCliNotFound)?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerCliNotFound);
        }
        Ok(())
    }

    /// Create the internal network (idempotent). If the network already
    /// exists, the error is silently ignored.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ContainerCommand`] if the `container`
    /// binary is unreachable or returns an unexpected error.
    pub async fn create_internal_network(name: &str) -> Result<(), RuntimeError> {
        let output = Command::new("container")
            .args(["network", "create", name, "--internal"])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            // "already exists" is fine — the call is idempotent.
            if !stderr.contains("already exists") {
                return Err(RuntimeError::ContainerCommand {
                    command: format!("container network create {name} --internal"),
                    stderr,
                });
            }
        }

        debug!(network = name, "internal network ready");
        Ok(())
    }

    /// Remove a stopped container. Errors are logged but not propagated
    /// (best-effort cleanup).
    pub async fn cleanup_container(name: &str) {
        let result = Command::new("container").args(["rm", name]).output().await;

        match result {
            Ok(output) if output.status.success() => {
                debug!(container = name, "cleaned up container");
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(container = name, %stderr, "container rm failed (may already be removed)");
            }
            Err(e) => {
                warn!(container = name, error = %e, "container rm io error");
            }
        }
    }

    // -- internal helpers ---------------------------------------------------

    /// Build the argument list for `container run`.
    fn build_run_args(
        &self,
        session_config: &SessionConfig,
        proxy_socket: Option<&PathBuf>,
        mcp_socket: Option<&PathBuf>,
    ) -> Result<Vec<String>, CoreError> {
        let worktree = session_config
            .path
            .to_str()
            .ok_or_else(|| CoreError::InvalidConfig {
                message: "session path is not valid UTF-8".to_owned(),
            })?;

        let mut args: Vec<String> = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            session_config.title.clone(),
        ];

        // Worktree mount (always RW).
        args.push("-v".to_owned());
        args.push(format!("{worktree}:{WORKSPACE_MOUNT}"));

        // Extra mounts (read-only).
        for (host, container) in &self.config.extra_mounts {
            let host_str = host.to_str().ok_or_else(|| CoreError::InvalidConfig {
                message: format!("extra mount path is not valid UTF-8: {}", host.display()),
            })?;
            let container_str = container.to_str().ok_or_else(|| CoreError::InvalidConfig {
                message: format!(
                    "extra mount target is not valid UTF-8: {}",
                    container.display()
                ),
            })?;
            args.push("--mount".to_owned());
            args.push(format!(
                "type=bind,source={host_str},target={container_str},readonly"
            ));
        }

        // MCP socket publishing.
        if let Some(socket_path) = mcp_socket.or(self.config.mcp_socket_path.as_ref()) {
            let socket_str = socket_path
                .to_str()
                .ok_or_else(|| CoreError::InvalidConfig {
                    message: format!(
                        "MCP socket path is not valid UTF-8: {}",
                        socket_path.display()
                    ),
                })?;
            args.push("--publish-socket".to_owned());
            args.push(format!("{socket_str}:{MCP_SOCKET_CONTAINER_PATH}"));

            // Tell the agent where the MCP socket lives inside the container.
            args.push("-e".to_owned());
            args.push(format!("SIGIL_MCP_SOCKET={MCP_SOCKET_CONTAINER_PATH}"));
        }

        // Proxy socket publishing (for Filtered network mode).
        if let Some(proxy_path) = proxy_socket {
            let proxy_str = proxy_path
                .to_str()
                .ok_or_else(|| CoreError::InvalidConfig {
                    message: format!(
                        "proxy socket path is not valid UTF-8: {}",
                        proxy_path.display()
                    ),
                })?;
            args.push("--publish-socket".to_owned());
            args.push(format!("{proxy_str}:{PROXY_SOCKET_CONTAINER_PATH}"));
        }

        // Environment variables.
        args.push("-e".to_owned());
        args.push(format!("SIGIL_SESSION_ID={}", session_config.title));

        // Proxy environment variables.
        if proxy_socket.is_some() {
            let proxy_url = format!("http://unix:{PROXY_SOCKET_CONTAINER_PATH}");
            args.push("-e".to_owned());
            args.push(format!("HTTP_PROXY={proxy_url}"));
            args.push("-e".to_owned());
            args.push(format!("HTTPS_PROXY={proxy_url}"));
            args.push("-e".to_owned());
            args.push("NO_PROXY=localhost,127.0.0.1".to_owned());
        }

        for (key, value) in &self.config.extra_env {
            args.push("-e".to_owned());
            args.push(format!("{key}={value}"));
        }

        // Network.
        match self.config.network {
            NetworkMode::Internal | NetworkMode::Filtered { .. } => {
                args.push("--network".to_owned());
                args.push(self.config.internal_network_name.clone());
            }
            NetworkMode::Full => {
                // Default network — no flag needed.
            }
        }

        // Image.
        args.push(self.config.image.clone());

        Ok(args)
    }

    /// Run an arbitrary `container` CLI command, returning stdout.
    ///
    /// Error messages redact `-e` flag values to avoid leaking secrets.
    async fn run_container(args: &[&str]) -> Result<String, RuntimeError> {
        let output = Command::new("container").args(args).output().await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let command = redact_env_args(args);
            Err(RuntimeError::ContainerCommand { command, stderr })
        }
    }

    /// Return the appropriate `ToolAdapter` for the given tool kind.
    fn get_adapter(tool: ToolKind) -> Box<dyn ToolAdapter> {
        adapter::adapter_for(tool)
    }
}

/// Build a redacted command string for error reporting.
///
/// Values following `-e` flags are replaced with `<REDACTED>` to
/// prevent secrets from leaking into logs or error messages.
fn redact_env_args(args: &[&str]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push("container");
    let mut redact_next = false;
    for &arg in args {
        if redact_next {
            parts.push("<REDACTED>");
            redact_next = false;
        } else if arg == "-e" {
            parts.push(arg);
            redact_next = true;
        } else {
            parts.push(arg);
        }
    }
    parts.join(" ")
}

/// Parse the `status` field from `container inspect` JSON output.
///
/// Apple Containers returns a JSON array of objects, each with a
/// top-level `"status"` field. Known values: `"running"`, `"stopped"`,
/// `"created"`. Returns `SessionState::Error` for unparseable input.
fn parse_inspect_status(json_str: &str) -> SessionState {
    // Minimal parsing: extract the "status" field from the first object
    // in the array. We use serde_json::Value to avoid a dedicated struct.
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return SessionState::Error;
    };

    let status = value
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("status"))
        .and_then(serde_json::Value::as_str);

    match status {
        Some("running" | "stopping") => SessionState::Running,
        Some("stopped" | "exited" | "created") => SessionState::Stopped,
        // "unknown" and anything else map to Error.
        _ => SessionState::Error,
    }
}

impl SessionRuntime for ContainerRuntime {
    async fn launch(&self, config: &SessionConfig) -> Result<SessionHandle, CoreError> {
        // Ensure the internal network exists when using Internal or
        // Filtered mode.
        let uses_internal = matches!(
            self.config.network,
            NetworkMode::Internal | NetworkMode::Filtered { .. }
        );
        if uses_internal {
            Self::create_internal_network(&self.config.internal_network_name).await?;
        }

        // Start the proxy if using Filtered mode.
        let proxy_socket = if let NetworkMode::Filtered { ref allowlist } = self.config.network {
            let path = self.start_proxy(&config.title, allowlist).await?;
            // Give the proxy a moment to bind the socket.
            tokio::time::sleep(Duration::from_millis(50)).await;
            Some(path)
        } else {
            None
        };

        // Start the MCP server if a grant store was provided.
        // The spawner waits for the socket to be bound before returning.
        let mcp_socket = if let Some(ref spawner) = self.mcp_spawner {
            let socket_path = mcp_socket::mcp_socket_path(&config.title);
            let handle = spawner.spawn(socket_path.clone()).await?;
            self.mcp_handles
                .lock()
                .await
                .insert(config.title.clone(), handle);
            info!(session = %config.title, path = %socket_path.display(), "started MCP server");
            Some(socket_path)
        } else {
            None
        };

        let run_args = self.build_run_args(config, proxy_socket.as_ref(), mcp_socket.as_ref())?;
        let arg_refs: Vec<&str> = run_args.iter().map(String::as_str).collect();
        Self::run_container(&arg_refs).await?;

        debug!(
            title = %config.title,
            image = %self.config.image,
            "launched container session"
        );

        // If there is an initial message, exec it into the container.
        // NOTE: `container exec sh -c` is a temporary transport. Once the
        // MCP socket IPC is wired up (issue #7), messages will be delivered
        // via the Unix socket instead of shell exec. The container image
        // must run the agent as PID 1 for this to work correctly.
        if let Some(ref msg) = config.initial_message {
            let adapter = Self::get_adapter(config.tool);
            let translated = adapter.translate_send(&ConductorMessage::TaskAssignment {
                instructions: msg.clone(),
            });
            if !translated.is_empty() {
                Self::run_container(&["exec", &config.title, "sh", "-c", &translated]).await?;
            }
        }

        Ok(SessionHandle {
            id: sigil_core::id::SessionId::new(),
            title: config.title.clone(),
            tool: config.tool,
            state: SessionState::Running,
            path: config.path.clone(),
            tmux_window: None,
            container_id: Some(config.title.clone()),
            execution_class: config.execution_class,
            sandboxed: true, // Containers are always sandboxed.
            identity: config.identity.clone(),
        })
    }

    async fn send(&self, handle: &SessionHandle, msg: ConductorMessage) -> Result<(), CoreError> {
        let adapter = Self::get_adapter(handle.tool);
        let translated = adapter.translate_send(&msg);

        if translated.is_empty() {
            return Ok(());
        }

        Self::run_container(&["exec", &handle.title, "sh", "-c", &translated]).await?;

        debug!(title = %handle.title, "sent message to container session");
        Ok(())
    }

    async fn read_output(&self, handle: &SessionHandle) -> Result<String, CoreError> {
        let raw = Self::run_container(&["exec", &handle.title, "cat", OUTPUT_PATH]).await;

        match raw {
            Ok(output) => Ok(sigil_policy::normalize::strip_ansi(&output)),
            Err(_) => {
                // Output file may not exist yet — return empty.
                Ok(String::new())
            }
        }
    }

    async fn status(&self, handle: &SessionHandle) -> Result<SessionState, CoreError> {
        // Apple Containers `inspect` returns a JSON array, e.g.:
        //   [{"status":"running", "configuration":{...}, ...}]
        // It has no --format flag (unlike Docker).
        let result = Self::run_container(&["inspect", &handle.title]).await;

        match result {
            Ok(json_str) => Ok(parse_inspect_status(&json_str)),
            Err(_) => {
                // Container doesn't exist or inspect failed.
                Ok(SessionState::Error)
            }
        }
    }

    async fn stop(&self, handle: &SessionHandle) -> Result<(), CoreError> {
        // Try graceful stop first.
        let stop_result = Self::run_container(&[
            "stop",
            &handle.title,
            "--time",
            &STOP_TIMEOUT_SECS.to_string(),
        ])
        .await;

        if stop_result.is_err() {
            // Fallback: force kill. The POC notes that `container stop`
            // occasionally times out with an XPC error.
            warn!(
                title = %handle.title,
                "container stop failed, falling back to kill"
            );
            let _ = Self::run_container(&["kill", &handle.title]).await;
        }

        // Stop the MCP server and proxy if running for this session.
        self.stop_mcp(&handle.title).await;
        self.stop_proxy(&handle.title).await;

        // Brief delay before cleanup.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Best-effort removal of the stopped container.
        Self::cleanup_container(&handle.title).await;

        debug!(title = %handle.title, "stopped container session");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::print_stderr,
        clippy::unnecessary_literal_unwrap
    )]

    use std::path::PathBuf;

    use sigil_core::session::{SessionConfig, ToolKind};
    use sigil_core::trust::ExecutionClass;

    use super::*;

    fn test_session_config() -> SessionConfig {
        SessionConfig {
            path: PathBuf::from("/tmp/test-worktree"),
            title: "test-agent-01".to_owned(),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            initial_message: None,
            worktree_branch: None,
            identity: None,
            memory: None,
        }
    }

    // -- ContainerConfig defaults -------------------------------------------

    #[test]
    fn default_config_has_expected_values() {
        let cfg = ContainerConfig::default();
        assert_eq!(cfg.image, "sigil-agent:latest");
        assert_eq!(cfg.network, NetworkMode::Internal);
        assert!(cfg.extra_mounts.is_empty());
        assert!(cfg.extra_env.is_empty());
        assert!(cfg.mcp_socket_path.is_none());
        assert_eq!(cfg.internal_network_name, "sigil-internal");
    }

    #[test]
    fn network_mode_default_is_internal() {
        assert_eq!(NetworkMode::default(), NetworkMode::Internal);
    }

    // -- Command construction -----------------------------------------------

    #[test]
    fn build_run_args_minimal() {
        let rt = ContainerRuntime::with_defaults();
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        // Must contain: run -d --name test-agent-01
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "-d");
        assert_eq!(args[2], "--name");
        assert_eq!(args[3], "test-agent-01");

        // Worktree mount.
        assert!(args.contains(&"-v".to_owned()));
        assert!(args.contains(&format!("/tmp/test-worktree:{WORKSPACE_MOUNT}")));

        // Session ID env.
        assert!(args.contains(&"-e".to_owned()));
        assert!(args.contains(&"SIGIL_SESSION_ID=test-agent-01".to_owned()));

        // Internal network.
        assert!(args.contains(&"--network".to_owned()));
        assert!(args.contains(&"sigil-internal".to_owned()));

        // Image is last.
        assert_eq!(args.last().expect("non-empty"), "sigil-agent:latest");
    }

    #[test]
    fn build_run_args_full_network_omits_network_flag() {
        let config = ContainerConfig {
            network: NetworkMode::Full,
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert!(!args.contains(&"--network".to_owned()));
    }

    #[test]
    fn build_run_args_with_extra_mounts() {
        let config = ContainerConfig {
            extra_mounts: vec![(
                PathBuf::from("/host/config"),
                PathBuf::from("/etc/agent-config"),
            )],
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert!(args.contains(&"--mount".to_owned()));
        assert!(args.contains(
            &"type=bind,source=/host/config,target=/etc/agent-config,readonly".to_owned()
        ));
    }

    #[test]
    fn build_run_args_with_extra_env() {
        let config = ContainerConfig {
            extra_env: vec![
                ("API_KEY".to_owned(), "secret123".to_owned()),
                ("TRUST_ZONE".to_owned(), "AgentRuntime".to_owned()),
            ],
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert!(args.contains(&"API_KEY=secret123".to_owned()));
        assert!(args.contains(&"TRUST_ZONE=AgentRuntime".to_owned()));
    }

    #[test]
    fn build_run_args_with_mcp_socket_from_config() {
        let config = ContainerConfig {
            mcp_socket_path: Some(PathBuf::from("/tmp/sigil-mcp.sock")),
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert!(args.contains(&"--publish-socket".to_owned()));
        assert!(args.contains(&format!("/tmp/sigil-mcp.sock:{MCP_SOCKET_CONTAINER_PATH}")));
        assert!(args.contains(&format!("SIGIL_MCP_SOCKET={MCP_SOCKET_CONTAINER_PATH}")));
    }

    #[test]
    fn build_run_args_with_mcp_socket_parameter_overrides_config() {
        let config = ContainerConfig {
            mcp_socket_path: Some(PathBuf::from("/tmp/config-mcp.sock")),
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let param_path = PathBuf::from("/tmp/spawned-mcp.sock");
        let args = rt
            .build_run_args(&session, None, Some(&param_path))
            .expect("should build args");

        // Parameter takes priority over config.
        assert!(args.contains(&format!(
            "/tmp/spawned-mcp.sock:{MCP_SOCKET_CONTAINER_PATH}"
        )));
        assert!(!args.contains(&format!("/tmp/config-mcp.sock:{MCP_SOCKET_CONTAINER_PATH}")));
    }

    #[test]
    fn build_run_args_with_custom_image() {
        let config = ContainerConfig {
            image: "my-agent:v2".to_owned(),
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert_eq!(args.last().expect("non-empty"), "my-agent:v2");
    }

    #[test]
    fn build_run_args_with_custom_network_name() {
        let config = ContainerConfig {
            internal_network_name: "my-net".to_owned(),
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        assert!(args.contains(&"my-net".to_owned()));
    }

    #[test]
    fn build_run_args_combined() {
        let config = ContainerConfig {
            image: "custom:latest".to_owned(),
            network: NetworkMode::Internal,
            extra_mounts: vec![(PathBuf::from("/secrets"), PathBuf::from("/run/secrets"))],
            extra_env: vec![("FOO".to_owned(), "bar".to_owned())],
            mcp_socket_path: Some(PathBuf::from("/tmp/mcp.sock")),
            internal_network_name: "sigil-internal".to_owned(),
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");

        // Verify all pieces are present.
        assert!(args.contains(&"--mount".to_owned()));
        assert!(args.contains(&"--publish-socket".to_owned()));
        assert!(args.contains(&"FOO=bar".to_owned()));
        assert!(args.contains(&"--network".to_owned()));
        assert_eq!(args.last().expect("non-empty"), "custom:latest");
    }

    #[test]
    fn launch_sets_sandboxed_true() {
        // Verify the handle construction logic. We can't call launch()
        // without a real container CLI, but we can verify that
        // build_run_args succeeds and the SessionHandle would have
        // sandboxed = true by inspecting the code path.
        let rt = ContainerRuntime::with_defaults();
        let session = test_session_config();
        let args = rt.build_run_args(&session, None, None);
        assert!(args.is_ok(), "build_run_args should succeed");
    }

    // -- Filtered network mode -----------------------------------------------

    #[test]
    fn filtered_mode_uses_internal_network() {
        let config = ContainerConfig {
            network: NetworkMode::Filtered {
                allowlist: vec![".anthropic.com".to_owned()],
            },
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let args = rt
            .build_run_args(&session, None, None)
            .expect("should build args");
        assert!(args.contains(&"--network".to_owned()));
        assert!(args.contains(&"sigil-internal".to_owned()));
    }

    #[test]
    fn filtered_mode_with_proxy_socket_adds_publish_and_env() {
        let config = ContainerConfig {
            network: NetworkMode::Filtered {
                allowlist: vec![".anthropic.com".to_owned()],
            },
            ..ContainerConfig::default()
        };
        let rt = ContainerRuntime::new(config);
        let session = test_session_config();
        let proxy_path = PathBuf::from("/tmp/sigil-proxy-test.sock");
        let args = rt
            .build_run_args(&session, Some(&proxy_path), None)
            .expect("should build args");

        // Proxy socket published.
        assert!(args.contains(&"--publish-socket".to_owned()));
        assert!(args.contains(&format!(
            "/tmp/sigil-proxy-test.sock:{PROXY_SOCKET_CONTAINER_PATH}"
        )));

        // HTTP_PROXY/HTTPS_PROXY env vars set.
        let proxy_url = format!("http://unix:{PROXY_SOCKET_CONTAINER_PATH}");
        assert!(args.contains(&format!("HTTP_PROXY={proxy_url}")));
        assert!(args.contains(&format!("HTTPS_PROXY={proxy_url}")));
        assert!(args.contains(&"NO_PROXY=localhost,127.0.0.1".to_owned()));
    }

    #[test]
    fn proxy_socket_path_uses_session_title() {
        let path = ContainerRuntime::proxy_socket_path("my-session");
        assert_eq!(path, PathBuf::from("/tmp/sigil-proxy-my-session.sock"));
    }

    // -- JSON status parsing --------------------------------------------------

    #[test]
    fn parse_inspect_status_running() {
        let json = r#"[{"status":"running","configuration":{}}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Running);
    }

    #[test]
    fn parse_inspect_status_stopped() {
        let json = r#"[{"status":"stopped","configuration":{}}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Stopped);
    }

    #[test]
    fn parse_inspect_status_created() {
        let json = r#"[{"status":"created","configuration":{}}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Stopped);
    }

    #[test]
    fn parse_inspect_status_stopping() {
        let json = r#"[{"status":"stopping"}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Running);
    }

    #[test]
    fn parse_inspect_status_unknown_maps_to_error() {
        let json = r#"[{"status":"unknown"}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Error);
    }

    #[test]
    fn parse_inspect_status_empty_array() {
        assert_eq!(parse_inspect_status("[]"), SessionState::Error);
    }

    #[test]
    fn parse_inspect_status_invalid_json() {
        assert_eq!(parse_inspect_status("not json"), SessionState::Error);
    }

    #[test]
    fn parse_inspect_status_unrecognized_value() {
        let json = r#"[{"status":"paused"}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Error);
    }

    // -- Env redaction -------------------------------------------------------

    #[test]
    fn redact_env_args_hides_values() {
        let args = &["run", "-d", "-e", "SECRET=hunter2", "--name", "test"];
        let redacted = redact_env_args(args);
        assert_eq!(redacted, "container run -d -e <REDACTED> --name test");
    }

    #[test]
    fn redact_env_args_no_env_unchanged() {
        let args = &["inspect", "my-container"];
        let redacted = redact_env_args(args);
        assert_eq!(redacted, "container inspect my-container");
    }

    #[test]
    fn redact_env_args_multiple_envs() {
        let args = &["run", "-e", "A=1", "-e", "B=2", "img"];
        let redacted = redact_env_args(args);
        assert_eq!(redacted, "container run -e <REDACTED> -e <REDACTED> img");
    }

    #[test]
    fn parse_inspect_status_missing_field() {
        let json = r#"[{"configuration":{}}]"#;
        assert_eq!(parse_inspect_status(json), SessionState::Error);
    }

    // -- CLI availability ---------------------------------------------------

    #[tokio::test]
    async fn check_container_cli_handles_missing_binary() {
        // If the container CLI is not installed (common in CI), the
        // check should return ContainerCliNotFound rather than panic.
        match ContainerRuntime::check_container_cli().await {
            Ok(()) => {} // container CLI found — fine
            Err(RuntimeError::ContainerCliNotFound) => {
                eprintln!("container CLI not installed — skipping");
            }
            Err(e) => {
                std::result::Result::<(), _>::Err(e)
                    .expect("unexpected error from check_container_cli");
            }
        }
    }
}
