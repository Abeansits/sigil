//! MCP Unix socket server for container sessions.
//!
//! When [`ContainerRuntime`] launches a session with MCP enabled, it
//! spawns a sigil-mcp server listening on a Unix socket. The socket is
//! published into the container at `/tmp/sigil-mcp.sock` so the agent
//! can send JSON-RPC requests through the policy evaluator.
//!
//! # Architecture
//!
//! ```text
//! Agent in container
//!   -> /tmp/sigil-mcp.sock (Unix socket, inside container)
//!   -> published to host at /tmp/sigil-mcp-{title}.sock
//!   -> MCP server (tokio task on host)
//!   -> sigil-mcp handle_stream (JSON-RPC -> policy evaluator -> response)
//! ```
//!
//! The [`McpSpawner`] trait type-erases the `GrantStore` generic so
//! [`ContainerRuntime`](super::container::ContainerRuntime) stays
//! non-generic.
//!
//! Feature-gated behind `container`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sigil_content::{DisabledFetcher, ExternalContentFetcher, Sanitizer};
use sigil_mcp::handle_stream;
use sigil_policy::grants::GrantStore;
use tokio::io::BufReader;
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::error::RuntimeError;

// ---------------------------------------------------------------------------
// Handle + Spawner
// ---------------------------------------------------------------------------

/// Handle for a running MCP socket server task.
pub(crate) struct McpHandle {
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) shutdown: tokio::sync::watch::Sender<bool>,
    pub(crate) socket_path: PathBuf,
}

/// Type-erased MCP server spawner.
///
/// This trait lets [`ContainerRuntime`](super::container::ContainerRuntime)
/// spawn MCP servers without being generic over `GrantStore`.
pub(crate) trait McpSpawner: Send + Sync {
    /// Spawn an MCP server listening on `socket_path`.
    ///
    /// Returns `Ok(McpHandle)` once the server has successfully bound the
    /// socket. Returns `Err` if the bind fails.
    fn spawn(
        &self,
        socket_path: PathBuf,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<McpHandle, RuntimeError>> + Send + '_>,
    >;
}

/// Concrete spawner that captures an `Arc<G>` for a specific `GrantStore`.
///
/// Carries the sanitizer and fetcher that the `fetch_url` MCP tool
/// consults. `sanitizer = None` disables `fetch_url` (the tool returns
/// a clean `Error` status without attempting to fetch); the default
/// fetcher is `DisabledFetcher`, which produces `FetchError::NotConfigured`
/// for every URL. Callers that want a working `fetch_url` pipeline must
/// install both via [`Self::with_sanitizer`] and [`Self::with_fetcher`].
pub(crate) struct McpSpawnerImpl<G> {
    grants: Arc<G>,
    sanitizer: Option<Arc<Sanitizer>>,
    fetcher: Arc<dyn ExternalContentFetcher>,
}

impl<G> McpSpawnerImpl<G> {
    pub(crate) fn new(grants: Arc<G>) -> Self {
        Self {
            grants,
            sanitizer: None,
            fetcher: Arc::new(DisabledFetcher),
        }
    }

    /// Install a sanitizer for the MCP `fetch_url` tool. Without this,
    /// `fetch_url` is a hard-disabled surface on spawned servers.
    pub(crate) fn with_sanitizer(mut self, sanitizer: Arc<Sanitizer>) -> Self {
        self.sanitizer = Some(sanitizer);
        self
    }

    /// Install a fetcher for the MCP `fetch_url` tool. Defaults to
    /// [`DisabledFetcher`].
    pub(crate) fn with_fetcher(mut self, fetcher: Arc<dyn ExternalContentFetcher>) -> Self {
        self.fetcher = fetcher;
        self
    }
}

impl<G: GrantStore + 'static> McpSpawner for McpSpawnerImpl<G> {
    fn spawn(
        &self,
        socket_path: PathBuf,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<McpHandle, RuntimeError>> + Send + '_>,
    > {
        let grants = self.grants.clone();
        let sanitizer = self.sanitizer.clone();
        let fetcher = Arc::clone(&self.fetcher);
        Box::pin(async move {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

            let path_for_task = socket_path.clone();
            let task = tokio::spawn(async move {
                if let Err(e) = run_mcp_socket(
                    grants,
                    sanitizer,
                    fetcher,
                    &path_for_task,
                    shutdown_rx,
                    ready_tx,
                )
                .await
                {
                    warn!(error = %e, "MCP socket server exited with error");
                }
            });

            // Wait for the server to signal that the socket is bound.
            match ready_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(RuntimeError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "MCP server task exited before signalling readiness",
                    )));
                }
            }

            Ok(McpHandle {
                task,
                shutdown: shutdown_tx,
                socket_path,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------------

/// Return the host-side MCP socket path for a session.
#[must_use]
pub fn mcp_socket_path(session_title: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/sigil-mcp-{session_title}.sock"))
}

// ---------------------------------------------------------------------------
// Socket server
// ---------------------------------------------------------------------------

/// Run the MCP server on a Unix socket until the shutdown signal fires.
///
/// Accepts multiple concurrent connections. Each connection gets its own
/// `McpServer` instance (separate `initialize` handshake).
///
/// Sends `Ok(())` on `ready_tx` once the socket is bound, or `Err` if
/// the bind fails. This lets the spawner wait for readiness without a
/// timing-based sleep.
async fn run_mcp_socket<G: GrantStore + 'static>(
    grants: Arc<G>,
    sanitizer: Option<Arc<Sanitizer>>,
    fetcher: Arc<dyn ExternalContentFetcher>,
    socket_path: &Path,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ready_tx: tokio::sync::oneshot::Sender<Result<(), RuntimeError>>,
) -> Result<(), RuntimeError> {
    // Remove stale socket if present.
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => {
            // Signal readiness to the spawner.
            let _ = ready_tx.send(Ok(()));
            l
        }
        Err(e) => {
            let err = RuntimeError::Io(e);
            let _ = ready_tx.send(Err(RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "failed to bind MCP socket",
            ))));
            return Err(err);
        }
    };

    info!(path = %socket_path.display(), "MCP socket server listening");

    // Track per-connection tasks so we can drain on shutdown.
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("MCP socket server shutting down");
                    break;
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let grants = grants.clone();
                        let sanitizer = sanitizer.clone();
                        let fetcher = Arc::clone(&fetcher);
                        let conn_shutdown = shutdown.clone();
                        connections.spawn(async move {
                            handle_mcp_connection(grants, sanitizer, fetcher, stream, conn_shutdown).await;
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to accept MCP connection");
                    }
                }
            }
            // Reap finished connection tasks.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    // Drain in-flight connections (the shutdown signal is already set,
    // so handle_mcp_connection will observe it and exit).
    while connections.join_next().await.is_some() {}

    // Best-effort socket cleanup.
    let _ = tokio::fs::remove_file(socket_path).await;
    Ok(())
}

/// Handle a single MCP client connection.
///
/// Reads line-delimited JSON-RPC from the stream and delegates to
/// `handle_stream`. Exits when the client disconnects or the shutdown
/// signal fires.
async fn handle_mcp_connection<G: GrantStore>(
    grants: Arc<G>,
    sanitizer: Option<Arc<Sanitizer>>,
    fetcher: Arc<dyn ExternalContentFetcher>,
    stream: tokio::net::UnixStream,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let (reader, writer) = stream.into_split();
    let reader = BufReader::new(reader);

    tokio::select! {
        result = handle_stream(grants, sanitizer, fetcher, reader, writer) => {
            if let Err(e) = result {
                debug!(error = %e, "MCP connection ended");
            }
        }
        _ = shutdown.changed() => {
            debug!("MCP connection terminated by shutdown");
        }
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
        clippy::uninlined_format_args
    )]

    use std::sync::Arc;
    use std::time::Duration;

    use sigil_core::id::SessionId;
    use sigil_mcp::tools::{ToolResult, ToolStatus};
    use sigil_policy::NoopGrantStore;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    use super::*;

    /// Start an MCP server on a temporary Unix socket. Returns the
    /// socket path, shutdown sender, and temp dir (must be kept alive).
    async fn start_test_server() -> (PathBuf, tokio::sync::watch::Sender<bool>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("test-mcp.sock");
        let grants: Arc<NoopGrantStore> = Arc::new(NoopGrantStore);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            // The socket-level tests exercise policy and transport
            // only; `fetch_url` happy-path coverage lives in the
            // sigil-conductor E2E test.
            let fetcher: Arc<dyn ExternalContentFetcher> = Arc::new(DisabledFetcher);
            if let Err(e) =
                run_mcp_socket(grants, None, fetcher, &path_clone, shutdown_rx, ready_tx).await
            {
                eprintln!("test MCP server error: {e}");
            }
        });

        // Wait for the server to signal readiness (socket bound).
        ready_rx
            .await
            .expect("ready channel")
            .expect("bind should succeed");

        (socket_path, shutdown_tx, dir)
    }

    /// Send a JSON-RPC line and read the response line.
    async fn send_request(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        json: &str,
    ) -> serde_json::Value {
        writer
            .write_all(json.as_bytes())
            .await
            .expect("write request");
        writer.write_all(b"\n").await.expect("write newline");
        writer.flush().await.expect("flush");

        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        serde_json::from_str(&line).expect("parse response JSON")
    }

    /// Connect to the server and initialize with a session ID.
    async fn connect_and_init(
        socket_path: &Path,
    ) -> (
        tokio::net::unix::OwnedWriteHalf,
        BufReader<tokio::net::unix::OwnedReadHalf>,
        SessionId,
    ) {
        let stream = UnixStream::connect(socket_path)
            .await
            .expect("connect to MCP socket");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let session_id = SessionId::new();
        let init = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"session_id":"{}"}}}}"#,
            session_id
        );
        let resp = send_request(&mut writer, &mut reader, &init).await;
        assert_eq!(resp["result"]["serverInfo"]["name"], "sigil-mcp");

        (writer, reader, session_id)
    }

    // -- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn mcp_socket_accepts_connection_and_initializes() {
        let (socket_path, shutdown, _dir) = start_test_server().await;

        let stream = UnixStream::connect(&socket_path)
            .await
            .expect("connect to MCP socket");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let session_id = SessionId::new();
        let init = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"session_id":"{}"}}}}"#,
            session_id
        );

        let resp = send_request(&mut writer, &mut reader, &init).await;

        assert!(resp.get("error").is_none(), "should not have error");
        assert_eq!(resp["result"]["serverInfo"]["name"], "sigil-mcp");
        assert!(resp["result"]["capabilities"]["tools"].is_object());

        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mcp_socket_tools_list_returns_schemas() {
        let (socket_path, shutdown, _dir) = start_test_server().await;
        let (mut writer, mut reader, _) = connect_and_init(&socket_path).await;

        let resp = send_request(
            &mut writer,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )
        .await;

        assert!(resp.get("error").is_none());
        let tools = resp["result"]["tools"].as_array().expect("tools array");
        assert!(!tools.is_empty());

        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"request_approval"));
        assert!(names.contains(&"list_sessions"));
        assert!(names.contains(&"get_session_status"));
        assert!(names.contains(&"send_message"));
        assert!(names.contains(&"read_session_output"));

        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mcp_socket_tools_call_allowed() {
        let (socket_path, shutdown, _dir) = start_test_server().await;
        let (mut writer, mut reader, _) = connect_and_init(&socket_path).await;

        // ListSessions is T0 — allowed for agents.
        let resp = send_request(
            &mut writer,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_sessions"}}"#,
        )
        .await;

        assert!(resp.get("error").is_none());
        let text = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let tool_result: ToolResult = serde_json::from_str(text).expect("ToolResult");
        assert_eq!(tool_result.status, ToolStatus::Allowed);

        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mcp_socket_tools_call_denied_by_ceiling() {
        let (socket_path, shutdown, _dir) = start_test_server().await;
        let (mut writer, mut reader, _) = connect_and_init(&socket_path).await;

        // ReadHostFile requires T3 — agent ceiling is T1 → denied.
        let resp = send_request(
            &mut writer,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_approval","arguments":{"action":"ReadHostFile","path":"/etc/shadow"}}}"#,
        )
        .await;

        assert!(resp.get("error").is_none());
        let text = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let tool_result: ToolResult = serde_json::from_str(text).expect("ToolResult");
        assert_eq!(tool_result.status, ToolStatus::Denied);

        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mcp_socket_shutdown_cleans_up() {
        let (socket_path, shutdown, _dir) = start_test_server().await;

        // Verify socket exists.
        assert!(socket_path.exists(), "socket should exist before shutdown");

        // Signal shutdown.
        let _ = shutdown.send(true);

        // Give the server a moment to clean up.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            !socket_path.exists(),
            "socket should be removed after shutdown"
        );
    }

    #[tokio::test]
    async fn mcp_socket_path_uses_session_title() {
        let path = mcp_socket_path("agent-01");
        assert_eq!(path, PathBuf::from("/tmp/sigil-mcp-agent-01.sock"));
    }

    #[tokio::test]
    async fn mcp_socket_rejects_tools_call_without_init() {
        let (socket_path, shutdown, _dir) = start_test_server().await;

        let stream = UnixStream::connect(&socket_path)
            .await
            .expect("connect to MCP socket");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Skip initialize — go straight to tools/call.
        let resp = send_request(
            &mut writer,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_sessions"}}"#,
        )
        .await;

        assert!(
            resp.get("error").is_some(),
            "should have error without init"
        );

        let _ = shutdown.send(true);
    }
}
