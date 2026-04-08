//! MCP server — policy-mediated proxy for agent actions.
//!
//! The server reads JSON-RPC 2.0 messages from stdin, dispatches tool
//! calls through the policy evaluator, and writes responses to stdout.
//! It is NOT a host shell — every action goes through the sigil policy
//! engine before any effect occurs.
//!
//! # Protocol
//!
//! ```text
//! Agent → MCP tool call → ActionRequest → sigil-policy → result
//! ```
//!
//! The server handles three MCP message types:
//! - `initialize` — handshake, returns server capabilities
//! - `tools/list` — returns available tool schemas
//! - `tools/call` — dispatches a tool call through policy

use std::sync::Arc;

use sigil_core::action::{ActionRequest, PolicyDecision};
use sigil_core::id::SessionId;
use sigil_core::origin::ActionOrigin;
use sigil_policy::grants::GrantStore;
use sigil_policy::{Evaluator, EvaluatorConfig};

use crate::error::{McpError, codes};
use crate::tools::{McpTool, ToolResult, ToolStatus, tool_schemas};
use crate::transport::{JsonRpcRequest, JsonRpcResponse};

/// The MCP server. Holds a policy evaluator and the session ID of the
/// agent that connects to it (set during initialization).
pub struct McpServer<G: GrantStore> {
    evaluator: Evaluator<G>,
    /// The session ID of the connected agent, set during `initialize`.
    agent_session_id: Option<SessionId>,
}

impl<G: GrantStore> McpServer<G> {
    /// Create a new MCP server with the given evaluator.
    #[must_use]
    pub fn new(evaluator: Evaluator<G>) -> Self {
        Self {
            evaluator,
            agent_session_id: None,
        }
    }

    /// Create a new MCP server with default config and the given grant store.
    #[must_use]
    pub fn with_grants(grants: Arc<G>) -> Self {
        Self {
            evaluator: Evaluator::new(EvaluatorConfig::default(), grants),
            agent_session_id: None,
        }
    }

    /// Handle a single JSON-RPC request and return a response.
    pub async fn handle_request(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request).await,
            "notifications/initialized" => {
                // Client acknowledgement — no response needed for notifications,
                // but we return success if an ID was provided.
                if let Some(ref id) = request.id {
                    JsonRpcResponse::success(Some(id.clone()), serde_json::json!({}))
                } else {
                    // Notifications have no ID — return an empty response.
                    JsonRpcResponse::success(None, serde_json::json!({}))
                }
            }
            _ => JsonRpcResponse::error(
                request.id.clone(),
                codes::METHOD_NOT_FOUND,
                format!("unknown method: {}", request.method),
            ),
        }
    }

    /// Handle the `initialize` handshake.
    ///
    /// A valid `session_id` is **required**. Without it, the server
    /// will still initialize (MCP protocol requirement) but tool calls
    /// will be rejected — we never fall back to `LocalCli` origin.
    fn handle_initialize(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        // Extract the session ID from params.
        if let Some(session_id_str) = request.params.get("session_id").and_then(|v| v.as_str()) {
            if let Ok(ulid) = session_id_str.parse::<ulid::Ulid>() {
                self.agent_session_id = Some(SessionId::from_ulid(ulid));
            }
        }

        if self.agent_session_id.is_none() {
            tracing::warn!("MCP initialize called without a valid session_id");
        }

        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "sigil-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
    }

    /// Handle `tools/list` — return available tool schemas.
    #[allow(clippy::unused_self)]
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let schemas = tool_schemas();
        JsonRpcResponse::success(request.id.clone(), serde_json::json!({ "tools": schemas }))
    }

    /// Handle `tools/call` — dispatch a tool call through policy.
    ///
    /// Requires a valid `session_id` from `initialize`. If no session ID
    /// was set, tool calls are rejected — we never fall back to `LocalCli`
    /// origin to prevent privilege escalation.
    async fn handle_tools_call(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        // Fail closed: reject tool calls without a valid agent session.
        let Some(session_id) = self.agent_session_id else {
            return JsonRpcResponse::error(
                request.id.clone(),
                codes::INVALID_REQUEST,
                "no valid session_id — call initialize with a session_id first".into(),
            );
        };

        // Parse the tool call from params.
        let tool = match serde_json::from_value::<McpTool>(request.params.clone()) {
            Ok(tool) => tool,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    codes::INVALID_PARAMS,
                    format!("invalid tool call: {e}"),
                );
            }
        };

        // Convert to a sigil-core Action.
        let action = match tool.into_action() {
            Ok(action) => action,
            Err(e) => {
                return JsonRpcResponse::error(request.id.clone(), codes::INVALID_PARAMS, e);
            }
        };

        // Create an ActionRequest with the agent's origin.
        let origin = ActionOrigin::AgentGenerated { session_id };

        let action_request = ActionRequest::new(action, origin);

        // Evaluate through policy.
        let tool_result = match self.evaluator.evaluate(&action_request).await {
            Ok(decision) => decision_to_tool_result(&decision),
            Err(e) => ToolResult {
                status: ToolStatus::Error,
                message: format!("policy evaluation failed: {e}"),
                data: None,
            },
        };

        // Wrap in MCP content format.
        let result_text = match serde_json::to_string(&tool_result) {
            Ok(text) => text,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    codes::INTERNAL_ERROR,
                    format!("failed to serialize tool result: {e}"),
                );
            }
        };

        let content = serde_json::json!({
            "content": [{
                "type": "text",
                "text": result_text,
            }],
            "isError": tool_result.status == ToolStatus::Error || tool_result.status == ToolStatus::Denied,
        });

        JsonRpcResponse::success(request.id.clone(), content)
    }
}

/// Convert a `PolicyDecision` to a `ToolResult`.
fn decision_to_tool_result(decision: &PolicyDecision) -> ToolResult {
    match decision {
        PolicyDecision::Allow => ToolResult {
            status: ToolStatus::Allowed,
            message: "Action allowed by policy.".into(),
            data: None,
        },
        PolicyDecision::Deny { reason } => ToolResult {
            status: ToolStatus::Denied,
            message: format!("Action denied: {reason}"),
            data: None,
        },
        PolicyDecision::NeedsApproval { description } => ToolResult {
            status: ToolStatus::NeedsApproval,
            message: format!("Action requires approval: {description}"),
            data: None,
        },
    }
}

/// Handle JSON-RPC messages from a buffered reader, writing responses
/// to a writer.
///
/// This is the transport-agnostic core of the MCP server. It reads
/// line-delimited JSON-RPC from `reader`, dispatches through the policy
/// evaluator, and writes responses to `writer`. Returns when the reader
/// reaches EOF (client disconnected).
///
/// Both `run_stdio` and the Unix socket transport in `sigil-runtime`
/// delegate to this function.
///
/// # Errors
///
/// Returns [`McpError`] on I/O or serialization failure.
pub async fn handle_stream<G, R, W>(
    grants: Arc<G>,
    mut reader: R,
    mut writer: W,
) -> Result<(), McpError>
where
    G: GrantStore,
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let mut server = McpServer::with_grants(grants);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        // EOF — client disconnected.
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse JSON-RPC request.
        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let resp =
                    JsonRpcResponse::error(None, codes::PARSE_ERROR, format!("invalid JSON: {e}"));
                let mut out = serde_json::to_vec(&resp)?;
                out.push(b'\n');
                writer.write_all(&out).await?;
                writer.flush().await?;
                continue;
            }
        };

        // Handle the request.
        let response = server.handle_request(&request).await;

        // Write response (skip for notifications without an ID).
        if request.id.is_some() || response.error.is_some() {
            let mut out = serde_json::to_vec(&response)?;
            out.push(b'\n');
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

/// Run the MCP server, reading from stdin and writing to stdout.
///
/// This is the main entry point for the `sigil mcp` command. It reads
/// line-delimited JSON-RPC messages from stdin, handles them, and
/// writes responses to stdout.
///
/// # Errors
///
/// Returns [`McpError::Io`] if stdin/stdout operations fail.
pub async fn run_stdio<G: GrantStore>(grants: Arc<G>) -> Result<(), McpError> {
    use tokio::io::BufReader;

    tracing::info!("sigil-mcp server starting on stdio");

    let reader = BufReader::new(tokio::io::stdin());
    let writer = tokio::io::stdout();
    handle_stream(grants, reader, writer).await?;

    tracing::info!("stdin closed, shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use std::sync::Arc;

    use sigil_policy::NoopGrantStore;

    use super::*;

    fn make_server() -> McpServer<NoopGrantStore> {
        McpServer::with_grants(Arc::new(NoopGrantStore))
    }

    fn make_request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::Value::Number(1.into())),
            method: method.into(),
            params,
        }
    }

    /// Initialize a server with a fresh agent session ID.
    async fn init_server() -> (McpServer<NoopGrantStore>, SessionId) {
        let mut server = make_server();
        let session_id = SessionId::new();
        let req = make_request(
            "initialize",
            serde_json::json!({ "session_id": session_id.to_string() }),
        );
        server.handle_request(&req).await;
        (server, session_id)
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let mut server = make_server();
        let req = make_request("initialize", serde_json::json!({}));
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_none());
        let result = resp.result.expect("should have result");
        assert_eq!(result["serverInfo"]["name"], "sigil-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn tools_list_returns_schemas() {
        let mut server = make_server();
        let req = make_request("tools/list", serde_json::json!({}));
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_none());
        let result = resp.result.expect("should have result");
        let tools = result["tools"].as_array().expect("tools should be array");
        assert!(!tools.is_empty());

        // Check that request_approval is in the list.
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"request_approval"));
        assert!(names.contains(&"list_sessions"));
    }

    #[tokio::test]
    async fn tools_call_without_init_rejected() {
        // Tool calls before initialize (no session_id) must be rejected
        // to prevent privilege escalation via LocalCli fallback.
        let mut server = make_server();
        let req = make_request("tools/call", serde_json::json!({ "name": "list_sessions" }));
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_some());
        let error = resp.error.expect("should have error");
        assert_eq!(error.code, codes::INVALID_REQUEST);
        assert!(error.message.contains("session_id"));
    }

    #[tokio::test]
    async fn tools_call_list_sessions_allowed_after_init() {
        let (mut server, _) = init_server().await;
        let req = make_request("tools/call", serde_json::json!({ "name": "list_sessions" }));
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_none());
        let result = resp.result.expect("should have result");
        let text = result["content"][0]["text"]
            .as_str()
            .expect("should have text");
        let tool_result: ToolResult = serde_json::from_str(text).expect("valid ToolResult");
        assert_eq!(tool_result.status, ToolStatus::Allowed);
    }

    #[tokio::test]
    async fn tools_call_invalid_tool_returns_error() {
        let (mut server, _) = init_server().await;
        let req = make_request(
            "tools/call",
            serde_json::json!({
                "name": "nonexistent_tool"
            }),
        );
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_some());
        let error = resp.error.expect("should have error");
        assert_eq!(error.code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let mut server = make_server();
        let req = make_request("bogus/method", serde_json::json!({}));
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_some());
        let error = resp.error.expect("should have error");
        assert_eq!(error.code, codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn initialize_with_session_id_sets_agent_origin() {
        let (server, session_id) = init_server().await;
        assert_eq!(server.agent_session_id, Some(session_id));
    }

    #[tokio::test]
    async fn agent_origin_read_host_file_denied_by_ceiling() {
        let (mut server, _) = init_server().await;

        // Agent tries to read a host file — denied because agent
        // ceiling is T1, ReadHostFile requires T3.
        let req = make_request(
            "tools/call",
            serde_json::json!({
                "name": "request_approval",
                "arguments": {
                    "action": "ReadHostFile",
                    "path": "/etc/shadow",
                }
            }),
        );
        let resp = server.handle_request(&req).await;

        assert!(resp.error.is_none());
        let result = resp.result.expect("should have result");
        let text = result["content"][0]["text"]
            .as_str()
            .expect("should have text");
        let tool_result: ToolResult = serde_json::from_str(text).expect("valid ToolResult");
        assert_eq!(tool_result.status, ToolStatus::Denied);
    }
}
