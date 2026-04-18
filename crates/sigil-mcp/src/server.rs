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

use sigil_content::{DisabledFetcher, ExternalContentFetcher, RawFetchedContent, Sanitizer};
use sigil_core::action::{Action, ActionRequest, ActionResult, PolicyDecision};
use sigil_core::content::{ContentSource, ContentType};
use sigil_core::id::SessionId;
use sigil_core::origin::ActionOrigin;
use sigil_policy::grants::GrantStore;
use sigil_policy::{Evaluator, EvaluatorConfig};

use crate::error::{McpError, codes};
use crate::tools::{McpTool, ToolResult, ToolStatus, tool_schemas};
use crate::transport::{JsonRpcRequest, JsonRpcResponse};

/// The MCP server. Holds a policy evaluator and the session ID of the
/// agent that connects to it (set during initialization).
///
/// When built with [`McpServer::with_sanitizer`], external-content
/// tool calls (`fetch_url`) run the fetched bytes through the
/// `sigil-content` pipeline before the agent sees any data. Servers
/// built without a sanitizer deny `fetch_url` requests cleanly through
/// the same post-dispatch evaluator gate that the conductor uses.
pub struct McpServer<G: GrantStore> {
    evaluator: Evaluator<G>,
    /// The session ID of the connected agent, set during `initialize`.
    agent_session_id: Option<SessionId>,
    /// Optional sanitizer. `None` means every `fetch_url` call fails
    /// cleanly — no silent passthrough.
    sanitizer: Option<Arc<Sanitizer>>,
    /// Fetcher implementation. Defaults to [`DisabledFetcher`].
    fetcher: Arc<dyn ExternalContentFetcher>,
}

impl<G: GrantStore> McpServer<G> {
    /// Create a new MCP server with the given evaluator.
    #[must_use]
    pub fn new(evaluator: Evaluator<G>) -> Self {
        Self {
            evaluator,
            agent_session_id: None,
            sanitizer: None,
            fetcher: Arc::new(DisabledFetcher),
        }
    }

    /// Create a new MCP server with default config and the given grant store.
    #[must_use]
    pub fn with_grants(grants: Arc<G>) -> Self {
        Self {
            evaluator: Evaluator::new(EvaluatorConfig::default(), grants),
            agent_session_id: None,
            sanitizer: None,
            fetcher: Arc::new(DisabledFetcher),
        }
    }

    /// Install a sanitizer. Without one, `fetch_url` tool calls produce
    /// a clean `Error` status rather than returning unsanitized bytes.
    #[must_use]
    pub fn with_sanitizer(mut self, sanitizer: Arc<Sanitizer>) -> Self {
        self.sanitizer = Some(sanitizer);
        self
    }

    /// Install a fetcher for `fetch_url` tool calls. Defaults to
    /// [`DisabledFetcher`].
    #[must_use]
    pub fn with_fetcher(mut self, fetcher: Arc<dyn ExternalContentFetcher>) -> Self {
        self.fetcher = fetcher;
        self
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
        let decision = match self.evaluator.evaluate(&action_request).await {
            Ok(decision) => decision,
            Err(e) => {
                let tool_result = ToolResult {
                    status: ToolStatus::Error,
                    message: format!("policy evaluation failed: {e}"),
                    data: None,
                };
                return package_tool_result(request.id.clone(), &tool_result);
            }
        };

        let tool_result = match &decision {
            PolicyDecision::Allow => self.dispatch_allowed(&action_request).await,
            PolicyDecision::Deny { .. } | PolicyDecision::NeedsApproval { .. } => {
                decision_to_tool_result(&decision)
            }
        };

        package_tool_result(request.id.clone(), &tool_result)
    }

    /// Run the MCP side of a post-`Allow` tool call.
    ///
    /// For `FetchExternalContent`, this is where the sanitizer runs:
    /// fetch → sanitize → `evaluate_result` gate → package the cleaned
    /// text + report into the [`ToolResult`] data field. Every other
    /// action's `Allow` today produces a "policy allowed" stub (no
    /// execution in MCP — that happens in the conductor via
    /// `ActionService`); the caller does not treat this as a
    /// regression.
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "only FetchExternalContent needs dispatch; everything else returns the policy-allowed stub"
    )]
    async fn dispatch_allowed(&self, request: &ActionRequest) -> ToolResult {
        match &request.action {
            Action::FetchExternalContent { url, content_type } => {
                self.dispatch_fetch_url(request, url, *content_type).await
            }
            _ => decision_to_tool_result(&PolicyDecision::Allow),
        }
    }

    /// Fetch + sanitize + post-dispatch gate. Factored out so the
    /// `Allow` dispatch stays readable.
    async fn dispatch_fetch_url(
        &self,
        request: &ActionRequest,
        url: &str,
        content_type: ContentType,
    ) -> ToolResult {
        let Some(sanitizer) = self.sanitizer.as_ref() else {
            return ToolResult {
                status: ToolStatus::Error,
                message: "fetch_url: no sanitizer configured on this MCP server".into(),
                data: None,
            };
        };

        // Fetch raw bytes.
        let bytes = match self.fetcher.fetch(url).await {
            Ok(b) => b,
            Err(e) => {
                return ToolResult {
                    status: ToolStatus::Error,
                    message: format!("fetch failed: {e}"),
                    data: None,
                };
            }
        };

        // Sanitize.
        let source =
            ContentSource::from_url(url).unwrap_or_else(|_| ContentSource::Other(url.to_owned()));
        let raw = RawFetchedContent::from_bytes(bytes);
        let cleaned = match run_sanitize(sanitizer, raw, source, content_type) {
            Ok(s) => s,
            Err(e) => {
                return ToolResult {
                    status: ToolStatus::Error,
                    message: format!("sanitize failed: {e}"),
                    data: None,
                };
            }
        };

        // Post-dispatch policy gate — enforces SanitizationRequirement
        // end-to-end even on the MCP path (not just the conductor).
        let report = cleaned.report.clone();
        let action_result = ActionResult::new().with_sanitize_report(report.clone());
        match self
            .evaluator
            .evaluate_result(request, &action_result)
            .await
        {
            Ok(PolicyDecision::Allow) => {
                let data = serde_json::json!({
                    "text": cleaned.text,
                    "report": report,
                });
                ToolResult {
                    status: ToolStatus::Allowed,
                    message: "fetch_url: content sanitized and returned.".into(),
                    data: Some(data),
                }
            }
            Ok(PolicyDecision::Deny { reason }) => ToolResult {
                status: ToolStatus::Denied,
                message: format!("post-dispatch policy deny: {reason}"),
                // Include the report so operators can see what was
                // seen even when the content itself is blocked.
                data: Some(serde_json::json!({ "report": report })),
            },
            Ok(PolicyDecision::NeedsApproval { description }) => ToolResult {
                status: ToolStatus::NeedsApproval,
                message: description,
                data: None,
            },
            Err(e) => ToolResult {
                status: ToolStatus::Error,
                message: format!("post-dispatch policy eval failed: {e}"),
                data: None,
            },
        }
    }
}

/// Wrap a [`ToolResult`] into the MCP `tools/call` response envelope.
fn package_tool_result(id: Option<serde_json::Value>, tool_result: &ToolResult) -> JsonRpcResponse {
    let result_text = match serde_json::to_string(tool_result) {
        Ok(text) => text,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
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

    JsonRpcResponse::success(id, content)
}

/// Dispatch raw bytes into the sanitizer entry point that matches
/// the declared content type. Thin wrapper around
/// [`sigil_content::dispatch_sanitize`] that stringifies the error so
/// it slots into [`ToolResult::message`].
///
/// Shared with `sigil-conductor` via `sigil_content::dispatch_sanitize`
/// — one format-dispatch switch for both call sites, so adding a new
/// `ContentType` variant is a one-place change.
fn run_sanitize(
    sanitizer: &Sanitizer,
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
) -> Result<sigil_core::content::SanitizedContent, String> {
    sigil_content::dispatch_sanitize(sanitizer, raw, source, content_type)
        .map_err(|e| format!("sanitize({content_type:?}): {e}"))
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

    // -----------------------------------------------------------------------
    // fetch_url tool — PR7 content-sanitization wiring
    // -----------------------------------------------------------------------

    /// Schema advertises the new tool with the right enum of content
    /// types. Other schemas stay present (regression check).
    #[tokio::test]
    async fn tools_list_includes_fetch_url_schema() {
        let mut server = make_server();
        let req = make_request("tools/list", serde_json::json!({}));
        let resp = server.handle_request(&req).await;
        let tools = resp.result.expect("result")["tools"]
            .as_array()
            .expect("tools array")
            .clone();
        let fetch = tools
            .iter()
            .find(|t| t["name"] == "fetch_url")
            .expect("fetch_url schema present");
        let types = fetch["inputSchema"]["properties"]["content_type"]["enum"]
            .as_array()
            .expect("content_type enum");
        let type_strs: Vec<&str> = types.iter().filter_map(|v| v.as_str()).collect();
        assert!(type_strs.contains(&"html"));
        assert!(type_strs.contains(&"markdown"));
        assert!(type_strs.contains(&"json"));
    }

    /// Without a configured grant for `FetchExternalContent`, the
    /// agent's `fetch_url` call hits the grant-gate and returns
    /// `NeedsApproval` — no fetch, no sanitize, no silent passthrough.
    #[tokio::test]
    async fn fetch_url_without_grant_needs_approval() {
        let (mut server, _) = init_server().await;
        let req = make_request(
            "tools/call",
            serde_json::json!({
                "name": "fetch_url",
                "arguments": {
                    "url": "https://example.com/a",
                    "content_type": "html",
                }
            }),
        );
        let resp = server.handle_request(&req).await;
        let result = resp.result.expect("result");
        let text = result["content"][0]["text"].as_str().expect("text");
        let tool_result: ToolResult = serde_json::from_str(text).expect("tool result");
        assert_eq!(tool_result.status, ToolStatus::NeedsApproval);
    }

    /// Invalid `content_type` in arguments surfaces as
    /// `INVALID_PARAMS` — the MCP server never falls back to a
    /// default sanitize path.
    #[tokio::test]
    async fn fetch_url_rejects_unknown_content_type() {
        let (mut server, _) = init_server().await;
        let req = make_request(
            "tools/call",
            serde_json::json!({
                "name": "fetch_url",
                "arguments": {
                    "url": "https://example.com/a",
                    "content_type": "yaml",
                }
            }),
        );
        let resp = server.handle_request(&req).await;
        assert!(
            resp.error.is_some(),
            "unknown content_type must be a JSON-RPC error"
        );
        assert_eq!(resp.error.expect("error").code, codes::INVALID_PARAMS,);
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
