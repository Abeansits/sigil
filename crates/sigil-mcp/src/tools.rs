//! MCP tool definitions.
//!
//! Each tool maps to an action that an agent can request through the
//! policy-mediated MCP server. The tools define the schema for
//! `tools/list` and are used to parse `tools/call` parameters.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use sigil_core::action::Action;
use sigil_core::id::SessionId;

/// The set of MCP tools exposed to agents.
///
/// Each variant maps to one or more `Action` variants in sigil-core.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "name", content = "arguments")]
#[non_exhaustive]
pub enum McpTool {
    /// Request approval to read a file on the host filesystem.
    #[serde(rename = "request_approval")]
    RequestApproval(RequestApprovalParams),

    /// List active sessions.
    #[serde(rename = "list_sessions")]
    ListSessions,

    /// Get the status of a specific session.
    #[serde(rename = "get_session_status")]
    GetSessionStatus(SessionIdParam),

    /// Send a message to a session.
    #[serde(rename = "send_message")]
    SendMessage(SendMessageParams),

    /// Read the output of a session.
    #[serde(rename = "read_session_output")]
    ReadSessionOutput(SessionIdParam),
}

/// Parameters for the `request_approval` tool.
#[derive(Clone, Debug, Deserialize)]
pub struct RequestApprovalParams {
    /// The action being requested (e.g., `ReadHostFile`, `WriteHostFile`).
    pub action: String,
    /// Optional file path for file operations.
    pub path: Option<String>,
    /// Optional justification for the request.
    pub justification: Option<String>,
}

/// A session ID parameter.
#[derive(Clone, Debug, Deserialize)]
pub struct SessionIdParam {
    pub session_id: String,
}

/// Parameters for the `send_message` tool.
#[derive(Clone, Debug, Deserialize)]
pub struct SendMessageParams {
    pub session_id: String,
    pub message: String,
}

/// The result of a tool call, returned to the agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the action was allowed, denied, or needs approval.
    pub status: ToolStatus,
    /// Human-readable description of the outcome.
    pub message: String,
    /// Optional structured data (e.g., session list, file contents).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// The status of a tool call.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Allowed,
    Denied,
    NeedsApproval,
    Error,
}

/// MCP tool schema for `tools/list` response.
#[derive(Clone, Debug, Serialize)]
pub struct ToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Return the list of tool schemas for the `tools/list` response.
pub fn tool_schemas() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "request_approval",
            description: "Request approval for a privileged action on the host. \
                          The action will be evaluated against the security policy. \
                          Returns allowed, denied, or needs_approval.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "The action to request (ReadHostFile, WriteHostFile, ExecuteHostCommand, ModifyGitState, BreakGlass)",
                    },
                    "path": {
                        "type": "string",
                        "description": "File or directory path for file operations",
                    },
                    "justification": {
                        "type": "string",
                        "description": "Why this action is needed (required for BreakGlass)",
                    },
                },
                "required": ["action"],
            }),
        },
        ToolSchema {
            name: "list_sessions",
            description: "List all active agent sessions.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
            }),
        },
        ToolSchema {
            name: "get_session_status",
            description: "Get the current status of a specific session.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session identifier",
                    },
                },
                "required": ["session_id"],
            }),
        },
        ToolSchema {
            name: "send_message",
            description: "Send a message to a specific agent session.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session identifier",
                    },
                    "message": {
                        "type": "string",
                        "description": "The message to send",
                    },
                },
                "required": ["session_id", "message"],
            }),
        },
        ToolSchema {
            name: "read_session_output",
            description: "Read the recent output of a specific agent session.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session identifier",
                    },
                },
                "required": ["session_id"],
            }),
        },
    ]
}

impl McpTool {
    /// Convert this tool call into a sigil-core `Action` and an
    /// originating `SessionId` (if available).
    ///
    /// # Errors
    ///
    /// Returns an error string if the parameters are invalid (e.g.,
    /// unrecognized action name, missing required fields).
    pub fn into_action(self) -> Result<Action, String> {
        match self {
            Self::RequestApproval(params) => params_to_action(&params),
            Self::ListSessions => Ok(Action::ListSessions),
            Self::GetSessionStatus(p) => {
                let session_id = parse_session_id(&p.session_id)?;
                Ok(Action::GetSessionStatus { session_id })
            }
            Self::SendMessage(p) => {
                let session_id = parse_session_id(&p.session_id)?;
                Ok(Action::SendMessage {
                    session_id,
                    message: p.message,
                })
            }
            Self::ReadSessionOutput(p) => {
                let session_id = parse_session_id(&p.session_id)?;
                Ok(Action::ReadSessionOutput { session_id })
            }
        }
    }
}

/// Parse a `RequestApprovalParams` into an `Action`.
fn params_to_action(params: &RequestApprovalParams) -> Result<Action, String> {
    match params.action.as_str() {
        "ReadHostFile" => {
            let path = params
                .path
                .as_deref()
                .ok_or("ReadHostFile requires a 'path' parameter")?;
            Ok(Action::ReadHostFile {
                path: PathBuf::from(path),
            })
        }
        "WriteHostFile" => {
            let path = params
                .path
                .as_deref()
                .ok_or("WriteHostFile requires a 'path' parameter")?;
            Ok(Action::WriteHostFile {
                path: PathBuf::from(path),
                content: Vec::new(), // Content handled separately
            })
        }
        "BreakGlass" => {
            let justification = params
                .justification
                .as_deref()
                .ok_or("BreakGlass requires a 'justification' parameter")?;
            let cwd = params
                .path
                .as_deref()
                .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            Ok(Action::BreakGlass {
                command: Vec::new(), // Command details come from approval flow
                cwd,
                justification: justification.to_owned(),
            })
        }
        other => Err(format!("unrecognized action: {other}")),
    }
}

/// Parse a session ID string into a `SessionId`.
fn parse_session_id(s: &str) -> Result<SessionId, String> {
    s.parse::<ulid::Ulid>()
        .map(SessionId::from_ulid)
        .map_err(|e| format!("invalid session_id '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn tool_schemas_are_valid_json() {
        let schemas = tool_schemas();
        assert!(!schemas.is_empty());
        for schema in &schemas {
            // Each schema should serialize to valid JSON.
            let json = serde_json::to_value(schema).expect("schema should serialize");
            assert!(json.get("name").is_some());
            assert!(json.get("description").is_some());
            assert!(json.get("inputSchema").is_some());
        }
    }

    #[test]
    fn parse_request_approval_read_host_file() {
        let tool = McpTool::RequestApproval(RequestApprovalParams {
            action: "ReadHostFile".into(),
            path: Some("/etc/hosts".into()),
            justification: None,
        });
        let action = tool.into_action().expect("should parse");
        assert!(matches!(action, Action::ReadHostFile { .. }));
    }

    #[test]
    fn parse_request_approval_missing_path_errors() {
        let tool = McpTool::RequestApproval(RequestApprovalParams {
            action: "ReadHostFile".into(),
            path: None,
            justification: None,
        });
        let result = tool.into_action();
        assert!(result.is_err());
    }

    #[test]
    fn parse_request_approval_unknown_action_errors() {
        let tool = McpTool::RequestApproval(RequestApprovalParams {
            action: "DeleteEverything".into(),
            path: None,
            justification: None,
        });
        let result = tool.into_action();
        assert!(result.is_err());
    }

    #[test]
    fn parse_list_sessions() {
        let tool = McpTool::ListSessions;
        let action = tool.into_action().expect("should parse");
        assert!(matches!(action, Action::ListSessions));
    }

    #[test]
    fn parse_break_glass_requires_justification() {
        let tool = McpTool::RequestApproval(RequestApprovalParams {
            action: "BreakGlass".into(),
            path: None,
            justification: None,
        });
        let result = tool.into_action();
        assert!(result.is_err());
    }

    #[test]
    fn parse_break_glass_with_justification() {
        let tool = McpTool::RequestApproval(RequestApprovalParams {
            action: "BreakGlass".into(),
            path: Some("/tmp".into()),
            justification: Some("debugging".into()),
        });
        let action = tool.into_action().expect("should parse");
        assert!(matches!(action, Action::BreakGlass { .. }));
    }

    #[test]
    fn tool_result_serialization() {
        let result = ToolResult {
            status: ToolStatus::Allowed,
            message: "Action allowed".into(),
            data: None,
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["status"], "allowed");
    }

    #[test]
    fn deserialize_mcp_tool_from_json() {
        let json = r#"{"name":"request_approval","arguments":{"action":"ReadHostFile","path":"/etc/hosts"}}"#;
        let tool: McpTool = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(tool, McpTool::RequestApproval(_)));
    }

    #[test]
    fn deserialize_list_sessions_from_json() {
        let json = r#"{"name":"list_sessions"}"#;
        let tool: McpTool = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(tool, McpTool::ListSessions));
    }
}
