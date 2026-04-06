use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::id::{RequestId, SessionId};
use crate::session::SessionState;

/// Messages the conductor sends to an agent session.
///
/// Translated by `ToolAdapter` into tool-specific format before delivery.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConductorMessage {
    /// Assign work to the agent.
    TaskAssignment { instructions: String },

    /// Response to an agent's approval request.
    ApprovalResponse {
        request_id: RequestId,
        approved: bool,
        constraints: Option<String>,
    },

    /// Tell the agent to stop what it's doing.
    StopRequest { reason: String },

    /// Liveness check.
    Ping,
}

/// Signals parsed from agent output (terminal scraping).
///
/// These are **observability only** — they never produce `ActionRequest`s.
/// Authority flows exclusively through structured MCP tool calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AgentSignal {
    /// Agent's state changed (running → waiting, etc.).
    StatusUpdate { state: SessionState },

    /// Agent is requesting approval for a privileged operation.
    /// This comes through MCP, not terminal parsing. The `action_hint`
    /// is the structured request from the MCP tool call.
    ApprovalRequest {
        request_id: RequestId,
        description: String,
        action_hint: Option<Action>,
    },

    /// Agent reports task completion.
    CompletionSignal { summary: String },

    /// Agent is alive (periodic from hook or MCP ping).
    Heartbeat,
}

/// Pattern for detecting session state from terminal output.
///
/// Used by `ToolAdapter` implementations. Observability only.
#[derive(Clone, Debug)]
pub struct StatusPattern {
    pub state: SessionState,
    pub pattern: String,
    pub confidence: Confidence,
}

/// How confident the adapter is about a parsed signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// How a specific tool emits status events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HookFormat {
    /// Claude Code: uses hooks system (notification events).
    ClaudeCodeHooks,
    /// Codex: TBD.
    CodexOutput,
}

/// A message routed through the bridge (inbound from user).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub origin: crate::origin::ActionOrigin,
    pub text: String,
    pub target_session: Option<SessionId>,
    pub is_command: bool,
}
