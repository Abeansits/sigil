use std::future::Future;

use crate::action::{ActionRequest, PolicyDecision};
use crate::error::CoreError;
use crate::protocol::{AgentSignal, BridgeMessage, ConductorMessage, HookFormat, StatusPattern};
use crate::session::{SessionConfig, SessionHandle, SessionState};

// ---------------------------------------------------------------------------
// Session runtime — implemented by tmux backend (and later container backend)
// ---------------------------------------------------------------------------

/// Manages agent session lifecycles. The conductor uses this trait;
/// the runtime crate provides the implementation.
pub trait SessionRuntime: Send + Sync {
    fn launch(
        &self,
        config: &SessionConfig,
    ) -> impl Future<Output = Result<SessionHandle, CoreError>> + Send;

    fn send(
        &self,
        handle: &SessionHandle,
        msg: ConductorMessage,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn read_output(
        &self,
        handle: &SessionHandle,
    ) -> impl Future<Output = Result<String, CoreError>> + Send;

    fn status(
        &self,
        handle: &SessionHandle,
    ) -> impl Future<Output = Result<SessionState, CoreError>> + Send;

    fn stop(&self, handle: &SessionHandle) -> impl Future<Output = Result<(), CoreError>> + Send;
}

// ---------------------------------------------------------------------------
// Tool adapter — translates between structured protocol and terminal I/O
// ---------------------------------------------------------------------------

/// Tool-specific behavior abstraction. Observability only — never authority.
pub trait ToolAdapter: Send + Sync {
    /// Regex patterns for detecting session state from terminal output.
    fn status_patterns(&self) -> &[StatusPattern];

    /// How this tool emits status events.
    fn hook_format(&self) -> HookFormat;

    /// Translate a structured conductor message to terminal input.
    fn translate_send(&self, msg: &ConductorMessage) -> String;

    /// Parse terminal output into structured signals.
    /// **Observability only** — results never produce `ActionRequest`s.
    fn parse_output(&self, raw: &str) -> Vec<AgentSignal>;
}

// ---------------------------------------------------------------------------
// Policy engine — evaluates action requests
// ---------------------------------------------------------------------------

/// Evaluates whether an action request should be allowed, denied, or
/// requires approval. Implemented by `ops-policy`.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        request: &ActionRequest,
    ) -> impl Future<Output = Result<PolicyDecision, CoreError>> + Send;
}

// ---------------------------------------------------------------------------
// Message routing — decouples bridge from conductor
// ---------------------------------------------------------------------------

/// Accepts messages from bridges for routing to sessions or conductor.
pub trait MessageSink: Send + Sync {
    fn accept(&self, message: BridgeMessage) -> impl Future<Output = Result<(), CoreError>> + Send;
}

/// Produces messages to send back through bridges.
pub trait MessageSource: Send + Sync {
    fn next_message(&self)
    -> impl Future<Output = Result<Option<BridgeMessage>, CoreError>> + Send;
}

/// Routes `ActionRequest`s to the appropriate handler.
pub trait ActionRouter: Send + Sync {
    fn route(
        &self,
        request: ActionRequest,
    ) -> impl Future<Output = Result<PolicyDecision, CoreError>> + Send;
}

// ---------------------------------------------------------------------------
// Audit writer — append-only event logging
// ---------------------------------------------------------------------------

/// Appends events to the audit trail. Implemented by `ops-audit`.
pub trait AuditWriter: Send + Sync {
    fn append(&self, event: &AuditEvent) -> impl Future<Output = Result<(), CoreError>> + Send;
}

/// An audit trail event.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub request_id: crate::id::RequestId,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: time::OffsetDateTime,
    pub action_summary: String,
    pub origin_summary: String,
    pub decision: PolicyDecision,
    pub session_id: Option<crate::id::SessionId>,
}
