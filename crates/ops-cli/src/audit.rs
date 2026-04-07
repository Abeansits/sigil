//! CLI audit integration — initializes the `AuditLogWriter` and provides
//! a helper for emitting audit events from command handlers.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use ops_audit::AuditLogWriter;
use ops_core::PolicyDecision;
use ops_core::id::{RequestId, SessionId};
use ops_core::traits::AuditEvent;

/// Default HMAC key for development. In production, set
/// `AGENT_OPS_AUDIT_KEY` (and later move to macOS Keychain).
const DEV_FALLBACK_KEY: &[u8] = b"agent-ops-dev-audit-key-CHANGE-ME";

/// Create an `AuditLogWriter` rooted in the agent-ops data directory.
///
/// Uses `AGENT_OPS_AUDIT_KEY` env var for the HMAC key, falling back
/// to a built-in development key.
///
/// # Errors
///
/// Returns an error if the audit log file cannot be opened or created.
pub async fn init_audit_writer(data_dir: &Path) -> Result<Arc<AuditLogWriter>> {
    let audit_path = data_dir.join("audit.jsonl");

    let key = std::env::var("AGENT_OPS_AUDIT_KEY")
        .map_or_else(|_| DEV_FALLBACK_KEY.to_vec(), String::into_bytes);

    let writer = AuditLogWriter::new(&audit_path, key)
        .await
        .context("failed to open audit log")?;

    Ok(Arc::new(writer))
}

/// Log an audit event. Errors are logged via tracing but never propagated
/// to the caller -- audit failures must not break user-facing operations.
pub async fn log_event(
    writer: &AuditLogWriter,
    action: &str,
    origin: &str,
    decision: PolicyDecision,
    session_id: Option<SessionId>,
) {
    let event = AuditEvent {
        request_id: RequestId::new(),
        timestamp: time::OffsetDateTime::now_utc(),
        action_summary: action.to_owned(),
        origin_summary: origin.to_owned(),
        decision,
        session_id,
    };

    if let Err(e) = writer.append(&event).await {
        tracing::warn!(error = %e, action, "failed to write audit event");
    }
}
