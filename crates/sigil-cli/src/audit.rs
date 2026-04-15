//! CLI audit integration — initializes the `AuditLogWriter` and provides
//! a helper for emitting audit events from command handlers.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use sigil_audit::{AuditLogWriter, LoadedKey, load_audit_key};
use sigil_core::PolicyDecision;
use sigil_core::id::{RequestId, SessionId};
use sigil_core::traits::AuditEvent;

/// Resolve the audit HMAC key using the documented priority order
/// (env > Keychain > opt-in dev fallback).
///
/// # Errors
///
/// Returns an error if no key source is available.
pub fn resolve_key() -> Result<LoadedKey> {
    load_audit_key().context("failed to resolve audit HMAC key")
}

/// Create an `AuditLogWriter` rooted in the sigil data directory.
///
/// The HMAC key is resolved via [`resolve_key`].
///
/// # Errors
///
/// Returns an error if no key source is available, or if the audit log
/// file cannot be opened or created.
pub async fn init_audit_writer(data_dir: &Path) -> Result<Arc<AuditLogWriter>> {
    let LoadedKey { bytes, source } = resolve_key()?;
    tracing::info!(source = source.label(), "loaded audit HMAC key");
    init_audit_writer_with_key(data_dir, bytes).await
}

/// Same as [`init_audit_writer`], but with an explicitly supplied key.
///
/// Intended for tests and embedders that resolve the key themselves.
///
/// # Errors
///
/// Returns an error if the audit log file cannot be opened or created.
pub async fn init_audit_writer_with_key(
    data_dir: &Path,
    key: impl Into<Zeroizing<Vec<u8>>>,
) -> Result<Arc<AuditLogWriter>> {
    let audit_path = data_dir.join("audit.jsonl");
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
