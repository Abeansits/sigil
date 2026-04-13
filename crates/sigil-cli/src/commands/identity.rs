//! Identity subcommands — reload and snapshot.

use std::sync::Arc;

use anyhow::{Result, bail};

use sigil_audit::AuditLogWriter;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::IdentitySpec;
use sigil_core::traits::SessionRuntime;
use sigil_store::Store;

use crate::IdentityCommands;
use crate::audit::log_event;
use crate::commands::session::resolve_session;

/// Route an `IdentityCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if any identity operation fails.
pub async fn run<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &Arc<AuditLogWriter>,
    cmd: IdentityCommands,
) -> Result<()> {
    match cmd {
        IdentityCommands::Reload { name } => reload(store, runtime, audit, &name).await,
        IdentityCommands::Snapshot { name } => snapshot(store, runtime, audit, &name).await,
    }
}

/// Send a reload message to an active session, instructing it to re-read
/// its identity files.
#[allow(clippy::print_stdout)]
async fn reload<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
) -> Result<()> {
    let session = resolve_session(store, name).await?;

    let spec = session
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("session '{name}' has no identity spec configured"))?;

    let message = build_reload_message(spec);
    let handle = sigil_conductor::action_service::record_to_handle(&session);

    runtime
        .send(
            &handle,
            ConductorMessage::TaskAssignment {
                instructions: message,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to send reload message: {e}"))?;

    log_event(
        audit,
        "identity.reload",
        "cli",
        sigil_core::PolicyDecision::Allow,
        Some(session.id),
    )
    .await;

    println!("Sent identity reload to '{}'.", session.title);
    Ok(())
}

/// Send a snapshot message to an active session, instructing it to persist
/// current state before context compaction.
#[allow(clippy::print_stdout)]
async fn snapshot<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
) -> Result<()> {
    let session = resolve_session(store, name).await?;

    if session.identity.is_none() {
        bail!("session '{name}' has no identity spec configured");
    }

    let message = build_snapshot_message();
    let handle = sigil_conductor::action_service::record_to_handle(&session);

    runtime
        .send(
            &handle,
            ConductorMessage::TaskAssignment {
                instructions: message,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to send snapshot message: {e}"))?;

    log_event(
        audit,
        "identity.snapshot",
        "cli",
        sigil_core::PolicyDecision::Allow,
        Some(session.id),
    )
    .await;

    println!("Sent identity snapshot to '{}'.", session.title);
    Ok(())
}

/// Build the reload message listing identity files in order.
fn build_reload_message(spec: &IdentitySpec) -> String {
    let file_list: String = spec
        .files
        .iter()
        .enumerate()
        .map(|(i, f)| format!("{}. {}", i + 1, f.display()))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "[SIGIL] Context was compacted. Re-read your identity files now, in this order:\n\
         {file_list}\n\
         These files define who you are and how you operate. Read each one before continuing."
    )
}

/// Build the pre-compaction snapshot message.
fn build_snapshot_message() -> String {
    "[SIGIL] Context compaction is about to happen. Write any important state to disk now. \
     Update state.json with current context before it's lost."
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sigil_core::session::{IdentitySpec, LifecycleEvent};

    use super::*;

    #[test]
    fn reload_message_includes_all_files_in_order() {
        let spec = IdentitySpec {
            files: vec![
                PathBuf::from("SOUL.md"),
                PathBuf::from("OPS.md"),
                PathBuf::from("state.json"),
            ],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let msg = build_reload_message(&spec);
        assert!(msg.contains("[SIGIL]"));
        assert!(msg.contains("1. SOUL.md"));
        assert!(msg.contains("2. OPS.md"));
        assert!(msg.contains("3. state.json"));
        assert!(msg.contains("Read each one before continuing"));
    }

    #[test]
    fn reload_message_single_file() {
        let spec = IdentitySpec {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let msg = build_reload_message(&spec);
        assert!(msg.contains("1. SOUL.md"));
        assert!(!msg.contains("2."));
    }

    #[test]
    fn reload_message_empty_files() {
        let spec = IdentitySpec {
            files: vec![],
            reload_on: vec![LifecycleEvent::PostCompact],
        };

        let msg = build_reload_message(&spec);
        assert!(msg.contains("[SIGIL]"));
        assert!(msg.contains("Read each one before continuing"));
    }

    #[test]
    fn snapshot_message_content() {
        let msg = build_snapshot_message();
        assert!(msg.contains("[SIGIL]"));
        assert!(msg.contains("compaction is about to happen"));
        assert!(msg.contains("state.json"));
    }
}
