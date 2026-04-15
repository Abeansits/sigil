//! Identity subcommands — reload and snapshot.
//!
//! Both variants build an `Action::SendMessage` with the appropriate
//! identity directive text and dispatch through [`ActionService`], so the
//! real policy decision is evaluated and audited by the same pipeline
//! that powers every other privileged CLI command.

use anyhow::{Context, Result, bail};

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::origin::ActionOrigin;
use sigil_core::session::IdentitySpec;
use sigil_core::traits::{LifecycleHooks, PolicyEngine, SessionRuntime};

use crate::IdentityCommands;
use crate::commands::session::resolve_session;

/// Route an `IdentityCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if policy denies the request or the send fails.
pub async fn run<R, P>(service: &ActionService<R, P>, cmd: IdentityCommands) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    match cmd {
        IdentityCommands::Reload { name } => reload(service, &name).await,
        IdentityCommands::Snapshot { name } => snapshot(service, &name).await,
    }
}

/// Send a reload message to an active session, instructing it to re-read
/// its identity files.
#[allow(clippy::print_stdout)]
async fn reload<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let spec = session
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("session '{name}' has no identity spec configured"))?;

    let message = build_reload_message(spec);
    dispatch_identity_send(service, session.id, message, "reload").await?;

    println!("Sent identity reload to '{}'.", session.title);
    Ok(())
}

/// Send a snapshot message to an active session, instructing it to persist
/// current state before context compaction.
#[allow(clippy::print_stdout)]
async fn snapshot<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    if session.identity.is_none() {
        bail!("session '{name}' has no identity spec configured");
    }

    let message = build_snapshot_message();
    dispatch_identity_send(service, session.id, message, "snapshot").await?;

    println!("Sent identity snapshot to '{}'.", session.title);
    Ok(())
}

/// Build and execute a `SendMessage` action through `ActionService`.
async fn dispatch_identity_send<R, P>(
    service: &ActionService<R, P>,
    session_id: sigil_core::id::SessionId,
    message: String,
    kind: &str,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let request = ActionRequest::new(
        Action::SendMessage {
            session_id,
            message,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service
        .execute(request)
        .await
        .with_context(|| format!("identity {kind}"))?;

    match outcome {
        ActionOutcome::Completed(DispatchResult::Done) => Ok(()),
        ActionOutcome::Completed(_) => bail!("unexpected dispatch result for SendMessage"),
        ActionOutcome::Denied { reason } => bail!("policy denied: {reason}"),
        ActionOutcome::NeedsApproval { description } => {
            bail!("approval required: {description}")
        }
    }
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
