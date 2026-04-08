//! The `audit` command group — audit log operations.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::AuditCommands;

/// Run the appropriate audit subcommand.
///
/// # Errors
///
/// Returns an error if verification fails.
pub async fn run(cmd: AuditCommands) -> Result<()> {
    match cmd {
        AuditCommands::Verify { path } => verify(path).await,
    }
}

/// Default HMAC key for development (mirrors `audit::DEV_FALLBACK_KEY`).
const DEV_FALLBACK_KEY: &[u8] = b"sigil-dev-audit-key-CHANGE-ME";

/// Verify the HMAC chain in an audit log file.
#[allow(clippy::print_stdout)]
async fn verify(path: Option<String>) -> Result<()> {
    let audit_path = if let Some(p) = path {
        crate::expand_tilde(&p)?
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".sigil").join("audit.jsonl")
    };

    let key = std::env::var("SIGIL_AUDIT_KEY")
        .map_or_else(|_| DEV_FALLBACK_KEY.to_vec(), String::into_bytes);

    let result = sigil_audit::verify_log(&audit_path, &key)
        .await
        .context("failed to verify audit log")?;

    println!("Audit log: {}", audit_path.display());
    println!("Total entries: {}", result.total_entries);

    if let Some(broken) = &result.first_broken {
        println!(
            "Chain: BROKEN at entry {} ({})",
            broken.index, broken.event_id
        );
        println!("Reason: {}", broken.reason);
        println!("Valid entries before break: {}", result.valid_entries);
    } else {
        println!("Chain: valid ({} entries verified)", result.valid_entries);
    }

    Ok(())
}
