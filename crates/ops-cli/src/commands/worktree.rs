//! Worktree subcommands — create, finish, list.

use anyhow::{Context, Result};

use ops_runtime::WorktreeManager;
use ops_store::Store;

use crate::WorktreeCommands;

/// Route a `WorktreeCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if any worktree operation fails.
#[allow(clippy::print_stdout)]
pub async fn run(store: &Store, cmd: WorktreeCommands) -> Result<()> {
    match cmd {
        WorktreeCommands::Create { name, branch } => create(store, &name, &branch).await,
        WorktreeCommands::Finish { name, merge } => finish(store, &name, merge).await,
        WorktreeCommands::List => list(store).await,
    }
}

#[allow(clippy::print_stdout)]
async fn create(store: &Store, name: &str, branch: &str) -> Result<()> {
    let session = crate::commands::session::resolve_session(store, name).await?;
    let repo = &session.path;
    let wt_path = WorktreeManager::worktree_path(repo, branch);

    WorktreeManager::create(repo, branch, &wt_path)
        .await
        .context("failed to create worktree")?;

    println!(
        "Created worktree for '{}' on branch '{branch}' at {}",
        session.title,
        wt_path.display(),
    );
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn finish(store: &Store, name: &str, merge: bool) -> Result<()> {
    let session = crate::commands::session::resolve_session(store, name).await?;
    let repo = &session.path;

    // The session's worktree_branch is not stored in SessionRecord, so we
    // need the caller to identify via the session. We look for any worktree
    // whose path is under {repo}/.worktrees/.
    let worktrees = WorktreeManager::list(repo)
        .await
        .context("failed to list worktrees")?;

    let wt_dir = repo.join(".worktrees");
    let session_wt = worktrees
        .iter()
        .find(|w| w.path.starts_with(&wt_dir) && !w.is_bare);

    let Some(wt) = session_wt else {
        anyhow::bail!(
            "no active worktree found under {} for session '{}'",
            wt_dir.display(),
            session.title,
        );
    };

    let branch = wt.branch.clone();
    let wt_path = wt.path.clone();

    WorktreeManager::finish(repo, &branch, &wt_path, merge)
        .await
        .context("failed to finish worktree")?;

    if merge {
        println!(
            "Merged and removed worktree for '{}' (branch '{branch}').",
            session.title,
        );
    } else {
        println!(
            "Removed worktree for '{}' (branch '{branch}').",
            session.title,
        );
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn list(store: &Store) -> Result<()> {
    let sessions = store
        .list_sessions()
        .await
        .context("failed to list sessions")?;

    let mut found_any = false;

    for session in &sessions {
        let Ok(worktrees) = WorktreeManager::list(&session.path).await else {
            continue; // Not a git repo or git unavailable.
        };

        let wt_dir = session.path.join(".worktrees");
        let session_wts: Vec<_> = worktrees
            .iter()
            .filter(|w| w.path.starts_with(&wt_dir))
            .collect();

        for wt in session_wts {
            found_any = true;
            println!(
                "  {:<26}  {:<30}  {}",
                session.title,
                wt.branch,
                wt.path.display(),
            );
        }
    }

    if !found_any {
        println!("No active worktrees.");
    }

    Ok(())
}
