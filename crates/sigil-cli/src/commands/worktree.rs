//! Worktree subcommands — create, finish, list.
//!
//! Mutating operations (`create`, `finish`) build T2 `ActionRequest`s and
//! go through [`ActionService`] for policy evaluation + audit. `ActionService`
//! returns [`DispatchResult::AuthorizedNotDispatched`] for these variants,
//! signalling that the caller is responsible for executing the side effect
//! (here, the git worktree operations).
//!
//! The read-only `list` command goes through `Action::ListSessions` so the
//! read is still policy-evaluated.

use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context, Result, bail};

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::origin::ActionOrigin;
use sigil_core::traits::{LifecycleHooks, PolicyEngine, SessionRuntime};
use sigil_runtime::WorktreeManager;

use crate::WorktreeCommands;

/// Resolve a session's repo root given its stored `path`.
///
/// The compound `session launch --worktree` flow stores the worktree
/// directory as `session.path` so the runtime lands in the right cwd.
/// That means `session.path` can be either the repo root itself or
/// `{repo}/.worktrees/<sanitised>`. Walk up one level when the last
/// path component's parent is `.worktrees/` — the `finish`/`list`
/// commands need the repo root to build the `.worktrees/` lookup and
/// to run git worktree ops.
fn repo_root_for_session(session_path: &Path) -> &Path {
    if let Some(parent) = session_path.parent() {
        if parent.file_name() == Some(OsStr::new(".worktrees")) {
            if let Some(grandparent) = parent.parent() {
                return grandparent;
            }
        }
    }
    session_path
}

/// Canonicalise `path` if possible, falling back to a clone on error.
///
/// `git worktree list --porcelain` emits canonical paths (symlinks
/// resolved). On macOS `/var/folders/...` is a symlink to
/// `/private/var/folders/...`, so the `WorktreeInfo.path` we parse
/// never starts with our freshly-built `repo.join(".worktrees")`
/// unless both sides are normalised. This helper is the minimum fix:
/// it does not touch semantics for paths that resolve to themselves.
fn canonical_or_owned(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Route a `WorktreeCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if policy denies the request or any worktree operation
/// fails.
#[allow(clippy::print_stdout)]
pub async fn run<R, P>(service: &ActionService<R, P>, cmd: WorktreeCommands) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    match cmd {
        WorktreeCommands::Create { name, branch } => create(service, &name, &branch).await,
        WorktreeCommands::Finish { name, merge } => finish(service, &name, merge).await,
        WorktreeCommands::List => list(service).await,
    }
}

/// Require that an outcome authorized the request. T2 actions are
/// `AuthorizedNotDispatched` (`ActionService` does not run git for us);
/// simpler T0/T1 session actions return `Completed(Session*)`.
fn require_authorized(outcome: ActionOutcome) -> Result<DispatchResult> {
    match outcome {
        ActionOutcome::Completed(result) => Ok(result),
        ActionOutcome::Denied { reason } => bail!("policy denied: {reason}"),
        ActionOutcome::NeedsApproval { description } => {
            bail!("approval required: {description}")
        }
    }
}

/// Assert a T2 worktree request came back as `AuthorizedNotDispatched`.
/// Any other `DispatchResult` variant means `ActionService` dispatch
/// semantics have drifted; refuse to run the git side effect rather than
/// proceed on ambiguous signal.
///
/// Also used by `commands::session` for the group/parent re-linking
/// subcommands, which follow the same "policy-evaluated, CLI runs the
/// write" pattern.
pub(crate) fn require_authorized_not_dispatched(outcome: ActionOutcome, what: &str) -> Result<()> {
    let result = require_authorized(outcome)?;
    if matches!(result, DispatchResult::AuthorizedNotDispatched) {
        Ok(())
    } else {
        bail!(
            "{what}: unexpected dispatch result {result:?}; \
             expected AuthorizedNotDispatched"
        )
    }
}

#[allow(clippy::print_stdout)]
async fn create<R, P>(service: &ActionService<R, P>, name: &str, branch: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = crate::commands::session::resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::CreateWorktree {
            session_id: session.id,
            branch: branch.to_owned(),
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("create worktree")?;
    require_authorized_not_dispatched(outcome, "create worktree")?;

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
async fn finish<R, P>(service: &ActionService<R, P>, name: &str, merge: bool) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = crate::commands::session::resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::FinishWorktree {
            session_id: session.id,
            merge,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("finish worktree")?;
    require_authorized_not_dispatched(outcome, "finish worktree")?;

    // `session.path` may already be the worktree dir (launch --worktree
    // stores it that way). Resolve back to the repo root before
    // building the `.worktrees/` lookup or running any git op.
    let repo = repo_root_for_session(&session.path);

    // The session's worktree_branch is not stored in SessionRecord, so we
    // need the caller to identify via the session. We look for any worktree
    // whose path is under {repo}/.worktrees/. Canonicalise both sides so
    // symlinked parents (e.g. macOS `/var → /private/var`) don't defeat
    // the prefix match.
    let worktrees = WorktreeManager::list(repo)
        .await
        .context("failed to list worktrees")?;

    let wt_dir = canonical_or_owned(&repo.join(".worktrees"));
    let session_wt = worktrees
        .iter()
        .find(|w| canonical_or_owned(&w.path).starts_with(&wt_dir) && !w.is_bare);

    let Some(wt) = session_wt else {
        bail!(
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
async fn list<R, P>(service: &ActionService<R, P>) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);
    let outcome = service.execute(request).await.context("list sessions")?;

    let DispatchResult::SessionList(sessions) = require_authorized(outcome)? else {
        bail!("unexpected dispatch result for ListSessions")
    };

    let mut found_any = false;

    for session in &sessions {
        let repo = repo_root_for_session(&session.path);
        let Ok(worktrees) = WorktreeManager::list(repo).await else {
            continue; // Not a git repo or git unavailable.
        };

        let wt_dir = canonical_or_owned(&repo.join(".worktrees"));
        let session_wts: Vec<_> = worktrees
            .iter()
            .filter(|w| canonical_or_owned(&w.path).starts_with(&wt_dir))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;

    use super::repo_root_for_session;

    #[test]
    fn repo_root_for_session_strips_worktree_suffix() {
        let p = PathBuf::from("/home/u/repo/.worktrees/feature-foo");
        assert_eq!(repo_root_for_session(&p), PathBuf::from("/home/u/repo"));
    }

    #[test]
    fn repo_root_for_session_passes_through_plain_repo() {
        let p = PathBuf::from("/home/u/repo");
        assert_eq!(repo_root_for_session(&p), PathBuf::from("/home/u/repo"));
    }

    #[test]
    fn repo_root_for_session_keeps_sanitised_subdir() {
        // A worktree named after a branch like `feature/nested-bit`
        // lands under `.worktrees/feature-nested-bit` (slash sanitised),
        // still a single path component — the helper must handle that.
        let p = PathBuf::from("/home/u/repo/.worktrees/feature-nested-bit");
        assert_eq!(repo_root_for_session(&p), PathBuf::from("/home/u/repo"));
    }

    #[test]
    fn repo_root_for_session_ignores_worktrees_that_are_not_the_parent() {
        // A repo directory literally named `.worktrees` somewhere earlier
        // in the path must not trigger the strip — only when the parent
        // of the session path is `.worktrees/` do we peel one level.
        let p = PathBuf::from("/tmp/.worktrees/repo");
        assert_eq!(repo_root_for_session(&p), PathBuf::from("/tmp"));
        // But:
        let p = PathBuf::from("/tmp/.worktrees/repo/src/nested");
        assert_eq!(
            repo_root_for_session(&p),
            PathBuf::from("/tmp/.worktrees/repo/src/nested"),
        );
    }
}
