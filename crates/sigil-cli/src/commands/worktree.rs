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

use anyhow::{Context, Result, bail};

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::origin::ActionOrigin;
use sigil_core::traits::{LifecycleHooks, PolicyEngine, SessionRuntime};
use sigil_runtime::WorktreeManager;

use crate::WorktreeCommands;

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
fn require_authorized_not_dispatched(outcome: ActionOutcome, what: &str) -> Result<()> {
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
