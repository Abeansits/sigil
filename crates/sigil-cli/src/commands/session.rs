//! Session subcommands — list, show, create, launch, start, stop,
//! restart, send, output, remove.
//!
//! All privileged operations go through [`ActionService::execute()`]:
//! policy evaluation → dispatch → audit. No more "call runtime then
//! log allowed."

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use serde::Serialize;

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::config::ProjectConfig;
use sigil_core::id::{GroupId, SessionId};
use sigil_core::origin::ActionOrigin;
use sigil_core::session::{IdentitySpec, LifecycleEvent, SessionRecord, SessionState, ToolKind};
use sigil_core::traits::{LifecycleHooks, PolicyEngine, SessionRuntime};
use sigil_store::Store;

use crate::SessionCommands;

/// Route a `SessionCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if any session operation fails.
#[allow(clippy::print_stdout)]
pub async fn run<R, P>(service: &ActionService<R, P>, cmd: SessionCommands) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    match cmd {
        SessionCommands::List { json } => list(service, json).await,
        SessionCommands::Show { name, json } => show(service, &name, json).await,
        SessionCommands::Create {
            path,
            title,
            tool,
            group,
            identity,
        } => {
            create(
                service,
                &path,
                &title,
                &tool,
                group.as_deref(),
                identity.as_deref(),
            )
            .await
        }
        SessionCommands::Launch {
            path,
            title,
            tool,
            group,
            message,
            identity,
            worktree,
            create_branch,
        } => {
            launch(
                service,
                &path,
                &title,
                &tool,
                group.as_deref(),
                message.as_deref(),
                identity.as_deref(),
                worktree.as_deref(),
                create_branch,
            )
            .await
        }
        SessionCommands::Start { name } => start(service, &name).await,
        SessionCommands::Stop { name } => stop(service, &name).await,
        SessionCommands::Restart { name } => restart(service, &name).await,
        SessionCommands::Send {
            name,
            message,
            wait,
            quiet,
        } => send(service, &name, &message, wait, quiet).await,
        SessionCommands::Output { name, quiet } => output(service, &name, quiet).await,
        SessionCommands::Remove { name } => remove(service, &name).await,
        SessionCommands::SetGroup { name, group, clear } => {
            set_group(service, &name, group.as_deref(), clear).await
        }
        SessionCommands::SetParent {
            name,
            parent,
            clear,
        } => set_parent(service, &name, parent.as_deref(), clear).await,
    }
}

/// Resolve a session by title first, then by ID prefix.
///
/// This gives fuzzy matching: exact title match wins, otherwise we look
/// for a session whose ID starts with the provided string.
///
/// # Errors
///
/// Returns an error if the session cannot be found by title, full ID,
/// or ID prefix, or if the lookup is ambiguous.
pub async fn resolve_session(store: &Store, name: &str) -> Result<SessionRecord> {
    // Try exact title match first.
    match store.get_session_by_title(name).await {
        Ok(session) => return Ok(session),
        Err(sigil_store::StoreError::SessionNotFound { .. }) => {}
        Err(e) => return Err(e).context("failed to look up session by title"),
    }

    // Try exact ID match.
    if let Ok(id) = SessionId::from_str(name) {
        match store.get_session(&id).await {
            Ok(session) => return Ok(session),
            Err(sigil_store::StoreError::SessionNotFound { .. }) => {}
            Err(e) => return Err(e).context("failed to look up session by ID"),
        }
    }

    // Try ID prefix match.
    let sessions = store
        .list_sessions()
        .await
        .context("failed to list sessions for prefix match")?;

    let name_lower = name.to_lowercase();
    let mut matches: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| s.id.to_string().to_lowercase().starts_with(&name_lower))
        .collect();

    if matches.len() == 1 {
        return Ok(matches.remove(0).clone());
    }

    if matches.len() > 1 {
        let titles: Vec<&str> = matches.iter().map(|s| s.title.as_str()).collect();
        bail!(
            "ambiguous session identifier '{name}' matches {} sessions: {}",
            matches.len(),
            titles.join(", ")
        );
    }

    bail!("session not found: '{name}'")
}

/// Parse a tool name string into a `ToolKind`.
fn parse_tool(tool: &str) -> Result<ToolKind> {
    match tool.to_lowercase().as_str() {
        "claude" | "claude-code" | "claudecode" => Ok(ToolKind::ClaudeCode),
        "codex" => Ok(ToolKind::Codex),
        _ => bail!("unknown tool '{tool}' (expected 'claude' or 'codex')"),
    }
}

// -- Identity resolution --

/// Resolve an `IdentitySpec` from CLI flag or project config.
///
/// Priority: CLI `--identity` flag > `.sigil/config.toml` > `None`.
///
/// The CLI flag is a comma-separated list of file paths. When provided,
/// it uses default `reload_on` events (`PostCompact`, `PreCompact`).
fn resolve_identity_spec(
    cli_flag: Option<&str>,
    project_dir: &Path,
) -> Result<Option<IdentitySpec>> {
    // 1. CLI flag (highest priority)
    if let Some(flag) = cli_flag {
        let files: Vec<PathBuf> = flag
            .split(',')
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| !p.as_os_str().is_empty())
            .collect();

        return Ok(Some(IdentitySpec {
            files,
            reload_on: vec![LifecycleEvent::PostCompact, LifecycleEvent::PreCompact],
        }));
    }

    // 2. .sigil/config.toml [identity] section
    let config = ProjectConfig::load(project_dir).context("failed to load project config")?;

    if let Some(config) = config {
        if let Some(section) = config.identity {
            let spec = section.into_spec().context("invalid identity config")?;
            return Ok(Some(spec));
        }
    }

    // 3. None
    Ok(None)
}

// -- Outcome handling --

/// Unwrap a completed `ActionOutcome` or bail on denial/approval.
fn require_completed(outcome: ActionOutcome) -> Result<DispatchResult> {
    match outcome {
        ActionOutcome::Completed(result) => Ok(result),
        ActionOutcome::Denied { reason } => bail!("policy denied: {reason}"),
        ActionOutcome::NeedsApproval { description } => {
            bail!("approval required: {description}")
        }
    }
}

// -- Subcommand handlers --

#[allow(clippy::print_stdout)]
async fn list<R, P>(service: &ActionService<R, P>, json: bool) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);
    let outcome = service.execute(request).await.context("list sessions")?;
    let result = require_completed(outcome)?;

    let DispatchResult::SessionList(sessions) = result else {
        bail!("unexpected dispatch result")
    };

    if json {
        let formatted =
            serde_json::to_string_pretty(&sessions).context("failed to serialize sessions")?;
        println!("{formatted}");
    } else if sessions.is_empty() {
        println!("No sessions.");
    } else {
        for s in &sessions {
            let group = s
                .group
                .as_ref()
                .map_or(String::new(), |g| format!(" [{g}]"));
            let state = format!("{:?}", s.state);
            let tool = format!("{:?}", s.tool);
            println!(
                "  {:<26}  {:<10}  {:<12}{group}  {}",
                s.title,
                state,
                tool,
                s.path.display(),
            );
        }
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn show<R, P>(service: &ActionService<R, P>, name: &str, json: bool) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    // Resolve the parent's title (if any) so JSON and text output can
    // surface a human-readable pointer alongside the ULID.
    let parent_title = match session.parent.as_ref() {
        Some(parent_id) => match service.store().get_session(parent_id).await {
            Ok(parent) => Some(parent.title),
            Err(sigil_store::StoreError::SessionNotFound { .. }) => None,
            Err(e) => return Err(e).context("failed to look up parent session"),
        },
        None => None,
    };

    if json {
        let response = ShowSessionResponse {
            session: &session,
            parent_title: parent_title.as_deref(),
        };
        let formatted =
            serde_json::to_string_pretty(&response).context("failed to serialize session JSON")?;
        println!("{formatted}");
    } else {
        println!("ID:         {}", session.id);
        println!("Title:      {}", session.title);
        println!("State:      {:?}", session.state);
        println!("Tool:       {:?}", session.tool);
        println!("Path:       {}", session.path.display());
        println!("Class:      {:?}", session.execution_class);
        println!("Sandboxed:  {}", session.sandboxed);
        if let Some(ref group) = session.group {
            println!("Group:      {group}");
        }
        if let Some(ref parent) = session.parent {
            match parent_title.as_deref() {
                Some(title) => println!("Parent:     {title} ({parent})"),
                None => println!("Parent:     {parent}"),
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::print_stdout)]
async fn create<R, P>(
    service: &ActionService<R, P>,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    identity_flag: Option<&str>,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let tool_kind = parse_tool(tool)?;
    let project_dir = PathBuf::from(path);
    let identity = resolve_identity_spec(identity_flag, &project_dir)?;

    let request = ActionRequest::new(
        Action::CreateSession {
            path: project_dir,
            title: title.to_owned(),
            group: group.map(GroupId::new),
            tool: tool_kind,
            identity,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("create session")?;
    let result = require_completed(outcome)?;

    let DispatchResult::Session(record) = result else {
        bail!("unexpected dispatch result")
    };
    println!("Created session '{}' ({})", record.title, record.id);

    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::print_stdout)]
async fn launch<R, P>(
    service: &ActionService<R, P>,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    message: Option<&str>,
    identity_flag: Option<&str>,
    worktree_branch: Option<&str>,
    create_branch: bool,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    if let Some(branch) = worktree_branch {
        launch_with_worktree(
            service,
            path,
            title,
            tool,
            group,
            message,
            identity_flag,
            branch,
            create_branch,
        )
        .await
    } else {
        launch_plain(service, path, title, tool, group, message, identity_flag).await
    }
}

#[allow(clippy::too_many_arguments, clippy::print_stdout)]
async fn launch_plain<R, P>(
    service: &ActionService<R, P>,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    message: Option<&str>,
    identity_flag: Option<&str>,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let tool_kind = parse_tool(tool)?;
    let project_dir = PathBuf::from(path);
    let identity = resolve_identity_spec(identity_flag, &project_dir)?;

    let request = ActionRequest::new(
        Action::LaunchSession {
            path: project_dir,
            title: title.to_owned(),
            tool: tool_kind,
            group: group.map(GroupId::new),
            message: message.map(ToOwned::to_owned),
            identity,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("launch session")?;
    let result = require_completed(outcome)?;

    let DispatchResult::Session(record) = result else {
        bail!("unexpected dispatch result")
    };
    println!("Launched session '{}' ({})", record.title, record.id);

    Ok(())
}

/// How far the compound launch flow progressed before failing. Routes
/// the compensating rollback so each committed side effect is unwound
/// in reverse and we don't clobber state we don't own.
///
/// The branch-owned flag is deliberately separate from the user's `-b`
/// intent: there is a TOCTOU window between pre-flight `branch_exists`
/// and `git worktree add -b` where another actor could create the
/// branch, causing `git worktree add` to fail with "already exists".
/// Deleting that branch in rollback would destroy unrelated work. We
/// only set `new_branch_owned` after `create_with_options` *succeeds*
/// with `create_branch = true`, which is the only case where we
/// unambiguously own the branch. The narrow path-occupied edge case
/// (git creates the branch, then fails on the path) therefore leaves
/// a harmless dangling branch rather than risking deletion of a
/// concurrently-created one.
#[derive(Clone, Copy, Debug, Default)]
struct LaunchProgress {
    /// This flow created the branch and can safely force-delete it on
    /// rollback.
    new_branch_owned: bool,
    /// The runtime was started (tmux session / container alive). Used
    /// to stop it before removing the session record so we don't
    /// orphan a live process.
    runtime_started: bool,
}

/// Compound flow: `sigil session launch ... --worktree BRANCH [-b]`.
///
/// Replaces the two-step `session create ... && worktree create -b BRANCH
/// && session start && session send`. Each privileged step still flows
/// through `ActionService` so policy + audit remain authoritative.
///
/// Ordering: create the session record with the original repo path →
/// authorize + execute the git worktree op → rewrite session.path to
/// the worktree → start → send. The path rewrite is what makes the
/// launched tool land inside the worktree (SessionHandle.path is the
/// tmux / container cwd).
///
/// Rollback is compensating: on failure we unwind each committed step
/// in reverse. `WorktreeManager::rollback_new_worktree` is existence-
/// aware and always invoked — it drops the worktree dir only if one
/// is on disk and the branch only when we created it via `-b`;
/// attached branches are left alone. We best-effort `delete_session`
/// last so retries on the same title aren't blocked by
/// `DuplicateTitle`. Cleanup errors are logged, never propagated —
/// the user already has one real error and shouldn't be spammed with
/// rollback noise.
#[allow(clippy::too_many_arguments, clippy::print_stdout)]
async fn launch_with_worktree<R, P>(
    service: &ActionService<R, P>,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    message: Option<&str>,
    identity_flag: Option<&str>,
    branch: &str,
    create_branch: bool,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let tool_kind = parse_tool(tool)?;
    let repo_path = PathBuf::from(path);
    let worktree_path = sigil_runtime::WorktreeManager::worktree_path(&repo_path, branch);

    // --worktree + any identity source (CLI flag *or* project config)
    // would race: identity hook registration writes into the session's
    // cwd, which we rewrite mid-flow. Resolve the spec before any side
    // effect so a `.sigil/config.toml` identity doesn't silently vanish
    // — fail explicitly instead of stripping it.
    if resolve_identity_spec(identity_flag, &repo_path)?.is_some() {
        bail!(
            "--worktree combined with an identity spec is not supported yet \
             (identity set via --identity or .sigil/config.toml); launch \
             without an identity and reload it after the session is up"
        );
    }

    // Pre-flight: branch existence must match the -b flag. Doing this
    // before any side effect keeps a surprised user from ending up
    // with a stranded session record. A TOCTOU race is possible (the
    // branch could appear between here and `create_with_options`) but
    // git's own error message surfaces in the Err path below, so the
    // worst case is a less-tailored message — not a stranded record.
    let branch_exists = sigil_runtime::WorktreeManager::branch_exists(&repo_path, branch)
        .await
        .context("failed to check whether branch exists")?;
    match (branch_exists, create_branch) {
        (true, true) => {
            bail!("branch '{branch}' already exists; drop -b/--create-branch to attach to it")
        }
        (false, false) => {
            bail!("branch '{branch}' does not exist; pass -b/--create-branch to create it")
        }
        _ => {}
    }

    // Step 1: create the session record with the repo path. Using the
    // repo path here (not the worktree path) means identity-less
    // CreateSession has no filesystem preconditions — the worktree
    // directory doesn't exist yet.
    let create_request = ActionRequest::new(
        Action::CreateSession {
            path: repo_path.clone(),
            title: title.to_owned(),
            group: group.map(GroupId::new),
            tool: tool_kind,
            identity: None,
        },
        ActionOrigin::LocalCli,
    );
    let outcome = service
        .execute(create_request)
        .await
        .context("create session")?;
    let DispatchResult::Session(session) = require_completed(outcome)? else {
        bail!("unexpected dispatch result for CreateSession")
    };

    let mut progress = LaunchProgress::default();
    let result = do_launch_with_worktree(
        service,
        &session,
        &repo_path,
        branch,
        create_branch,
        &worktree_path,
        message,
        &mut progress,
    )
    .await;

    match result {
        Ok(()) => {
            println!(
                "Launched session '{}' ({}) in worktree {}",
                session.title,
                session.id,
                worktree_path.display(),
            );
            Ok(())
        }
        Err(e) => {
            // Unwind in reverse:
            //   1. stop the runtime if it was started, so we don't orphan
            //      a live tmux / container after deleting the record,
            //   2. roll back the worktree (existence-aware; invoked even
            //      if `create_with_options` returned Err because a
            //      partial `git worktree add` can leave the worktree
            //      directory behind),
            //   3. delete the branch only if *we* created it — see
            //      `LaunchProgress::new_branch_owned` for the TOCTOU
            //      reasoning,
            //   4. delete the session record last.
            // Every step is best-effort and logs its own warnings so
            // the user's primary error surfaces cleanly.
            if progress.runtime_started {
                let handle = sigil_conductor::action_service::record_to_handle(&session);
                if let Err(stop_err) = service.runtime().stop(&handle).await {
                    tracing::warn!(
                        session = %session.title,
                        error = %stop_err,
                        "failed to stop runtime during launch-with-worktree rollback",
                    );
                }
            }
            sigil_runtime::WorktreeManager::rollback_new_worktree(
                &repo_path,
                branch,
                &worktree_path,
                progress.new_branch_owned,
            )
            .await;
            if let Err(cleanup_err) = service.store().delete_session(&session.id).await {
                tracing::warn!(
                    session = %session.title,
                    error = %cleanup_err,
                    "failed to roll back session record after launch-with-worktree error",
                );
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn do_launch_with_worktree<R, P>(
    service: &ActionService<R, P>,
    session: &SessionRecord,
    repo_path: &Path,
    branch: &str,
    create_branch: bool,
    worktree_path: &Path,
    message: Option<&str>,
    progress: &mut LaunchProgress,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    // Step 2: authorize the worktree op through policy / audit. The
    // action returns AuthorizedNotDispatched — the git side effect
    // below runs only after auth succeeds.
    let wt_request = ActionRequest::new(
        Action::CreateWorktree {
            session_id: session.id,
            branch: branch.to_owned(),
        },
        ActionOrigin::LocalCli,
    );
    let outcome = service
        .execute(wt_request)
        .await
        .context("authorize create worktree")?;
    let dispatch = require_completed(outcome)?;
    if !matches!(dispatch, DispatchResult::AuthorizedNotDispatched) {
        bail!("unexpected dispatch result for CreateWorktree: {dispatch:?}");
    }

    // Step 3: git op. Once this returns Ok we own the on-disk worktree
    // dir and, when `-b` was set, the branch as well. We flip the
    // `new_branch_owned` flag only on Ok so a TOCTOU "branch appeared
    // before our git ran" failure cannot drive a rollback that
    // force-deletes an unrelated branch.
    sigil_runtime::WorktreeManager::create_with_options(
        repo_path,
        branch,
        worktree_path,
        create_branch,
    )
    .await
    .context("failed to create git worktree")?;
    if create_branch {
        progress.new_branch_owned = true;
    }

    // Step 4: rewrite the session path so StartSession launches the
    // runtime inside the worktree.
    service
        .store()
        .update_session_path(&session.id, worktree_path)
        .await
        .context("failed to update session path to worktree")?;

    // Step 5: start the runtime (now running at the worktree path).
    // Flip `runtime_started` only after policy authorises AND dispatch
    // completes, so rollback's stop call fires exactly when there is
    // a live runtime to tear down.
    let start_request = ActionRequest::new(
        Action::StartSession {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );
    let outcome = service
        .execute(start_request)
        .await
        .context("start session")?;
    require_completed(outcome)?;
    progress.runtime_started = true;

    // Step 6: optional initial message.
    if let Some(msg) = message {
        let send_request = ActionRequest::new(
            Action::SendMessage {
                session_id: session.id,
                message: msg.to_owned(),
            },
            ActionOrigin::LocalCli,
        );
        let outcome = service
            .execute(send_request)
            .await
            .context("send message")?;
        require_completed(outcome)?;
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn start<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::StartSession {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("start session")?;
    require_completed(outcome)?;

    println!("Started session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn stop<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::StopSession {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("stop session")?;
    require_completed(outcome)?;

    println!("Stopped session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn restart<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::RestartSession {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("restart session")?;
    require_completed(outcome)?;

    println!("Restarted session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn send<R, P>(
    service: &ActionService<R, P>,
    name: &str,
    message: &str,
    wait: bool,
    quiet: bool,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::SendMessage {
            session_id: session.id,
            message: message.to_owned(),
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("send message")?;
    require_completed(outcome)?;

    if !quiet {
        println!("Sent to '{}'.", session.title);
    }

    if wait {
        // Poll for output until the session transitions away from Running.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        let handle = sigil_conductor::action_service::record_to_handle(&session);

        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let state = service
                .runtime()
                .status(&handle)
                .await
                .context("failed to check session status")?;

            if state != SessionState::Running {
                break;
            }

            if tokio::time::Instant::now() >= deadline {
                if !quiet {
                    println!("Timed out waiting for response.");
                }
                break;
            }
        }

        // Read final output via ActionService.
        let read_request = ActionRequest::new(
            Action::ReadSessionOutput {
                session_id: session.id,
            },
            ActionOrigin::LocalCli,
        );

        let read_outcome = service.execute(read_request).await.context("read output")?;
        let read_result = require_completed(read_outcome)?;

        let DispatchResult::Text(text) = read_result else {
            bail!("unexpected dispatch result")
        };

        if quiet {
            println!("{text}");
        } else {
            println!("--- output from '{}' ---", session.title);
            println!("{text}");
            println!("--- end ---");
        }
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn output<R, P>(service: &ActionService<R, P>, name: &str, quiet: bool) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::ReadSessionOutput {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("read output")?;
    let result = require_completed(outcome)?;

    let DispatchResult::Text(text) = result else {
        bail!("unexpected dispatch result")
    };

    if quiet {
        println!("{text}");
    } else {
        println!(
            "--- output from '{}' [{:?}] ---",
            session.title, session.state
        );
        println!("{text}");
        println!("--- end ---");
    }

    Ok(())
}

/// JSON shape for `session show --json`.
///
/// Flattens the persisted [`SessionRecord`] and augments it with
/// `parent_title`, a resolved lookup of the parent session's display
/// title. `parent_title` is `null` when the session has no parent or
/// when the parent pointer dangles (points at a record that was since
/// removed); callers rely on the ULID in `parent` to distinguish the
/// two.
#[derive(Debug, Serialize)]
struct ShowSessionResponse<'a> {
    #[serde(flatten)]
    session: &'a SessionRecord,
    parent_title: Option<&'a str>,
}

#[allow(clippy::print_stdout)]
async fn set_group<R, P>(
    service: &ActionService<R, P>,
    name: &str,
    group: Option<&str>,
    clear: bool,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    // One of `group` or `--clear` must be present, but not both. clap
    // enforces the `conflicts_with` side; we enforce the required side.
    let new_group = match (group, clear) {
        (Some(g), false) => Some(GroupId::new(g)),
        (None, true) => None,
        (None, false) => bail!("provide a GROUP argument or --clear to detach"),
        // Unreachable: clap's `conflicts_with = "group"` rejects this combo.
        (Some(_), true) => bail!("cannot specify both GROUP and --clear"),
    };

    // Policy evaluation / audit first — both set and clear are routed
    // through ActionService so every mutation lands in the audit log.
    let action = match new_group.as_ref() {
        Some(group_id) => Action::MoveSessionToGroup {
            session_id: session.id,
            group: group_id.clone(),
        },
        None => Action::ClearSessionGroup {
            session_id: session.id,
        },
    };
    let outcome = service
        .execute(ActionRequest::new(action, ActionOrigin::LocalCli))
        .await
        .context("set session group")?;
    crate::commands::worktree::require_authorized_not_dispatched(outcome, "set session group")?;

    service
        .store()
        .update_session_group(&session.id, new_group.as_ref())
        .await
        .context("failed to update session group")?;

    match new_group {
        Some(g) => println!("Moved session '{}' to group '{g}'.", session.title),
        None => println!("Cleared group on session '{}'.", session.title),
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn set_parent<R, P>(
    service: &ActionService<R, P>,
    name: &str,
    parent: Option<&str>,
    clear: bool,
) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    // Parent name resolution happens outside the transaction so fuzzy
    // title / ID-prefix matching stays a CLI concern. The cycle check
    // and the actual write are re-done atomically inside the Store
    // below so a concurrent writer cannot race us into a cycle.
    let new_parent = match (parent, clear) {
        (Some(p), false) => {
            let resolved = resolve_session(service.store(), p)
                .await
                .with_context(|| format!("failed to resolve parent '{p}'"))?;
            Some(resolved)
        }
        (None, true) => None,
        (None, false) => bail!("provide a PARENT argument or --clear to detach"),
        (Some(_), true) => bail!("cannot specify both PARENT and --clear"),
    };

    let action = match new_parent.as_ref() {
        Some(parent_rec) => Action::SetSessionParent {
            session_id: session.id,
            parent_id: parent_rec.id,
        },
        None => Action::ClearSessionParent {
            session_id: session.id,
        },
    };
    let outcome = service
        .execute(ActionRequest::new(action, ActionOrigin::LocalCli))
        .await
        .context("set session parent")?;
    crate::commands::worktree::require_authorized_not_dispatched(outcome, "set session parent")?;

    match service
        .store()
        .set_session_parent_checked(&session.id, new_parent.as_ref().map(|p| &p.id))
        .await
    {
        Ok(()) => {}
        Err(sigil_store::StoreError::ParentCycle { reason }) => {
            bail!("refusing to set parent: {reason}")
        }
        Err(e) => return Err(e).context("failed to update session parent"),
    }

    match new_parent {
        Some(p) => println!(
            "Set parent of '{}' to '{}' ({}).",
            session.title, p.title, p.id
        ),
        None => println!("Cleared parent on session '{}'.", session.title),
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn remove<R, P>(service: &ActionService<R, P>, name: &str) -> Result<()>
where
    R: SessionRuntime + LifecycleHooks,
    P: PolicyEngine,
{
    let session = resolve_session(service.store(), name).await?;

    let request = ActionRequest::new(
        Action::RemoveSession {
            session_id: session.id,
        },
        ActionOrigin::LocalCli,
    );

    let outcome = service.execute(request).await.context("remove session")?;
    require_completed(outcome)?;

    println!("Removed session '{}' ({}).", session.title, session.id);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn parse_tool_claude_variants() {
        assert!(matches!(parse_tool("claude"), Ok(ToolKind::ClaudeCode)));
        assert!(matches!(
            parse_tool("claude-code"),
            Ok(ToolKind::ClaudeCode)
        ));
        assert!(matches!(parse_tool("claudecode"), Ok(ToolKind::ClaudeCode)));
        assert!(matches!(parse_tool("Claude"), Ok(ToolKind::ClaudeCode)));
    }

    #[test]
    fn parse_tool_codex() {
        assert!(matches!(parse_tool("codex"), Ok(ToolKind::Codex)));
        assert!(matches!(parse_tool("Codex"), Ok(ToolKind::Codex)));
    }

    #[test]
    fn parse_tool_unknown_returns_error() {
        assert!(parse_tool("vim").is_err());
        assert!(parse_tool("").is_err());
    }

    #[tokio::test]
    async fn resolve_session_returns_not_found_for_empty_store() {
        let store = Store::new_in_memory()
            .await
            .expect("in-memory store should init");
        let result = resolve_session(&store, "nonexistent").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should be error"));
        assert!(err_msg.contains("not found"));
    }

    #[tokio::test]
    async fn resolve_session_finds_by_title() {
        let store = Store::new_in_memory()
            .await
            .expect("in-memory store should init");

        let record = SessionRecord {
            id: SessionId::new(),
            title: "my-test-session".into(),
            path: PathBuf::from("/tmp/test"),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
            identity: None,
        };
        store
            .create_session(&record)
            .await
            .expect("create should succeed");

        let found = resolve_session(&store, "my-test-session").await;
        assert!(found.is_ok());
        assert_eq!(found.expect("should resolve").id, record.id);
    }

    #[tokio::test]
    async fn resolve_session_finds_by_full_id() {
        let store = Store::new_in_memory()
            .await
            .expect("in-memory store should init");

        let record = SessionRecord {
            id: SessionId::new(),
            title: "id-lookup-test".into(),
            path: PathBuf::from("/tmp/test"),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
            identity: None,
        };
        store
            .create_session(&record)
            .await
            .expect("create should succeed");

        let id_str = record.id.to_string();
        let found = resolve_session(&store, &id_str).await;
        assert!(found.is_ok());
        assert_eq!(found.expect("should resolve").id, record.id);
    }

    #[tokio::test]
    async fn resolve_session_finds_by_id_prefix() {
        let store = Store::new_in_memory()
            .await
            .expect("in-memory store should init");

        let record = SessionRecord {
            id: SessionId::new(),
            title: "prefix-test".into(),
            path: PathBuf::from("/tmp/test"),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
            sandboxed: true,
            state: SessionState::Stopped,
            identity: None,
        };
        store
            .create_session(&record)
            .await
            .expect("create should succeed");

        // Use first 8 characters of the ID as prefix.
        let id_str = record.id.to_string();
        let prefix = &id_str[..8];
        let found = resolve_session(&store, prefix).await;
        assert!(found.is_ok());
        assert_eq!(found.expect("should resolve").id, record.id);
    }

    // -------------------------------------------------------------------
    // resolve_identity_spec tests
    // -------------------------------------------------------------------

    #[test]
    fn resolve_identity_cli_flag_comma_separated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_identity_spec(Some("SOUL.md,OPS.md,state.json"), dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert_eq!(
            spec.files,
            vec![
                PathBuf::from("SOUL.md"),
                PathBuf::from("OPS.md"),
                PathBuf::from("state.json"),
            ]
        );
        assert_eq!(
            spec.reload_on,
            vec![LifecycleEvent::PostCompact, LifecycleEvent::PreCompact,]
        );
    }

    #[test]
    fn resolve_identity_cli_flag_with_spaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_identity_spec(Some(" SOUL.md , OPS.md "), dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert_eq!(
            spec.files,
            vec![PathBuf::from("SOUL.md"), PathBuf::from("OPS.md"),]
        );
    }

    #[test]
    fn resolve_identity_cli_flag_trailing_comma() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_identity_spec(Some("SOUL.md,"), dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert_eq!(spec.files, vec![PathBuf::from("SOUL.md")]);
    }

    #[test]
    fn resolve_identity_cli_flag_empty_string() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_identity_spec(Some(""), dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert!(spec.files.is_empty());
    }

    #[test]
    fn resolve_identity_from_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).expect("mkdir");
        std::fs::write(
            sigil_dir.join("config.toml"),
            r#"
[identity]
files = ["SOUL.md", "state.json"]
reload_on = ["Restart"]
"#,
        )
        .expect("write config");

        let result = resolve_identity_spec(None, dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert_eq!(
            spec.files,
            vec![PathBuf::from("SOUL.md"), PathBuf::from("state.json"),]
        );
        assert_eq!(spec.reload_on, vec![LifecycleEvent::Restart]);
    }

    #[test]
    fn resolve_identity_cli_flag_overrides_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).expect("mkdir");
        std::fs::write(
            sigil_dir.join("config.toml"),
            r#"
[identity]
files = ["config-file.md"]
reload_on = ["Restart"]
"#,
        )
        .expect("write config");

        let result = resolve_identity_spec(Some("cli-override.md"), dir.path());
        let spec = result.expect("should succeed").expect("should be Some");
        assert_eq!(spec.files, vec![PathBuf::from("cli-override.md")]);
        // CLI flag uses default reload_on, not the config file's
        assert_eq!(
            spec.reload_on,
            vec![LifecycleEvent::PostCompact, LifecycleEvent::PreCompact,]
        );
    }

    #[test]
    fn resolve_identity_no_flag_no_config_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_identity_spec(None, dir.path());
        assert!(result.expect("should succeed").is_none());
    }

    #[test]
    fn resolve_identity_config_without_identity_section() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).expect("mkdir");
        std::fs::write(sigil_dir.join("config.toml"), "# no identity section\n")
            .expect("write config");

        let result = resolve_identity_spec(None, dir.path());
        assert!(result.expect("should succeed").is_none());
    }
}
