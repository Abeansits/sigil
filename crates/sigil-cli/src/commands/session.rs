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
        } => {
            launch(
                service,
                &path,
                &title,
                &tool,
                group.as_deref(),
                message.as_deref(),
                identity.as_deref(),
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

    if json {
        let formatted =
            serde_json::to_string_pretty(&session).context("failed to serialize session")?;
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
            println!("Parent:     {parent}");
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
