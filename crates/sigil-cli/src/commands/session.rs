//! Session subcommands — list, show, create, launch, start, stop,
//! restart, send, output, remove.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use sigil_audit::AuditLogWriter;
use sigil_core::PolicyDecision;
use sigil_core::config::ProjectConfig;
use sigil_core::id::{GroupId, SessionId};
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{
    IdentitySpec, LifecycleEvent, SessionConfig, SessionHandle, SessionRecord, SessionState,
    ToolKind,
};
use sigil_core::traits::{LifecycleHooks, SessionRuntime};
use sigil_core::trust::ExecutionClass;
use sigil_store::Store;

use crate::SessionCommands;
use crate::audit::log_event;

/// Route a `SessionCommands` variant to its handler.
///
/// # Errors
///
/// Returns an error if any session operation fails.
#[allow(clippy::print_stdout)]
pub async fn run<R: SessionRuntime + LifecycleHooks>(
    store: &Store,
    runtime: &R,
    audit: &Arc<AuditLogWriter>,
    cmd: SessionCommands,
) -> Result<()> {
    match cmd {
        SessionCommands::List { json } => list(store, json).await,
        SessionCommands::Show { name, json } => show(store, &name, json).await,
        SessionCommands::Create {
            path,
            title,
            tool,
            group,
            identity,
        } => {
            create(
                store,
                runtime,
                audit,
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
                store,
                runtime,
                audit,
                &path,
                &title,
                &tool,
                group.as_deref(),
                message.as_deref(),
                identity.as_deref(),
            )
            .await
        }
        SessionCommands::Start { name } => start(store, runtime, audit, &name).await,
        SessionCommands::Stop { name } => stop(store, runtime, audit, &name).await,
        SessionCommands::Restart { name } => restart(store, runtime, audit, &name).await,
        SessionCommands::Send {
            name,
            message,
            wait,
            quiet,
        } => send(store, runtime, audit, &name, &message, wait, quiet).await,
        SessionCommands::Output { name, quiet } => output(store, runtime, &name, quiet).await,
        SessionCommands::Remove { name } => remove(store, audit, &name).await,
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

/// Convert a `SessionRecord` to a `SessionHandle` for runtime calls.
pub(crate) fn record_to_handle(record: &SessionRecord) -> SessionHandle {
    SessionHandle {
        id: record.id,
        title: record.title.clone(),
        tool: record.tool,
        state: record.state,
        path: record.path.clone(),
        tmux_window: Some(record.title.clone()),
        container_id: None,
        execution_class: record.execution_class,
        sandboxed: record.sandboxed,
        identity: record.identity.clone(),
    }
}

/// Log an audit event for a session action (always `"cli"` origin, `Allow`
/// decision). Reduces boilerplate across the session subcommands.
async fn log_session_event(audit: &AuditLogWriter, action: &str, session_id: SessionId) {
    log_event(
        audit,
        action,
        "cli",
        PolicyDecision::Allow,
        Some(session_id),
    )
    .await;
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

// -- Subcommand handlers --

#[allow(clippy::print_stdout)]
async fn list(store: &Store, json: bool) -> Result<()> {
    let sessions = store
        .list_sessions()
        .await
        .context("failed to list sessions")?;

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
async fn show(store: &Store, name: &str, json: bool) -> Result<()> {
    let session = resolve_session(store, name).await?;

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
async fn create<R: SessionRuntime + LifecycleHooks>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    identity_flag: Option<&str>,
) -> Result<()> {
    let tool_kind = parse_tool(tool)?;
    let project_dir = PathBuf::from(path);
    let identity = resolve_identity_spec(identity_flag, &project_dir)?;

    let record = SessionRecord {
        id: SessionId::new(),
        title: title.to_owned(),
        path: project_dir,
        tool: tool_kind,
        group: group.map(GroupId::new),
        parent: None,
        execution_class: ExecutionClass::OfflineWorker,
        sandboxed: true,
        state: SessionState::Stopped,
        identity,
    };

    store
        .create_session(&record)
        .await
        .context("failed to create session")?;

    // Register identity hooks if the session has lifecycle events.
    if let Some(ref spec) = record.identity {
        if !spec.reload_on.is_empty() {
            let handle = record_to_handle(&record);
            runtime
                .register_identity_hooks(&handle, spec)
                .await
                .context("failed to register identity hooks")?;
        }
    }

    log_session_event(audit, "session.create", record.id).await;

    println!("Created session '{}' ({})", record.title, record.id);
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::print_stdout)]
async fn launch<R: SessionRuntime + LifecycleHooks>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    path: &str,
    title: &str,
    tool: &str,
    group: Option<&str>,
    message: Option<&str>,
    identity_flag: Option<&str>,
) -> Result<()> {
    let tool_kind = parse_tool(tool)?;
    let project_dir = PathBuf::from(path);
    let identity = resolve_identity_spec(identity_flag, &project_dir)?;

    let config = SessionConfig {
        path: project_dir,
        title: title.to_owned(),
        tool: tool_kind,
        group: group.map(GroupId::new),
        parent: None,
        execution_class: ExecutionClass::OfflineWorker,
        sandboxed: true,
        initial_message: message.map(ToOwned::to_owned),
        worktree_branch: None,
        identity,
        memory: None,
    };

    let handle = runtime
        .launch(&config)
        .await
        .context("failed to launch session")?;

    // Persist the session record.
    let record = SessionRecord {
        id: handle.id,
        title: handle.title.clone(),
        path: handle.path.clone(),
        tool: handle.tool,
        group: group.map(GroupId::new),
        parent: None,
        execution_class: handle.execution_class,
        sandboxed: handle.sandboxed,
        state: handle.state,
        identity: handle.identity.clone(),
    };

    store
        .create_session(&record)
        .await
        .context("failed to persist launched session")?;

    // Register identity hooks if the session has lifecycle events.
    if let Some(ref spec) = record.identity {
        if !spec.reload_on.is_empty() {
            runtime
                .register_identity_hooks(&handle, spec)
                .await
                .context("failed to register identity hooks")?;
        }
    }

    log_session_event(audit, "session.launch", record.id).await;

    println!("Launched session '{}' ({})", record.title, record.id);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn start<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
) -> Result<()> {
    let session = resolve_session(store, name).await?;

    if session.state != SessionState::Stopped {
        bail!(
            "session '{}' is {:?}, not Stopped — cannot start",
            session.title,
            session.state
        );
    }

    let config = SessionConfig {
        path: session.path.clone(),
        title: session.title.clone(),
        tool: session.tool,
        group: session.group.clone(),
        parent: session.parent,
        execution_class: session.execution_class,
        sandboxed: session.sandboxed,
        initial_message: None,
        worktree_branch: None,
        identity: session.identity.clone(),
        memory: None,
    };

    runtime
        .launch(&config)
        .await
        .context("failed to start session")?;

    // Hooks are already on disk from create/launch — no re-registration needed.

    store
        .update_session_state(&session.id, SessionState::Running)
        .await
        .context("failed to update session state")?;

    log_session_event(audit, "session.start", session.id).await;

    println!("Started session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn stop<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
) -> Result<()> {
    let session = resolve_session(store, name).await?;
    let handle = record_to_handle(&session);

    runtime
        .stop(&handle)
        .await
        .context("failed to stop session")?;

    store
        .update_session_state(&session.id, SessionState::Stopped)
        .await
        .context("failed to update session state")?;

    log_session_event(audit, "session.stop", session.id).await;

    println!("Stopped session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn restart<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
) -> Result<()> {
    let session = resolve_session(store, name).await?;
    let handle = record_to_handle(&session);

    // Stop if currently alive.
    if session.state != SessionState::Stopped {
        let _ = runtime.stop(&handle).await;
        // Brief pause for tmux to clean up.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let config = SessionConfig {
        path: session.path.clone(),
        title: session.title.clone(),
        tool: session.tool,
        group: session.group.clone(),
        parent: session.parent,
        execution_class: session.execution_class,
        sandboxed: session.sandboxed,
        initial_message: None,
        worktree_branch: None,
        identity: session.identity.clone(),
        memory: None,
    };

    runtime
        .launch(&config)
        .await
        .context("failed to relaunch session")?;

    // Hooks are already on disk from create/launch — no re-registration needed.

    store
        .update_session_state(&session.id, SessionState::Running)
        .await
        .context("failed to update session state")?;

    log_session_event(audit, "session.restart", session.id).await;

    println!("Restarted session '{}'.", session.title);
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn send<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    audit: &AuditLogWriter,
    name: &str,
    message: &str,
    wait: bool,
    quiet: bool,
) -> Result<()> {
    let session = resolve_session(store, name).await?;
    let handle = record_to_handle(&session);

    let conductor_msg = ConductorMessage::TaskAssignment {
        instructions: message.to_owned(),
    };

    runtime
        .send(&handle, conductor_msg)
        .await
        .context("failed to send message")?;

    log_session_event(audit, "session.send", session.id).await;

    if !quiet {
        println!("Sent to '{}'.", session.title);
    }

    if wait {
        // Poll for output until the session transitions away from Running.
        // Timeout after 5 minutes.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let state = runtime
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

        // Read final output.
        let text = runtime
            .read_output(&handle)
            .await
            .context("failed to read session output")?;

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
async fn output<R: SessionRuntime>(
    store: &Store,
    runtime: &R,
    name: &str,
    quiet: bool,
) -> Result<()> {
    let session = resolve_session(store, name).await?;
    let handle = record_to_handle(&session);

    let text = runtime
        .read_output(&handle)
        .await
        .context("failed to read session output")?;

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
async fn remove(store: &Store, audit: &AuditLogWriter, name: &str) -> Result<()> {
    let session = resolve_session(store, name).await?;

    store
        .delete_session(&session.id)
        .await
        .context("failed to delete session")?;

    log_session_event(audit, "session.remove", session.id).await;

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
            execution_class: ExecutionClass::OfflineWorker,
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
            execution_class: ExecutionClass::OfflineWorker,
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
            execution_class: ExecutionClass::OfflineWorker,
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
