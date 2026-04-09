//! sigil-cli — clap-based CLI binary for AI agent session orchestration.
//!
//! This is the application crate. It uses `anyhow` for error handling
//! and routes subcommands to the appropriate handler in `commands/`.

pub mod audit;
pub mod banner;
pub mod commands;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use sigil_core::error::CoreError;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{SessionConfig, SessionHandle, SessionState};
use sigil_core::traits::SessionRuntime;
#[cfg(feature = "container")]
use sigil_runtime::ContainerRuntime;
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

/// Selects the session runtime backend.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum RuntimeChoice {
    /// tmux-based sessions (default).
    #[default]
    Tmux,
    /// Apple Container VM sessions.
    Container,
}

/// AI agent session orchestration.
#[derive(Parser)]
#[command(name = "sigil", about = "AI agent session orchestration", version, long_version = banner::LONG_VERSION)]
pub struct Cli {
    /// `SQLite` database path.
    #[arg(long, default_value = "~/.sigil/sigil.db", env = "SIGIL_DB")]
    pub db: String,

    /// Session runtime backend.
    #[arg(long, value_enum, default_value_t, env = "SIGIL_RUNTIME")]
    pub runtime: RuntimeChoice,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Show system status summary.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Session management.
    #[command(subcommand)]
    Session(SessionCommands),

    /// Git worktree management.
    #[command(subcommand)]
    Worktree(WorktreeCommands),

    /// Start the conductor loop.
    Conductor {
        /// Heartbeat interval in seconds.
        #[arg(long, default_value = "60")]
        interval: u64,
    },

    /// Run bridge adapters (Telegram, Slack, or both).
    #[command(subcommand)]
    Bridge(BridgeCommands),

    /// Audit log operations.
    #[command(subcommand)]
    Audit(AuditCommands),
}

#[derive(Debug, Subcommand)]
pub enum SessionCommands {
    /// List all sessions.
    List {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show session details.
    Show {
        /// Session ID or title.
        name: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Create a new session.
    Create {
        /// Working directory path.
        path: String,
        /// Session title.
        #[arg(short, long)]
        title: String,
        /// Tool (claude or codex).
        #[arg(short = 'c', long, default_value = "claude")]
        tool: String,
        /// Group name.
        #[arg(short, long)]
        group: Option<String>,
    },

    /// Create, start, and send initial message.
    Launch {
        /// Working directory path.
        path: String,
        /// Session title.
        #[arg(short, long)]
        title: String,
        /// Tool (claude or codex).
        #[arg(short = 'c', long, default_value = "claude")]
        tool: String,
        /// Group name.
        #[arg(short, long)]
        group: Option<String>,
        /// Initial message to send.
        #[arg(short, long)]
        message: Option<String>,
    },

    /// Start a stopped session.
    Start {
        /// Session ID or title.
        name: String,
    },

    /// Stop a running session.
    Stop {
        /// Session ID or title.
        name: String,
    },

    /// Restart a session.
    Restart {
        /// Session ID or title.
        name: String,
    },

    /// Send a message to a session.
    Send {
        /// Session ID or title.
        name: String,
        /// Message text.
        message: String,
        /// Wait for response.
        #[arg(long)]
        wait: bool,
        /// Output raw text (no formatting).
        #[arg(short, long)]
        quiet: bool,
    },

    /// Read session output.
    Output {
        /// Session ID or title.
        name: String,
        /// Output raw text.
        #[arg(short, long)]
        quiet: bool,
    },

    /// Remove a session.
    Remove {
        /// Session ID or title.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum WorktreeCommands {
    /// Create a worktree for a session.
    Create {
        /// Session name or ID.
        name: String,
        /// Branch name.
        #[arg(short, long)]
        branch: String,
    },

    /// Finish a worktree (optionally merge before removing).
    Finish {
        /// Session name or ID.
        name: String,
        /// Merge branch into main before removing.
        #[arg(long)]
        merge: bool,
    },

    /// List active worktrees across sessions.
    List,
}

#[derive(Debug, Subcommand)]
pub enum BridgeCommands {
    /// Run only the Telegram bridge.
    Telegram,

    /// Run only the Slack bridge.
    Slack,

    /// Run both Telegram and Slack bridges concurrently.
    All,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// Verify the HMAC chain in an audit log file.
    Verify {
        /// Path to the audit log file (default: ~/.sigil/audit.jsonl).
        #[arg(long)]
        path: Option<String>,
    },
}

/// Expand a leading `~` to the user's home directory.
pub(crate) fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home).join(rest))
    } else if path == "~" {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home))
    } else {
        Ok(PathBuf::from(path))
    }
}

// ---------------------------------------------------------------------------
// Runtime backend dispatch
// ---------------------------------------------------------------------------

/// Runtime backend that delegates to the chosen session runtime.
pub(crate) enum RuntimeBackend {
    Tmux(TmuxRuntime),
    #[cfg(feature = "container")]
    Container(Box<ContainerRuntime>),
}

impl RuntimeBackend {
    /// Verify that the chosen runtime's prerequisites are met.
    async fn preflight_check(&self) -> Result<()> {
        match self {
            Self::Tmux(_) => TmuxRuntime::check_tmux().await.context("tmux is required"),
            #[cfg(feature = "container")]
            Self::Container(_) => ContainerRuntime::check_container_cli()
                .await
                .context("Apple Containers CLI is required"),
        }
    }
}

impl SessionRuntime for RuntimeBackend {
    async fn launch(&self, config: &SessionConfig) -> Result<SessionHandle, CoreError> {
        match self {
            Self::Tmux(r) => r.launch(config).await,
            #[cfg(feature = "container")]
            Self::Container(r) => r.launch(config).await,
        }
    }

    async fn send(&self, handle: &SessionHandle, msg: ConductorMessage) -> Result<(), CoreError> {
        match self {
            Self::Tmux(r) => r.send(handle, msg).await,
            #[cfg(feature = "container")]
            Self::Container(r) => r.send(handle, msg).await,
        }
    }

    async fn read_output(&self, handle: &SessionHandle) -> Result<String, CoreError> {
        match self {
            Self::Tmux(r) => r.read_output(handle).await,
            #[cfg(feature = "container")]
            Self::Container(r) => r.read_output(handle).await,
        }
    }

    async fn status(&self, handle: &SessionHandle) -> Result<SessionState, CoreError> {
        match self {
            Self::Tmux(r) => r.status(handle).await,
            #[cfg(feature = "container")]
            Self::Container(r) => r.status(handle).await,
        }
    }

    async fn stop(&self, handle: &SessionHandle) -> Result<(), CoreError> {
        match self {
            Self::Tmux(r) => r.stop(handle).await,
            #[cfg(feature = "container")]
            Self::Container(r) => r.stop(handle).await,
        }
    }
}

/// Construct the runtime backend based on the user's choice.
#[allow(clippy::unnecessary_wraps)]
fn build_runtime(choice: RuntimeChoice) -> Result<RuntimeBackend> {
    match choice {
        RuntimeChoice::Tmux => Ok(RuntimeBackend::Tmux(TmuxRuntime::new("sigil"))),
        RuntimeChoice::Container => {
            #[cfg(feature = "container")]
            {
                Ok(RuntimeBackend::Container(Box::new(
                    ContainerRuntime::with_defaults(),
                )))
            }
            #[cfg(not(feature = "container"))]
            {
                anyhow::bail!(
                    "container runtime requires the 'container' feature \
                     (rebuild with --features container)"
                )
            }
        }
    }
}

/// Run the CLI, routing to the appropriate subcommand handler.
///
/// # Errors
///
/// Returns `anyhow::Error` if any subcommand fails.
pub async fn run(cli: Cli) -> Result<()> {
    let db_path = expand_tilde(&cli.db)?;

    // Ensure the parent directory exists for the database file.
    let data_dir = db_path
        .parent()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);

    std::fs::create_dir_all(&data_dir).context("failed to create data directory")?;

    let audit = audit::init_audit_writer(&data_dir)
        .await
        .context("failed to initialize audit writer")?;

    // The bridge command only needs the audit writer — skip Store and
    // runtime initialization so it works without SQLite or tmux.
    if let Commands::Bridge(cmd) = cli.command {
        return commands::bridge::run(Arc::clone(&audit), cmd).await;
    }

    // The audit command is self-contained — no Store or runtime needed.
    if let Commands::Audit(cmd) = cli.command {
        return commands::audit::run(cmd).await;
    }

    let db_str = db_path
        .to_str()
        .context("database path is not valid UTF-8")?;

    let store = Store::new(db_str)
        .await
        .context("failed to open database")?;

    let runtime = build_runtime(cli.runtime)?;

    match cli.command {
        Commands::Status { json } => commands::status::run(&store, json).await,
        Commands::Session(cmd) => commands::session::run(&store, &runtime, &audit, cmd).await,
        Commands::Worktree(cmd) => commands::worktree::run(&store, cmd).await,
        Commands::Conductor { interval } => {
            runtime.preflight_check().await?;
            commands::conductor::run(
                Arc::new(store),
                Arc::new(runtime),
                Arc::clone(&audit),
                interval,
            )
            .await
        }
        Commands::Bridge(_) | Commands::Audit(_) => {
            // Already handled in the early match above.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::wildcard_enum_match_arm)]

    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_parses_status_command() {
        let cli = Cli::try_parse_from(["sigil", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Status { json: false }));
    }

    #[test]
    fn cli_parses_status_with_json_flag() {
        let cli = Cli::try_parse_from(["sigil", "status", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Status { json: true }));
    }

    #[test]
    fn cli_parses_session_list() {
        let cli = Cli::try_parse_from(["sigil", "session", "list"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Session(SessionCommands::List { json: false })
        ));
    }

    #[test]
    fn cli_parses_session_list_json() {
        let cli = Cli::try_parse_from(["sigil", "session", "list", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Session(SessionCommands::List { json: true })
        ));
    }

    #[test]
    fn cli_parses_session_show() {
        let cli = Cli::try_parse_from(["sigil", "session", "show", "my-session"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Show { name, json }) => {
                assert_eq!(name, "my-session");
                assert!(!json);
            }
            other => panic!("expected Session Show, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_session_create() {
        let cli = Cli::try_parse_from([
            "sigil",
            "session",
            "create",
            "/tmp/project",
            "-t",
            "my-session",
            "-c",
            "claude",
            "-g",
            "dev",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Create {
                path,
                title,
                tool,
                group,
            }) => {
                assert_eq!(path, "/tmp/project");
                assert_eq!(title, "my-session");
                assert_eq!(tool, "claude");
                assert_eq!(group.as_deref(), Some("dev"));
            }
            other => panic!("expected Session Create, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_session_launch() {
        let cli = Cli::try_parse_from([
            "sigil",
            "session",
            "launch",
            "/tmp/project",
            "-t",
            "launcher",
            "-m",
            "build the thing",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Launch {
                path,
                title,
                message,
                ..
            }) => {
                assert_eq!(path, "/tmp/project");
                assert_eq!(title, "launcher");
                assert_eq!(message.as_deref(), Some("build the thing"));
            }
            other => panic!("expected Session Launch, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_session_send() {
        let cli = Cli::try_parse_from([
            "sigil",
            "session",
            "send",
            "my-session",
            "hello world",
            "--wait",
            "-q",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Send {
                name,
                message,
                wait,
                quiet,
            }) => {
                assert_eq!(name, "my-session");
                assert_eq!(message, "hello world");
                assert!(wait);
                assert!(quiet);
            }
            other => panic!("expected Session Send, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_session_output() {
        let cli = Cli::try_parse_from(["sigil", "session", "output", "my-session", "-q"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Output { name, quiet }) => {
                assert_eq!(name, "my-session");
                assert!(quiet);
            }
            other => panic!("expected Session Output, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_conductor_command() {
        let cli = Cli::try_parse_from(["sigil", "conductor", "--interval", "30"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Conductor { interval: 30 }));
    }

    #[test]
    fn cli_parses_conductor_default_interval() {
        let cli = Cli::try_parse_from(["sigil", "conductor"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Conductor { interval: 60 }));
    }

    #[test]
    fn cli_runtime_defaults_to_tmux() {
        let cli = Cli::try_parse_from(["sigil", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.runtime, RuntimeChoice::Tmux));
    }

    #[test]
    fn cli_parses_runtime_tmux_explicit() {
        let cli = Cli::try_parse_from(["sigil", "--runtime", "tmux", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.runtime, RuntimeChoice::Tmux));
    }

    #[test]
    fn cli_parses_runtime_container() {
        let cli = Cli::try_parse_from(["sigil", "--runtime", "container", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.runtime, RuntimeChoice::Container));
    }

    #[test]
    fn cli_rejects_invalid_runtime() {
        let cli = Cli::try_parse_from(["sigil", "--runtime", "docker", "status"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_parses_custom_db_path() {
        let cli = Cli::try_parse_from(["sigil", "--db", "/tmp/test.db", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert_eq!(cli.db, "/tmp/test.db");
    }

    #[test]
    fn cli_default_db_path() {
        let cli = Cli::try_parse_from(["sigil", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert_eq!(cli.db, "~/.sigil/sigil.db");
    }

    #[test]
    fn cli_verify_command_structure() {
        // Verifies the clap derive macros produce a valid command tree.
        Cli::command().debug_assert();
    }

    #[test]
    fn expand_tilde_with_home_prefix() {
        let result = expand_tilde("~/foo/bar");
        assert!(result.is_ok());
        let path = result.expect("expand should succeed");
        assert!(!path.to_string_lossy().starts_with('~'));
        assert!(path.to_string_lossy().ends_with("foo/bar"));
    }

    #[test]
    fn expand_tilde_without_prefix_is_passthrough() {
        let result = expand_tilde("/absolute/path");
        assert!(result.is_ok());
        let path = result.expect("expand should succeed");
        assert_eq!(path.to_string_lossy(), "/absolute/path");
    }

    #[test]
    fn expand_tilde_bare_tilde() {
        let result = expand_tilde("~");
        assert!(result.is_ok());
        let path = result.expect("expand should succeed");
        assert!(!path.to_string_lossy().contains('~'));
    }

    // -----------------------------------------------------------------------
    // Worktree CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_worktree_create() {
        let cli = Cli::try_parse_from([
            "sigil",
            "worktree",
            "create",
            "session-name",
            "-b",
            "feature/foo",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Worktree(WorktreeCommands::Create { name, branch }) => {
                assert_eq!(name, "session-name");
                assert_eq!(branch, "feature/foo");
            }
            other => panic!("expected Worktree Create, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_worktree_finish_with_merge() {
        let cli = Cli::try_parse_from(["sigil", "worktree", "finish", "session-name", "--merge"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Worktree(WorktreeCommands::Finish { name, merge }) => {
                assert_eq!(name, "session-name");
                assert!(merge);
            }
            other => panic!("expected Worktree Finish, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_worktree_finish_without_merge() {
        let cli = Cli::try_parse_from(["sigil", "worktree", "finish", "session-name"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Worktree(WorktreeCommands::Finish { name, merge }) => {
                assert_eq!(name, "session-name");
                assert!(!merge);
            }
            other => panic!("expected Worktree Finish, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_worktree_list() {
        let cli = Cli::try_parse_from(["sigil", "worktree", "list"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Worktree(WorktreeCommands::List)
        ));
    }

    // -----------------------------------------------------------------------
    // Bridge CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_bridge_telegram() {
        let cli = Cli::try_parse_from(["sigil", "bridge", "telegram"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Bridge(BridgeCommands::Telegram)
        ));
    }

    #[test]
    fn cli_parses_bridge_slack() {
        let cli = Cli::try_parse_from(["sigil", "bridge", "slack"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Bridge(BridgeCommands::Slack)
        ));
    }

    #[test]
    fn cli_parses_bridge_all() {
        let cli = Cli::try_parse_from(["sigil", "bridge", "all"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Bridge(BridgeCommands::All)));
    }

    #[test]
    fn cli_bridge_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "bridge"]);
        assert!(cli.is_err());
    }

    // -----------------------------------------------------------------------
    // Audit CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_audit_verify() {
        let cli = Cli::try_parse_from(["sigil", "audit", "verify"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Audit(AuditCommands::Verify { path }) => {
                assert!(path.is_none());
            }
            other => panic!("expected Audit Verify, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_audit_verify_with_path() {
        let cli = Cli::try_parse_from(["sigil", "audit", "verify", "--path", "/tmp/audit.jsonl"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Audit(AuditCommands::Verify { path }) => {
                assert_eq!(path.as_deref(), Some("/tmp/audit.jsonl"));
            }
            other => panic!("expected Audit Verify, got {other:?}"),
        }
    }

    #[test]
    fn cli_audit_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "audit"]);
        assert!(cli.is_err());
    }
}
