//! ops-cli — clap-based CLI binary for AI agent session orchestration.
//!
//! This is the application crate. It uses `anyhow` for error handling
//! and routes subcommands to the appropriate handler in `commands/`.

pub mod audit;
pub mod commands;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use ops_runtime::TmuxRuntime;
use ops_store::Store;

/// AI agent session orchestration.
#[derive(Parser)]
#[command(name = "agent-ops", about = "AI agent session orchestration")]
pub struct Cli {
    /// `SQLite` database path.
    #[arg(
        long,
        default_value = "~/.agent-ops/agent-ops.db",
        env = "AGENT_OPS_DB"
    )]
    pub db: String,

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

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> Result<PathBuf> {
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

    let db_str = db_path
        .to_str()
        .context("database path is not valid UTF-8")?;

    let store = Store::new(db_str)
        .await
        .context("failed to open database")?;

    let runtime = TmuxRuntime::new("agent-ops");

    let audit = audit::init_audit_writer(&data_dir)
        .await
        .context("failed to initialize audit writer")?;

    match cli.command {
        Commands::Status { json } => commands::status::run(&store, json).await,
        Commands::Session(cmd) => commands::session::run(&store, &runtime, &audit, cmd).await,
        Commands::Worktree(cmd) => commands::worktree::run(&store, cmd).await,
        Commands::Conductor { interval } => {
            commands::conductor::run(
                Arc::new(store),
                Arc::new(runtime),
                Arc::clone(&audit),
                interval,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_parses_status_command() {
        let cli = Cli::try_parse_from(["agent-ops", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Status { json: false }));
    }

    #[test]
    fn cli_parses_status_with_json_flag() {
        let cli = Cli::try_parse_from(["agent-ops", "status", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Status { json: true }));
    }

    #[test]
    fn cli_parses_session_list() {
        let cli = Cli::try_parse_from(["agent-ops", "session", "list"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Session(SessionCommands::List { json: false })
        ));
    }

    #[test]
    fn cli_parses_session_list_json() {
        let cli = Cli::try_parse_from(["agent-ops", "session", "list", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Session(SessionCommands::List { json: true })
        ));
    }

    #[test]
    fn cli_parses_session_show() {
        let cli = Cli::try_parse_from(["agent-ops", "session", "show", "my-session"]);
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
            "agent-ops",
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
            "agent-ops",
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
            "agent-ops",
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
        let cli = Cli::try_parse_from(["agent-ops", "session", "output", "my-session", "-q"]);
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
        let cli = Cli::try_parse_from(["agent-ops", "conductor", "--interval", "30"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Conductor { interval: 30 }));
    }

    #[test]
    fn cli_parses_conductor_default_interval() {
        let cli = Cli::try_parse_from(["agent-ops", "conductor"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(cli.command, Commands::Conductor { interval: 60 }));
    }

    #[test]
    fn cli_parses_custom_db_path() {
        let cli = Cli::try_parse_from(["agent-ops", "--db", "/tmp/test.db", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert_eq!(cli.db, "/tmp/test.db");
    }

    #[test]
    fn cli_default_db_path() {
        let cli = Cli::try_parse_from(["agent-ops", "status"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert_eq!(cli.db, "~/.agent-ops/agent-ops.db");
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
            "agent-ops",
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
        let cli =
            Cli::try_parse_from(["agent-ops", "worktree", "finish", "session-name", "--merge"]);
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
        let cli = Cli::try_parse_from(["agent-ops", "worktree", "finish", "session-name"]);
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
        let cli = Cli::try_parse_from(["agent-ops", "worktree", "list"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Worktree(WorktreeCommands::List)
        ));
    }
}
