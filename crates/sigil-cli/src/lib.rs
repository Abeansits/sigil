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

use sigil_conductor::action_service::ActionService;
use sigil_core::EpisodeKind;
use sigil_core::error::CoreError;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::IdentitySpec;
use sigil_core::session::{SessionConfig, SessionHandle, SessionState};
use sigil_core::traits::{LifecycleHooks, SessionRuntime};
use sigil_policy::{EvaluatorConfig, PolicyService};
#[cfg(feature = "container")]
use sigil_runtime::ContainerRuntime;
use sigil_runtime::TmuxRuntime;
use sigil_store::Store;

/// How to interpret the bytes in an `audit key import` file.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum KeyFormat {
    /// Raw bytes, used verbatim (the default).
    #[default]
    Raw,
    /// Hex-encoded; whitespace is ignored before decoding.
    Hex,
}

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

    /// Start the conductor with optional bridge adapters.
    Run {
        /// Heartbeat interval in seconds.
        #[arg(long, default_value = "60")]
        interval: u64,

        /// Bridge to run alongside the conductor.
        #[arg(long, value_enum)]
        bridge: Option<commands::run::BridgeMode>,
    },

    /// Audit log operations.
    #[command(subcommand)]
    Audit(AuditCommands),

    /// Identity file management.
    #[command(subcommand)]
    Identity(IdentityCommands),

    /// Episodic memory operations.
    #[command(subcommand)]
    Memory(MemoryCommands),

    /// External-content sanitization utilities.
    #[command(subcommand)]
    Content(ContentCommands),
}

#[derive(Debug, Subcommand)]
pub enum ContentCommands {
    /// Sanitize a file and print the cleaned output + `SanitizeReport`.
    Sanitize {
        /// Path to the file to sanitize.
        #[arg(long)]
        file: String,
        /// Declared content type — never sniffed.
        #[arg(long = "type", value_enum, value_name = "KIND")]
        kind: commands::content::ContentKind,
        /// Override the `ContentSource` (URL or free-form identifier).
        /// Defaults to `File { path }` for the input file.
        #[arg(long)]
        source: Option<String>,
        /// Emit the full `SanitizedContent` (text + report) as pretty
        /// JSON instead of the human-readable summary.
        #[arg(long)]
        json: bool,
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
        /// Comma-separated identity files (e.g., SOUL.md,OPS.md,state.json).
        /// Overrides .sigil/config.toml [identity] section.
        #[arg(long)]
        identity: Option<String>,
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
        /// Comma-separated identity files (e.g., SOUL.md,OPS.md,state.json).
        /// Overrides .sigil/config.toml [identity] section.
        #[arg(long)]
        identity: Option<String>,
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
pub enum IdentityCommands {
    /// Reload identity files into an active session.
    Reload {
        /// Session name or ID.
        name: String,
    },

    /// Tell a session to snapshot state before compaction.
    Snapshot {
        /// Session name or ID.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// Verify the HMAC chain in an audit log file.
    Verify {
        /// Path to the audit log file (default: ~/.sigil/audit.jsonl).
        #[arg(long)]
        path: Option<String>,
    },

    /// Manage the HMAC key used to seal audit log entries.
    #[command(subcommand)]
    Key(AuditKeyCommands),
}

#[derive(Debug, Subcommand)]
pub enum AuditKeyCommands {
    /// Generate a new 32-byte audit key and store it in the macOS Keychain.
    Generate {
        /// Overwrite an existing Keychain entry without prompting.
        #[arg(long)]
        force: bool,
    },

    /// Print the audit key from the Keychain (hex-encoded).
    Show {
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },

    /// Import an audit key from a file into the Keychain.
    ///
    /// The file is read verbatim for `--format raw` (default) or
    /// hex-decoded (with whitespace stripped) for `--format hex`. Raw
    /// imports are byte-exact: a trailing newline in the file becomes
    /// part of the key — strip it yourself or use `--format hex`.
    Import {
        /// Path to the file containing the key bytes.
        path: String,
        /// Overwrite an existing Keychain entry without prompting.
        #[arg(long)]
        force: bool,
        /// How to interpret the file contents.
        #[arg(long, value_enum, default_value_t)]
        format: KeyFormat,
    },

    /// Delete the audit key from the Keychain.
    Delete {
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommands {
    /// Episode log operations.
    #[command(subcommand)]
    Episodes(EpisodeCommands),

    /// Search across episodes and learnings.
    Search {
        /// Substring to search for in episode summaries, tags, and learnings.
        query: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Run mechanical consolidation.
    Consolidate {
        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Show memory statistics.
    Stats {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EpisodeCommands {
    /// List episodes from the log.
    List {
        /// Filter by session ID (ULID).
        #[arg(long)]
        session: Option<String>,
        /// Filter by episode kind.
        #[arg(long, value_name = "KIND")]
        kind: Option<EpisodeKind>,
        /// Filter by tag.
        #[arg(long)]
        tag: Option<String>,
        /// Only include episodes at or after this date (YYYY-MM-DD).
        #[arg(long, value_name = "DATE")]
        since: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Write an episode to the log (used by hooks and manual capture).
    Write {
        /// Session ID to associate the episode with.
        session_id: String,
        /// Episode kind.
        #[arg(long, value_name = "KIND")]
        kind: EpisodeKind,
        /// One-line summary of the episode.
        #[arg(long)]
        summary: String,
        /// Comma-separated tags.
        #[arg(long)]
        tags: Option<String>,
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

impl LifecycleHooks for RuntimeBackend {
    async fn register_identity_hooks(
        &self,
        handle: &SessionHandle,
        spec: &IdentitySpec,
    ) -> Result<(), CoreError> {
        match self {
            Self::Tmux(r) => r.register_identity_hooks(handle, spec).await,
            #[cfg(feature = "container")]
            Self::Container(_) => {
                // Containers don't support lifecycle hooks in Phase 1.
                Ok(())
            }
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
    // The audit command group manages the HMAC key and verifies the log
    // directly. It must short-circuit *before* any DB / data-dir setup so
    // that bootstrap commands (`audit key generate` on a fresh install,
    // or recovery when SIGIL_DB points at an unwritable parent) still
    // work even if the rest of the CLI's prerequisites are unmet.
    if let Commands::Audit(cmd) = cli.command {
        return commands::audit::run(cmd).await;
    }

    // The `content` command group is a pure file-in/text-out utility.
    // It needs the fingerprint HMAC key (same source as the audit key)
    // but not the DB or runtime. Short-circuit before DB setup so
    // `sigil content sanitize` works on a host without a store.
    if let Commands::Content(cmd) = cli.command {
        return run_content(cmd).await;
    }

    let db_path = expand_tilde(&cli.db)?;

    // Ensure the parent directory exists for the database file.
    let data_dir = db_path
        .parent()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);

    std::fs::create_dir_all(&data_dir).context("failed to create data directory")?;

    // Memory commands are self-contained and must dispatch before audit
    // initialization so they don't create audit.jsonl as a side effect.
    if let Commands::Memory(cmd) = cli.command {
        return commands::memory::run(&data_dir, cmd).await;
    }

    let audit = audit::init_audit_writer(&data_dir)
        .await
        .context("failed to initialize audit writer")?;

    let db_str = db_path
        .to_str()
        .context("database path is not valid UTF-8")?;

    let store = Arc::new(
        Store::new(db_str)
            .await
            .context("failed to open database")?,
    );

    let runtime = Arc::new(build_runtime(cli.runtime)?);

    // Single ActionService for every CLI command that needs to route through
    // policy → dispatch → audit. Using the real Store as GrantStore means
    // approval grants persisted by bridge/conductor flows are honored here.
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let action_service = ActionService::new(
        policy,
        Arc::clone(&runtime),
        Arc::clone(&audit),
        Arc::clone(&store),
    );

    match cli.command {
        Commands::Status { json } => commands::status::run(&action_service, json).await,
        Commands::Session(cmd) => commands::session::run(&action_service, cmd).await,
        Commands::Worktree(cmd) => commands::worktree::run(&action_service, cmd).await,
        Commands::Conductor { interval } => {
            runtime.preflight_check().await?;
            commands::conductor::run(
                Arc::clone(&store),
                Arc::clone(&runtime),
                Arc::clone(&audit),
                interval,
            )
            .await
        }
        Commands::Bridge(cmd) => {
            runtime.preflight_check().await?;
            // Use the same loaded IdentityConfig the bridge loops will use,
            // so policy ceilings can never drift from the actual allowlist.
            let identity_config = commands::bridge::load_identity_config()?;
            let eval_config = commands::bridge::evaluator_config_from_identity(&identity_config);
            let conductor = Arc::new(
                sigil_conductor::Conductor::new(
                    Arc::clone(&store),
                    Arc::clone(&runtime),
                    std::time::Duration::from_secs(60),
                )
                .with_audit(Arc::clone(&audit))
                .with_evaluator_config(eval_config),
            );
            Box::pin(commands::bridge::run(conductor, Arc::clone(&audit), cmd)).await
        }
        Commands::Run { interval, bridge } => {
            runtime.preflight_check().await?;
            Box::pin(commands::run::run(
                Arc::clone(&store),
                Arc::clone(&runtime),
                Arc::clone(&audit),
                interval,
                bridge,
            ))
            .await
        }
        Commands::Identity(cmd) => commands::identity::run(&action_service, cmd).await,
        Commands::Audit(_) | Commands::Memory(_) | Commands::Content(_) => {
            // Already handled above.
            Ok(())
        }
    }
}

async fn run_content(cmd: ContentCommands) -> Result<()> {
    match cmd {
        ContentCommands::Sanitize {
            file,
            kind,
            source,
            json,
        } => commands::content::sanitize(&file, kind, source.as_deref(), json).await,
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
                identity,
            }) => {
                assert_eq!(path, "/tmp/project");
                assert_eq!(title, "my-session");
                assert_eq!(tool, "claude");
                assert_eq!(group.as_deref(), Some("dev"));
                assert!(identity.is_none());
            }
            other => panic!("expected Session Create, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_session_create_with_identity() {
        let cli = Cli::try_parse_from([
            "sigil",
            "session",
            "create",
            "/tmp/project",
            "-t",
            "my-session",
            "--identity",
            "SOUL.md,OPS.md,state.json",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Create { identity, .. }) => {
                assert_eq!(identity.as_deref(), Some("SOUL.md,OPS.md,state.json"));
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
    fn cli_parses_session_launch_with_identity() {
        let cli = Cli::try_parse_from([
            "sigil",
            "session",
            "launch",
            "/tmp/project",
            "-t",
            "launcher",
            "--identity",
            "SOUL.md,OPS.md",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Session(SessionCommands::Launch { identity, .. }) => {
                assert_eq!(identity.as_deref(), Some("SOUL.md,OPS.md"));
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

    // -----------------------------------------------------------------------
    // Identity CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_identity_reload() {
        let cli = Cli::try_parse_from(["sigil", "identity", "reload", "my-session"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Identity(IdentityCommands::Reload { name }) => {
                assert_eq!(name, "my-session");
            }
            other => panic!("expected Identity Reload, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_identity_snapshot() {
        let cli = Cli::try_parse_from(["sigil", "identity", "snapshot", "my-session"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Identity(IdentityCommands::Snapshot { name }) => {
                assert_eq!(name, "my-session");
            }
            other => panic!("expected Identity Snapshot, got {other:?}"),
        }
    }

    #[test]
    fn cli_identity_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "identity"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_identity_reload_requires_name() {
        let cli = Cli::try_parse_from(["sigil", "identity", "reload"]);
        assert!(cli.is_err());
    }

    // -----------------------------------------------------------------------
    // Memory CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_memory_episodes_list() {
        let cli = Cli::try_parse_from(["sigil", "memory", "episodes", "list"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Memory(MemoryCommands::Episodes(EpisodeCommands::List {
                session: None,
                kind: None,
                tag: None,
                since: None,
                json: false,
            }))
        ));
    }

    #[test]
    fn cli_parses_memory_episodes_list_with_filters() {
        let cli = Cli::try_parse_from([
            "sigil",
            "memory",
            "episodes",
            "list",
            "--kind",
            "ActionCompleted",
            "--tag",
            "infra",
            "--since",
            "2026-01-01",
            "--json",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Memory(MemoryCommands::Episodes(EpisodeCommands::List {
                kind,
                tag,
                since,
                json,
                ..
            })) => {
                assert_eq!(*kind, Some(sigil_core::EpisodeKind::ActionCompleted));
                assert_eq!(tag.as_deref(), Some("infra"));
                assert_eq!(since.as_deref(), Some("2026-01-01"));
                assert!(*json);
            }
            other => panic!("expected Memory Episodes List, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_memory_episodes_write() {
        let cli = Cli::try_parse_from([
            "sigil",
            "memory",
            "episodes",
            "write",
            "01JRR3SESSION000000000000",
            "--kind",
            "CandidateLearning",
            "--summary",
            "Test learning",
            "--tags",
            "test,infra",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Memory(MemoryCommands::Episodes(EpisodeCommands::Write {
                session_id,
                kind,
                summary,
                tags,
            })) => {
                assert_eq!(session_id, "01JRR3SESSION000000000000");
                assert_eq!(*kind, sigil_core::EpisodeKind::CandidateLearning);
                assert_eq!(summary, "Test learning");
                assert_eq!(tags.as_deref(), Some("test,infra"));
            }
            other => panic!("expected Memory Episodes Write, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_memory_search() {
        let cli = Cli::try_parse_from(["sigil", "memory", "search", "worktree"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Memory(MemoryCommands::Search { query, json }) => {
                assert_eq!(query, "worktree");
                assert!(!json);
            }
            other => panic!("expected Memory Search, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_memory_search_json() {
        let cli = Cli::try_parse_from(["sigil", "memory", "search", "worktree", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Memory(MemoryCommands::Search { json, .. }) => {
                assert!(json);
            }
            other => panic!("expected Memory Search, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_memory_consolidate() {
        let cli = Cli::try_parse_from(["sigil", "memory", "consolidate"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Memory(MemoryCommands::Consolidate { dry_run: false })
        ));
    }

    #[test]
    fn cli_parses_memory_consolidate_dry_run() {
        let cli = Cli::try_parse_from(["sigil", "memory", "consolidate", "--dry-run"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Memory(MemoryCommands::Consolidate { dry_run: true })
        ));
    }

    #[test]
    fn cli_parses_memory_stats() {
        let cli = Cli::try_parse_from(["sigil", "memory", "stats"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Memory(MemoryCommands::Stats { json: false })
        ));
    }

    #[test]
    fn cli_parses_memory_stats_json() {
        let cli = Cli::try_parse_from(["sigil", "memory", "stats", "--json"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Memory(MemoryCommands::Stats { json: true })
        ));
    }

    #[test]
    fn cli_memory_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "memory"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_memory_episodes_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "memory", "episodes"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_memory_episodes_write_requires_kind_and_summary() {
        let cli = Cli::try_parse_from([
            "sigil",
            "memory",
            "episodes",
            "write",
            "01JRR3SESSION000000000000",
        ]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_memory_episodes_write_rejects_invalid_kind() {
        let cli = Cli::try_parse_from([
            "sigil",
            "memory",
            "episodes",
            "write",
            "01JRR3SESSION000000000000",
            "--kind",
            "InvalidKind",
            "--summary",
            "test",
        ]);
        assert!(cli.is_err());
    }

    // -----------------------------------------------------------------------
    // Run CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_run_default() {
        let cli = Cli::try_parse_from(["sigil", "run"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { interval, bridge } => {
                assert_eq!(*interval, 60);
                assert!(bridge.is_none());
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_run_custom_interval() {
        let cli = Cli::try_parse_from(["sigil", "run", "--interval", "30"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { interval, bridge } => {
                assert_eq!(*interval, 30);
                assert!(bridge.is_none());
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_run_with_telegram_bridge() {
        let cli = Cli::try_parse_from(["sigil", "run", "--bridge", "telegram"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { bridge, .. } => {
                assert!(matches!(bridge, Some(commands::run::BridgeMode::Telegram)));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_run_with_slack_bridge() {
        let cli = Cli::try_parse_from(["sigil", "run", "--bridge", "slack"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { bridge, .. } => {
                assert!(matches!(bridge, Some(commands::run::BridgeMode::Slack)));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_run_with_all_bridges() {
        let cli = Cli::try_parse_from(["sigil", "run", "--bridge", "all"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { bridge, .. } => {
                assert!(matches!(bridge, Some(commands::run::BridgeMode::All)));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_run_with_interval_and_bridge() {
        let cli = Cli::try_parse_from(["sigil", "run", "--interval", "15", "--bridge", "all"]);
        assert!(cli.is_ok());
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Run { interval, bridge } => {
                assert_eq!(*interval, 15);
                assert!(matches!(bridge, Some(commands::run::BridgeMode::All)));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Content CLI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_content_sanitize_html() {
        let cli = Cli::try_parse_from([
            "sigil",
            "content",
            "sanitize",
            "--file",
            "/tmp/x.html",
            "--type",
            "html",
        ]);
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Content(ContentCommands::Sanitize {
                file,
                kind,
                source,
                json,
            }) => {
                assert_eq!(file, "/tmp/x.html");
                assert!(matches!(kind, commands::content::ContentKind::Html));
                assert!(source.is_none());
                assert!(!json);
            }
            other => panic!("expected Content Sanitize, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_content_sanitize_with_source_and_json() {
        let cli = Cli::try_parse_from([
            "sigil",
            "content",
            "sanitize",
            "--file",
            "/tmp/x.md",
            "--type",
            "md",
            "--source",
            "https://example.com/p",
            "--json",
        ]);
        let cli = cli.expect("parse should succeed");
        match &cli.command {
            Commands::Content(ContentCommands::Sanitize {
                kind, source, json, ..
            }) => {
                assert!(matches!(kind, commands::content::ContentKind::Md));
                assert_eq!(source.as_deref(), Some("https://example.com/p"));
                assert!(json);
            }
            other => panic!("expected Content Sanitize, got {other:?}"),
        }
    }

    #[test]
    fn cli_content_sanitize_rejects_unknown_type() {
        let cli = Cli::try_parse_from([
            "sigil", "content", "sanitize", "--file", "/tmp/x", "--type", "yaml",
        ]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_content_requires_subcommand() {
        let cli = Cli::try_parse_from(["sigil", "content"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_run_rejects_invalid_bridge() {
        let cli = Cli::try_parse_from(["sigil", "run", "--bridge", "discord"]);
        assert!(cli.is_err());
    }
}
