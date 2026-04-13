//! CLI subcommands for the memory subsystem.
//!
//! Provides `sigil memory episodes list` to inspect the episode log
//! and `sigil memory consolidate` to run a manual consolidation pass.

use std::path::Path;

use anyhow::{Context, Result};

use sigil_core::MemoryConfig;
use sigil_memory::{EpisodeFilter, EpisodeReader, MechanicalConsolidator};

use crate::MemoryCommands;

/// Run a memory subcommand.
///
/// `data_dir` is the `.sigil/` directory (parent of the db file).
///
/// # Errors
///
/// Returns an error if the subcommand fails (I/O, serialization, or
/// consolidation failures).
pub async fn run(data_dir: &Path, cmd: MemoryCommands) -> Result<()> {
    match cmd {
        MemoryCommands::Episodes(sub) => match sub {
            crate::MemoryEpisodesCommands::List { json, kind } => {
                episodes_list(data_dir, json, kind).await
            }
        },
        MemoryCommands::Consolidate => consolidate(data_dir).await,
    }
}

/// List episodes from the episode log.
#[allow(clippy::print_stdout)]
async fn episodes_list(data_dir: &Path, json: bool, kind: Option<String>) -> Result<()> {
    let episodes_path = data_dir.join("episodes.jsonl");
    let reader = EpisodeReader::new(&episodes_path);

    let kind_filter = kind
        .as_deref()
        .map(parse_episode_kind)
        .transpose()
        .context("invalid --kind value")?;

    let filter = EpisodeFilter {
        kind: kind_filter,
        ..EpisodeFilter::default()
    };

    let episodes = reader
        .read_filtered(&filter)
        .await
        .context("failed to read episodes")?;

    if json {
        let output = serde_json::to_string_pretty(&episodes)
            .context("failed to serialize episodes to JSON")?;
        println!("{output}");
    } else if episodes.is_empty() {
        println!("No episodes found.");
    } else {
        println!("{} episode(s):", episodes.len());
        for ep in &episodes {
            println!(
                "  [{ts}] {kind:?} \u{2014} {summary} [session: {sid}]",
                ts = ep.timestamp.date(),
                kind = ep.kind,
                summary = ep.summary,
                sid = ep.session_id,
            );
        }
    }

    Ok(())
}

/// Run a manual consolidation pass.
#[allow(clippy::print_stdout)]
async fn consolidate(data_dir: &Path) -> Result<()> {
    let episodes_path = data_dir.join("episodes.jsonl");
    let reader = EpisodeReader::new(&episodes_path);

    let episodes = reader.read_all().await.context("failed to read episodes")?;

    // Project root is the parent of .sigil/
    let project_dir = data_dir
        .parent()
        .context("cannot determine project directory from data dir")?;
    let learnings_path = project_dir.join("LEARNINGS.md");

    let existing_learnings = match tokio::fs::read_to_string(&learnings_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => anyhow::bail!("failed to read LEARNINGS.md: {e}"),
    };

    let config = load_memory_config(project_dir)?;
    let consolidator = MechanicalConsolidator::new(config);
    let now = time::OffsetDateTime::now_utc();

    let result = consolidator
        .consolidate(&episodes, &existing_learnings, now)
        .context("consolidation failed")?;

    // Write whenever content actually changed (covers promotion, dedup
    // reinforcement, staleness annotation, and stale→fresh transitions).
    if result.learnings_content != existing_learnings {
        tokio::fs::write(&learnings_path, &result.learnings_content)
            .await
            .context("failed to write LEARNINGS.md")?;
    }

    println!("Consolidation complete:");
    println!("  Promoted: {}", result.promoted.len());
    println!("  Marked stale: {}", result.marked_stale.len());
    println!("  Archived episodes: {}", result.archived_episodes.len());

    if !result.promoted.is_empty() {
        println!("\nPromoted learnings:");
        for learning in &result.promoted {
            println!("  - {learning}");
        }
    }

    if !result.marked_stale.is_empty() {
        println!("\nNewly stale:");
        for learning in &result.marked_stale {
            println!("  - {learning}");
        }
    }

    Ok(())
}

/// Load `MemoryConfig` from the project's `.sigil/config.toml`, falling
/// back to defaults if the file or section is missing.
fn load_memory_config(project_dir: &Path) -> Result<MemoryConfig> {
    let config = sigil_core::config::ProjectConfig::load(project_dir)
        .context("failed to load project config")?;

    match config {
        Some(pc) => match pc.memory {
            Some(section) => section
                .into_memory_config()
                .context("invalid memory config"),
            None => Ok(MemoryConfig::default()),
        },
        None => Ok(MemoryConfig::default()),
    }
}

/// Parse an `EpisodeKind` from a CLI string.
fn parse_episode_kind(s: &str) -> Result<sigil_core::EpisodeKind> {
    use sigil_core::EpisodeKind;
    match s {
        "ActionCompleted" => Ok(EpisodeKind::ActionCompleted),
        "ToolOutcome" => Ok(EpisodeKind::ToolOutcome),
        "ApprovalDecision" => Ok(EpisodeKind::ApprovalDecision),
        "UserCorrection" => Ok(EpisodeKind::UserCorrection),
        "CandidateLearning" => Ok(EpisodeKind::CandidateLearning),
        "SessionSummary" => Ok(EpisodeKind::SessionSummary),
        "StateCheckpoint" => Ok(EpisodeKind::StateCheckpoint),
        _ => anyhow::bail!(
            "unknown episode kind '{s}' (expected ActionCompleted, ToolOutcome, \
             ApprovalDecision, UserCorrection, CandidateLearning, SessionSummary, \
             or StateCheckpoint)"
        ),
    }
}
