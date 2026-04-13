//! The `memory` command group — episodic memory operations.
//!
//! Subcommands for reading, writing, searching, and consolidating
//! the episode log (`episodes.jsonl`) and learnings (`LEARNINGS.md`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig, SessionId};
use sigil_memory::{EpisodeFilter, EpisodeReader, EpisodeWriter, MechanicalConsolidator};

use crate::{EpisodeCommands, MemoryCommands};

/// Run the appropriate memory subcommand.
///
/// # Errors
///
/// Returns an error if any memory operation fails.
#[allow(clippy::print_stdout)]
pub async fn run(data_dir: &Path, cmd: MemoryCommands) -> Result<()> {
    match cmd {
        MemoryCommands::Episodes(ep_cmd) => run_episodes(data_dir, ep_cmd).await,
        MemoryCommands::Search { query, json } => run_search(data_dir, &query, json).await,
        MemoryCommands::Consolidate { dry_run } => run_consolidate(data_dir, dry_run).await,
        MemoryCommands::Stats { json } => run_stats(data_dir, json).await,
    }
}

/// Path to the episode log in the data directory.
fn episodes_path(data_dir: &Path) -> PathBuf {
    data_dir.join("episodes.jsonl")
}

// ---------------------------------------------------------------------------
// Episodes subcommands
// ---------------------------------------------------------------------------

async fn run_episodes(data_dir: &Path, cmd: EpisodeCommands) -> Result<()> {
    match cmd {
        EpisodeCommands::List {
            session,
            kind,
            tag,
            since,
            json,
        } => list_episodes(data_dir, session, kind, tag, since, json).await,
        EpisodeCommands::Write {
            session_id,
            kind,
            summary,
            tags,
        } => write_episode(data_dir, &session_id, kind, &summary, tags).await,
    }
}

#[allow(clippy::print_stdout)]
async fn list_episodes(
    data_dir: &Path,
    session: Option<String>,
    kind: Option<EpisodeKind>,
    tag: Option<String>,
    since: Option<String>,
    json: bool,
) -> Result<()> {
    let path = episodes_path(data_dir);
    let reader = EpisodeReader::new(&path);

    let session_id = session
        .map(|s| s.parse::<SessionId>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid session ID: {e}"))?;

    let since = since.map(|s| parse_date_arg(&s)).transpose()?;

    let filter = EpisodeFilter {
        session_id,
        kind,
        tag,
        since,
        ..EpisodeFilter::default()
    };

    let episodes = reader
        .read_filtered(&filter)
        .await
        .context("failed to read episodes")?;

    if json {
        let output =
            serde_json::to_string_pretty(&episodes).context("failed to serialize episodes")?;
        println!("{output}");
    } else if episodes.is_empty() {
        println!("No episodes found.");
    } else {
        for ep in &episodes {
            println!(
                "{} [{}] {} — {}",
                format_timestamp(ep.timestamp),
                ep.kind,
                ep.session_id,
                ep.summary,
            );
            if !ep.tags.is_empty() {
                println!("  tags: {}", ep.tags.join(", "));
            }
        }
        println!("\n{} episode(s)", episodes.len());
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
async fn write_episode(
    data_dir: &Path,
    session_id: &str,
    kind: EpisodeKind,
    summary: &str,
    tags: Option<String>,
) -> Result<()> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid session ID: {e}"))?;

    let tags: Vec<String> = tags
        .map(|t| t.split(',').map(|s| s.trim().to_owned()).collect())
        .unwrap_or_default();

    let event = EpisodeEvent {
        id: EpisodeId::new(),
        timestamp: time::OffsetDateTime::now_utc(),
        session_id,
        kind,
        summary: summary.to_owned(),
        details: None,
        tags,
        source: "cli".into(),
    };

    let path = episodes_path(data_dir);
    let writer = EpisodeWriter::new(&path)
        .await
        .context("failed to open episode log")?;
    writer
        .append(&event)
        .await
        .context("failed to write episode")?;

    println!("Episode {} written.", event.id);

    Ok(())
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

#[allow(clippy::print_stdout)]
async fn run_search(data_dir: &Path, query: &str, json: bool) -> Result<()> {
    let query_lower = query.to_lowercase();

    // Search episodes.
    let ep_path = episodes_path(data_dir);
    let reader = EpisodeReader::new(&ep_path);
    let episodes = reader.read_all().await.context("failed to read episodes")?;

    let matched_episodes: Vec<&EpisodeEvent> = episodes
        .iter()
        .filter(|ep| {
            ep.summary.to_lowercase().contains(&query_lower)
                || ep
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&query_lower))
        })
        .collect();

    // Search LEARNINGS.md in the current directory if present.
    let learnings_path = PathBuf::from("LEARNINGS.md");
    let matched_learnings = if learnings_path.exists() {
        std::fs::read_to_string(&learnings_path)
            .context("failed to read LEARNINGS.md")?
            .lines()
            .filter(|line| line.to_lowercase().contains(&query_lower))
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("<!--")
            })
            .map(|line| line.trim().to_owned())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    if json {
        let output = serde_json::json!({
            "episodes": matched_episodes,
            "learnings": matched_learnings,
        });
        let formatted =
            serde_json::to_string_pretty(&output).context("failed to serialize search results")?;
        println!("{formatted}");
    } else if matched_episodes.is_empty() && matched_learnings.is_empty() {
        println!("No matches found for '{query}'.");
    } else {
        if !matched_episodes.is_empty() {
            println!("Episodes ({}):", matched_episodes.len());
            for ep in &matched_episodes {
                println!(
                    "  {} [{}] {}",
                    format_timestamp(ep.timestamp),
                    ep.kind,
                    ep.summary,
                );
            }
        }
        if !matched_learnings.is_empty() {
            if !matched_episodes.is_empty() {
                println!();
            }
            println!("Learnings ({}):", matched_learnings.len());
            for line in &matched_learnings {
                println!("  {line}");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Consolidate
// ---------------------------------------------------------------------------

#[allow(clippy::print_stdout)]
async fn run_consolidate(data_dir: &Path, dry_run: bool) -> Result<()> {
    let ep_path = episodes_path(data_dir);
    let reader = EpisodeReader::new(&ep_path);
    let episodes = reader.read_all().await.context("failed to read episodes")?;

    let learnings_path = PathBuf::from("LEARNINGS.md");
    let existing_learnings = if learnings_path.exists() {
        std::fs::read_to_string(&learnings_path).context("failed to read LEARNINGS.md")?
    } else {
        String::new()
    };

    let config = MemoryConfig::default();
    let consolidator = MechanicalConsolidator::new(config);
    let now = time::OffsetDateTime::now_utc();

    let result = consolidator
        .consolidate(&episodes, &existing_learnings, now)
        .context("consolidation failed")?;

    println!("{}", result.summary);

    if !result.promoted.is_empty() {
        println!("\nPromoted:");
        for p in &result.promoted {
            println!("  + {p}");
        }
    }

    if !result.marked_stale.is_empty() {
        println!("\nMarked stale:");
        for s in &result.marked_stale {
            println!("  ~ {s}");
        }
    }

    if !result.archived_episodes.is_empty() {
        println!(
            "\n{} episode(s) eligible for archival",
            result.archived_episodes.len()
        );
    }

    if dry_run {
        println!("\n(dry run — no changes written)");
    } else {
        let has_changes = !result.promoted.is_empty() || !result.marked_stale.is_empty();
        if has_changes {
            std::fs::write(&learnings_path, &result.learnings_content)
                .context("failed to write LEARNINGS.md")?;
            println!("\nWrote LEARNINGS.md");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[allow(clippy::print_stdout)]
async fn run_stats(data_dir: &Path, json: bool) -> Result<()> {
    let ep_path = episodes_path(data_dir);
    let reader = EpisodeReader::new(&ep_path);
    let episodes = reader.read_all().await.context("failed to read episodes")?;

    let total_episodes = episodes.len();

    let mut kind_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut sessions = std::collections::HashSet::new();
    for ep in &episodes {
        *kind_counts.entry(ep.kind.to_string()).or_insert(0) += 1;
        sessions.insert(ep.session_id);
    }
    let session_count = sessions.len();

    let learnings_path = PathBuf::from("LEARNINGS.md");
    let (learning_count, stale_count) = if learnings_path.exists() {
        let content =
            std::fs::read_to_string(&learnings_path).context("failed to read LEARNINGS.md")?;
        let learnings = content
            .lines()
            .filter(|l| l.trim().starts_with("- "))
            .count();
        let stale = content.lines().filter(|l| l.contains("[stale]")).count();
        (learnings, stale)
    } else {
        (0, 0)
    };

    if json {
        let output = serde_json::json!({
            "episodes": total_episodes,
            "sessions": session_count,
            "by_kind": kind_counts,
            "learnings": learning_count,
            "stale_learnings": stale_count,
        });
        let formatted =
            serde_json::to_string_pretty(&output).context("failed to serialize stats")?;
        println!("{formatted}");
    } else {
        println!("Episodes:  {total_episodes}");
        println!("Sessions:  {session_count}");
        if !kind_counts.is_empty() {
            for (kind, count) in &kind_counts {
                println!("  {kind}: {count}");
            }
        }
        println!("Learnings: {learning_count}");
        println!("Stale:     {stale_count}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a `YYYY-MM-DD` date string into midnight UTC `OffsetDateTime`.
fn parse_date_arg(s: &str) -> Result<time::OffsetDateTime> {
    let mut parts = s.splitn(3, '-');
    let year: i32 = parts
        .next()
        .context("missing year")?
        .parse()
        .context("invalid year")?;
    let month: u8 = parts
        .next()
        .context("missing month")?
        .parse()
        .context("invalid month")?;
    let day: u8 = parts
        .next()
        .context("missing day")?
        .parse()
        .context("invalid day")?;
    let month =
        time::Month::try_from(month).map_err(|_| anyhow::anyhow!("invalid month: {month}"))?;
    let date = time::Date::from_calendar_date(year, month, day)
        .map_err(|_| anyhow::anyhow!("invalid date: {s}"))?;
    Ok(date.with_time(time::Time::MIDNIGHT).assume_utc())
}

/// Format a timestamp as `YYYY-MM-DD HH:MM:SS`.
fn format_timestamp(ts: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        ts.year(),
        ts.month() as u8,
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn list_empty_log_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(
            dir.path(),
            MemoryCommands::Episodes(EpisodeCommands::List {
                session: None,
                kind: None,
                tag: None,
                since: None,
                json: false,
            }),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn consolidate_dry_run_empty() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path(), MemoryCommands::Consolidate { dry_run: true }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn stats_zeros_for_fresh_project() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path(), MemoryCommands::Stats { json: true }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn write_and_list_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let session_id = SessionId::new().to_string();

        // Write an episode.
        run(
            dir.path(),
            MemoryCommands::Episodes(EpisodeCommands::Write {
                session_id: session_id.clone(),
                kind: EpisodeKind::ActionCompleted,
                summary: "test action completed".into(),
                tags: Some("infra,test".into()),
            }),
        )
        .await
        .unwrap();

        // List should find it.
        run(
            dir.path(),
            MemoryCommands::Episodes(EpisodeCommands::List {
                session: Some(session_id),
                kind: None,
                tag: None,
                since: None,
                json: true,
            }),
        )
        .await
        .unwrap();

        // Verify the file exists and has one line.
        let content = std::fs::read_to_string(episodes_path(dir.path())).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
    }

    #[tokio::test]
    async fn search_empty_returns_no_matches() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(
            dir.path(),
            MemoryCommands::Search {
                query: "nonexistent".into(),
                json: false,
            },
        )
        .await;
        assert!(result.is_ok());
    }

    #[test]
    fn parse_date_arg_valid() {
        let dt = parse_date_arg("2026-04-11").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month() as u8, 4);
        assert_eq!(dt.day(), 11);
    }

    #[test]
    fn parse_date_arg_invalid() {
        assert!(parse_date_arg("not-a-date").is_err());
        assert!(parse_date_arg("2026-13-01").is_err());
        assert!(parse_date_arg("2026-02-30").is_err());
    }

    #[test]
    fn format_timestamp_produces_expected_format() {
        let ts = time::Date::from_calendar_date(2026, time::Month::April, 11)
            .unwrap()
            .with_hms(14, 32, 0)
            .unwrap()
            .assume_utc();
        assert_eq!(format_timestamp(ts), "2026-04-11 14:32:00");
    }
}
