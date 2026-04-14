//! Memory system integration test (PR6 of 6).
//!
//! Proves the full memory pipeline works end-to-end:
//! 1. Write episodes via `EpisodeWriter` (multiple `EpisodeKind` variants).
//! 2. Read them back and verify via `EpisodeReader` (with filters).
//! 3. Run `MechanicalConsolidator` on the episodes.
//! 4. Verify consolidation output (promotion, staleness, archival).
//! 5. Test CLI commands (`sigil memory episodes list`, `sigil memory
//!    consolidate`) via `std::process::Command` black-box tests.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig, SessionId};
use sigil_memory::{EpisodeFilter, EpisodeReader, EpisodeWriter, MechanicalConsolidator};
use time::OffsetDateTime;

// =========================================================================
// Helpers
// =========================================================================

fn make_time(year: i32, month: u8, day: u8) -> OffsetDateTime {
    let month = time::Month::try_from(month).expect("valid month");
    time::Date::from_calendar_date(year, month, day)
        .expect("valid date")
        .with_time(time::Time::MIDNIGHT)
        .assume_utc()
}

fn make_episode(
    session_id: SessionId,
    kind: EpisodeKind,
    summary: &str,
    tags: Vec<String>,
    source: &str,
    details: Option<serde_json::Value>,
) -> EpisodeEvent {
    EpisodeEvent {
        id: EpisodeId::new(),
        timestamp: OffsetDateTime::now_utc(),
        session_id,
        kind,
        summary: summary.into(),
        details,
        tags,
        source: source.into(),
    }
}

fn make_episode_at(
    session_id: SessionId,
    kind: EpisodeKind,
    summary: &str,
    timestamp: OffsetDateTime,
) -> EpisodeEvent {
    EpisodeEvent {
        id: EpisodeId::new(),
        timestamp,
        session_id,
        kind,
        summary: summary.into(),
        details: None,
        tags: vec![],
        source: "test".into(),
    }
}

// =========================================================================
// Part 1: Library-level full pipeline test
// =========================================================================

/// Full pipeline: write multiple episode kinds -> read back -> filter ->
/// consolidate -> verify output.
#[tokio::test]
async fn full_memory_pipeline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let episodes_path = dir.path().join("episodes.jsonl");

    // --- Step 1: Create MemoryConfig ----------------------------------------
    let config = MemoryConfig {
        promotion_threshold: 2, // lower for test
        episode_retention_days: 30,
        staleness_days: 60,
        episodes_enabled: true,
        consolidation_enabled: true,
    };

    // --- Step 2: Write episodes via EpisodeWriter ---------------------------
    let writer = EpisodeWriter::new(&episodes_path)
        .await
        .expect("create writer");

    let s1 = SessionId::new();
    let s2 = SessionId::new();
    let s3 = SessionId::new();

    // ActionCompleted episodes.
    writer
        .append(&make_episode(
            s1,
            EpisodeKind::ActionCompleted,
            "Created worktree feature/auth",
            vec!["worktree".into(), "infrastructure".into()],
            "conductor",
            Some(serde_json::json!({"action": "WorktreeCreate", "branch": "feature/auth"})),
        ))
        .await
        .expect("append");

    // ToolOutcome episode.
    writer
        .append(&make_episode(
            s1,
            EpisodeKind::ToolOutcome,
            "cargo test passed with 42 tests",
            vec!["test".into()],
            "conductor",
            Some(serde_json::json!({"tool": "cargo", "exit_code": 0})),
        ))
        .await
        .expect("append");

    // ApprovalDecision episode.
    writer
        .append(&make_episode(
            s2,
            EpisodeKind::ApprovalDecision,
            "Approved deploy to staging",
            vec!["approval".into()],
            "conductor",
            None,
        ))
        .await
        .expect("append");

    // UserCorrection episode.
    writer
        .append(&make_episode(
            s2,
            EpisodeKind::UserCorrection,
            "Use snake_case for function names",
            vec!["style".into()],
            "agent",
            None,
        ))
        .await
        .expect("append");

    // CandidateLearning episodes from 2 distinct sessions (meets threshold).
    writer
        .append(&make_episode(
            s1,
            EpisodeKind::CandidateLearning,
            "Always verify session state before sending",
            vec!["best-practice".into()],
            "agent",
            Some(serde_json::json!({"confidence": "high"})),
        ))
        .await
        .expect("append");

    writer
        .append(&make_episode(
            s2,
            EpisodeKind::CandidateLearning,
            "Always verify session state before sending",
            vec!["best-practice".into()],
            "agent",
            Some(serde_json::json!({"confidence": "medium"})),
        ))
        .await
        .expect("append");

    // CandidateLearning from only 1 session (below threshold).
    writer
        .append(&make_episode(
            s3,
            EpisodeKind::CandidateLearning,
            "Worktree branches should match session title",
            vec!["naming".into()],
            "agent",
            None,
        ))
        .await
        .expect("append");

    // SessionSummary episode.
    writer
        .append(&make_episode(
            s1,
            EpisodeKind::SessionSummary,
            "Session s1 ended: implemented auth feature",
            vec![],
            "cli",
            None,
        ))
        .await
        .expect("append");

    // StateCheckpoint episode.
    writer
        .append(&make_episode(
            s2,
            EpisodeKind::StateCheckpoint,
            "Pre-compact state snapshot",
            vec!["checkpoint".into()],
            "conductor",
            Some(serde_json::json!({"state_hash": "abc123"})),
        ))
        .await
        .expect("append");

    // --- Step 3: Read back and verify ---------------------------------------
    let reader = EpisodeReader::new(&episodes_path);

    // Read all.
    let all = reader.read_all().await.expect("read all");
    assert_eq!(all.len(), 9, "should have 9 episodes total");

    // Filter by kind.
    let candidates = reader
        .read_filtered(&EpisodeFilter {
            kind: Some(EpisodeKind::CandidateLearning),
            ..EpisodeFilter::default()
        })
        .await
        .expect("filter by kind");
    assert_eq!(
        candidates.len(),
        3,
        "should have 3 CandidateLearning episodes"
    );

    // Filter by session.
    let s1_episodes = reader
        .read_filtered(&EpisodeFilter {
            session_id: Some(s1),
            ..EpisodeFilter::default()
        })
        .await
        .expect("filter by session");
    assert_eq!(
        s1_episodes.len(),
        4,
        "session s1 should have 4 episodes (ActionCompleted, ToolOutcome, CandidateLearning, SessionSummary)"
    );

    // Filter by tag.
    let infra_tagged = reader
        .read_filtered(&EpisodeFilter {
            tag: Some("infrastructure".into()),
            ..EpisodeFilter::default()
        })
        .await
        .expect("filter by tag");
    assert_eq!(infra_tagged.len(), 1);
    assert_eq!(infra_tagged[0].kind, EpisodeKind::ActionCompleted);

    // Combined filter: session + kind.
    let s2_candidates = reader
        .read_filtered(&EpisodeFilter {
            session_id: Some(s2),
            kind: Some(EpisodeKind::CandidateLearning),
            ..EpisodeFilter::default()
        })
        .await
        .expect("combined filter");
    assert_eq!(s2_candidates.len(), 1);
    assert_eq!(
        s2_candidates[0].summary,
        "Always verify session state before sending"
    );

    // --- Step 4: Run MechanicalConsolidator ---------------------------------
    let consolidator = MechanicalConsolidator::new(config.clone());
    let now = OffsetDateTime::now_utc();
    let result = consolidator
        .consolidate(&all, "", now)
        .expect("consolidation");

    // --- Step 5: Verify consolidation output --------------------------------
    // "Always verify session state before sending" appears in 2 distinct
    // sessions (s1 and s2), which meets the threshold of 2.
    assert_eq!(result.promoted.len(), 1, "one learning should be promoted");
    assert_eq!(
        result.promoted[0],
        "Always verify session state before sending"
    );

    // "Worktree branches should match session title" is only from 1 session.
    assert!(
        !result
            .learnings_content
            .contains("Worktree branches should match session title"),
        "below-threshold candidate should not appear"
    );

    // The promoted learning should appear in the LEARNINGS.md content.
    assert!(
        result
            .learnings_content
            .contains("Always verify session state before sending")
    );
    assert!(result.learnings_content.starts_with("# Learnings\n"));

    // No stale learnings (no existing learnings to go stale).
    assert!(result.marked_stale.is_empty());

    // No archived episodes (all are recent).
    assert!(result.archived_episodes.is_empty());

    // Summary is human-readable.
    assert!(result.summary.contains("promoted 1"));
}

/// Consolidation correctly marks stale learnings and flags old episodes
/// for archival.
#[tokio::test]
async fn consolidation_staleness_and_archival() {
    let dir = tempfile::tempdir().expect("tempdir");
    let episodes_path = dir.path().join("episodes.jsonl");

    let config = MemoryConfig {
        promotion_threshold: 2,
        episode_retention_days: 30,
        staleness_days: 60,
        ..MemoryConfig::default()
    };

    let writer = EpisodeWriter::new(&episodes_path)
        .await
        .expect("create writer");

    let now = make_time(2026, 4, 13);

    // Old episode (> 30 days) that should be flagged for archival.
    let old_event = make_episode_at(
        SessionId::new(),
        EpisodeKind::ActionCompleted,
        "old action from February",
        make_time(2026, 2, 1),
    );
    writer.append(&old_event).await.expect("append old");

    // Recent episode within retention window.
    let recent_event = make_episode_at(
        SessionId::new(),
        EpisodeKind::ActionCompleted,
        "recent action",
        make_time(2026, 4, 10),
    );
    writer.append(&recent_event).await.expect("append recent");

    // Existing learnings with a stale entry (last seen > 60 days ago).
    let existing_learnings = "\
# Learnings

- Old learning from last year
  <!-- sigil:count=5,last=2025-12-01 -->

- Fresh learning
  <!-- sigil:count=3,last=2026-04-01 -->
";

    let reader = EpisodeReader::new(&episodes_path);
    let episodes = reader.read_all().await.expect("read all");

    let consolidator = MechanicalConsolidator::new(config);
    let result = consolidator
        .consolidate(&episodes, existing_learnings, now)
        .expect("consolidation");

    // Old learning should be marked stale (last seen 2025-12-01, > 60 days).
    assert_eq!(result.marked_stale.len(), 1);
    assert_eq!(result.marked_stale[0], "Old learning from last year");
    assert!(result.learnings_content.contains("[stale]"));

    // Fresh learning should not be stale.
    assert!(!result.learnings_content.contains("[stale] Fresh learning"));

    // Old episode should be flagged for archival.
    assert_eq!(result.archived_episodes.len(), 1);
    assert_eq!(result.archived_episodes[0], old_event.id);
}

/// Consolidation is idempotent: running twice with the same input
/// produces the same output.
#[tokio::test]
async fn consolidation_idempotent_across_pipeline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let episodes_path = dir.path().join("episodes.jsonl");

    let config = MemoryConfig {
        promotion_threshold: 2,
        ..MemoryConfig::default()
    };

    let writer = EpisodeWriter::new(&episodes_path)
        .await
        .expect("create writer");

    // Write candidates from 3 sessions (exceeds threshold of 2).
    for _ in 0..3 {
        writer
            .append(&make_episode(
                SessionId::new(),
                EpisodeKind::CandidateLearning,
                "Test idempotent learning",
                vec![],
                "test",
                None,
            ))
            .await
            .expect("append");
    }

    let reader = EpisodeReader::new(&episodes_path);
    let episodes = reader.read_all().await.expect("read all");
    let now = OffsetDateTime::now_utc();

    let consolidator = MechanicalConsolidator::new(config);

    let r1 = consolidator
        .consolidate(&episodes, "", now)
        .expect("first pass");
    assert_eq!(r1.promoted.len(), 1);

    // Second pass with the output of the first.
    let r2 = consolidator
        .consolidate(&episodes, &r1.learnings_content, now)
        .expect("second pass");

    assert_eq!(
        r1.learnings_content, r2.learnings_content,
        "idempotent: same content"
    );
    assert!(r2.promoted.is_empty(), "second pass should not re-promote");
}

/// All seven EpisodeKind variants survive a write-read-serialize roundtrip.
#[tokio::test]
async fn all_episode_kinds_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let episodes_path = dir.path().join("episodes.jsonl");

    let writer = EpisodeWriter::new(&episodes_path)
        .await
        .expect("create writer");

    let session = SessionId::new();
    let kinds = [
        EpisodeKind::ActionCompleted,
        EpisodeKind::ToolOutcome,
        EpisodeKind::ApprovalDecision,
        EpisodeKind::UserCorrection,
        EpisodeKind::CandidateLearning,
        EpisodeKind::SessionSummary,
        EpisodeKind::StateCheckpoint,
    ];

    for kind in &kinds {
        writer
            .append(&make_episode(
                session,
                kind.clone(),
                &format!("test {kind:?}"),
                vec![],
                "test",
                None,
            ))
            .await
            .expect("append");
    }

    let reader = EpisodeReader::new(&episodes_path);
    let episodes = reader.read_all().await.expect("read all");

    assert_eq!(episodes.len(), 7);
    for (i, kind) in kinds.iter().enumerate() {
        assert_eq!(&episodes[i].kind, kind, "kind at index {i}");
    }
}

/// MemoryConfig parsed from TOML controls consolidation behavior.
#[test]
fn memory_config_from_toml_controls_threshold() {
    let toml_str = r"
[memory]
promotion_threshold = 5
episode_retention_days = 14
staleness_days = 30
";
    let config: sigil_core::config::ProjectConfig = toml::from_str(toml_str).expect("parse toml");
    let memory = config
        .memory
        .expect("memory section")
        .into_memory_config()
        .expect("valid config");

    assert_eq!(memory.promotion_threshold, 5);
    assert_eq!(memory.episode_retention_days, 14);
    assert_eq!(memory.staleness_days, 30);

    let consolidator = MechanicalConsolidator::new(memory);
    let now = OffsetDateTime::now_utc();

    // 4 sessions is below threshold of 5 — no promotion.
    let mut episodes = Vec::new();
    for _ in 0..4 {
        episodes.push(make_episode(
            SessionId::new(),
            EpisodeKind::CandidateLearning,
            "Threshold test learning",
            vec![],
            "test",
            None,
        ));
    }

    let result = consolidator
        .consolidate(&episodes, "", now)
        .expect("consolidation");
    assert!(
        result.promoted.is_empty(),
        "4 sessions < threshold 5, no promotion"
    );

    // Add a 5th distinct session — now it should promote.
    episodes.push(make_episode(
        SessionId::new(),
        EpisodeKind::CandidateLearning,
        "Threshold test learning",
        vec![],
        "test",
        None,
    ));

    let result = consolidator
        .consolidate(&episodes, "", now)
        .expect("consolidation");
    assert_eq!(result.promoted.len(), 1, "5 sessions >= threshold 5");
}

// =========================================================================
// Part 2: CLI black-box tests
// =========================================================================

/// Cached binary path — built once, reused across all tests.
static SIGIL_BIN: OnceLock<PathBuf> = OnceLock::new();

fn sigil_bin() -> &'static Path {
    SIGIL_BIN.get_or_init(|| {
        let output = Command::new("cargo")
            .args(["build", "--bin", "sigil", "--message-format=json"])
            .output()
            .expect("failed to run cargo build");
        assert!(
            output.status.success(),
            "cargo build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|msg| msg["reason"] == "compiler-artifact")
            .filter_map(|msg| msg["executable"].as_str().map(PathBuf::from))
            .next_back()
            .expect("cargo build should produce an executable artifact")
    })
}

fn run_sigil(tmp: &Path, args: &[&str]) -> Output {
    let sigil_dir = tmp.join(".sigil");
    let db_path = sigil_dir.join("sigil.db");

    Command::new(sigil_bin())
        .arg("--db")
        .arg(&db_path)
        .args(args)
        .env("HOME", tmp)
        .env("SIGIL_AUDIT_KEY", "test-memory-key")
        .env("RUST_LOG", "off")
        .env_remove("SIGIL_RUNTIME")
        .env_remove("SIGIL_DB")
        .output()
        .expect("failed to execute sigil binary")
}

/// Write episodes directly to the JSONL file for CLI tests.
fn seed_episodes(sigil_dir: &Path, episodes: &[EpisodeEvent]) {
    std::fs::create_dir_all(sigil_dir).expect("create .sigil dir");
    let path = sigil_dir.join("episodes.jsonl");
    let mut contents = String::new();
    for ep in episodes {
        let line = serde_json::to_string(ep).expect("serialize episode");
        contents.push_str(&line);
        contents.push('\n');
    }
    std::fs::write(path, contents).expect("write episodes.jsonl");
}

#[test]
fn cli_memory_episodes_list_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["memory", "episodes", "list"]);
    assert!(
        out.status.success(),
        "memory episodes list should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No episodes"),
        "empty log should say 'No episodes': {stdout}"
    );
}

#[test]
fn cli_memory_episodes_list_shows_written_episodes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    let s1 = SessionId::new();
    seed_episodes(
        &sigil_dir,
        &[
            make_episode(
                s1,
                EpisodeKind::ActionCompleted,
                "Created worktree",
                vec![],
                "conductor",
                None,
            ),
            make_episode(
                s1,
                EpisodeKind::CandidateLearning,
                "Always check state",
                vec![],
                "agent",
                None,
            ),
        ],
    );

    let out = run_sigil(tmp.path(), &["memory", "episodes", "list"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2 episode(s)"),
        "should show 2 episodes: {stdout}"
    );
    assert!(
        stdout.contains("Created worktree"),
        "should show first episode summary: {stdout}"
    );
    assert!(
        stdout.contains("Always check state"),
        "should show second episode summary: {stdout}"
    );
}

#[test]
fn cli_memory_episodes_list_json_returns_array() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    seed_episodes(
        &sigil_dir,
        &[make_episode(
            SessionId::new(),
            EpisodeKind::ToolOutcome,
            "cargo test passed",
            vec!["test".into()],
            "conductor",
            None,
        )],
    );

    let out = run_sigil(tmp.path(), &["memory", "episodes", "list", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert!(parsed.is_array(), "should be a JSON array");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["kind"], "ToolOutcome");
    assert_eq!(arr[0]["summary"], "cargo test passed");
}

#[test]
fn cli_memory_episodes_list_filter_by_kind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    let s1 = SessionId::new();
    seed_episodes(
        &sigil_dir,
        &[
            make_episode(
                s1,
                EpisodeKind::ActionCompleted,
                "action episode",
                vec![],
                "conductor",
                None,
            ),
            make_episode(
                s1,
                EpisodeKind::CandidateLearning,
                "candidate episode",
                vec![],
                "agent",
                None,
            ),
            make_episode(
                s1,
                EpisodeKind::CandidateLearning,
                "another candidate",
                vec![],
                "agent",
                None,
            ),
        ],
    );

    let out = run_sigil(
        tmp.path(),
        &["memory", "episodes", "list", "--kind", "CandidateLearning"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2 episode(s)"),
        "should show 2 CandidateLearning episodes: {stdout}"
    );
    assert!(
        !stdout.contains("action episode"),
        "should not include ActionCompleted"
    );
}

#[test]
fn cli_memory_consolidate_promotes_candidates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    // Write 3 candidates from 3 distinct sessions (meets default threshold=3).
    let episodes: Vec<EpisodeEvent> = (0..3)
        .map(|_| {
            make_episode(
                SessionId::new(),
                EpisodeKind::CandidateLearning,
                "Always verify state before sending",
                vec![],
                "agent",
                None,
            )
        })
        .collect();
    seed_episodes(&sigil_dir, &episodes);

    let out = run_sigil(tmp.path(), &["memory", "consolidate"]);
    assert!(
        out.status.success(),
        "memory consolidate should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("promoted 1"),
        "should promote 1 learning: {stdout}"
    );
    assert!(
        stdout.contains("Always verify state before sending"),
        "should show promoted learning: {stdout}"
    );

    // LEARNINGS.md lives alongside episodes.jsonl in the data directory.
    let learnings_path = sigil_dir.join("LEARNINGS.md");
    let content = std::fs::read_to_string(&learnings_path).expect("read LEARNINGS.md");
    assert!(
        content.contains("Always verify state before sending"),
        "LEARNINGS.md should contain the promoted learning: {content}"
    );
    assert!(
        content.starts_with("# Learnings"),
        "LEARNINGS.md should start with header: {content}"
    );
}

#[test]
fn cli_memory_consolidate_no_candidates_shows_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    // Write only non-candidate episodes.
    seed_episodes(
        &sigil_dir,
        &[make_episode(
            SessionId::new(),
            EpisodeKind::ActionCompleted,
            "just an action",
            vec![],
            "conductor",
            None,
        )],
    );

    let out = run_sigil(tmp.path(), &["memory", "consolidate"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("promoted 0"),
        "should promote nothing: {stdout}"
    );
    assert!(stdout.contains("marked 0 stale"), "nothing stale: {stdout}");

    // With no existing learnings and no promotions, the file should not be
    // written (content comparison gate).
    let learnings_path = sigil_dir.join("LEARNINGS.md");
    if learnings_path.exists() {
        let content = std::fs::read_to_string(&learnings_path).expect("read LEARNINGS.md");
        assert!(
            !content.contains("- "),
            "LEARNINGS.md should have no learning entries: {content}"
        );
    }
}

#[test]
fn cli_memory_consolidate_below_default_threshold_does_not_promote() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    // Default threshold is 3. Only 2 distinct sessions → no promotion.
    let episodes: Vec<EpisodeEvent> = (0..2)
        .map(|_| {
            make_episode(
                SessionId::new(),
                EpisodeKind::CandidateLearning,
                "Threshold test learning",
                vec![],
                "agent",
                None,
            )
        })
        .collect();
    seed_episodes(&sigil_dir, &episodes);

    let out = run_sigil(tmp.path(), &["memory", "consolidate"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("promoted 0"),
        "2 sessions < default threshold 3, should not promote: {stdout}"
    );
}

#[test]
fn cli_help_shows_memory_subcommand() {
    let out = Command::new(sigil_bin())
        .args(["--help"])
        .output()
        .expect("failed to execute");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("memory"),
        "--help should mention 'memory' subcommand: {stdout}"
    );
}

// =========================================================================
// Negative-path tests (from Codex review)
// =========================================================================

#[test]
fn cli_memory_episodes_list_invalid_kind_exits_nonzero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");

    seed_episodes(
        &sigil_dir,
        &[make_episode(
            SessionId::new(),
            EpisodeKind::ActionCompleted,
            "test",
            vec![],
            "test",
            None,
        )],
    );

    let out = run_sigil(
        tmp.path(),
        &["memory", "episodes", "list", "--kind", "NotARealKind"],
    );
    assert!(!out.status.success(), "invalid --kind should exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NotARealKind") || stderr.to_lowercase().contains("invalid"),
        "stderr should mention the bad kind or 'invalid': {stderr}"
    );
}

/// Dedup reinforcement (count/last_seen update) persists to LEARNINGS.md
/// even when no new learnings are promoted.
#[test]
fn cli_memory_consolidate_dedup_reinforcement_persists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigil_dir = tmp.path().join(".sigil");
    std::fs::create_dir_all(&sigil_dir).expect("create .sigil");

    // Pre-existing LEARNINGS.md (in data_dir) with an old count.
    let learnings_path = sigil_dir.join("LEARNINGS.md");
    std::fs::write(
        &learnings_path,
        "# Learnings\n\n- Always verify state before sending\n  <!-- sigil:count=3,last=2026-01-01 -->\n",
    )
    .expect("write LEARNINGS.md");

    // Write 4 candidates from 4 distinct sessions that match the existing
    // learning. Dedup should update count to max(3,4)=4 and last_seen.
    let episodes: Vec<EpisodeEvent> = (0..4)
        .map(|_| {
            make_episode(
                SessionId::new(),
                EpisodeKind::CandidateLearning,
                "Always verify state before sending",
                vec![],
                "agent",
                None,
            )
        })
        .collect();
    seed_episodes(&sigil_dir, &episodes);

    let out = run_sigil(tmp.path(), &["memory", "consolidate"]);
    assert!(
        out.status.success(),
        "consolidate should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Promoted count is 0 because the learning already exists (dedup).
    assert!(
        stdout.contains("promoted 0"),
        "should not re-promote existing learning: {stdout}"
    );

    // LEARNINGS.md should have been updated with the reinforced count.
    let content = std::fs::read_to_string(&learnings_path).expect("read LEARNINGS.md");
    assert!(
        content.contains("count=4"),
        "dedup should update count to 4: {content}"
    );
    // last_seen should be updated to today's date (not the old 2026-01-01).
    assert!(
        !content.contains("last=2026-01-01"),
        "last_seen should be updated: {content}"
    );
}

/// Memory commands do not create audit.jsonl as a side effect.
#[test]
fn cli_memory_does_not_create_audit_log() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_sigil(tmp.path(), &["memory", "episodes", "list"]);
    assert!(out.status.success());

    let audit_path = tmp.path().join(".sigil").join("audit.jsonl");
    assert!(
        !audit_path.exists(),
        "memory commands should not create audit.jsonl"
    );
}
