//! Mechanical consolidation of episode logs into learnings.
//!
//! [`MechanicalConsolidator`] applies deterministic rules to promote
//! candidate learnings, deduplicate, annotate staleness, and flag
//! episodes for archival. It is a **pure function** over its inputs:
//! it reads episodes and existing `LEARNINGS.md` content, and returns
//! a [`ConsolidationResult`] describing what changed. The caller
//! (typically the conductor) handles all I/O.
//!
//! # Rules
//!
//! 1. **Recurrence counting** — count distinct sessions per candidate
//!    learning, matched by normalized summary (lowercase, strip
//!    punctuation).
//! 2. **Promotion** — candidates appearing in N+ distinct sessions
//!    (default 3) are added to learnings.
//! 3. **Deduplication** — candidates matching existing learnings update
//!    the existing entry instead of adding a duplicate.
//! 4. **Staleness** — learnings not reinforced within the staleness
//!    window get a `[stale]` annotation.
//! 5. **Archival** — episodes older than the retention window are
//!    flagged for archival.
//! 6. **Idempotence** — same inputs always produce the same outputs.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig};

use crate::error::MemoryError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a consolidation pass.
#[derive(Debug, Clone)]
pub struct ConsolidationResult {
    /// New content for `LEARNINGS.md` (full replacement, not diff).
    pub learnings_content: String,
    /// Episode IDs flagged for archival (older than retention window).
    pub archived_episodes: Vec<EpisodeId>,
    /// Summaries of candidate learnings that were promoted.
    pub promoted: Vec<String>,
    /// Summaries of existing learnings newly marked stale.
    pub marked_stale: Vec<String>,
    /// Human-readable summary for logging.
    pub summary: String,
}

/// Mechanical consolidator that applies deterministic rules to episodes.
///
/// Does **not** touch the filesystem. Call
/// [`consolidate`](Self::consolidate) with the episode list and existing
/// learnings text; write the outputs yourself.
pub struct MechanicalConsolidator {
    config: MemoryConfig,
}

impl MechanicalConsolidator {
    /// Create a consolidator with the given configuration.
    #[must_use]
    pub fn new(config: MemoryConfig) -> Self {
        Self { config }
    }

    /// Run one consolidation pass.
    ///
    /// Reads `episodes` and `existing_learnings`, applies
    /// promotion/dedup/staleness/archival rules, and returns a
    /// [`ConsolidationResult`] describing what changed.
    ///
    /// `now` is passed explicitly so tests can control time.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Consolidation`] on internal logic failures
    /// (currently infallible but reserved for future invariant checks).
    pub fn consolidate(
        &self,
        episodes: &[EpisodeEvent],
        existing_learnings: &str,
        now: time::OffsetDateTime,
    ) -> Result<ConsolidationResult, MemoryError> {
        let mut learnings = parse_learnings(existing_learnings);
        let candidates = gather_candidates(episodes);
        let threshold = self.config.promotion_threshold as usize;

        let mut promoted = Vec::new();

        // --- Promotion + dedup ------------------------------------------------
        for (normalized, group) in &candidates {
            let session_count = group.session_ids.len();
            let episode_count = u32::try_from(session_count).unwrap_or(u32::MAX);

            if let Some(existing) = learnings
                .iter_mut()
                .find(|l| normalize(&l.text) == *normalized)
            {
                // Dedup: reinforce existing learning.
                existing.count = existing.count.max(episode_count);
                existing.last_seen = max_date(existing.last_seen, Some(group.latest_date));
                existing.stale = false; // reinforced
            } else if session_count >= threshold {
                learnings.push(ParsedLearning {
                    text: group.representative_summary.clone(),
                    count: episode_count,
                    last_seen: Some(group.latest_date),
                    stale: false,
                });
                promoted.push(group.representative_summary.clone());
            }
        }

        // --- Staleness --------------------------------------------------------
        let staleness_cutoff =
            now.date() - time::Duration::days(i64::from(self.config.staleness_days));
        let mut marked_stale = Vec::new();

        for learning in &mut learnings {
            if let Some(last) = learning.last_seen {
                if last < staleness_cutoff && !learning.stale {
                    learning.stale = true;
                    marked_stale.push(learning.text.clone());
                }
            }
        }

        // --- Archival ---------------------------------------------------------
        let retention_cutoff =
            now - time::Duration::days(i64::from(self.config.episode_retention_days));
        let archived_episodes: Vec<EpisodeId> = episodes
            .iter()
            .filter(|e| e.timestamp < retention_cutoff)
            .map(|e| e.id)
            .collect();

        // --- Output -----------------------------------------------------------
        let learnings_content = format_learnings(&learnings);
        let summary = format!(
            "promoted {}, marked {} stale, {} episodes for archival",
            promoted.len(),
            marked_stale.len(),
            archived_episodes.len(),
        );

        Ok(ConsolidationResult {
            learnings_content,
            archived_episodes,
            promoted,
            marked_stale,
            summary,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A learning parsed from `LEARNINGS.md`.
#[derive(Debug, Clone)]
struct ParsedLearning {
    text: String,
    count: u32,
    last_seen: Option<time::Date>,
    stale: bool,
}

/// Candidate group: all episodes sharing a normalized summary.
struct CandidateGroup {
    session_ids: HashSet<String>,
    representative_summary: String,
    latest_date: time::Date,
}

// ---------------------------------------------------------------------------
// Parsing / formatting
// ---------------------------------------------------------------------------

/// Parse `LEARNINGS.md` content into structured learnings.
///
/// Lines starting with `- ` are treated as learning entries. An optional
/// `[stale] ` prefix marks staleness. The next line may contain metadata
/// in the form `<!-- sigil:count=N,last=YYYY-MM-DD -->`.
fn parse_learnings(content: &str) -> Vec<ParsedLearning> {
    let mut learnings = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        let Some(after_bullet) = trimmed.strip_prefix("- ") else {
            continue;
        };

        let (text, stale) = if let Some(rest) = after_bullet.strip_prefix("[stale] ") {
            (rest.to_owned(), true)
        } else {
            (after_bullet.to_owned(), false)
        };

        // Peek at the next line for metadata.
        let (count, last_seen) = match lines.peek() {
            Some(next) => {
                if let Some(meta) = parse_metadata(next.trim()) {
                    lines.next(); // consume the metadata line
                    meta
                } else {
                    (1, None)
                }
            }
            None => (1, None),
        };

        learnings.push(ParsedLearning {
            text,
            count,
            last_seen,
            stale,
        });
    }

    learnings
}

/// Parse a metadata comment: `<!-- sigil:count=N,last=YYYY-MM-DD -->`.
fn parse_metadata(line: &str) -> Option<(u32, Option<time::Date>)> {
    let inner = line.strip_prefix("<!-- sigil:")?.strip_suffix(" -->")?;

    let mut count = 1u32;
    let mut last_seen = None;

    for part in inner.split(',') {
        if let Some(val) = part.strip_prefix("count=") {
            count = val.parse().ok()?;
        } else if let Some(val) = part.strip_prefix("last=") {
            last_seen = parse_date(val);
        }
    }

    Some((count, last_seen))
}

/// Format learnings back into `LEARNINGS.md` content.
fn format_learnings(learnings: &[ParsedLearning]) -> String {
    let mut out = String::from("# Learnings\n");

    for learning in learnings {
        out.push('\n');
        if learning.stale {
            let _ = write!(out, "- [stale] {}", learning.text);
        } else {
            let _ = write!(out, "- {}", learning.text);
        }
        out.push('\n');

        if let Some(last) = learning.last_seen {
            let _ = write!(
                out,
                "  <!-- sigil:count={},last={} -->",
                learning.count,
                format_date(last),
            );
            out.push('\n');
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Candidate gathering
// ---------------------------------------------------------------------------

/// Group `CandidateLearning` episodes by normalized summary.
///
/// Uses a `BTreeMap` so iteration order is deterministic (idempotence).
fn gather_candidates(episodes: &[EpisodeEvent]) -> BTreeMap<String, CandidateGroup> {
    let mut groups: BTreeMap<String, CandidateGroup> = BTreeMap::new();

    for event in episodes {
        if event.kind != EpisodeKind::CandidateLearning {
            continue;
        }

        let normalized = normalize(&event.summary);
        let date = event.timestamp.date();
        let session_str = event.session_id.to_string();

        groups
            .entry(normalized)
            .and_modify(|g| {
                g.session_ids.insert(session_str.clone());
                if date > g.latest_date {
                    g.latest_date = date;
                    g.representative_summary.clone_from(&event.summary);
                }
            })
            .or_insert_with(|| {
                let mut ids = HashSet::new();
                ids.insert(session_str);
                CandidateGroup {
                    session_ids: ids,
                    representative_summary: event.summary.clone(),
                    latest_date: date,
                }
            });
    }

    groups
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize a string for comparison: lowercase, strip punctuation,
/// collapse whitespace.
fn normalize(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Return the later of two optional dates.
fn max_date(a: Option<time::Date>, b: Option<time::Date>) -> Option<time::Date> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Format a `time::Date` as `YYYY-MM-DD`.
fn format_date(date: time::Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        date.month() as u8,
        date.day()
    )
}

/// Parse a `YYYY-MM-DD` string into a `time::Date`.
fn parse_date(s: &str) -> Option<time::Date> {
    let mut parts = s.splitn(3, '-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    let month = time::Month::try_from(month).ok()?;
    time::Date::from_calendar_date(year, month, day).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, SessionId};
    use time::OffsetDateTime;

    use super::*;

    // -- Helpers ------------------------------------------------------------

    fn make_time(year: i32, month: u8, day: u8) -> OffsetDateTime {
        let month = time::Month::try_from(month).unwrap();
        time::Date::from_calendar_date(year, month, day)
            .unwrap()
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
    }

    fn candidate_at(
        session_id: SessionId,
        summary: &str,
        timestamp: OffsetDateTime,
    ) -> EpisodeEvent {
        EpisodeEvent {
            id: EpisodeId::new(),
            timestamp,
            session_id,
            kind: EpisodeKind::CandidateLearning,
            summary: summary.into(),
            details: None,
            tags: vec![],
            source: "test".into(),
        }
    }

    fn action_event_at(session_id: SessionId, timestamp: OffsetDateTime) -> EpisodeEvent {
        EpisodeEvent {
            id: EpisodeId::new(),
            timestamp,
            session_id,
            kind: EpisodeKind::ActionCompleted,
            summary: "some action".into(),
            details: None,
            tags: vec![],
            source: "test".into(),
        }
    }

    fn default_consolidator() -> MechanicalConsolidator {
        MechanicalConsolidator::new(MemoryConfig::default())
    }

    // -- Promotion ----------------------------------------------------------

    #[test]
    fn promotion_at_3_distinct_sessions() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let episodes = vec![
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
        ];

        let result = c.consolidate(&episodes, "", now).unwrap();

        assert_eq!(result.promoted.len(), 1);
        assert_eq!(result.promoted[0], "Always check session state");
        assert!(
            result
                .learnings_content
                .contains("Always check session state")
        );
    }

    #[test]
    fn no_promotion_at_2_sessions() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let episodes = vec![
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
        ];

        let result = c.consolidate(&episodes, "", now).unwrap();

        assert!(result.promoted.is_empty());
        assert!(
            !result
                .learnings_content
                .contains("Always check session state")
        );
    }

    #[test]
    fn same_session_counts_once() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        // Three episodes from only two distinct sessions.
        let s1 = SessionId::new();
        let s2 = SessionId::new();
        let episodes = vec![
            candidate_at(s1, "Always check session state", now),
            candidate_at(s1, "Always check session state", now),
            candidate_at(s2, "Always check session state", now),
        ];

        let result = c.consolidate(&episodes, "", now).unwrap();
        assert!(result.promoted.is_empty(), "only 2 distinct sessions");
    }

    #[test]
    fn promotion_ignores_punctuation_differences() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let episodes = vec![
            candidate_at(SessionId::new(), "Always check session state!", now),
            candidate_at(SessionId::new(), "always check session state", now),
            candidate_at(SessionId::new(), "Always check session state.", now),
        ];

        let result = c.consolidate(&episodes, "", now).unwrap();
        assert_eq!(result.promoted.len(), 1);
    }

    // -- Deduplication ------------------------------------------------------

    #[test]
    fn dedup_does_not_create_duplicate_learning() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let existing = "\
# Learnings

- Always check session state
  <!-- sigil:count=3,last=2026-03-01 -->
";

        let episodes = vec![
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
        ];

        let result = c.consolidate(&episodes, existing, now).unwrap();

        assert!(result.promoted.is_empty(), "already exists — dedup");

        // Should appear exactly once in the output.
        let count = result
            .learnings_content
            .matches("Always check session state")
            .count();
        assert_eq!(count, 1, "no duplicate");
    }

    #[test]
    fn dedup_updates_count_and_last_seen() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let existing = "\
# Learnings

- Always check session state
  <!-- sigil:count=3,last=2026-01-01 -->
";

        let episodes = vec![
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
            candidate_at(SessionId::new(), "Always check session state", now),
        ];

        let result = c.consolidate(&episodes, existing, now).unwrap();

        // count should be max(3, 4) = 4
        assert!(result.learnings_content.contains("count=4"));
        // last_seen should be updated to 2026-04-11
        assert!(result.learnings_content.contains("last=2026-04-11"));
    }

    // -- Staleness ----------------------------------------------------------

    #[test]
    fn stale_learning_gets_annotated() {
        let c = default_consolidator(); // staleness_days = 180
        let now = make_time(2026, 4, 11);

        // Learning last seen 2025-06-01 = ~315 days ago (> 180).
        let existing = "\
# Learnings

- Old learning that should be stale
  <!-- sigil:count=3,last=2025-06-01 -->
";

        let result = c.consolidate(&[], existing, now).unwrap();

        assert_eq!(result.marked_stale.len(), 1);
        assert!(
            result
                .learnings_content
                .contains("[stale] Old learning that should be stale")
        );
    }

    #[test]
    fn fresh_learning_is_not_stale() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        // Learning last seen 2026-03-01 = ~41 days ago (< 180).
        let existing = "\
# Learnings

- Fresh learning
  <!-- sigil:count=3,last=2026-03-01 -->
";

        let result = c.consolidate(&[], existing, now).unwrap();

        assert!(result.marked_stale.is_empty());
        assert!(!result.learnings_content.contains("[stale]"));
    }

    #[test]
    fn stale_learning_reinforced_becomes_fresh() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let existing = "\
# Learnings

- [stale] Old learning gets new life
  <!-- sigil:count=3,last=2025-06-01 -->
";

        // Reinforce via candidate episodes.
        let episodes = vec![
            candidate_at(SessionId::new(), "Old learning gets new life", now),
            candidate_at(SessionId::new(), "Old learning gets new life", now),
            candidate_at(SessionId::new(), "Old learning gets new life", now),
        ];

        let result = c.consolidate(&episodes, existing, now).unwrap();

        // Should no longer be stale.
        assert!(!result.learnings_content.contains("[stale]"));
        assert!(
            result
                .learnings_content
                .contains("Old learning gets new life")
        );
    }

    // -- Idempotence --------------------------------------------------------

    #[test]
    fn consolidation_is_idempotent() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let episodes = vec![
            candidate_at(SessionId::new(), "Learning alpha", now),
            candidate_at(SessionId::new(), "Learning alpha", now),
            candidate_at(SessionId::new(), "Learning alpha", now),
            candidate_at(SessionId::new(), "Learning beta", now),
            candidate_at(SessionId::new(), "Learning beta", now),
        ];

        let r1 = c.consolidate(&episodes, "", now).unwrap();
        let r2 = c
            .consolidate(&episodes, &r1.learnings_content, now)
            .unwrap();

        assert_eq!(r1.learnings_content, r2.learnings_content);
        assert!(r2.promoted.is_empty(), "second pass should not re-promote");
    }

    // -- Archival -----------------------------------------------------------

    #[test]
    fn old_episodes_flagged_for_archival() {
        let c = default_consolidator(); // retention = 90 days
        let now = make_time(2026, 4, 11);

        let old = make_time(2025, 12, 1); // ~131 days ago
        let recent = make_time(2026, 3, 15); // ~27 days ago

        let episodes = vec![
            action_event_at(SessionId::new(), old),
            action_event_at(SessionId::new(), recent),
        ];

        let result = c.consolidate(&episodes, "", now).unwrap();

        assert_eq!(result.archived_episodes.len(), 1);
        assert_eq!(result.archived_episodes[0], episodes[0].id);
    }

    #[test]
    fn recent_episodes_not_flagged() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let recent = make_time(2026, 3, 15);
        let episodes = vec![action_event_at(SessionId::new(), recent)];

        let result = c.consolidate(&episodes, "", now).unwrap();
        assert!(result.archived_episodes.is_empty());
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn empty_episodes_and_learnings() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let result = c.consolidate(&[], "", now).unwrap();

        assert!(result.promoted.is_empty());
        assert!(result.marked_stale.is_empty());
        assert!(result.archived_episodes.is_empty());
        assert!(result.learnings_content.starts_with("# Learnings\n"));
    }

    #[test]
    fn learnings_without_metadata_preserved() {
        let c = default_consolidator();
        let now = make_time(2026, 4, 11);

        let existing = "\
# Learnings

- Manually added learning without metadata
";

        let result = c.consolidate(&[], existing, now).unwrap();

        assert!(
            result
                .learnings_content
                .contains("Manually added learning without metadata")
        );
        assert!(result.marked_stale.is_empty());
    }

    // -- Helpers (normalize) ------------------------------------------------

    #[test]
    fn normalize_strips_punctuation_and_lowercases() {
        assert_eq!(
            normalize("Hello, World! This is a test."),
            "hello world this is a test"
        );
    }

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(
            normalize("  multiple   spaces   here  "),
            "multiple spaces here"
        );
    }

    #[test]
    fn parse_and_format_roundtrip() {
        let input = "\
# Learnings

- First learning
  <!-- sigil:count=5,last=2026-04-01 -->

- [stale] Second learning
  <!-- sigil:count=3,last=2025-06-01 -->
";

        let parsed = parse_learnings(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].text, "First learning");
        assert_eq!(parsed[0].count, 5);
        assert!(!parsed[0].stale);
        assert_eq!(parsed[1].text, "Second learning");
        assert_eq!(parsed[1].count, 3);
        assert!(parsed[1].stale);

        // Re-format and re-parse should be stable.
        let formatted = format_learnings(&parsed);
        let reparsed = parse_learnings(&formatted);
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[0].text, parsed[0].text);
        assert_eq!(reparsed[0].count, parsed[0].count);
        assert_eq!(reparsed[1].text, parsed[1].text);
        assert_eq!(reparsed[1].stale, parsed[1].stale);
    }
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    #![allow(clippy::unwrap_used)]

    use proptest::prelude::*;
    use sigil_core::{EpisodeEvent, EpisodeId, EpisodeKind, MemoryConfig, SessionId};
    use time::OffsetDateTime;

    use super::*;

    proptest! {
        #[test]
        fn consolidation_idempotent(
            num_candidates in 1usize..=5,
            sessions_per_candidate in 1usize..=5,
        ) {
            let config = MemoryConfig::default();
            let c = MechanicalConsolidator::new(config);
            let now = OffsetDateTime::now_utc();

            let mut episodes = Vec::new();
            for i in 0..num_candidates {
                let summary = format!("candidate learning number {i}");
                for _ in 0..sessions_per_candidate {
                    episodes.push(EpisodeEvent {
                        id: EpisodeId::new(),
                        timestamp: now,
                        session_id: SessionId::new(),
                        kind: EpisodeKind::CandidateLearning,
                        summary: summary.clone(),
                        details: None,
                        tags: vec![],
                        source: "test".into(),
                    });
                }
            }

            let r1 = c.consolidate(&episodes, "", now).unwrap();
            let r2 = c.consolidate(&episodes, &r1.learnings_content, now).unwrap();

            prop_assert_eq!(&r1.learnings_content, &r2.learnings_content);
            prop_assert!(r2.promoted.is_empty());
        }

        #[test]
        fn threshold_respected(
            threshold in 1u32..=6,
            session_count in 1usize..=8,
        ) {
            let config = MemoryConfig {
                promotion_threshold: threshold,
                ..MemoryConfig::default()
            };
            let c = MechanicalConsolidator::new(config);
            let now = OffsetDateTime::now_utc();

            let mut episodes = Vec::new();
            for _ in 0..session_count {
                episodes.push(EpisodeEvent {
                    id: EpisodeId::new(),
                    timestamp: now,
                    session_id: SessionId::new(),
                    kind: EpisodeKind::CandidateLearning,
                    summary: "test learning".into(),
                    details: None,
                    tags: vec![],
                    source: "test".into(),
                });
            }

            let result = c.consolidate(&episodes, "", now).unwrap();

            if session_count >= threshold as usize {
                prop_assert_eq!(result.promoted.len(), 1);
            } else {
                prop_assert!(result.promoted.is_empty());
            }
        }
    }
}
