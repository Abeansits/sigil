//! Configuration for the sanitization pipeline.

/// Current rule-set catalog version. Bumped whenever the set of rule IDs
/// emitted by the sanitizer changes.
///
/// - `1` (PR2) — placeholder, zero rules.
/// - `2` (PR3) — initial injection-pattern catalog: `INJ-001..007`,
///   `ENC-001..003`, `REP-001..002`, `MIX-001`, `FMT-001`, `WRP-001`.
/// - `3` (PR3.6) — `FMT-001` demoted `High → Info` and reframed as
///   audit-only metadata; the declared-vs-observed HTML mismatch that
///   originally drove the rule is now handled by the pre-dispatch
///   reroute in [`crate::dispatch_sanitize`]. Rule set otherwise
///   unchanged.
pub const RULE_SET_VERSION: u32 = 3;

/// Current risk-score weighting version. Tracks the scoring formula so a
/// report from an older scoring pass is recognizably different. Bumped
/// independently of [`RULE_SET_VERSION`] so rule additions and scoring
/// recalibrations do not force one another.
///
/// - `1` (PR2) — placeholder, no scoring (always 0).
/// - `2` (PR3) — distinct-rule weighted scorer with normalize-strip and
///   repetition-ratio bonuses; see [`crate::risk`].
pub const SCORING_VERSION: u32 = 2;

/// Default maximum input size (2 MiB).
///
/// Applied before any UTF-8 decode so a multi-MiB payload cannot force a
/// full linear scan just to be rejected.
pub const DEFAULT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Default repetition-ratio ceiling (0.9).
///
/// **PR2 status — unused.** PR2 *computes* [`SanitizeReport::repetition_ratio`]
/// on every pass, but does not yet gate on it or emit a `Finding` when the
/// threshold is crossed. Rule emission lands with the pattern scanner in
/// PR3; until then policy code can still inspect the raw ratio from the
/// report. The ceiling value is kept in config now so PR3 is a zero-API
/// change for downstream consumers.
///
/// [`SanitizeReport::repetition_ratio`]: sigil_core::SanitizeReport::repetition_ratio
pub const DEFAULT_MAX_REPETITION_RATIO: f32 = 0.9;

/// Tunable parameters for a single sanitization pass.
#[derive(Clone, Debug)]
pub struct SanitizerConfig {
    /// Hard byte cap on the raw input. Enforced before decode.
    pub max_bytes: usize,
    /// Advisory ceiling on the per-byte repetition ratio. Flagged (not
    /// enforced) at this layer. **Unused by the PR2 pipeline** — the raw
    /// ratio lands in the report, but no `Finding` is emitted against this
    /// threshold until PR3 ships rule emission. See
    /// [`DEFAULT_MAX_REPETITION_RATIO`] for the full rationale.
    pub max_repetition_ratio: f32,
    /// Rule-set catalog version that produced the report.
    pub rule_set_version: u32,
    /// Risk-score weighting version that produced the report.
    pub scoring_version: u32,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_repetition_ratio: DEFAULT_MAX_REPETITION_RATIO,
            rule_set_version: RULE_SET_VERSION,
            scoring_version: SCORING_VERSION,
        }
    }
}
