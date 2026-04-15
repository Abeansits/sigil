//! Configuration for the sanitization pipeline.

/// Current rule-set catalog version. Bumped whenever the set of rule IDs
/// emitted by the sanitizer changes. PR2 ships with zero rules, so the
/// version starts at 1; PR3 adds the injection-pattern rules.
pub const RULE_SET_VERSION: u32 = 1;

/// Current risk-score weighting version. Tracks the scoring formula so a
/// report from an older scoring pass is recognizably different. Bumped
/// independently of [`RULE_SET_VERSION`] so rule additions and scoring
/// recalibrations do not force one another.
pub const SCORING_VERSION: u32 = 1;

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
