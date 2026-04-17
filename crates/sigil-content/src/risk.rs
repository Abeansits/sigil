//! Stage 5 — weighted risk score.
//!
//! Combines pattern findings, normalize-layer signals, and the per-byte
//! repetition ratio into a single `u8` score on `[0, 100]`. The score
//! drives policy: `sigil-policy` maps `risk_score >= 50` from
//! `AgentRuntime`-initiated fetches to `NeedsApproval`. The CI false-
//! positive gate uses the same threshold.
//!
//! Weights are deterministic and counted by **distinct rule ID**, not by
//! raw match count — a single noisy regex cannot flood the score by
//! firing on every match. The signal bumps add small, capped contributions
//! for orthogonal evidence (control characters stripped, repetition ratio
//! above the floor).
//!
//! When the formula or weights change, bump [`crate::SCORING_VERSION`] so
//! older reports remain identifiable.

use std::collections::HashSet;

use sigil_core::{Finding, NormalizeResult, Severity};

/// Threshold above which a [`SanitizeReport`] is considered a "hit" by the
/// FP gate. Kept in lockstep with the `risk_score >= 50` boundary the
/// policy evaluator uses for `AgentRuntime`-initiated fetches.
///
/// [`SanitizeReport`]: sigil_core::SanitizeReport
pub const RISK_GATE_THRESHOLD: u8 = 50;

/// Per-rule weight contributions. Tuned so that one Medium hit alone
/// (20) cannot exceed the gate; two distinct Medium hits plus a normalize
/// signal (40 + 10 = 50) just reaches it; one High hit (50) reaches it
/// directly.
const WEIGHT_HIGH: u32 = 50;
const WEIGHT_MEDIUM: u32 = 20;
const WEIGHT_LOW: u32 = 6;
const WEIGHT_INFO: u32 = 0;

/// Bonus applied when [`NormalizeResult::stripped_count`] is non-zero.
/// Zero-width or directional-override stripping is a strong tell on its
/// own and would otherwise leave no fingerprint in the score.
const NORMALIZE_STRIP_BONUS: u32 = 10;

/// Threshold above which a high per-byte repetition ratio adds to the
/// score. Calibrated above the ~0.10 ceiling typical of English prose.
///
/// **Intentionally lower than `SanitizerConfig::max_repetition_ratio`
/// (0.9 default).** The bonus fires *before* `REP-002` does, so the risk
/// score still picks up a signal in the gap where repetition is "high
/// enough to be suspicious" but not "high enough to flag a finding". The
/// asymmetry is deliberate, not a configuration oversight — keep the
/// bonus threshold strictly below the rule threshold so the score
/// degrades gracefully across the boundary.
pub const REPETITION_BONUS_THRESHOLD: f32 = 0.85;
const REPETITION_BONUS: u32 = 15;

/// Hard ceiling. The struct field is `u8`, so 100 is the natural cap.
const SCORE_CEILING: u32 = 100;

/// Compute the weighted risk score.
///
/// Deterministic: identical inputs produce identical output. Inputs are:
///
/// - `findings` — the [`Finding`] vec produced by [`crate::patterns::scan`].
///   Counted by distinct `rule_id`; weights track [`Severity`].
/// - `normalize` — the [`NormalizeResult`] from
///   `sigil_policy::normalize::normalize_text`. Only `stripped_count` is
///   consumed today; mixed-script flagging already has a dedicated
///   `MIX-001` finding so we do not double-count it here.
/// - `repetition_ratio` — the per-byte repetition ratio (0.0–1.0) from
///   the plain-text path. Above [`REPETITION_BONUS_THRESHOLD`] it adds
///   [`REPETITION_BONUS`].
///
/// The output is clamped to `u8::MAX` and capped at [`SCORE_CEILING`].
#[must_use]
pub fn compute(findings: &[Finding], normalize: &NormalizeResult, repetition_ratio: f32) -> u8 {
    let mut score: u32 = 0;
    let mut seen: HashSet<&str> = HashSet::with_capacity(findings.len());
    let mut highest_per_id: std::collections::HashMap<&str, Severity> =
        std::collections::HashMap::with_capacity(findings.len());

    // Collect the highest severity observed per distinct rule id. A rule
    // catalog change that re-emits the same id at a stronger severity
    // (e.g. promoting INJ-006 from Medium to High in a future revision)
    // takes effect on the next scoring pass without a `Vec` rebuild.
    for f in findings {
        let id = f.rule_id.as_str();
        seen.insert(id);
        highest_per_id
            .entry(id)
            .and_modify(|cur| {
                if f.severity > *cur {
                    *cur = f.severity;
                }
            })
            .or_insert(f.severity);
    }

    for severity in highest_per_id.values() {
        score = score.saturating_add(weight_for(*severity));
    }

    if normalize.stripped_count > 0 {
        score = score.saturating_add(NORMALIZE_STRIP_BONUS);
    }

    if repetition_ratio.is_finite() && repetition_ratio >= REPETITION_BONUS_THRESHOLD {
        score = score.saturating_add(REPETITION_BONUS);
    }

    let capped = score.min(SCORE_CEILING);
    // SCORE_CEILING is 100 which fits in u8; the saturating_add above
    // keeps `score` well within u32 range, so the cast is exact.
    u8::try_from(capped).unwrap_or(u8::MAX)
}

fn weight_for(sev: Severity) -> u32 {
    match sev {
        Severity::High => WEIGHT_HIGH,
        Severity::Medium => WEIGHT_MEDIUM,
        Severity::Low => WEIGHT_LOW,
        Severity::Info => WEIGHT_INFO,
        // `Severity` is `#[non_exhaustive]`. A future variant gets the
        // safest default — zero weight — until the catalog is updated and
        // `SCORING_VERSION` is bumped.
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::cast_possible_truncation,
        reason = "test code: u32 weight constants are known-small and fit in u8"
    )]

    use sigil_core::{ByteRange, Finding, NormalizeResult, Severity};

    use super::*;

    /// Test helper that builds a `NormalizeResult` with a non-default
    /// `stripped_count`, side-stepping the `field_reassign_with_default`
    /// lint without exposing builder methods on the public type.
    fn normalize_with_strip(stripped: usize) -> NormalizeResult {
        NormalizeResult {
            stripped_count: stripped,
            ..NormalizeResult::default()
        }
    }

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: id.to_owned(),
            severity,
            span: Some(ByteRange { start: 0, end: 1 }),
            sample: None,
        }
    }

    fn empty_normalize() -> NormalizeResult {
        NormalizeResult::default()
    }

    #[test]
    fn empty_inputs_score_zero() {
        let s = compute(&[], &empty_normalize(), 0.0);
        assert_eq!(s, 0);
    }

    #[test]
    fn one_medium_does_not_cross_threshold() {
        let f = vec![finding("INJ-001", Severity::Medium)];
        let s = compute(&f, &empty_normalize(), 0.0);
        assert!(s < RISK_GATE_THRESHOLD);
    }

    #[test]
    fn three_distinct_mediums_cross_threshold() {
        let f = vec![
            finding("INJ-001", Severity::Medium),
            finding("INJ-003", Severity::Medium),
            finding("INJ-005", Severity::Medium),
        ];
        let s = compute(&f, &empty_normalize(), 0.0);
        assert!(s >= RISK_GATE_THRESHOLD, "expected >= 50, got {s}");
    }

    #[test]
    fn duplicate_rule_id_counts_once() {
        let f = vec![
            finding("INJ-001", Severity::Medium),
            finding("INJ-001", Severity::Medium),
            finding("INJ-001", Severity::Medium),
        ];
        let s = compute(&f, &empty_normalize(), 0.0);
        assert_eq!(s, WEIGHT_MEDIUM as u8);
    }

    #[test]
    fn one_high_alone_crosses_threshold() {
        let f = vec![finding("FMT-001", Severity::High)];
        let s = compute(&f, &empty_normalize(), 0.0);
        assert!(s >= RISK_GATE_THRESHOLD);
    }

    #[test]
    fn normalize_strip_adds_bonus() {
        let n = normalize_with_strip(3);
        let s_with = compute(&[], &n, 0.0);
        let s_without = compute(&[], &empty_normalize(), 0.0);
        assert_eq!(s_with - s_without, NORMALIZE_STRIP_BONUS as u8);
    }

    #[test]
    fn repetition_above_threshold_adds_bonus() {
        let s = compute(&[], &empty_normalize(), 0.95);
        assert_eq!(s, REPETITION_BONUS as u8);
    }

    #[test]
    fn repetition_below_threshold_does_not_bonus() {
        let s = compute(&[], &empty_normalize(), 0.5);
        assert_eq!(s, 0);
    }

    #[test]
    fn nan_repetition_does_not_bonus() {
        let s = compute(&[], &empty_normalize(), f32::NAN);
        assert_eq!(s, 0);
    }

    #[test]
    fn score_caps_at_one_hundred() {
        let f: Vec<Finding> = (0..10)
            .map(|i| finding(&format!("FMT-{i:03}"), Severity::High))
            .collect();
        let n = normalize_with_strip(5);
        let s = compute(&f, &n, 0.99);
        assert_eq!(s, SCORE_CEILING as u8);
    }

    #[test]
    fn highest_severity_per_id_wins() {
        // Same id at Low + Medium: scored as Medium, not Low+Medium.
        let f = vec![
            finding("INJ-001", Severity::Low),
            finding("INJ-001", Severity::Medium),
        ];
        let s = compute(&f, &empty_normalize(), 0.0);
        assert_eq!(s, WEIGHT_MEDIUM as u8);
    }

    #[test]
    fn deterministic_across_repeated_calls() {
        let f = vec![
            finding("INJ-001", Severity::Medium),
            finding("MIX-001", Severity::Medium),
        ];
        let n = normalize_with_strip(2);
        let a = compute(&f, &n, 0.9);
        let b = compute(&f, &n, 0.9);
        assert_eq!(a, b);
    }
}
