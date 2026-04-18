//! Policy-layer configuration for the content-sanitization pipeline.
//!
//! PR6 of the content-sanitization series ships a presence-only check
//! (the [`Evaluator::evaluate_result`](crate::Evaluator::evaluate_result)
//! gate): an `Action` that declares
//! [`sigil_core::content::SanitizationRequirement::Required`] must have
//! a matching [`sigil_core::content::SanitizeReport`] on its
//! [`sigil_core::action::ActionResult`] — nothing more. PR7 grows the
//! check into risk-score / rule-id / size-/encoding-rejection
//! thresholds (per `docs/design/content-sanitization.md` §Stage 7),
//! and those thresholds live here.
//!
//! [`SanitizationConfig`] is intentionally empty today. It is shipped
//! as a `#[non_exhaustive]` struct so PR7 can add threshold fields
//! additively — callers that `SanitizationConfig::default()` today
//! keep working, callers that construct it with literal syntax are
//! prevented from accidentally depending on a field-free shape.

use serde::{Deserialize, Serialize};

/// Policy-layer thresholds for the content sanitization gate.
///
/// Placeholder in PR6 — PR7 adds fields such as:
///
/// - `risk_score_deny_threshold: u8`
/// - `risk_score_approval_threshold: u8`
/// - `deny_on_size_rejected: bool`
/// - `deny_on_encoding_rejected: bool`
/// - `deny_rule_ids: Vec<String>`
///
/// Keep this struct `#[non_exhaustive]` so the PR7 additions do not
/// break existing callers. `Default::default()` is the "presence-only
/// check, nothing else" configuration and matches the PR6 semantics
/// described in the module-level docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SanitizationConfig {}

impl SanitizationConfig {
    /// The PR6 default: presence-and-content-type checks only, no
    /// threshold gating. Equivalent to `SanitizationConfig::default()`
    /// and provided as a named constructor so the call site reads as
    /// an intentional "no thresholds yet" choice.
    #[must_use]
    pub fn presence_only() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn default_matches_presence_only() {
        assert_eq!(
            SanitizationConfig::default(),
            SanitizationConfig::presence_only()
        );
    }

    #[test]
    fn config_round_trips_through_json() {
        // #[serde(default)] on future fields must not break old-record
        // deserialization. Lock the empty-struct round-trip so a later
        // field addition that forgets the default is caught.
        let config = SanitizationConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let back: SanitizationConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, back);
    }
}
