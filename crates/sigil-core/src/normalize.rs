//! Text-normalization result type shared across crates.
//!
//! The `normalize_text` implementation (and `strip_ansi`) lives in
//! `sigil-policy::normalize`. The *result* type lives here so that
//! `SanitizeReport` (in `crate::content`) can embed it without creating
//! a `sigil-core` → `sigil-policy` dependency cycle.

use serde::{Deserialize, Serialize};

/// The result of normalizing a text input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizeResult {
    /// The cleaned text with invisible characters removed.
    pub cleaned: String,
    /// How many characters were stripped.
    pub stripped_count: usize,
    /// What categories of characters were stripped or flagged.
    pub categories: Vec<String>,
}
