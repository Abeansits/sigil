//! sigil-content — external-content sanitization pipeline.
//!
//! This crate implements the sanitization pipeline described in
//! `docs/design/content-sanitization.md`. PR2 ships the plain-text path;
//! HTML, Markdown, and JSON live behind Cargo features and are filled in
//! by later PRs. The crate is a **pure transform**: it produces a
//! [`sigil_core::SanitizedContent`] (cleaned text + [`sigil_core::SanitizeReport`])
//! and nothing else. Policy decisions (`Allow` / `Deny` / `NeedsApproval`)
//! live in `sigil-policy` and consume the report.
//!
//! # Type-level discipline
//!
//! Raw fetched bytes enter the sanitizer as a [`RawFetchedContent`] value.
//! The struct has a private body and is consumed by value by every
//! `sanitize_*` method, so once wrapped the bytes cannot be read back out
//! except by the sanitizer. This turns "a `RawFetchedContent` reaches the
//! model" from a convention into a compile error. Callers can still retain
//! the original source bytes *before* wrapping — the type guards the
//! sanitizer boundary, it does not pretend to be a runtime taint tracker.
//!
//! # Pipeline (plain-text path, PR2)
//!
//! 1. Size guard (before any decode).
//! 2. Declare & decode (caller supplies `ContentType`; UTF-8 is hard-required).
//! 3. Format-specific strip — no-op for `PlainText`, [`strip_ansi`] for `Log`.
//! 4. Text-layer normalize — delegated to
//!    [`sigil_policy::normalize::normalize_text`].
//! 5. Injection-pattern scan — **stubbed**, filled by PR3.
//! 6. Provenance wrap — **stubbed**, filled by PR3.
//! 7. Report assembly — full [`SanitizeReport`] with keyed HMAC
//!    fingerprints and a fresh per-call nonce.
//!
//! [`strip_ansi`]: sigil_policy::normalize::strip_ansi
//! [`SanitizeReport`]: sigil_core::SanitizeReport

use std::fmt;

use sigil_core::{ContentSource, ContentType, SanitizedContent};

pub mod config;
pub mod error;
pub mod plain;

pub use config::{
    DEFAULT_MAX_BYTES, DEFAULT_MAX_REPETITION_RATIO, RULE_SET_VERSION, SCORING_VERSION,
    SanitizerConfig,
};
pub use error::ContentError;

// Re-export core types consumers of this crate need so they do not have
// to pull `sigil-core` into their Cargo.toml for basic usage.
pub use sigil_core::{SanitizeReport, SanitizedContent as CoreSanitizedContent};

/// Raw bytes fetched from an external source, on their way to the
/// sanitizer.
///
/// The body is private and every `sanitize_*` method consumes the value
/// by move. Once a caller has wrapped bytes in a `RawFetchedContent` they
/// can (a) observe its length but not its contents, (b) hand it to a
/// sanitizer (which consumes it), or (c) drop it. There is no public
/// accessor for the underlying buffer, so a `RawFetchedContent` cannot
/// flow into the model prompt; only its [`SanitizedContent`] result can.
///
/// The discipline this type enforces is "wrapped raw content stays
/// sanitizer-bound", not "raw bytes never leave the caller" — a caller
/// that held onto the source `Vec<u8>` or `String` before wrapping has
/// already chosen to retain it. Callers that want the stronger property
/// should construct the wrapper at the fetch boundary and let the
/// original buffer drop.
///
/// `Clone` is deliberately not implemented: duplicating a wrapped buffer
/// defeats the "consumed by value" discipline.
pub struct RawFetchedContent {
    bytes: Vec<u8>,
}

impl RawFetchedContent {
    /// Wrap a byte buffer. The buffer moves into the struct; the caller
    /// has no way to observe it further except by handing this value to a
    /// sanitizer.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Wrap an owned string. Equivalent to `from_bytes(s.into_bytes())`.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self::from_bytes(s.into_bytes())
    }

    /// Byte length of the buffered content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Crate-private move-out of the buffer for the pipeline.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for RawFetchedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the body in debug output. Length alone is enough
        // context for logs without risking a raw-content leak into tracing.
        f.debug_struct("RawFetchedContent")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Orchestrator for the sanitization pipeline.
///
/// A `Sanitizer` holds the HMAC fingerprint key and a default
/// [`SanitizerConfig`]. Construct one per deployment and reuse it across
/// calls — the key must live with the audit key (see
/// `docs/SECURITY-PLAN.md` Priority 1). PR7 wires the key to the Keychain;
/// PR2 accepts it as a byte slice.
pub struct Sanitizer {
    key: Vec<u8>,
    config: SanitizerConfig,
}

impl Sanitizer {
    /// Build a sanitizer with [`SanitizerConfig::default`].
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::FingerprintKeyUnavailable`] if `key` is
    /// empty. The sanitizer never falls back to unkeyed SHA.
    pub fn new(key: &[u8]) -> Result<Self, ContentError> {
        Self::with_config(key, SanitizerConfig::default())
    }

    /// Build a sanitizer with a custom configuration.
    ///
    /// # Errors
    ///
    /// Same as [`Sanitizer::new`].
    pub fn with_config(key: &[u8], config: SanitizerConfig) -> Result<Self, ContentError> {
        if key.is_empty() {
            return Err(ContentError::FingerprintKeyUnavailable);
        }
        Ok(Self {
            key: key.to_vec(),
            config,
        })
    }

    /// Borrow the sanitizer's config, e.g. for test assertions.
    #[must_use]
    pub fn config(&self) -> &SanitizerConfig {
        &self.config
    }

    /// Run the plain-text path.
    ///
    /// Accepts `ContentType::PlainText` or `ContentType::Log` only. Other
    /// variants are PR4/PR5 territory and are rejected with
    /// [`ContentError::UnsupportedContentType`].
    ///
    /// # Errors
    ///
    /// See [`plain::sanitize`] for the full error matrix.
    pub fn sanitize_plain(
        &self,
        raw: RawFetchedContent,
        source: ContentSource,
        content_type: ContentType,
    ) -> Result<SanitizedContent, ContentError> {
        plain::sanitize(raw, source, content_type, &self.config, &self.key)
    }
}

impl fmt::Debug for Sanitizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Key material must never be rendered; expose only its presence
        // and the config.
        f.debug_struct("Sanitizer")
            .field("key", &"<redacted>")
            .field("config", &self.config)
            .finish()
    }
}

/// Free-function entry point for the plain-text path.
///
/// Equivalent to constructing a short-lived [`Sanitizer`] and calling
/// [`Sanitizer::sanitize_plain`]. Kept separate for callers that do not
/// want to retain a sanitizer instance (e.g. CLI one-shots in PR7).
///
/// # Errors
///
/// Same as [`Sanitizer::sanitize_plain`], plus
/// [`ContentError::FingerprintKeyUnavailable`] if `key` is empty.
pub fn sanitize_plain(
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
    if key.is_empty() {
        return Err(ContentError::FingerprintKeyUnavailable);
    }
    plain::sanitize(raw, source, content_type, config, key)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code asserts on values that are provably safe to unwrap"
    )]

    use assert_matches::assert_matches;
    use sigil_core::{ContentSource, ContentType};

    use super::*;

    const TEST_KEY: &[u8] = b"sigil-content-test-key-do-not-ship";

    fn file_source() -> ContentSource {
        ContentSource::File {
            path: "/tmp/fixture".into(),
        }
    }

    fn sanitizer() -> Sanitizer {
        Sanitizer::new(TEST_KEY).expect("test key must be accepted")
    }

    #[test]
    fn new_rejects_empty_key() {
        let err = Sanitizer::new(b"").expect_err("empty key must be rejected");
        assert_matches!(err, ContentError::FingerprintKeyUnavailable);
    }

    #[test]
    fn free_fn_rejects_empty_key() {
        let config = SanitizerConfig::default();
        let err = sanitize_plain(
            RawFetchedContent::from_string("hello".into()),
            file_source(),
            ContentType::PlainText,
            &config,
            b"",
        )
        .expect_err("empty key must be rejected");
        assert_matches!(err, ContentError::FingerprintKeyUnavailable);
    }

    #[test]
    fn plain_text_happy_path() {
        let s = sanitizer();
        let raw = RawFetchedContent::from_string("Hello, world!".into());
        let out = s
            .sanitize_plain(raw, file_source(), ContentType::PlainText)
            .expect("plain text must succeed");

        assert_eq!(out.text, "Hello, world!");
        assert_eq!(out.report.bytes_in, 13);
        assert_eq!(out.report.bytes_out, 13);
        assert!(out.report.findings.is_empty());
        assert!(out.report.stripped_elements.is_empty());
        assert_eq!(out.report.risk_score, 0);
        assert!(!out.report.size_rejected);
        assert!(!out.report.encoding_rejected);
        assert_eq!(out.report.nonce.len(), 16);
        assert!(out.report.nonce.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(out.report.content_type, ContentType::PlainText);
        assert_eq!(out.report.rule_set_version, RULE_SET_VERSION);
        assert_eq!(out.report.scoring_version, SCORING_VERSION);
        assert_eq!(out.report.text_normalize.stripped_count, 0);
    }

    #[test]
    fn oversize_input_is_rejected() {
        let config = SanitizerConfig {
            max_bytes: 8,
            ..SanitizerConfig::default()
        };
        let s = Sanitizer::with_config(TEST_KEY, config).unwrap();
        let raw = RawFetchedContent::from_string("this string is longer than eight bytes".into());
        let err = s
            .sanitize_plain(raw, file_source(), ContentType::PlainText)
            .expect_err("oversize must be rejected");
        assert_matches!(err, ContentError::SizeExceeded { bytes, max } if bytes > max && max == 8);
    }

    #[test]
    fn non_utf8_input_is_rejected() {
        let s = sanitizer();
        // Lone 0xFF is never a valid UTF-8 start byte.
        let raw = RawFetchedContent::from_bytes(vec![b'o', b'k', 0xFF, 0xFE]);
        let err = s
            .sanitize_plain(raw, file_source(), ContentType::PlainText)
            .expect_err("non-UTF-8 must be rejected");
        assert_matches!(err, ContentError::InvalidEncoding);
    }

    #[test]
    fn unsupported_content_type_is_rejected() {
        let s = sanitizer();
        let raw = RawFetchedContent::from_string("<p>hi</p>".into());
        let err = s
            .sanitize_plain(raw, file_source(), ContentType::Html)
            .expect_err("html is PR4 territory");
        assert_matches!(err, ContentError::UnsupportedContentType(ContentType::Html));
    }

    #[test]
    fn zero_width_and_directional_overrides_are_stripped() {
        // "hel<ZWSP>lo" + RTL override: both must vanish after normalize.
        let input = "hel\u{200B}lo\u{202E}world";
        let s = sanitizer();
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string(input.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();

        assert_eq!(out.text, "helloworld");
        assert_eq!(out.report.text_normalize.stripped_count, 2);
        assert!(
            out.report
                .text_normalize
                .categories
                .contains(&"zero-width".into())
        );
        assert!(
            out.report
                .text_normalize
                .categories
                .contains(&"directional-override".into())
        );
        assert_eq!(out.report.bytes_in, input.len());
        assert_eq!(out.report.bytes_out, "helloworld".len());
    }

    #[test]
    fn log_content_type_strips_ansi() {
        let input = "\x1b[31mred\x1b[0m text";
        let s = sanitizer();
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string(input.into()),
                file_source(),
                ContentType::Log,
            )
            .unwrap();
        assert_eq!(out.text, "red text");
        assert_eq!(out.report.content_type, ContentType::Log);
    }

    #[test]
    fn idempotent_on_already_clean_input() {
        let s = sanitizer();
        let raw = "Hello, normalize me!\u{200B}";
        let first = s
            .sanitize_plain(
                RawFetchedContent::from_string(raw.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let second = s
            .sanitize_plain(
                RawFetchedContent::from_string(first.text.clone()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();

        assert_eq!(first.text, second.text);
        assert_eq!(
            first.report.sanitized_fingerprint, second.report.raw_fingerprint,
            "second pass must see the same bytes as the first pass emitted",
        );
        assert_eq!(
            second.report.sanitized_fingerprint, second.report.raw_fingerprint,
            "a second pass over clean text must be a fixed point",
        );
        assert_eq!(second.report.text_normalize.stripped_count, 0);
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_input_and_key() {
        let s1 = Sanitizer::new(TEST_KEY).unwrap();
        let s2 = Sanitizer::new(TEST_KEY).unwrap();
        let payload = "determinism check";
        let a = s1
            .sanitize_plain(
                RawFetchedContent::from_string(payload.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let b = s2
            .sanitize_plain(
                RawFetchedContent::from_string(payload.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        assert_eq!(a.report.raw_fingerprint, b.report.raw_fingerprint);
        assert_eq!(
            a.report.sanitized_fingerprint,
            b.report.sanitized_fingerprint
        );
    }

    #[test]
    fn fingerprint_differs_with_different_keys() {
        let a = Sanitizer::new(b"key-one").unwrap();
        let b = Sanitizer::new(b"key-two").unwrap();
        let payload = "same payload";
        let ra = a
            .sanitize_plain(
                RawFetchedContent::from_string(payload.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let rb = b
            .sanitize_plain(
                RawFetchedContent::from_string(payload.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        assert_ne!(ra.report.raw_fingerprint, rb.report.raw_fingerprint);
    }

    #[test]
    fn nonce_differs_across_calls() {
        let s = sanitizer();
        let a = s
            .sanitize_plain(
                RawFetchedContent::from_string("x".into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let b = s
            .sanitize_plain(
                RawFetchedContent::from_string("x".into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        assert_ne!(
            a.report.nonce, b.report.nonce,
            "nonces are 64-bit random; collision probability is negligible",
        );
    }

    #[test]
    fn report_serializes_round_trip() {
        let s = sanitizer();
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string("round trip".into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let json = serde_json::to_string(&out).unwrap();
        let back: SanitizedContent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.text, out.text);
        assert_eq!(back.report.nonce, out.report.nonce);
        assert_eq!(back.report.raw_fingerprint, out.report.raw_fingerprint);
    }

    #[test]
    fn raw_fetched_content_debug_hides_body() {
        let raw = RawFetchedContent::from_string("SECRET".into());
        let rendered = format!("{raw:?}");
        assert!(!rendered.contains("SECRET"));
        assert!(rendered.contains("len"));
    }

    #[test]
    fn sanitizer_debug_hides_key() {
        let s = sanitizer();
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("sigil-content-test-key"));
        assert!(rendered.contains("redacted"));
    }
}
