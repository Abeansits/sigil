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
pub mod detect;
pub mod error;
pub mod fetcher;
#[cfg(feature = "html")]
pub mod html;
#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "markdown")]
pub mod markdown;
pub mod patterns;
pub mod plain;
pub mod risk;
pub mod wrap;

pub use config::{
    DEFAULT_MAX_BYTES, DEFAULT_MAX_REPETITION_RATIO, RULE_SET_VERSION, SCORING_VERSION,
    SanitizerConfig,
};
pub use error::ContentError;
pub use fetcher::{DisabledFetcher, ExternalContentFetcher, FetchError, FetchFuture};

/// Dispatch raw bytes to the sanitizer entry point matching the
/// caller's declared [`ContentType`]. Single source of truth for the
/// format-dispatch switch — both `sigil-conductor` (action dispatch)
/// and `sigil-mcp` (tool-call dispatch) route through this helper so
/// adding a new content type is a one-place change.
///
/// # Pre-dispatch reroute
///
/// When the caller declares [`ContentType::PlainText`] but the raw
/// bytes lead with an HTML document root (`<!DOCTYPE html>` or
/// `<html>`, ASCII-only sniff — see [`detect`]), the router reroutes
/// to the HTML sanitizer. The resulting [`SanitizeReport`] carries
/// `content_type: Html` (the effective path that actually ran) and
/// `routed_from: Some(PlainText)` (the declared type) so both are
/// visible to policy and audit consumers.
///
/// [`ContentType::Log`] is **deliberately excluded** from the reroute:
/// terminal captures legitimately contain HTML markers as part of the
/// captured output, so routing those to the HTML sanitizer would
/// destroy the payload the log was meant to preserve.
///
/// The sniff matches document-root markers only. Fragment-shape
/// heuristics (several distinct HTML openers plus a high close-tag
/// count) remain non-routing audit signal in
/// [`crate::patterns::scan`] — see `docs/design/fmt-001-scoping.md`
/// for the rationale.
///
/// # Errors
///
/// - [`ContentError::UnsupportedContentType`] if the declared type
///   has no dispatch arm (e.g. a future `ContentType` variant the
///   router hasn't learned about yet).
/// - Any sanitizer error from the selected entry point (size,
///   encoding, wrap-header injection, etc.).
pub fn dispatch_sanitize(
    sanitizer: &Sanitizer,
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
) -> Result<SanitizedContent, ContentError> {
    // Pre-dispatch HTML sniff on PlainText (but not Log — terminal
    // captures legitimately carry DOCTYPE text in them). The sniff runs
    // before UTF-8 decode so we work on raw bytes; matching is ASCII
    // only so a payload whose leading bytes happen to be non-UTF-8
    // noise cannot force a reroute.
    #[cfg(feature = "html")]
    if matches!(content_type, ContentType::PlainText)
        && detect::looks_like_html_document_root(raw.as_bytes())
    {
        return sanitizer.sanitize_html_routed_from(raw, source, ContentType::PlainText);
    }

    // `ContentType` is #[non_exhaustive]; unknown future variants fail
    // closed with a typed error rather than silently routing through
    // the plain-text path.
    match content_type {
        #[cfg(feature = "html")]
        ContentType::Html => sanitizer.sanitize_html(raw, source),
        #[cfg(not(feature = "html"))]
        ContentType::Html => Err(ContentError::UnsupportedContentType(ContentType::Html)),
        #[cfg(feature = "markdown")]
        ContentType::Markdown => sanitizer.sanitize_markdown(raw, source),
        #[cfg(not(feature = "markdown"))]
        ContentType::Markdown => Err(ContentError::UnsupportedContentType(ContentType::Markdown)),
        #[cfg(feature = "json")]
        ContentType::Json => sanitizer.sanitize_json(raw, source),
        #[cfg(not(feature = "json"))]
        ContentType::Json => Err(ContentError::UnsupportedContentType(ContentType::Json)),
        ContentType::PlainText | ContentType::Log => {
            sanitizer.sanitize_plain(raw, source, content_type)
        }
        other => Err(ContentError::UnsupportedContentType(other)),
    }
}

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

    /// Crate-private read-only view of the buffer, used by the
    /// pre-dispatch sniff in [`dispatch_sanitize`] before ownership
    /// transfers to the selected sanitizer. Kept `pub(crate)` so the
    /// sanitizer-bound discipline (no public accessor) still holds.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
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

    /// Run the HTML path.
    ///
    /// Parses `raw` with a tolerant html5ever tree builder, walks the
    /// DOM dropping `<script>`/`<style>`/`<template>`/`<noscript>`,
    /// comments, metadata containers, and hidden elements (see
    /// [`crate::html`] for the full strip rules), then feeds the
    /// extracted visible text through stages 4-7 of the shared
    /// pipeline. The returned [`SanitizeReport::content_type`] is
    /// [`ContentType::Html`].
    ///
    /// # Errors
    ///
    /// See [`html::sanitize`] for the full error matrix.
    #[cfg(feature = "html")]
    pub fn sanitize_html(
        &self,
        raw: RawFetchedContent,
        source: ContentSource,
    ) -> Result<SanitizedContent, ContentError> {
        html::sanitize(raw, source, &self.config, &self.key)
    }

    /// Internal HTML entry used by [`dispatch_sanitize`] on a
    /// plain-text → HTML reroute. Records `routed_from` in the report
    /// so policy and audit consumers can see the dispatcher picked a
    /// different path than the caller declared.
    #[cfg(feature = "html")]
    pub(crate) fn sanitize_html_routed_from(
        &self,
        raw: RawFetchedContent,
        source: ContentSource,
        declared: ContentType,
    ) -> Result<SanitizedContent, ContentError> {
        html::sanitize_with_routed_from(raw, source, &self.config, &self.key, Some(declared))
    }

    /// Run the Markdown path.
    ///
    /// Content type is implicitly [`ContentType::Markdown`]; the caller
    /// does not pass it. Bytes must decode as UTF-8 and must be within
    /// [`SanitizerConfig::max_bytes`].
    ///
    /// # Errors
    ///
    /// See [`markdown::sanitize`].
    #[cfg(feature = "markdown")]
    pub fn sanitize_markdown(
        &self,
        raw: RawFetchedContent,
        source: ContentSource,
    ) -> Result<SanitizedContent, ContentError> {
        markdown::sanitize(raw, source, &self.config, &self.key)
    }

    /// Run the JSON path.
    ///
    /// Content type is implicitly [`ContentType::Json`]; the caller does
    /// not pass it. Bytes must decode as UTF-8 and must be within
    /// [`SanitizerConfig::max_bytes`]; the top-level value must parse as
    /// JSON; nesting must be within [`crate::json::MAX_NESTING_DEPTH`].
    ///
    /// # Errors
    ///
    /// See [`json::sanitize`].
    #[cfg(feature = "json")]
    pub fn sanitize_json(
        &self,
        raw: RawFetchedContent,
        source: ContentSource,
    ) -> Result<SanitizedContent, ContentError> {
        json::sanitize(raw, source, &self.config, &self.key)
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

/// Free-function entry point for the HTML path.
///
/// Equivalent to constructing a short-lived [`Sanitizer`] and calling
/// [`Sanitizer::sanitize_html`].
///
/// # Errors
///
/// Same as [`Sanitizer::sanitize_html`], plus
/// [`ContentError::FingerprintKeyUnavailable`] if `key` is empty.
#[cfg(feature = "html")]
pub fn sanitize_html(
    raw: RawFetchedContent,
    source: ContentSource,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
    if key.is_empty() {
        return Err(ContentError::FingerprintKeyUnavailable);
    }
    html::sanitize(raw, source, config, key)
}

/// Free-function entry point for the Markdown path.
///
/// Equivalent to constructing a short-lived [`Sanitizer`] and calling
/// [`Sanitizer::sanitize_markdown`].
///
/// # Errors
///
/// Same as [`Sanitizer::sanitize_markdown`], plus
/// [`ContentError::FingerprintKeyUnavailable`] if `key` is empty.
#[cfg(feature = "markdown")]
pub fn sanitize_markdown(
    raw: RawFetchedContent,
    source: ContentSource,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
    if key.is_empty() {
        return Err(ContentError::FingerprintKeyUnavailable);
    }
    markdown::sanitize(raw, source, config, key)
}

/// Free-function entry point for the JSON path.
///
/// Equivalent to constructing a short-lived [`Sanitizer`] and calling
/// [`Sanitizer::sanitize_json`].
///
/// # Errors
///
/// Same as [`Sanitizer::sanitize_json`], plus
/// [`ContentError::FingerprintKeyUnavailable`] if `key` is empty.
#[cfg(feature = "json")]
pub fn sanitize_json(
    raw: RawFetchedContent,
    source: ContentSource,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
    if key.is_empty() {
        return Err(ContentError::FingerprintKeyUnavailable);
    }
    json::sanitize(raw, source, config, key)
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

        // PR3: `out.text` is the wrapped form; the bare cleaned body is
        // recoverable via `wrap::extract_body`.
        let body = wrap::extract_body(&out.text).expect("must round-trip");
        assert!(body.starts_with("Hello, world!"));
        assert_eq!(out.report.bytes_in, 13);
        assert_eq!(out.report.bytes_out, out.text.len());
        assert!(out.text.contains("source: file:///tmp/fixture"));
        assert!(out.text.contains("content_type: text/plain"));
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

        let body = wrap::extract_body(&out.text).unwrap();
        assert!(body.starts_with("helloworld"));
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
        assert_eq!(out.report.bytes_out, out.text.len());
    }

    #[test]
    fn log_content_type_strips_ansi_and_records_count() {
        // Two ANSI sequences (opening SGR + reset) and one plain space.
        let input = "\x1b[31mred\x1b[0m text";
        let s = sanitizer();
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string(input.into()),
                file_source(),
                ContentType::Log,
            )
            .unwrap();
        let body = wrap::extract_body(&out.text).unwrap();
        assert!(body.starts_with("red text"));
        assert_eq!(out.report.content_type, ContentType::Log);
        assert_eq!(
            out.report.stripped_elements,
            vec![("ansi-escape".to_owned(), 2)],
            "report must record both stripped ANSI escapes",
        );
    }

    #[test]
    fn log_content_type_without_ansi_records_nothing() {
        let s = sanitizer();
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string("no escapes here".into()),
                file_source(),
                ContentType::Log,
            )
            .unwrap();
        assert!(out.report.stripped_elements.is_empty());
    }

    #[test]
    fn idempotent_on_already_clean_input() {
        // Idempotence is checked over the *cleaned body*, not the wrapped
        // output: each call generates a fresh nonce, so the wrapped form
        // is intentionally non-deterministic.
        let s = sanitizer();
        let raw = "Hello, normalize me!\u{200B}";
        let first = s
            .sanitize_plain(
                RawFetchedContent::from_string(raw.into()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let first_body = wrap::extract_body(&first.text)
            .unwrap()
            .trim_end_matches('\n')
            .to_owned();
        let second = s
            .sanitize_plain(
                RawFetchedContent::from_string(first_body.clone()),
                file_source(),
                ContentType::PlainText,
            )
            .unwrap();
        let second_body = wrap::extract_body(&second.text)
            .unwrap()
            .trim_end_matches('\n')
            .to_owned();

        assert_eq!(first_body, second_body);
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

    // ---- Pre-dispatch HTML reroute -------------------------------------

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_reroutes_plain_declared_html_body_through_html_sanitizer() {
        // Declared PlainText, but the body is an actual HTML document.
        // Expected: the dispatcher reroutes to `sanitize_html` (so the
        // script content is stripped, not just flagged) and records the
        // declared type in `routed_from`.
        let s = sanitizer();
        let body = "<!DOCTYPE html>\n<html><head><title>x</title></head>\
            <body>Hello<script>alert('evil')</script>world</body></html>";
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string(body.into()),
            file_source(),
            ContentType::PlainText,
        )
        .expect("reroute must succeed");

        assert_eq!(out.report.content_type, ContentType::Html);
        assert_eq!(out.report.routed_from, Some(ContentType::PlainText));
        assert!(
            out.text.contains("content_type: text/html"),
            "wrap header must reflect the effective content type",
        );
        // `<script>` body must have been stripped by the HTML sanitizer.
        let cleaned = wrap::extract_body(&out.text).expect("must round-trip");
        assert!(!cleaned.contains("alert"));
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_does_not_reroute_log_with_doctype() {
        // Terminal captures legitimately carry DOCTYPE text as part of
        // the captured output. The router excludes Log from the reroute.
        let s = sanitizer();
        let body = "[2026-04-18T12:00:00Z] curl output:\n<!DOCTYPE html>\n<html>hi</html>\n";
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string(body.into()),
            file_source(),
            ContentType::Log,
        )
        .expect("log dispatch must succeed");

        assert_eq!(out.report.content_type, ContentType::Log);
        assert!(
            out.report.routed_from.is_none(),
            "Log must never be rerouted: {:?}",
            out.report.routed_from,
        );
        let cleaned = wrap::extract_body(&out.text).expect("must round-trip");
        // Log path preserves the captured DOCTYPE body.
        assert!(cleaned.contains("<!DOCTYPE html>"));
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_does_not_reroute_benign_prose_discussing_html() {
        // Prose that mentions `<!DOCTYPE html>` or `<html>` mid-sentence
        // trips the sniff too, but the sniff window is capped at the
        // leading bytes and the reroute's strip is safer than the
        // pattern-scan-only path. For benign prose that does NOT have
        // a document-root marker in the leading window, no reroute
        // should happen.
        let s = sanitizer();
        let body = "This article discusses HTML sanitization. \
            The sanitizer strips `<script>` tags and other elements. \
            Consider the fragment `<iframe src=x>` as an example.";
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string(body.into()),
            file_source(),
            ContentType::PlainText,
        )
        .expect("plain-text dispatch must succeed");

        assert_eq!(out.report.content_type, ContentType::PlainText);
        assert!(
            out.report.routed_from.is_none(),
            "benign prose must not be rerouted: {:?}",
            out.report.routed_from,
        );
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_reroutes_before_utf8_decode() {
        // The sniff runs on raw bytes before UTF-8 validation. A payload
        // whose HTML prefix is valid ASCII but whose tail contains
        // non-UTF-8 bytes must still reroute to HTML (html5ever does
        // its own decode and is tolerant — this test checks that the
        // sniff itself does not require a UTF-8 pre-pass).
        //
        // We use pure-ASCII bytes here since `sanitize_html` hard-fails
        // on non-UTF-8 input by design; the point of the test is that
        // `detect::looks_like_html_document_root` works on a `&[u8]`
        // and is not predicated on a successful decode.
        let s = sanitizer();
        let raw = RawFetchedContent::from_bytes(b"<html><body>hi</body></html>".to_vec());
        let out = dispatch_sanitize(&s, raw, file_source(), ContentType::PlainText)
            .expect("reroute must succeed");
        assert_eq!(out.report.routed_from, Some(ContentType::PlainText));
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_html_declared_carries_no_routed_from() {
        // When the caller already declared Html, no reroute happens and
        // `routed_from` stays `None`.
        let s = sanitizer();
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string("<html><body>hi</body></html>".into()),
            file_source(),
            ContentType::Html,
        )
        .expect("html dispatch must succeed");
        assert_eq!(out.report.content_type, ContentType::Html);
        assert!(out.report.routed_from.is_none());
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_does_not_reroute_marker_beyond_sniff_window() {
        // A document-root marker parked past the sniff window is
        // intentionally ignored — real HTML leads with the root. Lock
        // the behavior at the dispatch layer so a future window-size
        // change is visible in the test suite.
        let s = sanitizer();
        let mut padding = vec![b' '; 1500];
        padding.extend_from_slice(b"<!DOCTYPE html><html><body>x</body></html>");
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_bytes(padding),
            file_source(),
            ContentType::PlainText,
        )
        .expect("dispatch must succeed");
        assert_eq!(out.report.content_type, ContentType::PlainText);
        assert!(out.report.routed_from.is_none());
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_reroutes_prose_containing_doctype_marker() {
        // A prose passage that quotes `<!DOCTYPE html>` mid-sentence
        // trips the sniff — that's a semantic FP but a safety-positive
        // over-route (the HTML sanitizer strips nothing harmful from
        // text, it just rewraps it). This test pins the intentional
        // tradeoff so a future tightening to "leading token only" is a
        // reviewable diff, not a silent change. See
        // `docs/design/fmt-001-scoping.md` §Edge cases.
        let s = sanitizer();
        let body = "Example: <!DOCTYPE html> opens every HTML document. \
            The sanitizer handles this case safely.";
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string(body.into()),
            file_source(),
            ContentType::PlainText,
        )
        .expect("dispatch must succeed");
        assert_eq!(out.report.content_type, ContentType::Html);
        assert_eq!(out.report.routed_from, Some(ContentType::PlainText));
    }

    #[cfg(feature = "html")]
    #[test]
    fn dispatch_reroutes_on_tab_separated_doctype() {
        // Tab (and other ASCII-whitespace variants) between `<!DOCTYPE`
        // and `html` must trip the sniff — spec-valid HTML, and a
        // non-trivial false-negative if we only honored a literal space.
        let s = sanitizer();
        let body = "<!DOCTYPE\thtml>\n<html><body><script>x</script>ok</body></html>";
        let out = dispatch_sanitize(
            &s,
            RawFetchedContent::from_string(body.into()),
            file_source(),
            ContentType::PlainText,
        )
        .expect("dispatch must succeed");
        assert_eq!(out.report.routed_from, Some(ContentType::PlainText));
    }
}
