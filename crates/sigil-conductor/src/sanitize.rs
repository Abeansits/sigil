//! External-content fetch + sanitize pipeline for `ActionService`.
//!
//! PR7 wires the conductor's dispatch path for
//! [`Action::FetchExternalContent`] into `sigil-content`. The flow:
//!
//! ```text
//! Action::FetchExternalContent { url, content_type }
//!        │
//!        ▼
//!  ExternalContentFetcher::fetch(url)         ← pluggable; no network code in this crate
//!        │
//!        ▼
//!  Sanitizer::sanitize_{html,markdown,json,plain}
//!        │
//!        ▼
//!  DispatchResult::ExternalContent { text, report }
//! ```
//!
//! Two deliberate decisions:
//!
//! 1. **Sanitizer crate is the single implementation of the pipeline.**
//!    This module only assembles pieces it imports; it never parses HTML,
//!    runs regexes, or computes fingerprints directly. Behavior drift
//!    between the CLI debug harness and the conductor path is therefore
//!    impossible — both route through `sigil_content::Sanitizer`.
//!
//! 2. **Fetching is a trait, not a concrete client.** The design doc
//!    calls the fetcher out as deferred infrastructure; PR7 ships the
//!    shape (a trait + a `DisabledFetcher` default) so the plumbing
//!    works end-to-end in tests (`FixtureFetcher`) without pulling a
//!    full HTTP stack into `sigil-conductor` for production builds that
//!    do not yet have an allowlisted fetch path.
//!
//! Errors from any stage surface as `ConductorError::Internal`; callers
//! observe a `PolicyDecision::Deny` through `evaluate_result` when the
//! sanitizer rejects the input (size, encoding) or when the fetcher
//! fails.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sigil_content::{RawFetchedContent, Sanitizer};
use sigil_core::content::{ContentSource, ContentType, SanitizedContent};

use crate::error::ConductorError;

/// Boxed future returned by [`ExternalContentFetcher::fetch`].
///
/// The trait uses a boxed future instead of an `impl Future` return
/// because `ActionService` stores the fetcher behind
/// `Arc<dyn ExternalContentFetcher>` — `impl Future` return types are
/// not dyn-compatible. The box is allocated once per fetch and is not
/// on the hot path for any action (the underlying fetch dominates).
pub type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, FetchError>> + Send + 'a>>;

/// Fetcher for the bytes behind a URL declared by
/// [`sigil_core::action::Action::FetchExternalContent`].
///
/// This trait deliberately does not prescribe a transport. Production
/// wiring plugs in an HTTP client with the existing domain-filtering
/// proxy; tests plug in a fixture-backed implementation. The trait is
/// `Send + Sync` so an `Arc<dyn ExternalContentFetcher>` can be held by
/// [`crate::action_service::ActionService`] and used across await
/// points.
pub trait ExternalContentFetcher: Send + Sync {
    /// Fetch the raw bytes for `url`. The caller has already
    /// declared the content type in the originating action; no
    /// sniffing is performed here or downstream.
    fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a>;
}

/// Reasons a fetch attempt can fail.
///
/// Separate from [`ConductorError`] so the dispatch arm can map a
/// fetch failure to a typed denial reason that the audit log preserves
/// verbatim. The variants are intentionally coarse — PR7 does not wire
/// a real HTTP client, and a richer taxonomy (DNS / TLS / 4xx / 5xx /
/// size limit) is part of the deferred fetch-infrastructure work.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// No fetcher has been configured on the `ActionService`.
    /// Returned by [`DisabledFetcher`] and by the dispatch arm when
    /// the service was built without `with_fetcher`.
    #[error("external-content fetching is not configured on this ActionService")]
    NotConfigured,

    /// The fetcher found no bytes for the given URL. A fixture-backed
    /// fetcher emits this for an unknown URL; a production fetcher
    /// emits it for 404 / DNS-resolution failures.
    #[error("no content found for URL: {url}")]
    NotFound {
        /// The URL that had no backing bytes.
        url: String,
    },

    /// An implementation-specific failure (IO, decode, backing-store
    /// error). The `source` carries the underlying message.
    #[error("fetcher failure: {message}")]
    Other {
        /// Human-readable detail. Do not render secrets here — the
        /// value is echoed into the policy-decision `Deny.reason` and
        /// therefore into the audit log.
        message: String,
    },
}

/// A no-op fetcher that always returns [`FetchError::NotConfigured`].
///
/// The default on an `ActionService` built without `with_fetcher`.
/// Production deployments that have not wired a real fetcher therefore
/// produce a typed denial for any `FetchExternalContent` action rather
/// than silently pretending to have fetched empty bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledFetcher;

impl ExternalContentFetcher for DisabledFetcher {
    fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
        Box::pin(async { Err(FetchError::NotConfigured) })
    }
}

/// Run the full fetch + sanitize pipeline for a single URL.
///
/// Returns [`SanitizedContent`] on success; the caller packages this
/// into a `DispatchResult::ExternalContent` and feeds the report back
/// to the evaluator's `evaluate_result` gate.
///
/// # Errors
///
/// - [`ConductorError::Internal`] wrapping [`FetchError`] if fetching
///   fails.
/// - [`ConductorError::Internal`] wrapping
///   [`sigil_content::ContentError`] if the sanitizer rejects the
///   input (oversize, invalid UTF-8) or if the declared `content_type`
///   is unsupported.
pub async fn fetch_and_sanitize<F>(
    fetcher: &F,
    sanitizer: &Sanitizer,
    url: &str,
    content_type: ContentType,
) -> Result<SanitizedContent, ConductorError>
where
    F: ExternalContentFetcher + ?Sized,
{
    let bytes = fetcher.fetch(url).await.map_err(|e| ConductorError::Internal {
        message: format!("fetch failed for {url}: {e}"),
    })?;
    let source = ContentSource::from_url(url)
        .unwrap_or_else(|_| ContentSource::Other(url.to_owned()));
    let raw = RawFetchedContent::from_bytes(bytes);
    run_sanitize(sanitizer, raw, source, content_type)
}

/// Dispatch a raw buffer into the sanitizer entry point that matches
/// the declared content type. Factored out of
/// [`fetch_and_sanitize`] so tests (and a future bridge-attachment
/// caller) can skip the fetch step.
pub fn run_sanitize(
    sanitizer: &Sanitizer,
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
) -> Result<SanitizedContent, ConductorError> {
    // `ContentType` is #[non_exhaustive]; unknown future variants fail
    // closed with a typed error rather than silently routing through
    // the plain-text path.
    let sanitized = match content_type {
        ContentType::Html => sanitizer.sanitize_html(raw, source),
        ContentType::Markdown => sanitizer.sanitize_markdown(raw, source),
        ContentType::Json => sanitizer.sanitize_json(raw, source),
        ContentType::PlainText | ContentType::Log => {
            sanitizer.sanitize_plain(raw, source, content_type)
        }
        other => {
            return Err(ConductorError::Internal {
                message: format!(
                    "sanitize: content type {other:?} has no dispatch arm; \
                     add one in sigil-conductor::sanitize::run_sanitize"
                ),
            });
        }
    }
    .map_err(|e| ConductorError::Internal {
        message: format!("sanitize({content_type:?}) failed: {e}"),
    })?;
    Ok(sanitized)
}

/// Convenience type alias for the shared pointer `ActionService` holds.
pub type SharedFetcher = Arc<dyn ExternalContentFetcher + Send + Sync>;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test code asserts on values that are provably safe to unwrap"
    )]

    use std::collections::HashMap;

    use sigil_core::content::ContentType;

    use super::*;

    const TEST_KEY: &[u8] = b"sigil-conductor-sanitize-test-key";

    /// Fixture-backed fetcher: maps URLs to static bytes. Used by the
    /// integration tests and by this module's unit tests.
    #[derive(Clone, Default)]
    pub(crate) struct FixtureFetcher {
        map: HashMap<String, Vec<u8>>,
    }

    impl FixtureFetcher {
        pub(crate) fn with(url: &str, bytes: Vec<u8>) -> Self {
            let mut map = HashMap::new();
            map.insert(url.to_owned(), bytes);
            Self { map }
        }
    }

    impl ExternalContentFetcher for FixtureFetcher {
        fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a> {
            let result = self.map.get(url).cloned().ok_or_else(|| FetchError::NotFound {
                url: url.to_owned(),
            });
            Box::pin(async move { result })
        }
    }

    fn sanitizer() -> Sanitizer {
        Sanitizer::new(TEST_KEY).expect("key accepted")
    }

    #[tokio::test]
    async fn disabled_fetcher_errors_not_configured() {
        let err = DisabledFetcher.fetch("https://x.example").await.expect_err("err");
        assert!(matches!(err, FetchError::NotConfigured));
    }

    #[tokio::test]
    async fn fetch_and_sanitize_happy_path_html() {
        let fetcher = FixtureFetcher::with(
            "https://example.com/a",
            b"<html><body>hello</body></html>".to_vec(),
        );
        let out = fetch_and_sanitize(
            &fetcher,
            &sanitizer(),
            "https://example.com/a",
            ContentType::Html,
        )
        .await
        .expect("sanitize html");
        assert!(out.text.contains("hello"));
        assert_eq!(out.report.content_type, ContentType::Html);
    }

    #[tokio::test]
    async fn fetch_and_sanitize_propagates_not_found() {
        let fetcher = FixtureFetcher::default();
        let err = fetch_and_sanitize(
            &fetcher,
            &sanitizer(),
            "https://example.com/missing",
            ContentType::PlainText,
        )
        .await
        .expect_err("not found");
        match err {
            ConductorError::Internal { message } => {
                assert!(message.contains("missing"), "expected URL in error: {message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_and_sanitize_propagates_sanitizer_error() {
        // Oversize input → sanitizer rejects → Internal.
        let huge = vec![b'x'; 64 * 1024 * 1024]; // 64 MiB > default 2 MiB cap
        let fetcher = FixtureFetcher::with("https://example.com/big", huge);
        let err = fetch_and_sanitize(
            &fetcher,
            &sanitizer(),
            "https://example.com/big",
            ContentType::PlainText,
        )
        .await
        .expect_err("oversize");
        match err {
            ConductorError::Internal { message } => {
                assert!(
                    message.contains("sanitize(PlainText) failed"),
                    "error should name the content type: {message}",
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
