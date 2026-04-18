//! External-content fetcher — the port the sanitizer depends on but
//! does not implement.
//!
//! `sigil-content` is a pure transform: it sanitizes bytes the caller
//! hands it. Those bytes come from somewhere — an HTTP client, a
//! bridge attachment, a fixture loader in a test. That "somewhere" is
//! implemented outside this crate.
//!
//! The trait lives in `sigil-content` instead of the caller crates
//! because both `sigil-conductor` and `sigil-mcp` consume the same
//! contract. Putting it next to the sanitizer keeps the one-crate-per-
//! concern shape — fetching is part of the content-ingest surface,
//! even though the sanitizer does not own any transport code.
//!
//! No `reqwest` / `hyper` / `ureq` dependency is introduced here: this
//! module ships the trait, a [`FetchError`] variant taxonomy, and a
//! [`DisabledFetcher`] default. Production deployments that want real
//! network fetches plug in a concrete implementation alongside the
//! existing domain-filtering proxy.

use std::future::Future;
use std::pin::Pin;

/// Boxed future returned by [`ExternalContentFetcher::fetch`].
///
/// The trait uses a boxed future instead of an `impl Future` return
/// because callers store fetchers behind `Arc<dyn ...>` — `impl
/// Future` return types are not dyn-compatible. One allocation per
/// fetch; the HTTP round-trip dominates so this is not a hot path.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, FetchError>> + Send + 'a>>;

/// Fetch the bytes behind a URL on behalf of the sanitization
/// pipeline.
///
/// Implementations do not parse, decode, or inspect the bytes — they
/// return them verbatim for the sanitizer. Trust-zone classification,
/// content-type declaration, and policy gating are all the caller's
/// job. `Send + Sync` so `Arc<dyn ExternalContentFetcher>` can be
/// shared across tokio tasks.
pub trait ExternalContentFetcher: Send + Sync {
    /// Fetch raw bytes for `url`. See [`FetchError`] for the failure
    /// taxonomy.
    fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a>;
}

/// Reasons a fetch attempt can fail.
///
/// Coarse by design — the PR7 scope stops at "fetcher shape" and
/// does not wire a real network client. A production fetcher refines
/// [`Other`](Self::Other) into DNS / TLS / 4xx / 5xx / size-limit
/// cases as the transport code lands.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// No fetcher is configured on this caller. Returned by
    /// [`DisabledFetcher`] and by dispatch paths that were built
    /// without a fetcher.
    #[error("external-content fetching is not configured")]
    NotConfigured,

    /// The fetcher looked up the URL but had no bytes for it. A
    /// fixture fetcher emits this for unknown URLs; a production
    /// fetcher emits it for 404 / DNS failures.
    #[error("no content found for URL: {url}")]
    NotFound {
        /// The URL that had no backing bytes.
        url: String,
    },

    /// Any other implementation-specific failure.
    #[error("fetcher failure: {message}")]
    Other {
        /// Human-readable detail. **Do not put secrets here** — the
        /// message is echoed into the policy-decision `Deny.reason`
        /// and therefore into the audit log.
        message: String,
    },
}

/// A fetcher that always refuses. The default on callers that have
/// not wired a real fetch path, so a `FetchExternalContent` dispatch
/// produces a clean typed denial instead of silently succeeding with
/// empty bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledFetcher;

impl ExternalContentFetcher for DisabledFetcher {
    fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
        Box::pin(async { Err(FetchError::NotConfigured) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn disabled_fetcher_errors_not_configured() {
        let err = DisabledFetcher
            .fetch("https://x.example")
            .await
            .expect_err("err");
        assert_matches!(err, FetchError::NotConfigured);
    }
}
