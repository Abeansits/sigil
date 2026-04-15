//! Error type for the sanitization pipeline.

use sigil_core::ContentType;
use thiserror::Error;

/// Errors produced by the sanitization pipeline.
///
/// Size and encoding failures are deliberately hard errors rather than
/// "soft" report flags. The `size_rejected` / `encoding_rejected` fields on
/// [`sigil_core::SanitizeReport`] are reserved for future callers that want
/// to attach a partial report to a rejection; the current pipeline returns
/// the typed error and writes nothing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentError {
    /// Input exceeded [`crate::SanitizerConfig::max_bytes`]. The cap is
    /// enforced before decode so oversize inputs cannot even force a UTF-8
    /// scan of the whole payload.
    #[error("input size {bytes} exceeds configured max {max}")]
    SizeExceeded {
        /// Observed byte length of the input.
        bytes: usize,
        /// Configured byte ceiling.
        max: usize,
    },

    /// The caller declared a textual content type but the bytes did not
    /// decode as UTF-8. The pipeline never best-effort decodes; the caller
    /// must declare correctly or accept the rejection.
    #[error("input is not valid UTF-8")]
    InvalidEncoding,

    /// No fingerprint HMAC key is available. The pipeline refuses to fall
    /// back to unkeyed SHA, which would silently weaken the correlation
    /// property of the audit log.
    #[error("fingerprint key unavailable; keyed HMAC is required")]
    FingerprintKeyUnavailable,

    /// The caller asked the plain-text path to handle a content type it
    /// does not implement (e.g. `Html` before PR4 lands).
    #[error("content type {0:?} is not supported by this sanitizer path")]
    UnsupportedContentType(ContentType),

    /// A nonce or other random value could not be sourced from the OS.
    #[error("random source unavailable: {0}")]
    Random(String),

    /// An error from [`sigil_core`] propagated verbatim.
    #[error("core content error: {0}")]
    Core(#[from] sigil_core::ContentError),
}
