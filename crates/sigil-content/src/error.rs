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

    /// A wrap-header value contained a control character (CR, LF, NUL,
    /// DEL, or other byte `< 0x20`). Anti header-injection guard. Same
    /// class of bug as HTTP response splitting; we refuse at the
    /// serializer rather than try to escape.
    #[error("header injection attempt in field {field} at byte offset {offset}")]
    HeaderInjection {
        /// Header field name that contained the control character.
        field: &'static str,
        /// Byte offset within the offending value where the control
        /// character was found.
        offset: usize,
    },

    /// Wrap assembly hit an unexpected `fmt::Write` failure. Should never
    /// happen with `String` but the `write!` API returns `Result`, so the
    /// error type carries the underlying message for diagnostics.
    #[error("wrap assembly failed: {0}")]
    WrapAssembly(String),

    /// Declared `Json` body failed to parse. The message is the
    /// `serde_json::Error::to_string()` form; we wrap it in a `String`
    /// rather than `#[from] serde_json::Error` so the error type stays
    /// independent of `serde_json` being a compiled-in dependency.
    #[error("JSON parse failed: {0}")]
    JsonParse(String),

    /// JSON nesting exceeded [`crate::json::MAX_NESTING_DEPTH`].
    /// Hard-stop to cap recursion-based `DoS`.
    #[error("JSON nesting depth {depth} exceeds max {max}")]
    JsonTooDeep {
        /// Depth at which the walker bailed.
        depth: usize,
        /// Configured nesting ceiling.
        max: usize,
    },

    /// An error from [`sigil_core`] propagated verbatim.
    #[error("core content error: {0}")]
    Core(#[from] sigil_core::ContentError),
}
