//! Plain-text sanitization path (stages 1-2-4-5-6-7 with 5/6 stubbed).
//!
//! Stage 3 format-specific structural strip reduces to `strip_ansi` for
//! [`ContentType::Log`] and is a no-op for [`ContentType::PlainText`].
//! Stage 5 injection-pattern scanning and Stage 6 provenance wrapping are
//! deferred to PR3; this module leaves the corresponding report fields
//! empty and the cleaned text unwrapped.

use std::time::Instant;

use sigil_core::{
    ContentSource, ContentType, Fingerprint, REPORT_SCHEMA_VERSION, SanitizeReport,
    SanitizedContent,
};
use sigil_policy::normalize::{normalize_text, strip_ansi};

use crate::{ContentError, RawFetchedContent, SanitizerConfig};

/// Length of the per-call nonce, in hex characters (16 chars = 64 bits).
const NONCE_HEX_LEN: usize = 16;

/// Core plain-text sanitization entry point.
///
/// This is called by both [`crate::Sanitizer::sanitize_plain`] and the
/// free [`crate::sanitize_plain`] wrapper. The caller owns the key and the
/// config; this function contains the pipeline.
///
/// # Errors
///
/// Returns [`ContentError::UnsupportedContentType`] for any declared type
/// other than [`ContentType::PlainText`] or [`ContentType::Log`].
/// [`ContentError::SizeExceeded`] when the raw length is above
/// [`SanitizerConfig::max_bytes`]. [`ContentError::InvalidEncoding`] for
/// non-UTF-8 bytes. [`ContentError::FingerprintKeyUnavailable`] if the key
/// is empty. [`ContentError::Random`] if the OS random source fails.
pub(crate) fn sanitize(
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
    // Each known variant is listed so a future `ContentType` addition
    // forces a compile-time decision here. `#[non_exhaustive]` forces the
    // catch-all `_` arm for forward compatibility.
    let strip_ansi_first = match content_type {
        ContentType::PlainText => false,
        ContentType::Log => true,
        ContentType::Html | ContentType::Markdown | ContentType::Json => {
            return Err(ContentError::UnsupportedContentType(content_type));
        }
        _ => return Err(ContentError::UnsupportedContentType(content_type)),
    };

    let started = Instant::now();
    let bytes = raw.into_bytes();
    let bytes_in = bytes.len();

    // Stage 1 — raw byte-size cap. Applied *before* any decode or
    // fingerprint so an attacker cannot force even a linear scan.
    if bytes_in > config.max_bytes {
        return Err(ContentError::SizeExceeded {
            bytes: bytes_in,
            max: config.max_bytes,
        });
    }

    // Fingerprint of the raw bytes: computed on the accepted payload so a
    // size-rejected input cannot be cheaply probed via its fingerprint.
    let raw_fingerprint = Fingerprint::compute(key, &bytes).map_err(map_core_error)?;

    // Stage 2 — declare & decode. Caller already declared the content type;
    // the remaining obligation is UTF-8 validation. Non-UTF-8 is a hard
    // error — no best-effort decode, no replacement characters.
    let decoded = std::str::from_utf8(&bytes).map_err(|_| ContentError::InvalidEncoding)?;

    // Stage 3 — format-specific strip (plain-text path). For `PlainText`
    // this is a no-op. For `Log` we strip ANSI escape sequences, matching
    // the treatment already applied to captured tmux output.
    let stage3 = if strip_ansi_first {
        strip_ansi(decoded)
    } else {
        decoded.to_owned()
    };

    // Stage 4 — text-layer normalize (delegated to sigil-policy).
    let text_normalize = normalize_text(&stage3);
    let cleaned = text_normalize.cleaned.clone();

    // Stage 5 — injection-pattern scan (PR3). Intentionally skipped here;
    // the empty `findings` vector below is the placeholder.
    // TODO(PR3): run pattern scan, populate findings + risk_score.

    // Stage 6 — provenance wrap (PR3). Intentionally skipped here; the
    // cleaned text flows out bare for now.
    // TODO(PR3): wrap cleaned text with nonce-delimited sentinel.

    let sanitized_bytes = cleaned.as_bytes();
    let bytes_out = sanitized_bytes.len();
    let sanitized_fingerprint =
        Fingerprint::compute(key, sanitized_bytes).map_err(map_core_error)?;

    let nonce = generate_nonce()?;
    let repetition_ratio = repetition_ratio(&cleaned);

    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let report = SanitizeReport {
        schema_version: REPORT_SCHEMA_VERSION,
        rule_set_version: config.rule_set_version,
        scoring_version: config.scoring_version,
        source,
        content_type,
        bytes_in,
        bytes_out,
        stripped_elements: Vec::new(),
        text_normalize,
        findings: Vec::new(),
        risk_score: 0,
        repetition_ratio,
        size_rejected: false,
        encoding_rejected: false,
        nonce,
        duration_ms,
        raw_fingerprint,
        sanitized_fingerprint,
    };

    Ok(SanitizedContent {
        text: cleaned,
        report,
    })
}

/// Translate a [`sigil_core::ContentError`] into the local error enum.
///
/// Only the `FingerprintKeyUnavailable` variant can actually occur here;
/// URL-construction errors are produced by callers building the
/// `ContentSource` before invoking the pipeline. The catch-all forwards
/// anything else verbatim via `#[from]`.
fn map_core_error(err: sigil_core::ContentError) -> ContentError {
    // `sigil_core::ContentError` is `#[non_exhaustive]`, so a `match` would
    // have to spell out every known variant plus a `_` arm; `matches!`
    // keeps the intent focused — promote the single variant we care about,
    // forward everything else — without churning on future core changes.
    if matches!(err, sigil_core::ContentError::FingerprintKeyUnavailable) {
        ContentError::FingerprintKeyUnavailable
    } else {
        ContentError::Core(err)
    }
}

/// Emit a 16-character lowercase hex nonce backed by 8 random bytes.
fn generate_nonce() -> Result<String, ContentError> {
    let mut bytes = [0u8; NONCE_HEX_LEN / 2];
    getrandom::getrandom(&mut bytes).map_err(|e| ContentError::Random(e.to_string()))?;
    let mut out = String::with_capacity(NONCE_HEX_LEN);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    Ok(out)
}

/// O(n) per-byte repetition approximation.
///
/// Counts the fraction of bytes that equal their immediate predecessor.
/// `"aaaa"` → 0.75; `"abcd"` → 0.0; realistic English prose tends to sit
/// in the 0.03-0.10 range. This is deliberately crude — PR3's pattern
/// scanner layers a proper entropy check on top; this value is just the
/// cheap context-flooding signal that belongs in every report.
fn repetition_ratio(text: &str) -> f32 {
    let bytes = text.as_bytes();
    let total = bytes.len();
    if total < 2 {
        return 0.0;
    }
    let mut repeats: usize = 0;
    let mut prev: Option<u8> = None;
    for &b in bytes {
        if Some(b) == prev {
            repeats = repeats.saturating_add(1);
        }
        prev = Some(b);
    }
    // Division by `total` (not `total - 1`) keeps the ratio comparable
    // across chunk sizes and caps below 1.0 for any non-empty input,
    // which matches the design-doc treatment of the field.
    #[allow(clippy::cast_precision_loss)]
    let ratio = repeats as f32 / total as f32;
    ratio
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

    use super::*;

    #[test]
    fn repetition_ratio_empty_and_singleton_are_zero() {
        assert!((repetition_ratio("") - 0.0).abs() < f32::EPSILON);
        assert!((repetition_ratio("a") - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn repetition_ratio_all_same_is_near_one() {
        let r = repetition_ratio("aaaaa");
        assert!(r > 0.75, "expected high repetition ratio, got {r}");
    }

    #[test]
    fn repetition_ratio_alternating_is_zero() {
        assert!((repetition_ratio("abababab") - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn nonce_is_hex_and_right_length() {
        let n = generate_nonce().unwrap();
        assert_eq!(n.len(), NONCE_HEX_LEN);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
