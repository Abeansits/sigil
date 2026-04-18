//! Plain-text sanitization path — full Stage 1-7 pipeline.
//!
//! Stage 3 format-specific structural strip reduces to `strip_ansi` for
//! [`ContentType::Log`] and is a no-op for [`ContentType::PlainText`].
//! Stage 4 delegates Unicode/control normalization to
//! [`sigil_policy::normalize::normalize_text`]. Stages 5-6 are wired in
//! PR3 and live in [`crate::patterns`], [`crate::risk`], and
//! [`crate::wrap`]. The output `text` field is the wrapped form — the
//! string the model will see — and the report carries the unwrapped
//! cleaned-bytes fingerprint plus the per-call nonce.

use std::time::Instant;

use sigil_core::{
    ContentSource, ContentType, Fingerprint, NormalizeResult, REPORT_SCHEMA_VERSION,
    SanitizeReport, SanitizedContent,
};
use sigil_policy::normalize::{normalize_text, strip_ansi};

use crate::{
    ContentError, RawFetchedContent, SanitizerConfig,
    patterns::{self, RULE_REP_002, RULE_WRP_001},
    risk, wrap,
};

/// Length of the per-call nonce, in hex characters (16 chars = 64 bits).
const NONCE_HEX_LEN: usize = 16;

/// Maximum nonce regenerations before giving up. With a 64-bit nonce and
/// at most a handful of attacker-controlled wrapper-prefix collisions in
/// the payload, four retries is comfortably more than the birthday bound.
const NONCE_REGEN_LIMIT: u8 = 4;

/// Token used by the conductor when the fetch timestamp is not
/// surfaced. Plain text has no native `fetched_at`; PR2 left this implicit.
pub(crate) const UNKNOWN_FETCHED_AT: &str = "unknown";

/// Wire-format string for [`ContentType`] in the wrap header. Kept here
/// so the wrap module stays oblivious to the enum.
pub(crate) fn content_type_wire(ct: ContentType) -> &'static str {
    match ct {
        ContentType::PlainText => "text/plain",
        ContentType::Log => "text/x-log",
        ContentType::Html => "text/html",
        ContentType::Markdown => "text/markdown",
        ContentType::Json => "application/json",
        // `ContentType` is `#[non_exhaustive]`. Returning a stable token
        // for unknown variants keeps the wrap header well-formed even if
        // a future variant slips through the entry-point gate.
        _ => "application/octet-stream",
    }
}

/// Core plain-text sanitization entry point.
///
/// # Errors
///
/// Returns [`ContentError::UnsupportedContentType`] for any declared type
/// other than [`ContentType::PlainText`] or [`ContentType::Log`].
/// [`ContentError::SizeExceeded`] when the raw length is above
/// [`SanitizerConfig::max_bytes`]. [`ContentError::InvalidEncoding`] for
/// non-UTF-8 bytes. [`ContentError::FingerprintKeyUnavailable`] if the key
/// is empty. [`ContentError::Random`] if the OS random source fails.
/// [`ContentError::HeaderInjection`] if the `source`'s rendered form
/// contains a control character.
pub(crate) fn sanitize(
    raw: RawFetchedContent,
    source: ContentSource,
    content_type: ContentType,
    config: &SanitizerConfig,
    key: &[u8],
) -> Result<SanitizedContent, ContentError> {
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

    // Stage 1 — raw byte-size cap.
    if bytes_in > config.max_bytes {
        return Err(ContentError::SizeExceeded {
            bytes: bytes_in,
            max: config.max_bytes,
        });
    }

    let raw_fingerprint = Fingerprint::compute(key, &bytes).map_err(map_core_error)?;

    // Stage 2 — declare & decode (UTF-8 hard-required).
    let decoded = std::str::from_utf8(&bytes).map_err(|_| ContentError::InvalidEncoding)?;

    // Stage 3 — format-specific strip.
    let mut stripped_elements: Vec<(String, u32)> = Vec::new();
    let stage3 = if strip_ansi_first {
        let stripped = strip_ansi(decoded);
        let removed = count_esc_bytes(decoded).saturating_sub(count_esc_bytes(&stripped));
        if removed > 0 {
            let count = u32::try_from(removed).unwrap_or(u32::MAX);
            stripped_elements.push(("ansi-escape".to_owned(), count));
        }
        stripped
    } else {
        decoded.to_owned()
    };

    run_post_strip_pipeline(PostStripInput {
        stage3,
        stripped_elements,
        source,
        content_type,
        bytes_in,
        raw_fingerprint,
        started,
        prenormalized: None,
        config,
        key,
    })
}

/// Inputs to the stage 4-7 tail of the pipeline, shared by every
/// format-specific path. The format sanitizer runs stages 1-3 (size cap,
/// decode, structural strip) and hands control here with the cleaned
/// pre-normalize string, the stripped-element counts it recorded, and
/// the metadata needed for report assembly.
pub(crate) struct PostStripInput<'a> {
    /// Result of the format-specific structural strip.
    pub(crate) stage3: String,
    /// `(kind, count)` entries the stripper produced — preserved verbatim
    /// into the final report.
    pub(crate) stripped_elements: Vec<(String, u32)>,
    pub(crate) source: ContentSource,
    pub(crate) content_type: ContentType,
    /// Raw input byte length (stage 1 already enforced the cap).
    pub(crate) bytes_in: usize,
    /// HMAC of the raw input bytes, computed before the format decode.
    pub(crate) raw_fingerprint: Fingerprint,
    /// Timer start, captured at the head of the pipeline so `duration_ms`
    /// reflects the full cost of the call, not just the tail.
    pub(crate) started: Instant,
    /// Pre-computed Stage 4 result for callers (the JSON path) that
    /// normalize per-leaf before re-serializing. When `Some`,
    /// [`run_post_strip_pipeline`] uses this `NormalizeResult` directly
    /// rather than re-running `normalize_text` on `stage3` — otherwise
    /// the downstream `risk::compute` and `derive_flags` passes would
    /// see `stripped_count == 0` even though the walker actually
    /// stripped zero-widths / directional overrides / control chars
    /// from string leaves and object keys, and those payloads would
    /// fall below policy thresholds they should cross.
    ///
    /// `cleaned` on the supplied result is ignored — `stage3` is the
    /// canonical post-Stage-3 body and is used as-is.
    pub(crate) prenormalized: Option<NormalizeResult>,
    pub(crate) config: &'a SanitizerConfig,
    pub(crate) key: &'a [u8],
}

/// Stage 4-7: text-layer normalize → pattern scan → nonce wrap → report.
///
/// This is the half of the pipeline that every format shares. HTML /
/// Markdown / JSON paths do their own structural strip, convert the body
/// to a plain string, and call into here with the accumulated stripped
/// counts and fingerprint. Plain text and log both hit it via
/// [`sanitize`] above.
pub(crate) fn run_post_strip_pipeline(
    input: PostStripInput<'_>,
) -> Result<SanitizedContent, ContentError> {
    let PostStripInput {
        stage3,
        stripped_elements,
        source,
        content_type,
        bytes_in,
        raw_fingerprint,
        started,
        prenormalized,
        config,
        key,
    } = input;

    // Stage 4 — text-layer normalize.
    //
    // For paths whose Stage 3 output still contains potentially dirty
    // bytes (plain-text, Log, Markdown, HTML), we run `normalize_text`
    // here to strip invisible characters and produce the final
    // `cleaned` body.
    //
    // The JSON path normalizes each string leaf and object key during
    // its Stage 3 walk so that key-collision detection is possible; it
    // hands us the aggregated `NormalizeResult` via `prenormalized` and
    // the already-clean serialized body as `stage3`. We use the
    // caller-supplied counts and categories so that `risk::compute` and
    // `derive_flags` see the same normalize signal any other path would
    // have surfaced — a JSON payload that hides zero-widths in nested
    // string values must not score lower than the same content in a
    // plain-text wrapper.
    let text_normalize = if let Some(nr) = prenormalized {
        NormalizeResult {
            cleaned: stage3.clone(),
            stripped_count: nr.stripped_count,
            categories: nr.categories,
        }
    } else {
        normalize_text(&stage3)
    };
    let cleaned = text_normalize.cleaned.clone();

    let sanitized_bytes = cleaned.as_bytes();
    let sanitized_fingerprint =
        Fingerprint::compute(key, sanitized_bytes).map_err(map_core_error)?;

    // Stage 5 — pattern scan + risk score.
    let mixed_script = text_normalize
        .categories
        .iter()
        .any(|c| c == "mixed-script");
    let mut findings = patterns::scan(&cleaned, content_type, mixed_script);

    let repetition_ratio = repetition_ratio(&cleaned);
    if repetition_ratio.is_finite() && repetition_ratio >= config.max_repetition_ratio {
        findings.push(sigil_core::Finding {
            rule_id: RULE_REP_002.id.to_owned(),
            severity: RULE_REP_002.severity,
            span: None,
            sample: None,
        });
    }

    // Stage 6 — nonce-delimited wrap. Collision-regen bounded by
    // [`NONCE_REGEN_LIMIT`].
    let payload_has_prefix = patterns::detect_wrapper_collision(&cleaned);
    let nonce = pick_collision_free_nonce(&cleaned)?;
    if payload_has_prefix {
        findings.push(sigil_core::Finding {
            rule_id: RULE_WRP_001.id.to_owned(),
            severity: RULE_WRP_001.severity,
            span: None,
            sample: None,
        });
    }

    let risk_score = risk::compute(&findings, &text_normalize, repetition_ratio);

    let flags = derive_flags(&findings, &text_normalize);
    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    let flag_refs: Vec<&str> = flags.iter().map(String::as_str).collect();

    let wrapped = wrap::wrap(
        &cleaned,
        &source,
        content_type_wire(content_type),
        UNKNOWN_FETCHED_AT,
        &flag_refs,
        &rule_ids,
        &nonce,
    )?;

    let bytes_out = wrapped.len();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let report = SanitizeReport {
        schema_version: REPORT_SCHEMA_VERSION,
        rule_set_version: config.rule_set_version,
        scoring_version: config.scoring_version,
        source,
        content_type,
        bytes_in,
        bytes_out,
        stripped_elements,
        text_normalize,
        findings,
        risk_score,
        repetition_ratio,
        size_rejected: false,
        encoding_rejected: false,
        nonce,
        duration_ms,
        raw_fingerprint,
        sanitized_fingerprint,
    };

    Ok(SanitizedContent {
        text: wrapped,
        report,
    })
}

/// Build the `flags:` header value from findings + normalize categories.
///
/// Kept stable across PRs so audit-log consumers can grep for known
/// flag names. Order is deterministic (same input → same output).
fn derive_flags(
    findings: &[sigil_core::Finding],
    normalize: &sigil_core::NormalizeResult,
) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    let has = |needle: &str| findings.iter().any(|f| f.rule_id.starts_with(needle));
    if has("INJ-") {
        flags.push("injection_pattern".into());
    }
    if has("ENC-") {
        flags.push("encoded_payload".into());
    }
    if has("REP-") {
        flags.push("repetition".into());
    }
    if has("MIX-") {
        flags.push("mixed_script".into());
    }
    if has("FMT-") {
        flags.push("content_type_mismatch".into());
    }
    if has("WRP-") {
        flags.push("wrapper_collision".into());
    }
    for cat in &normalize.categories {
        if cat == "mixed-script" {
            continue; // already represented via MIX-001
        }
        let flag = format!("normalize_{}", cat.replace('-', "_"));
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }
    flags
}

/// Translate a [`sigil_core::ContentError`] into the crate-local error.
/// Shared with [`crate::html`] / [`crate::markdown`] / [`crate::json`]
/// paths so they don't each reinvent the mapping.
pub(crate) fn map_core_error(err: sigil_core::ContentError) -> ContentError {
    if matches!(err, sigil_core::ContentError::FingerprintKeyUnavailable) {
        ContentError::FingerprintKeyUnavailable
    } else {
        ContentError::Core(err)
    }
}

/// Pick a nonce whose start/end sentinel does not appear literally in
/// `cleaned`. Bounded by [`NONCE_REGEN_LIMIT`]; returns
/// [`ContentError::Random`] if no clean nonce is found inside the budget
/// (the payload is too saturated with sentinel-shaped strings to wrap
/// safely — surface the failure rather than emit a wrap with a
/// known-collision nonce).
fn pick_collision_free_nonce(cleaned: &str) -> Result<String, ContentError> {
    let mut nonce = generate_nonce()?;
    let mut regen_attempts: u8 = 0;
    loop {
        let start_marker = format!("{}{}", wrap::WRAP_PREFIX_START, nonce);
        let end_marker = format!("{}{}", wrap::WRAP_PREFIX_END, nonce);
        if !cleaned.contains(&start_marker) && !cleaned.contains(&end_marker) {
            return Ok(nonce);
        }
        if regen_attempts >= NONCE_REGEN_LIMIT {
            return Err(ContentError::Random(
                "nonce regeneration exhausted; payload contains too many sentinel collisions"
                    .into(),
            ));
        }
        nonce = generate_nonce()?;
        regen_attempts = regen_attempts.saturating_add(1);
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

#[allow(clippy::naive_bytecount)]
fn count_esc_bytes(s: &str) -> usize {
    s.as_bytes().iter().filter(|&&b| b == 0x1B).count()
}

/// O(n) per-byte repetition approximation. See PR2 for full rationale.
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

    #[test]
    fn content_type_wire_covers_known_variants() {
        assert_eq!(content_type_wire(ContentType::PlainText), "text/plain");
        assert_eq!(content_type_wire(ContentType::Log), "text/x-log");
        assert_eq!(content_type_wire(ContentType::Html), "text/html");
        assert_eq!(content_type_wire(ContentType::Markdown), "text/markdown");
        assert_eq!(content_type_wire(ContentType::Json), "application/json");
    }
}
