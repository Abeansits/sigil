//! Content sanitization — core types.
//!
//! This module defines the data types that flow through the external-content
//! sanitization pipeline described in `docs/design/content-sanitization.md`.
//! It is library code only: no sanitization logic, no policy decisions, no
//! runtime integration. Those live in `sigil-content` (PR2+) and
//! `sigil-policy` (PR6).
//!
//! The types exposed here are the wire contract between a future sanitizer
//! and its consumers (audit log, policy evaluator, conductor). Everything
//! derives `Serialize`/`Deserialize` so a `SanitizeReport` can be persisted
//! and replayed.
//!
//! Key invariants established at this layer:
//!
//! - [`ContentSource::from_url`] is PII-safe: query, fragment, and userinfo
//!   are always stripped. [`ContentSource::from_url_preserve_query`] keeps
//!   query + fragment but **still** drops userinfo (credentials in a URL
//!   are never a legitimate preserve case).
//! - [`Fingerprint::compute`] requires a non-empty HMAC key. There is no
//!   unkeyed-SHA fallback — callers must surface the missing-key condition
//!   rather than silently emitting a correlatable plain hash.

use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::NormalizeResult;

type HmacSha256 = Hmac<Sha256>;

/// Wire-format version of [`SanitizeReport`].
///
/// Bump when the struct shape changes in a way consumers must observe.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Domain-separation tag mixed into every content fingerprint.
///
/// The fingerprint key may be shared with (or colocated next to) other
/// HMAC consumers in the workspace — notably `sigil-audit`'s chain HMAC.
/// Prefixing a fixed, versioned tag ensures that `HMAC(k, raw_bytes)`
/// computed here can never collide with an HMAC computed over the same
/// bytes in a different protocol context. Bump the `v1` suffix if the
/// fingerprint input changes shape.
const FINGERPRINT_DOMAIN_TAG: &[u8] = b"sigil.content.fingerprint.v1\n";

/// Errors produced while constructing core content types.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentError {
    /// No HMAC key is available. The fingerprint would have to fall back to
    /// plain SHA, which is exactly the correlation attack the keyed-hash
    /// design exists to prevent. Callers must handle this as a hard error.
    #[error("fingerprint key unavailable; keyed HMAC is required")]
    FingerprintKeyUnavailable,

    /// The input string could not be parsed as a URL.
    #[error("invalid url: {reason}")]
    InvalidUrl {
        /// Parser-provided reason.
        reason: String,
    },

    /// The URL parsed but was missing a component required for provenance
    /// (currently: host).
    #[error("url missing required component: {component}")]
    UrlMissingComponent {
        /// Name of the missing component (e.g. `host`).
        component: &'static str,
    },
}

/// Declared content type of an external payload.
///
/// The caller **must** declare this; the sanitizer never sniffs. If the
/// caller doesn't know, the correct answer is to reject the input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ContentType {
    Html,
    Markdown,
    Json,
    #[default]
    PlainText,
    Log,
}

/// Severity of a single sanitization finding.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[non_exhaustive]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

/// Half-open byte range `[start, end)` into the *cleaned* text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

/// A single rule hit produced by the sanitizer.
///
/// `rule_id` is a stable identifier (e.g. `"INJ-001"`). `span` and `sample`
/// are optional so rules that cannot localize a match (e.g. entropy gates)
/// can still report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<ByteRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<String>,
}

/// A URL whose PII-sensitive components have been stripped at construction.
///
/// Fields are private: the only way to build a `UrlSource` is through
/// [`ContentSource::from_url`] or [`ContentSource::from_url_preserve_query`],
/// so the "no userinfo, no matrix params" invariant cannot be bypassed by a
/// struct literal. `Serialize`/`Deserialize` are derived to support audit
/// log persistence — a deserialized `UrlSource` is trusted to the same
/// degree as the store it came from (typically the HMAC-chained audit log).
///
/// Accessors are read-only. If mutation is ever needed, route it through a
/// constructor so the invariant stays enforced.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UrlSource {
    scheme: String,
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    /// Path with matrix-style params (`;key=val`, literal or
    /// percent-encoded) stripped from each segment. Secrets can still live
    /// in path segments (e.g. `/reset/<token>`); host-specific redaction
    /// is out of scope for PR1.
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fragment: Option<String>,
}

impl UrlSource {
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
}

impl fmt::Display for UrlSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        f.write_str(&self.path)?;
        if let Some(q) = &self.query {
            write!(f, "?{q}")?;
        }
        if let Some(fr) = &self.fragment {
            write!(f, "#{fr}")?;
        }
        Ok(())
    }
}

/// Provenance of an external payload.
///
/// `ContentSource` is serialized into the audit log and rendered into the
/// in-band provenance wrap. URLs are split into their non-secret parts at
/// construction (see [`UrlSource`]) so the `Display` impl has nothing
/// sensitive left to leak.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ContentSource {
    /// A URL with userinfo and (by default) query + fragment stripped.
    Url(UrlSource),
    /// Local file, identified by path.
    File { path: String },
    /// Bridge-delivered content (Telegram, Slack, …).
    Bridge { id: String },
    /// Free-form identifier when no structured source applies.
    Other(String),
}

impl ContentSource {
    /// PII-safe constructor.
    ///
    /// Retains `scheme + host + port + path`. Drops query, fragment, and
    /// userinfo (the `user:pass@` segment). Matrix-style path params
    /// (`;k=v`, including percent-encoded `%3B`) are stripped from each
    /// path segment.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::InvalidUrl`] if the input does not parse.
    /// Returns [`ContentError::UrlMissingComponent`] if the parsed URL has
    /// no host (e.g. `file:` URLs).
    pub fn from_url(url: &str) -> Result<Self, ContentError> {
        let parsed = url::Url::parse(url).map_err(|e| ContentError::InvalidUrl {
            reason: e.to_string(),
        })?;
        Ok(Self::Url(build_url_source(&parsed, false)?))
    }

    /// Opt-in constructor that preserves `?query` and `#fragment`.
    ///
    /// Userinfo is **still** stripped — credentials in a URL are never a
    /// legitimate preserve case. Use this only when the caller has verified
    /// the URL contains no secrets and the query string carries routing
    /// information the audit trail must retain.
    ///
    /// # Errors
    ///
    /// Same conditions as [`ContentSource::from_url`].
    pub fn from_url_preserve_query(url: &str) -> Result<Self, ContentError> {
        let parsed = url::Url::parse(url).map_err(|e| ContentError::InvalidUrl {
            reason: e.to_string(),
        })?;
        Ok(Self::Url(build_url_source(&parsed, true)?))
    }
}

fn build_url_source(url: &url::Url, preserve_query: bool) -> Result<UrlSource, ContentError> {
    let host = url
        .host_str()
        .ok_or(ContentError::UrlMissingComponent { component: "host" })?
        .to_owned();
    let (query, fragment) = if preserve_query {
        (
            url.query().map(ToOwned::to_owned),
            url.fragment().map(ToOwned::to_owned),
        )
    } else {
        (None, None)
    };
    Ok(UrlSource {
        scheme: url.scheme().to_owned(),
        host,
        port: url.port(),
        path: strip_matrix_params(url.path()),
        query,
        fragment,
    })
}

fn strip_matrix_params(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut first = true;
    for segment in path.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(first_matrix_cut(segment));
    }
    out
}

/// Return the prefix of `segment` up to the first matrix-param delimiter.
/// Recognizes a literal `;` and the case-insensitive percent-encoded
/// form `%3B` / `%3b`.
fn first_matrix_cut(segment: &str) -> &str {
    let mut idx = segment.len();
    if let Some(i) = segment.find(';') {
        idx = idx.min(i);
    }
    for (i, window) in segment.as_bytes().windows(3).enumerate() {
        if let [b'%', b'3', b'B' | b'b'] = *window {
            idx = idx.min(i);
            break;
        }
    }
    segment.get(..idx).unwrap_or(segment)
}

impl fmt::Display for ContentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(url) => url.fmt(f),
            Self::File { path } => write!(f, "file://{path}"),
            Self::Bridge { id } => write!(f, "bridge://{id}"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

/// Keyed HMAC-SHA256 fingerprint over payload bytes.
///
/// Used to prove "this is the same payload we saw before" without leaking
/// the payload itself. The key is a per-deployment secret held alongside
/// the audit key; plain SHA-256 is deliberately not supported because it
/// would enable offline dictionary / correlation attacks against a stolen
/// audit log.
///
/// Construct via [`Fingerprint::compute`], which fails hard when the key
/// is empty.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute `HMAC-SHA256(key, data)`.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::FingerprintKeyUnavailable`] if `key` is empty.
    /// There is no SHA-only fallback by design — callers must surface the
    /// missing-key condition.
    pub fn compute(key: &[u8], data: &[u8]) -> Result<Self, ContentError> {
        if key.is_empty() {
            return Err(ContentError::FingerprintKeyUnavailable);
        }
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| ContentError::FingerprintKeyUnavailable)?;
        // Domain separation: prefix every fingerprint input with a fixed
        // versioned tag so the same key used elsewhere in the workspace
        // cannot produce a colliding MAC.
        mac.update(FINGERPRINT_DOMAIN_TAG);
        mac.update(data);
        let out = mac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding of the 32-byte digest.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render as hex so debug dumps stay readable without exposing the
        // key (the digest alone is not secret, but an array of bytes in
        // debug output is noise).
        f.debug_tuple("Fingerprint").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex: String = Deserialize::deserialize(deserializer)?;
        if hex.len() != 64 {
            return Err(serde::de::Error::custom(
                "fingerprint hex must be 64 characters",
            ));
        }
        let mut bytes = [0u8; 32];
        for (slot, chunk) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let mut nibbles = chunk.iter().map(|&b| {
                hex_nibble(b).ok_or_else(|| {
                    serde::de::Error::custom("fingerprint contains non-hex characters")
                })
            });
            let hi = nibbles
                .next()
                .unwrap_or_else(|| Err(serde::de::Error::custom("fingerprint hex truncated")))?;
            let lo = nibbles
                .next()
                .unwrap_or_else(|| Err(serde::de::Error::custom("fingerprint hex truncated")))?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Diagnostic report emitted alongside every sanitization pass.
///
/// This is the authoritative provenance record — the audit log and policy
/// evaluator read from here, not from the in-band provenance wrap.
///
/// Three versions travel together so older reports stay interpretable:
///
/// - `schema_version` — wire shape of this struct.
/// - `rule_set_version` — which rule catalog produced `findings`.
/// - `scoring_version` — which weighting produced `risk_score`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizeReport {
    pub schema_version: u32,
    pub rule_set_version: u32,
    pub scoring_version: u32,
    pub source: ContentSource,
    pub content_type: ContentType,
    pub bytes_in: usize,
    pub bytes_out: usize,
    #[serde(default)]
    pub stripped_elements: Vec<(String, u32)>,
    pub text_normalize: NormalizeResult,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub risk_score: u8,
    pub repetition_ratio: f32,
    pub size_rejected: bool,
    pub encoding_rejected: bool,
    pub nonce: String,
    pub duration_ms: u64,
    pub raw_fingerprint: Fingerprint,
    pub sanitized_fingerprint: Fingerprint,
}

/// The output of a sanitization pass: cleaned text plus its report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizedContent {
    pub text: String,
    pub report: SanitizeReport,
}

/// Declares whether an action's result must be accompanied by a
/// [`SanitizeReport`].
///
/// `Required(ContentType)` lets the policy evaluator assert that the
/// reported `content_type` matches what the action claimed to fetch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SanitizationRequirement {
    #[default]
    None,
    Required(ContentType),
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::wildcard_enum_match_arm,
        reason = "test code asserts on values that are provably safe to unwrap"
    )]

    use super::*;

    fn sample_report() -> SanitizeReport {
        let key = b"test-key-not-a-real-secret";
        SanitizeReport {
            schema_version: REPORT_SCHEMA_VERSION,
            rule_set_version: 1,
            scoring_version: 1,
            source: ContentSource::from_url("https://example.com/article").unwrap(),
            content_type: ContentType::Html,
            bytes_in: 1024,
            bytes_out: 900,
            stripped_elements: vec![("script".into(), 2), ("comment".into(), 5)],
            text_normalize: NormalizeResult::default(),
            findings: vec![Finding {
                rule_id: "INJ-001".into(),
                severity: Severity::High,
                span: Some(ByteRange { start: 10, end: 42 }),
                sample: Some("ignore previous instructions".into()),
            }],
            risk_score: 75,
            repetition_ratio: 0.12,
            size_rejected: false,
            encoding_rejected: false,
            nonce: "7f3a9c2e".into(),
            duration_ms: 3,
            raw_fingerprint: Fingerprint::compute(key, b"raw bytes").unwrap(),
            sanitized_fingerprint: Fingerprint::compute(key, b"cleaned bytes").unwrap(),
        }
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = sample_report();
        let json = serde_json::to_string(&report).expect("serialize");
        let back: SanitizeReport = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.schema_version, report.schema_version);
        assert_eq!(back.rule_set_version, report.rule_set_version);
        assert_eq!(back.content_type, report.content_type);
        assert_eq!(back.source, report.source);
        assert_eq!(back.findings, report.findings);
        assert_eq!(back.raw_fingerprint, report.raw_fingerprint);
        assert_eq!(back.sanitized_fingerprint, report.sanitized_fingerprint);
    }

    #[test]
    fn sanitized_content_round_trips() {
        let content = SanitizedContent {
            text: "hello".into(),
            report: sample_report(),
        };
        let json = serde_json::to_string(&content).expect("serialize");
        let back: SanitizedContent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.text, content.text);
        assert_eq!(back.report.nonce, content.report.nonce);
    }

    fn expect_url(source: &ContentSource) -> &UrlSource {
        match source {
            ContentSource::Url(u) => u,
            other => panic!("expected Url variant, got {other:?}"),
        }
    }

    #[test]
    fn from_url_strips_query_fragment_and_userinfo() {
        let source = ContentSource::from_url(
            "https://user:pass@x.example/p?api_key=SECRET&email=me@x#section",
        )
        .expect("parse");

        assert_eq!(source.to_string(), "https://x.example/p");
        let url = expect_url(&source);
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host(), "x.example");
        assert_eq!(url.path(), "/p");
        assert!(url.port().is_none());
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn from_url_preserve_query_keeps_query_and_fragment_but_drops_userinfo() {
        let source =
            ContentSource::from_url_preserve_query("https://user:pass@x.example/p?k=v&more=1#frag")
                .expect("parse");

        assert_eq!(source.to_string(), "https://x.example/p?k=v&more=1#frag");
        let url = expect_url(&source);
        assert_eq!(url.query(), Some("k=v&more=1"));
        assert_eq!(url.fragment(), Some("frag"));
    }

    #[test]
    fn from_url_strips_matrix_params_from_path_segments() {
        let source = ContentSource::from_url("https://x.example/a;sid=abc/b;v=1/c").expect("parse");
        assert_eq!(source.to_string(), "https://x.example/a/b/c");
    }

    #[test]
    fn from_url_strips_percent_encoded_matrix_params() {
        // `%3B` is the percent-encoded form of `;`; the stripper must catch
        // it so attackers cannot hide matrix params by encoding them.
        let source =
            ContentSource::from_url("https://x.example/a%3Bsid=abc/b%3bv=1/c").expect("parse");
        assert_eq!(source.to_string(), "https://x.example/a/b/c");
    }

    #[test]
    fn from_url_preserves_non_default_port() {
        let source = ContentSource::from_url("https://x.example:8443/admin").expect("parse");
        let url = expect_url(&source);
        assert_eq!(url.port(), Some(8443));
        assert_eq!(source.to_string(), "https://x.example:8443/admin");
    }

    #[test]
    fn from_url_rejects_unparseable_input() {
        let err = ContentSource::from_url("not a url").expect_err("must reject");
        assert!(matches!(err, ContentError::InvalidUrl { .. }));
    }

    #[test]
    fn from_url_rejects_missing_host() {
        let err = ContentSource::from_url("file:///etc/hosts").expect_err("must reject");
        assert!(matches!(
            err,
            ContentError::UrlMissingComponent { component: "host" }
        ));
    }

    #[test]
    fn fingerprint_hard_fails_on_empty_key() {
        let err = Fingerprint::compute(b"", b"payload").expect_err("must reject empty key");
        assert!(matches!(err, ContentError::FingerprintKeyUnavailable));
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_key_and_input() {
        let a = Fingerprint::compute(b"k", b"data").unwrap();
        let b = Fingerprint::compute(b"k", b"data").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_hex().len(), 64);
    }

    #[test]
    fn fingerprint_differs_across_keys() {
        let a = Fingerprint::compute(b"k1", b"data").unwrap();
        let b = Fingerprint::compute(b"k2", b"data").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_round_trips_through_json() {
        let fp = Fingerprint::compute(b"k", b"data").unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        let back: Fingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }

    #[test]
    fn fingerprint_is_domain_separated_from_plain_hmac() {
        // If the fingerprint ever switched to a non-tagged HMAC, this digest
        // would collide with raw `HMAC-SHA256(key, data)`. Lock the tagged
        // behavior in by asserting that the computed digest matches the
        // tagged form — and differs from the untagged form.
        use hmac::{Mac as _, SimpleHmac};
        type Raw = SimpleHmac<Sha256>;

        let key = b"k";
        let data = b"payload";

        let mut tagged = Raw::new_from_slice(key).unwrap();
        tagged.update(FINGERPRINT_DOMAIN_TAG);
        tagged.update(data);
        let tagged_bytes: [u8; 32] = tagged.finalize().into_bytes().into();

        let mut plain = Raw::new_from_slice(key).unwrap();
        plain.update(data);
        let plain_bytes: [u8; 32] = plain.finalize().into_bytes().into();

        let fp = Fingerprint::compute(key, data).unwrap();
        assert_eq!(fp.as_bytes(), &tagged_bytes);
        assert_ne!(fp.as_bytes(), &plain_bytes);
    }

    #[test]
    fn fingerprint_rejects_malformed_hex() {
        let err = serde_json::from_str::<Fingerprint>("\"zz\"").unwrap_err();
        assert!(err.to_string().contains("64 characters"));
    }

    #[test]
    fn default_values_are_sensible() {
        assert_eq!(ContentType::default(), ContentType::PlainText);
        assert_eq!(Severity::default(), Severity::Info);
        assert_eq!(ByteRange::default(), ByteRange { start: 0, end: 0 });
        assert_eq!(
            SanitizationRequirement::default(),
            SanitizationRequirement::None
        );
    }

    #[test]
    fn severity_orders_info_lowest_high_highest() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }

    #[test]
    fn sanitization_requirement_round_trips() {
        for req in [
            SanitizationRequirement::None,
            SanitizationRequirement::Required(ContentType::Html),
            SanitizationRequirement::Required(ContentType::Json),
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: SanitizationRequirement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, req);
        }
    }

    #[test]
    fn content_source_display_never_leaks_stripped_parts() {
        let source =
            ContentSource::from_url("https://user:pass@x.example/p;sid=abc?api_key=SECRET#frag")
                .unwrap();

        let rendered = source.to_string();
        assert!(!rendered.contains("user"));
        assert!(!rendered.contains("pass"));
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("api_key"));
        assert!(!rendered.contains("sid"));
        assert!(!rendered.contains("frag"));
        assert!(!rendered.contains('?'));
        assert!(!rendered.contains('#'));
    }
}
