//! `sigil content sanitize` — debug / red-team harness for the
//! [`sigil_content`] pipeline.
//!
//! Reads a file from disk, dispatches to the format-appropriate sanitizer
//! entry point, and prints the cleaned text plus a human-readable summary
//! of the [`SanitizeReport`] (or the full JSON report, with `--json`).
//!
//! This command is the only production call site where a human — not an
//! agent — feeds bytes into the sanitizer. It exists so Sebastian can
//! eyeball a suspicious fixture, regressions can be reproduced by hand,
//! and CI can shell out to it for integration checks.

use std::path::Path;

use anyhow::{Context, Result};
use clap::ValueEnum;

use sigil_content::{RawFetchedContent, Sanitizer};
use sigil_core::{ContentSource, ContentType, SanitizedContent};

use crate::audit::resolve_key;
use crate::expand_tilde;

/// CLI-facing selector for which sanitizer entry point to invoke.
///
/// Mirrors [`ContentType`] but with CLI-friendly names (`md`/`text`).
/// Keeping the two separate lets us evolve the sanitizer's content-type
/// enum without breaking the command surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ContentKind {
    Html,
    Md,
    Json,
    Text,
    Log,
}

impl ContentKind {
    fn as_core(self) -> ContentType {
        match self {
            Self::Html => ContentType::Html,
            Self::Md => ContentType::Markdown,
            Self::Json => ContentType::Json,
            Self::Text => ContentType::PlainText,
            Self::Log => ContentType::Log,
        }
    }
}

/// Run `sigil content sanitize`.
///
/// # Errors
///
/// Propagates IO, key-resolution, and sanitizer errors. A sanitizer
/// rejection (oversize, invalid UTF-8, unsupported content type) surfaces
/// as an `anyhow::Error` rather than a silent partial result; callers can
/// distinguish cleanly from a successful call that produced a populated
/// report.
#[allow(clippy::print_stdout)]
pub async fn sanitize(
    file: &str,
    kind: ContentKind,
    source_override: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let path = expand_tilde(file)?;
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let source = resolve_source(&path, source_override);
    let content_type = kind.as_core();

    let key = resolve_key().context("failed to resolve fingerprint HMAC key")?;
    let sanitizer = Sanitizer::new(key.bytes.as_ref())
        .context("failed to initialize sanitizer (fingerprint key unavailable?)")?;

    let raw = RawFetchedContent::from_bytes(bytes);
    let result: SanitizedContent = match kind {
        ContentKind::Html => sanitizer
            .sanitize_html(raw, source)
            .context("HTML sanitization failed")?,
        ContentKind::Md => sanitizer
            .sanitize_markdown(raw, source)
            .context("Markdown sanitization failed")?,
        ContentKind::Json => sanitizer
            .sanitize_json(raw, source)
            .context("JSON sanitization failed")?,
        ContentKind::Text | ContentKind::Log => sanitizer
            .sanitize_plain(raw, source, content_type)
            .context("plain-text sanitization failed")?,
    };

    if json_out {
        let payload = serde_json::to_string_pretty(&result)
            .context("failed to serialize SanitizedContent to JSON")?;
        println!("{payload}");
    } else {
        print_human(&result);
    }
    Ok(())
}

fn resolve_source(path: &Path, source_override: Option<&str>) -> ContentSource {
    if let Some(raw) = source_override {
        // Accept either a URL (runs through the PII-safe constructor) or
        // a free-form identifier. `from_url` rejects inputs without a
        // host, which is the right behavior for CLI debugging: if you
        // pass `--source foo`, you get a `ContentSource::Other("foo")`,
        // not an error.
        if let Ok(url) = ContentSource::from_url(raw) {
            return url;
        }
        return ContentSource::Other(raw.to_owned());
    }
    ContentSource::File {
        path: path.to_string_lossy().into_owned(),
    }
}

#[allow(clippy::print_stdout)]
fn print_human(sc: &SanitizedContent) {
    let r = &sc.report;
    println!("=== SanitizeReport ===");
    println!("source         : {:?}", r.source);
    println!("content_type   : {:?}", r.content_type);
    println!("bytes_in       : {}", r.bytes_in);
    println!("bytes_out      : {}", r.bytes_out);
    println!("risk_score     : {}", r.risk_score);
    println!("repetition     : {:.4}", r.repetition_ratio);
    println!("duration_ms    : {}", r.duration_ms);
    println!("schema_ver     : {}", r.schema_version);
    println!("rule_set_ver   : {}", r.rule_set_version);
    println!("scoring_ver    : {}", r.scoring_version);
    println!("nonce          : {}", r.nonce);
    println!("raw_fp         : {}", hex(r.raw_fingerprint.as_bytes()));
    println!(
        "sanitized_fp   : {}",
        hex(r.sanitized_fingerprint.as_bytes())
    );
    if r.size_rejected {
        println!("size_rejected  : true");
    }
    if r.encoding_rejected {
        println!("encoding_rejected: true");
    }
    if !r.stripped_elements.is_empty() {
        println!("stripped       :");
        for (kind, count) in &r.stripped_elements {
            println!("  {kind}: {count}");
        }
    }
    let tn = &r.text_normalize;
    println!(
        "text_normalize : stripped={} categories={:?}",
        tn.stripped_count, tn.categories
    );
    if r.findings.is_empty() {
        println!("findings       : (none)");
    } else {
        println!("findings       :");
        for f in &r.findings {
            let sample = f.sample.as_deref().unwrap_or("");
            println!("  [{}] {:?}  {}", f.rule_id, f.severity, sample);
        }
    }
    println!();
    println!("=== Cleaned output ({} bytes) ===", r.bytes_out);
    println!("{}", sc.text);
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(char::from(to_hex_digit(b >> 4)));
        out.push(char::from(to_hex_digit(b & 0x0f)));
    }
    out
}

const fn to_hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => b'?',
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::wildcard_enum_match_arm,
        reason = "test code asserts on known-good variant construction"
    )]

    use super::*;

    #[test]
    fn content_kind_maps_to_core_content_type() {
        assert!(matches!(ContentKind::Html.as_core(), ContentType::Html));
        assert!(matches!(ContentKind::Md.as_core(), ContentType::Markdown));
        assert!(matches!(ContentKind::Json.as_core(), ContentType::Json));
        assert!(matches!(
            ContentKind::Text.as_core(),
            ContentType::PlainText
        ));
        assert!(matches!(ContentKind::Log.as_core(), ContentType::Log));
    }

    #[test]
    fn resolve_source_defaults_to_file() {
        let path = Path::new("/tmp/fixture.html");
        let src = resolve_source(path, None);
        match src {
            ContentSource::File { path } => assert_eq!(path, "/tmp/fixture.html"),
            other => panic!("expected File source, got {other:?}"),
        }
    }

    #[test]
    fn resolve_source_honors_url_override() {
        let path = Path::new("/tmp/x");
        let src = resolve_source(path, Some("https://example.com/a?k=SECRET"));
        match src {
            ContentSource::Url(u) => {
                assert_eq!(u.host(), "example.com");
                assert_eq!(u.path(), "/a");
                assert!(u.query().is_none(), "query must be stripped PII-safely");
            }
            other => panic!("expected Url source, got {other:?}"),
        }
    }

    #[test]
    fn resolve_source_falls_back_to_other_for_non_url_override() {
        let path = Path::new("/tmp/x");
        let src = resolve_source(path, Some("corpus:benign:001"));
        match src {
            ContentSource::Other(label) => assert_eq!(label, "corpus:benign:001"),
            other => panic!("expected Other source, got {other:?}"),
        }
    }

    #[test]
    fn hex_encodes_32_bytes_as_64_chars() {
        let bytes = [0u8; 32];
        let encoded = hex(&bytes);
        assert_eq!(encoded.len(), 64);
        assert!(encoded.chars().all(|c| c == '0'));

        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let encoded = hex(&bytes);
        assert!(encoded.starts_with("ab"));
        assert!(encoded.ends_with("cd"));
    }
}
