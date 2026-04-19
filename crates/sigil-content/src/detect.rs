//! Pre-dispatch content-type sniff.
//!
//! This module owns the narrow "should we reroute the declared content
//! type before picking a sanitizer?" question. It is deliberately much
//! stricter than Stage 5's `has_strong_html_markers` — the scan runs on
//! raw bytes, before UTF-8 decode, and before any pattern catalog.
//! We look for document-root markers only (`<!DOCTYPE html>` /
//! `<html>`), which do not appear at the head of legitimate prose.
//!
//! **Availability tradeoff.** The sniff searches anywhere in the first
//! [`SNIFF_WINDOW`] bytes, not just the leading token. A prose
//! passage that quotes `<!DOCTYPE html>` mid-sentence within the
//! first window will reroute to the HTML sanitizer. That's a
//! deliberate bias toward a safer strip — a false positive here costs
//! availability (over-routing, possible `SanitizationRequirement`
//! mismatch if the action declared `Required(PlainText)`) but never
//! integrity/confidentiality. If the FP rate proves painful, tighten
//! to "first significant token after BOM/whitespace/comments" in a
//! follow-up; the current behavior is pinned by
//! `crate::tests::dispatch_reroutes_prose_containing_doctype_marker`
//! so a future tightening is a reviewable diff.
//!
//! Path A (document-root) drives routing; Path B (fragment heuristic)
//! lives in [`crate::patterns::scan`] as non-routing audit signal.
//! See `docs/design/content-sanitization.md` for the routing design
//! and `docs/design/fmt-001-scoping.md` for the rationale.

/// Lowercase keyword prefix of an HTML doctype.
///
/// Anchored to `<!doctype`; `is_doctype_html_at` skips any run of
/// ASCII whitespace before matching the `html` name, then enforces a
/// tag-name terminator. HTML spec allows any ASCII-whitespace (space,
/// tab, CR, LF, FF) between `DOCTYPE` and `html`, and permits the
/// doctype to carry additional tokens (`<!DOCTYPE html PUBLIC "...">`,
/// the legacy XHTML doctypes) — we only need to recognize the opener.
const DOCTYPE_KEYWORD: &[u8] = b"<!doctype";

/// Lowercase `html` literal that must follow the doctype keyword +
/// whitespace for a Path-A match.
const HTML_NAME: &[u8] = b"html";

/// Lowercase `<html` prefix used to detect HTML document roots.
const HTML_TAG_PREFIX: &[u8] = b"<html";

/// Maximum prefix window scanned for a document-root marker.
///
/// Real HTML documents put the DOCTYPE or `<html>` tag in the first
/// few hundred bytes; scanning the whole payload would let an attacker
/// smuggle a marker deep inside otherwise-legitimate plain text and
/// force the reroute. The window is intentionally generous — a BOM
/// plus leading whitespace / HTML comments can push the marker a few
/// hundred bytes down — but bounded so the sniff stays O(1) in
/// payload size.
const SNIFF_WINDOW: usize = 1024;

/// ASCII-only sniff: does the leading window of `bytes` look like the
/// start of an HTML document?
///
/// Matches a case-insensitive `<!DOCTYPE html` or `<html` (followed by
/// whitespace, `>`, or end-of-input) anywhere in the first
/// [`SNIFF_WINDOW`] bytes. Byte-level — no UTF-8 decode, no regex.
/// The sniff is intentionally narrow enough that prose discussing
/// `<!DOCTYPE html>` mid-article does not trip it (the marker would
/// have to sit inside the prefix window, which ordinary prose does
/// not arrange).
///
/// Returns `true` when the caller should reroute from the declared
/// [`sigil_core::ContentType::PlainText`] to
/// [`sigil_core::ContentType::Html`] for a safer strip.
#[must_use]
pub(crate) fn looks_like_html_document_root(bytes: &[u8]) -> bool {
    let end = bytes.len().min(SNIFF_WINDOW);
    let Some(window) = bytes.get(..end) else {
        return false;
    };

    for i in 0..window.len() {
        if is_doctype_html_at(window, i) || is_html_tag_at(window, i) {
            return true;
        }
    }
    false
}

/// Case-insensitive ASCII match of `<!doctype` at `offset`, followed
/// by ≥ 1 ASCII-whitespace byte, then `html`, then a tag-name
/// terminator (whitespace, `>`, `/`, or end-of-window). The shape
/// covers `<!DOCTYPE html>`, `<!DOCTYPE  html>` (multiple spaces),
/// `<!DOCTYPE\thtml>` (tab), `<!DOCTYPE\r\nhtml>` (CR/LF), and the
/// legacy `<!DOCTYPE html PUBLIC ...>` form, without matching
/// `<!doctype htmlish>` or a bare `<!DOCTYPEfoo>`.
fn is_doctype_html_at(window: &[u8], offset: usize) -> bool {
    let after_keyword = offset.saturating_add(DOCTYPE_KEYWORD.len());
    let Some(keyword) = window.get(offset..after_keyword) else {
        return false;
    };
    if !ascii_eq_ignore_case(keyword, DOCTYPE_KEYWORD) {
        return false;
    }

    // At least one ASCII-whitespace byte must separate `<!doctype`
    // from `html`. An attacker cannot pack `<!DOCTYPEhtml>` — the HTML
    // spec requires the whitespace and no browser sniffs that form.
    let ws_start = after_keyword;
    let ws_end = skip_ascii_whitespace(window, ws_start);
    if ws_end == ws_start {
        // Keyword was followed by something other than whitespace or
        // end-of-window. End-of-window after the keyword alone is
        // treated as a match below — the payload is truncated and the
        // opener runs to EOF.
        return ws_start >= window.len();
    }

    let name_end = ws_end.saturating_add(HTML_NAME.len());
    let Some(name) = window.get(ws_end..name_end) else {
        // Truncated payload that starts `<!DOCTYPE ` (keyword + ws) but
        // runs off the end of the window mid-name — treat as a match,
        // same as the truncated-marker rule below.
        return true;
    };
    if !ascii_eq_ignore_case(name, HTML_NAME) {
        return false;
    }
    is_tag_name_terminator(window.get(name_end).copied())
}

/// Advance past a run of ASCII-whitespace bytes starting at `start`,
/// returning the index of the first non-whitespace byte (or
/// `window.len()` if the run extends to the end of the window).
fn skip_ascii_whitespace(window: &[u8], start: usize) -> usize {
    let mut i = start;
    while let Some(&b) = window.get(i) {
        if is_ascii_whitespace(b) {
            i = i.saturating_add(1);
        } else {
            break;
        }
    }
    i
}

/// ASCII-whitespace per the HTML spec: space, tab, LF, FF, CR.
fn is_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0C | b'\r')
}

/// Case-insensitive ASCII match of [`HTML_TAG_PREFIX`] at `offset`,
/// followed by a tag-name terminator so `<htmlfoo` does not match.
fn is_html_tag_at(window: &[u8], offset: usize) -> bool {
    let end = offset.saturating_add(HTML_TAG_PREFIX.len());
    let Some(slice) = window.get(offset..end) else {
        return false;
    };
    if !ascii_eq_ignore_case(slice, HTML_TAG_PREFIX) {
        return false;
    }
    is_tag_name_terminator(window.get(end).copied())
}

/// Tag-name terminator: end-of-window, ASCII whitespace, `>`, or `/`.
///
/// `None` means the sniff window ended mid-marker, which we treat as
/// a match (the opener runs to EOF). Non-alphanumeric ASCII after the
/// prefix is a terminator; alphanumerics extend the tag name and
/// reject the match.
fn is_tag_name_terminator(b: Option<u8>) -> bool {
    match b {
        None => true,
        Some(c) => is_ascii_whitespace(c) || matches!(c, b'>' | b'/'),
    }
}

/// Case-insensitive ASCII byte comparison. `needle` must already be
/// lowercase (the module's constants are).
fn ascii_eq_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() != needle.len() {
        return false;
    }
    for (h, n) in haystack.iter().zip(needle.iter()) {
        if h.to_ascii_lowercase() != *n {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn doctype_html_matches_canonical_form() {
        assert!(looks_like_html_document_root(
            b"<!DOCTYPE html>\n<html><body>hi</body></html>"
        ));
    }

    #[test]
    fn doctype_html_is_case_insensitive() {
        assert!(looks_like_html_document_root(b"<!doctype HTML>"));
        assert!(looks_like_html_document_root(b"<!DocType Html>"));
    }

    #[test]
    fn doctype_accepts_any_ascii_whitespace_run() {
        // Tab, CR/LF, form-feed, and multi-space separators between
        // `<!DOCTYPE` and `html` are all valid per the HTML spec. The
        // sniff must match all of them.
        assert!(looks_like_html_document_root(b"<!DOCTYPE\thtml>"));
        assert!(looks_like_html_document_root(b"<!DOCTYPE  html>"));
        assert!(looks_like_html_document_root(b"<!DOCTYPE\r\nhtml>"));
        assert!(looks_like_html_document_root(b"<!DOCTYPE\x0Chtml>"));
        assert!(looks_like_html_document_root(
            b"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">"
        ));
    }

    #[test]
    fn doctype_without_whitespace_does_not_match() {
        // `<!DOCTYPEhtml>` has no spec-valid form; reject it so we
        // don't create a new sniff attack surface.
        assert!(!looks_like_html_document_root(b"<!DOCTYPEhtml>"));
    }

    #[test]
    fn form_feed_is_a_tag_name_terminator() {
        // `<html\x0C...>` is spec-valid; form-feed must terminate the
        // tag name just like space/tab/CR/LF.
        assert!(looks_like_html_document_root(b"<html\x0Clang=en>"));
    }

    #[test]
    fn html_tag_alone_matches() {
        assert!(looks_like_html_document_root(b"<html><body>hi</body>"));
        assert!(looks_like_html_document_root(b"<HTML>\n  <body>"));
        assert!(looks_like_html_document_root(b"<html lang=\"en\">"));
    }

    #[test]
    fn html_tag_with_self_closing_slash_matches() {
        assert!(looks_like_html_document_root(b"<html/>"));
    }

    #[test]
    fn no_markers_is_plain_text() {
        assert!(!looks_like_html_document_root(b"Hello, world! Plain text."));
        assert!(!looks_like_html_document_root(b""));
    }

    #[test]
    fn htmlish_tag_does_not_match() {
        // Must require a tag-name terminator so a token like `<htmlfoo`
        // or `<htmlfiddle>` does not trip the sniff.
        assert!(!looks_like_html_document_root(b"<htmlfoo>bar</htmlfoo>"));
        assert!(!looks_like_html_document_root(b"<!doctype htmlish>"));
    }

    #[test]
    fn marker_after_leading_whitespace_matches() {
        assert!(looks_like_html_document_root(
            b"   \n\t<!DOCTYPE html>\n<html>"
        ));
    }

    #[test]
    fn marker_after_html_comment_in_window_matches() {
        assert!(looks_like_html_document_root(
            b"<!-- leading comment --><!DOCTYPE html>"
        ));
    }

    #[test]
    fn marker_outside_window_does_not_match() {
        // Any document-root marker beyond SNIFF_WINDOW bytes is ignored —
        // real HTML puts its root marker up front.
        let mut payload = vec![b' '; SNIFF_WINDOW + 16];
        payload.extend_from_slice(b"<!DOCTYPE html>");
        assert!(!looks_like_html_document_root(&payload));
    }

    #[test]
    fn marker_inline_in_prose_near_start_still_matches() {
        // A prose article that opens with `<!DOCTYPE html>` (e.g. a
        // markdown codeblock rendered as plain text) will trip the sniff.
        // That's an intentional false positive: the reroute to `sanitize_html`
        // is a safer strip than trusting the declared `text/plain`.
        assert!(looks_like_html_document_root(
            b"Example: <!DOCTYPE html> is the opener."
        ));
    }

    #[test]
    fn marker_truncated_at_window_boundary_still_matches() {
        // If a payload is short and happens to end mid-marker, treat it
        // as a match — the fragment is already suspicious enough, and a
        // truncated marker cannot be disambiguated without more bytes.
        assert!(looks_like_html_document_root(b"<html"));
        assert!(looks_like_html_document_root(b"<!DOCTYPE html"));
    }

    #[test]
    fn utf8_non_ascii_does_not_break_sniff() {
        // Non-ASCII bytes before a marker shouldn't confuse the scan —
        // the sniff is pure byte-level, so a UTF-8 BOM (EF BB BF) or
        // a Latin-1 smart quote just takes up space in the window.
        let mut payload = vec![0xEF, 0xBB, 0xBF];
        payload.extend_from_slice(b"<!DOCTYPE html>");
        assert!(looks_like_html_document_root(&payload));
    }
}
